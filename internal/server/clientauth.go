package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/natrontech/entra-cimd-bridge/internal/cimd"
)

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	assertionLeeway     = 60 * time.Second
	maxAssertionJTIs    = 10000
)

// clientIDFromRequest reads the client_id a token request names before the client's metadata document decides how that client must authenticate
func clientIDFromRequest(r *http.Request) (string, string) {
	formID := r.PostForm.Get("client_id")
	user, pass, ok := r.BasicAuth()
	if !ok {
		if formID == "" {
			return "", "The request has no client_id."
		}
		return formID, ""
	}
	id, err := url.QueryUnescape(user)
	switch {
	case err != nil:
		return "", "The client_id in the Authorization header isn't form-encoded."
	case pass != "":
		return "", "Clients must not send a client secret."
	case formID != "" && formID != id:
		return "", "The client_id in the form and in the Authorization header differ."
	}
	return id, ""
}

// authenticateClient enforces the method the client's CIMD document declares
// Public clients use no client authentication; private_key_jwt clients must present a signed assertion whose key is published at their jwks_uri
func (s *Server) authenticateClient(ctx context.Context, r *http.Request, doc *cimd.Document) *tokenError {
	if r.PostForm.Get("client_secret") != "" {
		return &tokenError{http.StatusUnauthorized, "invalid_client", "Clients must not send a client secret."}
	}
	switch doc.TokenEndpointAuthMethod {
	case "none":
		if r.PostForm.Get("client_assertion") != "" || r.PostForm.Get("client_assertion_type") != "" {
			return &tokenError{http.StatusUnauthorized, "invalid_client", "This client doesn't use a client assertion."}
		}
		return nil
	case "private_key_jwt":
		if r.PostForm.Get("client_assertion_type") != clientAssertionType {
			return &tokenError{http.StatusUnauthorized, "invalid_client", "The client assertion type is invalid."}
		}
		assertion := r.PostForm.Get("client_assertion")
		if assertion == "" {
			return &tokenError{http.StatusUnauthorized, "invalid_client", "The client assertion is missing."}
		}
		keys, err := s.clients.FetchJWKS(ctx, doc.ClientID, doc.JWKSURI)
		if err != nil {
			s.log.InfoContext(ctx, "Rejected a client assertion", slog.String("client_id", doc.ClientID), slog.Any("error", err))
			return &tokenError{http.StatusUnauthorized, "invalid_client", cimd.Message(err)}
		}
		jti, expiry, err := verifyClientAssertion(keys, doc.ClientID, s.issuer+"/token", assertion, time.Now())
		if err != nil {
			s.log.InfoContext(ctx, "Rejected a client assertion", slog.String("client_id", doc.ClientID), slog.Any("error", err))
			return &tokenError{http.StatusUnauthorized, "invalid_client", "The client assertion is invalid."}
		}
		if !s.rememberAssertion(doc.ClientID, jti, expiry) {
			s.log.InfoContext(ctx, "Rejected a replayed client assertion", slog.String("client_id", doc.ClientID))
			return &tokenError{http.StatusUnauthorized, "invalid_client", "The client assertion was already used."}
		}
		return nil
	default:
		return &tokenError{http.StatusUnauthorized, "invalid_client", "The client uses an unsupported authentication method."}
	}
}

// verifyClientAssertion validates a private_key_jwt assertion (RFC 7523) and returns its jti and expiry for replay protection
func verifyClientAssertion(keys *jose.JSONWebKeySet, clientID, tokenEndpoint, assertion string, now time.Time) (string, time.Time, error) {
	token, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse assertion: %w", err)
	}
	if len(token.Headers) != 1 {
		return "", time.Time{}, errors.New("assertion must have exactly one protected header")
	}
	key, err := assertionKey(keys, token.Headers[0].KeyID)
	if err != nil {
		return "", time.Time{}, err
	}
	var claims jwt.Claims
	if err = token.Claims(key.Key, &claims); err != nil {
		return "", time.Time{}, fmt.Errorf("verify assertion: %w", err)
	}
	if claims.Expiry == nil {
		return "", time.Time{}, errors.New("assertion has no exp claim")
	}
	if claims.ID == "" {
		return "", time.Time{}, errors.New("assertion has no jti claim")
	}
	// ChatGPT signs the advertised token endpoint as aud, rather than the issuer, even though CIMD -02 prefers the issuer form
	expected := jwt.Expected{
		Issuer:      clientID,
		Subject:     clientID,
		AnyAudience: jwt.Audience{tokenEndpoint},
		Time:        now,
	}
	if err = claims.ValidateWithLeeway(expected, assertionLeeway); err != nil {
		return "", time.Time{}, fmt.Errorf("validate assertion claims: %w", err)
	}
	return claims.ID, claims.Expiry.Time(), nil
}

func assertionKey(set *jose.JSONWebKeySet, kid string) (*jose.JSONWebKey, error) {
	if set == nil || len(set.Keys) == 0 {
		return nil, errors.New("the client published no signing keys")
	}
	signingKey := func(k jose.JSONWebKey) bool {
		return k.Use == "" || k.Use == "sig"
	}
	if kid != "" {
		for i := range set.Keys {
			if set.Keys[i].KeyID == kid && signingKey(set.Keys[i]) {
				return &set.Keys[i], nil
			}
		}
		return nil, errors.New("the assertion key id isn't published")
	}
	if len(set.Keys) == 1 && signingKey(set.Keys[0]) {
		return &set.Keys[0], nil
	}
	return nil, errors.New("the assertion has no key id and the client published several keys")
}

// rememberAssertion records a jti until its assertion expires, rejecting replays
// The map is bounded; if it fills with unexpired entries, new assertions are rejected rather than allowing unbounded memory growth
func (s *Server) rememberAssertion(clientID, jti string, expiry time.Time) bool {
	now := time.Now()
	key := clientID + "\x00" + jti

	s.assertionMu.Lock()
	defer s.assertionMu.Unlock()
	for k, exp := range s.assertionJTIs {
		if !now.Before(exp) {
			delete(s.assertionJTIs, k)
		}
	}
	if _, ok := s.assertionJTIs[key]; ok {
		return false
	}
	if len(s.assertionJTIs) >= maxAssertionJTIs {
		return false
	}
	s.assertionJTIs[key] = expiry.Add(assertionLeeway)
	return true
}
