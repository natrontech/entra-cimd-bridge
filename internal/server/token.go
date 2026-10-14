package server

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"gitlab.com/natrontech/applications/entra-cimd-bridge/internal/cimd"
	"gitlab.com/natrontech/applications/entra-cimd-bridge/internal/upstream"
)

// tokenResponse is what the client gets: the IdP's own tokens, without the ID token
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// tokenError is an OAuth error answer of the token endpoint
type tokenError struct {
	status      int
	code        string
	description string
}

// handleToken rewrites a client's token request into one the IdP accepts and relays the answer
// The code or refresh token goes to the IdP with the credentials of the app the resource maps to, so one issued for another MCP server's app fails there
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	allowCORS(w)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	tok, res, tErr := s.exchange(r)

	// The grant type only labels metrics when it is one of the two the bridge knows
	grantType := r.PostForm.Get("grant_type")
	if grantType != "authorization_code" && grantType != "refresh_token" {
		grantType = "other"
	}
	if tErr != nil {
		s.metrics.inc("bridge_token_requests_total", "grant_type", grantType, "outcome", tErr.code)
		if tErr.status == http.StatusUnauthorized && r.Header.Get("Authorization") != "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		}
		writeJSON(w, tErr.status, map[string]string{"error": tErr.code, "error_description": cleanDescription(tErr.description)})
		return
	}
	s.metrics.inc("bridge_token_requests_total", "grant_type", grantType, "outcome", "ok")
	s.log.InfoContext(r.Context(), "Issued tokens", slog.String("grant_type", grantType), slog.String("resource", res.uri))
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  tok.AccessToken,
		TokenType:    tok.TokenType,
		ExpiresIn:    int64(tok.ExpiresIn),
		RefreshToken: tok.RefreshToken,
		Scope:        tok.Scope,
	})
}

func (s *Server) exchange(r *http.Request) (*upstream.Token, *resource, *tokenError) {
	if err := r.ParseForm(); err != nil {
		return nil, nil, &tokenError{http.StatusBadRequest, "invalid_request", "The request body must be a form."}
	}
	form := r.PostForm
	for name, values := range form {
		if len(values) > 1 && name != "resource" {
			return nil, nil, &tokenError{http.StatusBadRequest, "invalid_request", "The request repeats " + name + "."}
		}
	}
	grantType := form.Get("grant_type")
	switch grantType {
	case "authorization_code", "refresh_token":
	case "":
		return nil, nil, &tokenError{http.StatusBadRequest, "invalid_request", "The request has no grant_type."}
	default:
		return nil, nil, &tokenError{http.StatusBadRequest, "unsupported_grant_type", "Only authorization_code and refresh_token are supported."}
	}

	// The client is checked like at authorization, so a client from a host that is no longer allowed can't refresh either
	clientID, problem := publicClientID(r)
	if problem != "" {
		return nil, nil, &tokenError{http.StatusUnauthorized, "invalid_client", problem}
	}
	doc, err := s.clients.Fetch(r.Context(), clientID)
	if err != nil {
		s.log.InfoContext(r.Context(), "Rejected a token request", slog.String("client_id", clientID), slog.Any("error", err))
		return nil, nil, &tokenError{http.StatusUnauthorized, "invalid_client", cimd.Message(err)}
	}
	res, err := s.resourceFor(form["resource"])
	if err != nil {
		return nil, nil, &tokenError{http.StatusBadRequest, "invalid_target", err.Error()}
	}

	// resource is never forwarded, since Entra rejects it next to scopes, and the mapped scopes stand in for it
	upstreamForm := url.Values{"grant_type": {grantType}, "scope": {strings.Join(res.scopes, " ")}}
	switch grantType {
	case "authorization_code":
		code, verifier, redirectURI := form.Get("code"), form.Get("code_verifier"), form.Get("redirect_uri")
		switch {
		case code == "" || verifier == "" || redirectURI == "":
			return nil, nil, &tokenError{http.StatusBadRequest, "invalid_request", "code, code_verifier and redirect_uri are required."}
		case !pkceValue.MatchString(verifier):
			return nil, nil, &tokenError{http.StatusBadRequest, "invalid_request", "The code_verifier must be 43 to 128 characters."}
		case !doc.AllowsRedirect(redirectURI):
			return nil, nil, &tokenError{http.StatusBadRequest, "invalid_grant", "The redirect_uri isn't registered for this client."}
		}

		// The IdP issued the code for the bridge's callback, so that is the redirect URI it expects back
		upstreamForm.Set("code", code)
		upstreamForm.Set("code_verifier", verifier)
		upstreamForm.Set("redirect_uri", s.callbackURL)
	case "refresh_token":
		if form.Get("refresh_token") == "" {
			return nil, nil, &tokenError{http.StatusBadRequest, "invalid_request", "refresh_token is required."}
		}
		upstreamForm.Set("refresh_token", form.Get("refresh_token"))
	}

	tok, err := res.provider.Token(r.Context(), res.creds, upstreamForm)
	if err != nil {
		status, code, description := upstream.TokenError(err)
		level := slog.LevelInfo
		if status >= 500 {
			level = slog.LevelError
		}
		s.log.Log(r.Context(), level, "The IdP refused a token request",
			slog.String("grant_type", grantType),
			slog.String("client_id", clientID),
			slog.String("resource", res.uri),
			slog.Any("error", err),
		)
		return nil, nil, &tokenError{status, code, description}
	}
	return tok, res, nil
}

// publicClientID reads the client ID from the form or from Basic authentication with an empty password, which some OAuth libraries send for public clients
// It returns the ID, or why the request can't be from a public client
func publicClientID(r *http.Request) (string, string) {
	formID := r.PostForm.Get("client_id")
	if r.PostForm.Get("client_secret") != "" {
		return "", "Clients here are public and must not send a secret."
	}
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
		return "", "Clients here are public and must not send a secret."
	case formID != "" && formID != id:
		return "", "The client_id in the form and in the Authorization header differ."
	}
	return id, ""
}

// handleTokenPreflight lets browser-based clients call the token endpoint, which needs no cookies
func (s *Server) handleTokenPreflight(w http.ResponseWriter, _ *http.Request) {
	allowCORS(w)
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}

func allowCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}
