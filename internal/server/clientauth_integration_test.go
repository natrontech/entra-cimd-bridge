package server

import (
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/natrontech/entra-cimd-bridge/internal/cimd"
)

func TestAuthenticateClientPrivateKeyJWT(t *testing.T) {
	key := newAssertionKey(t)
	signer := newAssertionSigner(t, key)
	pub := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	policy, err := cimd.NewPolicy([]string{"127.0.0.1"})
	require.NoError(t, err)
	fetcher := cimd.NewFetcher(policy, cimd.Options{AllowPrivateAddresses: true, RootCAs: pool})
	s := &Server{
		issuer:        "https://bridge.example",
		clients:       fetcher,
		log:           slog.Default(),
		assertionJTIs: map[string]time.Time{},
	}
	clientID := srv.URL + "/client.json"
	//nolint:gosec // test-only metadata with no credential
	doc := &cimd.Document{
		ClientID:                clientID,
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSURI:                 srv.URL + "/jwks.json",
	}
	claims := jwt.Claims{
		Issuer:   clientID,
		Subject:  clientID,
		Audience: jwt.Audience{s.issuer + "/token"},
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		ID:       "integration-1",
	}
	assertion := signAssertion(t, signer, claims)
	form := url.Values{
		"client_id":             {clientID},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {assertion},
	}
	r := httptest.NewRequest(http.MethodPost, s.issuer+"/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, r.ParseForm())

	assert.Nil(t, s.authenticateClient(t.Context(), r, doc))
	assert.NotNil(t, s.authenticateClient(t.Context(), r, doc), "the same jti must be rejected")
}
