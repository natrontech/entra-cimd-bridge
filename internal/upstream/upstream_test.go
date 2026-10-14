package upstream

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discoveryServer serves an OIDC discovery document with extra fields, and a token endpoint answering with token
func discoveryServer(t *testing.T, extra map[string]any, token func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			token(w, r)
			return
		}
		doc := map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		for k, v := range extra {
			doc[k] = v
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDiscoveryRequiresS256OnlyWhenMethodsAreListed(t *testing.T) {
	// Entra lists no methods at all and supports S256
	srv := discoveryServer(t, nil, nil)
	_, err := Discover(t.Context(), "entra", srv.URL, srv.Client())
	require.NoError(t, err)

	srv = discoveryServer(t, map[string]any{"code_challenge_methods_supported": []string{"plain"}}, nil)
	_, err = Discover(t.Context(), "plain-only", srv.URL, srv.Client())
	require.ErrorContains(t, err, "S256")

	srv = discoveryServer(t, map[string]any{"code_challenge_methods_supported": []string{"plain", "S256"}}, nil)
	_, err = Discover(t.Context(), "both", srv.URL, srv.Client())
	require.NoError(t, err)
}

func TestDiscoveryRequiresAClientSecretMethodWhenMethodsAreListed(t *testing.T) {
	srv := discoveryServer(t, map[string]any{"token_endpoint_auth_methods_supported": []string{"private_key_jwt"}}, nil)
	_, err := Discover(t.Context(), "jwt-only", srv.URL, srv.Client())
	require.ErrorContains(t, err, "client secret")

	srv = discoveryServer(t, map[string]any{"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "client_secret_post"}}, nil)
	_, err = Discover(t.Context(), "post", srv.URL, srv.Client())
	require.NoError(t, err)
}

func TestTokenSendsCredentialsTheWayTheProviderPrefers(t *testing.T) {
	var got *http.Request
	answer := func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r
		_, _ = w.Write([]byte(`{"access_token":"at","expires_in":"3599","refresh_token":"rt","id_token":"id"}`))
	}
	creds := Credentials{ClientID: "app", ClientSecret: "s+cret"}

	srv := discoveryServer(t, map[string]any{"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"}}, answer)
	p, err := Discover(t.Context(), "post", srv.URL, srv.Client())
	require.NoError(t, err)
	tok, err := p.Token(t.Context(), creds, url.Values{"grant_type": {"refresh_token"}})
	require.NoError(t, err)
	assert.Equal(t, "s+cret", got.PostForm.Get("client_secret"))
	assert.Equal(t, "app", got.PostForm.Get("client_id"))
	assert.Equal(t, &Token{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3599, RefreshToken: "rt"}, tok)

	srv = discoveryServer(t, map[string]any{"token_endpoint_auth_methods_supported": []string{"client_secret_basic"}}, answer)
	p, err = Discover(t.Context(), "basic", srv.URL, srv.Client())
	require.NoError(t, err)
	_, err = p.Token(t.Context(), creds, url.Values{"grant_type": {"refresh_token"}})
	require.NoError(t, err)
	user, pass, ok := got.BasicAuth()
	require.True(t, ok)
	assert.Equal(t, "app", user)
	assert.Equal(t, "s%2Bcret", pass, "RFC 6749 form-encodes the secret before it goes into the header")
	assert.False(t, got.PostForm.Has("client_secret"))
}

func TestTokenErrors(t *testing.T) {
	srv := discoveryServer(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"AADSTS70008: The refresh token has expired.\r\nTrace ID: 1\r\nCorrelation ID: 2"}`))
	})
	p, err := Discover(t.Context(), "entra", srv.URL, srv.Client())
	require.NoError(t, err)
	_, err = p.Token(t.Context(), Credentials{ClientID: "app", ClientSecret: "s"}, url.Values{})
	status, code, description := TokenError(err)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", code)
	assert.Equal(t, "AADSTS70008: The refresh token has expired.", description)
}

func TestTokenErrorMapping(t *testing.T) {
	for idpCode, want := range map[string]struct {
		status int
		code   string
	}{
		"invalid_grant":        {400, "invalid_grant"},
		"interaction_required": {400, "invalid_grant"},
		"invalid_scope":        {400, "invalid_scope"},
		"invalid_client":       {500, "server_error"},
		"unauthorized_client":  {500, "server_error"},
		"invalid_target":       {500, "server_error"},
	} {
		status, code, _ := TokenError(&Error{Status: 400, Code: idpCode})
		assert.Equal(t, want.status, status, idpCode)
		assert.Equal(t, want.code, code, idpCode)
	}
	status, code, _ := TokenError(errors.New("connection refused"))
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "temporarily_unavailable", code)
}

func TestAuthorizeErrorMapping(t *testing.T) {
	for idpCode, want := range map[string]string{
		"access_denied":           "access_denied",
		"temporarily_unavailable": "temporarily_unavailable",
		"interaction_required":    "access_denied",
		"invalid_request":         "server_error",
		"unauthorized_client":     "server_error",
	} {
		code, _ := AuthorizeError(idpCode, "AADSTS50011: something\r\nTrace ID: 1")
		assert.Equal(t, want, code, idpCode)
	}
}
