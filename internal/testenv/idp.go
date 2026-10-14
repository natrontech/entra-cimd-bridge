// Package testenv runs a bridge against a fake IdP and a fake client host, for tests
package testenv

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// App is an app registration at the fake IdP, which may only request scopes of its own API, api://<ClientID>/...
type App struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
}

// IdP is a small OpenID provider that behaves like Entra where the bridge depends on it
// Codes and refresh tokens are bound to the app that requested them, codes to the PKCE challenge, and refresh tokens rotate
// Like Entra, it rejects the resource parameter and doesn't advertise code_challenge_methods_supported
type IdP struct {
	*httptest.Server
	t      testing.TB
	signer jose.Signer
	jwks   jose.JSONWebKeySet

	mu sync.Mutex
	// Subject is who signs in at the authorization endpoint
	Subject string
	// AccessTokenTTL is the lifetime of access tokens, an hour by default
	AccessTokenTTL time.Duration
	// DenyAuthorization makes the authorization endpoint answer access_denied
	DenyAuthorization bool
	apps              map[string]App
	codes             map[string]*grant
	refreshTokens     map[string]*grant
	refreshes         int
	tokenRequests     []TokenRequest
}

// TokenRequest is a token request the IdP received, for asserting how the bridge rewrote it
type TokenRequest struct {
	Form     url.Values
	ClientID string
	Secret   string
}

type grant struct {
	clientID    string
	redirectURI string
	challenge   string
	scopes      []string
}

// NewIdP starts a fake IdP over TLS
func NewIdP(t testing.TB) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	p := &IdP{
		t:              t,
		signer:         signer,
		jwks:           jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}},
		Subject:        "user-1",
		AccessTokenTTL: time.Hour,
		apps:           map[string]App{},
		codes:          map[string]*grant{},
		refreshTokens:  map[string]*grant{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, p.jwks) })
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.Server = httptest.NewTLSServer(mux)
	t.Cleanup(p.Close)
	return p
}

// Issuer is the IdP's issuer URL
func (p *IdP) Issuer() string {
	return p.URL
}

// AddApp registers an app
func (p *IdP) AddApp(app App) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.apps[app.ClientID] = app
}

// Refreshes counts the refresh token grants the IdP answered successfully
func (p *IdP) Refreshes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshes
}

// TokenRequests returns every token request so far
func (p *IdP) TokenRequests() []TokenRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.tokenRequests)
}

// AccessToken signs an access token for an app's API, as if the IdP had issued it
func (p *IdP) AccessToken(clientID string, scopes []string) string {
	now := time.Now()
	var scp []string
	for _, s := range scopes {
		if api, name, ok := strings.Cut(strings.TrimPrefix(s, "api://"), "/"); ok && api == clientID {
			scp = append(scp, name)
		}
	}
	claims := map[string]any{
		"iss": p.Issuer(),
		"aud": clientID,
		"sub": p.Subject,
		"oid": p.Subject,
		"azp": clientID,
		"scp": strings.Join(scp, " "),
		"ver": "2.0",
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(p.AccessTokenTTL).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		p.t.Fatal(err)
	}
	signed, err := p.signer.Sign(payload)
	if err != nil {
		p.t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		p.t.Fatal(err)
	}
	return token
}

func (p *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.Issuer(),
		"authorization_endpoint":                p.URL + "/authorize",
		"token_endpoint":                        p.URL + "/token",
		"jwks_uri":                              p.URL + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	})
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	defer p.mu.Unlock()
	app, ok := p.apps[q.Get("client_id")]
	if !ok || !slices.Contains(app.RedirectURIs, q.Get("redirect_uri")) {
		http.Error(w, "unknown client or redirect URI", http.StatusBadRequest)
		return
	}
	fail := func(code string) {
		redirect(w, r, q.Get("redirect_uri"), url.Values{"error": {code}, "error_description": {"AADSTS00000: " + code + "\r\nTrace ID: 123"}, "state": {q.Get("state")}})
	}
	scopes := strings.Fields(q.Get("scope"))
	switch {
	case q.Get("response_type") != "code" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		fail("invalid_request")
	case q.Has("resource"):
		fail("invalid_target")
	case !p.ownScopes(app.ClientID, scopes):
		fail("invalid_scope")
	case p.DenyAuthorization:
		fail("access_denied")
	default:
		code := rand.Text()
		p.codes[code] = &grant{clientID: app.ClientID, redirectURI: q.Get("redirect_uri"), challenge: q.Get("code_challenge"), scopes: scopes}
		redirect(w, r, q.Get("redirect_uri"), url.Values{"code": {code}, "state": {q.Get("state")}})
	}
}

// ownScopes reports whether an app requests only scopes of its own API, plus the OpenID ones
func (p *IdP) ownScopes(clientID string, scopes []string) bool {
	for _, s := range scopes {
		if s == "offline_access" || s == "openid" || s == "profile" {
			continue
		}
		if !strings.HasPrefix(s, "api://"+clientID+"/") {
			return false
		}
	}
	return true
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	clientID, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if user, pass, ok := r.BasicAuth(); ok {
		clientID, _ = url.QueryUnescape(user)
		secret, _ = url.QueryUnescape(pass)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenRequests = append(p.tokenRequests, TokenRequest{Form: r.PostForm, ClientID: clientID, Secret: secret})
	app, ok := p.apps[clientID]
	if !ok || app.ClientSecret != secret {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Has("resource") {
		// Entra answers AADSTS9010010 when resource doesn't match the requested scopes
		oauthError(w, http.StatusBadRequest, "invalid_target")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		g, ok := p.codes[r.PostForm.Get("code")]
		switch {
		case !ok || g.clientID != clientID:
			// The code was issued to another app, or never
			oauthError(w, http.StatusBadRequest, "invalid_grant")
		case g.redirectURI != r.PostForm.Get("redirect_uri"):
			oauthError(w, http.StatusBadRequest, "invalid_grant")
		case s256(r.PostForm.Get("code_verifier")) != g.challenge:
			oauthError(w, http.StatusBadRequest, "invalid_grant")
		default:
			delete(p.codes, r.PostForm.Get("code"))
			p.issue(w, g)
		}
	case "refresh_token":
		g, ok := p.refreshTokens[r.PostForm.Get("refresh_token")]
		if !ok || g.clientID != clientID {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		delete(p.refreshTokens, r.PostForm.Get("refresh_token"))
		p.refreshes++
		p.issue(w, g)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// issue answers with an access token, an ID token and, with offline_access, a new refresh token
func (p *IdP) issue(w http.ResponseWriter, g *grant) {
	resp := map[string]any{
		"access_token": p.AccessToken(g.clientID, g.scopes),
		"token_type":   "Bearer",
		"expires_in":   int(p.AccessTokenTTL.Seconds()),
		"scope":        strings.Join(slices.DeleteFunc(slices.Clone(g.scopes), func(s string) bool { return s == "offline_access" }), " "),
		"id_token":     "not-relayed",
	}
	if slices.Contains(g.scopes, "offline_access") {
		rt := rand.Text()
		p.refreshTokens[rt] = g
		resp["refresh_token"] = rt
	}
	writeJSON(w, http.StatusOK, resp)
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func redirect(w http.ResponseWriter, r *http.Request, to string, params url.Values) {
	u, _ := url.Parse(to)
	q := u.Query()
	for k, v := range params {
		if v[0] != "" {
			q[k] = v
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": "AADSTS00000: " + code + "\r\nTrace ID: 123"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
