package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/natrontech/entra-cimd-bridge/internal/testenv"
)

const (
	resourceA = "https://a.example/mcp"
	resourceB = "https://b.example/mcp"
)

func TestMetadata(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA, resourceB}})
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		resp, err := env.HTTPClient.Get(env.Bridge.URL + path)
		require.NoError(t, err)
		var meta map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
		resp.Body.Close()

		assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, map[string]any{
			"issuer":                                         env.Bridge.URL,
			"authorization_endpoint":                         env.Bridge.URL + "/authorize",
			"token_endpoint":                                 env.Bridge.URL + "/token",
			"scopes_supported":                               []any{"api://app-a/access_as_user", "api://app-b/access_as_user", "offline_access"},
			"response_types_supported":                       []any{"code"},
			"response_modes_supported":                       []any{"query"},
			"grant_types_supported":                          []any{"authorization_code", "refresh_token"},
			"token_endpoint_auth_methods_supported":          []any{"none"},
			"code_challenge_methods_supported":               []any{"S256"},
			"client_id_metadata_document_supported":          true,
			"authorization_response_iss_parameter_supported": true,
		}, meta, path)
	}
}

func TestAuthorizeRedirectsToTheResourcesApp(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA, resourceB}})
	authURL, verifier := env.AuthorizeURL(resourceB)

	// The browser stops where the bridge sends it to the IdP
	idp, err := env.NewBrowser().Follow(authURL, func(u *url.URL) bool { return u.Path == "/authorize" && u.Host == env.IdP.Listener.Addr().String() })
	require.NoError(t, err)
	q := idp.Query()
	assert.Equal(t, "app-b", q.Get("client_id"))
	assert.Equal(t, env.Bridge.URL+"/callback", q.Get("redirect_uri"))
	assert.Equal(t, "api://app-b/access_as_user offline_access", q.Get("scope"), "the client's scope is replaced by the resource's")
	assert.Equal(t, testenvChallenge(t, authURL), q.Get("code_challenge"), "the client's own challenge goes to the IdP")
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.False(t, q.Has("resource"))
	assert.NotEqual(t, "client-state", q.Get("state"))
	assert.NotEmpty(t, verifier)
}

func testenvChallenge(t *testing.T, authURL string) string {
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	return u.Query().Get("code_challenge")
}

func TestCallbackReturnsTheIdPsCodeToTheClient(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	authURL, _ := env.AuthorizeURL(resourceA)
	to, err := env.NewBrowser().Authorize(authURL)
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:50000", to.Host)
	assert.Equal(t, "/callback", to.Path)
	assert.Equal(t, "client-state", to.Query().Get("state"))
	assert.Equal(t, env.Bridge.URL, to.Query().Get("iss"))
	assert.NotEmpty(t, to.Query().Get("code"))
}

func TestTokenRequestIsRewritten(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA, resourceB}})
	code, verifier := env.Code(resourceB)

	status, body := env.Token(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {testenv.RedirectURI},
		"resource":      {resourceB},
	})
	require.Equal(t, http.StatusOK, status, body)
	assert.NotEmpty(t, body["access_token"])
	assert.NotEmpty(t, body["refresh_token"])
	assert.Equal(t, "Bearer", body["token_type"])
	assert.Equal(t, "api://app-b/access_as_user", body["scope"])
	assert.NotContains(t, body, "id_token")

	// The IdP saw the bridge's callback, the resource's app and scopes, and no resource
	reqs := env.IdP.TokenRequests()
	require.Len(t, reqs, 1)
	got := reqs[0]
	assert.Equal(t, "app-b", got.ClientID)
	assert.Equal(t, env.Apps[resourceB].ClientSecret, got.Secret)
	assert.Equal(t, env.Bridge.URL+"/callback", got.Form.Get("redirect_uri"))
	assert.Equal(t, "api://app-b/access_as_user offline_access", got.Form.Get("scope"))
	assert.Equal(t, verifier, got.Form.Get("code_verifier"))
	assert.False(t, got.Form.Has("resource"))

	// A refresh is rewritten the same way, and the IdP's rotated refresh token comes back
	status, refreshed := env.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}, "resource": {resourceB}})
	require.Equal(t, http.StatusOK, status, refreshed)
	assert.NotEqual(t, body["refresh_token"], refreshed["refresh_token"])
	got = env.IdP.TokenRequests()[1]
	assert.Equal(t, "app-b", got.ClientID)
	assert.Equal(t, "api://app-b/access_as_user offline_access", got.Form.Get("scope"))
	assert.False(t, got.Form.Has("resource"))
	assert.False(t, got.Form.Has("redirect_uri"))
}

func TestTokenAcceptsTheClientIDInBasicAuth(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	code, verifier := env.Code(resourceA)

	// golang.org/x/oauth2 tries this first for clients without a secret
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {testenv.RedirectURI}, "resource": {resourceA}}
	req, err := http.NewRequest(http.MethodPost, env.Bridge.URL+"/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(env.ClientID), "")
	resp, err := env.HTTPClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTokenRejectsClientSecrets(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	status, body := env.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_secret": {"s"}})
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

func TestUnknownResourceIsInvalidTarget(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA, resourceB}})

	authURL, _ := env.AuthorizeURL("https://unknown.example/mcp")
	to, err := env.NewBrowser().Authorize(authURL)
	require.NoError(t, err)
	assert.Equal(t, "invalid_target", to.Query().Get("error"))
	assert.Equal(t, "client-state", to.Query().Get("state"))
	assert.Equal(t, env.Bridge.URL, to.Query().Get("iss"))

	status, body := env.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "resource": {"https://unknown.example/mcp"}})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_target", body["error"])
	assert.Empty(t, env.IdP.TokenRequests(), "nothing reaches the IdP")
}

func TestResourceIsRequiredWithSeveralServers(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA, resourceB}})
	authURL, _ := env.AuthorizeURL("")
	to, err := env.NewBrowser().Authorize(authURL)
	require.NoError(t, err)
	assert.Equal(t, "invalid_target", to.Query().Get("error"))

	status, body := env.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_target", body["error"])
}

func TestASingleServerNeedsNoResource(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	code, verifier := env.Code("")
	status, body := env.Token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {testenv.RedirectURI}})
	require.Equal(t, http.StatusOK, status, body)
	status, body = env.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}})
	require.Equal(t, http.StatusOK, status, body)
}

func TestResourceMatchingIsLenientAboutCaseAndTrailingSlash(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA, resourceB}})
	code, verifier := env.Code("HTTPS://B.example/mcp/")
	status, body := env.Token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {testenv.RedirectURI}, "resource": {resourceB}})
	require.Equal(t, http.StatusOK, status, body)
}

func TestInvalidClientsGetAnErrorPageInsteadOfARedirect(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	authURL, _ := env.AuthorizeURL(resourceA)
	for name, change := range map[string]func(url.Values){
		"unlisted redirect":  func(q url.Values) { q.Set("redirect_uri", "https://evil.example/callback") },
		"loopback elsewhere": func(q url.Values) { q.Set("redirect_uri", "http://127.0.0.1:50000/other") },
		"no client":          func(q url.Values) { q.Del("client_id") },
		"client off-policy":  func(q url.Values) { q.Set("client_id", "https://claude.ai/oauth/claude-code-client-metadata") },
		"missing document":   func(q url.Values) { q.Set("client_id", env.IdP.URL+"/client.json") },
	} {
		u, err := url.Parse(authURL)
		require.NoError(t, err)
		q := u.Query()
		change(q)
		u.RawQuery = q.Encode()

		resp, err := env.NewBrowser().Client.Get(u.String())
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, name)
		assert.Empty(t, resp.Header.Get("Location"), name)
		assert.Contains(t, string(body), "can&#39;t sign in here", name)
	}
}

func TestInvalidRequestsAreReturnedToTheClient(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	authURL, _ := env.AuthorizeURL(resourceA)
	for name, tc := range map[string]struct {
		change func(url.Values)
		want   string
	}{
		"plain PKCE":       {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		"no PKCE":          {func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") }, "invalid_request"},
		"short challenge":  {func(q url.Values) { q.Set("code_challenge", "abc") }, "invalid_request"},
		"token response":   {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		"two resources":    {func(q url.Values) { q["resource"] = []string{resourceA, resourceB} }, "invalid_target"},
		"repeated state":   {func(q url.Values) { q["state"] = []string{"a", "b"} }, "invalid_request"},
		"state too long":   {func(q url.Values) { q.Set("state", strings.Repeat("s", 2000)) }, "invalid_request"},
		"unknown resource": {func(q url.Values) { q.Set("resource", resourceB) }, "invalid_target"},
	} {
		u, err := url.Parse(authURL)
		require.NoError(t, err)
		q := u.Query()
		tc.change(q)
		u.RawQuery = q.Encode()

		to, err := env.NewBrowser().Authorize(u.String())
		require.NoError(t, err, name)
		assert.Equal(t, tc.want, to.Query().Get("error"), name)
		assert.Equal(t, env.Bridge.URL, to.Query().Get("iss"), name)
	}
}

func TestConsentIsRememberedPerClientAndServer(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA, resourceB}, ConsentTTL: time.Hour})
	browser := env.NewBrowser()
	for _, resource := range []string{resourceA, resourceA, resourceB} {
		authURL, _ := env.AuthorizeURL(resource)
		to, err := browser.Authorize(authURL)
		require.NoError(t, err)
		require.NotEmpty(t, to.Query().Get("code"))
	}
	assert.Equal(t, 2, browser.ConsentPages, "the second request for A skips the page, B gets its own")

	// Another browser has to consent again
	other := env.NewBrowser()
	authURL, _ := env.AuthorizeURL(resourceA)
	_, err := other.Authorize(authURL)
	require.NoError(t, err)
	assert.Equal(t, 1, other.ConsentPages)
}

func TestConsentIsAskedEveryTimeWithoutTTL(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	browser := env.NewBrowser()
	for range 2 {
		authURL, _ := env.AuthorizeURL(resourceA)
		_, err := browser.Authorize(authURL)
		require.NoError(t, err)
	}
	assert.Equal(t, 2, browser.ConsentPages)
}

func TestDeniedConsentReturnsAccessDenied(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}, ConsentTTL: time.Hour})
	browser := env.NewBrowser()
	browser.Decision = "deny"
	authURL, _ := env.AuthorizeURL(resourceA)
	to, err := browser.Authorize(authURL)
	require.NoError(t, err)
	assert.Equal(t, "access_denied", to.Query().Get("error"))
	assert.Equal(t, "client-state", to.Query().Get("state"))

	// A denial isn't remembered
	browser.Decision = "allow"
	_, err = browser.Authorize(authURL)
	require.NoError(t, err)
	assert.Equal(t, 2, browser.ConsentPages)
}

func TestConsentPage(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	authURL, _ := env.AuthorizeURL(resourceA)
	resp, err := env.NewBrowser().Client.Get(authURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	page := string(body)
	clientHost := strings.TrimPrefix(strings.TrimSuffix(env.ClientID, "/client.json"), "https://")
	assert.Contains(t, page, "Test Client")
	assert.Contains(t, page, clientHost, "the host of the client's metadata document")
	assert.Contains(t, page, "127.0.0.1:50000", "the redirect host")
	assert.Contains(t, page, "Server A")
	assert.Contains(t, page, resourceA)
	assert.Contains(t, page, "any program here could pretend to be Test Client", "loopback redirects get a warning")
	assert.NotContains(t, page, "<script")

	csp := resp.Header.Get("Content-Security-Policy")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	assert.Contains(t, csp, "default-src 'none'")
	assert.Contains(t, csp, "form-action 'self' "+env.IdP.URL+" http://127.0.0.1:50000")
	assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	// The browser cookie is Lax, so a client's cross-site navigation reuses it instead of replacing it and breaking consent pages open in other tabs
	var csrf *http.Cookie
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "bridge-csrf") {
			csrf = c
		}
	}
	require.NotNil(t, csrf)
	assert.Equal(t, http.SameSiteLaxMode, csrf.SameSite)
	assert.True(t, csrf.HttpOnly)
}

func TestConsentNeedsTheBrowserItWasShownIn(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	authURL, _ := env.AuthorizeURL(resourceA)

	// An attacker fetches a consent form for themselves
	resp, err := env.NewBrowser().Client.Get(authURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	request := strings.Split(strings.Split(string(body), `name="request" value="`)[1], `"`)[0]

	// and has a victim's browser post it, from a page of the same site so cross-origin protection doesn't catch it
	victim := env.NewBrowser()
	consent := func(headers map[string]string) int {
		req, err := http.NewRequest(http.MethodPost, env.Bridge.URL+"/consent", strings.NewReader(url.Values{"request": {request}, "decision": {"allow"}}.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := victim.Client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}
	assert.Equal(t, http.StatusForbidden, consent(map[string]string{"Sec-Fetch-Site": "same-origin"}))

	// A post from another site is refused before the form is even read
	assert.Equal(t, http.StatusForbidden, consent(map[string]string{"Sec-Fetch-Site": "cross-site"}))
	assert.Equal(t, http.StatusForbidden, consent(map[string]string{"Origin": "https://evil.example"}))
}

func TestStateOnlyCompletesInTheBrowserThatStartedIt(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}, ConsentTTL: time.Hour})
	attacker, victim := env.NewBrowser(), env.NewBrowser()
	atIdP := func(u *url.URL) bool { return u.Path == "/authorize" && u.Host == env.IdP.Listener.Addr().String() }
	atCallback := func(u *url.URL) bool { return u.Path == "/callback" && u.Host == env.Bridge.Listener.Addr().String() }

	// The attacker consents for themselves, the first time on the consent page and the second time remembered
	for range 2 {
		authURL, _ := env.AuthorizeURL(resourceA)
		idp, err := attacker.Follow(authURL, atIdP)
		require.NoError(t, err)

		// and has the victim's browser complete the IdP URL with its signed state
		callback, err := victim.Follow(idp.String(), atCallback)
		require.NoError(t, err)
		resp, err := victim.Client.Get(callback.String())
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Location"), "the victim's code goes nowhere")
	}
	assert.Equal(t, 1, attacker.ConsentPages)
	assert.Zero(t, victim.ConsentPages)
}

func TestTamperedStateIsRejected(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	authURL, _ := env.AuthorizeURL(resourceA)
	browser := env.NewBrowser()
	callback, err := browser.Follow(authURL, func(u *url.URL) bool { return u.Path == "/callback" && u.Host == env.Bridge.Listener.Addr().String() })
	require.NoError(t, err)

	q := callback.Query()
	q.Set("state", q.Get("state")+"x")
	callback.RawQuery = q.Encode()
	resp, err := browser.Client.Get(callback.String())
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "the code goes nowhere")
}

func TestIdPErrorsReachTheClient(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	env.IdP.DenyAuthorization = true
	authURL, _ := env.AuthorizeURL(resourceA)
	to, err := env.NewBrowser().Authorize(authURL)
	require.NoError(t, err)
	assert.Equal(t, "access_denied", to.Query().Get("error"))
	assert.Equal(t, "AADSTS00000: access_denied", to.Query().Get("error_description"), "only the first line of Entra's description")
	assert.Equal(t, "client-state", to.Query().Get("state"))
	assert.Equal(t, env.Bridge.URL, to.Query().Get("iss"))
}

func TestRedirectURIAtTokenMustBeTheClients(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	code, verifier := env.Code(resourceA)
	status, body := env.Token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"https://evil.example/cb"}, "resource": {resourceA}})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Empty(t, env.IdP.TokenRequests())
}

func TestWrongCodeVerifierIsRejectedByTheIdP(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	code, _ := env.Code(resourceA)
	status, body := env.Token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {strings.Repeat("v", 43)}, "redirect_uri": {testenv.RedirectURI}, "resource": {resourceA}})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	require.Len(t, env.IdP.TokenRequests(), 1, "the verifier is checked by the IdP, not the bridge")
}

func TestBrokenAppCredentialsAreAServerError(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	code, verifier := env.Code(resourceA)

	// The secret in Entra expired or was rotated without updating the bridge
	app := env.Apps[resourceA]
	app.ClientSecret = "rotated"
	env.IdP.AddApp(app)

	status, body := env.Token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {testenv.RedirectURI}, "resource": {resourceA}})
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.Equal(t, "server_error", body["error"])
}

func TestMetrics(t *testing.T) {
	env := testenv.New(t, testenv.Options{Resources: []string{resourceA}})
	env.Code(resourceA)

	rec := httptest.NewRecorder()
	env.Server.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	out := rec.Body.String()
	assert.Contains(t, out, `bridge_authorize_requests_total{outcome="consent"} 1`)
	assert.Contains(t, out, `bridge_consent_decisions_total{decision="allow"} 1`)
	assert.Contains(t, out, `bridge_callbacks_total{outcome="code"} 1`)
	assert.Contains(t, out, `bridge_client_lookups_total{outcome="fetched"}`)
	assert.Contains(t, out, "# TYPE bridge_token_requests_total counter")
}
