// Package e2e runs the official MCP Go SDK client through the bridge against MCP servers that validate the IdP's tokens themselves
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/natrontech/entra-cimd-bridge/internal/testenv"
	"github.com/natrontech/entra-cimd-bridge/resource"
)

// mcpServer is an MCP server that sends clients to the bridge and accepts only IdP tokens for its own API
type mcpServer struct {
	*httptest.Server
	handler http.Handler

	mu sync.Mutex
	// audiences are the audiences of the tokens it accepted
	audiences []string
}

// startMCPServers starts n MCP servers, which can only be configured once the bridge they point to runs
func startMCPServers(t *testing.T, n int) ([]*mcpServer, []string) {
	var servers []*mcpServer
	var uris []string
	for range n {
		s := &mcpServer{handler: http.NotFoundHandler()}
		s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }))
		t.Cleanup(s.Close)
		servers = append(servers, s)
		uris = append(uris, s.URL+"/mcp")
	}
	return servers, uris
}

// serve sets the server up like an MCP server behind the bridge would be: PRM and challenges from the resource package, and its own token validation
func (s *mcpServer) serve(t *testing.T, env *testenv.Env) {
	uri := s.URL + "/mcp"
	app := env.Apps[uri]
	meta := &resource.Metadata{
		Resource:             uri,
		AuthorizationServers: []string{env.Bridge.URL},
		ScopesSupported:      []string{"api://" + app.ClientID + "/access_as_user"},
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(t.Context(), env.HTTPClient), env.IdP.Issuer())
	require.NoError(t, err)
	verifier := provider.Verifier(&oidc.Config{ClientID: app.ClientID})

	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "ping", Description: "Answers pong"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "pong"}}}, nil, nil
	})
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)

	mux := http.NewServeMux()
	mux.Handle("GET "+meta.Path(), meta)
	mux.Handle("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := resource.BearerToken(r)
		if !ok {
			meta.Challenge(w)
			return
		}
		verified, err := verifier.Verify(r.Context(), token)
		if err != nil {
			meta.InvalidToken(w, "The access token is invalid or expired.")
			return
		}
		var claims struct {
			Scope string `json:"scp"`
		}
		if verified.Claims(&claims) != nil || !slices.Contains(strings.Fields(claims.Scope), "access_as_user") {
			meta.InsufficientScope(w, meta.ScopesSupported, "")
			return
		}
		s.mu.Lock()
		s.audiences = append(s.audiences, verified.Audience...)
		s.mu.Unlock()
		mcpHandler.ServeHTTP(w, r)
	}))
	s.handler = mux
}

func (s *mcpServer) acceptedAudiences() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Compact(slices.Clone(s.audiences))
}

// setup starts n MCP servers and a bridge for them
func setup(t *testing.T, n int) (*testenv.Env, []*mcpServer) {
	servers, uris := startMCPServers(t, n)
	env := testenv.New(t, testenv.Options{Resources: uris, ConsentTTL: time.Hour})
	for _, s := range servers {
		s.serve(t, env)
	}
	return env, servers
}

// connect connects an SDK client to an MCP server, signing in through browser whenever the server asks
func connect(t *testing.T, env *testenv.Env, browser *testenv.Browser, server *mcpServer, newTokenSource func(context.Context, *oauth2.Config, *oauth2.Token) (oauth2.TokenSource, error)) *mcp.ClientSession {
	handler, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		ClientIDMetadataDocumentConfig: &auth.ClientIDMetadataDocumentConfig{URL: env.ClientID},
		RedirectURL:                    testenv.RedirectURI,
		RequestRefreshToken:            true,
		Client:                         env.HTTPClient,
		NewTokenSource:                 newTokenSource,
		AuthorizationCodeFetcher: func(_ context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			to, err := browser.Authorize(args.URL)
			if err != nil {
				return nil, err
			}
			q := to.Query()
			if q.Has("error") {
				return nil, fmt.Errorf("authorization failed: %s: %s", q.Get("error"), q.Get("error_description"))
			}
			return &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}, nil
		},
	})
	require.NoError(t, err)

	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1.0.0"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:     server.URL + "/mcp",
		HTTPClient:   env.HTTPClient,
		OAuthHandler: handler,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func callPing(t *testing.T, session *mcp.ClientSession) {
	t.Helper()
	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "ping"})
	require.NoError(t, err)
	require.False(t, res.IsError)
	assert.Equal(t, "pong", res.Content[0].(*mcp.TextContent).Text)
}

func TestToolCallsWithTheIdPsTokens(t *testing.T) {
	env, servers := setup(t, 2)

	// Access tokens live shorter than oauth2's ten second margin, so every request refreshes first
	env.IdP.AccessTokenTTL = 5 * time.Second
	browser := env.NewBrowser()
	for i, server := range servers {
		session := connect(t, env, browser, server, refreshWithResource(server.URL+"/mcp"))
		callPing(t, session)
		callPing(t, session)
		assert.Equal(t, []string{fmt.Sprintf("app-%c", 'a'+i)}, server.acceptedAudiences(), "the server accepted only tokens for its own API")
	}
	assert.Equal(t, 2, browser.ConsentPages, "each MCP server needs its own consent")
	assert.Greater(t, env.IdP.Refreshes(), 4, "the clients refreshed through the bridge")
}

// The SDK's default token source refreshes without resource, which a bridge for a single MCP server doesn't need
func TestSDKRefreshWithoutResource(t *testing.T) {
	env, servers := setup(t, 1)
	env.IdP.AccessTokenTTL = 5 * time.Second
	session := connect(t, env, env.NewBrowser(), servers[0], nil)
	callPing(t, session)
	callPing(t, session)
	assert.Greater(t, env.IdP.Refreshes(), 1)
}

func TestTokenForOneServerIsRejectedByAnother(t *testing.T) {
	env, servers := setup(t, 2)
	code, verifier := env.Code(servers[0].URL + "/mcp")
	status, body := env.Token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {testenv.RedirectURI}, "resource": {servers[0].URL + "/mcp"}})
	require.Equal(t, http.StatusOK, status, body)

	req, err := http.NewRequest(http.MethodPost, servers[1].URL+"/mcp", strings.NewReader("{}"))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+body["access_token"].(string))
	resp, err := env.HTTPClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`)
}

func TestCodeIsBoundToItsServer(t *testing.T) {
	env, servers := setup(t, 2)
	serverA, serverB := servers[0].URL+"/mcp", servers[1].URL+"/mcp"
	code, verifier := env.Code(serverA)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {testenv.RedirectURI}}

	// Redeemed for B, the code goes to the IdP with B's app, which it wasn't issued to
	form.Set("resource", serverB)
	status, body := env.Token(form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])

	form.Set("resource", serverA)
	status, body = env.Token(form)
	assert.Equal(t, http.StatusOK, status, body)
}

func TestRefreshTokenIsBoundToItsServer(t *testing.T) {
	env, servers := setup(t, 2)
	serverA, serverB := servers[0].URL+"/mcp", servers[1].URL+"/mcp"
	code, verifier := env.Code(serverA)
	status, tokens := env.Token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {testenv.RedirectURI}, "resource": {serverA}})
	require.Equal(t, http.StatusOK, status, tokens)
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}}

	refresh.Set("resource", serverB)
	status, body := env.Token(refresh)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])

	refresh.Set("resource", serverA)
	status, body = env.Token(refresh)
	assert.Equal(t, http.StatusOK, status, body)
}

func TestWrongCodeVerifierIsRejectedByTheIdP(t *testing.T) {
	env, servers := setup(t, 1)
	code, _ := env.Code(servers[0].URL + "/mcp")
	otherVerifier := strings.Repeat("x", 64)
	status, body := env.Token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {otherVerifier}, "redirect_uri": {testenv.RedirectURI}, "resource": {servers[0].URL + "/mcp"}})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestStateWithAnotherRedirectIsRejected(t *testing.T) {
	env, servers := setup(t, 1)
	authURL, _ := env.AuthorizeURL(servers[0].URL + "/mcp")
	browser := env.NewBrowser()
	callback, err := browser.Follow(authURL, func(u *url.URL) bool { return u.Path == "/callback" && u.Host == env.Bridge.Listener.Addr().String() })
	require.NoError(t, err)

	// An attacker rewrites the redirect URI in the state the IdP carries and keeps the signature
	q := callback.Query()
	payload, signature, ok := strings.Cut(q.Get("state"), ".")
	require.True(t, ok)
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	require.NoError(t, err)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(decoded, &envelope))
	envelope["v"].(map[string]any)["r"] = "https://evil.example/callback"
	forged, err := json.Marshal(envelope)
	require.NoError(t, err)
	q.Set("state", base64.RawURLEncoding.EncodeToString(forged)+"."+signature)
	callback.RawQuery = q.Encode()

	resp, err := browser.Client.Get(callback.String())
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "the code goes nowhere")
}

// refreshWithResource makes a token source like oauth2's, except that refreshes send resource as the MCP spec asks
// oauth2's own refresher can't add parameters, which is why the SDK's default refreshes without resource
func refreshWithResource(resource string) func(context.Context, *oauth2.Config, *oauth2.Token) (oauth2.TokenSource, error) {
	return func(ctx context.Context, cfg *oauth2.Config, tok *oauth2.Token) (oauth2.TokenSource, error) {
		client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
		return oauth2.ReuseTokenSource(tok, &resourceRefresher{client: client, cfg: cfg, resource: resource, refreshToken: tok.RefreshToken}), nil
	}
}

type resourceRefresher struct {
	client       *http.Client
	cfg          *oauth2.Config
	resource     string
	refreshToken string
}

func (r *resourceRefresher) Token() (*oauth2.Token, error) {
	resp, err := r.client.PostForm(r.cfg.Endpoint.TokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {r.refreshToken},
		"client_id":     {r.cfg.ClientID},
		"resource":      {r.resource},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed: %s", body.Error)
	}
	r.refreshToken = body.RefreshToken
	return &oauth2.Token{
		AccessToken:  body.AccessToken,
		TokenType:    body.TokenType,
		RefreshToken: body.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(body.ExpiresIn) * time.Second),
	}, nil
}
