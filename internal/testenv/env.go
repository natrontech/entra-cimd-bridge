package testenv

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/natrontech/entra-cimd-bridge/internal/cimd"
	"github.com/natrontech/entra-cimd-bridge/internal/config"
	"github.com/natrontech/entra-cimd-bridge/internal/server"
)

// RedirectURI is where the test client receives codes, a loopback address the client's document registers without a port
const RedirectURI = "http://127.0.0.1:50000/callback"

// Options shape an environment
type Options struct {
	// Resources are the URIs of the MCP servers, each of which gets its own app at the IdP
	Resources []string
	// ConsentTTL is how long consent is remembered
	ConsentTTL time.Duration
}

// Env is a running bridge with a fake IdP and a host serving the test client's metadata document
type Env struct {
	t testing.TB
	// IdP is the fake identity provider
	IdP *IdP
	// Bridge serves the bridge over TLS
	Bridge *httptest.Server
	// Server is the bridge itself
	Server *server.Server
	// ClientID is the test client's metadata document URL
	ClientID string
	// Apps holds the app registration of each resource, by URI
	Apps map[string]App
	// HTTPClient trusts the test servers' certificate and keeps no cookies
	HTTPClient *http.Client
}

// New starts an environment, whose servers stop when the test ends
func New(t testing.TB, opts Options) *Env {
	t.Helper()
	if len(opts.Resources) == 0 {
		opts.Resources = []string{"https://mcp.example/mcp"}
	}
	e := &Env{t: t, IdP: NewIdP(t), Apps: map[string]App{}}
	e.HTTPClient = e.IdP.Client()

	// The bridge has to listen before its URL can go into its configuration
	var handler http.Handler
	handler = http.NotFoundHandler()
	e.Bridge = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	e.Bridge.StartTLS()
	t.Cleanup(e.Bridge.Close)

	clientHost := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  "https://" + r.Host + r.URL.Path,
			"client_name":                "Test Client",
			"redirect_uris":              []string{"http://127.0.0.1/callback"},
			"grant_types":                []string{"authorization_code", "refresh_token"},
			"response_types":             []string{"code"},
			"token_endpoint_auth_method": "none",
		})
	}))
	t.Cleanup(clientHost.Close)
	e.ClientID = clientHost.URL + "/client.json"

	// The configuration goes through the YAML loader, with the secrets from the environment like in production
	var resources strings.Builder
	for i, uri := range opts.Resources {
		app := App{ClientID: fmt.Sprintf("app-%c", 'a'+i), ClientSecret: rand.Text(), RedirectURIs: []string{e.Bridge.URL + "/callback"}}
		e.IdP.AddApp(app)
		e.Apps[uri] = app
		secretVar := fmt.Sprintf("TEST_SECRET_%d", i)
		t.Setenv(secretVar, app.ClientSecret)
		fmt.Fprintf(&resources, "  - uri: %s\n    name: Server %c\n    provider: test\n    client_id: %s\n    client_secret: ${%s}\n    scopes: [api://%s/access_as_user, offline_access]\n",
			uri, 'A'+i, app.ClientID, secretVar, app.ClientID)
	}
	t.Setenv("TEST_SIGNING_KEY", rand.Text()+rand.Text())
	yaml := fmt.Sprintf("issuer: %s\nsigning_keys: [\"${TEST_SIGNING_KEY}\"]\nproviders:\n  test:\n    issuer: %s\nclients:\n  cimd_hosts: [\"127.0.0.1\"]\nconsent_ttl: %s\nresources:\n%s",
		e.Bridge.URL, e.IdP.Issuer(), opts.ConsentTTL, resources.String())
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(e.Bridge.Certificate())
	e.Server, err = server.New(t.Context(), cfg, server.Options{
		UpstreamClient: e.IdP.Client(),
		CIMD:           cimd.Options{AllowPrivateAddresses: true, RootCAs: pool},
		Logger:         slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler = e.Server.Handler()
	return e
}

// AuthorizeURL builds an authorization request of the test client for resource, with a fresh PKCE pair
func (e *Env) AuthorizeURL(resource string) (authURL, verifier string) {
	verifier = rand.Text() + rand.Text()
	q := url.Values{
		"client_id":             {e.ClientID},
		"redirect_uri":          {RedirectURI},
		"response_type":         {"code"},
		"state":                 {"client-state"},
		"code_challenge":        {s256(verifier)},
		"code_challenge_method": {"S256"},
		"scope":                 {"anything"},
	}
	if resource != "" {
		q.Set("resource", resource)
	}
	return e.Bridge.URL + "/authorize?" + q.Encode(), verifier
}

// Code runs an authorization through a new browser and returns the code the client receives, with its verifier
func (e *Env) Code(resource string) (code, verifier string) {
	e.t.Helper()
	authURL, verifier := e.AuthorizeURL(resource)
	to, err := e.NewBrowser().Authorize(authURL)
	if err != nil {
		e.t.Fatal(err)
	}
	if to.Query().Get("code") == "" {
		e.t.Fatalf("no code in %s", to)
	}
	return to.Query().Get("code"), verifier
}

// Token posts a token request of the test client to the bridge and returns the status and the decoded body
func (e *Env) Token(form url.Values) (int, map[string]any) {
	e.t.Helper()
	if !form.Has("client_id") {
		form.Set("client_id", e.ClientID)
	}
	resp, err := e.HTTPClient.PostForm(e.Bridge.URL+"/token", form)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		e.t.Fatal(err)
	}
	return resp.StatusCode, body
}

// Browser follows redirects and keeps cookies like a browser, and answers consent pages
type Browser struct {
	env *Env
	// Client keeps the browser's cookies and leaves redirects to the browser
	Client *http.Client
	// Decision is the answer on consent pages, allow unless set
	Decision string
	// ConsentPages counts the consent pages the browser was shown
	ConsentPages int
}

// NewBrowser returns a browser without cookies
func (e *Env) NewBrowser() *Browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatal(err)
	}
	client := *e.HTTPClient
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Browser{env: e, Client: &client, Decision: "allow"}
}

// Authorize opens an authorization URL and returns where it finally sends the browser to the client
func (b *Browser) Authorize(authURL string) (*url.URL, error) {
	return b.Follow(authURL, func(u *url.URL) bool { return u.Scheme == "http" })
}

var requestField = regexp.MustCompile(`name="request" value="([^"]+)"`)

// Follow opens start and follows redirects until one leads to a URL stop accepts, which it returns without opening
func (b *Browser) Follow(start string, stop func(*url.URL) bool) (*url.URL, error) {
	next := start
	for range 10 {
		resp, err := b.Client.Get(next)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// A consent page is answered by posting its form, which redirects onwards
		if resp.StatusCode == http.StatusOK && requestField.Match(body) {
			b.ConsentPages++
			resp, err = b.postConsent(string(requestField.FindSubmatch(body)[1]))
			if err != nil {
				return nil, err
			}
			resp.Body.Close()
		}
		location, err := resp.Location()
		if err != nil {
			return nil, fmt.Errorf("%s answered %d without a redirect: %s", next, resp.StatusCode, body)
		}
		if stop(location) {
			return location, nil
		}
		next = location.String()
	}
	return nil, fmt.Errorf("too many redirects from %s", start)
}

func (b *Browser) postConsent(request string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, b.env.Bridge.URL+"/consent", strings.NewReader(url.Values{"request": {request}, "decision": {b.Decision}}.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.env.Bridge.URL)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := b.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("consent answered %d: %s", resp.StatusCode, body)
	}
	return resp, nil
}
