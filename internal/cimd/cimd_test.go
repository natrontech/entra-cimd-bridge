package cimd

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClientID(t *testing.T) {
	for id, ok := range map[string]bool{
		"https://claude.ai/oauth/claude-code-client-metadata": true,
		"https://vscode.dev/oauth/client-metadata.json":       true,
		"https://example.com:8443/client.json?v=1":            true,
		"":                                    false,
		"http://example.com/client.json":      false,
		"https://example.com":                 false,
		"https://example.com/":                false,
		"https://user:pw@example.com/c.json":  false,
		"https://example.com/c.json#frag":     false,
		"https://example.com/a/../c.json":     false,
		"https://example.com/a/%2e%2e/c.json": false,
		"https://example.com/./c.json":        false,
		"client-123":                          false,
		"https:/example.com/client.json":      false,
	} {
		_, err := ParseClientID(id)
		assert.Equal(t, ok, err == nil, id)
	}
}

func TestDocumentValidation(t *testing.T) {
	const id = "https://app.example/client.json"
	valid := map[string]any{
		"client_id":                  id,
		"client_name":                "App",
		"redirect_uris":              []string{"http://127.0.0.1/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	_, err := parseDocument(id, mustJSON(t, valid))
	require.NoError(t, err)

	privateKey := map[string]any{}
	for k, v := range valid {
		privateKey[k] = v
	}
	privateKey["token_endpoint_auth_method"] = "private_key_jwt"
	privateKey["token_endpoint_auth_methods_supported"] = []string{"none", "private_key_jwt"}
	privateKey["token_endpoint_auth_signing_alg"] = "RS256"
	privateKey["jwks_uri"] = "https://app.example/jwks.json"
	_, err = parseDocument(id, mustJSON(t, privateKey))
	require.NoError(t, err, "ChatGPT-style private_key_jwt client")

	for name, change := range map[string]func(map[string]any){
		"mismatched client_id":    func(d map[string]any) { d["client_id"] = "https://evil.example/client.json" },
		"client_id with slash":    func(d map[string]any) { d["client_id"] = id + "/" },
		"no client_name":          func(d map[string]any) { delete(d, "client_name") },
		"blank client_name":       func(d map[string]any) { d["client_name"] = "  " },
		"no redirect_uris":        func(d map[string]any) { delete(d, "redirect_uris") },
		"client secret":           func(d map[string]any) { d["client_secret"] = "s3cret" },
		"secret auth method":      func(d map[string]any) { d["token_endpoint_auth_method"] = "client_secret_post" },
		"private_key_jwt no jwks": func(d map[string]any) { d["token_endpoint_auth_method"] = "private_key_jwt" },
		"private_key_jwt wrong jwks": func(d map[string]any) {
			d["token_endpoint_auth_method"] = "private_key_jwt"
			d["jwks_uri"] = "https://evil.example/jwks.json"
		},
		"http jwks_uri": func(d map[string]any) {
			d["token_endpoint_auth_method"] = "private_key_jwt"
			d["jwks_uri"] = "http://app.example/jwks.json"
		},
		"private_key_jwt wrong alg": func(d map[string]any) {
			d["token_endpoint_auth_method"] = "private_key_jwt"
			d["jwks_uri"] = "https://app.example/jwks.json"
			d["token_endpoint_auth_signing_alg"] = "ES256"
		},
		"unlisted auth method": func(d map[string]any) {
			d["token_endpoint_auth_method"] = "private_key_jwt"
			d["token_endpoint_auth_methods_supported"] = []string{"none"}
			d["jwks_uri"] = "https://app.example/jwks.json"
		},
		"no authorization_code": func(d map[string]any) { d["grant_types"] = []string{"client_credentials"} },
		"no code response":      func(d map[string]any) { d["response_types"] = []string{"token"} },
	} {
		doc := map[string]any{}
		for k, v := range valid {
			doc[k] = v
		}
		change(doc)
		_, err := parseDocument(id, mustJSON(t, doc))
		assert.Error(t, err, name)
	}

	_, err = parseDocument(id, []byte("<html>"))
	assert.Error(t, err)
	_, err = parseDocument(id, []byte("[]"))
	assert.Error(t, err)
}

func TestRedirectMatching(t *testing.T) {
	doc := &Document{RedirectURIs: []string{
		"http://localhost/callback",
		"http://127.0.0.1:33418/",
		"https://app.example/oauth/callback",
	}}
	for uri, ok := range map[string]bool{
		"https://app.example/oauth/callback":     true,
		"http://localhost/callback":              true,
		"http://localhost:51234/callback":        true,
		"http://127.0.0.1:33418/":                true,
		"http://127.0.0.1:40000/":                true,
		"https://app.example/oauth/callback/":    false,
		"https://app.example/oauth/callback?x":   false,
		"https://app.example:444/oauth/callback": false,
		"http://localhost:51234/other":           false,
		"http://127.0.0.1:51234/callback":        false,
		"http://localhost:51234/callback?x=1":    false,
		"https://localhost:51234/callback":       false,
		"http://evil.example/callback":           false,
	} {
		assert.Equal(t, ok, doc.AllowsRedirect(uri), uri)
	}
}

func TestRedirectPolicy(t *testing.T) {
	for uri, ok := range map[string]bool{
		"https://claude.ai/api/mcp/auth_callback": true,
		"http://localhost:1234/callback":          true,
		"http://127.0.0.1/callback":               true,
		"http://[::1]:8080/callback":              true,
		"http://example.com/callback":             false,
		"http://127.0.0.2/callback":               false,
		"cursor://anysphere/oauth/callback":       false,
		"https://example.com/cb#frag":             false,
		"https://user@example.com/cb":             false,
		"/callback":                               false,
		"":                                        false,
	} {
		assert.Equal(t, ok, CheckRedirectURI(uri) == nil, uri)
	}
}

func TestPolicy(t *testing.T) {
	p, err := NewPolicy([]string{"claude.ai", "*.example.com", "VSCode.dev"})
	require.NoError(t, err)
	assert.True(t, p.Allows("claude.ai"))
	assert.True(t, p.Allows("vscode.dev"))
	assert.True(t, p.Allows("a.example.com"))
	assert.True(t, p.Allows("a.b.example.com"))
	assert.False(t, p.Allows("example.com"))
	assert.False(t, p.Allows("evilexample.com"))
	assert.False(t, p.Allows("claude.ai.evil.example"))

	// Unicode lowercasing turns U+0130 into i, while the connection would go to the punycode of the original, a different domain
	github, err := NewPolicy([]string{"github.com"})
	require.NoError(t, err)
	assert.False(t, github.Allows("g\u0130thub.com"))

	any, err := NewPolicy([]string{"*"})
	require.NoError(t, err)
	assert.True(t, any.Allows("anything.example"))

	for _, bad := range [][]string{nil, {"https://claude.ai"}, {"*.*.example.com"}, {"*."}, {"claude.ai/path"}, {"bücher.example"}} {
		_, err := NewPolicy(bad)
		assert.Error(t, err, bad)
	}
}

func TestBlockedAddresses(t *testing.T) {
	for addr, want := range map[string]bool{
		"169.254.169.254":    true,
		"100.100.100.200":    true,
		"10.0.0.1":           true,
		"172.16.0.1":         true,
		"192.168.1.1":        true,
		"127.0.0.1":          true,
		"::1":                true,
		"fd00::1":            true,
		"::ffff:192.168.1.1": true,
		"64:ff9b::a9fe:a9fe": true,
		"fd00:ec2::254":      true,
		"0.0.0.0":            true,
		"1.1.1.1":            false,
		"64:ff9b::101:101":   false,
		"2606:4700::1111":    false,
	} {
		assert.Equal(t, want, blocked(netip.MustParseAddr(addr)), addr)
	}

	// The dialer only passes resolved addresses, so a name means something went wrong and is refused
	control := dialControl(refusePrivate)
	assert.NoError(t, control("tcp", "1.1.1.1:443", nil))
	assert.Error(t, control("tcp", "10.0.0.1:443", nil))
	assert.Error(t, control("tcp", "metadata.internal:80", nil))
}

// documentServer serves client metadata documents over TLS, answering each path with what serve returns
type documentServer struct {
	*httptest.Server
	fetches atomic.Int32
}

func newDocumentServer(t *testing.T, serve func(w http.ResponseWriter, r *http.Request, id string)) *documentServer {
	t.Helper()
	ds := &documentServer{}
	ds.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ds.fetches.Add(1)
		serve(w, r, ds.URL+r.URL.Path)
	}))
	t.Cleanup(ds.Close)
	return ds
}

func (ds *documentServer) fetcher(t *testing.T, opts Options) *Fetcher {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ds.Certificate())
	opts.RootCAs = pool
	opts.AllowPrivateAddresses = true
	policy, err := NewPolicy([]string{"127.0.0.1"})
	require.NoError(t, err)
	return NewFetcher(policy, opts)
}

func serveDocument(cacheControl string) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, _ *http.Request, id string) {
		if cacheControl != "" {
			w.Header().Set("Cache-Control", cacheControl)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": id, "client_name": "Test", "redirect_uris": []string{"http://127.0.0.1/cb"}})
	}
}

func TestFetchValidatesAndCaches(t *testing.T) {
	ds := newDocumentServer(t, serveDocument("public, max-age=60"))
	f := ds.fetcher(t, Options{})
	now := time.Now()
	f.now = func() time.Time { return now }

	doc, err := f.Fetch(t.Context(), ds.URL+"/client.json")
	require.NoError(t, err)
	assert.Equal(t, "Test", doc.ClientName)
	_, err = f.Fetch(t.Context(), ds.URL+"/client.json")
	require.NoError(t, err)
	assert.EqualValues(t, 1, ds.fetches.Load(), "the second lookup comes from the cache")

	now = now.Add(61 * time.Second)
	_, err = f.Fetch(t.Context(), ds.URL+"/client.json")
	require.NoError(t, err)
	assert.EqualValues(t, 2, ds.fetches.Load(), "an expired entry is fetched again")
}

func TestFetchHonorsNoStore(t *testing.T) {
	ds := newDocumentServer(t, serveDocument("no-store,no-cache,max-age=0"))
	f := ds.fetcher(t, Options{})
	for range 2 {
		_, err := f.Fetch(t.Context(), ds.URL+"/client.json")
		require.NoError(t, err)
	}
	assert.EqualValues(t, 2, ds.fetches.Load())
}

func TestCacheTTL(t *testing.T) {
	f := NewFetcher(Policy{}, Options{DefaultTTL: time.Minute, MaxTTL: time.Hour})
	for header, want := range map[string]time.Duration{
		"":                       time.Minute,
		"public":                 time.Minute,
		"max-age=300":            5 * time.Minute,
		"public, max-age=999999": time.Hour,
		"no-store":               0,
		"max-age=60, no-cache":   0,
		"max-age=-1":             0,
		"max-age=abc":            0,
	} {
		h := http.Header{}
		if header != "" {
			h.Set("Cache-Control", header)
		}
		assert.Equal(t, want, f.ttl(h), header)
	}

	// The time a shared cache already kept the response counts against max-age
	assert.Equal(t, 10*time.Second, f.ttl(http.Header{"Cache-Control": {"max-age=60"}, "Age": {"50"}}))
	assert.Equal(t, time.Duration(0), f.ttl(http.Header{"Cache-Control": {"max-age=60"}, "Age": {"90"}}))

	// A no-store in a second Cache-Control field counts as much as in the first
	assert.Equal(t, time.Duration(0), f.ttl(http.Header{"Cache-Control": {"max-age=60", "no-store"}}))
}

func TestFetchRejectsInvalidDocumentsWithoutCaching(t *testing.T) {
	var name atomic.Value
	name.Store("")
	ds := newDocumentServer(t, func(w http.ResponseWriter, _ *http.Request, id string) {
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": id, "client_name": name.Load(), "redirect_uris": []string{"http://127.0.0.1/cb"}})
	})
	f := ds.fetcher(t, Options{})
	_, err := f.Fetch(t.Context(), ds.URL+"/client.json")
	require.Error(t, err)
	assert.Contains(t, Message(err), "client_name")

	name.Store("Fixed")
	_, err = f.Fetch(t.Context(), ds.URL+"/client.json")
	require.NoError(t, err)
}

func TestFetchSizeLimit(t *testing.T) {
	ds := newDocumentServer(t, func(w http.ResponseWriter, _ *http.Request, id string) {
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": id, "client_name": strings.Repeat("x", 6000), "redirect_uris": []string{"http://127.0.0.1/cb"}})
	})
	_, err := ds.fetcher(t, Options{}).Fetch(t.Context(), ds.URL+"/client.json")
	require.Error(t, err)
	assert.Contains(t, Message(err), "larger than")
}

func TestFetchRejectsHostsOutsideThePolicy(t *testing.T) {
	ds := newDocumentServer(t, serveDocument(""))
	policy, err := NewPolicy([]string{"claude.ai"})
	require.NoError(t, err)
	_, err = NewFetcher(policy, Options{AllowPrivateAddresses: true}).Fetch(t.Context(), ds.URL+"/client.json")
	require.Error(t, err)
	assert.EqualValues(t, 0, ds.fetches.Load(), "a host outside the policy is never contacted")
}

func TestFetchRejectsPrivateAddresses(t *testing.T) {
	ds := newDocumentServer(t, serveDocument(""))
	policy, err := NewPolicy([]string{"*"})
	require.NoError(t, err)
	_, err = NewFetcher(policy, Options{}).Fetch(t.Context(), ds.URL+"/client.json")
	require.ErrorIs(t, err, errBlocked)
	assert.EqualValues(t, 0, ds.fetches.Load())
}

func TestFetchChecksEveryRedirect(t *testing.T) {
	target := newDocumentServer(t, serveDocument(""))
	start := newDocumentServer(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		http.Redirect(w, r, target.URL+"/client.json", http.StatusFound)
	})
	f := start.fetcher(t, Options{})

	// Only the first server's port counts as public, so the redirect leads to a refused address
	allowed := netip.MustParseAddrPort(strings.TrimPrefix(start.URL, "https://"))
	f.refuse = func(a netip.AddrPort) bool { return a.Port() != allowed.Port() }

	_, err := f.Fetch(t.Context(), start.URL+"/client.json")
	require.ErrorIs(t, err, errBlocked)
	assert.EqualValues(t, 1, start.fetches.Load())
	assert.EqualValues(t, 0, target.fetches.Load())
}

func TestFetchRefusesRedirectsToHostsOutsideThePolicy(t *testing.T) {
	target := newDocumentServer(t, serveDocument(""))
	start := newDocumentServer(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		http.Redirect(w, r, strings.Replace(target.URL, "127.0.0.1", "localhost", 1)+"/client.json", http.StatusFound)
	})
	_, err := start.fetcher(t, Options{}).Fetch(t.Context(), start.URL+"/client.json")
	require.ErrorContains(t, err, "isn't allowed to serve client metadata documents")
	assert.EqualValues(t, 0, target.fetches.Load(), "an open redirect on an allowed host can't lead to a host the policy leaves out")
}

func TestFetchRefusesRedirectsAwayFromHTTPS(t *testing.T) {
	start := newDocumentServer(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		http.Redirect(w, r, "http://127.0.0.1:1/client.json", http.StatusFound)
	})
	_, err := start.fetcher(t, Options{}).Fetch(t.Context(), start.URL+"/client.json")
	require.Error(t, err)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
