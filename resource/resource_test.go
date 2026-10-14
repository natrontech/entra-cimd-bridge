package resource

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMetadata() *Metadata {
	return &Metadata{
		Resource:             "https://contactr.natron.ch/mcp",
		AuthorizationServers: []string{"https://mcp-auth.natron.ch"},
		ScopesSupported:      []string{"api://contactr/access_as_user"},
	}
}

func TestPaths(t *testing.T) {
	m := newMetadata()
	assert.Equal(t, "/.well-known/oauth-protected-resource/mcp", m.Path())
	assert.Equal(t, "https://contactr.natron.ch/.well-known/oauth-protected-resource/mcp", m.URL())

	root := &Metadata{Resource: "https://mcp.example.com"}
	assert.Equal(t, "/.well-known/oauth-protected-resource", root.Path())
	assert.Equal(t, "https://mcp.example.com/.well-known/oauth-protected-resource", root.URL())
}

func TestServeHTTP(t *testing.T) {
	rec := httptest.NewRecorder()
	newMetadata().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var doc map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	assert.Equal(t, map[string]any{
		"resource":                 "https://contactr.natron.ch/mcp",
		"authorization_servers":    []any{"https://mcp-auth.natron.ch"},
		"scopes_supported":         []any{"api://contactr/access_as_user"},
		"bearer_methods_supported": []any{"header"},
	}, doc)
	assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestChallenges(t *testing.T) {
	m := newMetadata()

	rec := httptest.NewRecorder()
	m.Challenge(rec)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer resource_metadata="https://contactr.natron.ch/.well-known/oauth-protected-resource/mcp", scope="api://contactr/access_as_user"`, rec.Header().Get("WWW-Authenticate"))

	rec = httptest.NewRecorder()
	m.InvalidToken(rec, `Token "expired"`)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token", error_description="Token expired"`)

	rec = httptest.NewRecorder()
	m.InsufficientScope(rec, []string{"a", "b"}, "")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `scope="a b", error="insufficient_scope"`)
}

func TestBearerToken(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer abc":  "abc",
		"bearer abc":  "abc",
		"Bearer  abc": "abc",
		"Basic abc":   "",
		"Bearer":      "",
		"Bearer ":     "",
		"":            "",
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", header)
		got, ok := BearerToken(r)
		assert.Equal(t, want, got, header)
		assert.Equal(t, want != "", ok, header)
	}
}
