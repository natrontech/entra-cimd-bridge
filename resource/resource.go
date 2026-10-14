// Package resource lets an MCP server send clients to the bridge for sign-in
// It serves the server's Protected Resource Metadata (RFC 9728) and writes the 401 and 403 challenges that point to it
// Tokens are still validated by the MCP server itself, as tokens of its IdP for its own API
//
//	meta := &resource.Metadata{
//		Resource:             "https://contactr.natron.ch/mcp",
//		AuthorizationServers: []string{"https://mcp-auth.natron.ch"},
//		ScopesSupported:      []string{"api://<client-id>/access_as_user"},
//	}
//	mux.Handle("GET "+meta.Path(), meta)
//	mux.Handle("/mcp", requireToken(meta, mcpHandler))
//
//	func requireToken(meta *resource.Metadata, next http.Handler) http.Handler {
//		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//			token, ok := resource.BearerToken(r)
//			if !ok {
//				meta.Challenge(w)
//				return
//			}
//			if err := verify(r.Context(), token); err != nil {
//				meta.InvalidToken(w, "The access token is invalid or expired.")
//				return
//			}
//			next.ServeHTTP(w, r)
//		})
//	}
package resource

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// wellKnown is where RFC 9728 puts the metadata, followed by the resource's path
const wellKnown = "/.well-known/oauth-protected-resource"

// Metadata describes an MCP server as an OAuth protected resource
type Metadata struct {
	// Resource is the MCP server's canonical URI, exactly as the bridge's config lists it, like https://contactr.natron.ch/mcp
	Resource string `json:"resource"`
	// AuthorizationServers holds the bridge's issuer
	AuthorizationServers []string `json:"authorization_servers"`
	// ScopesSupported are the scopes a token needs, which clients request and are also sent in challenges
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// BearerMethodsSupported defaults to the Authorization header
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	// ResourceName is a human-readable name of the MCP server
	ResourceName string `json:"resource_name,omitempty"`
	// ResourceDocumentation is a URL with documentation for people using the MCP server
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
}

// Path is where the metadata is served on the MCP server's host: /.well-known/oauth-protected-resource followed by the resource's path
func (m *Metadata) Path() string {
	u, err := url.Parse(m.Resource)
	if err != nil {
		return wellKnown
	}
	return wellKnown + strings.TrimSuffix(u.EscapedPath(), "/")
}

// URL is the absolute URL of the metadata, which challenges point to
func (m *Metadata) URL() string {
	u, err := url.Parse(m.Resource)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + m.Path()
}

// ServeHTTP serves the metadata, readable from browser-based clients too
func (m *Metadata) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	doc := *m
	if len(doc.BearerMethodsSupported) == 0 {
		doc.BearerMethodsSupported = []string{"header"}
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(doc)
}

// Challenge answers a request without a token with 401, telling the client where to find the metadata and which scopes to request
func (m *Metadata) Challenge(w http.ResponseWriter) {
	m.challenge(w, http.StatusUnauthorized, "", "", m.ScopesSupported)
}

// InvalidToken answers a request whose token is invalid, expired or for someone else with 401, which makes the client sign in again
func (m *Metadata) InvalidToken(w http.ResponseWriter, description string) {
	m.challenge(w, http.StatusUnauthorized, "invalid_token", description, m.ScopesSupported)
}

// InsufficientScope answers a request whose token lacks scopes with 403, naming all the scopes the request needs
func (m *Metadata) InsufficientScope(w http.ResponseWriter, scopes []string, description string) {
	m.challenge(w, http.StatusForbidden, "insufficient_scope", description, scopes)
}

func (m *Metadata) challenge(w http.ResponseWriter, status int, code, description string, scopes []string) {
	params := []string{"resource_metadata=" + quote(m.URL())}
	if len(scopes) > 0 {
		params = append(params, "scope="+quote(strings.Join(scopes, " ")))
	}
	if code != "" {
		params = append(params, "error="+quote(code))
	}
	if description != "" {
		params = append(params, "error_description="+quote(description))
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))
	w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
	w.WriteHeader(status)
}

// quote makes a quoted-string of s, dropping the characters RFC 6750 doesn't allow in its parameters
func quote(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, s)
	return `"` + s + `"`
}

// BearerToken returns the token of a request's Authorization header
func BearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	token = strings.TrimSpace(token)
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}
