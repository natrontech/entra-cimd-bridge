// Package cimd resolves OAuth clients that identify themselves with a Client ID Metadata Document, an https URL serving their metadata
package cimd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// maxClientIDLength keeps absurd client IDs from ever being fetched or signed into a state
const maxClientIDLength = 2000

// Document is the part of a client's metadata document the bridge reads
type Document struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`

	// The secret fields are only read to reject documents that carry them, since a public document can't hold a secret
	ClientSecret          json.RawMessage `json:"client_secret,omitempty"`
	ClientSecretExpiresAt json.RawMessage `json:"client_secret_expires_at,omitempty"`
}

// Error is a rejected client, whose message is safe to show to the person signing in and to return to the client
// The cause, which may name addresses the bridge resolved, is only for logs
type Error struct {
	msg   string
	cause error
}

func (e *Error) Error() string {
	if e.cause == nil {
		return e.msg
	}
	return e.msg + ": " + e.cause.Error()
}

func (e *Error) Unwrap() error {
	return e.cause
}

// Message is the explanation to show for a rejected client, without the cause
func Message(err error) string {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.msg
	}
	return "The client can't be verified."
}

func reject(format string, args ...any) *Error {
	return &Error{msg: fmt.Sprintf(format, args...)}
}

// ParseClientID checks that a client ID is a URL a metadata document may live at
func ParseClientID(clientID string) (*url.URL, error) {
	if clientID == "" {
		return nil, reject("The request has no client_id.")
	}
	if len(clientID) > maxClientIDLength {
		return nil, reject("The client_id is too long.")
	}
	u, err := url.Parse(clientID)
	switch {
	case err != nil:
		return nil, reject("The client_id isn't a valid URL.")
	case u.Scheme != "https" || u.Host == "" || u.Opaque != "":
		return nil, reject("The client_id must be an https URL.")
	case u.User != nil:
		return nil, reject("The client_id must not contain a username or password.")
	case strings.Contains(clientID, "#"):
		return nil, reject("The client_id must not contain a fragment.")
	case u.Path == "" || u.Path == "/":
		return nil, reject("The client_id must have a path naming its metadata document.")
	}
	for segment := range strings.SplitSeq(u.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, reject("The client_id must not contain dot segments.")
		}
	}
	return u, nil
}

// parseDocument decodes a fetched metadata document and checks that it describes the client it was fetched for
func parseDocument(clientID string, body []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &Error{msg: "The client's metadata document isn't valid JSON.", cause: err}
	}
	switch {
	case doc.ClientID != clientID:
		return nil, reject("The client's metadata document names a different client_id.")
	case strings.TrimSpace(doc.ClientName) == "":
		return nil, reject("The client's metadata document has no client_name.")
	case len(doc.RedirectURIs) == 0:
		return nil, reject("The client's metadata document lists no redirect_uris.")
	case len(doc.ClientSecret) > 0 || len(doc.ClientSecretExpiresAt) > 0:
		return nil, reject("The client's metadata document contains a client secret.")
	case doc.TokenEndpointAuthMethod != "" && doc.TokenEndpointAuthMethod != "none":
		return nil, reject("The client authenticates with %s, but only public clients are supported.", doc.TokenEndpointAuthMethod)
	case len(doc.GrantTypes) > 0 && !slices.Contains(doc.GrantTypes, "authorization_code"):
		return nil, reject("The client's metadata document doesn't allow the authorization_code grant.")
	case len(doc.ResponseTypes) > 0 && !slices.Contains(doc.ResponseTypes, "code"):
		return nil, reject("The client's metadata document doesn't allow the code response type.")
	}
	return &doc, nil
}

// AllowsRedirect reports whether the document registers uri as a redirect URI
// A loopback redirect URI matches with any port, since native apps pick a free one when they start
func (d *Document) AllowsRedirect(uri string) bool {
	if slices.Contains(d.RedirectURIs, uri) {
		return true
	}
	requested, err := url.Parse(uri)
	if err != nil || !isLoopback(requested) {
		return false
	}
	return slices.ContainsFunc(d.RedirectURIs, func(registered string) bool {
		r, err := url.Parse(registered)
		return err == nil && isLoopback(r) && r.Hostname() == requested.Hostname() && r.EscapedPath() == requested.EscapedPath() && r.RawQuery == requested.RawQuery
	})
}

// CheckRedirectURI applies the bridge's redirect policy, which allows https URIs and http ones on a loopback host
func CheckRedirectURI(uri string) error {
	u, err := url.Parse(uri)
	switch {
	case uri == "":
		return reject("The request has no redirect_uri.")
	case err != nil || u.Host == "" || u.Opaque != "":
		return reject("The redirect_uri isn't a valid absolute URL.")
	case u.User != nil || strings.Contains(uri, "#"):
		return reject("The redirect_uri must not contain a username, password or fragment.")
	case u.Scheme == "https", isLoopback(u):
		return nil
	default:
		return reject("The redirect_uri must use https, or http on localhost, 127.0.0.1 or [::1].")
	}
}

// IsLoopbackRedirect reports whether a redirect URI leads to this computer, where any program could be listening
func IsLoopbackRedirect(uri string) bool {
	u, err := url.Parse(uri)
	return err == nil && isLoopback(u)
}

func isLoopback(u *url.URL) bool {
	if u.Scheme != "http" || u.User != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
