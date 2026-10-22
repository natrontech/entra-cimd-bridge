package cimd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// jwksMaxSize caps a client's published key set
	jwksMaxSize = 64 << 10
	// jwksTTL is how long a fetched key set is reused
	jwksTTL = 5 * time.Minute
)

type jwksEntry struct {
	set     *jose.JSONWebKeySet
	expires time.Time
}

// FetchJWKS returns the signing keys named by a client's validated CIMD document
// The key set must stay on the same HTTPS host as the client metadata document and is fetched through the same guarded transport as the metadata itself
func (f *Fetcher) FetchJWKS(ctx context.Context, clientID, jwksURI string) (*jose.JSONWebKeySet, error) {
	clientURL, err := url.Parse(clientID)
	if err != nil {
		return nil, &Error{msg: "The client's signing keys can't be fetched.", cause: err}
	}
	u, err := url.Parse(jwksURI)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "":
		return nil, reject("The client's jwks_uri must be an https URL.")
	case u.User != nil || strings.Contains(jwksURI, "#"):
		return nil, reject("The client's jwks_uri must not contain a username, password or fragment.")
	case !strings.EqualFold(u.Host, clientURL.Host):
		return nil, reject("The client's jwks_uri must be on the same host as its client_id.")
	case u.Path == "" || u.Path == "/":
		return nil, reject("The client's jwks_uri must have a path.")
	}

	if set, ok := f.cachedJWKS(jwksURI); ok {
		return set, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, &Error{msg: "The client's signing keys can't be fetched.", cause: err}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, &Error{msg: "The client's signing keys can't be fetched.", cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{msg: "The client's signing keys can't be fetched.", cause: fmt.Errorf("status %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxSize+1))
	if err != nil {
		return nil, &Error{msg: "The client's signing keys can't be fetched.", cause: err}
	}
	if len(body) > jwksMaxSize {
		return nil, &Error{msg: "The client's signing keys are larger than 64 KiB."}
	}
	var set jose.JSONWebKeySet
	if err = json.Unmarshal(body, &set); err != nil {
		return nil, &Error{msg: "The client's signing keys aren't valid JSON.", cause: err}
	}
	if len(set.Keys) == 0 {
		return nil, &Error{msg: "The client's signing keys are empty."}
	}
	f.storeJWKS(jwksURI, &set)
	return &set, nil
}

func (f *Fetcher) cachedJWKS(uri string) (*jose.JSONWebKeySet, bool) {
	f.jwksMu.Lock()
	defer f.jwksMu.Unlock()
	e, ok := f.jwksEntries[uri]
	if !ok {
		return nil, false
	}
	if !f.now().Before(e.expires) {
		delete(f.jwksEntries, uri)
		return nil, false
	}
	return e.set, true
}

func (f *Fetcher) storeJWKS(uri string, set *jose.JSONWebKeySet) {
	now := f.now()
	f.jwksMu.Lock()
	defer f.jwksMu.Unlock()
	for key, entry := range f.jwksEntries {
		if !now.Before(entry.expires) {
			delete(f.jwksEntries, key)
		}
	}
	if f.opts.MaxEntries > 0 && len(f.jwksEntries) >= f.opts.MaxEntries {
		return
	}
	f.jwksEntries[uri] = jwksEntry{set: set, expires: now.Add(jwksTTL)}
}
