package cimd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// FetchJWKS returns the signing keys at a parsed document's jwks_uri, fetched through the same guarded transport as the document itself
func (f *Fetcher) FetchJWKS(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
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
