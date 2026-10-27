package cimd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Options tune a fetcher, where the zero value is right for production
type Options struct {
	// AllowPrivateAddresses lets fetches reach loopback and private addresses, which only tests should need
	AllowPrivateAddresses bool
	// RootCAs replaces the system's trusted roots, for tests with their own certificates
	RootCAs *x509.CertPool
	// MaxSize caps a document, 5 KiB by default as the CIMD draft suggests
	MaxSize int64
	// Timeout caps a whole fetch including redirects, 5 seconds by default
	Timeout time.Duration
	// DefaultTTL is how long a document without cache headers is kept, 5 minutes by default
	DefaultTTL time.Duration
	// MaxTTL caps how long any document is kept, 24 hours by default
	MaxTTL time.Duration
	// MaxEntries caps the number of cached documents, 1000 by default
	MaxEntries int
	// Observe, when set, is told the outcome of every lookup: cached, fetched or rejected
	Observe func(outcome string)
}

// maxRedirects is how many redirects a fetch follows, each of which must stay on https and on a host the policy allows
const maxRedirects = 3

// maxHeaderBytes caps the response headers of a document host, which would otherwise be allowed 10 MiB next to a body of a few KiB
const maxHeaderBytes = 64 << 10

// Fetcher resolves client IDs to their validated metadata documents, caching them as their HTTP cache headers allow
// The cache only saves fetches, so the bridge stays stateless
type Fetcher struct {
	policy Policy
	opts   Options
	client *http.Client
	now    func() time.Time
	// refuse reports the addresses fetches must not connect to
	refuse func(netip.AddrPort) bool

	mu      sync.Mutex
	entries map[string]entry

	jwksMu      sync.Mutex
	jwksEntries map[string]jwksEntry
}

type entry struct {
	doc     *Document
	expires time.Time
}

// NewFetcher creates a fetcher for clients whose documents live on hosts the policy allows
func NewFetcher(policy Policy, opts Options) *Fetcher {
	if opts.MaxSize <= 0 {
		opts.MaxSize = 5 << 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.DefaultTTL <= 0 {
		opts.DefaultTTL = 5 * time.Minute
	}
	if opts.MaxTTL <= 0 {
		opts.MaxTTL = 24 * time.Hour
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 1000
	}
	if opts.Observe == nil {
		opts.Observe = func(string) {}
	}

	f := &Fetcher{policy: policy, opts: opts, now: time.Now, entries: map[string]entry{}, jwksEntries: map[string]jwksEntry{}, refuse: refusePrivate}
	if opts.AllowPrivateAddresses {
		f.refuse = func(netip.AddrPort) bool { return false }
	}
	dialer := &net.Dialer{Timeout: opts.Timeout, Control: dialControl(func(a netip.AddrPort) bool { return f.refuse(a) })}
	transport := &http.Transport{
		// A proxy would connect to the target itself, so the dial check would only ever see the proxy's address
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{RootCAs: opts.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    opts.Timeout,
		ResponseHeaderTimeout:  opts.Timeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           20,
		IdleConnTimeout:        90 * time.Second,
	}
	f.client = &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirect to a URL that isn't https")
			}

			// Otherwise an open redirect on an allowed host would let any host serve documents in its name
			if !f.policy.Allows(req.URL.Hostname()) {
				return fmt.Errorf("redirect to %s, which isn't allowed to serve client metadata documents", req.URL.Hostname())
			}
			return nil
		},
	}
	return f
}

// Fetch returns the validated metadata document of the client clientID names
func (f *Fetcher) Fetch(ctx context.Context, clientID string) (*Document, error) {
	u, err := ParseClientID(clientID)
	if err != nil {
		f.opts.Observe("rejected")
		return nil, err
	}
	if !f.policy.Allows(u.Hostname()) {
		f.opts.Observe("rejected")
		return nil, reject("Clients from %s aren't allowed to sign in here.", u.Hostname())
	}
	if doc, ok := f.cached(clientID); ok {
		f.opts.Observe("cached")
		return doc, nil
	}

	doc, ttl, err := f.fetch(ctx, clientID)
	if err != nil {
		// Errors are never cached, so a client that fixes its document works right away
		f.opts.Observe("rejected")
		return nil, err
	}
	f.opts.Observe("fetched")
	if ttl > 0 {
		f.store(clientID, doc, ttl)
	}
	return doc, nil
}

func (f *Fetcher) fetch(ctx context.Context, clientID string) (*Document, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, 0, &Error{msg: "The client's metadata document can't be fetched.", cause: err}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, &Error{msg: "The client's metadata document can't be fetched.", cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, &Error{msg: "The client's metadata document can't be fetched.", cause: fmt.Errorf("status %d", resp.StatusCode)}
	}

	// Reading one byte past the limit tells a document that ends right at it from one that goes on
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.opts.MaxSize+1))
	if err != nil {
		return nil, 0, &Error{msg: "The client's metadata document can't be fetched.", cause: err}
	}
	if int64(len(body)) > f.opts.MaxSize {
		return nil, 0, reject("The client's metadata document is larger than %d bytes.", f.opts.MaxSize)
	}
	doc, err := parseDocument(clientID, body)
	if err != nil {
		return nil, 0, err
	}
	return doc, f.ttl(resp.Header), nil
}

// ttl is how long a response may be cached according to its Cache-Control and Age headers, within the fetcher's bounds
func (f *Fetcher) ttl(h http.Header) time.Duration {
	// A response may carry several Cache-Control fields, and a no-store in any of them counts
	cacheControl := strings.Join(h.Values("Cache-Control"), ",")
	if cacheControl == "" {
		return f.opts.DefaultTTL
	}
	ttl := f.opts.DefaultTTL
	for directive := range strings.SplitSeq(strings.ToLower(cacheControl), ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(directive), "=")
		switch name {
		case "no-store", "no-cache":
			return 0
		case "max-age":
			seconds, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
			if err != nil || seconds < 0 {
				return 0
			}
			ttl = time.Duration(seconds) * time.Second

			// A shared cache in front of the host may have kept the response for a while already, which max-age includes (RFC 9111 section 4.2.3)
			if age, err := strconv.ParseInt(h.Get("Age"), 10, 64); err == nil && age > 0 {
				ttl -= time.Duration(min(age, seconds)) * time.Second
			}
		}
	}
	return min(ttl, f.opts.MaxTTL)
}

func (f *Fetcher) cached(clientID string) (*Document, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[clientID]
	if !ok || !f.now().Before(e.expires) {
		return nil, false
	}
	return e.doc, true
}

func (f *Fetcher) store(clientID string, doc *Document, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()

	// A full cache first drops what has expired, and then whatever comes first, since any entry can simply be fetched again
	if len(f.entries) >= f.opts.MaxEntries {
		for id, e := range f.entries {
			if !now.Before(e.expires) {
				delete(f.entries, id)
			}
		}
	}
	for id := range f.entries {
		if len(f.entries) < f.opts.MaxEntries {
			break
		}
		delete(f.entries, id)
	}
	f.entries[clientID] = entry{doc: doc, expires: now.Add(ttl)}
}
