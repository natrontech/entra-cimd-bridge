// Package server is the bridge's HTTP side: an OAuth authorization server towards MCP clients, passing codes and tokens through to the IdP
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/natrontech/entra-cimd-bridge/internal/cimd"
	"github.com/natrontech/entra-cimd-bridge/internal/config"
	"github.com/natrontech/entra-cimd-bridge/internal/signing"
	"github.com/natrontech/entra-cimd-bridge/internal/upstream"
)

const (
	// The purposes the ring signs for, so a value made for one is never accepted as another
	purposeState       = "state"
	purposeConsentForm = "consent-form"
	purposeConsent     = "consent"

	// flowTTL is how long a person has from the consent page to coming back from the IdP
	flowTTL = 10 * time.Minute
	// maxStateLength caps the client's state, which the bridge signs into its own
	maxStateLength = 1024
)

// Options are the parts of a server that tests replace, where the zero value is right for production
type Options struct {
	// UpstreamClient makes the requests to the IdPs
	UpstreamClient *http.Client
	// CIMD tunes how client metadata documents are fetched
	CIMD   cimd.Options
	Logger *slog.Logger
}

// Server is a configured bridge
type Server struct {
	issuer      string
	callbackURL string
	// secureCookies is set when the issuer is https, which it is everywhere but on a developer's machine
	secureCookies bool
	ring          *signing.Ring
	clients       *cimd.Fetcher
	resources     []*resource
	byURI         map[string]*resource
	consentTTL    time.Duration
	metadata      []byte
	metrics       *metrics
	log           *slog.Logger
}

// resource is an MCP server, with the app registration the bridge uses for it at its IdP
type resource struct {
	uri      string
	name     string
	scopes   []string
	provider *upstream.Provider
	creds    upstream.Credentials
}

// New creates a server, discovering every provider first so a broken IdP setting fails at startup
func New(ctx context.Context, cfg *config.Config, opts Options) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opts.UpstreamClient == nil {
		opts.UpstreamClient = &http.Client{Timeout: 15 * time.Second}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	ring, err := signing.NewRing(cfg.SigningKeys)
	if err != nil {
		return nil, err
	}
	policy, err := cimd.NewPolicy(cfg.Clients.CIMDHosts)
	if err != nil {
		return nil, err
	}

	s := &Server{
		issuer:        cfg.Issuer,
		callbackURL:   cfg.Issuer + "/callback",
		secureCookies: strings.HasPrefix(cfg.Issuer, "https://"),
		ring:          ring,
		byURI:         map[string]*resource{},
		consentTTL:    cfg.ConsentTTL,
		metrics:       newMetrics(),
		log:           opts.Logger,
	}
	observe := opts.CIMD.Observe
	opts.CIMD.Observe = func(outcome string) {
		s.metrics.inc("bridge_client_lookups_total", "outcome", outcome)
		if observe != nil {
			observe(outcome)
		}
	}
	s.clients = cimd.NewFetcher(policy, opts.CIMD)

	providers := map[string]*upstream.Provider{}
	for _, name := range slices.Sorted(maps.Keys(cfg.Providers)) {
		p, err := upstream.Discover(ctx, name, cfg.Providers[name].Issuer, opts.UpstreamClient)
		if err != nil {
			return nil, err
		}
		providers[name] = p
	}
	for _, r := range cfg.Resources {
		res := &resource{
			uri:      r.URI,
			name:     r.Name,
			scopes:   r.Scopes,
			provider: providers[r.Provider],
			creds:    upstream.Credentials{ClientID: r.ClientID, ClientSecret: r.ClientSecret},
		}
		s.resources = append(s.resources, res)
		s.byURI[r.URI] = res
	}

	s.metadata, err = json.Marshal(s.authorizationServerMetadata())
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Handler serves the OAuth endpoints
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleMetadata)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.Handle("POST /consent", s.crossOriginProtection(http.HandlerFunc(s.handleConsent)))
	mux.HandleFunc("GET /callback", s.handleCallback)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("OPTIONS /token", s.handleTokenPreflight)
	mux.HandleFunc("GET /healthz", handleHealth)
	return s.logRequests(securityHeaders(mux))
}

// MetricsHandler serves /metrics and /healthz, for a listener that never faces the internet
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", s.metrics)
	mux.HandleFunc("GET /healthz", handleHealth)
	return mux
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// crossOriginProtection refuses consent posted from another site, so no page can approve a client on someone's behalf
func (s *Server) crossOriginProtection(next http.Handler) http.Handler {
	protection := http.NewCrossOriginProtection()
	protection.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.metrics.inc("bridge_consent_decisions_total", "decision", "invalid")
		s.errorPage(w, http.StatusForbidden, "Request refused", "The consent wasn't sent from this site's consent page.")
	}))
	return protection.Handler(next)
}

// resourceFor picks the MCP server a request is for, where a bridge for a single one doesn't need to be told
func (s *Server) resourceFor(values []string) (*resource, error) {
	values = slices.DeleteFunc(slices.Clone(values), func(v string) bool { return v == "" })
	switch len(values) {
	case 0:
		if len(s.resources) == 1 {
			return s.resources[0], nil
		}
		return nil, errors.New("resource is required, naming the MCP server the token is for")
	case 1:
	default:
		return nil, errors.New("only one resource per request is supported")
	}
	if res, ok := s.byURI[canonicalURI(values[0])]; ok {
		return res, nil
	}
	return nil, fmt.Errorf("%s isn't an MCP server this authorization server signs in to", values[0])
}

// canonicalURI accepts a resource with an uppercase scheme or host, or a trailing slash, as the MCP spec asks servers to
func canonicalURI(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" {
		return uri
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = strings.TrimSuffix(u.RawPath, "/")
	return u.String()
}

// statusRecorder remembers the status a handler answered with, for the request log
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// logRequests logs every request by its path alone, since the query carries codes and states
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" {
			return
		}
		s.log.InfoContext(r.Context(), "Request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		)
	})
}

// securityHeaders keeps every answer out of caches, frames and referrers, since they carry codes, tokens and states
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
