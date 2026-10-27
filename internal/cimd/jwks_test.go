package cimd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchJWKSValidatesAndCaches(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}
	var fetches atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks.json":
			fetches.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey}})
		case "/empty.json":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{})
		case "/bad.json":
			_, _ = w.Write([]byte("not json"))
		case "/large.json":
			_, _ = w.Write(make([]byte, jwksMaxSize+1))
		case "/status.json":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	policy, err := NewPolicy([]string{"127.0.0.1"})
	require.NoError(t, err)
	fetcher := NewFetcher(policy, Options{AllowPrivateAddresses: true, RootCAs: pool, MaxEntries: 2})
	now := time.Now()
	fetcher.now = func() time.Time { return now }
	jwksURI := server.URL + "/jwks.json"

	set, err := fetcher.FetchJWKS(context.Background(), jwksURI)
	require.NoError(t, err)
	require.Len(t, set.Keys, 1)
	assert.Equal(t, "test", set.Keys[0].KeyID)
	assert.Equal(t, int32(1), fetches.Load())

	_, err = fetcher.FetchJWKS(context.Background(), jwksURI)
	require.NoError(t, err)
	assert.Equal(t, int32(1), fetches.Load(), "a second lookup must use the cache")

	now = now.Add(jwksTTL + time.Second)
	_, err = fetcher.FetchJWKS(context.Background(), jwksURI)
	require.NoError(t, err)
	assert.Equal(t, int32(2), fetches.Load(), "an expired entry must be fetched again")

	for name, uri := range map[string]string{
		"not found":    server.URL + "/missing.json",
		"empty set":    server.URL + "/empty.json",
		"invalid json": server.URL + "/bad.json",
		"too large":    server.URL + "/large.json",
		"bad status":   server.URL + "/status.json",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fetcher.FetchJWKS(context.Background(), uri)
			assert.Error(t, err)
		})
	}
}
