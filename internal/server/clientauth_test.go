package server

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	assertionClient = "https://chatgpt.com/oauth/client.json"
	assertionIssuer = "https://bridge.example"
)

func TestVerifyClientAssertion(t *testing.T) {
	key := newAssertionKey(t)
	signer := newAssertionSigner(t, key)
	now := time.Now()
	claims := jwt.Claims{
		Issuer:   assertionClient,
		Subject:  assertionClient,
		Audience: jwt.Audience{assertionIssuer + "/token"},
		Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(now),
		ID:       "assertion-1",
	}
	keys := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &key.PublicKey,
		KeyID:     "test",
		Algorithm: "RS256",
		Use:       "sig",
	}}}

	require.NoError(t, verifyClientAssertion(keys, assertionClient, assertionIssuer, signAssertion(t, signer, claims), now), "ChatGPT signs the token endpoint as aud")
	withIssuer := claims
	withIssuer.Audience = jwt.Audience{assertionIssuer}
	require.NoError(t, verifyClientAssertion(keys, assertionClient, assertionIssuer, signAssertion(t, signer, withIssuer), now), "the CIMD draft prefers the issuer as aud")

	for name, change := range map[string]func(*jwt.Claims){
		"wrong issuer":  func(c *jwt.Claims) { c.Issuer = "https://evil.example/client.json" },
		"wrong subject": func(c *jwt.Claims) { c.Subject = "https://evil.example/client.json" },
		"wrong audience": func(c *jwt.Claims) {
			c.Audience = jwt.Audience{"https://other.example/token"}
		},
		"expired":     func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(now.Add(-2 * time.Minute)) },
		"missing exp": func(c *jwt.Claims) { c.Expiry = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := claims
			change(&changed)
			assert.Error(t, verifyClientAssertion(keys, assertionClient, assertionIssuer, signAssertion(t, signer, changed), now))
		})
	}

	otherKey := newAssertionKey(t)
	assert.Error(t, verifyClientAssertion(keys, assertionClient, assertionIssuer, signAssertion(t, newAssertionSigner(t, otherKey), claims), now), "an assertion signed by another key must fail")
}

func newAssertionKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func newAssertionSigner(t *testing.T, key *rsa.PrivateKey) jose.Signer {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	require.NoError(t, err)
	return signer
}

func signAssertion(t *testing.T, signer jose.Signer, claims jwt.Claims) string {
	t.Helper()
	assertion, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return assertion
}
