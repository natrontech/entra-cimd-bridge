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
	assertionTarget = "https://bridge.example/token"
)

func TestVerifyClientAssertion(t *testing.T) {
	key := newAssertionKey(t)
	signer := newAssertionSigner(t, key)
	now := time.Now()
	claims := jwt.Claims{
		Issuer:   assertionClient,
		Subject:  assertionClient,
		Audience: jwt.Audience{assertionTarget},
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

	jti, expiry, err := verifyClientAssertion(keys, assertionClient, assertionTarget, signAssertion(t, signer, claims), now)
	require.NoError(t, err)
	assert.Equal(t, "assertion-1", jti)
	assert.Equal(t, claims.Expiry.Time().Unix(), expiry.Unix())

	for name, change := range map[string]func(*jwt.Claims){
		"wrong issuer":  func(c *jwt.Claims) { c.Issuer = "https://evil.example/client.json" },
		"wrong subject": func(c *jwt.Claims) { c.Subject = "https://evil.example/client.json" },
		"wrong audience": func(c *jwt.Claims) {
			c.Audience = jwt.Audience{"https://other.example/token"}
		},
		"expired":     func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(now.Add(-2 * time.Minute)) },
		"missing jti": func(c *jwt.Claims) { c.ID = "" },
		"missing exp": func(c *jwt.Claims) { c.Expiry = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := claims
			change(&changed)
			_, _, err := verifyClientAssertion(keys, assertionClient, assertionTarget, signAssertion(t, signer, changed), now)
			assert.Error(t, err)
		})
	}

	otherKey := newAssertionKey(t)
	_, _, err = verifyClientAssertion(keys, assertionClient, assertionTarget, signAssertion(t, newAssertionSigner(t, otherKey), claims), now)
	assert.Error(t, err, "an assertion signed by another key must fail")
}

func TestRememberAssertionRejectsReplay(t *testing.T) {
	s := &Server{assertionJTIs: map[string]time.Time{}}
	expiry := time.Now().Add(time.Minute)
	assert.True(t, s.rememberAssertion(assertionClient, "jti-1", expiry))
	assert.False(t, s.rememberAssertion(assertionClient, "jti-1", expiry))
	assert.True(t, s.rememberAssertion(assertionClient, "jti-2", expiry))
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
