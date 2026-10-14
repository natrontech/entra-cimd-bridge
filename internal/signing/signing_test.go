package signing

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	keyA = "key-a-0123456789abcdef0123456789abcdef"
	keyB = "key-b-0123456789abcdef0123456789abcdef"
)

type payload struct {
	RedirectURI string `json:"r"`
	State       string `json:"s"`
}

func newRing(t *testing.T, keys ...string) *Ring {
	t.Helper()
	r, err := NewRing(keys)
	require.NoError(t, err)
	return r
}

func TestRoundTrip(t *testing.T) {
	r := newRing(t, keyA)
	token, err := r.Sign("state", payload{RedirectURI: "http://127.0.0.1/cb", State: "xyz"}, time.Minute)
	require.NoError(t, err)

	var got payload
	require.NoError(t, r.Verify("state", token, &got))
	assert.Equal(t, payload{RedirectURI: "http://127.0.0.1/cb", State: "xyz"}, got)
}

func TestTamperedValueIsRejected(t *testing.T) {
	r := newRing(t, keyA)
	token, err := r.Sign("state", payload{RedirectURI: "http://127.0.0.1/cb"}, time.Minute)
	require.NoError(t, err)

	// An attacker swaps the redirect URI and keeps the old signature
	data, sig, _ := strings.Cut(token, ".")
	body, err := base64.RawURLEncoding.DecodeString(data)
	require.NoError(t, err)
	forged := strings.Replace(string(body), "http://127.0.0.1/cb", "https://evil.example/cb", 1)
	tampered := base64.RawURLEncoding.EncodeToString([]byte(forged)) + "." + sig

	var got payload
	assert.ErrorIs(t, r.Verify("state", tampered, &got), ErrInvalid)
	assert.ErrorIs(t, r.Verify("state", data+".", &got), ErrInvalid)
	assert.ErrorIs(t, r.Verify("state", data, &got), ErrInvalid)
	assert.ErrorIs(t, r.Verify("state", "", &got), ErrInvalid)
}

func TestWrongPurposeIsRejected(t *testing.T) {
	r := newRing(t, keyA)
	token, err := r.Sign("consent", payload{}, time.Minute)
	require.NoError(t, err)

	var got payload
	assert.ErrorIs(t, r.Verify("state", token, &got), ErrInvalid)
}

func TestExpiredValueIsRejected(t *testing.T) {
	r := newRing(t, keyA)
	now := time.Now()
	r.SetClock(func() time.Time { return now })
	token, err := r.Sign("state", payload{}, 10*time.Minute)
	require.NoError(t, err)

	var got payload
	now = now.Add(9 * time.Minute)
	require.NoError(t, r.Verify("state", token, &got))
	now = now.Add(2 * time.Minute)
	assert.ErrorIs(t, r.Verify("state", token, &got), ErrExpired)
}

func TestRotation(t *testing.T) {
	old := newRing(t, keyA)
	token, err := old.Sign("state", payload{State: "s"}, time.Minute)
	require.NoError(t, err)

	// The new key signs while the old one still verifies what is in flight
	rotated := newRing(t, keyB, keyA)
	var got payload
	require.NoError(t, rotated.Verify("state", token, &got))
	fresh, err := rotated.Sign("state", payload{}, time.Minute)
	require.NoError(t, err)
	assert.ErrorIs(t, old.Verify("state", fresh, &got), ErrInvalid)

	// Once the old key is retired, its values stop verifying
	assert.ErrorIs(t, newRing(t, keyB).Verify("state", token, &got), ErrInvalid)
}

func TestKeysMustBeLongEnough(t *testing.T) {
	_, err := NewRing(nil)
	require.Error(t, err)
	_, err = NewRing([]string{"short"})
	require.Error(t, err)
}
