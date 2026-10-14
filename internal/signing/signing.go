// Package signing protects values the bridge hands out and expects back unchanged, such as the state it sends to the IdP and the consent cookie
// Values are signed, expire and are bound to a purpose, so one kind can never pass as another
// Nothing in them is secret, so they aren't encrypted
package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// MinKeyLength is the shortest key a ring accepts, in bytes
const MinKeyLength = 32

var (
	// ErrInvalid is returned for a value that wasn't signed by the ring for the purpose, or was changed since
	ErrInvalid = errors.New("invalid signed value")
	// ErrExpired is returned for a genuine value whose time is up
	ErrExpired = errors.New("signed value expired")
)

// Ring signs with its first key and verifies with all of them, so a new key can be rolled out before the old one is retired
type Ring struct {
	keys [][]byte
	now  func() time.Time
}

// NewRing creates a ring from keys, the first of which signs
func NewRing(keys []string) (*Ring, error) {
	if len(keys) == 0 {
		return nil, errors.New("at least one signing key is required")
	}
	r := &Ring{now: time.Now}
	for i, k := range keys {
		if len(k) < MinKeyLength {
			return nil, fmt.Errorf("signing key %d is shorter than %d bytes", i+1, MinKeyLength)
		}
		r.keys = append(r.keys, []byte(k))
	}
	return r, nil
}

// SetClock replaces the clock the ring checks expiry against, for tests
func (r *Ring) SetClock(now func() time.Time) {
	r.now = now
}

// envelope carries the expiry next to the value, so it is covered by the same signature
type envelope struct {
	Expires int64           `json:"exp"`
	Value   json.RawMessage `json:"v"`
}

// Sign encodes value as JSON and signs it for purpose, valid for ttl
func (r *Ring) Sign(purpose string, value any, ttl time.Duration) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(envelope{Expires: r.now().Add(ttl).Unix(), Value: raw})
	if err != nil {
		return "", err
	}
	data := base64.RawURLEncoding.EncodeToString(body)
	return data + "." + base64.RawURLEncoding.EncodeToString(mac(r.keys[0], purpose, data)), nil
}

// Verify checks that token was signed by the ring for purpose and hasn't expired, and decodes its value into out
func (r *Ring) Verify(purpose, token string, out any) error {
	data, sig, ok := strings.Cut(token, ".")
	if !ok {
		return ErrInvalid
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return ErrInvalid
	}
	if !slices.ContainsFunc(r.keys, func(k []byte) bool { return hmac.Equal(got, mac(k, purpose, data)) }) {
		return ErrInvalid
	}

	// Only a value with a genuine signature is decoded at all
	body, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return ErrInvalid
	}
	var env envelope
	if json.Unmarshal(body, &env) != nil {
		return ErrInvalid
	}
	if !r.now().Before(time.Unix(env.Expires, 0)) {
		return ErrExpired
	}
	if json.Unmarshal(env.Value, out) != nil {
		return ErrInvalid
	}
	return nil
}

// mac binds the signature to the purpose, so a value signed for one purpose never verifies for another
func mac(key []byte, purpose, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(purpose))
	h.Write([]byte{0})
	h.Write([]byte(data))
	return h.Sum(nil)
}
