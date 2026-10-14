package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const valid = `
issuer: https://mcp-auth.natron.ch
signing_keys:
  - ${BRIDGE_KEY_CURRENT}
providers:
  entra:
    issuer: https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
clients:
  cimd_hosts: [claude.ai, vscode.dev]
consent_ttl: 720h
resources:
  - uri: https://contactr.natron.ch/mcp
    name: Contactr
    provider: entra
    client_id: 11111111-1111-1111-1111-111111111111
    client_secret: ${CONTACTR_CLIENT_SECRET}
    scopes: [api://11111111-1111-1111-1111-111111111111/access_as_user, offline_access]
  - uri: https://other.natron.ch/mcp
    name: Other
    provider: entra
    client_id: 22222222-2222-2222-2222-222222222222
    client_secret: ${OTHER_CLIENT_SECRET}
    scopes: [api://22222222-2222-2222-2222-222222222222/access_as_user, offline_access]
`

func setSecrets(t *testing.T) {
	t.Setenv("BRIDGE_KEY_CURRENT", "0123456789abcdef0123456789abcdef")
	// Secrets full of YAML syntax and numbers stay plain strings
	t.Setenv("CONTACTR_CLIENT_SECRET", "a: b # {c} *d")
	t.Setenv("OTHER_CLIENT_SECRET", "12345")
}

func TestLoad(t *testing.T) {
	setSecrets(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(valid), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "https://mcp-auth.natron.ch", cfg.Issuer)
	assert.Equal(t, ":8080", cfg.Listen)
	assert.Equal(t, ":9090", cfg.MetricsListen)
	assert.Equal(t, []string{"0123456789abcdef0123456789abcdef"}, cfg.SigningKeys)
	assert.Equal(t, 720*time.Hour, cfg.ConsentTTL)
	assert.Equal(t, []string{"claude.ai", "vscode.dev"}, cfg.Clients.CIMDHosts)
	require.Len(t, cfg.Resources, 2)
	assert.Equal(t, "a: b # {c} *d", cfg.Resources[0].ClientSecret)
	assert.Equal(t, "12345", cfg.Resources[1].ClientSecret)
	assert.Equal(t, "entra", cfg.Resources[1].Provider)
}

func TestUnsetVariablesAreErrors(t *testing.T) {
	t.Setenv("BRIDGE_KEY_CURRENT", "0123456789abcdef0123456789abcdef")
	_, err := Parse([]byte(valid))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONTACTR_CLIENT_SECRET")
	assert.Contains(t, err.Error(), "OTHER_CLIENT_SECRET")
}

func TestUnknownFieldsAreErrors(t *testing.T) {
	setSecrets(t)
	_, err := Parse([]byte(valid + "consent_tll: 1h\n"))
	require.Error(t, err)
}

func TestValidation(t *testing.T) {
	setSecrets(t)
	for name, tc := range map[string]struct{ from, to, want string }{
		"shared client_id": {
			from: "22222222-2222-2222-2222-222222222222\n",
			to:   "11111111-1111-1111-1111-111111111111\n",
			want: "own app registration",
		},
		"http issuer":         {from: "issuer: https://mcp-auth.natron.ch", to: "issuer: http://mcp-auth.natron.ch", want: "issuer"},
		"http on 127.0.0.2":   {from: "issuer: https://mcp-auth.natron.ch", to: "issuer: http://127.0.0.2:8080", want: "issuer"},
		"issuer with path":    {from: "issuer: https://mcp-auth.natron.ch", to: "issuer: https://mcp-auth.natron.ch/", want: "issuer"},
		"unknown provider":    {from: "provider: entra\n    client_id: 2", to: "provider: okta\n    client_id: 2", want: "isn't one of the providers"},
		"trailing slash":      {from: "https://contactr.natron.ch/mcp", to: "https://contactr.natron.ch/mcp/", want: "slash"},
		"uppercase host":      {from: "https://contactr.natron.ch/mcp", to: "https://Contactr.natron.ch/mcp", want: "canonical"},
		"fragment":            {from: "https://contactr.natron.ch/mcp", to: "https://contactr.natron.ch/mcp#x", want: "fragment"},
		"plain http resource": {from: "https://contactr.natron.ch/mcp", to: "http://contactr.natron.ch/mcp", want: "https"},
		"duplicate resource":  {from: "https://other.natron.ch/mcp", to: "https://contactr.natron.ch/mcp", want: "listed twice"},
		"short key":           {from: "- ${BRIDGE_KEY_CURRENT}", to: "- tooshort", want: "signing_keys"},
		"bad cimd host":       {from: "[claude.ai, vscode.dev]", to: "[https://claude.ai]", want: "cimd_hosts"},
		"no scopes":           {from: "scopes: [api://22222222-2222-2222-2222-222222222222/access_as_user, offline_access]", to: "scopes: []", want: "scopes"},
		"no name":             {from: "name: Other", to: "name: \"\"", want: "name"},
	} {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(valid, tc.from, tc.to, 1)
			require.NotEqual(t, valid, changed, "the replacement must apply")
			_, err := Parse([]byte(changed))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestResourceURIs(t *testing.T) {
	for uri, ok := range map[string]bool{
		"https://mcp.example.com/mcp":        true,
		"https://mcp.example.com":            true,
		"https://mcp.example.com:8443":       true,
		"https://mcp.example.com/server/mcp": true,
		"http://localhost:3000/mcp":          true,
		"http://127.0.0.1:3000/mcp":          true,
		"mcp.example.com":                    false,
		"https://mcp.example.com/":           false,
		"https://mcp.example.com/mcp?x=1":    false,
		"HTTPS://mcp.example.com/mcp":        false,
		"http://mcp.example.com/mcp":         false,
	} {
		assert.Equal(t, ok, CheckResourceURI(uri) == nil, uri)
	}
}

func TestLoopbackIssuerMayUseHTTP(t *testing.T) {
	setSecrets(t)
	for _, issuer := range []string{"http://localhost:18080", "http://127.0.0.1:18080", "http://[::1]:18080"} {
		_, err := Parse([]byte(strings.Replace(valid, "issuer: https://mcp-auth.natron.ch", "issuer: "+issuer, 1)))
		assert.NoError(t, err, issuer)
	}
}
