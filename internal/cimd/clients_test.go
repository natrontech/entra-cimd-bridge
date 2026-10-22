package cimd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// knownClient is a real MCP client, with the metadata document it publishes and the redirect URIs it sends
type knownClient struct {
	name     string
	clientID string
	fixture  string
	// redirects are redirect URIs the client really sends, such as a loopback one with the ephemeral port it picked
	redirects []string
}

// knownClients are the MCP clients the bridge is meant to work with, whose documents are copied into testdata
var knownClients = []knownClient{
	{
		name:      "Claude Code",
		clientID:  "https://claude.ai/oauth/claude-code-client-metadata",
		fixture:   "claude-code.json",
		redirects: []string{"http://localhost:54321/callback", "http://127.0.0.1:54321/callback"},
	},
	{
		// claude.ai, Claude Desktop, Claude mobile and Cowork share this client, which signs in from Anthropic's servers
		name:      "Claude",
		clientID:  "https://claude.ai/oauth/mcp-oauth-client-metadata",
		fixture:   "claude.json",
		redirects: []string{"https://claude.ai/api/mcp/auth_callback"},
	},
	{
		// Codex uses this shared document because the bridge returns iss, and otherwise one per MCP server on the same host
		name:      "Codex",
		clientID:  "https://chatgpt.com/oauth/codex/client.json",
		fixture:   "codex.json",
		redirects: []string{"http://127.0.0.1:61234/callback", "http://localhost:61234/callback"},
	},
	{
		// ChatGPT's web connector publishes a private_key_jwt client document.
		name:      "ChatGPT",
		clientID:  "https://chatgpt.com/oauth/client.json",
		fixture:   "chatgpt.json",
		redirects: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
	},
	{
		name:      "VS Code",
		clientID:  "https://vscode.dev/oauth/client-metadata.json",
		fixture:   "vscode.json",
		redirects: []string{"http://127.0.0.1:33418/", "https://vscode.dev/redirect"},
	},
}

// The bridge's default policy, as in config.example.yaml and the chart
var defaultHosts = []string{"claude.ai", "chatgpt.com", "vscode.dev"}

func TestKnownClientsAreAccepted(t *testing.T) {
	policy, err := NewPolicy(defaultHosts)
	require.NoError(t, err)
	for _, c := range knownClients {
		t.Run(c.name, func(t *testing.T) {
			u, err := ParseClientID(c.clientID)
			require.NoError(t, err)
			assert.True(t, policy.Allows(u.Hostname()))

			body, err := os.ReadFile(filepath.Join("testdata", c.fixture))
			require.NoError(t, err)
			assert.LessOrEqual(t, len(body), 5<<10, "documents larger than 5 KB are refused")
			doc, err := parseDocument(c.clientID, body)
			require.NoError(t, err)
			for _, redirect := range c.redirects {
				assert.NoError(t, CheckRedirectURI(redirect), redirect)
				assert.True(t, doc.AllowsRedirect(redirect), redirect)
			}
			assert.False(t, doc.AllowsRedirect("https://evil.example/callback"))
		})
	}
}

// TestKnownClientsLive fetches the real documents through the guarded fetcher, so a client that changes its document shows up here first
// It needs the internet, so it only runs with CIMD_LIVE=1
func TestKnownClientsLive(t *testing.T) {
	if os.Getenv("CIMD_LIVE") == "" {
		t.Skip("set CIMD_LIVE=1 to fetch the real client metadata documents")
	}
	policy, err := NewPolicy(defaultHosts)
	require.NoError(t, err)
	f := NewFetcher(policy, Options{})
	for _, c := range knownClients {
		t.Run(c.name, func(t *testing.T) {
			doc, err := f.Fetch(t.Context(), c.clientID)
			require.NoError(t, err)
			for _, redirect := range c.redirects {
				assert.True(t, doc.AllowsRedirect(redirect), redirect)
			}
		})
	}
}
