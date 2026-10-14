# Unreleased

- MCP clients with Client ID Metadata Documents, like Claude Code, Claude Desktop, Codex and VS Code, can sign in to MCP servers through Entra ID, with consent per client and server.
- Every MCP server uses its own app registration, so a code or refresh token issued for one can't be redeemed for another.
- MCP servers written in Go can serve their metadata and challenges with the `resource` package.
- The bridge ships as a distroless image with a Helm chart, and exports Prometheus metrics on a separate port.
- The bridge can run on `http://localhost` for trying MCP servers on a developer's machine.
