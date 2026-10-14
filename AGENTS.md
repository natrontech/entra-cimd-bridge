# entra-cimd-bridge

An OAuth authorization server with Client ID Metadata Documents for MCP clients, in front of Entra ID or another IdP without them.
It passes the IdP's codes and tokens through unchanged; `README.md` explains the flow and why it needs no state but the signed `state`.

## Layout

- `cmd/bridge` — main and flags.
- `internal/config` — YAML loading, `${ENV}` expansion and validation.
- `internal/signing` — HMAC-signed, expiring, purpose-bound values and the key ring.
- `internal/cimd` — client metadata documents: validation, the SSRF-safe fetcher with its cache, and the host policy.
- `internal/upstream` — OIDC discovery, token requests to the IdP and how its errors map to the client's.
- `internal/server` — the HTTP handlers, the consent and error pages in `templates/`, and the metrics.
- `internal/testenv` — a fake IdP that behaves like Entra, a client metadata host and a browser, for tests only.
- `resource` — the public package MCP servers use to serve their metadata and challenges; standard library only.
- `e2e` — the MCP Go SDK client through the bridge against fake MCP servers.
- `chart` — the Helm chart.

## Rules

- Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:` …).
- Every user-visible change adds a line under `# Unreleased` in `CHANGELOG.md`; never invent a version heading.
- Releases follow Semantic Versioning: a tag like `0.2.0`, without a `v`, publishes the image and the chart with that version.
  Breaking changes to the config, the chart's values or the `resource` package bump the major version, or the minor one while it is `0.x`.
- The bridge stays stateless and issues no tokens of its own: anything it needs back later travels signed through the IdP or a cookie.
- Never log or render codes, tokens, secrets or query strings.
- Until a client and its redirect URI are verified, errors go to an error page, never to a redirect.
- A new config key goes into `config.example.yaml`, the README's table and the chart's `values.yaml`.
- `make test` and `make lint` must pass; tests use testify.

## Comments

- Exactly one sentence per line, never wrapped, no matter how long.
- No trailing period on single-line comments.
- Explain intent, invariants and why a branch exists; never restate the next line.
- Inside a function, put a one-sentence comment above each major step, so skimming the comments explains the flow.
