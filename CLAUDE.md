# soquery

See README.md for setup, deployment, and Salesforce Connected App configuration.

## Build & Test

```bash
go build ./cmd/soquery-server/   # MCP server
go build .                        # Legacy CLI
go test ./...                     # All tests
```

For local dev, create `.env` from `.env.example` and ensure `DATABASE_URL=sqlite:soquery.db` is set.

## Package Structure

```
cmd/soquery-server/     Entry point. Wires OAuth, MCP, and HTTP together.
internal/
  sfclient/             Salesforce REST API client. Query, Describe, CRUD.
                        All methods take context.Context. 30s HTTP timeout.
                        Max 10,000 records per query (MaxQueryRecords).
  store/                Persistence interface + SQLite implementation.
                        AES-256-GCM encryption for SF tokens at rest.
                        PostgreSQL implementation not yet built.
  oauth/                OAuth 2.1 Authorization Server.
                        DCR, authorize (chains to SF login), SF callback,
                        token endpoint with PKCE, JWT issuance.
                        sfrefresh.go handles SF token refresh.
  mcptools/             MCP tool definitions (6 tools) and handlers.
                        Auth middleware validates JWT, injects user ID.
                        Auto-refreshes SF tokens on 401.
  audit/                Structured JSON logger (slog) to stdout.
  config/               Env var loading and validation.
```

The root-level `main.go`, `auth.go`, `salesforce.go`, `format.go` are the legacy CLI. They are independent of the `internal/` packages.

## Key Architecture Decisions

- **Dual OAuth**: The server is both an OAuth 2.1 AS (for claude.ai) and an SF OAuth client. Claude.ai authenticates to us, we authenticate to SF on behalf of the user. The two flows chain during login via an `auth_session` that correlates the MCP authorization request with the SF callback.

- **Token chain on each MCP call**: JWT (from claude.ai) -> extract user_id -> look up encrypted SF tokens from DB -> decrypt -> create sfclient.Client -> call SF API. If SF returns 401, refresh the token and retry once.

- **SF tokens encrypted at rest**: AES-256-GCM with a server-side key (`TOKEN_ENCRYPTION_KEY`). Nonce prepended to ciphertext.

- **JWT**: HMAC-SHA256, standard library only. 1 hour TTL. Refresh tokens rotated on use (old one revoked).

## Testing

`internal/mcptools/tools_test.go` has a full end-to-end test (`TestEndToEnd`) that mocks Salesforce and exercises: DCR -> authorize -> SF callback -> token exchange -> refresh token rotation. No real SF org needed.

`internal/sfclient/` and `internal/store/` have unit tests with httptest mocks and temp SQLite DBs respectively.
