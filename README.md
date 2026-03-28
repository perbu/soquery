# soquery

MCP server that connects Claude (via claude.ai) to Salesforce. Supports SOQL queries and record CRUD operations with per-user OAuth authentication.

Designed for use with [Claude for Excel](https://support.claude.com/en/articles/12650343-use-claude-for-excel) but works with any MCP client that connects through claude.ai.

## Architecture

```
Excel -> Claude for Excel -> claude.ai -> soquery (MCP server) -> Salesforce API
```

The server acts as both an OAuth 2.1 Authorization Server (for claude.ai) and a Salesforce OAuth client (for per-user SF authentication). When a user connects, they authenticate through Salesforce and the server stores their tokens encrypted at rest.

### MCP Tools

| Tool | Description |
|------|-------------|
| `query` | Execute SOQL queries |
| `describe` | Get field metadata for an SObject |
| `list_objects` | List available Salesforce objects |
| `create_record` | Create a new record |
| `update_record` | Update a record by ID |
| `delete_record` | Delete a record by ID |

## Quick Start

### 1. Prerequisites

- Go 1.25+
- A Salesforce Connected App configured for the Authorization Code flow (see below)

### 2. Build

```bash
go build -o soquery-server ./cmd/soquery-server/
```

### 3. Configure

Copy `.env.example` and fill in the values:

```bash
cp .env.example .env
```

```
PORT=8080
EXTERNAL_URL=https://soquery.example.com

SF_DOMAIN=example.my.salesforce.com
SF_CLIENT_ID=your-connected-app-consumer-key
SF_CLIENT_SECRET=your-connected-app-consumer-secret

DATABASE_URL=sqlite:soquery.db

TOKEN_ENCRYPTION_KEY=<base64-encoded 32 bytes>
JWT_SIGNING_KEY=<base64-encoded 32 bytes>
```

Generate the encryption keys:

```bash
openssl rand -base64 32  # TOKEN_ENCRYPTION_KEY
openssl rand -base64 32  # JWT_SIGNING_KEY
```

### 4. Run

```bash
./soquery-server
```

The server starts on the configured port and logs structured JSON to stdout.

### 5. Connect from claude.ai

1. Go to claude.ai Settings > Integrations > Add custom connector
2. Enter your server URL (e.g., `https://soquery.example.com/mcp`)
3. Claude.ai will register via Dynamic Client Registration and redirect you to Salesforce to log in
4. After login, the connection is active and tools are available in any conversation

## Salesforce Connected App Setup

This app needs the **Authorization Code** OAuth flow (not client credentials) because each user authenticates individually.

### 1. Create the Connected App

- **Setup > App Manager > New Connected App**
- Fill in name and contact email
- **Enable OAuth Settings**:
  - Callback URL: `https://<your-domain>/oauth/sf-callback`
  - Selected OAuth Scopes: `Manage user data via APIs (api)` and `Perform requests at any time (refresh_token, offline_access)`
- Save and wait a few minutes for propagation

### 2. Get Credentials

- **App Manager** > find your app > dropdown > **View**
- Copy **Consumer Key** (`SF_CLIENT_ID`)
- Click **Manage Consumer Details**, verify identity, copy **Consumer Secret** (`SF_CLIENT_SECRET`)

### 3. Set the Domain

`SF_DOMAIN` is your Salesforce My Domain, e.g., `yourcompany.my.salesforce.com`.

## Deployment

### Docker

A pre-built image is available at `ghcr.io/perbu/soquery:latest`.

```bash
docker run -p 8080:8080 --env-file .env ghcr.io/perbu/soquery:latest
```

To build locally instead:

```bash
docker build -t soquery .
docker run -p 8080:8080 --env-file .env soquery
```

### Kubernetes

Manifests are in `k8s/`. Create the secrets first:

```bash
kubectl create secret generic soquery-config \
  --from-literal=external-url=https://soquery.example.com \
  --from-literal=sf-domain=yourcompany.my.salesforce.com

kubectl create secret generic soquery-secrets \
  --from-literal=sf-client-id=<key> \
  --from-literal=sf-client-secret=<secret> \
  --from-literal=database-url=sqlite:/data/soquery.db \
  --from-literal=token-encryption-key=<base64 key> \
  --from-literal=jwt-signing-key=<base64 key>

kubectl apply -f k8s/
```

Update the hostname in `k8s/ingress.yaml` before applying.

### Exposing locally for testing

The server needs to be reachable by your browser (for the SF login redirect) and by claude.ai (for MCP calls). For local testing, use a tunnel:

```bash
ngrok http 8080
```

Set `EXTERNAL_URL` to the ngrok URL.

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/mcp` | POST/GET | MCP Streamable HTTP transport (auth required) |
| `/.well-known/oauth-authorization-server` | GET | OAuth server metadata |
| `/.well-known/oauth-protected-resource` | GET | Protected resource metadata |
| `/oauth/register` | POST | Dynamic Client Registration |
| `/oauth/authorize` | GET | Authorization endpoint (redirects to SF) |
| `/oauth/sf-callback` | GET | Salesforce OAuth callback |
| `/oauth/token` | POST | Token exchange |
| `/healthz` | GET | Liveness probe |
| `/readyz` | GET | Readiness probe |

## Audit Logging

All operations are logged as structured JSON to stdout, suitable for collection by fluentd/fluentbit in k8s. Events include `tool_call`, `auth_start`, `auth_complete`, `auth_fail`, `token_refresh`, and `dcr_register`.

## Legacy CLI

The original read-only CLI tool is still available:

```bash
go build -o soquery .
export SALESFORCE_DOMAIN=yourcompany.my.salesforce.com
export SALESFORCE_CONSUMER_KEY=<key>
export SALESFORCE_CONSUMER_SECRET=<secret>
soquery "SELECT Id, Name FROM Account LIMIT 5"
```

This uses the client credentials flow (service account) and outputs markdown tables.
