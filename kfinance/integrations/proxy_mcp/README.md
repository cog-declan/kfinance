# Proxy MCP

This is a skeleton MCP proxy server that forwards requests to Kensho's remote LLM-ready API MCP backend and injects authentication tokens into every outgoing request. It is intended as a starting point for building a full production service.

Under the hood, it uses FastMCP's [Proxy Provider](https://gofastmcp.com/servers/providers/proxy), which handles tool/resource/prompt discovery and forwarding between the local server and the remote backend.

## How It Works

The proxy sits between an MCP client and our MCP server at `https://kfinance.kensho.com/integrations/mcp`. It handles token management transparently — clients connect to the proxy without needing to manage OAuth themselves.

```
MCP Client  -->  Proxy (this service)  -->  kfinance.kensho.com/integrations/mcp
                 (injects Bearer token)
```

## Configuration

All configuration is via environment variables (powered by pydantic-settings).

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BACKEND_URL` | No | `https://kfinance.kensho.com/integrations/mcp` | Remote MCP server URL |
| `AUTH_CLIENT_ID` | Yes* | — | Client ID for key pair authentication |
| `AUTH_PRIVATE_KEY` | Yes* | — | Private key for key pair authentication |
| `AUTH_OKTA_HOST` | No | `https://kensho.okta.com` | Okta host URL |
| `AUTH_REFRESH_TOKEN` | Yes* | — | Refresh token for obtaining access tokens (local dev fallback) |
| `AUTH_REFRESH_URL` | No | `https://kfinance.kensho.com/oauth2/refresh` | Token refresh endpoint |
| `PROXY_API_KEY` | No** | — | Pre-shared key MCP clients must send as `Authorization: Bearer <key>` |
| `CORS_ALLOWED_ORIGINS` | No | `[]` | JSON list of browser origins allowed to call the proxy, e.g. `'["https://app.example.com"]'`. Wildcards are rejected. |
| `ALLOWED_HOSTS` | No | `[]` | JSON list of extra `Host` header values to accept (loopback names and the bind address are always accepted), e.g. `'["proxy.internal"]'`. Wildcards are rejected. |

*Either both `AUTH_CLIENT_ID` and `AUTH_PRIVATE_KEY`, or `AUTH_REFRESH_TOKEN` must be set.

**Required when binding to a non-loopback `--host`, unless `--insecure-allow-unauthenticated-non-loopback` is passed.

## Authentication Methods

### Option 1: Refresh Token (for initial experimentation)

The quickest way to get started. Obtain a refresh token from https://kfinance.kensho.com/manual_login/ and set it as an environment variable:

```bash
export AUTH_REFRESH_TOKEN="your-refresh-token"
```

Note that refresh tokens are short-lived and tied to a single user session. For production use cases, a key pair must be used instead.

### Option 2: Key Pair (required for production)

Follow the guide at https://docs.kensho.com/llmreadyapi/python-library/kf-authentication#publicprivate-key to obtain a client ID and private key, then:

```bash
export AUTH_CLIENT_ID="your-client-id"
export AUTH_PRIVATE_KEY="your-private-key"
```

## Running

```bash
python -m kfinance.integrations.proxy_mcp.proxy_mcp --host 127.0.0.1 --port 8000
```

The server starts on `http://127.0.0.1:8000/mcp` using streamable-http transport.

Once the server is running, you can test it with the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector):

```bash
npx @modelcontextprotocol/inspector
```

In the inspector, connect using URL `http://127.0.0.1:8000/mcp` with transport type "Streamable HTTP". If `PROXY_API_KEY` is set, add an `Authorization: Bearer <key>` header.

| CLI Option | Default | Description |
|-----------|---------|-------------|
| `--host` | `127.0.0.1` | Host to bind to |
| `--port` | `8000` | Port to bind to |
| `--insecure-allow-unauthenticated-non-loopback` | off | Allow a non-loopback `--host` without `PROXY_API_KEY`. Only use behind an authenticating gateway. |

## Request Validation

- **Host / Origin**: every request is checked against loopback names, the bind address and `ALLOWED_HOSTS`, and any browser `Origin` against same-origin, loopback and `CORS_ALLOWED_ORIGINS`. Mismatches get `421` / `403`. This blocks DNS-rebinding attacks from web pages. When clients reach the proxy under another hostname or IP (e.g. behind a load balancer or with `--host 0.0.0.0`), add it to `ALLOWED_HOSTS`.
- **CORS**: no cross-origin browser access by default. Origins in `CORS_ALLOWED_ORIGINS` get a CORS grant without credentials.

## Client Authentication

When `PROXY_API_KEY` is set, requests to `/mcp` must carry `Authorization: Bearer <PROXY_API_KEY>`; others get `401`. `GET /health` is always unauthenticated. The inbound key is never forwarded to the backend.

Without `PROXY_API_KEY`, any client that can reach the proxy can use it with the operator's credentials, so the proxy refuses to start on a non-loopback `--host` unless `--insecure-allow-unauthenticated-non-loopback` is passed. For a production deployment, consider one of the following:

- **OAuth 2.0 Proxy** — The proxy runs its own OAuth flow (e.g., via FastMCP's built-in `OAuthProxy`). Clients register, get redirected to an IdP like Okta, and receive scoped tokens. 
- **JWT Validation** — Clients bring their own IdP-issued tokens. The proxy validates them against the IdP's JWKS endpoint (FastMCP provides `JWTVerifier` for this). Simpler than a full OAuth flow but requires clients to obtain tokens independently.
- **API Key / Static Token** — The proxy checks for a pre-shared secret in request headers (built in via `PROXY_API_KEY`). Simple and appropriate for internal services or controlled partner integrations.
- **Network-Level Trust** — No application-layer auth. The proxy is deployed behind a VPN, service mesh (e.g., Istio with mTLS), or internal load balancer so that only trusted services can reach it.

## Production Considerations

Beyond client authentication, a production deployment would additionally need:

- A more comprehensive health check (the current `GET /health` stub does not verify backend connectivity or token validity)
- Sentry or equivalent error tracking
- Redis for shared OAuth client state across replicas (if using OAuth proxy)
- Kubernetes deployment manifests and service configuration
