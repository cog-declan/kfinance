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
| `INBOUND_AUTH_TOKEN` | Yes** | — | Pre-shared token MCP clients must send as `Authorization: Bearer <token>` (at least 32 characters) |
| `ALLOWED_HOSTS` | No | `[]` | JSON list of extra `Host` header values accepted on `/mcp` (e.g. `'["mcp.internal.example"]'`). Loopback hosts and the bind address are always accepted; `fnmatch` wildcards are supported |
| `DANGEROUSLY_ALLOW_UNTRUSTED_UPSTREAM_URLS` | No | `false` | By default `BACKEND_URL`, `AUTH_OKTA_HOST` and `AUTH_REFRESH_URL` must be https URLs on `kfinance.kensho.com` or `kensho.okta.com`. Set to `true` to use other hosts; credentials are sent to them |
| `CORS_ALLOWED_ORIGINS` | No | `[]` | JSON list of browser origins allowed by CORS and by the `/mcp` `Origin` check (e.g. `'["https://app.example"]'`) |

*Either both `AUTH_CLIENT_ID` and `AUTH_PRIVATE_KEY`, or `AUTH_REFRESH_TOKEN` must be set.

**Required when binding to a non-loopback host, unless `--dangerously-allow-unauthenticated-network-access` is passed.

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

In the inspector, connect using URL `http://127.0.0.1:8000/mcp` with transport type "Streamable HTTP". If `INBOUND_AUTH_TOKEN` is set, add an `Authorization: Bearer <token>` header.

| CLI Option | Default | Description |
|-----------|---------|-------------|
| `--host` | `127.0.0.1` | Host to bind to |
| `--port` | `8000` | Port to bind to |
| `--dangerously-allow-unauthenticated-network-access` | off | Allow a non-loopback `--host` without `INBOUND_AUTH_TOKEN`. Only use behind network-level controls |

## Client Authentication

Every request the proxy forwards carries its own kfinance credentials, so anyone who can call the proxy acts as that user. The proxy therefore protects `/mcp` (`GET /health` stays public):

- **Static bearer token** — Set `INBOUND_AUTH_TOKEN` (e.g. from `python -c "import secrets; print(secrets.token_urlsafe(32))"`) and have clients send `Authorization: Bearer <token>`. Requests without it get a 401.
- **Non-loopback binds** — The proxy refuses to start on a non-loopback `--host` (e.g. `0.0.0.0`) without `INBOUND_AUTH_TOKEN`. If access is restricted at the network level instead (VPN, service mesh with mTLS, internal load balancer), pass `--dangerously-allow-unauthenticated-network-access`.
- **Host and Origin validation** — Requests whose `Host` header is not loopback, the bind address or in `ALLOWED_HOSTS` get a 421, and browser requests from origins other than loopback, same-origin or `CORS_ALLOWED_ORIGINS` get a 403. This blocks DNS rebinding. Behind a load balancer or Kubernetes service, add the hostnames clients use to `ALLOWED_HOSTS`.

A static token is shared by all clients. For per-client identities, consider replacing it with FastMCP's `JWTVerifier` (clients bring IdP-issued tokens) or `OAuthProxy`.

## Production Considerations

Beyond client authentication, a production deployment would additionally need:

- A more comprehensive health check (the current `GET /health` stub does not verify backend connectivity or token validity)
- Sentry or equivalent error tracking
- Redis for shared OAuth client state across replicas (if using OAuth proxy)
- Kubernetes deployment manifests and service configuration
