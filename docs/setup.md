# Setting Up mcp-gate with Claude.ai

mcp-gate is an OAuth 2.1 reverse proxy for MCP servers. It sits in front of any MCP server and handles JWT-based authentication, so the upstream server does not need to implement auth itself. Claude.ai discovers mcp-gate's auth requirements automatically via RFC 9728 metadata.

Architecture:

```
Claude.ai --> Reverse Proxy (optional) --> mcp-gate --> MCP Server --> Backend
```

This guide covers two things: creating an OAuth client in your OIDC provider, and connecting Claude.ai to the protected MCP server.

## Prerequisites

- An MCP server running and reachable from mcp-gate over HTTP
- An OIDC/OAuth 2.1 provider (Keycloak, Authentik, Okta, Auth0, or similar)
- A public HTTPS domain for mcp-gate (e.g., `mcp.example.com`)
- The `mcp-gate` binary or Docker image (`cpremus/mcp-gate:latest`)

## Step 1: Create an OAuth Client

Create a new OAuth/OIDC client (sometimes called an "application" or "app integration") in your provider with these settings:

### Required Settings

| Setting | Value |
|---------|-------|
| **Client type** | Confidential (has a client secret) |
| **Grant type** | Authorization Code with PKCE |
| **PKCE method** | S256 (required by OAuth 2.1) |
| **Redirect URI** | `https://claude.ai/api/mcp/auth_callback` |
| **Scopes** | `openid` at minimum |
| **Token format** | JWT, signed with RS256 |

### Provider-specific terminology

The settings above go by different names depending on your provider:

- **Keycloak**: Create a new Client. Set "Client authentication" to On (confidential). Under "Authentication flow", enable "Standard flow" (Authorization Code). PKCE is configured under Advanced Settings. Keycloak issues JWTs by default.
- **Authentik**: Create a new Provider (OAuth2/OIDC), then create an Application linked to it. Set the client type to Confidential. Authentik supports PKCE and JWT access tokens by default.
- **Okta**: Create a new App Integration with "OIDC - OpenID Connect" sign-in method and "Web Application" type. Enable "Authorization Code" grant type. Under General Settings, set "Proof Key for Code Exchange (PKCE)" to Required.
- **Auth0**: Create a new Application of type "Regular Web Application". Authorization Code with PKCE is the default. Go to APIs and ensure the API's token format is set to JWT (not opaque).

### Scopes

mcp-gate requires at least `openid` by default. If you set `REQUIRED_SCOPES` on mcp-gate to additional values (e.g., `openid,profile,email`), the OAuth client must be authorized to issue those scopes.

### Token signing

mcp-gate validates tokens using RS256 only. If your provider defaults to a different signing algorithm (e.g., HS256, ES256), change it to RS256. The provider must expose a JWKS endpoint that mcp-gate can reach over HTTPS.

## Step 2: Collect Provider Details

After creating the client, gather these values:

| Value | Where to find it | Used by |
|-------|-------------------|---------|
| **Client ID** | Shown after client creation | mcp-gate (`EXPECTED_AUDIENCE`) + Claude.ai |
| **Client Secret** | Shown after client creation | Claude.ai only |
| **Issuer URL** | Provider's OIDC discovery page or docs | mcp-gate (`EXPECTED_ISSUER`, `AUTHORIZATION_SERVER`) |
| **JWKS URI** | `<issuer>/.well-known/openid-configuration` under `jwks_uri` | mcp-gate (`JWKS_URI`) |

To find the JWKS URI, fetch your provider's OpenID configuration:

```bash
curl -s https://auth.example.com/.well-known/openid-configuration | jq '.jwks_uri'
```

In many providers, the issuer URL and the authorization server URL are the same value. Check your provider's OIDC discovery document to confirm the `issuer` field matches what appears in issued tokens.

**Note**: mcp-gate never sees the client secret. It validates tokens using the public keys from the JWKS endpoint. The client secret is only entered in Claude.ai, which uses it to exchange authorization codes for tokens.

## Step 3: Configure and Run mcp-gate

### Environment Variables

**Required:**

| Variable | Description | Example |
|----------|-------------|---------|
| `LISTEN_ADDR` | Address to bind | `0.0.0.0:8080` |
| `UPSTREAM_URL` | MCP server URL | `http://mcp-server:8000` |
| `RESOURCE_URI` | Public URL of mcp-gate | `https://mcp.example.com` |
| `AUTHORIZATION_SERVER` | OAuth provider URL | `https://auth.example.com/realms/main` |
| `JWKS_URI` | Provider's JWKS endpoint | `https://auth.example.com/realms/main/protocol/openid-connect/certs` |
| `EXPECTED_ISSUER` | JWT `iss` claim value | `https://auth.example.com/realms/main` |
| `EXPECTED_AUDIENCE` | JWT `aud` claim value (= client ID) | `mcp-gate-client` |

**Optional:**

| Variable | Default | Description |
|----------|---------|-------------|
| `REQUIRED_SCOPES` | `openid` | Comma-separated scopes required in the JWT |
| `SCOPES_SUPPORTED` | `openid,profile` | Scopes advertised in RFC 9728 metadata |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `METRICS_ADDR` | `:9090` | Prometheus metrics bind address |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated CIDRs for trusted reverse proxies |
| `RATE_LIMIT_RPS` | `10` | Per-IP requests per second |
| `RATE_LIMIT_BURST` | `20` | Per-IP burst allowance |
| `MAX_CONCURRENT_REQUESTS` | `100` | Max concurrent requests per IP |
| `MAX_TOTAL_CONNECTIONS` | `1000` | Max total connections |
| `MAX_REQUEST_BODY` | `10485760` | Max request body in bytes (10 MB) |

### Docker

```bash
docker run -d \
  --name mcp-gate \
  -p 8080:8080 \
  -e LISTEN_ADDR=0.0.0.0:8080 \
  -e UPSTREAM_URL=http://mcp-server:8000 \
  -e RESOURCE_URI=https://mcp.example.com \
  -e AUTHORIZATION_SERVER=https://auth.example.com/realms/main \
  -e JWKS_URI=https://auth.example.com/realms/main/protocol/openid-connect/certs \
  -e EXPECTED_ISSUER=https://auth.example.com/realms/main \
  -e EXPECTED_AUDIENCE=mcp-gate-client \
  cpremus/mcp-gate:latest
```

### Binary

```bash
export LISTEN_ADDR=0.0.0.0:8080
export UPSTREAM_URL=http://localhost:8000
export RESOURCE_URI=https://mcp.example.com
export AUTHORIZATION_SERVER=https://auth.example.com/realms/main
export JWKS_URI=https://auth.example.com/realms/main/protocol/openid-connect/certs
export EXPECTED_ISSUER=https://auth.example.com/realms/main
export EXPECTED_AUDIENCE=mcp-gate-client

./mcp-gate
```

### Verify mcp-gate is running

Check the health endpoint:

```bash
curl http://localhost:8080/healthz
# Expected: ok
```

Check the RFC 9728 metadata endpoint:

```bash
curl -s http://localhost:8080/.well-known/oauth-protected-resource | jq .
```

Expected output:

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://auth.example.com/realms/main"],
  "scopes_supported": ["openid", "profile"],
  "bearer_methods_supported": ["header"]
}
```

If `/healthz` returns 503, mcp-gate could not fetch keys from the JWKS endpoint. Check that `JWKS_URI` is reachable and uses HTTPS.

## Step 4: Connect Claude.ai

1. Open [Claude.ai](https://claude.ai) and go to **Settings**.
2. Navigate to the **MCP** or **Integrations** section.
3. Click **Add Custom MCP Connector** (or similar).
4. Enter the following:
   - **URL**: The public HTTPS URL of mcp-gate (the same value as `RESOURCE_URI`, e.g., `https://mcp.example.com`)
   - **Client ID**: The OAuth client ID from Step 2
   - **Client Secret**: The OAuth client secret from Step 2
5. Save the connector.

Claude.ai performs the rest automatically:

1. It fetches `https://mcp.example.com/.well-known/oauth-protected-resource`
2. It discovers the authorization server from the metadata response
3. It fetches the provider's `/.well-known/openid-configuration` to find the authorization and token endpoints

When you start a conversation that uses the MCP connector, Claude.ai will redirect you to your OAuth provider's login page. After you authenticate, Claude.ai receives a JWT and includes it as a Bearer token in requests to mcp-gate.

## How the Auth Flow Works

```
1. User adds connector in Claude.ai (URL + client ID + secret)
2. Claude.ai fetches /.well-known/oauth-protected-resource from mcp-gate
3. Claude.ai reads authorization_servers from the metadata
4. Claude.ai fetches /.well-known/openid-configuration from the auth server
5. User initiates an MCP request
6. Claude.ai redirects user to OAuth provider login
7. User authenticates, provider issues a JWT via Authorization Code + PKCE
8. Claude.ai sends MCP requests with Authorization: Bearer <JWT>
9. mcp-gate validates the JWT (signature, expiry, issuer, audience, scopes)
10. mcp-gate strips the Authorization header and proxies to the MCP server
```

The MCP server never sees the user's JWT. mcp-gate removes the `Authorization` header before forwarding requests.

## Troubleshooting

### mcp-gate fails to start

**"JWKS initial fetch" error**: mcp-gate could not reach the JWKS endpoint. Verify:
- `JWKS_URI` is correct and uses `https://`
- The JWKS endpoint is reachable from the mcp-gate container/host
- DNS resolution works (common issue in Docker networks)

**"required environment variable X is not set"**: A required env var is missing. See the table in Step 3.

### 401 Unauthorized: "The access token is invalid or expired"

Set `LOG_LEVEL=debug` and check the logs for the specific rejection reason.

**Wrong audience**: The `aud` claim in the JWT does not match `EXPECTED_AUDIENCE`. The audience should be the OAuth client ID. Some providers require explicit audience configuration on the client.

**Wrong issuer**: The `iss` claim does not match `EXPECTED_ISSUER`. Fetch a token and decode it at [jwt.io](https://jwt.io) to see the actual issuer value.

**Expired token**: The token's `exp` claim is in the past (mcp-gate allows 30 seconds of clock skew). Check clock sync between your systems.

**Wrong signing algorithm**: mcp-gate accepts RS256 only. If the provider signs tokens with a different algorithm, change the provider's signing configuration.

**Unknown key ID**: The token's `kid` header does not match any key in the JWKS. This can happen after a key rotation. mcp-gate refreshes JWKS keys at most once per minute for unknown key IDs.

### 403 Forbidden: "Required scope not granted"

The token does not contain a required scope. Decode the JWT and check the `scope` claim. Ensure:
- The OAuth client is authorized for the scopes listed in `REQUIRED_SCOPES`
- The user has consented to the scopes
- The provider includes the `scope` claim in access tokens (some providers omit it by default)

### Claude.ai cannot discover the auth server

- Confirm `RESOURCE_URI` matches the URL entered in Claude.ai (including scheme and no trailing slash)
- Test the metadata endpoint from a public network: `curl https://mcp.example.com/.well-known/oauth-protected-resource`
- Verify `AUTHORIZATION_SERVER` points to a valid OIDC provider that serves `/.well-known/openid-configuration`

### Claude.ai shows "redirect_uri mismatch"

The OAuth client's allowed redirect URIs must include `https://claude.ai/api/mcp/auth_callback` exactly. Check for typos, trailing slashes, or scheme mismatches.

### 502 Bad Gateway

mcp-gate cannot reach the upstream MCP server. Verify:
- `UPSTREAM_URL` is correct
- The MCP server is running and accepting connections
- Network connectivity exists between mcp-gate and the MCP server (check Docker networks, firewall rules)

### Reverse Proxy Considerations

If mcp-gate is behind a reverse proxy (e.g., Traefik, nginx, Caddy):

- Set `TRUSTED_PROXIES` to the proxy's IP or CIDR so mcp-gate reads the real client IP from `X-Forwarded-For` / `X-Real-IP`
- Make sure the reverse proxy forwards the `Authorization` header
- Do not configure the reverse proxy to return custom error pages for 401/403 responses -- these responses contain OAuth-required `WWW-Authenticate` headers that Claude.ai needs
