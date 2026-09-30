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
- The Docker image (`cpremus/mcp-gate` or `ghcr.io/c-premus/mcp-gate`) or a binary built from source

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

Scope matching is hierarchy-aware, as MCP 2026-07-28 requires: a granted scope that is a `:`-delimited prefix of a required one satisfies it, so a token carrying `files` satisfies a required `files:read`. It never works the other way round (`files:read` does not satisfy `files`), and the prefix must end at the `:` (`file` does not satisfy `files:read`). For providers that issue flat scopes such as `openid` and `profile`, this reduces to exact matching. The `scope` claim is accepted either as a space-delimited string (RFC 6749 §3.3) or as a JSON array.

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
| `EXPECTED_AUDIENCE` | JWT `aud` claim value (usually the client ID — see below) | `mcp-gate-client` |

**Optional:**

| Variable | Default | Description |
|----------|---------|-------------|
| `REQUIRED_SCOPES` | `openid` | Comma-separated scopes required in the JWT (hierarchy-aware, see Scopes above). Named in the `scope=` of the 403 challenge |
| `SCOPES_SUPPORTED` | `openid,profile` | Scopes advertised in RFC 9728 metadata and in the `scope=` of both 401 challenges |
| `AUTH_REALM` | *(RESOURCE_URI host)* | Protection space name in the `WWW-Authenticate` challenge. Defaults to the `RESOURCE_URI` hostname, so each deployment names its own resource |
| `RESOURCE_DOCUMENTATION` | `https://github.com/c-premus/mcp-gate` | `resource_documentation` URL in RFC 9728 metadata. Point this at your protected resource's own docs |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `METRICS_ADDR` | `:9090` | Prometheus metrics bind address |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated CIDRs for trusted reverse proxies. A bare IP is treated as `/32` or `/128`; catch-all `0.0.0.0/0` and `::/0` are refused at startup |
| `ALLOWED_ORIGINS` | *(empty)* | Comma-separated browser origins (e.g. `https://claude.ai`). Empty disables Origin validation. See "DNS rebinding" below |
| `RATE_LIMIT_RPS` | `10` | Per-IP requests per second |
| `RATE_LIMIT_BURST` | `20` | Per-IP burst allowance |
| `MAX_CONCURRENT_REQUESTS` | `100` | Max in-flight requests per IP (over the limit: `503`) |
| `MAX_TOTAL_CONNECTIONS` | `1000` | Max in-flight requests across all IPs (over the limit: `503`) |
| `MAX_REQUEST_BODY` | `10485760` | Max request body in bytes (10 MB). Larger bodies get `413 payload_too_large` |
| `UPSTREAM_TIMEOUT` | `120s` | Time to wait for the upstream's response headers |
| `READ_TIMEOUT` | `30s` | Inbound request read timeout |
| `IDLE_TIMEOUT` | `120s` | Keep-alive idle timeout |
| `MAX_HEADER_BYTES` | `131072` | Max request header size in bytes (128 KB) |
| `SSE_IDLE_TIMEOUT` | `5m` | Force-close an SSE response stream after this much silence. Surfaces as `mcpgate_sse_disconnects_total{reason="idle_timeout"}` |
| `JWKS_REFRESH_INTERVAL` | `1h` | Background JWKS refresh interval |
| `SHUTDOWN_TIMEOUT` | `30s` | Graceful shutdown drain timeout, applied independently per stage |
| `RESOURCE_NAME` | `MCP Server` | Human-readable `resource_name` in RFC 9728 metadata |

**About `EXPECTED_AUDIENCE`**: MCP 2026-07-28 (via RFC 8707) wants tokens bound to the resource's canonical URI, i.e. `aud` equal to `RESOURCE_URI`. Many providers ignore the `resource` parameter and put the client ID in `aud` instead, which is why this guide uses the client ID. When `EXPECTED_AUDIENCE` differs from `RESOURCE_URI`, mcp-gate logs `audience not bound to canonical resource URI` at startup as a warning. If your provider can issue `aud=<RESOURCE_URI>`, set `EXPECTED_AUDIENCE` to that value.

**Path-mounted resources**: if `RESOURCE_URI` has a path (e.g. `https://example.com/mcp`), the metadata document is also served at the RFC 9728 §3.1 path-inserted URL `/.well-known/oauth-protected-resource/mcp`, and the challenges point there. Other paths under the well-known prefix return `404`.

### Distributed rate limiting (optional)

Unset, the rate limiter is an in-process token bucket — which is **per-replica**:
N replicas allow N × `RATE_LIMIT_RPS` per client. Setting `REDIS_ADDR` switches it
to a Redis-backed GCRA limiter that coordinates globally.

The variable is `REDIS_ADDR` (a bare `host:port`), **not** `REDIS_URL`. Each value
is its own variable so a secrets manager can inject `REDIS_PASSWORD` verbatim:
`:`, `@`, `/`, `#` and `?` are all valid in a Redis ACL password and all reserved
in URL syntax, so rotation tooling that does not percent-encode breaks auth
silently at the next rotation.

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_ADDR` | *(empty)* | `host:port`. Empty = in-memory limiter |
| `REDIS_USERNAME` | *(empty)* | Redis 6+ ACL username (empty = legacy `default` user) |
| `REDIS_PASSWORD` | *(empty)* | Redis password |
| `REDIS_DB` | `0` | Logical database index |
| `REDIS_TIMEOUT` | `100ms` | Per-call deadline; **fails open** beyond it |
| `REDIS_KEY_PREFIX` | `mcpgate:rl:` | Bucket key prefix (redis_rate prepends its own `rate:`) |

The limiter **fails open**: on a Redis timeout or outage the request is forwarded
and `mcpgate_ratelimit_redis_errors_total{kind}` is incremented, rather than the
proxy going down with its rate limiter. If you rely on Redis, alert on that
counter — a silent Redis outage otherwise degrades to per-replica limiting with
no other signal.

### Tracing (optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(empty)* | OTLP **HTTP** endpoint, e.g. `http://alloy:4318`. Empty disables tracing. This is the *generic* OTLP variable, so when the URL has no path mcp-gate appends `/v1/traces`; a URL with an explicit path is used as-is |
| `OTEL_SERVICE_NAME` | `mcp-gate` | Service name in traces. Use the same value as the gate's Prometheus `service` label and Loki `service_name` — see "Running several gates" |
| `OTEL_TRACE_SAMPLE_RATE` | `1.0` | Sampling rate, 0.0–1.0. Parent-based: applies to root spans; an incoming sampled `traceparent` is honoured |

An `http://` endpoint disables TLS; anything else uses it. Export failures are
not surfaced on `/healthz` or by any metric, so verify tracing by looking for
spans in your backend rather than by the absence of errors.

**Timeout notes**: MCP connections are long-lived (SSE/streamable-http). `UPSTREAM_TIMEOUT` controls how long mcp-gate waits for the upstream MCP server to send its response headers — complex queries (e.g., PromQL range queries over weeks of data) may need the full 120s default. `IDLE_TIMEOUT` controls how long idle keep-alive connections stay open between MCP tool calls.

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
  cpremus/mcp-gate:0.20
```

Images are published for `linux/amd64` to Docker Hub (`cpremus/mcp-gate`) and GHCR (`ghcr.io/c-premus/mcp-gate`). Tags are `X.Y.Z`, `X.Y` and `latest`, with no `v` prefix. Pin a version: a floating `latest` makes "which build is running?" hard to answer, and it is the question the bundled alert rules ask.

The image's `HEALTHCHECK` runs `/mcp-gate healthcheck`, a built-in subcommand that probes `/healthz` on `LISTEN_ADDR` (the image has no shell or curl).

### Binary

No prebuilt binaries are published. Build one from source and stamp the version, or the build reports `version="dev"` in `mcpgate_info` (and the bundled "Running an Unidentified Build" alert fires):

```bash
go build -ldflags "-X main.version=$(git describe --tags --always)" -o mcp-gate ./cmd/mcp-gate
```

Then run it:

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
  "bearer_methods_supported": ["header"],
  "resource_name": "MCP Server",
  "resource_documentation": "https://github.com/c-premus/mcp-gate"
}
```

mcp-gate fetches the JWKS once at startup and exits if that fails (see Troubleshooting), so a running gate had keys when it started. `/healthz` returns `503` (body `unavailable`) if the key store later becomes empty. `/healthz` is also subject to the rate and concurrency limits, so a busy gate can return `429` or `503` to probes. The metrics port (`:9090`) also serves a `/healthz`, but that one always returns 200 and only shows the process is alive.

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
9. mcp-gate validates the JWT (signature, expiry, issuer, audience, subject, scopes)
10. mcp-gate strips the Authorization header and proxies to the MCP server
```

The MCP server never sees the user's JWT. Before forwarding, mcp-gate removes:

- the `Authorization` and `Cookie` headers;
- an `access_token` query parameter, which OAuth 2.1 and MCP disallow. Its removal is logged as a warning and counted in `mcpgate_deprecated_access_token_query_total`, and the token is never validated from the query string;
- hop-by-hop headers. Client-supplied `Forwarded` and `X-Forwarded-*` headers are discarded, and `X-Forwarded-For`, `-Host` and `-Proto` are set from the actual connection.

On the response path, mcp-gate drops the upstream's `Server` and `X-Powered-By` headers. It also replaces any upstream `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` and `Referrer-Policy` with its own values, because a duplicated `X-Frame-Options` is ignored by browsers.

## Monitoring

mcp-gate serves Prometheus metrics on `METRICS_ADDR` (default `:9090`, path `/metrics`), separate from the proxy port so the metrics endpoint is never exposed publicly.

### Scrape configuration

```yaml
scrape_configs:
  - job_name: "mcp-gate"
    static_configs:
      - targets: ["mcp-gate:9090"]
        labels:
          service: "mcp-gate"
```

Keep the job name `mcp-gate`: the bundled dashboard and every alert rule select on `job="mcp-gate"`.

### Running several gates

One mcp-gate fronts one upstream, so protecting several MCP servers means running several gates. Scrape them as **one job with one target group per gate**, and give each a `service` label set to that gate's `OTEL_SERVICE_NAME`:

```yaml
scrape_configs:
  - job_name: "mcp-gate"
    static_configs:
      - targets: ["mcp-gate:9090"]
        labels:
          service: "mcp-gate"          # OTEL_SERVICE_NAME of this gate
      - targets: ["mcp-gate-forgejo:9090"]
        labels:
          service: "mcp-gate-forgejo"  # OTEL_SERVICE_NAME of that gate
```

Using `OTEL_SERVICE_NAME` as the value is what makes one identity work across all three signals. mcp-gate itself only emits it as `resource.service.name` on traces. The Prometheus `service` label comes from your scrape config (above), and the Loki `service_name` stream label comes from your log shipper (Alloy, Promtail, etc.), because mcp-gate writes plain JSON to stdout. Set all three to the same value. The bundled dashboard's **Gate** variable is populated from `mcpgate_info`, and every panel — metrics, logs and traces alike — filters on it, so a single selector drives all three.

This label is a contract, not a convention:

- **The dashboard requires it.** Selecting "All" expands to the list of `service` values actually present. If no gate sets the label there is nothing to expand to, and the log panels in particular will not render — Loki rejects a stream selector that could match the empty string, and has no `job` label to fall back on.
- **The alert rules use it too**, but degrade quietly. The JWKS and target-down rules keep one alert instance per series, so each instance carries its gate's labels. The upstream-error-ratio and auth-failure rules aggregate `by (service)` and put the label in the summary. Without the label, those two produce a single instance whose summary reads `mcp-gate`, which is the single-gate behaviour. The two release rules (unidentified build, gates on different versions) compare gates on purpose and do not split by `service`.

Note that the alert rules deliberately carry no `service` label of their own. Grafana applies rule labels *on top of* query labels, so a hardcoded one would overwrite the scraped value and attribute every gate's alerts to the same instance.

### Dashboard and alerts

Provisioning artifacts ship in the repo:

| File | Copy to |
|------|---------|
| `docs/grafana/dashboard.json` | Grafana's dashboard provisioning directory |
| `docs/grafana/alerts.yaml` | Grafana's `alerting/` provisioning directory |

The dashboard is generated. Edit the TypeScript under `grafana/src/` and run `npm run generate` instead of editing the JSON.

Build panels with the factories in `grafana/src/panels/defaults.ts`, not with the SDK's `PanelBuilder` classes directly. The SDK seeds several required option fields as *explicitly empty* rather than absent — `reduceOptions.calcs: []`, `legend.showLegend: false` — and Grafana honours an empty field instead of falling back to its default, so the panel loads without error and renders nothing. `npm run generate` validates the dashboard before writing it and refuses to emit one that has an empty reducer, a hidden legend on a per-gate panel, a missing unit, or a `gridPos` that overflows or overlaps; `npm run validate` runs the same rules against the committed JSON.

## Troubleshooting

### mcp-gate fails to start

**"JWKS initial fetch" error**: mcp-gate could not reach the JWKS endpoint. (A non-`https://` `JWKS_URI` is rejected earlier, during config validation.) Verify:
- `JWKS_URI` is correct
- The JWKS endpoint is reachable from the mcp-gate container/host
- DNS resolution works (common issue in Docker networks)

**"required environment variable X is not set"**: A required env var is missing. See the table in Step 3.

### 401 Unauthorized: "The access token is invalid or expired"

Each rejection is logged at `warn` with a `category` field (`expired`, `wrong_audience`, `wrong_issuer`, `malformed`, …). `LOG_LEVEL=debug` adds the library's raw error message.

**Missing claims or wrong token type**: tokens without `sub` or `exp` are rejected, as are tokens whose `typ` header is neither `at+jwt` nor `JWT`. Some providers issue opaque (non-JWT) access tokens unless configured otherwise.

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

### 413, 429 and 503

- **413 `payload_too_large`**: the request body exceeded `MAX_REQUEST_BODY`.
- **429 `rate_limit_exceeded`** (with `Retry-After`): the client exceeded `RATE_LIMIT_RPS`/`RATE_LIMIT_BURST`.
- **503 `too_many_connections`** (with `Retry-After`): the client already has `MAX_CONCURRENT_REQUESTS` requests in flight, or `MAX_TOTAL_CONNECTIONS` are open across all clients. Long-lived SSE streams count until they close.

If every client seems to share one limit, `TRUSTED_PROXIES` is probably unset. Without it, mcp-gate sees the reverse proxy's IP as the client for every request.

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
- Make sure the reverse proxy forwards `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, and any `Mcp-Param-*` headers unmodified. MCP 2026-07-28 requires the origin server to reject a request whose headers disagree with its body, so a proxy that strips unknown headers turns every conformant request into a `-32020 HeaderMismatch` error -- and it looks like a bug in the MCP server, not in the proxy

### DNS Rebinding and `ALLOWED_ORIGINS`

MCP 2026-07-28 requires servers to validate the `Origin` header and return
`403` when it is present and not allowed. mcp-gate implements this but leaves
it **disabled by default**, and the choice of whether to enable it depends
entirely on how you have deployed it.

**Leave it unset** if mcp-gate is reachable only over public HTTPS at a real
domain. DNS rebinding requires an attacker to re-point a name your browser
already trusts, which is why the same spec section pairs the requirement with
"when running locally, servers SHOULD bind only to localhost". A public origin
with a real certificate cannot be rebound, and a cross-origin browser cannot
read mcp-gate's responses regardless, because it sends no CORS headers.

**Set it** if mcp-gate fronts an MCP server on a LAN or loopback interface,
where a victim's browser can reach it and rebinding is a live threat:

```bash
ALLOWED_ORIGINS=https://claude.ai,https://claude.com
```

Behavior when configured:

- A request with **no** `Origin` header is allowed. That is the spec's own
  carve-out, and it is what keeps every non-browser MCP client working.
- Matching is **exact** on scheme, host, and port, after lowercasing scheme and
  host. No wildcards -- `https://*.example.com` is rejected at startup rather
  than accepted and silently matching nothing. Suffix matching is the classic
  way origin checks fail open, so `https://claude.ai.evil.example` is refused.
- The port is part of the origin. Browsers omit the default port, so list
  `https://example.com`, not `https://example.com:443`, unless the client
  really sends the explicit form.
- `null` (the opaque origin) is refused in the allow-list: it is shared by every
  sandboxed iframe and `file://` document.
- `/healthz` is exempt, deliberately. If the liveness probe could be blocked by
  a bad allow-list, a misconfiguration would take the container down through the
  health check instead of surfacing as a visible `403`.

**Before enabling in production, know the failure mode.** A wrong allow-list
returns `403` on every request while `/healthz` stays green -- container health
checks pass, deploy smoke tests pass, and automatic rollback never fires. Watch
`mcpgate_origin_rejected_total`; it is the only signal you get.
