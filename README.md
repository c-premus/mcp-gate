<p align="center">
  <img src="https://raw.githubusercontent.com/c-premus/mcp-gate/main/docs/assets/logo.png" alt="mcp-gate logo" width="128" height="128">
</p>

<h1 align="center">mcp-gate</h1>

<p align="center">
  <strong>OAuth 2.1 in front of any MCP server, without touching it.</strong>
</p>

<p align="center">
  <a href="https://github.com/c-premus/mcp-gate/actions/workflows/ci.yaml"><img src="https://github.com/c-premus/mcp-gate/actions/workflows/ci.yaml/badge.svg" alt="CI"></a>
  <a href="https://github.com/c-premus/mcp-gate/tags"><img src="https://img.shields.io/github/v/tag/c-premus/mcp-gate?label=release&sort=semver" alt="Release"></a>
  <a href="https://github.com/c-premus/mcp-gate/blob/main/go.mod"><img src="https://img.shields.io/badge/go-1.27-00ADD8?logo=go&logoColor=white" alt="Go 1.27"></a>
  <a href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization"><img src="https://img.shields.io/badge/MCP-2026--07--28-3b82f6" alt="MCP authorization 2026-07-28"></a>
  <a href="https://github.com/c-premus/mcp-gate/blob/main/LICENSE"><img src="https://img.shields.io/github/license/c-premus/mcp-gate" alt="License"></a>
  <br>
  <a href="https://hub.docker.com/r/cpremus/mcp-gate"><img src="https://img.shields.io/docker/pulls/cpremus/mcp-gate?logo=docker&logoColor=white" alt="Docker pulls"></a>
  <a href="https://hub.docker.com/r/cpremus/mcp-gate"><img src="https://img.shields.io/docker/image-size/cpremus/mcp-gate?sort=semver&label=image%20size" alt="Image size"></a>
  <a href="https://github.com/c-premus/mcp-gate/pkgs/container/mcp-gate"><img src="https://img.shields.io/badge/ghcr.io-c--premus%2Fmcp--gate-24292f?logo=github" alt="GHCR image"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#connecting-a-client">Connecting a client</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="https://github.com/c-premus/mcp-gate/blob/main/docs/setup.md">Setup Guide</a>
</p>

OAuth 2.1 reverse proxy for MCP servers. Implements [RFC 9728 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) and JWT validation, delegating authentication to an external authorization server.

**Read the blog post**: [I couldn't find an OAuth 2.1 proxy for MCP servers, so I built one](https://dev.to/cpremus/i-couldnt-find-an-oauth-21-proxy-for-mcp-servers-so-i-built-one-59nd)

## What it does

`mcp-gate` sits in front of any HTTP MCP server and adds the resource-server side of the [MCP Authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (2026-07-28), which Claude.ai custom connectors require:

1. **`/.well-known/oauth-protected-resource`** — RFC 9728 metadata pointing clients to the authorization server (`GET` and `HEAD`). When `RESOURCE_URI` has a path, the document is also served at the RFC 9728 §3.1 path-inserted URL, e.g. `/.well-known/oauth-protected-resource/mcp`.
2. **`/healthz`** — Readiness check for container orchestration; returns 200 once signing keys are loaded.
3. **`/*`** — Validates the Bearer JWT against the provider's JWKS, then reverse-proxies to the upstream MCP server.

Prometheus metrics are served on a separate listener (`METRICS_ADDR`, default `:9090`) at `/metrics`.

## Features

- **Token validation**: RS256 only; signature, `exp`, `iss`, `aud` (string or array), and `sub` are required; 30-second clock-skew leeway. `typ` must be an access-token type (`at+jwt`, `application/at+jwt`, or `JWT` unless `STRICT_TOKEN_TYP=true`); tokens with a `crit` header or a `cnf` (sender-constrained) claim are refused.
- **Scopes**: required scopes are matched hierarchy-aware, so a granted `files` satisfies a required `files:read` (never the reverse). The `scope` claim is accepted as a space-delimited string or a JSON array.
- **Challenges**: RFC 6750 `WWW-Authenticate` on 401/403, carrying `realm`, `resource_metadata`, and `scope`; a malformed `Authorization` header (duplicated, or `Bearer` with no token) gets `400 invalid_request`.
- **Credential isolation**: the client's `Authorization` and `Cookie` headers are stripped before proxying, and an `access_token` query parameter is removed and logged. The upstream authenticates with its own credentials.
- **Streaming**: SSE responses are flushed immediately, with an idle timeout (`SSE_IDLE_TIMEOUT`) for silent streams.
- **Abuse limits**: per-IP rate and concurrency limits, a global connection cap, and a request body cap that returns 413. The rate limiter can optionally use Redis (see below).
- **Optional Origin validation** (`ALLOWED_ORIGINS`) for deployments exposed to DNS rebinding. It is off by default.
- **Observability**: structured JSON logs, Prometheus metrics, and optional OpenTelemetry tracing. A Grafana dashboard and alert rules are included.

MCP headers (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`) are forwarded verbatim. mcp-gate records them in metrics and logs but never acts on them.

## Why not oauth2-proxy or FastMCP?

Both came up when I was looking for something to put in front of an MCP server, and both are good at what they're built for.

**oauth2-proxy** is built around browser sessions: an unauthenticated request is redirected to a login page, and a successful login becomes a session cookie. It can also accept bearer JWTs (`--skip-jwt-bearer-tokens`), but at the time of writing it doesn't serve RFC 9728 Protected Resource Metadata or send the `resource_metadata` challenge that MCP clients use to find the authorization server. Without that, Claude.ai has no way to start the OAuth flow. If you're protecting a web app that people log into in a browser, use oauth2-proxy.

**FastMCP** does implement the resource-server side: `RemoteAuthProvider` with a `JWTVerifier` serves RFC 9728 metadata and validates JWTs against a JWKS, and `create_proxy` can front a remote MCP server. The difference is the layer. A FastMCP proxy is a Python MCP server that parses JSON-RPC and re-exposes the upstream's tools, and it's configured in code. If you're already writing your MCP server with FastMCP, use its auth and skip mcp-gate.

mcp-gate works at the HTTP layer instead. It validates the token, strips it, and passes the request through untouched. It never parses request bodies, it doesn't care what language the upstream is written in, and it's configured entirely with environment variables. Use it when you want to put auth in front of an MCP server you didn't write, or don't want to change.

## Architecture

```
Claude.ai → Reverse Proxy → mcp-gate (JWT validation) → MCP Server → Backend
                                 ↕
                         Authorization Server (OAuth 2.1 / OIDC)
```

## Quick Start

```bash
export LISTEN_ADDR=0.0.0.0:8080
export UPSTREAM_URL=http://mcp-server:8000
export RESOURCE_URI=https://mcp.example.com
export AUTHORIZATION_SERVER=https://auth.example.com/application/o/mcp/
export JWKS_URI=https://auth.example.com/application/o/mcp/jwks/
export EXPECTED_ISSUER=https://auth.example.com/application/o/mcp/
export EXPECTED_AUDIENCE=your-client-id

go run ./cmd/mcp-gate
```

## Docker

```bash
docker pull ghcr.io/c-premus/mcp-gate:0.21   # or: docker pull cpremus/mcp-gate:0.21

docker run -d --name mcp-gate -p 8080:8080 -p 9090:9090 \
  --env-file mcp-gate.env \
  cpremus/mcp-gate:0.21
```

Images are published to [Docker Hub](https://hub.docker.com/r/cpremus/mcp-gate) and [GHCR](https://github.com/c-premus/mcp-gate/pkgs/container/mcp-gate) (`ghcr.io/c-premus/mcp-gate`) on each release, for `linux/amd64`. Tags are `X.Y.Z`, `X.Y`, and `latest`, with no `v` prefix (for example `0.21.8`). Pin a version rather than tracking `latest`.

A Compose example is in [`docker-compose.example.yml`](docker-compose.example.yml).

## Connecting a client

Point the client at your public `RESOURCE_URI`. The client finds the authorization server through mcp-gate's 401 challenge and the RFC 9728 metadata, so mcp-gate itself needs no client-side configuration. The examples below assume an OAuth client you've registered yourself, which is what you need when dynamic client registration isn't enabled on your identity provider.

**Claude.ai**: add a custom connector with the URL, the client ID and the client secret, and register `https://claude.ai/api/mcp/auth_callback` as the client's redirect URI. Step-by-step instructions are in the [Setup Guide](docs/setup.md#step-4-connect-claudeai).

**Claude Code**: register `http://localhost:PORT/callback` as a redirect URI (pick any free port), then pass the same port when adding the server:

```bash
claude mcp add --transport http \
  --client-id your-client-id --client-secret --callback-port 8080 \
  mcp-gate https://mcp.example.com
```

`--client-secret` asks for the secret at the prompt; leave it out for a public client. Run `/mcp` in a session, or `claude mcp login mcp-gate`, to sign in. See the [Claude Code MCP docs](https://code.claude.com/docs/en/mcp) for the details.

## Setup

See the **[Setup Guide](https://github.com/c-premus/mcp-gate/blob/main/docs/setup.md)** for step-by-step instructions on:

1. Creating an OAuth client in your OIDC provider (Keycloak, Authentik, Okta, Auth0, etc.)
2. Configuring mcp-gate
3. Connecting Claude.ai to the protected MCP server

## Configuration

All configuration is via environment variables. There are no config files. See the [Setup Guide](https://github.com/c-premus/mcp-gate/blob/main/docs/setup.md#environment-variables) for the full list.

### Horizontal scaling

mcp-gate validates JWTs statelessly and is safe to run as multiple replicas behind a load balancer. The per-IP rate limiter defaults to in-memory state, which means the configured RPS holds *per replica*. Set `REDIS_ADDR=host:port` to back the limiter with Redis so the configured RPS is enforced globally across replicas. `REDIS_USERNAME`, `REDIS_PASSWORD`, and `REDIS_DB` are read separately so Vault can inject a password as a single secret. Redis errors fail open (the request passes through and a counter is incremented) so a Redis hiccup never blackholes user traffic.

## Observability

Every request is logged as structured JSON (`method`, `path`, `status`, `duration_ms`, `client_ip`, `user_agent`). `mcp_method`, `mcp_name`, and `mcp_name_encoded` are added when the client sends the corresponding MCP headers.

Metrics use the `mcpgate_` prefix. `mcpgate_info{version="…"}` reports the running build. Its `version` label keeps the release tag's `v` prefix (`v0.21.8`), which the image tag drops.

[`docs/grafana/`](docs/grafana/) contains a provisionable dashboard and alert rules. Both expect a Prometheus job named `mcp-gate` and a `service` target label on each gate. See [Monitoring](https://github.com/c-premus/mcp-gate/blob/main/docs/setup.md#monitoring) in the Setup Guide.

## License

MIT
