# mcp-gate

[![CI](https://github.com/c-premus/mcp-gate/actions/workflows/ci.yaml/badge.svg)](https://github.com/c-premus/mcp-gate/actions/workflows/ci.yaml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/c-premus/mcp-gate)](https://go.dev/)
[![License](https://img.shields.io/github/license/c-premus/mcp-gate)](LICENSE)

OAuth 2.1 reverse proxy for MCP servers. Implements [RFC 9728 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) and JWT validation, delegating authentication to an external authorization server.

**Read the blog post**: [I couldn't find an OAuth 2.1 proxy for MCP servers, so I built one](https://dev.to/cpremus/i-couldnt-find-an-oauth-21-proxy-for-mcp-servers-so-i-built-one-59nd)

## What it does

`mcp-gate` sits in front of any HTTP MCP server and adds the resource-server side of the [MCP Authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (2026-07-28), which Claude.ai custom connectors require:

1. **`/.well-known/oauth-protected-resource`** — RFC 9728 metadata pointing clients to the authorization server (`GET` and `HEAD`). When `RESOURCE_URI` has a path, the document is also served at the RFC 9728 §3.1 path-inserted URL, e.g. `/.well-known/oauth-protected-resource/mcp`.
2. **`/healthz`** — Readiness check for container orchestration; returns 200 once signing keys are loaded.
3. **`/*`** — Validates the Bearer JWT against the provider's JWKS, then reverse-proxies to the upstream MCP server.

Prometheus metrics are served on a separate listener (`METRICS_ADDR`, default `:9090`) at `/metrics`.

## Features

- **Token validation**: RS256 only; signature, `exp`, `iss`, `aud` (string or array), and `sub` are required; 30-second clock-skew leeway.
- **Scopes**: required scopes are matched hierarchy-aware, so a granted `files` satisfies a required `files:read` (never the reverse). The `scope` claim is accepted as a space-delimited string or a JSON array.
- **Challenges**: RFC 6750 `WWW-Authenticate` on 401/403, carrying `realm`, `resource_metadata`, and `scope`.
- **Credential isolation**: the client's `Authorization` and `Cookie` headers are stripped before proxying, and an `access_token` query parameter is removed and logged. The upstream authenticates with its own credentials.
- **Streaming**: SSE responses are flushed immediately, with an idle timeout (`SSE_IDLE_TIMEOUT`) for silent streams.
- **Abuse limits**: per-IP rate and concurrency limits, a global connection cap, and a request body cap that returns 413. The rate limiter can optionally use Redis (see below).
- **Optional Origin validation** (`ALLOWED_ORIGINS`) for deployments exposed to DNS rebinding. It is off by default.
- **Observability**: structured JSON logs, Prometheus metrics, and optional OpenTelemetry tracing. A Grafana dashboard and alert rules are included.

MCP headers (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`) are forwarded verbatim. mcp-gate records them in metrics and logs but never acts on them.

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
docker run -d --name mcp-gate -p 8080:8080 -p 9090:9090 \
  --env-file mcp-gate.env \
  cpremus/mcp-gate:0.20
```

Images are published to [Docker Hub](https://hub.docker.com/r/cpremus/mcp-gate) and [GHCR](https://github.com/c-premus/mcp-gate/pkgs/container/mcp-gate) (`ghcr.io/c-premus/mcp-gate`) on each release, for `linux/amd64`. Tags are `X.Y.Z`, `X.Y`, and `latest`, with no `v` prefix (for example `0.20.2`). Pin a version rather than tracking `latest`.

A Compose example is in [`docker-compose.example.yml`](docker-compose.example.yml).

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

Metrics use the `mcpgate_` prefix. `mcpgate_info{version="…"}` reports the running build. Its `version` label keeps the release tag's `v` prefix (`v0.20.2`), which the image tag drops.

[`docs/grafana/`](docs/grafana/) contains a provisionable dashboard and alert rules. Both expect a Prometheus job named `mcp-gate` and a `service` target label on each gate. See [Monitoring](https://github.com/c-premus/mcp-gate/blob/main/docs/setup.md#monitoring) in the Setup Guide.

## License

MIT
