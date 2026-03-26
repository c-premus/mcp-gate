# mcp-gate

OAuth 2.1 reverse proxy for MCP servers. Implements [RFC 9728 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) and JWT validation, delegating authentication to an external authorization server.

## What it does

`mcp-gate` sits in front of any MCP server and adds the [MCP Authorization specification](https://modelcontextprotocol.io/specification/draft/basic/authorization) endpoints required by Claude.ai custom connectors:

1. **`/.well-known/oauth-protected-resource`** — Serves RFC 9728 metadata pointing clients to the authorization server
2. **`/healthz`** — Health check for container orchestration
3. **`/*`** — Validates Bearer JWT tokens via JWKS, then reverse-proxies to the upstream MCP server

Every request is logged as structured JSON (`method`, `path`, `status`, `duration_ms`, `client_ip`, `user_agent`) for Loki/Alloy ingestion.

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
docker pull cpremus/mcp-gate:latest
```

Images are published to [Docker Hub](https://hub.docker.com/r/cpremus/mcp-gate) and [GHCR](https://github.com/c-premus/mcp-gate/pkgs/container/mcp-gate) on each release. Available tags: `latest`, version (e.g. `v1.2.0`).

## Configuration

All configuration is via environment variables. See the [environment variables table](cmd/mcp-gate/main.go) in the source for the full list.

## License

MIT
