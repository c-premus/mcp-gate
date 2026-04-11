# mcp-gate

[![CI](https://github.com/c-premus/mcp-gate/actions/workflows/ci.yaml/badge.svg)](https://github.com/c-premus/mcp-gate/actions/workflows/ci.yaml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/c-premus/mcp-gate)](https://go.dev/)
[![License](https://img.shields.io/github/license/c-premus/mcp-gate)](LICENSE)

OAuth 2.1 reverse proxy for MCP servers. Implements [RFC 9728 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) and JWT validation, delegating authentication to an external authorization server.

**Read the blog post**: [I couldn't find an OAuth 2.1 proxy for MCP servers, so I built one](https://dev.to/cpremus/i-couldnt-find-an-oauth-21-proxy-for-mcp-servers-so-i-built-one-59nd)

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

## Setup

See the **[Setup Guide](https://github.com/c-premus/mcp-gate/blob/main/docs/setup.md)** for step-by-step instructions on:

1. Creating an OAuth client in your OIDC provider (Keycloak, Authentik, Okta, Auth0, etc.)
2. Configuring mcp-gate
3. Connecting Claude.ai to the protected MCP server

## Configuration

All configuration is via environment variables. See the [Setup Guide](https://github.com/c-premus/mcp-gate/blob/main/docs/setup.md#step-3-configure-and-run-mcp-gate) for the full list.

## License

MIT
