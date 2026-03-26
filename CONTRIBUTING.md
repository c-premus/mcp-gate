# Contributing to mcp-gate

Thanks for your interest in contributing. This document covers the basics.

## Prerequisites

- Go 1.26+
- [golangci-lint](https://golangci-lint.run/) v2.11.3+
- Git with conventional commit knowledge

## Getting Started

```bash
git clone https://github.com/c-premus/mcp-gate.git
cd mcp-gate
go build -o mcp-gate ./cmd/mcp-gate
go test -race ./...
```

## Development Workflow

1. Fork the repository and create a branch from `dev`.
2. Make your changes.
3. Run tests and linting before pushing.
4. Open a pull request targeting the `dev` branch (not `main`).

## Build, Test, Lint

```bash
# Build
go build -o mcp-gate ./cmd/mcp-gate

# Run all tests with race detection
go test -race ./...

# Lint (26 linters configured in .golangci.yml)
golangci-lint run ./...
```

All three must pass before a PR will be reviewed.

## Project Conventions

### Code

- **Stdlib only** for HTTP handling. No web frameworks.
- **Environment variables** for all configuration. No config files.
- **Structured logging** with `log/slog` (key-value pairs, no `fmt.Sprintf` in log messages).
- **Table-driven tests** preferred. Tests live next to the code they test.

### Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add token introspection endpoint
fix: handle empty aud claim in JWT
docs: clarify TRUSTED_PROXIES format
refactor: extract header stripping into helper
test: add coverage for clock skew edge case
chore: bump keyfunc to v3.4.0
perf: reduce allocations in realip extraction
```

Write a short, specific subject line in imperative mood. Keep it under 72 characters.

### Pull Requests

- Target the `dev` branch.
- One logical change per PR.
- Include tests for new behavior.
- Update documentation if you change configuration or public behavior.

## Project Structure

```
cmd/mcp-gate/main.go        # Entrypoint, config loading, server startup
internal/
  auth/auth.go              # JWT validation middleware
  metadata/metadata.go      # RFC 9728 Protected Resource Metadata
  metrics/                  # Prometheus metrics & HTTP middleware
  otel/                     # OpenTelemetry tracing setup
  proxy/proxy.go            # Reverse proxy, header stripping
  realip/realip.go          # Client IP extraction (trusted proxy aware)
build/Dockerfile             # Multi-stage distroless build
```

## Running Locally

mcp-gate requires several environment variables. At minimum:

```bash
export LISTEN_ADDR="0.0.0.0:8080"
export UPSTREAM_URL="http://localhost:3000"
export RESOURCE_URI="https://example.com"
export AUTHORIZATION_SERVER="https://auth.example.com/application/o/my-provider/"
export JWKS_URI="https://auth.example.com/application/o/my-provider/jwks/"
export EXPECTED_ISSUER="https://auth.example.com/application/o/my-provider/"
export EXPECTED_AUDIENCE="my-client-id"
```

See the README for the full configuration reference.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## Questions

Open an issue if something is unclear. We prefer issues over guessing.
