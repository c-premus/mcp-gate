# Contributing to mcp-gate

Thanks for your interest in contributing. This document covers the basics.

## Project layout

- **GitHub** (`github.com/c-premus/mcp-gate`) is a public mirror.
- The source of truth lives in a **private Forgejo** instance. Commits
  flow Forgejo → GitHub via `.forgejo/workflows/sync-github.yaml`, which
  rewrites history with `git filter-repo` to strip internal paths (CI
  configs, devcontainer, dev-only docs, agent and memory-bank
  configuration) before force-pushing to GitHub.

This is one-way mirroring. Two consequences for contributors:

1. **PRs are welcome on GitHub.** Open them against `main`.
2. **PR commits get rewritten when they land.** Your authored commits
   will appear in the public history (with your name and email
   preserved), but their SHAs change on the next sync because the
   filter-repo rewrite is whole-history. If you fork later, fetch fresh
   to avoid working against stale SHAs.

## How a contribution moves through the system

1. You open a PR against `github.com/c-premus/mcp-gate:main`.
2. The maintainer reviews on GitHub. Discussion happens in PR comments.
3. When merged, the maintainer cherry-picks (or rebases) the change to
   the private Forgejo `dev` branch. CI runs there; the change reaches
   the public mirror at the next sync (push to `main` or release tag).
4. The GitHub PR is closed with a reference to the public commit.

If you'd prefer to discuss a change before opening a PR, file a GitHub
issue first.

## Prerequisites

- Go 1.26+. `go.mod` declares a `go 1.26` language floor and a newer
  `toolchain` line; with the default `GOTOOLCHAIN=auto`, Go downloads that
  toolchain on first use. Code must still compile at the 1.26 floor.
- [golangci-lint](https://golangci-lint.run/) at the version pinned in
  `.github/workflows/ci.yaml` (v2.14.0 at the time of writing)
- Node.js 24, only if you change the Grafana dashboard
- Git with conventional commit knowledge

## Getting Started

```bash
git clone https://github.com/c-premus/mcp-gate.git
cd mcp-gate
go build -o mcp-gate ./cmd/mcp-gate
go test -race ./...
```

## Build, Test, Lint

```bash
# Build
go build -o mcp-gate ./cmd/mcp-gate

# Run all tests with race detection
go test -race ./...

# Lint (26 linters configured in .golangci.yml)
golangci-lint run ./...

# go.mod / go.sum must be tidy (CI fails on any diff)
go mod tidy -diff
```

All four must pass before a PR will be reviewed.

The dashboard in `docs/grafana/dashboard.json` is generated. If you
change it, edit the TypeScript under `grafana/src/` and regenerate
instead of editing the JSON:

```bash
cd grafana
npm ci
npm run typecheck
npm run generate   # validates, then writes docs/grafana/dashboard.json
```

## Commit message format

Commit subjects drive the auto-generated `CHANGELOG.md`. Use
[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

Types that appear in the changelog:

- **feat:** new user-facing capability → `### Features`
- **fix:** bug fix → `### Fixes`
- **chore:** maintenance, dependency bumps, infra → `### Maintenance`
- **`!:` suffix or `BREAKING CHANGE:` body** → `### BREAKING CHANGES`

Types filtered out of the changelog (still welcome, just won't show in
release notes):

- `ci:`, `test:`, `refactor:`, `docs:`, `style:`, `perf:`

Promote anything user-visible (security fixes, API tweaks) to `fix:` or
`chore:` so it lands in the changelog.

Good subjects:

- `feat(auth): accept array form of scope claim`
- `fix(realip): preserve IPv4-mapped IPv6 canonicalization`
- `chore(deps): bump keyfunc to v3.9.0`

Write a short, specific subject line in imperative mood. Keep it under
72 characters.

## Pre-v1 versioning

Until v1.0.0, **breaking changes bump minor** (per
`.forgejo/workflows/version-release.yaml`):

- `feat!:` or `BREAKING CHANGE:` while major is `0` → minor bump.
- `v1.0.0` is reserved for an explicit, manually-dispatched cut.

This matches Semver §4 ("v0.x.y is unstable; anything may change").

## Project conventions

### Code

- **Stdlib only** for HTTP handling. No web frameworks.
- **Environment variables** for all configuration. No config files.
- **Structured logging** with `log/slog` (key-value pairs, no
  `fmt.Sprintf` in log messages).
- **Table-driven tests** preferred. Tests live next to the code they
  test.

### Pull Requests

- Target `main`.
- One logical change per PR.
- Include tests for new behavior.
- Update documentation if you change configuration or public behavior.

## Project Structure

```
cmd/mcp-gate/main.go        # Entrypoint, config loading, server startup
internal/
  auth/auth.go              # JWT validation middleware, scope matching
  metadata/metadata.go      # RFC 9728 Protected Resource Metadata
  metrics/                  # Prometheus metrics & HTTP middleware
  origin/origin.go          # Opt-in Origin validation (ALLOWED_ORIGINS)
  otel/                     # OpenTelemetry tracing setup
  proxy/proxy.go            # Reverse proxy, header stripping
  ratelimit/                # Per-IP + concurrent limits, optional Redis backend
  realip/realip.go          # Client IP extraction (trusted proxy aware)
build/Dockerfile            # Multi-stage distroless build
docs/setup.md               # Operator setup guide
docs/grafana/               # Generated dashboard + alert rules
grafana/src/                # Dashboard source (TypeScript)
scripts/                    # CHANGELOG generator
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

See [docs/setup.md](docs/setup.md#environment-variables) for the full
configuration reference.

## Reporting security issues

Don't open a public issue. See [SECURITY.md](SECURITY.md) — the
preferred channel is a GitHub private security advisory.

## License

By contributing, you agree that your contributions will be licensed
under the [MIT License](LICENSE).

## Questions

Open an issue if something is unclear. We prefer issues over guessing.
