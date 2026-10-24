FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
# No default. A build that forgets --build-arg VERSION must FAIL, not silently
# stamp an unidentifiable binary: mcpgate_info{version=...} is the only answer
# to "what is actually deployed", and a `dev` value makes that question
# unanswerable. Production ran such an image twice in Sept 2026 with every
# health check green. Rejecting "dev" as well as empty closes the other half —
# `var version = "dev"` in main.go is the fallback when ldflags never applied.
ARG VERSION
RUN case "${VERSION}" in \
      ""|dev) echo "ERROR: build-arg VERSION must be set to a release version (got '${VERSION}')" >&2; exit 1 ;; \
    esac && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /mcp-gate ./cmd/mcp-gate

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=builder /mcp-gate /mcp-gate
USER 65534:65534
# Dozzle app icon (https://dozzle.dev/guide/app-icons). Dozzle matches the last
# path segment of the image name against a bundled dashboard-icons subset, and
# "mcp-gate" is not in it, so the icon rides inline as a data URI instead. Docker
# merges image labels into every container's Config.Labels, which is what Dozzle
# reads, so this needs no compose edit on the host. Dozzle caps the value at 16KB.
# Source: docs/assets/mcp-gate-icon.svg. CI fails if the two drift. Regenerate with:
#   tr -d '\n' < docs/assets/mcp-gate-icon.svg | sed -E 's/>[[:space:]]+</></g' | base64 -w0
LABEL dev.dozzle.icon="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCIgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0Ij48cmVjdCB4PSIxNiIgeT0iMTQiIHdpZHRoPSIzMiIgaGVpZ2h0PSI0MyIgZmlsbD0iI2Y4ZmFmYyIgc3Ryb2tlPSIjNjQ3NDhiIiBzdHJva2Utd2lkdGg9IjEuNSIvPjxsaW5lIHgxPSIzMiIgeTE9IjE0IiB4Mj0iMzIiIHkyPSI1NyIgc3Ryb2tlPSIjNjQ3NDhiIiBzdHJva2Utd2lkdGg9IjEuNSIvPjxyZWN0IHg9IjkiIHk9IjE0IiB3aWR0aD0iNyIgaGVpZ2h0PSI0MyIgcng9IjEiIGZpbGw9IiNlMmU4ZjAiIHN0cm9rZT0iIzY0NzQ4YiIgc3Ryb2tlLXdpZHRoPSIxLjUiLz48cmVjdCB4PSI0OCIgeT0iMTQiIHdpZHRoPSI3IiBoZWlnaHQ9IjQzIiByeD0iMSIgZmlsbD0iI2UyZThmMCIgc3Ryb2tlPSIjNjQ3NDhiIiBzdHJva2Utd2lkdGg9IjEuNSIvPjxyZWN0IHg9IjQiIHk9IjYiIHdpZHRoPSI1NiIgaGVpZ2h0PSI4IiByeD0iMiIgZmlsbD0iI2UyZThmMCIgc3Ryb2tlPSIjNjQ3NDhiIiBzdHJva2Utd2lkdGg9IjEuNSIvPjxsaW5lIHgxPSI0IiB5MT0iNTciIHgyPSI2MCIgeTI9IjU3IiBzdHJva2U9IiM2NDc0OGIiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIi8+PHBhdGggZD0iTTI3LjUgMzcgTDM2LjUgMzcgTDM1IDUxIEwyOSA1MSBaIiBmaWxsPSIjM2I4MmY2Ii8+PGNpcmNsZSBjeD0iMzIiIGN5PSIzMiIgcj0iOSIgZmlsbD0iIzNiODJmNiIvPjxjaXJjbGUgY3g9IjMyIiBjeT0iMzIiIHI9IjMuNSIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg=="
EXPOSE 8080 9090
# start-period lets the process initialize (the blocking JWKS fetch, plus any
# cold start on the authorization server) without the first few healthcheck
# failures counting toward the retry budget, so a slow-but-legitimate startup
# does not mark the container unhealthy and trip an orchestrator rollback.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=30s \
  CMD ["/mcp-gate", "healthcheck"]
ENTRYPOINT ["/mcp-gate"]
