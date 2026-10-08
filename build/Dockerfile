FROM golang:1.27.2-alpine@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS builder
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
EXPOSE 8080 9090
# start-period lets the process initialize (the blocking JWKS fetch, plus any
# cold start on the authorization server) without the first few healthcheck
# failures counting toward the retry budget, so a slow-but-legitimate startup
# does not mark the container unhealthy and trip an orchestrator rollback.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=30s \
  CMD ["/mcp-gate", "healthcheck"]
ENTRYPOINT ["/mcp-gate"]
