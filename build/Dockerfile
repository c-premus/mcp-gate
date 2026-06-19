FROM golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /mcp-gate ./cmd/mcp-gate

FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160
COPY --from=builder /mcp-gate /mcp-gate
USER 65534:65534
EXPOSE 8080 9090
# start-period lets the process initialize (JWKS fetch + Authentik cold start)
# without the first few healthcheck failures counting toward the retry budget,
# preventing deploy.yaml from rolling back on a slow-but-legitimate startup.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=30s \
  CMD ["/mcp-gate", "healthcheck"]
ENTRYPOINT ["/mcp-gate"]
