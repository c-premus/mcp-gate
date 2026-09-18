FROM golang:1.27.1-alpine@sha256:e9bbdf282b51ac8b34c46e5f31d2d56e7bad60366c35f08d2f295b921b13388b AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
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
