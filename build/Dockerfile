FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /mcp-gate ./cmd/mcp-gate

FROM gcr.io/distroless/static-debian12@sha256:6447365a6337c3732f412d1b74357b30a633831955b2bc45552b0086be907687
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
