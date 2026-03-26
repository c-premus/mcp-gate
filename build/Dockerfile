FROM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /mcp-gate ./cmd/mcp-gate

FROM gcr.io/distroless/static-debian12@sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838
COPY --from=builder /mcp-gate /mcp-gate
USER 65534:65534
EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/mcp-gate", "healthcheck"]
ENTRYPOINT ["/mcp-gate"]
