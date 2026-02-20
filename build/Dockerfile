FROM golang:1.24.1-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o /mcp-gate ./cmd/mcp-gate

FROM gcr.io/distroless/static-debian12
COPY --from=builder /mcp-gate /mcp-gate
USER 65534:65534
ENTRYPOINT ["/mcp-gate"]
