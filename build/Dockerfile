FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mcp-gate ./cmd/mcp-gate

FROM gcr.io/distroless/static-debian12
COPY --from=builder /mcp-gate /mcp-gate
ENTRYPOINT ["/mcp-gate"]
