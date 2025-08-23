# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a \
    -installsuffix cgo \
    -ldflags="-w -s -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
    -o /app/any-oidc-proxy

# Runtime stage
FROM alpine:latest

# Install CA certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Create app directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/any-oidc-proxy /app/any-oidc-proxy
COPY start.sh /app/start.sh

# Create non-root user
RUN adduser -D -g '' appuser && \
    chown appuser:appuser /app/any-oidc-proxy /app/start.sh && \
    chmod +x /app/start.sh /app/any-oidc-proxy

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/healthz || exit 1

# Command to run when starting the container
ENTRYPOINT ["/app/start.sh"]
