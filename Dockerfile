# ── Stage 1: Build ─────────────────────────────────────────────────────────────
FROM golang:1.25-bookworm AS builder

# Set shell for robustness
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Enable CGO since go-sqlite3 requires a C compiler and CGO enabled
ENV CGO_ENABLED=1 \
    GOOS=linux

WORKDIR /app

# Copy dependency files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy rest of application source
COPY . .

# Build the application with CGO enabled and fts5 tags for SQLite full-text search
RUN go build -tags "fts5" -ldflags="-w -s" -o docops .

# ── Stage 2: Runner ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runner

# Install ca-certificates (needed for future cloud storage integrations)
# and sqlite3/curl for debugging inside container
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    sqlite3 \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group for runtime security
RUN groupadd -g 10001 docops && \
    useradd -u 10001 -g docops -m -s /sbin/nologin docops

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/docops /app/docops
COPY --from=builder /app/config.yaml /app/config.yaml

# Pre-create data directory with correct permissions for SQLite and uploads
RUN mkdir -p /app/docops-data && \
    chown -R docops:docops /app/docops-data

# Set volume mount point
VOLUME ["/app/docops-data"]

# Use the non-root user
USER docops

# Expose port (default 8080)
EXPOSE 8080

# Run the app
ENTRYPOINT ["/app/docops"]
