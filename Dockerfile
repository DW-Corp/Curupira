# Build stage
FROM rust:1.75-slim-bullseye as builder

WORKDIR /usr/src/app

# Install dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy over your manifests
COPY Cargo.toml Cargo.lock ./

# Build dependencies - this is the caching Docker layer
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY . .

# Build for release
RUN cargo build --release

# Final stage
FROM debian:bullseye-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y libpq5 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from builder stage
COPY --from=builder /usr/src/app/target/release/curupira /app/curupira

# Copy migrations for automatic database setup
COPY --from=builder /usr/src/app/migrations /app/migrations

# Set environment variables
ENV APP_HOST=0.0.0.0
ENV APP_PORT=8080

# Expose the port
EXPOSE 8080

# Run the binary
CMD ["/app/curupira"]
