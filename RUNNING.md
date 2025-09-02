# 🚀 Curupira - Running Guide

This guide covers everything you need to build, run, test, and develop the Curupira OAuth2 + OpenID Connect Identity Provider.

## 📋 Prerequisites

### System Requirements

- **Rust**: 1.75+ (tested with 1.89.0)
- **PostgreSQL**: 12+ 
- **Git**: For cloning and version control
- **OpenSSL**: For cryptographic operations (usually system-provided)

### Verify Your Environment

```bash
# Check Rust version
rustc --version
# Should show: rustc 1.89.0 (29483883e 2025-08-04) or newer

# Check Cargo version  
cargo --version
# Should show: cargo 1.89.0 (c24e10642 2025-06-23) or newer

# Check PostgreSQL is available
psql --version
# Should show: psql (PostgreSQL) 12.x or newer
```

## 🔧 Project Setup

### 1. Clone and Navigate

```bash
git clone <repository-url>
cd curupira
```

### 2. Environment Configuration

Create your environment file:

```bash
cp .env.example .env
```

Edit `.env` with your settings:

```env
# Required - Generate with: openssl rand -base64 32
SESSION_SECRET=your-generated-secret-here

# Server configuration
APP_HOST=0.0.0.0
APP_PORT=8080
ISSUER=http://localhost:8080

# Database configuration
DATABASE_URL=postgres://postgres:changeme@localhost:5432/authdb

# Cookie configuration
COOKIE_DOMAIN=localhost

# Token lifetimes
DEFAULT_ACCESS_TTL_SECS=3600
DEFAULT_REFRESH_TTL_MINS=43200

# Security settings
REQUIRE_API_KEY=true
```

### 3. Database Setup

#### Option A: Using Docker (Recommended)

```bash
# Start PostgreSQL container
docker-compose up -d postgres

# Wait for database to be ready (watch for "database system is ready to accept connections")
docker-compose logs -f postgres

# Verify database exists
docker exec -it postgres_container psql -U postgres -l

# If database doesn't exist, create it manually:
docker exec -it postgres_container psql -U postgres -c "CREATE DATABASE authdb;"
```

#### Running Database Migrations

**CRITICAL**: You must run migrations before building the application, as SQLx validates SQL queries against the actual database schema at compile time.

```bash
# Install sqlx CLI (one-time setup)
cargo install sqlx-cli --no-default-features --features postgres

# Run all pending migrations
sqlx migrate run

# Verify all tables were created
sqlx migrate info
```

**Expected output after migrations:**
```
Applied 1/migrate initial schema (230.770955ms)
Applied 2/migrate seed data (15.660795ms)
```

This creates all required tables: `tenants`, `applications`, `users`, `roles`, `user_roles`, `application_roles`, `auth_codes`, `refresh_tokens`, `sessions`.

**Troubleshooting Database Issues:**

```bash
# If you get "database does not exist" errors:

# 1. Clean reset (removes all data!)
docker-compose down -v
docker-compose up -d postgres

# 2. Manual database creation
docker exec -it postgres_container psql -U postgres -c "CREATE DATABASE authdb;"

# 3. Verify connection
docker exec -it postgres_container psql -U postgres -d authdb -c "SELECT current_database();"
```

#### Option B: Local PostgreSQL

```bash
# Create database
createdb authdb

# Or using psql
psql -c "CREATE DATABASE authdb;"
```

### 4. Generate Session Secret

```bash
# Generate a secure session secret
openssl rand -base64 32
```

Copy this value to your `.env` file as `SESSION_SECRET`.

## 🏗️ Building the Project

### Available Binaries

The project contains two binaries:

1. **`curupira`** - Main OAuth2/OIDC server application
2. **`keygen`** - RSA key pair generation utility

### Build Commands

```bash
# Build all binaries (debug mode)
cargo build

# Build all binaries (release mode - optimized)
cargo build --release

# Build specific binary
cargo build --bin curupira
cargo build --bin keygen

# Check for compilation errors without building
cargo check
```

## 🚀 Running the Project

### Main Application Server

```bash
# Run the main OAuth2 server (debug mode)
cargo run --bin curupira

# Run in release mode (better performance)
cargo run --release --bin curupira

# Run with specific environment file
ENV_FILE=.env.production cargo run --bin curupira

# Run with logging level override
RUST_LOG=debug cargo run --bin curupira
```

**Expected Output:**
```
🛡️  Starting Curupira - OAuth2 + OpenID Connect Identity Provider
Connecting to database...
Database connection established and migrations applied
Setting up routes...
🚀 Server starting on 0.0.0.0:8080
```

### Key Generation Utility

```bash
# Generate RSA key pairs for JWT signing
cargo run --bin keygen

# Generate keys for specific application (if implemented)
cargo run --bin keygen -- --application-id <uuid>
```

### Alternative: Direct Binary Execution

After building, you can run binaries directly:

```bash
# After cargo build
./target/debug/curupira
./target/debug/keygen

# After cargo build --release  
./target/release/curupira
./target/release/keygen
```

## 🧪 Testing

### Unit Tests

```bash
# Run all unit tests
cargo test

# Run tests with output (shows println! and logs)
cargo test -- --nocapture

# Run specific test module
cargo test oauth::tests
cargo test security::jwt::tests

# Run specific test function
cargo test test_validate_authorize_params

# Run tests with detailed output
cargo test --verbose
```

### Integration Tests

```bash
# Run integration tests (if present in tests/ directory)
cargo test --test integration

# Run specific integration test file
cargo test --test api_tests
```

### Database Tests

```bash
# Run tests that require database (ensure test DB is available)
TEST_DATABASE_URL=postgres://postgres:changeme@localhost:5432/authdb_test cargo test

# Run database-specific tests
cargo test db::tests
```

### Code Coverage

```bash
# Install tarpaulin for coverage (one time setup)
cargo install cargo-tarpaulin

# Run tests with coverage
cargo tarpaulin --out Html

# Open coverage report
open tarpaulin-report.html
```

## 🔍 Development Workflow

### Code Quality Checks

```bash
# Format code
cargo fmt

# Check formatting without changing files
cargo fmt --check

# Run Clippy linter
cargo clippy

# Run Clippy with all targets
cargo clippy --all-targets --all-features

# Fix auto-fixable Clippy warnings
cargo clippy --fix
```

### Dependency Management

```bash
# Update dependencies
cargo update

# Add new dependency
cargo add serde
cargo add tokio --features full

# Remove dependency
cargo remove unused-crate

# Check for outdated dependencies
cargo outdated

# Audit dependencies for security issues
cargo audit
```

### Development Server

```bash
# Install cargo-watch for auto-reload during development
cargo install cargo-watch

# Run server with auto-reload on file changes
cargo watch -x "run --bin curupira"

# Run tests on file changes
cargo watch -x test

# Run both checks and tests on changes
cargo watch -x check -x test
```

## 🐛 Debugging

### Debug Mode

```bash
# Run with debug logging
RUST_LOG=debug cargo run --bin curupira

# Run with trace logging (very verbose)
RUST_LOG=trace cargo run --bin curupira

# Module-specific logging
RUST_LOG=curupira::oauth=debug,curupira::security=trace cargo run --bin curupira
```

### Using GDB/LLDB

```bash
# Build with debug symbols
cargo build

# Debug with gdb
gdb ./target/debug/curupira

# Debug with lldb (macOS)
lldb ./target/debug/curupira
```

### Memory Profiling

```bash
# Install valgrind (Linux)
sudo apt-get install valgrind

# Run with valgrind
valgrind --tool=memcheck ./target/debug/curupira
```

## 🌐 Endpoints and Health Checks

### Health Check

```bash
# Verify server is running
curl http://localhost:8080/health
# Expected: OK
```

### OAuth2/OIDC Endpoints

```bash
# OIDC Discovery
curl http://localhost:8080/.well-known/openid-configuration | jq

# JWKS (Public Keys)
curl http://localhost:8080/.well-known/jwks.json | jq

# Health endpoint
curl http://localhost:8080/health
```

## 📊 Performance Testing

### Load Testing with Apache Bench

```bash
# Install apache2-utils
sudo apt-get install apache2-utils

# Simple load test
ab -n 1000 -c 10 http://localhost:8080/health

# OAuth2 endpoint load test
ab -n 100 -c 5 "http://localhost:8080/.well-known/openid-configuration"
```

### Load Testing with wrk

```bash
# Install wrk
sudo apt-get install wrk

# Load test health endpoint
wrk -t12 -c400 -d30s http://localhost:8080/health

# Test discovery endpoint
wrk -t4 -c100 -d10s http://localhost:8080/.well-known/openid-configuration
```

## 🔧 Troubleshooting

### Common Issues

#### Build Failures

```bash
# Clean build artifacts and rebuild
cargo clean
cargo build

# Update Rust toolchain
rustup update

# Check for missing system dependencies
sudo apt-get install build-essential pkg-config libssl-dev
```

#### SQLx Compile-Time Errors

If you get errors like "relation 'tenants' does not exist" or similar database table errors:

```bash
# This happens when SQLx tries to validate queries but tables don't exist
# Solution: Run migrations first, then build

# 1. Ensure database is running
docker-compose up -d postgres

# 2. Run migrations to create tables
sqlx migrate run

# 3. Now build/run the application
cargo run --bin curupira

# Alternative: Use offline mode (if you have .sqlx/ files)
cargo sqlx prepare
cargo build --offline
```

#### Database Connection Issues

```bash
# Check PostgreSQL is running
systemctl status postgresql

# Test database connection
psql $DATABASE_URL -c "SELECT 1;"

# Check database exists
psql -l | grep authdb

# Reset database (drops all data!)
dropdb authdb
createdb authdb
cargo run --bin curupira  # Will run migrations
```

#### Port Already in Use

```bash
# Find process using port 8080
lsof -i :8080

# Kill process using port
kill -9 <PID>

# Use different port
APP_PORT=8081 cargo run --bin curupira
```

#### Permission Denied Errors

```bash
# Fix binary permissions
chmod +x target/debug/curupira
chmod +x target/release/curupira

# Check file ownership
ls -la target/debug/curupira
```

### Logs and Debugging

```bash
# Enable all debug logs
RUST_LOG=debug cargo run --bin curupira 2>&1 | tee curupira.log

# Filter logs by module
RUST_LOG=curupira::oauth=debug cargo run --bin curupira

# Show backtraces on panic
RUST_BACKTRACE=1 cargo run --bin curupira

# Full backtrace
RUST_BACKTRACE=full cargo run --bin curupira
```

## 📦 Production Deployment

### Release Build

```bash
# Build optimized release binary
cargo build --release

# The binary will be at: ./target/release/curupira
# Copy to your deployment location
```

### Systemd Service

Create `/etc/systemd/system/curupira.service`:

```ini
[Unit]
Description=Curupira OAuth2 Identity Provider
After=postgresql.service

[Service]
Type=simple
User=curupira
Group=curupira
WorkingDirectory=/opt/curupira
Environment=RUST_LOG=info
EnvironmentFile=/opt/curupira/.env
ExecStart=/opt/curupira/curupira
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable curupira
sudo systemctl start curupira
sudo systemctl status curupira
```

### Docker Build

```bash
# Build Docker image
docker build -t curupira:latest .

# Run with Docker
docker run -d -p 8080:8080 --env-file .env curupira:latest

# Run with Docker Compose
docker-compose up -d
```

## 🔄 CI/CD Integration

### GitHub Actions Example

```yaml
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v3
    - uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
    - name: Run tests
      run: cargo test
      env:
        DATABASE_URL: postgres://postgres:postgres@localhost:5432/postgres
```

## 📝 Additional Resources

- **API Documentation**: See `DOCUMENTATION.md` for comprehensive code documentation
- **OAuth2 Flow Testing**: Use the examples in `README.md`
- **Security Best Practices**: Review the security comments in the codebase
- **Database Schema**: Check `migrations/001_initial_schema.sql`

---

**Need Help?** 

- Check the logs with `RUST_LOG=debug`
- Verify your `.env` configuration
- Ensure PostgreSQL is running and accessible
- Review the troubleshooting section above
- Check that all prerequisites are installed

Happy coding! 🦀 🛡️
