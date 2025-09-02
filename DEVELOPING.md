# 🛠️ Curupira - Development Guide

This guide covers database migrations, development workflows, and advanced development topics for the Curupira OAuth2 + OpenID Connect Identity Provider.

## 🗄️ Database Migrations with SQLx

### Understanding SQLx Compile-Time Checking

Curupira uses **SQLx** which performs **compile-time verification** of SQL queries against your actual database schema. This means:

- ✅ **Compile-time safety**: Typos in table/column names are caught at build time
- ✅ **Type safety**: Return types are verified against actual database schema  
- ⚠️ **Requirement**: Database tables must exist before building the code

### Migration Setup

#### Install SQLx CLI

```bash
# Install SQLx CLI with PostgreSQL support only (lighter install)
cargo install sqlx-cli --no-default-features --features postgres

# Verify installation
sqlx --version
```

#### Migration Commands

```bash
# Create a new migration file
sqlx migrate add create_users_table

# Run all pending migrations
sqlx migrate run

# Show migration status
sqlx migrate info

# Revert the last migration
sqlx migrate revert

# Revert to a specific migration
sqlx migrate revert --target-version 20231101000001
```

### Development Workflow

#### 1. Initial Setup (First Time)

```bash
# 1. Start database
docker-compose up -d postgres

# 2. Wait for database to be ready
docker-compose logs -f postgres

# 3. Run migrations to create schema
sqlx migrate run

# 4. Now you can build the application
cargo build --bin curupira

# 5. Run the application (will also apply any new migrations)
cargo run --bin curupira
```

#### 2. Day-to-Day Development

```bash
# Start your development session
docker-compose up -d postgres
sqlx migrate run  # Ensure you have latest schema
cargo run --bin curupira
```

#### 3. Adding New Features with Schema Changes

```bash
# 1. Create new migration
sqlx migrate add add_user_preferences_table

# 2. Edit the generated migration file in migrations/
# Example: migrations/20231101000001_add_user_preferences_table.sql

# 3. Run the migration
sqlx migrate run

# 4. Update your Rust code with new queries

# 5. Build and test
cargo build
cargo test
```

### Migration Best Practices

#### Naming Conventions

- Use descriptive names: `create_users_table`, `add_email_verification`, `remove_deprecated_columns`
- Include the action: `add_`, `remove_`, `create_`, `alter_`, `drop_`
- Use timestamps in filenames: SQLx automatically adds them

#### Writing Safe Migrations

```sql
-- ✅ Good: Use IF EXISTS/IF NOT EXISTS
CREATE TABLE IF NOT EXISTS user_preferences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    theme TEXT DEFAULT 'light',
    language TEXT DEFAULT 'en'
);

-- ✅ Good: Add indexes in separate statements
CREATE INDEX IF NOT EXISTS idx_user_preferences_user_id ON user_preferences(user_id);

-- ⚠️ Be careful with data modifications
UPDATE users SET email_verified = true WHERE email LIKE '%@dwcorp.com.br';

-- ❌ Avoid: DROP TABLE without IF EXISTS (unless you're sure)
-- DROP TABLE user_preferences;
```

#### Rollback-Safe Migrations

```sql
-- ✅ Additive changes are safe
ALTER TABLE users ADD COLUMN phone TEXT;

-- ⚠️ Destructive changes need careful planning
-- Consider data migration before dropping columns
-- 1. Add new column
-- 2. Migrate data
-- 3. Remove old column (in separate migration)

-- Example rollback strategy:
-- Migration: Add column
ALTER TABLE users ADD COLUMN full_name TEXT;

-- Migration: Populate column
UPDATE users SET full_name = CONCAT(given_name, ' ', family_name) WHERE given_name IS NOT NULL;

-- Migration: Drop old columns (reversible with next migration)
ALTER TABLE users DROP COLUMN given_name, DROP COLUMN family_name;
```

### Troubleshooting Migrations

#### Common Issues

**1. "relation does not exist" compile errors**

```bash
# Cause: SQLx is trying to validate queries but tables don't exist
# Solution: Run migrations first
sqlx migrate run
cargo build
```

**2. "migration xxx not found" errors**

```bash
# Check migration status
sqlx migrate info

# Verify migration files exist
ls -la migrations/

# Reset migration state (DANGER: removes migration history)
# sqlx migrate reset  # Use with caution!
```

**3. "connection refused" errors**

```bash
# Check database is running
docker-compose ps postgres

# Test connection manually
psql postgres://postgres:changeme@localhost:5432/authdb -c "SELECT 1;"

# Restart database if needed
docker-compose restart postgres
```

**4. "permission denied" on migrations**

```bash
# Check database permissions
docker exec -it postgres_container psql -U postgres -d authdb -c "\\du"

# Grant permissions if needed
docker exec -it postgres_container psql -U postgres -d authdb -c "GRANT ALL PRIVILEGES ON DATABASE authdb TO postgres;"
```

### Advanced Migration Techniques

#### Data Migrations

```sql
-- Example: Migrate from single name field to first/last name
-- Step 1: Add new columns
ALTER TABLE users ADD COLUMN given_name TEXT, ADD COLUMN family_name TEXT;

-- Step 2: Migrate existing data
UPDATE users 
SET 
    given_name = SPLIT_PART(name, ' ', 1),
    family_name = CASE 
        WHEN ARRAY_LENGTH(STRING_TO_ARRAY(name, ' '), 1) > 1 
        THEN TRIM(SUBSTRING(name FROM POSITION(' ' IN name) + 1))
        ELSE ''
    END
WHERE name IS NOT NULL;

-- Step 3: (In next migration) Drop old column
-- ALTER TABLE users DROP COLUMN name;
```

#### Environment-Specific Migrations

```bash
# Development environment
DATABASE_URL=postgres://postgres:changeme@localhost:5432/authdb sqlx migrate run

# Test environment
DATABASE_URL=postgres://postgres:changeme@localhost:5432/authdb_test sqlx migrate run

# Production environment (with SSL)
DATABASE_URL=postgres://user:pass@prod-db:5432/authdb?sslmode=require sqlx migrate run
```

### Offline Mode (CI/CD)

For CI/CD environments where database isn't available during build:

```bash
# Generate .sqlx files for offline compilation (run locally with DB)
cargo sqlx prepare

# Build in offline mode (in CI)
cargo build --offline

# The .sqlx/ directory should be committed to version control
git add .sqlx/
git commit -m "Update SQLx offline data"
```

### Testing with Migrations

#### Test Database Setup

```bash
# Create test database
createdb authdb_test

# Run migrations on test database
DATABASE_URL=postgres://postgres:changeme@localhost:5432/authdb_test sqlx migrate run

# Run tests with test database
TEST_DATABASE_URL=postgres://postgres:changeme@localhost:5432/authdb_test cargo test
```

#### Integration Tests

```rust
// Example test setup in tests/integration_test.rs
use sqlx::PgPool;

#[tokio::test]
async fn test_user_creation() {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:changeme@localhost:5432/authdb_test".to_string());
    
    let pool = PgPool::connect(&database_url).await.unwrap();
    
    // Run migrations for test
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    
    // Your test code here
    // ...
}
```

## 🔄 Development Workflow Summary

### Daily Development

1. **Start Development Session**
   ```bash
   docker-compose up -d postgres  # Start DB
   sqlx migrate run              # Apply any new migrations
   cargo run --bin curupira      # Start application
   ```

2. **Adding Database Changes**
   ```bash
   sqlx migrate add your_feature_name  # Create migration
   # Edit the migration file
   sqlx migrate run                    # Apply migration
   cargo build                         # Verify queries compile
   ```

3. **Testing Changes**
   ```bash
   cargo test                    # Run all tests
   cargo clippy                  # Rust linter for code quality
   cargo fmt                     # Rust code formatter
   cargo run --bin curupira      # Manual testing
   ```

4. **Before Committing**
   ```bash
   cargo clippy                # Check for code issues
   cargo fmt                   # Format code consistently
   cargo sqlx prepare          # Update offline query data
   git add .sqlx/              # Include in commit
   cargo test                  # Final test run
   ```

## 🧪 Testing Guide

### Running Tests

#### Basic Test Commands

```bash
# Run all tests
cargo test

# Run tests with output (shows println! and debug output)
cargo test -- --nocapture

# Run tests quietly (only show summary)
cargo test --quiet

# Run specific test by name
cargo test test_generate_keypair

# Run all tests in a specific module
cargo test keygen::tests

# Run all tests in a file/module path
cargo test oauth::authorize::tests
```

#### Advanced Test Filtering

```bash
# Run tests matching a pattern
cargo test password  # Runs all tests with 'password' in the name

# Run tests in specific binary (if you have multiple binaries)
cargo test --bin curupira

# Run only documentation tests
cargo test --doc

# Run tests and build in release mode (faster execution)
cargo test --release
```

#### Test-Specific Examples

```bash
# Run the keygen test specifically
cargo test keygen::tests::test_generate_keypair

# Run all OAuth2 authorization tests
cargo test oauth::authorize::tests

# Run all security-related tests
cargo test security::

# Run password hashing tests
cargo test security::password::tests

# Run web route tests
cargo test web::routes::tests
```

#### Running Tests with Database

Some tests may require database setup:

```bash
# Start test database
docker-compose up -d postgres

# Run database-dependent tests
DATABASE_URL=postgres://postgres:changeme@localhost:5432/authdb cargo test

# Run tests with specific test database
TEST_DATABASE_URL=postgres://postgres:changeme@localhost:5432/authdb_test cargo test
```

#### Test Output and Debugging

```bash
# Show all output including println! statements
cargo test -- --nocapture

# Show test execution details
cargo test -- --nocapture --test-threads=1

# Run tests with environment variable for debugging
RUST_LOG=debug cargo test -- --nocapture

# Run with backtraces on test failures
RUST_BACKTRACE=1 cargo test

# Run with full backtraces
RUST_BACKTRACE=full cargo test
```

#### Continuous Testing During Development

```bash
# Install cargo-watch for automatic test running
cargo install cargo-watch

# Run tests automatically when files change
cargo watch -x test

# Run specific test on file changes
cargo watch -x "test keygen::tests::test_generate_keypair"

# Run tests and clear screen each time
cargo watch -c -x test
```

#### Performance and Parallel Testing

```bash
# Run tests in single thread (useful for debugging)
cargo test -- --test-threads=1

# Run tests with specific number of threads
cargo test -- --test-threads=4

# Measure test execution time
time cargo test

# Run ignored tests (if any are marked with #[ignore])
cargo test -- --ignored

# Run both normal and ignored tests
cargo test -- --include-ignored
```

### Writing and Organizing Tests

#### Test Structure in Curupira

```rust
// Unit tests (in src files)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_name() {
        // Test implementation
    }

    #[tokio::test]  // For async tests
    async fn test_async_function() {
        // Async test implementation
    }
}
```

#### Integration Test Examples

```rust
// Integration tests (in tests/ directory)
#[tokio::test]
async fn test_oauth_flow() {
    // Full OAuth2 flow test
}

#[test]
fn test_configuration_loading() {
    // Test config from environment
}
```

### Test Coverage

```bash
# Install cargo-tarpaulin for coverage
cargo install cargo-tarpaulin

# Generate test coverage report
cargo tarpaulin --out Html

# Generate coverage and open in browser
cargo tarpaulin --out Html && open tarpaulin-report.html
```

### Team Development

#### Migration Conflicts

When multiple developers create migrations:

```bash
# Pull latest changes
git pull origin main

# Check for new migrations
sqlx migrate info

# Run any new migrations
sqlx migrate run

# If conflicts, may need to rename your migration file
# SQLx uses timestamps in filenames to determine order
```

#### Schema Reviews

Before merging migration PRs:

1. Review SQL for safety (reversibility, data loss risks)
2. Test migration on copy of production data
3. Verify rollback procedures
4. Update any affected documentation

### Production Deployment

#### Safe Deployment Strategy

1. **Backup database** before migration
2. **Test migration** on production copy
3. **Deploy during maintenance window**
4. **Monitor** application startup logs

```bash
# Production migration workflow
pg_dump authdb > backup_$(date +%Y%m%d_%H%M%S).sql  # Backup first
sqlx migrate run                                    # Apply migrations
cargo run --release --bin curupira                 # Start application
```

#### Rollback Procedures

```bash
# If migration needs rollback
sqlx migrate revert

# If data corruption occurred
psql authdb < backup_20231101_120000.sql  # Restore from backup

# Test rollback locally first
sqlx migrate revert --database-url postgres://postgres:changeme@localhost:5432/authdb_test
```

## 🧹 Code Quality Tools

### Rust Linting and Formatting

Curupira uses standard Rust tooling for code quality:

#### Clippy - Rust Linter
```bash
# Run clippy to check for common issues and improvements
cargo clippy

# Run clippy with additional strictness
cargo clippy -- -D warnings

# Fix automatically applicable suggestions
cargo clippy --fix
```

#### Rustfmt - Code Formatter
```bash
# Format all code in the project
cargo fmt

# Check if formatting is needed (useful in CI)
cargo fmt -- --check

# Format specific files
rustfmt src/main.rs src/config.rs
```

#### Common Development Commands
```bash
# Complete quality check sequence
cargo fmt                    # Format code
cargo clippy                 # Check for issues  
cargo test                   # Run tests
cargo build                  # Verify compilation

# Quick development loop
cargo check                  # Fast compilation check (no binary)
cargo clippy                 # Lint check
cargo run --bin curupira     # Run and test
```

#### Integration with Pre-commit Hooks

For teams, consider setting up pre-commit hooks:

```bash
# Install pre-commit (if using Python tooling)
pip install pre-commit

# Create .pre-commit-config.yaml with Rust hooks
# Then install hooks:
pre-commit install
```

---

## 📚 Additional Resources

- [SQLx Documentation](https://docs.rs/sqlx/latest/sqlx/)
- [PostgreSQL Migration Best Practices](https://www.postgresql.org/docs/current/ddl-alter.html)
- [Database Schema Design Patterns](https://www.postgresql.org/docs/current/ddl-schemas.html)

---

**Happy developing!** 🦀 🛡️
