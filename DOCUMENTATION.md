# Curupira 🛡️ - Comprehensive Developer Documentation

> **OAuth2 + OpenID Connect Identity Provider** built with Rust  
> A production-ready authentication and authorization server with multi-tenant support

## 📁 Project Structure Overview

This document provides an in-depth explanation of the Curupira codebase, including directory structure, file organization, Rust concepts, and business logic implementations.

```
curupira/
├── 📁 migrations/           # SQL database migrations
│   ├── 001_initial_schema.sql
│   └── 002_seed_data.sql
├── 📁 src/                  # Main source code directory
│   ├── 📁 config/           # Configuration management
│   ├── 📁 db/              # Database models and queries
│   ├── 📁 oauth/           # OAuth2/OpenID Connect implementation
│   ├── 📁 security/        # Cryptography and security utilities
│   ├── 📁 web/             # HTTP handlers and routing
│   ├── main.rs             # Application entry point
│   └── keygen.rs           # RSA key generation utility
├── Cargo.toml              # Rust project manifest
├── docker-compose.yaml     # Development database setup
└── README.md               # Project overview and setup
```

## 🗂️ Directory Breakdown

### `/migrations/` - Database Schema Evolution
Contains SQL migration files that define the database structure and seed data.

**📄 001_initial_schema.sql**
- **Purpose**: Defines the complete multi-tenant database schema
- **Key Features**:
  - PostgreSQL extensions (UUID, CITEXT)
  - Multi-tenant architecture with proper foreign key relationships
  - OAuth2-compliant tables for auth codes, tokens, and sessions
  - Comprehensive indexing strategy for performance
- **Tables**: `tenants`, `applications`, `users`, `roles`, `application_roles`, `user_roles`, `auth_codes`, `refresh_tokens`, `sessions`

**📄 002_seed_data.sql**
- **Purpose**: Populates initial test data for development
- **Contents**: Default tenant, test application with RSA keypair, test user account

### `/src/` - Main Application Code

#### 📁 **`/src/config/`** - Configuration Management

**📄 config.rs**
- **Purpose**: Environment-based configuration management
- **Rust Concepts Used**:
  - `struct` with `#[derive]` attributes for automatic trait implementations
  - `Secret<T>` wrapper for sensitive data protection
  - Error handling with `Result<T, E>` and `?` operator
  - Environment variable parsing with defaults
- **Business Logic**: 
  - Secure handling of secrets (database URL, session secret)
  - Environment-aware configuration (dev vs. prod)
  - Network binding configuration for deployment flexibility

#### 📁 **`/src/db/`** - Database Layer

**📄 mod.rs**
- **Purpose**: Database module organization and connection pooling
- **Rust Concepts Used**:
  - Module system (`pub mod`, `pub use`)
  - `Arc<T>` for shared ownership of database connection pool
  - `async`/`await` for non-blocking database operations
  - Automatic migrations on startup
- **Business Logic**: PostgreSQL connection management with SQLx

**📄 models.rs**
- **Purpose**: Data structures representing database entities and API responses
- **Rust Concepts Used**:
  - `struct` definitions with comprehensive derive attributes
  - `serde` for JSON serialization/deserialization
  - `sqlx::FromRow` for automatic database row mapping
  - `UUID` type for globally unique identifiers
  - `OffsetDateTime` for timezone-aware timestamps
  - `Vec<T>` for collections (arrays in database)
  - `Option<T>` for nullable fields
  - Custom `impl` blocks for behavior implementation
- **Business Logic**:
  - Multi-tenant data isolation
  - OAuth2 protocol compliance (auth codes, refresh tokens)
  - User management with role-based access control
  - JWT key pair storage per application

**📄 queries.rs**
- **Purpose**: Database query implementations
- **Rust Concepts Used**:
  - `async fn` for database operations
  - `sqlx` macros for compile-time SQL verification
  - Error handling and propagation
  - Complex JOIN queries for multi-table operations

#### 📁 **`/src/oauth/`** - OAuth2/OpenID Connect Implementation

**📄 mod.rs**
- **Purpose**: OAuth2 module organization
- **Contains**: Re-exports for all OAuth2 endpoints

**📄 authorize.rs**
- **Purpose**: OAuth2 authorization endpoint (`/oauth2/authorize`)
- **Business Logic**:
  - PKCE (Proof Key for Code Exchange) validation
  - Redirect URI validation
  - Authorization code generation
  - Consent flow management
- **Security Features**:
  - CSRF protection
  - State parameter validation
  - Strict redirect URI matching

**📄 token.rs**
- **Purpose**: OAuth2 token endpoint (`/oauth2/token`)
- **Business Logic**:
  - Authorization code exchange for tokens
  - JWT access token generation
  - Refresh token management
  - PKCE code verifier validation
- **Security Features**:
  - API key authentication
  - Rate limiting considerations
  - Secure random token generation

**📄 userinfo.rs**
- **Purpose**: OpenID Connect UserInfo endpoint (`/oauth2/userinfo`)
- **Business Logic**:
  - Bearer token validation
  - User profile information retrieval
  - Role aggregation per application context

**📄 introspect.rs**
- **Purpose**: RFC 7662 Token Introspection endpoint (`/oauth2/introspect`)
- **Business Logic**:
  - Token validation and metadata retrieval
  - Active/inactive token status determination

**📄 discovery.rs**
- **Purpose**: OpenID Connect Discovery endpoint (`/.well-known/openid-configuration`)
- **Business Logic**:
  - Metadata publication for client configuration
  - Endpoint advertisement
  - Supported features declaration

**📄 jwks.rs**
- **Purpose**: JSON Web Key Set endpoint (`/.well-known/jwks.json`)
- **Business Logic**:
  - Public key publication for JWT verification
  - Multi-application key management

**📄 logout.rs**
- **Purpose**: Session termination endpoint (`/oauth2/logout`)
- **Business Logic**:
  - Session cleanup
  - Redirect to post-logout URI

#### 📁 **`/src/security/`** - Cryptographic Operations

**📄 mod.rs**
- **Purpose**: Security module organization

**📄 jwt.rs**
- **Purpose**: JSON Web Token operations
- **Rust Concepts Used**:
  - External crate integration (`josekit`)
  - Error handling with custom error types
  - Cryptographic operations with proper key management
- **Business Logic**:
  - RS256 signing algorithm implementation
  - Token validation and parsing
  - Claims construction and verification

**📄 password.rs**
- **Purpose**: Password hashing and verification
- **Rust Concepts Used**:
  - Argon2id implementation for secure password hashing
  - Salt generation and verification
- **Security Features**:
  - Industry-standard password hashing
  - Constant-time comparison for timing attack protection

**📄 pkce.rs**
- **Purpose**: Proof Key for Code Exchange implementation
- **Business Logic**:
  - Code challenge generation and verification
  - S256 (SHA256) challenge method support
  - RFC 7636 compliance

#### 📁 **`/src/web/`** - HTTP Layer and User Interface

**📄 mod.rs**
- **Purpose**: Web module organization

**📄 routes.rs**
- **Purpose**: HTTP routing configuration
- **Rust Concepts Used**:
  - `axum` web framework integration
  - Router composition and middleware layering
  - State management with dependency injection
- **Business Logic**:
  - Endpoint mapping to handler functions
  - Middleware stack configuration (CORS, tracing, timeouts)
  - Cookie management setup

**📄 login.rs**
- **Purpose**: User authentication endpoints
- **Business Logic**:
  - Login form presentation and processing
  - Password verification
  - Session creation and management
  - CSRF protection

**📄 register.rs**
- **Purpose**: User registration endpoints
- **Business Logic**:
  - User account creation
  - Password strength validation
  - Email verification workflow

**📄 consent.rs**
- **Purpose**: OAuth2 consent screen handling
- **Business Logic**:
  - Scope approval interface
  - User consent recording
  - Authorization code issuance

### 📄 **`main.rs`** - Application Entry Point

**Purpose**: Application bootstrap and server initialization

**Rust Concepts Used**:
- `#[tokio::main]` for async runtime
- Module system with `mod` declarations
- Error propagation with `?` operator
- Middleware composition with `tower` ecosystem
- Structured logging with `tracing`

**Business Logic**:
- Configuration loading from environment
- Database connection establishment
- HTTP server startup with graceful shutdown
- Middleware stack configuration (CORS, tracing, timeouts)

**Key Features**:
- Automatic database migrations
- Comprehensive logging setup
- Production-ready HTTP server configuration

### 📄 **`keygen.rs`** - Key Generation Utility

**Purpose**: RSA key pair generation for JWT signing

**Rust Concepts Used**:
- Conditional compilation with `#[cfg]` attributes
- Binary target configuration in `Cargo.toml`
- Cryptographic key generation

## 🏗️ Architecture Patterns

### Multi-Tenant Architecture
- **Tenant Isolation**: All data queries are tenant-scoped
- **Per-Application Keys**: Each application has its own RSA keypair
- **Shared Infrastructure**: Common authentication logic across tenants

### Security-First Design
- **Defense in Depth**: Multiple layers of security validation
- **Principle of Least Privilege**: Minimal scope grants
- **Secure by Default**: PKCE required, strong password hashing

### Database Design
- **Normalized Schema**: Proper foreign key relationships
- **Performance Optimization**: Strategic indexing
- **Data Integrity**: Constraints and validation at database level

## 📚 Rust Concepts Explained

### Memory Management
- **Ownership**: Each value has a single owner, preventing memory leaks
- **Borrowing**: References allow access without transferring ownership
- **Lifetimes**: Ensure references remain valid during their usage
- **Arc<T>**: Atomic reference counting for shared ownership in concurrent contexts

### Error Handling
- **Result<T, E>**: Explicit error handling without exceptions
- **? Operator**: Early return on error, propagating errors up the call stack
- **anyhow**: Flexible error handling for applications
- **thiserror**: Structured error types for libraries

### Concurrency
- **async/await**: Non-blocking asynchronous programming
- **tokio**: Async runtime for handling I/O operations
- **Arc + Mutex**: Thread-safe shared state when needed

### Type System
- **Generics**: Type parameters for reusable code (e.g., `Result<T, E>`)
- **Traits**: Interface definitions for shared behavior
- **Derive Macros**: Automatic implementation of common traits
- **Option<T>**: Type-safe null handling

### Serialization
- **serde**: Framework for serializing/deserializing data structures
- **JSON Support**: Automatic conversion between Rust structs and JSON
- **Custom Serialization**: Control over data representation

## 🔒 Security Implementation

### OAuth2 Compliance
- **RFC 6749**: Core OAuth2 specification compliance
- **RFC 7636**: PKCE implementation for public clients
- **RFC 7662**: Token introspection endpoint
- **RFC 9700**: Security best practices implementation

### Cryptographic Operations
- **RS256**: RSA signature with SHA-256 for JWT signing
- **Argon2id**: Password hashing with salt and pepper
- **PKCE S256**: SHA-256 code challenge method
- **Random Generation**: Cryptographically secure randomness

### Session Management
- **HttpOnly Cookies**: Prevent XSS attacks
- **SameSite=Lax**: CSRF protection
- **CSRF Tokens**: Additional CSRF protection for forms
- **Session Expiration**: Time-based session invalidation

## 🗃️ Database Schema Design

### Core Entities
1. **Tenants**: Organization-level isolation
2. **Applications**: OAuth2 clients with individual configuration
3. **Users**: End-user accounts within tenants
4. **Roles**: Named permissions within tenant context

### OAuth2 Entities
1. **Auth Codes**: Short-lived authorization codes
2. **Refresh Tokens**: Long-lived tokens for re-authorization
3. **Sessions**: User session state with CSRF protection

### Relationships
- **One-to-Many**: Tenant → Applications, Users, Roles
- **Many-to-Many**: Applications ↔ Roles, Users ↔ Roles
- **Foreign Keys**: Ensure referential integrity

## 🚀 Performance Considerations

### Database Optimization
- **Connection Pooling**: Managed by SQLx for efficient connection reuse
- **Prepared Statements**: Compile-time SQL verification and optimization
- **Indexes**: Strategic indexing on frequently queried columns
- **Pagination**: Large result set handling

### Memory Management
- **Zero-Copy**: Minimize memory allocations where possible
- **Arc**: Shared ownership for database connections
- **Streaming**: Process large datasets without loading into memory

### Caching Strategy
- **Application-Level**: Configuration and key caching
- **Database-Level**: Query result caching opportunities
- **HTTP-Level**: Static resource caching headers

## 🧪 Testing Strategy

### Unit Tests
- **Pure Functions**: Business logic testing
- **Mock Databases**: Isolated testing with test databases
- **Error Scenarios**: Comprehensive error handling validation

### Integration Tests
- **End-to-End**: Complete OAuth2 flows
- **Database**: Real database operations with migrations
- **HTTP**: Full request/response cycle testing

## 🔧 Development Workflow

### Code Organization
- **Module System**: Clear separation of concerns
- **Re-exports**: Clean public APIs through `mod.rs` files
- **Documentation**: Comprehensive inline documentation

### Build System
- **Cargo**: Rust's package manager and build tool
- **Features**: Optional compilation features
- **Binary Targets**: Multiple binaries from single codebase

---

*This documentation is living and should be updated as the codebase evolves. Each section provides both technical implementation details and business context for comprehensive understanding.*
