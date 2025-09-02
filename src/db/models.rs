// [library] Serde - JSON serialization/deserialization framework for Rust
// Serialize: convert Rust structs to JSON for API responses
// Deserialize: parse JSON/form data into Rust structs
use serde::{Deserialize, Serialize};

// [library] SQLx type mappings for PostgreSQL-specific types
// OffsetDateTime: timezone-aware timestamps that map to TIMESTAMPTZ
// Json<T>: wrapper for JSONB columns, provides automatic JSON serialization
use sqlx::types::{time::OffsetDateTime, Json};

// [library] UUID v4 support - globally unique identifiers
// Preferred over auto-incrementing integers for public APIs and security
use uuid::Uuid;

// [business] Tenant entity - represents an organization/company in multi-tenant architecture
// Each tenant has isolated data and can have multiple applications and users
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
// [rust] Derive attributes provide automatic trait implementations:
// - Debug: enables {:?} formatting for logging
// - Clone: enables copying (cheap for most fields)
// - Serialize/Deserialize: automatic JSON conversion
// - sqlx::FromRow: automatic mapping from database rows
pub struct Tenant {
    pub id: Uuid,     // [business] Primary key - globally unique tenant identifier
    pub slug: String, // [business] URL-friendly identifier (e.g., "dwcorp")
    pub name: String, // [business] Human-readable organization name
    pub created_at: OffsetDateTime, // [business] Timestamp with timezone information
}

// [business] OAuth2 application/client entity - represents a registered OAuth2 client
// Each application belongs to a tenant and has its own RSA keypair for JWT signing
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Application {
    pub id: Uuid,                      // [business] Internal primary key
    pub tenant_id: Uuid,               // [business] Foreign key - which tenant owns this app
    pub client_id: Uuid, // [business] OAuth2 client_id - public identifier used in auth flows
    pub client_secret: Option<String>, // [security] OAuth2 client secret - for confidential clients only
    pub name: String,                  // [business] Human-readable application name

    // [business] OAuth2 redirect URI validation - exact string matching required by spec
    pub redirect_uris: Vec<String>, // [security] Allowed redirect URIs after authorization
    pub post_logout_redirect_uris: Vec<String>, // [security] Allowed URIs after logout

    // [security] JWT signing configuration - each app has its own RSA keypair
    pub jwk_kid: Uuid,           // [security] Key ID for JWT header (kid claim)
    pub jwk_private_pem: String, // [security] RSA private key in PEM format
    pub jwk_public_jwk: Json<serde_json::Value>, // [security] Public key in JWK format for JWKS endpoint

    pub api_key: String, // [security] API key for token endpoint authentication
    pub enabled: bool,   // [business] Application enable/disable flag
    pub created_at: OffsetDateTime, // [business] Creation timestamp
}

// [business] User entity - represents an end user within a specific tenant
// Users are tenant-scoped and can have roles assigned within applications
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid, // [business] Primary key - globally unique user identifier (sub claim in JWT)
    pub tenant_id: Uuid, // [business] Foreign key - which tenant this user belongs to
    pub email: String, // [business] User's email address (unique identifier for login)
    pub email_verified: bool, // [business] Email verification status for security
    pub password_hash: String, // [security] Argon2id hashed password - never store plaintext

    // [business] Optional user profile information for OpenID Connect
    pub given_name: Option<String>, // [rust] Option<T> represents nullable fields
    pub family_name: Option<String>, // [rust] None if not provided, Some(value) if set

    pub created_at: OffsetDateTime, // [business] Account creation timestamp
    pub disabled: bool,             // [business] Account disable flag for admin control
}

// [business] Role entity - represents a named permission/role within a tenant
// Used for Role-Based Access Control (RBAC) - users can have multiple roles
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,        // [business] Primary key
    pub tenant_id: Uuid, // [business] Foreign key - roles are tenant-scoped
    pub name: String,    // [business] Role name (e.g., "admin", "user", "editor")
}

// [business] OAuth2 authorization code entity - short-lived codes for token exchange
// Part of the authorization code flow - codes are single-use and expire quickly
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthCode {
    pub code: String,         // [security] Random authorization code (primary key)
    pub client_id: Uuid,      // [business] Which OAuth2 client requested this code
    pub tenant_id: Uuid,      // [business] Tenant context for data isolation
    pub user_id: Uuid,        // [business] Which user authorized the request
    pub redirect_uri: String, // [security] Exact redirect URI that must match during token exchange
    pub scope: Vec<String>,   // [business] Requested scopes (e.g., ["openid", "email", "profile"])

    // [security] PKCE (Proof Key for Code Exchange) parameters - required for all clients
    pub code_challenge: String, // [security] SHA256 hash of the code verifier
    pub code_challenge_method: String, // [security] "S256" - hashing method used

    // [business] Optional OpenID Connect parameters
    pub nonce: Option<String>, // [security] Prevents replay attacks in ID tokens
    pub state: Option<String>, // [security] CSRF protection parameter

    // [business] Lifecycle management
    pub created_at: OffsetDateTime, // [business] When the code was issued
    pub expires_at: OffsetDateTime, // [security] Short expiration (typically 5-10 minutes)
    pub consumed: bool,             // [security] Single-use flag - prevents code reuse
}

// [business] OAuth2 refresh token entity - long-lived tokens for obtaining new access tokens
// Allows clients to get new access tokens without user interaction
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RefreshToken {
    pub token: String, // [security] Opaque refresh token (primary key, cryptographically random)
    pub client_id: Uuid, // [business] Which OAuth2 client owns this token
    pub tenant_id: Uuid, // [business] Tenant context for data isolation
    pub user_id: Uuid, // [business] Which user this token represents
    pub scope: Vec<String>, // [business] Authorized scopes for this token
    pub created_at: OffsetDateTime, // [business] Token issuance time
    pub expires_at: OffsetDateTime, // [security] Long expiration (typically 30 days)
    pub revoked: bool, // [security] Token revocation flag for immediate invalidation
}

// [business] User session entity - tracks user authentication state and CSRF protection
// Used for web UI authentication and maintaining login state across requests
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid, // [business] Primary key - session identifier stored in cookie
    pub user_id: Option<Uuid>, // [business] None for anonymous sessions, Some(id) for authenticated
    pub tenant_id: Option<Uuid>, // [business] Tenant context (set when user_id is set)
    pub csrf: String, // [security] CSRF token for form submission protection
    pub created_at: OffsetDateTime, // [business] Session creation time
    pub expires_at: OffsetDateTime, // [security] Session expiration for automatic cleanup
}

// [business] Data Transfer Objects (DTOs) for API responses
// These structs define the JSON structure returned to OAuth2 clients

// [business] OAuth2 token endpoint response - RFC 6749 compliant
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String, // [security] JWT access token for API authentication
    pub id_token: String,     // [security] OpenID Connect ID token with user claims
    pub refresh_token: String, // [security] Opaque token for obtaining new access tokens
    pub token_type: String,   // [business] Always "Bearer" for JWT tokens
    pub expires_in: i64,      // [business] Access token lifetime in seconds
}

// [business] OpenID Connect UserInfo endpoint response
// Provides user profile information based on authorized scopes
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String, // [business] Subject - unique user identifier (same as JWT sub claim)
    pub email: String, // [business] User's email address
    pub email_verified: bool, // [business] Email verification status
    pub name: Option<String>, // [business] Full name (derived from given + family name)
    pub given_name: Option<String>, // [business] First name
    pub family_name: Option<String>, // [business] Last name
    pub tenant: String, // [business] Tenant identifier (custom claim)
    pub roles: Vec<String>, // [business] User's roles within the requesting application
}

// [business] RFC 7662 Token Introspection response
// Provides metadata about access tokens for resource servers
#[derive(Debug, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool, // [business] Whether the token is currently valid

    // [rust] skip_serializing_if removes fields with None values from JSON
    // This creates cleaner API responses and follows RFC 7662 recommendations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>, // [business] Space-separated list of token scopes

    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>, // [business] OAuth2 client that obtained this token

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>, // [business] User identifier (subject)

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>, // [business] "access_token" for access tokens

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>, // [business] Expiration timestamp (Unix epoch)

    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>, // [business] Issued at timestamp (Unix epoch)

    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>, // [business] Token issuer URL
}

// [business] JSON Web Key Set (JWKS) response for /.well-known/jwks.json
// Provides public keys for JWT signature verification
#[derive(Debug, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<serde_json::Value>, // [security] Array of JWK public keys in JSON format
}

// [business] OpenID Connect Discovery response for /.well-known/openid-configuration
// Advertises server capabilities and endpoint URLs to OAuth2/OIDC clients
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcDiscoveryResponse {
    pub issuer: String,                        // [business] OAuth2 issuer identifier
    pub authorization_endpoint: String,        // [business] /oauth2/authorize endpoint URL
    pub token_endpoint: String,                // [business] /oauth2/token endpoint URL
    pub userinfo_endpoint: String,             // [business] /oauth2/userinfo endpoint URL
    pub jwks_uri: String,                      // [business] /.well-known/jwks.json URL
    pub response_types_supported: Vec<String>, // [business] ["code"] - authorization code flow
    pub id_token_signing_alg_values_supported: Vec<String>, // [security] ["RS256"] - RSA signature algorithm
    pub scopes_supported: Vec<String>, // [business] ["openid", "email", "profile"]
    pub claims_supported: Vec<String>, // [business] Available JWT claims
    pub token_endpoint_auth_methods_supported: Vec<String>, // [security] API key authentication method
    pub code_challenge_methods_supported: Vec<String>,      // [security] ["S256"] - PKCE support
}

// [business] OAuth2 error response structure - RFC 6749 compliant error handling
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthError {
    pub error: String, // [business] Standard OAuth2 error codes (e.g., "invalid_request")

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>, // [business] Human-readable error description

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>, // [business] URI to error documentation

    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>, // [security] Echo back the client's state parameter
}

// [rust] Implementation block for OAuthError - provides constructor and builder methods
impl OAuthError {
    // [rust] Constructor function - creates a new error with just the error code
    pub fn new(error: &str) -> Self {
        Self {
            error: error.to_string(), // [rust] Convert &str to owned String
            error_description: None,
            error_uri: None,
            state: None,
        }
    }

    // [rust] Builder pattern method - adds description and returns self for chaining
    // `mut self` takes ownership and allows modification
    pub fn with_description(mut self, description: &str) -> Self {
        self.error_description = Some(description.to_string());
        self // [rust] Return modified self for method chaining
    }

    // [rust] Builder pattern method - adds state parameter for CSRF protection
    pub fn with_state(mut self, state: Option<String>) -> Self {
        self.state = state;
        self // [rust] Return self for method chaining
    }
}

// [business] Helper struct for user data with resolved roles
// Used internally for business logic that needs user + role information together
#[derive(Debug, Clone)]
pub struct UserWithRoles {
    pub user: User,         // [business] User entity with basic profile information
    pub roles: Vec<String>, // [business] Role names this user has within the current application context
}
