// [library] Secrecy crate - provides secure handling of sensitive data in memory
// ExposeSecret trait allows controlled access to wrapped secret values
// Secret<T> wrapper prevents accidental logging or serialization of sensitive data
use secrecy::{ExposeSecret, Secret};

// [library] Serde deserialization for automatic parsing from environment variables
// Deserialize trait enables automatic conversion from strings to typed values
use serde::Deserialize;

// [rust] Standard library networking types for IP addresses and network binding
// IpAddr is an enum that can be either IPv4 or IPv6
use std::net::{IpAddr, Ipv4Addr};

// [rust] Derive macro attributes provide automatic trait implementations
// Debug: enables {:?} formatting for logging and debugging
// Deserialize: enables automatic parsing from environment variables/config files
// Clone: enables copying config values (cheap for most fields due to Arc usage internally)
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    // [business] Network binding configuration - where the server listens for connections
    pub app_host: IpAddr, // [rust] IP address (v4 or v6) - 0.0.0.0 binds to all interfaces
    pub app_port: u16,    // [rust] Port number (16-bit unsigned integer, max 65535)

    // [business] OAuth2 issuer identifier - must match exactly what clients expect
    // Used in JWT tokens and OpenID Connect discovery responses
    pub issuer: String, // [rust] Heap-allocated string for dynamic content

    // [security] Database connection string wrapped in Secret for security
    // Secret<T> prevents accidental logging of database credentials
    pub database_url: Secret<String>,

    // [business] Cookie domain for session management - controls cookie scope
    // Leading dot (e.g., ".example.com") allows subdomains to share cookies
    pub cookie_domain: String,

    // [security] CORS allowed origins - specific origins that can make credentialed requests
    // Cannot use wildcard (*) when credentials are enabled for security reasons
    pub allowed_origins: Vec<String>,

    // [security] Session encryption key - must be cryptographically secure random bytes
    // Used for cookie encryption and CSRF token generation
    pub session_secret: Secret<String>,

    // [business] Token lifetime configuration - balances security vs. user experience
    pub default_access_ttl_secs: i64, // [business] Access token lifetime in seconds (typically 1 hour)
    pub default_refresh_ttl_mins: i64, // [business] Refresh token lifetime in minutes (typically 30 days)

    // [security] API key requirement flag - can disable for development/testing
    pub require_api_key: bool, // [rust] Boolean type - true/false
}

// [rust] Implementation block - defines methods associated with the Config struct
impl Config {
    // [business] Factory method pattern - creates Config from environment variables
    // Returns Result<Self, Error> to handle configuration errors gracefully
    pub fn from_env() -> Result<Self, anyhow::Error> {
        // [library] Load .env file if present - useful for development environments
        // .ok() converts Result to Option, discarding any file-not-found errors
        dotenvy::dotenv().ok();

        // [rust] Struct initialization with explicit field assignment
        let config = Config {
            // [rust] Environment variable parsing with fallback pattern
            // unwrap_or_else() provides a closure that runs only if env var is missing
            // parse() converts string to target type, with error handling via unwrap_or_else()
            app_host: std::env::var("APP_HOST")
                .unwrap_or_else(|_| "0.0.0.0".to_string()) // [business] Default: bind to all interfaces
                .parse() // [rust] String -> IpAddr conversion
                .unwrap_or_else(|_| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))), // [business] Fallback to IPv4 wildcard

            app_port: std::env::var("APP_PORT")
                .unwrap_or_else(|_| "8080".to_string()) // [business] Standard development port
                .parse() // [rust] String -> u16 conversion
                .unwrap_or(8080), // [business] Safe fallback port

            issuer: std::env::var("ISSUER")
                .unwrap_or_else(|_| "http://auth.dwcorp.com.br".to_string()), // [business] Default issuer URL

            // [security] Database URL wrapped in Secret to prevent accidental exposure
            database_url: Secret::new(
                std::env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "postgres://postgres:changeme@localhost:5432/authdb".to_string()), // [business] Development database URL
            ),

            cookie_domain: std::env::var("COOKIE_DOMAIN")
                .unwrap_or_else(|_| ".dwcorp.com.br".to_string()), // [business] Default cookie domain with subdomain support

            // [security] Parse comma-separated list of allowed origins for CORS
            // [business] Cannot use wildcard (*) with credentials=true per CORS spec
            allowed_origins: std::env::var("ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000,http://localhost:8080,http://auth.dwcorp.com.br,https://auth.dwcorp.com.br".to_string()) // [business] Development and production defaults
                .split(',') // [rust] String splitting on comma delimiter
                .map(|s| s.trim().to_string()) // [rust] Remove whitespace and convert to owned String
                .filter(|s| !s.is_empty()) // [rust] Remove empty strings from malformed config
                .collect(), // [rust] Iterator -> Vec<String> collection

            // [security] Session secret is REQUIRED - no default for security reasons
            session_secret: Secret::new(
                std::env::var("SESSION_SECRET")
                    .map_err(|_| anyhow::anyhow!("SESSION_SECRET must be set"))? // [rust] ? operator for early return on error
            ),

            default_access_ttl_secs: std::env::var("DEFAULT_ACCESS_TTL_SECS")
                .unwrap_or_else(|_| "3600".to_string()) // [business] 1 hour default
                .parse()
                .unwrap_or(3600), // [business] Safe fallback to 1 hour

            default_refresh_ttl_mins: std::env::var("DEFAULT_REFRESH_TTL_MINS")
                .unwrap_or_else(|_| "43200".to_string()) // [business] 30 days default (43200 minutes)
                .parse()
                .unwrap_or(43200), // [business] Safe fallback to 30 days

            require_api_key: std::env::var("REQUIRE_API_KEY")
                .unwrap_or_else(|_| "true".to_string()) // [security] Default to requiring API keys
                .parse()
                .unwrap_or(true), // [security] Safe fallback to secure default
        };

        // [library] Structured logging of configuration (without secrets) for debugging
        tracing::info!(
            "Config loaded - Host: {}:{}, Issuer: {}, API Key Required: {}",
            config.app_host,
            config.app_port,
            config.issuer,
            config.require_api_key
        );

        // [rust] Return the successfully constructed config
        Ok(config)
    }

    // [business] Helper method to create network bind address string for TCP listener
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.app_host, self.app_port) // [rust] String interpolation via format! macro
    }

    // [security] Controlled access to database URL - exposes the secret when needed
    // &self parameter makes this a method call on the instance
    // Returns &str (string slice) for efficient string handling
    pub fn database_url(&self) -> &str {
        self.database_url.expose_secret() // [security] Explicit exposure of wrapped secret
    }

    // [security] Session secret as bytes for cryptographic operations
    // as_bytes() converts String to &[u8] for crypto libraries that expect bytes
    pub fn session_secret(&self) -> &[u8] {
        self.session_secret.expose_secret().as_bytes() // [security] String -> bytes conversion
    }
}
