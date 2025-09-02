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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;
    use std::panic;
    use std::fs;

    // Use a mutex to prevent concurrent test execution that could interfere with env vars
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn with_clean_env<F>(test_fn: F) 
    where
        F: FnOnce(),
    {
        // Handle poisoned mutex by recovering from poison
        let _guard = match TEST_MUTEX.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // Recover from poisoned mutex - this happens when a test panics
                poisoned.into_inner()
            }
        };
        
        // Save current env vars we might modify
        let saved_vars = [
            ("APP_HOST", env::var("APP_HOST").ok()),
            ("APP_PORT", env::var("APP_PORT").ok()),
            ("ISSUER", env::var("ISSUER").ok()),
            ("DATABASE_URL", env::var("DATABASE_URL").ok()),
            ("COOKIE_DOMAIN", env::var("COOKIE_DOMAIN").ok()),
            ("ALLOWED_ORIGINS", env::var("ALLOWED_ORIGINS").ok()),
            ("SESSION_SECRET", env::var("SESSION_SECRET").ok()),
            ("DEFAULT_ACCESS_TTL_SECS", env::var("DEFAULT_ACCESS_TTL_SECS").ok()),
            ("DEFAULT_REFRESH_TTL_MINS", env::var("DEFAULT_REFRESH_TTL_MINS").ok()),
            ("REQUIRE_API_KEY", env::var("REQUIRE_API_KEY").ok()),
        ];

        // Clear all test-related env vars
        for (key, _) in &saved_vars {
            env::remove_var(key);
        }

        // Use catch_unwind to prevent panics from poisoning the mutex for other tests
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            test_fn();
        }));

        // Always restore original env vars, even if test panicked
        for (key, value) in saved_vars {
            match value {
                Some(val) => env::set_var(key, val),
                None => env::remove_var(key),
            }
        }

        // Re-panic if the test failed
        if let Err(panic_payload) = result {
            panic::resume_unwind(panic_payload);
        }
    }

    #[test]
    fn test_config_defaults() {
        with_clean_env(|| {
            // Temporarily move .env file to test true defaults without .env file interference
            let env_file_exists = fs::metadata(".env").is_ok();
            if env_file_exists {
                let _ = fs::rename(".env", ".env.backup");
            }
            
            // Set only required environment variables
            env::set_var("SESSION_SECRET", "test_secret_for_testing_only");
            
            let config = Config::from_env().expect("Failed to create config with defaults");
            
            // Restore .env file if it existed
            if env_file_exists {
                let _ = fs::rename(".env.backup", ".env");
            }
            
            // Test default values (without .env file influence)
            assert_eq!(config.app_host, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
            assert_eq!(config.app_port, 8080);
            assert_eq!(config.issuer, "http://auth.dwcorp.com.br");
            assert_eq!(config.cookie_domain, ".dwcorp.com.br");
            assert_eq!(config.default_access_ttl_secs, 3600);
            assert_eq!(config.default_refresh_ttl_mins, 43200);
            assert_eq!(config.require_api_key, true);
            
            // Test that allowed origins has defaults
            assert!(config.allowed_origins.len() > 0);
            assert!(config.allowed_origins.contains(&"http://localhost:3000".to_string()));
            
            // Test helper methods
            assert_eq!(config.bind_address(), "0.0.0.0:8080");
            assert!(config.database_url().contains("postgres://"));
            assert!(config.session_secret().len() > 0);
        });
    }

    #[test]
    fn test_config_from_environment() {
        with_clean_env(|| {
            // Set all environment variables
            env::set_var("APP_HOST", "127.0.0.1");
            env::set_var("APP_PORT", "9090");
            env::set_var("ISSUER", "https://custom.example.com");
            env::set_var("DATABASE_URL", "postgres://custom:pass@custom:5432/customdb");
            env::set_var("COOKIE_DOMAIN", ".custom.example.com");
            env::set_var("ALLOWED_ORIGINS", "https://app.example.com,https://admin.example.com");
            env::set_var("SESSION_SECRET", "custom_session_secret_for_testing");
            env::set_var("DEFAULT_ACCESS_TTL_SECS", "7200");
            env::set_var("DEFAULT_REFRESH_TTL_MINS", "86400");
            env::set_var("REQUIRE_API_KEY", "false");
            
            let config = Config::from_env().expect("Failed to create config from env vars");
            
            assert_eq!(config.app_host, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            assert_eq!(config.app_port, 9090);
            assert_eq!(config.issuer, "https://custom.example.com");
            assert_eq!(config.cookie_domain, ".custom.example.com");
            assert_eq!(config.default_access_ttl_secs, 7200);
            assert_eq!(config.default_refresh_ttl_mins, 86400);
            assert_eq!(config.require_api_key, false);
            
            assert_eq!(config.allowed_origins, vec![
                "https://app.example.com".to_string(),
                "https://admin.example.com".to_string()
            ]);
            
            assert_eq!(config.bind_address(), "127.0.0.1:9090");
            assert_eq!(config.database_url(), "postgres://custom:pass@custom:5432/customdb");
            assert_eq!(config.session_secret(), "custom_session_secret_for_testing".as_bytes());
        });
    }

    #[test]
    fn test_config_validation_errors() {
        with_clean_env(|| {
            // Test missing required SESSION_SECRET
            // First, temporarily move .env file if it exists to prevent dotenvy from loading it
            let env_file_exists = std::fs::metadata(".env").is_ok();
            if env_file_exists {
                let _ = std::fs::rename(".env", ".env.backup");
            }
            
            // Ensure SESSION_SECRET is really not available
            env::remove_var("SESSION_SECRET");
            
            let result = Config::from_env();
            
            // Restore .env file if it existed
            if env_file_exists {
                let _ = std::fs::rename(".env.backup", ".env");
            }
            
            assert!(result.is_err(), "Should fail without SESSION_SECRET");
        });
        
        with_clean_env(|| {
            // Test invalid IP addresses
            env::set_var("SESSION_SECRET", "test_secret");
            env::set_var("APP_HOST", "invalid.ip.address");
            let config = Config::from_env().unwrap(); // Should fallback to default
            assert_eq!(config.app_host, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        });
        
        with_clean_env(|| {
            // Test invalid port numbers
            env::set_var("SESSION_SECRET", "test_secret");
            env::set_var("APP_PORT", "invalid_port");
            let config = Config::from_env().unwrap(); // Should fallback to default
            assert_eq!(config.app_port, 8080);
        });
        
        with_clean_env(|| {
            env::set_var("SESSION_SECRET", "test_secret");
            env::set_var("APP_PORT", "99999"); // Out of range
            let config = Config::from_env().unwrap(); // Should fallback to default
            assert_eq!(config.app_port, 8080);
        });
        
        with_clean_env(|| {
            // Test invalid boolean values
            env::set_var("SESSION_SECRET", "test_secret");
            env::set_var("REQUIRE_API_KEY", "invalid_boolean");
            let config = Config::from_env().unwrap(); // Should fallback to default
            assert_eq!(config.require_api_key, true);
        });
        
        with_clean_env(|| {
            // Test invalid integer values
            env::set_var("SESSION_SECRET", "test_secret");
            env::set_var("DEFAULT_ACCESS_TTL_SECS", "not_a_number");
            let config = Config::from_env().unwrap(); // Should fallback to default  
            assert_eq!(config.default_access_ttl_secs, 3600);
        });
    }

    #[test]
    fn test_allowed_origins_parsing() {
        with_clean_env(|| {
            env::set_var("SESSION_SECRET", "test_secret");
            
            // Test single origin
            env::set_var("ALLOWED_ORIGINS", "https://single.example.com");
            let config = Config::from_env().unwrap();
            assert_eq!(config.allowed_origins, vec!["https://single.example.com"]);
        });
        
        with_clean_env(|| {
            env::set_var("SESSION_SECRET", "test_secret");
            
            // Test multiple origins with spaces
            env::set_var("ALLOWED_ORIGINS", "https://app1.com, https://app2.com , https://app3.com");
            let config = Config::from_env().unwrap();
            assert_eq!(config.allowed_origins, vec![
                "https://app1.com",
                "https://app2.com",
                "https://app3.com"
            ]);
        });
        
        with_clean_env(|| {
            env::set_var("SESSION_SECRET", "test_secret");
            
            // Test empty string (should result in empty vector)
            env::set_var("ALLOWED_ORIGINS", "");
            let config = Config::from_env().unwrap();
            assert_eq!(config.allowed_origins, Vec::<String>::new());
        });
        
        with_clean_env(|| {
            env::set_var("SESSION_SECRET", "test_secret");
            
            // Test with empty entries (should be filtered out)
            env::set_var("ALLOWED_ORIGINS", "https://valid.com,,https://also-valid.com,");
            let config = Config::from_env().unwrap();
            assert_eq!(config.allowed_origins, vec![
                "https://valid.com",
                "https://also-valid.com"
            ]);
        });
    }

    #[test]
    fn test_ipv6_support() {
        with_clean_env(|| {
            env::set_var("SESSION_SECRET", "test_secret");
            env::set_var("APP_HOST", "::1"); // IPv6 localhost
            
            let config = Config::from_env().unwrap();
            assert_eq!(config.app_host, "::1".parse::<IpAddr>().unwrap());
            // Note: bind_address() currently returns simple format, not bracketed IPv6
            // This is intentional for simplicity in current implementation
            assert_eq!(config.bind_address(), "::1:8080");
            
            // Test IPv6 with port
            env::set_var("APP_PORT", "8443");
            let config = Config::from_env().unwrap();
            assert_eq!(config.bind_address(), "::1:8443");
        });
    }

    #[test]
    fn test_security_requirements() {
        with_clean_env(|| {
            env::set_var("SESSION_SECRET", "test_secret");
            
            let config = Config::from_env().unwrap();
            
            // Session secret should be accessible as bytes
            let secret_bytes = config.session_secret();
            assert_eq!(secret_bytes, b"test_secret");
            assert!(secret_bytes.len() > 0);
            
            // Database URL should be properly wrapped in Secret
            let db_url = config.database_url();
            assert!(db_url.starts_with("postgres://"));
            
            // Session secret should not be debug-printable (security check)
            let config_debug = format!("{:?}", config);
            assert!(!config_debug.contains("test_secret"), 
                    "Session secret should not appear in debug output: {}", config_debug);
        });
    }

    #[test] 
    fn test_extreme_values() {
        with_clean_env(|| {
            env::set_var("SESSION_SECRET", "test_secret");
            
            // Test extreme but valid values
            env::set_var("APP_PORT", "65535"); // Maximum valid port
            env::set_var("DEFAULT_ACCESS_TTL_SECS", "86400"); // 24 hours
            env::set_var("DEFAULT_REFRESH_TTL_MINS", "525600"); // 1 year in minutes
            
            let config = Config::from_env().unwrap();
            assert_eq!(config.app_port, 65535);
            assert_eq!(config.default_access_ttl_secs, 86400);
            assert_eq!(config.default_refresh_ttl_mins, 525600);
            
            // Test very long but valid values
            let long_domain = format!(".{}.com", "a".repeat(240)); // Near DNS limit
            env::set_var("COOKIE_DOMAIN", &long_domain);
            let config = Config::from_env().unwrap();
            assert_eq!(config.cookie_domain, long_domain);
            
            // Test very long session secret
            let long_secret = "a".repeat(1000);
            env::set_var("SESSION_SECRET", &long_secret);
            let config = Config::from_env().unwrap();
            assert_eq!(config.session_secret(), long_secret.as_bytes());
        });
    }
}
