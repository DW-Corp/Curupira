// [library] Axum web framework routing components
use axum::{
    extract::FromRef,     // [library] State extraction trait
    routing::{get, post}, // [library] HTTP method routing builders
    Router,               // [library] HTTP request router for URL pattern matching
};

// [library] Cookie management middleware for session handling
use tower_cookies::CookieManagerLayer;

// [business] Import application modules for dependency injection and routing
use crate::{
    config::Config, // [business] Application configuration
    db::Database,   // [business] Database connection pool
    oauth,          // [business] OAuth2/OpenID Connect handlers
    web::{
        consent_handler, login_handler, login_page_handler, register_handler, register_page_handler,
    }, // [business] Web UI handlers
};

// [business] Application state combining database and configuration
// This allows Axum to inject both database and config into handlers
#[derive(Debug, Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
}

impl AppState {
    pub fn new(db: Database, config: Config) -> Self {
        Self { db, config }
    }
}

// [library] Implement FromRef to allow Axum to extract Database from AppState
impl FromRef<AppState> for Database {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.db.clone()
    }
}

// [library] Implement FromRef to allow Axum to extract Config from AppState
impl FromRef<AppState> for Config {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.config.clone()
    }
}

// [business] Create the main HTTP application router with all OAuth2 and web endpoints
// Implements complete OAuth2 + OpenID Connect server with web UI for authentication
pub fn create_app_router(db: Database, config: Config) -> Router {
    let app_state = AppState::new(db, config);
    Router::new()
        // [business] RFC-compliant well-known discovery endpoints for OAuth2/OIDC clients
        .route("/.well-known/jwks.json", get(oauth::jwks_handler)) // [security] Public keys for JWT verification
        .route(
            "/.well-known/openid-configuration",
            get(oauth::discovery_handler),
        ) // [business] OIDC discovery metadata
        // [business] Core OAuth2/OpenID Connect protocol endpoints
        .route("/oauth2/authorize", get(oauth::authorize_handler)) // [business] Authorization code flow entry point
        .route("/oauth2/token", post(oauth::token_handler)) // [security] Token exchange endpoint
        .route("/oauth2/userinfo", get(oauth::userinfo_handler)) // [business] User profile information
        .route("/oauth2/introspect", post(oauth::introspect_handler)) // [business] Token validation for resource servers
        .route("/oauth2/logout", get(oauth::logout_handler)) // [business] Session termination
        // [business] Web UI endpoints for user authentication and consent
        .route("/login", get(login_page_handler)) // [business] Display login form
        .route("/login", post(login_handler)) // [business] Process login credentials
        .route("/register", get(register_page_handler)) // [business] Display registration form
        .route("/register", post(register_handler)) // [business] Process user registration
        .route("/consent", post(consent_handler)) // [business] Process OAuth2 consent decisions
        // [business] System health monitoring endpoint
        .route("/health", get(health_check)) // [business] Health check for load balancers
        // [library] Dependency injection - make database and config available to all handlers
        .with_state(app_state) // [rust] Inject combined application state
        // [library] HTTP middleware layer for session cookie management
        .layer(CookieManagerLayer::new()) // [security] Enable secure cookie handling
}

// [business] Health check endpoint for monitoring and load balancer probes
// Returns simple "OK" response to indicate service is running and responsive
async fn health_check() -> &'static str {
    "OK" // [business] Static string - minimal overhead for high-frequency checks
}

// [rust] Unit tests for HTTP routing and endpoint functionality
#[cfg(test)]
mod tests {
    use super::*;
    // Unused imports removed - tests only need basic functionality currently
    // use crate::config::Config;
    // use axum::http::StatusCode;
    // use std::sync::Arc;
    // Removed unused tower::ServiceExt import - tests don't require it currently

    #[tokio::test]
    async fn test_health_check() {
        // [business] Verify health endpoint returns expected response
        let result = health_check().await;
        assert_eq!(result, "OK"); // [rust] Assert expected health status
    }
}
