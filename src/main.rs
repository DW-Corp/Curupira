// [rust] Module declarations - tells Rust which source files are part of this crate
mod config; // Configuration management and environment variable handling
mod db; // Database models, queries, and connection pooling
mod oauth; // OAuth2/OpenID Connect protocol implementation
mod security; // Cryptographic operations (JWT, password hashing, PKCE)
mod web; // HTTP routing, handlers, and web UI

// [rust] Conditional compilation - only include keygen module when NOT building the keygen binary
// This prevents circular dependencies when building the separate keygen utility
#[cfg(not(feature = "bin"))]
mod keygen;

// [library] Error handling crate - provides flexible error types for applications
// `Result<T>` is a type alias for `Result<T, anyhow::Error>` - simplifies error propagation
use anyhow::Result;

// [library] HTTP utilities from axum web framework
use axum::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE}, // [business] Standard HTTP headers for API requests
    HeaderValue,
    Method, // [rust] Types for HTTP header values and methods
};

// [business] Local modules - bringing our configuration and database utilities into scope
use config::Config; // Application configuration management
use db::create_pool; // Database connection pool factory

// [rust] Standard library Duration type for representing time spans (unused, commented out)
// use std::time::Duration;

// [library] Tower ecosystem - middleware and service abstractions for HTTP servers
use tower_http::{
    cors::CorsLayer,   // [security] Cross-Origin Resource Sharing middleware
    trace::TraceLayer, // [library] HTTP request/response logging middleware
};

// [library] Structured logging framework - provides hierarchical, contextual logging
use tracing::info; // Logging macros (LevelFilter unused, removed)
use tracing_subscriber::{EnvFilter, FmtSubscriber}; // Log formatting and environment-based filtering

// [rust] Attribute macro that transforms this function to run in tokio's async runtime
// tokio is a multi-threaded async runtime that handles I/O operations efficiently
#[tokio::main]
async fn main() -> Result<()> {
    // [library] Initialize structured logging system for observability and debugging
    // FmtSubscriber formats log output in human-readable format
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(
            // [library] Environment-based log filtering - allows runtime log level control
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("curupira=info,tower_http=debug")),
        )
        .finish();

    // [library] Set the global default subscriber for all tracing throughout the application
    // Uses expect() because logging failure should cause immediate program termination
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    // [business] Application startup banner with emoji for easy log identification
    info!("🛡️  Starting Curupira - OAuth2 + OpenID Connect Identity Provider");

    // [business] Load application configuration from environment variables
    // Uses ? operator for early return on configuration errors - fail fast principle
    let config = Config::from_env()?;
    let bind_address = config.bind_address();

    // [business] Database connection establishment with automatic migrations
    info!("Connecting to database...");
    // [rust] await keyword suspends this function until the async operation completes
    // ? operator propagates database connection errors up the call stack
    let db = create_pool(config.database_url()).await?;
    info!("Database connection established and migrations applied");

    // [business] HTTP application setup - routes, middleware, and state injection
    info!("Setting up routes...");

    // [security] Convert allowed origins from config to HeaderValue format for CORS
    // [library] tower-http CorsLayer requires HeaderValue type for origins
    let allowed_origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter() // [rust] Borrowing iterator over Vec<String>
        .filter_map(|origin| origin.parse().ok()) // [rust] String -> HeaderValue conversion, ignore invalid
        .collect(); // [rust] Iterator -> Vec<HeaderValue> collection

    let app = web::create_app_router(db, config)
        .layer(
            // [security] CORS configuration for web browser security model compliance
            // [security] Cannot combine allow_credentials(true) with allow_origin(Any/*) per CORS spec
            CorsLayer::new()
                .allow_origin(allowed_origins) // [security] Specific origins required for credentialed requests
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS]) // [business] OAuth2 required methods
                .allow_headers([ACCEPT, AUTHORIZATION, CONTENT_TYPE]) // [business] OAuth2 required headers
                .allow_credentials(true), // [security] Enable cookies/authorization headers for session management
        )
        .layer(
            // [library] HTTP request/response logging for observability and debugging
            TraceLayer::new_for_http(),
        );

    // [business] HTTP server startup with graceful error handling
    info!("🚀 Server starting on {}", bind_address);
    // [rust] TCP listener binding - creates socket for incoming connections
    let listener = tokio::net::TcpListener::bind(&bind_address).await?;

    // [library] axum's HTTP server - handles concurrent requests using tokio's async runtime
    // This call blocks until server shutdown or error occurs
    axum::serve(listener, app.into_make_service()).await?;

    // [rust] Explicit Ok(()) return - main function succeeds
    Ok(())
}
