// [business] Import internal modules for OAuth2 authorization endpoint implementation
use crate::{
    config::Config,                             // [business] Application configuration
    db::{models::*, queries, Database},         // [business] Database entities and queries
    security::{generate_random_token, pkce::*}, // [security] Random token generation and PKCE validation
};

// [library] Axum web framework components for HTTP handling
use axum::{
    extract::{Query, State}, // [library] Request parameter extraction and application state
    http::StatusCode, // [library] HTTP status codes (Uri import removed as unused)
    response::Html, // [library] HTTP response types (Redirect import removed as unused)
    // Extension,               // [library] Request extensions (middleware data) - Unused import removed
};

// [library] Base64 encoding for PKCE parameter handling (imports removed as unused)
// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _}; // [security] URL-safe base64 without padding

// [library] Serde for JSON/form serialization and deserialization
use serde::{Deserialize, Serialize};

// [rust] Standard library collections for key-value data (HashMap unused, commented out)
// use std::collections::HashMap;

// [library] Time handling for token expiration and timestamps (Duration unused, commented out)
use time::OffsetDateTime;
// use time::Duration;

// [library] Cookie management for session handling
use tower_cookies::Cookies;

// [library] Structured logging for debugging and monitoring
use tracing::{error, info, warn};

// [library] UUID handling for client IDs and session management
use uuid::Uuid;

// [business] OAuth2 authorization request parameters - RFC 6749 + RFC 7636 (PKCE) compliant
#[derive(Debug, Deserialize, Clone)]
pub struct AuthorizeParams {
    pub client_id: Uuid, // [business] OAuth2 client identifier - registered application ID
    pub redirect_uri: String, // [security] Where to redirect after authorization - must be pre-registered
    pub response_type: String, // [business] Must be "code" for authorization code flow
    pub scope: String,        // [business] Space-separated list of requested permissions
    pub state: Option<String>, // [security] CSRF protection parameter - should be verified by client

    // [security] PKCE (Proof Key for Code Exchange) parameters - mandatory for security
    pub code_challenge: String, // [security] SHA256 hash of code verifier (base64url encoded)
    pub code_challenge_method: String, // [security] Must be "S256" (SHA256 hashing)

    // [business] OpenID Connect specific parameters
    pub nonce: Option<String>, // [security] Prevents token replay attacks in ID tokens
    pub prompt: Option<String>, // [business] Controls authentication/consent UI behavior
}

// [business] Data structure for rendering the OAuth2 consent page UI
// Contains all necessary information for user to make an informed authorization decision
#[derive(Debug, Serialize)]
pub struct ConsentPageData {
    pub app_name: String,    // [business] Human-readable application name
    pub tenant_name: String, // [business] Organization name that owns the app
    pub scopes: Vec<String>, // [business] Individual permission scopes to display

    // [business] OAuth2 parameters to preserve in consent form submission
    pub client_id: String,      // [business] Client ID as string for HTML form
    pub redirect_uri: String,   // [business] Where to redirect after consent
    pub state: Option<String>,  // [security] CSRF state parameter
    pub code_challenge: String, // [security] PKCE code challenge
    pub code_challenge_method: String, // [security] PKCE method ("S256")
    pub nonce: Option<String>,  // [security] OpenID Connect nonce

    pub csrf_token: String, // [security] CSRF token for consent form submission
}

// [business] GET /oauth2/authorize - OAuth2 Authorization Code flow entry point
// Implements RFC 6749 (OAuth2) + RFC 7636 (PKCE) + OpenID Connect specifications
// This is the first step in the OAuth2 flow where users are redirected from client applications
pub async fn authorize_handler(
    Query(params): Query<AuthorizeParams>, // [library] Extract query parameters from URL
    State(db): State<Database>,            // [library] Inject database connection pool
    State(_config): State<Config>,          // [library] Inject application configuration
    cookies: Cookies, // [library] Access to HTTP cookies for session management
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    // [rust] Result type for error handling
    // [library] Log authorization attempt for audit trail and debugging
    info!("Authorization request for client_id: {}", params.client_id);

    // [security] Step 1: Validate request parameters according to OAuth2 specification
    // Ensures request is well-formed and uses secure parameters before proceeding
    if let Err(error_response) = validate_authorize_params(&params) {
        return Err(error_response); // [rust] Early return on validation failure
    }

    // [business] Step 2: Load and validate the OAuth2 application from database
    // Ensures the client_id exists and is registered in our system
    let app = match queries::get_application_by_client_id(&db, &params.client_id).await {
        Ok(Some(app)) => app, // [rust] Application found - proceed with authorization
        Ok(None) => {
            // [security] Log unknown client attempt for security monitoring
            warn!("Unknown client_id: {}", params.client_id);
            return Err(create_error_response(
                &params.redirect_uri,
                "invalid_client",        // [business] OAuth2 standard error code
                "Unknown client",        // [business] Human-readable description
                params.state.as_deref(), // [security] Preserve state for CSRF protection
            ));
        }
        Err(e) => {
            // [library] Log database errors for operational monitoring
            error!("Database error checking client: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("Internal server error".to_string()),
            ));
        }
    };

    // [security] Step 3: Validate redirect URI with exact string matching
    // Critical security check - prevents authorization code hijacking attacks
    // redirect_uri must be pre-registered and match exactly (no wildcards allowed)
    if !app.redirect_uris.contains(&params.redirect_uri) {
        warn!(
            "Invalid redirect_uri: {} for client: {}",
            params.redirect_uri, params.client_id
        );
        // [security] Don't redirect to invalid URI - return error directly
        return Err((
            StatusCode::BAD_REQUEST,
            Html("Invalid redirect_uri".to_string()),
        ));
    }

    // [business] Step 4: Check user authentication status via session cookie
    // Determines if user needs to log in before proceeding with authorization
    let session_id = cookies
        .get("session") // [library] Get session cookie from request
        .and_then(|cookie| cookie.value().parse::<Uuid>().ok()); // [rust] Parse UUID, ignore invalid formats

    // [business] Load user and tenant information if session exists and is valid
    let (user, tenant) = if let Some(session_id) = session_id {
        match queries::get_session(&db, &session_id).await {
            Ok(Some(session)) if session.user_id.is_some() => {
                // [business] Session is authenticated - extract user and tenant IDs
                let user_id = session.user_id.unwrap(); // [rust] Safe unwrap due to is_some() check
                let _tenant_id = session.tenant_id.unwrap(); // [rust] Tenant always set when user is set

                match queries::get_user_by_id(&db, &user_id).await {
                    Ok(Some(user)) => {
                        // [business] Load tenant information for consent page display
                        match queries::get_tenant_by_slug(&db, &app.tenant_id.to_string()).await {
                            Ok(Some(tenant)) => (Some(user), Some(tenant)),
                            _ => (Some(user), None), // [business] User exists but tenant query failed
                        }
                    }
                    _ => (None, None), // [business] Session exists but user doesn't - invalid session
                }
            }
            _ => (None, None), // [business] No session or session not authenticated
        }
    } else {
        (None, None) // [business] No session cookie found
    };

    // [business] Step 5: Redirect to login page if user is not authenticated
    // Preserves all OAuth2 parameters so authorization can continue after login
    if user.is_none() {
        let login_url = format!(
            "/login?{}",
            preserve_oauth_params(&params) // [business] Maintain OAuth2 flow state
        );
        // [library] JavaScript redirect for better browser compatibility
        return Ok(Html(format!(
            r#"<script>window.location.href = "{}";</script>"#,
            login_url
        )));
    }

    let _user = user.unwrap();
    let tenant = tenant.unwrap_or(Tenant {
        id: app.tenant_id,
        slug: "unknown".to_string(),
        name: "Unknown Tenant".to_string(),
        created_at: OffsetDateTime::now_utc(),
    });

    // [business] Step 6: Prepare consent screen (always required for security)
    // Parse space-separated scope string into individual permissions
    let scopes: Vec<String> = params
        .scope
        .split_whitespace() // [rust] Split on any whitespace characters
        .map(|s| s.to_string()) // [rust] Convert string slices to owned strings
        .collect(); // [rust] Collect iterator into Vec<String>

    // [security] Generate CSRF token for consent form submission
    let csrf_token = generate_random_token();

    // [business] TODO: Store CSRF token in session for server-side validation
    // Currently included in form for basic protection

    let consent_data = ConsentPageData {
        app_name: app.name.clone(),
        tenant_name: tenant.name,
        scopes,
        client_id: params.client_id.to_string(),
        redirect_uri: params.redirect_uri,
        state: params.state,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        nonce: params.nonce,
        csrf_token,
    };

    // 7. Render consent page
    Ok(Html(render_consent_page(&consent_data)))
}

// [security] Validate OAuth2 authorization request parameters
// Implements security requirements from RFC 6749, RFC 7636, and RFC 9700
fn validate_authorize_params(params: &AuthorizeParams) -> Result<(), (StatusCode, Html<String>)> {
    // [business] Only authorization code flow is supported (most secure)
    // Implicit flow is deprecated and not implemented for security reasons
    if params.response_type != "code" {
        return Err((
            StatusCode::BAD_REQUEST,
            Html("Unsupported response_type. Only 'code' is supported.".to_string()),
        ));
    }

    // [security] PKCE is mandatory - RFC 9700 security best practices
    // Only SHA256 challenge method is supported ("plain" is insecure)
    if params.code_challenge_method != "S256" {
        return Err((
            StatusCode::BAD_REQUEST,
            Html("Invalid code_challenge_method. Only 'S256' is supported.".to_string()),
        ));
    }

    // [security] Validate PKCE code challenge format and length
    // Must be base64url-encoded SHA256 hash (43-128 characters)
    if let Err(_) = validate_code_challenge(&params.code_challenge) {
        return Err((
            StatusCode::BAD_REQUEST,
            Html("Invalid code_challenge format.".to_string()),
        ));
    }

    // [business] Warn if OpenID Connect scope is missing
    // Not an error, but indicates client may not get ID tokens
    if !params.scope.split_whitespace().any(|s| s == "openid") {
        warn!("Authorization request without 'openid' scope");
    }

    Ok(()) // [rust] All validations passed
}

// [business] Create OAuth2 error response that redirects back to client
// Follows RFC 6749 error response format for proper client error handling
fn create_error_response(
    redirect_uri: &str,  // [business] Client's registered redirect URI
    error: &str,         // [business] OAuth2 standard error code
    description: &str,   // [business] Human-readable error description
    state: Option<&str>, // [security] Client's state parameter for CSRF protection
) -> (StatusCode, Html<String>) {
    // [business] Build query parameters for error redirect
    let mut params = vec![
        format!("error={}", error),
        format!("error_description={}", urlencoding::encode(description)), // [security] URL encode for safe transmission
    ];

    // [security] Include state parameter if provided (CSRF protection)
    if let Some(state) = state {
        params.push(format!("state={}", urlencoding::encode(state)));
    }

    // [business] Construct full redirect URL with error parameters
    let redirect_url = format!("{}?{}", redirect_uri, params.join("&"));

    // [library] Return JavaScript redirect with HTTP 302 status
    (
        StatusCode::FOUND,
        Html(format!(
            r#"<script>window.location.href = "{}";</script>"#,
            redirect_url
        )),
    )
}

// [business] Preserve OAuth2 parameters for login redirect
// Maintains authorization flow state when user needs to authenticate first
fn preserve_oauth_params(params: &AuthorizeParams) -> String {
    // [business] Required OAuth2 parameters that must be preserved
    let mut query_params = vec![
        format!("client_id={}", params.client_id),
        format!("redirect_uri={}", urlencoding::encode(&params.redirect_uri)), // [security] URL encode for safety
        format!("response_type={}", params.response_type),
        format!("scope={}", urlencoding::encode(&params.scope)),
        // [security] PKCE parameters must be preserved for security
        format!(
            "code_challenge={}",
            urlencoding::encode(&params.code_challenge)
        ),
        format!("code_challenge_method={}", params.code_challenge_method),
    ];

    // [security] Optional parameters - include if present
    if let Some(state) = &params.state {
        query_params.push(format!("state={}", urlencoding::encode(state)));
    }

    if let Some(nonce) = &params.nonce {
        query_params.push(format!("nonce={}", urlencoding::encode(nonce)));
    }

    if let Some(prompt) = &params.prompt {
        query_params.push(format!("prompt={}", urlencoding::encode(prompt)));
    }

    // [rust] Join all parameters with & separator for query string
    query_params.join("&")
}

// [business] Generate HTML consent page for OAuth2 authorization
// Provides user-friendly interface for granting/denying application permissions
fn render_consent_page(data: &ConsentPageData) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize Application - Curupira</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 500px;
            margin: 100px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .card {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .app-info {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }}
        .scopes {{
            margin: 20px 0;
        }}
        .scope-item {{
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }}
        .buttons {{
            display: flex;
            gap: 10px;
            margin-top: 30px;
        }}
        button {{
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 4px;
            font-weight: 500;
            cursor: pointer;
        }}
        .approve {{
            background: #007bff;
            color: white;
        }}
        .deny {{
            background: #6c757d;
            color: white;
        }}
        .approve:hover {{
            background: #0056b3;
        }}
        .deny:hover {{
            background: #545b62;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h1>🛡️ Curupira</h1>
            <h2>Authorize Application</h2>
        </div>
        
        <div class="app-info">
            <h3>{}</h3>
            <p><strong>Tenant:</strong> {}</p>
            <p>This application is requesting access to your account.</p>
        </div>

        <div class="scopes">
            <h4>Requested Permissions:</h4>
            {}
        </div>

        <form method="POST" action="/consent">
            <input type="hidden" name="client_id" value="{}">
            <input type="hidden" name="redirect_uri" value="{}">
            <input type="hidden" name="code_challenge" value="{}">
            <input type="hidden" name="code_challenge_method" value="{}">
            <input type="hidden" name="scope" value="{}">
            <input type="hidden" name="csrf_token" value="{}">
            {}
            {}
            
            <div class="buttons">
                <button type="submit" name="action" value="approve" class="approve">
                    Allow Access
                </button>
                <button type="submit" name="action" value="deny" class="deny">
                    Deny
                </button>
            </div>
        </form>
    </div>
</body>
</html>"#,
        data.app_name,
        data.tenant_name,
        data.scopes
            .iter()
            .map(|scope| format!(
                r#"<div class="scope-item">• {}</div>"#,
                match scope.as_str() {
                    "openid" => "Identity information",
                    "email" => "Email address",
                    "profile" => "Profile information",
                    other => other,
                }
            ))
            .collect::<Vec<_>>()
            .join(""),
        data.client_id,
        data.redirect_uri,
        data.code_challenge,
        data.code_challenge_method,
        data.scopes.join(" "),
        data.csrf_token,
        data.state
            .as_ref()
            .map(|s| format!(r#"<input type="hidden" name="state" value="{}">"#, s))
            .unwrap_or_default(),
        data.nonce
            .as_ref()
            .map(|n| format!(r#"<input type="hidden" name="nonce" value="{}">"#, n))
            .unwrap_or_default(),
    )
}

// [rust] Unit tests for OAuth2 authorization parameter validation
// Ensures security requirements are enforced correctly
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_authorize_params() {
        // [business] Create valid OAuth2 authorization parameters for testing
        let valid_params = AuthorizeParams {
            client_id: Uuid::new_v4(),
            redirect_uri: "https://example.com/callback".to_string(),
            response_type: "code".to_string(), // [business] Only supported response type
            scope: "openid email".to_string(),
            state: Some("state123".to_string()),
            code_challenge: "a".repeat(43), // [security] Valid PKCE challenge length
            code_challenge_method: "S256".to_string(), // [security] Only supported PKCE method
            nonce: Some("nonce123".to_string()),
            prompt: None,
        };

        // [rust] Valid parameters should pass validation
        assert!(validate_authorize_params(&valid_params).is_ok());

        // [security] Test rejection of insecure implicit flow
        let mut invalid_params = valid_params.clone();
        invalid_params.response_type = "token".to_string();
        assert!(validate_authorize_params(&invalid_params).is_err());

        // [security] Test rejection of insecure PKCE method
        let mut invalid_params = valid_params.clone();
        invalid_params.code_challenge_method = "plain".to_string();
        assert!(validate_authorize_params(&invalid_params).is_err());
    }
}
