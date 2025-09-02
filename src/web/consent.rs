use crate::{
    config::Config,
    db::{queries, Database}, // models::* import removed as unused
    // security::generate_random_token, // Unused import removed
};
use axum::{extract::State, http::StatusCode, response::Html, Form};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use tower_cookies::Cookies;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub action: String, // "approve" or "deny"
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub csrf_token: String,
}

/// POST /consent - Handle consent form submission
pub async fn consent_handler(
    State(db): State<Database>,
    State(_config): State<Config>,
    cookies: Cookies,
    Form(form): Form<ConsentForm>,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    info!("Consent form submitted for client_id: {}", form.client_id);

    // Get current session
    let session_id = cookies
        .get("session")
        .and_then(|cookie| cookie.value().parse::<Uuid>().ok())
        .ok_or_else(|| {
            warn!("Consent form submitted without valid session");
            (StatusCode::BAD_REQUEST, Html("Invalid session".to_string()))
        })?;

    let session = queries::get_session(&db, &session_id)
        .await
        .map_err(|e| {
            error!("Database error getting session: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("Internal server error".to_string()),
            )
        })?
        .ok_or_else(|| {
            warn!("Session not found for consent");
            (StatusCode::BAD_REQUEST, Html("Invalid session".to_string()))
        })?;

    // Verify CSRF token
    if session.csrf != form.csrf_token {
        warn!("CSRF token mismatch in consent form");
        return Err((
            StatusCode::BAD_REQUEST,
            Html("Invalid request. Please try again.".to_string()),
        ));
    }

    // Verify user is logged in
    let user_id = session.user_id.ok_or_else(|| {
        warn!("Consent form submitted without logged in user");
        (
            StatusCode::UNAUTHORIZED,
            Html("Please log in first".to_string()),
        )
    })?;

    let tenant_id = session.tenant_id.ok_or_else(|| {
        error!("Session missing tenant_id");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html("Invalid session state".to_string()),
        )
    })?;

    // Load application to validate
    let app = queries::get_application_by_client_id(&db, &form.client_id)
        .await
        .map_err(|e| {
            error!("Database error loading application: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("Internal server error".to_string()),
            )
        })?
        .ok_or_else(|| {
            warn!("Application not found for client_id: {}", form.client_id);
            (
                StatusCode::BAD_REQUEST,
                Html("Invalid application".to_string()),
            )
        })?;

    // Validate redirect_uri
    if !app.redirect_uris.contains(&form.redirect_uri) {
        warn!(
            "Invalid redirect_uri: {} for client: {}",
            form.redirect_uri, form.client_id
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Html("Invalid redirect URI".to_string()),
        ));
    }

    if form.action == "deny" {
        info!("User denied consent for client_id: {}", form.client_id);
        return Ok(Html(create_error_redirect(
            &form.redirect_uri,
            "access_denied",
            "User denied the request",
            form.state.as_deref(),
        )));
    }

    if form.action != "approve" {
        warn!("Invalid consent action: {}", form.action);
        return Err((StatusCode::BAD_REQUEST, Html("Invalid action".to_string())));
    }

    // User approved - generate authorization code
    let auth_code = generate_auth_code();
    let scopes: Vec<String> = form
        .scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Store authorization code with 5-minute expiration
    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);

    if let Err(e) = queries::create_auth_code(
        &db,
        &auth_code,
        &form.client_id,
        &tenant_id,
        &user_id,
        &form.redirect_uri,
        &scopes,
        &form.code_challenge,
        &form.code_challenge_method,
        form.nonce.as_deref(),
        form.state.as_deref(),
        expires_at,
    )
    .await
    {
        error!("Failed to create authorization code: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Html("Failed to create authorization code".to_string()),
        ));
    }

    info!(
        "Created authorization code for user {} and client {}",
        user_id, form.client_id
    );

    // Redirect back to client with authorization code
    Ok(Html(create_success_redirect(
        &form.redirect_uri,
        &auth_code,
        form.state.as_deref(),
    )))
}

fn generate_auth_code() -> String {
    // Generate a secure random code
    use rand::Rng;
    let random_bytes: [u8; 32] = rand::thread_rng().gen();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

fn create_success_redirect(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let mut params = vec![format!("code={}", urlencoding::encode(code))];

    if let Some(state) = state {
        params.push(format!("state={}", urlencoding::encode(state)));
    }

    let redirect_url = format!("{}?{}", redirect_uri, params.join("&"));

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Redirecting...</title>
</head>
<body>
    <p>Redirecting...</p>
    <script>
        window.location.href = "{}";
    </script>
</body>
</html>"#,
        redirect_url
    )
}

fn create_error_redirect(
    redirect_uri: &str,
    error: &str,
    error_description: &str,
    state: Option<&str>,
) -> String {
    let mut params = vec![
        format!("error={}", urlencoding::encode(error)),
        format!(
            "error_description={}",
            urlencoding::encode(error_description)
        ),
    ];

    if let Some(state) = state {
        params.push(format!("state={}", urlencoding::encode(state)));
    }

    let redirect_url = format!("{}?{}", redirect_uri, params.join("&"));

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Redirecting...</title>
</head>
<body>
    <p>Redirecting...</p>
    <script>
        window.location.href = "{}";
    </script>
</body>
</html>"#,
        redirect_url
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_auth_code() {
        let code1 = generate_auth_code();
        let code2 = generate_auth_code();

        // Codes should be different
        assert_ne!(code1, code2);

        // Should be properly base64url encoded (no padding)
        assert!(!code1.contains('='));
        assert!(!code2.contains('='));

        // Should be reasonable length
        assert!(code1.len() >= 40);
        assert!(code2.len() >= 40);
    }

    #[test]
    fn test_create_success_redirect() {
        let redirect = create_success_redirect(
            "https://example.com/callback",
            "test-code-123",
            Some("state-456"),
        );

        assert!(redirect.contains("https://example.com/callback"));
        assert!(redirect.contains("code=test-code-123"));
        assert!(redirect.contains("state=state-456"));
        assert!(redirect.contains("window.location.href"));
    }

    #[test]
    fn test_create_error_redirect() {
        let redirect = create_error_redirect(
            "https://example.com/callback",
            "access_denied",
            "User denied the request",
            Some("state-789"),
        );

        assert!(redirect.contains("https://example.com/callback"));
        assert!(redirect.contains("error=access_denied"));
        assert!(redirect.contains("error_description="));
        assert!(redirect.contains("state=state-789"));
    }
}
