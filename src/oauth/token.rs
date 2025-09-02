use crate::{
    config::Config,
    db::{models::*, queries, Database},
    security::{generate_random_token, jwt::JwtSigner, pkce::verify_code_challenge},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    Form,
};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<Uuid>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

/// POST /oauth2/token - Token exchange endpoint
pub async fn token_handler(
    State(db): State<Database>,
    State(config): State<Config>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<OAuthError>)> {
    info!("Token request with grant_type: {}", request.grant_type);

    // Check API key requirement
    if config.require_api_key {
        let api_key = extract_api_key(&headers)?;

        // Validate API key belongs to the client
        let app = queries::get_application_by_api_key(&db, &api_key)
            .await
            .map_err(|e| {
                error!("Database error checking API key: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(OAuthError::new("server_error")),
                )
            })?
            .ok_or_else(|| {
                warn!("Invalid API key provided");
                (
                    StatusCode::UNAUTHORIZED,
                    Json(OAuthError::new("invalid_client")),
                )
            })?;

        // Verify client_id matches API key if provided
        if let Some(client_id) = request.client_id {
            if app.client_id != client_id {
                warn!("Client ID mismatch with API key");
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(OAuthError::new("invalid_client")),
                ));
            }
        }

        match request.grant_type.as_str() {
            "authorization_code" => {
                handle_authorization_code_grant(&db, &config, &app, request).await
            }
            "refresh_token" => handle_refresh_token_grant(&db, &config, &app, request).await,
            _ => Err((
                StatusCode::BAD_REQUEST,
                Json(OAuthError::new("unsupported_grant_type")),
            )),
        }
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(
                OAuthError::new("invalid_request")
                    .with_description("API key authentication is required"),
            ),
        ))
    }
}

async fn handle_authorization_code_grant(
    db: &Database,
    config: &Config,
    app: &Application,
    request: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<OAuthError>)> {
    // Validate required parameters
    let code = request.code.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(OAuthError::new("invalid_request").with_description("Missing 'code' parameter")),
        )
    })?;

    let redirect_uri = request.redirect_uri.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                OAuthError::new("invalid_request")
                    .with_description("Missing 'redirect_uri' parameter"),
            ),
        )
    })?;

    let code_verifier = request.code_verifier.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                OAuthError::new("invalid_request")
                    .with_description("Missing 'code_verifier' parameter for PKCE"),
            ),
        )
    })?;

    // Load and validate auth code
    let auth_code = queries::get_auth_code(db, &code)
        .await
        .map_err(|e| {
            error!("Database error checking auth code: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?
        .ok_or_else(|| {
            warn!("Invalid or expired authorization code");
            (
                StatusCode::BAD_REQUEST,
                Json(OAuthError::new("invalid_grant")),
            )
        })?;

    // Check if code is already consumed
    if auth_code.consumed {
        warn!("Authorization code already used");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                OAuthError::new("invalid_grant")
                    .with_description("Authorization code already used"),
            ),
        ));
    }

    // Check expiration
    let now = OffsetDateTime::now_utc();
    if auth_code.expires_at < now {
        warn!("Authorization code expired");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(OAuthError::new("invalid_grant").with_description("Authorization code expired")),
        ));
    }

    // Validate client_id matches
    if auth_code.client_id != app.client_id {
        warn!("Client ID mismatch in authorization code");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(OAuthError::new("invalid_grant")),
        ));
    }

    // Validate redirect_uri matches
    if auth_code.redirect_uri != redirect_uri {
        warn!("Redirect URI mismatch");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(OAuthError::new("invalid_grant")),
        ));
    }

    // PKCE verification - critical for RFC 9700 compliance
    if let Err(e) = verify_code_challenge(
        &code_verifier,
        &auth_code.code_challenge,
        &auth_code.code_challenge_method,
    ) {
        warn!("PKCE verification failed: {}", e);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(OAuthError::new("invalid_grant").with_description("PKCE verification failed")),
        ));
    }

    // Mark code as consumed
    queries::consume_auth_code(db, &code).await.map_err(|e| {
        error!("Failed to consume auth code: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OAuthError::new("server_error")),
        )
    })?;

    // Load user
    let user = queries::get_user_by_id(db, &auth_code.user_id)
        .await
        .map_err(|e| {
            error!("Database error loading user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?
        .ok_or_else(|| {
            error!("User not found for auth code");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?;

    // Get user roles for this application
    let roles = queries::get_user_roles_for_application(db, &user.id, &app.id)
        .await
        .map_err(|e| {
            error!("Database error loading user roles: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?;

    // Create JWT signer
    let jwt_signer = JwtSigner::new(config.issuer.clone());

    // Generate tokens
    let scope = auth_code.scope.join(" ");

    let access_token = jwt_signer
        .create_access_token(app, &user, roles, &scope, config.default_access_ttl_secs)
        .map_err(|e| {
            error!("Failed to create access token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?;

    let id_token = jwt_signer
        .create_id_token(
            app,
            &user,
            auth_code.nonce.clone(),
            config.default_access_ttl_secs,
        )
        .map_err(|e| {
            error!("Failed to create ID token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?;

    // Generate and store refresh token
    let refresh_token = generate_random_token();
    let refresh_expires_at = now + Duration::minutes(config.default_refresh_ttl_mins);

    queries::create_refresh_token(
        db,
        &refresh_token,
        &app.client_id,
        &auth_code.tenant_id,
        &user.id,
        &auth_code.scope,
        refresh_expires_at,
    )
    .await
    .map_err(|e| {
        error!("Failed to create refresh token: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OAuthError::new("server_error")),
        )
    })?;

    info!(
        "Successfully issued tokens for user {} and client {}",
        user.id, app.client_id
    );

    Ok(Json(TokenResponse {
        access_token,
        id_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: config.default_access_ttl_secs,
    }))
}

async fn handle_refresh_token_grant(
    db: &Database,
    config: &Config,
    app: &Application,
    request: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<OAuthError>)> {
    let refresh_token = request.refresh_token.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                OAuthError::new("invalid_request")
                    .with_description("Missing 'refresh_token' parameter"),
            ),
        )
    })?;

    // Load and validate refresh token
    let token_record = queries::get_refresh_token(db, &refresh_token)
        .await
        .map_err(|e| {
            error!("Database error checking refresh token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?
        .ok_or_else(|| {
            warn!("Invalid refresh token");
            (
                StatusCode::BAD_REQUEST,
                Json(OAuthError::new("invalid_grant")),
            )
        })?;

    // Check if token is revoked
    if token_record.revoked {
        warn!("Refresh token is revoked");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(OAuthError::new("invalid_grant")),
        ));
    }

    // Check expiration
    let now = OffsetDateTime::now_utc();
    if token_record.expires_at < now {
        warn!("Refresh token expired");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(OAuthError::new("invalid_grant")),
        ));
    }

    // Validate client matches
    if token_record.client_id != app.client_id {
        warn!("Client ID mismatch for refresh token");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(OAuthError::new("invalid_grant")),
        ));
    }

    // Load user
    let user = queries::get_user_by_id(db, &token_record.user_id)
        .await
        .map_err(|e| {
            error!("Database error loading user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?
        .ok_or_else(|| {
            error!("User not found for refresh token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?;

    // Get current user roles
    let roles = queries::get_user_roles_for_application(db, &user.id, &app.id)
        .await
        .map_err(|e| {
            error!("Database error loading user roles: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?;

    // Create JWT signer
    let jwt_signer = JwtSigner::new(config.issuer.clone());

    // Generate new tokens
    let scope = token_record.scope.join(" ");

    let access_token = jwt_signer
        .create_access_token(app, &user, roles, &scope, config.default_access_ttl_secs)
        .map_err(|e| {
            error!("Failed to create access token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?;

    let id_token = jwt_signer
        .create_id_token(app, &user, None, config.default_access_ttl_secs)
        .map_err(|e| {
            error!("Failed to create ID token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?;

    // Optionally rotate refresh token (recommended for security)
    let new_refresh_token = generate_random_token();
    let refresh_expires_at = now + Duration::minutes(config.default_refresh_ttl_mins);

    // Revoke old refresh token
    queries::revoke_refresh_token(db, &refresh_token)
        .await
        .map_err(|e| {
            error!("Failed to revoke old refresh token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?;

    // Create new refresh token
    queries::create_refresh_token(
        db,
        &new_refresh_token,
        &app.client_id,
        &token_record.tenant_id,
        &user.id,
        &token_record.scope,
        refresh_expires_at,
    )
    .await
    .map_err(|e| {
        error!("Failed to create new refresh token: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OAuthError::new("server_error")),
        )
    })?;

    info!(
        "Successfully refreshed tokens for user {} and client {}",
        user.id, app.client_id
    );

    Ok(Json(TokenResponse {
        access_token,
        id_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: config.default_access_ttl_secs,
    }))
}

fn extract_api_key(headers: &HeaderMap) -> Result<String, (StatusCode, Json<OAuthError>)> {
    // Try X-API-Key header first
    if let Some(api_key) = headers.get("x-api-key") {
        return api_key.to_str().map(|s| s.to_string()).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(
                    OAuthError::new("invalid_request").with_description("Invalid X-API-Key header"),
                ),
            )
        });
    }

    // Try Authorization: API-Key header
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(key) = auth_str.strip_prefix("API-Key ") {
                return Ok(key.to_string());
            }
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(
            OAuthError::new("invalid_client")
                .with_description("API key required in X-API-Key or Authorization header"),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_api_key() {
        let mut headers = HeaderMap::new();

        // Test X-API-Key header
        headers.insert("x-api-key", HeaderValue::from_static("test-key-123"));
        assert_eq!(extract_api_key(&headers).unwrap(), "test-key-123");

        // Test Authorization header
        headers.clear();
        headers.insert(
            "authorization",
            HeaderValue::from_static("API-Key test-key-456"),
        );
        assert_eq!(extract_api_key(&headers).unwrap(), "test-key-456");

        // Test missing headers
        headers.clear();
        assert!(extract_api_key(&headers).is_err());
    }
}
