use crate::{
    config::Config,
    db::{models::*, queries, Database},
    security::jwt::JwtSigner,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use tracing::{error, info, warn};

/// GET /oauth2/userinfo - OIDC UserInfo endpoint
pub async fn userinfo_handler(
    State(db): State<Database>,
    State(config): State<Config>,
    headers: HeaderMap,
) -> Result<Json<UserInfo>, (StatusCode, Json<OAuthError>)> {
    info!("UserInfo endpoint called");

    // Extract Bearer token from Authorization header
    let access_token = extract_bearer_token(&headers)?;

    // Decode and verify the JWT access token
    let (claims, app) = verify_access_token(&db, &config, &access_token).await?;

    // Load user information
    let user_id = claims.sub.parse().map_err(|_| {
        error!("Invalid user ID in token subject");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OAuthError::new("server_error")),
        )
    })?;

    let user = queries::get_user_by_id(&db, &user_id)
        .await
        .map_err(|e| {
            error!("Database error loading user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?
        .ok_or_else(|| {
            warn!("User not found for valid token");
            (
                StatusCode::UNAUTHORIZED,
                Json(OAuthError::new("invalid_token")),
            )
        })?;

    // Get user roles for this application (from the token claims)
    let roles = claims.roles;

    // Build UserInfo response
    let user_info = UserInfo {
        sub: user.id.to_string(),
        email: user.email.clone(),
        email_verified: user.email_verified,
        name: user
            .given_name
            .as_ref()
            .zip(user.family_name.as_ref())
            .map(|(given, family)| format!("{} {}", given, family)),
        given_name: user.given_name.clone(),
        family_name: user.family_name.clone(),
        tenant: claims.tenant,
        roles,
    };

    info!("Successfully returned user info for user {}", user.id);
    Ok(Json(user_info))
}

async fn verify_access_token(
    db: &Database,
    config: &Config,
    token: &str,
) -> Result<(crate::security::jwt::JwtClaims, Application), (StatusCode, Json<OAuthError>)> {
    // First, we need to find which application's key to use for verification
    // We can either:
    // 1. Extract the 'kid' from the JWT header to find the right key
    // 2. Try all applications (less efficient but more robust)

    // For now, let's extract the audience claim to find the right application
    // This is a bit of a chicken-and-egg problem, but we can decode without verification first

    let jwt_parts: Vec<&str> = token.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(OAuthError::new("invalid_token").with_description("Malformed JWT")),
        ));
    }

    // Decode payload without verification to get the audience
    let payload_json = URL_SAFE_NO_PAD.decode(jwt_parts[1]).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(OAuthError::new("invalid_token").with_description("Invalid JWT encoding")),
        )
    })?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_json).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(OAuthError::new("invalid_token").with_description("Invalid JWT payload")),
        )
    })?;

    let audience = payload.get("aud").and_then(|v| v.as_str()).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(OAuthError::new("invalid_token").with_description("Missing audience claim")),
        )
    })?;

    let client_id = audience.parse().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(OAuthError::new("invalid_token").with_description("Invalid audience format")),
        )
    })?;

    // Load application by client_id
    let app = queries::get_application_by_client_id(db, &client_id)
        .await
        .map_err(|e| {
            error!("Database error loading application: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error")),
            )
        })?
        .ok_or_else(|| {
            warn!("Application not found for token audience");
            (
                StatusCode::UNAUTHORIZED,
                Json(OAuthError::new("invalid_token")),
            )
        })?;

    // Now verify the token using the application's key
    let jwt_signer = JwtSigner::new(config.issuer.clone());
    let claims = jwt_signer.verify_jwt(token, &app).map_err(|e| {
        warn!("JWT verification failed: {}", e);
        (
            StatusCode::UNAUTHORIZED,
            Json(OAuthError::new("invalid_token")),
        )
    })?;

    Ok((claims, app))
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let auth_header = headers.get("authorization").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(
                OAuthError::new("invalid_request").with_description("Missing Authorization header"),
            ),
        )
    })?;

    let auth_str = auth_header.to_str().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(
                OAuthError::new("invalid_request").with_description("Invalid Authorization header"),
            ),
        )
    })?;

    if let Some(token) = auth_str.strip_prefix("Bearer ") {
        Ok(token.to_string())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(
                OAuthError::new("invalid_request")
                    .with_description("Authorization header must use Bearer scheme"),
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_bearer_token() {
        let mut headers = HeaderMap::new();

        // Test valid Bearer token
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."),
        );
        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...");

        // Test missing header
        headers.clear();
        assert!(extract_bearer_token(&headers).is_err());

        // Test invalid scheme
        headers.insert(
            "authorization",
            HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA=="),
        );
        assert!(extract_bearer_token(&headers).is_err());
    }
}
