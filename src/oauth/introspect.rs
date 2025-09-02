use crate::{
    config::Config,
    db::{models::*, queries, Database},
    security::jwt::JwtSigner,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    Form,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use time::OffsetDateTime;
use tracing::{error, info, warn};

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
}

/// POST /oauth2/introspect - RFC 7662 Token Introspection
pub async fn introspect_handler(
    State(db): State<Database>,
    State(config): State<Config>,
    headers: HeaderMap,
    Form(request): Form<IntrospectRequest>,
) -> Result<Json<IntrospectionResponse>, (StatusCode, Json<OAuthError>)> {
    info!("Token introspection request");

    // Check API key requirement
    if config.require_api_key {
        let api_key = extract_api_key(&headers)?;

        // Validate API key
        let _app = queries::get_application_by_api_key(&db, &api_key)
            .await
            .map_err(|e| {
                error!("Database error checking API key: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(OAuthError::new("server_error")),
                )
            })?
            .ok_or_else(|| {
                warn!("Invalid API key provided for introspection");
                (
                    StatusCode::UNAUTHORIZED,
                    Json(OAuthError::new("invalid_client")),
                )
            })?;
    }

    // Try to introspect the token
    let introspection_result = introspect_token(&db, &config, &request.token).await;

    match introspection_result {
        Ok(response) => {
            info!(
                "Token introspection successful, active: {}",
                response.active
            );
            Ok(Json(response))
        }
        Err(e) => {
            // For introspection, we should return inactive rather than error for invalid tokens
            warn!("Token introspection failed: {}", e);
            Ok(Json(IntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                sub: None,
                token_type: None,
                exp: None,
                iat: None,
                iss: None,
            }))
        }
    }
}

async fn introspect_token(
    db: &Database,
    config: &Config,
    token: &str,
) -> anyhow::Result<IntrospectionResponse> {
    // First, try to parse as JWT (access token)
    if let Ok(jwt_response) = introspect_jwt_token(db, config, token).await {
        return Ok(jwt_response);
    }

    // If not a valid JWT, try as refresh token
    introspect_refresh_token(db, token).await
}

async fn introspect_jwt_token(
    db: &Database,
    config: &Config,
    token: &str,
) -> anyhow::Result<IntrospectionResponse> {
    // Decode JWT payload without verification to get audience
    let jwt_parts: Vec<&str> = token.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err(anyhow::anyhow!("Invalid JWT format"));
    }

    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(jwt_parts[1])?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_json)?;

    let audience = payload
        .get("aud")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing audience claim"))?;

    let client_id = audience.parse()?;

    // Load application
    let app = queries::get_application_by_client_id(db, &client_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Application not found"))?;

    // Verify JWT
    let jwt_signer = JwtSigner::new(config.issuer.clone());
    let claims = jwt_signer.verify_jwt(token, &app)?;

    // Check if token is expired (with clock skew tolerance)
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if claims.exp < (now - 60) {
        return Ok(IntrospectionResponse {
            active: false,
            scope: Some(claims.scope),
            client_id: Some(claims.aud),
            sub: Some(claims.sub),
            token_type: Some("access_token".to_string()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            iss: Some(claims.iss),
        });
    }

    Ok(IntrospectionResponse {
        active: true,
        scope: Some(claims.scope),
        client_id: Some(claims.aud),
        sub: Some(claims.sub),
        token_type: Some("access_token".to_string()),
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        iss: Some(claims.iss),
    })
}

async fn introspect_refresh_token(
    db: &Database,
    token: &str,
) -> anyhow::Result<IntrospectionResponse> {
    // Look up refresh token in database
    let refresh_token = queries::get_refresh_token(db, token)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Refresh token not found"))?;

    // Check if token is revoked
    if refresh_token.revoked {
        return Ok(IntrospectionResponse {
            active: false,
            scope: Some(refresh_token.scope.join(" ")),
            client_id: Some(refresh_token.client_id.to_string()),
            sub: Some(refresh_token.user_id.to_string()),
            token_type: Some("refresh_token".to_string()),
            exp: Some(refresh_token.expires_at.unix_timestamp()),
            iat: Some(refresh_token.created_at.unix_timestamp()),
            iss: None,
        });
    }

    // Check if token is expired
    let now = OffsetDateTime::now_utc();
    if refresh_token.expires_at < now {
        return Ok(IntrospectionResponse {
            active: false,
            scope: Some(refresh_token.scope.join(" ")),
            client_id: Some(refresh_token.client_id.to_string()),
            sub: Some(refresh_token.user_id.to_string()),
            token_type: Some("refresh_token".to_string()),
            exp: Some(refresh_token.expires_at.unix_timestamp()),
            iat: Some(refresh_token.created_at.unix_timestamp()),
            iss: None,
        });
    }

    Ok(IntrospectionResponse {
        active: true,
        scope: Some(refresh_token.scope.join(" ")),
        client_id: Some(refresh_token.client_id.to_string()),
        sub: Some(refresh_token.user_id.to_string()),
        token_type: Some("refresh_token".to_string()),
        exp: Some(refresh_token.expires_at.unix_timestamp()),
        iat: Some(refresh_token.created_at.unix_timestamp()),
        iss: None,
    })
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

    #[test]
    fn test_introspection_response_serialization() {
        let response = IntrospectionResponse {
            active: true,
            scope: Some("openid email".to_string()),
            client_id: Some("test-client".to_string()),
            sub: Some("user-123".to_string()),
            token_type: Some("access_token".to_string()),
            exp: Some(1234567890),
            iat: Some(1234560000),
            iss: Some("https://auth.example.com".to_string()),
        };

        let json = serde_json::to_string(&response).expect("Failed to serialize");
        assert!(json.contains("\"active\":true"));
        assert!(json.contains("\"token_type\":\"access_token\""));
    }
}
