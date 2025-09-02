use crate::db::models::{JwksResponse, OAuthError};
use crate::db::{queries, Database};
use axum::{extract::State, http::StatusCode, response::Json, Extension};
use tracing::{error, info};

/// GET /.well-known/jwks.json
/// Returns the JSON Web Key Set containing public keys for all enabled applications
pub async fn jwks_handler(
    State(db): State<Database>,
) -> Result<Json<JwksResponse>, (StatusCode, Json<OAuthError>)> {
    info!("JWKS endpoint called");

    match get_jwks(&db).await {
        Ok(jwks) => {
            info!("Returning JWKS with {} keys", jwks.keys.len());
            Ok(Json(jwks))
        }
        Err(e) => {
            error!("Failed to get JWKS: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError::new("server_error").with_description("Failed to retrieve keys")),
            ))
        }
    }
}

/// Get all public keys from enabled applications
async fn get_jwks(db: &Database) -> anyhow::Result<JwksResponse> {
    let apps = queries::get_all_enabled_applications(db).await?;

    let mut keys = Vec::new();

    for app in apps {
        // Extract the public JWK and ensure it has the required fields
        let mut public_jwk = app.jwk_public_jwk.0.clone();

        // Ensure required fields are set
        if let Some(obj) = public_jwk.as_object_mut() {
            obj.insert(
                "kid".to_string(),
                serde_json::json!(app.jwk_kid.to_string()),
            );
            obj.insert("use".to_string(), serde_json::json!("sig"));
            obj.insert("alg".to_string(), serde_json::json!("RS256"));

            keys.push(public_jwk);
        }
    }

    Ok(JwksResponse { keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_jwks_response_structure() {
        let jwks = JwksResponse {
            keys: vec![serde_json::json!({
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-1",
                "alg": "RS256",
                "n": "test-n-value",
                "e": "AQAB"
            })],
        };

        let json = serde_json::to_string(&jwks).expect("Failed to serialize JWKS");
        assert!(json.contains("\"keys\""));
        assert!(json.contains("\"kty\":\"RSA\""));
    }
}
