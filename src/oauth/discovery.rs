use crate::config::Config;
use crate::db::models::{OAuthError, OidcDiscoveryResponse};
use axum::{extract::State, http::StatusCode, response::Json};
use tracing::info;

/// GET /.well-known/openid-configuration  
/// Returns OpenID Connect discovery metadata
pub async fn discovery_handler(
    State(config): State<Config>,
) -> Result<Json<OidcDiscoveryResponse>, (StatusCode, Json<OAuthError>)> {
    info!("OpenID Connect discovery endpoint called");

    let discovery = create_discovery_response(&config);
    Ok(Json(discovery))
}

fn create_discovery_response(config: &Config) -> OidcDiscoveryResponse {
    let base_url = &config.issuer;

    OidcDiscoveryResponse {
        issuer: config.issuer.clone(),
        authorization_endpoint: format!("{}/oauth2/authorize", base_url),
        token_endpoint: format!("{}/oauth2/token", base_url),
        userinfo_endpoint: format!("{}/oauth2/userinfo", base_url),
        jwks_uri: format!("{}/.well-known/jwks.json", base_url),
        response_types_supported: vec!["code".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        scopes_supported: vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        claims_supported: vec![
            "sub".to_string(),
            "iss".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "email".to_string(),
            "email_verified".to_string(),
            "name".to_string(),
            "given_name".to_string(),
            "family_name".to_string(),
            "tenant".to_string(),
            "roles".to_string(),
        ],
        token_endpoint_auth_methods_supported: if config.require_api_key {
            vec!["none".to_string(), "api_key".to_string()]
        } else {
            vec!["none".to_string()]
        },
        code_challenge_methods_supported: vec!["S256".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_response() {
        let config = Config {
            app_host: "0.0.0.0".parse().unwrap(),
            app_port: 8080,
            issuer: "https://auth.example.com".to_string(),
            database_url: secrecy::Secret::new(
                "postgres://user:pass@localhost:5432/db".to_string(),
            ),
            cookie_domain: ".example.com".to_string(),
            session_secret: secrecy::Secret::new("secret".to_string()),
            default_access_ttl_secs: 3600,
            default_refresh_ttl_mins: 43200,
            require_api_key: true,
        };

        let discovery = create_discovery_response(&config);

        assert_eq!(discovery.issuer, "https://auth.example.com");
        assert_eq!(
            discovery.authorization_endpoint,
            "https://auth.example.com/oauth2/authorize"
        );
        assert_eq!(
            discovery.token_endpoint,
            "https://auth.example.com/oauth2/token"
        );
        assert!(discovery
            .code_challenge_methods_supported
            .contains(&"S256".to_string()));
        assert!(discovery
            .token_endpoint_auth_methods_supported
            .contains(&"api_key".to_string()));
    }
}
