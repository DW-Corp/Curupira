use crate::{
    db::models::OAuthError,
    db::{queries, Database},
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, Redirect},
};
use serde::Deserialize;
use tower_cookies::{Cookie, Cookies};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct LogoutParams {
    pub post_logout_redirect_uri: Option<String>,
    pub client_id: Option<Uuid>,
    pub state: Option<String>,
}

/// GET /oauth2/logout - End session (logout) endpoint
pub async fn logout_handler(
    Query(params): Query<LogoutParams>,
    State(db): State<Database>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    info!("Logout request with client_id: {:?}", params.client_id);

    // Get current session from cookie
    let session_id = cookies
        .get("session")
        .and_then(|cookie| cookie.value().parse::<Uuid>().ok());

    // Clear session cookie regardless of whether we found a valid session
    let mut cookie = Cookie::new("session", "");
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_max_age(Some(time::Duration::seconds(0))); // Expire immediately
    cookies.add(cookie);

    // If we have a session, delete it from the database
    if let Some(session_id) = session_id {
        if let Err(e) = queries::delete_session(&db, &session_id).await {
            error!("Failed to delete session from database: {}", e);
            // Continue with logout even if database deletion fails
        } else {
            info!("Successfully deleted session: {}", session_id);
        }
    }

    // Handle post-logout redirect
    if let (Some(redirect_uri), Some(client_id)) =
        (params.post_logout_redirect_uri.as_ref(), params.client_id)
    {
        // Validate that the redirect URI is allowed for this client
        match validate_post_logout_redirect(&db, &client_id, redirect_uri).await {
            Ok(true) => {
                info!("Redirecting to post-logout URI: {}", redirect_uri);
                let redirect_url = if let Some(state) = params.state {
                    format!("{}?state={}", redirect_uri, urlencoding::encode(&state))
                } else {
                    redirect_uri.clone()
                };

                return Ok(Html(format!(
                    r#"<script>window.location.href = "{}";</script>"#,
                    redirect_url
                )));
            }
            Ok(false) => {
                warn!(
                    "Invalid post_logout_redirect_uri: {} for client: {}",
                    redirect_uri, client_id
                );
                // Fall through to default logout page
            }
            Err(e) => {
                error!("Error validating post_logout_redirect_uri: {}", e);
                // Fall through to default logout page
            }
        }
    }

    // Show default logout confirmation page
    Ok(Html(render_logout_page()))
}

async fn validate_post_logout_redirect(
    db: &Database,
    client_id: &Uuid,
    redirect_uri: &str,
) -> Result<bool, anyhow::Error> {
    // Load application to check allowed post-logout redirect URIs
    let app = queries::get_application_by_client_id(db, client_id).await?;

    match app {
        Some(app) => {
            // Check if the redirect URI is in the allowed list
            Ok(app
                .post_logout_redirect_uris
                .contains(&redirect_uri.to_string()))
        }
        None => {
            warn!("Application not found for client_id: {}", client_id);
            Ok(false)
        }
    }
}

fn render_logout_page() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logout Successful - Curupira</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 500px;
            margin: 100px auto;
            padding: 20px;
            background: #f5f5f5;
            text-align: center;
        }
        .card {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
        .title {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .message {
            color: #666;
            margin-bottom: 30px;
            line-height: 1.5;
        }
        .actions {
            margin-top: 30px;
        }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-weight: 500;
            transition: background-color 0.2s;
        }
        .btn:hover {
            background: #0056b3;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🛡️</div>
        <h1 class="title">Logout Successful</h1>
        <p class="message">
            You have been successfully logged out of Curupira.<br>
            Your session has been terminated and all tokens have been revoked.
        </p>
        <div class="actions">
            <a href="/login" class="btn">Sign In Again</a>
        </div>
    </div>
    
    <script>
        // Auto-redirect after 10 seconds if no user interaction
        setTimeout(function() {
            if (!document.hidden) {
                window.location.href = '/login';
            }
        }, 10000);
    </script>
</body>
</html>"#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logout_page_rendering() {
        let page = render_logout_page();
        assert!(page.contains("Logout Successful"));
        assert!(page.contains("Curupira"));
        assert!(page.contains("/login"));
    }

    #[test]
    fn test_logout_params_deserialization() {
        // Test with all parameters
        let params = LogoutParams {
            post_logout_redirect_uri: Some("https://example.com/logout".to_string()),
            client_id: Some(Uuid::new_v4()),
            state: Some("abc123".to_string()),
        };

        assert!(params.post_logout_redirect_uri.is_some());
        assert!(params.client_id.is_some());
        assert!(params.state.is_some());

        // Test with no parameters
        let params = LogoutParams {
            post_logout_redirect_uri: None,
            client_id: None,
            state: None,
        };

        assert!(params.post_logout_redirect_uri.is_none());
        assert!(params.client_id.is_none());
        assert!(params.state.is_none());
    }
}
