// [business] Import application modules for login functionality
use crate::{
    // config::Config,                      // [business] Application configuration - Unused import removed
    db::{models::*, queries, Database}, // [business] Database entities and operations
    security::password::verify_password, // [security] Password verification using Argon2id
};

// [library] Axum web framework components for HTTP handling
use axum::{
    extract::{Query, State}, // [library] Extract query parameters and application state
    http::StatusCode,        // [library] HTTP status codes
    response::Html,          // [library] HTTP response types (Redirect unused, removed)
    Form,                    // [library] HTML form data extraction
};

// [library] JSON/form serialization and deserialization
use serde::{Deserialize, Serialize};

// [library] Time handling for session management
use time::{Duration, OffsetDateTime};

// [library] Cookie management for session handling
use tower_cookies::{Cookie, Cookies};

// [library] Structured logging for authentication events
use tracing::{error, info, warn};

// [library] UUID handling for session and client IDs
use uuid::Uuid;

// [security] Random token generation for CSRF protection
use crate::security::generate_random_token;

// [business] OAuth2 parameters from authorization request that need to be preserved during login
// These parameters are passed through the login flow to continue OAuth2 after authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginParams {
    // [business] OAuth2 parameters to preserve across authentication flow
    pub client_id: Option<Uuid>, // [business] OAuth2 client requesting authorization
    pub redirect_uri: Option<String>, // [security] Where to redirect after authorization
    pub response_type: Option<String>, // [business] OAuth2 response type ("code")
    pub scope: Option<String>,   // [business] Requested permissions
    pub state: Option<String>,   // [security] CSRF protection parameter
    pub code_challenge: Option<String>, // [security] PKCE code challenge
    pub code_challenge_method: Option<String>, // [security] PKCE challenge method ("S256")
    pub nonce: Option<String>,   // [security] OpenID Connect nonce for replay protection
    pub prompt: Option<String>,  // [business] UI behavior hint
}

// [business] Login form data submitted by users including OAuth2 flow preservation
// Contains both authentication credentials and OAuth2 parameters as hidden fields
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    // [business] User authentication credentials
    pub email: String,      // [business] User's email address (login identifier)
    pub password: String,   // [security] User's plaintext password (hashed for verification)
    pub csrf_token: String, // [security] CSRF protection token

    // [business] OAuth2 parameters preserved as hidden form fields
    pub client_id: Option<Uuid>,        // [business] OAuth2 client ID
    pub redirect_uri: Option<String>,   // [security] OAuth2 redirect URI
    pub response_type: Option<String>,  // [business] OAuth2 response type
    pub scope: Option<String>,          // [business] Requested OAuth2 scopes
    pub state: Option<String>,          // [security] OAuth2 state parameter
    pub code_challenge: Option<String>, // [security] PKCE code challenge
    pub code_challenge_method: Option<String>, // [security] PKCE challenge method
    pub nonce: Option<String>,          // [security] OpenID Connect nonce
    pub prompt: Option<String>,         // [business] OAuth2 prompt parameter
}

// [business] Data structure for rendering the login page template
// Contains OAuth2 parameters, CSRF token, and any error messages to display
#[derive(Debug, Serialize)]
struct LoginPageData {
    pub oauth_params: LoginParams, // [business] OAuth2 flow parameters to preserve
    pub csrf_token: String,        // [security] CSRF protection token for form submission
    pub error_message: Option<String>, // [business] Error message to display (e.g., invalid credentials)
}

// [business] GET /login - Display login form with OAuth2 parameter preservation
// Entry point for user authentication, either direct or as part of OAuth2 flow
pub async fn login_page_handler(
    Query(params): Query<LoginParams>,
    State(db): State<Database>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    info!("Login page requested");

    // Generate CSRF token
    let csrf_token = generate_random_token();

    // Create or update session for CSRF token
    let session_id = match create_anonymous_session(&db, &csrf_token).await {
        Ok(session) => session.id,
        Err(e) => {
            error!("Failed to create session: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("Internal server error".to_string()),
            ));
        }
    };

    // Set session cookie
    let mut cookie = Cookie::new("session", session_id.to_string());
    cookie.set_http_only(true);
    cookie.set_path("/");
    cookie.set_same_site(tower_cookies::cookie::SameSite::Lax);
    // Set secure flag in production
    cookies.add(cookie);

    let page_data = LoginPageData {
        oauth_params: params,
        csrf_token,
        error_message: None,
    };

    Ok(Html(render_login_page(&page_data)))
}

/// POST /login - Process login form
pub async fn login_handler(
    State(db): State<Database>,
    cookies: Cookies,
    Form(form): Form<LoginForm>,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    info!("Login attempt for email: {}", form.email);

    // Get session and verify CSRF
    let session_id = cookies
        .get("session")
        .and_then(|cookie| cookie.value().parse::<Uuid>().ok())
        .ok_or_else(|| {
            warn!("Login attempt without valid session");
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
            warn!("Session not found for login");
            (StatusCode::BAD_REQUEST, Html("Invalid session".to_string()))
        })?;

    // Verify CSRF token
    if session.csrf != form.csrf_token {
        warn!("CSRF token mismatch in login form");
        return render_login_error(&form, "Invalid request. Please try again.");
    }

    // For multi-tenant, we need to determine the tenant
    // For now, let's assume we have a default tenant or extract from client_id
    let tenant = match form.client_id {
        Some(client_id) => {
            // Look up application to get tenant
            match queries::get_application_by_client_id(&db, &client_id).await {
                Ok(Some(app)) => {
                    // Get tenant by id (we need to add this query)
                    // For now, use a simple lookup by converting UUID to string
                    match queries::get_tenant_by_slug(&db, &app.tenant_id.to_string()).await {
                        Ok(Some(tenant)) => tenant,
                        _ => {
                            error!("Tenant not found for application");
                            return render_login_error(&form, "Invalid application configuration.");
                        }
                    }
                }
                _ => {
                    warn!("Application not found for client_id: {}", client_id);
                    return render_login_error(&form, "Invalid application.");
                }
            }
        }
        None => {
            // Use default tenant - get the first one or create logic to determine default
            match get_default_tenant(&db).await {
                Ok(tenant) => tenant,
                Err(e) => {
                    error!("Failed to get default tenant: {}", e);
                    return render_login_error(&form, "Authentication not available.");
                }
            }
        }
    };

    // Authenticate user
    let user = match queries::get_user_by_email(&db, &tenant.id, &form.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!("User not found: {}", form.email);
            return render_login_error(&form, "Invalid email or password.");
        }
        Err(e) => {
            error!("Database error finding user: {}", e);
            return render_login_error(&form, "Authentication failed.");
        }
    };

    // Verify password
    match verify_password(&form.password, &user.password_hash) {
        Ok(true) => {
            info!("Successful login for user: {}", user.email);

            // Update session with user information
            if let Err(e) =
                queries::update_session_user(&db, &session_id, &user.id, &tenant.id).await
            {
                error!("Failed to update session with user: {}", e);
                return render_login_error(&form, "Login failed.");
            }

            // If we have OAuth parameters, redirect back to authorization
            if form.client_id.is_some() {
                let oauth_params = preserve_oauth_params(&form);
                let redirect_url = format!("/oauth2/authorize?{}", oauth_params);
                return Ok(Html(format!(
                    r#"<script>window.location.href = "{}";</script>"#,
                    redirect_url
                )));
            }

            // Otherwise, redirect to a default success page
            Ok(Html(render_login_success()))
        }
        Ok(false) => {
            warn!("Invalid password for user: {}", form.email);
            render_login_error(&form, "Invalid email or password.")
        }
        Err(e) => {
            error!("Password verification error: {}", e);
            render_login_error(&form, "Authentication failed.")
        }
    }
}

async fn create_anonymous_session(db: &Database, csrf: &str) -> Result<Session, anyhow::Error> {
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(1); // Session expires in 1 hour
    queries::create_session(db, None, None, csrf, expires_at).await
}

async fn get_default_tenant(db: &Database) -> Result<Tenant, anyhow::Error> {
    // For simplicity, get the first tenant
    // In production, you might want a more sophisticated default tenant logic
    queries::get_tenant_by_slug(db, "dwcorp")
        .await?
        .ok_or_else(|| anyhow::anyhow!("Default tenant not found"))
}

fn preserve_oauth_params(form: &LoginForm) -> String {
    let mut params = Vec::new();

    if let Some(client_id) = &form.client_id {
        params.push(format!("client_id={}", client_id));
    }
    if let Some(redirect_uri) = &form.redirect_uri {
        params.push(format!(
            "redirect_uri={}",
            urlencoding::encode(redirect_uri)
        ));
    }
    if let Some(response_type) = &form.response_type {
        params.push(format!("response_type={}", response_type));
    }
    if let Some(scope) = &form.scope {
        params.push(format!("scope={}", urlencoding::encode(scope)));
    }
    if let Some(state) = &form.state {
        params.push(format!("state={}", urlencoding::encode(state)));
    }
    if let Some(code_challenge) = &form.code_challenge {
        params.push(format!(
            "code_challenge={}",
            urlencoding::encode(code_challenge)
        ));
    }
    if let Some(code_challenge_method) = &form.code_challenge_method {
        params.push(format!("code_challenge_method={}", code_challenge_method));
    }
    if let Some(nonce) = &form.nonce {
        params.push(format!("nonce={}", urlencoding::encode(nonce)));
    }
    if let Some(prompt) = &form.prompt {
        params.push(format!("prompt={}", urlencoding::encode(prompt)));
    }

    params.join("&")
}

fn render_login_error(
    form: &LoginForm,
    error: &str,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    let params = LoginParams {
        client_id: form.client_id,
        redirect_uri: form.redirect_uri.clone(),
        response_type: form.response_type.clone(),
        scope: form.scope.clone(),
        state: form.state.clone(),
        code_challenge: form.code_challenge.clone(),
        code_challenge_method: form.code_challenge_method.clone(),
        nonce: form.nonce.clone(),
        prompt: form.prompt.clone(),
    };

    let page_data = LoginPageData {
        oauth_params: params,
        csrf_token: form.csrf_token.clone(),
        error_message: Some(error.to_string()),
    };

    Ok(Html(render_login_page(&page_data)))
}

fn render_login_page(data: &LoginPageData) -> String {
    let error_html = if let Some(error) = &data.error_message {
        format!(
            r#"<div class="error">
                <strong>❌ Error:</strong> {}
            </div>"#,
            error
        )
    } else {
        String::new()
    };

    let hidden_fields = generate_hidden_fields(&data.oauth_params);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - Curupira</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 400px;
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
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #2c3e50;
        }}
        input[type="email"], input[type="password"] {{
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }}
        input[type="email"]:focus, input[type="password"]:focus {{
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 2px rgba(0,123,255,0.25);
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
        }}
        button:hover {{
            background: #0056b3;
        }}
        .error {{
            background: #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            border: 1px solid #f5c6cb;
        }}
        .footer {{
            text-align: center;
            margin-top: 20px;
            color: #666;
        }}
        .footer a {{
            color: #007bff;
            text-decoration: none;
        }}
        .footer a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h1>🛡️ Curupira</h1>
            <h2>Sign In</h2>
        </div>

        {}

        <form method="POST" action="/login">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>

            <input type="hidden" name="csrf_token" value="{}">
            {}

            <button type="submit">Sign In</button>
        </form>

        <div class="footer">
            <p>Don't have an account? <a href="/register{}">Sign up</a></p>
        </div>
    </div>
</body>
</html>"#,
        error_html,
        data.csrf_token,
        hidden_fields,
        if data.oauth_params.client_id.is_some() {
            format!("?{}", preserve_oauth_query(&data.oauth_params))
        } else {
            String::new()
        }
    )
}

fn generate_hidden_fields(params: &LoginParams) -> String {
    let mut fields = Vec::new();

    if let Some(client_id) = &params.client_id {
        fields.push(format!(
            r#"<input type="hidden" name="client_id" value="{}">"#,
            client_id
        ));
    }
    if let Some(redirect_uri) = &params.redirect_uri {
        fields.push(format!(
            r#"<input type="hidden" name="redirect_uri" value="{}">"#,
            redirect_uri
        ));
    }
    if let Some(response_type) = &params.response_type {
        fields.push(format!(
            r#"<input type="hidden" name="response_type" value="{}">"#,
            response_type
        ));
    }
    if let Some(scope) = &params.scope {
        fields.push(format!(
            r#"<input type="hidden" name="scope" value="{}">"#,
            scope
        ));
    }
    if let Some(state) = &params.state {
        fields.push(format!(
            r#"<input type="hidden" name="state" value="{}">"#,
            state
        ));
    }
    if let Some(code_challenge) = &params.code_challenge {
        fields.push(format!(
            r#"<input type="hidden" name="code_challenge" value="{}">"#,
            code_challenge
        ));
    }
    if let Some(code_challenge_method) = &params.code_challenge_method {
        fields.push(format!(
            r#"<input type="hidden" name="code_challenge_method" value="{}">"#,
            code_challenge_method
        ));
    }
    if let Some(nonce) = &params.nonce {
        fields.push(format!(
            r#"<input type="hidden" name="nonce" value="{}">"#,
            nonce
        ));
    }
    if let Some(prompt) = &params.prompt {
        fields.push(format!(
            r#"<input type="hidden" name="prompt" value="{}">"#,
            prompt
        ));
    }

    fields.join("\n            ")
}

fn preserve_oauth_query(params: &LoginParams) -> String {
    let mut query_params = Vec::new();

    if let Some(client_id) = &params.client_id {
        query_params.push(format!("client_id={}", client_id));
    }
    if let Some(redirect_uri) = &params.redirect_uri {
        query_params.push(format!(
            "redirect_uri={}",
            urlencoding::encode(redirect_uri)
        ));
    }
    if let Some(response_type) = &params.response_type {
        query_params.push(format!("response_type={}", response_type));
    }
    if let Some(scope) = &params.scope {
        query_params.push(format!("scope={}", urlencoding::encode(scope)));
    }
    if let Some(state) = &params.state {
        query_params.push(format!("state={}", urlencoding::encode(state)));
    }
    if let Some(code_challenge) = &params.code_challenge {
        query_params.push(format!(
            "code_challenge={}",
            urlencoding::encode(code_challenge)
        ));
    }
    if let Some(code_challenge_method) = &params.code_challenge_method {
        query_params.push(format!("code_challenge_method={}", code_challenge_method));
    }
    if let Some(nonce) = &params.nonce {
        query_params.push(format!("nonce={}", urlencoding::encode(nonce)));
    }
    if let Some(prompt) = &params.prompt {
        query_params.push(format!("prompt={}", urlencoding::encode(prompt)));
    }

    query_params.join("&")
}

fn render_login_success() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Successful - Curupira</title>
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
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">✅</div>
        <h1 class="title">Login Successful</h1>
        <p class="message">
            You have been successfully logged in to Curupira.
        </p>
    </div>
</body>
</html>"#
        .to_string()
}
