use crate::{
    config::Config,
    db::{models::*, queries, Database},
    security::{generate_random_token, password::hash_password},
    web::login::LoginParams,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Html,
    Form,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tower_cookies::{Cookie, Cookies};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct RegisterForm {
    pub email: String,
    pub password: String,
    pub confirm_password: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub csrf_token: String,
    // OAuth parameters to preserve after registration
    pub client_id: Option<Uuid>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterPageData {
    pub oauth_params: crate::web::login::LoginParams,
    pub csrf_token: String,
    pub error_message: Option<String>,
}

/// GET /register - Show registration form
pub async fn register_page_handler(
    Query(params): Query<LoginParams>,
    State(db): State<Database>,
    cookies: Cookies,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    info!("Registration page requested");

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
    cookies.add(cookie);

    let page_data = RegisterPageData {
        oauth_params: params,
        csrf_token,
        error_message: None,
    };

    Ok(Html(render_register_page(&page_data)))
}

/// POST /register - Process registration form
pub async fn register_handler(
    State(db): State<Database>,
    cookies: Cookies,
    Form(form): Form<RegisterForm>,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    info!("Registration attempt for email: {}", form.email);

    // Get session and verify CSRF
    let session_id = cookies
        .get("session")
        .and_then(|cookie| cookie.value().parse::<Uuid>().ok())
        .ok_or_else(|| {
            warn!("Registration attempt without valid session");
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
            warn!("Session not found for registration");
            (StatusCode::BAD_REQUEST, Html("Invalid session".to_string()))
        })?;

    // Verify CSRF token
    if session.csrf != form.csrf_token {
        warn!("CSRF token mismatch in registration form");
        return render_register_error(&form, "Invalid request. Please try again.");
    }

    // Validate form
    if let Some(error) = validate_registration_form(&form) {
        return render_register_error(&form, &error);
    }

    // Get tenant (same logic as login)
    let tenant = match form.client_id {
        Some(client_id) => match queries::get_application_by_client_id(&db, &client_id).await {
            Ok(Some(app)) => {
                match queries::get_tenant_by_slug(&db, &app.tenant_id.to_string()).await {
                    Ok(Some(tenant)) => tenant,
                    _ => {
                        error!("Tenant not found for application");
                        return render_register_error(&form, "Invalid application configuration.");
                    }
                }
            }
            _ => {
                warn!("Application not found for client_id: {}", client_id);
                return render_register_error(&form, "Invalid application.");
            }
        },
        None => match get_default_tenant(&db).await {
            Ok(tenant) => tenant,
            Err(e) => {
                error!("Failed to get default tenant: {}", e);
                return render_register_error(&form, "Registration not available.");
            }
        },
    };

    // Check if user already exists
    match queries::get_user_by_email(&db, &tenant.id, &form.email).await {
        Ok(Some(_)) => {
            warn!("Registration attempt with existing email: {}", form.email);
            return render_register_error(&form, "An account with this email already exists.");
        }
        Ok(None) => {
            // Good, user doesn't exist
        }
        Err(e) => {
            error!("Database error checking user existence: {}", e);
            return render_register_error(&form, "Registration failed.");
        }
    }

    // Hash password
    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Password hashing failed: {}", e);
            return render_register_error(&form, "Registration failed.");
        }
    };

    // Create user
    let user = match queries::create_user(
        &db,
        &tenant.id,
        &form.email,
        &password_hash,
        form.given_name.as_deref(),
        form.family_name.as_deref(),
    )
    .await
    {
        Ok(user) => user,
        Err(e) => {
            error!("Failed to create user: {}", e);
            return render_register_error(&form, "Registration failed.");
        }
    };

    info!("Successfully created user: {}", user.email);

    // Log the user in automatically
    if let Err(e) = queries::update_session_user(&db, &session_id, &user.id, &tenant.id).await {
        error!("Failed to log in new user: {}", e);
        return render_register_error(&form, "Registration successful but login failed.");
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

    // Otherwise, show success page
    Ok(Html(render_registration_success(&user)))
}

async fn create_anonymous_session(db: &Database, csrf: &str) -> Result<Session, anyhow::Error> {
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
    queries::create_session(db, None, None, csrf, expires_at).await
}

async fn get_default_tenant(db: &Database) -> Result<Tenant, anyhow::Error> {
    queries::get_tenant_by_slug(db, "dwcorp")
        .await?
        .ok_or_else(|| anyhow::anyhow!("Default tenant not found"))
}

fn validate_registration_form(form: &RegisterForm) -> Option<String> {
    // Email validation
    if form.email.is_empty() {
        return Some("Email is required".to_string());
    }

    if !form.email.contains('@') {
        return Some("Please enter a valid email address".to_string());
    }

    // Password validation
    if form.password.is_empty() {
        return Some("Password is required".to_string());
    }

    if form.password.len() < 8 {
        return Some("Password must be at least 8 characters long".to_string());
    }

    if form.password != form.confirm_password {
        return Some("Passwords do not match".to_string());
    }

    // Name validation (optional but if provided should not be empty)
    if let Some(given_name) = &form.given_name {
        if given_name.trim().is_empty() {
            return Some("Given name cannot be empty".to_string());
        }
    }

    if let Some(family_name) = &form.family_name {
        if family_name.trim().is_empty() {
            return Some("Family name cannot be empty".to_string());
        }
    }

    None
}

fn preserve_oauth_params(form: &RegisterForm) -> String {
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

fn render_register_error(
    form: &RegisterForm,
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

    let page_data = RegisterPageData {
        oauth_params: params,
        csrf_token: form.csrf_token.clone(),
        error_message: Some(error.to_string()),
    };

    Ok(Html(render_register_page(&page_data)))
}

fn render_register_page(data: &RegisterPageData) -> String {
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
    <title>Create Account - Curupira</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 400px;
            margin: 80px auto;
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
        input[type="email"], input[type="password"], input[type="text"] {{
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }}
        input:focus {{
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 2px rgba(0,123,255,0.25);
        }}
        .name-row {{
            display: flex;
            gap: 10px;
        }}
        .name-row .form-group {{
            flex: 1;
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: #28a745;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
        }}
        button:hover {{
            background: #218838;
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
        .password-requirements {{
            font-size: 14px;
            color: #666;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h1>🛡️ Curupira</h1>
            <h2>Create Account</h2>
        </div>

        {}

        <form method="POST" action="/register">
            <div class="form-group">
                <label for="email">Email *</label>
                <input type="email" id="email" name="email" required>
            </div>

            <div class="name-row">
                <div class="form-group">
                    <label for="given_name">First Name</label>
                    <input type="text" id="given_name" name="given_name">
                </div>
                <div class="form-group">
                    <label for="family_name">Last Name</label>
                    <input type="text" id="family_name" name="family_name">
                </div>
            </div>

            <div class="form-group">
                <label for="password">Password *</label>
                <input type="password" id="password" name="password" required>
                <div class="password-requirements">
                    Must be at least 8 characters long
                </div>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm Password *</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>

            <input type="hidden" name="csrf_token" value="{}">
            {}

            <button type="submit">Create Account</button>
        </form>

        <div class="footer">
            <p>Already have an account? <a href="/login{}">Sign in</a></p>
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

fn render_registration_success(user: &User) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Successful - Curupira</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 500px;
            margin: 100px auto;
            padding: 20px;
            background: #f5f5f5;
            text-align: center;
        }}
        .card {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .icon {{
            font-size: 4em;
            margin-bottom: 20px;
        }}
        .title {{
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        .message {{
            color: #666;
            margin-bottom: 20px;
            line-height: 1.5;
        }}
        .user-info {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🎉</div>
        <h1 class="title">Welcome to Curupira!</h1>
        <p class="message">
            Your account has been created successfully and you are now signed in.
        </p>
        <div class="user-info">
            <p><strong>Email:</strong> {}</p>
            {}
        </div>
    </div>
</body>
</html>"#,
        user.email,
        if let (Some(given), Some(family)) = (&user.given_name, &user.family_name) {
            format!("<p><strong>Name:</strong> {} {}</p>", given, family)
        } else {
            String::new()
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_registration_form() {
        // Valid form
        let valid_form = RegisterForm {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            confirm_password: "password123".to_string(),
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            csrf_token: "token".to_string(),
            client_id: None,
            redirect_uri: None,
            response_type: None,
            scope: None,
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            prompt: None,
        };

        assert!(validate_registration_form(&valid_form).is_none());

        // Invalid email
        let mut invalid_form = valid_form.clone();
        invalid_form.email = "invalid-email".to_string();
        assert!(validate_registration_form(&invalid_form).is_some());

        // Short password
        let mut invalid_form = valid_form.clone();
        invalid_form.password = "short".to_string();
        assert!(validate_registration_form(&invalid_form).is_some());

        // Password mismatch
        let mut invalid_form = valid_form.clone();
        invalid_form.confirm_password = "different".to_string();
        assert!(validate_registration_form(&invalid_form).is_some());
    }
}
