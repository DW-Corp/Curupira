use super::models::*;
use crate::db::Database;
use anyhow::Result;
use sqlx::{query, query_as, query_scalar};
use time::OffsetDateTime;
use uuid::Uuid;

// Tenant queries
pub async fn get_tenant_by_slug(db: &Database, slug: &str) -> Result<Option<Tenant>> {
    let tenant = query_as!(
        Tenant,
        "SELECT id, slug, name, created_at FROM tenants WHERE slug = $1",
        slug
    )
    .fetch_optional(db.as_ref())
    .await?;

    Ok(tenant)
}

// Application queries
pub async fn get_application_by_client_id(
    db: &Database,
    client_id: &Uuid,
) -> Result<Option<Application>> {
    let app = query_as!(
        Application,
        r#"SELECT 
            id, tenant_id, client_id, client_secret, name, 
            redirect_uris, post_logout_redirect_uris, jwk_kid, 
            jwk_private_pem, jwk_public_jwk as "jwk_public_jwk: sqlx::types::Json<serde_json::Value>", 
            api_key, enabled, created_at
        FROM applications 
        WHERE client_id = $1 AND enabled = true"#,
        client_id
    )
    .fetch_optional(db.as_ref())
    .await?;

    Ok(app)
}

pub async fn get_application_by_api_key(
    db: &Database,
    api_key: &str,
) -> Result<Option<Application>> {
    let app = query_as!(
        Application,
        r#"SELECT 
            id, tenant_id, client_id, client_secret, name, 
            redirect_uris, post_logout_redirect_uris, jwk_kid, 
            jwk_private_pem, jwk_public_jwk as "jwk_public_jwk: sqlx::types::Json<serde_json::Value>", 
            api_key, enabled, created_at
        FROM applications 
        WHERE api_key = $1 AND enabled = true"#,
        api_key
    )
    .fetch_optional(db.as_ref())
    .await?;

    Ok(app)
}

pub async fn get_all_enabled_applications(db: &Database) -> Result<Vec<Application>> {
    let apps = query_as!(
        Application,
        r#"SELECT 
            id, tenant_id, client_id, client_secret, name, 
            redirect_uris, post_logout_redirect_uris, jwk_kid, 
            jwk_private_pem, jwk_public_jwk as "jwk_public_jwk: sqlx::types::Json<serde_json::Value>", 
            api_key, enabled, created_at
        FROM applications 
        WHERE enabled = true"#
    )
    .fetch_all(db.as_ref())
    .await?;

    Ok(apps)
}

// User queries
pub async fn get_user_by_email(
    db: &Database,
    tenant_id: &Uuid,
    email: &str,
) -> Result<Option<User>> {
    let user = query_as!(
        User,
        "SELECT id, tenant_id, email, email_verified, password_hash, given_name, family_name, created_at, disabled 
         FROM users 
         WHERE tenant_id = $1 AND email = $2 AND disabled = false",
        tenant_id, email
    )
    .fetch_optional(db.as_ref())
    .await?;

    Ok(user)
}

pub async fn get_user_by_id(db: &Database, user_id: &Uuid) -> Result<Option<User>> {
    let user = query_as!(
        User,
        "SELECT id, tenant_id, email, email_verified, password_hash, given_name, family_name, created_at, disabled 
         FROM users 
         WHERE id = $1 AND disabled = false",
        user_id
    )
    .fetch_optional(db.as_ref())
    .await?;

    Ok(user)
}

pub async fn create_user(
    db: &Database,
    tenant_id: &Uuid,
    email: &str,
    password_hash: &str,
    given_name: Option<&str>,
    family_name: Option<&str>,
) -> Result<User> {
    let user = query_as!(
        User,
        "INSERT INTO users (tenant_id, email, password_hash, given_name, family_name) 
         VALUES ($1, $2, $3, $4, $5) 
         RETURNING id, tenant_id, email, email_verified, password_hash, given_name, family_name, created_at, disabled",
        tenant_id, email, password_hash, given_name, family_name
    )
    .fetch_one(db.as_ref())
    .await?;

    Ok(user)
}

// Role queries
pub async fn get_user_roles_for_application(
    db: &Database,
    user_id: &Uuid,
    application_id: &Uuid,
) -> Result<Vec<String>> {
    let roles = query_scalar!(
        "SELECT r.name 
         FROM user_roles ur 
         JOIN roles r ON ur.role_id = r.id 
         JOIN application_roles ar ON r.id = ar.role_id 
         WHERE ur.user_id = $1 AND ar.application_id = $2",
        user_id,
        application_id
    )
    .fetch_all(db.as_ref())
    .await?;

    Ok(roles)
}

// Auth code queries
pub async fn create_auth_code(
    db: &Database,
    code: &str,
    client_id: &Uuid,
    tenant_id: &Uuid,
    user_id: &Uuid,
    redirect_uri: &str,
    scope: &[String],
    code_challenge: &str,
    code_challenge_method: &str,
    nonce: Option<&str>,
    state: Option<&str>,
    expires_at: OffsetDateTime,
) -> Result<()> {
    query!(
        "INSERT INTO auth_codes 
         (code, client_id, tenant_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, state, expires_at) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        code, client_id, tenant_id, user_id, redirect_uri, scope,
        code_challenge, code_challenge_method, nonce, state, expires_at
    )
    .execute(db.as_ref())
    .await?;

    Ok(())
}

pub async fn get_auth_code(db: &Database, code: &str) -> Result<Option<AuthCode>> {
    let auth_code = query_as!(
        AuthCode,
        "SELECT code, client_id, tenant_id, user_id, redirect_uri, scope, 
                code_challenge, code_challenge_method, nonce, state, 
                created_at, expires_at, consumed 
         FROM auth_codes 
         WHERE code = $1",
        code
    )
    .fetch_optional(db.as_ref())
    .await?;

    Ok(auth_code)
}

pub async fn consume_auth_code(db: &Database, code: &str) -> Result<()> {
    query!(
        "UPDATE auth_codes SET consumed = true WHERE code = $1",
        code
    )
    .execute(db.as_ref())
    .await?;

    Ok(())
}

pub async fn cleanup_expired_auth_codes(db: &Database) -> Result<()> {
    query!("DELETE FROM auth_codes WHERE expires_at < NOW()")
        .execute(db.as_ref())
        .await?;

    Ok(())
}

// Refresh token queries
pub async fn create_refresh_token(
    db: &Database,
    token: &str,
    client_id: &Uuid,
    tenant_id: &Uuid,
    user_id: &Uuid,
    scope: &[String],
    expires_at: OffsetDateTime,
) -> Result<()> {
    query!(
        "INSERT INTO refresh_tokens (token, client_id, tenant_id, user_id, scope, expires_at) 
         VALUES ($1, $2, $3, $4, $5, $6)",
        token,
        client_id,
        tenant_id,
        user_id,
        scope,
        expires_at
    )
    .execute(db.as_ref())
    .await?;

    Ok(())
}

pub async fn get_refresh_token(db: &Database, token: &str) -> Result<Option<RefreshToken>> {
    let refresh_token = query_as!(
        RefreshToken,
        "SELECT token, client_id, tenant_id, user_id, scope, created_at, expires_at, revoked 
         FROM refresh_tokens 
         WHERE token = $1",
        token
    )
    .fetch_optional(db.as_ref())
    .await?;

    Ok(refresh_token)
}

pub async fn revoke_refresh_token(db: &Database, token: &str) -> Result<()> {
    query!(
        "UPDATE refresh_tokens SET revoked = true WHERE token = $1",
        token
    )
    .execute(db.as_ref())
    .await?;

    Ok(())
}

pub async fn cleanup_expired_refresh_tokens(db: &Database) -> Result<()> {
    query!("DELETE FROM refresh_tokens WHERE expires_at < NOW() OR revoked = true")
        .execute(db.as_ref())
        .await?;

    Ok(())
}

// Session queries
pub async fn create_session(
    db: &Database,
    user_id: Option<&Uuid>,
    tenant_id: Option<&Uuid>,
    csrf: &str,
    expires_at: OffsetDateTime,
) -> Result<Session> {
    let session = query_as!(
        Session,
        "INSERT INTO sessions (user_id, tenant_id, csrf, expires_at) 
         VALUES ($1, $2, $3, $4) 
         RETURNING id, user_id, tenant_id, csrf, created_at, expires_at",
        user_id,
        tenant_id,
        csrf,
        expires_at
    )
    .fetch_one(db.as_ref())
    .await?;

    Ok(session)
}

pub async fn get_session(db: &Database, session_id: &Uuid) -> Result<Option<Session>> {
    let session = query_as!(
        Session,
        "SELECT id, user_id, tenant_id, csrf, created_at, expires_at 
         FROM sessions 
         WHERE id = $1 AND expires_at > NOW()",
        session_id
    )
    .fetch_optional(db.as_ref())
    .await?;

    Ok(session)
}

pub async fn update_session_user(
    db: &Database,
    session_id: &Uuid,
    user_id: &Uuid,
    tenant_id: &Uuid,
) -> Result<()> {
    query!(
        "UPDATE sessions SET user_id = $2, tenant_id = $3 WHERE id = $1",
        session_id,
        user_id,
        tenant_id
    )
    .execute(db.as_ref())
    .await?;

    Ok(())
}

pub async fn delete_session(db: &Database, session_id: &Uuid) -> Result<()> {
    query!("DELETE FROM sessions WHERE id = $1", session_id)
        .execute(db.as_ref())
        .await?;

    Ok(())
}

pub async fn cleanup_expired_sessions(db: &Database) -> Result<()> {
    query!("DELETE FROM sessions WHERE expires_at < NOW()")
        .execute(db.as_ref())
        .await?;

    Ok(())
}
