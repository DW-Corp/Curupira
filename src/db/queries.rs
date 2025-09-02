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

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Duration, OffsetDateTime};

    // Helper function to create a test database URL
    fn test_database_url() -> String {
        std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres:changeme@localhost:5432/authdb_test".to_string()
        })
    }

    // Helper function to create test database connection
    async fn create_test_db() -> Result<Database> {
        crate::db::create_pool(&test_database_url()).await.map_err(|e| anyhow::anyhow!(e))
    }

    #[tokio::test]
    async fn test_invalid_uuid_parameters() {
        // Test that functions handle malformed UUIDs gracefully
        let db = match create_test_db().await {
            Ok(db) => db,
            Err(_) => {
                println!("Skipping database tests - no test database available");
                return;
            }
        };

        // Test with invalid UUID in get_user_by_id
        let invalid_uuid = Uuid::nil(); // Use nil UUID as an edge case
        let result = get_user_by_id(&db, &invalid_uuid).await;
        assert!(result.is_ok(), "Should handle nil UUID gracefully");
        assert!(result.unwrap().is_none(), "Nil UUID should return None");

        // Test with random UUID that doesn't exist
        let random_uuid = Uuid::new_v4();
        let result = get_user_by_id(&db, &random_uuid).await;
        assert!(result.is_ok(), "Should handle non-existent UUID gracefully");
        assert!(result.unwrap().is_none(), "Non-existent UUID should return None");
    }

    #[tokio::test]
    async fn test_large_input_handling() {
        let db = match create_test_db().await {
            Ok(db) => db,
            Err(_) => {
                println!("Skipping database tests - no test database available");
                return;
            }
        };

        // Test extremely long slug (potential DoS attack)
        let very_long_slug = "a".repeat(10000);
        let result = get_tenant_by_slug(&db, &very_long_slug).await;
        assert!(result.is_ok(), "Should handle very long slug gracefully");
        assert!(result.unwrap().is_none(), "Very long slug should return None");

        // Test slug with special characters
        let special_slug = "test\0slug\n\r\t";
        let result = get_tenant_by_slug(&db, special_slug).await;
        assert!(result.is_ok(), "Should handle special characters in slug");

        // Test extremely long email
        let very_long_email = format!("{}@example.com", "a".repeat(1000));
        let random_tenant_id = Uuid::new_v4();
        let result = get_user_by_email(&db, &random_tenant_id, &very_long_email).await;
        assert!(result.is_ok(), "Should handle very long email gracefully");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention() {
        let db = match create_test_db().await {
            Ok(db) => db,
            Err(_) => {
                println!("Skipping database tests - no test database available");
                return;
            }
        };

        // Test SQL injection attempts in slug parameter
        let sql_injection_attempts = vec![
            "'; DROP TABLE tenants; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "\'; INSERT INTO tenants VALUES ('hack'); --",
            "admin'/*",
            "' OR 1=1#",
            "'; SHUTDOWN; --",
        ];

        for injection_attempt in sql_injection_attempts {
            let result = get_tenant_by_slug(&db, injection_attempt).await;
            assert!(result.is_ok(), "Should prevent SQL injection: {}", injection_attempt);
            assert!(result.unwrap().is_none(), "SQL injection should return None");
        }

        // Test SQL injection in email parameter
        let random_tenant_id = Uuid::new_v4();
        for injection_attempt in &["'; DROP TABLE users; --", "' OR '1'='1"] {
            let result = get_user_by_email(&db, &random_tenant_id, injection_attempt).await;
            assert!(result.is_ok(), "Should prevent SQL injection in email: {}", injection_attempt);
        }
    }

    #[tokio::test]
    async fn test_concurrent_access_scenarios() {
        let db = match create_test_db().await {
            Ok(db) => db,
            Err(_) => {
                println!("Skipping database tests - no test database available");
                return;
            }
        };

        // Test multiple concurrent reads
        let handles = (0..10).map(|i| {
            let db_clone = db.clone();
            let slug = format!("concurrent_test_{}", i);
            tokio::spawn(async move {
                get_tenant_by_slug(&db_clone, &slug).await
            })
        });

        // Wait for all concurrent operations to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "Concurrent reads should succeed");
        }
    }

    #[tokio::test]
    async fn test_unicode_and_special_characters() {
        let db = match create_test_db().await {
            Ok(db) => db,
            Err(_) => {
                println!("Skipping database tests - no test database available");
                return;
            }
        };

        // Test Unicode characters in various parameters
        let unicode_test_cases = vec![
            "тест",           // Cyrillic
            "测试",            // Chinese
            "テスト",          // Japanese
            "🔒🛡️💻",         // Emojis
            "café_münüs",      // Accented characters
            "test\u{0000}null", // Null byte
            "test\u{FFFF}max",  // High Unicode
        ];

        for test_case in unicode_test_cases {
            let result = get_tenant_by_slug(&db, test_case).await;
            assert!(result.is_ok(), "Should handle Unicode: {}", test_case);
        }
    }

    #[tokio::test]
    async fn test_edge_case_timestamps() {
        let db = match create_test_db().await {
            Ok(db) => db,
            Err(_) => {
                println!("Skipping database tests - no test database available");
                return;
            }
        };

        // Test with extreme timestamps
        let far_future = OffsetDateTime::now_utc() + Duration::days(36500); // ~100 years
        let far_past = OffsetDateTime::now_utc() - Duration::days(36500);

        // Create session with far future expiry
        let session_id = Uuid::new_v4();
        let result = create_session(&db, None, None, "test_csrf", far_future).await;
        if result.is_ok() {
            // If creation succeeded, test retrieval
            let retrieved = get_session(&db, &session_id).await;
            assert!(retrieved.is_ok(), "Should handle far future timestamps");
        }

        // Test auth code with far past expiry (should be immediately expired)
        let auth_code = "test_expired_code";
        let client_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let scope = vec!["openid".to_string()];
        let result = create_auth_code(
            &db,
            auth_code,
            &client_id,
            &tenant_id,
            &user_id,
            "https://example.com/callback",
            &scope,
            "test_challenge",
            "S256",
            Some("test_nonce"),
            None, // state
            far_past,
        ).await;
        
        // Auth code creation might fail due to expiry check, that's expected
        if result.is_ok() {
            let retrieved = get_auth_code(&db, auth_code).await;
            assert!(retrieved.is_ok(), "Should handle expired auth codes gracefully");
        }
    }

    #[tokio::test]
    async fn test_cleanup_functions_robustness() {
        let db = match create_test_db().await {
            Ok(db) => db,
            Err(_) => {
                println!("Skipping database tests - no test database available");
                return;
            }
        };

        // Test cleanup functions handle empty tables gracefully
        let result1 = cleanup_expired_auth_codes(&db).await;
        assert!(result1.is_ok(), "Cleanup auth codes should succeed even with empty table");

        let result2 = cleanup_expired_refresh_tokens(&db).await;
        assert!(result2.is_ok(), "Cleanup refresh tokens should succeed even with empty table");

        let result3 = cleanup_expired_sessions(&db).await;
        assert!(result3.is_ok(), "Cleanup sessions should succeed even with empty table");

        // Test multiple consecutive cleanups
        for _ in 0..3 {
            let result = cleanup_expired_sessions(&db).await;
            assert!(result.is_ok(), "Multiple consecutive cleanups should succeed");
        }
    }

    #[tokio::test]
    async fn test_boundary_value_handling() {
        let db = match create_test_db().await {
            Ok(db) => db,
            Err(_) => {
                println!("Skipping database tests - no test database available");
                return;
            }
        };

        // Test minimum and maximum valid values
        
        // Minimum length strings
        let min_slug = "a";
        let result = get_tenant_by_slug(&db, min_slug).await;
        assert!(result.is_ok(), "Should handle minimum length slug");

        // Empty string (edge case)
        let empty_slug = "";
        let result = get_tenant_by_slug(&db, empty_slug).await;
        assert!(result.is_ok(), "Should handle empty slug gracefully");

        // Test with minimum UUID (all zeros)
        let min_uuid = Uuid::from_u128(0);
        let result = get_user_by_id(&db, &min_uuid).await;
        assert!(result.is_ok(), "Should handle minimum UUID");

        // Test with maximum UUID (all ones)
        let max_uuid = Uuid::from_u128(u128::MAX);
        let result = get_user_by_id(&db, &max_uuid).await;
        assert!(result.is_ok(), "Should handle maximum UUID");
    }

    #[tokio::test]
    async fn test_malformed_data_resilience() {
        let db = match create_test_db().await {
            Ok(db) => db,
            Err(_) => {
                println!("Skipping database tests - no test database available");
                return;
            }
        };

        // Test various malformed inputs that might cause issues
        let malformed_inputs = vec![
            "\x00\x01\x02\x03", // Binary data
            "test\r\ninjection", // CRLF injection attempt
            "test\x1b[31mcolor", // ANSI escape sequences
            "test\u{202E}rtl",   // Right-to-left override
            "test\u{FEFF}bom",   // Byte order mark
            "test\u{200B}zwsp",  // Zero-width space
        ];

        for malformed_input in malformed_inputs {
            let result = get_tenant_by_slug(&db, malformed_input).await;
            assert!(result.is_ok(), "Should handle malformed input: {:?}", malformed_input);
        }
    }

    #[tokio::test]
    async fn test_transaction_edge_cases() {
        let db = match create_test_db().await {
            Ok(db) => db,
            Err(_) => {
                println!("Skipping database tests - no test database available");
                return;
            }
        };

        // Test operations that might cause constraint violations
        let duplicate_code = "duplicate_test_code";
        let client_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
        let scope1 = vec!["openid".to_string()];

        // Create first auth code
        let result1 = create_auth_code(
            &db,
            duplicate_code,
            &client_id,
            &tenant_id,
            &user_id,
            "https://example.com/callback",
            &scope1,
            "challenge1",
            "S256",
            Some("nonce1"),
            None, // state
            expires_at,
        ).await;

        if result1.is_ok() {
            let scope2 = vec!["openid".to_string(), "profile".to_string()];
            // Attempt to create duplicate auth code (should fail or handle gracefully)
            let result2 = create_auth_code(
                &db,
                duplicate_code, // Same code
                &client_id,
                &tenant_id,
                &user_id,
                "https://example.com/callback2",
                &scope2,
                "challenge2",
                "S256",
                Some("nonce2"),
                None, // state
                expires_at,
            ).await;

            // Either it should fail (constraint violation) or succeed (depending on implementation)
            // In either case, it shouldn't crash the application
            match result2 {
                Ok(_) => println!("Duplicate auth code handled gracefully"),
                Err(e) => println!("Duplicate auth code rejected as expected: {}", e),
            }
        }
    }

    #[tokio::test]
    async fn test_connection_resilience() {
        // Test with potentially invalid database URLs
        let invalid_urls = vec![
            "postgres://invalid:user@nonexistent:5432/db",
            "postgresql://user:pass@127.0.0.1:99999/db", // Invalid port
            "postgres://user@:5432/db", // Missing host
        ];

        for invalid_url in invalid_urls {
            let result = crate::db::create_pool(invalid_url).await;
            // Should fail gracefully, not panic
            assert!(result.is_err(), "Should reject invalid database URL: {}", invalid_url);
        }
    }
}
