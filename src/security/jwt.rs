// [business] Import database entities for JWT token creation and validation
use crate::db::models::{Application, User};

// [library] Error handling - anyhow provides flexible error types for applications
use anyhow::{anyhow, Result};

// [library] JOSE kit - JSON Web Signature and JWT implementation for Rust
use josekit::{
    jwk::Jwk,                // [security] JSON Web Key format for cryptographic keys
    jws::{JwsHeader, RS256}, // [security] JSON Web Signature with RSA-SHA256 algorithm
    jwt::{self, JwtPayload}, // [security] JWT creation and parsing utilities
};

// [library] JSON serialization for JWT claims and responses
use serde::{Deserialize, Serialize};
use serde_json::Value; // [library] JSON value manipulation (json import removed as unused)

// [rust] Standard library collections for key-value data (HashMap unused, commented out)
// use std::collections::HashMap;

// [library] Time handling for token expiration and timestamps
use time::{Duration, OffsetDateTime};

// [library] UUID generation for unique token identifiers (jti claim)
use uuid::Uuid;

// [library] Base64 encoding for JWTs and PKCE code challenges
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

// [business] JWT claims structure - represents all data contained in JWT tokens
// Combines standard JWT claims with OAuth2/OpenID Connect specific claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    // [security] Standard JWT claims (RFC 7519) - required for token validation
    pub iss: String, // [security] Issuer - who created and signed the token
    pub sub: String, // [business] Subject - unique user identifier
    pub aud: String, // [security] Audience - intended token recipient (client_id)
    pub exp: i64,    // [security] Expiration time - Unix timestamp when token expires
    pub iat: i64,    // [security] Issued at - Unix timestamp when token was created
    pub jti: String, // [security] JWT ID - unique token identifier for revocation

    // [business] OAuth2/OIDC specific claims for authorization and user info
    pub scope: String,  // [business] Space-separated list of granted permissions
    pub tenant: String, // [business] Multi-tenant isolation - which organization
    pub roles: Vec<String>, // [business] User's roles within the requesting application

    // [business] OpenID Connect claims (for ID tokens) - user profile information
    pub nonce: Option<String>, // [security] Prevents token replay attacks
    pub email: Option<String>, // [business] User's email address
    pub email_verified: Option<bool>, // [business] Email verification status
    pub name: Option<String>,  // [business] Full display name
    pub given_name: Option<String>, // [business] First name
    pub family_name: Option<String>, // [business] Last name
}

// [business] JWT token signing and verification service
// Handles creation and validation of access tokens and ID tokens using RSA signatures
pub struct JwtSigner {
    issuer: String, // [business] OAuth2 issuer identifier - goes into iss claim
}

// [rust] Implementation block for JWT signing operations
impl JwtSigner {
    // [rust] Constructor - creates new JwtSigner instance with issuer URL
    pub fn new(issuer: String) -> Self {
        Self { issuer }
    }

    // [business] Create OAuth2 access token - used for API authentication
    // Access tokens contain user identity, permissions, and authorization scope
    pub fn create_access_token(
        &self,
        app: &Application, // [business] OAuth2 client application requesting the token
        user: &User,       // [business] User being authenticated
        roles: Vec<String>, // [business] User's roles within this application
        scope: &str,       // [business] Granted OAuth2 scopes (permissions)
        ttl_secs: i64,     // [business] Token lifetime in seconds (typically 1 hour)
    ) -> Result<String> {
        // [rust] Returns JWT string or error
        // [business] Calculate token timestamps for security validation
        let now = OffsetDateTime::now_utc(); // [library] Current time in UTC
        let exp = now + Duration::seconds(ttl_secs); // [business] Token expiration time

        // [business] Construct JWT claims with all required information
        let claims = JwtClaims {
            iss: self.issuer.clone(),        // [security] Token issuer (our auth server)
            sub: user.id.to_string(),        // [business] User UUID as subject
            aud: app.client_id.to_string(),  // [security] Application client ID as audience
            exp: exp.unix_timestamp(),       // [security] Expiration timestamp
            iat: now.unix_timestamp(),       // [security] Issued at timestamp
            jti: Uuid::new_v4().to_string(), // [security] Unique token ID for tracking/revocation
            scope: scope.to_string(),        // [business] Authorized permissions
            tenant: app.tenant_id.to_string(), // [business] Multi-tenant context
            roles,                           // [business] User's application-specific roles
            nonce: None,                     // [business] Not used in access tokens
            email: Some(user.email.clone()), // [business] User email for convenience
            email_verified: Some(user.email_verified), // [business] Email verification status
            // [rust] Combine given and family names if both exist, using zip for Option handling
            name: user
                .given_name
                .as_ref()
                .zip(user.family_name.as_ref())
                .map(|(given, family)| format!("{} {}", given, family)),
            given_name: user.given_name.clone(), // [business] User's first name
            family_name: user.family_name.clone(), // [business] User's last name
        };

        // [security] Sign the JWT with the application's private RSA key
        self.sign_jwt(&claims, app)
    }

    // [business] Create OpenID Connect ID token - provides user identity information
    // ID tokens are meant for client applications to identify the authenticated user
    pub fn create_id_token(
        &self,
        app: &Application, // [business] OAuth2 client application requesting the token
        user: &User,       // [business] User being authenticated
        nonce: Option<String>, // [security] Prevents replay attacks - from authorization request
        ttl_secs: i64,     // [business] Token lifetime (typically same as access token)
    ) -> Result<String> {
        // [rust] Returns JWT string or error
        // [business] Calculate token timestamps
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::seconds(ttl_secs);

        // [business] Construct ID token claims - focused on user identity
        let claims = JwtClaims {
            iss: self.issuer.clone(),                  // [security] Token issuer
            sub: user.id.to_string(), // [business] User identifier (consistent across tokens)
            aud: app.client_id.to_string(), // [security] Application that requested authentication
            exp: exp.unix_timestamp(), // [security] Expiration timestamp
            iat: now.unix_timestamp(), // [security] Issued at timestamp
            jti: Uuid::new_v4().to_string(), // [security] Unique token ID
            scope: "openid".to_string(), // [business] ID tokens always have openid scope
            tenant: app.tenant_id.to_string(), // [business] Multi-tenant context
            roles: vec![],            // [business] ID tokens don't include authorization info
            nonce,                    // [security] Echo back nonce from authorization request
            email: Some(user.email.clone()), // [business] User's email address
            email_verified: Some(user.email_verified), // [business] Email verification status
            // [rust] Combine names for display purposes
            name: user
                .given_name
                .as_ref()
                .zip(user.family_name.as_ref())
                .map(|(given, family)| format!("{} {}", given, family)),
            given_name: user.given_name.clone(), // [business] User's first name
            family_name: user.family_name.clone(), // [business] User's last name
        };

        // [security] Sign with application's private key
        self.sign_jwt(&claims, app)
    }

    // [security] Sign JWT using RSA-SHA256 algorithm with application's private key
    // Each application has its own RSA keypair for cryptographic isolation
    fn sign_jwt(&self, claims: &JwtClaims, app: &Application) -> Result<String> {
        // [security] Parse RSA private key from PEM format stored in database
        let private_key = Jwk::from_bytes(&app.jwk_private_pem)?;

        // [security] Create JWT header with cryptographic algorithm and key identifier
        let mut header = JwsHeader::new();
        header.set_algorithm("RS256"); // [security] RSA signature with SHA-256 hash
        header.set_key_id(&app.jwk_kid.to_string()); // [security] Key ID for key rotation support

        // [library] Convert claims struct to JWT payload format
        let payload_json = serde_json::to_value(claims)?; // [library] Serialize to JSON Value
        let mut payload = JwtPayload::new(); // [library] Create JWT payload container
        if let Value::Object(map) = payload_json {
            // [library] Transfer all claims from JSON object to JWT payload
            for (key, value) in map {
                payload.set_claim(&key, Some(value))?; // [library] Set individual JWT claims
            }
        }

        // [security] Create digital signature using RSA private key
        let signer = RS256.signer_from_jwk(&private_key)?; // [security] Initialize RSA signer
        let jwt = jwt::encode_with_signer(&payload, &header, &signer)?; // [security] Sign and encode JWT

        Ok(jwt) // [rust] Return signed JWT string
    }

    // [security] Verify JWT signature and validate claims using application's public key
    // Critical security function - ensures token authenticity and validity
    pub fn verify_jwt(&self, token: &str, app: &Application) -> Result<JwtClaims> {
        // [security] Parse RSA public key from JWK format stored in database
        let public_key = Jwk::from_bytes(app.jwk_public_jwk.0.to_string().as_bytes())?;

        // [security] Verify JWT signature using RSA public key
        let verifier = RS256.verifier_from_jwk(&public_key)?; // [security] Initialize RSA verifier
        let (payload, header) = jwt::decode_with_verifier(token, &verifier)?; // [security] Verify and decode

        // [security] Validate key ID matches expected application key
        if let Some(kid) = header.key_id() {
            if kid != app.jwk_kid.to_string() {
                return Err(anyhow!("Token key ID does not match application key"));
            }
        }

        // [business] Extract all claims from verified JWT payload
        let claims = self.extract_claims(&payload)?;

        // [security] Validate standard JWT claims (expiration, issuer, audience)
        self.validate_claims(&claims, app)?;

        Ok(claims) // [rust] Return validated claims
    }

    /// Extract claims from JWT payload
    fn extract_claims(&self, payload: &JwtPayload) -> Result<JwtClaims> {
        let claims = JwtClaims {
            iss: payload
                .claim("iss")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing or invalid 'iss' claim"))?
                .to_string(),
            sub: payload
                .claim("sub")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing or invalid 'sub' claim"))?
                .to_string(),
            aud: payload
                .claim("aud")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing or invalid 'aud' claim"))?
                .to_string(),
            exp: payload
                .claim("exp")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| anyhow!("Missing or invalid 'exp' claim"))?,
            iat: payload
                .claim("iat")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| anyhow!("Missing or invalid 'iat' claim"))?,
            jti: payload
                .claim("jti")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing or invalid 'jti' claim"))?
                .to_string(),
            scope: payload
                .claim("scope")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            tenant: payload
                .claim("tenant")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            roles: payload
                .claim("roles")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            nonce: payload
                .claim("nonce")
                .and_then(|v| v.as_str())
                .map(String::from),
            email: payload
                .claim("email")
                .and_then(|v| v.as_str())
                .map(String::from),
            email_verified: payload.claim("email_verified").and_then(|v| v.as_bool()),
            name: payload
                .claim("name")
                .and_then(|v| v.as_str())
                .map(String::from),
            given_name: payload
                .claim("given_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            family_name: payload
                .claim("family_name")
                .and_then(|v| v.as_str())
                .map(String::from),
        };

        Ok(claims)
    }

    // [security] Validate critical JWT claims to ensure token authenticity and validity
    // Implements security checks required by JWT and OAuth2 specifications
    fn validate_claims(&self, claims: &JwtClaims, app: &Application) -> Result<()> {
        let now = OffsetDateTime::now_utc().unix_timestamp(); // [library] Current time for expiration checks

        // [security] Validate issuer claim - prevents token forgery from other issuers
        if claims.iss != self.issuer {
            return Err(anyhow!(
                "Invalid issuer: expected {}, got {}",
                self.issuer,
                claims.iss
            ));
        }

        // [security] Validate audience claim - ensures token is intended for this application
        if claims.aud != app.client_id.to_string() {
            return Err(anyhow!(
                "Invalid audience: expected {}, got {}",
                app.client_id,
                claims.aud
            ));
        }

        // [security] Check token expiration with clock skew tolerance
        // 60-second tolerance accounts for time differences between servers
        if claims.exp < (now - 60) {
            return Err(anyhow!("Token has expired"));
        }

        // [security] Validate issued-at time - prevents tokens "issued in the future"
        // Helps detect clock skew issues and potential replay attacks
        if claims.iat > (now + 60) {
            return Err(anyhow!("Token issued in the future"));
        }

        Ok(()) // [rust] All validations passed
    }
}

// [business] Extract key ID from JWT header without full token verification
// Used for key lookup before performing expensive signature verification
pub fn extract_kid_from_jwt(token: &str) -> Result<String> {
    // [library] Parse JWT structure - header.payload.signature format
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT format")); // [security] Reject malformed tokens
    }

    // [library] Decode base64url-encoded header (first part of JWT)
    let header_json = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| anyhow!("Invalid JWT header encoding"))?;

    // [library] Parse JSON header to extract metadata
    let header: Value =
        serde_json::from_slice(&header_json).map_err(|_| anyhow!("Invalid JWT header JSON"))?;

    // [security] Extract key ID for application key lookup
    let kid = header
        .get("kid") // [library] Get kid field from JSON
        .and_then(|v| v.as_str()) // [rust] Convert to string if present
        .ok_or_else(|| anyhow!("Missing 'kid' in JWT header"))?; // [security] Error if kid missing

    Ok(kid.to_string()) // [rust] Return key ID as owned string
}

// [security] Generate cryptographically secure random token
// Used for refresh tokens, CSRF tokens, and other security-critical random values
pub fn generate_random_token() -> String {
    use rand::Rng; // [library] Random number generation trait

    // [security] Generate 32 bytes (256 bits) of cryptographically secure randomness
    let random_bytes: [u8; 32] = rand::thread_rng().gen(); // [security] Thread-safe crypto RNG

    // [library] Encode as base64url without padding for URL safety
    URL_SAFE_NO_PAD.encode(random_bytes)
}

// [rust] Unit tests for JWT functionality and security properties
#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    // [rust] Test helper - create a mock user for testing JWT operations
    fn create_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            email_verified: true,
            password_hash: "hash".to_string(), // [business] Not used in JWT tests
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            created_at: OffsetDateTime::now_utc(),
            disabled: false,
        }
    }

    #[test]
    fn test_generate_random_token() {
        // [security] Test that random token generation produces unique values
        let token1 = generate_random_token();
        let token2 = generate_random_token();

        // [security] Tokens must be different (extremely low probability of collision)
        assert_ne!(token1, token2);
        // [library] Base64 encoding of 32 bytes should be ~43 characters
        assert!(token1.len() > 40);
    }
}
