// [library] Base64 encoding for PKCE code challenges - RFC 7636 requires base64url without padding
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

// [library] Cryptographically secure random number generation for code verifiers
use rand::{distributions::Alphanumeric, Rng};

// [library] SHA-256 cryptographic hash function for PKCE S256 method
use sha2::{Digest, Sha256};

// [library] Structured error handling with automatic trait derivation
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PkceError {
    #[error("Invalid code verifier length: {0}. Must be between 43 and 128 characters")]
    InvalidVerifierLength(usize),
    #[error("Invalid code challenge length: {0}. Must be between 43 and 128 characters")]
    InvalidChallengeLength(usize),
    #[error("Unsupported code challenge method: {0}. Only S256 is supported")]
    UnsupportedMethod(String),
    #[error("Code verifier contains invalid characters")]
    InvalidVerifierCharacters,
    #[error("PKCE verification failed")]
    VerificationFailed,
}

// [security] Generate cryptographically secure PKCE code verifier
// Used by OAuth2 clients to prevent authorization code interception attacks
pub fn generate_code_verifier() -> String {
    // [security] Generate 32 random alphanumeric bytes for sufficient entropy
    // Results in 43-character base64url string when encoded
    let random_bytes: Vec<u8> = rand::thread_rng() // [security] Cryptographically secure RNG
        .sample_iter(&Alphanumeric) // [library] Alphanumeric character distribution
        .take(32) // [security] 32 bytes = 256 bits entropy
        .collect();

    // [library] Base64url encode without padding per RFC 7636
    URL_SAFE_NO_PAD.encode(random_bytes)
}

/// Create a code challenge from a code verifier using S256 method
pub fn create_code_challenge(code_verifier: &str) -> Result<String, PkceError> {
    validate_code_verifier(code_verifier)?;

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let digest = hasher.finalize();

    Ok(URL_SAFE_NO_PAD.encode(digest))
}

/// Validate that a code verifier meets PKCE requirements
pub fn validate_code_verifier(code_verifier: &str) -> Result<(), PkceError> {
    let len = code_verifier.len();
    if len < 43 || len > 128 {
        return Err(PkceError::InvalidVerifierLength(len));
    }

    // RFC 7636: code_verifier should use [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
    if !code_verifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
    {
        return Err(PkceError::InvalidVerifierCharacters);
    }

    Ok(())
}

/// Validate that a code challenge meets PKCE requirements  
pub fn validate_code_challenge(code_challenge: &str) -> Result<(), PkceError> {
    let len = code_challenge.len();
    if len < 43 || len > 128 {
        return Err(PkceError::InvalidChallengeLength(len));
    }

    Ok(())
}

/// Verify that a code verifier matches the given code challenge
pub fn verify_code_challenge(
    code_verifier: &str,
    code_challenge: &str,
    code_challenge_method: &str,
) -> Result<(), PkceError> {
    // Only S256 method is supported per RFC 9700 best practices
    if code_challenge_method != "S256" {
        return Err(PkceError::UnsupportedMethod(
            code_challenge_method.to_string(),
        ));
    }

    validate_code_verifier(code_verifier)?;
    validate_code_challenge(code_challenge)?;

    let computed_challenge = create_code_challenge(code_verifier)?;

    if computed_challenge != code_challenge {
        return Err(PkceError::VerificationFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_verifier() {
        let verifier = generate_code_verifier();
        assert!(verifier.len() >= 43);
        assert!(verifier.len() <= 128);
        validate_code_verifier(&verifier).expect("Generated verifier should be valid");
    }

    #[test]
    fn test_create_and_verify_code_challenge() {
        let verifier = generate_code_verifier();
        let challenge = create_code_challenge(&verifier).expect("Failed to create challenge");

        verify_code_challenge(&verifier, &challenge, "S256")
            .expect("Failed to verify valid PKCE pair");
    }

    #[test]
    fn test_invalid_verifier_length() {
        let short_verifier = "short";
        let long_verifier = "a".repeat(129);

        assert!(matches!(
            validate_code_verifier(&short_verifier),
            Err(PkceError::InvalidVerifierLength(_))
        ));

        assert!(matches!(
            validate_code_verifier(&long_verifier),
            Err(PkceError::InvalidVerifierLength(_))
        ));
    }

    #[test]
    fn test_invalid_verifier_characters() {
        let invalid_verifier = "a".repeat(43) + "!"; // Contains invalid character

        assert!(matches!(
            validate_code_verifier(&invalid_verifier),
            Err(PkceError::InvalidVerifierCharacters)
        ));
    }

    #[test]
    fn test_verification_failure() {
        let verifier = generate_code_verifier();
        let challenge = create_code_challenge(&verifier).expect("Failed to create challenge");
        let wrong_verifier = generate_code_verifier();

        assert!(matches!(
            verify_code_challenge(&wrong_verifier, &challenge, "S256"),
            Err(PkceError::VerificationFailed)
        ));
    }

    #[test]
    fn test_unsupported_challenge_method() {
        let verifier = generate_code_verifier();
        let challenge = create_code_challenge(&verifier).expect("Failed to create challenge");

        assert!(matches!(
            verify_code_challenge(&verifier, &challenge, "plain"),
            Err(PkceError::UnsupportedMethod(_))
        ));
    }
}
