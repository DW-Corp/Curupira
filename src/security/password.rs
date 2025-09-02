// [library] Argon2 - industry-standard password hashing algorithm
// Argon2id variant provides both memory-hard and compute-hard properties
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, // [security] Password hashing traits and secure randomness
    Argon2, // [security] Argon2 algorithm implementation
};

// [library] Structured error types with automatic Display and Error trait derivation
use thiserror::Error;

// [rust] Custom error type for password operations with structured error handling
#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Password hashing failed: {0}")] // [rust] Error message template with placeholder
    HashError(argon2::password_hash::Error), // [rust] Manual error wrapping
}

// [rust] Manual implementation of From trait for error conversion
impl From<argon2::password_hash::Error> for PasswordError {
    fn from(err: argon2::password_hash::Error) -> Self {
        PasswordError::HashError(err)
    }
}

// [security] Hash password using Argon2id with cryptographically secure salt
// Stores salt in the hash string for verification - never store plaintext passwords
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    // [security] Generate cryptographically secure random salt using OS entropy
    let salt = SaltString::generate(&mut OsRng); // [security] Each password gets unique salt

    // [security] Use Argon2id with default parameters (memory cost, time cost, parallelism)
    let argon2 = Argon2::default(); // [security] Secure default parameters

    // [security] Hash password with salt - result includes algorithm parameters and salt
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)? // [rust] Convert string to bytes, propagate errors
        .to_string(); // [library] Convert to PHC string format

    Ok(password_hash) // [rust] Return PHC-formatted hash string
}

// [security] Verify password against stored Argon2id hash using constant-time comparison
// Prevents timing attacks by always taking the same time regardless of result
pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
    // [security] Parse PHC string format to extract algorithm parameters, salt, and hash
    let parsed_hash = PasswordHash::new(hash)?; // [library] Parse stored hash string

    // [security] Initialize Argon2 with same parameters used during hashing
    let argon2 = Argon2::default(); // [security] Must match hashing parameters

    // [security] Perform constant-time password verification
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true), // [security] Password matches - verification successful
        Err(argon2::password_hash::Error::Password) => Ok(false), // [security] Password mismatch - expected error
        Err(e) => Err(PasswordError::HashError(e)), // [rust] Unexpected error - propagate up
    }
}

// [rust] Unit tests for password security functions
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let password = "test_password_123";
        let hash = hash_password(password).expect("Failed to hash password");

        assert!(verify_password(password, &hash).expect("Failed to verify password"));
        assert!(!verify_password("wrong_password", &hash).expect("Failed to verify wrong password"));
    }

    #[test]
    fn test_different_hashes_for_same_password() {
        let password = "same_password";
        let hash1 = hash_password(password).expect("Failed to hash password");
        let hash2 = hash_password(password).expect("Failed to hash password");

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(verify_password(password, &hash1).expect("Failed to verify password"));
        assert!(verify_password(password, &hash2).expect("Failed to verify password"));
    }
}
