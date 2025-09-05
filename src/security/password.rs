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

    #[test]
    fn test_password_security_edge_cases() {
        // Test empty password
        let empty_result = hash_password("");
        assert!(empty_result.is_ok(), "Should handle empty password");
        let empty_hash = empty_result.unwrap();
        assert!(verify_password("", &empty_hash).unwrap());
        assert!(!verify_password("not_empty", &empty_hash).unwrap());

        // Test very long password (potential DoS vector)
        let long_password = "a".repeat(10000);
        let long_hash = hash_password(&long_password).expect("Failed to hash long password");
        assert!(verify_password(&long_password, &long_hash).unwrap());
        assert!(!verify_password("short", &long_hash).unwrap());

        // Test password with special characters
        let special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
        let special_hash = hash_password(special_chars).expect("Failed to hash special chars");
        assert!(verify_password(special_chars, &special_hash).unwrap());

        // Test unicode characters
        let unicode_password = "пароль🔒密码";
        let unicode_hash = hash_password(unicode_password).expect("Failed to hash unicode");
        assert!(verify_password(unicode_password, &unicode_hash).unwrap());
        assert!(!verify_password("password", &unicode_hash).unwrap());

        // Test whitespace handling
        let whitespace_password = "  password with spaces  ";
        let whitespace_hash =
            hash_password(whitespace_password).expect("Failed to hash whitespace");
        assert!(verify_password(whitespace_password, &whitespace_hash).unwrap());
        assert!(!verify_password("password with spaces", &whitespace_hash).unwrap()); // No leading/trailing spaces
        assert!(!verify_password("passwordwithspaces", &whitespace_hash).unwrap());
        // No spaces at all
    }

    #[test]
    fn test_password_verification_attacks() {
        let password = "correct_password";
        let hash = hash_password(password).expect("Failed to hash password");

        // Test common attack vectors
        let attack_vectors = vec![
            "",                   // Empty password
            "\0",                 // Null byte
            "\n",                 // Newline
            "\r\n",               // CRLF injection
            "correct_password\0", // Null byte injection
            "correct_password\n", // Newline injection
            "CORRECT_PASSWORD",   // Case sensitivity test
            "correct_password ",  // Trailing space
            " correct_password",  // Leading space
            "correct\0password",  // Null byte in middle
            "çorrect_password",   // Similar looking character
            "correct_passwörd",   // Similar with umlaut
        ];

        for attack in attack_vectors {
            assert!(
                !verify_password(attack, &hash).unwrap(),
                "Attack vector should fail: {:?}",
                attack
            );
        }

        // Verify the correct password still works
        assert!(verify_password(password, &hash).unwrap());
    }

    #[test]
    fn test_hash_format_validation() {
        let password = "test_password";
        let valid_hash = hash_password(password).expect("Failed to hash password");

        // Valid hash should start with Argon2id parameters
        assert!(
            valid_hash.starts_with("$argon2id$"),
            "Hash should use Argon2id: {}",
            valid_hash
        );

        // Test invalid hash formats
        let invalid_hashes = vec![
            "",                               // Empty hash
            "invalid_hash",                   // Plain text
            "$argon2$invalid$format",         // Wrong Argon2 variant
            "$argon2id$",                     // Incomplete hash
            "$argon2id$v=19$m=4096$t=3$p=1$", // Missing salt and hash
            "plain_text_password",            // Not hashed at all
            "$2b$10$invalid_bcrypt_hash",     // Different algorithm
            "$1$invalid$md5hash",             // MD5 (insecure)
        ];

        for invalid_hash in invalid_hashes {
            assert!(
                verify_password(password, invalid_hash).is_err(),
                "Should reject invalid hash format: {}",
                invalid_hash
            );
        }
    }

    #[test]
    fn test_timing_attack_resistance() {
        let password = "test_password";
        let hash = hash_password(password).expect("Failed to hash password");

        // Test that verification takes similar time for valid and invalid passwords
        // This is a basic test - real timing attack testing requires more sophisticated approaches

        use std::time::Instant;

        // Measure valid password verification
        let start = Instant::now();
        let _valid_result = verify_password(password, &hash).unwrap();
        let valid_duration = start.elapsed();

        // Measure invalid password verification
        let start = Instant::now();
        let _invalid_result = verify_password("wrong_password", &hash).unwrap();
        let invalid_duration = start.elapsed();

        // Both should take some time (Argon2 is designed to be slow)
        assert!(
            valid_duration.as_millis() > 0,
            "Valid password verification should take time"
        );
        assert!(
            invalid_duration.as_millis() > 0,
            "Invalid password verification should take time"
        );

        // The ratio shouldn't be extreme (within 10x of each other)
        // Note: This is a very loose test, real timing attack resistance requires more analysis
        let ratio = if valid_duration > invalid_duration {
            valid_duration.as_nanos() as f64 / invalid_duration.as_nanos() as f64
        } else {
            invalid_duration.as_nanos() as f64 / valid_duration.as_nanos() as f64
        };

        assert!(ratio < 10.0, "Timing difference too large: {}x", ratio);
    }

    #[test]
    fn test_password_strength_scenarios() {
        // Test various password strength scenarios to ensure they all work
        let test_passwords = vec![
            // Weak passwords (still should hash successfully)
            ("123456", "Weak numeric"),
            ("password", "Common word"),
            ("qwerty", "Keyboard pattern"),
            // Medium strength
            ("Password123", "Mixed case + numbers"),
            ("my_secure_pass", "Underscores and words"),
            // Strong passwords
            ("MySecureP@ssw0rd!", "Mixed case, numbers, symbols"),
            ("correct horse battery staple", "Passphrase"),
            ("Tr0ub4dor&3", "XKCD style"),
            // Very long passwords
            (
                "This is a very long password that someone might actually use in real life",
                "Long passphrase",
            ),
            // International characters
            ("强密码123", "Chinese characters"),
            ("пароль123", "Cyrillic"),
            ("パスワード123", "Japanese"),
        ];

        for (password, description) in test_passwords {
            let hash = hash_password(password)
                .expect(&format!("Failed to hash {}: {}", description, password));

            assert!(
                verify_password(password, &hash).unwrap(),
                "Failed to verify {}: {}",
                description,
                password
            );

            // Ensure other passwords don't work
            assert!(
                !verify_password("wrong_password", &hash).unwrap(),
                "Wrong password incorrectly verified for {}: {}",
                description,
                password
            );
        }
    }
}
