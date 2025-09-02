// [rust] Security module organization - cryptographic and security utilities
pub mod jwt; // [security] JSON Web Token signing, verification, and claims management
pub mod password; // [security] Argon2id password hashing and verification
pub mod pkce; // [security] Proof Key for Code Exchange (RFC 7636) implementation

// [rust] Re-export all public items for easier imports
// This creates a flat namespace: use crate::security::hash_password instead of crate::security::password::hash_password
pub use jwt::*; // [security] JWT signing, verification, and token generation functions
// Note: Re-exports commented out as they are currently unused
// pub use password::*; // [security] Password hashing and verification functions
// pub use pkce::*; // [security] PKCE code challenge generation and validation functions
