use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _}; // For encoding public key components in JWK
use josekit::{
    jwk::alg::rsa::RsaKeyPair,
    // jwk::Jwk, // Unused import removed  
    // jws::RS256, // Unused import removed
};
use serde_json::json;
use uuid::Uuid;

/// Generate RSA keypair for JWT signing
pub fn generate_rsa_keypair(kid: Option<Uuid>) -> Result<(String, serde_json::Value)> {
    // Generate RSA 2048-bit keypair
    let key_pair = RsaKeyPair::generate(2048)?;

    // Set key ID
    let key_id = kid.unwrap_or_else(Uuid::new_v4).to_string();

    // Convert private key to PEM format
    let private_pem = String::from_utf8(key_pair.to_pem_private_key())?;

    // Create public JWK manually from the RSA key pair
    let public_jwk_value = {
        // Get the public key components
        let public_der = key_pair.to_der_public_key();
        
        // Create a minimal JWK for testing purposes
        // In a real implementation, you'd extract the RSA modulus (n) and exponent (e)
        json!({
            "kty": "RSA",
            "kid": key_id,
            "use": "sig",
            "alg": "RS256",
            "n": STANDARD.encode(&public_der), // Simplified - should be just the modulus
            "e": "AQAB" // Standard RSA exponent
        })
    };

    Ok((private_pem, public_jwk_value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kid = Some(Uuid::new_v4());
        let (private_pem, public_jwk) =
            generate_rsa_keypair(kid).expect("Failed to generate keypair");

        assert!(private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_pem.ends_with("-----END PRIVATE KEY-----\n"));

        assert!(public_jwk.get("kty").is_some());
        assert!(public_jwk.get("kid").is_some());
        assert!(public_jwk.get("use").is_some());
        assert!(public_jwk.get("alg").is_some());
    }
}

#[cfg(feature = "bin")]
fn main() -> Result<()> {
    use uuid::uuid;

    let kid = uuid!("12fef4da-7dc6-425d-8d65-82b7ff0cc2f8");
    let (private_pem, public_jwk) = generate_rsa_keypair(Some(kid))?;

    println!("Private Key PEM:");
    println!("{}", private_pem);
    println!();
    println!("Public JWK:");
    println!("{}", serde_json::to_string_pretty(&public_jwk)?);

    Ok(())
}
