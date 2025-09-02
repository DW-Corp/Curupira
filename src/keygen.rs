use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use josekit::{
    jwk::{alg::rsa::RsaKeyPair, Jwk},
    jws::RS256,
};
use serde_json::json;
use uuid::Uuid;

/// Generate RSA keypair for JWT signing
pub fn generate_rsa_keypair(kid: Option<Uuid>) -> Result<(String, serde_json::Value)> {
    // Generate RSA 2048-bit keypair
    let key_pair = RsaKeyPair::generate(2048)?;
    let private_jwk = Jwk::from_bytes(key_pair.to_der_private_key())?;

    // Create public JWK
    let public_jwk = private_jwk.to_public_key()?;

    // Set key ID
    let key_id = kid.unwrap_or_else(Uuid::new_v4).to_string();

    // Convert private key to PEM format
    let private_pem = String::from_utf8(key_pair.to_pem_private_key())?;

    // Create public JWK JSON using the public_jwk we already have
    let mut public_jwk_json = serde_json::to_value(&public_jwk)?;

    // Add the required fields for JWKS
    if let serde_json::Value::Object(ref mut obj) = public_jwk_json {
        obj.insert("kid".to_string(), json!(key_id));
        obj.insert("use".to_string(), json!("sig"));
        obj.insert("alg".to_string(), json!("RS256"));
    }

    let public_jwk_value = public_jwk_json;

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
