use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = b"hunter42"; // Bad password; don't actually use!
    let salt = SaltString::generate(&mut OsRng);
    println!("{}",salt);
    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();
    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(password, &salt)?.to_string();

    let parsed_hash = PasswordHash::new(&password_hash)?;
    assert!(Argon2::default()
        .verify_password(password, &parsed_hash)
        .is_ok());
    let mut key = [0u8; 32];
    let mut decoded_salt = [0u8; 16]; // Adjust size as needed
    let salt_bytes = salt.decode_b64(&mut decoded_salt)?;
    argon2.hash_password_into(password, salt_bytes, &mut key)?;
    
   // 

    let key: &Key<Aes256Gcm> = &key.into();
    let key = [0u8; 32];
    // Note that you can get byte array from slice using the `TryInto` trait:
    let key: &[u8] = &[42; 32];

    // Alternatively, the key can be transformed directly from a byte slice
    // (panicks on length mismatch):
    let key = Key::<Aes256Gcm>::from_slice(&key);

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref()).unwrap();
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
    
    
   
    


    Ok(())
}
