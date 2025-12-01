use aes_gcm::{Aes256Gcm, Key, Nonce}; 
use aes_gcm::aead::{Aead, KeyInit}; 
use argon2::Argon2; 
use rand::RngCore;
use std::{fs, env};
use zeroize::Zeroize;

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon = Argon2::default();
    let mut key = [0u8; 32];

    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("KDF failed");

    key
}

fn encrypt(input: &str, password: &str) {
    let data = fs::read(input).expect("Cannot read file");

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key_bytes = derive_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher.encrypt(nonce, data.as_ref())
        .expect("Encryption failed");

    let mut output = salt.to_vec();
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);

    fs::write(format!("{}.enc", input), output)
        .expect("Write failed");

    // Secure cleanup
    let mut pw = password.to_string();
    pw.zeroize();

    println!("File encrypted → {}.enc", input);
}

fn decrypt(input: &str, password: &str) {
    let data = fs::read(input).expect("Cannot read file");

    let salt = &data[..16];
    let nonce = &data[16..28];
    let ciphertext = &data[28..];

    let key_bytes = derive_key(password, salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    let cipher = Aes256Gcm::new(key);
    let decrypted = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
        .expect("Decryption failed");

    let out_name = input.trim_end_matches(".enc");
    fs::write(out_name, decrypted).expect("Write failed");

    println!("File decrypted → {}", out_name);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage:
  ./masquerade encrypt <file> <password>
  ./masquerade decrypt <file.enc> <password>");
        return;
    }

    let cmd = &args[1];
    let file = &args[2];
    let password = &args[3];

    match cmd.as_str() {
        "encrypt" => encrypt(file, password),
        "decrypt" => decrypt(file, password),
        _ => eprintln!("Unknown command"),
    }
}
