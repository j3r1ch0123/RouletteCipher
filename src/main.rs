use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use std::fs::{read, write};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher}};
use rand::rngs::OsRng;
use rand::Rng; // For Russian Roulette and padding
use rand::RngCore; // For fill_bytes
use base64ct::{Base64, Encoding};
use anyhow::{Result, anyhow};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        input: String,
        output: String,
        password: Option<String>,
    },
    Decrypt {
        input: String,
        output: String,
        password: Option<String>,
    }
}

/// Helper to Base64-encode a byte slice
fn b64_encode(data: &[u8]) -> Result<String> {
    let mut buf = vec![0u8; Base64::encoded_len(data)];
    let encoded_str = Base64::encode(data, &mut buf)
        .map_err(|e| anyhow!("Base64 encode error: {:?}", e))?;
    Ok(encoded_str.to_string())
}

/// Helper to Base64-decode a string
fn b64_decode(s: &str) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; s.len()];
    let decoded_bytes = Base64::decode(s.as_bytes(), &mut buf)
        .map_err(|e| anyhow!("Base64 decode error: {:?}", e))?;
    Ok(decoded_bytes.to_vec())
}

/// Encrypt a file with password and polymorphic padding
fn encrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<()> {
    let mut plaintext = read(input_path)?;

    // Add random padding (polymorphic)
    let mut rng = rand::thread_rng();
    let pad_len = rng.gen_range(16..128);
    plaintext.extend((0..pad_len).map(|_| rng.gen::<u8>()));

    // Salt & key derivation
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let key_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Argon2 error: {:?}", e))?
        .hash
        .ok_or_else(|| anyhow!("Failed to derive key"))?;
    let key_bytes = key_hash.as_bytes();

    // AES cipher
    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| anyhow!("AES cipher error: {:?}", e))?;

    // Nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow!("AES encryption error: {:?}", e))?;

    // Encode & write
    let salt_b64 = b64_encode(salt.as_bytes())?;
    let nonce_b64 = b64_encode(&nonce_bytes)?;
    let ct_b64 = b64_encode(&ciphertext)?;
    write(output_path, format!("{}:{}:{}", salt_b64, nonce_b64, ct_b64))?;

    Ok(())
}

/// Decrypt with Russian Roulette: 1 in 3 chance of destroying file on wrong password
fn decrypt_file_roulette(input_path: &str, output_path: &str, password: &str) -> Result<()> {
    let content_bytes = read(input_path)?;
    let content_str = std::str::from_utf8(&content_bytes)?;
    let parts: Vec<&str> = content_str.split(':').collect();
    if parts.len() != 3 { return Err(anyhow!("Invalid input format")); }

    let salt_bytes = b64_decode(parts[0])?;
    let nonce_bytes = b64_decode(parts[1])?;
    let ct_bytes = b64_decode(parts[2])?;

    let salt = SaltString::new(std::str::from_utf8(&salt_bytes)?)
        .map_err(|e| anyhow!("Invalid salt: {:?}", e))?;
    let argon2 = Argon2::default();
    let key_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Argon2 error: {:?}", e))?
        .hash.ok_or_else(|| anyhow!("Failed to derive key"))?;
    let key_bytes = key_hash.as_bytes();

    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| anyhow!("AES cipher error: {:?}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.decrypt(nonce, ct_bytes.as_ref()) {
        Ok(plaintext) => {
            write(output_path, plaintext)?;
            println!("File decrypted successfully: {}", output_path);
            Ok(())
        },
        Err(_) => {
            // Russian Roulette: 1 in 3 chance to destroy file
            let mut rng = rand::thread_rng();
            if rng.gen_ratio(1, 3) {
                std::fs::remove_file(input_path)?;
                eprintln!("Wrong password! The file has been destroyed!");
            } else {
                eprintln!("Wrong password! The file survives... for now.");
            }
            Err(anyhow!("AES decryption failed"))
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output, password } => {
            let pw = password.unwrap_or_else(|| prompt_password("Enter password: ").unwrap());
            encrypt_file(&input, &output, &pw)?;
            println!("File encrypted successfully: {}", output);
        },
        Commands::Decrypt { input, output, password } => {
            let mut attempts = 0;
            let mut success = false;

            while attempts < 3 {
                let pw = if attempts == 0 {
                    password.clone().unwrap_or_else(|| prompt_password("Enter password: ").unwrap())
                } else {
                    prompt_password("Re-enter password: ").unwrap()
                };

                match decrypt_file_roulette(&input, &output, &pw) {
                    Ok(_) => {
                        success = true;
                        break;
                    },
                    Err(e) => {
                        eprintln!("{:?}", e);
                        attempts += 1;
                    }
                }
            }

            if !success {
                std::fs::remove_file(&input)?;
                eprintln!("Decryption failed after 3 attempts. Encrypted file deleted.");
            }
        }
    }

    Ok(())
}
