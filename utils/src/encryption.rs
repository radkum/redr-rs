use std::{error::Error, io::Write, path::Path};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::Argon2;
use rand::random;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub const AMSI_PASSWORD: &[u8; 32] = b"YDsW_vKS=ds=Bq_#Fz3Fh;2Pws%.wpg=";

/// Decrypts a file encrypted in chunks by encrypt_file, writing the decrypted
/// data to the output path.
/// Returns the SHA-256 hash of the decrypted (plaintext) file.
pub fn decrypt_file(
    mut input_file: std::fs::File,
    mut output_file: std::fs::File,
    password: &[u8],
    hasher: Option<Sha256>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    let mut hasher = hasher.unwrap_or_default();
    loop {
        let mut len_bytes = [0u8; 4];
        // Read the length of the next encrypted chunk
        if input_file.read_exact(&mut len_bytes).is_err() {
            break; // EOF reached
        }
        let chunk_len = u32::from_be_bytes(len_bytes) as usize;
        let mut encrypted_chunk = vec![0u8; chunk_len];
        input_file.read_exact(&mut encrypted_chunk)?;
        let decrypted = decrypt_chunk(&encrypted_chunk, password)?;
        hasher.update(&decrypted);
        output_file.write_all(&decrypted)?;
    }
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}

/// Helper to decrypt a single chunk (same as decrypt_reader but for &[u8])
fn decrypt_chunk(data: &[u8], password: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if data.len() < 28 {
        return Err("Chunk too small".into());
    }
    let salt = &data[..16];
    let nonce = &data[16..28];
    let ciphertext = &data[28..];
    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext.as_ref())
        .map_err(|e| Into::<Box<dyn Error>>::into(format!("Decryption error: {:?}", e)))?;
    Ok(plaintext)
}

pub fn read_json_file<T: DeserializeOwned>(
    path: &Path,
    password: &[u8],
) -> Result<T, Box<dyn Error>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let decrypted = decrypt_reader(reader, password)?;
    let data = serde_json::from_slice(decrypted.as_slice())?;
    Ok(data)
}

pub fn decrypt_reader<R: std::io::Read>(
    mut reader: R,
    password: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut data = Vec::new();
    let _size = reader.read_to_end(&mut data)?;

    let salt = &data[..16];
    let nonce = &data[16..28];
    let ciphertext = &data[28..];

    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext.as_ref())
        .map_err(|e| Into::<Box<dyn Error>>::into(format!("Decryption error: {:?}", e)))?;

    Ok(plaintext)
}

pub fn save_json_file<T: Serialize>(
    path: &Path,
    password: &[u8],
    data: &T,
) -> Result<(), Box<dyn Error>> {
    let json = serde_json::to_vec(data)?;
    let encrypted = encrypt_data(json, password)?;
    std::fs::write(path, encrypted)?;
    Ok(())
}

pub fn encrypt_data(
    plaintext: Vec<u8>,
    password: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Generate salt + nonce
    let salt: [u8; 16] = random();
    let nonce: [u8; 12] = random();

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|e| -> Box<dyn std::error::Error> { format!("Encryption error: {}", e).into() })?;

    let mut output_data = Vec::new();
    output_data.extend_from_slice(&salt);
    output_data.extend_from_slice(&nonce);
    output_data.extend_from_slice(&ciphertext);

    Ok(output_data)
}

/// Encrypts a file in chunks and writes the encrypted data to the output path.
/// Each chunk is encrypted independently with its own salt and nonce.
/// Returns the SHA-256 hash of the plaintext file.
pub async fn encrypt_file(
    mut input: std::fs::File,
    mut output: std::fs::File,
    password: &[u8],
    hasher: Option<Sha256>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const CHUNK_SIZE: usize = 1024 * 1024; // 1MB per chunk
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut hasher = hasher.unwrap_or_default();
    loop {
        let read_bytes = std::io::Read::read(&mut input, &mut buffer)?;
        if read_bytes == 0 {
            break;
        }
        let chunk = &buffer[..read_bytes];
        hasher.update(chunk);
        let encrypted = encrypt_data(chunk.to_vec(), password)?;
        // Write the length of the encrypted chunk as u32 (big-endian)
        let len_bytes = (encrypted.len() as u32).to_be_bytes();
        output.write_all(&len_bytes)?;
        output.write_all(&encrypted)?;
    }
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}

fn derive_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];

    argon2
        .hash_password_into(password, salt, &mut key)
        .expect("Key derivation failed");

    key
}
