use alloc::{string::String, vec::Vec};
use core::mem;
use sha2::Digest;

pub const SHA256_LEN: usize = 32;
pub type Sha256Buff = [u8; SHA256_LEN];

use thiserror_no_std::Error;

#[derive(Error, Debug)]
pub enum ShaError {
    #[error("Sha string must have 32 chars not {string_len}")]
    IncorrectStringLen { string_len: usize },
    #[error("ToHex error: {0}")]
    ToHexError(#[from] hex::FromHexError),
}

pub fn sha256_from_vec(v: Vec<u8>) -> Sha256Buff {
    let mut hasher = sha2::Sha256::new();
    hasher.update(v);

    let mut checksum_buf = Sha256Buff::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    checksum_buf
}

pub fn sha256_from_bytes(v: &[u8]) -> Sha256Buff {
    sha256_from_vec(v.to_vec())
}

#[allow(dead_code)]
pub fn sha256_from_vec_of_vec(vec: Vec<Vec<u8>>) -> Sha256Buff {
    let mut hasher = sha2::Sha256::new();

    for v in vec {
        hasher.update(v);
    }

    let mut checksum_buf = Sha256Buff::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    checksum_buf
}

pub fn sha256_from_string(s: String) -> Sha256Buff {
    let mut hasher = sha2::Sha256::new();
    hasher.update(s.as_bytes());

    let mut checksum_buf = Sha256Buff::default();
    checksum_buf.copy_from_slice(&hasher.finalize()[..]);
    checksum_buf
}

pub fn sha256_from_sha_string(s: &str) -> Result<Sha256Buff, ShaError> {
    let mut sha = Sha256Buff::default();
    let v = hex::decode(s)?;

    if v.len() != SHA256_LEN {
        return Err(ShaError::IncorrectStringLen {
            string_len: v.len(),
        });
    }
    sha.copy_from_slice(&v);
    Ok(sha)
}

pub fn convert_sha256_to_string(sha: &Sha256Buff) -> String {
    hex::encode_upper(sha)
}

pub fn align(size: usize) -> u32 {
    //const ALIGNMENT: usize = mem::size_of::<usize>();
    const ALIGNMENT: usize = mem::size_of::<u32>();
    if size % ALIGNMENT == 0 {
        size as u32
    } else {
        (size + (ALIGNMENT - size % ALIGNMENT)) as u32
    }
}
