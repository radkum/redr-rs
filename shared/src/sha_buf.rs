use alloc::{string::String, vec::Vec};
use core::{cmp::Ordering, mem};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use sha2::{
    Digest,
    digest::{generic_array::GenericArray, typenum::U32},
};

pub const SHA256_LEN: usize = 32;

#[derive(
    Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Archive, RkyvSerialize,
    RkyvDeserialize,
)]
pub struct Sha256Buff(pub [u8; SHA256_LEN]);

impl PartialOrd for Sha256Buff {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Sha256Buff {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl AsRef<[u8]> for Sha256Buff {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; SHA256_LEN]> for Sha256Buff {
    fn from(arr: [u8; SHA256_LEN]) -> Self {
        Sha256Buff(arr)
    }
}

impl From<GenericArray<u8, U32>> for Sha256Buff {
    fn from(arr: GenericArray<u8, U32>) -> Self {
        let mut buf = [0u8; SHA256_LEN];
        buf.copy_from_slice(&arr);
        Sha256Buff(buf)
    }
}

impl Sha256Buff {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn rand() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; SHA256_LEN];
        rng.fill(&mut buf);
        Self(buf)
    }

    pub fn from_vec(v: Vec<u8>) -> Result<Self, ShaError> {
        let mut sha = Sha256Buff::default();
        if v.len() != SHA256_LEN {
            return Err(ShaError::IncorrectLen {
                string_len: v.len(),
            });
        }
        sha.0.copy_from_slice(&v);
        Ok(sha)
    }
}

use thiserror_no_std::Error;

#[derive(Error, Debug)]
pub enum ShaError {
    #[error("Sha string must have 32 chars not {string_len}")]
    IncorrectLen { string_len: usize },
    #[error("ToHex error: {0}")]
    ToHexError(#[from] hex::FromHexError),
}

pub fn sha256_from_vec(v: Vec<u8>) -> Sha256Buff {
    let mut hasher = sha2::Sha256::new();
    hasher.update(v);

    let mut checksum_buf = Sha256Buff::default();
    checksum_buf.0.copy_from_slice(&hasher.finalize()[..]);
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
    checksum_buf.0.copy_from_slice(&hasher.finalize()[..]);
    checksum_buf
}

pub fn sha256_from_string(s: String) -> Sha256Buff {
    let mut hasher = sha2::Sha256::new();
    hasher.update(s.as_bytes());

    let mut checksum_buf = Sha256Buff::default();
    checksum_buf.0.copy_from_slice(&hasher.finalize()[..]);
    checksum_buf
}

pub fn sha256_from_sha_string(s: &str) -> Result<Sha256Buff, ShaError> {
    let mut sha = Sha256Buff::default();
    let v = hex::decode(s)?;

    if v.len() != SHA256_LEN {
        return Err(ShaError::IncorrectLen {
            string_len: v.len(),
        });
    }
    sha.0.copy_from_slice(&v);
    Ok(sha)
}

pub fn convert_sha256_to_string(sha: &Sha256Buff) -> String {
    hex::encode_upper(sha.0)
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
