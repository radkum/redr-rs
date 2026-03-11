use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use chrono::Utc;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize, rancor::Error};
use sha2::{Digest, Sha256};
use shared::{quarantine::QuarantineInfo, sha_buf::Sha256Buff};
use shared::RedrResult;
use uuid::Uuid;
use rkyv::with::Skip;

pub const QUARANTINE_FILE_VERSION: u32 = 0;
pub const QUARANTINE_FILE_MAGIC: &[u8; 4] = b"QUAR";
pub const QUARANTINE_FILE_MAGIC_U32: u32 = u32::from_ne_bytes(*QUARANTINE_FILE_MAGIC);

#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
pub struct QuarantineHeader {
    magic: u32,
    pub sha: Sha256Buff,
    version: u32,
    #[rkyv(with = Skip)]
    key: Sha256Buff,
}

impl QuarantineHeader {
    pub const fn header_size() -> usize {
        std::mem::size_of::<u32>() + std::mem::size_of::<Sha256Buff>() + std::mem::size_of::<u32>()
    }
    pub fn new() -> Self {
        Self {
            magic: QUARANTINE_FILE_MAGIC_U32,
            sha: Sha256Buff::default(),
            version: QUARANTINE_FILE_VERSION,
            key: Sha256Buff::rand(),
        }
    }

    pub fn quarantine_info(&self, original_path: &Path, quarantine_path: &Path) -> QuarantineInfo {
        QuarantineInfo {
            original_path: original_path.to_string_lossy().into_owned(),
            quarantine_path: quarantine_path.to_string_lossy().into_owned(),
            date: Utc::now(),
            key: self.key.clone(),
            sha: self.sha.clone(),
        }
    }

    pub fn quarantine_path(&self, path: &Path) -> RedrResult<PathBuf> {
        Ok(utils::redr_quarantine_dir().join(self.quarantined_filename(path)?))
    }

    pub fn key(&self) -> &Sha256Buff {
        &self.key
    }

    pub fn quarantined_filename(&self, path: &Path) -> RedrResult<String> {
        let filename = path
            .file_name()
            .and_then(|name| name.to_str().map(String::from))
            .ok_or_else(|| "Could not get file name")?;
        let id = Uuid::new_v4();
        Ok(format!("{}{}", filename, Self::suffix(id.to_string())))
    }

    pub fn suffix<S: AsRef<str>>(id: S) -> String {
        format!("-{}.{}", id.as_ref(), Self::ext())
    }

    pub fn ext() -> &'static str {
        "qrt"
    }

    pub fn hasher(&self) -> Sha256 {
        let mut hasher = Sha256::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.key);
        hasher
    }

    pub fn deserialize_path<P: AsRef<Path>>(file: P) -> RedrResult<Self> {
        let mut file = File::open(file.as_ref())?;
        Self::deserialize_file(&mut file)
    }

    pub fn deserialize_file(file: &mut File) -> RedrResult<Self> {
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let deserialized = rkyv::from_bytes::<Self, Error>(&buf)
            .map_err(|err| format!("Unable to parse quarantine file header: {err}"))?;

        if deserialized.magic != QUARANTINE_FILE_MAGIC_U32 {
            return Err("Invalid file format: magic value does not match".into());
        }
        Ok(deserialized)
    }

    pub fn serialize_to_file(&self, file: &mut File) -> RedrResult<()> {
        let bytes = rkyv::to_bytes::<Error>(self)
            .map_err(|err| format!("Failed to serialize header: {err}"))?;
        file.write_all(&bytes)?;
        Ok(())
    }
}
