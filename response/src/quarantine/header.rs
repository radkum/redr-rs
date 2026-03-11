use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::sha_buf::Sha256Buff;
use shared::RedrResult;
use uuid::Uuid;

pub const QUARANTINE_FILE_VERSION: u32 = 0;
pub const QUARANTINE_FILE_MAGIC: &[u8; 4] = b"QUAR";
pub const QUARANTINE_FILE_MAGIC_U32: u32 = u32::from_ne_bytes(*QUARANTINE_FILE_MAGIC);

#[derive(Deserialize, Serialize)]
pub struct QuarantineHeader {
    magic: u32,
    pub sha: Sha256Buff,
    version: u32,
    id: Uuid,
    key: Sha256Buff,
}

impl QuarantineHeader {
    pub fn new() -> Self {
        Self {
            magic: QUARANTINE_FILE_MAGIC_U32,
            sha: Sha256Buff::default(),
            version: QUARANTINE_FILE_VERSION,
            id: Uuid::new_v4(),
            key: Sha256Buff::rand(),
        }
    }

    pub fn quarantine_path(&self, path: &Path) -> RedrResult<PathBuf> {
        Ok(super::quarantine_dir()?.join(self.quarantined_filename(path)?))
    }

    pub fn key(&self) -> &Sha256Buff {
        &self.key
    }

    fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn quarantined_filename(&self, path: &Path) -> RedrResult<String> {
        let filename = path
            .file_name()
            .and_then(|name| name.to_str().map(String::from))
            .ok_or_else(|| "Could not get file name")?;
        Ok(format!("{}{}", filename, Self::suffix(self.id.to_string())))
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
        hasher.update(&self.id);
        hasher.update(&self.key);
        hasher
    }

    pub fn deserialize_path<P: AsRef<Path>>(file: P) -> RedrResult<Self> {
        let mut file = File::open(file.as_ref())?;

        // read in header size
        Self::deserialize_file(&mut file)
    }

    pub fn deserialize_file(file: &mut File) -> RedrResult<Self> {
        let deserialized: Self = bincode::deserialize_from(file)
            .map_err(|err| format!("Unable to parse quarantine file header: {err}"))?;

        if deserialized.magic != QUARANTINE_FILE_MAGIC_U32 {
            return Err("Invalid file format: magic value does not match".into());
        }
        Ok(deserialized)
    }

    pub fn serialize_to_file(&self, file: &mut File) -> RedrResult<()> {
        bincode::serialize_into(file, self)
            .map_err(|err| format!("Failed to serialize header: {err}"))?;
        Ok(())
    }
}
