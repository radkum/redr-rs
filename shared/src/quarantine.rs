use super::sha_buf::Sha256Buff;
use alloc::string::String;
use chrono::{DateTime, Utc};
pub struct QuarantineInfo {
    pub original_path: String,
    pub quarantine_path: String,
    pub date: DateTime<Utc>,
    pub key: Sha256Buff,
    pub sha: Sha256Buff,
}
