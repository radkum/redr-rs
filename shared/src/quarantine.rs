use alloc::string::String;
use chrono::{DateTime, Utc};
pub struct QuarantineInfo {
    pub original_path: String,
    pub quarantine_path: String,
    pub date: DateTime<Utc>,
    pub id: [u8; 16],
    pub key: [u8; 32],
    pub sha: [u8; 32],
}