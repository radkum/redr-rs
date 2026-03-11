use alloc::string::String;
use chrono::{DateTime, Utc};
pub struct QuarantineInfo {
    pub original_path: String,
    pub quarantine_path: String,
    pub date: DateTime<Utc>,
}