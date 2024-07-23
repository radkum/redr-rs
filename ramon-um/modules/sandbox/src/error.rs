use std::ffi::OsString;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Can't convert OsString to String. After to_string_lossy(): {0}")]
    OsStringError(String),
    #[error("Failed to perform sandbox. Reason '{reason}'")]
    PerformSandboxError { reason: String },
    #[error("SigSetError: {0}")]
    SigSetError(#[from] signatures::error::SigSetError),
}

impl From<OsString> for SandboxError {
    fn from(arg: OsString) -> Self {
        Self::OsStringError(arg.to_string_lossy().into())
    }
}
