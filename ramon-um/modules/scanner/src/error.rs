use signatures::error::SigSetError;
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JoinError: {0}")]
    JoinError(#[from] JoinError),
    #[error("SignatureError: {0}")]
    SignatureError(#[from] SigSetError),
}
