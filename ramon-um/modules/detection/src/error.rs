use signatures::error::SigSetError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),
    #[error("SignatureError: {0}")]
    SignatureError(#[from] SigSetError),
}
