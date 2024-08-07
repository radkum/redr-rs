use signatures::error::SigSetError;
use thiserror::Error;
use tokio::{sync::mpsc::error::SendError, task::JoinError};

use crate::scanner::RamonEvent;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JoinError: {0}")]
    JoinError(#[from] JoinError),
    #[error("SendTransactionError: {0}")]
    SendMsgError(String),
    #[error("SignatureError: {0}")]
    SignatureError(#[from] SigSetError),
    #[error("Unknown Event")]
    UnknownEvent,
}

impl From<SendError<RamonEvent>> for ScanError {
    fn from(_value: SendError<RamonEvent>) -> Self {
        ScanError::SendMsgError(format!("{:?}", "todo"))
    }
}
