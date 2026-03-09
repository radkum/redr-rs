use std::ffi::OsString;

use common::utils::ShaError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigSetError {
    #[error("Bincode deserialize error: {0}")]
    BincodeDeserializeError(#[from] bincode::error::DecodeError),
    #[error("Bincode serialize error: {0}")]
    BincodeSerializeError(#[from] bincode::error::EncodeError),
    #[error("FileObjectError: {0}")]
    FileObjectError(#[from] object::Error),
    #[error("Incorrect magic. Found '{current}'")]
    IncorrectMagicError { current: String },
    #[error("Incorrect checksum. Expected '{expected}' but found '{current}'")]
    IncorrectChecksumError { current: String, expected: String },
    #[error("Incorrect file size. Size: '{size}'")]
    IncorrectFileSizeError { size: u64 },
    #[error("Incorrect signature size. Size: '{size}'")]
    IncorrectSignatureSizeError { size: u32 },
    #[error("Incorrect signature. Info: '{info}'")]
    IncorrectSignatureError { info: String },
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Given property doesn't exist in map: {0}")]
    NoSuchPropertyError(String),
    #[error("Can't convert OsString to String. After to_string_lossy(): {0}")]
    OsStringError(String),
    #[error("Serde yaml error: {0}")]
    SerdeYamlError(#[from] serde_yaml::Error),
    #[error("Sha Error: {0}")]
    ShaError(common::utils::ShaError),
}

impl From<common::utils::ShaError> for SigSetError {
    fn from(value: ShaError) -> Self {
        Self::ShaError(value)
    }
}

impl From<OsString> for SigSetError {
    fn from(arg: OsString) -> Self {
        Self::OsStringError(arg.to_string_lossy().into())
    }
}
