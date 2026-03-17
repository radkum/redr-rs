use thiserror::Error;
use utils::windows::Win32Error;

#[derive(Error, Debug)]
pub enum DeleteError {
    #[error("Win32 error: {0}")]
    Win32(Win32Error),

    #[error("Message: {0}")]
    Msg(String),
}

impl From<Win32Error> for DeleteError {
    fn from(err: Win32Error) -> DeleteError {
        DeleteError::Win32(err)
    }
}

impl From<&str> for DeleteError {
    fn from(err: &str) -> DeleteError {
        DeleteError::Msg(err.into())
    }
}

impl DeleteError {
    pub fn last_err() -> DeleteError {
        Win32Error::last().into()
    }
}