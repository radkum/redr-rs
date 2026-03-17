use thiserror::Error;

#[derive(Error, Debug)]
pub enum DeleteError {
    #[error("Win32 error: {0}")]
    Win32(u32, String),

    #[error("Message: {0}")]
    Msg(&'static str),
}

impl DeleteError {
    fn last_err() -> DeleteError {
        let code = windows::last_error();
        let message = windows::last_error_as_string();
        DeleteError::Win32(code, message)
    }
}