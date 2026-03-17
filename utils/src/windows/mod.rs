mod win_error;
mod smart_handle;
mod smart_buffer;
mod output_debug_string;

pub use smart_buffer::SmartBuffer;
pub use smart_handle::SmartHandle;
pub use output_debug_string::output_debug_string;
pub use win_error::*;

use thiserror::Error;
use std::os::windows::ffi::OsStrExt;

pub fn to_wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

#[derive(Error, Debug)]
pub struct Win32Error(u32, String);

impl Win32Error {
    pub fn last() -> Self {
        let code = last_error();
        let message = last_error_as_string();
        Win32Error(code, message)
    }
}

impl std::fmt::Display for Win32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Win32Error {}: {}", self.0, self.1)
    }
}

pub type Win32Result<T> = Result<T, Win32Error>;