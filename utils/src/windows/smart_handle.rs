use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use super::Win32Error;
use super::Win32Result;
pub struct SmartHandle(HANDLE);

impl SmartHandle {
    pub fn new(handle: HANDLE) -> Win32Result<SmartHandle> {
        if handle.is_null() {
            Err(Win32Error::last())
        } else {
            Ok(Self(handle))
        }
    }

    pub fn as_mut_ref(&mut self) -> &mut HANDLE {
        &mut self.0
    }

    pub fn get(&self) -> HANDLE {
        self.0
    }
}

impl Default for SmartHandle {
    fn default() -> Self {
        Self(std::ptr::null_mut())
    }
}

impl Drop for SmartHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

impl Into<HANDLE> for SmartHandle {
    fn into(self) -> HANDLE {
        self.0
    }
}
