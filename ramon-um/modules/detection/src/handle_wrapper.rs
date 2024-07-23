use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
pub struct SmartHandle(HANDLE);

impl SmartHandle {
    pub fn new() -> SmartHandle {
        Self(0)
    }

    pub fn as_mut_ref(&mut self) -> &mut HANDLE {
        &mut self.0
    }

    pub fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for SmartHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { CloseHandle(self.0) };
        }
    }
}

impl Into<HANDLE> for SmartHandle {
    fn into(self) -> HANDLE {
        self.0
    }
}
