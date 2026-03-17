use windows_sys::Win32::Foundation::LocalFree;

pub struct SmartBuffer<T>(*mut T);

impl<T> SmartBuffer<T> {
    pub fn new() -> SmartBuffer<T> {
        Self(std::ptr::null_mut())
    }

    pub fn as_mut_ref(&mut self) -> &mut *mut T {
        &mut self.0
    }

    pub fn get(&self) -> *mut T {
        self.0
    }

    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl<T> Drop for SmartBuffer<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0 as _) };
        }
    }
}
