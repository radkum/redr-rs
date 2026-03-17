use super::SmartBuffer;

use std::ptr::null_mut;

use windows_sys::{
    Win32::{
        Foundation::GetLastError,
        System::Diagnostics::Debug::*,
    },
};

const FACILITY_WIN32: u32 = 0x0007;

pub fn hresult_from_win32(x: i32) -> u32 {
    let x = x as u32;
    if x <= 0 {
        x
    } else {
        (x & 0x0000FFFF) | (FACILITY_WIN32 << 16) | 0x80000000
    }
}

pub fn win32_error_to_string(code: u32) -> String {
    unsafe {
        let mut buffer = SmartBuffer::<u16>::new();

        let len = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            null_mut(),
            code,
            0,
            buffer.as_mut_ref() as *mut _ as _,
            0,
            null_mut(),
        );

        if len == 0 || buffer.is_null() {
            return format!("Unknown error ({})", code);
        }

        let slice = std::slice::from_raw_parts(buffer.get(), len as usize);
        let message = String::from_utf16_lossy(slice);

        message.trim().to_string()
    }
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

pub fn last_error_as_string() -> String {
    let error_code = last_error();
    if error_code == 0 {
        return String::from("STATUS_SUCCESS");
    }
    win32_error_to_string(error_code)
}