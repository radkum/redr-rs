use std::{os::raw::c_void, ptr::null_mut};

use windows_sys::{
    core::HRESULT,
    Win32::{
        Foundation::{GetLastError, LocalFree},
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

pub fn print_hr_result(msg: &str, error_code: HRESULT) {
    let error_code = hresult_from_win32(error_code);
    print_error(msg, error_code);
}

fn print_error(msg: &str, error_code: u32) {
    let error_msg = get_error_as_string(error_code).unwrap_or("Failed to get msg".to_string());

    let space = if !msg.is_empty() { ", " } else { "" };

    println!("{msg}{space}ErrorCode: 0x{:08x}, ErrorMsg: \"{}\"", error_code, error_msg.trim_end());
}

pub fn print_last_error(msg: &str) {
    let error_code = unsafe { GetLastError() };
    print_error(msg, error_code);
}

pub fn get_error_as_string(error_msg_id: u32) -> Option<String> {
    unsafe {
        let mut message_buffer = null_mut();
        let chars = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            null_mut(),
            error_msg_id,
            0,
            &mut message_buffer as *mut *mut u16 as *mut u16,
            0,
            null_mut(),
        );

        let msg = if chars > 0 {
            let parts = std::slice::from_raw_parts(message_buffer, chars as _);
            String::from_utf16(parts).ok()
        } else {
            None
        };

        LocalFree(message_buffer as *mut c_void);

        msg
    }
}

#[allow(dead_code)]
pub fn get_last_error_as_string() -> Option<String> {
    unsafe {
        //Get the error message, if any.
        let error_msg_id = GetLastError();
        if error_msg_id == 0 {
            return Some(String::from("STATUS_SUCCESS"));
        }
        get_error_as_string(error_msg_id)
    }
}
