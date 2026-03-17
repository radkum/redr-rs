use std::{os::raw::c_void, ptr::null_mut};

use windows_sys::{
    Win32::{
        Foundation::{GetLastError, LocalFree},
        System::Diagnostics::Debug::*,
    },
    core::HRESULT,
};

use utils::windows;

pub fn print_hr_result(msg: &str, error_code: HRESULT) {
    let error_code = windows::hresult_from_win32(error_code);
    print_error(msg, error_code);
}

fn print_error(msg: &str, error_code: u32) {
    let error_msg = windows::win32_error_to_string(error_code).unwrap_or("Failed to get msg".to_string());

    let space = if !msg.is_empty() { ", " } else { "" };

    println!(
        "{msg}{space}ErrorCode: 0x{:08x}, ErrorMsg: \"{}\"",
        error_code,
        error_msg.trim_end()
    );
}

pub fn print_last_error(msg: &str) {
    let error_code = windows::last_error();
    print_error(msg, error_code);
}