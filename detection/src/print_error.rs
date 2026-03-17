
use windows_sys::{
    core::HRESULT,
};

use utils::windows;

pub fn print_hr_result(msg: &str, error_code: HRESULT) {
    let error_code = windows::hresult_from_win32(error_code);
    print_error(msg, error_code);
}

fn print_error(msg: &str, error_code: u32) {
    let space = if !msg.is_empty() { ", " } else { "" };

    println!(
        "{msg}{space}ErrorCode: 0x{:08x}, ErrorMsg: \"{}\"",
        error_code,
        windows::win32_error_to_string(error_code).trim_end()
    );
}

pub fn print_last_error(msg: &str) {
    let error_code = windows::last_error();
    print_error(msg, error_code);
}