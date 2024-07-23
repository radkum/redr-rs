use std::{mem, ptr::null_mut};

use ffi_support::{rust_string_to_c, FfiStr};

use crate::error::SandboxError;

type PFfiStr = *mut FfiStr<'static>;
type PPFfiStr = *mut PFfiStr;

// #[link(name = "..\\Sandbox\\Sandbox")]
// extern "C" {
//     //unfortunately exported function in Sandbox.dll are in C++ mangling. Fortunately we can add link_name attribute
//     #[link_name = "?sandboxFile@@YAHPEADH0H@Z"]
//     pub fn sandboxFile(path: *const u8, path_len: usize, lines: *mut *const FfiStr, lines_number: *mut u32) -> u32;
// }

unsafe fn sandbox_file_mock(
    _path: *const u8,
    _path_len: usize,
    lines: PPFfiStr,
    lines_number: *mut usize,
) -> u32 {
    fn str_to_ffistr(str: &str) -> FfiStr {
        unsafe { FfiStr::from_raw(rust_string_to_c(str)) }
    }

    let mut v = vec![
        str_to_ffistr("BlockInput"),
        str_to_ffistr("Sleep"),
        str_to_ffistr("ShellExecuteW"),
        str_to_ffistr("SetCursorPos"),
    ];

    *lines_number = v.len();
    *lines = v.as_mut_ptr();

    mem::forget(v);
    0
}

pub(crate) fn perform_sandboxing(path: &str) -> Result<Vec<String>, SandboxError> {
    let mut path_plus_null = String::from(path);
    path_plus_null.push('\0');

    let mut lines: PFfiStr = null_mut();
    let mut lines_number: usize = 0;

    //let result = unsafe { sandboxFile(path_plus_null.as_ptr()) };
    let result = unsafe {
        sandbox_file_mock(
            path_plus_null.as_ptr(),
            path_plus_null.len(),
            &mut lines as PPFfiStr,
            &mut lines_number,
        )
    };

    if result != 0 {
        return Err(SandboxError::PerformSandboxError { reason: get_sandbox_result(result) });
    } else {
        let v: Vec<FfiStr> = unsafe { Vec::from_raw_parts(lines, lines_number, lines_number) };
        Ok(v.iter().map(|s| s.as_str().to_string().to_ascii_lowercase()).collect())
    }
}

fn get_sandbox_result(res: u32) -> String {
    let s = match res {
        0 => "Success",
        1 => "InputPathIsNull",
        2 => "GivenFileNotExists",
        3 => "ReportDirAlreadyExists",
        4 => "FailedToPerformApiAnalysis",
        _ => "UNKNOWN",
    };
    String::from(s)
}
