extern "C" {
    pub fn OutputDebugStringA(lpOutputString: *const u8);
}

pub fn output_debug_string(str: String) {
    let mut str2 = str.clone();
    str2.push('\0');
    unsafe {
        OutputDebugStringA(str2.as_ptr());
    }
}
