mod error;
mod acl;
mod restart_manager;

use error::DeleteError;
use utils::windows;

use std::{ffi::OsStr, ptr};
use std::os::windows::prelude::*;

use windows_sys::{
    core::*,
    Win32::{
        Foundation::*,
        Security::*,
        Security::Authorization::*,
        Storage::FileSystem::*,
        System::{
            RestartManager::*,
            Threading::*,
        },
    },
};


fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

//
// ================= PUBLIC API =================
//

pub fn delete_file_force(path: &str) -> Result<(), DeleteError> {
    if try_delete(path).is_ok() {
        return Ok(());
    }

    acl::fix_permissions(path)?;

    if try_delete(path).is_ok() {
        return Ok(());
    }

    let lockers = get_locking_processes(path)?;
    if !lockers.is_empty() {
        println!("Locking processes:");
        for p in &lockers {
            println!("PID: {}", p.Process.dwProcessId);
        }
    }

    close_locking_processes(path)?;

    if try_delete(path).is_ok() {
        return Ok(());
    }

    schedule_delete_on_reboot(path)?;

    Ok(())
}

//
// ================= DELETE =================
//

fn try_delete(path: &str) -> Result<(), DeleteError> {
    let w = to_wide(path);

    unsafe {
        if DeleteFileW(PCWSTR(w.as_ptr())).as_bool() {
            Ok(())
        } else {
            Err(last_err())
        }
    }
}


//
// ================= FALLBACK =================
//

fn schedule_delete_on_reboot(path: &str) -> Result<(), DeleteError> {
    let w = to_wide(path);

    unsafe {
        MoveFileExW(
            PCWSTR(w.as_ptr()),
            PCWSTR(ptr::null()),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
        .ok()
        .map_err(|_| last_err())?;
    }

    Ok(())
}