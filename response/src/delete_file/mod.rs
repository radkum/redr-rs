mod error;
mod acl;
mod restart_manager;
mod unlock_file;
mod unload_dll;

use error::DeleteError;

use std::ptr;

use windows_sys::Win32::{
    Storage::FileSystem::*,
};

use utils::windows;

pub(self) use restart_manager::{get_locking_processes};

// Re-export DLL unloading functions
pub use unlock_file::find_processes_with_loaded_module;
pub use unload_dll::{
    unload_dll_from_process,
    unload_dll_from_all_processes,
};

//
// ================= PUBLIC API =================
//

pub fn delete_file_force(path: &str) -> Result<(), DeleteError> {
    log::info!("Try delete file 1 time");
    if try_delete(path) {
        return Ok(());
    }

    acl::fix_permissions(path)?;

    log::info!("Try delete file 2 time");
    if try_delete(path) {
        return Ok(());
    }

    // If the file is a DLL loaded by processes, try to unload it
    let unloaded = unload_dll::unload_dll_from_all_processes(path);
    if unloaded > 0 {
        log::info!("Unloaded DLL from {} processes", unloaded);
    }

    log::info!("Try delete file 3 time");
    if try_delete(path) {
        return Ok(());
    }

    let lockers = get_locking_processes(path)?;
    if !lockers.is_empty() {
        log::debug!("Locking processes:");
        for p in &lockers {
            log::debug!("PID: {}", p.Process.dwProcessId);
        }
    }

    restart_manager::close_locking_processes(path)?;

    log::info!("Try delete file 4 time");
    if try_delete(path) {
        return Ok(());
    }

    unlock_file::unlock_file_force(path);

    log::info!("Try delete file 5 time");
    if try_delete(path) {
        return Ok(());
    }

    
    schedule_delete_on_reboot(path)?;

    Err("Failed to delete file. File is scheduled to remove after reboot".into())
}

//
// ================= DELETE =================
//

fn try_delete(path: &str) -> bool {
    let w = windows::to_wide(path);

    unsafe {
        if DeleteFileW(w.as_ptr()) != 0 {
            true
        } else {
            log::debug!("Failed to delete file: {}", DeleteError::last_err());
            false
        }
    }
}


//
// ================= FALLBACK =================
//

fn schedule_delete_on_reboot(path: &str) -> Result<(), DeleteError> {
    let w = windows::to_wide(path);

    unsafe {
        if MoveFileExW(
            w.as_ptr(),
            ptr::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        ) != 0 {
            Ok(())
        } else {
            Err(DeleteError::last_err())
        }
    }
}