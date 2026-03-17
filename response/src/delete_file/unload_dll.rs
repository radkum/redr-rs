use shared::RedrResult;
use utils::windows::SmartHandle;

use std::ptr;

use windows_sys::Win32::{
    Foundation::*,
    System::LibraryLoader::*,
    System::ProcessStatus::*,
    System::Threading::*,
};

use super::unlock_file::find_processes_with_loaded_module;

//
// ================= GET REMOTE MODULE HANDLE =================
//

/// Get the HMODULE of a specific DLL in a remote process
fn get_remote_module_handle(process_handle: HANDLE, target_path: &str) -> Option<HMODULE> {
    let target_lower = target_path.to_lowercase();
    
    let mut modules: [HMODULE; 1024] = [ptr::null_mut(); 1024];
    let mut cb_needed: u32 = 0;
    
    unsafe {
        if K32EnumProcessModules(
            process_handle,
            modules.as_mut_ptr(),
            std::mem::size_of_val(&modules) as u32,
            &mut cb_needed,
        ) == 0 {
            return None;
        }
    }
    
    let num_modules = cb_needed as usize / std::mem::size_of::<HMODULE>();
    
    for i in 0..num_modules {
        let mut module_path = [0u16; MAX_PATH as usize];
        
        let len = unsafe {
            K32GetModuleFileNameExW(
                process_handle,
                modules[i],
                module_path.as_mut_ptr(),
                module_path.len() as u32,
            )
        };
        
        if len > 0 {
            let path = String::from_utf16_lossy(&module_path[..len as usize]);
            if path.to_lowercase().contains(&target_lower) {
                return Some(modules[i]);
            }
        }
    }
    
    None
}

//
// ================= UNLOAD DLL FROM PROCESS =================
//

/// Unload a DLL from a remote process by creating a remote thread that calls FreeLibrary.
/// This is a forceful operation and may cause the target process to crash if the DLL
/// is actively being used.
/// 
/// Returns Ok(true) if successfully unloaded, Ok(false) if module not found, Err on failure.
pub fn unload_dll_from_process(pid: u32, dll_path: &str) -> RedrResult<bool> {
    // Open process with necessary permissions
    let process_handle = SmartHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | 
            PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
            0,
            pid,
        )
    })?;
    
    // Find the module handle in the remote process
    let Some(module_handle) = get_remote_module_handle(process_handle.get(), dll_path) else {
        log::debug!("Module '{}' not found in PID {}", dll_path, pid);
        return Ok(false);
    };
    
    log::info!("Found module handle {:?} for '{}' in PID {}", module_handle, dll_path, pid);
    
    // Get FreeLibrary address - it's the same in all processes due to ASLR being per-boot
    let kernel32 = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    if kernel32.is_null() {
        return Err("Failed to get kernel32.dll handle".into());
    }
    
    let free_library_addr = unsafe { GetProcAddress(kernel32, b"FreeLibrary\0".as_ptr()) };
    if free_library_addr.is_none() {
        return Err("Failed to get FreeLibrary address".into());
    }
    
    // Create remote thread to call FreeLibrary(module_handle)
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle.get(),
            ptr::null(),
            0,
            Some(std::mem::transmute(free_library_addr.unwrap())),
            module_handle as *const _,
            0,
            ptr::null_mut(),
        )
    };
    
    if thread_handle.is_null() {
        return Err(format!(
            "Failed to create remote thread: {}",
            utils::windows::Win32Error::last()
        ).into());
    }
    
    // Wait for the thread to complete
    let thread_handle = SmartHandle::new(thread_handle)?;
    let wait_result = unsafe { WaitForSingleObject(thread_handle.get(), 5000) };
    
    if wait_result != WAIT_OBJECT_0 {
        return Err(format!("Remote thread wait failed: {}", wait_result).into());
    }
    
    log::info!("Successfully unloaded DLL '{}' from PID {}", dll_path, pid);
    Ok(true)
}

//
// ================= UNLOAD DLL FROM ALL PROCESSES =================
//

/// Find all processes with the specified DLL loaded and attempt to unload it from each.
/// Returns the number of processes from which the DLL was successfully unloaded.
pub fn unload_dll_from_all_processes(dll_path: &str) -> usize {
    let pids = find_processes_with_loaded_module(dll_path);
    
    if pids.is_empty() {
        log::info!("No processes found with '{}' loaded", dll_path);
        return 0;
    }
    
    log::info!("Found {} processes with '{}' loaded", pids.len(), dll_path);
    
    let mut success_count = 0;
    for pid in pids {
        match unload_dll_from_process(pid, dll_path) {
            Ok(true) => {
                success_count += 1;
                println!("Unloaded DLL from PID {}", pid);
            }
            Ok(false) => {
                log::warn!("Module disappeared from PID {} before unload", pid);
            }
            Err(e) => {
                log::error!("Failed to unload from PID {}: {}", pid, e);
                println!("Failed to unload from PID {}: {}", pid, e);
            }
        }
    }
    
    success_count
}