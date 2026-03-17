#![allow(non_snake_case)]

use shared::RedrResult;
use utils::windows::{SmartHandle, Win32Error};

use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicU8, Ordering};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::LibraryLoader::*,
    System::Memory::*,
    System::Threading::*,
    System::ProcessStatus::*,
};

type NTSTATUS = i32;

const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004u32 as i32;
const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;

// ⚠ This value can vary between Windows versions.
// In practice, FILE object type is usually ~0x25–0x28 range.
// We detect dynamically below.
static FILE_TYPE_INDEX: AtomicU8 = AtomicU8::new(0);

const DUPLICATE_CLOSE_SOURCE: u32 = 0x1;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *mut u8,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;

    unsafe fn NtDuplicateObject(
        SourceProcessHandle: HANDLE,
        SourceHandle: HANDLE,
        TargetProcessHandle: HANDLE,
        TargetHandle: *mut HANDLE,
        DesiredAccess: u32,
        Attributes: u32,
        Options: u32,
    ) -> NTSTATUS;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SYSTEM_HANDLE {
    process_id: u32,
    object_type_number: u8,
    flags: u8,
    handle: u16,
    object: usize,
    granted_access: u32,
}

#[repr(C)]
struct SYSTEM_HANDLE_INFORMATION {
    count: u32,
    handles: [SYSTEM_HANDLE; 1],
}


//
// ================= HANDLE ENUM =================
//

fn query_system_handles() -> Vec<SYSTEM_HANDLE> {
    let mut size = 0x10000;

    loop {
        let mut buffer = vec![0u8; size];
        let mut return_len = 0;

        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION_CLASS,
                buffer.as_mut_ptr(),
                size as u32,
                &mut return_len,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            size *= 2;
            continue;
        }

        if status < 0 {
            return vec![];
        }

        let info = buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION;

        let count = unsafe { (*info).count as usize };
        let handles_ptr = unsafe { &(*info).handles as *const SYSTEM_HANDLE };

        return unsafe { std::slice::from_raw_parts(handles_ptr, count) }.to_vec();
    }
}

//
// ================= DUPLICATE HANDLE =================
//

fn duplicate_handle(process_handle: HANDLE, handle: u16) -> Option<HANDLE> {
    unsafe {
        let mut target: HANDLE = ptr::null_mut();

        // Try to duplicate with same access first
        if NtDuplicateObject(
            process_handle,
            handle as _,
            GetCurrentProcess(),
            &mut target,
            0, // Same access as source
            0,
            0,
        ) >= 0 {
            return Some(target);
        }
        
        None
    }
}

//
// ================= GET HANDLE PATH =================
//

fn get_handle_path(handle: HANDLE) -> Option<String> {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    // First, quick check if this is a valid file handle using GetFileType
    let file_type = unsafe { GetFileType(handle) };
    if file_type != FILE_TYPE_DISK {
        // Not a disk file - skip it (could be pipe, char device, etc.)
        log::trace!("Skipping non-disk file handle {:?}: {}", handle, file_type);
        return None;
    }

    let (tx, rx) = mpsc::channel();
    
    // Cast HANDLE to usize so it can be sent across threads
    let handle_val = handle as usize;
    
    // GetFinalPathNameByHandleW can hang on certain handle types
    thread::spawn(move || {
        let handle = handle_val as HANDLE;
        let result = unsafe {
            let mut buf = vec![0u16; 1024];

            let len = GetFinalPathNameByHandleW(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                0,
            );
            if len == 0 || len as usize > buf.len() {
                Err(Win32Error::last())
            } else {
                Ok(String::from_utf16_lossy(&buf[..len as usize]))
            }
        };
        let _ = tx.send(result);
    });

    // Wait up to 100ms - if it takes longer, it's probably a problematic handle
    match rx.recv_timeout(Duration::from_millis(100)) {
        Ok(Ok(result)) => Some(result),
        Ok(Err(e)) => {
            log::error!("Failed to get handle path for {:?}: {}", handle, e);
            None
        }
        Err(_) => {
            log::warn!("Timeout getting handle path for {:?}", handle);
            None
        }
    }
}


//
// ================= FIND LOCKS =================
//

pub fn find_file_locks(target: &str) -> HashMap<u32, Vec<u16>> {
    let handles = query_system_handles();
    log::debug!("Found {} handles", handles.len());

    let mut map: HashMap<u32, Vec<(u16, u8)>> = HashMap::new();
    let mut return_map: HashMap<u32, Vec<u16>> = HashMap::new();

    for h in handles {
        if map.contains_key(&h.process_id) {
            map.get_mut(&h.process_id).unwrap().push((h.handle, h.object_type_number));
        } else {
            map.insert(h.process_id, vec![(h.handle, h.object_type_number)]);
        }
    }

    let mut file_type_idx = None;
    for (pid, handles) in map {
        let Ok(process_handle) = SmartHandle::new(unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) }) else {
            continue;
        };
        for (h, object_type) in handles {
            if let Some(file_type_idx) = file_type_idx {
                if file_type_idx != 0 && object_type != file_type_idx {
                    continue; // 🔥 filter only FILE objects
                }
            }
            if let Some(dup) = duplicate_handle(process_handle.get(), h) {
                if let Some(path) = get_handle_path(dup) {
                    if file_type_idx.is_none() {
                        if path.contains(":\\") {
                            log::info!("Detected FILE type index: {}", object_type);
                            file_type_idx = Some(object_type);
                        }
                    }
                    if path.contains("infocyte") {
                        log::debug!("Infocyte is loaded in PID {}", pid);
                    }
                    if path.contains(target) {
                        if return_map.contains_key(&pid) {
                            return_map.get_mut(&pid).unwrap().push(h);
                        } else {
                            return_map.insert(pid, vec![h]);
                        }
                    }
                }
            }
        }
    }

    log::debug!("return map: {:?}", return_map);
    return_map
}

//
// ================= FORCE CLOSE HANDLE =================
//

pub fn close_remote_handle(process_handle: HANDLE, handle: u16) -> RedrResult<()> {
    unsafe {
        let status = NtDuplicateObject(
            process_handle,
            handle as _,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            DUPLICATE_CLOSE_SOURCE,
        );

        if status < 0 {
            Err(format!("Failed to close handle: NTSTATUS {:#X}", status).into())
        } else {
            Ok(())
        }
    }
}

//
// ================= MAIN HELPER =================
//

pub fn unlock_file_force(path: &str) {
    let locks = find_file_locks(path);

    println!("Found {} locking handles", locks.len());

    let mut closed_handles_len = 0;
    for (pid, handles) in &locks {
        let Ok(process_handle) = SmartHandle::new(unsafe {OpenProcess(PROCESS_DUP_HANDLE, 0, *pid)}) else {
            continue;
        };
        for handle in handles {
            if let Err(err) = close_remote_handle(process_handle.get(), *handle) {
                println!("Failed to close handle: {}", err);
            } else {
                closed_handles_len += 1;
            }
        }
    }

    log::info!("Closed {} handles", closed_handles_len);
}

//
// ================= FIND PROCESSES WITH LOADED DLL =================
//

/// Find all processes that have the specified DLL/file loaded as a module.
/// This is different from file handles - DLLs are memory-mapped sections.
/// Returns a list of PIDs that have the module loaded.
pub fn find_processes_with_loaded_module(target_path: &str) -> Vec<u32> {
    // Enable SeDebugPrivilege to access more processes
    if let Err(e) = crate::enable_privilege(crate::Priviledge::Debug) {
        log::warn!("Failed to enable SeDebugPrivilege: {} - some processes may be inaccessible", e);
    } else {
        log::debug!("SeDebugPrivilege enabled");
    }
    
    // Normalize path: remove \\?\ prefix if present, lowercase for comparison
    let target_normalized = target_path
        .trim_start_matches("\\\\?\\")
        .to_lowercase();
    
    // Also try matching just the filename for flexibility
    let target_filename = std::path::Path::new(&target_normalized)
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    
    log::info!("Searching for module: '{}' (filename: '{}')", target_normalized, target_filename);
    
    let mut result = Vec::new();
    
    // Get list of all process IDs
    let mut pids = vec![0u32; 4096];
    let mut bytes_returned: u32 = 0;
    
    unsafe {
        if K32EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * std::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        ) == 0 {
            log::error!("K32EnumProcesses failed");
            return result;
        }
    }
    
    let num_pids = bytes_returned as usize / std::mem::size_of::<u32>();
    pids.truncate(num_pids);
    
    log::debug!("Scanning {} processes for loaded module", num_pids);
    
    let mut skipped_access_denied = 0;
    let mut skipped_enum_failed = 0;
    
    for pid in pids {
        if pid == 0 {
            continue;
        }
        
        // Open process with query and VM read access
        let process_handle = unsafe { 
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) 
        };
        
        let process_handle = if process_handle.is_null() {
            // Try with limited access for protected/WOW64 processes
            let limited_handle = unsafe { 
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) 
            };
            
            if limited_handle.is_null() {
                skipped_access_denied += 1;
                log::trace!("Cannot open PID {} - access denied", pid);
                continue;
            }
            limited_handle
        } else {
            process_handle
        };
        
        let Ok(process_handle) = SmartHandle::new(process_handle) else {
            skipped_access_denied += 1;
            continue;
        };
        
        match check_process_modules_verbose(&process_handle, pid, &target_normalized, &target_filename) {
            Ok(true) => result.push(pid),
            Ok(false) => {},
            Err(e) => {
                skipped_enum_failed += 1;
                log::trace!("Failed to enumerate modules for PID {}: {}", pid, e);
            }
        }
    }
    
    log::info!("Found {} processes with module loaded (skipped: {} access denied, {} enum failed)", 
               result.len(), skipped_access_denied, skipped_enum_failed);
    result
}

fn check_process_modules_verbose(process_handle: &SmartHandle, pid: u32, target_normalized: &str, target_filename: &str) -> Result<bool, &'static str> {
    // Enumerate modules
    let mut modules: [HMODULE; 1024] = [ptr::null_mut(); 1024];
    let mut cb_needed: u32 = 0;
    
    unsafe {
        // Try LIST_MODULES_ALL to get both 32-bit and 64-bit modules
        if K32EnumProcessModulesEx(
            process_handle.get(),
            modules.as_mut_ptr(),
            std::mem::size_of_val(&modules) as u32,
            &mut cb_needed,
            LIST_MODULES_ALL,
        ) == 0 {
            // Fall back to regular enumeration
            if K32EnumProcessModules(
                process_handle.get(),
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut cb_needed,
            ) == 0 {
                return Err("K32EnumProcessModules failed");
            }
        }
    }
    
    let num_modules = cb_needed as usize / std::mem::size_of::<HMODULE>();
    
    for i in 0..num_modules {
        let mut module_path = [0u16; MAX_PATH as usize];
        
        let len = unsafe {
            K32GetModuleFileNameExW(
                process_handle.get(),
                modules[i],
                module_path.as_mut_ptr(),
                module_path.len() as u32,
            )
        };
        
        if len > 0 {
            let path = String::from_utf16_lossy(&module_path[..len as usize]);
            let path_lower = path.to_lowercase();
            let path_normalized = path_lower.trim_start_matches("\\\\?\\");
            
            // Match by full path or just filename
            let module_filename = std::path::Path::new(&path_lower)
                .file_name()
                .map(|f| f.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            
            if path_normalized.contains(target_normalized) || 
               target_normalized.contains(path_normalized) ||
               (!target_filename.is_empty() && module_filename == target_filename) {
                log::info!("Found module '{}' loaded in PID {}", path, pid);
                return Ok(true);
            }
        }
    }
    
    Ok(false)
}