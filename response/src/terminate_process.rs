use shared::RedrResult;
use utils::windows::SmartHandle;
use utils::windows::Win32Result;

use utils::windows::Win32Error;
use std::ptr;
use windows_sys::Win32::{
    Foundation::*,
    System::{
        ProcessStatus::K32GetModuleBaseNameW,
        Services::*,
        Threading::*,
    },
    UI::WindowsAndMessaging::*,
};

// BOOL type alias for clarity
type BOOL = i32;

//
// ================= PROCESS NAME =================
//

pub fn get_process_name(handle: HANDLE) -> RedrResult<Option<String>> {
    unsafe {

        let mut buf = [0u16; 260];

        let len = K32GetModuleBaseNameW(
            handle,
            ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        );

        if len == 0 {
            Ok(None)
        } else {
            Ok(Some(String::from_utf16_lossy(&buf[..len as usize])))
        }
    }
}

//
// ================= CRITICAL PROCESS FILTER =================
//

pub fn is_critical_process(pid: u32, name: Option<&str>) -> bool {
    if pid == 0 || pid == 4 {
        return true;
    }

    if let Some(name) = name {
        let n = name.to_ascii_lowercase();

        return matches!(
            n.as_str(),
            "system"
                | "idle"
                | "wininit.exe"
                | "winlogon.exe"
                | "csrss.exe"
                | "lsass.exe"
                | "services.exe"
                | "smss.exe"
        );
    }

    false
}

//
// ================= WM_CLOSE =================
//

fn send_wm_close(pid: u32) {
    extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let target = lparam as u32;

        let mut win_pid = 0;
        unsafe { GetWindowThreadProcessId(hwnd, &mut win_pid) };

        if win_pid == target {
            unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
        }

        TRUE
    }

    unsafe {
        EnumWindows(Some(enum_proc), pid as isize);
    }
}

//
// ================= SERVICE STOP =================
//

struct ScManager(HANDLE);
impl ScManager {
    fn new(permission: u32) -> Win32Result<Self> {
        let handle = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), permission) };
        if handle.is_null() {
            return Err(Win32Error::last());
        }
        Ok(ScManager(handle))
    }

    fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for ScManager {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.get());
        }
    }
}

pub fn try_stop_service(pid: u32) -> Win32Result<()> {
    unsafe {
        let scm = ScManager::new(SC_MANAGER_ENUMERATE_SERVICE)?;

        let mut bytes_needed = 0;
        let mut count = 0;

        EnumServicesStatusExW(
            scm.get(),
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            ptr::null_mut(),
            0,
            &mut bytes_needed,
            &mut count,
            ptr::null_mut(),
            ptr::null(),
        );

        if bytes_needed == 0 {
            return Err(Win32Error::last());
        }

        let mut buffer = vec![0u8; bytes_needed as usize];

        if EnumServicesStatusExW(
            scm.get(),
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buffer.as_mut_ptr(),
            bytes_needed,
            &mut bytes_needed,
            &mut count,
            ptr::null_mut(),
            ptr::null(),
        ) == 0
        {
            return Err(Win32Error::last());
        }

        let services = std::slice::from_raw_parts(
            buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            count as usize,
        );

        for svc in services {
            if svc.ServiceStatusProcess.dwProcessId == pid {
                let service = OpenServiceW(
                    scm.get(),
                    svc.lpServiceName,
                    SERVICE_STOP,
                );

                if !service.is_null() {
                    let mut status: SERVICE_STATUS = std::mem::zeroed();
                    ControlService(service, SERVICE_CONTROL_STOP, &mut status);
                }
            }
        }

        Ok(())
    }
}

//
// ================= MAIN KILL FUNCTION =================
//
fn is_process_alive(handle: HANDLE) -> RedrResult<()> {
    unsafe {
        // WaitForSingleObject returns WAIT_TIMEOUT if process is running
        if !WaitForSingleObject(handle, 0) == WAIT_TIMEOUT {
            Err(format!("Process is not alive").into())
        } else {
            Ok(())
        }
    }
}

pub fn kill_process_advanced(pid: u32) -> RedrResult<()> {
    super::enable_privilege(super::Priviledge::Debug)?;
    let handle = SmartHandle::new(unsafe {OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid)})?;
    is_process_alive(handle.get())?;

    let name = get_process_name(handle.get())?;

    println!(
        "Handling PID {} ({})",
        pid,
        name.clone().unwrap_or_else(|| "unknown".into())
    );

    if is_critical_process(pid, name.as_deref()) {
        return Err(format!("Skipping critical process {}", pid).into());
    }

    unsafe {
        log::info!("Successfully opened process {}: {:p}", pid, handle.get());
        // 1️⃣ Try service stop
        if let Err(err) = try_stop_service(pid) {
            eprintln!("Failed to stop service: {}", err);
        }

        // 2️⃣ Try graceful WM_CLOSE
        send_wm_close(pid);

        // 3️⃣ Wait
        if WaitForSingleObject(handle.get(), 3000) == WAIT_OBJECT_0 {
            return Ok(());
        }

        // 4️⃣ Force kill
        println!("Force killing PID {}", pid);

        if TerminateProcess(handle.get(), 1) != 0 {
            return Err(format!("TerminateProcess failed: {}", pid).into());
        }

        WaitForSingleObject(handle.get(), 2000);
    }

    Ok(())
}