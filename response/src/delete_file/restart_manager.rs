use std::ptr;
use windows_sys::Win32::System::RestartManager::*;

use utils::windows;
use super::DeleteError;

struct RmSession {
    id: u32,
    abandon: bool,
}

impl RmSession {
    fn new() -> Result<Self, DeleteError> {
        let mut session: u32 = 0;
        let mut key = [0u16; 33]; // CCH_RM_SESSION_KEY + 1

        if unsafe { RmStartSession(&mut session, 0, key.as_mut_ptr()) } != 0 {
            return Err(DeleteError::last_err());
        }

        Ok(RmSession { id: session, abandon: false })
    }

    fn register(&self, path: &str) -> Result<(), DeleteError> {
        let w = windows::to_wide(path);
        let file_ptr = w.as_ptr();

        if unsafe { RmRegisterResources(self.get(), 1, &file_ptr, 0, ptr::null(), 0, ptr::null()) } != 0 {
            return Err(DeleteError::last_err());
        }

        Ok(())
    }

    fn get(&self) -> u32 {
        self.id
    }
}

impl Drop for RmSession {
    fn drop(&mut self) {
        unsafe {
            if !self.abandon {
                RmEndSession(self.get());
            }
            
        }
    }
}

pub(super) fn get_locking_processes(path: &str) -> Result<Vec<RM_PROCESS_INFO>, DeleteError> {
    unsafe {
        let session = RmSession::new()?;

        session.register(path)?;

        let mut needed: u32 = 0;
        let mut count: u32 = 0;
        let mut reason: u32 = 0;

        // First call to get the count
        RmGetList(session.get(), &mut needed, &mut count, ptr::null_mut(), &mut reason);

        if needed == 0 {
            return Ok(Vec::new());
        }

        let mut processes: Vec<RM_PROCESS_INFO> = vec![std::mem::zeroed(); needed as usize];
        count = needed;

        if RmGetList(
            session.get(),
            &mut needed,
            &mut count,
            processes.as_mut_ptr(),
            &mut reason,
        ) != 0 {
            return Err(DeleteError::last_err());
        }

        processes.truncate(count as usize);
        Ok(processes)
    }
}


pub(super) fn close_locking_processes(path: &str) -> Result<(), DeleteError> {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    extern "system" fn status_callback(percent: u32) {
        log::debug!("Restart Manager progress: {}%", percent);
    }

    let mut session = RmSession::new()?;
    session.register(path)?;

    const RM_FORCE_SHUTDOWN: u32 = 0x1;
    
    // RmShutdown can hang, so run it with a timeout
    let session_handle = session.get();
    let (tx, rx) = mpsc::channel();
    
    thread::spawn(move || {
        let result = unsafe { RmShutdown(session_handle, RM_FORCE_SHUTDOWN, Some(status_callback)) };
        let _ = tx.send(result);
    });

    // Wait up to 5 seconds for shutdown
    match rx.recv_timeout(Duration::from_secs(3)) {
        Ok(0) => {
            log::info!("RmShutdown completed successfully");
        }
        Ok(code) => {
            log::warn!("RmShutdown completed with code: {}", code);
            // Even if it returned, it might not have succeeded, so we can still try to forcefully terminate the session
            session.abandon = true;
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            log::warn!("RmShutdown timed out after 3 seconds");
            // If we timed out, we can still try to forcefully terminate the session
            session.abandon = true;
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            log::warn!("RmShutdown thread disconnected");
            session.abandon = true;
        }
    }

    log::debug!("RmShutdown completed");
    // session will be dropped here, calling RmEndSession
    Ok(())
}