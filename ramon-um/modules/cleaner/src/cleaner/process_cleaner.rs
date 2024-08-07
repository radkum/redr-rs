use common::event::Pid;
use windows_sys::Win32::{
    Foundation::{FALSE, STATUS_SUCCESS},
    System::Threading::{OpenProcess, TerminateProcess, PROCESS_ALL_ACCESS},
};

pub fn try_to_kill_process(pid: &Pid) -> bool {
    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid.0);
        if h_process != 0 {
            let result = TerminateProcess(h_process, 0);
            if result != STATUS_SUCCESS {
                log::warn!("Failed to TerminateProcess. Err: {}", result);
                return false;
            }
        } else {
            log::warn!("Failed to OpenProcess");
            return false;
        }
    }
    true
}
