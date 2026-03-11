use core::ptr::null_mut;

use kernel_fast_mutex::auto_lock::AutoLock;
use km_api_sys::{
    flt_kernel::{FltSendMessage, CONST_PVOID},
    wmd::{LARGE_INTEGER, PLARGE_INTEGER},
};
use winapi::shared::ntdef::PVOID;

use crate::{minifilter::S_MINIFILTER, G_MUTEX};

pub(crate) fn send_message(event_ptr: *const u8, event_len: u32) {
    unsafe {
        let _locker = AutoLock::new(&mut G_MUTEX);
        if let Some(ramon) = &S_MINIFILTER {
            if ramon.is_comm_active() {
                let mut timeout = LARGE_INTEGER::new_from_i64(0x1000);

                log::info!("Send message");
                let s = FltSendMessage(
                    ramon.filter_handle,
                    &ramon.client_port,
                    event_ptr as CONST_PVOID,
                    event_len as u32,
                    null_mut(),
                    null_mut(),
                    &mut timeout as PLARGE_INTEGER as PVOID,
                );
                log::info!("Status: 0x{:08x}", s);
            }
        }
    }
}
