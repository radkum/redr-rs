use common::event::{process_create::ProcessCreateEvent, Event};
use kernel_macros::HandleToU32;
use km_api_sys::ntddk::{PPS_CREATE_NOTIFY_INFO, PS_CREATE_NOTIFY_INFO};
use winapi::{km::wdm::PEPROCESS, shared::ntdef::HANDLE};

use crate::send_message::send_message;

pub extern "system" fn OnProcessNotify(
    _process: PEPROCESS,
    process_id: HANDLE,
    create_info: PPS_CREATE_NOTIFY_INFO,
) {
    unsafe {
        log::info!("OnProcessNotify");
        if !create_info.is_null() {
            let create_info: &PS_CREATE_NOTIFY_INFO = &*create_info;
            let create_info: &PS_CREATE_NOTIFY_INFO = &*create_info;

            let image_file_name = &*create_info.ImageFileName;

            let event = ProcessCreateEvent::new(
                HandleToU32!(process_id),
                HandleToU32!(create_info.ParentProcessId),
                image_file_name.as_rust_string().unwrap_or_default(),
            );
            let v = event.serialize().unwrap_or_default();
            let event_ptr = v.as_ptr();
            let event_len = v.len() as u32;
            send_message(event_ptr, event_len);
        } // else {
          //     ProcessExit {
          //         pid: HandleToU32!(process_id),
          //     }
          // }
    }
}
