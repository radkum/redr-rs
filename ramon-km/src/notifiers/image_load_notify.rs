use alloc::string::ToString;

use common::event::{image_load::ImageLoadEvent, Event};
use kernel_macros::HandleToU32;
use kernel_string::PUNICODE_STRING;
use km_api_sys::ntddk::PIMAGE_INFO;
use winapi::shared::ntdef::HANDLE;

use crate::send_message::send_message;

pub extern "system" fn OnImageLoadNotify(
    full_image_name: PUNICODE_STRING,
    process_id: HANDLE,
    image_info: PIMAGE_INFO,
) {
    if process_id.is_null() {
        // system image, ignore
        return;
    }

    unsafe {
        log::info!("OnImageLoadNotify");

        let image_name = if full_image_name.is_null() {
            "(unknown)".to_string()
        } else {
            (*full_image_name).as_rust_string().unwrap_or("(unknown)".to_string())
        };

        let image_info = &*image_info;
        let event = ImageLoadEvent::new(
            HandleToU32!(process_id),
            image_info.ImageBase as u64,
            image_info.ImageSize as u64,
            image_name,
        );
        let v = event.serialize().unwrap_or_default();
        let event_ptr = v.as_ptr();
        let event_len = v.len() as u32;
        send_message(event_ptr, event_len);
    }
}
