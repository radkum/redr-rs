use alloc::vec::Vec;
use core::{mem, ptr::null_mut};

use common::event::{registry_set_value::RegistrySetValueEvent, Event};
use kernel_macros::{HandleToU32, NT_SUCCESS};
use kernel_string::PUNICODE_STRING;
use km_api_sys::{
    ntddk::{PsGetCurrentProcessId, PsGetCurrentThreadId, REG_NT_POST_SET_VALUE_KEY},
    wmd::{
        CmCallbackGetKeyObjectIDEx, CmCallbackReleaseKeyObjectIDEx,
        PREG_POST_OPERATION_INFORMATION, PREG_SET_VALUE_KEY_INFORMATION,
    },
};
use winapi::shared::{
    ntdef::{NTSTATUS, PVOID},
    ntstatus::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL},
};

use crate::{send_message::send_message, G_COOKIE};

pub extern "system" fn OnRegistryNotify(_context: PVOID, arg1: PVOID, arg2: PVOID) -> NTSTATUS {
    let reg_notify = HandleToU32!(arg1);
    if reg_notify == REG_NT_POST_SET_VALUE_KEY {
        log::info!("OnRegistryNotify");
        unsafe {
            let op_info = &*(arg2 as PREG_POST_OPERATION_INFORMATION);
            if !NT_SUCCESS!(op_info.Status) {
                return STATUS_SUCCESS;
            }

            let mut name: PUNICODE_STRING = null_mut();
            let status =
                CmCallbackGetKeyObjectIDEx(&G_COOKIE, op_info.Object, null_mut(), &mut name, 0);
            if !NT_SUCCESS!(status) {
                return STATUS_SUCCESS;
            }

            if name.is_null() {
                //something wrong
                return STATUS_UNSUCCESSFUL;
            }

            loop {
                let key_name = if let Some(key_name) = (*name).as_rust_string() {
                    key_name
                } else {
                    log::info!("Something wrong. Can't convert \"key_name\" to rust string");
                    break;
                };
                let registry_machine = "\\REGISTRY\\MACHINE";

                // filter out none-HKLM writes
                if key_name.contains(registry_machine) {
                    if op_info.PreInformation.is_null() {
                        //something wrong
                        break;
                    }

                    let pre_info = &*(op_info.PreInformation as PREG_SET_VALUE_KEY_INFORMATION);
                    let value_name =
                        if let Some(value_name) = (*pre_info.ValueName).as_rust_string() {
                            value_name
                        } else {
                            //log::info!("Something wrong. Can't convert \"value_name\" to rust string");
                            break;
                        };

                    if pre_info.Data.is_null() {
                        break;
                    }

                    let data = {
                        let size = if pre_info.DataSize < 0x400 {
                            pre_info.DataSize as usize
                        } else {
                            0x400
                        };

                        Vec::from_raw_parts(pre_info.Data as *mut u8, size, size)
                    };
                    log::info!("{data:?}");
                    if data.len() > 4 {
                        let d = pre_info.Data as *const u8;
                        log::info!(
                            "[{}, {}, {}, {}]",
                            *d,
                            *(d.offset(1)),
                            *(d.offset(2)),
                            *(d.offset(3))
                        );
                        log::info!("[{}, {}, {}, {}]", data[0], data[1], data[2], data[3]);
                    }
                    let event = RegistrySetValueEvent::new(
                        HandleToU32!(PsGetCurrentProcessId()),
                        HandleToU32!(PsGetCurrentThreadId()),
                        key_name,
                        value_name,
                        pre_info.DataType,
                        data.clone(),
                    );
                    let v = event.serialize().unwrap_or_default();
                    let event_ptr = v.as_ptr();
                    let event_len = v.len() as u32;
                    send_message(event_ptr, event_len);

                    mem::forget(data);
                    // let item = RegistrySetValue {
                    //     pid: HandleToU32!(PsGetCurrentProcessId()),
                    //     tid: HandleToU32!(PsGetCurrentThreadId()),
                    //     key_name: ItemInfo::string_to_buffer(key_name),
                    //     value_name,
                    //     data_type: pre_info.DataType,
                    //     data: v.clone(),
                    // };
                }
                break;
            }
            CmCallbackReleaseKeyObjectIDEx(name);
        }
    }

    STATUS_SUCCESS
}
