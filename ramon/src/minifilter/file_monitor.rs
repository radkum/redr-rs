#![allow(static_mut_refs)]

use alloc::string::String;
use core::ptr::null_mut;

use common::event::{Event, FileCreateEvent};
use kernel_fast_mutex::auto_lock::AutoLock;
use kernel_macros::NT_SUCCESS;
use kernel_string::{PUNICODE_STRING, UNICODE_STRING};
use km_api_sys::flt_kernel::{
    FltGetFileNameInformation, FltGetVolumeFromFileObject, FltGetVolumeGuidName, FltIsDirectory,
    FltParseFileNameInformation, FltReleaseFileNameInformation, FLT_CALLBACK_DATA,
    FLT_FILE_NAME_OPTIONS, FLT_POSTOP_CALLBACK_STATUS,
    FLT_POSTOP_CALLBACK_STATUS::FLT_POSTOP_FINISHED_PROCESSING, FLT_POST_OPERATION_FLAGS,
    FLT_RELATED_OBJECTS,
};
use winapi::{
    km::wdm::KPROCESSOR_MODE,
    shared::ntdef::{BOOLEAN, NTSTATUS, PVOID, TRUE, ULONG},
};

use crate::{send_message::send_message, G_FILE_NAMES, G_MUTEX};

pub(crate) struct FileMonitor {}
impl FileMonitor {
    /*************************************************************************
    MiniFilter callback routines.
    *************************************************************************/
    pub(crate) extern "system" fn RamonPostCreate(
        data: &mut FLT_CALLBACK_DATA,
        flt_objects: &mut FLT_RELATED_OBJECTS,
        _completion_context: PVOID,
        _flags: FLT_POST_OPERATION_FLAGS,
    ) -> FLT_POSTOP_CALLBACK_STATUS {
        #[allow(unused_assignments)]
        let mut ntstatus = unsafe { data.IoStatus.__bindgen_anon_1.Status().clone() };

        // skip if dir is created
        let mut is_dir: BOOLEAN = 0;
        ntstatus = unsafe { FltIsDirectory(flt_objects.Filter, flt_objects.Instance, &mut is_dir) };

        if NT_SUCCESS!(ntstatus) && is_dir == TRUE {
            log::info!("Skip directory");
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        if let KPROCESSOR_MODE::KernelMode = data.RequestorMode {
            //log::info!("RamonPreCreate kernel request")
        }

        if flt_objects.FileObject.is_null() {
            log::warn!("FileObject is null");
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        //get file info
        let fni_flags = FLT_FILE_NAME_OPTIONS(FLT_FILE_NAME_OPTIONS::FLT_FILE_NAME_NORMALIZED);
        let mut pfile_name_info = null_mut();

        ntstatus = unsafe { FltGetFileNameInformation(data, fni_flags, &mut pfile_name_info) };
        if !NT_SUCCESS!(ntstatus) {
            log::warn!("FltGetFileNameInformation failed. Err: 0x{:08x}", ntstatus);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        if pfile_name_info.is_null() {
            log::warn!("pfile_name_info is null");
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        loop {
            ntstatus = unsafe { FltParseFileNameInformation(pfile_name_info) };
            if !NT_SUCCESS!(ntstatus) {
                log::warn!("FltParseFileNameInformation failed. Err: 0x{:08x}", ntstatus);
                break;
            }

            let mut p_volume = null_mut();
            ntstatus = unsafe {
                FltGetVolumeFromFileObject(
                    flt_objects.Filter,
                    flt_objects.FileObject,
                    &mut p_volume,
                )
            };
            if !NT_SUCCESS!(ntstatus) {
                log::warn!("FltGetVolumeFromFileObject failed. Err: 0x{:08x}", ntstatus);
                break;
            }

            let mut buffer_size: ULONG = 0;

            let _ = unsafe { FltGetVolumeGuidName(p_volume, null_mut(), &mut buffer_size) };
            let mut guid_name = UNICODE_STRING::with_buffer_50();
            //todo: allocate buffer in better way

            ntstatus = unsafe {
                FltGetVolumeGuidName(p_volume, &mut guid_name as PUNICODE_STRING, &mut buffer_size)
            };
            if !NT_SUCCESS!(ntstatus) {
                log::debug!("FltGetVolumeGuidName failed. Err: 0x{:08x}", ntstatus);
                break;
            }

            let file_name_info = unsafe { &*pfile_name_info };
            if let (Some(mut guid_name), Some(volume), Some(name)) = (
                guid_name.as_rust_string(),
                file_name_info.Volume.as_rust_string(),
                file_name_info.Name.as_rust_string(),
            ) {
                //log::warn!("{} -{}-{}", guid_name, volume, name);
                if let Some(stripped) = name.strip_prefix(&volume) {
                    guid_name.push_str(stripped);

                    //temporary to scan only exe
                    if let Some(extension) = file_name_info.Extension.as_rust_string() {
                        //log::warn!("extension: {:?}" ,extension.as_str());
                        if extension == "exe" {
                            FileMonitor::ProcessFileEvent(guid_name);
                        }
                    }
                }
            }
            //log::warn!("guid_name {:?}", guid_name.as_rust_string());
            break;
        }

        unsafe { FltReleaseFileNameInformation(pfile_name_info) };

        FLT_POSTOP_FINISHED_PROCESSING
    }

    // pub(crate) extern "system" fn RamonPreSetInformation(
    //     data: &mut FLT_CALLBACK_DATA,
    //     _flt_objects: PFLT_RELATED_OBJECTS,
    //     _reserved: *mut PVOID,
    // ) -> FLT_PREOP_CALLBACK_STATUS {
    //     //log::info!("RamonPreSetInformation");
    //     let status = FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK;
    //
    //     unsafe {
    //         let process = PsGetThreadProcess(data.Thread);
    //         if process.is_null() {
    //             //something is wrong
    //             return status;
    //         }
    //
    //         let mut h_process: HANDLE = usize::MAX as HANDLE;
    //         let ret = ObOpenObjectByPointer(
    //             process,
    //             OBJ_KERNEL_HANDLE,
    //             null_mut(),
    //             0,
    //             null_mut(),
    //             KPROCESSOR_MODE::KernelMode,
    //             &mut h_process,
    //         );
    //         if !NT_SUCCESS!(ret) {
    //             return status;
    //         }
    //
    //         FileMonitor::ProcessFileEvent(h_process);
    //         ZwClose(h_process);
    //     }
    //     status
    // }
}

impl FileMonitor {
    fn ProcessFileEvent(file_name: String) {
        unsafe {
            //log::info!("Before lock. Len: {}", return_length);
            let _locker = AutoLock::new(&mut G_MUTEX);
            if let Some(file_names) = &mut G_FILE_NAMES {
                let file_name_len = file_name.len();
                if file_names.contains(&file_name_len) {
                    //todo: recognize file in other way
                    //return;
                }
                file_names.push_back(file_name_len);
            }
        }

        log::warn!("file_name: {}", &file_name);

        let event = FileCreateEvent::new(file_name);
        let v = event.serialize().unwrap_or_default();
        let event_ptr = v.as_ptr();
        let event_len = v.len() as u32;
        send_message(event_ptr, event_len);
    }
}
