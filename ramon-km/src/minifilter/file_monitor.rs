#![allow(static_mut_refs)]

use common::event::{Event, FileCreateEvent};
use kernel_fast_mutex::auto_lock::AutoLock;
use kernel_macros::NT_SUCCESS;
use kernel_string::PUNICODE_STRING;
use km_api_sys::{
    flt_kernel::{
        FltIsDirectory, FLT_CALLBACK_DATA, FLT_POSTOP_CALLBACK_STATUS,
        FLT_POSTOP_CALLBACK_STATUS::FLT_POSTOP_FINISHED_PROCESSING, FLT_POST_OPERATION_FLAGS,
        FLT_RELATED_OBJECTS,
    },
    ntddk::PROCESSINFOCLASS,
    ntoskrnl::{ExAllocatePool2, ExFreePoolWithTag, POOL_FLAG_PAGED},
    wmd::{NtCurrentProcess, ZwQueryInformationProcess},
};
use winapi::{
    km::wdm::KPROCESSOR_MODE,
    shared::{
        ntdef::{BOOLEAN, HANDLE, NTSTATUS, PVOID, ULONG},
        ntstatus::STATUS_INFO_LENGTH_MISMATCH,
    },
};

use crate::{send_message::send_message, G_MUTEX, G_PROCESS_NAMES, POOL_TAG};

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
        //let is_txt_writer = false;

        // skip if file creation not succeed
        // if !NT_SUCCESS!(ntstatus) || ntstatus == STATUS_REPARSE {
        //     log::info!("file craetion may failed");
        //
        //     return FLT_POSTOP_FINISHED_PROCESSING;
        // }

        // skip if dir is created
        let mut is_dir: BOOLEAN = 0;
        ntstatus = unsafe { FltIsDirectory(flt_objects.Filter, flt_objects.Instance, &mut is_dir) };

        let is_dir = false;
        if NT_SUCCESS!(ntstatus) && is_dir {
            log::info!("Skip directory");
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        if let KPROCESSOR_MODE::KernelMode = data.RequestorMode {
            //log::info!("RamonPreCreate kernel request")
        }

        FileMonitor::ProcessFileEvent(NtCurrentProcess());

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
    fn ProcessFileEvent(h_process: HANDLE) {
        let process_name_size = 300;
        let process_name = unsafe {
            ExAllocatePool2(POOL_FLAG_PAGED, process_name_size, POOL_TAG) as PUNICODE_STRING
        };

        if process_name.is_null() {
            log::info!("fail to reserve a {} bytes of memory", process_name_size);
            return;
        }

        let mut return_length: ULONG = 0;
        let status = unsafe {
            ZwQueryInformationProcess(
                h_process,
                PROCESSINFOCLASS::ProcessImageFileName,
                process_name as PVOID,
                (process_name_size - 2) as u32,
                &mut return_length,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            //too small buffer
            unsafe { ExFreePoolWithTag(process_name as PVOID, POOL_TAG) };
            return;
        }

        //prevent spam
        unsafe {
            //log::info!("Before lock. Len: {}", return_length);
            let _locker = AutoLock::new(&mut G_MUTEX);
            if let Some(process_names) = &mut G_PROCESS_NAMES {
                if process_names.contains(&return_length) {
                    return;
                }
                process_names.push_back(return_length);
            }
        }

        log::info!(
            "ZwQueryInformationProcess - status: {}, returnLength: {}",
            status,
            return_length
        );

        if NT_SUCCESS!(status) {
            let unicode_process_name = unsafe { &*process_name };
            if let Some(rust_process_name) = unicode_process_name.as_rust_string() {
                log::info!("Name: {}", rust_process_name);

                let event = FileCreateEvent::new(rust_process_name);
                let v = event.serialize().unwrap_or_default();
                let event_ptr = v.as_ptr();
                let event_len = v.len() as u32;
                send_message(event_ptr, event_len);
            } else {
                log::warn!("Something wrong. can't get rust string");
            }

            unsafe { ExFreePoolWithTag(process_name as PVOID, POOL_TAG) };
        }
    }
}
