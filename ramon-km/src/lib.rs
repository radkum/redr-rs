#![no_std]
#![allow(non_snake_case)]
#![allow(static_mut_refs)]

mod cleaner;

mod ioctl_code;
mod irp;
mod minifilter;
mod notifiers;
mod send_message;

use notifiers::{OnImageLoadNotify, OnProcessNotify, OnRegistryNotify};

extern crate alloc;

use alloc::collections::VecDeque;
use core::ptr::null_mut;

use kernel_fast_mutex::{fast_mutex::FastMutex, locker::Locker};
/// kernel-init deliver a few elements (eg. panic implementation) necessary to run code in kernel
#[allow(unused_imports)]
use kernel_init;
use kernel_log::KernelLogger;
use kernel_macros::NT_SUCCESS;
use kernel_string::UNICODE_STRING;
use km_api_sys::{
    ntddk::{
        PsRemoveLoadImageNotifyRoutine, PsSetCreateProcessNotifyRoutineEx,
        PsSetLoadImageNotifyRoutine,
    },
    wmd::{CmRegisterCallbackEx, CmUnRegisterCallback, LARGE_INTEGER},
};
use log::LevelFilter;
use winapi::{
    km::wdm::{DEVICE_OBJECT, DRIVER_OBJECT, IRP, IRP_MJ},
    shared::{
        ntdef::{FALSE, NTSTATUS, PVOID, TRUE},
        ntstatus::{STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS},
    },
};

use crate::{
    alloc::string::ToString, cleaner::Cleaner, irp::complete_irp_success, minifilter::Minifilter,
};

#[allow(dead_code)]
pub(crate) const POOL_TAG: u32 = u32::from_ne_bytes(*b"RDER");
const MAX_ITEM_COUNT: usize = 32;

static mut G_MUTEX: FastMutex = FastMutex::new();
//static mut G_PROCESS_NAMES: Option<BTreeSet<ULONG>> = None;
static mut G_FILE_NAMES: Option<VecDeque<usize>> = None;
static mut G_COOKIE: LARGE_INTEGER = LARGE_INTEGER::new();

#[link_section = "INIT"]
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(
    driver: &mut DRIVER_OBJECT,
    _path: *const UNICODE_STRING,
) -> NTSTATUS {
    KernelLogger::init(LevelFilter::Warn).expect("Failed to initialize logger");

    log::info!("START Ramon");

    let hello_world = UNICODE_STRING::create("Hello World!");
    log::info!("{}", hello_world.as_rust_string().unwrap_or("failed to unwrap".to_string()));

    //--------------------GLOBALS--------------------------------
    G_MUTEX.Init();
    let mut processes: VecDeque<usize> = VecDeque::new();
    if let Err(e) = processes.try_reserve_exact(MAX_ITEM_COUNT) {
        log::info!(
            "fail to reserve a {} bytes of memory. Err: {:?}",
            ::core::mem::size_of::<usize>() * MAX_ITEM_COUNT,
            e
        );
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    //let processes = processes.into_iter().collect();
    G_FILE_NAMES = Some(processes);

    //--------------------DISPATCH_ROUTINES-----------------------
    driver.MajorFunction[IRP_MJ::CREATE as usize] = Some(DispatchCreateClose);
    driver.MajorFunction[IRP_MJ::CLOSE as usize] = Some(DispatchCreateClose);
    driver.DriverUnload = Some(RamonUnloadDriver);

    //--------------------INIT MINIFILTER-----------------------
    #[allow(unused_assignments)]
    let mut status = STATUS_SUCCESS;

    let mut cleaner = Cleaner::new();
    loop {
        //--------------------PROCESS NOTIFY-----------------------
        status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);

        if NT_SUCCESS!(status) {
            cleaner.init_process_create_callback(OnProcessNotify);
        } else {
            log::info!("failed to create process nofity rountine 0x{:08x}", status);
            break;
        }

        //--------------------IMAGE NOTIFY-----------------------
        status = PsSetLoadImageNotifyRoutine(OnImageLoadNotify);

        if NT_SUCCESS!(status) {
            cleaner.init_image_load_callback(OnImageLoadNotify);
        } else {
            log::info!("failed to create image load routine 0x{:08x}", status);
            break;
        }

        //--------------------REGISTRY NOTIFY-----------------------
        let altitude = UNICODE_STRING::create("7657.124");
        status = CmRegisterCallbackEx(
            OnRegistryNotify as PVOID,
            &altitude,
            driver,
            null_mut(),
            &G_COOKIE,
            null_mut(),
        );

        if NT_SUCCESS!(status) {
            cleaner.init_registry_callback(G_COOKIE);
        } else {
            log::info!("failed to create registry routine 0x{:08x}", status);
            break;
        }

        //#[allow(unused_assignments)]
        status = Minifilter::create(driver);
        break;
    }

    //clean if initialization failed
    if NT_SUCCESS!(status) {
        log::info!("SUCCESS");
    } else {
        cleaner.clean();
    }

    status
}

/*************************************************************************
                    Dispatch  routines.
*************************************************************************/
extern "system" fn RamonUnloadDriver(_driver: &mut DRIVER_OBJECT) {
    log::info!("rust_unload");

    unsafe {
        PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);

        //PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);

        PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);

        CmUnRegisterCallback(G_COOKIE);
    }
}

extern "system" fn DispatchCreateClose(_driver: &mut DEVICE_OBJECT, irp: &mut IRP) -> NTSTATUS {
    complete_irp_success(irp)
}
