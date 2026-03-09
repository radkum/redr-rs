pub mod error;
mod error_msg;
mod handle_wrapper;
pub mod winapi;

use std::{
    fs::File,
    mem,
    ptr::{null, null_mut},
    sync::Arc,
};

use ansi_term::{
    Colour::{Green, Red},
    Style,
};
use cleaner::cleaner::Cleaner;
use common::{
    cleaning_info::CleaningInfoTrait,
    constants::COMM_PORT_NAME,
    event::{
        get_event_type, image_load::ImageLoadEvent, process_create::ProcessCreateEvent,
        registry_set_value::RegistrySetValueEvent, Event, FileCreateEvent,
    },
    hasher::MemberHasher,
};
use common_um::{redr, redr::MalwareInfo};
use console::Term;
use scanner::{error::ScanError, ScanResult, Scanner};
use signatures::sig_store::SignatureStore;
use widestring::u16cstr;
use windows_sys::Win32::{
    Foundation::STATUS_SUCCESS,
    Storage::InstallableFileSystems::{
        FilterConnectCommunicationPort, FilterGetMessage, FILTER_MESSAGE_HEADER,
    },
};

use crate::{
    error_msg::{print_hr_result, print_last_error},
    handle_wrapper::SmartHandle,
    winapi::output_debug_string,
};

#[tokio::main]
pub async fn start_detection(signatures: SignatureStore) {
    //todo: check signatures
    let port_name = u16cstr!(COMM_PORT_NAME).as_ptr();
    let Some(connection_port) = init_port(port_name) else {
        return;
    };

    let _ = ansi_term::enable_ansi_support();
    println!("{} Client connected to driver", Green.paint("SUCCESS!"));

    message_loop(connection_port, signatures);

    //CloseHandle(h_connection_port); ??
}

fn init_port(port_name: *const u16) -> Option<SmartHandle> {
    let mut connection_port = SmartHandle::new();

    let hr = unsafe {
        FilterConnectCommunicationPort(
            port_name,
            0,
            null(),
            0,
            null_mut(),
            connection_port.as_mut_ref() as *mut isize,
        )
    };

    if hr != STATUS_SUCCESS {
        println!("Failed to connect");
        print_hr_result("", hr);
        print_last_error("");
        None
    } else {
        Some(connection_port)
    }
}
fn message_loop(connection_port: SmartHandle, sig_store: SignatureStore) {
    let arc_sig_store = Arc::new(sig_store);
    let arc_connection_port = Arc::new(connection_port);

    // why we need to clone? there is no reason to have two instance of the same sig_store
    let scanner = Scanner::new(arc_sig_store.clone());

    let _t = tokio::spawn(async move {
        loop {
            if let Ok(ScanResult::Malicious(d, c)) =
                process_message(arc_connection_port.clone(), &scanner, arc_sig_store.clone()).await
            {
                print_report(d);
                let _ = c.clean(); //todo
            }
        }
    });

    let stdout = Term::buffered_stdout();
    loop {
        if let Ok(character) = stdout.read_char() {
            match character {
                'q' => break,
                _ => {},
            }
        }
    }
}

async fn process_message(
    connection_port: Arc<SmartHandle>,
    scanner: &Scanner,
    sig_store: Arc<SignatureStore>,
) -> Result<ScanResult, ScanError> {
    let msg_header = mem::size_of::<FILTER_MESSAGE_HEADER>();

    // In a loop, read data from the socket and write the data back.
    let mut buff: [u8; 0x1000] = unsafe { mem::zeroed() };

    let hr = unsafe {
        FilterGetMessage(
            connection_port.get() as isize,
            buff.as_mut_ptr() as *mut FILTER_MESSAGE_HEADER,
            mem::size_of_val(&buff) as u32,
            null_mut(),
        )
    };

    if hr != STATUS_SUCCESS {
        println!("Failed to get message");
        print_hr_result("", hr);
        print_last_error("");
        return Err(ScanError::SendMsgError("Failed to get message".to_string()));
    }

    let event_buff = &buff[msg_header..];
    let e = get_event_type(event_buff);

    if e == FileCreateEvent::EVENT_CLASS {
        let file_create_event = FileCreateEvent::deserialize(event_buff).unwrap();
        let path = file_create_event.get_path();
        let file_info_res = create_file_reader_and_info(path.as_str());
        log::info!("Path: {}", path.as_str());
        match file_info_res {
            Ok(file_info) => scanner.process_file(file_info).await?,
            Err(err) => log::warn!("Path: {}, Err: {:?}", path, err),
        }
    }

    let predicates_and_pid = match e {
        ProcessCreateEvent::EVENT_CLASS => {
            let e = ProcessCreateEvent::deserialize(event_buff);
            e.map(|e| (e.hash_members(), e.get_pid()))
        },
        ImageLoadEvent::EVENT_CLASS => {
            let e = ImageLoadEvent::deserialize(event_buff);
            e.map(|e| (e.hash_members(), e.get_pid()))
        },
        RegistrySetValueEvent::EVENT_CLASS => {
            let e = RegistrySetValueEvent::deserialize(event_buff);
            e.map(|e| (e.hash_members(), e.get_pid()))
        },
        _ => {
            return Err(ScanError::UnknownEvent);
        },
    };

    let Some((predicates, pid)) = predicates_and_pid else {
        return Ok(ScanResult::Clean);
    };
    let detection_report = sig_store.eval_vec(predicates)?;

    Ok(match detection_report {
        None => ScanResult::Clean,
        Some(report) => {
            ScanResult::Malicious(MalwareInfo::new(report.into()), Cleaner::Process(pid))
        },
    })
}

fn print_report(detection_report: MalwareInfo) {
    let report: String = detection_report.into();
    println!("{} - {}", Red.paint("MALWARE"), Style::new().bold().paint(&report));
    log::warn!("{} - {}", Red.paint("MALWARE"), Style::new().bold().paint(&report));
    output_debug_string(report);
}

fn create_file_reader_and_info(path: &str) -> Result<redr::FileReaderAndInfo, ScanError> {
    let file = File::open(path.to_string())?;
    let file_info = redr::FileScanInfo::real_file(path.into());
    Ok((redr::FileReader::from_file(file), file_info))
}

#[cfg(test)]
mod test {
    use common::{event::registry_set_value::RegistrySetValueEvent, hasher::MemberHasher};

    #[test]
    fn compile_and_eval_signature() {
        let sig = r#"name: Wacatac.exe
description: Watacat - behavioural detection
event:
  RegSetValue:
    value_name: Windows Live Messenger
    key_name: \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    data: C:\WINDOWS\system32\evil.exe"#;

        let vec = vec![sig.to_string()];

        let sig_store = signatures::create_sig_store_from_string_vec(vec).unwrap();

        let e1 = RegistrySetValueEvent::new(
            123,
            234,
            r#"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"#.to_string(),
            "Windows Live Messenger".to_string(),
            3,
            r#"C:\WINDOWS\system32\evil.exe"#.as_bytes().to_vec(),
        );

        let x = sig_store.eval_vec(e1.hash_members()).unwrap().unwrap();

        assert_eq!(x.desc, "Watacat - behavioural detection");
    }
}
