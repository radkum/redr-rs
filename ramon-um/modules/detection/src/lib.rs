pub mod error;
mod error_msg;
mod handle_wrapper;
pub mod winapi;

use std::{
    io::Write,
    mem,
    ptr::{null, null_mut},
};
use std::fs::File;

use ansi_term::{
    Colour::{Green, Red},
    Style,
};
use common::{
    cleaning_info::CleaningInfo,
    constants::COMM_PORT_NAME,
    event::{
        get_event_type,
        registry_set_value::RegistrySetValueEvent, Event, FileCreateEvent,
    },
    hasher::MemberHasher,
};
use console::Term;
use signatures::sig_store::SignatureStore;
use widestring::u16cstr;
use windows_sys::Win32::{
    Foundation::STATUS_SUCCESS,
    Storage::InstallableFileSystems::{
        FilterConnectCommunicationPort, FilterGetMessage, FILTER_MESSAGE_HEADER,
    },
};
use common_um::redr;
use scanner::error::ScanError;
use scanner::Scanner;

use crate::{
    error_msg::{print_hr_result, print_last_error},
    handle_wrapper::SmartHandle,
    winapi::output_debug_string,
};

#[tokio::main]
pub async fn start_detection(signatures: SignatureStore, signatures2: SignatureStore) {
    //todo: check signatures
    let port_name = u16cstr!(COMM_PORT_NAME).as_ptr();
    let Some(connection_port) = init_port(port_name) else {
        return;
    };

    let _ = ansi_term::enable_ansi_support();
    println!("{} Client connected to driver", Green.paint("SUCCESS!"));

    message_loop(connection_port, signatures, signatures2);

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
fn message_loop(connection_port: SmartHandle, sig_store: SignatureStore, sig_store2: SignatureStore) {
    let _t = tokio::spawn(async move {
        // why we need to clone? there is no reason to have two instance of the same sig_store
        let scanner = Scanner::new(sig_store2);

        let msg_header = mem::size_of::<FILTER_MESSAGE_HEADER>();

        // In a loop, read data from the socket and write the data back.
        let mut buff: [u8; 0x1000] = unsafe { mem::zeroed() };
        loop {
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
                return;
            }

            let event_buff = &buff[msg_header..];
            let e = get_event_type(event_buff);

            if e == FileCreateEvent::EVENT_CLASS {
                let file_create_event = FileCreateEvent::deserialize(event_buff).unwrap();
                let path = file_create_event.get_path();
                let file_info = create_file_reader_and_info(path);
                scanner.process_file(file_info.unwrap()).await.unwrap();
            }

            let detection_report = match e {
                // ProcessCreateEvent::EVENT_CLASS => {
                //     //println!("{:?}", ProcessCreateEvent::deserialize(event_buff))
                //     ProcessCreateEvent::deserialize(event_buff).map(|e| sig_store.eval_vec(e.hash_members()))
                // },
                // ImageLoadEvent::EVENT_CLASS => {
                //     //println!("{:?}", ImageLoadEvent::deserialize(event_buff))
                //     ImageLoadEvent::deserialize(event_buff).map(|e| sig_store.eval_vec(e.hash_members()))
                // },
                RegistrySetValueEvent::EVENT_CLASS => {
                    let event = RegistrySetValueEvent::deserialize(event_buff);
                    event.map(|e| (e.get_pid(), sig_store.eval_vec(e.hash_members()).unwrap()))
                },
                _ => {
                    todo!()
                },
            };

            if let None = detection_report {
                continue;
            }
            let (pid, detection_report) = detection_report.unwrap();

            if let Some(detection_report) = detection_report {
                let detection = format!("{}", detection_report);
                println!("{} - {}", Red.paint("MALWARE"), Style::new().bold().paint(&detection));
                output_debug_string(detection);
                if cleaner::process_cleaner::try_to_kill_process(pid) {
                    println!("{} Process terminated. Pid: {}", Green.paint("SUCCESS!"), pid);
                    output_debug_string(format!("Success to terminate process. Pid: {}", pid));
                } else {
                    output_debug_string(format!("Failed to terminate process. Pid: {}", pid));
                }
            }

            let _ = std::io::stdout().flush();
            // tokio::spawn(async move {
            //     process_event(e.hash_members(), signatures).await;
            // });
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

fn create_file_reader_and_info(path: String) -> Result<redr::FileReaderAndInfo, ScanError> {
    let file = File::open(path.clone())?;
    let file_info = redr::FileScanInfo::real_file(path.into());
    Ok((redr::FileReader::from_file(file), file_info))
}
// async fn process_event(hashes: Vec<[u8; 32]>, signatures: &BedetSet) {
//     println!(
//         "{}",
//         hashes
//             .iter()
//             .map(|sha| convert_sha256_to_string(sha).unwrap())
//             .collect::<Vec<_>>()
//             .join(", ")
//     );
//     println!("{:?}", signatures.eval_event(hashes).unwrap());
// }

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
        // assert_eq!(
        //     x.cause,
        //     "Detected Event: RegSetValue: { {\"data\": \"C:\\\\WINDOWS\\\\system32\\\\evil.exe\", \
        //      \"data_type\": \"1\", \"key_name\": \
        //      \"\\\\REGISTRY\\\\MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\\
        //      Run\", \"value_name\": \"Windows Live Messenger\"} }"
        // );
    }
}
