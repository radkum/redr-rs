mod detection;
mod scan_path;
mod cli;
use cli::*;
use clap::Parser;
use database::Database;
use std::{env, ffi::OsString};

use ansi_term::Colour::{Green, Red};
use tokio::


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().collect::<Vec<_>>();
    if args.len() == 1 {
        args.push(OsString::from("--help"));
    }
    let args = Cli::parse_from(args);
    let _ = ansi_term::enable_ansi_support();
    let log_level = match args.log_level {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::Builder::new().filter_level(log_level).init();

    match args.commands {
        Commands::Signature(signature_command) => match signature_command {
            SignatureCommand::Compile(args) => {
                let sig_store = signatures::create_sig_store_from_path(args.dir.as_str())?;
                match signatures::seralize_sig_store_to_file(sig_store, args.out_path.as_str()) {
                    Ok(number) => {
                        println!("{} Compiled signatures: {number}", Green.paint("SUCCESS!"))
                    }
                    Err(e) => log::error!("Failed to compile sigs. Err: {e}"),
                }
            }
        },
        Commands::Evaluate {
            sig_store_path,
            file_path,
        } => {
            // if let Err(e) = scan_path::scan_path(file_path.as_str(), sig_store_path) {
            //     println!("{} Cause: {e}", Red.paint("ERROR!"))
            // }
            if let Err(e) = scan_path::async_scan_path(file_path.as_str(), sig_store_path) {
                println!("{} Cause: {e}", Red.paint("ERROR!"))
            }
        }
        Commands::StartDetection { sig_store_path } => {
            detection::start_detection(sig_store_path.as_str()).unwrap()
        }
        Commands::Response { response } => {
            match response {
                Responses::Isolation { action } => {
                    let isolator = response::Isolator::default();
                    match action {
                        Isolation::Start => {
                            let mut response = isolator;
                            response.add_allow(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                142, 250, 120, 136,
                            )));
                            response.isolate()?;
                            println!("{} Isolation started", Green.paint("SUCCESS!"))
                        }
                        Isolation::Stop => {
                            isolator.restore()?;
                            println!("{} Isolation stopped", Green.paint("SUCCESS!"))
                        }
                        Isolation::Check => {
                            if isolator.status()? {
                                println!("Isolation is active")
                            } else {
                                println!("Isolation is NOT active")
                            }
                        }
                    }
                }
                Responses::Quarantine { action } => {
                    let database = Database::connect(utils::redr_database_path()).await?;
                    match action {
                        Quarantine::List => {
                            database.list_quarantined_files()?;
                        }
                        Quarantine::Perform(file_path) => {
                            response::quarantine_file(file_path, database).await?;
                        }
                        Quarantine::Restore(file_id) => {
                            response::unquarantine_file(file_id, database).await?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
