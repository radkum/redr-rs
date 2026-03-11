mod detection;
mod scan_path;

use std::{env, ffi::OsString};

use ansi_term::Colour::{Green, Red};
use clap::{Parser, Subcommand};
// #[derive(clap::Args)]
// pub struct CompileRaw {
//     /// Malware dir
//     #[clap(short, long)]
//     dir: String,
//     /// Out path of sigset. Extenstion should be "sset"
//     #[clap(short, long)]
//     out_path: String,
// }

#[derive(clap::Args)]
pub struct Compile {
    /// Signature directory
    #[clap(long)]
    dir: String,
    /// Output name/path of sigset. Extenstion should be "sset"
    #[clap(short, long)]
    out_path: String,
}

#[derive(Subcommand)]
pub enum SignatureCommand {
    //CompileRaw(CompileRaw),
    Compile(Compile),
    //Unpack(Unpack), - todo in future
    //List(List), - todo in future
}

#[derive(clap::Args)]
pub struct Unpack {
    /// Path to sset
    #[clap(short, long)]
    set: String,
    /// Directory where sigs should be unpack
    #[clap(short, long)]
    out_dir: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Build malware signature set
    #[command(subcommand)]
    Signature(SignatureCommand),
    /// Evaluate a suspected file
    Evaluate {
        /// Path to signature store
        #[clap(short)]
        sig_store_path: String,
        /// Path to scan. Dir or file
        #[clap(value_name = "PATH")]
        file_path: String,
    },
    StartDetection {
        /// Path to signature store
        #[clap(short)]
        sig_store_path: String,
    },
    Response {
        // isolate
        #[clap(short, long)]
        isolation: Isolation,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum Isolation {
    Start,
    Stop,
    Check,
}

#[derive(Parser)]
#[command(author, about)]
pub struct Cli {
    /// Increase log message verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    log_level: u8,
    #[arg(short = 'V', long)]
    /// Print version information
    version: bool,
    #[command(subcommand)]
    commands: Commands,
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        Commands::Response { isolation } => {
            // TODO: Implement isolation handling
            let response = response::Isolator::default();
            match isolation {
                Isolation::Start => {
                    let mut response = response;
                    response.add_allow(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        142, 250, 120, 136,
                    )));
                    response.isolate()?;
                    println!("{} Isolation started", Green.paint("SUCCESS!"))
                }
                Isolation::Stop => {
                    response.restore()?;
                    println!("{} Isolation stopped", Green.paint("SUCCESS!"))
                }
                Isolation::Check => {
                    if response.status()? {
                        println!("Isolation is active")
                    } else {
                        println!("Isolation is NOT active")
                    }
                }
            }
        }
    }

    Ok(())
}
