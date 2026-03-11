use clap::{Parser, Subcommand};

#[derive(clap::Args)]
pub struct Compile {
    /// Signature directory
    #[clap(long)]
    pub dir: String,
    /// Output name/path of sigset. Extenstion should be "sset"
    #[clap(short, long)]
    pub out_path: String,
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
    pub set: String,
    /// Directory where sigs should be unpack
    #[clap(short, long)]
    pub out_dir: String,
}

#[derive(Subcommand)]
pub enum Commands {
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

#[derive(Subcommand)]
enum Responses {
    // isolate
    Isolation(Isolation),
    Quarantine(Quarantine),
}
#[derive(Clone, clap::ValueEnum)]
pub enum Isolation {
    Start,
    Stop,
    Check,
}

#[derive(Clone, clap::ValueEnum)]
pub enum Quarantine {
    List,
    Quarantine(std::path::PathBuf),
    UnquarantineById(u32),
}

#[derive(Parser)]
#[command(author, about)]
pub struct Cli {
    /// Increase log message verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub log_level: u8,
    #[arg(short = 'V', long)]
    /// Print version information
    version: bool,
    #[command(subcommand)]
    pub commands: Commands,
}