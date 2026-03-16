mod isolation;
mod process_kill;
mod quarantine;

pub use isolation::Isolator;
pub use quarantine::{quarantine_file, unquarantine_file};
