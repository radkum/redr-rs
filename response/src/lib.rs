mod isolation;
mod terminate_process;
mod quarantine;
mod delete_file;
mod priviledge;

pub use isolation::Isolator;
pub use quarantine::{quarantine_file, unquarantine_file};
pub use delete_file::delete_file_force;
pub use delete_file::{find_processes_with_loaded_module, unload_dll_from_process, unload_dll_from_all_processes};
pub use terminate_process::kill_process_advanced;

pub(crate) use priviledge::enable_privilege;
pub(crate) use priviledge::Priviledge;