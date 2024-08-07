mod file_cleaner;
mod process_cleaner;

use std::path::PathBuf;

use common::event::Pid;

pub enum Cleaner {
    Process(Pid),
    File(PathBuf),
}

impl Cleaner {
    pub fn clean(&self) -> bool {
        match &self {
            Cleaner::Process(pid) => process_cleaner::try_to_kill_process(pid),
            Cleaner::File(path) => file_cleaner::delete_file(path),
        }
    }
}
