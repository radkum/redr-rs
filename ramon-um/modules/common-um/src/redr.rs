mod file_abstraction;
mod file_info;
mod file_scan_info;

pub use file_abstraction::FileReader;
pub use file_info::FileInfo;
pub use file_scan_info::{FileScanInfo, RcMut};

pub type FileReaderAndInfo = (FileReader, FileScanInfo);
