use cleaner::cleaner::Cleaner;
use common_um::redr::MalwareInfo;

pub enum ScanResult {
    Clean,
    Malicious(MalwareInfo, Cleaner),
}
