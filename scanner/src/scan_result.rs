use utils::redr::MalwareInfo;

pub enum ScanResult {
    Clean,
    Malicious(MalwareInfo),
}
