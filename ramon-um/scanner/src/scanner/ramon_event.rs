use common_um::redr::FileReaderAndInfo;

pub enum RamonEvent {
    CreateFile(FileReaderAndInfo),
    Close,
}
