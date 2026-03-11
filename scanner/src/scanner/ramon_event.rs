use utils::redr::FileReaderAndInfo;

pub enum RamonEvent {
    CreateFile(FileReaderAndInfo),
    Close,
}
