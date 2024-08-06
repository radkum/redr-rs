use std::{
    fs, io,
    io::SeekFrom,
    ops::DerefMut,
    sync::{Arc, RwLock},
};

enum Input {
    File(fs::File),
    Buff(io::Cursor<Vec<u8>>),
}

unsafe impl Send for Input {}
unsafe impl Sync for Input {}

pub struct FileReader {
    input: Arc<RwLock<Input>>,
}

impl FileReader {
    pub fn from_file(file: std::fs::File) -> Self {
        Self { input: Arc::new(RwLock::new(Input::File(file))) }
    }

    // pub fn from_zip_file(file: zip::read::ZipFile) -> Self {
    //     Self { input: Rc::new(RefCell::new(Input::ZipFile(file))) }
    // }

    pub fn from_buff(buff: io::Cursor<Vec<u8>>) -> Self {
        Self { input: Arc::new(RwLock::new(Input::Buff(buff))) }
    }
}

impl io::Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut reader = self.input.write().unwrap();
        match reader.deref_mut() {
            Input::File(file) => file.read(buf),
            Input::Buff(cursor) => cursor.read(buf),
        }
    }
}

impl io::Seek for FileReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut reader = self.input.write().unwrap();
        match reader.deref_mut() {
            Input::File(file) => file.seek(pos),
            Input::Buff(cursor) => cursor.seek(pos),
        }
    }
}
