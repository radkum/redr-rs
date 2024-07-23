use std::{cell::RefCell, fs, io, io::SeekFrom, rc::Rc};

enum Input {
    File(fs::File),
    //ZipFile(zip::read::ZipFile)
    Buff(io::Cursor<Vec<u8>>),
}
pub struct FileReader {
    input: Rc<RefCell<Input>>,
}

impl FileReader {
    pub fn from_file(file: std::fs::File) -> Self {
        Self { input: Rc::new(RefCell::new(Input::File(file))) }
    }

    // pub fn from_zip_file(file: zip::read::ZipFile) -> Self {
    //     Self { input: Rc::new(RefCell::new(Input::ZipFile(file))) }
    // }

    pub fn from_buff(buff: io::Cursor<Vec<u8>>) -> Self {
        Self { input: Rc::new(RefCell::new(Input::Buff(buff))) }
    }
}

impl io::Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut reader = self.input.borrow_mut();
        match &mut *reader {
            Input::File(file) => file.read(buf),
            Input::Buff(cursor) => cursor.read(buf),
        }
    }
}

impl io::Seek for FileReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut reader = self.input.borrow_mut();
        match &mut *reader {
            Input::File(file) => file.seek(pos),
            Input::Buff(cursor) => cursor.seek(pos),
        }
    }
}
