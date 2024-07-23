use std::{collections::VecDeque, io::Read};

use common_um::{redr, redr::RcMut};
use shared_arcom::{ExtractError, FileExtractor};

pub struct OleExtractor {}

impl FileExtractor for OleExtractor {
    fn extract_files(
        &self,
        file: redr::FileReader,
        original_file: RcMut<redr::FileInfo>,
        queue: &mut VecDeque<redr::FileReaderAndInfo>,
    ) -> Result<(), ExtractError> {
        let parser = ole::Reader::new(file)?;

        for entry in parser.iterate() {
            if entry.name() == "Root Entry" {
                //todo why reading a root entry fails?
                continue;
            }

            let mut file = if let Ok(file) = parser.get_entry_slice(entry) {
                file
            } else {
                //empty slice
                //todo!()
                continue;
            };

            log::trace!("{}, {}, len: {}", entry.name(), entry._type(), entry.len());
            let mut buffer = Vec::new();
            let size = file.read_to_end(&mut buffer)?;
            if file.len() != size {
                //return Err()
                todo!()
            }
            // std::fs::write("trash\\".to_owned() + entry.name(), buffer.clone())?;
            let reader = redr::FileReader::from_buff(std::io::Cursor::new(buffer));
            queue.push_front((
                reader,
                redr::FileScanInfo::embedded_file(original_file.clone(), entry.name()),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
