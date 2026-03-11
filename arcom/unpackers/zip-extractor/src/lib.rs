use std::{collections::VecDeque, io::Read};

use shared_arcom::{ExtractError, FileExtractor};
use utils::{redr, redr::ArcMut};

pub struct ZipExtractor {}

impl FileExtractor for ZipExtractor {
    fn extract_files(
        &self,
        file: redr::FileReader,
        original_file: ArcMut<redr::FileInfo>,
        queue: &mut VecDeque<redr::FileReaderAndInfo>,
    ) -> Result<(), ExtractError> {
        let mut archive = zip::ZipArchive::new(file).unwrap();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            //let file_reader = redr::FileReader::from_zip_file(file);
            let mut buffer = Vec::new();
            let size = file.read_to_end(&mut buffer)?;
            if file.size() as usize != size {
                log::error!("{}, {}", file.size(), size);
                todo!()
            }
            let reader = redr::FileReader::from_buff(std::io::Cursor::new(buffer));
            queue.push_front((
                reader,
                redr::FileScanInfo::embedded_file(original_file.clone(), file.name()),
            ));

            // let outpath = match file.name() {
            //     Some(path) => path.to_owned(),
            //     None => continue,
            // };
            log::trace!("{:?}", file.name());
        }

        Ok(())
    }
}
