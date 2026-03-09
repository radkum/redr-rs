mod error;

use std::collections::VecDeque;

use common_um::{redr, redr::ArcMut};
pub use error::ExtractError;
pub trait FileExtractor {
    fn extract_files(
        &self,
        file: redr::FileReader,
        original_file: ArcMut<redr::FileInfo>,
        queue: &mut VecDeque<redr::FileReaderAndInfo>,
    ) -> Result<(), ExtractError>;
}
