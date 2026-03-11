mod error;

use std::collections::VecDeque;

pub use error::ExtractError;
use utils::{redr, redr::ArcMut};
pub trait FileExtractor {
    fn extract_files(
        &self,
        file: redr::FileReader,
        original_file: ArcMut<redr::FileInfo>,
        queue: &mut VecDeque<redr::FileReaderAndInfo>,
    ) -> Result<(), ExtractError>;
}
