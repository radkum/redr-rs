use std::{
    fmt::{Display, Formatter},
    path::PathBuf,
};

#[derive(Clone)]
pub struct FileInfo {
    pub name: String,
    pub path: PathBuf,
    pub canonical_path: String,
    pub sha256: Option<String>,
}

impl FileInfo {
    pub fn new(path: PathBuf) -> Self {
        let name: String = path.file_name().unwrap_or_default().to_string_lossy().into();
        let canonical_path: String =
            path.canonicalize().unwrap_or_default().to_string_lossy().into();

        Self { name, path, canonical_path, sha256: None }
    }
}

impl Display for FileInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileInfo: {{ name: {}, path: {} }}", self.name, self.canonical_path)
    }
}
