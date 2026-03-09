use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use crate::detection_report::DetectionReport;

pub type ArcMut<T> = Arc<RwLock<T>>;

use crate::redr::{malware_info::MalwareInfo, FileInfo};

pub enum FileScanInfo {
    RealFile(ArcMut<FileInfo>),
    EmbeddedFile {
        original_file: ArcMut<FileInfo>,
        //original_file: FileInfo,
        name: String,
    },
}

impl FileScanInfo {
    pub fn get_malware_info(&self, detection_info: DetectionReport) -> MalwareInfo {
        MalwareInfo(match self {
            FileScanInfo::RealFile(file) => {
                let name: String = file.read().unwrap().name.clone();
                //let path: String = file.borrow().canonical_path.clone();

                format!(
                    //"\"{name}\" -> Malicious {{ path: \"{path}\", desc: \"{}\", cause: {} }}",
                    "\"{name}\" -> Malicious {{ desc: \"{}\", cause: {} }}",
                    detection_info.desc, detection_info.cause
                )
            },
            FileScanInfo::EmbeddedFile { original_file: file, name } => {
                let original_name: String = file.read().unwrap().name.clone();
                //let path: String = file.borrow().canonical_path.clone();

                //let sha256 = file.borrow().sha256.clone().unwrap_or("UNKNOWN".to_string());

                let cause = format!(
                    "EmbeddedFile: {{ name: {name}, desc: \"{}\", cause: {} }}",
                    detection_info.desc, detection_info.cause
                );
                format!("\"{original_name}\" -> Malicious {{ cause: {cause} }}")
            },
        })
    }

    pub fn get_origin_file(&self) -> ArcMut<FileInfo> {
        match self {
            FileScanInfo::RealFile(rc) => rc.clone(),
            FileScanInfo::EmbeddedFile { original_file, name: _name } => original_file.clone(),
        }
    }

    pub fn get_name(&self) -> String {
        match self {
            FileScanInfo::RealFile(file) => {
                let name: String = file.read().unwrap().name.clone();
                name.to_string()
            },
            FileScanInfo::EmbeddedFile { original_file: _, name } => {
                //let original_name: String = file.borrow().name.clone();
                name.to_string()
            },
        }
    }

    pub fn get_path(&self) -> PathBuf {
        match self {
            FileScanInfo::RealFile(file)
            | FileScanInfo::EmbeddedFile { original_file: file, name: _ } => {
                file.read().unwrap().path.clone()
            },
        }
    }

    pub fn set_sha(&mut self, sha: String) {
        if let FileScanInfo::RealFile(rc) = self {
            rc.write().unwrap().sha256 = Some(sha);
        }
    }

    pub fn real_file(path: PathBuf) -> Self {
        Self::RealFile(Arc::new(RwLock::new(FileInfo::new(path))))
    }

    pub fn embedded_file(original_file: ArcMut<FileInfo>, name: &str) -> Self {
        Self::EmbeddedFile { original_file, name: name.to_string() }
    }
}
