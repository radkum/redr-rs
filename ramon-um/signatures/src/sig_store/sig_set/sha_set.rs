use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::DirEntry,
};

use common_um::{
    detection_report::DetectionReport,
    redr,
    sha256_utils::{sha256_from_path, Sha256Buff},
};

use super::{
    signature::{SigBase, SigData, SigId, Signature},
    sigset_serializer::{SigSetSerializer, BIN_CONFIG},
    Description, SigName, SigSetTrait,
};
use crate::SigSetError;

pub struct ShaSet {
    sha_list: BTreeSet<Sha256Buff>,
    sha_to_name: HashMap<Sha256Buff, SigName>,
    sha_to_description: HashMap<Sha256Buff, Description>,
}

impl ShaSet {
    const PROPERTY_DESC: &'static str = "description";
    //55ET
    //const SHASET_MAGIC: [u8; 4] = [0x35, 0x35, 0x45, 0x54]; //55ET

    const PROPERTY_NAME: &'static str = "name";
    const PROPERTY_SHA256: &'static str = "sha256";
    pub(crate) const SET_MAGIC_U32: u32 = 0x54453535;

    // pub(crate) fn new_empty() -> Self {
    //     Self {
    //         sha_list: Default::default(),
    //         sha_to_name: Default::default(),
    //         sha_to_description: Default::default(),
    //     }
    // }

    fn match_(&self, sha: &Sha256Buff) -> Result<Option<Signature>, SigSetError> {
        if self.sha_list.contains(sha) {
            let sig = Signature::new_sha(
                self.sha_to_name[sha].clone(),
                self.sha_to_description[sha].clone(),
                sha.clone(),
            );
            return Ok(Some(sig));
        }

        Ok(None)
    }

    pub fn from_dir(path_to_dir: &str) -> Result<ShaSet, SigSetError> {
        let paths = std::fs::read_dir(path_to_dir)?;

        let mut sha_set = ShaSet::new_empty(Self::SET_MAGIC_U32);

        let mut sig_id = 0;
        for entry_res in paths {
            let entry = entry_res?;
            //log::trace!("path: {:?}", &path);
            if entry.file_type()?.is_file() {
                let sha = sha256_from_path(entry.path().into_os_string().into_string()?.as_str())?;
                let sha_sig = Signature {
                    base: SigBase {
                        name: "Unknown".to_string(),
                        description: Self::create_file_info(&entry, &sha)?,
                    },
                    data: SigData::Sha(sha),
                };
                sha_set.append_signature(sig_id, sha_sig);
                sig_id += 1;
                log::trace!("path: {:?}", &entry);
            }
        }

        log::info!("shaset size: {}", sha_set.sha_list.len());
        Ok(sha_set)
    }

    fn create_file_info(path: &DirEntry, sha256: &Sha256Buff) -> Result<String, SigSetError> {
        Ok(format!(
            "{}: {}\n{}: {}\n{}: {:?}\n",
            Self::PROPERTY_NAME,
            path.file_name().into_string()?,
            Self::PROPERTY_SHA256,
            hex::encode_upper(&sha256),
            Self::PROPERTY_DESC,
            path.metadata()?
        ))
    }

    pub fn unpack_to_dir(&self, out_dir: &String) -> Result<usize, SigSetError> {
        let path = std::path::Path::new(&out_dir);
        for (sha, desc) in self.sha_to_description.iter() {
            let file_path = path.join(hex::encode_upper(&sha));
            std::fs::write(file_path, desc)?;
        }

        Ok(self.sha_to_description.len())
    }
}

impl SigSetTrait for ShaSet {
    fn append_signature(&mut self, _sig_id: SigId, sig_sha: Signature) {
        let SigData::Sha(sha) = sig_sha.data else { todo!() };

        self.sha_list.insert(sha);
        self.sha_to_description.insert(sha, sig_sha.description());
        self.sha_to_name.insert(sha, sig_sha.name());
    }

    fn signatures_number(&self) -> usize {
        self.sha_list.len()
    }

    fn eval_file(
        &self,
        file: &mut redr::FileReader,
    ) -> Result<Option<DetectionReport>, SigSetError> {
        let sha256 = common_um::sha256_utils::sha256_from_file_pointer(file)?;

        let sig_info = self.match_(&sha256)?;
        let desc_and_info = sig_info.map(|sig| sig.into());
        Ok(desc_and_info)
    }

    fn eval_vec(&self, sha_vec: Vec<Sha256Buff>) -> Result<Option<DetectionReport>, SigSetError> {
        let mut sha_vec = sha_vec;
        let Some(sha256) = sha_vec.pop() else {
            //something wrong
            return Ok(None);
        };

        let sig_info = self.match_(&sha256)?;
        let report = sig_info.map(|sig| sig.into());
        Ok(report)
    }

    fn new_empty(_magic: u32) -> Self
    where
        Self: Sized,
    {
        Self {
            sha_list: Default::default(),
            sha_to_name: Default::default(),
            sha_to_description: Default::default(),
        }
    }

    fn to_set_serializer(&self) -> SigSetSerializer {
        let mut ser = SigSetSerializer::new(Self::SET_MAGIC_U32);
        let sorted_map: BTreeMap<Sha256Buff, Description> =
            self.sha_to_description.clone().into_iter().collect();

        let mut sig_id = 0;
        for (sha, desc) in sorted_map {
            let name = self.sha_to_name.get(&sha).unwrap();
            let sig = Signature::new_sha(name.clone(), desc, sha);
            let serialized_data = bincode::serde::encode_to_vec(sig, BIN_CONFIG).unwrap();

            ser.serialize_signature(sig_id, serialized_data);
            sig_id += 1;
        }
        ser
    }
}
