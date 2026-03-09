use std::{
    io::{Seek, SeekFrom},
    mem::size_of,
};

use common_um::{detection_report::DetectionReport, redr, sha256_utils::Sha256Buff};
use serde::{Deserialize, Serialize};

pub mod sig_set;

use sig_set::{
    heuristic_set::HeurSet,
    sha_set::ShaSet,
    signature::{yaml_signature::YamlSignature, SigData, Signature},
    sigset_deserializer::SigSetDeserializer,
    sigset_serializer::BIN_CONFIG,
    SigSetTrait,
};

use crate::{sig_store::sig_set::SigSetType, SigSetError};

#[derive(Debug, Serialize, Deserialize)]
struct StoreHeader {
    magic: u32,
    elem_count: u32,
}

impl StoreHeader {
    pub(crate) const HEADER_SIZE: usize = size_of::<StoreHeader>();
    const STORE_MAGIC_U32: u32 = 0x5445354D;

    //M5ET
    //const SHASET_MAGIC: [u8; 4] = [0x4D, 0x35, 0x45, 0x54]; //M5ET

    pub fn new(elem_count: u32) -> Self {
        Self { magic: Self::STORE_MAGIC_U32, elem_count }
    }

    pub(crate) fn verify_magic(&self) -> Result<(), SigSetError> {
        if Self::STORE_MAGIC_U32 != self.magic {
            return Err(SigSetError::IncorrectMagicError {
                current: String::from_utf8_lossy(&self.magic.to_le_bytes()).into(),
            });
        }
        Ok(())
    }

    #[inline]
    pub fn elem_count(&self) -> u32 {
        self.elem_count
    }
}

pub struct SignatureStore {
    sigset_vec: Vec<Box<dyn SigSetTrait>>,
    sandbox_set: Option<Box<dyn SigSetTrait>>,
    behavioural_set: Option<Box<dyn SigSetTrait>>,
}

impl SignatureStore {
    pub(crate) fn new(
        sigset_vec: Vec<Box<dyn SigSetTrait>>,
        sandbox_set: Option<Box<dyn SigSetTrait>>,
        behavioural_set: Option<Box<dyn SigSetTrait>>,
    ) -> Self {
        Self { sigset_vec, sandbox_set, behavioural_set }
    }

    pub fn eval_sandboxed_file(
        &self,
        sha_vec: Vec<Sha256Buff>,
    ) -> Result<Option<DetectionReport>, SigSetError> {
        if let Some(box_set) = &self.sandbox_set {
            box_set.eval_vec(sha_vec)
        } else {
            Ok(None)
        }
    }

    pub fn eval_vec(&self, vec: Vec<Sha256Buff>) -> Result<Option<DetectionReport>, SigSetError> {
        if let Some(set) = &self.behavioural_set {
            set.eval_vec(vec)
        } else {
            Ok(None)
        }
    }

    pub fn eval_file(
        &self,
        file: &mut redr::FileReader,
    ) -> Result<Option<DetectionReport>, SigSetError> {
        for sig_set in self.sigset_vec.iter() {
            file.seek(SeekFrom::Start(0))?;
            if let Some(detection) = sig_set.eval_file(file)? {
                return Ok(Some(detection));
            }
        }
        Ok(None)
    }

    fn get_signatures_from_path(
        path_to_dir: &std::path::Path,
        signatures: &mut Vec<Signature>,
    ) -> Result<(), SigSetError> {
        let paths = std::fs::read_dir(path_to_dir)?;

        for entry_res in paths {
            let entry = entry_res?;
            //log::trace!("path: {:?}", &path);
            if entry.file_type()?.is_file() {
                let f = std::fs::File::open(entry.path())?;

                let yaml_sig: YamlSignature = serde_yaml::from_reader(&f).unwrap();
                //let yaml_sig: YamlSignature = serde_yaml::from_reader(&f)?;
                log::trace!("{:?}", yaml_sig);

                signatures.push(Signature::from_yaml(yaml_sig)?);
            } else if entry.file_type()?.is_dir() {
                Self::get_signatures_from_path(entry.path().as_path(), signatures)?
            }
        }
        Ok(())
    }

    pub(crate) fn from_path(path_to_dir: &str) -> Result<Self, SigSetError> {
        let mut signatures = vec![];
        let path = std::path::Path::new(path_to_dir);
        Self::get_signatures_from_path(path, &mut signatures)?;
        Self::from_yaml_signatures(signatures)
    }

    pub(crate) fn from_string_vec(vec: Vec<String>) -> Result<Self, SigSetError> {
        let mut signatures = vec![];
        for s in vec {
            let yaml_sig: YamlSignature = serde_yaml::from_str(&s).unwrap();
            signatures.push(Signature::from_yaml(yaml_sig)?);
        }
        Self::from_yaml_signatures(signatures)
    }

    fn from_yaml_signatures(signatures: Vec<Signature>) -> Result<Self, SigSetError> {
        let mut sha_set = ShaSet::new_empty(ShaSet::SET_MAGIC_U32);
        let mut heur_set = HeurSet::new_empty(HeurSet::HEUR_MAGIC_U32);
        let mut dyn_set = HeurSet::new_empty(HeurSet::DYN_MAGIC_U32);
        let mut beh_set = HeurSet::new_empty(HeurSet::BEH_MAGIC_U32);

        let mut sig_id = 0;
        for sig in signatures {
            match sig.sig_data() {
                SigData::Sha(..) => sha_set.append_signature(sig_id, sig),
                SigData::Imports(..) => heur_set.append_signature(sig_id, sig),
                SigData::Calls(..) => dyn_set.append_signature(sig_id, sig),
                SigData::Event(..) => beh_set.append_signature(sig_id, sig),
            }
            sig_id += 1;
        }

        let mut sigset_vec = Vec::<Box<dyn SigSetTrait>>::new();
        let mut box_dyn_set: Option<Box<dyn SigSetTrait>> = None;
        let mut box_beh_set: Option<Box<dyn SigSetTrait>> = None;
        //let mut sigset_vec = Vec::<Box<dyn SigSetTrait>>::new();

        if sha_set.signatures_number() > 0 {
            sigset_vec.push(Box::new(sha_set));
        }

        if heur_set.signatures_number() > 0 {
            sigset_vec.push(Box::new(heur_set));
        }

        if dyn_set.signatures_number() > 0 {
            box_dyn_set = Some(Box::new(dyn_set));
        }

        if beh_set.signatures_number() > 0 {
            box_beh_set = Some(Box::new(beh_set));
        }

        log::info!("sig store size: {}", sig_id);
        Ok(Self::new(sigset_vec, box_dyn_set, box_beh_set))
    }

    pub(crate) fn deserialize<R: std::io::Read>(mut io_reader: R) -> Result<Self, SigSetError> {
        let mut data = vec![];
        let _size = io_reader.read_to_end(&mut data)?;
        Self::deserialize_vec(&mut data)
    }

    pub(crate) fn deserialize_vec(data: &mut Vec<u8>) -> Result<Self, SigSetError> {
        if data.len() < StoreHeader::HEADER_SIZE {
            return Err(SigSetError::IncorrectFileSizeError { size: data.len() as u64 });
        }

        let store_header_data = data.drain(..StoreHeader::HEADER_SIZE).collect::<Vec<u8>>();
        let store_header: StoreHeader =
            bincode::serde::decode_from_slice(&store_header_data, BIN_CONFIG)?.0;

        store_header.verify_magic()?;

        let mut sigset_vec = vec![];
        let mut sandbox_set = None;
        let mut behavioral_set = None;
        for _ in 0..store_header.elem_count() {
            let des = SigSetDeserializer::new_with_buffer(data)?;
            let (box_sig_set, sha_type) = des.get_set_box()?;
            match sha_type {
                SigSetType::Sha | SigSetType::Heuristic => sigset_vec.push(box_sig_set),
                SigSetType::Dynamic => sandbox_set = Some(box_sig_set),
                SigSetType::Behavioral => behavioral_set = Some(box_sig_set),
            }
        }

        Ok(Self::new(sigset_vec, sandbox_set, behavioral_set))
    }

    pub(crate) fn serialize<W: std::io::Write>(&self, out: &mut W) -> Result<usize, SigSetError> {
        let mut sigset_ref_vec: Vec<_> = self.sigset_vec.iter().collect();
        if let Some(sandbox_set) = &self.sandbox_set {
            sigset_ref_vec.push(sandbox_set);
        }
        if let Some(behavioural_set) = &self.behavioural_set {
            sigset_ref_vec.push(behavioural_set);
        }

        let store_header = StoreHeader::new(sigset_ref_vec.len() as u32);
        let header_vec = bincode::serde::encode_to_vec(&store_header, BIN_CONFIG)?;
        out.write_all(&header_vec)?;

        let mut serialized_sigs = 0;
        for sigset in sigset_ref_vec.iter() {
            let size = sigset.to_set_serializer().serialize(out)?;
            serialized_sigs += size;
        }

        Ok(serialized_sigs)
    }
}
