use std::mem::size_of;

use common_um::{detection::DetectionReport, redr, sha256_utils::Sha256Buff};
use heuristic_set::HeurSet;
use serde::{Deserialize, Serialize};
use sha_set::ShaSet;
use signature::{SigId, Signature};
use sigset_serializer::SigSetSerializer;

use crate::SigSetError;

pub mod heuristic_set;
pub mod sha_set;
pub mod signature;
pub mod sigset_deserializer;
pub mod sigset_serializer;

pub(crate) type Description = String;
pub(crate) type SigName = String;

#[derive(Debug, Serialize, Deserialize)]
struct SigSetHeader {
    magic: u32,
    checksum: Sha256Buff,
    size: u32,
    elem_count: u32,
}

impl SigSetHeader {
    pub(crate) const HEADER_SIZE: usize = size_of::<SigSetHeader>();
    const MAGIC_LIST: [u32; 4] = [
        ShaSet::SET_MAGIC_U32,
        HeurSet::HEUR_MAGIC_U32,
        HeurSet::DYN_MAGIC_U32,
        HeurSet::BEH_MAGIC_U32,
    ];

    pub(crate) fn verify_magic(&self) -> Result<(), SigSetError> {
        if !Self::MAGIC_LIST.contains(&self.magic) {
            return Err(SigSetError::IncorrectMagicError {
                current: String::from_utf8_lossy(&self.magic.to_le_bytes()).into(),
            });
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn size(&self) -> u32 {
        self.size
    }
}

//pub(crate) trait SigSetTrait {
use downcast_rs::DowncastSync;

pub(crate) trait SigSetTrait: DowncastSync {
    fn append_signature(&mut self, id: SigId, signature: Signature);

    fn signatures_number(&self) -> usize;

    fn eval_file(
        &self,
        file: &mut redr::FileReader,
    ) -> Result<Option<DetectionReport>, SigSetError>;

    fn eval_vec(&self, vec: Vec<Sha256Buff>) -> Result<Option<DetectionReport>, SigSetError>;

    fn new_empty(magic: u32) -> Self
    where
        Self: Sized;

    fn to_set_serializer(&self) -> SigSetSerializer;
}
downcast_rs::impl_downcast!(SigSetTrait);

pub(crate) enum SigSetType {
    Sha,
    Heuristic,
    Dynamic,
    Behavioral,
}
