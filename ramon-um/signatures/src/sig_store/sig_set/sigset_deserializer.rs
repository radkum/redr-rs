use std::mem::size_of;

use common_um::sha256_utils::Sha256Buff;
use sha2::Digest;

use super::{
    heuristic_set::HeurSet,
    sha_set::ShaSet,
    signature::{SerSigHeader, Signature},
    sigset_serializer::BIN_CONFIG,
    SigSetHeader, SigSetTrait,
};
use crate::{sig_store::sig_set::SigSetType, SigSetError};

#[derive(Debug)]
pub(crate) struct SigSetDeserializer {
    ser_set_header: SigSetHeader,
    data: Vec<u8>,
}

impl SigSetDeserializer {
    // 4 MB
    const MAX_BUF_LEN: u64 = 0x400000;

    // pub fn new_from_file(name: &str) -> Result<Self, SigSetError> {
    //     let mut file = std::fs::File::open(name)?;
    //     let metadata = file.metadata()?;
    //
    //     if metadata.len() > Self::MAX_BUF_LEN {
    //         return Err(SigSetError::IncorrectFileSizeError { size: metadata.len() });
    //     }
    //
    //     let mut buffer = vec![0; metadata.len() as usize];
    //     let _ = file.read(&mut buffer)?;
    //
    //     Self::new_with_buffer(&mut buffer)
    // }

    pub(crate) fn new_with_buffer(data: &mut Vec<u8>) -> Result<Self, SigSetError> {
        if data.len() < SigSetHeader::HEADER_SIZE {
            return Err(SigSetError::IncorrectFileSizeError { size: data.len() as u64 });
        }
        let set_header_data = data.drain(..SigSetHeader::HEADER_SIZE).collect::<Vec<u8>>();
        let set_header: SigSetHeader =
            bincode::serde::decode_from_slice(&set_header_data, BIN_CONFIG)?.0;

        set_header.verify_magic()?;

        let sig_set_data = data.drain(..set_header.size() as usize).collect::<Vec<u8>>();

        let reader = Self { ser_set_header: set_header, data: sig_set_data };
        reader.verify_checksum()?;

        Ok(reader)
    }

    fn verify_checksum(&self) -> Result<(), SigSetError> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.ser_set_header.size.to_le_bytes());
        hasher.update(&self.ser_set_header.elem_count.to_le_bytes());
        hasher.update(&self.data);
        let mut checksum_buf = Sha256Buff::default();
        checksum_buf.copy_from_slice(&hasher.finalize()[..]);
        if self.ser_set_header.checksum != checksum_buf {
            return Err(SigSetError::IncorrectChecksumError {
                current: hex::encode(checksum_buf),
                expected: hex::encode(self.ser_set_header.checksum),
            });
        }
        Ok(())
    }

    pub(crate) fn get_set_box(&self) -> Result<(Box<dyn SigSetTrait>, SigSetType), SigSetError> {
        match self.ser_set_header.magic {
            HeurSet::HEUR_MAGIC_U32 => {
                Ok((Box::new(self.get_set::<HeurSet>()?), SigSetType::Heuristic))
            },
            ShaSet::SET_MAGIC_U32 => Ok((Box::new(self.get_set::<ShaSet>()?), SigSetType::Sha)),
            HeurSet::DYN_MAGIC_U32 => {
                Ok((Box::new(self.get_set::<HeurSet>()?), SigSetType::Dynamic))
            },
            HeurSet::BEH_MAGIC_U32 => {
                Ok((Box::new(self.get_set::<HeurSet>()?), SigSetType::Behavioral))
            },
            _ => Err(SigSetError::IncorrectMagicError {
                current: String::from_utf8_lossy(&self.ser_set_header.magic.to_le_bytes()).into(),
            }),
        }
    }

    fn get_set<SigSet: SigSetTrait>(&self) -> Result<SigSet, SigSetError> {
        let elem_count = self.ser_set_header.elem_count as usize;
        let signature_header_size = size_of::<SerSigHeader>();
        let start_of_data = elem_count * signature_header_size;

        let mut signature_set = SigSet::new_empty(self.ser_set_header.magic);
        for i in 0..elem_count {
            let curr_header_offset = i * signature_header_size;

            let sig_header: SerSigHeader =
                bincode::serde::decode_from_slice(&self.data[curr_header_offset..], BIN_CONFIG)?.0;

            log::debug!("sig_header: {:?}", sig_header);

            if sig_header.size > Self::MAX_BUF_LEN as u32 {
                return Err(SigSetError::IncorrectSignatureSizeError { size: sig_header.size });
            }

            let start_offset = sig_header.offset as usize + start_of_data;
            let end_offset = start_offset + sig_header.size as usize;

            if end_offset > self.data.len() {
                return Err(SigSetError::IncorrectSignatureSizeError { size: sig_header.size });
            }

            let (signature, _): (Signature, usize) = bincode::serde::decode_from_slice(
                &self.data[start_offset..end_offset],
                BIN_CONFIG,
            )?;

            signature_set.append_signature(i as u32, signature);
        }

        Ok(signature_set)
    }
}
