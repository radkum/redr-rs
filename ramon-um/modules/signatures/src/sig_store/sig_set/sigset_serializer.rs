use std::mem::size_of;

use bincode::config::{Configuration, Fixint, LittleEndian, NoLimit};
use common_um::sha256_utils::Sha256Buff;
use sha2::Digest;

use super::{
    signature::{SerSigHeader, SigId},
    SigSetHeader,
};
use crate::SigSetError;

pub(crate) const BIN_CONFIG: Configuration<LittleEndian, Fixint, NoLimit> =
    bincode::config::legacy();

pub(crate) struct SigSetSerializer {
    magic: u32,
    sig_headers_vec: Vec<SerSigHeader>,
    curr_offset: u32,
    signatures: Vec<u8>,
}

impl SigSetSerializer {
    pub(crate) fn new(magic: u32) -> Self {
        Self { magic, sig_headers_vec: Vec::new(), curr_offset: 0, signatures: Vec::new() }
    }

    pub(crate) fn serialize_signature(&mut self, id: SigId, mut data: Vec<u8>) {
        self.sig_headers_vec.push(SerSigHeader {
            id,
            size: data.len() as u32,
            offset: self.curr_offset,
        });

        self.signatures.append(&mut data);
        self.curr_offset = self.signatures.len() as u32;
    }

    pub fn serialize<W: std::io::Write>(&self, out: &mut W) -> Result<usize, SigSetError> {
        //let mut file = std::fs::File::create(set_name)?;

        let mut checksum_buf = Sha256Buff::default();
        checksum_buf.copy_from_slice(&self.calculate_checksum()?);

        let set_header = SigSetHeader {
            magic: self.magic,
            checksum: checksum_buf,
            size: self.whole_size(),
            elem_count: self.sig_headers_vec.len() as u32,
        };

        let header = bincode::serde::encode_to_vec(&set_header, BIN_CONFIG)?;
        out.write_all(&header)?;

        //write info about each sig
        for sig_header in &self.sig_headers_vec {
            let data = bincode::serde::encode_to_vec(&sig_header, BIN_CONFIG)?;
            out.write_all(&data)?;
        }

        //write signatures to out
        out.write_all(&self.signatures)?;
        Ok(self.sig_headers_vec.len())
    }

    //headers and data size
    fn whole_size(&self) -> u32 {
        let signature_header_size = size_of::<SerSigHeader>();
        let headers_size = self.sig_headers_vec.len() * signature_header_size;
        let whole_size = self.signatures.len() + headers_size;
        whole_size as u32
    }

    fn calculate_checksum(&self) -> Result<Sha256Buff, SigSetError> {
        let mut hasher = sha2::Sha256::new();

        hasher.update(&self.whole_size().to_le_bytes());
        hasher.update(&(self.sig_headers_vec.len() as u32).to_le_bytes());

        for header in &self.sig_headers_vec {
            hasher.update(&bincode::serde::encode_to_vec(&header, BIN_CONFIG)?);
        }

        hasher.update(&self.signatures);
        Ok(hasher.finalize().into())
    }
}
