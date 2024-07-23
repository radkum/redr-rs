extern crate core;

pub mod error;
pub mod sig_store;

use crate::{error::SigSetError, sig_store::SignatureStore};

pub fn deserialize_sig_store<R: std::io::Read>(
    io_reader: R,
) -> Result<SignatureStore, SigSetError> {
    SignatureStore::deserialize(io_reader)
}

pub fn deserialize_sig_store_from_path(set_path: &str) -> Result<SignatureStore, SigSetError> {
    let file = std::fs::File::open(set_path)?;
    deserialize_sig_store(file)
}

pub fn create_sig_store_from_path(set_path: &str) -> Result<SignatureStore, SigSetError> {
    SignatureStore::from_path(set_path)
}

pub fn create_sig_store_from_string_vec(vec: Vec<String>) -> Result<SignatureStore, SigSetError> {
    SignatureStore::from_string_vec(vec)
}

pub fn seralize_sig_store<W: std::io::Write>(
    sig_store: SignatureStore,
    out: &mut W,
) -> Result<usize, SigSetError> {
    sig_store.serialize(out)
}

pub fn seralize_sig_store_to_file(
    sig_store: SignatureStore,
    out_path: &str,
) -> Result<usize, SigSetError> {
    let mut file = std::fs::File::create(out_path)?;
    seralize_sig_store(sig_store, &mut file)
}
