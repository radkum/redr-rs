pub(crate) fn start_detection(sig_store_path: &str) -> anyhow::Result<()> {
    log::debug!("sig_store_path: {}", sig_store_path);
    let sig_store = signatures::deserialize_sig_store_from_path(sig_store_path)?;
    let sig_store2 = signatures::deserialize_sig_store_from_path(sig_store_path)?;
    detection::start_detection(sig_store, sig_store2);
    Ok(())
}
