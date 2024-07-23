use crate::utils::{convert_sha256_to_string, sha256_from_bytes, Sha256Buff};
use alloc::{format, vec::Vec};

pub trait MemberHasher {
    const EVENT_NAME: &'static str;

    fn hash_members(&self) -> Vec<Sha256Buff>;
}

pub fn member_to_hash<T: core::fmt::Display>(
    event_type: &str,
    attr_name: &str,
    attr_value: T,
) -> Sha256Buff {
    let attr = format!("{}+{}+{}", event_type, attr_name, attr_value);

    let sha_buff = sha256_from_bytes(attr.as_bytes());
    log::debug!(
        "member: \"{} -- {}\"",
        attr.to_lowercase(),
        convert_sha256_to_string(&sha_buff)
    );

    sha_buff
}
