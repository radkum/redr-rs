use super::{Deserializer, Event, Serializer};
use crate::{
    hasher::MemberHasher,
    utils::{sha256_from_bytes, Sha256Buff},
};
use alloc::{collections::TryReserveError, format, string::String, vec::Vec};
use core::mem;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct ImageLoadEvent {
    pid: u32,
    image_base: u64,
    image_size: u64,
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YamlImageLoadEvent {
    pid: Option<u32>,
    image_base: Option<u64>,
    image_size: Option<u64>,
    path: Option<String>,
}

impl From<YamlImageLoadEvent> for ImageLoadEvent {
    fn from(yaml: YamlImageLoadEvent) -> Self {
        Self {
            pid: yaml.pid.unwrap_or_default(),
            image_base: yaml.image_base.unwrap_or_default(),
            image_size: yaml.image_size.unwrap_or_default(),
            path: yaml.path.unwrap_or_default(),
        }
    }
}

impl ImageLoadEvent {
    pub fn new(pid: u32, image_base: u64, image_size: u64, path: String) -> Self {
        Self {
            pid,
            image_base,
            image_size,
            path,
        }
    }
}

impl Event for ImageLoadEvent {
    //"DLL " as u32-> 44 4C 4C 20
    const EVENT_CLASS: u32 = 0x204C4C44;
}

impl<'a> Serializer for ImageLoadEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32
            + mem::size_of::<u64>() as u32
            + mem::size_of::<u64>() as u32
            + self.path.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        let v_len = self.blob_size() as usize;
        v.try_reserve_exact(v_len)?;

        v.append(&mut self.pid.to_blob()?);
        v.append(&mut self.image_base.to_blob()?);
        v.append(&mut self.image_size.to_blob()?);
        v.append(&mut self.path.to_blob()?);

        Ok(v)
    }
}

impl<'a> Deserializer for ImageLoadEvent {
    fn from_blob(bytes: &[u8]) -> Self {
        let pid = u32::from_blob(bytes);
        let bytes = &bytes[4..];

        let image_base = u64::from_blob(bytes);
        let bytes = &bytes[8..];

        let image_size = u64::from_blob(bytes);
        let bytes = &bytes[8..];

        let path = String::from_blob(bytes);
        Self {
            pid,
            image_base,
            image_size,
            path,
        }
    }
}

impl MemberHasher for ImageLoadEvent {
    const EVENT_NAME: &'static str = "ImageLoad";

    fn hash_members(&self) -> Vec<Sha256Buff> {
        let mut v = Vec::new();

        if self.pid != 0 {
            let pid = format!("{}+{}+{}", Self::EVENT_NAME, "pid", self.pid);
            v.push(sha256_from_bytes(pid.as_bytes()));
        }

        if self.image_base != 0 {
            let image_base = format!("{}+{}+{}", Self::EVENT_NAME, "image_base", self.image_base);
            v.push(sha256_from_bytes(image_base.as_bytes()));
        }

        if self.image_size != 0 {
            let image_size = format!("{}+{}+{}", Self::EVENT_NAME, "image_size", self.image_size);
            v.push(sha256_from_bytes(image_size.as_bytes()));
        }

        if !self.path.is_empty() {
            let path = format!("{}+{}+{}", Self::EVENT_NAME, "path", self.path);
            v.push(sha256_from_bytes(path.as_bytes()));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::event::get_event_type;
    use alloc::string::ToString;

    #[test]
    fn simple() {
        let e1 = ImageLoadEvent::new(123, 234, 345, "elo mordo".to_string());
        let event_buff = e1.serialize().unwrap();

        let event_type = get_event_type(event_buff.as_slice());
        assert_eq!(event_type, ImageLoadEvent::EVENT_CLASS);

        let e2 = ImageLoadEvent::deserialize(event_buff.as_slice()).unwrap();
        assert_eq!(e1.pid, e2.pid);
        assert_eq!(e1.image_size, e2.image_size);
        assert_eq!(e1.image_base, e2.image_base);
        assert_eq!(e1.path, e2.path);
    }
}
