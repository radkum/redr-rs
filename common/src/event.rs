use alloc::{collections::TryReserveError, vec::Vec};
use core::mem;

pub mod file_create;
pub mod image_load;
pub mod process_create;
pub mod registry_set_value;

use crate::{deserializer::Deserializer, hasher::MemberHasher, serializer::Serializer};
pub use file_create::FileCreateEvent;

pub fn get_event_type(bytes: &[u8]) -> u32 {
    u32::from_blob(bytes)
}

pub trait Event: Serializer + Deserializer + MemberHasher {
    const EVENT_CLASS: u32;

    fn blob_with_header_size(&self) -> usize {
        EventHeader::EVENT_HEADER_SIZE + self.blob_size() as usize
    }

    fn serialize(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_with_header_size())?;

        let mut file_event_blob = self.to_blob()?;
        let header = EventHeader::new(Self::EVENT_CLASS, file_event_blob.len() as u32);
        v.append(&mut header.to_blob()?);

        v.append(&mut file_event_blob);
        Ok(v)
    }
    fn deserialize(bytes: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        let header = EventHeader::deserialize(bytes);
        if header.event_class != Self::EVENT_CLASS {
            return None;
        }
        let beg = EventHeader::EVENT_HEADER_SIZE;
        let end = EventHeader::EVENT_HEADER_SIZE + header.event_size as usize;
        Some(Self::from_blob(&bytes[beg..end]))
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub(crate) struct EventHeader {
    pub event_class: u32,
    pub event_size: u32,
}

impl EventHeader {
    const EVENT_HEADER_SIZE: usize = mem::size_of::<EventHeader>();

    pub fn deserialize(bytes: &[u8]) -> Self {
        EventHeader::from_blob(bytes)
    }

    pub fn new(event_class: u32, event_size: u32) -> Self {
        Self {
            event_class,
            event_size,
        }
    }

    pub fn header_struct_size() -> usize {
        Self::EVENT_HEADER_SIZE
    }

    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const u8 {
        self as *const Self as *const u8
    }

    #[allow(dead_code)]
    pub fn as_ref(&self) -> &Self {
        self
    }
}
