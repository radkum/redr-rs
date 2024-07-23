use crate::{event::EventHeader, utils::align};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::mem;

pub trait Deserializer {
    fn from_blob(bytes: &[u8]) -> Self;
}

impl<'a> Deserializer for EventHeader {
    fn from_blob(bytes: &[u8]) -> Self {
        let (class, size) = bytes.split_at(4);
        let event_class = u32::from_blob(class);
        let event_size = u32::from_blob(size);
        Self {
            event_class,
            event_size,
        }
    }
}

impl<'a> Deserializer for u32 {
    fn from_blob(bytes: &[u8]) -> Self {
        const BYTES_LEN: usize = 4;
        let mut buff: [u8; BYTES_LEN] = [0u8; BYTES_LEN];
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buff.as_mut_ptr(), BYTES_LEN) };
        u32::from_le_bytes(buff)
    }
}

impl<'a> Deserializer for u64 {
    fn from_blob(bytes: &[u8]) -> Self {
        const BYTES_LEN: usize = 8;
        let mut buff: [u8; BYTES_LEN] = [0u8; BYTES_LEN];
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buff.as_mut_ptr(), BYTES_LEN) };
        u64::from_le_bytes(buff)
    }
}

impl<'a> Deserializer for String {
    fn from_blob(bytes: &[u8]) -> Self {
        //string len as u32 and then char array
        let (size, chars) = bytes.split_at(4);
        let size = u32::from_blob(size);
        let mut s = string_from_bytes(size as usize, chars);
        if s.ends_with("\0") {
            s.pop();
        }
        s
    }
}

impl<'a> Deserializer for Vec<u8> {
    fn from_blob(bytes: &[u8]) -> Self {
        let (size, chars) = bytes.split_at(4);
        let size = u32::from_blob(size) as usize;
        chars[0..size].to_vec()
    }
}

#[allow(private_bounds)]
pub(crate) trait DeserializerWithSize {
    fn from_blob_with_size(bytes: &[u8]) -> (Self, usize)
    where
        Self: Sized;
}

impl<'a> DeserializerWithSize for String {
    fn from_blob_with_size(bytes: &[u8]) -> (Self, usize) {
        //string len as u32 and then char array
        let (size, chars) = bytes.split_at(4);
        let size = u32::from_blob(size) as usize;
        let mut s = string_from_bytes(size as usize, chars);
        if s.ends_with("\0") {
            s.pop();
        }
        (s, align(size) as usize + mem::size_of::<u32>())
    }
}

impl<'a> DeserializerWithSize for Vec<u8> {
    fn from_blob_with_size(bytes: &[u8]) -> (Self, usize) {
        let (size, chars) = bytes.split_at(4);
        let size = u32::from_blob(size) as usize;
        (chars[0..size].to_vec(), size + mem::size_of::<u32>())
    }
}

//helper
fn string_from_bytes(size: usize, bytes: &[u8]) -> String {
    let mut v = Vec::with_capacity(size);
    v.resize(size, 0u8);
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), v.as_mut_ptr(), size) };
    String::from_utf8(v).unwrap_or("Something wrong".to_string())
}