use crate::{event::EventHeader, utils::align};
use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::mem;

pub trait Serializer {
    fn blob_size(&self) -> u32;
    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError>;
}

impl<'a> Serializer for String {
    fn blob_size(&self) -> u32 {
        //string len as u32 and then char array
        const NULL_CHAR_LEN: usize = 1;
        align(self.len() + NULL_CHAR_LEN) + mem::size_of::<u32>() as u32
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        let v_len = self.blob_size() as usize;

        v.try_reserve_exact(v_len)?;
        v.resize(v_len, 0u8);

        let u32_len = self.len() as u32 + 1;
        v[0..mem::size_of::<u32>()].copy_from_slice(&u32_len.to_le_bytes());

        //push null at the end of string
        let mut s = self.clone();
        s.push('\0');

        let path_offset = mem::size_of::<u32>() as isize;
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), v.as_mut_ptr().offset(path_offset), s.len());
        }
        Ok(v)
    }
}

impl<'a> Serializer for EventHeader {
    fn blob_size(&self) -> u32 {
        align(Self::header_struct_size())
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_size() as usize)?;
        v.resize(self.blob_size() as usize, 0u8);

        let u32_size = mem::size_of::<u32>();

        v[0..u32_size].copy_from_slice(&self.event_class.to_le_bytes());
        v[u32_size..2 * u32_size].copy_from_slice(&self.event_size.to_le_bytes());
        Ok(v)
    }
}

impl<'a> Serializer for u32 {
    fn blob_size(&self) -> u32 {
        4
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_size() as usize)?;
        v.resize(self.blob_size() as usize, 0u8);
        v[0..mem::size_of::<u32>()].copy_from_slice(&self.to_le_bytes());
        Ok(v)
    }
}

impl<'a> Serializer for u64 {
    fn blob_size(&self) -> u32 {
        8
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.blob_size() as usize)?;
        v.resize(self.blob_size() as usize, 0u8);
        v[0..mem::size_of::<u64>()].copy_from_slice(&self.to_le_bytes());
        Ok(v)
    }
}

impl<'a> Serializer for Vec<u8> {
    fn blob_size(&self) -> u32 {
        //string len as u32 and then char array
        align(self.len()) + mem::size_of::<u32>() as u32
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = u32::to_blob(&(self.len() as u32))?;

        v.append(&mut self.clone());
        Ok(v)
    }
}
