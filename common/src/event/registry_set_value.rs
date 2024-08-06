use super::{Deserializer, Event, Serializer};
use crate::{
    deserializer::DeserializerWithSize,
    hasher::{member_to_hash, MemberHasher},
    utils::Sha256Buff,
};
use alloc::{collections::TryReserveError, string::String, vec::Vec};
use core::mem;
use serde::{Deserialize, Serialize};
use crate::cleaning_info::CleaningInfo;
use crate::enums::RegType;

#[derive(Debug)]
pub struct RegistrySetValueEvent {
    pid: u32,
    tid: u32,
    key_name: String,
    value_name: String,
    data_type: u32,
    data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YamlRegistrySetValueEvent {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub key_name: Option<String>,
    pub value_name: Option<String>,
    pub data_type: Option<u32>,
    //pub data: Option<Vec<u8>>,
    pub data: Option<String>,
}

impl From<YamlRegistrySetValueEvent> for RegistrySetValueEvent {
    fn from(yaml: YamlRegistrySetValueEvent) -> Self {
        Self {
            pid: yaml.pid.unwrap_or_default(),
            tid: yaml.tid.unwrap_or_default(),
            key_name: yaml.key_name.unwrap_or_default(),
            value_name: yaml.value_name.unwrap_or_default(),
            data_type: yaml.data_type.unwrap_or_default(),
            data: yaml.data.unwrap_or_default().into()
        }
    }
}

impl RegistrySetValueEvent {
    pub fn new(
        pid: u32,
        tid: u32,
        key_name: String,
        value_name: String,
        data_type: u32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            pid,
            tid,
            key_name,
            value_name,
            data_type,
            data,
        }
    }

    pub fn data_as_string(&self) -> Option<String> {
        //todo: support more types
        let data_type = RegType::from(self.data_type);
        if !data_type.is_string() {
            return None;
        }

        let data = self.data.clone();

        let data_u16: &[u16] =
            unsafe { core::slice::from_raw_parts(data.as_ptr() as *const u16, data.len() / 2) };

        let mut s = String::new();
        s.reserve(data_u16.len());
        for e in data_u16 {
            if *e == 0 {
                break;
            }
            s.push(*e as u8 as char);
        }
        Some(s)
    }

    pub fn data_as_string2(&self) -> Option<String> {
        //todo: support more types
        let data_type = RegType::from(self.data_type);
        if !data_type.is_string() {
            return None;
        }

        let data = self.data.clone();

        let mut s = String::new();
        s.reserve(data.len());
        for e in data {
            if e == 0 {
                break;
            }
            s.push(e as char);
        }
        Some(s)
    }
}

impl Event for RegistrySetValueEvent {
    //"REG " as u32-> 52 45 47 20
    const EVENT_CLASS: u32 = 0x20474552;
}

impl<'a> Serializer for RegistrySetValueEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32
            + mem::size_of::<u32>() as u32
            + self.key_name.blob_size()
            + mem::size_of::<u32>() as u32
            + self.value_name.blob_size()
            + self.data.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        let v_len = self.blob_size() as usize;
        v.try_reserve_exact(v_len)?;

        v.append(&mut self.pid.to_blob()?);
        v.append(&mut self.tid.to_blob()?);
        v.append(&mut self.key_name.to_blob()?);
        v.append(&mut self.value_name.to_blob()?);
        v.append(&mut self.data_type.to_blob()?);
        v.append(&mut self.data.to_blob()?);

        Ok(v)
    }
}

impl<'a> Deserializer for RegistrySetValueEvent {
    fn from_blob(bytes: &[u8]) -> Self {
        let pid = u32::from_blob(bytes);
        let bytes = &bytes[4..];

        let tid = u32::from_blob(bytes);
        let bytes = &bytes[4..];

        let (key_name, shift) = String::from_blob_with_size(bytes);
        let bytes = &bytes[shift..];

        let (value_name, shift) = String::from_blob_with_size(bytes);
        let bytes = &bytes[shift..];

        let data_type = u32::from_blob(bytes);
        let bytes = &bytes[4..];

        let data = Vec::<u8>::from_blob(bytes);

        Self {
            pid,
            tid,
            key_name,
            value_name,
            data_type,
            data,
        }
    }
}

impl MemberHasher for RegistrySetValueEvent {
    const EVENT_NAME: &'static str = "RegSetValue";

    fn hash_members(&self) -> Vec<Sha256Buff> {
        let mut v = Vec::new();

        if self.pid != 0 {
            let pid = member_to_hash(Self::EVENT_NAME, "pid", self.pid);
            v.push(pid);
        }

        if self.tid != 0 {
            let tid = member_to_hash(Self::EVENT_NAME, "tid", self.tid);
            v.push(tid);
        }

        if !self.key_name.is_empty() {
            let key_name = member_to_hash(Self::EVENT_NAME, "key_name", self.key_name.clone());
            v.push(key_name);
        }

        if !self.value_name.is_empty() {
            let value_name = member_to_hash(Self::EVENT_NAME, "value_name", self.value_name.clone());
            v.push(value_name);
        }

        if self.data_type != 0 {
            let data_type = member_to_hash(Self::EVENT_NAME, "data_type", self.data_type);
            v.push(data_type);
        }

        //todo: parse not only strings
        if let Some(data) = self.data_as_string() {
            log::debug!("data_as_string: {}", &data);
            if !data.is_empty() {
                let data = member_to_hash(Self::EVENT_NAME, "data", data.clone());
                v.push(data);
            }
        }
        v
    }
}

impl CleaningInfo for RegistrySetValueEvent {
    fn get_pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::event::get_event_type;
    use alloc::{string::ToString, vec};

    #[test]
    fn simple() {
        let e1 = RegistrySetValueEvent::new(
            123,
            234,
            "key name".to_string(),
            "value_name".to_string(),
            345,
            vec![1, 8, 7, 4],
        );
        let event_buff = e1.serialize().unwrap();

        std::println!("{e1:?}");
        let event_type = get_event_type(event_buff.as_slice());
        assert_eq!(event_type, RegistrySetValueEvent::EVENT_CLASS);

        let e2 = RegistrySetValueEvent::deserialize(event_buff.as_slice()).unwrap();
        std::println!("{e2:?}");
        assert_eq!(e1.pid, e2.pid);
        assert_eq!(e1.tid, e2.tid);
        assert_eq!(e1.key_name, e2.key_name);
        assert_eq!(e1.value_name, e2.value_name);
        assert_eq!(e1.data_type, e2.data_type);
        assert_eq!(e1.data, e2.data);
    }

    #[test]
    fn hash_test() {
        let e1 = RegistrySetValueEvent::new(
            123,
            234,
            "key name".to_string(),
            "value_name".to_string(),
            345,
            vec![0x65, 0x6C, 0x6F, 0x20, 0x0, 0x0, 0x0, 0x0],
        );
        let v = e1.hash_members();
        assert_eq!(
            v[0],
            [
                84, 206, 227, 212, 1, 254, 12, 72, 89, 14, 153, 91, 71, 68, 184, 166, 163, 0, 227,
                153, 33, 253, 197, 63, 127, 55, 110, 14, 114, 191, 150, 20
            ]
        );
    }
}
