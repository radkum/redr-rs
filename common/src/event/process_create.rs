use super::{Deserializer, Event, Serializer};
use crate::{
    hasher::MemberHasher,
    utils::{sha256_from_bytes, Sha256Buff},
};
use alloc::{collections::TryReserveError, format, string::String, vec::Vec};
use core::mem;
use serde::{Deserialize, Serialize};
use crate::cleaning_info::CleaningInfoTrait;
use crate::event::Pid;

#[derive(Debug)]
pub struct ProcessCreateEvent {
    pid: u32,
    parent_id: u32,
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YamlProcessCreateEvent {
    pid: Option<u32>,
    parent_id: Option<u32>,
    path: Option<String>,
}

impl From<YamlProcessCreateEvent> for ProcessCreateEvent {
    fn from(yaml: YamlProcessCreateEvent) -> Self {
        Self {
            pid: yaml.pid.unwrap_or_default(),
            parent_id: yaml.parent_id.unwrap_or_default(),
            path: yaml.path.unwrap_or_default(),
        }
    }
}

impl ProcessCreateEvent {
    pub fn new(pid: u32, parent_id: u32, path: String) -> Self {
        Self {
            pid,
            parent_id,
            path,
        }
    }
}

impl Event for ProcessCreateEvent {
    //"PRO " as u32-> 50 52 4F 20
    const EVENT_CLASS: u32 = 0x204F5250;
}

impl<'a> Serializer for ProcessCreateEvent {
    fn blob_size(&self) -> u32 {
        mem::size_of::<u32>() as u32 + mem::size_of::<u32>() as u32 + self.path.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut v = Vec::new();
        let v_len = self.blob_size() as usize;
        v.try_reserve_exact(v_len)?;

        v.append(&mut self.pid.to_blob()?);
        v.append(&mut self.parent_id.to_blob()?);
        v.append(&mut self.path.to_blob()?);

        Ok(v)
    }
}

impl<'a> Deserializer for ProcessCreateEvent {
    fn from_blob(bytes: &[u8]) -> Self {
        let pid = u32::from_blob(bytes);
        let bytes = &bytes[4..];

        let parent_id = u32::from_blob(bytes);
        let bytes = &bytes[4..];

        let path = String::from_blob(bytes);
        Self {
            pid,
            parent_id,
            path,
        }
    }
}

impl MemberHasher for ProcessCreateEvent {
    const EVENT_NAME: &'static str = "ProcessCreate";

    fn hash_members(&self) -> Vec<Sha256Buff> {
        let mut v = Vec::new();

        if self.pid != 0 {
            let pid = format!("{}+{}+{}", Self::EVENT_NAME, "pid", self.pid);
            v.push(sha256_from_bytes(pid.as_bytes()));
        }

        if self.pid != 0 {
            let parent_id = format!("{}+{}+{}", Self::EVENT_NAME, "parent_id", self.parent_id);
            v.push(sha256_from_bytes(parent_id.as_bytes()));
        }

        if !self.path.is_empty() {
            let path = format!("{}+{}+{}", Self::EVENT_NAME, "path", self.path);
            v.push(sha256_from_bytes(path.as_bytes()));
        }

        v
    }
}

impl CleaningInfoTrait for ProcessCreateEvent {
    fn get_pid(&self) -> Pid {
        Pid(self.pid)
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
        let e1 = ProcessCreateEvent::new(123, 234, "elo mordo".to_string());
        let event_buff = e1.serialize().unwrap();

        let event_type = get_event_type(event_buff.as_slice());
        assert_eq!(event_type, ProcessCreateEvent::EVENT_CLASS);

        let e2 = ProcessCreateEvent::deserialize(event_buff.as_slice()).unwrap();
        assert_eq!(e1.pid, e2.pid);
        assert_eq!(e1.parent_id, e2.parent_id);
        assert_eq!(e1.path, e2.path);
    }
}
