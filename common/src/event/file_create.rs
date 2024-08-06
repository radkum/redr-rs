use super::{Deserializer, Event, Serializer};
use crate::{
    hasher::MemberHasher,
    utils::{sha256_from_bytes, Sha256Buff},
};
use alloc::{collections::TryReserveError, format, string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use crate::cleaning_info::CleaningInfo;

#[derive(Debug)]
pub struct FileCreateEvent {
    //header: EventHeader,
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YamlFileCreateEvent {
    path: Option<String>,
}

impl From<YamlFileCreateEvent> for FileCreateEvent {
    fn from(yaml: YamlFileCreateEvent) -> Self {
        Self {
            path: yaml.path.unwrap_or_default()
        }
    }
}

impl FileCreateEvent {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    pub fn get_path(&self) -> String {
        self.path.clone()
    }
}
impl Event for FileCreateEvent {
    //"CRE " as u32-> 43 52 45 20
    const EVENT_CLASS: u32 = 0x20455243;
}

impl<'a> Serializer for FileCreateEvent {
    fn blob_size(&self) -> u32 {
        self.path.blob_size()
    }

    fn to_blob(&self) -> Result<Vec<u8>, TryReserveError> {
        self.path.to_blob()
    }
}

impl<'a> Deserializer for FileCreateEvent {
    fn from_blob(bytes: &[u8]) -> Self {
        let path = String::from_blob(bytes);
        Self { path }
    }
}

impl MemberHasher for FileCreateEvent {
    const EVENT_NAME: &'static str = "FileCreate";

    fn hash_members(&self) -> Vec<Sha256Buff> {
        let mut v = Vec::new();

        if !self.path.is_empty() {
            let s = format!("{}+{}+{}", Self::EVENT_NAME, "path", self.path);
            v.push(sha256_from_bytes(s.as_bytes()));
        }

        v
    }
}

impl CleaningInfo for FileCreateEvent {
    fn get_pid(&self) -> u32 {
        todo!()
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
        let e1 = FileCreateEvent::new("elo mordo".to_string());
        let event_buff = e1.serialize().unwrap();

        let event_type = get_event_type(event_buff.as_slice());
        assert_eq!(event_type, FileCreateEvent::EVENT_CLASS);

        let e2 = FileCreateEvent::deserialize(event_buff.as_slice()).unwrap();
        assert_eq!(e1.path, e2.path);
    }
}
