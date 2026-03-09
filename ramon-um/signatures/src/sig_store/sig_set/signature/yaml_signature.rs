use common::event::{
    file_create::YamlFileCreateEvent, image_load::YamlImageLoadEvent,
    process_create::YamlProcessCreateEvent, registry_set_value::YamlRegistrySetValueEvent,
};
use serde::{Deserialize, Serialize};

use super::SigBase;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct YamlSignature {
    #[serde(flatten)]
    pub(crate) base: SigBase,
    #[serde(flatten)]
    pub(crate) data: YamlSigData,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum YamlSigData {
    #[serde(rename = "sha256")]
    Sha(String),
    #[serde(rename = "imports")]
    Imports(Vec<String>),
    #[serde(rename = "calls")]
    Calls(Vec<String>),
    #[serde(rename = "event")]
    Event(EventData),
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum EventData {
    ProcessCreate(YamlProcessCreateEvent),
    FileCreate(YamlFileCreateEvent),
    ImageLoad(YamlImageLoadEvent),
    RegSetValue(YamlRegistrySetValueEvent),
}
