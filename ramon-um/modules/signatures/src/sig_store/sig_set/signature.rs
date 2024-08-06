use common::{
    event::{
        image_load::ImageLoadEvent, process_create::ProcessCreateEvent,
        registry_set_value::RegistrySetValueEvent, FileCreateEvent,
    },
    hasher::MemberHasher,
    utils::{convert_sha256_to_string, sha256_from_sha_string, sha256_from_vec, Sha256Buff},
};
use common_um::detection::DetectionReport;
use serde::{Deserialize, Serialize};
pub(super) use yaml_signature::{YamlSigData, YamlSignature};

use super::{Description, SigName};
use crate::{
    sig_store::sig_set::{heuristic_set::HeurSet, signature::yaml_signature::EventData},
    SigSetError,
};

pub(crate) mod yaml_signature;
pub(crate) type SigId = u32;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SerSigHeader {
    pub(crate) id: SigId,
    pub(crate) size: u32,
    pub(crate) offset: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SigBase {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Signature {
    pub(crate) base: SigBase,
    pub(crate) data: SigData,
}

impl Signature {
    pub(crate) fn from_yaml(yaml_sig: YamlSignature) -> Result<Self, SigSetError> {
        Ok(Self { base: yaml_sig.base, data: SigData::from_yaml(yaml_sig.data)? })
    }

    pub(crate) fn sig_data(&self) -> &SigData {
        &self.data
    }

    pub(crate) fn new_heur(
        name: SigName,
        description: Description,
        imports: Vec<Sha256Buff>,
        sig_type: u32,
    ) -> Signature {
        match sig_type {
            HeurSet::HEUR_MAGIC_U32 => {
                Self { base: SigBase { name, description }, data: SigData::Imports(imports) }
            },
            HeurSet::DYN_MAGIC_U32 => {
                Self { base: SigBase { name, description }, data: SigData::Calls(imports) }
            },
            HeurSet::BEH_MAGIC_U32 => {
                Self { base: SigBase { name, description }, data: SigData::Event(imports) }
            },
            _ => unreachable!("There is no other sig type"),
        }
    }

    pub(crate) fn new_sha(name: SigName, description: Description, sha: Sha256Buff) -> Signature {
        Self { base: SigBase { name, description }, data: SigData::Sha(sha) }
    }

    pub(crate) fn description(&self) -> String {
        self.base.description.clone()
    }

    pub(crate) fn name(&self) -> String {
        self.base.name.clone()
    }
}

impl From<Signature> for DetectionReport {
    fn from(sig: Signature) -> Self {
        let cause = match sig.data {
            SigData::Sha(sha) => format!("Found sha: '{}'", convert_sha256_to_string(&sha)),
            SigData::Imports(imports) => format!("Found {} suspicious imports", imports.len()),
            SigData::Calls(calls) => format!("Found {} suspicious calls", calls.len()),
            SigData::Event(attributes) => {
                format!("Matched event with {} attributes", attributes.len())
            },
        };
        Self { name: sig.base.name, desc: sig.base.description, cause }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum SigData {
    Sha(Sha256Buff),
    Imports(Vec<Sha256Buff>),
    Calls(Vec<Sha256Buff>),
    Event(Vec<Sha256Buff>),
}

impl SigData {
    pub(crate) fn get_sha_vec(&self) -> Option<Vec<Sha256Buff>> {
        match self {
            SigData::Sha(_) => None,
            SigData::Imports(v) | SigData::Calls(v) | SigData::Event(v) => Some(v.clone()),
        }
    }

    fn from_yaml(yaml_sig_data: YamlSigData) -> Result<Self, SigSetError> {
        fn import_string_to_sha(s: &String) -> Sha256Buff {
            let import_sha = sha256_from_vec(s.to_lowercase().as_bytes().to_vec());
            #[cfg(debug_assertions)]
            log::debug!(
                "import: \"{} -- {}\"",
                s.to_lowercase(),
                convert_sha256_to_string(&import_sha)
            );
            import_sha
        }

        Ok(match yaml_sig_data {
            YamlSigData::Sha(sha) => Self::Sha(sha256_from_sha_string(sha.as_str())?),
            YamlSigData::Imports(imports) => {
                Self::Imports(imports.iter().map(|s| import_string_to_sha(s)).collect())
            },
            YamlSigData::Calls(calls) => {
                Self::Calls(calls.iter().map(|s| import_string_to_sha(s)).collect())
            },
            YamlSigData::Event(event_data) => {
                let hash_list = match event_data {
                    EventData::RegSetValue(yaml_event) => {
                        let event = RegistrySetValueEvent::from(yaml_event);
                        event.hash_members()
                    },
                    EventData::FileCreate(yaml_event) => {
                        let event = FileCreateEvent::from(yaml_event);
                        event.hash_members()
                    },
                    EventData::ProcessCreate(yaml_event) => {
                        let event = ProcessCreateEvent::from(yaml_event);
                        event.hash_members()
                    },
                    EventData::ImageLoad(yaml_event) => {
                        let event = ImageLoadEvent::from(yaml_event);
                        event.hash_members()
                    },
                };

                Self::Event(hash_list)
            },
        })
    }
}
