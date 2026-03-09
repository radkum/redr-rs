#[cfg_attr(target_pointer_width = "32", path = "api32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "api64.rs")]
#[allow(non_camel_case_types, non_snake_case, dead_code)]
mod api;

mod condition;
mod engine;
use std::{
    fmt,
    mem::zeroed,
    net::IpAddr,
    ptr::null_mut,
    sync::{Arc, Mutex},
    time::Instant,
};

use api::*;
pub(super) use condition::Condition;
use engine::{FwpmEngine, FwpmEnum, FwpmFilter, FwpmFilters, FwpmProvider, FwpmSublayer};
use lazy_static::lazy_static;
use log::warn;
use shared::RedrResult;
use uuid::Uuid;
use widestring::WideCString;

#[allow(clippy::upper_case_acronyms)]
type HANDLE = *mut ::std::os::raw::c_void;

const PROVIDER_NAME: &str = "Redr";
const SUBLAYER_NAME: &str = "RedrSublayer";

const PROVIDER_GUID: GUID = GUID {
    Data1: 0xa5a097da,
    Data2: 0x9a41,
    Data3: 0x4149,
    Data4: [0x99, 0xaf, 0xbf, 0x1e, 0x1c, 0x76, 0xc3, 0x05],
};

const SUBLAYER_GUID: GUID = GUID {
    Data1: 0x71fea44a,
    Data2: 0xf98e,
    Data3: 0x415a,
    Data4: [0xac, 0xa3, 0x19, 0x40, 0xbf, 0x70, 0x05, 0xd9],
};

const FWPM_LAYER_ALE_AUTH_CONNECT_V4: GUID = GUID {
    Data1: 0xc38d57d1,
    Data2: 0x05a7,
    Data3: 0x4c33,
    Data4: [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
};

const FWPM_LAYER_ALE_AUTH_CONNECT_V6: GUID = GUID {
    Data1: 0x4a72393b,
    Data2: 0x319f,
    Data3: 0x44bc,
    Data4: [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4],
};

const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: GUID = GUID {
    Data1: 0xe1cd9fe7,
    Data2: 0xf4b5,
    Data3: 0x4273,
    Data4: [0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50],
};

const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: GUID = GUID {
    Data1: 0xa3b42c97,
    Data2: 0x9f04,
    Data3: 0x4672,
    Data4: [0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f],
};
const BLOCK_LAYERS: &[GUID] = &[
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];
#[derive(Clone, Debug)]
pub enum FilterType {
    Inbound,
    Outbound,
}

impl FilterType {
    pub fn ip_v4(&self) -> GUID {
        match self {
            Self::Outbound => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Self::Inbound => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        }
    }

    pub fn ip_v6(&self) -> GUID {
        match self {
            Self::Outbound => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            Self::Inbound => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        }
    }
}

impl fmt::Display for FilterType {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

struct Isolator<'a> {
    provider_guid: GUID,
    provider_name: &'a str,
    sublayer_guid: GUID,
    sublayer_name: &'a str,
    allow: Vec<IpAddr>,
}

impl<'a> Isolator<'a> {
    pub fn isolate_internal(&mut self) -> RedrResult<()> {
        let engine = FwpmEngine::open()?;
        let provider = FwpmProvider::new(&self.provider_guid, self.provider_name)?;
        let sublayer =
            FwpmSublayer::new(&self.provider_guid, &self.sublayer_guid, self.sublayer_name)?;
        engine.add_provider(&provider)?;
        engine.add_sublayer(&sublayer)?;

        let mut filter_weight: u64 = 0;

        for layer in BLOCK_LAYERS {
            let filter = FwpmFilter::new(
                layer,
                &mut self.provider_guid,
                &mut self.sublayer_guid,
                FWP_ACTION_BLOCK,
                "Redr blocking web traffic",
            )?;
            engine.add_filter(&filter)?;
        }

        for allow in &self.allow {
            self.add_allow_filter(&engine, allow, FilterType::Outbound)?;
            self.add_allow_filter(&engine, allow, FilterType::Inbound)?;
        }

        Ok(())
    }

    pub fn restore(&mut self) -> RedrResult<()> {
        let engine = FwpmEngine::open()?;

        for layer in BLOCK_LAYERS {
            let enum_handle = FwpmEnum::new(&engine, layer, &mut self.provider_guid)?;
            let filters = FwpmFilters::new(&engine, &enum_handle)?;
            filters.delete_filters(&engine);
        }

        engine.delete_sublayer(&self.sublayer_guid);
        engine.delete_provider(&self.provider_guid);
        Ok(())
    }

    pub fn is_isolated(&mut self) -> RedrResult<bool> {
        let engine = FwpmEngine::open()?;

        // Check if the provider exists
        Ok(FwpmProvider::by_key(&engine, &self.provider_guid).is_ok())
    }

    fn add_allow_filter(
        &self,
        engine: &FwpmEngine,
        ip: &IpAddr,
        filter_type: FilterType,
    ) -> RedrResult<()> {
        let condition = Condition::from(ip);
        let layer = match ip {
            IpAddr::V4(_) => filter_type.ip_v4(),
            IpAddr::V6(_) => filter_type.ip_v6(),
        };

        let mut filter = FwpmFilter::new(
            &layer,
            &self.provider_guid,
            &self.sublayer_guid,
            FWP_ACTION_PERMIT,
            &format!("Redr allow {filter_type} to {}:*", ip),
        )?;
        filter.add_condition(&condition);
        engine.add_filter(&filter)?;

        Ok(())
    }
}
