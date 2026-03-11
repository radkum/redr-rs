#[cfg_attr(target_pointer_width = "32", path = "api32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "api64.rs")]
#[allow(non_camel_case_types, non_snake_case, dead_code)]
mod api;

mod condition;
mod engine;

use std::{fmt, net::IpAddr};

use api::*;
use engine::{FwpmAction, FwpmEngine, FwpmEnum, FwpmFilters};
use shared::RedrResult;

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

pub struct Isolator<'a> {
    provider_guid: GUID,
    provider_name: &'a str,
    sublayer_guid: GUID,
    sublayer_name: &'a str,
    #[allow(dead_code)]
    allow: Vec<IpAddr>,
}

impl Default for Isolator<'_> {
    fn default() -> Self {
        Self {
            provider_guid: PROVIDER_GUID,
            provider_name: "Redr",
            sublayer_guid: SUBLAYER_GUID,
            sublayer_name: "RedrSublayer",
            allow: Vec::new(),
        }
    }
}

impl Isolator<'_> {
    pub fn isolate(&self) -> RedrResult<()> {
        let engine = FwpmEngine::open()?;

        // Add provider
        engine.add_provider(&self.provider_guid, self.provider_name)?;

        // Add sublayer
        engine.add_sublayer(&self.provider_guid, &self.sublayer_guid, self.sublayer_name)?;

        // Add blocking filters for all layers
        for layer in BLOCK_LAYERS {
            engine.add_filter(
                layer,
                &self.provider_guid,
                &self.sublayer_guid,
                FwpmAction::Block,
                "Redr blocking web traffic",
            )?;
        }

        for allow in &self.allow {
            self.allow(&engine, allow, FilterType::Inbound)?;
            self.allow(&engine, allow, FilterType::Outbound)?;
        }

        Ok(())
    }

    pub fn restore(&self) -> RedrResult<()> {
        let engine = FwpmEngine::open()?;

        // Delete all filters for each layer
        for layer in BLOCK_LAYERS {
            let enum_handle = FwpmEnum::new(&engine, layer, &self.provider_guid)?;
            let filters = FwpmFilters::new(&engine, &enum_handle)?;
            filters.delete_filters(&engine);
        }

        // Delete sublayer and provider
        engine.delete_sublayer(&self.sublayer_guid);
        engine.delete_provider(&self.provider_guid);
        Ok(())
    }

    fn allow(&self, engine: &FwpmEngine, ip: &IpAddr, filter_type: FilterType) -> RedrResult<()> {
        let condition = condition::Condition::from(ip);
        let layer = match ip {
            IpAddr::V4(_) => filter_type.ip_v4(),
            IpAddr::V6(_) => filter_type.ip_v6(),
        };

        engine.add_filter(
            &layer,
            &self.provider_guid,
            &self.sublayer_guid,
            FwpmAction::Permit(condition),
            &format!("Redr allow {filter_type} to {}:*", ip),
        )?;

        Ok(())
    }

    pub fn add_allow(&mut self, ip: IpAddr) {
        self.allow.push(ip);
    }

    pub fn status(&self) -> RedrResult<bool> {
        let engine = FwpmEngine::open()?;
        Ok(engine.provider_exists(&self.provider_guid))
    }
}
