use std::ptr::null_mut;

use shared::RedrResult;
use widestring::WideCString;

use super::{Condition, api::*};
const ERROR_SUCCESS: u32 = 0x00000000;
const FWPM_PROVIDER_FLAG_PERSISTENT: u32 = 0x00000001;
const FWPM_FILTER_FLAG_PERSISTENT: u32 = 0x00000001;
const FWPM_ALREADY_EXISTS: u32 = 0x80320009;

pub struct FwpmEngine {
    handle: HANDLE,
}

impl FwpmEngine {
    pub fn open() -> RedrResult<Self> {
        let mut handle: HANDLE = null_mut();
        let status = unsafe {
            FwpmEngineOpen0(null_mut(), RPC_C_AUTHN_WINNT, null_mut(), null_mut(), &mut handle)
        };
        if status > 0 {
            return Err(format!("Cannot open engine: 0x{:08x}", status).into());
        }
        Ok(Self { handle })
    }

    pub fn add_provider(&self, provider: &FwpmProvider) -> RedrResult<()> {
        let status = unsafe { FwpmProviderAdd0(self.handle, provider.as_ref(), null_mut()) };
        if status == FWPM_ALREADY_EXISTS {
            return Err("Provider already exists".into());
        } else if status > 0 {
            return Err(format!("Cannot add provider: 0x{:08x}", status).into());
        }

        Ok(())
    }

    pub fn add_sublayer(&self, sublayer: &FwpmSublayer) -> RedrResult<()> {
        let status = unsafe { FwpmSubLayerAdd0(self.handle, sublayer.as_ref(), null_mut()) };
        if status == FWPM_ALREADY_EXISTS {
            return Err("Sublayer already exists".into());
        } else if status > 0 {
            return Err(format!("Cannot add sublayer: 0x{:08x}", status).into());
        }

        Ok(())
    }

    pub fn add_filter(&self, filter: &FwpmFilter) -> RedrResult<()> {
        let status = unsafe { FwpmFilterAdd0(self.handle, &filter.0, null_mut(), null_mut()) };
        if status > 0 {
            return Err(format!("Cannot add filter: 0x{:08x}", status).into());
        }

        Ok(())
    }

    pub fn delete_sublayer(&self, sublayer: &GUID) {
        let status = unsafe { FwpmSubLayerDeleteByKey0(self.handle, sublayer) };
        if status > 0 {
            log::error!("Cannot delete sublayer: 0x{:08x}", status);
        }
    }

    pub fn delete_provider(&self, provider: &GUID) {
        let status = unsafe { FwpmProviderDeleteByKey0(self.handle, provider) };
        if status > 0 {
            log::error!("Cannot delete provider: 0x{:08x}", status);
        }
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for FwpmEngine {
    fn drop(&mut self) {
        let status = unsafe { FwpmEngineClose0(self.handle) };
        if status > 0 {
            log::error!("Cannot close engine: 0x{:08x}", status);
        }
    }
}

pub struct FwpmEnum {
    handle: HANDLE,
    h_engine: HANDLE,
}

impl FwpmEnum {
    pub fn new(engine: &FwpmEngine, layer: &_GUID, provider_key: &mut GUID) -> RedrResult<Self> {
        let mut handle: HANDLE = null_mut();
        let template = Self::template(layer, provider_key);

        let status =
            unsafe { FwpmFilterCreateEnumHandle0(engine.handle(), &template, &mut handle) };
        if status > 0 {
            return Err(format!("Cannot create filter enumerator: 0x{:08x}", status).into());
        }
        Ok(Self { handle, h_engine: engine.handle() })
    }

    fn template(layer: &GUID, provider_key: &mut GUID) -> FWPM_FILTER_ENUM_TEMPLATE0 {
        let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        template.providerKey = provider_key;
        template.layerKey = *layer;
        template.numFilterConditions = 0;
        template.actionMask = 0xFFFFFFFF;
        template
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for FwpmEnum {
    fn drop(&mut self) {
        let status = unsafe { FwpmFilterDestroyEnumHandle0(self.h_engine, self.handle) };
        if status > 0 {
            log::error!("Cannot destroy filter enumerator: 0x{:08x}", status);
        }
    }
}

pub struct FwpmFilter(FWPM_FILTER0);

impl FwpmFilter {
    pub fn new(
        layer: &GUID,
        provider_key: &GUID,
        sublayer_key: &GUID,
        action_type: u32,
        filter_name: &str,
    ) -> RedrResult<Self> {
        let mut filter_weight = 0;
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };

        let mut p_key = provider_key.clone();
        filter.layerKey = *layer;
        filter.providerKey = &mut p_key;
        filter.subLayerKey = *sublayer_key;
        filter.weight.type_ = FWP_DATA_TYPE__FWP_UINT64;
        filter.action.type_ = action_type;
        filter.weight.__bindgen_anon_1.uint64 = &mut filter_weight;
        filter.displayData.name = WideCString::from_str(filter_name)?.as_ucstr().as_ptr() as _;
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
        Ok(Self(filter))
    }

    // pub fn by_key(engine: &FwpmEngine, key: &GUID) -> RedrResult<Self> {
    //     let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };

    //     let status = unsafe { FwpmFilterGetByKey0(engine.handle(), key, &mut filter as *mut _ as _) };
    //     if status > 0 {
    //         return Err(format!("Cannot create filter object: 0x{:08x}", status).into());
    //     }
    //     Ok(Self(filter))
    // }

    // pub fn by_id(engine: &FwpmEngine, id: u64) -> RedrResult<Self> {
    //     let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };

    //     let status = unsafe { FwpmFilterGetById0(engine.handle(), id, &mut filter as *mut _ as _) };
    //     if status > 0 {
    //         return Err(format!("Cannot create filter object: 0x{:08x}", status).into());
    //     }
    //     Ok(Self(filter))
    // }

    pub fn add_condition(&mut self, condition: &Condition) {
        let mut conditions = vec![condition.0];
        self.0.numFilterConditions = conditions.len() as _;
        self.0.filterCondition = conditions.as_mut_ptr();
    }
}

impl Drop for FwpmFilter {
    fn drop(&mut self) {
        unsafe {
            FwpmFreeMemory0(&mut self.0 as *mut _ as _);
        }
    }
}

pub struct FwpmFilters {
    h_filters: *mut *mut FWPM_FILTER0,
    filters: Vec<*mut FWPM_FILTER0>,
}

impl FwpmFilters {
    pub fn new(engine: &FwpmEngine, fwpm_enum: &FwpmEnum) -> RedrResult<Self> {
        let mut h_filters: *mut *mut FWPM_FILTER0 = null_mut();
        let mut num_filters = 0;

        let status = unsafe {
            FwpmFilterEnum0(
                engine.handle(),
                fwpm_enum.handle(),
                0xFFFFFFFF,
                &mut h_filters,
                &mut num_filters,
            )
        };
        if status > 0 {
            return Err(format!("Cannot create filter enumerator: 0x{:08x}", status).into());
        }
        let filters_list = unsafe { std::slice::from_raw_parts(h_filters, num_filters as _) };
        Ok(Self { h_filters, filters: filters_list.to_vec() })
    }

    pub fn delete_filters(&self, engine: &FwpmEngine) {
        for filter in &self.filters {
            let id = unsafe { (*(*filter)).filterId };
            let status = unsafe { FwpmFilterDeleteById0(engine.handle(), id) };
            if status > 0 {
                log::error!("Cannot destroy filter: 0x{:08x}", status);
            }
        }
    }
}

impl Drop for FwpmFilters {
    fn drop(&mut self) {
        if !self.h_filters.is_null() {
            unsafe {
                FwpmFreeMemory0(&mut self.h_filters as *mut _ as _);
            }
        }
    }
}

pub struct FwpmProvider {
    provider: FWPM_PROVIDER0,
}

impl FwpmProvider {
    pub fn new(provider_key: &GUID, provider_name: &str) -> RedrResult<Self> {
        let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };

        provider.displayData.name = WideCString::from_str(provider_name)?.as_ucstr().as_ptr() as _;
        provider.providerKey = *provider_key;
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

        Ok(Self { provider })
    }

    pub fn by_key(engine: &FwpmEngine, provider_guid: &GUID) -> RedrResult<Self> {
        let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };

        let status = unsafe {
            FwpmProviderGetByKey0(engine.handle(), provider_guid, &mut provider as *mut _ as _)
        };
        if status > 0 {
            return Err(format!("Cannot create provider: 0x{:08x}", status).into());
        }
        Ok(Self { provider })
    }

    pub fn as_ref(&self) -> &FWPM_PROVIDER0 {
        &self.provider
    }
}

pub struct FwpmSublayer {
    sublayer: FWPM_SUBLAYER0,
}

impl FwpmSublayer {
    pub fn new(provider_key: &GUID, sublayer_key: &GUID, sublayer_name: &str) -> RedrResult<Self> {
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };

        let mut p_key = provider_key.clone();
        sublayer.displayData.name = WideCString::from_str(sublayer_name)?.as_ucstr().as_ptr() as _;
        sublayer.providerKey = &mut p_key;
        sublayer.subLayerKey = *sublayer_key;
        sublayer.flags = FWPM_PROVIDER_FLAG_PERSISTENT as u16;

        Ok(Self { sublayer })
    }

    pub fn as_ref(&self) -> &FWPM_SUBLAYER0 {
        &self.sublayer
    }
}
