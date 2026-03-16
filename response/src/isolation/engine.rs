use std::ptr::null_mut;

use shared::RedrResult;
use widestring::WideCString;

use super::{api::*, condition::Condition};

const FWPM_PROVIDER_FLAG_PERSISTENT: u32 = 0x00000001;
const FWPM_FILTER_FLAG_PERSISTENT: u32 = 0x00000001;
const FWP_E_ALREADY_EXISTS: u32 = 0x80320009;

pub struct FwpmEngine {
    handle: HANDLE,
}

impl FwpmEngine {
    pub fn open() -> RedrResult<Self> {
        let mut handle: HANDLE = null_mut();
        let status = unsafe {
            FwpmEngineOpen0(
                null_mut(),
                RPC_C_AUTHN_WINNT,
                null_mut(),
                null_mut(),
                &mut handle,
            )
        };
        if status != 0 {
            return Err(format!("Cannot open engine: 0x{:08x}", status).into());
        }
        Ok(Self { handle })
    }

    pub fn add_provider(&self, provider_key: &GUID, provider_name: &str) -> RedrResult<()> {
        let name = WideCString::from_str(provider_name)?;
        let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
        provider.displayData.name = name.as_ptr() as _;
        provider.providerKey = *provider_key;
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

        let status = unsafe { FwpmProviderAdd0(self.handle, &provider, null_mut()) };
        if status == FWP_E_ALREADY_EXISTS {
            log::info!("Provider already exists, continuing...");
            return Ok(());
        } else if status != 0 {
            return Err(format!("Cannot add provider: 0x{:08x}", status).into());
        }
        Ok(())
    }

    pub fn add_sublayer(
        &self,
        provider_key: &GUID,
        sublayer_key: &GUID,
        sublayer_name: &str,
    ) -> RedrResult<()> {
        let name = WideCString::from_str(sublayer_name)?;
        let mut p_key = *provider_key;
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.displayData.name = name.as_ptr() as _;
        sublayer.providerKey = &mut p_key;
        sublayer.subLayerKey = *sublayer_key;
        sublayer.flags = FWPM_PROVIDER_FLAG_PERSISTENT as u16;

        let status = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, null_mut()) };
        if status == FWP_E_ALREADY_EXISTS {
            log::info!("Sublayer already exists, continuing...");
            return Ok(());
        } else if status != 0 {
            return Err(format!("Cannot add sublayer: 0x{:08x}", status).into());
        }
        Ok(())
    }

    pub fn add_filter(
        &self,
        layer: &GUID,
        provider_key: &GUID,
        sublayer_key: &GUID,
        fwpm_action: FwpmAction,
        filter_name: &str,
    ) -> RedrResult<()> {
        let name = WideCString::from_str(filter_name)?;
        let mut p_key = *provider_key;
        let mut filter_weight: u64 = 0;
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };

        filter.layerKey = *layer;
        filter.providerKey = &mut p_key;
        filter.subLayerKey = *sublayer_key;
        filter.weight.type_ = FWP_DATA_TYPE__FWP_UINT64;
        filter.action.type_ = fwpm_action.to_raw();
        filter.weight.__bindgen_anon_1.uint64 = &mut filter_weight;
        filter.displayData.name = name.as_ptr() as _;
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
        if let FwpmAction::Permit(condition) = fwpm_action {
            filter.numFilterConditions = 1;
            filter.filterCondition = &condition.0 as *const FWPM_FILTER_CONDITION0 as _;
        }

        let status = unsafe { FwpmFilterAdd0(self.handle, &filter, null_mut(), null_mut()) };
        if status == FWP_E_ALREADY_EXISTS {
            log::info!("Filter already exists, continuing...");
            return Ok(());
        } else if status != 0 {
            return Err(format!("Cannot add filter: 0x{:08x}", status).into());
        }
        Ok(())
    }

    pub fn delete_sublayer(&self, sublayer: &GUID) {
        let status = unsafe { FwpmSubLayerDeleteByKey0(self.handle, sublayer) };
        if status != 0 {
            log::warn!("Cannot delete sublayer: 0x{:08x}", status);
        }
    }

    pub fn delete_provider(&self, provider: &GUID) {
        let status = unsafe { FwpmProviderDeleteByKey0(self.handle, provider) };
        if status != 0 {
            log::warn!("Cannot delete provider: 0x{:08x}", status);
        }
    }

    pub fn provider_exists(&self, provider_guid: &GUID) -> bool {
        let mut provider: *mut FWPM_PROVIDER0 = null_mut();
        let status = unsafe { FwpmProviderGetByKey0(self.handle, provider_guid, &mut provider) };
        if status == 0 && !provider.is_null() {
            unsafe { FwpmFreeMemory0(&mut provider as *mut _ as _) };
            true
        } else {
            false
        }
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for FwpmEngine {
    fn drop(&mut self) {
        let status = unsafe { FwpmEngineClose0(self.handle) };
        if status != 0 {
            log::error!("Cannot close engine: 0x{:08x}", status);
        }
    }
}

pub struct FwpmEnum {
    handle: HANDLE,
    h_engine: HANDLE,
}

impl FwpmEnum {
    pub fn new(engine: &FwpmEngine, layer: &GUID, provider_key: &GUID) -> RedrResult<Self> {
        let mut handle: HANDLE = null_mut();
        let mut p_key = *provider_key;
        let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        template.providerKey = &mut p_key;
        template.layerKey = *layer;
        template.numFilterConditions = 0;
        template.actionMask = 0xFFFFFFFF;

        let status =
            unsafe { FwpmFilterCreateEnumHandle0(engine.handle(), &template, &mut handle) };
        if status != 0 {
            return Err(format!("Cannot create filter enumerator: 0x{:08x}", status).into());
        }
        Ok(Self {
            handle,
            h_engine: engine.handle(),
        })
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for FwpmEnum {
    fn drop(&mut self) {
        let status = unsafe { FwpmFilterDestroyEnumHandle0(self.h_engine, self.handle) };
        if status != 0 {
            log::error!("Cannot destroy filter enumerator: 0x{:08x}", status);
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
        if status != 0 {
            return Err(format!("Cannot enumerate filters: 0x{:08x}", status).into());
        }
        let filters_list = unsafe { std::slice::from_raw_parts(h_filters, num_filters as _) };
        Ok(Self {
            h_filters,
            filters: filters_list.to_vec(),
        })
    }

    pub fn delete_filters(&self, engine: &FwpmEngine) {
        for filter in &self.filters {
            let id = unsafe { (*(*filter)).filterId };
            let status = unsafe { FwpmFilterDeleteById0(engine.handle(), id) };
            if status != 0 {
                log::warn!("Cannot destroy filter: 0x{:08x}", status);
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

pub enum FwpmAction {
    Block,
    Permit(Condition),
}

impl FwpmAction {
    fn to_raw(&self) -> u32 {
        match self {
            FwpmAction::Block => FWP_ACTION_BLOCK,
            FwpmAction::Permit(_) => FWP_ACTION_PERMIT,
        }
    }
}
