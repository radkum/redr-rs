use std::{mem::zeroed, net::IpAddr};

use super::api::*;

pub struct Condition(pub FWPM_FILTER_CONDITION0);

impl From<&IpAddr> for Condition {
    fn from(ip_addr: &IpAddr) -> Condition {
        let mut condition: FWPM_FILTER_CONDITION0 = unsafe { zeroed() };

        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.matchType = FWP_MATCH_TYPE__FWP_MATCH_EQUAL;

        match ip_addr {
            IpAddr::V4(ip) => {
                let mut ip_mask: Box<FWP_V4_ADDR_AND_MASK> = unsafe { Box::new(zeroed()) };
                let addr: u32 = (*ip).into();

                ip_mask.mask = 0xFFFFFFFF;
                ip_mask.addr = addr;

                let cond_mask = FWP_CONDITION_VALUE0___bindgen_ty_1 {
                    v4AddrMask: &mut *ip_mask,
                };

                condition.conditionValue.type_ = FWP_DATA_TYPE__FWP_V4_ADDR_MASK;
                condition.conditionValue.__bindgen_anon_1 = cond_mask;
            }
            IpAddr::V6(ip) => {
                let mut ip_mask: Box<FWP_V6_ADDR_AND_MASK> = unsafe { Box::new(zeroed()) };

                ip_mask.prefixLength = 16;

                for (idx, oct) in ip.octets().to_vec().iter().enumerate() {
                    ip_mask.addr[idx] = *oct;
                }

                condition.conditionValue.type_ = FWP_DATA_TYPE__FWP_V6_ADDR_MASK;

                condition.conditionValue.__bindgen_anon_1 = FWP_CONDITION_VALUE0___bindgen_ty_1 {
                    v6AddrMask: &mut *ip_mask,
                };
            }
        }

        Condition(condition)
    }
}

const FWPM_CONDITION_IP_REMOTE_ADDRESS: GUID = GUID {
    Data1: 0xb235ae9a,
    Data2: 0x1d64,
    Data3: 0x49b8,
    Data4: [0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45],
};

const FWPM_CONDITION_IP_REMOTE_PORT: GUID = GUID {
    Data1: 0xc35a604d,
    Data2: 0xd22b,
    Data3: 0x4e1a,
    Data4: [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b],
};

const FWPM_CONDITION_IP_LOCAL_PORT: GUID = GUID {
    Data1: 0x0c1ba1af,
    Data2: 0x5765,
    Data3: 0x453f,
    Data4: [0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b],
};
