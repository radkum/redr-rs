#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
pub enum RegType {
    REG_NONE = 0,
    REG_SZ = 1,
    REG_EXPAND_SZ = 2,
    REG_BINARY = 3,
    REG_DWORD = 4,
    REG_DWORD_BIG_ENDIAN = 5,
    REG_LINK = 6,
    REG_MULTI_SZ = 7,
    REG_RESOURCE_LIST = 8,
    REG_FULL_RESOURCE_DESCRIPTOR = 9,
    REG_RESOURCE_REQUIREMENTS_LIST = 10,
    REG_QWORD = 11,
}
impl RegType {
    pub fn is_string(&self) -> bool {
        let reg_type: u32 = self.into();
        if reg_type == 1 || reg_type == 2 || reg_type == 6 {
            true
        } else {
            false
        }
    }
}
impl From<&RegType> for u32 {
    fn from(value: &RegType) -> Self {
        *value as u32
    }
}
impl From<u32> for RegType {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::REG_SZ,
            2 => Self::REG_EXPAND_SZ,
            3 => Self::REG_BINARY,
            4 => Self::REG_DWORD,
            5 => Self::REG_DWORD_BIG_ENDIAN,
            6 => Self::REG_LINK,
            7 => Self::REG_MULTI_SZ,
            8 => Self::REG_RESOURCE_LIST,
            9 => Self::REG_FULL_RESOURCE_DESCRIPTOR,
            10 => Self::REG_RESOURCE_REQUIREMENTS_LIST,
            11 => Self::REG_QWORD,
            _ => Self::REG_NONE,
        }
    }
}
