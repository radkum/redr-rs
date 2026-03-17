use utils::windows::Win32Error;
use utils::windows;
use utils::windows::SmartHandle;

use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    System::Threading::*,
};

pub(super) enum Priviledge {
    TakeOwnership,
    Restore,
    Debug,
}

impl Priviledge {
    fn name(&self) -> &'static str {
        match self {
            Priviledge::TakeOwnership => "SeTakeOwnershipPrivilege\0",
            Priviledge::Restore => "SeRestorePrivilege\0",
            Priviledge::Debug => "SeDebugPrivilege\0",
        }
    }
}

impl std::fmt::Display for Priviledge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = self.name();
        write!(f, "{}", name)
    }
}

pub(super) fn enable_privilege(priviledge: Priviledge) -> Result<(), Win32Error> {
    unsafe {
        let mut token = SmartHandle::default();

        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            token.as_mut_ref(),
        ) == 0 {
            return Err(Win32Error::last());
        }

        let mut luid: LUID = std::mem::zeroed();
        let w = windows::to_wide(priviledge.name());

        if LookupPrivilegeValueW(std::ptr::null(), w.as_ptr(), &mut luid) == 0 {
            return Err(Win32Error::last());
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        if AdjustTokenPrivileges(token.get(), 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
            return Err(Win32Error::last());
        }
    }

    Ok(())
}
