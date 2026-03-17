use std::ptr;
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    Security::Authorization::*,
    System::Threading::*,
};

use utils::windows::{self, SmartBuffer};
use super::DeleteError;
use crate::enable_privilege;
use crate::Priviledge;

pub(super) fn fix_permissions(path: &str) -> Result<(), DeleteError> {
    enable_privilege(Priviledge::TakeOwnership)?;
    enable_privilege(Priviledge::Restore)?;

    let w = windows::to_wide(path);

    unsafe {
        let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = sid.len() as u32;

        if CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            sid.as_mut_ptr() as _,
            &mut size,
        ) == 0 {
            return Err(DeleteError::last_err());
        }

        // Take ownership
        SetNamedSecurityInfoW(
            w.as_ptr() as _,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            sid.as_mut_ptr() as _,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );

        // Build ACL
        let mut ea: EXPLICIT_ACCESS_W = std::mem::zeroed();

        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;

        BuildTrusteeWithSidW(&mut ea.Trustee, sid.as_mut_ptr() as _);
        let mut new_acl = SmartBuffer::<ACL>::new();

        if SetEntriesInAclW(1, &mut ea, ptr::null_mut(), new_acl.as_mut_ref()) != 0 {
            return Err(DeleteError::last_err());
        }

        SetNamedSecurityInfoW(
            w.as_ptr() as _,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_acl.get(),
            ptr::null_mut(),
        );
    }

    Ok(())
}