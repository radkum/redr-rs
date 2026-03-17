use super::DeleteError;

pub(super) fn fix_permissions(path: &str) -> Result<(), DeleteError> {
    enable_privilege("SeTakeOwnershipPrivilege")?;
    enable_privilege("SeRestorePrivilege")?;

    let w = to_wide(path);

    unsafe {
        let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = sid.len() as u32;

        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            None,
            sid.as_mut_ptr() as _,
            &mut size,
        )
        .ok()
        .map_err(|_| last_err())?;

        // Take ownership
        SetNamedSecurityInfoW(
            PWSTR(w.as_ptr() as _),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            sid.as_mut_ptr() as _,
            None,
            None,
            None,
        );

        // Build ACL
        let mut ea = EXPLICIT_ACCESS_W::default();

        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;

        BuildTrusteeWithSidW(&mut ea.Trustee, sid.as_mut_ptr() as _);

        let mut new_acl = ptr::null_mut();

        SetEntriesInAclW(1, &mut ea, None, &mut new_acl)
            .ok()
            .map_err(|_| last_err())?;

        SetNamedSecurityInfoW(
            PWSTR(w.as_ptr() as _),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            new_acl,
            None,
        );

        LocalFree(new_acl as _);
    }

    Ok(())
}

//
// ================= PRIVILEGES =================
//

fn enable_privilege(name: &str) -> Result<(), DeleteError> {
    unsafe {
        let mut token = HANDLE::default();

        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ).ok().map_err(|_| last_err())?;

        let mut luid = LUID::default();

        LookupPrivilegeValueW(None, &to_wide(name), &mut luid)
            .ok()
            .map_err(|_| last_err())?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)
            .ok()
            .map_err(|_| last_err())?;
    }

    Ok(())
}
