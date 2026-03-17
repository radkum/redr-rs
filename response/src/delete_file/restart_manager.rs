fn get_locking_processes(path: &str) -> Result<Vec<RM_PROCESS_INFO>, DeleteError> {
    unsafe {
        let mut session = 0;
        let mut key = [0u16; 32];

        RmStartSession(&mut session, 0, &mut key)
            .ok()
            .map_err(|_| last_err())?;

        let w = to_wide(path);

        RmRegisterResources(
            session,
            1,
            &PCWSTR(w.as_ptr()),
            0,
            ptr::null(),
            0,
            ptr::null(),
        )
        .ok()
        .map_err(|_| last_err())?;

        let mut needed = 0;
        let mut count = 0;

        RmGetList(session, &mut needed, &mut count, ptr::null_mut(), ptr::null_mut());

        let mut processes = vec![RM_PROCESS_INFO::default(); needed as usize];
        count = needed;

        RmGetList(
            session,
            &mut needed,
            &mut count,
            processes.as_mut_ptr(),
            ptr::null_mut(),
        )
        .ok()
        .map_err(|_| last_err())?;

        RmEndSession(session);

        Ok(processes)
    }
}

fn close_locking_processes(path: &str) -> Result<(), DeleteError> {
    unsafe {
        let mut session = 0;
        let mut key = [0u16; 32];

        RmStartSession(&mut session, 0, &mut key)
            .ok()
            .map_err(|_| last_err())?;

        let w = to_wide(path);

        RmRegisterResources(
            session,
            1,
            &PCWSTR(w.as_ptr()),
            0,
            ptr::null(),
            0,
            ptr::null(),
        )
        .ok()
        .map_err(|_| last_err())?;

        // graceful shutdown
        RmShutdown(session, 0, None).ok();

        RmEndSession(session);
    }

    Ok(())
}