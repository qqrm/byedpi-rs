// src/win_service.rs
#![cfg(windows)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::ffi::c_void;
use std::sync::OnceLock;

use windows_sys::Win32::System::{
    Environment::SetCurrentDirectoryA, LibraryLoader::GetModuleFileNameA, Services::*,
};

const SERVICE_NAME: &[u8] = b"ByeDPI\0";

type AppMain = unsafe extern "C" fn(i32, *mut *mut i8) -> i32;

#[derive(Copy, Clone)]
struct ArgvPtr(*mut *mut i8);
unsafe impl Send for ArgvPtr {}
unsafe impl Sync for ArgvPtr {}

#[derive(Copy, Clone)]
struct StatusHandle(SERVICE_STATUS_HANDLE);
unsafe impl Send for StatusHandle {}
unsafe impl Sync for StatusHandle {}

struct SavedArgs {
    argc: i32,
    argv: ArgvPtr,
    app_main: AppMain,
}

static SAVED: OnceLock<SavedArgs> = OnceLock::new();
static STATUS_HANDLE: OnceLock<StatusHandle> = OnceLock::new();

static mut STATUS: SERVICE_STATUS = SERVICE_STATUS {
    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
    dwCurrentState: SERVICE_STOPPED,
    dwControlsAccepted: 0,
    dwWin32ExitCode: 0,
    dwServiceSpecificExitCode: 0,
    dwCheckPoint: 0,
    dwWaitHint: 0,
};

unsafe fn set_status(state: u32, win32_exit: u32) {
    let Some(h) = STATUS_HANDLE.get().copied() else {
        return;
    };
    let h = h.0;

    unsafe { STATUS.dwCurrentState = state };
    unsafe { STATUS.dwWin32ExitCode = win32_exit };

    // In running state accept stop/shutdown
    unsafe {
        STATUS.dwControlsAccepted = match state {
            SERVICE_RUNNING => SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            _ => 0,
        }
    };

    unsafe { SetServiceStatus(h, &raw const STATUS) };
}

unsafe extern "system" fn ctrl_handler(request: u32) {
    match request {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            unsafe { set_status(SERVICE_STOPPED, 0) };
        }
        _ => {
            // keep current state
            let h = STATUS_HANDLE
                .get()
                .map(|x| x.0)
                .unwrap_or(std::ptr::null_mut());
            let _ = unsafe { SetServiceStatus(h, &raw const STATUS) };
        }
    }
}

unsafe fn set_working_dir_to_exe_dir() {
    // For services current dir is %WinDir%\System32; fix relative paths.
    let mut buf = [0u8; 260]; // MAX_PATH
    let n = unsafe { GetModuleFileNameA(0 as *mut c_void, buf.as_mut_ptr(), buf.len() as u32) }
        as usize;
    if n == 0 || n >= buf.len() {
        return;
    }

    // truncate to directory
    let mut i = n;
    while i > 0 {
        i -= 1;
        if buf[i] == b'\\' || buf[i] == b'/' {
            buf[i + 1] = 0;
            break;
        }
    }

    let _ = unsafe { SetCurrentDirectoryA(buf.as_ptr()) };
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u8) {
    unsafe { set_working_dir_to_exe_dir() };

    let h = unsafe { RegisterServiceCtrlHandlerA(SERVICE_NAME.as_ptr(), Some(ctrl_handler)) };
    if h.is_null() {
        return;
    }
    let _ = STATUS_HANDLE.set(StatusHandle(h));

    // mark running
    unsafe { set_status(SERVICE_RUNNING, 0) };

    // run real app main with saved console args
    let exit_code = SAVED
        .get()
        .map(|s| unsafe { (s.app_main)(s.argc, (s.argv).0) })
        .unwrap_or(0);

    unsafe { set_status(SERVICE_STOPPED, exit_code as u32) };
}

/// Tries to attach to SCM and run as Windows service.
/// Returns `true` if started as a service (i.e. dispatcher took control).
/// Returns `false` if started from console (or dispatcher failed).
pub fn try_run_as_service(argc: i32, argv: *mut *mut i8, app_main: AppMain) -> bool {
    let _ = SAVED.set(SavedArgs {
        argc,
        argv: ArgvPtr(argv),
        app_main,
    });

    // SERVICE_TABLE_ENTRYA uses PSTR (*mut u8), windows-sys models it as mutable.
    let mut table: [SERVICE_TABLE_ENTRYA; 2] = unsafe { std::mem::zeroed() };
    table[0].lpServiceName = SERVICE_NAME.as_ptr() as *mut u8;
    table[0].lpServiceProc = Some(service_main);
    table[1].lpServiceName = std::ptr::null_mut();
    table[1].lpServiceProc = None;

    unsafe { StartServiceCtrlDispatcherA(table.as_ptr()) != 0 }
}
