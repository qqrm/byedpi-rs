// src/main.rs
#![allow(dead_code)]
#![allow(non_camel_case_types)]

mod cli;
mod conev;
mod config;
mod error;
mod kavl;
mod params;

mod extend;
mod mpool;

mod desync;
mod main_util;
mod packets;
mod proxy;
mod win_service;

#[cfg(windows)]
unsafe extern "C" fn app_main(_argc: i32, _argv: *mut *mut i8) -> i32 {
    // TODO: port main.c logic here:
    // - parse args into params
    // - init ws2_32 (if needed in your other modules)
    // - run proxy/conev loop
    0
}

fn main() {
    // Minimal “buildable” main.
    // Later we’ll replace this with the ported main.c flow (CLI -> params -> run).

    #[cfg(all(windows, feature = "windows-service"))]
    unsafe {
        // If started by SCM as a service, dispatcher takes control and we should return.
        // If started from console, StartServiceCtrlDispatcherA returns 0 and we continue.
        let argc = 0;
        let argv = core::ptr::null_mut();
        if win_service::try_run_as_service(argc, argv, app_main) {
            return;
        }
    }

    // Console mode placeholder. Replace with real CLI entrypoint once cli/main.c is ported.
    #[cfg(windows)]
    unsafe {
        let _ = app_main(0, core::ptr::null_mut());
    }

    #[cfg(not(windows))]
    {
        // TODO: unix main.c port
    }
}
