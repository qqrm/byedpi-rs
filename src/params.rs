// src/params.rs
//
// Minimal, compiling Windows-first port of params.h data definitions.
// Fixes: SockaddrU now implements Debug (manual), so structs containing it can derive Debug.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use core::{fmt, mem, ptr};

#[cfg(not(windows))]
use libc::{sockaddr, sockaddr_in, sockaddr_in6};

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

pub const OFFSET_END: i32 = 1;
pub const OFFSET_MID: i32 = 2;
pub const OFFSET_RAND: i32 = 4;
pub const OFFSET_SNI: i32 = 8;
pub const OFFSET_HOST: i32 = 16;
pub const OFFSET_START: i32 = 32;

pub const DETECT_HTTP_LOCAT: i32 = 1;
pub const DETECT_TLS_ERR: i32 = 2;
pub const DETECT_TORST: i32 = 8;

pub const AUTO_RECONN: i32 = 1;
pub const AUTO_POST: i32 = 2;
pub const AUTO_SORT: i32 = 4;

pub const FM_RAND: i32 = 1;
pub const FM_ORIG: i32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum demode {
    DESYNC_NONE = 0,
    DESYNC_SPLIT = 1,
    DESYNC_DISORDER = 2,
    DESYNC_OOB = 3,
    DESYNC_DISOOB = 4,
    DESYNC_FAKE = 5,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SockaddrU {
    #[cfg(not(windows))]
    pub sa: sockaddr,
    #[cfg(not(windows))]
    pub in_: sockaddr_in,
    #[cfg(not(windows))]
    pub in6: sockaddr_in6,

    #[cfg(windows)]
    pub sa: SOCKADDR,
    #[cfg(windows)]
    pub in_: SOCKADDR_IN,
    #[cfg(windows)]
    pub in6: SOCKADDR_IN6,
}

impl Default for SockaddrU {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

impl fmt::Debug for SockaddrU {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No allocations, no inet_ntop/WSAAddressToString here (avoid module deps).
        // Just show family and raw bytes length.
        #[cfg(not(windows))]
        unsafe {
            let fam = self.sa.sa_family as i32;
            return f
                .debug_struct("SockaddrU")
                .field("sa_family", &fam)
                .finish();
        }

        #[cfg(windows)]
        unsafe {
            let fam = self.sa.sa_family as i32;
            return f
                .debug_struct("SockaddrU")
                .field("sa_family", &fam)
                .finish();
        }
    }
}

impl SockaddrU {
    // Used by error::addr_to_str.
    #[cfg(not(windows))]
    pub fn as_sockaddr(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        unsafe {
            (
                ptr::addr_of!(self.sa) as *const libc::sockaddr,
                mem::size_of::<sockaddr>() as libc::socklen_t,
            )
        }
    }

    #[cfg(windows)]
    pub fn as_sockaddr(
        &self,
    ) -> (
        *const windows_sys::Win32::Networking::WinSock::SOCKADDR,
        i32,
    ) {
        (
            ptr::addr_of!(self.sa) as *const SOCKADDR,
            mem::size_of::<SOCKADDR>() as i32,
        )
    }
}

// mpool.h stub (replace when you port mpool.*)
#[repr(C)]
pub struct mphdr {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct part {
    pub m: i32,
    pub flag: i32,
    pub pos: i64, // C: long
    pub r: i32,
    pub s: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct packet {
    pub size: isize, // ssize_t
    pub data: *mut i8,
    pub off: isize,
}

impl Default for packet {
    fn default() -> Self {
        Self {
            size: 0,
            data: ptr::null_mut(),
            off: 0,
        }
    }
}

#[repr(C)]
pub struct desync_params {
    pub ttl: i32,
    pub md5sig: bool,
    pub fake_data: packet,
    pub udp_fake_count: i32,
    pub fake_offset: part,
    pub fake_sni_count: i32,
    pub fake_sni_list: *const *const i8,
    pub fake_mod: i32,
    pub fake_tls_size: i32,
    pub drop_sack: bool,
    pub oob_char: [i8; 2],

    pub parts_n: i32,
    pub parts: *mut part,

    pub mod_http: i32,
    pub tlsrec_n: i32,
    pub tlsrec: *mut part,
    pub tlsminor: u8,
    pub tlsminor_set: bool,

    pub proto: i32,
    pub detect: i32,
    pub hosts: *mut mphdr,
    pub ipset: *mut mphdr,
    pub pf: [u16; 2],
    pub rounds: [i32; 2],

    pub ext_socks: SockaddrU,

    pub file_ptr: *mut i8,
    pub file_size: isize,

    pub _optind: i32,
    pub id: i32,
    pub bit: u64,
    pub fail_count: i32,
    pub pri: i32,
    pub str_: *const i8,

    pub prev: *mut desync_params,
    pub next: *mut desync_params,
}

impl Default for desync_params {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

// Rust-friendly alias names expected by other modules
pub type DesyncParams = desync_params;

#[repr(C)]
pub struct params {
    pub dp_n: i32,
    pub dp: *mut desync_params,
    pub await_int: i32,
    pub wait_send: bool,
    pub def_ttl: i32,
    pub custom_ttl: bool,

    pub tfo: bool,
    pub timeout: u32,
    pub auto_level: i32,
    pub cache_ttl_n: i32,
    pub cache_ttl: *mut u32,
    pub ipv6: bool,
    pub resolve: bool,
    pub udp: bool,
    pub transparent: bool,
    pub http_connect: bool,
    pub max_open: i32,
    pub debug: i32,
    pub bfsize: usize,
    pub baddr: SockaddrU,
    pub laddr: SockaddrU,
    pub mempool: *mut mphdr,

    pub protect_path: *const i8,
    pub pid_file: *const i8,
    pub pid_fd: i32,
    pub cache_file: *const i8,
}

impl Default for params {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

// C globals
pub static mut PARAMS: params = params {
    dp_n: 0,
    dp: ptr::null_mut(),
    await_int: 0,
    wait_send: false,
    def_ttl: 0,
    custom_ttl: false,

    tfo: false,
    timeout: 0,
    auto_level: 0,
    cache_ttl_n: 0,
    cache_ttl: ptr::null_mut(),
    ipv6: false,
    resolve: false,
    udp: false,
    transparent: false,
    http_connect: false,
    max_open: 0,
    debug: 0,
    bfsize: 0,
    baddr: SockaddrU {
        sa: unsafe { mem::zeroed() },
    },
    laddr: SockaddrU {
        sa: unsafe { mem::zeroed() },
    },
    mempool: ptr::null_mut(),

    protect_path: ptr::null(),
    pid_file: ptr::null(),
    pid_fd: -1,
    cache_file: ptr::null(),
};

// fake_* packets declared in C
pub static mut FAKE_TLS: packet = packet {
    size: 0,
    data: ptr::null_mut(),
    off: 0,
};
pub static mut FAKE_HTTP: packet = packet {
    size: 0,
    data: ptr::null_mut(),
    off: 0,
};
pub static mut FAKE_UDP: packet = packet {
    size: 0,
    data: ptr::null_mut(),
    off: 0,
};
