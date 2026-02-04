// src/error.rs
//
// Line-by-line style port of error.h.
// - get_e(): returns errno (unix) or WSAGetLastError mapped to errno-like codes (windows)
// - uniperror(): prints last OS error (windows: GetLastError; unix: perror-like)
// - LOG_* + log(): gated by global params.debug (C: params.debug)
//
// This expects crate::params::{SockaddrU, PARAMS} to exist (PARAMS = global runtime params).
// You can stub PARAMS early and wire it later.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::params::{PARAMS, SockaddrU};

#[cfg(not(windows))]
use std::ffi::CStr;

pub const LOG_E: i32 = -1;
pub const LOG_S: i32 = 1;
pub const LOG_L: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
    EINTR,
    EAGAIN,
    ETIMEDOUT,
    ENETUNREACH,
    EHOSTUNREACH,
    ECONNREFUSED,
    ECONNRESET,
    Other(i32),
}

impl Errno {
    pub fn as_raw(self) -> i32 {
        match self {
            Errno::EINTR => libc::EINTR,
            Errno::EAGAIN => libc::EAGAIN,
            Errno::ETIMEDOUT => libc::ETIMEDOUT,
            Errno::ENETUNREACH => libc::ENETUNREACH,
            Errno::EHOSTUNREACH => libc::EHOSTUNREACH,
            Errno::ECONNREFUSED => libc::ECONNREFUSED,
            Errno::ECONNRESET => libc::ECONNRESET,
            Errno::Other(v) => v,
        }
    }

    pub fn from_raw(v: i32) -> Self {
        match v {
            x if x == libc::EINTR => Errno::EINTR,
            x if x == libc::EAGAIN => Errno::EAGAIN,
            x if x == libc::ETIMEDOUT => Errno::ETIMEDOUT,
            x if x == libc::ENETUNREACH => Errno::ENETUNREACH,
            x if x == libc::EHOSTUNREACH => Errno::EHOSTUNREACH,
            x if x == libc::ECONNREFUSED => Errno::ECONNREFUSED,
            x if x == libc::ECONNRESET => Errno::ECONNRESET,
            other => Errno::Other(other),
        }
    }
}

// C: static int unie(int e) { switch (WSA...) return errno-like; }
#[inline]
pub fn unie(e: i32) -> i32 {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::*;
        match e {
            x if x == WSAEWOULDBLOCK as i32 => libc::EAGAIN,
            x if x == WSAETIMEDOUT as i32 => libc::ETIMEDOUT,
            x if x == WSAENETUNREACH as i32 => libc::ENETUNREACH,
            x if x == WSAEHOSTUNREACH as i32 => libc::EHOSTUNREACH,
            x if x == WSAECONNREFUSED as i32 => libc::ECONNREFUSED,
            x if x == WSAECONNRESET as i32 => libc::ECONNRESET,
            other => other,
        }
    }
    #[cfg(not(windows))]
    {
        e
    }
}

#[inline]
pub fn get_e_raw() -> i32 {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Networking::WinSock::WSAGetLastError;
        unie(WSAGetLastError() as i32)
    }

    #[cfg(not(windows))]
    unsafe {
        *libc::__errno_location()
    }
}

#[inline]
pub fn get_e() -> Errno {
    Errno::from_raw(get_e_raw())
}

// C: uniperror(str)
pub fn uniperror(s: &str) {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::GetLastError;
        eprintln!("{}: {}", s, GetLastError());
    }

    #[cfg(not(windows))]
    unsafe {
        // perror(str)
        let cs =
            std::ffi::CString::new(s).unwrap_or_else(|_| std::ffi::CString::new("<bad>").unwrap());
        libc::perror(cs.as_ptr());
    }
}

// C: LOG(s, str, ...) gated by params.debug >= s (non-android)
#[inline]
pub fn log(level: i32, msg: &str) {
    // SAFETY: mirrors C global `params.debug`.
    let dbg = unsafe { PARAMS.debug };
    if dbg >= level {
        eprint!("{}", msg);
    }
}

#[inline]
pub fn log_enabled() -> bool {
    let dbg = unsafe { PARAMS.debug };
    dbg >= LOG_S
}

// C: INIT_ADDR_STR(dst) -> inet_ntop into ADDR_STR
pub fn addr_to_str(dst: &SockaddrU) -> Option<String> {
    // SockaddrU is a union in C; in Rust you’ll likely represent it as enum or repr(C) union.
    // This implementation assumes SockaddrU provides a method `.as_sockaddr()` returning (&sockaddr, len).
    let (sa, salen) = dst.as_sockaddr();

    let mut buf = [0u8; libc::INET6_ADDRSTRLEN as usize];

    let (af, src_ptr) = unsafe {
        match (*sa).sa_family as i32 {
            libc::AF_INET => {
                let sin = sa as *const libc::sockaddr_in;
                (
                    libc::AF_INET,
                    (&(*sin).sin_addr as *const libc::in_addr).cast::<libc::c_void>(),
                )
            }
            libc::AF_INET6 => {
                let sin6 = sa as *const libc::sockaddr_in6;
                (
                    libc::AF_INET6,
                    (&(*sin6).sin6_addr as *const libc::in6_addr).cast::<libc::c_void>(),
                )
            }
            _ => return None,
        }
    };

    let p = unsafe { libc::inet_ntop(af, src_ptr, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if p.is_null() {
        uniperror("inet_ntop");
        return None;
    }

    let cstr = unsafe { CStr::from_ptr(p) };
    Some(cstr.to_string_lossy().into_owned())
}

// C: INIT_HEX_STR(b, s)
pub fn hex_str(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", x);
    }
    out
}
