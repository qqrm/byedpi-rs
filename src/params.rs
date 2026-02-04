// src/error.rs
//
// Updated to match params.h: uses PARAMS.debug and SockaddrU union.
// Minimal C-like helpers: get_e/unie/uniperror + LOG levels + addr_to_str/hex_str.

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

pub fn uniperror(s: &str) {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::GetLastError;
        eprintln!("{}: {}", s, GetLastError());
    }

    #[cfg(not(windows))]
    unsafe {
        let cs =
            std::ffi::CString::new(s).unwrap_or_else(|_| std::ffi::CString::new("<bad>").unwrap());
        libc::perror(cs.as_ptr());
    }
}

#[inline]
pub fn log(level: i32, msg: &str) {
    let dbg = unsafe { PARAMS.debug };
    if dbg >= level {
        eprint!("{}", msg);
    }
}

pub fn addr_to_str(dst: &SockaddrU) -> Option<String> {
    let (sa, _salen) = dst.as_sockaddr();

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

pub fn hex_str(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        use core::fmt::Write;
        let _ = write!(&mut out, "{:02x}", x);
    }
    out
}
