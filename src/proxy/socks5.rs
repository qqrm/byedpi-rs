// src/proxy/socks5.rs
//
// SOCKS4/SOCKS5 parsing and reply helpers ported from proxy.h/proxy.c.
// This module is intentionally “C-shaped” (packed structs + constants).

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use core::{mem, ptr};

use crate::params::SockaddrU;

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::*;

#[cfg(not(windows))]
use libc::*;

pub const S_AUTH_NONE: u8 = 0x00;
pub const S_AUTH_BAD: u8 = 0xff;

pub const S_ATP_I4: u8 = 0x01;
pub const S_ATP_ID: u8 = 0x03;
pub const S_ATP_I6: u8 = 0x04;

pub const S_CMD_CONN: u8 = 0x01;
pub const S_CMD_BIND: u8 = 0x02;
pub const S_CMD_AUDP: u8 = 0x03;

pub const S_ER_OK: u8 = 0x00;
pub const S_ER_GEN: u8 = 0x01;
pub const S_ER_DENY: u8 = 0x02;
pub const S_ER_NET: u8 = 0x03;
pub const S_ER_HOST: u8 = 0x04;
pub const S_ER_CONN: u8 = 0x05;
pub const S_ER_TTL: u8 = 0x06;
pub const S_ER_CMD: u8 = 0x07;
pub const S_ER_ATP: u8 = 0x08;

pub const S4_OK: u8 = 0x5a;
pub const S4_ER: u8 = 0x5b;

pub const S_VER5: u8 = 0x05;
pub const S_VER4: u8 = 0x04;

pub const S_SIZE_MIN: usize = 8;
pub const S_SIZE_I4: usize = 10;
pub const S_SIZE_I6: usize = 22;
pub const S_SIZE_ID: usize = 7;

// C: #pragma pack(push,1)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct s4_req {
    pub ver: u8,
    pub cmd: u8,
    pub port: u16,
    pub i4: in_addr_compat,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct s5_req {
    pub ver: u8,
    pub cmd: u8,
    pub zero: u8,
    pub atp: u8,
    pub dst: s5_dst,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub union s5_dst {
    pub i4: s5_i4,
    pub i6: s5_i6,
    pub id: s5_id,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct s5_i4 {
    pub ip: in_addr_compat,
    pub port: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct s5_i6 {
    pub ip: in6_addr_compat,
    pub port: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct s5_id {
    pub len: u8,
    pub domain: [u8; 257],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct s5_rep {
    pub ver: u8,
    pub code: u8,
    pub zero: u8,
    pub atp: u8,
    pub addr: s5_rep_addr,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct s5_rep_addr {
    pub i4: in_addr_compat,
    pub port: u16,
}

// platform address types
#[cfg(windows)]
pub type in_addr_compat = IN_ADDR;
#[cfg(windows)]
pub type in6_addr_compat = IN6_ADDR;

#[cfg(not(windows))]
pub type in_addr_compat = in_addr;
#[cfg(not(windows))]
pub type in6_addr_compat = in6_addr;

// C: s5_set_addr(char *buffer, size_t n, const union sockaddr_u *addr, char end)
pub fn s5_set_addr(buffer: &mut [u8], addr: &SockaddrU, end: bool) -> i32 {
    // Writes a SOCKS5 address+port (BND.ADDR/BND.PORT style) into buffer.
    // Returns bytes written, or -1 on error.
    //
    // NOTE: This is a minimal, Windows-safe implementation.
    // It assumes addr is either sockaddr_in or sockaddr_in6 in the union.

    if buffer.len() < S_SIZE_MIN {
        return -1;
    }

    // layout:
    //  [0]=VER, [1]=REP, [2]=RSV, [3]=ATYP, then addr, then port
    // Caller decides VER/REP elsewhere; here we write only ATYP+ADDR+PORT (like C helper).
    // In C, `end` controls whether to terminate with '\n' for HTTP CONNECT etc.
    let mut off = 0usize;

    // We'll write starting at buffer[0] (caller can offset if needed).
    unsafe {
        // determine family by reading sa_family from the union "sa"
        #[cfg(windows)]
        let fam = addr.sa.sa_family as i32;
        #[cfg(not(windows))]
        let fam = addr.sa.sa_family as i32;

        if fam == AF_INET as i32 {
            if buffer.len() < S_SIZE_I4 + if end { 1 } else { 0 } {
                return -1;
            }
            buffer[off] = S_ATP_I4;
            off += 1;

            #[cfg(windows)]
            {
                let sin: SOCKADDR_IN = addr.in_;
                buffer[off..off + 4].copy_from_slice(&sin.sin_addr.S_un.S_addr.to_ne_bytes());
                off += 4;
                buffer[off..off + 2].copy_from_slice(&sin.sin_port.to_be_bytes());
                off += 2;
            }
            #[cfg(not(windows))]
            {
                let sin: sockaddr_in = addr.in_;
                buffer[off..off + 4].copy_from_slice(&sin.sin_addr.s_addr.to_ne_bytes());
                off += 4;
                buffer[off..off + 2].copy_from_slice(&sin.sin_port.to_be_bytes());
                off += 2;
            }
        } else if fam == AF_INET6 as i32 {
            if buffer.len() < S_SIZE_I6 + if end { 1 } else { 0 } {
                return -1;
            }
            buffer[off] = S_ATP_I6;
            off += 1;

            #[cfg(windows)]
            {
                let sin6: SOCKADDR_IN6 = addr.in6;
                buffer[off..off + 16].copy_from_slice(&sin6.sin6_addr.u.Byte);
                off += 16;
                buffer[off..off + 2].copy_from_slice(&sin6.sin6_port.to_be_bytes());
                off += 2;
            }
            #[cfg(not(windows))]
            {
                let sin6: sockaddr_in6 = addr.in6;
                buffer[off..off + 16].copy_from_slice(&sin6.sin6_addr.s6_addr);
                off += 16;
                buffer[off..off + 2].copy_from_slice(&sin6.sin6_port.to_be_bytes());
                off += 2;
            }
        } else {
            return -1;
        }
    }

    if end {
        buffer[off] = b'\n';
        off += 1;
    }

    off as i32
}
