// src/proxy/http_connect.rs
//
// Minimal port placeholder for HTTP CONNECT address parsing from proxy.c.
// We keep it as a module so the project structure matches your mod tree.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use core::ptr;

use crate::error::{LOG_E, log};
use crate::packets::parse_http;
use crate::params::SockaddrU;
use crate::proxy::{resolve, sock_stream_compat};

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::*;

#[cfg(not(windows))]
use libc::*;

fn parse_port(port: &[u8]) -> Option<u16> {
    if port.is_empty() {
        return None;
    }
    let mut acc: u32 = 0;
    for &b in port {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.saturating_mul(10).saturating_add((b - b'0') as u32);
        if acc > 0xffff {
            return None;
        }
    }
    if acc == 0 {
        return None;
    }
    Some(acc as u16)
}

fn find_line_end(buf: &[u8], start: usize) -> Option<usize> {
    let Some(pos) = buf[start..].iter().position(|&b| b == b'\n') else {
        return None;
    };
    Some(start + pos)
}

fn set_port(addr: &mut SockaddrU, port: u16) {
    unsafe {
        if addr.sa.sa_family as i32 == AF_INET6 {
            addr.in6.sin6_port = port.to_be();
        } else {
            addr.in_.sin_port = port.to_be();
        }
    }
}

fn parse_connect_line(buf: &[u8]) -> Option<(&[u8], u16, usize)> {
    const PREFIX: &[u8] = b"CONNECT ";
    if buf.len() <= PREFIX.len() || &buf[..PREFIX.len()] != PREFIX {
        return None;
    }

    let line_end = find_line_end(buf, 0)?;
    let mut line_end_excl = line_end;
    if line_end_excl > 0 && buf[line_end_excl - 1] == b'\r' {
        line_end_excl -= 1;
    }

    let mut pos = PREFIX.len();
    while pos < line_end_excl && buf[pos] == b' ' {
        pos += 1;
    }
    if pos >= line_end_excl {
        return None;
    }
    let host_start = pos;
    while pos < line_end_excl && buf[pos] != b' ' {
        pos += 1;
    }
    if pos == host_start {
        return None;
    }

    let host_port = &buf[host_start..pos];
    let (host, port) = if host_port.first() == Some(&b'[') {
        let close = host_port.iter().position(|&b| b == b']')?;
        if close + 1 >= host_port.len() || host_port[close + 1] != b':' {
            return None;
        }
        let host = &host_port[1..close];
        let port = parse_port(&host_port[close + 2..])?;
        (host, port)
    } else {
        let colon = host_port.iter().rposition(|&b| b == b':')?;
        let host = &host_port[..colon];
        let port = parse_port(&host_port[colon + 1..])?;
        (host, port)
    };

    let consumed = line_end + 1;
    Some((host, port, consumed))
}

pub fn http_get_addr(buf: &[u8]) -> Option<(SockaddrU, usize)> {
    if let Some((host, port, consumed)) = parse_connect_line(buf) {
        if host.len() < 3 || host.len() > 255 {
            return None;
        }
        let mut dst = SockaddrU::default();
        if resolve(host, &mut dst, sock_stream_compat()) != 0 {
            log(LOG_E, &format!("not resolved: {:?}\n", host));
            return None;
        }
        set_port(&mut dst, port);
        return Some((dst, consumed));
    }

    let mut host_ptr: *mut i8 = ptr::null_mut();
    let mut port: u16 = 0;
    let host_len = unsafe {
        parse_http(
            buf.as_ptr() as *const i8,
            buf.len(),
            &mut host_ptr,
            &mut port,
        )
    };
    if host_len < 3 || host_len > 255 {
        return None;
    }
    let host = unsafe { core::slice::from_raw_parts(host_ptr as *const u8, host_len as usize) };
    let mut dst = SockaddrU::default();
    if resolve(host, &mut dst, sock_stream_compat()) != 0 {
        log(LOG_E, &format!("not resolved: {:?}\n", host));
        return None;
    }
    set_port(&mut dst, port);
    Some((dst, 0))
}
