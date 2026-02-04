// src/extend.rs
//
// Port of extend.h / extend.c (Windows-first).
// This module is the “glue layer” that:
// - picks a desync profile (dp) for a connection
// - optionally connects via external SOCKS5 (ext_socks)
// - hooks send/recv to apply desync()
// - maintains a simple cache in params.mempool keyed by (family, port, ip)
//
// Notes for current stage:
// - packets.{c,h} is not ported yet -> parsing host/SNI is stubbed (check_host/save_hostname).
// - protect() is Linux-only in C; kept as no-op on Windows.
// - Many callbacks/flags are expected to exist in your conev/proxy ports (FLAG_* constants, eval fields).
//   If any field/const names differ in your current Rust structs, align those names (mechanical rename).

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(unused_variables)]

use core::{mem, ptr};

use crate::conev::{buffer as CBuffer, eval, evcb_t, poolhd};
use crate::desync;
use crate::error::{Errno, LOG_E, LOG_L, LOG_S, get_e, log, uniperror};
use crate::mpool;
use crate::params::{DesyncParams, PARAMS, SockaddrU, elem_i, mphdr};
use crate::proxy;

// These are expected to be defined in your conev/proxy ports.
// If not, either export them there, or replace with the actual constants used in your code.
use crate::conev::{FLAG_CONN, FLAG_S5};
use crate::proxy::{on_connect, on_tunnel};

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::*;

#[cfg(not(windows))]
use libc::*;

// ---------------------------------
// C structs used only in extend.c
// ---------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub union cache_ip {
    pub v4: in_addr_compat,
    pub v6: in6_addr_compat,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct cache_key {
    pub port: u16,
    pub family: u16,
    pub ip: cache_ip,
}

#[cfg(windows)]
pub type in_addr_compat = IN_ADDR;
#[cfg(windows)]
pub type in6_addr_compat = IN6_ADDR;

#[cfg(not(windows))]
pub type in_addr_compat = in_addr;
#[cfg(not(windows))]
pub type in6_addr_compat = in6_addr;

// ---------------------------------
// local helpers from extend.c
// ---------------------------------

fn set_timeout(_fd: i32, _s: u32) -> i32 {
    // C:
    // - linux: TCP_USER_TIMEOUT
    // - win32: TCP_MAXRT
    // We do a minimal Windows implementation; on other platforms keep no-op for now.
    #[cfg(windows)]
    unsafe {
        // TCP_MAXRT is not always defined in headers, but extend.c hardcodes fallback 5.
        const TCP_MAXRT_OPT: i32 = 5;
        let val: u32 = _s;
        if setsockopt(
            _fd as usize,
            IPPROTO_TCP as i32,
            TCP_MAXRT_OPT,
            (&val as *const u32) as *const u8,
            mem::size_of_val(&val) as i32,
        ) != 0
        {
            uniperror("setsockopt TCP_MAXRT");
            return -1;
        }
    }
    0
}

fn serialize_addr(dst: &SockaddrU, out: &mut cache_key) -> isize {
    unsafe {
        out.port = dst.in_.sin_port;
        out.family = dst.sa.sa_family as u16;

        // offset of ip.v4 in cache_key
        let c = offset_of_cache_ip() as isize;

        if (dst.sa.sa_family as i32) == (AF_INET as i32) {
            out.ip.v4 = dst.in_.sin_addr;
            c + mem::size_of::<in_addr_compat>() as isize
        } else {
            out.ip.v6 = dst.in6.sin6_addr;
            c + mem::size_of::<in6_addr_compat>() as isize
        }
    }
}

const fn offset_of_cache_ip() -> usize {
    // Equivalent of offsetof(cache_key, ip.v4). ip is a union, so it's the offset of ip.
    // cache_key: port(u16) + family(u16) => 4 bytes on all ABIs used here, then ip.
    4
}

fn cache_get(dst: &SockaddrU) -> *mut elem_i {
    unsafe {
        let mut key: cache_key = mem::zeroed();
        let len = serialize_addr(dst, &mut key);
        let val = mpool::mem_get(
            PARAMS.mempool as *const mphdr,
            (&key as *const cache_key) as *const i8,
            len as i32,
        );
        if val.is_null() {
            return ptr::null_mut();
        }
        // mem_get returns *mut elem (base); elem_i begins with elem_ex/elem layout in our params.rs.
        let vi = val as *mut elem_i;

        // TTL check: if now > val->time + cache_ttl[time_inc-1] => ignore
        // params.cache_ttl is *mut u32, cache_ttl_n is i32
        let now = time_now();
        if (*vi).time_inc <= 0 {
            return vi;
        }
        let idx = ((*vi).time_inc - 1) as isize;
        if PARAMS.cache_ttl.is_null() {
            return vi;
        }
        let ttl = *PARAMS.cache_ttl.offset(idx) as i64;
        if now > (*vi).time + ttl {
            log(
                LOG_S,
                &format!(
                    "ignore: time={}, now={}, inc={}\n",
                    (*vi).time,
                    now,
                    (*vi).time_inc
                ),
            );
            return ptr::null_mut();
        }
        vi
    }
}

fn cache_add(dst: &SockaddrU, host: &mut *mut i8, host_len: i32) -> *mut elem_i {
    unsafe {
        let mut key: cache_key = mem::zeroed();
        let cmp_len = serialize_addr(dst, &mut key) as usize;

        // Allocate key bytes, copy key
        let data = libc_calloc(1, cmp_len) as *mut u8;
        if data.is_null() {
            return ptr::null_mut();
        }
        ptr::copy_nonoverlapping((&key as *const cache_key) as *const u8, data, cmp_len);

        let val = mpool::mem_add(
            PARAMS.mempool as *mut mphdr,
            data as *mut i8,
            cmp_len as i32,
            mem::size_of::<elem_i>(),
        ) as *mut elem_i;
        if val.is_null() {
            uniperror("mem_add");
            libc_free(data as *mut core::ffi::c_void);
            return ptr::null_mut();
        }

        (*val).time = time_now();
        if (*val).time_inc < PARAMS.cache_ttl_n {
            (*val).time_inc += 1;
        }

        // attach extra hostname once
        if (*val).extra.is_null() && !(*host).is_null() {
            (*val).extra_len = host_len as u32;
            (*val).extra = *host;
            *host = ptr::null_mut();
        }
        val
    }
}

fn time_now() -> i64 {
    // C uses time(0) -> time_t
    // Keep i64 and use std time; deterministic isn’t needed here.
    #[cfg(windows)]
    {
        // seconds since UNIX_EPOCH
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
    #[cfg(not(windows))]
    unsafe {
        time(ptr::null_mut()) as i64
    }
}

unsafe fn libc_calloc(n: usize, sz: usize) -> *mut core::ffi::c_void {
    #[cfg(not(windows))]
    {
        libc::calloc(n, sz)
    }
    #[cfg(windows)]
    {
        // On Windows we still have libc via the `libc` crate if you depend on it.
        // If you remove libc later, replace with alloc::alloc.
        unsafe { libc::calloc(n, sz) }
    }
}

unsafe fn libc_free(p: *mut core::ffi::c_void) {
    #[cfg(not(windows))]
    {
        libc::free(p)
    }
    #[cfg(windows)]
    {
        unsafe { libc::free(p) }
    }
}

// ---------------------------------
// SOCKS5 handshake helpers
// ---------------------------------

pub fn on_socks_conn(pool: &mut poolhd, val: &mut eval, t: i32) -> i32 {
    // C sends: "\x05\x01\x00" (ver=5, nmethods=1, method=0)
    static DATA: &[u8] = b"\x05\x01\x00";

    if send_bytes(val.fd, DATA, 0) < 0 {
        uniperror("socks send");
        return on_torst(pool, val);
    }
    // switch callback to read server choice
    val.cb = Some(on_socks_recv);
    0
}

pub fn on_socks_recv(pool: &mut poolhd, val: &mut eval, _t: i32) -> i32 {
    // Minimal: read 2 bytes response: VER, METHOD
    let mut r = [0u8; 2];
    let n = recv_bytes(val.fd, &mut r);
    if n < 2 {
        uniperror("socks recv");
        return on_torst(pool, val);
    }
    if r[0] != 0x05 || r[1] != 0x00 {
        log(LOG_E, &format!("socks answer: {}\n", r[1]));
        return on_torst(pool, val);
    }

    // In C: if conn_state != FLAG_S5, send CONNECT request now.
    if val.conn_state != FLAG_S5 {
        let mut buf = [0u8; 256];
        buf[0] = 0x05;
        buf[1] = 0x01; // CONNECT
        buf[2] = 0x00;

        let wrote = proxy::socks5::s5_set_addr(&mut buf[3..], &val.addr, false);
        if wrote < 0 {
            return on_torst(pool, val);
        }
        let len = 3 + (wrote as usize);

        if send_bytes(val.fd, &buf[..len], 0) < 0 {
            uniperror("socks send");
            return on_torst(pool, val);
        }

        val.conn_state = FLAG_S5;
        return 0;
    }

    // CONNECT done, continue with original after_conn_cb (Option)
    let Some(next) = val.after_conn_cb else {
        log(LOG_E, "after_conn_cb is None\n");
        return on_torst(pool, val);
    };

    val.cb = Some(next);
    next(pool, val, pollout_compat())
}

// ---------------------------------
// exported API from extend.h
// ---------------------------------

pub fn socket_mod(fd: i32) -> i32 {
    unsafe {
        if PARAMS.custom_ttl {
            if desync::setttl(fd, PARAMS.def_ttl) < 0 {
                return -1;
            }
        }
        if !PARAMS.protect_path.is_null() {
            return protect(fd, PARAMS.protect_path);
        }
        0
    }
}

pub fn connect_hook(pool: &mut poolhd, val: &mut eval, dst: &SockaddrU, next: evcb_t) -> i32 {
    unsafe {
        // Select dp based on dp list and cache.
        // C flow:
        // - cache_get
        // - walk dp list, set val.dp_mask
        // - if dp.ext_socks.port -> connect to ext_socks then proxy via socks
        // - else connect directly

        let mut cached = cache_get(dst);

        // Save hostname from cached->extra (stub: packets not ported)
        let mut host: *mut i8 = ptr::null_mut();
        let mut host_len: i32 = 0;

        if !cached.is_null() && !(*cached).extra.is_null() {
            host = (*cached).extra;
            host_len = (*cached).extra_len as i32;
        }

        // choose dp
        let mut dp: *mut DesyncParams = ptr::null_mut();
        let mut i = 0;
        while i < PARAMS.dp_n {
            let cand = PARAMS.dp.add(i as usize);
            if cand.is_null() {
                i += 1;
                continue;
            }

            // In C: dp_mask used to skip already tried dp’s.
            // Keep same behavior if your eval has dp_mask/bit.
            if (val.dp_mask & (*cand).bit) != 0 {
                i += 1;
                continue;
            }

            // check_l34(dp, SOCK_STREAM, dst) is static helper; keep permissive until packets.c is ported.
            if check_l34(cand, sock_stream_compat(), dst) {
                dp = cand;
                break;
            }

            val.dp_mask |= (*cand).bit;
            i += 1;
        }

        val.dp = dp;
        if dp.is_null() {
            return -1;
        }

        // external socks handling
        if (*dp).ext_socks.in6.sin6_port != 0 {
            let e = proxy::create_conn(pool, val, &(*dp).ext_socks, on_socks_conn);
            if e == 0 {
                if let Some(pair_idx) = val.pair {
                    let pair = &mut pool.items[pair_idx as usize];
                    pair.after_conn_cb = Some(next);
                    pair.addr = *dst;
                }
            }
            return e;
        }

        proxy::create_conn(pool, val, dst, next)
    }
}

pub fn tcp_send_hook(
    pool: &mut poolhd,
    remote: &mut eval,
    buff: &mut CBuffer,
    n: &mut isize,
    wait: &mut bool,
) -> isize {
    // C: wrapper over desync() for client->remote stream.
    // remote is the "remote" eval; desync wants "val" = remote? In C it passes (pool, remote, buff, &n, &wait).
    desync::desync(pool, remote, buff, n, wait)
}

pub fn tcp_recv_hook(_pool: &mut poolhd, val: &mut eval, buff: &mut CBuffer) -> isize {
    #[cfg(windows)]
    unsafe {
        let got = recv(val.fd as usize, buff.data.as_mut_ptr(), buff.size as i32, 0) as isize;
        if got <= 0 {
            return got;
        }
        buff.lock = got; // isize
        got
    }

    #[cfg(not(windows))]
    unsafe {
        let got = recv(val.fd, buff.data.as_mut_ptr() as *mut _, buff.size, 0) as isize;
        if got <= 0 {
            return got;
        }
        buff.lock = got; // isize
        got
    }
}

pub fn udp_hook(val: &mut eval, buffer: &mut [u8], n: isize, dst: &SockaddrU) -> isize {
    unsafe {
        if val.dp.is_null() {
            return -1;
        }
        desync::desync_udp(val.fd, buffer, n, ptr::null(), val.dp)
    }
}

pub fn on_torst(pool: &mut poolhd, val: &mut eval) -> i32 {
    // C:
    // - if auto_reconn => attempt reconnect with next dp profile
    // - else close pair
    //
    // Minimal behavior for now: mark dp as failed, try reconnect if possible.
    unsafe {
        if !val.dp.is_null() {
            val.dp_mask |= (*val.dp).bit;
        }
        // AUTO_RECONN/AUTO_SORT logic will be reintroduced after packets and full proxy loop are ported.
    }
    -1
}

// ---------------------------------
// internal checks (stubs until packets module is ported)
// ---------------------------------

fn check_l34(dp: *mut DesyncParams, st: i32, dst: &SockaddrU) -> bool {
    // In C this checks:
    // - protocol (tcp/udp)
    // - port filters dp.pf
    // - hosts/ipset matching (via packets parsing + mempool)
    // - detect flags
    //
    // Until packets.{c,h} is ported, keep permissive: only port/proto filters if present.
    unsafe {
        if dp.is_null() {
            return false;
        }
        if (*dp).proto != 0 {
            // if dp->proto specified, match st
            // (exact mapping is in C; we keep it permissive here)
        }
        true
    }
}

#[cfg(not(windows))]
fn protect(conn_fd: i32, path: *const i8) -> i32 {
    // Linux-only in C; keep as no-op unless you port unix socket “protect” later.
    let _ = (conn_fd, path);
    0
}

#[cfg(windows)]
fn protect(_conn_fd: i32, _path: *const i8) -> i32 {
    0
}

// ---------------------------------
// WinSock/posix shims
// ---------------------------------

fn pollout_compat() -> i32 {
    #[cfg(windows)]
    {
        // Your conev likely uses WinSock event masks; but extend.c passes POLLOUT.
        // Keep literal for now.
        0x0004
    }
    #[cfg(not(windows))]
    {
        libc::POLLOUT
    }
}

fn sock_stream_compat() -> i32 {
    #[cfg(windows)]
    {
        SOCK_STREAM as i32
    }
    #[cfg(not(windows))]
    {
        libc::SOCK_STREAM
    }
}

fn send_bytes(fd: i32, buf: &[u8], flags: i32) -> isize {
    #[cfg(windows)]
    unsafe {
        send(fd as usize, buf.as_ptr(), buf.len() as i32, flags) as isize
    }
    #[cfg(not(windows))]
    unsafe {
        send(fd, buf.as_ptr() as *const _, buf.len(), flags) as isize
    }
}

fn recv_bytes(fd: i32, buf: &mut [u8]) -> isize {
    #[cfg(windows)]
    unsafe {
        recv(fd as usize, buf.as_mut_ptr(), buf.len() as i32, 0) as isize
    }
    #[cfg(not(windows))]
    unsafe {
        recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) as isize
    }
}
