// src/proxy/mod.rs
//
// Port of proxy.h/proxy.c (top-level glue).
// Windows-first. Some heavy networking parts are still stubs because we haven't ported
// net/sock, resolve, and main loop accept wiring yet.
//
// Exposes the same public surface as proxy.h:
// - map_fix
// - create_conn
// - s5_set_addr (re-exported from socks5)
// - listen_socket
// - on_tunnel / on_udp_tunnel / on_request / on_connect / on_ignore
// - start_event_loop
// - run

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use core::{mem, ptr};

use crate::conev::{self, eval, evcb_t, poolhd};
use crate::error::{Errno, LOG_E, LOG_L, LOG_S, get_e, log, uniperror};
use crate::params::{PARAMS, SockaddrU};

pub mod http_connect;
pub mod socks5;
pub mod udp;

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::*;

#[cfg(not(windows))]
use libc::*;

// C: map_fix(union sockaddr_u *addr, char f6);
pub fn map_fix(_addr: &mut SockaddrU, _f6: bool) {
    // TODO: proxy.c does IPv4-mapped-IPv6 normalization and "force v6/v4" mapping.
    // For now keep as no-op so the project compiles and we can proceed module-by-module.
}

// C: listen_socket(const union sockaddr_u *srv)
pub fn listen_socket(_srv: &SockaddrU) -> i32 {
    // TODO: create/bind/listen with params.* options (ipv6/transparent/etc).
    // Stub for now (compile-only).
    -1
}

// C: create_conn(pool, val, dst, next)
pub fn create_conn(_pool: &mut poolhd, _val: &mut eval, _dst: &SockaddrU, _next: evcb_t) -> i32 {
    // TODO: open remote socket, connect nonblocking, set val.cb = on_connect then transition to next.
    -1
}

// --- event callbacks (called from conev loop) ---

pub fn on_ignore(_pool: &mut poolhd, _val: &mut eval, _etype: i32) -> i32 {
    // C: on_ignore just drains/ignores and keeps connection alive until closed.
    0
}

pub fn on_connect(_pool: &mut poolhd, _val: &mut eval, _etype: i32) -> i32 {
    // TODO: finalize connect(), check SO_ERROR, then call val.after_conn_cb / next state.
    -1
}

pub fn on_request(_pool: &mut poolhd, _val: &mut eval, _etype: i32) -> i32 {
    // TODO: parse inbound request (SOCKS4/SOCKS5/HTTP CONNECT), set up tunnel pair(s),
    // respond to client, switch val.cb to on_tunnel/on_udp_tunnel.
    -1
}

pub fn on_tunnel(_pool: &mut poolhd, _val: &mut eval, _etype: i32) -> i32 {
    // TODO: bidirectional relay. In C this uses val.pair and buffers.
    0
}

pub fn on_udp_tunnel(pool: &mut poolhd, val: &mut eval, etype: i32) -> i32 {
    udp::on_udp_tunnel(pool, val, etype)
}

// --- loop glue ---

pub fn start_event_loop(_srvfd: i32) -> i32 {
    // TODO: accept loop -> add_event(on_request, clientfd, POLLIN|...)
    // Right now conev::loop_event is wired, but we still need accept callback wiring.
    -1
}

pub fn run(srv: &SockaddrU) -> i32 {
    let srvfd = listen_socket(srv);
    if srvfd < 0 {
        return -1;
    }
    start_event_loop(srvfd)
}
