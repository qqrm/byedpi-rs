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
use std::ffi::CString;

use crate::conev::{self, eval, evcb_t, poolhd};
use crate::error::{LOG_E, LOG_S, get_e_raw, log, unie, uniperror};
use crate::extend::{connect_hook, on_torst, socket_mod, tcp_recv_hook, tcp_send_hook};
use crate::packets::parse_http;
use crate::params::{PARAMS, SockaddrU};
use crate::proxy::socks5::{
    s4_req, s5_rep, s5_req, S4_ER, S4_OK, S_ATP_I4, S_ATP_I6, S_ATP_ID, S_AUTH_BAD,
    S_AUTH_NONE, S_CMD_AUDP, S_CMD_CONN, S_ER_ATP, S_ER_CMD, S_ER_CONN, S_ER_GEN, S_ER_HOST,
    S_ER_NET, S_ER_OK, S_VER4, S_VER5, S_SIZE_I4, S_SIZE_I6, S_SIZE_ID, S_SIZE_MIN,
};

pub mod http_connect;
pub mod socks5;
pub mod udp;

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::*;

#[cfg(not(windows))]
use libc::*;

#[cfg(windows)]
use libc::{addrinfo, freeaddrinfo, getaddrinfo, AI_ADDRCONFIG, AI_NUMERICHOST};

#[cfg(windows)]
type SockLen = i32;

#[cfg(not(windows))]
type SockLen = socklen_t;

#[cfg(target_os = "linux")]
const IP6T_SO_ORIGINAL_DST: i32 = 0x50;

// C: map_fix(union sockaddr_u *addr, char f6);
pub fn map_fix(addr: &mut SockaddrU, f6: bool) {
    unsafe {
        let family = addr.sa.sa_family as i32;

        #[cfg(not(windows))]
        {
            if family == AF_INET && f6 {
                let v4 = addr.in_.sin_addr;
                let port = addr.in_.sin_port;
                addr.in6.sin6_family = AF_INET6 as _;
                addr.in6.sin6_port = port;
                addr.in6.sin6_flowinfo = 0;
                addr.in6.sin6_addr = mem::zeroed();
                addr.in6.sin6_addr.s6_addr[10] = 0xff;
                addr.in6.sin6_addr.s6_addr[11] = 0xff;
                addr.in6.sin6_addr.s6_addr[12..16].copy_from_slice(&v4.s_addr.to_ne_bytes());
                return;
            }

            if family == AF_INET6 && !f6 {
                let v6 = addr.in6.sin6_addr.s6_addr;
                if v6[..10].iter().all(|&b| b == 0)
                    && v6[10] == 0xff
                    && v6[11] == 0xff
                {
                    let port = addr.in6.sin6_port;
                    let mut v4 = in_addr { s_addr: 0 };
                    v4.s_addr = u32::from_ne_bytes([v6[12], v6[13], v6[14], v6[15]]);
                    addr.in_.sin_family = AF_INET as _;
                    addr.in_.sin_port = port;
                    addr.in_.sin_addr = v4;
                }
            }
        }

        #[cfg(windows)]
        {
            if family == AF_INET as i32 && f6 {
                let v4 = addr.in_.sin_addr.S_un.S_addr;
                let port = addr.in_.sin_port;
                addr.in6.sin6_family = AF_INET6 as _;
                addr.in6.sin6_port = port;
                addr.in6.sin6_flowinfo = 0;
                addr.in6.sin6_addr.u.Byte = [0u8; 16];
                addr.in6.sin6_addr.u.Byte[10] = 0xff;
                addr.in6.sin6_addr.u.Byte[11] = 0xff;
                addr.in6.sin6_addr.u.Byte[12..16].copy_from_slice(&v4.to_ne_bytes());
                return;
            }

            if family == AF_INET6 as i32 && !f6 {
                let v6 = addr.in6.sin6_addr.u.Byte;
                if v6[..10].iter().all(|&b| b == 0)
                    && v6[10] == 0xff
                    && v6[11] == 0xff
                {
                    let port = addr.in6.sin6_port;
                    let mut v4 = IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes([v6[12], v6[13], v6[14], v6[15]]),
                        },
                    };
                    addr.in_.sin_family = AF_INET as _;
                    addr.in_.sin_port = port;
                    addr.in_.sin_addr = v4;
                }
            }
        }
    }
}

// C: listen_socket(const union sockaddr_u *srv)
pub fn listen_socket(srv: &SockaddrU) -> i32 {
    let srvfd = nb_socket(srv.sa.sa_family as i32, sock_stream_compat());
    if srvfd < 0 {
        uniperror("socket");
        return -1;
    }

    let opt: i32 = 1;
    let opt_ptr = (&opt as *const i32).cast::<core::ffi::c_void>();
    let opt_len = mem::size_of_val(&opt) as SockLen;
    let rc = unsafe { setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, opt_ptr, opt_len) };
    if rc == -1 {
        uniperror("setsockopt");
        close_fd(srvfd);
        return -1;
    }

    if unsafe { bind(srvfd, addr_ptr(srv), addr_len(srv)) } < 0 {
        uniperror("bind");
        close_fd(srvfd);
        return -1;
    }
    if unsafe { listen(srvfd, 10) } != 0 {
        uniperror("listen");
        close_fd(srvfd);
        return -1;
    }
    srvfd
}

// C: create_conn(pool, val, dst, next)
pub fn create_conn(pool: &mut poolhd, val: &mut eval, dst: &SockaddrU, next: evcb_t) -> i32 {
    let mut addr = *dst;

    let sfd = remote_sock(&mut addr, sock_stream_compat());
    if sfd < 0 {
        return -1;
    }

    #[cfg(target_os = "linux")]
    {
        let syn_count: i32 = 1;
        if unsafe {
            setsockopt(
                sfd,
                IPPROTO_TCP,
                TCP_SYNCNT,
                (&syn_count as *const i32).cast::<core::ffi::c_void>(),
                mem::size_of_val(&syn_count) as SockLen,
            )
        } != 0
        {
            uniperror("setsockopt TCP_SYNCNT");
            close_fd(sfd);
            return -1;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            const TCP_FASTOPEN_CONNECT_OPT: i32 = TCP_FASTOPEN_CONNECT;
            if unsafe { PARAMS.tfo } {
                let yes: i32 = 1;
                if unsafe {
                    setsockopt(
                        sfd,
                        IPPROTO_TCP,
                        TCP_FASTOPEN_CONNECT_OPT,
                        (&yes as *const i32).cast::<core::ffi::c_void>(),
                        mem::size_of_val(&yes) as SockLen,
                    )
                } != 0
                {
                    uniperror("setsockopt TCP_FASTOPEN_CONNECT");
                    close_fd(sfd);
                    return -1;
                }
            }
        }
    }

    let one: i32 = 1;
    if unsafe {
        setsockopt(
            sfd,
            IPPROTO_TCP,
            TCP_NODELAY,
            (&one as *const i32).cast::<core::ffi::c_void>(),
            mem::size_of_val(&one) as SockLen,
        )
    } != 0
    {
        uniperror("setsockopt TCP_NODELAY");
        close_fd(sfd);
        return -1;
    }

    if unsafe { PARAMS.debug } >= LOG_S {
        if let Some(addr_str) = crate::error::addr_to_str(dst) {
            log(
                LOG_S,
                &format!(
                    "new conn: fd={}, pair={}, addr={}:{}\n",
                    sfd,
                    val.fd,
                    addr_str,
                    unsafe { ntohs(dst.in_.sin_port) }
                ),
            );
        }
    }

    let status = unsafe { connect(sfd, addr_ptr(&addr), addr_len(&addr)) };
    if status == 0 && unsafe { PARAMS.tfo } {
        log(LOG_S, "TFO supported!\n");
    }
    if status < 0 {
        let e = get_e_raw();
        if e != libc::EINPROGRESS && e != libc::EAGAIN {
            uniperror("connect");
            close_fd(sfd);
            return -1;
        }
    }

    let pair_index = match conev::add_event(pool, next, sfd, pollout_compat()) {
        Some(idx) => idx,
        None => {
            close_fd(sfd);
            return -1;
        }
    };

    if conev::mod_etype(pool, val.index, 0) < 0 {
        uniperror("mod_etype");
        return -1;
    }

    val.pair = Some(pair_index);
    pool.items[pair_index as usize].pair = Some(val.index);
    #[cfg(target_os = "netbsd")]
    {
        pool.items[pair_index as usize].addr = addr;
    }
    #[cfg(not(target_os = "netbsd"))]
    {
        pool.items[pair_index as usize].addr = *dst;
    }
    pool.items[pair_index as usize].flag = conev::FLAG_CONN;
    val.cb = Some(on_ignore);
    0
}

// --- event callbacks (called from conev loop) ---

pub fn on_ignore(_pool: &mut poolhd, _val: &mut eval, _etype: i32) -> i32 {
    // C: on_ignore just drains/ignores and keeps connection alive until closed.
    if _etype & (pollhup_compat() | pollerr_compat() | pollrdhup_compat()) != 0 {
        -1
    } else {
        0
    }
}

pub fn on_connect(_pool: &mut poolhd, _val: &mut eval, _etype: i32) -> i32 {
    on_connect_impl(_pool, _val, _etype)
}

pub fn on_request(_pool: &mut poolhd, _val: &mut eval, _etype: i32) -> i32 {
    on_request_impl(_pool, _val, _etype)
}

pub fn on_tunnel(_pool: &mut poolhd, _val: &mut eval, _etype: i32) -> i32 {
    on_tunnel_impl(_pool, _val, _etype)
}

pub fn on_udp_tunnel(pool: &mut poolhd, val: &mut eval, etype: i32) -> i32 {
    udp::on_udp_tunnel(pool, val, etype)
}

// --- loop glue ---

pub fn start_event_loop(_srvfd: i32) -> i32 {
    server_fd_store(_srvfd);

    let mut pool = match conev::init_pool(unsafe { PARAMS.max_open } * 2 + 1) {
        Some(pool) => pool,
        None => {
            close_fd(_srvfd);
            return -1;
        }
    };

    if conev::add_event(&mut pool, on_accept, _srvfd, pollin_compat()).is_none() {
        conev::destroy_pool(pool);
        close_fd(_srvfd);
        return -1;
    }

    conev::loop_event(&mut pool);

    log(LOG_S, "exit\n");
    conev::destroy_pool(pool);
    0
}

pub fn run(srv: &SockaddrU) -> i32 {
    let srvfd = listen_socket(srv);
    if srvfd < 0 {
        return -1;
    }
    start_event_loop(srvfd)
}

static mut SERVER_FD: i32 = -1;

fn server_fd_store(fd: i32) {
    unsafe {
        SERVER_FD = fd;
    }
}

#[cfg(not(windows))]
fn close_fd(fd: i32) {
    unsafe {
        close(fd);
    }
}

#[cfg(windows)]
fn close_fd(fd: i32) {
    unsafe {
        closesocket(fd as usize);
    }
}

#[cfg(not(windows))]
fn addr_ptr(addr: &SockaddrU) -> *const sockaddr {
    unsafe { &addr.sa as *const _ }
}

#[cfg(not(windows))]
fn addr_len(addr: &SockaddrU) -> SockLen {
    unsafe {
        match addr.sa.sa_family as i32 {
            AF_INET => mem::size_of::<sockaddr_in>() as SockLen,
            AF_INET6 => mem::size_of::<sockaddr_in6>() as SockLen,
            _ => mem::size_of::<sockaddr>() as SockLen,
        }
    }
}

#[cfg(not(windows))]
fn addr_ptr_mut(addr: &mut SockaddrU) -> *mut sockaddr {
    unsafe { &mut addr.sa as *mut _ }
}

#[cfg(windows)]
fn addr_ptr(addr: &SockaddrU) -> *const SOCKADDR {
    unsafe { &addr.sa as *const _ }
}

#[cfg(windows)]
fn addr_len(addr: &SockaddrU) -> i32 {
    unsafe {
        match addr.sa.sa_family as i32 {
            AF_INET => mem::size_of::<SOCKADDR_IN>() as i32,
            AF_INET6 => mem::size_of::<SOCKADDR_IN6>() as i32,
            _ => mem::size_of::<SOCKADDR>() as i32,
        }
    }
}

#[cfg(windows)]
fn addr_ptr_mut(addr: &mut SockaddrU) -> *mut SOCKADDR {
    unsafe { &mut addr.sa as *mut _ }
}

fn pollin_compat() -> i32 {
    #[cfg(windows)]
    {
        POLLRDNORM as i32
    }
    #[cfg(not(windows))]
    {
        POLLIN
    }
}

fn pollout_compat() -> i32 {
    #[cfg(windows)]
    {
        POLLWRNORM as i32
    }
    #[cfg(not(windows))]
    {
        POLLOUT
    }
}

fn pollerr_compat() -> i32 {
    #[cfg(windows)]
    {
        POLLERR as i32
    }
    #[cfg(not(windows))]
    {
        POLLERR
    }
}

fn pollhup_compat() -> i32 {
    #[cfg(windows)]
    {
        POLLHUP as i32
    }
    #[cfg(not(windows))]
    {
        POLLHUP
    }
}

fn pollrdhup_compat() -> i32 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        POLLRDHUP
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        0
    }
}

fn sock_stream_compat() -> i32 {
    #[cfg(windows)]
    {
        SOCK_STREAM as i32
    }
    #[cfg(not(windows))]
    {
        SOCK_STREAM
    }
}

fn sock_dgram_compat() -> i32 {
    #[cfg(windows)]
    {
        SOCK_DGRAM as i32
    }
    #[cfg(not(windows))]
    {
        SOCK_DGRAM
    }
}

pub(crate) fn nb_socket(domain: i32, sock_type: i32) -> i32 {
    #[cfg(target_os = "linux")]
    unsafe {
        let fd = socket(domain, sock_type | SOCK_NONBLOCK, 0);
        if fd < 0 {
            uniperror("socket");
            return -1;
        }
        fd
    }

    #[cfg(not(target_os = "linux"))]
    unsafe {
        let fd = socket(domain, sock_type, 0);
        if fd < 0 {
            uniperror("socket");
            return -1;
        }
        #[cfg(windows)]
        {
            let mut mode: u32 = 1;
            if ioctlsocket(fd as usize, FIONBIO, &mut mode) != 0 {
                uniperror("ioctlsocket");
                close_fd(fd);
                return -1;
            }
        }
        #[cfg(not(windows))]
        {
            if fcntl(fd, F_SETFL, O_NONBLOCK) < 0 {
                uniperror("fcntl");
                close_fd(fd);
                return -1;
            }
        }
        fd
    }
}

pub(crate) fn remote_sock(dst: &mut SockaddrU, sock_type: i32) -> i32 {
    unsafe {
        if PARAMS.baddr.sa.sa_family as i32 == AF_INET6 {
            map_fix(dst, true);
        } else {
            map_fix(dst, false);
        }
        if dst.sa.sa_family != PARAMS.baddr.sa.sa_family {
            log(LOG_E, "different addresses family\n");
            return -1;
        }

        let sfd = nb_socket(dst.sa.sa_family as i32, sock_type);
        if sfd < 0 {
            uniperror("socket");
            return -1;
        }
        if socket_mod(sfd) < 0 {
            close_fd(sfd);
            return -1;
        }
        if dst.sa.sa_family as i32 == AF_INET6 {
            let no: i32 = 0;
            if setsockopt(
                sfd,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                (&no as *const i32).cast::<core::ffi::c_void>(),
                mem::size_of_val(&no) as SockLen,
            ) != 0
            {
                uniperror("setsockopt IPV6_V6ONLY");
                close_fd(sfd);
                return -1;
            }
        }
        if bind(sfd, addr_ptr(&PARAMS.baddr), addr_len(&PARAMS.baddr)) < 0 {
            uniperror("bind");
            close_fd(sfd);
            return -1;
        }
        sfd
    }
}

fn addr_equ(a: &SockaddrU, b: &SockaddrU) -> bool {
    unsafe {
        if a.sa.sa_family as i32 == AF_INET {
            a.in_.sin_addr.s_addr == b.in_.sin_addr.s_addr
        } else {
            #[cfg(not(windows))]
            {
                a.in6.sin6_addr.s6_addr == b.in6.sin6_addr.s6_addr
            }
            #[cfg(windows)]
            {
                a.in6.sin6_addr.u.Byte == b.in6.sin6_addr.u.Byte
            }
        }
    }
}

fn resolve(chost: &[u8], addr: &mut SockaddrU, sock_type: i32) -> i32 {
    let mut hints: addrinfo = unsafe { mem::zeroed() };
    hints.ai_socktype = sock_type;
    hints.ai_flags = AI_ADDRCONFIG;
    unsafe {
        if !PARAMS.resolve {
            hints.ai_flags |= AI_NUMERICHOST;
        }
        hints.ai_family = if PARAMS.ipv6 { AF_UNSPEC } else { AF_INET };
    }

    let host = match CString::new(chost) {
        Ok(h) => h,
        Err(_) => return -1,
    };

    let mut res: *mut addrinfo = ptr::null_mut();
    let rc = unsafe { getaddrinfo(host.as_ptr(), ptr::null(), &hints, &mut res) };
    if rc != 0 || res.is_null() {
        return -1;
    }

    unsafe {
        let len = (*res).ai_addrlen as usize;
        ptr::copy_nonoverlapping((*res).ai_addr.cast::<u8>(), addr as *mut _ as *mut u8, len);
        freeaddrinfo(res);
    }

    0
}

fn auth_socks5(fd: i32, buffer: &[u8]) -> i32 {
    if buffer.len() <= 2 || buffer[1] as usize != buffer.len() - 2 {
        return -1;
    }
    let mut c = S_AUTH_BAD;
    for &method in &buffer[2..] {
        if method == S_AUTH_NONE {
            c = S_AUTH_NONE;
            break;
        }
    }
    let a = [S_VER5, c];
    if send_bytes(fd, &a) < 0 {
        uniperror("send");
        return -1;
    }
    if c != S_AUTH_BAD {
        0
    } else {
        -1
    }
}

fn resp_s5_error(fd: i32, e: i32) -> isize {
    let s5r = s5_rep {
        ver: 0x05,
        code: e as u8,
        zero: 0,
        atp: S_ATP_I4,
        addr: socks5::s5_rep_addr {
            i4: unsafe { mem::zeroed() },
            port: 0,
        },
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &s5r as *const s5_rep as *const u8,
            mem::size_of::<s5_rep>(),
        )
    };
    send_bytes(fd, bytes)
}

fn resp_error(fd: i32, e: i32, flag: i32) -> isize {
    if flag == conev::FLAG_S4 {
        let s4r = s4_req {
            ver: 0,
            cmd: if e != 0 { S4_ER } else { S4_OK },
            port: 0,
            i4: unsafe { mem::zeroed() },
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &s4r as *const s4_req as *const u8,
                mem::size_of::<s4_req>(),
            )
        };
        return send_bytes(fd, bytes);
    } else if flag == conev::FLAG_S5 {
        let mapped = match unie(e) {
            0 => S_ER_OK,
            x if x == libc::ECONNREFUSED => S_ER_CONN,
            x if x == libc::EHOSTUNREACH || x == libc::ETIMEDOUT => S_ER_HOST,
            x if x == libc::ENETUNREACH => S_ER_NET,
            _ => S_ER_GEN,
        };
        return resp_s5_error(fd, mapped as i32);
    } else if flag == conev::FLAG_HTTP {
        if e == 0 {
            return send_bytes(fd, b"HTTP/1.1 200 OK\r\n\r\n");
        }
        return send_bytes(fd, b"HTTP/1.1 503 Fail\r\n\r\n");
    }
    #[cfg(target_os = "linux")]
    unsafe {
        if PARAMS.transparent && (e == libc::ECONNREFUSED || e == libc::ETIMEDOUT) {
            let l = linger {
                l_onoff: 1,
                l_linger: 0,
            };
            if setsockopt(
                fd,
                SOL_SOCKET,
                SO_LINGER,
                (&l as *const linger).cast::<core::ffi::c_void>(),
                mem::size_of_val(&l) as SockLen,
            ) != 0
            {
                uniperror("setsockopt SO_LINGER");
                return -1;
            }
        }
    }
    0
}

fn s4_get_addr(buffer: &[u8], dst: &mut SockaddrU) -> i32 {
    if buffer.len() < mem::size_of::<s4_req>() + 1 {
        return -1;
    }
    let r = unsafe { &*(buffer.as_ptr() as *const s4_req) };
    if r.cmd != S_CMD_CONN {
        return -1;
    }
    let ip = u32::from_be(r.i4.s_addr);
    if ip <= 255 {
        unsafe {
            if !PARAMS.resolve || buffer[buffer.len() - 1] != 0 {
                return -1;
            }
        }
        let id_end = buffer[mem::size_of::<s4_req>()..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| p + mem::size_of::<s4_req>());
        let Some(id_end) = id_end else {
            return -1;
        };
        let len = buffer.len().saturating_sub(id_end + 2);
        if len < 3 || len > 255 {
            return -1;
        }
        let host = &buffer[id_end + 1..id_end + 1 + len];
        if resolve(host, dst, sock_stream_compat()) != 0 {
            log(LOG_E, &format!("not resolved: {:?}\n", host));
            return -1;
        }
    } else {
        unsafe {
            dst.in_.sin_family = AF_INET as _;
            dst.in_.sin_addr = r.i4;
        }
    }
    unsafe {
        dst.in_.sin_port = r.port;
    }
    0
}

pub(crate) fn s5_get_addr(buffer: &[u8], addr: &mut SockaddrU, sock_type: i32) -> i32 {
    if buffer.len() < S_SIZE_MIN {
        log(LOG_E, "ss: request too small\n");
        return -S_ER_GEN as i32;
    }
    let r = unsafe { &*(buffer.as_ptr() as *const s5_req) };

    let o = match r.atp {
        S_ATP_I4 => S_SIZE_I4,
        S_ATP_ID => r.dst.id.len as usize + S_SIZE_ID,
        S_ATP_I6 => S_SIZE_I6,
        _ => 0,
    };
    if o == 0 || buffer.len() < o {
        log(LOG_E, "ss: bad request\n");
        return -S_ER_GEN as i32;
    }
    match r.atp {
        S_ATP_I4 => unsafe {
            addr.in_.sin_family = AF_INET as _;
            addr.in_.sin_addr = r.dst.i4.ip;
        },
        S_ATP_ID => unsafe {
            if !PARAMS.resolve {
                return -S_ER_ATP as i32;
            }
            let len = r.dst.id.len as usize;
            if len < 3 {
                return -S_ER_HOST as i32;
            }
            let host = &r.dst.id.domain[..len];
            if resolve(host, addr, sock_type) != 0 {
                log(LOG_E, &format!("not resolved: {:?}\n", host));
                return -S_ER_HOST as i32;
            }
        },
        S_ATP_I6 => unsafe {
            if !PARAMS.ipv6 {
                return -S_ER_ATP as i32;
            }
            addr.in6.sin6_family = AF_INET6 as _;
            addr.in6.sin6_addr = r.dst.i6.ip;
        },
        _ => {}
    }
    let port = u16::from_be_bytes([buffer[o - 2], buffer[o - 1]]).to_be();
    unsafe {
        if addr.sa.sa_family as i32 == AF_INET6 {
            addr.in6.sin6_port = port;
        } else {
            addr.in_.sin_port = port;
        }
    }
    o as i32
}

fn http_get_addr(buffer: &[u8], dst: &mut SockaddrU) -> i32 {
    let mut host_ptr: *mut i8 = ptr::null_mut();
    let mut port: u16 = 0;
    let host_len = unsafe {
        parse_http(
            buffer.as_ptr() as *const i8,
            buffer.len(),
            &mut host_ptr,
            &mut port,
        )
    };
    if host_len < 3 || host_len > 255 {
        return -1;
    }
    let host =
        unsafe { core::slice::from_raw_parts(host_ptr as *const u8, host_len as usize) };
    if resolve(host, dst, sock_stream_compat()) != 0 {
        log(LOG_E, &format!("not resolved: {:?}\n", host));
        return -1;
    }
    unsafe {
        dst.in_.sin_port = port.to_be();
    }
    0
}

fn send_bytes(fd: i32, buffer: &[u8]) -> isize {
    #[cfg(windows)]
    unsafe {
        send(fd as usize, buffer.as_ptr(), buffer.len() as i32, 0) as isize
    }
    #[cfg(not(windows))]
    unsafe {
        send(fd, buffer.as_ptr() as *const _, buffer.len(), 0) as isize
    }
}

fn on_request_impl(pool: &mut poolhd, val: &mut eval, _etype: i32) -> i32 {
    let Some(mut buff) = conev::buff_pop(pool, unsafe { PARAMS.bfsize }) else {
        return -1;
    };
    let n = recv_bytes(val.fd, &mut buff.data);
    if n < 1 {
        if n != 0 {
            uniperror("ss recv");
        }
        conev::buff_push(pool, buff);
        return -1;
    }

    let n = n as usize;
    let mut error = 0;

    if buff.data[0] == S_VER5 {
        if val.flag != conev::FLAG_S5 {
            if auth_socks5(val.fd, &buff.data[..n]) != 0 {
                conev::buff_push(pool, buff);
                return -1;
            }
            val.flag = conev::FLAG_S5;
            conev::buff_push(pool, buff);
            return 0;
        }
        if n < S_SIZE_MIN {
            log(LOG_E, &format!("ss: request too small ({n})\n"));
            conev::buff_push(pool, buff);
            return -1;
        }
        let r = unsafe { &*(buff.data.as_ptr() as *const s5_req) };
        let mut s5e = 0;
        let mut dst = SockaddrU::default();
        match r.cmd {
            S_CMD_CONN => {
                s5e = s5_get_addr(&buff.data[..n], &mut dst, sock_stream_compat());
                if s5e >= 0 {
                    error = connect_hook(pool, val, &dst, on_connect);
                }
            }
            S_CMD_AUDP => {
                if unsafe { PARAMS.udp } {
                    s5e = s5_get_addr(&buff.data[..n], &mut dst, sock_dgram_compat());
                    if s5e >= 0 {
                        error = udp::udp_associate(pool, val, &dst);
                    }
                } else {
                    s5e = -(S_ER_CMD as i32);
                }
            }
            _ => {
                log(LOG_E, &format!("ss: unsupported cmd: 0x{:x}\n", r.cmd));
                s5e = -(S_ER_CMD as i32);
            }
        }
        if s5e < 0 {
            if resp_s5_error(val.fd, -s5e) < 0 {
                uniperror("send");
            }
            conev::buff_push(pool, buff);
            return -1;
        }
    } else if buff.data[0] == S_VER4 {
        val.flag = conev::FLAG_S4;
        let mut dst = SockaddrU::default();
        error = s4_get_addr(&buff.data[..n], &mut dst);
        if error != 0 {
            if resp_error(val.fd, error, conev::FLAG_S4) < 0 {
                uniperror("send");
            }
            conev::buff_push(pool, buff);
            return -1;
        }
        error = connect_hook(pool, val, &dst, on_connect);
    } else if unsafe { PARAMS.http_connect }
        && n > 7
        && &buff.data[..7] == b"CONNECT"
    {
        val.flag = conev::FLAG_HTTP;
        let mut dst = SockaddrU::default();
        if http_get_addr(&buff.data[..n], &mut dst) != 0 {
            conev::buff_push(pool, buff);
            return -1;
        }
        error = connect_hook(pool, val, &dst, on_connect);
    } else {
        log(LOG_E, &format!("ss: invalid version: 0x{:x} ({n})\n", buff.data[0]));
        conev::buff_push(pool, buff);
        return -1;
    }

    if error != 0 {
        let en = get_e_raw();
        let error = if en != 0 { en } else { error };
        if resp_error(val.fd, error, val.flag) < 0 {
            uniperror("send");
        }
        log(LOG_S, &format!("ss error: {en}\n"));
        conev::buff_push(pool, buff);
        return -1;
    }

    conev::buff_push(pool, buff);
    0
}

fn on_connect_impl(pool: &mut poolhd, val: &mut eval, et: i32) -> i32 {
    let pair_idx = match val.pair {
        Some(idx) => idx,
        None => return -1,
    };

    let mut error: i32 = 0;
    if et & pollerr_compat() != 0 {
        let mut len = mem::size_of_val(&error) as SockLen;
        if unsafe {
            getsockopt(
                val.fd,
                SOL_SOCKET,
                SO_ERROR,
                (&mut error as *mut i32).cast::<core::ffi::c_void>(),
                &mut len,
            )
        } != 0
        {
            uniperror("getsockopt SO_ERROR");
            return -1;
        }
        if matches!(
            error,
            libc::ECONNRESET | libc::ECONNREFUSED | libc::ETIMEDOUT | libc::EHOSTUNREACH
        ) {
            if on_torst(pool, val) == 0 {
                return 0;
            }
        }
    } else {
        if conev::mod_etype(pool, val.index, pollin_compat()) != 0
            || conev::mod_etype(pool, pair_idx, pollin_compat()) != 0
        {
            uniperror("mod_etype");
            return -1;
        }
        val.cb = Some(on_tunnel);
        unsafe {
            let pair = pool.items.get_unchecked_mut(pair_idx as usize);
            pair.cb = Some(on_tunnel);
        }
    }

    let pair = unsafe { pool.items.get_unchecked(pair_idx as usize) };
    if resp_error(pair.fd, error, pair.flag) < 0 {
        uniperror("send");
        return -1;
    }
    if error != 0 {
        -1
    } else {
        0
    }
}

fn on_tunnel_impl(pool: &mut poolhd, val: &mut eval, etype: i32) -> i32 {
    let pair_idx = match val.pair {
        Some(idx) => idx,
        None => return -1,
    };
    let val_idx = val.index;
    let (mut src_idx, mut dst_idx) = (val_idx, pair_idx);
    if etype & pollout_compat() != 0 || etype == conev::POLLTIMEOUT {
        src_idx = pair_idx;
        dst_idx = val_idx;
    }

    unsafe {
        let (src, dst) = pair_refs(pool, src_idx, dst_idx);

        if let Some(buff) = src.buff.as_mut() {
            if etype & pollhup_compat() != 0 {
                return -1;
            }
            let n = buff.lock - buff.offset as isize;
            let mut wait = false;
            let mut lock = buff.lock;
            let sn = tcp_send_hook(pool, dst, buff, &mut lock, &mut wait);
            if sn < 0 {
                uniperror("send");
                return -1;
            }
            if sn < n || wait {
                buff.offset = buff.offset.saturating_add(sn as u32);
                buff.lock = lock;
                return 0;
            }
            let buff = src.buff.take().unwrap();
            conev::buff_push(pool, buff);
            if conev::mod_etype(pool, src_idx, pollin_compat()) != 0
                || conev::mod_etype(pool, dst_idx, pollin_compat()) != 0
            {
                uniperror("mod_etype");
                return -1;
            }
        }

        let Some(mut buff) = conev::buff_pop(pool, unsafe { PARAMS.bfsize }) else {
            return -1;
        };
        src.buff = Some(buff);
        let buff = src.buff.as_mut().unwrap();
        loop {
            let n = tcp_recv_hook(pool, src, buff);
            if n == 0 {
                break;
            }
            if n < 0 {
                return -1;
            }

            let mut wait = false;
            let mut to_send = n;
            let sn = tcp_send_hook(pool, dst, buff, &mut to_send, &mut wait);
            if sn < 0 {
                uniperror("send");
                return -1;
            }
            if sn < to_send || wait {
                if sn < to_send {
                    log(
                        LOG_S,
                        &format!("send: {} != {} (fd={})\n", sn, to_send, dst.fd),
                    );
                } else {
                    log(LOG_S, &format!("send: {}, but not done yet (fd={})\n", sn, dst.fd));
                }
                buff.lock = to_send;
                buff.offset = sn as u32;
                if conev::mod_etype(pool, src_idx, 0) != 0
                    || conev::mod_etype(pool, dst_idx, if wait { 0 } else { pollout_compat() })
                        != 0
                {
                    uniperror("mod_etype");
                    return -1;
                }
                return 0;
            }
            if n != buff.size as isize {
                break;
            }
        }
        let buff = src.buff.take().unwrap();
        conev::buff_push(pool, buff);
        0
    }
}

unsafe fn pair_refs(
    pool: &mut poolhd,
    a: i32,
    b: i32,
) -> (&mut eval, &mut eval) {
    if a == b {
        let ptr = pool.items.get_unchecked_mut(a as usize) as *mut eval;
        return (&mut *ptr, &mut *ptr);
    }
    let (low, high, flip) = if a < b { (a, b, false) } else { (b, a, true) };
    let (left, right) = pool.items.split_at_mut(high as usize);
    let first = left.get_unchecked_mut(low as usize) as *mut eval;
    let second = right.get_unchecked_mut(0) as *mut eval;
    if flip {
        (&mut *second, &mut *first)
    } else {
        (&mut *first, &mut *second)
    }
}

fn recv_bytes(fd: i32, buffer: &mut [u8]) -> isize {
    #[cfg(windows)]
    unsafe {
        recv(fd as usize, buffer.as_mut_ptr(), buffer.len() as i32, 0) as isize
    }
    #[cfg(not(windows))]
    unsafe {
        recv(fd, buffer.as_mut_ptr() as *mut _, buffer.len(), 0) as isize
    }
}

fn on_accept(pool: &mut poolhd, val: &mut eval, _et: i32) -> i32 {
    loop {
        let mut client: SockaddrU = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<SockaddrU>() as SockLen;
        #[cfg(target_os = "linux")]
        let cfd = unsafe { accept4(val.fd, addr_ptr_mut(&mut client), &mut len, SOCK_NONBLOCK) };
        #[cfg(not(target_os = "linux"))]
        let cfd = unsafe { accept(val.fd, addr_ptr_mut(&mut client), &mut len) };

        if cfd < 0 {
            let e = get_e_raw();
            if e == libc::EAGAIN || e == libc::EINPROGRESS {
                break;
            }
            uniperror("accept");
            pool.brk = true;
            return -1;
        }
        log(LOG_S, &format!("accept: fd={}\n", cfd));

        #[cfg(not(target_os = "linux"))]
        {
            #[cfg(windows)]
            {
                let mut mode: u32 = 1;
                if unsafe { ioctlsocket(cfd as usize, FIONBIO, &mut mode) } != 0 {
                    uniperror("ioctlsocket");
                    close_fd(cfd);
                    continue;
                }
            }
            #[cfg(not(windows))]
            {
                if unsafe { fcntl(cfd, F_SETFL, O_NONBLOCK) } < 0 {
                    uniperror("fcntl");
                    close_fd(cfd);
                    continue;
                }
            }
        }

        let one: i32 = 1;
        if unsafe {
            setsockopt(
                cfd,
                IPPROTO_TCP,
                TCP_NODELAY,
                (&one as *const i32).cast::<core::ffi::c_void>(),
                mem::size_of_val(&one) as SockLen,
            )
        } != 0
        {
            uniperror("setsockopt TCP_NODELAY");
            close_fd(cfd);
            continue;
        }

        let rval_idx = match conev::add_event(pool, on_request, cfd, pollin_compat()) {
            Some(idx) => idx,
            None => {
                close_fd(cfd);
                continue;
            }
        };
        pool.items[rval_idx as usize].addr = client;
        #[cfg(target_os = "linux")]
        unsafe {
            if PARAMS.transparent && transp_conn(pool, rval_idx) < 0 {
                conev::del_event(pool, rval_idx);
                continue;
            }
        }
    }
    0
}

#[cfg(target_os = "linux")]
unsafe fn transp_conn(pool: &mut poolhd, val_idx: i32) -> i32 {
    let mut remote: SockaddrU = mem::zeroed();
    let mut self_addr: SockaddrU = mem::zeroed();
    let mut rlen = mem::size_of::<SockaddrU>() as SockLen;
    let mut slen = mem::size_of::<SockaddrU>() as SockLen;

    let mut got = getsockopt(
        pool.items[val_idx as usize].fd,
        IPPROTO_IP,
        SO_ORIGINAL_DST,
        (&mut remote as *mut SockaddrU).cast::<core::ffi::c_void>(),
        &mut rlen,
    );
    if got != 0 {
        let ip6t_so_original_dst = IP6T_SO_ORIGINAL_DST;
        got = getsockopt(
            pool.items[val_idx as usize].fd,
            IPPROTO_IPV6,
            ip6t_so_original_dst,
            (&mut remote as *mut SockaddrU).cast::<core::ffi::c_void>(),
            &mut rlen,
        );
        if got != 0 {
            uniperror("getsockopt SO_ORIGINAL_DST");
            return -1;
        }
    }

    if getsockname(
        pool.items[val_idx as usize].fd,
        addr_ptr_mut(&mut self_addr),
        &mut slen,
    ) < 0
    {
        uniperror("getsockname");
        return -1;
    }

    if self_addr.sa.sa_family == remote.sa.sa_family
        && self_addr.in_.sin_port == remote.in_.sin_port
        && addr_equ(&self_addr, &remote)
    {
        log(LOG_E, "connect to self, ignore\n");
        return -1;
    }

    let val = pool.items.get_unchecked_mut(val_idx as usize);
    let error = connect_hook(pool, val, &remote, on_connect);
    if error != 0 {
        uniperror("connect_hook");
        return -1;
    }
    0
}
