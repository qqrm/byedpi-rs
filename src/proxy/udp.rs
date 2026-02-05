// src/proxy/udp.rs
//
// UDP associate / UDP tunnel parts from proxy.c.
// Placeholder until we port full UDP relay logic.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use core::mem;

use crate::conev::{self, eval, poolhd};
use crate::error::{LOG_E, LOG_S, get_e_raw, log, uniperror};
use crate::extend::udp_hook;
use crate::params::{PARAMS, SockaddrU};
use crate::proxy::{map_fix, nb_socket, on_ignore, remote_sock, s5_get_addr};
use crate::proxy::socks5::{s5_set_addr, S_SIZE_I4, S_SIZE_I6};

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::*;

#[cfg(not(windows))]
use libc::*;

#[cfg(windows)]
type SockLen = i32;

#[cfg(not(windows))]
type SockLen = socklen_t;

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

#[cfg(not(windows))]
fn addr_ptr_mut(addr: &mut SockaddrU) -> *mut sockaddr {
    unsafe { &mut addr.sa as *mut _ }
}

#[cfg(windows)]
fn addr_ptr_mut(addr: &mut SockaddrU) -> *mut SOCKADDR {
    unsafe { &mut addr.sa as *mut _ }
}

pub fn udp_associate(pool: &mut poolhd, val: &mut eval, dst: &SockaddrU) -> i32 {
    let mut addr = *dst;
    let ufd = remote_sock(&mut addr, sock_dgram_compat());
    if ufd < 0 {
        return -1;
    }
    let pair_idx = match conev::add_event(pool, on_udp_tunnel, ufd, pollin_compat()) {
        Some(idx) => idx,
        None => {
            close_fd(ufd);
            return -1;
        }
    };

    let mut sz = mem::size_of::<SockaddrU>() as SockLen;
    if unsafe { getsockname(val.fd, addr_ptr_mut(&mut addr), &mut sz) } != 0 {
        uniperror("getsockname");
        return -1;
    }
    unsafe {
        addr.in_.sin_port = 0;
    }

    let cfd = nb_socket(addr.sa.sa_family as i32, sock_dgram_compat());
    if cfd < 0 {
        uniperror("socket");
        conev::del_event(pool, pair_idx);
        return -1;
    }
    if unsafe { bind(cfd, addr_ptr_mut(&mut addr), sz) } < 0 {
        uniperror("bind");
        conev::del_event(pool, pair_idx);
        close_fd(cfd);
        return -1;
    }
    let client_idx = match conev::add_event(pool, on_udp_tunnel, cfd, pollin_compat()) {
        Some(idx) => idx,
        None => {
            conev::del_event(pool, pair_idx);
            close_fd(cfd);
            return -1;
        }
    };

    if unsafe { PARAMS.debug } >= LOG_S {
        if let Some(addr_str) = crate::error::addr_to_str(dst) {
            log(
                LOG_S,
                &format!(
                    "udp associate: fds={},{},{} addr={}:{}\n",
                    ufd,
                    cfd,
                    val.fd,
                    addr_str,
                    unsafe { ntohs(dst.in_.sin_port) }
                ),
            );
        }
    }

    val.cb = Some(on_ignore);
    val.pair = Some(client_idx);
    pool.items[client_idx as usize].pair = Some(pair_idx);
    pool.items[pair_idx as usize].pair = Some(val.index);

    pool.items[client_idx as usize].flag = conev::FLAG_CONN;
    pool.items[client_idx as usize].addr = val.addr;
    unsafe {
        pool.items[client_idx as usize].addr.in_.sin_port = 0;
    }

    sz = mem::size_of::<SockaddrU>() as SockLen;
    if unsafe { getsockname(cfd, addr_ptr_mut(&mut addr), &mut sz) } != 0 {
        uniperror("getsockname");
        return -1;
    }

    let mut s5r = [0u8; S_SIZE_I6 + 4];
    s5r[0] = 0x05;
    s5r[1] = 0x00;
    s5r[2] = 0x00;
    let len = s5_set_addr(&mut s5r[3..], &addr, false);
    if len < 0 {
        return -1;
    }
    let len = 3 + len as usize;
    if send_bytes(val.fd, &s5r[..len]) < 0 {
        uniperror("send");
        return -1;
    }
    if conev::mod_etype(pool, val.index, pollrdhup_compat()) != 0 {
        uniperror("mod_etype");
        return -1;
    }
    0
}

pub fn on_udp_tunnel(pool: &mut poolhd, val: &mut eval, _et: i32) -> i32 {
    let Some(mut buff) = conev::buff_pop(pool, unsafe { PARAMS.bfsize }) else {
        return -1;
    };
    let mut data_offset = 0usize;
    if val.flag != conev::FLAG_CONN {
        data_offset = S_SIZE_I6;
    }
    let data_len = buff.size - data_offset;
    let mut pair_idx = val.pair;
    if val.flag != conev::FLAG_CONN {
        if let Some(idx) = pair_idx {
            pair_idx = pool.items[idx as usize].pair;
        }
    }
    let Some(pair_idx) = pair_idx else {
        conev::buff_push(pool, buff);
        return -1;
    };

    loop {
        let mut addr: SockaddrU = unsafe { mem::zeroed() };
        let mut asz = mem::size_of::<SockaddrU>() as SockLen;
        let n = unsafe {
            #[cfg(windows)]
            {
                recvfrom(
                    val.fd as usize,
                    buff.data[data_offset..].as_mut_ptr().cast(),
                    data_len as i32,
                    0,
                    addr_ptr_mut(&mut addr),
                    &mut asz,
                ) as isize
            }
            #[cfg(not(windows))]
            {
                recvfrom(
                    val.fd,
                    buff.data[data_offset..].as_mut_ptr().cast(),
                    data_len,
                    0,
                    addr_ptr_mut(&mut addr),
                    &mut asz,
                ) as isize
            }
        };
        if n < 1 {
            if n != 0 && get_e_raw() == libc::EAGAIN {
                break;
            }
            uniperror("recv udp");
            return -1;
        }
        let n = n as usize;
        val.recv_count += n as isize;
        if val.round_sent == 0 {
            val.round_count += 1;
            val.round_sent += n as isize;
            pool.items[pair_idx as usize].round_sent = 0;
        }

        let ns = if val.flag == conev::FLAG_CONN {
            if unsafe { val.addr.in_.sin_port } == 0 {
                if !addr_equ(&addr, &val.addr) {
                    return 0;
                }
                if unsafe { connect(val.fd, addr_ptr_mut(&mut addr), asz) } < 0 {
                    uniperror("connect");
                    return -1;
                }
                val.addr = addr;
            }
            if buff.data[data_offset + 2] != 0 {
                continue;
            }
            let offs = s5_get_addr(
                &buff.data[data_offset..data_offset + n],
                &mut addr,
                sock_dgram_compat(),
            );
            if offs < 0 {
                log(LOG_E, "udp parse error\n");
                return -1;
            }
            let offs = offs as usize;
            if unsafe { pool.items[pair_idx as usize].addr.in_.sin_port } == 0 {
                if unsafe { PARAMS.baddr.sa.sa_family as i32 == AF_INET6 } {
                    map_fix(&mut addr, true);
                }
                if unsafe { PARAMS.baddr.sa.sa_family } != addr.sa.sa_family {
                    return -1;
                }
                if let Some(addr_str) = crate::error::addr_to_str(&addr) {
                    log(
                        LOG_S,
                        &format!(
                            "udp addr: fd={}, addr={}:{}\n",
                            val.fd,
                            addr_str,
                            unsafe { ntohs(addr.in_.sin_port) }
                        ),
                    );
                }
                if unsafe { connect(pool.items[pair_idx as usize].fd, addr_ptr_mut(&mut addr), asz) }
                    < 0
                {
                    uniperror("connect");
                    return -1;
                }
                pool.items[pair_idx as usize].addr = addr;
            }
            udp_hook(
                &mut pool.items[pair_idx as usize],
                &mut buff.data[data_offset + offs..data_offset + n],
                (n - offs) as isize,
                &pool.items[pair_idx as usize].addr,
            )
        } else {
            map_fix(&mut addr, false);
            buff.data[..S_SIZE_I6].fill(0);
            let offs = match addr.sa.sa_family as i32 {
                x if x == AF_INET as i32 => S_SIZE_I4,
                x if x == AF_INET6 as i32 => S_SIZE_I6,
                _ => return -1,
            };
            let header_start = S_SIZE_I6 - offs;
            let wrote = s5_set_addr(
                &mut buff.data[header_start..header_start + offs],
                &addr,
                false,
            );
            if wrote < 0 || wrote as usize != offs {
                return -1;
            }
            let send_start = header_start;
            let total = offs + n;
            unsafe {
                #[cfg(windows)]
                {
                    send(
                        pool.items[pair_idx as usize].fd as usize,
                        buff.data[send_start..send_start + total].as_ptr().cast(),
                        total as i32,
                        0,
                    ) as isize
                }
                #[cfg(not(windows))]
                {
                    send(
                        pool.items[pair_idx as usize].fd,
                        buff.data[send_start..send_start + total].as_ptr().cast(),
                        total,
                        0,
                    ) as isize
                }
            }
        };

        if ns < 0 {
            uniperror("sendto");
            return -1;
        }
    }
    conev::buff_push(pool, buff);
    0
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
