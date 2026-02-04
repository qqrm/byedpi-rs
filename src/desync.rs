// src/desync.rs
//
// Port of desync.h / desync.c (Windows-first).
// Notes:
// - Linux-only optimizations (TCP_INFO notsent bytes, BPF drop_sack, TCP_MD5SIG, splice/vmsplice) are stubbed or simplified.
// - FAKE_SUPPORT is behind feature "fake-support" (off by default).
//
// Public API matches C:
//   desync(pool, val, buff, n, wait)
//   desync_udp(sfd, buffer, n, dst, dp)
//   setttl(fd, ttl)
//   pre_desync(sfd, dp)
//   post_desync(sfd, dp)

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use core::{cmp::min, mem, ptr};

use crate::conev::{self, buffer as CBuffer, eval, poolhd};
use crate::error::{Errno, LOG_E, LOG_L, LOG_S, get_e, log, uniperror};
use crate::params::{
    DesyncParams, OFFSET_END, OFFSET_HOST, OFFSET_MID, OFFSET_RAND, OFFSET_SNI, OFFSET_START,
    PARAMS, demode, part,
};

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::*;

#[cfg(not(windows))]
use libc::*;

const ERR_WAIT: isize = -12;

// ---- packets glue (will be fully ported later) ----
mod packets_glue {
    pub const IS_HTTP: u8 = 1;
    pub const IS_HTTPS: u8 = 2;

    #[inline]
    pub fn is_tls_chello(_buf: &[u8]) -> bool {
        false
    }
    #[inline]
    pub fn is_http(_buf: &[u8]) -> bool {
        false
    }

    // Returns host_len and host_pos (offset in buffer). 0 means "not found".
    #[inline]
    pub fn parse_tls(_buf: &[u8]) -> Option<(usize, usize)> {
        None
    }
    #[inline]
    pub fn parse_http(_buf: &[u8]) -> Option<(usize, usize)> {
        None
    }

    #[inline]
    pub fn mod_http(_buf: &mut [u8], _mode: i32) -> Result<(), ()> {
        Err(())
    }

    #[inline]
    pub fn part_tls(_buf: &mut [u8], _pos: usize) -> bool {
        false
    }

    #[inline]
    pub fn randomize_tls(_buf: &mut [u8]) {}

    #[inline]
    pub fn change_tls_sni(_sni: *const i8, _buf: &mut [u8], _limit: usize) -> i32 {
        -1
    }
}

// ---- protocol info ----

#[derive(Clone, Copy, Default)]
pub struct ProtoInfo {
    pub init: bool,
    pub type_: u8,
    pub host_len: i32,
    pub host_pos: i32,
}

fn init_proto_info(buffer: &[u8], info: &mut ProtoInfo) {
    if info.init {
        return;
    }

    if let Some((hlen, hpos)) = packets_glue::parse_tls(buffer) {
        info.type_ = packets_glue::IS_HTTPS;
        info.host_len = hlen as i32;
        info.host_pos = hpos as i32;
        info.init = true;
        return;
    }
    if let Some((hlen, hpos)) = packets_glue::parse_http(buffer) {
        info.type_ = packets_glue::IS_HTTP;
        info.host_len = hlen as i32;
        info.host_pos = hpos as i32;
        info.init = true;
        return;
    }

    info.init = true;
}

// static long gen_offset(...)
fn gen_offset(mut pos: i64, flag: i32, buffer: &[u8], lp: i64, info: &mut ProtoInfo) -> i64 {
    let n = buffer.len() as i64;

    if (flag & (OFFSET_SNI | OFFSET_HOST)) != 0 {
        init_proto_info(buffer, info);

        if info.host_pos == 0
            || (((flag & OFFSET_SNI) != 0) && info.type_ != packets_glue::IS_HTTPS)
        {
            return -1;
        }

        pos += info.host_pos as i64;

        if (flag & OFFSET_END) != 0 {
            pos += info.host_len as i64;
        } else if (flag & OFFSET_MID) != 0 {
            pos += (info.host_len as i64) / 2;
        } else if (flag & OFFSET_RAND) != 0 {
            let hl = info.host_len.max(0) as u32;
            if hl != 0 {
                pos += (rand_u32() % hl) as i64;
            }
        }
    } else if (flag & OFFSET_RAND) != 0 {
        let span = (n - lp).max(0) as u32;
        if span != 0 {
            pos += lp + (rand_u32() % span) as i64;
        } else {
            pos += lp;
        }
    } else if (flag & OFFSET_MID) != 0 {
        pos += n / 2;
    } else if pos < 0 || (flag & OFFSET_END) != 0 {
        pos += n;
    }

    pos
}

// C uses rand(); keep deterministic-ish but local.
fn rand_u32() -> u32 {
    // xorshift32
    static mut S: u32 = 0x1234_5678;
    unsafe {
        let mut x = S;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        S = x;
        x
    }
}

fn eval_index(pool: &poolhd, val: &eval) -> i32 {
    // pool.items: Vec<eval>, and val is &mut pool.items[idx] inside loop.
    let base = pool.items.as_ptr();
    let cur = val as *const eval;
    let idx = unsafe { cur.offset_from(base) };
    idx as i32
}

// ---- socket helpers ----

pub fn setttl(fd: i32, ttl: i32) -> i32 {
    #[cfg(windows)]
    unsafe {
        let ttlv: i32 = ttl;

        let ret6 = setsockopt(
            fd as usize,
            IPPROTO_IPV6 as i32,
            IPV6_UNICAST_HOPS as i32,
            (&ttlv as *const i32) as *const u8,
            mem::size_of_val(&ttlv) as i32,
        );

        let ret4 = setsockopt(
            fd as usize,
            IPPROTO_IP as i32,
            IP_TTL as i32,
            (&ttlv as *const i32) as *const u8,
            mem::size_of_val(&ttlv) as i32,
        );

        if ret4 != 0 && ret6 != 0 {
            uniperror("setttl");
            return -1;
        }
        0
    }

    #[cfg(not(windows))]
    unsafe {
        let ttlv = ttl;
        let ret6 = setsockopt(
            fd,
            IPPROTO_IPV6,
            IPV6_UNICAST_HOPS,
            &ttlv as *const _ as *const _,
            mem::size_of_val(&ttlv) as u32,
        );
        let ret4 = setsockopt(
            fd,
            IPPROTO_IP,
            IP_TTL,
            &ttlv as *const _ as *const _,
            mem::size_of_val(&ttlv) as u32,
        );

        if ret4 != 0 && ret6 != 0 {
            uniperror("setttl");
            return -1;
        }
        0
    }
}

fn restore_state(val: &mut eval) {
    // Linux-only restore_fake/md5sig is skipped in this stage.
    if val.restore_ttl {
        unsafe {
            let ttl = PARAMS.def_ttl;
            let _ = setttl(val.fd, ttl);
        }
        val.restore_ttl = false;
    }
}

fn send_bytes(fd: i32, buf: &[u8], flags: i32) -> isize {
    #[cfg(windows)]
    unsafe {
        send(fd as usize, buf.as_ptr(), buf.len() as i32, flags) as isize
    }

    #[cfg(not(windows))]
    unsafe {
        let p = buf.as_ptr() as *const i8;
        send(fd, p as *const _, buf.len(), flags) as isize
    }
}

fn send_oob(fd: i32, buffer: &mut [u8], n: isize, pos: i64, c: [i8; 2]) -> isize {
    if n as i64 <= pos || pos < 0 {
        return -1;
    }
    let posu = pos as usize;

    let rchar = buffer[posu];
    buffer[posu] = if c[1] != 0 { c[0] as u8 } else { b'a' };

    let len = send_bytes(fd, &buffer[..posu + 1], MSG_OOB as i32);
    buffer[posu] = rchar;

    if len < 0 {
        uniperror("send");
        return -1;
    }
    let len = len - 1;
    if len as i64 != pos {
        return len;
    }
    len
}

fn tamp(buffer: &mut [u8], n: &mut isize, dp: &DesyncParams, info: &mut ProtoInfo) {
    // HTTP modifications
    if dp.mod_http != 0 && packets_glue::is_http(&buffer[..(*n as usize)]) {
        log(LOG_S, &format!("modify HTTP: n={}\n", *n));
        if packets_glue::mod_http(&mut buffer[..(*n as usize)], dp.mod_http).is_err() {
            log(LOG_E, "mod http error\n");
        }
    }

    // TLS minor version
    if dp.tlsminor_set && packets_glue::is_tls_chello(&buffer[..(*n as usize)]) {
        if *n >= 3 {
            buffer[2] = dp.tlsminor;
        }
    }

    // TLS record splitting (simplified placeholder)
    if dp.tlsrec_n != 0 && packets_glue::is_tls_chello(&buffer[..(*n as usize)]) {
        // Full part_tls port lands with packets.c/h.
        let _ = info;
        let _ = dp;
    }
}

// ---- API ----

pub fn pre_desync(_sfd: i32, _dp: *mut DesyncParams) -> i32 {
    // Linux drop_sack not ported here; keep as no-op for Windows-first.
    0
}

pub fn post_desync(_sfd: i32, _dp: *mut DesyncParams) -> i32 {
    0
}

pub fn desync(
    pool: &mut poolhd,
    val: &mut eval,
    buff: &mut CBuffer,
    n_inout: &mut isize,
    wait: &mut bool,
) -> isize {
    *wait = false;

    let pair_idx = match val.pair {
        Some(i) => i,
        None => return -1,
    };
    let pair = &mut pool.items[pair_idx as usize];

    let dp_ptr = pair.dp;
    if dp_ptr.is_null() {
        return -1;
    }
    let dp = unsafe { &*dp_ptr }; // borrow
    let mut info = ProtoInfo::default();

    let sfd = val.fd;
    let offset = buff.offset as isize;
    let mut n = *n_inout;

    if n < 0 {
        return -1;
    }
    if (offset as isize) > n {
        return 0;
    }

    let bfsize = buff.size;
    if bfsize == 0 {
        return 0;
    }

    // Ensure we can mutate buffer
    let buf_len = buff.data.len();
    let mut_view = &mut buff.data[..min(buf_len, bfsize)];

    // skip bookkeeping
    let skip = pair.round_sent;
    let part_skip = pair.part_sent;

    if skip == 0 {
        init_proto_info(&mut_view[..(n as usize)], &mut info);

        if info.host_pos != 0 {
            let hp = info.host_pos as usize;
            let hl = info.host_len.max(0) as usize;
            if hp + hl <= n as usize {
                let host = &mut_view[hp..hp + hl];
                if let Ok(s) = core::str::from_utf8(host) {
                    log(LOG_S, &format!("host: {} ({})\n", s, info.host_pos));
                }
            }
        } else {
            let take = min(16usize, n as usize);
            let mut hex = String::new();
            for b in &mut_view[..take] {
                hex.push_str(&format!("{:02X}", b));
            }
            log(LOG_S, &format!("bytes: {} ({})\n", hex, n));
        }
    }

    if skip == 0 {
        tamp(mut_view, &mut n, &dp, &mut info);
    }

    let mut lp = offset as i64;
    let mut i = 0;
    let mut r = 0;
    let mut curr_part: u32 = 0;

    while r > 0 || i < dp.parts_n {
        if r <= 0 {
            unsafe {
                let parts = core::slice::from_raw_parts(dp.parts, dp.parts_n as usize);
                let p = parts[i as usize];
                PART_TMP = p;
            }
            r = unsafe { PART_TMP.r };
            i += 1;
        }
        curr_part += 1;

        let part = unsafe { PART_TMP };
        let mut pos = gen_offset(
            part.pos as i64,
            part.flag,
            &mut_view[..(n as usize)],
            lp,
            &mut info,
        );
        pos += (part.s as i64) * ((part.r - r) as i64);

        // skip logic
        if (skip != 0 && (pos as isize) < skip as isize || curr_part < part_skip)
            && (part.flag & OFFSET_START) == 0
        {
            r -= 1;
            continue;
        }
        if offset != 0 && (pos as isize) < offset {
            r -= 1;
            continue;
        }
        if pos < 0 || pos < lp {
            log(
                LOG_E,
                &format!("split cancel: pos={} - {}, n={}\n", lp, pos, n),
            );
            break;
        }
        if pos as isize > n {
            log(LOG_E, &format!("pos reduced: {} -> {}\n", pos, n));
            pos = n as i64;
        }

        let mut s: isize = 0;

        if curr_part == part_skip {
            s = (pos - lp) as isize;
        } else {
            match part.m {
                x if x == demode::DESYNC_OOB as i32 => {
                    let start = lp as usize;
                    let end = pos as usize;
                    s = send_oob(
                        sfd,
                        &mut mut_view[start..],
                        (n - lp as isize),
                        (pos - lp) as i64,
                        dp.oob_char,
                    );
                }
                x if x == demode::DESYNC_DISORDER as i32 || x == demode::DESYNC_DISOOB as i32 => {
                    if ((part.r - r) % 2) == 0 {
                        if setttl(sfd, 1) < 0 {
                            s = -1;
                        } else {
                            val.restore_ttl = true;
                        }
                    } else {
                        val.restore_ttl = true;
                    }

                    let start = lp as usize;
                    let end = pos as usize;

                    if x == demode::DESYNC_DISOOB as i32 {
                        s = send_oob(
                            sfd,
                            &mut mut_view[start..],
                            (n - lp as isize),
                            (pos - lp) as i64,
                            dp.oob_char,
                        );
                    } else {
                        s = send_bytes(sfd, &mut_view[start..end], 0);
                        if s < 0 {
                            uniperror("send");
                        }
                    }
                }
                _ => {
                    // DESYNC_SPLIT / DESYNC_NONE / default
                    let start = lp as usize;
                    let end = pos as usize;
                    s = send_bytes(sfd, &mut_view[start..end], 0);
                }
            }
        }

        log(
            LOG_S,
            &format!(
                "split: pos={}-{} ({}), m={}\n",
                lp,
                pos,
                s,
                part_mode_name(part.m)
            ),
        );

        pair.part_sent = curr_part;

        if s == ERR_WAIT {
            let vidx = eval_index(pool, val);
            conev::set_timer(pool, vidx, unsafe { PARAMS.await_int as i64 });
            *wait = true;
            return (lp as isize) - offset;
        }

        if s < 0 {
            if get_e() == Errno::EAGAIN {
                return (lp as isize) - offset;
            }
            return -1;
        } else if s != (pos - lp) as isize {
            log(LOG_E, &format!("{} != {}\n", s, (pos - lp)));
            return (lp as isize) + s - offset;
        }

        // wait_send / notsent detection (linux tcpi_notsent not ported here)
        let wait_send = unsafe { PARAMS.wait_send };
        if wait_send && curr_part > part_skip {
            log(LOG_S, "wait_send\n");
            let vidx = eval_index(pool, val);
            conev::set_timer(pool, vidx, unsafe { PARAMS.await_int as i64 });
            *wait = true;
            return (pos as isize) - offset;
        }

        restore_state(val);
        lp = pos;

        r -= 1;
    }

    // send rest
    if (lp as isize) < n {
        log(
            if lp != 0 { LOG_S } else { LOG_L },
            &format!("send: pos={} - {}\n", lp, n),
        );
        let start = lp as usize;
        let s = send_bytes(sfd, &mut_view[start..(n as usize)], 0);
        if s < 0 {
            if get_e() == Errno::EAGAIN {
                return (lp as isize) - offset;
            }
            uniperror("send");
            return -1;
        }
    }

    *n_inout = n;
    n - offset
}

pub fn desync_udp(
    sfd: i32,
    buffer: &mut [u8],
    n: isize,
    _dst: *const core::ffi::c_void,
    dp: *mut DesyncParams,
) -> isize {
    if dp.is_null() {
        return -1;
    }
    let dp = unsafe { &*dp };

    if n <= 0 {
        return n;
    }

    // logging (first 16 bytes)
    let take = min(16usize, n as usize);
    let mut hex = String::new();
    for b in &buffer[..take] {
        hex.push_str(&format!("{:02X}", b));
    }
    log(LOG_S, &format!("bytes: {} ({})\n", hex, n));

    // UDP fake send not implemented here (needs packets.c port).
    // Keep the real send path.
    send_bytes(sfd, &buffer[..(n as usize)], 0)
}

// ---- small helpers ----

static mut PART_TMP: part = part {
    m: 0,
    flag: 0,
    pos: 0,
    r: 0,
    s: 0,
};

unsafe fn part_copy(dst: &mut part, src: &part) {
    *dst = *src;
}

fn part_mode_name(m: i32) -> &'static str {
    match m {
        x if x == demode::DESYNC_NONE as i32 => "none",
        x if x == demode::DESYNC_SPLIT as i32 => "split",
        x if x == demode::DESYNC_DISORDER as i32 => "disorder",
        x if x == demode::DESYNC_OOB as i32 => "oob",
        x if x == demode::DESYNC_DISOOB as i32 => "disoob",
        x if x == demode::DESYNC_FAKE as i32 => "fake",
        _ => "unknown",
    }
}
