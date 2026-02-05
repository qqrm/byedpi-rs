// src/desync.rs
//
// Port of desync.h / desync.c (Windows-first).
// Notes:
// - Linux-only optimizations (TCP_INFO notsent bytes, BPF drop_sack, TCP_MD5SIG, splice/vmsplice) are cfg-gated.
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
use crate::packets;
use crate::params::{
    DesyncParams, FM_ORIG, FM_RAND, OFFSET_END, OFFSET_HOST, OFFSET_MID, OFFSET_RAND, OFFSET_SNI,
    OFFSET_START, PARAMS, demode, packet, part,
};

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::*;

#[cfg(not(windows))]
use libc::*;

const ERR_WAIT: isize = -12;
#[cfg(target_os = "linux")]
const DEFAULT_TTL: i32 = 8;

// ---- protocol info ----

#[derive(Clone, Copy, Default)]
pub struct ProtoInfo {
    pub init: bool,
    pub type_: i32,
    pub host_len: i32,
    pub host_pos: i32,
}

fn init_proto_info(buffer: &[u8], info: &mut ProtoInfo) {
    if info.init {
        return;
    }

    let mut host: *mut i8 = ptr::null_mut();
    let hlen = packets::parse_tls(
        buffer.as_ptr() as *const i8,
        buffer.len(),
        &mut host,
    );
    if hlen != 0 {
        info.type_ = packets::IS_HTTPS;
        info.host_len = hlen;
    } else {
        let hlen = packets::parse_http(
            buffer.as_ptr() as *const i8,
            buffer.len(),
            &mut host,
            ptr::null_mut(),
        );
        if hlen != 0 {
            info.type_ = packets::IS_HTTP;
            info.host_len = hlen;
        }
    }
    info.host_pos = if host.is_null() {
        0
    } else {
        unsafe { (host as *const u8).offset_from(buffer.as_ptr()) as i32 }
    };
    info.init = true;
}

// static long gen_offset(...)
fn gen_offset(mut pos: i64, flag: i32, buffer: &[u8], lp: i64, info: &mut ProtoInfo) -> i64 {
    let n = buffer.len() as i64;

    if (flag & (OFFSET_SNI | OFFSET_HOST)) != 0 {
        init_proto_info(buffer, info);

        if info.host_pos == 0
            || (((flag & OFFSET_SNI) != 0) && info.type_ != packets::IS_HTTPS)
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
    #[cfg(target_os = "linux")]
    {
        if !val.restore_fake.is_null() && val.restore_fake_len != 0 {
            unsafe {
                ptr::copy_nonoverlapping(
                    val.restore_orig,
                    val.restore_fake,
                    val.restore_orig_len,
                );
                libc::munmap(
                    val.restore_fake as *mut libc::c_void,
                    val.restore_fake_len,
                );
            }
            val.restore_fake = ptr::null_mut();
            val.restore_fake_len = 0;
        }
        if val.restore_md5 {
            let _ = set_md5sig(val.fd, 0);
            val.restore_md5 = false;
        }
    }
    if val.restore_ttl {
        unsafe {
            let ttl = PARAMS.def_ttl;
            let _ = setttl(val.fd, ttl);
        }
        val.restore_ttl = false;
    }
}

#[cfg(target_os = "linux")]
fn drop_sack(fd: i32) -> i32 {
    let code = [
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 0x0000000c,
        },
        libc::sock_filter {
            code: 0x74,
            jt: 0,
            jf: 0,
            k: 0x00000004,
        },
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 3,
            k: 0x0000000b,
        },
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 0x00000022,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: 0x00000005,
        },
        libc::sock_filter {
            code: 0x6,
            jt: 0,
            jf: 0,
            k: 0x00000000,
        },
        libc::sock_filter {
            code: 0x6,
            jt: 0,
            jf: 0,
            k: 0x00040000,
        },
    ];
    let bpf = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_ptr() as *mut libc::sock_filter,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &bpf as *const _ as *const libc::c_void,
            mem::size_of_val(&bpf) as libc::socklen_t,
        )
    };
    if rc == -1 {
        uniperror("setsockopt SO_ATTACH_FILTER");
        return -1;
    }
    0
}

#[cfg(not(target_os = "linux"))]
fn drop_sack(_fd: i32) -> i32 {
    0
}

#[cfg(target_os = "linux")]
fn sock_has_notsent(sfd: i32) -> bool {
    let mut tcpi: libc::tcp_info = unsafe { mem::zeroed() };
    let mut ts = mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sfd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut tcpi as *mut _ as *mut libc::c_void,
            &mut ts,
        )
    };
    if rc < 0 {
        uniperror("getsockopt TCP_INFO");
        return false;
    }
    if tcpi.tcpi_state != libc::TCP_ESTABLISHED as u8 {
        log(LOG_E, &format!("state: {}\n", tcpi.tcpi_state));
        return false;
    }
    let notsent_offset = core::mem::offset_of!(libc::tcp_info, tcpi_notsent_bytes);
    if (ts as usize) <= notsent_offset {
        log(LOG_E, "tcpi_notsent_bytes not provided\n");
        return false;
    }
    tcpi.tcpi_notsent_bytes != 0
}

#[cfg(not(target_os = "linux"))]
fn sock_has_notsent(_sfd: i32) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn alloc_pktd(n: usize) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            n,
            libc::PROT_WRITE | libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        ptr::null_mut()
    } else {
        p as *mut u8
    }
}

#[cfg(not(target_os = "linux"))]
fn alloc_pktd(n: usize) -> *mut u8 {
    unsafe { libc::malloc(n) as *mut u8 }
}

#[cfg(target_os = "linux")]
fn set_md5sig(sfd: i32, key_len: u16) -> i32 {
    let mut md5: libc::tcp_md5sig = unsafe { mem::zeroed() };
    md5.tcpm_keylen = key_len;
    let mut addr_size = mem::size_of_val(&md5.tcpm_addr) as libc::socklen_t;
    let rc = unsafe {
        libc::getpeername(
            sfd,
            &mut md5.tcpm_addr as *mut _ as *mut libc::sockaddr,
            &mut addr_size,
        )
    };
    if rc < 0 {
        uniperror("getpeername");
        return -1;
    }
    let rc = unsafe {
        libc::setsockopt(
            sfd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            &md5 as *const _ as *const libc::c_void,
            mem::size_of_val(&md5) as libc::socklen_t,
        )
    };
    if rc < 0 {
        uniperror("setsockopt TCP_MD5SIG");
        return -1;
    }
    0
}

#[cfg(not(target_os = "linux"))]
fn set_md5sig(_sfd: i32, _key_len: u16) -> i32 {
    0
}

fn get_tcp_fake(buffer: &[u8], info: &mut ProtoInfo, opt: &DesyncParams) -> packet {
    let mut pkt = if !opt.fake_data.data.is_null() {
        opt.fake_data
    } else {
        if info.type_ == 0 {
            if packets::is_tls_chello(buffer.as_ptr() as *const i8, buffer.len()) {
                info.type_ = packets::IS_HTTPS;
            } else if packets::is_http(buffer.as_ptr() as *const i8, buffer.len()) {
                info.type_ = packets::IS_HTTP;
            }
        }
        if info.type_ == packets::IS_HTTP {
            packet {
                size: packets::HTTP_DATA.len() as isize,
                data: packets::HTTP_DATA.as_ptr() as *mut i8,
                off: 0,
            }
        } else {
            packet {
                size: packets::TLS_DATA.len() as isize,
                data: packets::TLS_DATA.as_ptr() as *mut i8,
                off: 0,
            }
        }
    };

    let n = buffer.len() as isize;
    let ps = if n > pkt.size { n } else { pkt.size };
    let p = alloc_pktd(ps as usize);
    if p.is_null() {
        uniperror("malloc/mmap");
        pkt.data = ptr::null_mut();
        return pkt;
    }

    let mut sni: *const i8 = ptr::null();
    if opt.fake_sni_count != 0 {
        let idx = (rand_u32() % (opt.fake_sni_count as u32)) as isize;
        unsafe {
            sni = *opt.fake_sni_list.offset(idx);
        }
    }

    loop {
        let mut f_size = opt.fake_tls_size;
        if f_size < 0 {
            f_size = n as i32 + f_size;
        }
        if f_size > n as i32 || f_size <= 0 {
            f_size = n as i32;
        }

        if (opt.fake_mod & FM_ORIG) != 0 && info.type_ == packets::IS_HTTPS {
            unsafe {
                ptr::copy_nonoverlapping(buffer.as_ptr(), p, n as usize);
            }
            if sni.is_null()
                || unsafe {
                    packets::change_tls_sni(sni, p as *mut i8, n, f_size as isize)
                } != 0
            {
                break;
            }
            log(LOG_E, "change sni error\n");
        }
        unsafe {
            ptr::copy_nonoverlapping(pkt.data as *const u8, p, pkt.size as usize);
        }
        if !sni.is_null()
            && unsafe {
                packets::change_tls_sni(sni, p as *mut i8, pkt.size, f_size as isize)
            } < 0
        {
            break;
        }
        break;
    }

    if (opt.fake_mod & FM_RAND) != 0 {
        unsafe {
            packets::randomize_tls(p as *mut i8, ps);
        }
    }
    pkt.data = p as *mut i8;
    pkt.size = ps;

    if opt.fake_offset.m != 0 {
        let off = gen_offset(
            opt.fake_offset.pos as i64,
            opt.fake_offset.flag,
            buffer,
            0,
            info,
        );
        pkt.off = off as isize;
        if pkt.off > pkt.size || pkt.off < 0 {
            pkt.off = 0;
        }
    }
    pkt
}

#[cfg(target_os = "linux")]
fn send_fake(
    val: &mut eval,
    buffer: &[u8],
    pos: isize,
    opt: &DesyncParams,
    pkt: packet,
) -> isize {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        uniperror("pipe");
        return -1;
    }
    let mut ret: isize = -1;
    val.restore_orig = buffer.as_ptr();
    val.restore_orig_len = pos as usize;

    loop {
        let p = unsafe { pkt.data.offset(pkt.off) };
        val.restore_fake = p as *mut u8;
        val.restore_fake_len = pkt.size as usize;

        let ttl = if opt.ttl != 0 { opt.ttl } else { DEFAULT_TTL };
        if setttl(val.fd, ttl) < 0 {
            break;
        }
        val.restore_ttl = true;

        if opt.md5sig && set_md5sig(val.fd, 5) != 0 {
            break;
        }
        val.restore_md5 = opt.md5sig;

        let mut vec = libc::iovec {
            iov_base: p as *mut libc::c_void,
            iov_len: pos as usize,
        };
        let len = unsafe { libc::vmsplice(fds[1], &mut vec as *mut _, 1, libc::SPLICE_F_GIFT) };
        if len < 0 {
            uniperror("vmsplice");
            break;
        }
        let len = unsafe { libc::splice(fds[0], ptr::null_mut(), val.fd, ptr::null_mut(), len as usize, 0) };
        if len < 0 {
            uniperror("splice");
            break;
        }
        ret = len as isize;
        break;
    }

    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    ret
}

#[cfg(not(target_os = "linux"))]
fn send_fake(
    _val: &mut eval,
    _buffer: &[u8],
    _pos: isize,
    _opt: &DesyncParams,
    _pkt: packet,
) -> isize {
    -1
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

fn tamp(
    buffer: &mut [u8],
    bfsize: usize,
    n: &mut isize,
    dp: &DesyncParams,
    info: &mut ProtoInfo,
) {
    // HTTP modifications
    if dp.mod_http != 0
        && packets::is_http(buffer.as_ptr() as *const i8, *n as usize)
    {
        log(LOG_S, &format!("modify HTTP: n={}\n", *n));
        if packets::mod_http(
            buffer.as_mut_ptr() as *mut i8,
            *n as usize,
            dp.mod_http,
        ) != 0
        {
            log(LOG_E, "mod http error\n");
        }
    }

    // TLS minor version
    if dp.tlsminor_set
        && packets::is_tls_chello(buffer.as_ptr() as *const i8, *n as usize)
    {
        if *n >= 3 {
            buffer[2] = dp.tlsminor;
        }
    }

    // TLS record splitting
    if dp.tlsrec_n != 0
        && packets::is_tls_chello(buffer.as_ptr() as *const i8, *n as usize)
    {
        let mut lp: i64 = 0;
        let mut part = part {
            m: 0,
            flag: 0,
            pos: 0,
            r: 0,
            s: 0,
        };
        let mut i = 0;
        let mut r = 0;
        let mut rc = 0;

        while r > 0 || i < dp.tlsrec_n {
            if r <= 0 {
                unsafe {
                    let parts = core::slice::from_raw_parts(dp.tlsrec, dp.tlsrec_n as usize);
                    part_copy(&mut part, &parts[i as usize]);
                }
                r = part.r;
                i += 1;
            }

            let mut pos = (rc as i64) * 5;
            let remaining = (*n as i64).saturating_sub(pos);
            let slice_len = remaining.max(0) as usize;
            pos += gen_offset(
                part.pos as i64,
                part.flag,
                &buffer[..min(slice_len, buffer.len())],
                lp,
                info,
            );
            if part.pos < 0 || part.flag != 0 {
                pos -= 5;
            }
            pos += (part.s as i64) * ((part.r - r) as i64);

            if pos < lp {
                log(LOG_E, &format!("tlsrec cancel: {} < {}\n", pos, lp));
                break;
            }

            let lp_usize = lp.max(0) as usize;
            if lp_usize >= bfsize {
                log(LOG_E, &format!("tlsrec error: pos={}, n={}\n", pos, *n));
                break;
            }
            let bsize = min(bfsize, buffer.len()).saturating_sub(lp_usize);
            let n_rem = *n - lp as isize;
            let pos_rel = pos - lp;
            if packets::part_tls(
                buffer[lp_usize..].as_mut_ptr() as *mut i8,
                bsize,
                n_rem,
                pos_rel,
            ) == 0
            {
                log(LOG_E, &format!("tlsrec error: pos={}, n={}\n", pos, *n));
                break;
            }

            log(LOG_S, &format!("tlsrec: pos={}, n={}\n", pos, *n));
            *n += 5;
            lp = pos + 5;

            rc += 1;
            r -= 1;
        }
    }
}

// ---- API ----

pub fn pre_desync(sfd: i32, dp: *mut DesyncParams) -> i32 {
    if dp.is_null() {
        return -1;
    }
    let dp = unsafe { &*dp };
    if dp.drop_sack && drop_sack(sfd) != 0 {
        return -1;
    }
    0
}

pub fn post_desync(sfd: i32, dp: *mut DesyncParams) -> i32 {
    if dp.is_null() {
        return -1;
    }
    let dp = unsafe { &*dp };
    #[cfg(target_os = "linux")]
    {
        if dp.drop_sack {
            let nop: i32 = 0;
            let rc = unsafe {
                libc::setsockopt(
                    sfd,
                    libc::SOL_SOCKET,
                    libc::SO_DETACH_FILTER,
                    &nop as *const _ as *const libc::c_void,
                    mem::size_of_val(&nop) as libc::socklen_t,
                )
            };
            if rc == -1 {
                uniperror("setsockopt SO_DETACH_FILTER");
                return -1;
            }
        }
    }
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
        tamp(mut_view, bfsize, &mut n, &dp, &mut info);
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
                x if x == demode::DESYNC_FAKE as i32 => {
                    let pkt = get_tcp_fake(&mut_view[..(n as usize)], &mut info, dp);
                    if pkt.data.is_null() {
                        return -1;
                    }
                    if pos != lp {
                        let start = lp as usize;
                        let len = (pos - lp) as usize;
                        s = send_fake(
                            val,
                            &mut_view[start..start.saturating_add(len)],
                            len as isize,
                            dp,
                            pkt,
                        );
                    }
                    #[cfg(not(target_os = "linux"))]
                    unsafe {
                        libc::free(pkt.data as *mut libc::c_void);
                    }
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

        // wait_send / notsent detection
        let wait_send = unsafe { PARAMS.wait_send };
        if sock_has_notsent(sfd) || (wait_send && curr_part > part_skip) {
            log(LOG_S, "sock_has_notsent\n");
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
