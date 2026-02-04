// src/packets.rs
//
// Port of packets.h / packets.c (Windows-first, no OS deps).
// This is a direct translation of the C parsing/mutation logic for:
// - TLS ClientHello / ServerHello detection + SNI rewrite + randomization
// - HTTP request detection + Host parsing + header “mod_http” tweaks
// - HTTP redirect check
// - TLS session id mismatch check
//
// API intentionally keeps C-like signatures (raw pointers) because the rest of the port
// currently passes raw buffers around.
//
// NOTE: These functions assume `buffer` points to writable memory of at least `bsize` bytes.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use core::{cmp::min, ptr};

pub const IS_TCP: i32 = 1;
pub const IS_UDP: i32 = 2;
pub const IS_HTTP: i32 = 4;
pub const IS_HTTPS: i32 = 8;
pub const IS_IPV4: i32 = 16;

pub const MH_HMIX: i32 = 1;
pub const MH_SPACE: i32 = 2;
pub const MH_DMIX: i32 = 4;

#[inline]
fn antohs(data: &[u8], i: usize) -> u16 {
    ((data[i] as u16) << 8) | (data[i + 1] as u16)
}

#[inline]
fn shtona(data: &mut [u8], i: usize, x: u16) {
    data[i] = (x >> 8) as u8;
    data[i + 1] = (x & 0xff) as u8;
}

pub static TLS_DATA: [u8; 517] = {
    let mut a = [0u8; 517];
    let b = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x03\x5f\
\x6f\x2c\xed\x13\x22\xf8\xdc\xb2\xf2\x60\x48\x2d\x72\
\x66\x6f\x57\xdd\x13\x9d\x1b\x37\xdc\xfa\x36\x2e\xba\
\xf9\x92\x99\x3a\x20\xf9\xdf\x0c\x2e\x8a\x55\x89\x82\
\x31\x63\x1a\xef\xa8\xbe\x08\x58\xa7\xa3\x5a\x18\xd3\
\x96\x5f\x04\x5c\xb4\x62\xaf\x89\xd7\x0f\x8b\x00\x3e\
\x13\x02\x13\x03\x13\x01\xc0\x2c\xc0\x30\x00\x9f\xcc\
\xa9\xcc\xa8\xcc\xaa\xc0\x2b\xc0\x2f\x00\x9e\xc0\x24\
\xc0\x28\x00\x6b\xc0\x23\xc0\x27\x00\x67\xc0\x0a\xc0\
\x14\x00\x39\xc0\x09\xc0\x13\x00\x33\x00\x9d\x00\x9c\
\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff\x01\x00\x01\
\x75\x00\x00\x00\x16\x00\x14\x00\x00\x11\x77\x77\x77\
\x2e\x77\x69\x6b\x69\x70\x65\x64\x69\x61\x2e\x6f\x72\
\x67\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x16\
\x00\x14\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x01\
\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x10\x00\x0e\
\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\
\x31\x00\x16\x00\x00\x00\x17\x00\x00\x00\x31\x00\x00\
\x00\x0d\x00\x2a\x00\x28\x04\x03\x05\x03\x06\x03\x08\
\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\
\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\
\x02\x04\x02\x05\x02\x06\x02\x00\x2b\x00\x09\x08\x03\
\x04\x03\x03\x03\x02\x03\x01\x00\x2d\x00\x02\x01\x01\
\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x11\x8c\xb8\
\x8c\xe8\x8a\x08\x90\x1e\xee\x19\xd9\xdd\xe8\xd4\x06\
\xb1\xd1\xe2\xab\xe0\x16\x63\xd6\xdc\xda\x84\xa4\xb8\
\x4b\xfb\x0e\x00\x15\x00\xac\x00\x00\x00\x00\x00\x00";
    let mut i = 0usize;
    while i < b.len() {
        a[i] = b[i];
        i += 1;
    }
    a
};

pub static HTTP_DATA: [u8; 43] = *b"GET / HTTP/1.1\r\nHost: www.wikipedia.org\r\n\r\n";

pub static mut UDP_DATA: [u8; 64] = [0u8; 64];

fn rand_u8() -> u8 {
    // xorshift32
    static mut S: u32 = 0x1234_5678;
    unsafe {
        let mut x = S;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        S = x;
        (x & 0xff) as u8
    }
}

fn strncasestr(a: &[u8], b: &[u8]) -> Option<usize> {
    if b.is_empty() || a.len() < b.len() {
        return None;
    }
    let first = b[0].to_ascii_lowercase();
    let bs = b.len();

    let mut p = 0usize;
    while p < a.len() {
        // find first byte occurrence
        while p < a.len() && a[p].to_ascii_lowercase() != first {
            p += 1;
        }
        if p >= a.len() || p + bs > a.len() {
            return None;
        }
        let mut ok = true;
        for i in 0..bs {
            if a[p + i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
                ok = false;
                break;
            }
        }
        if ok {
            return Some(p);
        }
        p += 1;
    }
    None
}

fn find_tls_ext_offset(type_: u16, data: &[u8], size: usize, mut skip: usize) -> usize {
    if size <= skip + 2 {
        return 0;
    }
    let mut ext_len = antohs(data, skip) as usize;
    skip += 2;

    if ext_len < size.saturating_sub(skip) {
        ext_len += skip;
    } else {
        ext_len = size;
    }

    let mut cur = skip;
    while cur + 4 < ext_len {
        let epyt = antohs(data, cur);
        if type_ == epyt {
            return cur;
        }
        let len = antohs(data, cur + 2) as usize;
        cur = cur.saturating_add(len + 4);
    }
    0
}

fn find_ext_block(data: &[u8], size: usize) -> usize {
    if size < 44 {
        return 0;
    }
    let sid_len = data[43] as usize;
    if size < 44 + sid_len + 2 {
        return 0;
    }
    let cip_len = antohs(data, 44 + sid_len) as usize;
    let skip = 44 + sid_len + 2 + cip_len + 2;
    if skip > size { 0 } else { skip }
}

fn merge_tls_records(buffer: &mut [u8], n: isize) -> i32 {
    if n < 5 {
        return 0;
    }
    let n = n as usize;

    let mut full_sz: u16 = 0;
    let mut r_sz = antohs(buffer, 3);
    let mut i = 0i32;

    loop {
        full_sz = full_sz.wrapping_add(r_sz);
        let idx = 5usize + (full_sz as usize);
        if idx > n.saturating_sub(5) || buffer[idx] != buffer[0] {
            break;
        }
        r_sz = antohs(buffer, idx + 3);
        if (full_sz as usize) + 10 + (r_sz as usize) > n {
            break;
        }

        // memmove(buffer + 5 + full_sz, buffer + 10 + full_sz, ...)
        let dst = 5 + (full_sz as usize);
        let src = 10 + (full_sz as usize);
        if src <= n {
            buffer.copy_within(src..n, dst);
        }
        i += 1;
    }

    shtona(buffer, 3, full_sz);
    shtona(buffer, 7, full_sz.wrapping_sub(4));
    i * 5
}

fn copy_name(out: &mut [u8], name: &[u8]) {
    for i in 0..out.len() {
        out[i] = match name[i] {
            b'*' => {
                let r = (rand_u8() as u16) % (10 + (b'z' - b'a' + 1) as u16);
                if r < 10 {
                    (b'0' + (r as u8))
                } else {
                    (b'a' - 10 + (r as u8))
                }
            }
            b'?' => b'a' + (rand_u8() % (b'z' - b'a' + 1)),
            b'#' => b'0' + (rand_u8() % 10),
            c => c,
        };
    }
}

fn remove_ks_group(buffer: &mut [u8], n: isize, skip: usize, group: u16) -> i32 {
    let n = n as usize;
    let ks_offs = find_tls_ext_offset(0x0033, buffer, n, skip);
    if ks_offs == 0 || ks_offs + 6 >= n {
        return 0;
    }
    let ks_sz = antohs(buffer, ks_offs + 2) as usize;
    if ks_offs + 4 + ks_sz > n {
        return 0;
    }

    let mut g_offs = ks_offs + 4 + 2;
    while g_offs + 4 < ks_offs + 4 + ks_sz {
        let g_sz = antohs(buffer, g_offs + 2) as usize;
        if ks_offs + 4 + g_sz > n {
            return 0;
        }
        let g_tp = antohs(buffer, g_offs);
        if g_tp == group {
            let g_end = g_offs + 4 + g_sz;
            buffer.copy_within(g_end..n, g_offs);

            let new_ks = (ks_sz - (4 + g_sz)) as u16;
            shtona(buffer, ks_offs + 2, new_ks);
            shtona(buffer, ks_offs + 4, (new_ks as i32 - 2) as u16);
            return (4 + g_sz) as i32;
        }
        g_offs += 4 + g_sz;
    }
    0
}

fn remove_tls_ext(buffer: &mut [u8], n: isize, skip: usize, type_: u16) -> i32 {
    let n = n as usize;
    let ext_offs = find_tls_ext_offset(type_, buffer, n, skip);
    if ext_offs == 0 {
        return 0;
    }
    let ext_sz = antohs(buffer, ext_offs + 2) as usize;
    let ext_end = ext_offs + 4 + ext_sz;
    if ext_end > n {
        return 0;
    }
    buffer.copy_within(ext_end..n, ext_offs);
    (ext_sz + 4) as i32
}

fn resize_ech_ext(buffer: &mut [u8], n: isize, skip: usize, mut inc: i32) -> i32 {
    let n = n as usize;
    let ech_offs = find_tls_ext_offset(0xfe0d, buffer, n, skip);
    if ech_offs == 0 {
        return 0;
    }
    let ech_sz = antohs(buffer, ech_offs + 2) as usize;
    let ech_end = ech_offs + 4 + ech_sz;

    if ech_sz < 12 || ech_end > n {
        return 0;
    }
    let enc_sz = antohs(buffer, ech_offs + 4 + 6) as usize;
    let pay_offs = ech_offs + 4 + 8 + enc_sz;
    let pay_sz = ech_sz as i32 - (8 + enc_sz + 2) as i32;

    if pay_offs + 2 > n {
        return 0;
    }
    if pay_sz < -inc {
        inc = -pay_sz;
    }

    shtona(buffer, ech_offs + 2, (ech_sz as i32 + inc) as u16);
    shtona(buffer, pay_offs, (pay_sz + inc) as u16);

    let inc_us = if inc >= 0 {
        inc as usize
    } else {
        (-inc) as usize
    };

    if inc >= 0 {
        // shift right
        if ech_end + inc_us <= n {
            buffer.copy_within(ech_end..n - inc_us, ech_end + inc_us);
        }
    } else {
        // shift left
        buffer.copy_within(ech_end..n, ech_end - inc_us);
    }
    inc
}

fn resize_sni(buffer: &mut [u8], n: isize, sni_offs: usize, sni_sz: usize, new_sz: usize) {
    shtona(buffer, sni_offs + 2, (new_sz + 5) as u16);
    shtona(buffer, sni_offs + 4, (new_sz + 3) as u16);
    shtona(buffer, sni_offs + 7, new_sz as u16);

    let sni_end = sni_offs + 4 + sni_sz;
    let diff = new_sz as isize - (sni_sz as isize - 5);
    if diff == 0 {
        return;
    }
    if diff > 0 {
        let d = diff as usize;
        // shift right
        buffer.copy_within(sni_end..(n as usize) - d, sni_end + d);
    } else {
        let d = (-diff) as usize;
        // shift left
        buffer.copy_within(sni_end..(n as usize), sni_end - d);
    }
}

pub fn change_tls_sni(host: *const i8, buffer: *mut i8, n: isize, nn: isize) -> i32 {
    if host.is_null() || buffer.is_null() || n <= 0 || nn <= 0 {
        return -1;
    }

    unsafe {
        let host_bytes = cstr_bytes(host);
        let buf = core::slice::from_raw_parts_mut(buffer as *mut u8, nn as usize);

        let mut avail = merge_tls_records(buf, n) as i32;
        avail += (nn - n) as i32;

        let mut r_sz = antohs(buf, 3) as i32;
        r_sz += avail;

        let skip = find_ext_block(buf, n as usize);
        if skip == 0 {
            return -1;
        }

        let mut sni_offs = find_tls_ext_offset(0x0000, buf, n as usize, skip);
        if sni_offs == 0 {
            return -1;
        }

        let new_sz = host_bytes.len();
        let sni_sz = antohs(buf, sni_offs + 2) as usize;

        if sni_offs + 4 + sni_sz > n as usize {
            return -1;
        }

        let mut diff = (new_sz as i32) - (sni_sz as i32 - 5);
        avail -= diff;

        if diff < 0 && avail > 0 {
            resize_sni(buf, n, sni_offs, sni_sz, new_sz);
            diff = 0;
        }

        if avail != 0 {
            avail -= resize_ech_ext(buf, n, skip, avail);
        }
        if avail < -50 {
            avail += remove_ks_group(buf, n, skip, 0x11ec);
        }

        const EXTS: &[u16] = &[
            0x0015, // padding
            0x0031, // post_handshake_auth
            0x0010, // ALPN
            0x001c, // record_size_limit
            0x0023, // session_ticket
            0x0005, // status_request
            0x0022, // delegated_credentials
            0x0012, // signed_certificate_timestamp
            0x001b, // compress_certificate
            0,
        ];

        let mut ei = 0usize;
        while avail != 0 && avail < 4 {
            let t = EXTS[ei];
            if t == 0 {
                return -1;
            }
            avail += remove_tls_ext(buf, n, skip, t);
            ei += 1;
        }

        sni_offs = find_tls_ext_offset(0x0000, buf, n as usize, skip);
        if sni_offs == 0 {
            return -1;
        }

        if diff != 0 {
            resize_sni(buf, n, sni_offs, sni_sz, new_sz);
        }

        if sni_offs + 9 + new_sz > nn as usize {
            return -1;
        }
        copy_name(&mut buf[sni_offs + 9..sni_offs + 9 + new_sz], host_bytes);

        if avail > 0 {
            avail -= resize_ech_ext(buf, n, skip, avail);
        }

        if avail >= 4 {
            let tail = (5 + (r_sz as usize)).saturating_sub(avail as usize);
            if tail + 4 <= nn as usize {
                shtona(buf, tail, 0x0015);
                shtona(buf, tail + 2, (avail - 4) as u16);
                let pad_len = (avail - 4) as usize;
                if tail + 4 + pad_len <= nn as usize {
                    buf[tail + 4..tail + 4 + pad_len].fill(0);
                }
            }
        }

        shtona(buf, 3, r_sz as u16);
        shtona(buf, 7, (r_sz - 4) as u16);
        shtona(buf, skip, (5 + (r_sz as usize) - skip - 2) as u16);
        0
    }
}

pub fn is_tls_chello(buffer: *const i8, bsize: usize) -> bool {
    if buffer.is_null() || bsize <= 5 {
        return false;
    }
    unsafe {
        let b = core::slice::from_raw_parts(buffer as *const u8, bsize);
        bsize > 5 && antohs(b, 0) == 0x1603 && b[5] == 0x01
    }
}

pub fn parse_tls(buffer: *const i8, bsize: usize, hs: *mut *mut i8) -> i32 {
    if buffer.is_null() || hs.is_null() {
        return 0;
    }
    unsafe {
        let b = core::slice::from_raw_parts(buffer as *const u8, bsize);
        if !is_tls_chello(buffer, bsize) {
            return 0;
        }
        let skip = find_ext_block(b, bsize);
        if skip == 0 {
            return 0;
        }
        let sni_offs = find_tls_ext_offset(0x0000, b, bsize, skip);
        if sni_offs == 0 || sni_offs + 12 >= bsize {
            return 0;
        }
        let len = antohs(b, sni_offs + 7) as usize;
        if sni_offs + 9 + len > bsize {
            return 0;
        }
        *hs = (buffer as *mut i8).add(sni_offs + 9);
        len as i32
    }
}

pub fn is_http(buffer: *const i8, bsize: usize) -> bool {
    if buffer.is_null() || bsize < 16 {
        return false;
    }
    unsafe {
        let b = core::slice::from_raw_parts(buffer as *const u8, bsize);
        let c0 = b[0];
        if c0 < b'C' || c0 > b'T' {
            return false;
        }
        const METHODS: &[&[u8]] = &[
            b"HEAD", b"GET", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT", b"TRACE", b"PATCH",
        ];
        for m in METHODS {
            if b.len() >= m.len() && &b[..m.len()] == *m {
                return true;
            }
        }
        false
    }
}

pub fn parse_http(buffer: *const i8, bsize: usize, hs: *mut *mut i8, port: *mut u16) -> i32 {
    if buffer.is_null() || hs.is_null() {
        return 0;
    }
    unsafe {
        let b = core::slice::from_raw_parts(buffer as *const u8, bsize);
        if !is_http(buffer, bsize) {
            return 0;
        }
        let host_tag = b"\nHost:";
        let Some(mut p) = strncasestr(b, host_tag) else {
            return 0;
        };
        p += host_tag.len();

        while p < b.len() && b[p] == b' ' {
            p += 1;
        }
        let Some(mut l_end) = b[p..].iter().position(|&c| c == b'\n').map(|x| p + x) else {
            return 0;
        };

        while l_end > p && b[l_end - 1].is_ascii_whitespace() {
            l_end -= 1;
        }

        if l_end == 0 {
            return 0;
        }

        // scan optional :port at end
        let mut h_end = l_end.saturating_sub(1);
        while h_end > p && b[h_end].is_ascii_digit() {
            h_end -= 1;
        }

        if b.get(h_end).copied() != Some(b':') {
            if !port.is_null() {
                *port = 80;
            }
            h_end = l_end;
        } else if !port.is_null() {
            // parse digits
            let digits = &b[h_end + 1..l_end];
            let mut acc: u32 = 0;
            if digits.is_empty() {
                return 0;
            }
            for &d in digits {
                if !d.is_ascii_digit() {
                    return 0;
                }
                acc = acc.saturating_mul(10).saturating_add((d - b'0') as u32);
                if acc > 0xffff {
                    return 0;
                }
            }
            if acc == 0 {
                return 0;
            }
            *port = acc as u16;
        }

        let mut host = p;
        if b.get(host) == Some(&b'[') {
            if h_end == 0 || b.get(h_end - 1) != Some(&b']') {
                return 0;
            }
            host += 1;
            h_end -= 1;
        }

        *hs = (buffer as *mut i8).add(host);
        (h_end as i32 - host as i32)
    }
}

fn get_http_code(b: &[u8]) -> i32 {
    if b.len() < 13 || &b[..7] != b"HTTP/1." {
        return 0;
    }
    if !b[12..].contains(&b'\n') {
        return 0;
    }
    // parse number at b[9..]
    if b.len() < 12 {
        return 0;
    }
    if !b[9].is_ascii_digit() || !b[10].is_ascii_digit() || !b[11].is_ascii_digit() {
        return 0;
    }
    let num = ((b[9] - b'0') as i32) * 100 + ((b[10] - b'0') as i32) * 10 + ((b[11] - b'0') as i32);
    if num < 100 || num > 511 {
        return 0;
    }
    if !b[12].is_ascii_whitespace() {
        return 0;
    }
    num
}

pub fn is_http_redirect(req: *const i8, qn: usize, resp: *const i8, sn: usize) -> bool {
    if req.is_null() || resp.is_null() {
        return false;
    }
    unsafe {
        let rq = core::slice::from_raw_parts(req as *const u8, qn);
        let rs = core::slice::from_raw_parts(resp as *const u8, sn);

        let mut host_ptr: *mut i8 = ptr::null_mut();
        let len = parse_http(req, qn, &mut host_ptr, ptr::null_mut());
        if len <= 0 || sn < 29 {
            return false;
        }

        let code = get_http_code(rs);
        if code < 300 || code > 308 {
            return false;
        }

        let loc_tag = b"\nLocation:";
        let Some(mut loc) = strncasestr(rs, loc_tag) else {
            return false;
        };
        loc += 11;
        if loc + 8 >= rs.len() {
            return false;
        }
        let Some(mut l_end) = rs[loc..].iter().position(|&c| c == b'\n').map(|x| loc + x) else {
            return false;
        };
        while l_end > loc && rs[l_end - 1].is_ascii_whitespace() {
            l_end -= 1;
        }

        // strip scheme
        if l_end.saturating_sub(loc) > 7 {
            if rs[loc..].starts_with(b"http://") {
                loc += 7;
            } else if rs[loc..].starts_with(b"https://") {
                loc += 8;
            }
        }

        let mut le = rs[loc..l_end]
            .iter()
            .position(|&c| c == b'/')
            .map(|x| loc + x)
            .unwrap_or(l_end);

        let host_off = (host_ptr as *const u8).offset_from(rq.as_ptr()) as usize;
        let he = host_off + (len as usize);

        // pick last 2 labels of host
        let mut h = he;
        let mut dots = 0;
        while h > host_off {
            h -= 1;
            if rq[h] == b'.' {
                dots += 1;
                if dots == 2 {
                    break;
                }
            }
        }
        // align like C: if reached start without 2 dots, h == host_off
        if dots < 2 {
            h = host_off;
        } else {
            // C’s loop stops *after* stepping over '.', so h points to byte after '.'.
            h += 1;
        }

        let left = le.saturating_sub(loc);
        let right = he.saturating_sub(h);

        left < right || (le >= right && rs[le - right..le] != rq[h..he])
    }
}

pub fn neq_tls_sid(req: *const i8, qn: usize, resp: *const i8, sn: usize) -> bool {
    if req.is_null() || resp.is_null() || qn < 75 || sn < 75 {
        return false;
    }
    unsafe {
        let rq = core::slice::from_raw_parts(req as *const u8, qn);
        let rs = core::slice::from_raw_parts(resp as *const u8, sn);

        if !is_tls_chello(req, qn) || antohs(rs, 0) != 0x1603 {
            return false;
        }

        let sid_len = rq[43] as usize;
        let skip = 44 + sid_len + 3;
        if find_tls_ext_offset(0x002b, rs, sn, skip) == 0 {
            return false;
        }
        if rq[43] != rs[43] {
            return true;
        }
        rq[44..44 + sid_len] != rs[44..44 + sid_len]
    }
}

pub fn is_tls_shello(buffer: *const i8, bsize: usize) -> bool {
    if buffer.is_null() || bsize <= 5 {
        return false;
    }
    unsafe {
        let b = core::slice::from_raw_parts(buffer as *const u8, bsize);
        bsize > 5 && antohs(b, 0) == 0x1603 && b[5] == 0x02
    }
}

pub fn mod_http(buffer: *mut i8, bsize: usize, m: i32) -> i32 {
    if buffer.is_null() {
        return -1;
    }
    unsafe {
        let b = core::slice::from_raw_parts_mut(buffer as *mut u8, bsize);

        let mut host_ptr: *mut i8 = ptr::null_mut();
        let hlen = parse_http(buffer as *const i8, bsize, &mut host_ptr, ptr::null_mut());
        if hlen == 0 {
            return -1;
        }

        let host_off = (host_ptr as *mut u8).offset_from(b.as_mut_ptr()) as usize;
        let hlen_u = hlen as usize;

        // par = host - 1; while (*par != ':') par--; par -= 4;
        let mut par = host_off.saturating_sub(1);
        while par > 0 && b[par] != b':' {
            par -= 1;
        }
        if par < 4 {
            return -1;
        }
        par -= 4;

        if (m & MH_HMIX) != 0 {
            b[par + 0] = b[par + 0].to_ascii_lowercase();
            b[par + 1] = b[par + 1].to_ascii_uppercase();
            b[par + 3] = b[par + 3].to_ascii_uppercase();
        }
        if (m & MH_DMIX) != 0 {
            let mut i = 0usize;
            while i < hlen_u {
                b[host_off + i] = b[host_off + i].to_ascii_uppercase();
                i += 2;
            }
        }
        if (m & MH_SPACE) != 0 {
            let mut end = host_off + hlen_u;
            while end < b.len() && !b[end].is_ascii_whitespace() {
                end += 1;
            }
            if end > b.len() {
                return -1;
            }
            let sc = host_off as isize - (par as isize + 5);
            if sc < 0 {
                return -1;
            }
            let sc = sc as usize;

            // memmove(par+5, host, hlen2) where hlen2 includes until whitespace
            let hlen2 = end - host_off;
            b.copy_within(host_off..host_off + hlen2, par + 5);
            b[par + 5 + hlen2..par + 5 + hlen2 + sc].fill(b'\t');
        }

        0
    }
}

pub fn part_tls(buffer: *mut i8, bsize: usize, n: isize, pos: i64) -> i32 {
    if buffer.is_null() {
        return 0;
    }
    if n < 3 || (bsize as isize - n) < 5 || pos < 0 || (pos as isize) + 5 > n {
        return 0;
    }
    unsafe {
        let b = core::slice::from_raw_parts_mut(buffer as *mut u8, bsize);
        let r_sz = antohs(b, 3) as i64;
        if r_sz < pos {
            return n as i32;
        }

        // memmove(buffer + 5 + pos + 5, buffer + 5 + pos, n - (5 + pos))
        let posu = pos as usize;
        let n_u = n as usize;
        let src = 5 + posu;
        let dst = 5 + posu + 5;
        if dst + (n_u - src) <= b.len() {
            b.copy_within(src..n_u, dst);
        }

        // memcpy(buffer + 5 + pos, buffer, 3)
        let hdr = [b[0], b[1], b[2]];
        b[5 + posu..5 + posu + 3].copy_from_slice(&hdr);

        shtona(b, 3, pos as u16);
        shtona(b, 5 + posu + 3, (r_sz - pos) as u16);
        5
    }
}

fn gen_rand_array(out: &mut [u8]) {
    for c in out.iter_mut() {
        *c = rand_u8();
    }
}

pub fn randomize_tls(buffer: *mut i8, n: isize) {
    if buffer.is_null() || n < 44 {
        return;
    }
    unsafe {
        let b = core::slice::from_raw_parts_mut(buffer as *mut u8, n as usize);
        let sid_len = b[43] as usize;
        if n < (44 + sid_len + 2) as isize {
            return;
        }

        gen_rand_array(&mut b[11..11 + 32]);
        gen_rand_array(&mut b[44..44 + sid_len]);

        let skip = find_ext_block(b, n as usize);
        if skip == 0 {
            return;
        }

        let ks_offs = find_tls_ext_offset(0x0033, b, n as usize, skip);
        if ks_offs == 0 || ks_offs + 6 >= n as usize {
            return;
        }
        let ks_sz = antohs(b, ks_offs + 2) as usize;
        if ks_offs + 4 + ks_sz > n as usize {
            return;
        }

        let mut g_offs = ks_offs + 4 + 2;
        while g_offs + 4 < ks_offs + 4 + ks_sz {
            let g_sz = antohs(b, g_offs + 2) as usize;
            if ks_offs + 4 + g_sz > n as usize {
                return;
            }
            gen_rand_array(&mut b[g_offs + 4..g_offs + 4 + g_sz]);
            g_offs += 4 + g_sz;
        }
    }
}

// -------- small C-interop helper --------

unsafe fn cstr_bytes(mut p: *const i8) -> &'static [u8] {
    let mut len = 0usize;
    while unsafe { *p } != 0 {
        len += 1;
        p = unsafe { p.add(1) };
    }
    unsafe { core::slice::from_raw_parts(unsafe { p.sub(len) } as *const u8, len) }
}
