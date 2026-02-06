// src/mpool.rs
//
// Port of mpool.h / mpool.c.
// Windows-first: dump_cache/load_cache are left as stubs for now (they depend on inet_ntop/inet_pton + FILE* I/O).
// Core API is implemented: mem_pool / mem_get / mem_add / mem_delete / mem_destroy.
// Data structure: ordered set with the same comparator semantics as C (CMP_BYTES/CMP_BITS/CMP_HOST).
//
// This is intentional for the early “postrочный” phase: it compiles, matches behavior,
// and we can later swap storage to an AVL/RB tree when needed.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use core::{cmp::Ordering, mem, ptr};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice;

use crate::params::{
    CMP_BITS, CMP_BYTES, CMP_HOST, ElemPtr, MF_EXTRA, MF_STATIC, PARAMS, elem, elem_ex, elem_i,
    mphdr,
};

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[cfg(not(windows))]
use libc::{AF_INET, AF_INET6};

fn bit_cmp(p: &elem, q: &elem) -> Ordering {
    let len = if q.len < p.len { q.len } else { p.len };
    let df = (len % 8) as usize;
    let bytes = (len / 8) as usize;

    unsafe {
        let pd =
            core::slice::from_raw_parts(p.data as *const u8, bytes + if df != 0 { 1 } else { 0 });
        let qd =
            core::slice::from_raw_parts(q.data as *const u8, bytes + if df != 0 { 1 } else { 0 });

        let cmp = pd[..bytes].cmp(&qd[..bytes]);
        if cmp != Ordering::Equal || df == 0 {
            return cmp;
        }

        let c1 = pd[bytes] >> (8 - df);
        let c2 = qd[bytes] >> (8 - df);
        c1.cmp(&c2)
    }
}

fn byte_cmp(p: &elem, q: &elem) -> Ordering {
    if p.len != q.len {
        return p.len.cmp(&q.len);
    }
    unsafe {
        let pd = core::slice::from_raw_parts(p.data as *const u8, p.len as usize);
        let qd = core::slice::from_raw_parts(q.data as *const u8, q.len as usize);
        pd.cmp(qd)
    }
}

fn host_cmp(p: &elem, q: &elem) -> Ordering {
    // C compares from the end (suffix compare), with a '.' boundary rule.
    let len = if q.len < p.len { q.len } else { p.len } as isize;

    unsafe {
        let mut pd = p.data.add(p.len as usize) as *const u8;
        let mut qd = q.data.add(q.len as usize) as *const u8;

        let mut i = len;
        while i > 0 {
            pd = pd.offset(-1);
            qd = qd.offset(-1);
            let a = *pd;
            let b = *qd;
            if a != b {
                return a.cmp(&b);
            }
            i -= 1;
        }

        if p.len == q.len {
            return Ordering::Equal;
        }

        // boundary rule:
        // if next char before the unmatched part is '.', treat as equal
        if p.len > q.len {
            let prev = *(p.data.add((p.len as usize) - (q.len as usize) - 1) as *const u8);
            if prev == b'.' {
                return Ordering::Equal;
            }
            Ordering::Greater
        } else {
            let prev = *(q.data.add((q.len as usize) - (p.len as usize) - 1) as *const u8);
            if prev == b'.' {
                return Ordering::Equal;
            }
            Ordering::Less
        }
    }
}

fn scmp(p: &elem, q: &elem) -> Ordering {
    match p.cmp_type {
        CMP_BITS => bit_cmp(p, q),
        CMP_HOST => host_cmp(p, q),
        _ => byte_cmp(p, q),
    }
}

impl PartialEq for ElemPtr {
    fn eq(&self, other: &Self) -> bool {
        if self.0 == other.0 {
            return true;
        }
        if self.0.is_null() || other.0.is_null() {
            return false;
        }
        unsafe { scmp(&*self.0, &*other.0) == Ordering::Equal }
    }
}

impl Eq for ElemPtr {}

impl PartialOrd for ElemPtr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ElemPtr {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.0 == other.0 {
            return Ordering::Equal;
        }
        if self.0.is_null() || other.0.is_null() {
            return (self.0 as usize).cmp(&(other.0 as usize));
        }
        unsafe { scmp(&*self.0, &*other.0) }
    }
}

unsafe fn destroy_elem(hdr: *mut mphdr, e: *mut elem) {
    if hdr.is_null() || e.is_null() {
        return;
    }

    // free(e->data) unless MF_STATIC
    if ((*hdr).flags & MF_STATIC) == 0 {
        if !(*e).data.is_null() {
            libc_free((*e).data as *mut core::ffi::c_void);
        }
    }

    // free(extra) if MF_EXTRA
    if ((*hdr).flags & MF_EXTRA) != 0 {
        let ex = e as *mut elem_ex;
        if !(*ex).extra.is_null() {
            libc_free((*ex).extra as *mut core::ffi::c_void);
        }
    }

    // free struct itself (elem / elem_ex / elem_i)
    // We don't know the exact concrete type, but elem_i starts with elem_ex layout,
    // and elem_ex starts with elem layout, so freeing as the largest we allocated is OK
    // only if we allocated it as that type. We do: see alloc_by_size().
    let kind = (*hdr).alloc_kind;
    match kind {
        2 => {
            let _ = Box::from_raw(e as *mut elem_i);
        }
        1 => {
            let _ = Box::from_raw(e as *mut elem_ex);
        }
        _ => {
            let _ = Box::from_raw(e as *mut elem);
        }
    }
}

unsafe fn alloc_by_size(struct_size: usize) -> (*mut elem, u8) {
    let sz_e = mem::size_of::<elem>();
    let sz_ex = mem::size_of::<elem_ex>();
    let sz_i = mem::size_of::<elem_i>();

    if struct_size >= sz_i {
        let b: Box<elem_i> = Box::new(mem::zeroed());
        (Box::into_raw(b) as *mut elem, 2)
    } else if struct_size >= sz_ex {
        let b: Box<elem_ex> = Box::new(mem::zeroed());
        (Box::into_raw(b) as *mut elem, 1)
    } else if struct_size >= sz_e {
        let b: Box<elem> = Box::new(mem::zeroed());
        (Box::into_raw(b) as *mut elem, 0)
    } else {
        (ptr::null_mut(), 0)
    }
}

// struct mphdr *mem_pool(unsigned short flags, unsigned char cmp_type);
pub fn mem_pool(flags: u16, cmp_type: u8) -> *mut mphdr {
    let mut b = Box::new(mphdr::default());
    b.flags = flags;
    b.cmp_type = cmp_type;
    b.count = 0;
    b.root = ptr::null_mut();
    b.items = std::collections::BTreeSet::new();
    b.alloc_kind = 0;
    Box::into_raw(b)
}

// void *mem_get(const struct mphdr *hdr, const char *str, int len);
pub fn mem_get(hdr: *const mphdr, str_: *const i8, len: i32) -> *mut elem {
    if hdr.is_null() || str_.is_null() || len < 0 {
        return ptr::null_mut();
    }
    unsafe {
        let temp = elem {
            len,
            data: str_ as *mut i8,
            cmp_type: (*hdr).cmp_type,
        };

        let key = ElemPtr(&temp as *const elem as *mut elem);
        if let Some(found) = (*hdr).items.get(&key) {
            return found.0;
        }
    }
    ptr::null_mut()
}

// void *mem_add(struct mphdr *hdr, char *str, int len, size_t ssize);
pub fn mem_add(hdr: *mut mphdr, str_: *mut i8, len: i32, struct_size: usize) -> *mut elem {
    if hdr.is_null() || str_.is_null() || len < 0 {
        return ptr::null_mut();
    }

    unsafe {
        let (e, kind) = alloc_by_size(struct_size);
        if e.is_null() {
            return ptr::null_mut();
        }

        (*hdr).alloc_kind = kind;

        (*e).len = len;
        (*e).cmp_type = (*hdr).cmp_type;
        (*e).data = str_;

        let key = ElemPtr(e);
        let existing = (*hdr).items.get(&key).copied();

        if existing.is_none() {
            (*hdr).items.insert(key);
            (*hdr).count += 1;
            return e;
        }

        let existing = existing.unwrap();

        // C logic:
        // v = insert(); while (e != v && e->len < v->len) { delete(v); v = insert(e); }
        // Here: if new is shorter than existing, delete existing and add new.
        if (*e).len < (*existing.0).len {
            if let Some(removed) = (*hdr).items.take(&existing) {
                destroy_elem(hdr, removed.0);
                (*hdr).count = (*hdr).count.saturating_sub(1);
            }
            (*hdr).items.insert(key);
            (*hdr).count += 1;
            return e;
        }

        // else keep existing, destroy new allocation
        destroy_elem(hdr, e);
        existing.0
    }
}

// void mem_delete(struct mphdr *hdr, const char *str, int len);
pub fn mem_delete(hdr: *mut mphdr, str_: *const i8, len: i32) {
    if hdr.is_null() || str_.is_null() || len < 0 {
        return;
    }

    unsafe {
        let temp = elem {
            len,
            data: str_ as *mut i8,
            cmp_type: (*hdr).cmp_type,
        };

        let key = ElemPtr(&temp as *const elem as *mut elem);
        let Some(existing) = (*hdr).items.take(&key) else {
            return;
        };
        destroy_elem(hdr, existing.0);
        (*hdr).count = (*hdr).count.saturating_sub(1);
    }
}

// void mem_destroy(struct mphdr *hdr);
pub fn mem_destroy(hdr: *mut mphdr) {
    if hdr.is_null() {
        return;
    }

    unsafe {
        while let Some(e) = (*hdr).items.iter().next().copied() {
            let e = (*hdr).items.take(&e);
            if let Some(e) = e {
                destroy_elem(hdr, e.0);
            }
        }
        let _ = Box::from_raw(hdr);
    }
}

// void dump_cache(struct mphdr *hdr, FILE *out);
pub fn dump_cache(hdr: *mut mphdr, out: &mut dyn Write) -> io::Result<()> {
    if hdr.is_null() {
        return Ok(());
    }
    let now = time_now();

    let (cache_ttl_n, cache_ttl_ptr) = unsafe { (PARAMS.cache_ttl_n, PARAMS.cache_ttl) };
    let cache_ttl = unsafe {
        if cache_ttl_ptr.is_null() || cache_ttl_n <= 0 {
            None
        } else {
            Some(slice::from_raw_parts(
                cache_ttl_ptr,
                cache_ttl_n as usize,
            ))
        }
    };

    unsafe {
        for p in (*hdr).items.iter().copied() {
            if p.0.is_null() {
                continue;
            }
            let item = &*(p.0 as *mut elem_i);
            if item.main.data.is_null() {
                continue;
            }

            if item.main.len < 4 {
                continue;
            }

            let data = slice::from_raw_parts(item.main.data as *const u8, item.main.len as usize);
            if data.len() < 4 {
                continue;
            }

            let port = u16::from_be_bytes([data[0], data[1]]);
            let family = u16::from_ne_bytes([data[2], data[3]]);
            let addr_bytes = &data[4..];

            let addr = if family == AF_INET as u16 {
                if addr_bytes.len() < 4 {
                    continue;
                }
                IpAddr::V4(Ipv4Addr::from([
                    addr_bytes[0],
                    addr_bytes[1],
                    addr_bytes[2],
                    addr_bytes[3],
                ]))
            } else if family == AF_INET6 as u16 {
                if addr_bytes.len() < 16 {
                    continue;
                }
                IpAddr::V6(Ipv6Addr::from([
                    addr_bytes[0],
                    addr_bytes[1],
                    addr_bytes[2],
                    addr_bytes[3],
                    addr_bytes[4],
                    addr_bytes[5],
                    addr_bytes[6],
                    addr_bytes[7],
                    addr_bytes[8],
                    addr_bytes[9],
                    addr_bytes[10],
                    addr_bytes[11],
                    addr_bytes[12],
                    addr_bytes[13],
                    addr_bytes[14],
                    addr_bytes[15],
                ]))
            } else {
                continue;
            };

            if let Some(ttl) = cache_ttl {
                if item.time_inc <= 0 {
                    continue;
                }
                let idx = (item.time_inc - 1) as usize;
                if idx >= ttl.len() {
                    continue;
                }
                let ttl = ttl[idx] as i64;
                if now > item.time + ttl {
                    continue;
                }
            }

            write!(
                out,
                "0 {} {} {} {} {} ",
                addr, port, item.dp_mask, item.time, item.time_inc
            )?;

            if item.extra_len > 0 && !item.extra.is_null() {
                let extra =
                    slice::from_raw_parts(item.extra as *const u8, item.extra_len as usize);
                out.write_all(extra)?;
            }
            out.write_all(b"\n")?;
        }
    }
    out.flush()
}

// void load_cache(struct mphdr *hdr, FILE *in);
pub fn load_cache(hdr: *mut mphdr, input: &mut dyn Read) -> io::Result<()> {
    if hdr.is_null() {
        return Ok(());
    }
    let mut buf = String::new();
    input.read_to_string(&mut buf)?;

    let cache_ttl_n = unsafe { PARAMS.cache_ttl_n };

    for line in buf.lines() {
        let mut parts = line.split_whitespace();
        let Some(tag) = parts.next() else {
            continue;
        };
        if tag != "0" {
            continue;
        }

        let Some(addr_str) = parts.next() else {
            continue;
        };
        let Some(port_str) = parts.next() else {
            continue;
        };
        let Some(mask_str) = parts.next() else {
            continue;
        };
        let Some(time_str) = parts.next() else {
            continue;
        };
        let Some(inc_str) = parts.next() else {
            continue;
        };
        let host = parts.next().unwrap_or("");

        let port: u16 = match port_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mask: u64 = match mask_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let cache_time: i64 = match time_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let cache_inc: i32 = match inc_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        if cache_inc > cache_ttl_n {
            continue;
        }

        let ip = match addr_str.parse::<IpAddr>() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let (family, addr_bytes) = match ip {
            IpAddr::V4(v4) => (AF_INET as u16, v4.octets().to_vec()),
            IpAddr::V6(v6) => (AF_INET6 as u16, v6.octets().to_vec()),
        };

        let mut key = Vec::with_capacity(4 + addr_bytes.len());
        key.extend_from_slice(&port.to_be_bytes());
        key.extend_from_slice(&family.to_ne_bytes());
        key.extend_from_slice(&addr_bytes);

        let key_size = key.len();
        let data = unsafe { libc_calloc(1, key_size) as *mut u8 };
        if data.is_null() {
            return Ok(());
        }
        unsafe {
            ptr::copy_nonoverlapping(key.as_ptr(), data, key_size);
        }

        let e = unsafe {
            mem_add(
                hdr,
                data as *mut i8,
                key_size as i32,
                mem::size_of::<elem_i>(),
            ) as *mut elem_i
        };
        if e.is_null() {
            unsafe {
                libc_free(data as *mut core::ffi::c_void);
            }
            return Ok(());
        }

        unsafe {
            (*e).detect = -1;
            (*e).dp_mask = mask;
            (*e).time = cache_time;
            (*e).time_inc = cache_inc;
            (*e).extra_len = host.len() as u32;

            if (*e).extra_len > 0 {
                let extra = libc_malloc((*e).extra_len as usize + 1) as *mut u8;
                if !extra.is_null() {
                    ptr::copy_nonoverlapping(host.as_ptr(), extra, (*e).extra_len as usize);
                    *extra.add((*e).extra_len as usize) = 0;
                    (*e).extra = extra as *mut i8;
                }
            }
        }
    }
    Ok(())
}

fn time_now() -> i64 {
    #[cfg(windows)]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
    #[cfg(not(windows))]
    unsafe {
        libc::time(ptr::null_mut()) as i64
    }
}

unsafe fn libc_calloc(n: usize, sz: usize) -> *mut core::ffi::c_void {
    #[cfg(not(windows))]
    {
        libc::calloc(n, sz)
    }
    #[cfg(windows)]
    {
        libc::calloc(n, sz)
    }
}

unsafe fn libc_malloc(sz: usize) -> *mut core::ffi::c_void {
    #[cfg(not(windows))]
    {
        libc::malloc(sz)
    }
    #[cfg(windows)]
    {
        libc::malloc(sz)
    }
}

unsafe fn libc_free(p: *mut core::ffi::c_void) {
    #[cfg(not(windows))]
    {
        libc::free(p)
    }
    #[cfg(windows)]
    {
        libc::free(p)
    }
}
