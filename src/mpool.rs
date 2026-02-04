// src/mpool.rs
//
// Port of mpool.h / mpool.c.
// Windows-first: dump_cache/load_cache are left as stubs for now (they depend on inet_ntop/inet_pton + FILE* I/O).
// Core API is implemented: mem_pool / mem_get / mem_add / mem_delete / mem_destroy.
// Data structure: simple Vec-based set with the same comparator semantics as C (CMP_BYTES/CMP_BITS/CMP_HOST).
//
// This is intentional for the early “postrочный” phase: it compiles, matches behavior,
// and we can later swap storage to an AVL/RB tree when needed.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use core::{cmp::Ordering, mem, ptr};

use crate::params::{
    CMP_BITS, CMP_BYTES, CMP_HOST, MF_EXTRA, MF_STATIC, elem, elem_ex, elem_i, mphdr,
};

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

unsafe fn destroy_elem(hdr: *mut mphdr, e: *mut elem) {
    if hdr.is_null() || e.is_null() {
        return;
    }

    // free(e->data) unless MF_STATIC
    if ((*hdr).flags & MF_STATIC) == 0 {
        if !(*e).data.is_null() {
            let _ = Box::from_raw((*e).data as *mut u8);
            // NOTE: This only works correctly if callers allocate `data` via Box::into_raw on a u8.
            // For now, most callers will allocate via our helpers later; until then you can set MF_STATIC.
        }
    }

    // free(extra) if MF_EXTRA
    if ((*hdr).flags & MF_EXTRA) != 0 {
        let ex = e as *mut elem_ex;
        if !(*ex).extra.is_null() {
            let _ = Box::from_raw((*ex).extra as *mut u8);
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
    b.items = Vec::new();
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

        for &p in (*hdr).items.iter() {
            if p.is_null() {
                continue;
            }
            if scmp(&temp, &*p) == Ordering::Equal {
                return p;
            }
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

        // find existing equivalent
        let mut existing: *mut elem = ptr::null_mut();
        for &p in (*hdr).items.iter() {
            if p.is_null() {
                continue;
            }
            if scmp(&*e, &*p) == Ordering::Equal {
                existing = p;
                break;
            }
        }

        if existing.is_null() {
            (*hdr).items.push(e);
            (*hdr).count += 1;
            return e;
        }

        // C logic:
        // v = insert(); while (e != v && e->len < v->len) { delete(v); v = insert(e); }
        // Here: if new is shorter than existing, delete existing and add new.
        if (*e).len < (*existing).len {
            mem_delete(hdr, (*existing).data as *const i8, (*existing).len);
            (*hdr).items.push(e);
            (*hdr).count += 1;
            return e;
        }

        // else keep existing, destroy new allocation
        destroy_elem(hdr, e);
        existing
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

        let mut idx: Option<usize> = None;
        for (i, &p) in (*hdr).items.iter().enumerate() {
            if p.is_null() {
                continue;
            }
            if scmp(&temp, &*p) == Ordering::Equal {
                idx = Some(i);
                break;
            }
        }

        let Some(i) = idx else {
            return;
        };
        let e = (*hdr).items.swap_remove(i);
        if !e.is_null() {
            destroy_elem(hdr, e);
            (*hdr).count = (*hdr).count.saturating_sub(1);
        }
    }
}

// void mem_destroy(struct mphdr *hdr);
pub fn mem_destroy(hdr: *mut mphdr) {
    if hdr.is_null() {
        return;
    }

    unsafe {
        while let Some(e) = (*hdr).items.pop() {
            if !e.is_null() {
                destroy_elem(hdr, e);
            }
        }
        let _ = Box::from_raw(hdr);
    }
}

// void dump_cache(struct mphdr *hdr, FILE *out);
pub fn dump_cache(_hdr: *mut mphdr, _out: *mut core::ffi::c_void) {
    // TODO: port once we wire cache format + inet_ntop/FILE* equivalents for Windows.
}

// void load_cache(struct mphdr *hdr, FILE *in);
pub fn load_cache(_hdr: *mut mphdr, _in: *mut core::ffi::c_void) {
    // TODO: same as above.
}
