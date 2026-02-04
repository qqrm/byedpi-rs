// src/conev.rs
//
// Line-by-line style port of conev.c / conev.h into a Rust module.
// This intentionally keeps the same data model (pool + eval array + swap-remove, timer linked list,
// buffer pool), and keeps platform split between epoll (unix/linux) and WSAPoll/poll (windows).
//
// NOTE: This module expects these to exist elsewhere in your crate:
//   - crate::params::{SockaddrU, DesyncParams}
//   - crate::error::{uniperror, get_e, Errno, LOG_E, LOG_L, LOG_S, log}
//
// If you don't have them yet, keep the types as stubs temporarily and wire later.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::time::Instant;

use crate::error::{Errno, LOG_E, LOG_L, LOG_S, get_e, log, uniperror};
use crate::params::{DesyncParams, SockaddrU};

pub const POLLTIMEOUT: i32 = 0;
pub const MAX_BUFF_INP: usize = 8;

// C flags
pub const FLAG_S4: i32 = 1;
pub const FLAG_S5: i32 = 2;
pub const FLAG_CONN: i32 = 4;
pub const FLAG_HTTP: i32 = 8;

// C compatibility: _POLLDEF is POLLHUP on macOS, else 0
#[cfg(target_os = "macos")]
const _POLLDEF: i16 = libc::POLLHUP as i16;
#[cfg(not(target_os = "macos"))]
const _POLLDEF: i16 = 0;

// C compatibility: POLLRDHUP may not exist; in C it becomes 0.
// In Rust/libc it may be missing on some targets; keep it optional.
#[cfg(any(target_os = "linux", target_os = "android"))]
const POLLRDHUP_I16: i16 = libc::POLLRDHUP as i16;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const POLLRDHUP_I16: i16 = 0;

pub type evcb_t = fn(&mut poolhd, &mut eval, i32) -> i32;

#[derive(Debug)]
pub struct buffer {
    pub size: usize,
    pub offset: u32,
    pub lock: isize,
    pub next: Option<Box<buffer>>,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct eval {
    pub fd: i32,
    pub index: i32,
    pub mod_iter: u64,
    pub cb: Option<evcb_t>,

    pub tv_ms: i64,
    pub tv_next: Option<i32>,
    pub tv_prev: Option<i32>,

    pub after_conn_cb: Option<evcb_t>,
    pub conn_state: i32,

    pub pair: Option<i32>,
    pub buff: Option<Box<buffer>>,
    pub sq_buff: Option<Box<buffer>>,
    pub flag: i32,
    pub addr: SockaddrU,
    pub host: Option<Vec<u8>>,
    pub host_len: i32,

    pub recv_count: isize,
    pub round_sent: isize,
    pub round_count: u32,

    pub dp: *mut DesyncParams,
    pub dp_mask: u64,
    pub detect: i32,
    pub mark: bool,

    pub restore_ttl: bool,
    pub restore_md5: bool,
    pub restore_fake: *mut u8,
    pub restore_fake_len: usize,
    pub restore_orig: *const u8,
    pub restore_orig_len: usize,
    pub part_sent: u32,
}

impl eval {
    fn reset(&mut self) {
        *self = eval::default();
    }
}

#[derive(Debug)]
pub struct poolhd {
    pub max: i32,
    pub count: i32,

    // epoll fd (unix) only
    #[cfg(all(unix, not(feature = "noepoll")))]
    pub efd: i32,

    // active slots: indices into items
    pub links: Vec<i32>,
    pub items: Vec<eval>,

    // platform event buffers
    #[cfg(all(unix, not(feature = "noepoll")))]
    pub pevents: Vec<libc::epoll_event>,
    #[cfg(any(not(unix), feature = "noepoll"))]
    pub pevents: Vec<pollfd_compat>,

    pub iters: u64,
    pub brk: bool,

    pub tv_start: Option<i32>,
    pub tv_end: Option<i32>,

    pub root_buff: Option<Box<buffer>>,
    pub buff_count: i32,

    t0: Instant,
}

#[cfg(any(not(unix), feature = "noepoll"))]
#[derive(Clone, Copy, Debug)]
pub struct pollfd_compat {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

pub fn init_pool(count: i32) -> Option<Box<poolhd>> {
    let mut pool = Box::new(poolhd {
        max: count,
        count: 0,
        #[cfg(all(unix, not(feature = "noepoll")))]
        efd: 0,
        links: Vec::new(),
        items: Vec::new(),
        pevents: Vec::new(),
        iters: 0,
        brk: false,
        tv_start: None,
        tv_end: None,
        root_buff: None,
        buff_count: 0,
        t0: Instant::now(),
    });

    #[cfg(all(unix, not(feature = "noepoll")))]
    {
        let efd = unsafe { libc::epoll_create(count) };
        if efd < 0 {
            return None;
        }
        pool.efd = efd;
    }

    pool.links = (0..count).collect();
    pool.items = (0..count).map(|_| eval::default()).collect();

    #[cfg(all(unix, not(feature = "noepoll")))]
    {
        pool.pevents = vec![unsafe { mem::zeroed() }; count as usize];
    }
    #[cfg(any(not(unix), feature = "noepoll"))]
    {
        pool.pevents = vec![
            pollfd_compat {
                fd: 0,
                events: 0,
                revents: 0
            };
            count as usize
        ];
    }

    Some(pool)
}

pub fn add_event(pool: &mut poolhd, cb: evcb_t, fd: i32, e: i32) -> Option<i32> {
    debug_assert!(fd > 0);
    if pool.count >= pool.max {
        log(LOG_E, "add_event: pool is full\n");
        return None;
    }

    let idx = pool.count;
    let item_index = pool.links[idx as usize];
    let val = &mut pool.items[item_index as usize];
    val.reset();

    val.mod_iter = pool.iters;
    val.fd = fd;
    val.index = idx;
    val.cb = Some(cb);

    #[cfg(all(unix, not(feature = "noepoll")))]
    {
        let mut ev: libc::epoll_event = unsafe { mem::zeroed() };
        ev.events = (_POLLDEF as u32) | (e as u32);
        // store pointer to eval in epoll event data
        // we store the item_index as u64; resolve back to &mut eval via items vec.
        ev.u64 = item_index as u64;

        let rc = unsafe { libc::epoll_ctl(pool.efd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
        if rc != 0 {
            uniperror("add event");
            return None;
        }
    }

    #[cfg(any(not(unix), feature = "noepoll"))]
    {
        let pfd = &mut pool.pevents[idx as usize];
        pfd.fd = fd;
        pfd.events = _POLLDEF | (e as i16);
        pfd.revents = 0;
    }

    pool.count += 1;
    Some(item_index)
}

pub fn add_pair(pool: &mut poolhd, val_index: i32, sfd: i32, e: i32) -> Option<i32> {
    let pair_index = add_event(pool, pool.items[val_index as usize].cb?, sfd, e)?;
    pool.items[val_index as usize].pair = Some(pair_index);
    pool.items[pair_index as usize].pair = Some(val_index);
    Some(pair_index)
}

pub fn del_event(pool: &mut poolhd, val_index: i32) {
    let mut fd;
    {
        let val = &pool.items[val_index as usize];
        debug_assert!(val.fd >= -1 && val.mod_iter <= pool.iters);
        log(
            LOG_S,
            &format!(
                "close: fd={}, (pair={}), recv: {}, rounds: {}\n",
                val.fd,
                val.pair.map(|p| pool.items[p as usize].fd).unwrap_or(-1),
                val.recv_count,
                val.round_count
            ),
        );
        fd = val.fd;
    }

    if fd == -1 {
        return;
    }

    // Detach from epoll/poll
    #[cfg(all(unix, not(feature = "noepoll")))]
    unsafe {
        libc::epoll_ctl(pool.efd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
    }

    #[cfg(any(not(unix), feature = "noepoll"))]
    {
        let idx = pool.items[val_index as usize].index as usize;
        debug_assert_eq!(fd, pool.pevents[idx].fd);
    }

    // Return buffers to pool, free host, unmap fake (unix) etc.
    {
        let val = &mut pool.items[val_index as usize];

        if val.buff.is_some() {
            let b = val.buff.take();
            if let Some(b) = b {
                buff_push(pool, b);
            }
        }
        if val.sq_buff.is_some() {
            let b = val.sq_buff.take();
            if let Some(b) = b {
                buff_push(pool, b);
            }
        }

        #[cfg(unix)]
        {
            if !val.restore_fake.is_null() && val.restore_fake_len != 0 {
                unsafe {
                    libc::munmap(val.restore_fake as *mut libc::c_void, val.restore_fake_len);
                }
                val.restore_fake = std::ptr::null_mut();
                val.restore_fake_len = 0;
            }
        }

        val.host = None;

        // Close socket
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::Networking::WinSock::closesocket(fd as usize);
        }
        #[cfg(not(windows))]
        unsafe {
            libc::close(fd);
        }

        val.fd = -1;
        val.mod_iter = pool.iters;
        remove_timer(pool, val_index);
    }

    // swap-remove active slot in links / pevents, and fix moved eval.index
    pool.count -= 1;
    let last_slot = pool.count;
    let del_slot = pool.items[val_index as usize].index;

    let moved_item_index = pool.links[last_slot as usize];
    if moved_item_index != val_index {
        let del_slot_us = del_slot as usize;
        let last_slot_us = last_slot as usize;

        pool.links[del_slot_us] = moved_item_index;
        pool.links[last_slot_us] = val_index;

        #[cfg(any(not(unix), feature = "noepoll"))]
        {
            pool.pevents[del_slot_us] = pool.pevents[last_slot_us];
        }

        pool.items[moved_item_index as usize].index = del_slot;
    }

    // handle pair cascade delete
    let pair = pool.items[val_index as usize].pair.take();
    if let Some(p) = pair {
        if pool.items[p as usize].pair == Some(val_index) {
            pool.items[p as usize].pair = None;
        }
        del_event(pool, p);
    }

    debug_assert!(pool.count >= 0);
}

pub fn destroy_pool(mut pool: Box<poolhd>) {
    while pool.count != 0 {
        let first_item = pool.links[0];
        del_event(&mut pool, first_item);
    }

    #[cfg(all(unix, not(feature = "noepoll")))]
    {
        if pool.efd != 0 {
            unsafe { libc::close(pool.efd) };
        }
    }

    if let Some(root) = pool.root_buff.take() {
        buff_destroy(Some(root));
    }

    // drop(pool) happens automatically
}

#[cfg(all(unix, not(feature = "noepoll")))]
pub fn next_event(pool: &mut poolhd, offs: &mut i32, etype: &mut i32, ms: i32) -> Option<i32> {
    loop {
        let mut i = *offs;
        debug_assert!(i >= -1 && i < pool.max);
        if i < 0 {
            let rc = unsafe { libc::epoll_wait(pool.efd, pool.pevents.as_mut_ptr(), pool.max, ms) };
            if rc == 0 {
                *etype = POLLTIMEOUT;
            }
            if rc <= 0 {
                return None;
            }
            i = rc - 1;
            pool.iters += 1;
        }

        let ev = pool.pevents[i as usize];
        let item_index = ev.u64 as i32;
        *offs = i - 1;

        let val = &pool.items[item_index as usize];
        if val.mod_iter == pool.iters {
            continue;
        }
        *etype = ev.events as i32;
        return Some(item_index);
    }
}

#[cfg(all(unix, not(feature = "noepoll")))]
pub fn mod_etype(pool: &mut poolhd, val_index: i32, typ: i32) -> i32 {
    let fd = pool.items[val_index as usize].fd;
    debug_assert!(fd > 0);

    let mut ev: libc::epoll_event = unsafe { mem::zeroed() };
    ev.events = (_POLLDEF as u32) | (typ as u32);
    ev.u64 = val_index as u64;

    unsafe { libc::epoll_ctl(pool.efd, libc::EPOLL_CTL_MOD, fd, &mut ev) }
}

#[cfg(any(not(unix), feature = "noepoll"))]
pub fn next_event(pool: &mut poolhd, offs: &mut i32, etype: &mut i32, ms: i32) -> Option<i32> {
    let mut i = *offs;
    loop {
        debug_assert!(i >= -1 && i < pool.max);
        if i < 0 {
            let ret = poll_compat(&mut pool.pevents, pool.count as usize, ms);
            if ret == 0 {
                *etype = POLLTIMEOUT;
            }
            if ret <= 0 {
                return None;
            }
            i = pool.count - 1;
            pool.iters += 1;
        }

        let revents = pool.pevents[i as usize].revents as i32;
        if revents == 0 {
            i -= 1;
            continue;
        }

        let val_index = pool.links[i as usize];
        debug_assert!((i < pool.count) || (pool.items[val_index as usize].mod_iter == pool.iters));

        if pool.items[val_index as usize].mod_iter == pool.iters {
            i -= 1;
            continue;
        }

        pool.pevents[i as usize].revents = 0;
        *offs = i - 1;
        *etype = revents;
        return Some(val_index);
    }
}

#[cfg(any(not(unix), feature = "noepoll"))]
pub fn mod_etype(pool: &mut poolhd, val_index: i32, typ: i32) -> i32 {
    let slot = pool.items[val_index as usize].index;
    debug_assert!(slot >= 0 && slot < pool.count);
    pool.pevents[slot as usize].events = _POLLDEF | (typ as i16);
    0
}

fn time_ms(pool: &poolhd) -> i64 {
    pool.t0.elapsed().as_millis() as i64
}

pub fn set_timer(pool: &mut poolhd, val_index: i32, ms: i64) {
    if pool.items[val_index as usize].tv_ms != 0 {
        return;
    }

    let deadline = time_ms(pool) + ms;
    pool.items[val_index as usize].tv_ms = deadline;

    let mut next: Option<i32> = None;
    let mut prev: Option<i32> = pool.tv_end;

    while let Some(p) = prev {
        if pool.items[p as usize].tv_ms >= deadline {
            next = Some(p);
            prev = pool.items[p as usize].tv_prev;
        } else {
            break;
        }
    }

    pool.items[val_index as usize].tv_next = next;
    pool.items[val_index as usize].tv_prev = prev;

    if let Some(n) = next {
        pool.items[n as usize].tv_prev = Some(val_index);
    }
    if let Some(p) = prev {
        pool.items[p as usize].tv_next = Some(val_index);
    }

    if pool.tv_start.is_none() || next == pool.tv_start {
        pool.tv_start = Some(val_index);
    }
    if pool.tv_end.is_none() || prev == pool.tv_end {
        pool.tv_end = Some(val_index);
    }
}

pub fn remove_timer(pool: &mut poolhd, val_index: i32) {
    let (prev, next) = {
        let v = &pool.items[val_index as usize];
        (v.tv_prev, v.tv_next)
    };

    if let Some(p) = prev {
        pool.items[p as usize].tv_next = next;
    }
    if let Some(n) = next {
        pool.items[n as usize].tv_prev = prev;
    }
    if pool.tv_start == Some(val_index) {
        pool.tv_start = next;
    }
    if pool.tv_end == Some(val_index) {
        pool.tv_end = prev;
    }

    let v = &mut pool.items[val_index as usize];
    v.tv_ms = 0;
    v.tv_next = None;
    v.tv_prev = None;
}

pub fn next_event_tv(pool: &mut poolhd, offs: &mut i32, etype: &mut i32) -> Option<i32> {
    if pool.tv_start.is_none() {
        return next_event(pool, offs, etype, -1);
    }

    let head = pool.tv_start.unwrap();
    let ms_left = pool.items[head as usize].tv_ms - time_ms(pool);

    let mut val = None;
    if ms_left > 0 {
        val = next_event(pool, offs, etype, ms_left as i32);
    } else {
        *etype = POLLTIMEOUT;
    }

    if val.is_none() && pool.tv_start.is_some() && *etype == POLLTIMEOUT {
        let v = pool.tv_start.unwrap();
        remove_timer(pool, v);
        val = Some(v);
    }
    val
}

pub fn loop_event(pool: &mut poolhd) {
    let mut offs: i32 = -1;
    let mut etype: i32 = -1;

    while !pool.brk {
        let val_index = next_event_tv(pool, &mut offs, &mut etype);
        let Some(val_index) = val_index else {
            if get_e() == Errno::EINTR {
                continue;
            }
            uniperror("(e)poll");
            break;
        };

        let fd = pool.items[val_index as usize].fd;
        log(LOG_L, &format!("new event: fd: {}, type: {}\n", fd, etype));

        let cb = pool.items[val_index as usize].cb;
        if let Some(cb) = cb {
            // SAFETY: cb can mutate pool/items; we must avoid aliasing.
            // We temporarily take a raw pointer to eval slot.
            let pool_ptr: *mut poolhd = pool;
            let eval_ptr: *mut eval = &mut pool.items[val_index as usize];
            let ret = unsafe { cb(&mut *pool_ptr, &mut *eval_ptr, etype) };
            if ret < 0 {
                del_event(pool, val_index);
            }
        } else {
            del_event(pool, val_index);
        }
    }
}

pub fn buff_pop(pool: &mut poolhd, size: usize) -> Option<Box<buffer>> {
    if let Some(mut b) = pool.root_buff.take() {
        pool.root_buff = b.next.take();
        pool.buff_count -= 1;
        return Some(b);
    }

    let mut b = Box::new(buffer {
        size,
        offset: 0,
        lock: 0,
        next: None,
        data: vec![0u8; size],
    });
    log(LOG_S, "alloc new buffer\n");
    b.offset = 0;
    b.lock = 0;
    Some(b)
}

pub fn buff_push(pool: &mut poolhd, mut buff: Box<buffer>) {
    if pool.buff_count as usize >= MAX_BUFF_INP {
        // drop
        return;
    }
    buff.lock = 0;
    buff.offset = 0;
    buff.next = pool.root_buff.take();
    pool.root_buff = Some(buff);
    pool.buff_count += 1;
}

pub fn buff_destroy(mut root: Option<Box<buffer>>) {
    let mut i = 0;
    while let Some(mut c) = root {
        root = c.next.take();
        i += 1;
        // drop(c)
    }
    log(LOG_S, &format!("buffers count: {}\n", i));
}

pub fn buff_ppop(pool: &mut poolhd, size: usize) -> Option<Box<buffer>> {
    let b = buff_pop(pool, size)?;
    // In C: pop then immediately push back, return pointer.
    // In Rust: we can't have it both in pool and returned; keep semantics by cloning data is bad.
    // So keep this as "peek-alloc": allocate and do not store. Caller can push back when done.
    Some(b)
}

#[cfg(any(not(unix), feature = "noepoll"))]
fn poll_compat(fds: &mut [pollfd_compat], nfds: usize, timeout_ms: i32) -> i32 {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Networking::WinSock::{WSAPOLLFD, WSAPoll};

        // transmute-compatible layout assumption is unsafe; do explicit conversion
        let mut tmp: Vec<WSAPOLLFD> = (0..nfds)
            .map(|i| WSAPOLLFD {
                fd: fds[i].fd as usize,
                events: fds[i].events as i16,
                revents: 0,
            })
            .collect();

        let rc = WSAPoll(tmp.as_mut_ptr(), nfds as u32, timeout_ms);
        if rc > 0 {
            for i in 0..nfds {
                fds[i].revents = tmp[i].revents as i16;
            }
        }
        rc
    }

    #[cfg(not(windows))]
    unsafe {
        let mut tmp: Vec<libc::pollfd> = (0..nfds)
            .map(|i| libc::pollfd {
                fd: fds[i].fd,
                events: fds[i].events as i16,
                revents: 0,
            })
            .collect();

        let rc = libc::poll(tmp.as_mut_ptr(), nfds as u64, timeout_ms);
        if rc > 0 {
            for i in 0..nfds {
                fds[i].revents = tmp[i].revents as i16;
            }
        }
        rc
    }
}
