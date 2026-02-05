// src/main.rs
#![allow(clippy::needless_return)]
#![allow(clippy::match_single_binding)]

mod conev;
mod desync;
mod error;
mod extend;
mod mpool;
mod packets;
mod params;
mod proxy;

use std::ffi::OsString;
use std::fs;
use std::io::{self};
use std::net::{IpAddr, SocketAddr};
use std::mem;
use std::str::FromStr;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::mpool;
use crate::params::{CMP_BYTES, MF_EXTRA, PARAMS};

const VERSION: &str = "17.3";

// These flags/constants are referenced by main.c. Keep them aligned with your Rust port of headers.
const OFFSET_SNI: u32 = 1 << 0;
const OFFSET_HOST: u32 = 1 << 1;
const OFFSET_END: u32 = 1 << 2;
const OFFSET_MID: u32 = 1 << 3;
const OFFSET_RAND: u32 = 1 << 4;
const OFFSET_START: u32 = 1 << 5;

const DESYNC_SPLIT: u8 = 1;
const DESYNC_DISORDER: u8 = 2;
const DESYNC_OOB: u8 = 3;
const DESYNC_DISOOB: u8 = 4;
const DESYNC_FAKE: u8 = 5;

const AUTO_POST: u32 = 1 << 0;
const AUTO_SORT: u32 = 1 << 1;
const AUTO_RECONN: u32 = 1 << 2;

const DETECT_TORST: u32 = 1 << 0;
const DETECT_HTTP_LOCAT: u32 = 1 << 1;
const DETECT_TLS_ERR: u32 = 1 << 2;

const IS_TCP: u32 = 1 << 0;
const IS_HTTPS: u32 = 1 << 1;
const IS_HTTP: u32 = 1 << 2;
const IS_UDP: u32 = 1 << 3;
const IS_IPV4: u32 = 1 << 4;

const FM_RAND: u32 = 1 << 0;
const FM_ORIG: u32 = 1 << 1;

const MH_SPACE: u32 = 1 << 0;
const MH_HMIX: u32 = 1 << 1;
const MH_DMIX: u32 = 1 << 2;

#[derive(Clone, Debug, Default)]
struct Part {
    pos: i64,
    r: Option<u32>,
    s: Option<u32>,
    flag: u32,
    m: u8, // DESYNC_* kind
}

#[derive(Clone, Debug, Default)]
struct DataBuf {
    data: Option<Vec<u8>>,
    size: usize,
}

#[derive(Clone, Debug)]
struct DesyncParams {
    id: u32,
    bit: u64,
    str_tag: String,

    // limits/filters:
    detect: u32,
    proto: u32,
    pf: [u16; 2],
    hosts: Option<Vec<String>>,
    ipset: Option<Vec<IpNetBits>>,

    // desync knobs:
    parts: Vec<Part>,
    ttl: u8,
    md5sig: bool,
    fake_offset: Option<Part>,
    fake_mod: u32,
    fake_tls_size: Option<u32>,
    fake_sni_list: Vec<String>,
    fake_data: DataBuf,
    oob_char: Option<u8>,
    mod_http: u32,
    tlsrec: Vec<Part>,
    tlsminor: Option<u8>,
    udp_fake_count: i32,
    drop_sack: bool,

    // to-socks5:
    ext_socks: Option<SocketAddr>,

    // bookkeeping for -B rewind:
    optind_at_A: usize,
    fail_count: i32,
    pri: i32,
}

impl DesyncParams {
    fn new(id: u32, dp_n: u32, optind_at_A: usize) -> Self {
        Self {
            id,
            bit: 1u64 << id,
            str_tag: String::new(),
            detect: 0,
            proto: 0,
            pf: [0, 0],
            hosts: None,
            ipset: None,
            parts: Vec::new(),
            ttl: 0,
            md5sig: false,
            fake_offset: None,
            fake_mod: 0,
            fake_tls_size: None,
            fake_sni_list: Vec::new(),
            fake_data: DataBuf::default(),
            oob_char: None,
            mod_http: 0,
            tlsrec: Vec::new(),
            tlsminor: None,
            udp_fake_count: 0,
            drop_sack: false,
            ext_socks: None,
            optind_at_A,
            fail_count: 0,
            pri: 0,
        }
    }
}

#[derive(Clone, Debug)]
struct IpNetBits {
    raw: Vec<u8>, // truncated to bytes needed by bits
    bits: u8,     // prefix length
}

#[derive(Clone, Debug)]
struct Params {
    await_int: i32,

    ipv6: bool,
    resolve: bool,
    udp: bool,
    max_open: i32,
    bfsize: i32,

    // listen addr (SOCKS5 server)
    laddr: SocketAddr,

    // bind addr for outgoing connections
    baddr: IpAddr,

    debug: i32,

    // misc:
    http_connect: bool,
    transparent: bool,
    tfo: bool,
    auto_level: u32,
    timeout_ms: Option<u32>,

    def_ttl: u8,
    custom_ttl: bool,

    cache_file: Option<String>,
    cache_ttl: Vec<u32>,

    wait_send: bool,
    protect_path: Option<String>,

    // groups:
    dp: Vec<DesyncParams>,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            await_int: 10,
            ipv6: true,
            resolve: true,
            udp: true,
            max_open: 512,
            bfsize: 16384,

            // defaults from C:
            laddr: SocketAddr::new(IpAddr::from_str("0.0.0.0").unwrap(), 1080),

            // default :: (if supported; else overridden below)
            baddr: IpAddr::from_str("::").unwrap(),

            debug: 0,

            http_connect: false,
            transparent: false,
            tfo: false,
            auto_level: 0,
            timeout_ms: None,

            def_ttl: 0,
            custom_ttl: false,

            cache_file: None,
            cache_ttl: Vec::new(),

            wait_send: false,
            protect_path: None,

            dp: Vec::new(),
        }
    }
}

// ---- helpers ported from C ----

fn parse_cform(input: &str, max_len: usize) -> Vec<u8> {
    // C behavior: walks bytes; supports escapes: r n t \\ f b v a; also \xHH and \OOO
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len().min(max_len));

    let mut p = 0usize;
    while p < bytes.len() && out.len() < max_len {
        if bytes[p] != b'\\' {
            out.push(bytes[p]);
            p += 1;
            continue;
        }
        p += 1;
        if p >= bytes.len() {
            // trailing backslash => treat as literal backslash (matches C-ish behavior best)
            if out.len() < max_len {
                out.push(b'\\');
            }
            break;
        }

        let c = bytes[p];
        let mapped = match c {
            b'r' => Some(b'\r'),
            b'n' => Some(b'\n'),
            b't' => Some(b'\t'),
            b'\\' => Some(b'\\'),
            b'f' => Some(b'\x0c'),
            b'b' => Some(b'\x08'),
            b'v' => Some(b'\x0b'),
            b'a' => Some(b'\x07'),
            _ => None,
        };
        if let Some(v) = mapped {
            out.push(v);
            p += 1;
            continue;
        }

        // \xHH
        if c == b'x' {
            let mut v: u8 = 0;
            let mut used = 0usize;
            for i in 0..2 {
                if p + 1 + i >= bytes.len() {
                    break;
                }
                let h = bytes[p + 1 + i];
                let d = match h {
                    b'0'..=b'9' => h - b'0',
                    b'a'..=b'f' => 10 + (h - b'a'),
                    b'A'..=b'F' => 10 + (h - b'A'),
                    _ => break,
                };
                v = (v << 4) | d;
                used += 1;
            }
            if used > 0 {
                out.push(v);
                p += 1 + used;
                continue;
            }
        }

        // \OOO (up to 3 oct digits)
        if (b'0'..=b'7').contains(&c) {
            let mut v: u16 = (c - b'0') as u16;
            let mut used = 1usize;
            for i in 0..2 {
                if p + i + 1 >= bytes.len() {
                    break;
                }
                let o = bytes[p + i + 1];
                if !(b'0'..=b'7').contains(&o) {
                    break;
                }
                v = (v << 3) | (o - b'0') as u16;
                used += 1;
            }
            out.push((v & 0xFF) as u8);
            p += used;
            continue;
        }

        // fallback: keep backslash + char as literals (closest to C loop i--/p--)
        out.push(b'\\');
        if out.len() < max_len {
            out.push(bytes[p]);
        }
        p += 1;
    }

    out
}

fn data_from_str(spec: &str) -> Option<Vec<u8>> {
    if spec.is_empty() {
        return None;
    }
    let v = parse_cform(spec, spec.len());
    if v.is_empty() { None } else { Some(v) }
}

fn ftob(spec: &str) -> Option<Vec<u8>> {
    if let Some(rest) = spec.strip_prefix(':') {
        return data_from_str(rest);
    }
    let mut f = match fs::File::open(spec) {
        Ok(f) => f,
        Err(_) => return None,
    };
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
        Some(buf)
    } else {
        None
    }
}

fn lower_char_ascii(b: u8) -> Result<u8, ()> {
    // C rule:
    // if c < 'A': allow '-'..'9' only
    // else if c < 'a': allow 'A'..'Z' (convert to lower)
    // else allow 'a'..'z' only
    if b < b'A' {
        if b > b'9' || b < b'-' {
            return Err(());
        }
        return Ok(b);
    }
    if b < b'a' {
        if b > b'Z' {
            return Err(());
        }
        return Ok(b + 32);
    }
    if b > b'z' {
        return Err(());
    }
    Ok(b)
}

fn parse_hosts(bytes: &[u8]) -> Result<Vec<String>, ()> {
    let mut out: Vec<String> = Vec::new();

    let mut s = 0usize;
    let mut drop = false;
    let mut num = 0usize;

    let mut i = 0usize;
    while i <= bytes.len() {
        let is_sep = i == bytes.len() || bytes[i] == b' ' || bytes[i] == b'\n' || bytes[i] == b'\r';

        if !is_sep {
            if lower_char_ascii(bytes[i]).is_err() {
                drop = true;
            }
            i += 1;
            continue;
        }

        if s == i {
            s = s.saturating_add(1);
            i += 1;
            continue;
        }

        num += 1;
        if !drop {
            let mut v = Vec::with_capacity(i - s);
            for &b in &bytes[s..i] {
                v.push(lower_char_ascii(b).map_err(|_| ())?);
            }
            let host = String::from_utf8(v).map_err(|_| ())?;
            out.push(host);
        } else {
            // match C behavior: log invalid host and skip
            drop = false;
        }

        s = i + 1;
        i += 1;
    }

    // match C: it logs count; we just return it
    let _ = num;
    Ok(out)
}

fn parse_ip_net(s: &str) -> Result<IpNetBits, ()> {
    let (addr_part, bits_opt) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };

    let ip = IpAddr::from_str(addr_part).map_err(|_| ())?;
    let max_bits = match ip {
        IpAddr::V4(_) => 32u8,
        IpAddr::V6(_) => 128u8,
    };

    let bits = if let Some(b) = bits_opt {
        let v = b.parse::<u16>().map_err(|_| ())?;
        if v == 0 {
            return Err(());
        }
        let v = v.min(max_bits as u16) as u8;
        v
    } else {
        max_bits
    };

    let full = match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };

    let len = (bits / 8) as usize + if bits % 8 != 0 { 1 } else { 0 };
    Ok(IpNetBits {
        raw: full[..len].to_vec(),
        bits,
    })
}

fn parse_ipset(bytes: &[u8]) -> Result<Vec<IpNetBits>, ()> {
    let s = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut out = Vec::new();

    let mut num = 0usize;
    for token in s
        .split(|c| c == ' ' || c == '\n' || c == '\r')
        .filter(|t| !t.is_empty())
    {
        num += 1;
        if let Ok(net) = parse_ip_net(token) {
            out.push(net);
        } else {
            // match C: log invalid ip and continue
        }
    }

    let _ = num;
    Ok(out)
}

fn get_addr(spec: &str) -> Result<SocketAddr, ()> {
    // C accepts:
    // - IPv4 or IPv6 numeric host (no DNS)
    // - optional port via :port
    // - IPv6 with port in [addr]:port
    // If no port, returns addr with port=0.
    let (host, port) = if let Some(rest) = spec.strip_prefix('[') {
        let end = rest.find(']').ok_or(())?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = if let Some(p) = tail.strip_prefix(':') {
            if p.is_empty() {
                0u16
            } else {
                p.parse::<u16>().map_err(|_| ())?
            }
        } else {
            0u16
        };
        (host, port)
    } else {
        // split last ':' only if it looks like :<digits>
        let mut host = spec;
        let mut port = 0u16;
        if let Some(idx) = spec.rfind(':') {
            let p = &spec[idx + 1..];
            if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
                port = p.parse::<u16>().map_err(|_| ())?;
                host = &spec[..idx];
            }
        }
        (host, port)
    };

    let ip = IpAddr::from_str(host).map_err(|_| ())?;
    Ok(SocketAddr::new(ip, port))
}

fn get_default_ttl() -> io::Result<u8> {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    // socket2 returns u32 for ttl
    let ttl = sock.ttl_v4()? as u8;
    Ok(ttl)
}

fn ipv6_support() -> bool {
    Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).is_ok()
}

fn parse_offset(part: &mut Part, s: &str) -> Result<(), ()> {
    // C format:
    // offset[:repeats:skip][+flag1[flag2]]
    // flags: +s (SNI), +h (HTTP host), +n (null/no flag)
    // extra: +e end, +m middle, +r rand, +s start (note: second 's' in C is "start")
    let mut main = s;
    let mut flags_str = "";

    if let Some((a, b)) = s.split_once('+') {
        main = a;
        flags_str = b;
    }

    let mut it = main.split(':');
    let pos = it.next().ok_or(())?.parse::<i64>().map_err(|_| ())?;
    part.pos = pos;

    if let Some(r) = it.next() {
        let rv = r.parse::<i64>().map_err(|_| ())?;
        if rv < 0 || rv > i64::from(i32::MAX) || rv == 0 {
            return Err(());
        }
        part.r = Some(rv as u32);
    }
    if let Some(sk) = it.next() {
        let sv = sk.parse::<i64>().map_err(|_| ())?;
        if sv < 0 || sv > i64::from(i32::MAX) {
            return Err(());
        }
        part.s = Some(sv as u32);
    }

    if !flags_str.is_empty() {
        let mut ch = flags_str.chars();
        match ch.next().ok_or(())? {
            's' => part.flag |= OFFSET_SNI,
            'h' => part.flag |= OFFSET_HOST,
            'n' => {}
            _ => return Err(()),
        }
        if let Some(x) = ch.next() {
            match x {
                'e' => part.flag |= OFFSET_END,
                'm' => part.flag |= OFFSET_MID,
                'r' => part.flag |= OFFSET_RAND,
                's' => part.flag |= OFFSET_START,
                _ => {}
            }
        }
    }

    Ok(())
}

// ---- program-specific hooks (port wiring) ----

fn sockaddru_from_socketaddr(addr: SocketAddr) -> params::SockaddrU {
    let sock = SockAddr::from(addr);
    let mut out: params::SockaddrU = unsafe { mem::zeroed() };
    unsafe {
        let src = sock.as_ptr() as *const u8;
        let dst = (&mut out as *mut params::SockaddrU) as *mut u8;
        std::ptr::copy_nonoverlapping(src, dst, sock.len() as usize);
    }
    out
}

fn sockaddru_from_ipaddr(addr: IpAddr) -> params::SockaddrU {
    sockaddru_from_socketaddr(SocketAddr::new(addr, 0))
}

#[cfg(not(windows))]
struct PidFileGuard {
    path: Option<std::ffi::CString>,
    fd: Option<std::os::unix::io::RawFd>,
}

#[cfg(not(windows))]
impl PidFileGuard {
    fn empty() -> Self {
        Self {
            path: None,
            fd: None,
        }
    }
}

#[cfg(not(windows))]
impl Drop for PidFileGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(fd) = self.fd.take() {
                libc::close(fd);
            }
            if let Some(path) = self.path.as_ref() {
                libc::unlink(path.as_ptr());
            }
        }
    }
}

#[cfg(not(windows))]
fn init_pid_file(path: &str) -> Result<PidFileGuard, ()> {
    let c_path = std::ffi::CString::new(path).map_err(|_| ())?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o640) };
    if fd < 0 {
        return Err(());
    }
    let mut lock = libc::flock {
        l_type: libc::F_WRLCK as i16,
        l_whence: libc::SEEK_CUR as i16,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    if unsafe { libc::fcntl(fd, libc::F_SETLK, &mut lock) } < 0 {
        unsafe {
            libc::close(fd);
        }
        return Err(());
    }
    let pid = unsafe { libc::getpid() };
    let pid_str = pid.to_string();
    unsafe {
        libc::write(fd, pid_str.as_ptr().cast(), pid_str.len());
    }
    unsafe {
        PARAMS.pid_fd = fd;
        PARAMS.pid_file = c_path.as_ptr();
    }
    Ok(PidFileGuard {
        path: Some(c_path),
        fd: Some(fd),
    })
}

// ---- argv parsing (faithful to main.c control flow, including -A/-B rewind) ----

fn main() {
    let code = match real_main(std::env::args_os().collect()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            -1
        }
    };
    std::process::exit(code);
}

fn real_main(argv: Vec<OsString>) -> Result<i32, String> {
    let args: Vec<String> = argv
        .into_iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();

    let mut params = Params::default();

    // port from C:
    if !ipv6_support() {
        params.baddr = IpAddr::from_str("0.0.0.0").unwrap();
    }

    // group 0 exists from the start
    let mut dp_n: u32 = 0;
    let mut dp_curr_index: usize = 0;
    params.dp.push(DesyncParams::new(dp_n, dp_n, 1));
    params.dp[0].id = dp_n;
    params.dp[0].bit = 1u64 << dp_n;
    dp_n += 1;

    let mut pid_file: Option<String> = None;
    let mut daemonize = false;

    let mut invalid_opt: Option<(String, Option<String>)> = None;

    let mut all_limited = true;

    // emulate getopt_long-ish scan
    let mut i = 1usize;
    let mut curr_optind = 1usize;

    while i < args.len() && invalid_opt.is_none() {
        let a = &args[i];

        if a == "--" {
            i += 1;
            break;
        }

        let (key, val_opt, consumed) = if a.starts_with("--") {
            // --long or --long=val
            let mut s = &a[2..];
            let mut v: Option<String> = None;
            if let Some((k, vv)) = s.split_once('=') {
                s = k;
                v = Some(vv.to_string());
                (format!("--{s}"), v, 1usize)
            } else {
                (format!("--{s}"), None, 1usize)
            }
        } else if a.starts_with('-') && a.len() >= 2 {
            // -x or -xVAL (we only support -x VAL like C here)
            (a.clone(), None, 1usize)
        } else {
            // positional: ignore (C code ignores leftovers too)
            i += 1;
            continue;
        };

        // helper to fetch required arg (like getopt has_arg=1)
        let mut need_arg = |already: Option<String>| -> Result<(String, usize), String> {
            if let Some(v) = already {
                return Ok((v, consumed));
            }
            if i + consumed >= args.len() {
                return Err(format!("missing value for {key}"));
            }
            Ok((args[i + consumed].clone(), consumed + 1))
        };

        // current group mutable reference (careful with borrow rules)
        let cur = dp_curr_index;

        match key.as_str() {
            // simple flags
            "-N" | "--no-domain" => {
                params.resolve = false;
                i += consumed;
            }
            "-X" | "--no-ipv6" => {
                params.ipv6 = false;
                i += consumed;
            }
            "-U" | "--no-udp" => {
                params.udp = false;
                i += consumed;
            }
            "-G" | "--http-connect" => {
                params.http_connect = true;
                i += consumed;
            }

            // daemon bits (kept for parity; actual daemon/service port is separate work)
            "-D" | "--daemon" => {
                daemonize = true;
                i += consumed;
            }
            "-w" | "--pidfile" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                pid_file = Some(v);
                i += c;
            }

            "-h" | "--help" => {
                print_help();
                return Ok(0);
            }
            "-v" | "--version" => {
                println!("{VERSION}");
                return Ok(0);
            }

            "-i" | "--ip" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let sa = get_addr(&v).map_err(|_| format!("invalid value: {key} {v}"))?;
                params.laddr = SocketAddr::new(sa.ip(), params.laddr.port());
                if sa.port() != 0 {
                    // match C: if port is provided in -i, it sets it too
                    params.laddr.set_port(sa.port());
                }
                i += c;
            }
            "-p" | "--port" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let port = v
                    .parse::<u16>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if port == 0 {
                    return Err(format!("invalid value: {key} {v}"));
                }
                params.laddr.set_port(port);
                i += c;
            }
            "-I" | "--conn-ip" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let sa = get_addr(&v).map_err(|_| format!("invalid value: {key} {v}"))?;
                params.baddr = sa.ip();
                i += c;
            }
            "-b" | "--buf-size" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let val = v
                    .parse::<i32>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if val <= 0 || val > i32::MAX / 4 {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.bfsize = val;
                }
                i += c;
            }
            "-c" | "--max-conn" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let val = v
                    .parse::<i32>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if val <= 0 || val >= (0xffff / 2) {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.max_open = val;
                }
                i += c;
            }
            "-x" | "--debug" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let val = v
                    .parse::<i32>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if val < 0 {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.debug = val;
                }
                i += c;
            }
            "-y" | "--cache-dump" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                params.cache_file = Some(v);
                i += c;
            }

            // desync flags
            "-F" | "--tfo" => {
                params.tfo = true;
                i += consumed;
            }
            "-L" | "--auto-mode" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                for token in v.split(',') {
                    match token {
                        "0" => {}
                        "1" | "p" => params.auto_level |= AUTO_POST,
                        "2" | "s" => params.auto_level |= AUTO_SORT,
                        "3" => params.auto_level |= (AUTO_POST | AUTO_SORT),
                        "r" => params.auto_level = 0,
                        _ => {
                            invalid_opt = Some((key, Some(v.clone())));
                            break;
                        }
                    }
                }
                i += c;
            }
            "-A" | "--auto" => {
                // emulate C: if optind < curr_optind => rewind handling; here we implement by skipping if i < curr_optind
                if i < curr_optind {
                    i += consumed;
                    continue;
                }

                // if current dp has no limits => all_limited=false
                {
                    let dp = &params.dp[dp_curr_index];
                    if dp.hosts.is_none()
                        && dp.proto == 0
                        && dp.pf[0] == 0
                        && dp.detect == 0
                        && dp.ipset.is_none()
                    {
                        all_limited = false;
                    }
                }

                // create new group
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let new_index = params.dp.len();
                params.dp.push(DesyncParams::new(
                    dp_n,
                    dp_n,
                    i + c, /* optind after consuming */
                ));
                params.dp[new_index].id = dp_n;
                params.dp[new_index].bit = 1u64 << dp_n;
                dp_n += 1;

                dp_curr_index = new_index;

                for token in v.split(',') {
                    match token {
                        "t" => params.dp[dp_curr_index].detect |= DETECT_TORST,
                        "r" => params.dp[dp_curr_index].detect |= DETECT_HTTP_LOCAT,
                        "a" | "s" => params.dp[dp_curr_index].detect |= DETECT_TLS_ERR,
                        "n" => {}
                        _ => {
                            invalid_opt = Some((key, Some(v.clone())));
                            break;
                        }
                    }
                }
                if params.dp[dp_curr_index].detect != 0 {
                    params.auto_level |= AUTO_RECONN;
                }
                params.dp[dp_curr_index].optind_at_A = i + c;
                i += c;
            }
            "-B" | "--copy" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                if i < curr_optind {
                    i += c;
                    continue;
                }
                if v == "i" {
                    params.dp[dp_curr_index].pf[0] = 1u16.to_be();
                    i += c;
                    continue;
                }
                let val = v.parse::<i32>().ok();
                if val.is_none() || val.unwrap() <= 0 {
                    invalid_opt = Some((key, Some(v)));
                    i += c;
                    continue;
                }
                let want = (val.unwrap() as u32).saturating_sub(1);
                if let Some((idx, _)) = params.dp.iter().enumerate().find(|(_, d)| d.id == want) {
                    curr_optind = i + c;
                    i = params.dp[idx].optind_at_A;
                    continue;
                } else {
                    invalid_opt = Some((key, Some(v)));
                    i += c;
                    continue;
                }
            }
            "-#" | "--comment" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                params.dp[dp_curr_index].str_tag = v;
                i += c;
            }
            "-u" | "--cache-ttl" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let val = v
                    .parse::<u32>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if val == 0 {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.cache_ttl.push(val);
                }
                i += c;
            }
            "-T" | "--timeout" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                // C: linux parses float seconds->ms, else integer seconds. Here: accept float seconds, store ms.
                let f = v
                    .parse::<f64>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                let ms = (f * 1000.0) as i64;
                if ms <= 0 || ms > u32::MAX as i64 {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.timeout_ms = Some(ms as u32);
                }
                i += c;
            }
            "-K" | "--proto" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                for token in v.split(',') {
                    match token {
                        "t" => params.dp[dp_curr_index].proto |= IS_TCP | IS_HTTPS,
                        "h" => params.dp[dp_curr_index].proto |= IS_TCP | IS_HTTP,
                        "u" => params.dp[dp_curr_index].proto |= IS_UDP,
                        "i" => params.dp[dp_curr_index].proto |= IS_IPV4,
                        _ => {
                            invalid_opt = Some((key, Some(v.clone())));
                            break;
                        }
                    }
                }
                i += c;
            }
            "-H" | "--hosts" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                if params.dp[dp_curr_index].hosts.is_some() {
                    i += c;
                    continue;
                }
                let data = ftob(&v).ok_or_else(|| format!("read/parse failed: {key} {v}"))?;
                let hosts =
                    parse_hosts(&data).map_err(|_| format!("parse_hosts failed: {key} {v}"))?;
                params.dp[dp_curr_index].hosts = Some(hosts);
                i += c;
            }
            "-j" | "--ipset" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                if params.dp[dp_curr_index].ipset.is_some() {
                    i += c;
                    continue;
                }
                let data = ftob(&v).ok_or_else(|| format!("read/parse failed: {key} {v}"))?;
                let ipset =
                    parse_ipset(&data).map_err(|_| format!("parse_ipset failed: {key} {v}"))?;
                params.dp[dp_curr_index].ipset = Some(ipset);
                i += c;
            }

            "-s" | "--split" | "-d" | "--disorder" | "-o" | "--oob" | "-q" | "--disoob" | "-f"
            | "--fake" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let mut part = Part::default();
                parse_offset(&mut part, &v).map_err(|_| format!("invalid value: {key} {v}"))?;
                part.m = match key.as_str() {
                    "-s" | "--split" => DESYNC_SPLIT,
                    "-d" | "--disorder" => DESYNC_DISORDER,
                    "-o" | "--oob" => DESYNC_OOB,
                    "-q" | "--disoob" => DESYNC_DISOOB,
                    "-f" | "--fake" => DESYNC_FAKE,
                    _ => DESYNC_SPLIT,
                };
                params.dp[dp_curr_index].parts.push(part);
                i += c;
            }

            "-t" | "--ttl" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let val = v
                    .parse::<u16>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if val == 0 || val > 255 {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.dp[dp_curr_index].ttl = val as u8;
                }
                i += c;
            }
            "-S" | "--md5sig" => {
                params.dp[dp_curr_index].md5sig = true;
                i += consumed;
            }
            "-O" | "--fake-offset" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let mut part = Part::default();
                parse_offset(&mut part, &v).map_err(|_| format!("invalid value: {key} {v}"))?;
                part.m = 1; // C sets m=1 as a marker
                params.dp[dp_curr_index].fake_offset = Some(part);
                i += c;
            }
            "-Q" | "--fake-tls-mod" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                for token in v.split(',') {
                    if token == "rand" || token == "r" {
                        params.dp[dp_curr_index].fake_mod |= FM_RAND;
                        continue;
                    }
                    if token == "orig" || token == "o" {
                        params.dp[dp_curr_index].fake_mod |= FM_ORIG;
                        continue;
                    }
                    if let Some(msz) = token.strip_prefix("msize=") {
                        let n = msz
                            .parse::<u32>()
                            .map_err(|_| format!("invalid value: {key} {v}"))?;
                        params.dp[dp_curr_index].fake_tls_size = Some(n);
                        continue;
                    }
                    invalid_opt = Some((key, Some(v.clone())));
                    break;
                }
                i += c;
            }
            "-n" | "--fake-sni" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                params.dp[dp_curr_index].fake_sni_list.push(v);
                i += c;
            }
            "-l" | "--fake-data" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                if params.dp[dp_curr_index].fake_data.data.is_some() {
                    i += c;
                    continue;
                }
                let data = ftob(&v).ok_or_else(|| format!("read/parse failed: {key} {v}"))?;
                params.dp[dp_curr_index].fake_data.size = data.len();
                params.dp[dp_curr_index].fake_data.data = Some(data);
                i += c;
            }
            "-e" | "--oob-data" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let bytes = parse_cform(&v, 1);
                if bytes.len() != 1 {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.dp[dp_curr_index].oob_char = Some(bytes[0]);
                }
                i += c;
            }
            "-M" | "--mod-http" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                for token in v.split(',') {
                    match token {
                        "r" | "rmspace" => params.dp[dp_curr_index].mod_http |= MH_SPACE,
                        "h" | "hcsmix" => params.dp[dp_curr_index].mod_http |= MH_HMIX,
                        "d" | "dcsmix" => params.dp[dp_curr_index].mod_http |= MH_DMIX,
                        _ => {
                            invalid_opt = Some((key, Some(v.clone())));
                            break;
                        }
                    }
                }
                i += c;
            }
            "-r" | "--tlsrec" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let mut part = Part::default();
                parse_offset(&mut part, &v).map_err(|_| format!("invalid value: {key} {v}"))?;
                if part.pos > 0xffff {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.dp[dp_curr_index].tlsrec.push(part);
                }
                i += c;
            }
            "-m" | "--tlsminor" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let val = v
                    .parse::<u16>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if val == 0 || val > 255 {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.dp[dp_curr_index].tlsminor = Some(val as u8);
                }
                i += c;
            }
            "-a" | "--udp-fake" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let val = v
                    .parse::<i32>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if val < 0 {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.dp[dp_curr_index].udp_fake_count = val;
                }
                i += c;
            }
            "-V" | "--pf" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let (a, b) = if let Some((x, y)) = v.split_once('-') {
                    (x, Some(y))
                } else {
                    (v.as_str(), None)
                };
                let p0 = a
                    .parse::<u16>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if p0 == 0 {
                    invalid_opt = Some((key, Some(v)));
                    i += c;
                    continue;
                }
                let p1 = if let Some(y) = b {
                    let p = y
                        .parse::<u16>()
                        .map_err(|_| format!("invalid value: {key} {v}"))?;
                    if p == 0 {
                        return Err(format!("invalid value: {key} {v}"));
                    }
                    p
                } else {
                    p0
                };
                params.dp[dp_curr_index].pf = [p0.to_be(), p1.to_be()];
                i += c;
            }
            "-R" | "--round" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let (a, b) = if let Some((x, y)) = v.split_once('-') {
                    (x, Some(y))
                } else {
                    (v.as_str(), None)
                };
                let r0 = a
                    .parse::<i32>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if r0 <= 0 {
                    invalid_opt = Some((key, Some(v)));
                    i += c;
                    continue;
                }
                let r1 = if let Some(y) = b {
                    let r = y
                        .parse::<i32>()
                        .map_err(|_| format!("invalid value: {key} {v}"))?;
                    if r <= 0 {
                        return Err(format!("invalid value: {key} {v}"));
                    }
                    r
                } else {
                    r0
                };
                // main.c writes to dp->rounds[0/1]; keep placeholders if you add those fields.
                let _ = (r0, r1);
                i += c;
            }
            "-g" | "--def-ttl" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let val = v
                    .parse::<u16>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                if val == 0 || val > 255 {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.def_ttl = val as u8;
                    params.custom_ttl = true;
                }
                i += c;
            }
            "-Y" | "--drop-sack" => {
                params.dp[dp_curr_index].drop_sack = true;
                i += consumed;
            }
            "-Z" | "--wait-send" => {
                params.wait_send = true;
                i += consumed;
            }
            "-W" | "--await-int" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let val = v
                    .parse::<i32>()
                    .map_err(|_| format!("invalid value: {key} {v}"))?;
                params.await_int = val;
                i += c;
            }
            "-C" | "--to-socks5" => {
                let (v, c) = need_arg(val_opt).map_err(|e| e)?;
                let sa = get_addr(&v).map_err(|_| format!("invalid value: {key} {v}"))?;
                if sa.port() == 0 {
                    invalid_opt = Some((key, Some(v)));
                } else {
                    params.dp[dp_curr_index].ext_socks = Some(sa);
                }
                i += c;
            }

            other => {
                // unknown option => like getopt returns '?'
                return Err(format!("unknown option: {other}"));
            }
        }
    }

    if let Some((k, v)) = invalid_opt {
        return Err(format!(
            "invalid value: {} {}",
            k,
            v.unwrap_or_else(|| "".to_string())
        ));
    }

    // post-parse logic from C:
    if all_limited {
        // add an extra group at end
        let optind_at = args.len();
        params.dp.push(DesyncParams::new(dp_n, dp_n, optind_at));
        params.dp.last_mut().unwrap().id = dp_n;
        params.dp.last_mut().unwrap().bit = 1u64 << dp_n;
        dp_n += 1;
    }

    // if bind addr isn't v6 => ipv6=0 (C: params.baddr.sa.sa_family != AF_INET6)
    if !matches!(params.baddr, IpAddr::V6(_)) {
        params.ipv6 = false;
    }

    if params.def_ttl == 0 {
        params.def_ttl = get_default_ttl().map_err(|e| format!("get_default_ttl failed: {e}"))?;
        if params.def_ttl == 0 {
            return Err("get_default_ttl returned 0".into());
        }
    }

    if params.cache_ttl.is_empty() {
        params.cache_ttl.push(100800);
    }

    // cache load
    let mempool = mpool::mem_pool(MF_EXTRA, CMP_BYTES);
    if mempool.is_null() {
        return Err("mem_pool failed".into());
    }

    let laddr = sockaddru_from_socketaddr(params.laddr);
    let baddr = sockaddru_from_ipaddr(params.baddr);
    let protect_path = if let Some(path) = &params.protect_path {
        Some(std::ffi::CString::new(path.as_str()).map_err(|_| "invalid protect path")?)
    } else {
        None
    };
    unsafe {
        PARAMS.await_int = params.await_int;
        PARAMS.wait_send = params.wait_send;
        PARAMS.def_ttl = params.def_ttl as i32;
        PARAMS.custom_ttl = params.custom_ttl;
        PARAMS.tfo = params.tfo;
        PARAMS.timeout = params.timeout_ms.unwrap_or(0);
        PARAMS.auto_level = params.auto_level as i32;
        PARAMS.cache_ttl_n = params.cache_ttl.len() as i32;
        PARAMS.cache_ttl = params.cache_ttl.as_mut_ptr();
        PARAMS.ipv6 = params.ipv6;
        PARAMS.resolve = params.resolve;
        PARAMS.udp = params.udp;
        PARAMS.transparent = params.transparent;
        PARAMS.http_connect = params.http_connect;
        PARAMS.max_open = params.max_open;
        PARAMS.debug = params.debug;
        PARAMS.bfsize = params.bfsize as usize;
        PARAMS.baddr = baddr;
        PARAMS.laddr = laddr;
        PARAMS.protect_path = protect_path
            .as_ref()
            .map_or(std::ptr::null(), |p| p.as_ptr());
        PARAMS.pid_file = std::ptr::null();
        PARAMS.pid_fd = -1;
        PARAMS.mempool = mempool;
    }

    #[cfg(not(windows))]
    let mut pid_guard = PidFileGuard::empty();
    #[cfg(not(windows))]
    {
        if daemonize && unsafe { libc::daemon(0, 0) } < 0 {
            mpool::mem_destroy(mempool);
            unsafe {
                PARAMS.mempool = std::ptr::null_mut();
            }
            return Ok(-1);
        }
        if let Some(pid_path) = &pid_file {
            match init_pid_file(pid_path) {
                Ok(guard) => pid_guard = guard,
                Err(_) => {
                    mpool::mem_destroy(mempool);
                    unsafe {
                        PARAMS.mempool = std::ptr::null_mut();
                    }
                    return Ok(-1);
                }
            }
        }
    }

    if let Some(cf) = &params.cache_file {
        if cf != "-" {
            if let Ok(mut f) = fs::File::open(cf) {
                let _ = mpool::load_cache(mempool, &mut f);
            }
        }
    }

    // run server
    let status = unsafe { proxy::run(&PARAMS.laddr) };

    // group logging (placeholder; wire to your logging)
    for dp in &params.dp {
        eprintln!(
            "group: {} ({}), triggered: {}, pri: {}",
            dp.id, dp.str_tag, dp.fail_count, dp.pri
        );
    }

    // cache dump
    if let Some(cf) = &params.cache_file {
        if cf == "-" {
            let mut w = io::stdout();
            let _ = mpool::dump_cache(mempool, &mut w);
        } else {
            let mut f = fs::File::create(cf).map_err(|e| format!("fopen/create failed: {e}"))?;
            let _ = mpool::dump_cache(mempool, &mut f);
        }
    }

    mpool::mem_destroy(mempool);
    unsafe {
        PARAMS.mempool = std::ptr::null_mut();
    }

    #[cfg(not(windows))]
    drop(pid_guard);

    Ok(status)
}

fn print_help() {
    // Ported text is intentionally minimal; keep the canonical help in one place when you fully port.
    print!(
        "    -i, --ip <ip>              Listening IP, default 0.0.0.0\n\
         \x20   -p, --port <num>            Listening port, default 1080\n\
         \x20   -c, --max-conn <count>      Connection count limit, default 512\n\
         \x20   -N, --no-domain             Deny domain resolving\n\
         \x20   -U, --no-udp                Deny UDP association\n\
         \x20   -I, --conn-ip <ip>          Connection bind IP, default ::\n\
         \x20   -b, --buf-size <size>       Buffer size, default 16384\n\
         \x20   -x, --debug <level>         Print logs, 0, 1 or 2\n\
         \x20   -v, --version               Print version\n\
         \x20   -h, --help                  Print help\n"
    );
}
