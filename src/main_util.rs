// src/main_util.rs
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

fn from_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// C: ssize_t parse_cform(char *buffer, size_t blen, const char *str, size_t slen)
pub fn parse_cform(buffer: &mut [u8], s: &[u8]) -> usize {
    // Mapping pairs like C string: "r\r n\n t\t \\ \\ f\f b\b v\v a\a 0\0"
    // Rust byte strings don't support \v or \a escapes, so encode explicitly.
    const ESCA: &[u8] = &[
        b'r', b'\r', b'n', b'\n', b't', b'\t', b'\\', b'\\', b'f', 0x0c, // \f
        b'b', 0x08, // \b
        b'v', 0x0b, // \v
        b'a', 0x07, // \a
        b'0', 0x00, // \0
        0, 0, // terminator for loop (ESCA[e] != 0)
    ];

    let mut i: usize = 0;
    let mut p: usize = 0;

    while p < s.len() && i < buffer.len() {
        if s[p] != b'\\' {
            buffer[i] = s[p];
            p += 1;
            i += 1;
            continue;
        }

        // saw backslash
        p += 1;
        if p >= s.len() {
            break;
        }

        // simple escapes
        let mut e = 0usize;
        let mut matched = false;
        while e + 1 < ESCA.len() && ESCA[e] != 0 {
            if ESCA[e] == s[p] {
                buffer[i] = ESCA[e + 1];
                matched = true;
                break;
            }
            e += 2;
        }
        if matched {
            p += 1;
            i += 1;
            continue;
        }

        // hex \xNN
        if s[p] == b'x' {
            if p + 2 < s.len() {
                let hi = s[p + 1];
                let lo = s[p + 2];
                if let (Some(h), Some(l)) = (from_hex(hi), from_hex(lo)) {
                    buffer[i] = (h << 4) | l;
                    p += 3;
                    i += 1;
                    continue;
                }
            }
        } else {
            // octal \NNN (up to 3 digits)
            let mut k = p;
            let mut val: u16 = 0;
            let mut nd: usize = 0;
            while k < s.len() && nd < 3 {
                let c = s[k];
                if !(b'0'..=b'7').contains(&c) {
                    break;
                }
                val = (val << 3) | ((c - b'0') as u16);
                nd += 1;
                k += 1;
            }
            if nd > 0 && val <= 0xFF {
                buffer[i] = val as u8;
                p += nd;
                i += 1;
                continue;
            }
        }

        // fallback: keep '\' and do not consume the following char
        buffer[i] = b'\\';
        i += 1;
        // p unchanged: next loop will process current s[p]
    }

    i
}

// C: char *data_from_str(const char *str, ssize_t *size)
pub fn data_from_str(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let mut buf = vec![0u8; bytes.len()];
    let n = parse_cform(&mut buf, bytes);
    if n == 0 {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

// C: ftob(const char *str, ssize_t *size)
// - ":<data>" => parse_cform over substring
// - "<path>"  => read file as bytes
pub fn ftob(spec: &str) -> Option<Vec<u8>> {
    if let Some(rest) = spec.strip_prefix(':') {
        return data_from_str(rest);
    }

    let mut f = File::open(spec).ok()?;
    let size = f.seek(SeekFrom::End(0)).ok()? as usize;
    if size == 0 {
        return None;
    }
    f.seek(SeekFrom::Start(0)).ok()?;

    let mut buf = vec![0u8; size];
    let mut off = 0usize;
    while off < size {
        let n = f.read(&mut buf[off..]).ok()?;
        if n == 0 {
            return None;
        }
        off += n;
    }
    Some(buf)
}
