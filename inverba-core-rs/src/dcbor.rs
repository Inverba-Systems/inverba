//! Deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding), restricted.
//!
//! IRF deliberately forbids a subset of CBOR that is legal but hazardous in a
//! signature preimage:
//!
//! * **No floating point.** The single most error-prone part of any JCS or dCBOR
//!   implementation is IEEE-754 normalisation (negative zero, exponent
//!   boundaries, NaN payloads). IRF has no need for floats, so the entire bug
//!   class is removed by construction. Encode fixed-point as integers.
//! * **No tags.** Semantic tags add a second interpretation layer over identical
//!   bytes. Not needed.
//! * **No indefinite-length items.** Definite lengths only.
//! * **No `undefined`.**
//!
//! Two guarantees are provided:
//!
//! 1. `encode` emits exactly one byte string for a given `Value`.
//! 2. `decode_canonical` accepts input **only** if it is already in that exact
//!    form. Non-canonical input is rejected, never re-canonicalised. Re-
//!    canonicalising attacker-supplied bytes is how "same bytes, different
//!    meaning" bugs are born.

use crate::error::{Invalid, Reason};
use alloc_shim::*;

mod alloc_shim {
    pub use std::string::String;
    pub use std::vec::Vec;
}

/// The restricted CBOR data model used by IRF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Major type 0: 0 ..= u64::MAX
    Uint(u64),
    /// Major type 1: encodes the integer `-1 - n`
    Nint(u64),
    /// Major type 2
    Bytes(Vec<u8>),
    /// Major type 3, must be valid UTF-8
    Text(String),
    /// Major type 4
    Array(Vec<Value>),
    /// Major type 5. Entries MUST be sorted by encoded-key bytes and unique.
    Map(Vec<(Value, Value)>),
    /// Major type 7, simple value 20/21
    Bool(bool),
    /// Major type 7, simple value 22
    Null,
}

impl Value {
    /// Convenience: build a map, sorting and rejecting duplicate keys.
    pub fn map(mut entries: Vec<(Value, Value)>) -> Result<Value, Invalid> {
        let mut keyed: Vec<(Vec<u8>, (Value, Value))> = Vec::with_capacity(entries.len());
        for e in entries.drain(..) {
            let k = encode(&e.0);
            keyed.push((k, e));
        }
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        for w in keyed.windows(2) {
            match (w.first(), w.get(1)) {
                (Some(a), Some(b)) if a.0 == b.0 => {
                    return Err(Invalid::new(Reason::DuplicateMapKey))
                }
                _ => {}
            }
        }
        Ok(Value::Map(keyed.into_iter().map(|(_, e)| e).collect()))
    }

    /// Look up a text key in a map. Returns `None` for non-maps.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                Value::Text(t) if t == key => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::Uint(n) => Some(*n),
            _ => None,
        }
    }

    /// Signed integer view over Uint/Nint.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Uint(n) => i64::try_from(*n).ok(),
            Value::Nint(n) => i64::try_from(*n).ok().and_then(|v| (-1i64).checked_sub(v)),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Shortest-form head for `major` with argument `n`.
fn push_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let mt = major << 5;
    if n < 24 {
        out.push(mt | (n as u8));
    } else if n <= u64::from(u8::MAX) {
        out.push(mt | 24);
        out.push(n as u8);
    } else if n <= u64::from(u16::MAX) {
        out.push(mt | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u64::from(u32::MAX) {
        out.push(mt | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Deterministic encoding. Total, non-panicking, allocation only.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Uint(n) => push_head(out, 0, *n),
        Value::Nint(n) => push_head(out, 1, *n),
        Value::Bytes(b) => {
            push_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            let b = t.as_bytes();
            push_head(out, 3, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Array(items) => {
            push_head(out, 4, items.len() as u64);
            for i in items {
                encode_into(i, out);
            }
        }
        Value::Map(entries) => {
            push_head(out, 5, entries.len() as u64);
            for (k, val) in entries {
                encode_into(k, out);
                encode_into(val, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Maximum nesting depth accepted by the decoder. Bounds stack use and kills
/// the "deeply nested structure" DoS vector at parse time.
pub const MAX_DEPTH: usize = 32;

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Invalid> {
        let end = self.pos.checked_add(n).ok_or(Invalid::new(Reason::Truncated))?;
        let slice = self.buf.get(self.pos..end).ok_or(Invalid::new(Reason::Truncated))?;
        self.pos = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, Invalid> {
        let b = *self.buf.get(self.pos).ok_or(Invalid::new(Reason::Truncated))?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }
}

/// Read a shortest-form argument, rejecting non-minimal encodings outright.
fn read_arg(c: &mut Cursor<'_>, ai: u8) -> Result<u64, Invalid> {
    match ai {
        0..=23 => Ok(u64::from(ai)),
        24 => {
            let b = c.byte()?;
            if b < 24 {
                return Err(Invalid::new(Reason::NonCanonicalInt));
            }
            Ok(u64::from(b))
        }
        25 => {
            let b = c.take(2)?;
            let n = u64::from(u16::from_be_bytes([
                *b.first().unwrap_or(&0),
                *b.get(1).unwrap_or(&0),
            ]));
            if n <= u64::from(u8::MAX) {
                return Err(Invalid::new(Reason::NonCanonicalInt));
            }
            Ok(n)
        }
        26 => {
            let b = c.take(4)?;
            let mut a = [0u8; 4];
            a.copy_from_slice(b);
            let n = u64::from(u32::from_be_bytes(a));
            if n <= u64::from(u16::MAX) {
                return Err(Invalid::new(Reason::NonCanonicalInt));
            }
            Ok(n)
        }
        27 => {
            let b = c.take(8)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            let n = u64::from_be_bytes(a);
            if n <= u64::from(u32::MAX) {
                return Err(Invalid::new(Reason::NonCanonicalInt));
            }
            Ok(n)
        }
        // 28..=30 are reserved; 31 is indefinite length.
        _ => Err(Invalid::new(Reason::ForbiddenCborConstruct)),
    }
}

fn decode_value(c: &mut Cursor<'_>, depth: usize) -> Result<Value, Invalid> {
    if depth > MAX_DEPTH {
        return Err(Invalid::new(Reason::DepthLimit));
    }
    let ib = c.byte()?;
    let major = ib >> 5;
    let ai = ib & 0x1f;

    match major {
        0 => Ok(Value::Uint(read_arg(c, ai)?)),
        1 => Ok(Value::Nint(read_arg(c, ai)?)),
        2 => {
            let n = read_arg(c, ai)?;
            let n = usize::try_from(n).map_err(|_| Invalid::new(Reason::Truncated))?;
            Ok(Value::Bytes(c.take(n)?.to_vec()))
        }
        3 => {
            let n = read_arg(c, ai)?;
            let n = usize::try_from(n).map_err(|_| Invalid::new(Reason::Truncated))?;
            let raw = c.take(n)?;
            let s = core::str::from_utf8(raw).map_err(|_| Invalid::new(Reason::InvalidUtf8))?;
            Ok(Value::Text(String::from(s)))
        }
        4 => {
            let n = read_arg(c, ai)?;
            let n = usize::try_from(n).map_err(|_| Invalid::new(Reason::Truncated))?;
            // Guard: each item costs >= 1 byte, so n cannot exceed remaining input.
            if n > c.buf.len().saturating_sub(c.pos) {
                return Err(Invalid::new(Reason::Truncated));
            }
            let mut items = Vec::with_capacity(n);
            for _ in 0..n {
                items.push(decode_value(c, depth.saturating_add(1))?);
            }
            Ok(Value::Array(items))
        }
        5 => {
            let n = read_arg(c, ai)?;
            let n = usize::try_from(n).map_err(|_| Invalid::new(Reason::Truncated))?;
            if n > c.buf.len().saturating_sub(c.pos) {
                return Err(Invalid::new(Reason::Truncated));
            }
            let mut entries = Vec::with_capacity(n);
            let mut prev_key: Option<Vec<u8>> = None;
            for _ in 0..n {
                let k = decode_value(c, depth.saturating_add(1))?;
                let v = decode_value(c, depth.saturating_add(1))?;
                let ke = encode(&k);
                match &prev_key {
                    Some(p) if *p == ke => return Err(Invalid::new(Reason::DuplicateMapKey)),
                    Some(p) if *p > ke => return Err(Invalid::new(Reason::UnsortedMapKeys)),
                    _ => {}
                }
                prev_key = Some(ke);
                entries.push((k, v));
            }
            Ok(Value::Map(entries))
        }
        7 => match ai {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            // 23 = undefined, 25/26/27 = float16/32/64 -> all forbidden by IRF.
            _ => Err(Invalid::new(Reason::ForbiddenCborConstruct)),
        },
        // 6 = semantic tag -> forbidden by IRF.
        _ => Err(Invalid::new(Reason::ForbiddenCborConstruct)),
    }
}

/// Decode strictly-canonical CBOR. Rejects trailing bytes.
///
/// Belt and braces: after structural decoding, the value is re-encoded and
/// compared byte-for-byte with the input. Any encoding variance the structural
/// checks somehow missed still yields INVALID.
pub fn decode_canonical(input: &[u8]) -> Result<Value, Invalid> {
    let mut c = Cursor { buf: input, pos: 0 };
    let v = decode_value(&mut c, 0)?;
    if c.pos != input.len() {
        return Err(Invalid::new(Reason::TrailingBytes));
    }
    if encode(&v) != input {
        return Err(Invalid::new(Reason::NonCanonicalEncoding));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_head_shortest_form() {
        assert_eq!(encode(&Value::Uint(0)), vec![0x00]);
        assert_eq!(encode(&Value::Uint(23)), vec![0x17]);
        assert_eq!(encode(&Value::Uint(24)), vec![0x18, 0x18]);
        assert_eq!(encode(&Value::Uint(255)), vec![0x18, 0xff]);
        assert_eq!(encode(&Value::Uint(256)), vec![0x19, 0x01, 0x00]);
        assert_eq!(encode(&Value::Nint(0)), vec![0x20]); // -1
    }

    #[test]
    fn rejects_non_minimal_int() {
        // 24 encoded in a 1-byte head slot that should have been inlined
        assert!(decode_canonical(&[0x18, 0x05]).is_err());
        // 256 encoded as 4 bytes
        assert!(decode_canonical(&[0x1a, 0x00, 0x00, 0x01, 0x00]).is_err());
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0x5f = indefinite-length byte string
        assert!(decode_canonical(&[0x5f, 0x41, 0x61, 0xff]).is_err());
    }

    #[test]
    fn rejects_floats_and_tags() {
        assert!(decode_canonical(&[0xf9, 0x00, 0x00]).is_err()); // float16 0.0
        assert!(decode_canonical(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]).is_err()); // float64
        assert!(decode_canonical(&[0xc0, 0x61, 0x61]).is_err()); // tag(0)
        assert!(decode_canonical(&[0xf7]).is_err()); // undefined
    }

    #[test]
    fn rejects_unsorted_and_duplicate_keys() {
        // {"b":1,"a":1} -> unsorted
        assert!(decode_canonical(&[0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x01]).is_err());
        // {"a":1,"a":1} -> duplicate
        assert!(decode_canonical(&[0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x01]).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert!(decode_canonical(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode_canonical(&[0x42, 0x01]).is_err()); // 2-byte bstr, 1 byte present
        assert!(decode_canonical(&[]).is_err());
    }

    #[test]
    fn rejects_depth_bomb() {
        // MAX_DEPTH+2 nested single-element arrays
        let mut b = vec![0x81u8; MAX_DEPTH + 2];
        b.push(0x00);
        assert!(decode_canonical(&b).is_err());
    }

    #[test]
    fn rejects_array_length_lie() {
        // claims 2^32 items with no payload
        assert!(decode_canonical(&[0x9a, 0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn map_builder_sorts_and_rejects_dupes() {
        let m = Value::map(vec![
            (Value::Text(String::from("b")), Value::Uint(2)),
            (Value::Text(String::from("a")), Value::Uint(1)),
        ])
        .expect("sortable");
        assert_eq!(encode(&m), vec![0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]);
        assert!(Value::map(vec![
            (Value::Text(String::from("a")), Value::Uint(1)),
            (Value::Text(String::from("a")), Value::Uint(2)),
        ])
        .is_err());
    }

    #[test]
    fn round_trip_is_stable() {
        let v = Value::map(vec![
            (Value::Text(String::from("uri")), Value::Text(String::from("https://x/y"))),
            (Value::Text(String::from("len")), Value::Uint(4096)),
            (Value::Text(String::from("h")), Value::Bytes(vec![0xde, 0xad])),
            (Value::Text(String::from("ok")), Value::Bool(true)),
            (Value::Text(String::from("nil")), Value::Null),
            (Value::Text(String::from("neg")), Value::Nint(41)),
        ])
        .expect("map");
        let enc = encode(&v);
        let dec = decode_canonical(&enc).expect("canonical");
        assert_eq!(dec, v);
        assert_eq!(encode(&dec), enc);
    }
}
