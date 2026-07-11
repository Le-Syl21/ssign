//! A tiny DER (TLV) encoder — just enough to hand-build the Microsoft
//! Authenticode structures that no general CMS crate models directly.
//!
//! Everything returns owned `Vec<u8>` of complete tag-length-value encodings.

/// DER length octets for `n`.
fn len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut b = n.to_be_bytes().to_vec();
        while b.first() == Some(&0) {
            b.remove(0);
        }
        let mut out = vec![0x80 | b.len() as u8];
        out.extend_from_slice(&b);
        out
    }
}

/// A tag-length-value with an arbitrary tag byte over `content`.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    out.extend_from_slice(&len(content.len()));
    out.extend_from_slice(content);
    out
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &concat(parts))
}

/// SET (0x31). For SET OF, pass already-sorted members.
pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &concat(parts))
}

pub fn octet_string(v: &[u8]) -> Vec<u8> {
    tlv(0x04, v)
}

pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// INTEGER 1 (only value we need to build from scratch).
pub fn int_one() -> Vec<u8> {
    vec![0x02, 0x01, 0x01]
}

/// Context-specific constructed tag `[n]` (0xA0 | n) over `content`.
pub fn ctx(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

/// Context-specific primitive tag `[n]` (0x80 | n) over raw `content`.
pub fn ctx_prim(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | n, content)
}

/// UTCTime, `YYMMDDhhmmssZ`.
pub fn utc_time(s: &str) -> Vec<u8> {
    tlv(0x17, s.as_bytes())
}

/// OBJECT IDENTIFIER from a dotted string.
pub fn oid(dotted: &str) -> Vec<u8> {
    let parts: Vec<u64> = dotted.split('.').map(|p| p.parse().unwrap()).collect();
    let mut body = vec![(parts[0] * 40 + parts[1]) as u8];
    for &n in &parts[2..] {
        let mut stack = vec![(n & 0x7f) as u8];
        let mut n = n >> 7;
        while n > 0 {
            stack.push((n & 0x7f) as u8 | 0x80);
            n >>= 7;
        }
        stack.reverse();
        body.extend_from_slice(&stack);
    }
    tlv(0x06, &body)
}

/// Wrap raw bytes verbatim (already a complete TLV). Handy for constants.
pub fn raw(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

/// BOOLEAN TRUE.
pub fn bool_true() -> Vec<u8> {
    vec![0x01, 0x01, 0xff]
}

/// Split a constructed TLV (SEQUENCE/SET) into its child TLVs. Returns the
/// slices of each element within `tlv`'s content, or an error on malformed DER.
pub fn children(tlv: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    let (hdr, len) = read_len(tlv, 1)?;
    let content = tlv.get(hdr..hdr + len).ok_or("truncated TLV")?;
    let mut out = Vec::new();
    let mut i = 0;
    while i < content.len() {
        let (h, l) = read_len(content, i + 1)?;
        let end = h + l;
        out.push(content.get(i..end).ok_or("truncated element")?);
        i = end;
    }
    Ok(out)
}

/// Parse a DER length that starts at `at` (just after the tag). Returns the
/// content start offset (absolute in `b`) and the content length.
fn read_len(b: &[u8], at: usize) -> Result<(usize, usize), &'static str> {
    let first = *b.get(at).ok_or("truncated length")?;
    if first < 0x80 {
        Ok((at + 1, first as usize))
    } else {
        let n = (first & 0x7f) as usize;
        let bytes = b.get(at + 1..at + 1 + n).ok_or("truncated long length")?;
        let mut len = 0usize;
        for &byte in bytes {
            len = (len << 8) | byte as usize;
        }
        Ok((at + 1 + n, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_oids() {
        // sha256 = 2.16.840.1.101.3.4.2.1
        assert_eq!(
            hex::encode(oid("2.16.840.1.101.3.4.2.1")),
            "0609608648016503040201"
        );
        // SPC_INDIRECT_DATA = 1.3.6.1.4.1.311.2.1.4
        assert_eq!(
            hex::encode(oid("1.3.6.1.4.1.311.2.1.4")),
            "060a2b060104018237020104"
        );
    }

    #[test]
    fn long_length() {
        let content = vec![0u8; 300];
        let e = tlv(0x04, &content);
        assert_eq!(&e[..4], &[0x04, 0x82, 0x01, 0x2c]);
    }
}
