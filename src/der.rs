//! Just enough ASN.1 for PKCS#12, X.509 and CMS: a bounds-checked BER/DER reader and DER
//! encoders.

use crate::util::{Result, bail};

pub mod oid {
    pub const DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
    pub const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
    pub const ENCRYPTED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06];
    pub const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
    pub const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    pub const SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    pub const CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
    pub const MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
    pub const SIGNING_TIME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
    pub const APPLE_CDHASHES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x01];
    pub const APPLE_CDHASHES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x02];
    pub const KEY_BAG: &[u8] = &[
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x01,
    ];
    pub const SHROUDED_KEY_BAG: &[u8] = &[
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02,
    ];
    pub const CERT_BAG: &[u8] = &[
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03,
    ];
    pub const X509_CERT: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01];
    /// pbeWithSHAAnd* (PKCS#12 PBE), last arc picks the cipher.
    pub const PKCS12_PBE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01];
    pub const PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
    pub const PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
    pub const HMAC_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
    pub const DES_EDE3_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07];
    /// aes-CBC, last byte 2/22/42 for 128/192/256.
    pub const AES_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01];
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    pub const ORG_UNIT: &[u8] = &[0x55, 0x04, 0x0b];
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let mut out = vec![tag];
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let len = n.to_be_bytes();
        let skip = len.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (len.len() - skip) as u8);
        out.extend_from_slice(&len[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

pub fn oid(o: &[u8]) -> Vec<u8> {
    tlv(0x06, o)
}

pub fn octets(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

pub fn utf8(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes())
}

pub fn int(v: i64) -> Vec<u8> {
    let b = v.to_be_bytes();
    // drop leading bytes that only repeat the sign
    let mut i = 0;
    while i < 7 && ((b[i] == 0 && b[i + 1] < 0x80) || (b[i] == 0xff && b[i + 1] >= 0x80)) {
        i += 1;
    }
    tlv(0x02, &b[i..])
}

/// AlgorithmIdentifier with NULL parameters.
pub fn alg(o: &[u8]) -> Vec<u8> {
    seq(&[&oid(o), &[0x05, 0x00]])
}

/// Reads consecutive TLVs; indefinite lengths (BER) are accepted.
pub struct Der<'a>(pub &'a [u8]);

impl<'a> Der<'a> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The next element as (tag, content).
    pub fn next(&mut self) -> Result<(u8, &'a [u8])> {
        let (tag, content, len) = parse(self.0)?;
        self.0 = &self.0[len..];
        Ok((tag, content))
    }

    /// The next element, which must have `tag`.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        match self.next()? {
            (t, c) if t == tag => Ok(c),
            (t, _) => bail(format!("ASN.1: expected tag {tag:#04x}, found {t:#04x}")),
        }
    }

    /// The next element as a whole encoding (tag and length included).
    pub fn raw(&mut self) -> Result<&'a [u8]> {
        let (_, _, len) = parse(self.0)?;
        let r = &self.0[..len];
        self.0 = &self.0[len..];
        Ok(r)
    }

    pub fn uint(&mut self) -> Result<u64> {
        let c = self.expect(0x02)?;
        if c.len() > 9 || (c.len() == 9 && c[0] != 0) || c.first().is_some_and(|b| b & 0x80 != 0) {
            return bail("ASN.1: integer out of range");
        }
        Ok(c.iter().fold(0, |n, b| n << 8 | *b as u64))
    }

    /// An OCTET STRING, joining the pieces of a constructed (BER) one.
    pub fn octets(&mut self) -> Result<Vec<u8>> {
        match self.next()? {
            (0x04, c) => Ok(c.to_vec()),
            (0x24, c) => {
                let (mut d, mut out) = (Der(c), vec![]);
                while !d.is_empty() {
                    out.extend(d.octets()?);
                }
                Ok(out)
            }
            (t, _) => bail(format!("ASN.1: expected an OCTET STRING, found {t:#04x}")),
        }
    }
}

/// (tag, content, total length) of the element at the start of `b`.
fn parse(b: &[u8]) -> Result<(u8, &[u8], usize)> {
    let short = || crate::util::Error::msg("ASN.1: truncated element");
    let tag = *b.first().ok_or_else(short)?;
    if tag & 0x1f == 0x1f {
        return bail("ASN.1: multi-byte tags are not supported");
    }
    let l = *b.get(1).ok_or_else(short)?;
    let (len, hdr) = match l {
        0x80 => {
            // indefinite: children up to the end-of-contents marker
            let mut off = 2;
            loop {
                if b.get(off..off + 2).ok_or_else(short)? == [0, 0] {
                    return Ok((tag, &b[2..off], off + 2));
                }
                off += parse(&b[off..])?.2;
            }
        }
        l if l < 0x80 => (l as usize, 2),
        l => {
            let n = (l & 0x7f) as usize;
            if n > 4 {
                return bail("ASN.1: length too large");
            }
            let bytes = b.get(2..2 + n).ok_or_else(short)?;
            (bytes.iter().fold(0, |a, x| a << 8 | *x as usize), 2 + n)
        }
    };
    let content = b.get(hdr..hdr + len).ok_or_else(short)?;
    Ok((tag, content, hdr + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_minimal() {
        assert_eq!(int(0), [2, 1, 0]);
        assert_eq!(int(127), [2, 1, 0x7f]);
        assert_eq!(int(128), [2, 2, 0, 0x80]);
        assert_eq!(int(-1), [2, 1, 0xff]);
        assert_eq!(int(2048), [2, 2, 8, 0]);
    }

    #[test]
    fn long_lengths_round_trip() {
        let big = tlv(0x04, &[7; 300]);
        assert_eq!(&big[..4], [0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(Der(&big).octets().unwrap(), vec![7; 300]);
    }

    #[test]
    fn reads_ber_indefinite_and_constructed_octets() {
        // SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "c" }, INTEGER 5 }
        let ber = [
            0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0, 0, 0x02, 0x01, 5,
            0, 0,
        ];
        let mut d = Der(&ber);
        let mut s = Der(d.expect(0x30).unwrap());
        assert!(d.is_empty());
        assert_eq!(s.octets().unwrap(), b"abc");
        assert_eq!(s.uint().unwrap(), 5);
        assert!(s.is_empty());
    }

    #[test]
    fn truncated_input_is_an_error() {
        assert!(Der(&[0x30, 0x05, 0x02]).next().is_err());
        assert!(Der(&[0x30, 0x80, 0x02, 0x01, 0x01]).next().is_err());
        assert!(Der(&[0x30]).next().is_err());
    }
}
