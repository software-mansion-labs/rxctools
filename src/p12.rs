//! Signing identities from PKCS#12 (.p12) files, and the few X.509 fields code signing needs.
//!
//! Reads what Keychain Access and OpenSSL (old and new defaults) write: PKCS#12 PBE with
//! 3DES or RC2, PBES2 with PBKDF2 and AES or 3DES, SHA-1 or SHA-256 MACs.

use crate::der::{Der, oid};
use crate::util::{Error, Result, bail};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, InnerIvInit, KeyIvInit};
use ring::digest;
use ring::signature::{KeyPair, RsaKeyPair};

pub struct Identity {
    pub key: RsaKeyPair,
    /// DER of the certificate that goes with `key`.
    pub cert: Vec<u8>,
}

pub struct Cert<'a> {
    /// Whole DER encodings, as CMS IssuerAndSerialNumber wants them.
    pub issuer: &'a [u8],
    pub serial: &'a [u8],
    /// RSAPublicKey DER from subjectPublicKeyInfo.
    pub public_key: &'a [u8],
    pub common_name: String,
    /// The team id, for Apple developer certificates.
    pub org_unit: String,
}

pub fn parse_cert(der: &[u8]) -> Result<Cert<'_>> {
    let mut tbs = Der(Der(Der(der).expect(0x30)?).expect(0x30)?);
    if tbs.0.first() == Some(&0xa0) {
        tbs.next()?; // version
    }
    let serial = tbs.raw()?;
    tbs.next()?; // signature algorithm
    let issuer = tbs.raw()?;
    tbs.next()?; // validity
    let (mut common_name, mut org_unit) = (String::new(), String::new());
    let mut rdns = Der(tbs.expect(0x30)?);
    while !rdns.is_empty() {
        let mut atvs = Der(rdns.expect(0x31)?);
        while !atvs.is_empty() {
            let mut atv = Der(atvs.expect(0x30)?);
            let (o, (_, v)) = (atv.expect(0x06)?, atv.next()?);
            let v = String::from_utf8_lossy(v).into_owned();
            match o {
                oid::COMMON_NAME => common_name = v,
                oid::ORG_UNIT => org_unit = v,
                _ => {}
            }
        }
    }
    let mut spki = Der(tbs.expect(0x30)?);
    spki.next()?; // algorithm
    let public_key = match spki.expect(0x03)? {
        [0, k @ ..] => k,
        _ => return bail("certificate: malformed public key"),
    };
    Ok(Cert {
        issuer,
        serial,
        public_key,
        common_name,
        org_unit,
    })
}

pub fn load(p12: &[u8], password: &str) -> Result<Identity> {
    let mut pfx = Der(Der(p12).expect(0x30)?);
    if pfx.uint()? != 3 {
        return bail("p12: unsupported version");
    }
    let mut auth = Der(pfx.expect(0x30)?);
    if auth.expect(0x06)? != oid::DATA {
        return bail("p12: public-key integrity mode is not supported");
    }
    let safe = Der(auth.expect(0xa0)?).octets()?;
    if !pfx.is_empty() {
        check_mac(&mut Der(pfx.expect(0x30)?), &safe, password)?;
    }

    let (mut keys, mut certs) = (vec![], vec![]);
    let mut infos = Der(Der(&safe).expect(0x30)?);
    while !infos.is_empty() {
        let mut info = Der(infos.expect(0x30)?);
        let kind = info.expect(0x06)?;
        let mut body = Der(info.expect(0xa0)?);
        let contents = match kind {
            oid::DATA => body.octets()?,
            oid::ENCRYPTED_DATA => {
                let mut ed = Der(body.expect(0x30)?);
                ed.uint()?;
                let mut eci = Der(ed.expect(0x30)?);
                eci.expect(0x06)?;
                let alg = eci.raw()?;
                let data = match eci.next()? {
                    (0x80, c) => c.to_vec(),
                    (0xa0, c) => {
                        let (mut pieces, mut data) = (Der(c), vec![]);
                        while !pieces.is_empty() {
                            data.extend(pieces.octets()?);
                        }
                        data
                    }
                    _ => return bail("p12: malformed encrypted data"),
                };
                decrypt(alg, &data, password)?
            }
            _ => continue,
        };
        let mut bags = Der(Der(&contents).expect(0x30)?);
        while !bags.is_empty() {
            let mut bag = Der(bags.expect(0x30)?);
            let kind = bag.expect(0x06)?;
            let value = Der(bag.expect(0xa0)?);
            match kind {
                oid::KEY_BAG => keys.push(value.0.to_vec()),
                oid::SHROUDED_KEY_BAG => {
                    let mut epki = Der(Der(value.0).expect(0x30)?);
                    let alg = epki.raw()?;
                    keys.push(decrypt(alg, &epki.octets()?, password)?);
                }
                oid::CERT_BAG => {
                    let mut cb = Der(Der(value.0).expect(0x30)?);
                    if cb.expect(0x06)? == oid::X509_CERT {
                        certs.push(Der(cb.expect(0xa0)?).octets()?);
                    }
                }
                _ => {}
            }
        }
    }

    for k in keys {
        // PrivateKeyInfo { version, algorithm, privateKey, [attributes] }: ring's PKCS#8 parser
        // refuses the attributes Keychain adds, so take the PKCS#1 key out directly
        let mut pki = Der(Der(&k).expect(0x30)?);
        pki.uint()?;
        pki.next()?;
        let key = RsaKeyPair::from_der(&pki.octets()?)
            .map_err(|e| Error::msg(format!("p12: unsupported private key ({e})")))?;
        let public = key.public_key().as_ref().to_vec();
        if let Some(cert) = certs
            .iter()
            .find(|c| parse_cert(c).is_ok_and(|c| c.public_key == public))
        {
            return Ok(Identity {
                key,
                cert: cert.clone(),
            });
        }
    }
    bail("p12: no RSA private key with a matching certificate")
}

fn check_mac(mac: &mut Der, data: &[u8], password: &str) -> Result<()> {
    let mut digest_info = Der(mac.expect(0x30)?);
    let alg = Der(digest_info.expect(0x30)?).expect(0x06)?;
    let expected = digest_info.octets()?;
    let salt = mac.octets()?;
    let iterations = if mac.is_empty() { 1 } else { mac.uint()? };
    let (h, m) = match alg {
        oid::SHA1 => (
            &digest::SHA1_FOR_LEGACY_USE_ONLY,
            ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        ),
        oid::SHA256 => (&digest::SHA256, ring::hmac::HMAC_SHA256),
        _ => return bail("p12: unsupported MAC algorithm"),
    };
    // an empty password is either the BMPString terminator alone or no bytes at all
    let mut candidates = vec![bmp(password)];
    if password.is_empty() {
        candidates.push(vec![]);
    }
    for pw in candidates {
        let key = kdf(h, &pw, &salt, 3, iterations, h.output_len())?;
        if ring::hmac::verify(&ring::hmac::Key::new(m, &key), data, &expected).is_ok() {
            return Ok(());
        }
    }
    bail("p12: wrong password (MAC check failed)")
}

fn decrypt(alg: &[u8], data: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut a = Der(Der(alg).expect(0x30)?);
    let o = a.expect(0x06)?;
    let mut params = Der(a.expect(0x30)?);
    let mut buf = data.to_vec();
    let bad = |_| Error::msg("p12: decryption failed, wrong password?");
    let out = if o.len() == oid::PKCS12_PBE.len() + 1 && o.starts_with(oid::PKCS12_PBE) {
        let salt = params.octets()?;
        let iterations = params.uint()?;
        let pw = bmp(password);
        let sha1 = &digest::SHA1_FOR_LEGACY_USE_ONLY;
        let iv = kdf(sha1, &pw, &salt, 2, iterations, 8)?;
        match o[o.len() - 1] {
            3 => {
                let key = kdf(sha1, &pw, &salt, 1, iterations, 24)?;
                cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
                    .map_err(|_| Error::msg("p12: bad 3DES parameters"))?
                    .decrypt_padded::<Pkcs7>(&mut buf)
                    .map_err(bad)?
            }
            n @ (5 | 6) => {
                let len = if n == 5 { 16 } else { 5 };
                let key = kdf(sha1, &pw, &salt, 1, iterations, len)?;
                let rc2 = rc2::Rc2::new_with_eff_key_len(&key, len * 8);
                cbc::Decryptor::<rc2::Rc2>::inner_iv_slice_init(rc2, &iv)
                    .map_err(|_| Error::msg("p12: bad RC2 parameters"))?
                    .decrypt_padded::<Pkcs7>(&mut buf)
                    .map_err(bad)?
            }
            _ => return bail("p12: unsupported PBE cipher"),
        }
    } else if o == oid::PBES2 {
        let mut kdf_alg = Der(params.expect(0x30)?);
        if kdf_alg.expect(0x06)? != oid::PBKDF2 {
            return bail("p12: unsupported key derivation");
        }
        let mut kp = Der(kdf_alg.expect(0x30)?);
        let salt = kp.octets()?;
        let iterations = std::num::NonZeroU32::new(u32::try_from(kp.uint()?).unwrap_or(0))
            .ok_or_else(|| Error::msg("p12: bad PBKDF2 iteration count"))?;
        if kp.0.first() == Some(&0x02) {
            kp.uint()?; // keyLength, implied by the cipher
        }
        let prf = match kp.is_empty() {
            true => ring::pbkdf2::PBKDF2_HMAC_SHA1,
            false => match Der(kp.expect(0x30)?).expect(0x06)? {
                oid::HMAC_SHA256 => ring::pbkdf2::PBKDF2_HMAC_SHA256,
                _ => return bail("p12: unsupported PBKDF2 PRF"),
            },
        };
        let mut enc = Der(params.expect(0x30)?);
        let cipher = enc.expect(0x06)?;
        let iv = enc.octets()?;
        let derive = |len: usize| {
            let mut key = vec![0; len];
            ring::pbkdf2::derive(prf, iterations, &salt, password.as_bytes(), &mut key);
            key
        };
        macro_rules! cbc_with {
            ($c:ty, $len:expr) => {
                cbc::Decryptor::<$c>::new_from_slices(&derive($len), &iv)
                    .map_err(|_| Error::msg("p12: bad cipher parameters"))?
                    .decrypt_padded::<Pkcs7>(&mut buf)
                    .map_err(bad)?
            };
        }
        match cipher {
            oid::DES_EDE3_CBC => cbc_with!(des::TdesEde3, 24),
            [p @ .., 2] if p == oid::AES_CBC => cbc_with!(aes::Aes128, 16),
            [p @ .., 22] if p == oid::AES_CBC => cbc_with!(aes::Aes192, 24),
            [p @ .., 42] if p == oid::AES_CBC => cbc_with!(aes::Aes256, 32),
            _ => return bail("p12: unsupported PBES2 cipher"),
        }
    } else {
        return bail("p12: unsupported encryption algorithm");
    };
    Ok(out.to_vec())
}

/// The password as PKCS#12 wants it: UTF-16BE with a terminating NUL.
fn bmp(password: &str) -> Vec<u8> {
    password
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_be_bytes)
        .collect()
}

/// RFC 7292 appendix B.2 key derivation (id 1 key, 2 IV, 3 MAC key).
fn kdf(
    h: &'static digest::Algorithm,
    pw: &[u8],
    salt: &[u8],
    id: u8,
    iterations: u64,
    n: usize,
) -> Result<Vec<u8>> {
    if iterations == 0 || iterations > 10_000_000 {
        return bail("p12: bad iteration count");
    }
    let (u, v) = (h.output_len(), h.block_len());
    let fill = |x: &[u8]| -> Vec<u8> {
        (0..x.len().div_ceil(v) * v)
            .map(|i| x[i % x.len()])
            .collect()
    };
    let mut i_buf = [fill(salt), fill(pw)].concat();
    let mut out = vec![];
    while out.len() < n {
        let mut ctx = digest::Context::new(h);
        ctx.update(&vec![id; v]);
        ctx.update(&i_buf);
        let mut a = ctx.finish();
        for _ in 1..iterations {
            a = digest::digest(h, a.as_ref());
        }
        let a = a.as_ref();
        out.extend_from_slice(a);
        for chunk in i_buf.chunks_mut(v) {
            // chunk = chunk + B + 1, B being `a` repeated to v bytes
            let mut carry = 1u16;
            for k in (0..v).rev() {
                let s = chunk[k] as u16 + a[k % u] as u16 + carry;
                chunk[k] = s as u8;
                carry = s >> 8;
            }
        }
    }
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sign");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    // Test identities made with OpenSSL/LibreSSL (see tests/fixtures/sign/README.md), one per
    // encryption scheme, all for the same key and certificate.
    #[test]
    fn loads_every_encryption_scheme() {
        let cert = fixture("cert.der");
        for name in [
            "legacy-3des-rc2.p12",
            "pbes2-aes256.p12",
            "pbes2-3des.p12",
            "nomac-aes128.p12",
        ] {
            let id = load(&fixture(name), "test").unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(id.cert, cert, "{name}");
        }
        assert!(load(&fixture("empty-password.p12"), "").is_ok());
    }

    #[test]
    fn wrong_password_is_reported() {
        let e = load(&fixture("pbes2-aes256.p12"), "nope").err().unwrap();
        assert!(e.0.contains("wrong password"), "{e}");
        let e = load(&fixture("nomac-aes128.p12"), "nope").err().unwrap();
        assert!(e.0.contains("wrong password"), "{e}");
    }

    #[test]
    fn certificate_fields() {
        let der = fixture("cert.der");
        let c = parse_cert(&der).unwrap();
        assert_eq!(c.common_name, "Apple Development: rios test (TESTTEAM01)");
        assert_eq!(c.org_unit, "TESTTEAM01");
        assert_eq!(c.issuer[0], 0x30);
        assert_eq!(c.serial[0], 0x02);
    }

    // RFC 7292 KDF against OpenSSL's PKCS12_key_gen output for password "smeg", salt
    // 0a58cf64530d823f, 1 iteration (the vectors from OpenSSL's test suite).
    #[test]
    fn kdf_matches_openssl() {
        let salt = [0x0a, 0x58, 0xcf, 0x64, 0x53, 0x0d, 0x82, 0x3f];
        let sha1 = &digest::SHA1_FOR_LEGACY_USE_ONLY;
        let key = kdf(sha1, &bmp("smeg"), &salt, 1, 1, 24).unwrap();
        assert_eq!(
            crate::util::hex(&key),
            "8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3"
        );
        let iv = kdf(sha1, &bmp("smeg"), &salt, 2, 1, 8).unwrap();
        assert_eq!(crate::util::hex(&iv), "79993dfe048d3b76");
    }
}
