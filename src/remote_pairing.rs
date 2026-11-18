//! RemotePairing, the pairing CoreDevice uses since iOS 17: remotepairingdeviced's handshake over
//! lockdown, both sides of pair-setup (SRP-6a, 3072-bit, SHA-512, with the pinless setup code) and
//! pair-verify (X25519, Ed25519) as sans-IO state machines over TLV8 messages, and the encrypted
//! session they lead to. The caller moves the messages in whatever envelope its transport uses.

use crate::lockdown::Device;
use crate::util::{Error, Result, bail};
use num_bigint::BigUint;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{EphemeralPrivateKey, X25519, agree_ephemeral};
use ring::digest::{Context, SHA512};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde_json::{Value as J, json};
use std::io::{Read, Write};

pub const LOCKDOWN_SERVICE: &str = "com.apple.dt.remotepairingdeviced.lockdown";

/// The device's `peerDeviceInfo`, from remotepairingdeviced's handshake. Reads metadata only; it
/// neither pairs nor verifies.
pub fn peer_device_info(dev: &mut Device) -> Result<J> {
    let mut s = dev.connect_service(LOCKDOWN_SERVICE)?;
    s.write_all(&rppairing_frame(&json!({
        "message": {"plain": {"_0": {"request": {"_0": {"handshake": {"_0": {
            "hostOptions": {"attemptPairVerify": true}, "wireProtocolVersion": 19,
        }}}}}}},
        "originatedBy": "host", "sequenceNumber": 0,
    })))?;
    s.flush()?;
    read_rppairing(&mut s)?
        .pointer("/message/plain/_0/response/_1/handshake/_0/peerDeviceInfo")
        .cloned()
        .ok_or_else(|| Error::msg("remotepairingdeviced: no peerDeviceInfo in the handshake"))
}

fn rppairing_frame(v: &J) -> Vec<u8> {
    let body = v.to_string();
    let mut f = b"RPPairing".to_vec();
    f.extend((body.len() as u16).to_be_bytes());
    f.extend(body.as_bytes());
    f
}

fn read_rppairing(r: &mut impl Read) -> Result<J> {
    let mut h = [0u8; 11];
    r.read_exact(&mut h)?;
    if &h[..9] != b"RPPairing" {
        return bail("remotepairingdeviced: not an RPPairing frame");
    }
    let mut body = vec![0; u16::from_be_bytes([h[9], h[10]]) as usize];
    r.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

/// TLV8, the encoding of pairing messages.
pub mod tlv {
    use crate::util::{Result, bail};

    pub const METHOD: u8 = 0x00;
    pub const IDENTIFIER: u8 = 0x01;
    pub const SALT: u8 = 0x02;
    pub const PUBLIC_KEY: u8 = 0x03;
    pub const PROOF: u8 = 0x04;
    pub const ENCRYPTED_DATA: u8 = 0x05;
    pub const STATE: u8 = 0x06;
    pub const ERROR: u8 = 0x07;
    pub const SIGNATURE: u8 = 0x0a;
    pub const INFO: u8 = 0x11;

    /// Values over 255 bytes are split into consecutive fragments.
    pub fn encode(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = vec![];
        for (kind, value) in entries {
            for part in value.chunks(255) {
                out.extend([*kind, part.len() as u8]);
                out.extend(part);
            }
        }
        out
    }

    /// The value of `kind`, its fragments joined.
    pub fn get(bytes: &[u8], kind: u8) -> Result<Vec<u8>> {
        let (mut rest, mut out, mut found) = (bytes, vec![], false);
        while !rest.is_empty() {
            let Some((&[k, n], tail)) = rest.split_first_chunk::<2>() else {
                return bail("TLV8: truncated header");
            };
            let Some(value) = tail.get(..n as usize) else {
                return bail("TLV8: truncated value");
            };
            if k == kind {
                out.extend(value);
                found = true;
            }
            rest = &tail[n as usize..];
        }
        if !found {
            return bail(format!("TLV8: no item of type {kind:#04x}"));
        }
        Ok(out)
    }
}

/// A long-term pairing identity: an identifier and an Ed25519 key, kept as its 32-byte seed.
pub struct Identity {
    pub identifier: String,
    key: Ed25519KeyPair,
}

impl Identity {
    pub fn new(identifier: impl Into<String>, seed: &[u8; 32]) -> Result<Identity> {
        let identifier = identifier.into();
        self::identifier(identifier.as_bytes())?;
        let key = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|e| Error::msg(format!("Ed25519 seed: {e}")))?;
        Ok(Identity { identifier, key })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.public_key().as_ref().try_into().unwrap()
    }

    fn sign(&self, parts: &[&[u8]]) -> Vec<u8> {
        self.key.sign(&parts.concat()).as_ref().to_vec()
    }
}

/// The other side of a finished pair-setup or pair-verify, and the key its [`Session`] starts from.
#[derive(Clone)]
pub struct Peer {
    pub identifier: String,
    pub public_key: [u8; 32],
    pub session_key: Vec<u8>,
}

// leaves the session key out, so a logged peer does not leak it
impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("identifier", &self.identifier)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// The device's side of pair-setup: answers the host's M1, M3 and M5.
pub struct SetupResponder {
    identity: Identity,
    info: Vec<u8>,
    state: Setup,
}

enum Setup {
    Start,
    SentM2 { salt: [u8; 16], b: BigUint },
    SentM4 { key: Vec<u8> },
    Done(Peer),
    Failed,
}

impl SetupResponder {
    /// `info` reaches the host in M6, in OPACK: the device's `name`, `model`, `accountID`,
    /// `altIRK` and the like.
    pub fn new(identity: Identity, info: &plist::Dictionary) -> Result<SetupResponder> {
        Ok(SetupResponder {
            identity,
            info: opack(&plist::Value::Dictionary(info.clone()))?,
            state: Setup::Start,
        })
    }

    /// The reply to the host's next pair-setup message. A wrong setup code gets an error reply
    /// and ends the exchange.
    pub fn handle(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        match (
            std::mem::replace(&mut self.state, Setup::Failed),
            state(msg)?,
        ) {
            (Setup::Start, 1) => {
                let salt = random::<16>();
                let v = srp_verifier(&salt);
                // a full-length B, as Apple's side expects
                let (b, b_pub) = loop {
                    let b = BigUint::from_bytes_be(&random::<32>());
                    let b_pub = srp_b_pub(&v, &b);
                    if b_pub.bits() > 3064 {
                        break (b, b_pub);
                    }
                };
                self.state = Setup::SentM2 { salt, b };
                Ok(tlv::encode(&[
                    (tlv::STATE, &[2]),
                    (tlv::SALT, &salt),
                    (tlv::PUBLIC_KEY, &b_pub.to_bytes_be()),
                ]))
            }
            (Setup::SentM2 { salt, b }, 3) => {
                let a_pub = BigUint::from_bytes_be(&tlv::get(msg, tlv::PUBLIC_KEY)?);
                let v = srp_verifier(&salt);
                let b_pub = srp_b_pub(&v, &b);
                if &a_pub % srp_n() == BigUint::ZERO {
                    return bail("pair-setup: invalid public key from the host");
                }
                let u = srp_u(&a_pub, &b_pub);
                let s = (&a_pub * v.modpow(&u, &srp_n()) % srp_n()).modpow(&b, &srp_n());
                let (key, m1, m2) = srp_proofs(&salt, &a_pub, &b_pub, &s);
                if !constant_eq(&m1, &tlv::get(msg, tlv::PROOF)?) {
                    // kTLVError_Authentication
                    return Ok(tlv::encode(&[(tlv::STATE, &[4]), (tlv::ERROR, &[2])]));
                }
                self.state = Setup::SentM4 { key };
                Ok(tlv::encode(&[(tlv::STATE, &[4]), (tlv::PROOF, &m2)]))
            }
            (Setup::SentM4 { key }, 5) => {
                let c = cipher(&key, b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info");
                let plain = open(&c, label(b"PS-Msg05"), &tlv::get(msg, tlv::ENCRYPTED_DATA)?)?;
                let host = signed_peer(
                    &plain,
                    &hkdf(
                        &key,
                        b"Pair-Setup-Controller-Sign-Salt",
                        b"Pair-Setup-Controller-Sign-Info",
                    ),
                    &key,
                )?;
                let x = hkdf(
                    &key,
                    b"Pair-Setup-Accessory-Sign-Salt",
                    b"Pair-Setup-Accessory-Sign-Info",
                );
                let (id, pk) = (
                    self.identity.identifier.as_bytes(),
                    self.identity.public_key(),
                );
                let sig = self.identity.sign(&[&x, id, &pk]);
                let inner = tlv::encode(&[
                    (tlv::IDENTIFIER, id),
                    (tlv::PUBLIC_KEY, &pk),
                    (tlv::SIGNATURE, &sig),
                    (tlv::INFO, &self.info),
                ]);
                self.state = Setup::Done(host);
                Ok(tlv::encode(&[
                    (tlv::ENCRYPTED_DATA, &seal(&c, label(b"PS-Msg06"), &inner)),
                    (tlv::STATE, &[6]),
                ]))
            }
            (_, n) => bail(format!("pair-setup: unexpected M{n}")),
        }
    }

    /// The host, once M6 has been produced.
    pub fn paired(&self) -> Option<&Peer> {
        match &self.state {
            Setup::Done(p) => Some(p),
            _ => None,
        }
    }
}

/// The device's side of pair-verify: answers the host's M1 and M3.
pub struct VerifyResponder {
    identity: Identity,
    state: Verify,
}

enum Verify {
    Start,
    SentM2 {
        host_pub: [u8; 32],
        our_pub: [u8; 32],
        shared: Vec<u8>,
    },
    Done(Peer),
    Failed,
}

impl VerifyResponder {
    pub fn new(identity: Identity) -> VerifyResponder {
        VerifyResponder {
            identity,
            state: Verify::Start,
        }
    }

    /// The reply to the host's next pair-verify message. `known` gives the public key of a host
    /// paired earlier; an unknown host gets an error reply.
    pub fn handle(
        &mut self,
        msg: &[u8],
        known: impl Fn(&str) -> Option<[u8; 32]>,
    ) -> Result<Vec<u8>> {
        match (
            std::mem::replace(&mut self.state, Verify::Failed),
            state(msg)?,
        ) {
            (Verify::Start, 1) => {
                let host_pub = key32(&tlv::get(msg, tlv::PUBLIC_KEY)?)?;
                let (our_pub, shared) = x25519(&host_pub)?;
                let id = self.identity.identifier.as_bytes();
                let sig = self.identity.sign(&[&our_pub, id, &host_pub]);
                let c = cipher(
                    &shared,
                    b"Pair-Verify-Encrypt-Salt",
                    b"Pair-Verify-Encrypt-Info",
                );
                let inner = tlv::encode(&[(tlv::IDENTIFIER, id), (tlv::SIGNATURE, &sig)]);
                self.state = Verify::SentM2 {
                    host_pub,
                    our_pub,
                    shared: shared.clone(),
                };
                Ok(tlv::encode(&[
                    (tlv::STATE, &[2]),
                    (tlv::PUBLIC_KEY, &our_pub),
                    (tlv::ENCRYPTED_DATA, &seal(&c, label(b"PV-Msg02"), &inner)),
                ]))
            }
            (
                Verify::SentM2 {
                    host_pub,
                    our_pub,
                    shared,
                },
                3,
            ) => {
                let c = cipher(
                    &shared,
                    b"Pair-Verify-Encrypt-Salt",
                    b"Pair-Verify-Encrypt-Info",
                );
                let plain = open(&c, label(b"PV-Msg03"), &tlv::get(msg, tlv::ENCRYPTED_DATA)?)?;
                let id = identifier(&tlv::get(&plain, tlv::IDENTIFIER)?)?;
                let Some(pk) = known(&id) else {
                    return Ok(tlv::encode(&[(tlv::STATE, &[4]), (tlv::ERROR, &[4])]));
                };
                let signed = [&host_pub[..], id.as_bytes(), &our_pub].concat();
                verify(&pk, &signed, &tlv::get(&plain, tlv::SIGNATURE)?)?;
                self.state = Verify::Done(Peer {
                    identifier: id,
                    public_key: pk,
                    session_key: shared,
                });
                Ok(tlv::encode(&[(tlv::STATE, &[4])]))
            }
            (_, n) => bail(format!("pair-verify: unexpected M{n}")),
        }
    }

    /// The host, once its M3 checked out.
    pub fn verified(&self) -> Option<&Peer> {
        match &self.state {
            Verify::Done(p) => Some(p),
            _ => None,
        }
    }
}

/// The host's side of pair-setup with the pinless setup code.
pub struct SetupClient {
    identity: Identity,
    info: Vec<u8>,
    state: Client,
}

enum Client {
    Start,
    SentM1,
    SentM3 { key: Vec<u8>, m2: Vec<u8> },
    SentM5 { key: Vec<u8> },
    Done(Peer),
    Failed,
}

impl SetupClient {
    /// `info` reaches the device in M5, in OPACK.
    pub fn new(identity: Identity, info: &plist::Dictionary) -> Result<SetupClient> {
        Ok(SetupClient {
            identity,
            info: opack(&plist::Value::Dictionary(info.clone()))?,
            state: Client::Start,
        })
    }

    /// M1.
    pub fn start(&mut self) -> Vec<u8> {
        self.state = Client::SentM1;
        tlv::encode(&[(tlv::METHOD, &[0]), (tlv::STATE, &[1])])
    }

    /// The next message for the device (M3, M5), or None once its M6 checked out.
    pub fn handle(&mut self, msg: &[u8]) -> Result<Option<Vec<u8>>> {
        match (
            std::mem::replace(&mut self.state, Client::Failed),
            state(msg)?,
        ) {
            (Client::SentM1, 2) => {
                let salt = tlv::get(msg, tlv::SALT)?;
                let b_pub = BigUint::from_bytes_be(&tlv::get(msg, tlv::PUBLIC_KEY)?);
                if &b_pub % srp_n() == BigUint::ZERO {
                    return bail("pair-setup: invalid public key from the device");
                }
                // a full-length A, like the device's B
                let (a, a_pub) = loop {
                    let a = BigUint::from_bytes_be(&random::<32>());
                    let a_pub = srp_g().modpow(&a, &srp_n());
                    if a_pub.bits() > 3064 {
                        break (a, a_pub);
                    }
                };
                let (k, x) = (srp_k(), srp_x(&salt));
                let u = srp_u(&a_pub, &b_pub);
                let base =
                    (&b_pub + srp_n() - k * srp_g().modpow(&x, &srp_n()) % srp_n()) % srp_n();
                let s = base.modpow(&(a + u * x), &srp_n());
                let (key, m1, m2) = srp_proofs(&salt, &a_pub, &b_pub, &s);
                self.state = Client::SentM3 { key, m2 };
                Ok(Some(tlv::encode(&[
                    (tlv::STATE, &[3]),
                    (tlv::PUBLIC_KEY, &a_pub.to_bytes_be()),
                    (tlv::PROOF, &m1),
                ])))
            }
            (Client::SentM3 { key, m2 }, 4) => {
                if !constant_eq(&m2, &tlv::get(msg, tlv::PROOF)?) {
                    return bail("pair-setup: the device's proof does not match");
                }
                let prefix = hkdf(
                    &key,
                    b"Pair-Setup-Controller-Sign-Salt",
                    b"Pair-Setup-Controller-Sign-Info",
                );
                let (id, pk) = (
                    self.identity.identifier.as_bytes(),
                    self.identity.public_key(),
                );
                let sig = self.identity.sign(&[&prefix, id, &pk]);
                let inner = tlv::encode(&[
                    (tlv::IDENTIFIER, id),
                    (tlv::PUBLIC_KEY, &pk),
                    (tlv::SIGNATURE, &sig),
                    (tlv::INFO, &self.info),
                ]);
                let c = cipher(&key, b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info");
                let m5 = tlv::encode(&[
                    (tlv::STATE, &[5]),
                    (tlv::ENCRYPTED_DATA, &seal(&c, label(b"PS-Msg05"), &inner)),
                ]);
                self.state = Client::SentM5 { key };
                Ok(Some(m5))
            }
            (Client::SentM5 { key }, 6) => {
                let c = cipher(&key, b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info");
                let plain = open(&c, label(b"PS-Msg06"), &tlv::get(msg, tlv::ENCRYPTED_DATA)?)?;
                let x = hkdf(
                    &key,
                    b"Pair-Setup-Accessory-Sign-Salt",
                    b"Pair-Setup-Accessory-Sign-Info",
                );
                self.state = Client::Done(signed_peer(&plain, &x, &key)?);
                Ok(None)
            }
            (_, n) => bail(format!("pair-setup: unexpected M{n}")),
        }
    }

    /// The device, once its M6 checked out.
    pub fn paired(&self) -> Option<&Peer> {
        match &self.state {
            Client::Done(p) => Some(p),
            _ => None,
        }
    }
}

/// The host's side of pair-verify.
pub struct VerifyClient {
    identity: Identity,
    secret: Option<EphemeralPrivateKey>,
    pending: Option<Peer>,
    peer: Option<Peer>,
}

impl VerifyClient {
    pub fn new(identity: Identity) -> VerifyClient {
        VerifyClient {
            identity,
            secret: None,
            pending: None,
            peer: None,
        }
    }

    /// M1.
    pub fn start(&mut self) -> Result<Vec<u8>> {
        let secret = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())
            .map_err(|_| Error::msg("X25519: no key"))?;
        let public = secret
            .compute_public_key()
            .map_err(|_| Error::msg("X25519: no public key"))?;
        self.secret = Some(secret);
        Ok(tlv::encode(&[
            (tlv::STATE, &[1]),
            (tlv::PUBLIC_KEY, public.as_ref()),
        ]))
    }

    /// M3 for the device's M2, or None once its M4 accepted us. `known` gives the public key of
    /// a device paired earlier.
    pub fn handle(
        &mut self,
        msg: &[u8],
        known: impl Fn(&str) -> Option<[u8; 32]>,
    ) -> Result<Option<Vec<u8>>> {
        match state(msg)? {
            2 => {
                let secret = self
                    .secret
                    .take()
                    .ok_or_else(|| Error::msg("pair-verify: M2 before M1"))?;
                let our_pub = key32(
                    secret
                        .compute_public_key()
                        .map_err(|_| Error::msg("X25519"))?
                        .as_ref(),
                )?;
                let dev_pub = key32(&tlv::get(msg, tlv::PUBLIC_KEY)?)?;
                let shared = agree_ephemeral(
                    secret,
                    &ring::agreement::UnparsedPublicKey::new(&X25519, dev_pub),
                    |k| k.to_vec(),
                )
                .map_err(|_| Error::msg("pair-verify: X25519 agreement failed"))?;
                let c = cipher(
                    &shared,
                    b"Pair-Verify-Encrypt-Salt",
                    b"Pair-Verify-Encrypt-Info",
                );
                let plain = open(&c, label(b"PV-Msg02"), &tlv::get(msg, tlv::ENCRYPTED_DATA)?)?;
                let id = identifier(&tlv::get(&plain, tlv::IDENTIFIER)?)?;
                let pk = known(&id)
                    .ok_or_else(|| Error::msg(format!("pair-verify: {id} is not paired")))?;
                let signed = [&dev_pub[..], id.as_bytes(), &our_pub].concat();
                verify(&pk, &signed, &tlv::get(&plain, tlv::SIGNATURE)?)?;
                let our_id = self.identity.identifier.as_bytes();
                let sig = self.identity.sign(&[&our_pub, our_id, &dev_pub]);
                let inner = tlv::encode(&[(tlv::IDENTIFIER, our_id), (tlv::SIGNATURE, &sig)]);
                self.pending = Some(Peer {
                    identifier: id,
                    public_key: pk,
                    session_key: shared,
                });
                Ok(Some(tlv::encode(&[
                    (tlv::STATE, &[3]),
                    (tlv::ENCRYPTED_DATA, &seal(&c, label(b"PV-Msg03"), &inner)),
                ])))
            }
            4 if self.pending.is_some() => {
                self.peer = self.pending.take();
                Ok(None)
            }
            n => bail(format!("pair-verify: unexpected M{n}")),
        }
    }

    /// The device, once its M4 accepted us.
    pub fn verified(&self) -> Option<&Peer> {
        self.peer.as_ref()
    }
}

/// The encrypted channel after pairing: ChaCha20-Poly1305 with one key per direction and counter
/// nonces.
pub struct Session {
    seal: LessSafeKey,
    open: LessSafeKey,
    sealed: u64,
    opened: u64,
}

impl Session {
    /// The device's end, from [`Peer::session_key`].
    pub fn device(key: &[u8]) -> Session {
        Session::new(key, b"ServerEncrypt-main", b"ClientEncrypt-main")
    }

    /// The host's end.
    pub fn host(key: &[u8]) -> Session {
        Session::new(key, b"ClientEncrypt-main", b"ServerEncrypt-main")
    }

    fn new(key: &[u8], seal: &[u8], open: &[u8]) -> Session {
        Session {
            seal: cipher(key, b"", seal),
            open: cipher(key, b"", open),
            sealed: 0,
            opened: 0,
        }
    }

    pub fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        self.sealed += 1;
        seal(&self.seal, counter(self.sealed - 1), plain)
    }

    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>> {
        let plain = open(&self.open, counter(self.opened), sealed)?;
        self.opened += 1;
        Ok(plain)
    }
}

/// The `authTag` of a RemotePairing Bonjour record: SipHash-2-4 of `identifier` keyed with the
/// 16-byte `altIRK`, its first six output bytes, last first.
pub fn auth_tag(alt_irk: &[u8; 16], identifier: &str) -> [u8; 6] {
    use std::hash::Hasher;
    let k0 = u64::from_le_bytes(alt_irk[..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(alt_irk[8..].try_into().unwrap());
    #[allow(deprecated)] // std's SipHasher is SipHash-2-4
    let mut h = std::hash::SipHasher::new_with_keys(k0, k1);
    h.write(identifier.as_bytes());
    let out = h.finish().to_le_bytes();
    std::array::from_fn(|i| out[5 - i])
}

/// OPACK, Apple's compact binary plist, for the strings, data, booleans and dictionaries pairing
/// info carries.
pub fn opack(v: &plist::Value) -> Result<Vec<u8>> {
    fn sized(out: &mut Vec<u8>, small: u8, large: u8, b: &[u8]) {
        match b.len() {
            n if n <= 0x20 => out.push(small + n as u8),
            n if n <= 0xff => out.extend([large, n as u8]),
            n if n <= 0xffff => {
                out.push(large + 1);
                out.extend((n as u16).to_le_bytes());
            }
            n => {
                out.push(large + 2);
                out.extend((n as u32).to_le_bytes());
            }
        }
        out.extend(b);
    }
    let mut out = vec![];
    match v {
        plist::Value::Boolean(b) => out.push(if *b { 1 } else { 2 }),
        plist::Value::String(s) => sized(&mut out, 0x40, 0x61, s.as_bytes()),
        plist::Value::Data(d) => sized(&mut out, 0x70, 0x91, d),
        plist::Value::Dictionary(d) => {
            // up to 14 entries carry their count, more end with a terminator
            out.push(0xe0 + d.len().min(15) as u8);
            for (k, v) in d {
                sized(&mut out, 0x40, 0x61, k.as_bytes());
                out.extend(opack(v)?);
            }
            if d.len() > 14 {
                out.push(0x03);
            }
        }
        other => return bail(format!("OPACK: unsupported value {other:?}")),
    }
    Ok(out)
}

// --- SRP-6a over RFC 5054's 3072-bit group with SHA-512, as Apple's pair-setup uses it ---

const SRP_USER: &[u8] = b"Pair-Setup";
const SRP_CODE: &[u8] = b"000000";
const SRP_N: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff";

fn srp_n() -> BigUint {
    BigUint::parse_bytes(SRP_N.as_bytes(), 16).unwrap()
}

fn srp_g() -> BigUint {
    BigUint::from(5u8)
}

fn sha512(parts: &[&[u8]]) -> Vec<u8> {
    let mut c = Context::new(&SHA512);
    for p in parts {
        c.update(p);
    }
    c.finish().as_ref().to_vec()
}

fn padded(x: &BigUint) -> Vec<u8> {
    let b = x.to_bytes_be();
    [vec![0; 384usize.saturating_sub(b.len())], b].concat()
}

/// `k = H(N | PAD(g))`
fn srp_k() -> BigUint {
    BigUint::from_bytes_be(&sha512(&[&srp_n().to_bytes_be(), &padded(&srp_g())]))
}

/// `x = H(s | H(I ":" P))`
fn srp_x(salt: &[u8]) -> BigUint {
    BigUint::from_bytes_be(&sha512(&[salt, &sha512(&[SRP_USER, b":", SRP_CODE])]))
}

fn srp_verifier(salt: &[u8]) -> BigUint {
    srp_g().modpow(&srp_x(salt), &srp_n())
}

/// `B = k*v + g^b`
fn srp_b_pub(v: &BigUint, b: &BigUint) -> BigUint {
    (srp_k() * v + srp_g().modpow(b, &srp_n())) % srp_n()
}

/// `u = H(A | B)`
fn srp_u(a_pub: &BigUint, b_pub: &BigUint) -> BigUint {
    BigUint::from_bytes_be(&sha512(&[&a_pub.to_bytes_be(), &b_pub.to_bytes_be()]))
}

/// The session key `K = H(S)` and both proofs: `M1 = H(H(N) xor H(g) | H(I) | s | A | B | K)`,
/// `M2 = H(A | M1 | K)`.
fn srp_proofs(
    salt: &[u8],
    a_pub: &BigUint,
    b_pub: &BigUint,
    s: &BigUint,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let key = sha512(&[&s.to_bytes_be()]);
    let (hn, hg) = (
        sha512(&[&srp_n().to_bytes_be()]),
        sha512(&[&srp_g().to_bytes_be()]),
    );
    let hng: Vec<u8> = hn.iter().zip(&hg).map(|(a, b)| a ^ b).collect();
    let m1 = sha512(&[
        &hng,
        &sha512(&[SRP_USER]),
        salt,
        &padded(a_pub),
        &padded(b_pub),
        &key,
    ]);
    let m2 = sha512(&[&a_pub.to_bytes_be(), &m1, &key]);
    (key, m1, m2)
}

// --- shared helpers ---

/// The message's state, or the error it reports.
fn state(msg: &[u8]) -> Result<u8> {
    if let Ok(e) = tlv::get(msg, tlv::ERROR) {
        return bail(format!("pairing refused with error {e:?}"));
    }
    match tlv::get(msg, tlv::STATE)?[..] {
        [s] => Ok(s),
        _ => bail("TLV8: bad state"),
    }
}

/// Identifier, public key and signature over `prefix | identifier | public key`.
fn signed_peer(plain: &[u8], prefix: &[u8], session_key: &[u8]) -> Result<Peer> {
    let identifier = identifier(&tlv::get(plain, tlv::IDENTIFIER)?)?;
    let public_key = key32(&tlv::get(plain, tlv::PUBLIC_KEY)?)?;
    let signed = [prefix, identifier.as_bytes(), &public_key].concat();
    verify(&public_key, &signed, &tlv::get(plain, tlv::SIGNATURE)?)?;
    Ok(Peer {
        identifier,
        public_key,
        session_key: session_key.to_vec(),
    })
}

fn identifier(b: &[u8]) -> Result<String> {
    match std::str::from_utf8(b) {
        Ok(s) if !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control) => {
            Ok(s.into())
        }
        _ => bail("pairing: invalid identifier"),
    }
}

fn key32(b: &[u8]) -> Result<[u8; 32]> {
    b.try_into()
        .map_err(|_| Error::msg("pairing: a key is not 32 bytes"))
}

fn verify(public_key: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(msg, sig)
        .map_err(|_| Error::msg("pairing: bad signature"))
}

/// Our X25519 public key and the shared secret with `peer`.
fn x25519(peer: &[u8; 32]) -> Result<([u8; 32], Vec<u8>)> {
    let secret = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())
        .map_err(|_| Error::msg("X25519: no key"))?;
    let public = key32(
        secret
            .compute_public_key()
            .map_err(|_| Error::msg("X25519: no public key"))?
            .as_ref(),
    )?;
    let shared = agree_ephemeral(
        secret,
        &ring::agreement::UnparsedPublicKey::new(&X25519, peer),
        |k| k.to_vec(),
    )
    .map_err(|_| Error::msg("pair-verify: X25519 agreement failed"))?;
    Ok((public, shared))
}

fn hkdf(key: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    struct Len;
    impl ring::hkdf::KeyType for Len {
        fn len(&self) -> usize {
            32
        }
    }
    let mut out = [0; 32];
    ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA512, salt)
        .extract(key)
        .expand(&[info], Len)
        .and_then(|okm| okm.fill(&mut out))
        .unwrap();
    out
}

fn cipher(key: &[u8], salt: &[u8], info: &[u8]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &hkdf(key, salt, info)).unwrap())
}

/// Pairing messages' nonces: four zero bytes, then an 8-byte label like `PS-Msg05`.
fn label(l: &[u8; 8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(l);
    n
}

/// The session's nonces: a little-endian message counter, then four zero bytes.
fn counter(c: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&c.to_le_bytes());
    n
}

fn seal(c: &LessSafeKey, nonce: [u8; 12], plain: &[u8]) -> Vec<u8> {
    let mut buf = plain.to_vec();
    c.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
        .unwrap();
    buf
}

fn open(c: &LessSafeKey, nonce: [u8; 12], sealed: &[u8]) -> Result<Vec<u8>> {
    let mut buf = sealed.to_vec();
    let n = c
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
        .map_err(|_| Error::msg("pairing: a message failed to decrypt"))?
        .len();
    buf.truncate(n);
    Ok(buf)
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    SystemRandom::new().fill(&mut b).unwrap();
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // fixed inputs, outputs from the SRP implementation that pairs with Apple's devices
    #[test]
    fn srp_matches_reference_vectors() {
        let salt = [0x11; 16];
        let a = BigUint::from_bytes_be(&[0x22; 32]);
        let b = BigUint::from_bytes_be(&[0x33; 32]);
        let v = srp_verifier(&salt);
        let b_pub = srp_b_pub(&v, &b);
        assert_eq!(
            hex(&b_pub.to_bytes_be()[..16]),
            "b5c74efe59f0fe0230c25f24c9d56b7b"
        );
        let a_pub = srp_g().modpow(&a, &srp_n());
        let u = srp_u(&a_pub, &b_pub);
        let s = (&a_pub * v.modpow(&u, &srp_n()) % srp_n()).modpow(&b, &srp_n());
        let (key, m1, m2) = srp_proofs(&salt, &a_pub, &b_pub, &s);
        assert_eq!(
            hex(&m1),
            "8f196e63bcdd33113a3c027e448e52fbc4a4d3d87a62db3113f438d1fb551e0a32cf2100db0cf542f0a15aef3d6fa93b00b59641182549b404ee5d37c1bc7ed2"
        );
        assert_eq!(
            hex(&m2),
            "50d526ecda429c9da9e836cb5d474cf97bdec8e1568cfa97ae9954bc15b0465ffb5040ac3761b0771fe28138f29f2fdba79ceffde5d1c9dd2e6e31088aa8b913"
        );
        assert_eq!(
            hex(&key),
            "2653913e787af5c3d524c1da982c8e457ad069d2e38d2ee0fe653e8fc687c68c01bb73653588bef95bfc24a56c09f9d8fadba4af618fad9bdf5f48e5b4f2492b"
        );
    }

    #[test]
    fn pair_setup_then_verify_then_session() {
        let device = || Identity::new("DEVICE", &[1; 32]).unwrap();
        let host = || Identity::new("host", &[2; 32]).unwrap();
        let (dev_pk, host_pk) = (device().public_key(), host().public_key());
        let mut info = plist::Dictionary::new();
        info.insert("name".into(), "iPhone".into());

        let mut r = SetupResponder::new(device(), &info).unwrap();
        let mut c = SetupClient::new(host(), &info).unwrap();
        let m2 = r.handle(&c.start()).unwrap();
        let m4 = r.handle(&c.handle(&m2).unwrap().unwrap()).unwrap();
        let m6 = r.handle(&c.handle(&m4).unwrap().unwrap()).unwrap();
        assert!(c.handle(&m6).unwrap().is_none());
        let (on_device, on_host) = (r.paired().unwrap(), c.paired().unwrap());
        assert_eq!(
            (on_device.identifier.as_str(), on_device.public_key),
            ("host", host_pk)
        );
        assert_eq!(
            (on_host.identifier.as_str(), on_host.public_key),
            ("DEVICE", dev_pk)
        );
        assert_eq!(on_device.session_key, on_host.session_key);

        let knows = |id: &str, pk| (id == "host" || id == "DEVICE").then_some(pk);
        let mut vr = VerifyResponder::new(device());
        let mut vc = VerifyClient::new(host());
        let v2 = vr
            .handle(&vc.start().unwrap(), |id| knows(id, host_pk))
            .unwrap();
        let v3 = vc.handle(&v2, |id| knows(id, dev_pk)).unwrap().unwrap();
        let v4 = vr.handle(&v3, |id| knows(id, host_pk)).unwrap();
        assert!(vc.handle(&v4, |id| knows(id, dev_pk)).unwrap().is_none());
        let key = &vr.verified().unwrap().session_key;
        assert_eq!(key, &vc.verified().unwrap().session_key);

        let (mut d, mut h) = (Session::device(key), Session::host(key));
        let sealed = h.seal(b"hello");
        assert_eq!(d.open(&sealed).unwrap(), b"hello");
        assert!(d.open(&sealed).is_err(), "a replay must not open");
        assert_eq!(h.open(&d.seal(b"back")).unwrap(), b"back");

        // a host the device does not know gets an error, which the host reports
        let mut vr = VerifyResponder::new(device());
        let mut vc = VerifyClient::new(host());
        let v2 = vr.handle(&vc.start().unwrap(), |_| None).unwrap();
        let v4 = vr.handle(
            &vc.handle(&v2, |id| knows(id, dev_pk)).unwrap().unwrap(),
            |_| None,
        );
        assert!(vc.handle(&v4.unwrap(), |id| knows(id, dev_pk)).is_err());
        assert!(vr.verified().is_none());

        // a known identifier signed with another key: the device refuses the host...
        let mut vr = VerifyResponder::new(device());
        let mut vc = VerifyClient::new(Identity::new("host", &[3; 32]).unwrap());
        let v2 = vr
            .handle(&vc.start().unwrap(), |id| knows(id, host_pk))
            .unwrap();
        let v3 = vc.handle(&v2, |id| knows(id, dev_pk)).unwrap().unwrap();
        assert!(vr.handle(&v3, |id| knows(id, host_pk)).is_err());
        assert!(vr.verified().is_none());
        // ...and the host refuses the device, also when it does not know it at all
        let mut vr = VerifyResponder::new(Identity::new("DEVICE", &[4; 32]).unwrap());
        let mut vc = VerifyClient::new(host());
        let v2 = vr
            .handle(&vc.start().unwrap(), |id| knows(id, host_pk))
            .unwrap();
        assert!(vc.handle(&v2, |id| knows(id, dev_pk)).is_err());
        let mut vc = VerifyClient::new(host());
        let v2 = VerifyResponder::new(device())
            .handle(&vc.start().unwrap(), |id| knows(id, host_pk))
            .unwrap();
        assert!(vc.handle(&v2, |_| None).is_err());

        // a wrong proof from the device ends pair-setup on the host
        let mut r = SetupResponder::new(device(), &info).unwrap();
        let mut c = SetupClient::new(host(), &info).unwrap();
        let m2 = r.handle(&c.start()).unwrap();
        let mut m4 = r.handle(&c.handle(&m2).unwrap().unwrap()).unwrap();
        *m4.last_mut().unwrap() ^= 1;
        assert!(c.handle(&m4).is_err());
        assert!(c.paired().is_none());

        // a wrong SRP proof ends pair-setup with an error
        let mut r = SetupResponder::new(device(), &info).unwrap();
        let mut c = SetupClient::new(host(), &info).unwrap();
        let m2 = r.handle(&c.start()).unwrap();
        let mut m3 = c.handle(&m2).unwrap().unwrap();
        *m3.last_mut().unwrap() ^= 1;
        assert!(c.handle(&r.handle(&m3).unwrap()).is_err());
        assert!(r.paired().is_none());
    }

    // SipHash-2-4 paper's test value: key 00..0f, message 00..0e, 0xa129ca6149be45e5
    #[test]
    fn auth_tag_is_siphash() {
        let key: [u8; 16] = std::array::from_fn(|i| i as u8);
        let msg: String = (0u8..15).map(char::from).collect();
        assert_eq!(auth_tag(&key, &msg), [0xca, 0x61, 0x49, 0xbe, 0x45, 0xe5]);
    }

    // what an unauthenticated host may send: nothing, messages out of order, A = N, a zero key
    #[test]
    fn responders_refuse_bad_input() {
        let device = || Identity::new("DEVICE", &[1; 32]).unwrap();
        let setup = || SetupResponder::new(device(), &plist::Dictionary::new()).unwrap();
        assert!(setup().handle(&[]).is_err());
        assert!(setup().handle(&tlv::encode(&[(tlv::STATE, &[3])])).is_err());
        let mut r = setup();
        r.handle(&tlv::encode(&[(tlv::STATE, &[1])])).unwrap();
        let n = srp_n().to_bytes_be();
        let m3 = tlv::encode(&[
            (tlv::STATE, &[3]),
            (tlv::PUBLIC_KEY, &n),
            (tlv::PROOF, &[0; 64]),
        ]);
        assert!(r.handle(&m3).is_err());
        assert!(r.paired().is_none());

        let m3 = tlv::encode(&[(tlv::STATE, &[3])]);
        assert!(
            VerifyResponder::new(device())
                .handle(&m3, |_| None)
                .is_err()
        );
        let m1 = tlv::encode(&[(tlv::STATE, &[1]), (tlv::PUBLIC_KEY, &[0; 32])]);
        assert!(
            VerifyResponder::new(device())
                .handle(&m1, |_| None)
                .is_err()
        );
        assert!(Identity::new("", &[1; 32]).is_err());
    }

    #[test]
    fn opack_and_frames() {
        let mut d = plist::Dictionary::new();
        d.insert("a".into(), "b".into());
        d.insert("d".into(), plist::Value::Data(vec![1, 2]));
        d.insert("t".into(), true.into());
        let got = opack(&plist::Value::Dictionary(d)).unwrap();
        assert_eq!(
            got,
            [
                0xe3, 0x41, b'a', 0x41, b'b', 0x41, b'd', 0x72, 1, 2, 0x41, b't', 1
            ]
        );
        assert!(opack(&plist::Value::Real(1.5)).is_err());

        let v = json!({"message": {"plain": {"_0": {}}}});
        assert_eq!(read_rppairing(&mut &rppairing_frame(&v)[..]).unwrap(), v);
        assert!(read_rppairing(&mut &b"RPPairinx\x00\x00"[..]).is_err());
        assert_eq!(
            tlv::get(&tlv::encode(&[(5, &[7; 300])]), 5).unwrap(),
            [7; 300]
        );
        assert!(tlv::get(&[5, 9, 1], 5).is_err());
    }
}
