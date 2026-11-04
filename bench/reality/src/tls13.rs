//! Минимальный TLS 1.3 (RFC 8446): наборы шифров, график ключей, защита записей, сообщения рукопожатия.
//! Только то, что нужно обоим концам нашего протокола и пробе cover; без PSK/0-RTT/HRR/клиентских сертификатов.
use ring::{aead, digest, hmac};

use crate::error::{Error, Result};
use crate::util::{put_u24, Rd};

pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
pub const HS_NEW_SESSION_TICKET: u8 = 4;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_FINISHED: u8 = 20;
pub const HS_KEY_UPDATE: u8 = 24;

pub const CT_CCS: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPDATA: u8 = 23;

/// Максимум открытого текста записи TLS 1.3 вместе с типом и набивкой (RFC 8446 5.4: 2^14 + 1 для внутреннего содержимого).
pub const MAX_INNER: usize = 16384 + 1;
pub const MAX_CIPHERTEXT: usize = 16384 + 256;

pub const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2,
    0xC8, 0xA8, 0x33, 0x9C,
];

#[derive(Clone, Copy)]
pub struct Suite {
    pub id: u16,
    hash: &'static digest::Algorithm,
    hmac: hmac::Algorithm,
    aead: &'static aead::Algorithm,
}

impl std::fmt::Debug for Suite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Suite({:04x})", self.id)
    }
}

pub const TLS_AES_128_GCM_SHA256: Suite = Suite { id: 0x1301, hash: &digest::SHA256, hmac: hmac::HMAC_SHA256, aead: &aead::AES_128_GCM };
pub const TLS_AES_256_GCM_SHA384: Suite = Suite { id: 0x1302, hash: &digest::SHA384, hmac: hmac::HMAC_SHA384, aead: &aead::AES_256_GCM };
pub const TLS_CHACHA20_POLY1305_SHA256: Suite = Suite { id: 0x1303, hash: &digest::SHA256, hmac: hmac::HMAC_SHA256, aead: &aead::CHACHA20_POLY1305 };

pub fn suite_by_id(id: u16) -> Option<Suite> {
    [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256].into_iter().find(|s| s.id == id)
}

impl Suite {
    pub fn hash_len(&self) -> usize {
        self.hash.output_len()
    }
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        digest::digest(self.hash, data).as_ref().to_vec()
    }
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        hmac::sign(&hmac::Key::new(self.hmac, key), data).as_ref().to_vec()
    }
}

pub fn hkdf_extract(s: &Suite, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    s.hmac(salt, ikm)
}

pub fn hkdf_expand(s: &Suite, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let key = hmac::Key::new(s.hmac, prk);
    let mut out = Vec::with_capacity(len + 64);
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&t);
        ctx.update(info);
        ctx.update(&[i]);
        t = ctx.sign().as_ref().to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(len);
    out
}

pub fn expand_label(s: &Suite, secret: &[u8], label: &str, ctx: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    let full = format!("tls13 {label}");
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(ctx.len() as u8);
    info.extend_from_slice(ctx);
    hkdf_expand(s, secret, &info, len)
}

pub fn derive_secret(s: &Suite, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    expand_label(s, secret, label, transcript_hash, s.hash_len())
}

/// Секреты рукопожатия и «вход» для главного секрета.
pub struct HsSecrets {
    pub master_input: Vec<u8>,
    pub client: Vec<u8>,
    pub server: Vec<u8>,
}

pub fn handshake_secrets(s: &Suite, ecdhe: &[u8], th_ch_sh: &[u8]) -> HsSecrets {
    let zeros = vec![0u8; s.hash_len()];
    let empty = s.hash(&[]);
    let early = hkdf_extract(s, &zeros, &zeros);
    let derived = derive_secret(s, &early, "derived", &empty);
    let hs = hkdf_extract(s, &derived, ecdhe);
    HsSecrets {
        client: derive_secret(s, &hs, "c hs traffic", th_ch_sh),
        server: derive_secret(s, &hs, "s hs traffic", th_ch_sh),
        master_input: derive_secret(s, &hs, "derived", &empty),
    }
}

/// (client_application_traffic_secret_0, server_application_traffic_secret_0)
pub fn app_secrets(s: &Suite, master_input: &[u8], th_to_server_fin: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let zeros = vec![0u8; s.hash_len()];
    let master = hkdf_extract(s, master_input, &zeros);
    (derive_secret(s, &master, "c ap traffic", th_to_server_fin), derive_secret(s, &master, "s ap traffic", th_to_server_fin))
}

pub fn finished_verify_data(s: &Suite, base_secret: &[u8], th: &[u8]) -> Vec<u8> {
    let fk = expand_label(s, base_secret, "finished", &[], s.hash_len());
    s.hmac(&fk, th)
}

pub fn cert_verify_input(th: &[u8]) -> Vec<u8> {
    let mut v = vec![0x20u8; 64];
    v.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    v.extend_from_slice(th);
    v
}

/// Односторонний шифр записей (ключ, IV, номер).
pub struct Cipher {
    suite: Suite,
    secret: Vec<u8>,
    key: aead::LessSafeKey,
    iv: [u8; 12],
    pub seq: u64,
}

impl Cipher {
    pub fn new(suite: Suite, secret: Vec<u8>) -> Cipher {
        let key = expand_label(&suite, &secret, "key", &[], suite.aead.key_len());
        let iv = expand_label(&suite, &secret, "iv", &[], 12);
        Cipher {
            key: aead::LessSafeKey::new(aead::UnboundKey::new(suite.aead, &key).expect("длина ключа")),
            iv: iv.try_into().expect("iv 12 байт"),
            suite,
            secret,
            seq: 0,
        }
    }

    fn nonce(&self) -> aead::Nonce {
        let mut n = self.iv;
        for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        aead::Nonce::assume_unique_for_key(n)
    }

    /// Запечатывает запись: `content | type | 0*pad`. Возвращает запись целиком с заголовком.
    pub fn seal(&mut self, typ: u8, content: &[u8], pad: usize) -> Vec<u8> {
        let inner_len = content.len() + 1 + pad;
        debug_assert!(inner_len <= MAX_INNER);
        let mut buf = Vec::with_capacity(5 + inner_len + 16);
        buf.extend_from_slice(&[CT_APPDATA, 3, 3]);
        buf.extend_from_slice(&((inner_len + 16) as u16).to_be_bytes());
        buf.extend_from_slice(content);
        buf.push(typ);
        buf.resize(5 + inner_len, 0);
        let aad = [buf[0], buf[1], buf[2], buf[3], buf[4]];
        let mut inner = buf.split_off(5);
        self.key.seal_in_place_append_tag(self.nonce(), aead::Aad::from(aad), &mut inner).expect("seal");
        self.seq += 1;
        buf.extend_from_slice(&inner);
        buf
    }

    /// Расшифровывает тело записи (шифртекст с тегом) на месте; возвращает (тип, содержимое).
    pub fn open<'a>(&mut self, header: [u8; 5], body: &'a mut [u8]) -> Result<(u8, &'a [u8])> {
        if body.len() < 17 || body.len() > MAX_CIPHERTEXT {
            return Err(Error::Protocol("bad record length"));
        }
        let n = self.nonce();
        let pt = self.key.open_in_place(n, aead::Aad::from(header), body).map_err(|_| Error::Protocol("bad record MAC"))?;
        self.seq += 1;
        let mut end = pt.len();
        while end > 0 && pt[end - 1] == 0 {
            end -= 1;
        }
        if end == 0 {
            return Err(Error::Protocol("record without content type"));
        }
        let typ = pt[end - 1];
        Ok((typ, &pt[..end - 1]))
    }

    /// Следующее поколение ключей (KeyUpdate, RFC 8446 7.2).
    pub fn rekey(&mut self) {
        let next = expand_label(&self.suite, &self.secret, "traffic upd", &[], self.suite.hash_len());
        *self = Cipher::new(self.suite, next);
    }
}

pub fn hs_msg(t: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.push(t);
    put_u24(&mut m, body.len());
    m.extend_from_slice(body);
    m
}

/// Накопитель сообщений рукопожатия из фрагментов записей.
#[derive(Default)]
pub struct HsBuf {
    buf: Vec<u8>,
}

pub const MAX_HS_MSG: usize = 1 << 17;

impl HsBuf {
    pub fn push(&mut self, d: &[u8]) {
        self.buf.extend_from_slice(d);
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    /// Следующее полное сообщение (с заголовком) или None; Err при чрезмерной длине.
    pub fn next(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let n = ((self.buf[1] as usize) << 16) | ((self.buf[2] as usize) << 8) | self.buf[3] as usize;
        if n > MAX_HS_MSG {
            return Err(Error::Protocol("handshake message too large"));
        }
        if self.buf.len() < 4 + n {
            return Ok(None);
        }
        let rest = self.buf.split_off(4 + n);
        Ok(Some(std::mem::replace(&mut self.buf, rest)))
    }
}

/// Разобранный ServerHello.
pub struct ServerHello<'a> {
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub suite: u16,
    pub exts: Vec<u16>,
    pub group: u16,
    pub key_exchange: &'a [u8],
    pub version: u16,
}

pub fn parse_server_hello(msg: &[u8]) -> Result<ServerHello<'_>> {
    let bad = || Error::Protocol("bad ServerHello");
    let mut r = Rd::new(msg);
    if r.u8().ok_or_else(bad)? != HS_SERVER_HELLO {
        return Err(bad());
    }
    let len = r.u24().ok_or_else(bad)?;
    if len != r.left() {
        return Err(bad());
    }
    r.u16().ok_or_else(bad)?;
    let random = r.bytes(32).ok_or_else(bad)?;
    let session_id = r.vec8().ok_or_else(bad)?;
    let suite = r.u16().ok_or_else(bad)?;
    if r.u8().ok_or_else(bad)? != 0 {
        return Err(bad());
    }
    let mut er = Rd::new(r.vec16().ok_or_else(bad)?);
    if r.left() != 0 {
        return Err(bad());
    }
    let (mut group, mut kex, mut version) = (0, &[][..], 0);
    let mut exts = vec![];
    while er.left() > 0 {
        let id = er.u16().ok_or_else(bad)?;
        let d = er.vec16().ok_or_else(bad)?;
        if exts.contains(&id) {
            return Err(bad());
        }
        exts.push(id);
        let mut dr = Rd::new(d);
        match id {
            43 => version = dr.u16().ok_or_else(bad)?,
            51 => {
                group = dr.u16().ok_or_else(bad)?;
                kex = dr.vec16().ok_or_else(bad)?;
            }
            _ => {}
        }
    }
    Ok(ServerHello { random, session_id, suite, exts, group, key_exchange: kex, version })
}

/// ALPN из EncryptedExtensions.
pub fn parse_ee_alpn(msg: &[u8]) -> Result<Option<Vec<u8>>> {
    let bad = || Error::Protocol("bad EncryptedExtensions");
    let mut r = Rd::new(msg);
    if r.u8().ok_or_else(bad)? != HS_ENCRYPTED_EXTENSIONS {
        return Err(bad());
    }
    let len = r.u24().ok_or_else(bad)?;
    if len != r.left() {
        return Err(bad());
    }
    let mut er = Rd::new(r.vec16().ok_or_else(bad)?);
    let mut alpn = None;
    while er.left() > 0 {
        let id = er.u16().ok_or_else(bad)?;
        let d = er.vec16().ok_or_else(bad)?;
        if id == 16 {
            let mut l = Rd::new(Rd::new(d).vec16().ok_or_else(bad)?);
            alpn = Some(l.vec8().ok_or_else(bad)?.to_vec());
        }
    }
    Ok(alpn)
}

/// Первый сертификат (DER) из сообщения Certificate.
pub fn parse_certificate(msg: &[u8]) -> Result<Vec<u8>> {
    let bad = || Error::Protocol("bad Certificate");
    let mut r = Rd::new(msg);
    if r.u8().ok_or_else(bad)? != HS_CERTIFICATE {
        return Err(bad());
    }
    let len = r.u24().ok_or_else(bad)?;
    if len != r.left() {
        return Err(bad());
    }
    r.vec8().ok_or_else(bad)?; // request context
    let n = r.u24().ok_or_else(bad)?;
    if n != r.left() {
        return Err(bad());
    }
    let cl = r.u24().ok_or_else(bad)?;
    let cert = r.bytes(cl).ok_or_else(bad)?.to_vec();
    if cert.is_empty() {
        return Err(bad());
    }
    Ok(cert)
}

pub fn parse_certificate_verify(msg: &[u8]) -> Result<(u16, Vec<u8>)> {
    let bad = || Error::Protocol("bad CertificateVerify");
    let mut r = Rd::new(msg);
    if r.u8().ok_or_else(bad)? != HS_CERTIFICATE_VERIFY {
        return Err(bad());
    }
    let len = r.u24().ok_or_else(bad)?;
    if len != r.left() {
        return Err(bad());
    }
    let alg = r.u16().ok_or_else(bad)?;
    let sig = r.vec16().ok_or_else(bad)?.to_vec();
    if r.left() != 0 {
        return Err(bad());
    }
    Ok((alg, sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        crate::util::unhex(s).unwrap()
    }

    /// RFC 8448 раздел 3 («Simple 1-RTT Handshake»): график ключей AES-128-GCM-SHA256, x25519.
    #[test]
    fn rfc8448_key_schedule() {
        let s = TLS_AES_128_GCM_SHA256;
        let ecdhe = h("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let th = h("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let hs = handshake_secrets(&s, &ecdhe, &th);
        assert_eq!(hs.client, h("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"));
        assert_eq!(hs.server, h("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"));
        let c = Cipher::new(s, hs.server.clone());
        assert_eq!(c.iv.to_vec(), h("5d313eb2671276ee13000b30"));
    }
}
