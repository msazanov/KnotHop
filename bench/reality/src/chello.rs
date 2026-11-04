//! Разбор ClientHello (сервер читает первую запись; тесты и JA4). Не паникует на любых входах.
use crate::kx::{GROUP_HYBRID, GROUP_X25519};
use crate::util::{is_grease, Rd};

/// Результат разбора первой записи соединения.
#[derive(Debug, PartialEq, Eq)]
pub enum Record {
    /// записи ещё не хватает: всего нужно столько байт
    NeedMore(usize),
    /// ClientHello целиком в одной записи: длина записи с заголовком
    Hello(usize),
    /// не похоже на ClientHello в одной записи
    NotHello,
}

pub const MAX_RECORD_BODY: usize = 16384;

/// Определяет по началу потока, есть ли целая запись с ClientHello. `max_len` - наш предел размера записи с заголовком.
pub fn check_record(buf: &[u8], max_len: usize) -> Record {
    if buf.len() >= 1 && buf[0] != 22 {
        return Record::NotHello;
    }
    if buf.len() >= 2 && buf[1] != 3 {
        return Record::NotHello;
    }
    if buf.len() < 9 {
        return Record::NeedMore(9);
    }
    if buf[5] != 1 {
        return Record::NotHello;
    }
    let rlen = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let hlen = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize;
    if rlen > MAX_RECORD_BODY || rlen < 4 + 34 || hlen + 4 != rlen || 5 + rlen > max_len {
        return Record::NotHello;
    }
    if buf.len() < 5 + rlen {
        return Record::NeedMore(5 + rlen);
    }
    Record::Hello(5 + rlen)
}

#[derive(Debug, Clone)]
pub struct Hello<'a> {
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub ciphers: Vec<u16>,
    pub exts: Vec<(u16, &'a [u8])>,
    pub sni: Option<String>,
    pub groups: Vec<u16>,
    pub versions: Vec<u16>,
    pub sigalgs: Vec<u16>,
    pub alpn: Vec<Vec<u8>>,
    /// доли key_share: (группа, данные)
    pub shares: Vec<(u16, &'a [u8])>,
}

impl<'a> Hello<'a> {
    pub fn ext(&self, id: u16) -> Option<&'a [u8]> {
        self.exts.iter().find(|e| e.0 == id).map(|e| e.1)
    }
    pub fn x25519_share(&self) -> Option<&'a [u8]> {
        self.shares.iter().find(|s| s.0 == GROUP_X25519 && s.1.len() == 32).map(|s| s.1)
    }
    pub fn hybrid_share(&self) -> Option<&'a [u8]> {
        self.shares.iter().find(|s| s.0 == GROUP_HYBRID && s.1.len() == crate::kx::MLKEM_EK_LEN + 32).map(|s| s.1)
    }
}

/// `msg` - сообщение рукопожатия целиком, с 4-байтным заголовком.
pub fn parse_hello(msg: &[u8]) -> Option<Hello<'_>> {
    let mut r = Rd::new(msg);
    if r.u8()? != 1 {
        return None;
    }
    let len = r.u24()?;
    if len != r.left() {
        return None;
    }
    r.u16()?; // legacy_version
    let random = r.bytes(32)?;
    let session_id = r.vec8()?;
    let cs = r.vec16()?;
    if cs.len() % 2 != 0 {
        return None;
    }
    let ciphers = cs.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    r.vec8()?; // compression
    let mut er = Rd::new(r.vec16()?);
    if r.left() != 0 {
        return None;
    }
    let mut h = Hello { random, session_id, ciphers, exts: vec![], sni: None, groups: vec![], versions: vec![], sigalgs: vec![], alpn: vec![], shares: vec![] };
    while er.left() > 0 {
        let id = er.u16()?;
        let d = er.vec16()?;
        if h.exts.iter().any(|e| e.0 == id) {
            return None; // повтор расширения запрещён
        }
        h.exts.push((id, d));
    }
    for &(id, d) in &h.exts.clone() {
        let mut dr = Rd::new(d);
        match id {
            0 => {
                let mut l = Rd::new(dr.vec16()?);
                while l.left() > 0 {
                    let t = l.u8()?;
                    let n = l.vec16()?;
                    if t == 0 && h.sni.is_none() {
                        h.sni = Some(String::from_utf8(n.to_vec()).ok()?);
                    }
                }
            }
            10 => h.groups = u16list(dr.vec16()?)?,
            13 => h.sigalgs = u16list(dr.vec16()?)?,
            43 => h.versions = u16list(dr.vec8()?)?,
            16 => {
                let mut l = Rd::new(dr.vec16()?);
                while l.left() > 0 {
                    h.alpn.push(l.vec8()?.to_vec());
                }
            }
            51 => {
                let mut l = Rd::new(dr.vec16()?);
                while l.left() > 0 {
                    let g = l.u16()?;
                    h.shares.push((g, l.vec16()?));
                }
            }
            _ => {}
        }
    }
    Some(h)
}

fn u16list(b: &[u8]) -> Option<Vec<u16>> {
    if b.len() % 2 != 0 {
        return None;
    }
    Some(b.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect())
}

/// JA4 (FoxIO) по разобранному ClientHello, TCP.
pub fn ja4(h: &Hello<'_>) -> String {
    let ciphers: Vec<u16> = h.ciphers.iter().copied().filter(|c| !is_grease(*c)).collect();
    let exts: Vec<u16> = h.exts.iter().map(|e| e.0).filter(|e| !is_grease(*e)).collect();
    let tls13 = h.versions.iter().any(|v| *v == 0x0304);
    let alpn = match h.alpn.first() {
        Some(a) if !a.is_empty() => format!("{}{}", a[0] as char, a[a.len() - 1] as char),
        _ => "00".into(),
    };
    let a = format!("t{}{}{:02}{:02}{}", if tls13 { "13" } else { "12" }, if h.sni.is_some() { 'd' } else { 'i' }, ciphers.len().min(99), exts.len().min(99), alpn);
    let mut sc = ciphers.clone();
    sc.sort_unstable();
    let b = sha12(&sc.iter().map(|c| format!("{c:04x}")).collect::<Vec<_>>().join(","));
    let mut se: Vec<u16> = exts.iter().copied().filter(|e| *e != 0 && *e != 16).collect();
    se.sort_unstable();
    let mut cs = se.iter().map(|c| format!("{c:04x}")).collect::<Vec<_>>().join(",");
    let sigs: Vec<u16> = h.sigalgs.iter().copied().filter(|s| !is_grease(*s)).collect();
    if !sigs.is_empty() {
        cs.push('_');
        cs.push_str(&sigs.iter().map(|c| format!("{c:04x}")).collect::<Vec<_>>().join(","));
    }
    format!("{a}_{b}_{}", sha12(&cs))
}

fn sha12(s: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, s.as_bytes());
    crate::util::hex(&d.as_ref()[..6])
}
