//! Профиль ClientHello браузера (данные) и построитель ClientHello по профилю.
//!
//! Профиль - текстовый файл (`hello-profiles/*.txt`, вшит через `include_str!`, можно подгрузить свой из строки):
//! ```text
//! name chrome155 | record_version 0301 | legacy_version 0303 | session_id_len 32 | compression 00 | shuffle 1
//! ciphers G:cipher 1301 1302 ...            # G:<слот> - значение GREASE (новое на каждое хелло; слот одинаков внутри хелло)
//! ext <id (десятичный)|G:слот> <first|any|last> <вид> [аргументы]
//!   raw [hex]  sni  groups|sigalgs|versions <токены>  keyshare <G:слот|mlkem768x25519|x25519>...  ech <длины полезной нагрузки>
//! ```
//! Слоты GREASE: cipher, group (одинаков в supported_groups и key_share), ext1, ext2 (отличается от ext1), version, sigalg.
use std::collections::HashMap;

use ml_kem::{DecapsulationKey, MlKem768};
use x25519_dalek::StaticSecret;

use crate::error::{Error, Result};
use crate::kx::{self, GROUP_HYBRID, GROUP_X25519};
use crate::util::{self, put_u16, put_u24, put_vec16, put_vec8};

pub const CHROME155: &str = include_str!("../hello-profiles/chrome155.txt");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Slot {
    Cipher,
    Group,
    Ext1,
    Ext2,
    Version,
    SigAlg,
}

#[derive(Clone, Debug)]
pub enum Tok {
    Grease(Slot),
    Val(u16),
}

#[derive(Clone, Debug)]
pub enum KsEntry {
    Grease(Slot),
    MlKem768X25519,
    X25519,
}

#[derive(Clone, Debug)]
pub enum Body {
    Raw(Vec<u8>),
    Sni,
    Groups(Vec<Tok>),
    SigAlgs(Vec<Tok>),
    Versions(Vec<Tok>),
    KeyShare(Vec<KsEntry>),
    Ech(Vec<usize>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pos {
    First,
    Any,
    Last,
}

#[derive(Clone, Debug)]
pub struct ExtSpec {
    pub id: Tok,
    pub pos: Pos,
    pub body: Body,
}

#[derive(Clone, Debug)]
pub struct Profile {
    pub name: String,
    pub record_version: u16,
    pub legacy_version: u16,
    pub session_id_len: usize,
    pub compression: Vec<u8>,
    pub shuffle: bool,
    pub ciphers: Vec<Tok>,
    pub exts: Vec<ExtSpec>,
}

fn slot(s: &str) -> Result<Slot> {
    Ok(match s {
        "cipher" => Slot::Cipher,
        "group" => Slot::Group,
        "ext1" => Slot::Ext1,
        "ext2" => Slot::Ext2,
        "version" => Slot::Version,
        "sigalg" => Slot::SigAlg,
        _ => return Err(Error::Config(format!("profile: unknown GREASE slot {s}"))),
    })
}

fn tok(s: &str) -> Result<Tok> {
    if let Some(g) = s.strip_prefix("G:") {
        return Ok(Tok::Grease(slot(g)?));
    }
    u16::from_str_radix(s, 16).map(Tok::Val).map_err(|_| Error::Config(format!("profile: bad token {s}")))
}

impl Profile {
    pub fn chrome155() -> Profile {
        Profile::parse(CHROME155).expect("встроенный профиль chrome155 корректен")
    }

    pub fn parse(text: &str) -> Result<Profile> {
        let mut p = Profile {
            name: String::new(),
            record_version: 0x0301,
            legacy_version: 0x0303,
            session_id_len: 32,
            compression: vec![0],
            shuffle: true,
            ciphers: vec![],
            exts: vec![],
        };
        let bad = |l: &str| Error::Config(format!("profile: bad line `{l}`"));
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let t: Vec<&str> = line.split_whitespace().collect();
            match t[0] {
                "name" => p.name = t.get(1).ok_or_else(|| bad(line))?.to_string(),
                "record_version" => p.record_version = u16::from_str_radix(t.get(1).ok_or_else(|| bad(line))?, 16).map_err(|_| bad(line))?,
                "legacy_version" => p.legacy_version = u16::from_str_radix(t.get(1).ok_or_else(|| bad(line))?, 16).map_err(|_| bad(line))?,
                "session_id_len" => p.session_id_len = t.get(1).ok_or_else(|| bad(line))?.parse().map_err(|_| bad(line))?,
                "compression" => p.compression = util::unhex(t.get(1).ok_or_else(|| bad(line))?).ok_or_else(|| bad(line))?,
                "shuffle" => p.shuffle = t.get(1) == Some(&"1"),
                "ciphers" => p.ciphers = t[1..].iter().map(|s| tok(s)).collect::<Result<_>>()?,
                "ext" => {
                    if t.len() < 4 {
                        return Err(bad(line));
                    }
                    // id расширения - десятичное число (как в IANA) или G:слот
                    let id = match t[1].strip_prefix("G:") {
                        Some(g) => Tok::Grease(slot(g)?),
                        None => Tok::Val(t[1].parse().map_err(|_| bad(line))?),
                    };
                    let pos = match t[2] {
                        "first" => Pos::First,
                        "any" => Pos::Any,
                        "last" => Pos::Last,
                        _ => return Err(bad(line)),
                    };
                    let args = &t[4..];
                    let body = match t[3] {
                        "raw" => Body::Raw(if args.is_empty() { vec![] } else { util::unhex(args[0]).ok_or_else(|| bad(line))? }),
                        "sni" => Body::Sni,
                        "groups" => Body::Groups(args.iter().map(|s| tok(s)).collect::<Result<_>>()?),
                        "sigalgs" => Body::SigAlgs(args.iter().map(|s| tok(s)).collect::<Result<_>>()?),
                        "versions" => Body::Versions(args.iter().map(|s| tok(s)).collect::<Result<_>>()?),
                        "keyshare" => Body::KeyShare(
                            args.iter()
                                .map(|s| {
                                    Ok(match *s {
                                        "mlkem768x25519" => KsEntry::MlKem768X25519,
                                        "x25519" => KsEntry::X25519,
                                        g if g.starts_with("G:") => KsEntry::Grease(slot(&g[2..])?),
                                        _ => return Err(bad(line)),
                                    })
                                })
                                .collect::<Result<_>>()?,
                        ),
                        "ech" => Body::Ech(args.iter().map(|s| s.parse().map_err(|_| bad(line))).collect::<Result<_>>()?),
                        _ => return Err(bad(line)),
                    };
                    p.exts.push(ExtSpec { id, pos, body });
                }
                _ => return Err(bad(line)),
            }
        }
        if p.ciphers.is_empty() || p.exts.is_empty() || p.session_id_len != 32 {
            return Err(Error::Config("profile: нужны ciphers, ext и session_id_len 32".into()));
        }
        Ok(p)
    }
}

/// Ключи клиента, созданные вместе с ClientHello.
pub struct ClientKeys {
    /// отдельная доля x25519 (0x001d); именно её ключ участвует в аутентификации
    pub x25519: StaticSecret,
    pub x25519_pub: [u8; 32],
    /// x25519-часть гибридной доли
    pub hybrid_x: StaticSecret,
    pub mlkem: DecapsulationKey<MlKem768>,
}

/// ClientHello с нулевым session_id (для AAD токена); `with_sid` подставляет настоящий.
pub struct HelloDraft {
    pub msg: Vec<u8>,
    pub sid_off: usize,
    pub random: [u8; 32],
    pub keys: ClientKeys,
    pub record_version: u16,
}

impl HelloDraft {
    pub fn with_sid(&self, sid: &[u8; 32]) -> Vec<u8> {
        let mut m = self.msg.clone();
        m[self.sid_off..self.sid_off + 32].copy_from_slice(sid);
        m
    }
    /// Полная TLS-запись с рукопожатием.
    pub fn record(&self, msg: &[u8]) -> Vec<u8> {
        let mut r = Vec::with_capacity(5 + msg.len());
        r.push(22);
        put_u16(&mut r, self.record_version);
        put_vec16(&mut r, msg);
        r
    }
}

fn grease_val() -> u16 {
    let n = (util::below(16) as u16) << 4 | 0x0a;
    n << 8 | n
}

pub fn build_hello(p: &Profile, sni: &str) -> HelloDraft {
    let mut gs: HashMap<Slot, u16> = HashMap::new();
    for s in [Slot::Cipher, Slot::Group, Slot::Ext1, Slot::Ext2, Slot::Version, Slot::SigAlg] {
        gs.insert(s, grease_val());
    }
    if gs[&Slot::Ext1] == gs[&Slot::Ext2] {
        let v = gs[&Slot::Ext2] ^ 0x1010;
        gs.insert(Slot::Ext2, v);
    }
    let val = |t: &Tok| match t {
        Tok::Val(v) => *v,
        Tok::Grease(s) => gs[s],
    };

    let x = kx::x25519_pair();
    let hx = kx::x25519_pair();
    let mk = kx::mlkem_pair();
    let random: [u8; 32] = util::random();

    let mut exts: Vec<(u16, Vec<u8>, Pos)> = Vec::new();
    for e in &p.exts {
        let mut d = Vec::new();
        match &e.body {
            Body::Raw(r) => d.extend_from_slice(r),
            Body::Sni => {
                let mut l = vec![0u8];
                put_vec16(&mut l, sni.as_bytes());
                put_vec16(&mut d, &l);
            }
            Body::Groups(g) | Body::SigAlgs(g) => {
                let mut l = Vec::new();
                g.iter().for_each(|t| put_u16(&mut l, val(t)));
                put_vec16(&mut d, &l);
            }
            Body::Versions(g) => {
                let mut l = Vec::new();
                g.iter().for_each(|t| put_u16(&mut l, val(t)));
                put_vec8(&mut d, &l);
            }
            Body::KeyShare(k) => {
                let mut l = Vec::new();
                for ent in k {
                    match ent {
                        KsEntry::Grease(s) => {
                            put_u16(&mut l, gs[s]);
                            put_vec16(&mut l, &[0]);
                        }
                        KsEntry::MlKem768X25519 => {
                            put_u16(&mut l, GROUP_HYBRID);
                            let mut v = mk.ek.clone();
                            v.extend_from_slice(&hx.public);
                            put_vec16(&mut l, &v);
                        }
                        KsEntry::X25519 => {
                            put_u16(&mut l, GROUP_X25519);
                            put_vec16(&mut l, &x.public);
                        }
                    }
                }
                put_vec16(&mut d, &l);
            }
            Body::Ech(lens) => {
                // ECH GREASE: outer(0), HKDF-SHA256 (1), AES-128-GCM (1), случайный config_id, enc 32 Б, payload
                let n = lens[util::below(lens.len() as u32) as usize];
                d.push(0);
                put_u16(&mut d, 1);
                put_u16(&mut d, 1);
                d.push(util::random::<1>()[0]);
                put_vec16(&mut d, &util::random::<32>());
                let mut pl = vec![0u8; n];
                util::fill(&mut pl);
                put_vec16(&mut d, &pl);
            }
        }
        exts.push((val(&e.id), d, e.pos));
    }
    // Chrome >= 110: первое/последнее фиксированы, остальные в случайном порядке
    let mut mid: Vec<(u16, Vec<u8>, Pos)> = exts.iter().filter(|e| e.2 == Pos::Any).cloned().collect();
    if p.shuffle {
        util::shuffle(&mut mid);
    }
    let mut order = Vec::new();
    order.extend(exts.iter().filter(|e| e.2 == Pos::First).cloned());
    order.extend(mid);
    order.extend(exts.iter().filter(|e| e.2 == Pos::Last).cloned());
    let mut ext_bytes = Vec::new();
    for (id, d, _) in &order {
        put_u16(&mut ext_bytes, *id);
        put_vec16(&mut ext_bytes, d);
    }

    let mut b = Vec::new();
    put_u16(&mut b, p.legacy_version);
    b.extend_from_slice(&random);
    b.push(32);
    let sid_in_body = b.len();
    b.extend_from_slice(&[0u8; 32]);
    let mut cs = Vec::new();
    p.ciphers.iter().for_each(|t| put_u16(&mut cs, val(t)));
    put_vec16(&mut b, &cs);
    put_vec8(&mut b, &p.compression);
    put_vec16(&mut b, &ext_bytes);

    let mut msg = vec![1u8];
    put_u24(&mut msg, b.len());
    msg.extend_from_slice(&b);
    HelloDraft {
        sid_off: 4 + sid_in_body,
        msg,
        random,
        record_version: p.record_version,
        keys: ClientKeys { x25519: x.secret, x25519_pub: x.public, hybrid_x: hx.secret, mlkem: mk.dk },
    }
}
