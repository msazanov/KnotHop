//! Аутентификация клиента в session_id ClientHello и подтверждение сервера по HMAC «сертификата».
//!
//! auth_key = HKDF-SHA256(ECDH(эфемерный x25519 клиента из key_share, статический x25519 сервера), salt = random[..20], info = LABEL).
//! session_id (32 Б) = ChaCha20-Poly1305(auth_key, nonce = random[20..32], AAD = ClientHello с обнулённым session_id,
//!                      открытый текст 16 Б = версия | флаги | время u32 | short_id 8 Б | резерв 2 Б), то есть 16 Б шифртекста + 16 Б тега.
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ring::aead;

use crate::tls13::{hkdf_expand, hkdf_extract, TLS_AES_128_GCM_SHA256};
use crate::util::ct_eq;

pub const LABEL: &[u8] = b"knothop-reality/1 auth";
pub const TOKEN_VERSION: u8 = 1;
/// смещение session_id внутри сообщения ClientHello: заголовок 4 + версия 2 + random 32 + длина 1
pub const SID_OFF: usize = 39;

pub type ShortId = [u8; 8];

pub fn derive_auth_key(shared: &[u8; 32], random: &[u8]) -> [u8; 32] {
    let s = TLS_AES_128_GCM_SHA256; // нужен только HKDF-SHA256
    let prk = hkdf_extract(&s, &random[..20], shared);
    let k = hkdf_expand(&s, &prk, LABEL, 32);
    k.try_into().expect("32")
}

fn key(auth_key: &[u8; 32]) -> aead::LessSafeKey {
    aead::LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, auth_key).expect("ключ 32 Б"))
}

/// `msg` - ClientHello с обнулённым session_id.
pub fn seal_token(auth_key: &[u8; 32], random: &[u8], msg_zero_sid: &[u8], short_id: ShortId, now_unix: u64) -> [u8; 32] {
    let mut pt = Vec::with_capacity(32);
    pt.push(TOKEN_VERSION);
    pt.push(0);
    pt.extend_from_slice(&(now_unix as u32).to_be_bytes());
    pt.extend_from_slice(&short_id);
    pt.extend_from_slice(&[0, 0]);
    let nonce = aead::Nonce::try_assume_unique_for_key(&random[20..32]).expect("nonce 12 Б");
    key(auth_key).seal_in_place_append_tag(nonce, aead::Aad::from(msg_zero_sid), &mut pt).expect("seal");
    pt.try_into().expect("32")
}

#[derive(Debug, PartialEq, Eq)]
pub struct Token {
    pub version: u8,
    pub time: u32,
    pub short_id: ShortId,
}

pub fn open_token(auth_key: &[u8; 32], random: &[u8], msg_zero_sid: &[u8], sid: &[u8]) -> Option<Token> {
    if sid.len() != 32 || random.len() != 32 {
        return None;
    }
    let mut b = sid.to_vec();
    let nonce = aead::Nonce::try_assume_unique_for_key(&random[20..32]).ok()?;
    let pt = key(auth_key).open_in_place(nonce, aead::Aad::from(msg_zero_sid), &mut b).ok()?;
    if pt.len() != 16 || pt[0] != TOKEN_VERSION || pt[14] != 0 || pt[15] != 0 {
        return None;
    }
    Some(Token { version: pt[0], time: u32::from_be_bytes([pt[2], pt[3], pt[4], pt[5]]), short_id: pt[6..14].try_into().ok()? })
}

/// Окно времени: |now - t| <= skew (с учётом перехода u32).
pub fn time_ok(token_time: u32, now_unix: u64, skew_secs: u64) -> bool {
    let n = now_unix as u32;
    let d = n.wrapping_sub(token_time) as i32;
    (d.unsigned_abs() as u64) <= skew_secs
}

/// short_id разрешён? Без раннего выхода по номеру записи.
pub fn short_id_allowed(list: &[ShortId], id: &ShortId) -> bool {
    let mut ok = false;
    for s in list {
        ok |= ct_eq(s, id);
    }
    ok
}

/// HMAC-SHA512(auth_key, открытый ключ временного сертификата): «подпись» сертификата, как в REALITY.
pub fn cert_mac(auth_key: &[u8; 32], ed_pub: &[u8; 32]) -> [u8; 64] {
    let m = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA512, auth_key), ed_pub);
    m.as_ref().try_into().expect("64")
}

/// Кэш повторов: ограничен по числу записей и времени жизни; вносятся только токены, прошедшие AEAD.
pub struct ReplayCache {
    inner: Mutex<RcInner>,
    ttl: Duration,
    cap: usize,
}

struct RcInner {
    map: HashMap<[u8; 32], Instant>,
    order: VecDeque<([u8; 32], Instant)>,
    evicted_early: u64,
}

impl ReplayCache {
    pub fn new(cap: usize, ttl: Duration) -> Self {
        ReplayCache { inner: Mutex::new(RcInner { map: HashMap::new(), order: VecDeque::new(), evicted_early: 0 }), ttl, cap: cap.max(1) }
    }
    /// true - ключ свежий (запомнен); false - повтор.
    pub fn insert(&self, sid: &[u8; 32], now: Instant) -> bool {
        let mut g = self.inner.lock().unwrap();
        while let Some((k, t)) = g.order.front().copied() {
            if now.duration_since(t) > self.ttl {
                g.order.pop_front();
                g.map.remove(&k);
            } else {
                break;
            }
        }
        if g.map.contains_key(sid) {
            return false;
        }
        if g.map.len() >= self.cap {
            if let Some((k, _)) = g.order.pop_front() {
                g.map.remove(&k);
                g.evicted_early += 1;
            }
        }
        g.map.insert(*sid, now);
        g.order.push_back((*sid, now));
        true
    }
    /// сколько записей вытеснено раньше срока (в это время повтор прошёл бы)
    pub fn evicted_early(&self) -> u64 {
        self.inner.lock().unwrap().evicted_early
    }
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
