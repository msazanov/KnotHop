//! Обмен ключами: X25519 и ML-KEM-768 (гибрид X25519MLKEM768 = 0x11EC, порядок как в draft-ietf-tls-ecdhe-mlkem:
//! клиент `ek(1184) | x25519(32)`, сервер `ct(1088) | x25519(32)`, секрет `mlkem_ss(32) | x25519_ss(32)`).
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768, Seed, B32};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::util;

pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_HYBRID: u16 = 0x11ec;
pub const MLKEM_EK_LEN: usize = 1184;
pub const MLKEM_CT_LEN: usize = 1088;

pub struct X25519Pair {
    pub secret: StaticSecret,
    pub public: [u8; 32],
}

pub fn x25519_pair() -> X25519Pair {
    let secret = StaticSecret::from(util::random::<32>());
    let public = PublicKey::from(&secret).to_bytes();
    X25519Pair { secret, public }
}

pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// None, если точка малого порядка (общий секрет нулевой): такое отвергаем.
pub fn x25519_dh(sk: &StaticSecret, pk: &[u8]) -> Option<[u8; 32]> {
    let pk: [u8; 32] = pk.try_into().ok()?;
    let ss = sk.diffie_hellman(&PublicKey::from(pk));
    if !ss.was_contributory() {
        return None;
    }
    Some(ss.to_bytes())
}

pub struct MlKemPair {
    pub dk: DecapsulationKey<MlKem768>,
    pub ek: Vec<u8>,
}

pub fn mlkem_pair() -> MlKemPair {
    let mut seed = Seed::default();
    util::fill(seed.as_mut());
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    let ek = dk.encapsulation_key().to_bytes().to_vec();
    debug_assert_eq!(ek.len(), MLKEM_EK_LEN);
    MlKemPair { dk, ek }
}

/// Инкапсуляция к ключу клиента: (шифртекст, секрет). None при некорректном ключе (проверка по FIPS 203).
pub fn mlkem_encapsulate(ek: &[u8]) -> Option<(Vec<u8>, [u8; 32])> {
    if ek.len() != MLKEM_EK_LEN {
        return None;
    }
    let key = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(ek).ok()?;
    let ek = EncapsulationKey::<MlKem768>::new(&key).ok()?;
    let mut m = B32::default();
    util::fill(m.as_mut());
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    let mut s = [0u8; 32];
    s.copy_from_slice(ss.as_ref());
    let ct: &[u8] = ct.as_ref();
    Some((ct.to_vec(), s))
}

pub fn mlkem_decapsulate(dk: &DecapsulationKey<MlKem768>, ct: &[u8]) -> Option<[u8; 32]> {
    if ct.len() != MLKEM_CT_LEN {
        return None;
    }
    let ss = dk.decapsulate_slice(ct).ok()?;
    let mut s = [0u8; 32];
    s.copy_from_slice(ss.as_ref());
    Some(s)
}
