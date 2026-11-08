//! Доказательство смены однохопового mesh-транзита для уже установленного QUIC.
//! Ключ не передаётся по сети: TLS exporter привязывает MAC к конкретной сессии.
use super::{id_of, Key, TAG};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
pub(super) const LABEL: &[u8] = b"EXPORTER-knothop-mesh-migrate-v1";
const DOMAIN: &[u8] = b"knothop-mesh-migrate-v1";
pub(super) const KIND: u8 = 1;
pub(super) const LEN: usize = 3 + 8 + 8 + 8 + 8 + 32;

/// Счётчик получателя принадлежит одному TLS-сеансу. Обновляется только
/// после проверки MAC; повтор и переставленная старая команда не меняют путь.
#[derive(Default)]
pub(super) struct ReplayGuard(u64);

impl ReplayGuard {
    pub(super) fn accept(&mut self, key: &[u8; 32], src: &Key, dst: &Key, via: &Key, proof: &[u8]) -> bool {
        let Some(seq) = verify(key, src, dst, via, proof) else { return false };
        if seq <= self.0 { return false; }
        self.0 = seq;
        true
    }
}

fn mac(key: &[u8; 32], src: &Key, dst: &Key, via: &Key, seq: u64) -> HmacSha256 {
    let mut h = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    h.update(DOMAIN);
    h.update(src);
    h.update(dst);
    h.update(via);
    h.update(&seq.to_be_bytes());
    h
}

/// `via` включён в MAC полным ключом: скопировавший пакет сосед не может
/// перенаправить обратный маршрут на себя. Уведомление не несёт ключ сессии.
pub(super) fn encode(key: &[u8; 32], src: &Key, dst: &Key, via: &Key, seq: u64) -> Option<Vec<u8>> {
    if seq == 0 { return None; }
    let mut b = Vec::with_capacity(LEN);
    b.extend_from_slice(&[TAG, 0, KIND]);
    b.extend_from_slice(&id_of(dst));
    b.extend_from_slice(&id_of(src));
    b.extend_from_slice(&id_of(via));
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&mac(key, src, dst, via, seq).finalize().into_bytes());
    Some(b)
}

pub(super) fn verify(key: &[u8; 32], src: &Key, dst: &Key, via: &Key, b: &[u8]) -> Option<u64> {
    if b.len() != LEN || b[..3] != [TAG, 0, KIND] || b[3..11] != id_of(dst) || b[11..19] != id_of(src) || b[19..27] != id_of(via) { return None; }
    let seq = u64::from_be_bytes(b[27..35].try_into().ok()?);
    if seq == 0 { return None; }
    mac(key, src, dst, via, seq).verify_slice(&b[35..]).ok()?;
    Some(seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_route_proof_binds_all_keys_and_session() {
        let (secret, src, dst, via) = ([1; 32], [2; 32], [3; 32], [4; 32]);
        let b = encode(&secret, &src, &dst, &via, 7).unwrap();
        assert_eq!(verify(&secret, &src, &dst, &via, &b), Some(7));
        assert_eq!(verify(&[9; 32], &src, &dst, &via, &b), None);
        assert_eq!(verify(&secret, &[9; 32], &dst, &via, &b), None);
        assert_eq!(verify(&secret, &src, &[9; 32], &via, &b), None);
        assert_eq!(verify(&secret, &src, &dst, &[9; 32], &b), None);
        let mut tampered = b.clone();
        tampered[34] ^= 1;
        assert_eq!(verify(&secret, &src, &dst, &via, &tampered), None);
        assert_eq!(verify(&secret, &src, &dst, &via, &b[..b.len()-1]), None);
        assert!(encode(&secret, &src, &dst, &via, 0).is_none());
    }

    #[test]
    fn truncated_identity_collision_and_reflection_do_not_validate() {
        let (secret, src, dst, via) = ([1; 32], [2; 32], [3; 32], [4; 32]);
        let proof = encode(&secret, &src, &dst, &via, 1).unwrap();
        // Маршрутный id содержит только первые восемь байтов. MAC обязан
        // связывать полный ключ, даже если id двух ключей совпадает.
        for which in 0..3 {
            let (mut s, mut d, mut v) = (src, dst, via);
            match which { 0 => s[31] ^= 1, 1 => d[31] ^= 1, _ => v[31] ^= 1 }
            assert_eq!(verify(&secret, &s, &d, &v, &proof), None);
        }
        assert_eq!(verify(&secret, &dst, &src, &via, &proof), None);
    }

    #[test]
    fn every_wire_byte_is_authenticated_or_checked() {
        let (secret, src, dst, via) = ([1; 32], [2; 32], [3; 32], [4; 32]);
        let proof = encode(&secret, &src, &dst, &via, 42).unwrap();
        for i in 0..proof.len() {
            let mut altered = proof.clone();
            altered[i] ^= 1;
            assert_eq!(verify(&secret, &src, &dst, &via, &altered), None, "byte {i}");
        }
        let mut extended = proof.clone();
        extended.push(0);
        assert_eq!(verify(&secret, &src, &dst, &via, &extended), None);
    }

    #[test]
    fn replay_guard_rejects_reordering_and_invalid_mac_without_advancing() {
        let (key, src, dst, via) = ([1; 32], [2; 32], [3; 32], [4; 32]);
        let mut guard = ReplayGuard::default();
        let one = encode(&key, &src, &dst, &via, 1).unwrap();
        let two = encode(&key, &src, &dst, &via, 2).unwrap();
        let mut forged = encode(&key, &src, &dst, &via, u64::MAX).unwrap();
        forged[LEN - 1] ^= 1;
        assert!(!guard.accept(&key, &src, &dst, &via, &forged));
        assert!(guard.accept(&key, &src, &dst, &via, &two));
        assert!(!guard.accept(&key, &src, &dst, &via, &two));
        assert!(!guard.accept(&key, &src, &dst, &via, &one));
        let three = encode(&key, &src, &dst, &via, 3).unwrap();
        assert!(guard.accept(&key, &src, &dst, &via, &three));
        // Доказательство старой сессии не должно расходовать счётчик новой.
        let new_key = [9; 32];
        let mut new_session = ReplayGuard::default();
        assert!(!new_session.accept(&new_key, &src, &dst, &via, &three));
        let new_one = encode(&new_key, &src, &dst, &via, 1).unwrap();
        assert!(new_session.accept(&new_key, &src, &dst, &via, &new_one));
    }
}
