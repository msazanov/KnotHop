//! Токен: привязка к ClientHello (AAD) и ключу, пересадка отвергается, окно времени, кэш повторов, разбор без паник.
use std::time::{Duration, Instant};

use knothop_reality::auth::*;
use knothop_reality::chello::{self, parse_hello};
use knothop_reality::kx;
use knothop_reality::profile::{build_hello, Profile};
use knothop_reality::util;

struct Fixture {
    server_secret: [u8; 32],
    server_pub: [u8; 32],
}

fn fixture() -> Fixture {
    let s = util::random::<32>();
    Fixture { server_secret: s, server_pub: kx::x25519_public(&s) }
}

/// Клиентская сторона: (ClientHello с токеном, ClientHello с нулевым sid, session_id)
fn client_hello(f: &Fixture, sid: ShortId, now: u64) -> (Vec<u8>, Vec<u8>, [u8; 32], knothop_reality::profile::HelloDraft) {
    let d = build_hello(&Profile::chrome155(), "cover.example.org");
    let shared = kx::x25519_dh(&d.keys.x25519, &f.server_pub).unwrap();
    let ak = derive_auth_key(&shared, &d.random);
    let tok = seal_token(&ak, &d.random, &d.msg, sid, now);
    (d.with_sid(&tok), d.msg.clone(), tok, d)
}

/// Серверная сторона: проверка по сообщению хелло.
fn server_check(f: &Fixture, msg: &[u8]) -> Option<Token> {
    let h = parse_hello(msg)?;
    let share = h.x25519_share()?;
    let sk = x25519_dalek::StaticSecret::from(f.server_secret);
    let shared = kx::x25519_dh(&sk, share)?;
    let ak = derive_auth_key(&shared, h.random);
    let mut z = msg.to_vec();
    z[SID_OFF..SID_OFF + 32].fill(0);
    open_token(&ak, h.random, &z, h.session_id)
}

#[test]
fn token_roundtrip() {
    let f = fixture();
    let (msg, _, _, _) = client_hello(&f, [1, 2, 3, 4, 5, 6, 7, 8], 1_800_000_000);
    let t = server_check(&f, &msg).expect("токен принят");
    assert_eq!(t, Token { version: 1, time: 1_800_000_000, short_id: [1, 2, 3, 4, 5, 6, 7, 8] });
}

#[test]
fn token_bound_to_every_byte_of_hello() {
    let f = fixture();
    let (msg, _, _, _) = client_hello(&f, [9; 8], 1_800_000_000);
    assert!(server_check(&f, &msg).is_some());
    // изменение любого байта ClientHello (кроме session_id, он сам токен) ломает проверку; для session_id - тоже
    let mut bad = 0;
    for i in (4..msg.len()).step_by(7) {
        let mut m = msg.clone();
        m[i] ^= 0x01;
        if server_check(&f, &m).is_none() {
            bad += 1;
        } else {
            panic!("изменение байта {i} не замечено");
        }
    }
    assert!(bad > 100);
}

#[test]
fn token_transplant_rejected() {
    let f = fixture();
    let (msg_a, _, tok_a, _) = client_hello(&f, [1; 8], 1_800_000_000);
    let (msg_b, _, _, _) = client_hello(&f, [1; 8], 1_800_000_000);
    // токен из хелло A в хелло B (другие random и key_share)
    let mut t = msg_b.clone();
    t[SID_OFF..SID_OFF + 32].copy_from_slice(&tok_a);
    assert!(server_check(&f, &t).is_none());
    // токен из A в хелло A с другим SNI (иной AAD)
    let h = parse_hello(&msg_a).unwrap();
    assert!(h.sni.is_some());
    let mut m = msg_a.clone();
    let pos = m.windows(17).position(|w| w == b"cover.example.org").unwrap();
    m[pos] = b'x';
    assert!(server_check(&f, &m).is_none());
}

#[test]
fn token_wrong_server_key_rejected() {
    let f = fixture();
    let other = fixture();
    let (msg, _, _, _) = client_hello(&f, [1; 8], 1_800_000_000);
    assert!(server_check(&other, &msg).is_none());
}

#[test]
fn random_session_id_never_validates() {
    let f = fixture();
    for _ in 0..200 {
        let d = build_hello(&Profile::chrome155(), "cover.example.org");
        let m = d.with_sid(&util::random::<32>());
        assert!(server_check(&f, &m).is_none());
    }
}

#[test]
fn time_window() {
    assert!(time_ok(1000, 1000, 120));
    assert!(time_ok(1000, 1120, 120));
    assert!(time_ok(1120, 1000, 120));
    assert!(!time_ok(1000, 1121, 120));
    assert!(!time_ok(1121, 1000, 120));
    assert!(!time_ok(0, 1_800_000_000, 120));
}

#[test]
fn short_id_list() {
    let l = vec![[1u8; 8], [2u8; 8]];
    assert!(short_id_allowed(&l, &[2; 8]));
    assert!(!short_id_allowed(&l, &[3; 8]));
    assert!(!short_id_allowed(&[], &[1; 8]));
}

#[test]
fn replay_cache_semantics() {
    let c = ReplayCache::new(3, Duration::from_millis(50));
    let t0 = Instant::now();
    assert!(c.insert(&[1; 32], t0));
    assert!(!c.insert(&[1; 32], t0));
    assert!(c.insert(&[2; 32], t0));
    assert!(c.insert(&[3; 32], t0));
    assert_eq!(c.len(), 3);
    // переполнение вытесняет самую старую запись (учитывается)
    assert!(c.insert(&[4; 32], t0));
    assert_eq!(c.len(), 3);
    assert_eq!(c.evicted_early(), 1);
    assert!(c.insert(&[1; 32], t0), "вытесненная запись снова принимается");
    // по истечении TTL записи удаляются
    let t1 = t0 + Duration::from_millis(100);
    assert!(c.insert(&[3; 32], t1));
    assert_eq!(c.len(), 1);
}

/// Фаззоподобные входы: ни паники, ни зависаний.
#[test]
fn parser_does_not_panic() {
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let f = fixture();
    let (valid, _, _, _) = client_hello(&f, [1; 8], 1_800_000_000);
    let rec = {
        let mut r = vec![22, 3, 1];
        r.extend_from_slice(&(valid.len() as u16).to_be_bytes());
        r.extend_from_slice(&valid);
        r
    };
    for _ in 0..20_000 {
        // 1) случайные байты
        let n = (rnd() % 300) as usize;
        let b: Vec<u8> = (0..n).map(|_| rnd() as u8).collect();
        let _ = chello::check_record(&b, 16384);
        let _ = parse_hello(&b);
        // 2) мутации и усечения настоящего хелло
        let mut m = valid.clone();
        for _ in 0..(1 + rnd() % 6) {
            let i = (rnd() as usize) % m.len();
            m[i] = rnd() as u8;
        }
        if rnd() % 3 == 0 {
            m.truncate((rnd() as usize) % m.len());
        }
        if let Some(h) = parse_hello(&m) {
            let _ = chello::ja4(&h);
            let _ = h.x25519_share();
            let _ = h.hybrid_share();
        }
        let mut r = rec.clone();
        let i = (rnd() as usize) % r.len();
        r[i] = rnd() as u8;
        r.truncate(5 + (rnd() as usize) % (r.len() - 4));
        let _ = chello::check_record(&r, 16384);
    }
}
