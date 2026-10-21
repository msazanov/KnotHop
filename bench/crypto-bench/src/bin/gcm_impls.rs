//! AES-256-GCM implementations on one wire format: RustCrypto `aes-gcm` against `ring`.
//!
//! Same record layout as Link GCM v1: nonce(12) | ciphertext | tag(16), AAD = 22 bytes,
//! counter nonces. Fixed PUBLIC synthetic key, no network. Checks that the two
//! implementations interoperate (each opens what the other sealed, a flipped bit is refused)
//! before it times anything: a faster AEAD that is not the same AEAD is worthless.
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce as RingNonce, UnboundKey};
use std::{hint::black_box, time::Instant};

fn cpu_seconds() -> f64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) }, 0);
    ts.tv_sec as f64 + ts.tv_nsec as f64 * 1e-9
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0xA5u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

fn main() {
    let key = [0x42u8; 32];
    let aad = [0x11u8; 22];
    let rc = Aes256Gcm::new_from_slice(&key).unwrap();
    let ring = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).unwrap());

    // 1. Interoperability and tamper refusal, every size.
    for size in [0usize, 1, 15, 16, 17, 400, 1400, 16000, 64000] {
        let plain: Vec<u8> = (0..size).map(|i| (i * 7) as u8).collect();
        let n = nonce(size as u64);
        let mut a = plain.clone();
        let tag_a = rc.encrypt_in_place_detached(Nonce::from_slice(&n), &aad, &mut a).unwrap();
        let mut b = plain.clone();
        let tag_b = ring
            .seal_in_place_separate_tag(RingNonce::assume_unique_for_key(n), Aad::from(aad), &mut b)
            .unwrap();
        assert_eq!(a, b, "ciphertext differs at {size}");
        assert_eq!(tag_a.as_slice(), tag_b.as_ref(), "tag differs at {size}");
        // ring opens what aes-gcm sealed; aes-gcm opens what ring sealed.
        let mut joined = a.clone();
        joined.extend_from_slice(&tag_a);
        let opened = ring.open_in_place(RingNonce::assume_unique_for_key(n), Aad::from(aad), &mut joined).unwrap();
        assert_eq!(opened, &plain[..]);
        let mut c = b.clone();
        rc.decrypt_in_place_detached(Nonce::from_slice(&n), &aad, &mut c, Tag::from_slice(tag_b.as_ref())).unwrap();
        assert_eq!(c, plain);
        // A flipped bit anywhere is refused by both.
        if size > 0 {
            let mut bad = a.clone();
            bad[size / 2] ^= 1;
            assert!(rc.decrypt_in_place_detached(Nonce::from_slice(&n), &aad, &mut bad, &tag_a).is_err());
            let mut bad_joined = a.clone();
            bad_joined[size / 2] ^= 1;
            bad_joined.extend_from_slice(&tag_a);
            assert!(ring.open_in_place(RingNonce::assume_unique_for_key(n), Aad::from(aad), &mut bad_joined).is_err());
        }
    }
    eprintln!("interoperability and tamper checks passed");

    // 2. Timing.
    let mut records = Vec::new();
    for size in [400usize, 1400, 16000, 64000] {
        let plain: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let iterations = (128 * 1024 * 1024 / size).max(2000);
        // Sealed fixture for the decrypt loops.
        let fixed = nonce(u64::MAX);
        let mut sealed = plain.clone();
        let tag = rc.encrypt_in_place_detached(Nonce::from_slice(&fixed), &aad, &mut sealed).unwrap();
        let mut sealed_joined = sealed.clone();
        sealed_joined.extend_from_slice(&tag);
        for repeat in 0..5 {
            let order = if repeat % 2 == 0 { ["aes-gcm", "ring"] } else { ["ring", "aes-gcm"] };
            for imp in order {
                for dir in ["encrypt", "decrypt"] {
                    let mut buf = vec![0u8; size + 16];
                    let (cpu0, t0) = (cpu_seconds(), Instant::now());
                    for i in 0..iterations {
                        let n = nonce(i as u64);
                        match (imp, dir) {
                            ("aes-gcm", "encrypt") => {
                                buf[..size].copy_from_slice(black_box(&plain));
                                black_box(rc.encrypt_in_place_detached(Nonce::from_slice(&n), &aad, &mut buf[..size]).unwrap());
                            }
                            ("ring", "encrypt") => {
                                buf[..size].copy_from_slice(black_box(&plain));
                                black_box(ring.seal_in_place_separate_tag(RingNonce::assume_unique_for_key(n), Aad::from(aad), &mut buf[..size]).unwrap());
                            }
                            ("aes-gcm", "decrypt") => {
                                buf[..size].copy_from_slice(black_box(&sealed));
                                rc.decrypt_in_place_detached(Nonce::from_slice(&fixed), &aad, &mut buf[..size], &tag).unwrap();
                            }
                            ("ring", "decrypt") => {
                                buf[..size + 16].copy_from_slice(black_box(&sealed_joined));
                                ring.open_in_place(RingNonce::assume_unique_for_key(fixed), Aad::from(aad), &mut buf[..size + 16]).unwrap();
                            }
                            _ => unreachable!(),
                        }
                    }
                    let (cpu, wall) = (cpu_seconds() - cpu0, t0.elapsed().as_secs_f64());
                    let bytes = (iterations * size) as f64;
                    records.push(serde_json::json!({
                        "impl": imp, "dir": dir, "size": size, "repeat": repeat, "cpu_s_per_gib": cpu * 1073741824.0 / bytes,
                        "mib_s": bytes / 1048576.0 / wall, "us_per_record": cpu * 1e6 / iterations as f64 }));
                }
            }
        }
    }
    let out = serde_json::json!({"records": records, "note": "single thread, in-place, key schedule cached, buffer copy included for both"});
    if let Some(path) = std::env::args().nth(1) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();
        f.write_all(serde_json::to_string_pretty(&out).unwrap().as_bytes()).unwrap();
    } else {
        println!("{out}");
    }
}
