//! Compare the actual leviculum token implementation with RustCrypto AES-GCM.
//! Fixed PUBLIC synthetic key, monotonically increasing nonce, no network I/O.
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use std::{hint::black_box, time::Instant};

fn cpu_seconds() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) },
        0
    );
    ts.tv_sec as f64 + ts.tv_nsec as f64 * 1e-9
}

fn main() {
    let key = [0x42u8; 64]; // Public test fixture, never a deployed key.
    let gcm = Aes256Gcm::new_from_slice(&key[32..]).unwrap();
    let mut records = Vec::new();
    let mut nonce_counter = 0u64;
    for size in [400usize, 1400, 16000] {
        let plain: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let mut token = vec![0u8; size + 64];
        let token_len =
            leviculum_core::crypto::encrypt_token(&key, &[0u8; 16], &plain, &mut token).unwrap();
        let mut gcm_ciphertext = plain.clone();
        let mut fixed_nonce = [0xFFu8; 12];
        // Fixture nonces occupy a namespace distinct from timed encryptions.
        fixed_nonce[4..].copy_from_slice(&(size as u64).to_be_bytes());
        let tag = gcm
            .encrypt_in_place_detached(Nonce::from_slice(&fixed_nonce), b"", &mut gcm_ciphertext)
            .unwrap();
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let mut bad = gcm_ciphertext.clone();
        assert!(
            gcm.decrypt_in_place_detached(Nonce::from_slice(&fixed_nonce), b"", &mut bad, &bad_tag)
                .is_err()
        );
        let mut output = vec![0u8; size + 64];
        let n =
            leviculum_core::crypto::decrypt_token(&key, &token[..token_len], &mut output).unwrap();
        assert_eq!(&output[..n], &plain);
        let iterations = (64 * 1024 * 1024 / size).max(1000);
        for repeat in 0..5 {
            // Reverse order on alternate repeats to reduce order bias.
            let modes = if repeat % 2 == 0 {
                ["cbc", "gcm", "gcm-rekey"]
            } else {
                ["gcm-rekey", "gcm", "cbc"]
            };
            for mode in modes {
                for direction in ["encrypt", "decrypt"] {
                    let mut buffer = vec![0u8; if mode == "cbc" { size + 64 } else { size }];
                    let cpu0 = cpu_seconds();
                    let start = Instant::now();
                    for _ in 0..iterations {
                        // CBC currently constructs its key schedule per token;
                        // also measure GCM that does so, separating key caching
                        // from the choice of cipher/MAC.
                        let fresh_gcm = if mode == "gcm-rekey" {
                            Some(Aes256Gcm::new_from_slice(&key[32..]).unwrap())
                        } else {
                            None
                        };
                        let gcm = fresh_gcm.as_ref().unwrap_or(&gcm);
                        if mode == "cbc" {
                            if direction == "encrypt" {
                                nonce_counter = nonce_counter.checked_add(1).unwrap();
                                let mut iv = [0u8; 16];
                                iv[8..].copy_from_slice(&nonce_counter.to_be_bytes());
                                black_box(
                                    leviculum_core::crypto::encrypt_token(
                                        &key,
                                        &iv,
                                        black_box(&plain),
                                        &mut buffer,
                                    )
                                    .unwrap(),
                                );
                            } else {
                                let n = leviculum_core::crypto::decrypt_token(
                                    &key,
                                    black_box(&token[..token_len]),
                                    &mut buffer,
                                )
                                .unwrap();
                                black_box(&buffer[..n]);
                            }
                        } else if direction == "encrypt" {
                            nonce_counter = nonce_counter.checked_add(1).unwrap();
                            let mut nonce = [0u8; 12];
                            nonce[4..].copy_from_slice(&nonce_counter.to_be_bytes());
                            buffer.copy_from_slice(black_box(&plain));
                            black_box(
                                gcm.encrypt_in_place_detached(
                                    Nonce::from_slice(&nonce),
                                    b"",
                                    &mut buffer,
                                )
                                .unwrap(),
                            );
                        } else {
                            buffer.copy_from_slice(black_box(&gcm_ciphertext));
                            gcm.decrypt_in_place_detached(
                                Nonce::from_slice(&fixed_nonce),
                                b"",
                                &mut buffer,
                                &tag,
                            )
                            .unwrap();
                            black_box(&buffer);
                        }
                    }
                    let wall = start.elapsed().as_secs_f64();
                    let cpu = cpu_seconds() - cpu0;
                    let bytes = iterations * size;
                    records.push(serde_json::json!({
                        "mode": mode, "direction": direction, "size": size, "repeat": repeat,
                        "bytes": bytes, "wall_s": wall, "cpu_s": cpu,
                        "mib_s": bytes as f64 / 1048576.0 / wall,
                        "cpu_s_per_gib": cpu * 1073741824.0 / bytes as f64,
                        "us_per_record": cpu * 1e6 / iterations as f64,
                        "token_bytes": if mode == "cbc" { token_len } else { size + 12 + 16 },
                    }));
                    if direction == "decrypt" {
                        assert_eq!(&buffer[..size], &plain);
                    }
                }
            }
        }
    }
    let result = serde_json::json!({"records": records, "note": "single-thread synthetic crypto benchmark; not Link throughput or Android energy; gcm caches the key schedule, gcm-rekey rebuilds it per record as CBC currently does"});
    if let Some(path) = std::env::args().nth(1) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(serde_json::to_string_pretty(&result).unwrap().as_bytes())
            .unwrap();
        println!("saved {} records", records.len());
    } else {
        println!("{result}");
    }
}
