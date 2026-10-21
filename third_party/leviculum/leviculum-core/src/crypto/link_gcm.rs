//! rawg Link GCM v1. Only negotiated Link tokens use this format; identity
//! tokens and the separately encrypted Resource body keep their existing format.
use core::cell::{Cell, RefCell};

/// AES-256-GCM on one key, sealed and opened IN PLACE over `ciphertext || tag`.
///
/// Two interchangeable backends produce the identical AEAD (same ciphertext, same tag,
/// same refusal of any modified bit), so the choice is a build decision, not a protocol one:
/// RustCrypto `aes-gcm` (pure Rust, `no_std`, the default) and `ring` (feature `ring-gcm`,
/// hand-tuned assembly, about 3x cheaper per byte on x86-64). `cross_backend_*` below checks
/// the equivalence whenever both are compiled.
mod backend {
    pub(super) const TAG: usize = 16;

    #[cfg(not(feature = "ring-gcm"))]
    pub(super) struct Key(aes_gcm::Aes256Gcm);
    #[cfg(not(feature = "ring-gcm"))]
    impl Key {
        pub(super) fn new(key: &[u8]) -> Self {
            use aes_gcm::KeyInit;
            Self(aes_gcm::Aes256Gcm::new_from_slice(key).unwrap())
        }
        /// `buf` = plaintext followed by `TAG` spare bytes; leaves `ciphertext || tag`.
        pub(super) fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<(), ()> {
            use aes_gcm::aead::AeadInPlace;
            let n = buf.len() - TAG;
            let tag = self
                .0
                .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut buf[..n])
                .map_err(|_| ())?;
            buf[n..].copy_from_slice(&tag);
            Ok(())
        }
        /// `buf` = `ciphertext || tag`; on success the first `len - TAG` bytes are the plaintext.
        pub(super) fn open(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<(), ()> {
            use aes_gcm::aead::AeadInPlace;
            let n = buf.len() - TAG;
            let (ct, tag) = buf.split_at_mut(n);
            self.0
                .decrypt_in_place_detached(
                    aes_gcm::Nonce::from_slice(nonce),
                    aad,
                    ct,
                    aes_gcm::Tag::from_slice(tag),
                )
                .map_err(|_| ())
        }
    }

    #[cfg(feature = "ring-gcm")]
    pub(super) struct Key(ring::aead::LessSafeKey);
    #[cfg(feature = "ring-gcm")]
    impl Key {
        pub(super) fn new(key: &[u8]) -> Self {
            let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key).unwrap();
            Self(ring::aead::LessSafeKey::new(unbound))
        }
        pub(super) fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<(), ()> {
            let n = buf.len() - TAG;
            // Nonce uniqueness is the caller's invariant, kept by `LinkGcm`: a strictly increasing
            // per-direction counter, reserved before sealing and never reused or wrapped.
            let tag = self
                .0
                .seal_in_place_separate_tag(
                    ring::aead::Nonce::assume_unique_for_key(*nonce),
                    ring::aead::Aad::from(aad),
                    &mut buf[..n],
                )
                .map_err(|_| ())?;
            buf[n..].copy_from_slice(tag.as_ref());
            Ok(())
        }
        pub(super) fn open(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<(), ()> {
            self.0
                .open_in_place(
                    ring::aead::Nonce::assume_unique_for_key(*nonce),
                    ring::aead::Aad::from(aad),
                    buf,
                )
                .map(|_| ())
                .map_err(|_| ())
        }
    }
}

pub(crate) const OVERHEAD: usize = 12 + 16;
const MAX_RECORDS: u64 = 1 << 32;
const MAX_BYTES: u64 = 1 << 36; // Re-establish with fresh ephemeral keys at 64 GiB/direction.
const REPLAY_BITS: usize = 2048;

pub(crate) struct LinkGcm {
    tx: backend::Key,
    rx: backend::Key,
    tx_prefix: [u8; 4],
    rx_prefix: [u8; 4],
    tx_aad: [u8; 22],
    rx_aad: [u8; 22],
    counter: Cell<u64>,
    bytes: Cell<u64>,
    rx_highest: Cell<Option<u64>>,
    rx_seen: RefCell<[u64; REPLAY_BITS / 64]>,
}

impl LinkGcm {
    pub(crate) fn new(master: &[u8; 64], link_id: &[u8; 16], initiator: bool) -> Self {
        // Independent keys and nonce prefixes in each direction. Never reuse
        // CBC's AES key as a GCM key; include a versioned HKDF domain label.
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(link_id), master);
        let mut i2r = [0u8; 36];
        let mut r2i = [0u8; 36];
        hk.expand(b"rawg/link/aes256-gcm/v1/i2r", &mut i2r).unwrap();
        hk.expand(b"rawg/link/aes256-gcm/v1/r2i", &mut r2i).unwrap();
        let (tx, rx, tx_dir) = if initiator {
            (&i2r, &r2i, 0)
        } else {
            (&r2i, &i2r, 1)
        };
        let mut tx_aad = [0u8; 22];
        tx_aad[..4].copy_from_slice(b"GCM1");
        tx_aad[4..20].copy_from_slice(link_id);
        tx_aad[20] = tx_dir;
        let mut rx_aad = tx_aad;
        rx_aad[20] ^= 1;
        Self {
            tx: backend::Key::new(&tx[..32]),
            rx: backend::Key::new(&rx[..32]),
            tx_prefix: tx[32..].try_into().unwrap(),
            rx_prefix: rx[32..].try_into().unwrap(),
            tx_aad,
            rx_aad,
            counter: Cell::new(0),
            bytes: Cell::new(0),
            rx_highest: Cell::new(None),
            rx_seen: RefCell::new([0; REPLAY_BITS / 64]),
        }
    }

    #[cfg(test)]
    fn encrypt(&self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        self.encrypt_context(plaintext, output, 0)
    }

    pub(crate) fn encrypt_context(
        &self,
        plaintext: &[u8],
        output: &mut [u8],
        context: u8,
    ) -> Result<usize, ()> {
        let len = plaintext.len().checked_add(OVERHEAD).ok_or(())?;
        let next_bytes = self
            .bytes
            .get()
            .checked_add(plaintext.len() as u64)
            .ok_or(())?;
        let counter = self.counter.get();
        if output.len() < len || counter >= MAX_RECORDS || next_bytes > MAX_BYTES {
            return Err(());
        }
        // Reserve the nonce before encryption, including on an encryption error.
        self.counter.set(counter + 1);
        self.bytes.set(next_bytes);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.tx_prefix);
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        output[..12].copy_from_slice(&nonce);
        // plaintext, then room for the tag: sealed in place to `ciphertext || tag`.
        let sealed = &mut output[12..len];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        let mut aad = self.tx_aad;
        aad[21] = context;
        self.tx.seal(&nonce, &aad, sealed)?;
        Ok(len)
    }

    #[cfg(test)]
    fn decrypt(&self, token: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        self.decrypt_context(token, output, 0)
    }

    pub(crate) fn decrypt_context(
        &self,
        token: &[u8],
        output: &mut [u8],
        context: u8,
    ) -> Result<usize, ()> {
        if token.len() < OVERHEAD || token[..4] != self.rx_prefix {
            return Err(());
        }
        let counter = u64::from_be_bytes(token[4..12].try_into().unwrap());
        if counter >= MAX_RECORDS || self.replayed(counter) {
            return Err(());
        }
        let len = token.len() - OVERHEAD;
        if output.len() < len {
            return Err(());
        }
        let mut aad = self.rx_aad;
        aad[21] = context;
        let nonce: &[u8; 12] = token[..12].try_into().unwrap();
        // Open over `ciphertext || tag` in place. Callers normally hand in a buffer of the whole
        // token's size, which has the 16 spare bytes; a tighter one falls back to a temporary.
        let opened = if output.len() >= len + backend::TAG {
            let buf = &mut output[..len + backend::TAG];
            buf.copy_from_slice(&token[12..]);
            let result = self.rx.open(nonce, &aad, buf);
            // Neither plaintext nor the copied tag may outlive a failed open.
            if result.is_err() {
                buf.fill(0);
            }
            result
        } else {
            let mut tmp = alloc::vec::Vec::from(&token[12..]);
            let result = self.rx.open(nonce, &aad, &mut tmp);
            if result.is_ok() {
                output[..len].copy_from_slice(&tmp[..len]);
            }
            tmp.fill(0);
            result
        };
        if opened.is_err() {
            output[..len].fill(0);
            return Err(());
        }
        // Only authenticated records advance replay state. Nonces are wider
        // than the Channel's wrapping 16-bit sequence numbers.
        self.accept_counter(counter);
        Ok(len)
    }

    fn replayed(&self, counter: u64) -> bool {
        let Some(highest) = self.rx_highest.get() else {
            return false;
        };
        if counter > highest {
            return false;
        }
        let distance = highest - counter;
        if distance >= REPLAY_BITS as u64 {
            return true;
        }
        let distance = distance as usize;
        self.rx_seen.borrow()[distance / 64] & (1u64 << (distance % 64)) != 0
    }

    fn accept_counter(&self, counter: u64) {
        let mut seen = self.rx_seen.borrow_mut();
        let Some(highest) = self.rx_highest.get() else {
            self.rx_highest.set(Some(counter));
            seen[0] = 1;
            return;
        };
        if counter <= highest {
            let distance = (highest - counter) as usize;
            seen[distance / 64] |= 1u64 << (distance % 64);
            return;
        }
        let shift = counter - highest;
        if shift >= REPLAY_BITS as u64 {
            seen.fill(0);
        } else {
            let words = shift as usize / 64;
            let bits = shift as usize % 64;
            for i in (0..seen.len()).rev() {
                let mut value = if i >= words {
                    seen[i - words] << bits
                } else {
                    0
                };
                if bits != 0 && i > words {
                    value |= seen[i - words - 1] >> (64 - bits);
                }
                seen[i] = value;
            }
        }
        seen[0] |= 1;
        self.rx_highest.set(Some(counter));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directions_tamper_binding_and_fresh_keys() {
        let a = LinkGcm::new(&[42; 64], &[1; 16], true);
        let b = LinkGcm::new(&[42; 64], &[1; 16], false);
        let wrong_link = LinkGcm::new(&[42; 64], &[2; 16], false);
        let fresh_keys = LinkGcm::new(&[43; 64], &[1; 16], false);
        let mut packet = [0u8; 128];
        let mut out = [0u8; 128];
        for payload in [&b""[..], &b"hello"[..], &[7u8; 64][..]] {
            let n = a.encrypt(payload, &mut packet).unwrap();
            assert_eq!(b.decrypt(&packet[..n], &mut out).unwrap(), payload.len());
            assert_eq!(&out[..payload.len()], payload);
            assert!(a.decrypt(&packet[..n], &mut out).is_err()); // no reflection
            assert!(wrong_link.decrypt(&packet[..n], &mut out).is_err());
            assert!(fresh_keys.decrypt(&packet[..n], &mut out).is_err());
            for byte in 0..n {
                let mut damaged = packet;
                damaged[byte] ^= 1;
                let fresh_receiver = LinkGcm::new(&[42; 64], &[1; 16], false);
                assert!(fresh_receiver.decrypt(&damaged[..n], &mut out).is_err());
            }
        }
        let n = b.encrypt(b"reverse", &mut packet).unwrap();
        assert_eq!(a.decrypt(&packet[..n], &mut out).unwrap(), 7);
        assert_eq!(&out[..7], b"reverse");
        let n = a.encrypt_context(b"channel", &mut packet, 0x0e).unwrap();
        assert!(b.decrypt_context(&packet[..n], &mut out, 0).is_err());
        assert_eq!(b.decrypt_context(&packet[..n], &mut out, 0x0e).unwrap(), 7);
    }

    #[test]
    fn nonce_uniqueness_and_budget_do_not_wrap() {
        let a = LinkGcm::new(&[42; 64], &[1; 16], true);
        let mut x = [0u8; 32];
        let mut y = x;
        a.encrypt(b"same", &mut x).unwrap();
        a.encrypt(b"same", &mut y).unwrap();
        assert_ne!(&x[..12], &y[..12]);
        a.counter.set(MAX_RECORDS);
        assert!(a.encrypt(b"", &mut x).is_err());
        a.counter.set(0);
        a.bytes.set(MAX_BYTES);
        assert!(a.encrypt(b"x", &mut x).is_err());
    }

    #[test]
    fn replay_window_allows_reordering_but_rejects_old_epochs() {
        let a = LinkGcm::new(&[42; 64], &[1; 16], true);
        let b = LinkGcm::new(&[42; 64], &[1; 16], false);
        let mut packets = [[0u8; 32]; 4];
        for packet in &mut packets {
            a.encrypt(b"data", packet).unwrap();
        }
        let mut out = [0u8; 32];
        b.decrypt(&packets[2], &mut out).unwrap();
        b.decrypt(&packets[0], &mut out).unwrap();
        assert!(b.decrypt(&packets[0], &mut out).is_err());
        let mut forged = packets[3];
        forged[4..12].copy_from_slice(&((1u64 << 20) + 3).to_be_bytes());
        assert!(b.decrypt(&forged, &mut out).is_err());
        b.decrypt(&packets[1], &mut out).unwrap();
        b.decrypt(&packets[3], &mut out).unwrap();
        // Channel seq wraps after 65536 messages. A replay from the prior
        // epoch must not become a new message even when its seq matches.
        a.counter.set(65536);
        let mut next_epoch = [0u8; 32];
        a.encrypt(b"data", &mut next_epoch).unwrap();
        b.decrypt(&next_epoch, &mut out).unwrap();
        assert!(b.decrypt(&packets[0], &mut out).is_err());
        assert!(b.decrypt(&packets[3], &mut out).is_err());
    }
}

#[cfg(test)]
mod backend_tests {
    use super::*;

    const AAD: [u8; 22] = [0x11; 22];
    const KEY: [u8; 32] = [0x42; 32];

    fn sizes() -> [usize; 9] {
        [0, 1, 15, 16, 17, 400, 1400, 16000, 64000]
    }

    /// Whichever backend is compiled in, an open must refuse every single flipped bit
    /// position class (ciphertext, tag, nonce, AAD) and leave nothing usable behind.
    #[test]
    fn open_refuses_any_modification_for_the_active_backend() {
        let key = backend::Key::new(&KEY);
        for size in sizes() {
            let nonce = [7u8; 12];
            let plain: alloc::vec::Vec<u8> = (0..size).map(|i| (i * 13) as u8).collect();
            let mut sealed = plain.clone();
            sealed.extend_from_slice(&[0u8; backend::TAG]);
            key.seal(&nonce, &AAD, &mut sealed).unwrap();

            let mut ok = sealed.clone();
            key.open(&nonce, &AAD, &mut ok).unwrap();
            assert_eq!(&ok[..size], &plain[..], "size {size}");

            for flip in [0, size / 2, size + backend::TAG - 1] {
                if size + backend::TAG == 0 {
                    continue;
                }
                let mut bad = sealed.clone();
                let at = flip.min(bad.len() - 1);
                bad[at] ^= 0x01;
                assert!(key.open(&nonce, &AAD, &mut bad).is_err(), "size {size} flip {flip}");
            }
            let mut wrong_nonce = sealed.clone();
            assert!(key.open(&[8u8; 12], &AAD, &mut wrong_nonce).is_err());
            let mut wrong_aad = sealed.clone();
            assert!(key.open(&nonce, &[0x12; 22], &mut wrong_aad).is_err());
        }
    }

    /// The two backends are the same AEAD: byte-identical sealed output, and each opens the
    /// other's records. This is what makes `ring-gcm` a build switch rather than a protocol change.
    #[cfg(feature = "ring-gcm")]
    #[test]
    fn cross_backend_ring_and_rustcrypto_are_the_same_aead() {
        use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
        let ring_key = backend::Key::new(&KEY);
        let rustcrypto = Aes256Gcm::new_from_slice(&KEY).unwrap();
        for size in sizes() {
            let nonce = [3u8; 12];
            let plain: alloc::vec::Vec<u8> = (0..size).map(|i| (i * 31) as u8).collect();

            // ring seals -> RustCrypto opens, and the bytes are what RustCrypto would have produced.
            let mut ring_sealed = plain.clone();
            ring_sealed.extend_from_slice(&[0u8; backend::TAG]);
            ring_key.seal(&nonce, &AAD, &mut ring_sealed).unwrap();
            let mut rc_ct = plain.clone();
            let rc_tag = rustcrypto
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), &AAD, &mut rc_ct)
                .unwrap();
            assert_eq!(&ring_sealed[..size], &rc_ct[..], "ciphertext differs at {size}");
            assert_eq!(&ring_sealed[size..], rc_tag.as_slice(), "tag differs at {size}");

            let mut opened = ring_sealed[..size].to_vec();
            rustcrypto
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    &AAD,
                    &mut opened,
                    Tag::from_slice(&ring_sealed[size..]),
                )
                .unwrap();
            assert_eq!(opened, plain);

            // RustCrypto seals -> ring opens.
            let mut joined = rc_ct.clone();
            joined.extend_from_slice(&rc_tag);
            ring_key.open(&nonce, &AAD, &mut joined).unwrap();
            assert_eq!(&joined[..size], &plain[..]);
        }
    }

    /// A destination buffer with no room for the tag still decrypts (temporary path), and a
    /// failed open leaves the destination zeroed instead of holding unauthenticated bytes.
    #[test]
    fn decrypt_into_a_tight_buffer_and_zero_on_failure() {
        let a = LinkGcm::new(&[42; 64], &[1; 16], true);
        let b = LinkGcm::new(&[42; 64], &[1; 16], false);
        let payload = [0xC3u8; 300];
        let mut packet = [0u8; 300 + OVERHEAD];
        let n = a.encrypt_context(&payload, &mut packet, 0x0e).unwrap();

        let mut tight = [0u8; 300];
        assert_eq!(b.decrypt_context(&packet[..n], &mut tight, 0x0e).unwrap(), 300);
        assert_eq!(tight, payload);

        let mut damaged = packet;
        damaged[40] ^= 0x80;
        let fresh = LinkGcm::new(&[42; 64], &[1; 16], false);
        let mut roomy = [0xEEu8; 400];
        assert!(fresh.decrypt_context(&damaged[..n], &mut roomy, 0x0e).is_err());
        assert!(roomy[..300].iter().all(|&x| x == 0), "no unauthenticated plaintext may remain");
        let fresh = LinkGcm::new(&[42; 64], &[1; 16], false);
        let mut tight2 = [0xEEu8; 300];
        assert!(fresh.decrypt_context(&damaged[..n], &mut tight2, 0x0e).is_err());
        assert!(tight2.iter().all(|&x| x == 0));
    }
}
