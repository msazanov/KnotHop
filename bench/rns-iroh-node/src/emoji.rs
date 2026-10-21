//! Кодек «эмодзи» для приглашений: любые байты <-> строка из эмодзи. Порт идеи `anybase` из BaseEmoji (tejado/BaseEmoji, MIT):
//! число из байтов переводится в систему счисления с основанием, равным размеру алфавита (самый короткий из вариантов BaseEmoji;
//! `group256` даёт ровно один эмодзи на байт). Алфавит здесь свой и закреплён навсегда (см. `emoji_alphabet.rs`): у BaseEmoji
//! набор зависит от версии Unicode и фильтров, а расшифровка выданного приглашения не должна зависеть от версии библиотеки.
//!
//! Ведущие нулевые байты сохраняются, как в base58: каждый превращается в ведущий «нулевой» эмодзи (первый символ алфавита).
//! Один эмодзи несёт log2(1058) ~ 10,05 бита против 6 у base64: приглашение v2 с 8 нодами (225 байт) - 179 эмодзи вместо 300 символов.
//! Это текстовая форма для чатов; в QR остаётся base64 (эмодзи занимает 4 байта UTF-8).
//!
//! Декодер терпим к тому, что делают мессенджеры: пробелы и переводы строк, селекторы вариантов U+FE0F/U+FE0E, U+200B пропускаются.
//! Любой другой символ вне алфавита - ошибка. Длина ограничена (защита от гигантского ввода).

use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::{Result, bail};

pub use crate::emoji_alphabet::{ALPHABET, ALPHABET_LEN, ALPHABET_SHA256};

/// Не больше столько символов на входе декодера (приглашение - сотни).
pub const MAX_CHARS: usize = 4096;

fn chars() -> &'static Vec<char> {
    static T: OnceLock<Vec<char>> = OnceLock::new();
    T.get_or_init(|| ALPHABET.chars().collect())
}

fn index() -> &'static HashMap<char, u16> {
    static T: OnceLock<HashMap<char, u16>> = OnceLock::new();
    T.get_or_init(|| chars().iter().enumerate().map(|(i, c)| (*c, i as u16)).collect())
}

/// Символ, который мессенджер мог дописать или поменять, не меняя смысла.
fn ignorable(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{FE0F}' | '\u{FE0E}' | '\u{200B}')
}

/// Строка целиком состоит из символов алфавита (и пропускаемых) и не пуста: так отличаем эмодзи-форму от `rawgi-…`.
pub fn looks_like(s: &str) -> bool {
    let mut any = false;
    for c in s.chars() {
        if ignorable(c) {
            continue;
        }
        if !index().contains_key(&c) {
            return false;
        }
        any = true;
    }
    any
}

pub fn encode(data: &[u8]) -> String {
    let base = ALPHABET_LEN as u32;
    let zeros = data.iter().take_while(|b| **b == 0).count();
    let mut num: Vec<u8> = data[zeros..].to_vec();
    let mut digits: Vec<u16> = Vec::new();
    while !num.is_empty() {
        let mut rem = 0u32;
        let mut quo: Vec<u8> = Vec::with_capacity(num.len());
        for &b in &num {
            let cur = rem * 256 + b as u32;
            let q = cur / base;
            rem = cur % base;
            // q < 256, потому что rem < base
            if !quo.is_empty() || q != 0 {
                quo.push(q as u8);
            }
        }
        digits.push(rem as u16);
        num = quo;
    }
    let t = chars();
    let mut out = String::with_capacity((zeros + digits.len()) * 4);
    for _ in 0..zeros {
        out.push(t[0]);
    }
    for d in digits.iter().rev() {
        out.push(t[*d as usize]);
    }
    out
}

pub fn decode(s: &str) -> Result<Vec<u8>> {
    let mut digits: Vec<u16> = Vec::new();
    for (n, c) in s.chars().enumerate() {
        if n > MAX_CHARS {
            bail!("эмодзи-строка слишком длинная (больше {MAX_CHARS} символов)");
        }
        if ignorable(c) {
            continue;
        }
        match index().get(&c) {
            Some(i) => digits.push(*i),
            None => bail!("символ {c:?} (позиция {n}) не из алфавита эмодзи"),
        }
    }
    if digits.is_empty() {
        bail!("пустая эмодзи-строка");
    }
    let zeros = digits.iter().take_while(|d| **d == 0).count();
    // число = sum d_i * base^k, хранится порядком от младшего байта
    let base = ALPHABET_LEN as u32;
    let mut num: Vec<u8> = Vec::new();
    for d in &digits[zeros..] {
        let mut carry = *d as u32;
        for b in num.iter_mut() {
            let cur = *b as u32 * base + carry;
            *b = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(num.iter().rev());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn alphabet_is_pinned() {
        assert_eq!(chars().len(), ALPHABET_LEN);
        assert_eq!(index().len(), ALPHABET_LEN, "повторов нет");
        let h: String = Sha256::digest(ALPHABET.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(h, ALPHABET_SHA256, "алфавит менять нельзя: сломается расшифровка выданных приглашений");
        // все символы без селекторов и ZWJ: одна позиция = один код-пойнт
        assert!(chars().iter().all(|c| !ignorable(*c) && *c != '\u{200D}'));
    }

    #[test]
    fn roundtrip_lengths_and_leading_zeros() {
        let mut x = 0x1234_5678u32;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        };
        for len in [0usize, 1, 2, 3, 16, 31, 64, 225, 400] {
            for z in [0usize, 1, 5] {
                let mut v: Vec<u8> = (0..len).map(|_| rnd()).collect();
                for b in v.iter_mut().take(z) {
                    *b = 0;
                }
                let s = encode(&v);
                if v.is_empty() {
                    assert!(s.is_empty());
                    assert!(decode(&s).is_err(), "пустая строка не декодируется");
                    continue;
                }
                assert_eq!(decode(&s).unwrap(), v, "len={len} z={z}");
            }
        }
        // только нули
        assert_eq!(decode(&encode(&[0, 0, 0])).unwrap(), vec![0, 0, 0]);
        // крайние значения
        assert_eq!(decode(&encode(&[0xff; 64])).unwrap(), vec![0xff; 64]);
    }

    #[test]
    fn compactness_and_tolerance() {
        let v: Vec<u8> = (0..225u32).map(|i| (i * 7 + 3) as u8).collect();
        let s = encode(&v);
        let n = s.chars().count();
        // ceil(225*8/log2(1058)) = 179 (+1 при неудачном ведущем разряде)
        assert!((178..=181).contains(&n), "{n}");
        // мессенджер вставил пробелы, переводы строк и селекторы вариантов
        let noisy: String = s.chars().enumerate().flat_map(|(i, c)| {
            let mut v = vec![c];
            if i % 7 == 0 { v.push('\u{FE0F}'); }
            if i % 11 == 0 { v.push(' '); }
            if i % 50 == 49 { v.push('\n'); }
            v
        }).collect();
        assert_eq!(decode(&noisy).unwrap(), v);
        assert!(looks_like(&noisy));
        assert!(!looks_like("rawgi-AAAA"));
        assert!(!looks_like(""));
        assert!(decode(&format!("{s}x")).is_err());
        assert!(decode(&"😀".repeat(MAX_CHARS + 10)).is_err());
    }
}
