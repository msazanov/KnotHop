//! Мелкие помощники: случайные числа (ring), разбор/сборка байтовых структур TLS.
use ring::rand::{SecureRandom, SystemRandom};

pub fn fill(b: &mut [u8]) {
    SystemRandom::new().fill(b).expect("системный генератор случайных чисел недоступен");
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    fill(&mut b);
    b
}

/// Равномерное число в 0..n (n>0), отбраковкой без смещения.
pub fn below(n: u32) -> u32 {
    assert!(n > 0);
    let lim = u32::MAX - (u32::MAX % n);
    loop {
        let v = u32::from_le_bytes(random::<4>());
        if v < lim {
            return v % n;
        }
    }
}

/// Перемешивание Фишера-Йетса.
pub fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = below(i as u32 + 1) as usize;
        v.swap(i, j);
    }
}

pub fn put_u16(o: &mut Vec<u8>, v: u16) {
    o.extend_from_slice(&v.to_be_bytes());
}
pub fn put_u24(o: &mut Vec<u8>, v: usize) {
    debug_assert!(v < 1 << 24);
    o.extend_from_slice(&(v as u32).to_be_bytes()[1..]);
}
/// Пишет `u16 длина | данные`.
pub fn put_vec16(o: &mut Vec<u8>, d: &[u8]) {
    put_u16(o, d.len() as u16);
    o.extend_from_slice(d);
}
pub fn put_vec8(o: &mut Vec<u8>, d: &[u8]) {
    o.push(d.len() as u8);
    o.extend_from_slice(d);
}

/// Безопасный курсор по байтам: любое чтение за пределами возвращает None (без паник).
#[derive(Clone)]
pub struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Rd { b, pos: 0 }
    }
    pub fn left(&self) -> usize {
        self.b.len() - self.pos
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    pub fn u16(&mut self) -> Option<u16> {
        let s = self.bytes(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u24(&mut self) -> Option<usize> {
        let s = self.bytes(3)?;
        Some(((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
    }
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    pub fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.bytes(n)
    }
    pub fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.pos..];
        self.pos = self.b.len();
        s
    }
}

pub fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// Сравнение без раннего выхода по содержимому (длины считаются публичными).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    std::hint::black_box(d) == 0
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
