//! Поведение маршрутизатора на границе MTU туннеля (только IPv4): ICMP «Fragmentation Needed» и IPv4-фрагментация.
//!
//! Зачем. VPN-пакет идёт датаграммой QUIC `0xFE | пакет`; `max_datagram_size` пути бывает меньше TUN MTU (чёрная дыра, сжатие MTU mesh).
//! Раньше такой пакет уходил в Link (`too_large`). Теперь вместо этого: DF=1 - отправителю возвращается ICMP type 3 code 4 с MTU следующего
//! участка (RFC 1191); DF=0 - пакет режется на фрагменты (RFC 791), каждый едет своей датаграммой.
//!
//! Модуль чистый: ни сети, ни состояния туннеля. Права, ACL и source-IP проверяет прежний обработчик (`TunState::on_link_packet_with`):
//! ICMP на выходе тоже проходит через него, а не пишется в TUN напрямую.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Наименьший MTU, который можно объявить (RFC 791: 68).
pub const MIN_MTU: u16 = 68;
/// Предел числа фрагментов одного пакета (пакеты TUN <= ~1.4 КБ; защита от вырожденного `limit`).
pub const MAX_FRAGMENTS: usize = 32;

/// Внутренняя сумма RFC 1071 (дополнение до единицы).
pub fn csum(b: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in b.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ihl(pkt: &[u8]) -> usize {
    usize::from(pkt[0] & 0x0f) * 4
}

fn is_multicast_or_bcast(a: [u8; 4]) -> bool {
    a[0] >= 224 // 224/4 multicast, 240/4 класс E, 255.255.255.255
}

/// Можно ли отвечать на этот пакет ICMP-ошибкой (RFC 1122 3.2.2, RFC 1812 4.3.2.7).
/// Нельзя: не IPv4/короткий, фрагмент с offset != 0, источник 0/loopback/multicast/broadcast/класс E,
/// получатель multicast/broadcast, а также сам ICMP, кроме запросов/ответов (ошибки и неизвестные типы - нельзя).
pub fn icmp_eligible(pkt: &[u8]) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return false;
    }
    let h = ihl(pkt);
    if h < 20 || pkt.len() < h {
        return false;
    }
    if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff != 0 {
        return false;
    }
    let (src, dst): ([u8; 4], [u8; 4]) = (pkt[12..16].try_into().unwrap(), pkt[16..20].try_into().unwrap());
    if src == [0; 4] || src[0] == 127 || is_multicast_or_bcast(src) || is_multicast_or_bcast(dst) {
        return false;
    }
    if pkt[9] == 1 {
        let Some(&t) = pkt.get(h) else { return false };
        // эхо, метки времени, информационные запросы: ответ допустим; всё остальное (3,4,5,11,12 и неизвестное) - ошибка или неопределённо
        if !matches!(t, 0 | 8 | 13 | 14 | 15 | 16 | 17 | 18) {
            return false;
        }
    }
    true
}

/// ICMPv4 type 3 code 4 (RFC 1191) в ответ на `orig`: IP-пакет `src -> orig.src`, MTU следующего участка `mtu`, цитата - заголовок исходного пакета + 8 байт.
/// None - ответ недопустим (`icmp_eligible`).
pub fn build_frag_needed(orig: &[u8], mtu: u16, src: [u8; 4]) -> Option<Vec<u8>> {
    if !icmp_eligible(orig) {
        return None;
    }
    let quote = (ihl(orig) + 8).min(orig.len());
    let total = 20 + 8 + quote;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 1;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&orig[12..16]);
    let c = csum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[20] = 3;
    p[21] = 4;
    // p[22..24] - контрольная сумма ICMP, p[24..26] - не используется
    p[26..28].copy_from_slice(&mtu.max(MIN_MTU).to_be_bytes());
    p[28..].copy_from_slice(&orig[..quote]);
    let c = csum(&p[20..]);
    p[22..24].copy_from_slice(&c.to_be_bytes());
    Some(p)
}

#[derive(Debug, PartialEq, Eq)]
pub enum FragError {
    /// DF=1: резать нельзя
    DontFragment,
    /// не IPv4 / битый заголовок / битые опции
    Malformed,
    /// предел не вмещает даже 8 байт данных или нужно больше `MAX_FRAGMENTS` кусков
    TooSmall,
}

/// Опции, копируемые в не первые фрагменты (RFC 791: бит «copied»), дополненные нулями до границы 4 байт. None - опции разобрать нельзя.
fn copied_options(opts: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < opts.len() {
        let t = opts[i];
        match t {
            0 => break,
            1 => i += 1,
            _ => {
                let l = usize::from(*opts.get(i + 1)?);
                if l < 2 || i + l > opts.len() {
                    return None;
                }
                if t & 0x80 != 0 {
                    out.extend_from_slice(&opts[i..i + l]);
                }
                i += l;
            }
        }
    }
    while out.len() % 4 != 0 {
        out.push(0);
    }
    Some(out)
}

/// Разрезать IPv4-пакет `pkt` (DF=0) на фрагменты, каждый не длиннее `max_len` байт. Уже фрагмент тоже режется (offset прибавляется, MF последнего куска
/// наследуется). Смещения кратны 8, контрольные суммы заголовков пересчитаны, ID сохранён. Пакет, который вмещается, возвращается одним куском без изменений.
pub fn fragment(pkt: &[u8], max_len: usize) -> Result<Vec<Vec<u8>>, FragError> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return Err(FragError::Malformed);
    }
    let h = ihl(pkt);
    if !(20..=60).contains(&h) || h > pkt.len() || usize::from(u16::from_be_bytes([pkt[2], pkt[3]])) != pkt.len() {
        return Err(FragError::Malformed);
    }
    if pkt.len() <= max_len {
        return Ok(vec![pkt.to_vec()]);
    }
    let field = u16::from_be_bytes([pkt[6], pkt[7]]);
    if field & 0x4000 != 0 {
        return Err(FragError::DontFragment);
    }
    let rest_opts = copied_options(&pkt[20..h]).ok_or(FragError::Malformed)?;
    let rest_h = 20 + rest_opts.len();
    if max_len < h.max(rest_h) + 8 {
        return Err(FragError::TooSmall);
    }
    let first_cap = (max_len - h) & !7;
    let rest_cap = (max_len - rest_h) & !7;
    let payload = &pkt[h..];
    let base_off = usize::from(field & 0x1fff) * 8;
    let mf_orig = field & 0x2000 != 0;
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let first = pos == 0;
        let (hl, cap) = if first { (h, first_cap) } else { (rest_h, rest_cap) };
        let n = (payload.len() - pos).min(cap);
        let last = pos + n == payload.len();
        if out.len() >= MAX_FRAGMENTS {
            return Err(FragError::TooSmall);
        }
        let off = base_off + pos;
        if off / 8 > 0x1fff {
            return Err(FragError::Malformed);
        }
        let mut f = Vec::with_capacity(hl + n);
        f.extend_from_slice(&pkt[..20]);
        if first {
            f.extend_from_slice(&pkt[20..h]);
        } else {
            f.extend_from_slice(&rest_opts);
        }
        f[0] = 0x40 | (hl / 4) as u8;
        f[2..4].copy_from_slice(&((hl + n) as u16).to_be_bytes());
        let mut fl = (off / 8) as u16;
        if !last || mf_orig {
            fl |= 0x2000;
        }
        f[6..8].copy_from_slice(&fl.to_be_bytes());
        f[10] = 0;
        f[11] = 0;
        let c = csum(&f[..hl]);
        f[10..12].copy_from_slice(&c.to_be_bytes());
        f.extend_from_slice(&payload[pos..pos + n]);
        out.push(f);
        pos += n;
    }
    Ok(out)
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(burst: f64, now: Instant) -> Self {
        Bucket { tokens: burst, last: now }
    }
    fn take(&mut self, rate: f64, burst: f64, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * rate).min(burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Предел частоты ICMP-ответов: общий (на узел) и на адрес получателя. Общий 50/с (всплеск 50) - потолок исходящего «шума» узла и
/// защита от отражения; на адрес 10/с (всплеск 10) - хватает на начальное окно TCP (10 сегментов) одного потока, а один хост не съедает общий бюджет.
/// Таблица адресов ограничена: при переполнении удаляются остывшие записи, иначе ответ отклоняется (fail-closed).
pub struct IcmpLimiter {
    global: Bucket,
    per: HashMap<[u8; 4], Bucket>,
}

pub const GLOBAL_RATE: f64 = 50.0;
pub const GLOBAL_BURST: f64 = 50.0;
pub const PER_ADDR_RATE: f64 = 10.0;
pub const PER_ADDR_BURST: f64 = 10.0;
const MAX_ADDRS: usize = 512;
const COOL: Duration = Duration::from_secs(5);

impl IcmpLimiter {
    pub fn new(now: Instant) -> Self {
        IcmpLimiter { global: Bucket::new(GLOBAL_BURST, now), per: HashMap::new() }
    }

    /// Разрешить ещё один ответ адресату `dst`. Токен снимается только при полном разрешении.
    pub fn allow(&mut self, dst: [u8; 4], now: Instant) -> bool {
        if self.per.len() >= MAX_ADDRS && !self.per.contains_key(&dst) {
            self.per.retain(|_, b| now.saturating_duration_since(b.last) < COOL);
            if self.per.len() >= MAX_ADDRS {
                return false;
            }
        }
        // сначала адрес, потом общий: отказ по адресу не тратит общий бюджет, а отказ общего возвращает токен адреса
        let b = self.per.entry(dst).or_insert_with(|| Bucket::new(PER_ADDR_BURST, now));
        if !b.take(PER_ADDR_RATE, PER_ADDR_BURST, now) {
            return false;
        }
        if !self.global.take(GLOBAL_RATE, GLOBAL_BURST, now) {
            b.tokens += 1.0;
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8], flags_off: u16) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[6..8].copy_from_slice(&flags_off.to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        let c = csum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    const A: [u8; 4] = [198, 18, 0, 5];
    const B: [u8; 4] = [93, 184, 216, 34];

    #[test]
    fn frag_needed_layout_checksums_and_quote() {
        let orig = ip(A, B, 6, &data(1300), 0x4000);
        let r = build_frag_needed(&orig, 1162, [10, 99, 0, 1]).unwrap();
        // внешний заголовок
        assert_eq!((r[0], r[9], r[8]), (0x45, 1, 64));
        assert_eq!(usize::from(u16::from_be_bytes([r[2], r[3]])), r.len());
        assert_eq!(&r[12..16], &[10, 99, 0, 1]);
        assert_eq!(&r[16..20], &A, "ответ уходит отправителю исходного пакета");
        assert_eq!(csum(&r[..20]), 0, "контрольная сумма IP верна");
        // ICMP
        assert_eq!((r[20], r[21]), (3, 4));
        assert_eq!(&r[24..26], &[0, 0]);
        assert_eq!(u16::from_be_bytes([r[26], r[27]]), 1162);
        assert_eq!(csum(&r[20..]), 0, "контрольная сумма ICMP верна");
        // цитата: заголовок 20 + 8 байт, дословно
        assert_eq!(r.len(), 20 + 8 + 28);
        assert_eq!(&r[28..], &orig[..28]);
    }

    #[test]
    fn frag_needed_quote_covers_ip_options_and_short_packets() {
        // IHL=6: цитата = 24 + 8
        let mut orig = ip(A, B, 17, &data(40), 0x4000);
        orig.splice(20..20, [1u8, 1, 1, 0]);
        orig[0] = 0x46;
        let l = orig.len() as u16;
        orig[2..4].copy_from_slice(&l.to_be_bytes());
        let r = build_frag_needed(&orig, 1000, [1, 2, 3, 4]).unwrap();
        assert_eq!(r.len(), 28 + 32);
        assert_eq!(&r[28..], &orig[..32]);
        assert_eq!(csum(&r[20..]), 0);
        // пакет короче 28 байт: цитируется целиком
        let tiny = ip(A, B, 17, &[1, 2, 3], 0x4000);
        let r = build_frag_needed(&tiny, 1000, [1, 2, 3, 4]).unwrap();
        assert_eq!(&r[28..], &tiny[..]);
        assert_eq!(csum(&r[20..]), 0);
        // MTU ниже 68 поднимается до 68
        let r = build_frag_needed(&tiny, 10, [1, 2, 3, 4]).unwrap();
        assert_eq!(u16::from_be_bytes([r[26], r[27]]), MIN_MTU);
    }

    #[test]
    fn no_icmp_for_icmp_errors_fragments_and_special_addresses() {
        let icmp = |t: u8| ip(A, B, 1, &[t, 0, 0, 0, 0, 0, 0, 0], 0x4000);
        for t in [3u8, 4, 5, 11, 12, 99] {
            assert!(build_frag_needed(&icmp(t), 1200, [1, 1, 1, 1]).is_none(), "на ICMP-ошибку type {t} не отвечаем");
        }
        for t in [0u8, 8, 13] {
            assert!(build_frag_needed(&icmp(t), 1200, [1, 1, 1, 1]).is_some(), "эхо type {t} - можно");
        }
        // фрагмент с offset != 0
        assert!(build_frag_needed(&ip(A, B, 6, &data(64), 0x0005), 1200, [1, 1, 1, 1]).is_none());
        // первый фрагмент (MF, offset 0) - можно
        assert!(build_frag_needed(&ip(A, B, 6, &data(64), 0x2000), 1200, [1, 1, 1, 1]).is_some());
        // multicast / broadcast / класс E получатель; недопустимые источники
        for dst in [[224, 0, 0, 1], [239, 1, 1, 1], [255, 255, 255, 255], [240, 0, 0, 1]] {
            assert!(build_frag_needed(&ip(A, dst, 17, &data(64), 0x4000), 1200, [1, 1, 1, 1]).is_none());
        }
        for src in [[0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [255, 255, 255, 255]] {
            assert!(build_frag_needed(&ip(src, B, 17, &data(64), 0x4000), 1200, [1, 1, 1, 1]).is_none());
        }
        // мусор
        assert!(build_frag_needed(&[0x45; 10], 1200, [1, 1, 1, 1]).is_none());
        assert!(build_frag_needed(&[], 1200, [1, 1, 1, 1]).is_none());
        // ICMP без байта типа
        let mut trunc = ip(A, B, 1, &[], 0x4000);
        trunc[9] = 1;
        assert!(build_frag_needed(&trunc, 1200, [1, 1, 1, 1]).is_none());
    }

    /// Сборка обратно: соединить фрагменты по offset и сравнить с оригиналом (полезная нагрузка, поля, ID).
    fn reassemble(frags: &[Vec<u8>]) -> (Vec<u8>, bool) {
        let mut buf: Vec<u8> = Vec::new();
        let mut last_mf = false;
        let mut expect = 0usize;
        for f in frags {
            assert_eq!(csum(&f[..ihl(f)]), 0, "контрольная сумма заголовка фрагмента");
            assert_eq!(usize::from(u16::from_be_bytes([f[2], f[3]])), f.len());
            let fl = u16::from_be_bytes([f[6], f[7]]);
            assert_eq!(fl & 0x4000, 0, "DF=0");
            let off = usize::from(fl & 0x1fff) * 8;
            assert_eq!(off, expect, "фрагменты идут подряд, смещение кратно 8");
            let pl = &f[ihl(f)..];
            if fl & 0x2000 != 0 {
                assert_eq!(pl.len() % 8, 0, "не последний фрагмент кратен 8");
            }
            last_mf = fl & 0x2000 != 0;
            buf.extend_from_slice(pl);
            expect += pl.len();
        }
        (buf, last_mf)
    }

    #[test]
    fn fragment_roundtrip_df0() {
        for (len, max) in [(1300usize, 1161usize), (1300, 600), (1500, 576), (1327 - 20, 1000), (3000, 1161), (29, 28)] {
            let payload = data(len);
            let orig = ip(A, B, 17, &payload, 0);
            let frags = fragment(&orig, max).unwrap();
            assert!(frags.len() >= 2, "len {len} max {max}");
            assert!(frags.iter().all(|f| f.len() <= max), "каждый кусок <= {max}");
            for f in &frags {
                assert_eq!(&f[4..6], &orig[4..6], "ID сохранён");
                assert_eq!(&f[12..20], &orig[12..20]);
                assert_eq!(f[8], 64);
                assert_eq!(f[9], 17);
            }
            let (back, last_mf) = reassemble(&frags);
            assert_eq!(back, payload);
            assert!(!last_mf, "у последнего MF сброшен");
            // у всех, кроме последнего, MF=1
            for f in &frags[..frags.len() - 1] {
                assert_ne!(u16::from_be_bytes([f[6], f[7]]) & 0x2000, 0);
            }
        }
    }

    #[test]
    fn fragment_fits_unchanged_and_refuses_df() {
        let orig = ip(A, B, 17, &data(100), 0);
        assert_eq!(fragment(&orig, 1161).unwrap(), vec![orig.clone()]);
        let df = ip(A, B, 17, &data(1300), 0x4000);
        assert_eq!(fragment(&df, 1161), Err(FragError::DontFragment));
        // слишком малый предел
        assert_eq!(fragment(&orig, 27), Err(FragError::TooSmall));
        // слишком много кусков
        let big = ip(A, B, 17, &data(1300), 0);
        assert_eq!(fragment(&big, 20 + 8 + 7), Err(FragError::TooSmall));
        // битая длина
        let mut bad = orig.clone();
        bad[3] ^= 1;
        assert_eq!(fragment(&bad, 60), Err(FragError::Malformed));
    }

    #[test]
    fn fragment_of_a_fragment_keeps_offset_and_mf() {
        // середина цепочки: offset 100*8, MF=1 - последний кусок обязан сохранить MF=1
        let payload = data(1200);
        let orig = ip(A, B, 17, &payload, 0x2000 | 100);
        let frags = fragment(&orig, 700).unwrap();
        let first = u16::from_be_bytes([frags[0][6], frags[0][7]]);
        assert_eq!(first & 0x1fff, 100);
        let lastf = frags.last().unwrap();
        let lf = u16::from_be_bytes([lastf[6], lastf[7]]);
        assert_ne!(lf & 0x2000, 0, "MF исходного сохранён на последнем куске");
        let mut expect = 100usize * 8;
        let mut back = Vec::new();
        for f in &frags {
            let fl = u16::from_be_bytes([f[6], f[7]]);
            assert_eq!(usize::from(fl & 0x1fff) * 8, expect);
            back.extend_from_slice(&f[20..]);
            expect += f.len() - 20;
        }
        assert_eq!(back, payload);
        // последний фрагмент цепочки (MF=0, offset>0) режется без MF на последнем куске
        let orig = ip(A, B, 17, &payload, 100);
        let frags = fragment(&orig, 700).unwrap();
        let lastf = frags.last().unwrap();
        assert_eq!(u16::from_be_bytes([lastf[6], lastf[7]]) & 0x2000, 0);
    }

    #[test]
    fn fragment_options_follow_rfc791() {
        // опции: LSRR-подобная (0x83, copied), NOP, timestamp-подобная (0x44, не copied), EOL -> IHL 8 слов
        let mut orig = ip(A, B, 17, &data(1300), 0);
        let opts: Vec<u8> = vec![0x83, 7, 4, 1, 2, 3, 4, 1, 0x44, 4, 5, 0, 0, 0, 0, 0];
        orig.splice(20..20, opts.clone());
        orig[0] = 0x40 | ((20 + opts.len()) / 4) as u8;
        let l = orig.len() as u16;
        orig[2..4].copy_from_slice(&l.to_be_bytes());
        orig[10] = 0;
        orig[11] = 0;
        let c = csum(&orig[..36]);
        orig[10..12].copy_from_slice(&c.to_be_bytes());
        let frags = fragment(&orig, 600).unwrap();
        assert!(frags.len() >= 3);
        // первый несёт все опции
        assert_eq!(ihl(&frags[0]), 36);
        assert_eq!(&frags[0][20..36], &opts[..]);
        // остальные - только copied (0x83, длина 7 + 1 байт добивки)
        for f in &frags[1..] {
            assert_eq!(ihl(f), 28);
            assert_eq!(&f[20..27], &[0x83, 7, 4, 1, 2, 3, 4]);
            assert_eq!(f[27], 0);
        }
        // данные собираются
        let mut back = Vec::new();
        for f in &frags {
            back.extend_from_slice(&f[ihl(f)..]);
        }
        assert_eq!(back, data(1300));
        // битые опции -> отказ
        let mut bad = orig.clone();
        bad[21] = 40; // длина выходит за заголовок
        assert_eq!(fragment(&bad, 600), Err(FragError::Malformed));
    }

    #[test]
    fn limiter_global_and_per_address_and_refill() {
        let t0 = Instant::now();
        let mut l = IcmpLimiter::new(t0);
        // на адрес: всплеск 10, дальше отказ
        let a = [1, 1, 1, 1];
        assert_eq!((0..20).filter(|_| l.allow(a, t0)).count(), PER_ADDR_BURST as usize);
        // пополнение 10/с: через 0,5 с +5
        let t1 = t0 + Duration::from_millis(500);
        assert_eq!((0..20).filter(|_| l.allow(a, t1)).count(), 5);
        // общий: 50 токенов на все адреса; адресов 100 по 1 ответу - ровно 50 минус уже потраченные
        let mut l = IcmpLimiter::new(t0);
        let ok = (0..100u8).filter(|i| l.allow([9, 9, 9, *i], t0)).count();
        assert_eq!(ok, GLOBAL_BURST as usize);
        // отказ по общему не сжигает токен адреса
        assert!(l.per.get(&[9, 9, 9, 99]).unwrap().tokens >= 9.9);
        // пополнение общего 50/с
        let t2 = t0 + Duration::from_secs(1);
        let ok = (0..100u8).filter(|i| l.allow([9, 9, 9, *i], t2)).count();
        assert_eq!(ok, 50);
    }

    #[test]
    fn limiter_table_is_bounded() {
        let t0 = Instant::now();
        let mut l = IcmpLimiter::new(t0);
        // много разных адресов: общий бюджет мал, но таблица растёт только до MAX_ADDRS
        for i in 0..2000u32 {
            let _ = l.allow(i.to_be_bytes(), t0);
        }
        assert!(l.per.len() <= MAX_ADDRS);
        // переполнено и все свежие: новый адрес отклонён
        assert!(!l.allow([200, 200, 200, 200], t0));
        // остыли - таблица чистится
        let later = t0 + Duration::from_secs(30);
        assert!(l.allow([200, 200, 200, 200], later));
        assert!(l.per.len() < MAX_ADDRS);
    }
}
