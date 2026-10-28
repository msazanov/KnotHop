//! Зонд QUIC перед возвратом с TCP (docs/decisions/0021): проверка датаграммного пути отдельным iroh-соединением.
//!
//! Клиент, сидящий на TCP, перед возвратом на QUIC проверяет датаграммный путь отдельным iroh-соединением. На клиенте оно до зонда не привязано к
//! интерфейсу пира; на принимающей стороне оно привязано сразу (носитель без выбора, данные от него переключат ответ только после двух пакетов):
//! восемь коротких датаграмм с эхом сервера, порог 7/8. TCP и Link при этом не трогаются. Сервер отвечает эхом только соединению, которому выдал
//! разрешение (`Grants::grant`) по запросу `'G'` от самого соединения, и только если у того же ключа iroh уже есть другой носитель (`mux.rs`);
//! без такого носителя эха нет. Эхо ограничено бюджетом, равно запросу по длине и не усиливает трафик. Датаграмма с магическим префиксом никогда
//! не попадает в RNS.
//!
//! Формат: MAGIC(8) | kind(1: 'Q' запрос, 'E' эхо) | idx(1) | nonce(8) | заполнитель. Эхо равно запросу по длине (не больше) и повторяет его байты:
//! ни адресов, ни секретов, ни данных VPN в нём нет.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use iroh::endpoint::Connection;

/// Первый байт 0xFF (флаг IFAC) не бывает у пакетов нашего пакетного интерфейса RNS, поэтому с настоящим пакетом префикс не совпадёт.
pub const MAGIC: [u8; 8] = *b"\xFFRGQprb1";
pub const KIND_REQ: u8 = b'Q';
pub const KIND_ECHO: u8 = b'E';
/// запрос и ответ разрешения на зонд по самой датаграммной связи кандидата
pub const KIND_GREQ: u8 = b'G';
pub const KIND_GREP: u8 = b'H';
/// статус ответа: у пира нет другого носителя, разрешение не положено (коды `Deny` - 1 и 2)
pub const DENY_NO_CARRIER: u8 = 3;
/// заголовок: MAGIC + kind + idx + nonce
pub const HEAD: usize = 8 + 1 + 1 + 8;
/// потолок размера датаграммы зонда (меньше типичного MTU пути)
pub const MAX_LEN: usize = 1200;
/// датаграмм в зонде и порог успеха
pub const PROBE_COUNT: u8 = 8;
pub const PROBE_MIN_OK: u8 = 7;
const SMALL_LEN: usize = 40;
const SPACING: Duration = Duration::from_millis(25);
const REPLY_WAIT: Duration = Duration::from_millis(1500);

/// Срок действия разрешения и бюджет эха на одно разрешение.
pub const GRANT_TTL: Duration = Duration::from_secs(10);
const GRANT_PKTS: u8 = 16;
const GRANT_BYTES: u32 = 16 * 1280;
/// Не чаще одного разрешения за этот срок на допущенного пира (по ключу RNS) и на ключ iroh; расписание возврата (>= 120 с) заведомо реже.
pub const GRANT_INTERVAL: Duration = Duration::from_secs(30);
/// Одновременных разрешений и выданных за минуту на весь узел.
const MAX_LIVE: usize = 8;
const MAX_PER_MINUTE: usize = 12;
/// Память «когда выдавали» ограничена: старее этого забывается, число записей не больше MAX_MEMORY.
const MEMORY: Duration = Duration::from_secs(120);
const MAX_MEMORY: usize = 256;

/// Сколько датаграмм с магическим префиксом приёмный фильтр съедает за один вызов `try_recv` / между уступками исполнителю в `recv` (QAB-M5).
/// Дальше `try_recv` возвращает управление, а `recv` делает `yield_now`: поток magic не удерживает ни опрос, ни выбор исходящей очереди/останова.
pub const WORK_BUDGET: u32 = 16;
/// Магических датаграмм в секунду на соединение, которые вообще доходят до `Grants::echo`: остальные отбрасываются счётчиком, без блокировки и разбора.
/// Честный зонд шлёт 8 за ~0,2 с. Лимит действует и на соединения без разрешения (пред-допусковые), и на мусор с магическим префиксом.
pub const MAGIC_RATE: u32 = 128;

pub static GRANTED: AtomicU64 = AtomicU64::new(0);
pub static DENIED: AtomicU64 = AtomicU64::new(0);
pub static ECHO_PKTS: AtomicU64 = AtomicU64::new(0);
pub static ECHO_BYTES: AtomicU64 = AtomicU64::new(0);
/// Датаграмм с магическим префиксом, снятых фильтром с соединений узла (все: эхо, отказ, мусор), и из них отброшенных лимитом `MAGIC_RATE`.
pub static MAGIC_SEEN: AtomicU64 = AtomicU64::new(0);
pub static MAGIC_DROPPED: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Deny {
    /// этот пир (или ключ iroh) уже получал разрешение недавно
    TooSoon,
    /// на узле слишком много живых разрешений или выдач за минуту
    Busy,
}

impl Deny {
    /// код статуса в ответе на запрос разрешения (0 - разрешено)
    pub fn code(self) -> u8 {
        match self {
            Deny::TooSoon => 1,
            Deny::Busy => 2,
        }
    }
}

struct Grant {
    expires: Instant,
    pkts: u8,
    bytes: u32,
}

#[derive(Default)]
struct Inner {
    live: HashMap<[u8; 32], Grant>,
    by_ep: HashMap<[u8; 32], Instant>,
    by_owner: HashMap<[u8; 32], Instant>,
    minute: VecDeque<Instant>,
}

/// Разрешения на эхо: ключ iroh -> ограниченный бюджет. Выдаёт узел по запросу самого соединения, у которого уже есть другой носитель (`mux.rs`); память ограничена.
#[derive(Default)]
pub struct Grants(Mutex<Inner>);

impl Grants {
    /// `ep` - ключ iroh соединения зонда, `owner` - по чему считается частота выдач (для узла - адрес источника, `mux::owner_key`: смена ключа лимит не обходит).
    /// Вызывать только когда у этого ключа уже есть другой носитель (`mux.rs`), без await под guard.
    pub fn grant(&self, ep: [u8; 32], owner: [u8; 32], now: Instant) -> Result<(), Deny> {
        let mut g = self.0.lock().unwrap();
        g.live.retain(|_, v| v.expires > now);
        g.by_ep.retain(|_, t| now.saturating_duration_since(*t) < MEMORY);
        g.by_owner.retain(|_, t| now.saturating_duration_since(*t) < MEMORY);
        while g.minute.front().is_some_and(|t| now.saturating_duration_since(*t) >= Duration::from_secs(60)) {
            g.minute.pop_front();
        }
        let recent = |t: Option<&Instant>| t.is_some_and(|t| now.saturating_duration_since(*t) < GRANT_INTERVAL);
        if recent(g.by_ep.get(&ep)) || recent(g.by_owner.get(&owner)) {
            DENIED.fetch_add(1, Relaxed);
            return Err(Deny::TooSoon);
        }
        if g.live.len() >= MAX_LIVE || g.minute.len() >= MAX_PER_MINUTE || g.by_ep.len() >= MAX_MEMORY || g.by_owner.len() >= MAX_MEMORY {
            DENIED.fetch_add(1, Relaxed);
            return Err(Deny::Busy);
        }
        g.live.insert(ep, Grant { expires: now + GRANT_TTL, pkts: GRANT_PKTS, bytes: GRANT_BYTES });
        g.by_ep.insert(ep, now);
        g.by_owner.insert(owner, now);
        g.minute.push_back(now);
        GRANTED.fetch_add(1, Relaxed);
        Ok(())
    }

    /// Ответ на запрос зонда от соединения `ep`: None - эха нет (нет разрешения, оно истекло, бюджет исчерпан, датаграмма не запрос).
    /// Ответ повторяет запрос байт в байт, кроме kind, и не длиннее его.
    pub fn echo(&self, ep: &[u8; 32], req: &[u8], now: Instant) -> Option<Vec<u8>> {
        if req.len() < HEAD || req.len() > MAX_LEN || req[..8] != MAGIC || req[8] != KIND_REQ {
            return None;
        }
        let mut g = self.0.lock().unwrap();
        let v = g.live.get_mut(ep)?;
        if v.expires <= now || v.pkts == 0 || v.bytes < req.len() as u32 {
            return None;
        }
        v.pkts -= 1;
        v.bytes -= req.len() as u32;
        let mut out = req.to_vec();
        out[8] = KIND_ECHO;
        ECHO_PKTS.fetch_add(1, Relaxed);
        ECHO_BYTES.fetch_add(out.len() as u64, Relaxed);
        Some(out)
    }

    #[cfg(test)]
    fn live(&self) -> usize {
        self.0.lock().unwrap().live.len()
    }
}

pub fn grants() -> &'static Grants {
    static G: OnceLock<Grants> = OnceLock::new();
    G.get_or_init(Grants::default)
}

/// Приёмный фильтр одного соединения (QAB-M5): ограничивает работу над магическими датаграммами и их долю, чтобы поток таких пакетов от пира,
/// которому ничего не разрешено, не держал опрос источника и не обходил burst-лимит вызывающего. Состояние на соединение, без таймеров и задач.
pub struct Filter {
    window: Instant,
    in_window: u32,
    /// съедено подряд без отдачи в RNS (бюджет работы на вызов)
    run: u32,
    /// отброшено лимитом `MAGIC_RATE` на этом соединении
    pub dropped: u64,
    /// всего магических датаграмм на этом соединении
    pub seen: u64,
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter {
    pub fn new() -> Self {
        Filter { window: Instant::now(), in_window: 0, run: 0, dropped: 0, seen: 0 }
    }

    /// Пропустить магическую датаграмму к `Grants::echo`? false - выше `MAGIC_RATE` в секунду: отбрасывается и считается.
    pub fn rate_ok(&mut self, now: Instant) -> bool {
        self.seen += 1;
        MAGIC_SEEN.fetch_add(1, Relaxed);
        if now.saturating_duration_since(self.window) >= Duration::from_secs(1) {
            self.window = now;
            self.in_window = 0;
        }
        if self.in_window >= MAGIC_RATE {
            self.dropped += 1;
            MAGIC_DROPPED.fetch_add(1, Relaxed);
            return false;
        }
        self.in_window += 1;
        true
    }

    /// Датаграмма принадлежит зонду? Тогда она обработана здесь (эхо или отброс) и в RNS не идёт.
    pub fn intercept(&mut self, conn: &Connection, datagram: &[u8]) -> bool {
        self.intercept_at(conn.remote_id().as_bytes(), datagram, Instant::now(), |echo| {
            // потеря эха - потеря одной пробы; ошибки отправки не фатальны
            let _ = conn.send_datagram(bytes::Bytes::from(echo));
        })
    }

    /// То же без соединения (для проверки): `send` получает эхо, если оно положено.
    pub fn intercept_at(&mut self, remote: &[u8; 32], datagram: &[u8], now: Instant, send: impl FnOnce(Vec<u8>)) -> bool {
        if datagram.len() < MAGIC.len() || datagram[..8] != MAGIC {
            self.run = 0;
            return false;
        }
        if self.rate_ok(now) {
            if let Some(echo) = grants().echo(remote, datagram, now) {
                send(echo);
            }
        }
        true
    }

    /// Магическая датаграмма съедена (не ушла в RNS): true - бюджет работы на вызов исчерпан, вызывающий должен отдать управление.
    pub fn ate(&mut self) -> bool {
        self.run += 1;
        if self.run >= WORK_BUDGET {
            self.run = 0;
            return true;
        }
        false
    }

    /// Обычный пакет вернулся вызывающему: серия съеденных прерывается.
    pub fn delivered(&mut self) {
        self.run = 0;
    }
}

// ------------------------------------------------------------------------------------------------ провод запроса разрешения

/// Запрос разрешения: `MAGIC | 'G' | 0 | nonce`.
pub fn grant_request(nonce: u64) -> Vec<u8> {
    let mut d = vec![0u8; HEAD];
    d[..8].copy_from_slice(&MAGIC);
    d[8] = KIND_GREQ;
    d[10..18].copy_from_slice(&nonce.to_le_bytes());
    d
}

/// Ответ на запрос разрешения: `MAGIC | 'H' | status | nonce` (nonce из запроса).
pub fn grant_reply(status: u8, nonce: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; HEAD];
    d[..8].copy_from_slice(&MAGIC);
    d[8] = KIND_GREP;
    d[9] = status;
    d[10..18].copy_from_slice(nonce);
    d
}

/// Просит у сервера разрешение на зонд через `conn` (ещё не привязанное к RNS соединение). Ok - разрешено на `GRANT_TTL` с момента ответа;
/// Err(None) - ответа нет за 2 с; Err(Some(код)) - отказ (1 слишком рано, 2 занято, 3 нет другого носителя).
pub async fn request_grant(conn: &Connection, nonce: u64) -> Result<(), Option<u8>> {
    conn.send_datagram(bytes::Bytes::from(grant_request(nonce))).map_err(|_| None)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let r = tokio::time::timeout_at(deadline, conn.read_datagram()).await.map_err(|_| None)?.map_err(|_| None)?;
        if r.len() == HEAD && r[..8] == MAGIC && r[8] == KIND_GREP && r[10..18] == nonce.to_le_bytes() {
            return if r[9] == 0 { Ok(()) } else { Err(Some(r[9])) };
        }
    }
}

// ------------------------------------------------------------------------------------------------ клиентский прогон

/// Итог прогона: сколько запросов отправлено и сколько эх с верным nonce пришло, байты проб (без рукопожатия), время до последнего эха.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProbeStats {
    pub sent: u8,
    pub echoed: u8,
    pub bytes_up: u32,
    pub bytes_down: u32,
    pub took_ms: u32,
}

/// Порог успеха: доля эх не ниже `PROBE_MIN_OK` из `PROBE_COUNT` отправленных. Недоотправленный зонд (TooLarge и т. п.) не проходит.
pub fn probe_passed(s: &ProbeStats) -> bool {
    s.sent == PROBE_COUNT && s.echoed >= PROBE_MIN_OK
}

pub(crate) fn build(idx: u8, nonce: u64, len: usize) -> Vec<u8> {
    let mut d = vec![0u8; len.max(HEAD)];
    d[..8].copy_from_slice(&MAGIC);
    d[8] = KIND_REQ;
    d[9] = idx;
    d[10..18].copy_from_slice(&nonce.to_le_bytes());
    // заполнитель по индексу: эхо должно совпасть байт в байт
    for (i, b) in d[HEAD..].iter_mut().enumerate() {
        *b = (idx as usize).wrapping_add(i) as u8;
    }
    d
}

/// Эхо на запрос (idx, nonce, len)? Проверка длины и содержимого: эхо, не равное запросу, не засчитывается.
pub fn echo_matches(d: &[u8], idx: u8, nonce: u64, len: usize) -> bool {
    d.len() == len.max(HEAD) && d[..8] == MAGIC && d[8] == KIND_ECHO && d[9] == idx && d[10..18] == nonce.to_le_bytes() && d[HEAD..] == build(idx, nonce, len)[HEAD..]
}

/// Прогнать зонд по ещё не привязанному к RNS соединению. Чётные запросы короткие, нечётные близки к MAX_LEN (ограничены `max_datagram_size`).
pub async fn run(conn: &Connection, nonce: u64) -> ProbeStats {
    let big = conn.max_datagram_size().map(|m| m.min(MAX_LEN)).unwrap_or(SMALL_LEN).max(SMALL_LEN);
    let lens: Vec<usize> = (0..PROBE_COUNT).map(|i| if i % 2 == 0 { SMALL_LEN } else { big }).collect();
    let mut st = ProbeStats::default();
    let mut got = [false; PROBE_COUNT as usize];
    let t0 = Instant::now();
    let mut next_send = tokio::time::Instant::now();
    let mut idx = 0u8;
    let mut deadline: Option<tokio::time::Instant> = None;
    loop {
        if idx < PROBE_COUNT {
            tokio::select! {
                _ = tokio::time::sleep_until(next_send) => {
                    let d = build(idx, nonce, lens[idx as usize]);
                    if conn.send_datagram(bytes::Bytes::from(d.clone())).is_ok() {
                        st.sent += 1;
                        st.bytes_up += d.len() as u32;
                    }
                    idx += 1;
                    next_send += SPACING;
                    if idx == PROBE_COUNT {
                        deadline = Some(tokio::time::Instant::now() + REPLY_WAIT);
                    }
                }
                r = conn.read_datagram() => match r {
                    Ok(b) => take_echo(&b, nonce, &lens, &mut got, &mut st),
                    Err(_) => break,
                },
            }
        } else {
            let Some(dl) = deadline else { break };
            tokio::select! {
                _ = tokio::time::sleep_until(dl) => break,
                r = conn.read_datagram() => match r {
                    Ok(b) => take_echo(&b, nonce, &lens, &mut got, &mut st),
                    Err(_) => break,
                },
            }
            if st.echoed == st.sent {
                break;
            }
        }
    }
    st.took_ms = t0.elapsed().as_millis().min(u32::MAX as u128) as u32;
    st
}

fn take_echo(b: &[u8], nonce: u64, lens: &[usize], got: &mut [bool], st: &mut ProbeStats) {
    if b.len() < HEAD {
        return;
    }
    let idx = b[9];
    if (idx as usize) < got.len() && !got[idx as usize] && echo_matches(b, idx, nonce, lens[idx as usize]) {
        got[idx as usize] = true;
        st.echoed += 1;
        st.bytes_down += b.len() as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn req(idx: u8, len: usize) -> Vec<u8> {
        build(idx, 7, len)
    }


    #[test]
    fn magic_flood_without_grant_is_counted_rate_limited_and_never_echoed() {
        let mut f = Filter::new();
        let t0 = Instant::now();
        let mut echoes = 0u32;
        let r = req(0, 40);
        for _ in 0..10_000 {
            assert!(f.intercept_at(&ep(77), &r, t0, |_| echoes += 1), "magic всегда съедается, в RNS не идёт");
        }
        assert_eq!(echoes, 0, "без разрешения эха нет");
        assert_eq!(f.seen, 10_000);
        assert_eq!(f.dropped, 10_000 - MAGIC_RATE as u64, "сверх лимита отбрасывается и считается");
        // следующая секунда - лимит обновился
        let mut after = 0u32;
        f.intercept_at(&ep(77), &r, t0 + Duration::from_millis(1100), |_| after += 1);
        assert_eq!(f.dropped, 10_000 - MAGIC_RATE as u64);
    }

    #[test]
    fn work_budget_forces_a_yield_after_a_burst_of_eaten_datagrams() {
        let mut f = Filter::new();
        let mut yields = 0;
        for _ in 0..(WORK_BUDGET * 3) {
            if f.ate() {
                yields += 1;
            }
        }
        assert_eq!(yields, 3);
        // обычный пакет прерывает серию
        for _ in 0..(WORK_BUDGET - 1) {
            assert!(!f.ate());
        }
        f.delivered();
        for _ in 0..(WORK_BUDGET - 1) {
            assert!(!f.ate());
        }
        assert!(f.ate());
    }

    // разрешённая проба проходит лимит: 8 датаграмм зонда далеко ниже MAGIC_RATE
    #[test]
    fn granted_probe_still_passes_the_rate_limit() {
        let mut f = Filter::new();
        let t0 = Instant::now();
        // проба из PROBE_COUNT датаграмм и две подряд идущие пробы за секунду укладываются в лимит (глобальный реестр разрешений тут не трогаем)
        for _ in 0..(PROBE_COUNT as u32 * 2) {
            assert!(f.rate_ok(t0));
        }
        assert_eq!(f.dropped, 0);
        assert!(PROBE_COUNT as u32 * 2 <= MAGIC_RATE);
    }

    #[test]
    fn echo_requires_a_live_grant_for_that_connection_and_never_exceeds_the_request() {
        let g = Grants::default();
        let now = Instant::now();
        let r = req(0, 40);
        assert!(g.echo(&ep(1), &r, now).is_none(), "пред-допусковый пир эха не получает");
        g.grant(ep(1), ep(100), now).unwrap();
        assert!(g.echo(&ep(2), &r, now).is_none(), "разрешение привязано к ключу соединения");
        let e = g.echo(&ep(1), &r, now).unwrap();
        assert!(e.len() <= r.len() && e.len() == r.len());
        assert!(echo_matches(&e, 0, 7, 40));
        assert_ne!(e, r, "эхо отличается от запроса только kind");
        assert_eq!(e[..8], r[..8]);
        assert_eq!(e[9..], r[9..]);
    }

    #[test]
    fn echo_ignores_malformed_oversized_and_non_request_datagrams() {
        let g = Grants::default();
        let now = Instant::now();
        g.grant(ep(1), ep(100), now).unwrap();
        assert!(g.echo(&ep(1), &req(0, 40)[..HEAD - 1], now).is_none(), "короче заголовка");
        assert!(g.echo(&ep(1), &req(0, MAX_LEN + 1), now).is_none(), "длиннее потолка");
        let mut bad = req(0, 40);
        bad[0] = 0;
        assert!(g.echo(&ep(1), &bad, now).is_none(), "не наш префикс");
        let mut echo_kind = req(0, 40);
        echo_kind[8] = KIND_ECHO;
        assert!(g.echo(&ep(1), &echo_kind, now).is_none(), "эхо на эхо не отвечаем: нет петли");
    }

    #[test]
    fn grant_budget_ttl_and_rate_are_bounded() {
        let g = Grants::default();
        let t0 = Instant::now();
        g.grant(ep(1), ep(100), t0).unwrap();
        // бюджет пакетов
        for i in 0..GRANT_PKTS {
            assert!(g.echo(&ep(1), &req(i % 8, 40), t0).is_some(), "эхо {i}");
        }
        assert!(g.echo(&ep(1), &req(0, 40), t0).is_none(), "бюджет пакетов исчерпан");
        // бюджет байт: большие запросы кончаются раньше пакетов
        let g = Grants::default();
        g.grant(ep(1), ep(100), t0).unwrap();
        let n = (0..64).take_while(|_| g.echo(&ep(1), &req(1, MAX_LEN), t0).is_some()).count();
        assert!(n >= 1 && n <= GRANT_PKTS as usize && n as u32 * MAX_LEN as u32 <= GRANT_BYTES, "эхо больших не превышает бюджет: {n}");
        // срок действия
        let g = Grants::default();
        g.grant(ep(1), ep(100), t0).unwrap();
        assert!(g.echo(&ep(1), &req(0, 40), t0 + GRANT_TTL).is_none(), "разрешение истекло");
    }

    #[test]
    fn grant_is_rate_limited_per_owner_and_per_endpoint_and_globally() {
        let t0 = Instant::now();
        let g = Grants::default();
        g.grant(ep(1), ep(100), t0).unwrap();
        // тот же владелец с другим ключом iroh: нельзя обойти сменой ключа
        assert_eq!(g.grant(ep(2), ep(100), t0 + Duration::from_secs(1)), Err(Deny::TooSoon));
        // тот же ключ iroh от другого владельца
        assert_eq!(g.grant(ep(1), ep(101), t0 + Duration::from_secs(1)), Err(Deny::TooSoon));
        // через GRANT_INTERVAL можно снова
        assert!(g.grant(ep(2), ep(100), t0 + GRANT_INTERVAL).is_ok());
        // глобально: не более MAX_LIVE живых и MAX_PER_MINUTE за минуту
        let g = Grants::default();
        let mut ok = 0;
        for i in 0..40u8 {
            if g.grant(ep(i), ep(100 + i), t0).is_ok() {
                ok += 1;
            }
        }
        assert_eq!(ok, MAX_LIVE, "одновременных разрешений не больше MAX_LIVE");
        assert_eq!(g.live(), MAX_LIVE);
        assert_eq!(g.grant(ep(50), ep(200), t0), Err(Deny::Busy));
        // истёкшие освобождают место, но минутный потолок остаётся
        let mut total = MAX_LIVE;
        for i in 0..40u8 {
            let t = t0 + GRANT_TTL + Duration::from_secs(1);
            if g.grant(ep(100 + i), ep(150 + i), t).is_ok() {
                total += 1;
            }
        }
        assert_eq!(total, MAX_PER_MINUTE, "за минуту не больше MAX_PER_MINUTE");
    }

    #[test]
    fn memory_of_grants_is_bounded() {
        let g = Grants::default();
        let t0 = Instant::now();
        // длинная череда выдач с интервалом больше окна памяти не накапливает записей
        for i in 0..2000u32 {
            let t = t0 + Duration::from_secs(i as u64 * 130);
            let mut e = [0u8; 32];
            e[..4].copy_from_slice(&i.to_le_bytes());
            assert!(g.grant(e, e, t).is_ok());
        }
        let inner = g.0.lock().unwrap();
        assert!(inner.by_ep.len() <= MAX_MEMORY && inner.by_owner.len() <= MAX_MEMORY && inner.live.len() <= MAX_LIVE && inner.minute.len() <= MAX_PER_MINUTE);
    }

    #[test]
    fn threshold_is_seven_of_eight_and_requires_everything_sent() {
        let mk = |sent, echoed| ProbeStats { sent, echoed, ..Default::default() };
        assert!(probe_passed(&mk(8, 8)) && probe_passed(&mk(8, 7)));
        assert!(!probe_passed(&mk(8, 6)) && !probe_passed(&mk(8, 0)));
        assert!(!probe_passed(&mk(7, 7)), "не все запросы ушли: не засчитывается");
    }

    #[test]
    fn only_a_byte_exact_echo_of_our_own_request_counts() {
        let q = req(3, 100);
        let mut e = q.clone();
        e[8] = KIND_ECHO;
        assert!(echo_matches(&e, 3, 7, 100));
        assert!(!echo_matches(&e, 4, 7, 100), "чужой idx");
        assert!(!echo_matches(&e, 3, 8, 100), "чужой nonce");
        assert!(!echo_matches(&e, 3, 7, 101), "длина другая");
        let mut tampered = e.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(!echo_matches(&tampered, 3, 7, 100), "содержимое изменено");
        assert!(!echo_matches(&q, 3, 7, 100), "запрос не эхо");
        let mut st = ProbeStats::default();
        let mut got = [false; 8];
        take_echo(&e, 7, &[40, 40, 40, 100, 40, 40, 40, 40], &mut got, &mut st);
        take_echo(&e, 7, &[40, 40, 40, 100, 40, 40, 40, 40], &mut got, &mut st);
        assert_eq!(st.echoed, 1, "повтор эха не засчитывается дважды");
    }

    #[test]
    fn magic_cannot_be_a_real_rns_packet_prefix() {
        // флаг IFAC в первом байте: наш пакетный интерфейс RNS без IFAC
        assert_eq!(MAGIC[0] & 0x80, 0x80);
        assert!(HEAD <= SMALL_LEN && MAX_LEN <= 1280);
    }

    // ---- loopback на двух настоящих iroh-эндпоинтах: тот же путь, что у узла (intercept до RNS), без RNS ----

    use iroh::endpoint::presets;
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

    async fn endpoint() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![b"rns/0".to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    /// Сервер: принимает одно соединение и пропускает его датаграммы через `intercept`, как `QuicDgramSource`. Возвращает, сколько датаграмм ушло бы в RNS.
    async fn serve_one(server: Endpoint) -> tokio::task::JoinHandle<u32> {
        tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let mut to_rns = 0u32;
            let mut filter = Filter::new();
            while let Ok(Ok(b)) = tokio::time::timeout(Duration::from_secs(4), conn.read_datagram()).await {
                if !filter.intercept(&conn, &b) {
                    to_rns += 1;
                }
            }
            to_rns
        })
    }

    async fn dial(client: &Endpoint, server: &Endpoint) -> Connection {
        let port = server.bound_sockets()[0].port();
        let addr = EndpointAddr::new(server.id()).with_ip_addr(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        client.connect(addr, b"rns/0").await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_probe_passes_only_with_a_grant_for_this_connection() {
        let now = Instant::now();
        // разрешение именно для ключа клиента
        let (server, client) = (endpoint().await, endpoint().await);
        let srv = serve_one(server.clone()).await;
        let conn = dial(&client, &server).await;
        grants().grant(*client.id().as_bytes(), [1; 32], now).unwrap();
        let st = run(&conn, 42).await;
        assert!(probe_passed(&st), "{st:?}");
        assert_eq!(st.sent, PROBE_COUNT);
        assert!(st.bytes_up as usize <= 4 * SMALL_LEN + 4 * MAX_LEN && st.bytes_down == st.bytes_up, "эхо не больше запроса: {st:?}");
        conn.close(0u32.into(), b"done");
        assert_eq!(srv.await.unwrap(), 0, "ни одна датаграмма зонда не попала в RNS");

        // без разрешения (пред-допусковый пир): эха нет, в RNS тоже ничего не уходит
        let (server, client) = (endpoint().await, endpoint().await);
        let srv = serve_one(server.clone()).await;
        let conn = dial(&client, &server).await;
        let st = run(&conn, 43).await;
        assert_eq!((st.echoed, probe_passed(&st)), (0, false), "{st:?}");
        conn.close(0u32.into(), b"done");
        assert_eq!(srv.await.unwrap(), 0);

        // разрешение выдано другому ключу: чужое соединение эха не получает
        let (server, client) = (endpoint().await, endpoint().await);
        let srv = serve_one(server.clone()).await;
        let conn = dial(&client, &server).await;
        grants().grant([0xAB; 32], [2; 32], now).unwrap();
        let st = run(&conn, 44).await;
        assert!(st.echoed == 0 && !probe_passed(&st), "{st:?}");
        conn.close(0u32.into(), b"done");
        assert_eq!(srv.await.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_rns_packets_pass_the_server_filter_untouched() {
        let (server, client) = (endpoint().await, endpoint().await);
        let srv = serve_one(server.clone()).await;
        let conn = dial(&client, &server).await;
        for first in [0x00u8, 0x08, 0x45, 0x7F, 0xFE] {
            conn.send_datagram(bytes::Bytes::from(vec![first; 100])).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        conn.close(0u32.into(), b"done");
        assert_eq!(srv.await.unwrap(), 5, "обычные пакеты доходят до RNS");
    }
}
