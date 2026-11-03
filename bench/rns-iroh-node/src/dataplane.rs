//! Прямой канал VPN-данных поверх того же QUIC-соединения носителя (docs/decisions/0023).
//!
//! Одно соединение iroh клиент↔выход несёт два канала: RNS-датаграммы (управление, допуск, телеметрия; `mux.rs`) и IP-пакеты VPN. Пакет VPN идёт
//! датаграммой `TAG | ip-пакет` прямо по носителю, без заголовка RNS и без шифрования Link: конфиденциальность и целостность даёт TLS 1.3 QUIC, а
//! ключ iroh соединения равен ключу подписи identity RNS (`iroh_key_from_identity`).
//!
//! Что здесь НЕ решается. Права, ACL, source-IP, HOST_ACCESS и kill switch остаются за прежним обработчиком Link-пакетов (`TunState::on_link_packet`):
//! датаграмма доходит до него под тем же `LinkId`, под которым пакет пришёл бы по Link. Этот модуль лишь отвечает на вопрос «какому допущенному Link
//! соответствует ключ, доказанный TLS соединения» и ничего не повышает: привязка создаётся только после допуска (выход: `admit_client13`; клиент:
//! `connect_exit` после AUTH_OK и проверки EXIT) и снимается вместе с Link (`TunState::disallow`, `LinkClosed`).
//!
//! Правила:
//! - ключ пира берётся только из `Connection::remote_id()`, никогда из содержимого датаграммы;
//! - нет привязки - отбросить и посчитать; датаграмма с `TAG` никогда не попадает в RNS;
//! - отправка: только если у Link есть привязка и выбранный мультиплексором носитель - живое QUIC-соединение этого же ключа; иначе (TCP-носитель, пир
//!   не сосед) пакет идёт по Link. Пакет никогда не уходит в оба пути; открытого пути без шифрования нет: нет ни QUIC, ни Link - потеря;
//! - пакет больше `max_datagram_size - 1` (`TooLarge`) по Link НЕ идёт (кроме `KNOTHOP_TOO_LARGE_LINK=1`): DF=1 - вызывающему возвращается
//!   `Tx::TooBig(mtu)` (он строит ICMP «Fragmentation Needed», `pmtu.rs`), DF=0 - пакет режется на фрагменты IPv4, каждый своей датаграммой;
//! - таблицы ограничены, замки листовые, без await под замком.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock, RwLock, Weak};

use iroh::endpoint::Connection;
use leviculum_std::api::LinkId;

use crate::mux::Mux;
use crate::pmtu;

/// Первый байт датаграммы VPN. Первый байт пакета RNS нашего интерфейса (без IFAC) имеет бит 0x80 равным нулю; `TAG` его выставляет, как и магия
/// зонда `qprobe::MAGIC[0]` (0xFF), от которой он отличается.
pub const TAG: u8 = 0xFE;
/// Минимальный IP-пакет QUIC внутри VPN: UDP-датаграмма QUIC не меньше 1200 Б + заголовки IPv4/UDP.
const QUIC_MIN_IP: usize = 1228;

/// Привязок «ключ пира ↔ Link» не больше (выход допускает не больше 256 клиентов, клиент держит единицы выходов).
const MAX_BINDINGS: usize = 1024;
/// Пиров с зарегистрированными соединениями и соединений на пира (рабочий + кандидат + запас, см. `mux::MAX_CARRIERS`).
const MAX_PEERS: usize = 1024;
const MAX_CONNS_PER_PEER: usize = 4;

/// Приёмник пакета: получает `LinkId` допущенного Link и IP-пакет (без метки). Синхронный и быстрый: вызывается из опроса мультиплексора.
pub type Sink = Arc<dyn Fn(LinkId, &[u8]) + Send + Sync>;

#[derive(Default)]
struct Binds {
    by_key: HashMap<[u8; 32], LinkId>,
    by_link: HashMap<LinkId, [u8; 32]>,
}

struct Entry {
    /// адрес мультиплексора (для снятия записи); 0 - соединение зарегистрировано напрямую (проверки)
    mux_id: usize,
    mux: Option<Weak<Mux>>,
    car: u64,
    conn: Connection,
}

#[derive(Default)]
pub struct Counters {
    /// датаграмм VPN отправлено по QUIC
    pub tx: AtomicU64,
    /// датаграмм VPN доставлено обработчику допущенного Link
    pub rx: AtomicU64,
    /// пакетов, ушедших по Link при привязанном Link (нет подходящего QUIC, TooLarge, обрыв)
    pub fallback: AtomicU64,
    /// принятых датаграмм от ключа без привязки (отброшены)
    pub unbound_drops: AtomicU64,
    /// отправок, отклонённых QUIC как слишком большие
    pub too_large: AtomicU64,
    /// отказов привязать/зарегистрировать из-за предела таблицы
    pub table_full: AtomicU64,
    /// ICMP «Fragmentation Needed» построено и отдано вызывающему (DF=1, пакет не влез)
    pub pmtu_icmp_sent: AtomicU64,
    /// ICMP не построено из-за предела частоты
    pub pmtu_icmp_limited: AtomicU64,
    /// ICMP не построено: на этот пакет отвечать нельзя (ICMP-ошибка, фрагмент, multicast...)
    pub pmtu_icmp_skipped: AtomicU64,
    /// пакетов (DF=0), разрезанных на фрагменты, и фрагментов, ушедших датаграммами
    pub frag_pkts: AtomicU64,
    pub frag_out: AtomicU64,
    /// пакетов, потерянных на границе MTU (не режутся/не отправились фрагменты); по Link они не идут
    pub pmtu_dropped: AtomicU64,
    /// выход снял DF и порезал пакет (`df_fragment`)
    pub df_cleared: AtomicU64,
}

/// Итог `Plane::try_send`.
#[derive(Debug, PartialEq, Eq)]
pub enum Tx {
    /// пакет (или все его фрагменты) ушёл прямой датаграммой; по Link слать нельзя
    Sent,
    /// прямого пути нет: слать по Link
    Link,
    /// пакет потерян (счётчик `pmtu_dropped`); по Link не слать
    Dropped,
    /// DF=1 и пакет больше предела: отправителю нужен ICMP с MTU следующего участка (значение - наибольший IP-пакет)
    TooBig(u16),
}

pub struct Plane {
    binds: RwLock<Binds>,
    conns: RwLock<HashMap<[u8; 32], Vec<Entry>>>,
    sink: RwLock<Option<Sink>>,
    tx_enabled: AtomicBool,
    /// `KNOTHOP_TOO_LARGE_LINK=1`: слишком большой пакет по-старому уходит в Link (резерв/откат); по умолчанию выключено
    link_oversize: AtomicBool,
    /// выход: пакет больше пути режется на фрагменты и при DF=1 (DF снимается) - ICMP интернет-хостам через NAT не доходит/игнорируется (v0.1.39, ru1)
    df_fragment: AtomicBool,
    icmp: std::sync::Mutex<pmtu::IcmpLimiter>,
    pub c: Counters,
}

/// Процессный экземпляр. Отправку выключает `KNOTHOP_DIRECT_DATA=0` (приём остаётся); по умолчанию включена.
pub fn plane() -> &'static Plane {
    static P: OnceLock<Plane> = OnceLock::new();
    P.get_or_init(|| {
        let p = Plane::new(std::env::var("KNOTHOP_DIRECT_DATA").map(|v| v.trim() != "0").unwrap_or(true));
        p.link_oversize.store(std::env::var("KNOTHOP_TOO_LARGE_LINK").map(|v| v.trim() == "1").unwrap_or(false), Relaxed);
        p
    })
}

/// Датаграмма принадлежит каналу VPN?
#[inline]
pub fn is_tag(datagram: &[u8]) -> bool {
    datagram.first() == Some(&TAG)
}

impl Plane {
    pub fn new(tx_enabled: bool) -> Self {
        Plane {
            binds: RwLock::new(Binds::default()),
            conns: RwLock::new(HashMap::new()),
            sink: RwLock::new(None),
            tx_enabled: AtomicBool::new(tx_enabled),
            link_oversize: AtomicBool::new(false),
            df_fragment: AtomicBool::new(false),
            icmp: std::sync::Mutex::new(pmtu::IcmpLimiter::new(std::time::Instant::now())),
            c: Counters::default(),
        }
    }

    #[cfg(test)]
    pub fn set_tx_enabled(&self, on: bool) {
        self.tx_enabled.store(on, Relaxed);
    }

    /// Выход: фрагментировать и пакеты с DF (поведение VPN-шлюза на своей стороне туннеля; клиент учит PMTU по ICMP в своём TUN).
    pub fn set_df_fragment(&self, on: bool) {
        self.df_fragment.store(on, Relaxed);
    }

    #[cfg(test)]
    pub fn set_link_oversize(&self, on: bool) {
        self.link_oversize.store(on, Relaxed);
    }

    /// Куда отдавать принятые пакеты. Узел задаёт один раз при запуске (выход - `on_link_packet`, клиент - его разбор по текущему/дополнительному Link).
    pub fn set_sink(&self, sink: Sink) {
        *self.sink.write().unwrap() = Some(sink);
    }

    // ---------------------------------------------------------------- привязки

    /// Привязать ключ пира к допущенному Link. Один ключ - один Link: прежняя привязка ключа (и прежний ключ этого Link) снимаются.
    /// Вызывать только после допуска. false - таблица заполнена (пакеты этого Link пойдут по Link).
    pub fn bind(&self, key: [u8; 32], link: LinkId) -> bool {
        let mut b = self.binds.write().unwrap();
        // Предел проверяется до любых изменений: отказ не оставляет таблицы рассогласованными. Перепривязка существующего ключа или Link
        // не увеличивает число записей.
        if !b.by_key.contains_key(&key) && !b.by_link.contains_key(&link) && b.by_key.len() >= MAX_BINDINGS {
            self.c.table_full.fetch_add(1, Relaxed);
            return false;
        }
        if let Some(old) = b.by_key.get(&key).copied() {
            if old != link {
                b.by_link.remove(&old);
            }
        }
        if let Some(old_key) = b.by_link.get(&link).copied() {
            if old_key != key {
                b.by_key.remove(&old_key);
            }
        }
        b.by_key.insert(key, link);
        b.by_link.insert(link, key);
        true
    }

    /// Снять привязку Link (закрытие, отзыв, вытеснение). Привязку, уже переданную другому Link того же ключа, не трогает.
    pub fn unbind(&self, link: &LinkId) {
        let mut b = self.binds.write().unwrap();
        if let Some(key) = b.by_link.remove(link) {
            if b.by_key.get(&key) == Some(link) {
                b.by_key.remove(&key);
            }
        }
    }

    pub fn link_of(&self, key: &[u8; 32]) -> Option<LinkId> {
        self.binds.read().unwrap().by_key.get(key).copied()
    }

    pub fn key_of(&self, link: &LinkId) -> Option<[u8; 32]> {
        self.binds.read().unwrap().by_link.get(link).copied()
    }

    pub fn bindings(&self) -> usize {
        self.binds.read().unwrap().by_key.len()
    }

    // ---------------------------------------------------------------- соединения носителей

    /// Запомнить живое QUIC-соединение носителя (из `Mux::add_quic`). Ключ - `conn.remote_id()`, доказан TLS.
    pub(crate) fn register(&self, mux: &Arc<Mux>, car: u64, conn: &Connection) {
        self.register_entry(Entry { mux_id: Arc::as_ptr(mux) as usize, mux: Some(Arc::downgrade(mux)), car, conn: conn.clone() });
    }

    /// Соединение без мультиплексора (проверки): считается выбранным, пока живо.
    #[cfg(test)]
    fn register_plain(&self, conn: &Connection) {
        self.register_entry(Entry { mux_id: 0, mux: None, car: 0, conn: conn.clone() });
    }

    fn register_entry(&self, e: Entry) {
        let key = *e.conn.remote_id().as_bytes();
        let mut m = self.conns.write().unwrap();
        // старые записи: закрытые соединения и умершие мультиплексоры
        for v in m.values_mut() {
            v.retain(|x| x.conn.close_reason().is_none() && x.mux.as_ref().map_or(true, |w| w.strong_count() > 0));
        }
        m.retain(|_, v| !v.is_empty());
        if !m.contains_key(&key) && m.len() >= MAX_PEERS {
            self.c.table_full.fetch_add(1, Relaxed);
            return;
        }
        let v = m.entry(key).or_default();
        v.retain(|x| !(x.mux_id == e.mux_id && x.car == e.car));
        if v.len() >= MAX_CONNS_PER_PEER {
            self.c.table_full.fetch_add(1, Relaxed);
            return;
        }
        v.push(e);
    }

    /// Носитель `car` мультиплексора `mux_id` закончился.
    pub(crate) fn unregister(&self, peer: &[u8; 32], mux_id: usize, car: u64) {
        let mut m = self.conns.write().unwrap();
        if let Some(v) = m.get_mut(peer) {
            v.retain(|x| !(x.mux_id == mux_id && x.car == car));
            if v.is_empty() {
                m.remove(peer);
            }
        }
    }

    /// Живое QUIC-соединение к ключу, которое мультиплексор выбрал рабочим носителем. Выбран TCP (или ничего) - None: данные идут по Link.
    fn carrier(&self, key: &[u8; 32]) -> Option<Connection> {
        self.carrier_filtered(key, |_| true)
    }

    /// Как `carrier`, но среди соединений, подходящих под `ok` (mesh исключает сквозные соединения, которые сами идут по mesh).
    pub(crate) fn carrier_filtered(&self, key: &[u8; 32], ok: impl Fn(&Connection) -> bool) -> Option<Connection> {
        // Порядок замков: `Mux::remove`/`close` держат `Mux::st` и вызывают `unregister` (`conns.write`). Поэтому под `conns` в мультиплексор не
        // заходим: копируем кандидатов (не больше MAX_CONNS_PER_PEER) и проверяем выбор носителя уже без замка `conns`. По той же причине `ok`
        // (он может читать состояние соединения) тоже вызывается без замка `conns`.
        let cands: Vec<(Option<Weak<Mux>>, u64, Connection)> = {
            let m = self.conns.read().unwrap();
            m.get(key)?.iter().filter(|e| e.conn.close_reason().is_none()).map(|e| (e.mux.clone(), e.car, e.conn.clone())).collect()
        };
        cands.into_iter().filter(|(_, _, conn)| ok(conn)).find_map(|(mux, car, conn)| {
            let selected = match mux {
                None => true,
                Some(w) => w.upgrade().is_some_and(|mx| mx.carrier_selected(car)),
            };
            selected.then_some(conn)
        })
    }

    /// Выбранный QUIC-носитель к ключу (для статуса: путь и RTT берутся из его статистики).
    pub fn carrier_conn(&self, key: &[u8; 32]) -> Option<Connection> {
        self.carrier(key)
    }

    /// Есть ли выбранный QUIC-носитель к ключу (любой, в том числе сквозной по mesh).
    pub fn has_carrier(&self, key: &[u8; 32]) -> bool {
        self.carrier(key).is_some()
    }

    // ---------------------------------------------------------------- отправка

    /// Отправить IP-пакет Link `link` прямой датаграммой. `Tx::Sent` - ушёл (по Link слать нельзя), `Tx::Link` - слать по Link: привязки нет,
    /// отправка выключена, нет подходящего QUIC-носителя. Пакет больше датаграммы пути обрабатывает `oversize`. Горячий путь: одна аллокация
    /// `TAG | пакет` и один `send_datagram`; проверка длины делается внутри QUIC, лишних обращений к соединению нет.
    pub fn try_send(&self, link: &LinkId, pkt: &[u8]) -> Tx {
        if !self.tx_enabled.load(Relaxed) {
            return Tx::Link;
        }
        let Some(key) = self.key_of(link) else { return Tx::Link };
        let Some(conn) = self.carrier(&key) else {
            self.c.fallback.fetch_add(1, Relaxed);
            return Tx::Link;
        };
        match Self::send_tagged(&conn, pkt) {
            Ok(()) => {
                self.c.tx.fetch_add(1, Relaxed);
                Tx::Sent
            }
            Err(iroh::endpoint::SendDatagramError::TooLarge) => {
                self.c.too_large.fetch_add(1, Relaxed);
                self.oversize(&conn, pkt)
            }
            Err(_) => {
                self.c.fallback.fetch_add(1, Relaxed);
                Tx::Link
            }
        }
    }

    fn send_tagged(conn: &Connection, pkt: &[u8]) -> Result<(), iroh::endpoint::SendDatagramError> {
        let mut buf = Vec::with_capacity(1 + pkt.len());
        buf.push(TAG);
        buf.extend_from_slice(pkt);
        conn.send_datagram(bytes::Bytes::from(buf))
    }

    /// Пакет не поместился в датаграмму. Резерв `KNOTHOP_TOO_LARGE_LINK=1` или нет датаграмм вообще (`max_datagram_size` = None) - Link, как раньше.
    /// Иначе поведение маршрутизатора: DF=1 - `TooBig(предел)` (вызывающий строит ICMP), DF=0 - IPv4-фрагментация; в Link пакет не идёт.
    fn oversize(&self, conn: &Connection, pkt: &[u8]) -> Tx {
        let limit = match conn.max_datagram_size() {
            Some(m) if !self.link_oversize.load(Relaxed) => m.saturating_sub(1),
            _ => {
                self.c.fallback.fetch_add(1, Relaxed);
                return Tx::Link;
            }
        };
        if pkt.len() < 20 {
            self.c.pmtu_dropped.fetch_add(1, Relaxed);
            return Tx::Dropped;
        }
        if pkt.len() <= limit {
            // предел успел вырасти между отказом и чтением: одна повторная отправка
            return match Self::send_tagged(conn, pkt) {
                Ok(()) => {
                    self.c.tx.fetch_add(1, Relaxed);
                    Tx::Sent
                }
                Err(_) => {
                    self.c.pmtu_dropped.fetch_add(1, Relaxed);
                    Tx::Dropped
                }
            };
        }
        if pkt[0] >> 4 != 4 {
            // не IPv4 (TUN несёт только IPv4, но на всякий случай): разбирать флаги нельзя - прежний резерв
            self.c.fallback.fetch_add(1, Relaxed);
            return Tx::Link;
        }
        let cleared;
        let pkt = if pkt[6] & 0x40 != 0 && self.df_fragment.load(Relaxed) {
            // выход: DF снимаем, фрагменты получают новые контрольные суммы в `pmtu::fragment`
            let mut v = pkt.to_vec();
            v[6] &= !0x40;
            self.c.df_cleared.fetch_add(1, Relaxed);
            cleared = v;
            &cleared[..]
        } else {
            pkt
        };
        if pkt[6] & 0x40 != 0 {
            // UDP с DF при пределе ниже минимального пакета QUIC (1200 + 28): ICMP не поможет - QUIC внутри VPN встал бы совсем.
            // До фрагментации на уровне туннеля такие пакеты везёт Link (редкий случай: путь сжат до минимума QUIC).
            if pkt[9] == 17 && limit < QUIC_MIN_IP {
                self.c.fallback.fetch_add(1, Relaxed);
                return Tx::Link;
            }
            return Tx::TooBig(limit.min(usize::from(u16::MAX)) as u16);
        }
        match pmtu::fragment(pkt, limit) {
            Ok(frags) => {
                let mut sent = 0u64;
                for f in &frags {
                    if Self::send_tagged(conn, f).is_err() {
                        break; // предел снова упал: остаток теряется, по Link не идёт (дубликатов нет)
                    }
                    sent += 1;
                }
                self.c.frag_out.fetch_add(sent, Relaxed);
                self.c.tx.fetch_add(sent, Relaxed);
                if sent as usize == frags.len() {
                    self.c.frag_pkts.fetch_add(1, Relaxed);
                } else {
                    self.c.pmtu_dropped.fetch_add(1, Relaxed);
                }
                Tx::Sent
            }
            Err(_) => {
                self.c.pmtu_dropped.fetch_add(1, Relaxed);
                Tx::Dropped
            }
        }
    }

    /// ICMP «Fragmentation Needed» для `orig` (источник ответа `src`): учитывает допустимость, предел частоты и счётчики. None - не отправлять.
    pub fn frag_needed(&self, orig: &[u8], mtu: u16, src: [u8; 4]) -> Option<Vec<u8>> {
        if !pmtu::icmp_eligible(orig) {
            self.c.pmtu_icmp_skipped.fetch_add(1, Relaxed);
            return None;
        }
        let dst: [u8; 4] = orig[12..16].try_into().unwrap();
        if !self.icmp.lock().unwrap().allow(dst, std::time::Instant::now()) {
            self.c.pmtu_icmp_limited.fetch_add(1, Relaxed);
            return None;
        }
        let r = pmtu::build_frag_needed(orig, mtu, src);
        if r.is_some() {
            self.c.pmtu_icmp_sent.fetch_add(1, Relaxed);
        }
        r
    }

    // ---------------------------------------------------------------- приём

    /// Принять тело датаграммы (без метки) от соединения с ключом `peer` (из `remote_id()`). Нет привязки - отбросить. Иначе пакет уходит тому же
    /// обработчику, что и пакеты этого Link; окончательную проверку (allowed, source-IP, ACL, HOST_ACCESS) делает он.
    pub fn on_datagram(&self, peer: &[u8; 32], body: &[u8]) {
        let Some(link) = self.link_of(peer) else {
            self.c.unbound_drops.fetch_add(1, Relaxed);
            return;
        };
        let sink = self.sink.read().unwrap().clone();
        let Some(sink) = sink else {
            self.c.unbound_drops.fetch_add(1, Relaxed);
            return;
        };
        self.c.rx.fetch_add(1, Relaxed);
        sink(link, body);
    }

    pub fn stats(&self) -> serde_json::Value {
        let (min_mds, total_bh, mtu_drops, nat_suppressed) = {
            let m = self.conns.read().unwrap();
            let mut mds: Option<usize> = None;
            let mut bh = 0u64;
            let mut mtu_drops = 0u64;
            let mut nat_suppressed = 0u64;
            for v in m.values() {
                for e in v.iter().filter(|e| e.conn.close_reason().is_none()) {
                    let cs = e.conn.stats();
                    mtu_drops = mtu_drops.saturating_add(cs.datagram_mtu_drops);
                    nat_suppressed = nat_suppressed.saturating_add(cs.nat_probes_suppressed);
                    if let Some(sz) = e.conn.max_datagram_size() {
                        mds = Some(mds.map_or(sz, |m| m.min(sz)));
                    }
                    for p in e.conn.paths().iter() {
                        bh += p.stats().black_holes_detected;
                    }
                }
            }
            (mds, bh, mtu_drops, nat_suppressed)
        };
        serde_json::json!({
            "tx": self.c.tx.load(Relaxed), "rx": self.c.rx.load(Relaxed), "fallback": self.c.fallback.load(Relaxed),
            "unbound_drops": self.c.unbound_drops.load(Relaxed), "too_large": self.c.too_large.load(Relaxed),
            "table_full": self.c.table_full.load(Relaxed),
            "bindings": self.bindings(), "tx_enabled": self.tx_enabled.load(Relaxed),
            "max_datagram_size": min_mds,
            "black_holes_detected": total_bh,
            "datagram_mtu_drops": mtu_drops,
            "nat_probes_suppressed": nat_suppressed,
            "pmtu_icmp_sent": self.c.pmtu_icmp_sent.load(Relaxed), "pmtu_icmp_limited": self.c.pmtu_icmp_limited.load(Relaxed),
            "pmtu_icmp_skipped": self.c.pmtu_icmp_skipped.load(Relaxed),
            "frag_pkts": self.c.frag_pkts.load(Relaxed), "frag_out": self.c.frag_out.load(Relaxed),
            "pmtu_dropped": self.c.pmtu_dropped.load(Relaxed), "df_cleared": self.c.df_cleared.load(Relaxed), "too_large_link": self.link_oversize.load(Relaxed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    use iroh::endpoint::presets;
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

    fn lid(n: u8) -> LinkId {
        LinkId::new([n; 16])
    }

    #[test]
    fn tag_never_collides_with_rns_or_probe_prefix() {
        assert_ne!(TAG, crate::qprobe::MAGIC[0]);
        // флаг IFAC (0x80) у пакетов нашего интерфейса без IFAC всегда сброшен: ни TAG, ни магия зонда настоящим пакетом RNS быть не могут
        assert_eq!(TAG & 0x80, 0x80);
        assert_eq!(crate::qprobe::MAGIC[0] & 0x80, 0x80);
        // и IP-пакеты (0x45..) и RNS-заголовки без IFAC (0x00..0x7F) метку не дают
        for b in 0u8..=0x7F {
            assert_ne!(b, TAG);
        }
        assert!(is_tag(&[TAG, 1, 2]) && !is_tag(&[0x45]) && !is_tag(&[]));
    }

    #[test]
    fn bind_unbind_rebind_and_limit() {
        let p = Plane::new(true);
        let (k1, k2) = ([1u8; 32], [2u8; 32]);
        assert!(p.bind(k1, lid(1)));
        assert_eq!((p.link_of(&k1), p.key_of(&lid(1))), (Some(lid(1)), Some(k1)));
        // один ключ - один Link: новый Link вытесняет старый
        assert!(p.bind(k1, lid(2)));
        assert_eq!((p.link_of(&k1), p.key_of(&lid(1)), p.key_of(&lid(2))), (Some(lid(2)), None, Some(k1)));
        // снятие вытесненного Link новую привязку не трогает
        p.unbind(&lid(1));
        assert_eq!(p.link_of(&k1), Some(lid(2)));
        // тот же Link под другим ключом: прежний ключ освобождается
        assert!(p.bind(k2, lid(2)));
        assert_eq!((p.link_of(&k1), p.link_of(&k2)), (None, Some(lid(2))));
        p.unbind(&lid(2));
        assert_eq!((p.link_of(&k2), p.key_of(&lid(2)), p.bindings()), (None, None, 0));
        // предел: сверх него отказ, существующее переживает
        let p = Plane::new(true);
        for i in 0..MAX_BINDINGS {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut l = [0u8; 16];
            l[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(p.bind(k, LinkId::new(l)));
        }
        assert_eq!(p.bindings(), MAX_BINDINGS);
        assert!(!p.bind([0xEE; 32], lid(0xEE)), "сверх предела - отказ");
        assert_eq!(p.link_of(&[0xEE; 32]), None);
        assert_eq!(p.c.table_full.load(Relaxed), 1);
        // существующий ключ перепривязывается и при полной таблице
        let mut k0 = [0u8; 32];
        k0[..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(p.bind(k0, lid(0xAA)));
        assert_eq!(p.bindings(), MAX_BINDINGS);
    }

    type Log = Arc<Mutex<Vec<(LinkId, Vec<u8>)>>>;

    fn with_sink(p: &Plane) -> Log {
        let log: Log = Arc::default();
        let l2 = log.clone();
        p.set_sink(Arc::new(move |l, b| l2.lock().unwrap().push((l, b.to_vec()))));
        log
    }

    #[test]
    fn datagram_from_unbound_key_is_dropped_and_unbind_stops_delivery() {
        let p = Plane::new(true);
        let log = with_sink(&p);
        let k = [7u8; 32];
        p.on_datagram(&k, &[0x45, 0, 0]);
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(p.c.unbound_drops.load(Relaxed), 1);

        assert!(p.bind(k, lid(5)));
        p.on_datagram(&k, &[0x45, 1]);
        // чужой ключ при чужой привязке не доставляется
        p.on_datagram(&[8u8; 32], &[0x45, 2]);
        assert_eq!(log.lock().unwrap().as_slice(), &[(lid(5), vec![0x45, 1])]);
        assert_eq!((p.c.rx.load(Relaxed), p.c.unbound_drops.load(Relaxed)), (1, 2));

        // drop_link_state / disallow снимают привязку: пакет больше не доходит
        p.unbind(&lid(5));
        p.on_datagram(&k, &[0x45, 3]);
        assert_eq!(log.lock().unwrap().len(), 1);
        assert_eq!(p.c.unbound_drops.load(Relaxed), 3);
        // без приёмника тоже отброс
        let p2 = Plane::new(true);
        p2.bind(k, lid(5));
        p2.on_datagram(&k, &[0x45]);
        assert_eq!(p2.c.rx.load(Relaxed), 0);
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    /// Привязка осталась, а допуска в TUN нет (отзыв/гонка): окончательная проверка выхода пакет отбрасывает, в TUN он не попадает.
    #[test]
    fn revoked_link_is_dropped_by_tun_even_if_binding_remains() {
        let tun = crate::TunState::build(true, None);
        tun.enforce.store(true, Relaxed);
        let p = Plane::new(true);
        let t2 = tun.clone();
        p.set_sink(Arc::new(move |l, b| t2.on_link_packet_with(&|_| panic!("в принудительном режиме обратный маршрут не строится"), l, b)));
        let k = [9u8; 32];
        p.bind(k, lid(3));
        let pkt = ipv4([10, 99, 0, 7], [8, 8, 8, 8]);
        p.on_datagram(&k, &pkt);
        assert_eq!(p.c.rx.load(Relaxed), 1, "привязка есть - обработчику отдано");
        assert_eq!(tun.c.unauth_drops.load(Relaxed), 1, "allowed[link] нет - отброшено прежней проверкой");
        assert_eq!(tun.c.to_tun_pkts.load(Relaxed) + tun.c.tun_write_drops.load(Relaxed), 0, "до TUN не дошло");
    }

    // ---------------------------------------------------------------- loopback на настоящих эндпоинтах iroh

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

    async fn pair() -> (Endpoint, Endpoint, Connection, Connection) {
        let (server, client) = (endpoint().await, endpoint().await);
        let addr = EndpointAddr::new(server.id()).with_ip_addr(std::net::SocketAddr::from(([127, 0, 0, 1], server.bound_sockets()[0].port())));
        let incoming = async { server.accept().await.unwrap().await.unwrap() };
        let (c, s) = tokio::join!(client.connect(addr, b"rns/0"), incoming);
        (server, client, c.unwrap(), s)
    }

    /// Носитель с RNS-датаграммами и датаграммами VPN одновременно: RNS не теряется и не попадает в приёмник VPN, метка не попадает в RNS.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_rns_and_vpn_datagrams_share_one_connection() {
        let (_server, client, cconn, sconn) = pair().await;
        let plane = Arc::new(Plane::new(true));
        let log = with_sink(&plane);
        // клиентский ключ iroh привязан к Link выхода: ключ берётся из TLS соединения, а не из содержимого
        assert_eq!(sconn.remote_id(), client.id());
        plane.bind(*sconn.remote_id().as_bytes(), lid(1));

        let rns: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let (p2, r2) = (plane.clone(), rns.clone());
        let reader = tokio::spawn(async move {
            // тот же выбор, что в `MuxSource`: метка уходит в плоскость данных, остальное - в RNS
            while let Ok(Ok(b)) = tokio::time::timeout(Duration::from_secs(2), sconn.read_datagram()).await {
                if is_tag(&b) {
                    p2.on_datagram(sconn.remote_id().as_bytes(), &b[1..]);
                } else {
                    r2.lock().unwrap().push(b.to_vec());
                }
            }
        });

        const N: usize = 40;
        for i in 0..N {
            // «RNS»: первый байт без IFAC; «VPN» через try_send клиента
            let mut r = vec![0x08u8; 60];
            r[1] = i as u8;
            cconn.send_datagram(bytes::Bytes::from(r)).unwrap();
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // клиентская плоскость: Link 9 привязан к ключу выхода, соединение зарегистрировано
        let cplane = Plane::new(true);
        cplane.register_plain(&cconn);
        assert!(cplane.bind(*cconn.remote_id().as_bytes(), lid(9)));
        for i in 0..N {
            let mut pkt = ipv4([10, 99, 0, 2], [1, 1, 1, 1]);
            pkt[4] = i as u8;
            assert_eq!(cplane.try_send(&lid(9), &pkt), Tx::Sent);
            let mut r = vec![0x08u8; 60];
            r[1] = (100 + i) as u8;
            cconn.send_datagram(bytes::Bytes::from(r)).unwrap();
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        cconn.close(0u32.into(), b"done");
        reader.await.unwrap();

        let rns = rns.lock().unwrap();
        assert_eq!(rns.len(), 2 * N, "RNS-датаграммы не потеряны");
        assert!(rns.iter().all(|d| d[0] == 0x08), "метка VPN не попала в RNS");
        let vpn = log.lock().unwrap();
        assert_eq!(vpn.len(), N, "каждая датаграмма VPN дошла");
        assert!(vpn.iter().all(|(l, b)| *l == lid(1) && b.len() == 28 && b[0] == 0x45), "в приёмник VPN попали только IP-пакеты, под Link выхода");
        assert_eq!(cplane.c.tx.load(Relaxed), N as u64);
        assert_eq!(plane.c.unbound_drops.load(Relaxed), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_falls_back_without_duplicating() {
        let (_server, _client, cconn, _sconn) = pair().await;
        let p = Plane::new(true);
        let key = *cconn.remote_id().as_bytes();
        let pkt = ipv4([10, 99, 0, 2], [1, 1, 1, 1]);

        // Link без привязки: плоскость молчит, счётчики не двигаются
        assert_eq!(p.try_send(&lid(1), &pkt), Tx::Link);
        assert_eq!((p.c.fallback.load(Relaxed), p.c.tx.load(Relaxed)), (0, 0));
        // привязка есть, соединения нет
        p.bind(key, lid(1));
        assert_eq!(p.try_send(&lid(1), &pkt), Tx::Link);
        assert_eq!(p.c.fallback.load(Relaxed), 1);
        // соединение есть: ушло ровно один раз
        p.register_plain(&cconn);
        assert_eq!(p.try_send(&lid(1), &pkt), Tx::Sent);
        assert_eq!((p.c.tx.load(Relaxed), p.c.fallback.load(Relaxed)), (1, 1));
        // слишком большая датаграмма с DF (0x45 в байте флагов даёт DF=1): не в Link, а TooBig(max_datagram_size - 1)
        let big = vec![0x45u8; 4000];
        let limit = (cconn.max_datagram_size().unwrap() - 1) as u16;
        assert_eq!(p.try_send(&lid(1), &big), Tx::TooBig(limit));
        assert_eq!((p.c.too_large.load(Relaxed), p.c.fallback.load(Relaxed), p.c.tx.load(Relaxed)), (1, 1, 1));
        // резерв KNOTHOP_TOO_LARGE_LINK=1 возвращает старое поведение
        p.set_link_oversize(true);
        assert_eq!(p.try_send(&lid(1), &big), Tx::Link);
        assert_eq!((p.c.too_large.load(Relaxed), p.c.fallback.load(Relaxed), p.c.tx.load(Relaxed)), (2, 2, 1));
        p.set_link_oversize(false);
        // выключатель
        p.set_tx_enabled(false);
        assert_eq!(p.try_send(&lid(1), &pkt), Tx::Link);
        assert_eq!(p.c.tx.load(Relaxed), 1);
        p.set_tx_enabled(true);
        // после unbind привязки нет: слать нечем, остаётся Link
        p.unbind(&lid(1));
        assert_eq!(p.try_send(&lid(1), &pkt), Tx::Link);
        // закрытое соединение не выбирается
        p.bind(key, lid(1));
        cconn.close(0u32.into(), b"done");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(p.try_send(&lid(1), &pkt), Tx::Link);
    }

    fn ip_with(src: [u8; 4], dst: [u8; 4], payload_len: usize, flags_off: u16) -> Vec<u8> {
        let mut p = vec![0u8; 20 + payload_len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
        p[4..6].copy_from_slice(&0x4321u16.to_be_bytes());
        p[6..8].copy_from_slice(&flags_off.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        let c = pmtu::csum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        for (i, b) in p[20..].iter_mut().enumerate() {
            *b = (i % 253) as u8;
        }
        p
    }

    /// Большой пакет без DF: фрагменты доходят датаграммами с меткой, собираются в оригинал, в Link ничего не уходит.
    /// Большой с DF: `TooBig`, на wire ничего. ICMP строится по пределу соединения.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversize_df0_is_fragmented_and_df1_gets_icmp_input() {
        let (_server, _client, cconn, sconn) = pair().await;
        let p = Plane::new(true);
        let key = *cconn.remote_id().as_bytes();
        p.register_plain(&cconn);
        p.bind(key, lid(1));
        let (src, dst) = ([198, 18, 0, 5], [93, 184, 216, 34]);

        let orig = ip_with(src, dst, 3000, 0);
        assert_eq!(p.try_send(&lid(1), &orig), Tx::Sent);
        let n = p.c.frag_out.load(Relaxed) as usize;
        assert!(n >= 3, "3020 Б в датаграммы ~1160: {n}");
        assert_eq!((p.c.frag_pkts.load(Relaxed), p.c.fallback.load(Relaxed), p.c.pmtu_dropped.load(Relaxed)), (1, 0, 0));
        let limit = cconn.max_datagram_size().unwrap() - 1;
        let mut frags = Vec::new();
        for _ in 0..n {
            let d = tokio::time::timeout(Duration::from_secs(2), sconn.read_datagram()).await.unwrap().unwrap();
            assert!(is_tag(&d));
            frags.push(d[1..].to_vec());
        }
        assert!(frags.iter().all(|f| f.len() <= limit + 64), "куски не длиннее предела (предел мог вырасти)");
        let mut back = Vec::new();
        let mut off = 0usize;
        for f in &frags {
            assert_eq!(pmtu::csum(&f[..20]), 0);
            let fl = u16::from_be_bytes([f[6], f[7]]);
            assert_eq!(usize::from(fl & 0x1fff) * 8, off);
            back.extend_from_slice(&f[20..]);
            off += f.len() - 20;
        }
        assert_eq!(back, orig[20..]);

        // DF=1: ничего не отправлено, предел вернулся вызывающему; ICMP строится и принимается плоскостью частоты
        let tx_before = p.c.tx.load(Relaxed);
        let df = ip_with(src, dst, 3000, 0x4000);
        let Tx::TooBig(mtu) = p.try_send(&lid(1), &df) else { panic!("ждали TooBig") };
        assert_eq!(usize::from(mtu), cconn.max_datagram_size().unwrap() - 1);
        assert_eq!(p.c.tx.load(Relaxed), tx_before);
        let icmp = p.frag_needed(&df, mtu, [10, 99, 0, 1]).unwrap();
        assert_eq!((icmp[20], icmp[21]), (3, 4));
        assert_eq!(u16::from_be_bytes([icmp[26], icmp[27]]), mtu);
        assert_eq!(&icmp[16..20], &src);
        assert_eq!(p.c.pmtu_icmp_sent.load(Relaxed), 1);
        assert_eq!(p.stats()["pmtu_icmp_sent"], 1);
        // ответ на ICMP-ошибку не строится и не тратит бюджет
        let mut err = ip_with(src, dst, 3000, 0x4000);
        err[9] = 1;
        err[20] = 3;
        assert!(p.frag_needed(&err, mtu, [10, 99, 0, 1]).is_none());
        assert_eq!(p.c.pmtu_icmp_skipped.load(Relaxed), 1);
        // предел частоты на адрес: 10 подряд, остальные отказ
        let ok = (0..30).filter(|_| p.frag_needed(&df, mtu, [10, 99, 0, 1]).is_some()).count();
        assert!((9..=10).contains(&ok), "один токен уже потрачен выше (+ возможное пополнение): {ok}");
        assert_eq!(p.c.pmtu_icmp_limited.load(Relaxed), 30 - ok as u64);

        // выход (`df_fragment`): DF=1 тоже режется, DF в кусках снят, собирается в оригинал
        p.set_df_fragment(true);
        let out0 = p.c.frag_out.load(Relaxed) as usize;
        assert_eq!(p.try_send(&lid(1), &df), Tx::Sent);
        assert_eq!(p.c.df_cleared.load(Relaxed), 1);
        let n = p.c.frag_out.load(Relaxed) as usize - out0;
        let mut back = Vec::new();
        for _ in 0..n {
            let d = tokio::time::timeout(Duration::from_secs(2), sconn.read_datagram()).await.unwrap().unwrap();
            let f = &d[1..];
            assert_eq!(pmtu::csum(&f[..20]), 0);
            assert_eq!(f[6] & 0x40, 0, "DF снят");
            back.extend_from_slice(&f[20..]);
        }
        assert_eq!(back, df[20..]);
    }

    /// Ядро Linux принимает построенный ICMP: после доставки локальному адресу `ip route get` показывает `mtu` из ICMP.
    /// Запуск: `unshare -rn sh -c 'ip link set lo up; KH_NETNS=1 bash bench/cargo_fork.sh rns-iroh-node test --offline --locked --lib dataplane::tests::kernel_accepts -- --ignored --nocapture'`.
    #[test]
    #[ignore = "нужен приватный netns (unshare -rn)"]
    fn kernel_accepts_frag_needed_and_records_pmtu() {
        assert!(std::env::var("KH_NETNS").is_ok(), "только в приватном netns");
        let ip = |args: &[&str]| {
            let o = std::process::Command::new("ip").args(args).output().unwrap();
            assert!(o.status.success(), "ip {args:?}: {}", String::from_utf8_lossy(&o.stderr));
            String::from_utf8_lossy(&o.stdout).to_string()
        };
        ip(&["link", "add", "d0", "type", "dummy"]);
        ip(&["link", "set", "d0", "up"]);
        ip(&["addr", "add", "198.18.0.5/32", "dev", "d0"]);
        ip(&["route", "add", "1.1.1.1/32", "dev", "d0"]);
        let before = ip(&["-4", "route", "get", "1.1.1.1"]);
        assert!(!before.contains("mtu"), "{before}");

        // ядро применяет PMTU по ICMP через обработчик протокола: нужен подключённый UDP-сокет, чьи порты стоят в цитате
        let sock = std::net::UdpSocket::bind("198.18.0.5:0").unwrap();
        sock.connect("1.1.1.1:9").unwrap();
        let port = sock.local_addr().unwrap().port();
        let p = Plane::new(true);
        let mut orig = ip_with([198, 18, 0, 5], [93, 184, 216, 34], 1308, 0x4000);
        orig[20..22].copy_from_slice(&port.to_be_bytes());
        orig[22..24].copy_from_slice(&9u16.to_be_bytes());
        orig[24..26].copy_from_slice(&1308u16.to_be_bytes());
        // источник - адрес выхода в туннеле, как на клиенте
        let icmp = p.frag_needed(&orig, 1161, [10, 99, 0, 1]).unwrap();
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
            assert!(fd >= 0, "raw socket: {}", std::io::Error::last_os_error());
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([198, 18, 0, 5]) },
                sin_zero: [0; 8],
            };
            let n = libc::sendto(fd, icmp.as_ptr() as *const _, icmp.len(), 0, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32);
            assert_eq!(n, icmp.len() as isize, "sendto: {}", std::io::Error::last_os_error());
            libc::close(fd);
        }
        std::thread::sleep(Duration::from_millis(200));
        let after = ip(&["-4", "route", "get", "1.1.1.1"]);
        println!("[kernel pmtu] {after}");
        assert!(after.contains("mtu 1161"), "ядро не приняло PMTU: {after}");
    }
}
