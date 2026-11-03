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
//!   не сосед, `TooLarge`) пакет идёт по Link. Пакет никогда не уходит в оба пути; открытого пути без шифрования нет: нет ни QUIC, ни Link - потеря;
//! - таблицы ограничены, замки листовые, без await под замком.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock, RwLock, Weak};

use iroh::endpoint::Connection;
use leviculum_std::api::LinkId;

use crate::mux::Mux;

/// Первый байт датаграммы VPN. Первый байт пакета RNS нашего интерфейса (без IFAC) имеет бит 0x80 равным нулю; `TAG` его выставляет, как и магия
/// зонда `qprobe::MAGIC[0]` (0xFF), от которой он отличается.
pub const TAG: u8 = 0xFE;

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
}

pub struct Plane {
    binds: RwLock<Binds>,
    conns: RwLock<HashMap<[u8; 32], Vec<Entry>>>,
    sink: RwLock<Option<Sink>>,
    tx_enabled: AtomicBool,
    pub c: Counters,
}

/// Процессный экземпляр. Отправку выключает `KNOTHOP_DIRECT_DATA=0` (приём остаётся); по умолчанию включена.
pub fn plane() -> &'static Plane {
    static P: OnceLock<Plane> = OnceLock::new();
    P.get_or_init(|| Plane::new(std::env::var("KNOTHOP_DIRECT_DATA").map(|v| v.trim() != "0").unwrap_or(true)))
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
            c: Counters::default(),
        }
    }

    #[cfg(test)]
    pub fn set_tx_enabled(&self, on: bool) {
        self.tx_enabled.store(on, Relaxed);
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

    /// Отправить IP-пакет Link `link` прямой датаграммой. true - пакет ушёл (по Link его слать нельзя). false - слать по Link: привязки нет,
    /// отправка выключена, нет подходящего QUIC-носителя или датаграмма не поместилась. Пакет не копируется дважды: одна аллокация `TAG | пакет`.
    pub fn try_send(&self, link: &LinkId, pkt: &[u8]) -> bool {
        if !self.tx_enabled.load(Relaxed) {
            return false;
        }
        let Some(key) = self.key_of(link) else { return false };
        let Some(conn) = self.carrier(&key) else {
            self.c.fallback.fetch_add(1, Relaxed);
            return false;
        };
        let mut buf = Vec::with_capacity(1 + pkt.len());
        buf.push(TAG);
        buf.extend_from_slice(pkt);
        match conn.send_datagram(bytes::Bytes::from(buf)) {
            Ok(()) => {
                self.c.tx.fetch_add(1, Relaxed);
                true
            }
            Err(e) => {
                if matches!(e, iroh::endpoint::SendDatagramError::TooLarge) {
                    self.c.too_large.fetch_add(1, Relaxed);
                }
                self.c.fallback.fetch_add(1, Relaxed);
                false
            }
        }
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
            assert!(cplane.try_send(&lid(9), &pkt));
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
        assert!(!p.try_send(&lid(1), &pkt));
        assert_eq!((p.c.fallback.load(Relaxed), p.c.tx.load(Relaxed)), (0, 0));
        // привязка есть, соединения нет
        p.bind(key, lid(1));
        assert!(!p.try_send(&lid(1), &pkt));
        assert_eq!(p.c.fallback.load(Relaxed), 1);
        // соединение есть: ушло ровно один раз
        p.register_plain(&cconn);
        assert!(p.try_send(&lid(1), &pkt));
        assert_eq!((p.c.tx.load(Relaxed), p.c.fallback.load(Relaxed)), (1, 1));
        // слишком большая датаграмма - fallback на Link и счётчик
        let big = vec![0x45u8; 4000];
        assert!(!p.try_send(&lid(1), &big));
        assert_eq!((p.c.too_large.load(Relaxed), p.c.fallback.load(Relaxed), p.c.tx.load(Relaxed)), (1, 2, 1));
        // выключатель
        p.set_tx_enabled(false);
        assert!(!p.try_send(&lid(1), &pkt));
        assert_eq!(p.c.tx.load(Relaxed), 1);
        p.set_tx_enabled(true);
        // после unbind привязки нет: слать нечем, остаётся Link
        p.unbind(&lid(1));
        assert!(!p.try_send(&lid(1), &pkt));
        // закрытое соединение не выбирается
        p.bind(key, lid(1));
        cconn.close(0u32.into(), b"done");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!p.try_send(&lid(1), &pkt));
    }
}
