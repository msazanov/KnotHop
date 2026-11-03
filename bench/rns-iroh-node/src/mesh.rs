//! Mesh-транспорт: сквозное QUIC-соединение клиент↔выход через промежуточные узлы (ADR 0023, «транзит»).
//!
//! Свой `CustomTransport` iroh (feature `unstable-custom-transports`). Адрес `CustomAddr { id = MESH_ID, data = 32-байтный ключ Ed25519 }` -
//! это ключ iroh/identity пира. Пакет QUIC сквозного соединения (уже зашифрованный TLS 1.3 между клиентом и выходом) уходит датаграммой
//! `0xFD | ttl | id(dst)(8) | id(src)(8) | UDP-полезная нагрузка` по QUIC-носителю соседа. Транзит видит только шифротекст и заголовок: он пересылает кадр
//! следующему соседу, последний хоп отдаёт полезную нагрузку в `poll_recv` своего endpoint-а с адресом источника `src`.
//!
//! Что здесь НЕ решается. Права VPN, допуск Link и привязка dataplane остаются прежними: кто на самом деле на том конце, доказывает сквозной TLS
//! (`Connection::remote_id()`), а допуск - существующий (Link + `dataplane::bind`). Заголовок не аутентифицирован: подмена `src` позволяет лишь
//! мешать (QUIC чужой кадр не примет), поэтому каждая пересылка проверяется политикой (`Policy`) и ограничивается по частоте.
//!
//! Правила пересылки (всё fail-closed, до отправки следующему хопу):
//! - узел не клиент и держит TRANSIT в корне, где предыдущий хоп, `src` и `dst` держат какие-либо права (`Policy::may_forward`);
//! - `ttl > 1`; следующий хоп не равен предыдущему (запрет разворота);
//! - токен-бакеты: кадры/с на соседа и на пару `(src, dst)`;
//! - следующий хоп - сосед с живым QUIC-носителем (TCP-носитель кадры не несёт), чья датаграмма вмещает `1200 + HDR`.
//!
//! Следующий хоп выбирается так: `dst` - прямой сосед; иначе обратная таблица (`src -> предыдущий хоп`, выучена из пересланных кадров, ~60 с); иначе
//! таблица путей RNS (`Policy::route`). Выключатель `KNOTHOP_MESH=0` отключает и пересылку, и использование.

use std::collections::HashMap;
use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use iroh::endpoint::Connection;
use iroh::endpoint::transports::{
    AddrKind, CustomEndpoint, CustomSender, CustomTransport, PathSelection, PathSelectionContext, PathSelectionData, PathSelector, RecvInfo, Transmit,
};
use iroh_base::CustomAddr;
use tokio::sync::mpsc;

/// Идентификатор транспорта (не из реестра iroh; значение произвольное, одинаковое на всех узлах).
pub const MESH_ID: u64 = 0x4B48_4D53;
/// Метка датаграммы mesh в соседском QUIC. Бит 0x80 выставлен, как у 0xFE (`dataplane::TAG`) и 0xFF (магия `qprobe`): с RNS-пакетами нашего интерфейса не пересекается.
pub const TAG: u8 = 0xFD;
/// Заголовок: TAG(1) + TTL(1) + id(dst)(8) + id(src)(8); id - первые 8 байт ключа Ed25519. Полные ключи узел находит по базе доверия (`Policy::key_for_id`):
/// неизвестный id отбрасывается. Сжатие нужно, чтобы IP-пакет TUN (1327 Б) помещался в датаграмму сквозного соединения (66-байтный заголовок не помещал).
pub const HDR: usize = 18;
pub type Id = [u8; 8];

pub fn id_of(k: &Key) -> Id {
    k[..8].try_into().unwrap()
}
/// Наибольший TTL при отправке.
pub const MAX_TTL: u8 = 8;
/// Наименьший допустимый UDP-пакет QUIC (Initial) - соседская датаграмма должна вмещать его вместе с заголовком.
const QUIC_MIN_UDP: usize = 1200;
/// Накладные расходы QUIC на одну датаграмму соседа: `MTU - max_datagram_size` (1452 - 1414 по замерам lab13 `meshfail`).
const NBR_DGRAM_OVERHEAD: usize = 38;

/// Наибольший UDP-пакет сквозного QUIC, который заведомо влезает в датаграмму соседа с MTU `nbr_mtu`: `nbr_mtu - накладные - HDR`.
/// Custom-транспорт не сообщает QUIC MTU, поэтому потолок задаёт приложение (`iroh::knothop::set_custom_path_max_udp`): иначе
/// тёплый путь mesh стартует с `initial_mtu` соединения, пакеты больше потолка теряются сериями, детектор чёрной дыры noq
/// сбрасывает MTU пути в 1200 на 60 с, и IP-пакет TUN (1328 Б с меткой) уходит в fallback Link.
pub fn e2e_max_udp(nbr_mtu: u16) -> u16 {
    (nbr_mtu as usize).saturating_sub(NBR_DGRAM_OVERHEAD + HDR) as u16
}

/// Сколько сегментов GSO принимает наш sender. Не меньше, чем у IP-транспорта (Linux: 64): iroh берёт минимум по всем транспортам
/// (`socket/transports.rs: max_transmit_segments`), и меньшее значение отключило бы GSO прямому IP-пути.
pub const MAX_SEGMENTS: usize = 64;
/// Очередь локальной доставки (кадры, ожидающие `poll_recv`).
const DELIVER_QUEUE: usize = 2048;
/// Срок жизни записи обратной таблицы и её размер.
const REV_TTL: Duration = Duration::from_secs(60);
const REV_MAX: usize = 1024;
/// Кэш решений политики: верно - 5 с (отзыв прав действует с такой задержкой), неверно - 2 с.
const AUTH_TTL_OK: Duration = Duration::from_secs(5);
const AUTH_TTL_NO: Duration = Duration::from_secs(2);
const AUTH_MAX: usize = 2048;
const ROUTE_TTL: Duration = Duration::from_secs(2);
/// Запись `hops` старше этого запрашивает обновление, старше `HOP_MAX_AGE` - не используется (кадр теряется, как при отсутствии маршрута).
const HOP_REFRESH: Duration = Duration::from_millis(500);
const HOP_MAX_AGE: Duration = Duration::from_secs(5);
const HOP_MAX: usize = 256;
/// Сколько сквозных соединений и пиров с ними помечаем (больше - соединение закрывается: непомеченное могло бы стать «соседом» mesh).
const E2E_MAX: usize = 256;
const BUCKET_MAX_NBR: usize = 256;
const BUCKET_MAX_PAIR: usize = 1024;

pub type Key = [u8; 32];

/// Решения, зависящие от доверия и таблицы путей RNS: реализует узел (`vpn.rs`). Пока политика не задана, mesh ничего не пересылает и не использует.
pub trait Policy: Send + Sync {
    /// Может ли ЭТОТ узел переслать кадр `src -> dst`, пришедший от соседа `prev`: узел держит TRANSIT, а в одном и том же принятом корне источник и
    /// назначение держат права друг относительно друга (или этого узла), предыдущий хоп - сам источник либо узел с TRANSIT. Клиент всегда отвечает false.
    fn may_forward(&self, prev: &Key, src: &Key, dst: &Key) -> bool;
    /// Держит ли ключ права USE/TRANSIT/EXIT в принятом корне применительно к этому узлу (последний хоп принимает кадры только от таких соседей).
    fn holds_rights(&self, key: &Key) -> bool;
    /// Держит ли ключ право TRANSIT в принятом корне применительно к этому узлу (только такой сосед вправе вести за собой чужого источника).
    fn is_transit(&self, key: &Key) -> bool;
    /// Ключи узлов с правом TRANSIT применительно к этому узлу: из них выбирается альтернативный транзит для тёплого запасного пути.
    fn transit_candidates(&self) -> Vec<Key>;
    /// Поколение прав: меняется при любом изменении записей, зачислений, якорей и политик. Кэши решений mesh сбрасываются при смене - отзыв действует сразу.
    fn generation(&self) -> u64;
    /// Сосед, через которого таблица путей RNS ведёт к назначению узла с ключом `dst`. Только подсказка маршрута, не полномочие.
    fn route(&self, dst: &Key) -> Option<Key>;
    /// Полный ключ по 8-байтному id среди ключей, известных хранилищу доверия (любой держатель прав или якорь). Неизвестный id - None.
    fn key_for_id(&self, id: &Id) -> Option<Key>;
}

#[derive(Default)]
pub struct Counters {
    /// кадров отправлено первым хопом (наш исходящий QUIC)
    pub tx: AtomicU64,
    pub fwd: AtomicU64,
    pub delivered: AtomicU64,
    pub deliver_queue_full: AtomicU64,
    pub drop_disabled: AtomicU64,
    pub drop_no_policy: AtomicU64,
    pub drop_malformed: AtomicU64,
    pub drop_e2e_conn: AtomicU64,
    pub drop_transit_not_allowed: AtomicU64,
    pub drop_policy: AtomicU64,
    /// id источника/назначения не принадлежит известному держателю прав
    pub drop_unknown_key: AtomicU64,
    pub drop_ttl: AtomicU64,
    pub drop_uturn: AtomicU64,
    pub drop_rate_neighbor: AtomicU64,
    pub drop_rate_pair: AtomicU64,
    pub drop_no_route: AtomicU64,
    /// следующий хоп без живого QUIC-носителя (в частности, только TCP)
    pub drop_no_quic: AtomicU64,
    /// соседская датаграмма не вмещает 1200 + HDR или кадр
    pub drop_mtu: AtomicU64,
    pub drop_send_err: AtomicU64,
    pub rev_learned: AtomicU64,
    /// запись обратной таблицы не заменена: прежний сосед жив, а новый не источник
    pub rev_conflict: AtomicU64,
    /// мой id8 совпал с другим известным ключом или не разрешился в мой ключ: локально не доставляем
    pub drop_id_ambiguous: AtomicU64,
    /// хоп из кэша оказался соединением, идущим по mesh
    pub drop_recursion: AtomicU64,
    /// не удалось пометить сквозное соединение (таблица заполнена): соединение закрывается
    pub e2e_overflow: AtomicU64,
    /// очередь отправки кадров полна (кадр потерян)
    pub drop_queue_full: AtomicU64,
    /// путь mesh тёплого запасного пути: кадров через альтернативный транзит
    pub alt_hops: AtomicU64,
    /// сколько раз кэши решений сброшены сменой поколения прав
    pub gen_resets: AtomicU64,
}

#[derive(Clone, Copy)]
pub struct Limits {
    /// кадров/с и всплеск на одного соседа
    pub nbr_rate: f64,
    pub nbr_burst: f64,
    /// кадров/с и всплеск на пару (src, dst)
    pub pair_rate: f64,
    pub pair_burst: f64,
}

impl Default for Limits {
    fn default() -> Self {
        // Один TCP-поток на стенде (450 Мбит/с) - около 45 kpps данных на пару; одно ядро тянет порядка 100-120 kpps пересылки. Пара: 80 kpps (запас ~1,8x),
        // сосед: 100 kpps (все пары одного соседа + ответные ACK), всплеск ~200 мс.
        Limits { nbr_rate: 100_000.0, nbr_burst: 20_000.0, pair_rate: 80_000.0, pair_burst: 16_000.0 }
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn take(&mut self, now: Instant, rate: f64, burst: f64) -> bool {
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

type Carriers = Arc<dyn Fn(&Key) -> Option<Connection> + Send + Sync>;

pub struct Mesh {
    me: Key,
    enabled: AtomicBool,
    policy: RwLock<Option<Arc<dyn Policy>>>,
    carriers: Carriers,
    limits: Mutex<Limits>,
    nbr_buckets: Mutex<HashMap<Key, Bucket>>,
    pair_buckets: Mutex<HashMap<(Key, Key), Bucket>>,
    auth: Mutex<HashMap<(Key, Key, Key), (bool, Instant)>>,
    rev: Mutex<HashMap<Key, (Key, Instant)>>,
    /// кэш маршрутов RNS (путь меняется редко, а запрос таблицы путей дорог): 2 с
    routes: Mutex<HashMap<Key, (Option<Key>, Instant)>>,
    /// Следующий хоп для исходящих кадров (poll_send читает ТОЛЬКО его: poll_send вызывается под замком QUIC-соединения, а разрешение хопа берёт замки
    /// мультиплексоров и Trust - обратный порядок замков у `Mux::send` дал бы взаимную блокировку). Заполняют `warm`/`prepare` и поток-разрешитель.
    hops: Mutex<HashMap<Key, HopEntry>>,
    ids: Mutex<HashMap<Id, (Option<Key>, Instant)>>,
    ride_cache: Mutex<HashMap<usize, (bool, Instant)>>,
    hop_pending: Mutex<std::collections::HashSet<Key>>,
    hop_req: Mutex<std::sync::mpsc::Sender<Key>>,
    /// очередь исходящих кадров: poll_send работает под замком QUIC-соединения, а `send_datagram` хопа берёт замок ДРУГОГО соединения; чтобы вложенные замки
    /// (и циклы между соединениями с mesh-путём) были невозможны, кадры отправляет отдельный поток
    txq: std::sync::mpsc::SyncSender<(Connection, Bytes)>,
    /// stable_id соединений, которые сами идут по mesh (сквозные): они не соседи и кадры mesh не несут
    e2e: Mutex<E2e>,
    e2e_max: AtomicU64,
    /// поколение прав, на котором получены кэши auth/ids/routes/hops/rev
    seen_gen: AtomicU64,
    min_nbr_dgram: AtomicU64,
    pub c: Counters,
    rx_tx: mpsc::Sender<(Bytes, Key)>,
    rx: Mutex<Option<mpsc::Receiver<(Bytes, Key)>>>,
    local: n0_watcher::Watchable<Vec<CustomAddr>>,
}

impl std::fmt::Debug for Mesh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mesh")
    }
}

pub fn addr_of(key: &Key) -> CustomAddr {
    CustomAddr::from_parts(MESH_ID, key)
}

/// Процессный экземпляр узла (создаётся до endpoint-а: транспорт передаётся в `Builder::add_custom_transport`).
static GLOBAL: OnceLock<Arc<Mesh>> = OnceLock::new();

/// Установить mesh узла. Повторный вызов возвращает уже созданный (ключ узла не меняется за процесс).
pub fn install(me: Key) -> Arc<Mesh> {
    GLOBAL
        .get_or_init(|| {
            let on = std::env::var("KNOTHOP_MESH").map(|v| v.trim() != "0").unwrap_or(true);
            let carriers: Carriers = Arc::new(|k: &Key| crate::dataplane::plane().carrier_filtered(k, |_| true));
            Mesh::build(me, on, carriers)
        })
        .clone()
}

pub fn global() -> Option<&'static Arc<Mesh>> {
    GLOBAL.get()
}

impl Mesh {
    fn build(me: Key, enabled: bool, carriers: Carriers) -> Arc<Self> {
        let (rx_tx, rx) = mpsc::channel(DELIVER_QUEUE);
        let (hop_tx, hop_rx) = std::sync::mpsc::channel::<Key>();
        let (txq, txq_rx) = std::sync::mpsc::sync_channel::<(Connection, Bytes)>(8192);
        let mesh = Arc::new(Mesh {
            me,
            enabled: AtomicBool::new(enabled),
            policy: RwLock::new(None),
            carriers,
            limits: Mutex::new(Limits::default()),
            nbr_buckets: Default::default(),
            pair_buckets: Default::default(),
            auth: Default::default(),
            rev: Default::default(),
            routes: Default::default(),
            hops: Default::default(),
            ids: Default::default(),
            ride_cache: Default::default(),
            hop_pending: Default::default(),
            hop_req: Mutex::new(hop_tx),
            txq,
            e2e: Default::default(),
            e2e_max: AtomicU64::new(E2E_MAX as u64),
            seen_gen: AtomicU64::new(0),
            min_nbr_dgram: AtomicU64::new((QUIC_MIN_UDP + HDR) as u64),
            c: Counters::default(),
            rx_tx,
            rx: Mutex::new(Some(rx)),
            local: n0_watcher::Watchable::new(vec![addr_of(&me)]),
        });
        let w2 = Arc::downgrade(&mesh);
        let _ = std::thread::Builder::new().name("knothop-mesh-tx".into()).spawn(move || {
            while let Ok((conn, b)) = txq_rx.recv() {
                let Some(m) = w2.upgrade() else { break };
                match conn.send_datagram(b) {
                    Ok(()) => {}
                    // пакет сквозного QUIC + заголовок не влезает в датаграмму соседа: QUIC видит потерю (см. `e2e_max_udp`)
                    Err(iroh::endpoint::SendDatagramError::TooLarge) => {
                        m.c.drop_mtu.fetch_add(1, Relaxed);
                    }
                    Err(_) => {
                        m.c.drop_send_err.fetch_add(1, Relaxed);
                    }
                }
            }
        });
        // поток-разрешитель следующих хопов: заменяет вычисление в poll_send (см. `hops`)
        let w = Arc::downgrade(&mesh);
        let _ = std::thread::Builder::new().name("knothop-mesh-hop".into()).spawn(move || loop {
            match hop_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(k) => match w.upgrade() {
                    Some(m) => {
                        m.hop_pending.lock().unwrap().remove(&k);
                        m.warm(&k);
                    }
                    None => break,
                },
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if w.strong_count() == 0 {
                        break;
                    }
                }
                Err(_) => break,
            }
        });
        mesh
    }

    /// Для проверок и стендов: свой источник соседских соединений.
    pub fn with_carriers(me: Key, enabled: bool, carriers: Carriers) -> Arc<Self> {
        Self::build(me, enabled, carriers)
    }

    pub fn me(&self) -> &Key {
        &self.me
    }

    pub fn set_policy(&self, p: Arc<dyn Policy>) {
        *self.policy.write().unwrap() = Some(p);
    }

    pub fn set_limits(&self, l: Limits) {
        *self.limits.lock().unwrap() = l;
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Relaxed)
    }

    /// Нижняя граница соседской датаграммы (проверки подменяют, чтобы смоделировать узкий путь).
    pub fn set_min_nbr_dgram(&self, n: usize) {
        self.min_nbr_dgram.store(n as u64, Relaxed);
    }

    pub fn transport(self: &Arc<Self>) -> Arc<dyn CustomTransport> {
        Arc::new(MeshTransport(self.clone()))
    }

    /// Пометить соединение как сквозное (начато по mesh). Оно не может быть соседом: кадры mesh по нему не шлём и не принимаем.
    /// false - таблица заполнена: вызывающий ОБЯЗАН закрыть соединение (непомеченное могло бы стать «соседом»).
    pub fn mark_e2e(self: &Arc<Self>, conn: &Connection) -> bool {
        let id = conn.stable_id();
        let max = self.e2e_max.load(Relaxed) as usize;
        {
            let mut e = self.e2e.lock().unwrap();
            if !e.ids.contains(&id) {
                if e.ids.len() >= max {
                    drop(e);
                    self.c.e2e_overflow.fetch_add(1, Relaxed);
                    return false;
                }
                e.ids.insert(id);
            }
        }
        let (m, c) = (self.clone(), conn.clone());
        tokio::spawn(async move {
            let _ = c.closed().await;
            m.e2e.lock().unwrap().ids.remove(&id);
        });
        true
    }

    pub fn is_e2e(&self, conn: &Connection) -> bool {
        self.e2e.lock().unwrap().ids.contains(&conn.stable_id())
    }

    /// Проверка при отправке: без обращения к соединению (стабильный id записан в запись хопа).
    fn hop_rides_mesh(&self, h: &HopConn, _now: Instant) -> bool {
        self.e2e.lock().unwrap().ids.contains(&h.sid)
    }

    pub fn set_e2e_max(&self, n: usize) {
        self.e2e_max.store(n as u64, Relaxed);
    }

    /// Соединение сейчас едет по mesh: помечено сквозным либо выбранный путь у него `Custom`. Соединение с тёплым запасным mesh-путём (основной - IP) соседом
    /// быть может, пока основной путь прямой; в сквозное, идущее по mesh, класть кадры mesh нельзя (вложенность и петли). Решение по путям держим 1 с.
    pub fn rides_mesh(&self, conn: &Connection) -> bool {
        if self.is_e2e(conn) {
            return true;
        }
        let (id, now) = (conn.stable_id(), Instant::now());
        {
            let c = self.ride_cache.lock().unwrap();
            if let Some((v, t)) = c.get(&id) {
                if now.saturating_duration_since(*t) < Duration::from_secs(1) {
                    return *v;
                }
            }
        }
        let v = conn.paths().iter().any(|p| p.is_selected() && matches!(p.remote_addr(), iroh::TransportAddr::Custom(_)));
        let mut c = self.ride_cache.lock().unwrap();
        if c.len() >= 256 {
            c.retain(|_, (_, t)| now.saturating_duration_since(*t) < Duration::from_secs(1));
        }
        if c.len() < 256 {
            c.insert(id, (v, now));
        }
        v
    }

    /// Сверить поколение прав политики и при смене сбросить все кэши, в которых зашиты решения (отзыв действует со следующего кадра).
    fn sync_gen(&self, policy: &dyn Policy) {
        let g = policy.generation();
        if self.seen_gen.swap(g, Relaxed) != g {
            self.auth.lock().unwrap().clear();
            self.ids.lock().unwrap().clear();
            self.routes.lock().unwrap().clear();
            self.hops.lock().unwrap().clear();
            self.rev.lock().unwrap().clear();
            self.c.gen_resets.fetch_add(1, Relaxed);
        }
    }

    pub fn stats(&self) -> serde_json::Value {
        let c = &self.c;
        serde_json::json!({
            "enabled": self.enabled(), "tx": c.tx.load(Relaxed), "fwd": c.fwd.load(Relaxed), "delivered": c.delivered.load(Relaxed),
            "deliver_queue_full": c.deliver_queue_full.load(Relaxed), "drop_disabled": c.drop_disabled.load(Relaxed),
            "drop_no_policy": c.drop_no_policy.load(Relaxed), "drop_malformed": c.drop_malformed.load(Relaxed),
            "drop_e2e_conn": c.drop_e2e_conn.load(Relaxed), "drop_transit_not_allowed": c.drop_transit_not_allowed.load(Relaxed),
            "drop_policy": c.drop_policy.load(Relaxed), "drop_unknown_key": c.drop_unknown_key.load(Relaxed), "drop_ttl": c.drop_ttl.load(Relaxed), "drop_uturn": c.drop_uturn.load(Relaxed),
            "drop_rate_neighbor": c.drop_rate_neighbor.load(Relaxed), "drop_rate_pair": c.drop_rate_pair.load(Relaxed),
            "drop_no_route": c.drop_no_route.load(Relaxed), "drop_no_quic": c.drop_no_quic.load(Relaxed), "drop_mtu": c.drop_mtu.load(Relaxed),
            "drop_send_err": c.drop_send_err.load(Relaxed), "rev_learned": c.rev_learned.load(Relaxed),
            "rev_conflict": c.rev_conflict.load(Relaxed), "drop_id_ambiguous": c.drop_id_ambiguous.load(Relaxed), "drop_recursion": c.drop_recursion.load(Relaxed),
            "e2e_overflow": c.e2e_overflow.load(Relaxed), "drop_queue_full": c.drop_queue_full.load(Relaxed), "alt_hops": c.alt_hops.load(Relaxed), "gen_resets": c.gen_resets.load(Relaxed),
            "egress_blocked": iroh::knothop::blocked_egress(), "rev_size": self.rev.lock().unwrap().len(), "e2e_conns": self.e2e.lock().unwrap().ids.len(),
        })
    }

    // ---------------------------------------------------------------- решения

    fn policy(&self) -> Option<Arc<dyn Policy>> {
        self.policy.read().unwrap().clone()
    }

    /// Решение политики с кэшем (ключ - тройка; для одиночного ключа `(k, 0, 0)`). Таблицы ограничены: переполнение чистит устаревшее, иначе отказ.
    fn cached(&self, now: Instant, k: (Key, Key, Key), f: impl FnOnce() -> bool) -> bool {
        {
            let a = self.auth.lock().unwrap();
            if let Some((ok, until)) = a.get(&k) {
                if *until > now {
                    return *ok;
                }
            }
        }
        let ok = f();
        let mut a = self.auth.lock().unwrap();
        if a.len() >= AUTH_MAX {
            a.retain(|_, (_, until)| *until > now);
            if a.len() >= AUTH_MAX {
                return ok;
            }
        }
        a.insert(k, (ok, now + if ok { AUTH_TTL_OK } else { AUTH_TTL_NO }));
        ok
    }

    fn rate_neighbor(&self, now: Instant, prev: &Key) -> bool {
        let l = *self.limits.lock().unwrap();
        let mut m = self.nbr_buckets.lock().unwrap();
        if !m.contains_key(prev) && m.len() >= BUCKET_MAX_NBR {
            m.retain(|_, b| now.saturating_duration_since(b.last) < Duration::from_secs(30));
            if m.len() >= BUCKET_MAX_NBR {
                return false;
            }
        }
        m.entry(*prev).or_insert(Bucket { tokens: l.nbr_burst, last: now }).take(now, l.nbr_rate, l.nbr_burst)
    }

    fn rate_pair(&self, now: Instant, src: &Key, dst: &Key) -> bool {
        let l = *self.limits.lock().unwrap();
        let mut m = self.pair_buckets.lock().unwrap();
        let k = (*src, *dst);
        if !m.contains_key(&k) && m.len() >= BUCKET_MAX_PAIR {
            m.retain(|_, b| now.saturating_duration_since(b.last) < Duration::from_secs(30));
            if m.len() >= BUCKET_MAX_PAIR {
                return false;
            }
        }
        m.entry(k).or_insert(Bucket { tokens: l.pair_burst, last: now }).take(now, l.pair_rate, l.pair_burst)
    }

    /// Ключ по id с кэшем (30 с / отказ 5 с, не больше 1024 записей; сбрасывается сменой поколения прав). Мой собственный id тоже проходит через политику:
    /// если он совпал с другим известным ключом (или не разрешился в мой ключ), локально ничего не доставляем.
    fn key_of(&self, now: Instant, id: &Id, policy: &dyn Policy) -> Option<Key> {
        {
            let c = self.ids.lock().unwrap();
            if let Some((k, until)) = c.get(id) {
                if *until > now {
                    return *k;
                }
            }
        }
        let k = policy.key_for_id(id);
        let mut c = self.ids.lock().unwrap();
        if c.len() >= 1024 {
            c.retain(|_, (_, until)| *until > now);
        }
        if c.len() < 1024 {
            c.insert(*id, (k, now + if k.is_some() { Duration::from_secs(30) } else { Duration::from_secs(5) }));
        }
        k
    }

    /// Запомнить «источник `src` за соседом `prev`». Вызывать только ПОСЛЕ успешной пересылки/доставки и только если `prev` - узел с TRANSIT (проверено до
    /// этого): `src` не аутентифицирован, и рядовой сосед иначе перехватывал бы чужие ответы. Свежую запись с другим соседом не затираем, пока тот жив.
    fn learn(&self, now: Instant, src: &Key, prev: &Key) {
        if src == &self.me || src == prev {
            return;
        }
        let old = self.rev.lock().unwrap().get(src).copied();
        if let Some((old_prev, t)) = old {
            if &old_prev != prev && now.saturating_duration_since(t) < REV_TTL && self.carrier(&old_prev).is_some() {
                self.c.rev_conflict.fetch_add(1, Relaxed);
                return;
            }
        }
        let mut r = self.rev.lock().unwrap();
        if !r.contains_key(src) && r.len() >= REV_MAX {
            r.retain(|_, (_, t)| now.saturating_duration_since(*t) < REV_TTL);
            if r.len() >= REV_MAX {
                return;
            }
        }
        if r.insert(*src, (*prev, now)).is_none() {
            self.c.rev_learned.fetch_add(1, Relaxed);
        }
    }

    /// Живой QUIC-носитель к ключу, который может быть соседом mesh: соединение, идущее по mesh, не годится (см. `rides_mesh`).
    fn carrier(&self, key: &Key) -> Option<Connection> {
        (self.carriers)(key).filter(|c| !self.rides_mesh(c))
    }

    /// Живой соседский QUIC-носитель к ключу, если он вмещает `1200 + HDR`.
    fn neighbor(&self, key: &Key) -> Result<Connection, NbrErr> {
        match self.carrier(key) {
            None => Err(NbrErr::NoQuic),
            Some(c) => {
                let need = self.min_nbr_dgram.load(Relaxed) as usize;
                if c.max_datagram_size().unwrap_or(0) < need {
                    Err(NbrErr::TooSmall)
                } else {
                    Ok(c)
                }
            }
        }
    }

    /// Следующий хоп к `dst`: прямой сосед; путь RNS (если назначение анонсирует себя, он главнее выученного); обратная таблица. Хоп, равный `dst` (интерфейс самого
    /// сквозного соединения к нему), пропускается; наличие живого QUIC-носителя у выбранного хопа проверяет `neighbor`.
    fn next_hop(&self, now: Instant, dst: &Key, policy: &dyn Policy) -> Option<Key> {
        if self.carrier(dst).is_some() {
            return Some(*dst);
        }
        self.next_hop_via(now, dst, policy)
    }

    /// Путь RNS (главнее выученного) и обратная таблица; хоп, равный `dst`, пропускается.
    fn next_hop_via(&self, now: Instant, dst: &Key, policy: &dyn Policy) -> Option<Key> {
        let routed = {
            let cached = {
                let r = self.routes.lock().unwrap();
                r.get(dst).copied().filter(|(_, t)| now.saturating_duration_since(*t) < ROUTE_TTL)
            };
            match cached {
                Some((v, _)) => v,
                None => {
                    let v = policy.route(dst);
                    let mut r = self.routes.lock().unwrap();
                    if r.len() >= 256 {
                        r.retain(|_, (_, t)| now.saturating_duration_since(*t) < ROUTE_TTL);
                    }
                    if r.len() < 256 {
                        r.insert(*dst, (v, now));
                    }
                    v
                }
            }
        };
        if let Some(v) = routed.filter(|v| v != dst) {
            return Some(v);
        }
        let learned = self.rev.lock().unwrap().get(dst).copied();
        if let Some((via, t)) = learned {
            if now.saturating_duration_since(t) < REV_TTL {
                return Some(via);
            }
        }
        None
    }

    /// Следующий хоп для СВОИХ кадров (poll_send). Если до `dst` есть прямой носитель (путь IP), mesh - запасной путь и обязан идти МИМО него: через
    /// альтернативный транзит (`alt_transit`). Иначе - путь RNS или обратная таблица, как при пересылке.
    fn next_hop_origin(&self, now: Instant, dst: &Key, policy: &dyn Policy) -> Option<Key> {
        if self.carrier(dst).is_some() {
            let k = self.alt_transit(dst, policy)?;
            self.c.alt_hops.fetch_add(1, Relaxed);
            return Some(k);
        }
        self.next_hop_via(now, dst, policy)
    }

    /// Альтернативный транзит к `dst`: узел с правом TRANSIT, не `dst`, с живым QUIC-носителем вне mesh; выбор стабилен (меньший `k xor dst`).
    /// Знания о том, видит ли транзит само `dst`, нет: если он `dst` не достаёт, он кадры отбросит, и путь не подтвердится (запасным он не станет).
    fn alt_transit(&self, dst: &Key, policy: &dyn Policy) -> Option<Key> {
        policy
            .transit_candidates()
            .into_iter()
            .filter(|k| k != dst && k != &self.me && self.carrier(k).is_some())
            .min_by_key(|k| {
                let mut x = [0u8; 8];
                for i in 0..8 {
                    x[i] = k[i] ^ dst[i];
                }
                u64::from_be_bytes(x)
            })
    }

    fn count_nbr_err(&self, e: NbrErr) {
        match e {
            NbrErr::NoQuic => self.c.drop_no_quic.fetch_add(1, Relaxed),
            NbrErr::TooSmall => self.c.drop_mtu.fetch_add(1, Relaxed),
        };
    }

    // ---------------------------------------------------------------- приём кадра от соседа

    /// Кадр `0xFD` от соседа - соединения `conn` (ключ соседа - из TLS, `remote_id()`). Вызывается читателем датаграмм носителя; в RNS кадр не идёт никогда.
    pub fn on_datagram(&self, conn: &Connection, d: &Bytes) {
        let prev = *conn.remote_id().as_bytes();
        if self.rides_mesh(conn) {
            self.c.drop_e2e_conn.fetch_add(1, Relaxed);
            return;
        }
        self.on_frame(&prev, d);
    }

    /// Ядро обработки (отдельно от `Connection`, чтобы проверять без сети).
    pub fn on_frame(&self, prev: &Key, d: &Bytes) {
        let c = &self.c;
        if !self.enabled() {
            c.drop_disabled.fetch_add(1, Relaxed);
            return;
        }
        if d.len() < HDR || d[0] != TAG {
            c.drop_malformed.fetch_add(1, Relaxed);
            return;
        }
        let Some(policy) = self.policy() else {
            c.drop_no_policy.fetch_add(1, Relaxed);
            return;
        };
        self.sync_gen(policy.as_ref());
        let ttl = d[1];
        if ttl == 0 || ttl > MAX_TTL {
            // отправитель не ставит больше MAX_TTL: такой кадр либо чужой, либо зацикливается
            c.drop_ttl.fetch_add(1, Relaxed);
            return;
        }
        let now = Instant::now();
        if !self.rate_neighbor(now, prev) {
            c.drop_rate_neighbor.fetch_add(1, Relaxed);
            return;
        }
        let dst_id: Id = d[2..10].try_into().unwrap();
        let src_id: Id = d[10..18].try_into().unwrap();
        let Some(src) = self.key_of(now, &src_id, policy.as_ref()) else {
            c.drop_unknown_key.fetch_add(1, Relaxed);
            return;
        };
        if dst_id == id_of(&self.me) {
            // последний хоп. Мой id8 обязан однозначно разрешаться в мой ключ
            if self.key_of(now, &dst_id, policy.as_ref()) != Some(self.me) {
                c.drop_id_ambiguous.fetch_add(1, Relaxed);
                return;
            }
            // принимаем только от соседа с правами; источник за этим соседом - только если сосед и есть источник либо узел с TRANSIT
            if !self.cached(now, (*prev, [0; 32], [0; 32]), || policy.holds_rights(prev)) {
                c.drop_policy.fetch_add(1, Relaxed);
                return;
            }
            let via_transit = prev != &src && self.cached(now, (*prev, [1; 32], [0; 32]), || policy.is_transit(prev));
            if prev != &src && !via_transit {
                c.drop_policy.fetch_add(1, Relaxed);
                return;
            }
            if !self.rate_pair(now, &src, &self.me) {
                c.drop_rate_pair.fetch_add(1, Relaxed);
                return;
            }
            match self.rx_tx.try_send((d.slice(HDR..), src)) {
                Ok(()) => {
                    c.delivered.fetch_add(1, Relaxed);
                    if via_transit {
                        self.learn(now, &src, prev);
                    }
                    // ответ на этот кадр пойдёт к `src`: хоп готовим здесь (в читателе датаграмм), а не в poll_send
                    self.warm_if_stale(now, &src);
                }
                Err(_) => {
                    c.deliver_queue_full.fetch_add(1, Relaxed);
                }
            }
            return;
        }
        let Some(dst) = self.key_of(now, &dst_id, policy.as_ref()) else {
            c.drop_unknown_key.fetch_add(1, Relaxed);
            return;
        };
        // транзит: сначала всё проверяем, потом пересылаем
        if ttl <= 1 {
            c.drop_ttl.fetch_add(1, Relaxed);
            return;
        }
        if !self.cached(now, (*prev, src, dst), || policy.may_forward(prev, &src, &dst)) {
            // клиент и узел без TRANSIT отвечают здесь же; различить причину политика не обязана - счётчик общий с отказом по правам
            c.drop_policy.fetch_add(1, Relaxed);
            return;
        }
        if !self.rate_pair(now, &src, &dst) {
            c.drop_rate_pair.fetch_add(1, Relaxed);
            return;
        }
        let Some(next) = self.next_hop(now, &dst, policy.as_ref()) else {
            c.drop_no_route.fetch_add(1, Relaxed);
            return;
        };
        if &next == prev {
            c.drop_uturn.fetch_add(1, Relaxed);
            return;
        }
        let conn = match self.neighbor(&next) {
            Ok(x) => x,
            Err(e) => {
                self.count_nbr_err(e);
                return;
            }
        };
        let mut b = BytesMut::from(&d[..]);
        b[1] = ttl - 1;
        match conn.send_datagram(b.freeze()) {
            Ok(()) => {
                c.fwd.fetch_add(1, Relaxed);
                // обратная таблица: ответ dst -> src пойдёт к тому, от кого пришёл кадр (если это не сам источник: тот и так сосед)
                if prev != &src {
                    self.learn(now, &src, prev);
                }
            }
            Err(_) => {
                c.drop_send_err.fetch_add(1, Relaxed);
            }
        }
    }

    /// Разрешить следующий хоп к `dst` целиком (политика, обратная таблица, соседи) и запомнить в `hops`. Вызывать НЕ из poll_send:
    /// берёт замки мультиплексоров и Trust. Безопасно из читателя датаграмм носителя, задач tokio и потока-разрешителя.
    pub fn warm(&self, dst: &Key) {
        let Some(policy) = self.policy() else { return };
        self.sync_gen(policy.as_ref());
        let now = Instant::now();
        let res = match self.next_hop_origin(now, dst, policy.as_ref()) {
            None => Err(HopErr::NoRoute),
            Some(next) => self
                .neighbor(&next)
                .map(|conn| HopConn { sid: conn.stable_id(), peer: *conn.remote_id().as_bytes(), conn })
                .map_err(|e| match e {
                    NbrErr::NoQuic => HopErr::NoQuic,
                    NbrErr::TooSmall => HopErr::TooSmall,
                }),
        };
        let mut h = self.hops.lock().unwrap();
        if !h.contains_key(dst) && h.len() >= HOP_MAX {
            h.retain(|_, e| now.saturating_duration_since(e.at) < HOP_MAX_AGE);
            if h.len() >= HOP_MAX {
                return;
            }
        }
        h.insert(*dst, HopEntry { res, at: now });
    }

    fn warm_if_stale(&self, now: Instant, dst: &Key) {
        let fresh = self.hops.lock().unwrap().get(dst).is_some_and(|e| now.saturating_duration_since(e.at) < HOP_REFRESH && e.res.is_ok());
        if !fresh {
            self.warm(dst);
        }
    }

    /// Заранее разрешить хоп к `dst` (перед первым пакетом сквозного соединения).
    /// Сосед, через которого сейчас идут кадры mesh к `dst` (по кэшу хопов).
    pub fn hop_peer(&self, dst: &Key) -> Option<Key> {
        self.hops.lock().unwrap().get(dst).and_then(|e| e.res.as_ref().ok().map(|h| h.peer))
    }

    pub fn prepare(&self, dst: &Key) {
        self.warm(dst);
    }

    /// Выходные кадры нашего endpoint-а (источник - мы). `payload` - один UDP-пакет сквозного QUIC. Вызывается из poll_send под замком QUIC-соединения:
    /// никаких замков мультиплексоров/Trust, хоп берётся из кэша `hops`.
    fn send_payload(&self, dst: &Key, payload: &[u8]) {
        let c = &self.c;
        if !self.enabled() {
            c.drop_disabled.fetch_add(1, Relaxed);
            return;
        }
        let now = Instant::now();
        if let Some(p) = self.policy() {
            self.sync_gen(p.as_ref());
        }
        let (entry, need_refresh) = {
            let h = self.hops.lock().unwrap();
            match h.get(dst) {
                Some(e) => {
                    let age = now.saturating_duration_since(e.at);
                    (if age < HOP_MAX_AGE { Some(e.res.clone()) } else { None }, age >= HOP_REFRESH)
                }
                None => (None, true),
            }
        };
        if need_refresh && self.hop_pending.lock().unwrap().insert(*dst) {
            let _ = self.hop_req.lock().unwrap().send(*dst);
        }
        let conn = match entry {
            Some(Ok(h)) => {
                // кэш хопа мог устареть: соединение стало едущим по mesh после разрешения. Проверка по записям (без обращения к самому соединению)
                if self.hop_rides_mesh(&h, now) {
                    c.drop_recursion.fetch_add(1, Relaxed);
                    return;
                }
                h.conn
            }
            Some(Err(HopErr::NoQuic)) => {
                c.drop_no_quic.fetch_add(1, Relaxed);
                return;
            }
            Some(Err(HopErr::TooSmall)) => {
                c.drop_mtu.fetch_add(1, Relaxed);
                return;
            }
            Some(Err(HopErr::NoRoute)) | None => {
                if self.policy().is_none() {
                    c.drop_no_policy.fetch_add(1, Relaxed);
                } else {
                    c.drop_no_route.fetch_add(1, Relaxed);
                }
                return;
            }
        };
        let mut b = BytesMut::with_capacity(HDR + payload.len());
        b.extend_from_slice(&[TAG, MAX_TTL]);
        b.extend_from_slice(&id_of(dst));
        b.extend_from_slice(&id_of(&self.me));
        b.extend_from_slice(payload);
        match self.txq.try_send((conn, b.freeze())) {
            Ok(()) => c.tx.fetch_add(1, Relaxed),
            Err(_) => c.drop_queue_full.fetch_add(1, Relaxed),
        };
    }
}

#[derive(Clone, Copy)]
enum HopErr {
    NoRoute,
    NoQuic,
    TooSmall,
}

/// Соединение следующего хопа вместе с тем, что нужно знать при отправке БЕЗ обращения к самому соединению (в poll_send замок этого соединения может уже держаться).
#[derive(Clone)]
struct HopConn {
    conn: Connection,
    sid: usize,
    peer: Key,
}

struct HopEntry {
    res: Result<HopConn, HopErr>,
    at: Instant,
}

/// Сквозные соединения, начатые по mesh (помечены `mark_e2e`): они не соседи.
#[derive(Default)]
struct E2e {
    ids: std::collections::HashSet<usize>,
}

enum NbrErr {
    NoQuic,
    TooSmall,
}

// -------------------------------------------------------------------- iroh

#[derive(Debug)]
struct MeshTransport(Arc<Mesh>);

impl CustomTransport for MeshTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let rx = self.0.rx.lock().unwrap().take().ok_or_else(|| io::Error::other("mesh endpoint already bound"))?;
        Ok(Box::new(MeshEp { mesh: self.0.clone(), rx }))
    }
}

#[derive(Debug)]
struct MeshEp {
    mesh: Arc<Mesh>,
    rx: mpsc::Receiver<(Bytes, Key)>,
}

impl CustomEndpoint for MeshEp {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.mesh.local.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(MeshSender(self.mesh.clone()))
    }

    fn poll_recv(&mut self, cx: &mut Context, bufs: &mut [io::IoSliceMut<'_>], metas: &mut [noq_udp::RecvMeta], infos: &mut [RecvInfo]) -> Poll<io::Result<usize>> {
        let mut n = 0;
        while n < bufs.len() {
            let (data, src) = if n == 0 {
                match self.rx.poll_recv(cx) {
                    Poll::Ready(Some(x)) => x,
                    Poll::Ready(None) => return Poll::Ready(Err(io::Error::other("mesh closed"))),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match self.rx.try_recv() {
                    Ok(x) => x,
                    Err(_) => break,
                }
            };
            if data.len() > bufs[n].len() {
                continue;
            }
            bufs[n][..data.len()].copy_from_slice(&data);
            metas[n].len = data.len();
            metas[n].stride = data.len();
            metas[n].ecn = None;
            metas[n].dst_ip = None;
            infos[n] = RecvInfo::new(addr_of(&src), Some(addr_of(&self.mesh.me)));
            n += 1;
        }
        Poll::Ready(Ok(n))
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(MAX_SEGMENTS).unwrap()
    }
}

#[derive(Debug)]
struct MeshSender(Arc<Mesh>);

/// Разбор transmit на датаграммы: GSO склеивает несколько одинаковых по размеру (кроме последней) пакетов в один буфер.
pub fn segments(contents: &[u8], segment_size: Option<usize>) -> impl Iterator<Item = &[u8]> {
    contents.chunks(segment_size.filter(|s| *s > 0).unwrap_or(contents.len().max(1)))
}

impl CustomSender for MeshSender {
    fn is_valid_send_addr(&self, a: &CustomAddr) -> bool {
        a.id() == MESH_ID && a.data().len() == 32
    }

    fn poll_send(&self, _cx: &mut Context, dst: &CustomAddr, _src: Option<&CustomAddr>, t: &Transmit<'_>) -> Poll<io::Result<()>> {
        let Ok(dst) = <Key>::try_from(dst.data()) else { return Poll::Ready(Err(io::Error::other("bad mesh address"))) };
        for seg in segments(t.contents, t.segment_size) {
            self.0.send_payload(&dst, seg);
        }
        // UDP-семантика: потеря не ошибка; QUIC сквозного соединения её переживёт
        Poll::Ready(Ok(()))
    }
}

// -------------------------------------------------------------------- выбор пути

/// IP - основной путь, mesh и relay - запасные (`Backup`); внутри уровня меньший RTT с гистерезисом 5 мс, у IPv6 преимущество 3 мс (как у выбора iroh по умолчанию).
#[derive(Debug, Default)]
pub struct MeshBackupSelector;

fn sort_key(p: &PathSelectionData<'_>) -> Option<(u8, i128)> {
    let rtt = p.stats()?.rtt.as_nanos() as i128;
    Some(match p.network_path().addr_kind() {
        AddrKind::IpV4 => (0, rtt),
        AddrKind::IpV6 => (0, rtt - Duration::from_millis(3).as_nanos() as i128),
        _ => (1, rtt),
    })
}

impl PathSelector for MeshBackupSelector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let cur = ctx.current();
        let mut best: Option<(PathSelectionData<'_>, (u8, i128))> = None;
        let mut cur_key: Option<(u8, i128)> = None;
        for p in ctx.paths() {
            let Some(k) = sort_key(&p) else { continue };
            if Some(p.network_path()) == cur && cur_key.is_none_or(|c| k < c) {
                cur_key = Some(k);
            }
            if best.as_ref().is_none_or(|(_, b)| k < *b) {
                best = Some((p, k));
            }
        }
        let mut sel = PathSelection::none();
        let Some((bp, bk)) = best else { return sel };
        match cur_key {
            None => sel.set(&bp),
            Some(ck) if ck.0 != bk.0 => sel.set(&bp),
            Some(ck) if bk.1 + Duration::from_millis(5).as_nanos() as i128 <= ck.1 => sel.set(&bp),
            _ => {}
        }
        sel
    }
}

/// Состояние пути соединения для статуса: источник RTT и «как идёт» - сам QUIC (путь, статистика), а не пинги Link. `kind`: direct (IP) / mesh / relay;
/// `via` - диагностический префикс ключа транзита (4 байта hex, не destination RNS), `backup` - открытые запасные пути.
pub fn path_json(conn: &Connection, via: Option<Key>) -> serde_json::Value {
    use iroh::TransportAddr as T;
    let paths = conn.paths();
    let sel = paths.iter().find(|p| p.is_selected());
    let kind = match sel.as_ref().map(|p| p.remote_addr().clone()) {
        Some(T::Ip(_)) => "direct",
        Some(T::Custom(_)) => "mesh",
        Some(T::Relay(_)) => "relay",
        _ => "none",
    };
    let backups: Vec<&str> = paths
        .iter()
        .filter(|p| !p.is_selected())
        .map(|p| match p.remote_addr() {
            T::Ip(_) => "direct",
            T::Custom(_) => "mesh",
            T::Relay(_) => "relay",
            _ => "other",
        })
        .collect();
    let st = conn.stats();
    let via = if kind == "mesh" { via.map(|k| k[..4].iter().map(|b| format!("{b:02x}")).collect::<String>()) } else { None };
    let path_desc = match kind {
        "direct" => "прямой (IP)".to_string(),
        "mesh" => via.as_ref().map(|v| format!("mesh через {v}")).unwrap_or_else(|| "mesh".to_string()),
        "relay" => "relay".to_string(),
        _ => "путь не выбран".to_string(),
    };
    let black_holes_detected: u64 = paths.iter().map(|p| p.stats().black_holes_detected).sum();
    // по каждому открытому пути: тип, выбран ли, MTU и счётчики MTUD (диагностика PMTU запасных путей)
    let paths_detail: Vec<serde_json::Value> = paths
        .iter()
        .map(|p| {
            let s = p.stats();
            serde_json::json!({
                "kind": match p.remote_addr() { T::Ip(_) => "direct", T::Custom(_) => "mesh", T::Relay(_) => "relay", _ => "other" },
                "selected": p.is_selected(), "mtu": s.current_mtu,
                "probes_sent": s.sent_plpmtud_probes, "probes_lost": s.lost_plpmtud_probes, "black_holes": s.black_holes_detected,
            })
        })
        .collect();
    serde_json::json!({
        "paths_detail": paths_detail,
        "kind": kind,
        "connection_id": conn.stable_id(),
        "via": via, "path_desc": path_desc,
        "rtt_ms": sel.as_ref().map(|p| (p.rtt().as_secs_f64() * 1000.0 * 100.0).round() / 100.0),
        "backup": backups, "lost_packets": st.lost_packets, "paths": paths.len(),
        "max_datagram_size": conn.max_datagram_size(),
        "current_mtu": sel.as_ref().map(|p| p.stats().current_mtu),
        "black_holes_detected": black_holes_detected,
        "datagram_mtu_drops": st.datagram_mtu_drops,
    })
}

/// Конфигурация QUIC сквозных соединений по mesh (начальный MTU 1200); узел задаёт её при запуске.
static QUIC_CFG: OnceLock<iroh::endpoint::QuicTransportConfig> = OnceLock::new();

pub fn set_quic_cfg(c: iroh::endpoint::QuicTransportConfig) {
    let _ = QUIC_CFG.set(c);
}

pub fn quic_cfg() -> Option<iroh::endpoint::QuicTransportConfig> {
    QUIC_CFG.get().cloned()
}

impl Mesh {
    /// Принимать ли сквозное соединение от ключа: mesh включён, политика задана, ключ держит какие-либо права. Допуск VPN от этого не зависит.
    pub fn admit_e2e(&self, key: &Key) -> bool {
        self.enabled() && self.policy().is_some_and(|p| p.holds_rights(key))
    }
}

/// Входящее соединение пришло по mesh?
pub fn incoming_is_mesh(a: &iroh::endpoint::IncomingAddr) -> bool {
    matches!(a, iroh::endpoint::IncomingAddr::Custom(c) if c.id() == MESH_ID)
}

/// Адрес выхода только по mesh, без подсказок IP (проверки; в узле используется `endpoint_addr_with`).
#[cfg(test)]
pub fn endpoint_addr(key: &Key) -> Option<iroh::EndpointAddr> {
    let id = iroh::EndpointId::from_bytes(key).ok()?;
    Some(iroh::EndpointAddr::from_parts(id, [iroh::TransportAddr::Custom(addr_of(key))]))
}

/// Адрес выхода: mesh плюс проверенные подсказки IP (прошедшие фильтр носителя). С IP-подсказкой соединение сразу идёт прямым путём, если он достижим;
/// mesh остаётся тёплым запасным путём (правка iroh `open_custom_backups`). Подсказки нужны за NAT: iroh без relay/QAD не знает собственного публичного адреса.
pub fn endpoint_addr_with(key: &Key, ips: &[std::net::SocketAddr]) -> Option<iroh::EndpointAddr> {
    let id = iroh::EndpointId::from_bytes(key).ok()?;
    let mut addrs: Vec<iroh::TransportAddr> = ips.iter().map(|a| iroh::TransportAddr::Ip(*a)).collect();
    addrs.push(iroh::TransportAddr::Custom(addr_of(key)));
    Some(iroh::EndpointAddr::from_parts(id, addrs))
}

/// Выбранный путь соединения идёт через mesh (custom-транспорт), а не по IP.
pub fn selected_is_mesh(conn: &Connection) -> bool {
    conn.paths().iter().find(|p| p.is_selected()).is_some_and(|p| matches!(p.remote_addr(), iroh::TransportAddr::Custom(_)))
}

#[cfg(test)]
mod tests;
