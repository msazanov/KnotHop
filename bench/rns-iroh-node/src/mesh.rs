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

mod migration;

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
/// Одно соседское уведомление о недостижимости на пару в секунду, ограниченная память.
const UNREACH_INTERVAL: Duration = Duration::from_secs(1);
const UNREACH_MAX: usize = 1024;
/// Кэш решений политики: верно - 5 с (отзыв прав действует с такой задержкой), неверно - 2 с.
const AUTH_TTL_OK: Duration = Duration::from_secs(5);
const AUTH_TTL_NO: Duration = Duration::from_secs(2);
const AUTH_MAX: usize = 2048;
const ROUTE_TTL: Duration = Duration::from_secs(2);
/// Запись `hops` старше этого запрашивает обновление, старше `HOP_MAX_AGE` - не используется (кадр теряется, как при отсутствии маршрута).
const HOP_REFRESH: Duration = Duration::from_millis(500);
const HOP_MAX_AGE: Duration = Duration::from_secs(5);
const HOP_MAX: usize = 256;
/// Транзит, выбранный сторожком застоя, не закрепляется навсегда: после этого срока решение снова принимает маршрут RNS.
const STALL_HOP_TTL: Duration = Duration::from_secs(300);
/// Сколько не выбирать повторно транзит, отказавший для этого назначения (застой или явное «нет пути»).
const FAILED_VIA_TTL: Duration = Duration::from_secs(60);
/// Потолок нарастающей пометки повторно отказывающего транзита (60 с, 2, 4, 8 мин, 15 мин).
const FAILED_VIA_TTL_MAX: Duration = Duration::from_secs(15 * 60);
/// Столько подряд принимать через новый хоп, чтобы считать его рабочим и простить прежние отказы.
const VIA_PROVEN_AFTER: Duration = Duration::from_secs(20);
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
    /// Проверка именно местного назначения; она не меняет правила разрешения источников.
    fn local_key_for_id(&self, id: &Id) -> Option<Key> { self.key_for_id(id) }
    /// Источник кадра для конечного получателя; транзит всегда использует key_for_id.
    fn local_source_key_for_id(&self, id: &Id) -> Option<Key> { self.key_for_id(id) }
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
    /// Принятые доказательства смены транзита и те из них, что действительно изменили маршрут.
    pub migration_accepted: AtomicU64,
    pub migration_changed: AtomicU64,
    /// Транзит запомнен как отказавший по его собственному уведомлению.
    pub unreach_marked: AtomicU64,
    /// Соседские уведомления об отказе и реально снятые обратные пути.
    pub unreach_sent: AtomicU64,
    pub unreach_received: AtomicU64,
    pub unreach_removed: AtomicU64,
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
    /// смены первого хопа своих кадров (любая причина) и срабатывания сторожка застоя
    pub hop_changes: AtomicU64,
    pub stall_rotations: AtomicU64,
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
    migration_buckets: Mutex<HashMap<Key, Bucket>>,
    migration_sent: Mutex<HashMap<(Key, Key), Instant>>,
    auth: Mutex<HashMap<(Key, Key, Key), (bool, Instant)>>,
    rev: Mutex<HashMap<Key, (Key, Instant)>>,
    /// Подтверждённый сквозной TLS миграционный маршрут: действует только
    /// пока живо соответствующее соединение и не сменилось поколение прав.
    verified_rev: Mutex<HashMap<Key, (Key, usize)>>,
    hop_events: Mutex<std::collections::VecDeque<HopEvent>>,
    unreach_sent: Mutex<HashMap<(Key, Key), Instant>>,
    /// кэш маршрутов RNS (путь меняется редко, а запрос таблицы путей дорог): 2 с
    routes: Mutex<HashMap<Key, (Option<Key>, Instant)>>,
    /// Следующий хоп для исходящих кадров (poll_send читает ТОЛЬКО его: poll_send вызывается под замком QUIC-соединения, а разрешение хопа берёт замки
    /// мультиплексоров и Trust - обратный порядок замков у `Mux::send` дал бы взаимную блокировку). Заполняют `warm`/`prepare` и поток-разрешитель.
    hops: Mutex<HashMap<Key, HopEntry>>,
    ids: Mutex<HashMap<Id, (Option<Key>, Instant)>>,
    local_sources: Mutex<HashMap<Id, (Option<Key>, u64, Instant)>>,
    local_id: Mutex<Option<(Option<Key>, u64, Instant)>>,
    ride_cache: Mutex<HashMap<usize, (bool, Instant)>>,
    /// сдвиг выбора альтернативного транзита по назначению (растёт после неудачной попытки соединения)
    alt_rot: Mutex<HashMap<Key, u32>>,
    stall_hops: Mutex<HashMap<Key, (Key, Instant)>>,
    /// (назначение, транзит) -> до какого момента не выбирать при смене транзита
    failed_via: Mutex<HashMap<(Key, Key), Instant>>,
    /// подряд отказов транзита к dst: срок пометки растёт вдвое (`FAILED_VIA_TTL` .. `FAILED_VIA_TTL_MAX`); сброс — после
    /// `VIA_PROVEN_AFTER` приёма через него. Иначе неисправный сосед (de 10.11) снова попадал в ротацию каждые 60 с.
    via_fails: Mutex<HashMap<(Key, Key), u32>>,
    /// Прямые адреса выходов, реально подтверждённые двусторонней передачей >1 МиБ через этот конкретный IP-путь.
    confirmed_direct: Mutex<HashMap<std::net::SocketAddr, Instant>>,
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
    migration_seq: AtomicU64,
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
            migration_buckets: Default::default(),
            migration_sent: Default::default(),
            auth: Default::default(),
            rev: Default::default(),
            verified_rev: Default::default(),
            hop_events: Default::default(),
            unreach_sent: Default::default(),
            routes: Default::default(),
            hops: Default::default(),
            ids: Default::default(),
            local_sources: Default::default(),
            local_id: Default::default(),
            ride_cache: Default::default(),
            alt_rot: Default::default(),
            stall_hops: Default::default(),
            failed_via: Default::default(),
            via_fails: Default::default(),
            confirmed_direct: Default::default(),
            hop_pending: Default::default(),
            hop_req: Mutex::new(hop_tx),
            txq,
            e2e: Default::default(),
            e2e_max: AtomicU64::new(E2E_MAX as u64),
            seen_gen: AtomicU64::new(0),
            min_nbr_dgram: AtomicU64::new((QUIC_MIN_UDP + HDR) as u64),
            migration_seq: AtomicU64::new(0),
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

    pub fn selector(self: &Arc<Self>) -> Arc<MeshBackupSelector> {
        Arc::new(MeshBackupSelector(Some(Arc::downgrade(self))))
    }

    pub fn confirm_direct(&self, addr: std::net::SocketAddr) {
        const TTL: Duration = Duration::from_secs(30 * 60);
        let addr = std::net::SocketAddr::new(addr.ip().to_canonical(), addr.port());
        let now = Instant::now();
        let mut m = self.confirmed_direct.lock().unwrap();
        if !m.contains_key(&addr) && m.len() >= 256 {
            m.retain(|_, t| now.saturating_duration_since(*t) < TTL);
            if m.len() >= 256 {
                return;
            }
        }
        m.insert(addr, now);
    }

    pub fn revoke_direct(&self, addr: &std::net::SocketAddr) {
        let addr = std::net::SocketAddr::new(addr.ip().to_canonical(), addr.port());
        self.confirmed_direct.lock().unwrap().remove(&addr);
    }

    pub fn is_direct_confirmed(&self, addr: &std::net::SocketAddr) -> bool {
        const TTL: Duration = Duration::from_secs(30 * 60);
        let addr = std::net::SocketAddr::new(addr.ip().to_canonical(), addr.port());
        let now = Instant::now();
        let mut m = self.confirmed_direct.lock().unwrap();
        match m.get(&addr).copied() {
            Some(t) if now.saturating_duration_since(t) < TTL => true,
            Some(_) => {
                m.remove(&addr);
                false
            }
            None => false,
        }
    }

    /// Зарегистрировать соединение для аутентифицированной миграции транзита (`e2e.conns`), не помечая его
    /// навсегда сквозным (`e2e.ids`): пока соединение идёт прямым IP-путём, оно остаётся обычным носителем,
    /// но при переходе на тёплый запасной mesh-путь поддерживает смену транзита с TLS-exporter MAC.
    pub fn register_migratable(self: &Arc<Self>, conn: &Connection) {
        let id = conn.stable_id();
        let max = (self.e2e_max.load(Relaxed) as usize).saturating_mul(2).max(E2E_MAX);
        {
            let mut e = self.e2e.lock().unwrap();
            if e.conns.contains_key(&id) || e.conns.len() >= max {
                return;
            }
            e.conns.insert(id, (conn.clone(), migration::ReplayGuard::default()));
        }
        let (m, c) = (self.clone(), conn.clone());
        tokio::spawn(async move {
            let _ = c.closed().await;
            {
                let mut e = m.e2e.lock().unwrap();
                e.ids.remove(&id);
                e.conns.remove(&id);
            }
            m.verified_rev.lock().unwrap().retain(|_, (_, sid)| *sid != id);
        });
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
                e.conns.insert(id, (conn.clone(), migration::ReplayGuard::default()));
            }
        }
        let (m, c) = (self.clone(), conn.clone());
        tokio::spawn(async move {
            let _ = c.closed().await;
            {
                let mut e = m.e2e.lock().unwrap();
                e.ids.remove(&id);
                e.conns.remove(&id);
            }
            m.verified_rev.lock().unwrap().retain(|_, (_, sid)| *sid != id);
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

    /// Соединение сейчас едет по mesh: помечено сквозным либо выбранный путь у него `Custom` с `MESH_ID` (не REALITY). Соединение с тёплым запасным mesh-путём (основной - IP) соседом
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
        // только mesh: туннель REALITY (другой custom-путь, `reality_carrier::REALITY_ID`) - обычный TCP-носитель к соседу, кадры mesh по нему ходят как по IP
        let v = conn.paths().iter().any(|p| p.is_selected() && is_mesh_addr(p.remote_addr()));
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
            self.local_sources.lock().unwrap().clear();
            *self.local_id.lock().unwrap() = None;
            self.routes.lock().unwrap().clear();
            self.hops.lock().unwrap().clear();
            self.rev.lock().unwrap().clear();
            self.verified_rev.lock().unwrap().clear();
            self.stall_hops.lock().unwrap().clear();
            self.failed_via.lock().unwrap().clear();
            self.via_fails.lock().unwrap().clear();
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
            "rev_conflict": c.rev_conflict.load(Relaxed), "unreach_sent": c.unreach_sent.load(Relaxed), "unreach_received": c.unreach_received.load(Relaxed), "unreach_removed": c.unreach_removed.load(Relaxed), "drop_id_ambiguous": c.drop_id_ambiguous.load(Relaxed), "drop_recursion": c.drop_recursion.load(Relaxed),
            "e2e_overflow": c.e2e_overflow.load(Relaxed), "drop_queue_full": c.drop_queue_full.load(Relaxed), "alt_hops": c.alt_hops.load(Relaxed), "hop_changes": c.hop_changes.load(Relaxed), "stall_rotations": c.stall_rotations.load(Relaxed), "gen_resets": c.gen_resets.load(Relaxed),
            "migration_accepted": c.migration_accepted.load(Relaxed), "migration_changed": c.migration_changed.load(Relaxed), "unreach_marked": c.unreach_marked.load(Relaxed),
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

    /// Миграция проверяет MAC: отдельный небольшой бюджет до криптографии.
    fn rate_migration(&self, now: Instant, prev: &Key) -> bool {
        let mut m = self.migration_buckets.lock().unwrap();
        if !m.contains_key(prev) && m.len() >= BUCKET_MAX_NBR {
            m.retain(|_, b| now.saturating_duration_since(b.last) < Duration::from_secs(30));
            if m.len() >= BUCKET_MAX_NBR { return false; }
        }
        m.entry(*prev).or_insert(Bucket { tokens: 4.0, last: now }).take(now, 2.0, 4.0)
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

    /// Отдельный кэш для своего назначения: не добавляем собственный ключ в кэш источников.
    fn local_key(&self, now: Instant, policy: &dyn Policy) -> Option<Key> {
        let generation = policy.generation();
        {
            let c = self.local_id.lock().unwrap();
            if let Some((k, g, until)) = *c {
                if g == generation && until > now { return k; }
            }
        }
        let k = policy.local_key_for_id(&id_of(&self.me));
        // Изменение прав во время разрешения нельзя закэшировать под новым поколением.
        if policy.generation() != generation { return None; }
        *self.local_id.lock().unwrap() = Some((k, generation, now + if k.is_some() { Duration::from_secs(30) } else { Duration::from_secs(5) }));
        k
    }

    fn local_source_key(&self, now: Instant, id: &Id, policy: &dyn Policy) -> Option<Key> {
        let generation = policy.generation();
        {
            let c = self.local_sources.lock().unwrap();
            if let Some((k, g, until)) = c.get(id) {
                if *g == generation && *until > now { return *k; }
            }
        }
        let k = policy.local_source_key_for_id(id);
        if policy.generation() != generation { return None; }
        let mut c = self.local_sources.lock().unwrap();
        if c.len() >= 1024 { c.retain(|_, (_, _, until)| *until > now); }
        if c.len() < 1024 { c.insert(*id, (k, generation, now + if k.is_some() { Duration::from_secs(30) } else { Duration::from_secs(5) })); }
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

    /// Ошибка маршрута направляется только непосредственному соседу, от которого
    /// пришёл разрешённый к пересылке кадр; ответ меньше исходного кадра.
    fn send_unreachable(&self, now: Instant, prev: &Key, dst: &Key) {
        let Some(conn) = self.carrier(prev) else { return };
        let mut sent = self.unreach_sent.lock().unwrap();
        if sent.get(&(*prev, *dst)).is_some_and(|t| now.saturating_duration_since(*t) < UNREACH_INTERVAL) { return; }
        if sent.len() >= UNREACH_MAX {
            sent.retain(|_, t| now.saturating_duration_since(*t) < UNREACH_INTERVAL);
            if sent.len() >= UNREACH_MAX { return; }
        }
        sent.insert((*prev, *dst), now);
        drop(sent);
        let mut b = BytesMut::with_capacity(10);
        b.extend_from_slice(&[TAG, 0]);
        b.extend_from_slice(&id_of(dst));
        if conn.send_datagram(b.freeze()).is_ok() { self.c.unreach_sent.fetch_add(1, Relaxed); }
    }

    /// Отзыв обратного пути возможен только от TLS-аутентифицированного соседа,
    /// через которого именно эта запись была выучена. Уведомление не создаёт и
    /// не переназначает путь и не действует на другой/более новый транзит.
    fn accept_unreachable(&self, now: Instant, prev: &Key, id: &Id, policy: &dyn Policy) {
        self.c.unreach_received.fetch_add(1, Relaxed);
        if !self.cached(now, (*prev, [0; 32], [0; 32]), || policy.holds_rights(prev)) ||
            !self.cached(now, (*prev, [1; 32], [0; 32]), || policy.is_transit(prev)) { return; }
        let Some(dst) = self.local_source_key(now, id, policy) else { return };
        let removed = {
            let mut rev = self.rev.lock().unwrap();
            if rev.get(&dst).is_some_and(|(via, _)| via == prev) { rev.remove(&dst); true } else { false }
        };
        if removed {
            self.c.unreach_removed.fetch_add(1, Relaxed);
            self.warm(&dst);
        }
        // Транзит сообщил, что не довёл кадр до `dst`: не брать его при следующей смене. Само уведомление транзит не меняет:
        // оно бывает и при временной причине (просадка MTU, смена носителя), а работающий путь бросать нельзя (W v0.1.68–69: метание
        // транзита каждые 10–30 с). Застой определяет сторожок по реальному приёму. Сосед может пометить только самого себя.
        if self.originates_to(&dst) {
            let now = Instant::now();
            let mut failed = self.failed_via.lock().unwrap();
            if failed.len() >= HOP_MAX { failed.retain(|_, until| now < *until); }
            if failed.len() < HOP_MAX {
                failed.insert((dst, *prev), now + FAILED_VIA_TTL);
                self.c.unreach_marked.fetch_add(1, Relaxed);
            }
        }
    }

    /// Отказ транзита `via` к `dst`: следующий срок пометки (вдвое длиннее предыдущего подряд идущего отказа).
    fn failed_ttl(&self, dst: &Key, via: &Key) -> Duration {
        let mut f = self.via_fails.lock().unwrap();
        if f.len() >= HOP_MAX * 4 && !f.contains_key(&(*dst, *via)) { f.clear(); }
        let n = f.entry((*dst, *via)).or_insert(0);
        let ttl = FAILED_VIA_TTL.saturating_mul(1u32 << (*n).min(5)).min(FAILED_VIA_TTL_MAX);
        *n = n.saturating_add(1);
        ttl
    }

    /// Через `via` к `dst` устойчиво принимаем: прежние отказы прощены.
    fn via_proven(&self, dst: &Key, via: &Key) {
        self.via_fails.lock().unwrap().remove(&(*dst, *via));
    }

    fn via_failed(&self, dst: &Key, via: &Key, now: Instant) -> bool {
        self.failed_via.lock().unwrap().get(&(*dst, *via)).is_some_and(|until| now < *until)
    }

    /// Есть живое сквозное соединение к `dst`, начатое этим узлом.
    fn initiates_to(&self, dst: &Key) -> bool {
        let connections: Vec<_> = self.e2e.lock().unwrap().conns.values().map(|(c, _)| c.clone()).collect();
        connections.iter().any(|c| c.remote_id().as_bytes() == dst && c.close_reason().is_none() && matches!(c.side(), iroh::endpoint::Side::Client))
    }

    /// Мы инициатор соединения с `dst`, которое едет по mesh: сквозного либо собственного носителя с тёплым mesh-путём
    /// (дозвон клиента; у обоих работают сторожок застоя и миграция).
    fn originates_to(&self, dst: &Key) -> bool {
        // сырой носитель: `carrier()` отбрасывает именно тот случай, что нужен, — носитель, выбравший mesh-путь
        self.initiates_to(dst) || (self.carriers)(dst).is_some_and(|c| c.close_reason().is_none() && matches!(c.side(), iroh::endpoint::Side::Client))
    }

    /// Доказательство приходит от последнего TLS-аутентифицированного соседа.
    /// Оно не заменяет проверок прав и действительно только для живого e2e TLS.
    fn accept_migration(&self, now: Instant, prev: &Key, d: &[u8], policy: &dyn Policy) {
        if !self.rate_migration(now, prev) || d.len() != migration::LEN { return; }
        if d[3..11] != id_of(&self.me) || self.local_key(now, policy) != Some(self.me) { return; }
        let src_id: Id = match d[11..19].try_into() { Ok(id) => id, Err(_) => return };
        let Some(src) = self.local_source_key(now, &src_id, policy) else { return };
        let generation = policy.generation();
        if src == self.me || src == *prev || !policy.holds_rights(&src)
            || !policy.holds_rights(prev) || !policy.is_transit(prev) { return; }
        // Exporter берёт замок QUIC: нельзя держать e2e при обращении к нему,
        // поскольку poll_send под замком QUIC проверяет e2e.
        let connections: Vec<_> = self.e2e.lock().unwrap().conns.iter()
            .map(|(sid, (conn, _))| (*sid, conn.clone())).collect();
        for (sid, conn) in connections {
            // Следует только отвечающая сторона: если следуют обе, разные начальные маршруты заставляют их меняться транзитами бесконечно.
            if conn.remote_id().as_bytes() != &src || conn.close_reason().is_some() || !matches!(conn.side(), iroh::endpoint::Side::Server) { continue; }
            let mut key = [0u8; 32];
            if conn.export_keying_material(&mut key, migration::LABEL, b"").is_err() { continue; }
            let mut e = self.e2e.lock().unwrap();
            let Some((_, replay)) = e.conns.get_mut(&sid) else { continue };
            if !replay.accept(&key, &src, &self.me, prev, d) { continue; }
            if policy.generation() != generation { return; }
            let mut verified = self.verified_rev.lock().unwrap();
            if !verified.contains_key(&src) && verified.len() >= E2E_MAX { return; }
            let previous = verified.insert(src, (*prev, sid));
            drop(verified);
            drop(e);
            self.c.migration_accepted.fetch_add(1, Relaxed);
            // Доказательства идут и при неизменном транзите; запись хопа заменяется на месте,
            // потому что между удалением и пересчётом `send_payload` теряет все кадры.
            if previous != Some((*prev, sid)) {
                self.c.migration_changed.fetch_add(1, Relaxed);
                // журнал отвечающей стороны: за клиентом перешли на его новый транзит (иначе асимметрию путей не видно)
                self.push_hop_event(HopEvent { dst: src, old: previous.map(|(v, _)| v), new: Some(*prev), why: "migrated", detail: String::new() });
                self.warm(&src);
            }
            return;
        }
    }

    /// Только один транзит: источник и назначение — непосредственные соседи.
    /// Транзит не может изменить доказательство и не устанавливает маршрут.
    fn forward_migration(&self, now: Instant, prev: &Key, d: &Bytes, policy: &dyn Policy) {
        if !self.rate_migration(now, prev) || d.len() != migration::LEN || d[19..27] != id_of(&self.me) { return; }
        let src_id: Id = d[11..19].try_into().unwrap();
        let dst_id: Id = d[3..11].try_into().unwrap();
        let Some(src) = self.key_of(now, &src_id, policy) else { return };
        let Some(dst) = self.key_of(now, &dst_id, policy) else { return };
        if &src != prev || dst == src || dst == self.me || !policy.may_forward(prev, &src, &dst) { return; }
        if let Some(conn) = self.carrier(&dst) {
            let _ = conn.send_datagram(d.clone());
        }
    }

    /// Вызывается вне poll_send и вне замков QUIC. Экспортёр и счётчик
    /// принадлежат сквозному соединению; размер/частота сообщений ограничены.
    fn send_migration(&self, dst: &Key, via: &Key, carrier: &Connection) {
        if via == dst { return; }
        let now = Instant::now();
        {
            let mut sent = self.migration_sent.lock().unwrap();
            if sent.get(&(*dst, *via)).is_some_and(|t| now.saturating_duration_since(*t) < Duration::from_secs(1)) { return; }
            if sent.len() >= E2E_MAX {
                sent.retain(|_, t| now.saturating_duration_since(*t) < Duration::from_secs(30));
                if sent.len() >= E2E_MAX && !sent.contains_key(&(*dst, *via)) { return; }
            }
            sent.insert((*dst, *via), now);
        }
        let connections: Vec<_> = self.e2e.lock().unwrap().conns.values().map(|(c, _)| c.clone()).collect();
        for conn in connections {
            // Маршрут сквозного соединения определяет его инициатор (см. `accept_migration`).
            if conn.remote_id().as_bytes() != dst || conn.close_reason().is_some() || !matches!(conn.side(), iroh::endpoint::Side::Client) { continue; }
            let mut key = [0u8; 32];
            if conn.export_keying_material(&mut key, migration::LABEL, b"").is_err() { continue; }
            let Ok(seq) = self.migration_seq.fetch_update(Relaxed, Relaxed, |n| n.checked_add(1)) else { return };
            if let Some(proof) = migration::encode(&key, &self.me, dst, via, seq + 1) {
                let _ = carrier.send_datagram(Bytes::from(proof));
            }
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
                let available = c.max_datagram_size().unwrap_or(0);
                if available < need {
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
        self.hop_origin_why(now, dst, policy).map(|(k, _)| k)
    }

    /// `next_hop_origin` с причиной выбора (для журнала смен хопа): stall | verified | alt-direct | rns | alt.
    fn hop_origin_why(&self, now: Instant, dst: &Key, policy: &dyn Policy) -> Option<(Key, &'static str)> {
        // Локальное решение о застое важнее старого подтверждения от пира:
        // иначе подтверждённый, но замолчавший хоп отменял бы переключение.
        let forced = {
            let mut pins = self.stall_hops.lock().unwrap();
            match pins.get(dst).copied() {
                Some((_, until)) if now >= until => { pins.remove(dst); None }
                Some((via, _)) => Some(via),
                None => None,
            }
        };
        if let Some(via) = forced {
            if policy.is_transit(&via) && policy.holds_rights(&via) && self.neighbor(&via).is_ok() { return Some((via, "stall")); }
            // Закреплённый транзит потерял носитель/право: закрепление снимаем сразу. Иначе оно 300 с перехватывает трафик всякий раз,
            // когда мигающий носитель снова жив (полевой журнал 10.11: uae ↔ de каждые 3–15 с, de с QUIC то есть, то нет).
            let mut pins = self.stall_hops.lock().unwrap();
            if pins.get(dst).is_some_and(|(v, _)| *v == via) { pins.remove(dst); }
        }
        let verified = self.verified_rev.lock().unwrap().get(dst).copied();
        if let Some((via, sid)) = verified {
            let live = self.e2e.lock().unwrap().conns.contains_key(&sid);
            if live && policy.holds_rights(dst)
                && policy.holds_rights(&via) && policy.is_transit(&via) && self.neighbor(&via).is_ok() {
                return Some((via, "verified"));
            }
        }
        // Работающий транзит не бросаем ради пересчёта: смена маршрута RNS, состава соседей с QUIC (сдвиг `alt_transit`) или истечение
        // закрепления сторожка уводили живое соединение на непроверенный хоп (полевой журнал 10.11: nl1 → ru1 по `rns` через 1 с после
        // установления, затем 3–4 с застоя на ru1 и de; повтор каждые `STALL_HOP_TTL`). Хоп меняют только сторожок застоя/отказа
        // (`stall`, `via_failed`), проверенная миграция (`verified`) или потеря права/носителя у самого транзита.
        // Только у инициатора сквозного соединения: у него работают сторожок и пометка `unreachable`; отвечающая сторона следует за ним
        // (`verified`) и уходит со старого транзита снятием обратной записи по `unreachable`.
        if let Some(cur) = self.hop_peer(dst).filter(|_| self.originates_to(dst)) {
            if cur != *dst && policy.is_transit(&cur) && policy.holds_rights(&cur) && self.neighbor(&cur).is_ok()
                && !self.via_failed(dst, &cur, now) {
                return Some((cur, "keep"));
            }
        }
        if self.carrier(dst).is_some() {
            let k = self.alt_transit(dst, policy)?;
            self.c.alt_hops.fetch_add(1, Relaxed);
            return Some((k, "alt-direct"));
        }
        // Нет ни прямого носителя, ни маршрута RNS через наш QUIC-носитель, ни обратной записи (прямой путь к выходу закрыт, путь RNS идёт через TCP
        // публичного хаба): первым хопом берём транзит с живым QUIC. Это подсказка, не право: пересылку разрешает сам транзит (`may_forward`).
        let routed = self.next_hop_via(now, dst, policy);
        if routed.is_some_and(|k| self.neighbor(&k).is_ok()) {
            return routed.map(|k| (k, "rns"));
        }
        if let Some(k) = self.alt_transit(dst, policy) {
            self.c.alt_hops.fetch_add(1, Relaxed);
            return Some((k, "alt"));
        }
        // Сохраняем диагностическую причину (нет QUIC / слишком мал MTU),
        // когда подходящего запасного транзита тоже нет.
        routed.map(|k| (k, "rns"))
    }

    /// Следующая попытка соединения с `dst` идёт через другой транзит (после неудачи; сдвиг в списке кандидатов `alt_transit`).
    pub fn rotate_alt(&self, dst: &Key) {
        let mut r = self.alt_rot.lock().unwrap();
        if r.len() >= 64 && !r.contains_key(dst) {
            r.clear();
        }
        let e = r.entry(*dst).or_insert(0);
        *e = e.wrapping_add(1);
        drop(r);
        self.hops.lock().unwrap().remove(dst);
    }

    /// Число живых транзитных соседей к `dst` прямо сейчас (для быстрого перебора без лишнего ожидания).
    pub fn live_transit_count(&self, dst: &Key) -> usize {
        let Some(policy) = self.policy() else { return 0 };
        let mut c: Vec<Key> = policy.transit_candidates().into_iter()
            .filter(|k| k != dst && k != &self.me && policy.holds_rights(k) && policy.is_transit(k) && self.neighbor(k).is_ok())
            .collect();
        c.sort();
        c.dedup();
        c.len()
    }

    /// Выбор другого доступного первого хопа после застоя; RNS-маршрут остаётся
    /// подсказкой, но не должен немедленно вернуть нас на тот же чёрный ход.
    /// Перебор круговой (`alt_rot`), чтобы при 3+ транзитах не зациклиться между двумя.
    fn rotate_stalled(&self, dst: &Key) -> bool { self.rotate_hop(dst, true) }

    /// Смена хопа сторожком. `escalate` — настоящий застой (нет приёма): отказавший транзит помечается нарастающим сроком.
    /// Отказ сразу после смены («нет пути» от нового транзита) — фиксированные `FAILED_VIA_TTL`: «нет пути» бывает и временным,
    /// а нарастание за секунды перекидки исключало исправные транзиты на минуты (Honor 11.11, es ↔ uae раз в секунду).
    fn rotate_hop(&self, dst: &Key, escalate: bool) -> bool {
        let Some(policy) = self.policy() else { return false };
        self.sync_gen(policy.as_ref());
        let old = self.hop_peer(dst);
        let mut candidates: Vec<_> = policy.transit_candidates().into_iter()
            .filter(|k| k != dst && k != &self.me && Some(*k) != old
                && policy.holds_rights(k) && policy.is_transit(k) && self.neighbor(k).is_ok())
            .collect();
        candidates.sort();
        candidates.dedup();
        if candidates.is_empty() { return false; }
        let all_failed = {
            let now = Instant::now();
            let mut failed = self.failed_via.lock().unwrap();
            failed.retain(|_, until| now < *until);
            if let Some(o) = old {
                let ttl = if escalate { self.failed_ttl(dst, &o) } else { FAILED_VIA_TTL };
                if failed.len() < HOP_MAX { failed.insert((*dst, o), now + ttl); }
            }
            // Если отказали все, выбирать из всех: остаться совсем без транзита хуже. Тогда — наименее отказывавший, а не
            // следующий по кругу: иначе выбор снова попадал на только что отказавший и через секунду — новый «отказ».
            let fresh: Vec<_> = candidates.iter().copied().filter(|k| !failed.contains_key(&(*dst, *k))).collect();
            if !fresh.is_empty() {
                candidates = fresh;
                false
            } else {
                let fails = self.via_fails.lock().unwrap();
                let least = candidates.iter().map(|k| fails.get(&(*dst, *k)).copied().unwrap_or(0)).min().unwrap_or(0);
                candidates.retain(|k| fails.get(&(*dst, *k)).copied().unwrap_or(0) == least);
                true
            }
        };
        let idx = {
            let mut r = self.alt_rot.lock().unwrap();
            if r.len() >= 64 && !r.contains_key(dst) { r.clear(); }
            let e = r.entry(*dst).or_insert(0);
            let cur = *e as usize;
            *e = e.wrapping_add(1);
            cur
        };
        let via = candidates[idx % candidates.len()];
        let mut forced = self.stall_hops.lock().unwrap();
        let now = Instant::now();
        if forced.len() >= HOP_MAX && !forced.contains_key(dst) {
            forced.retain(|_, (_, until)| now < *until);
            if forced.len() >= HOP_MAX { return false; }
        }
        forced.insert(*dst, (via, now + STALL_HOP_TTL));
        drop(forced);
        if all_failed {
            // Выбран заведомо помеченный (лучше, чем остаться без транзита): старая пометка снимается, иначе проверка «отказа»
            // через секунду принимала её за новый отказ и меняла хоп по кругу (fin1 12.11: nl1↔uae раз в 1–1,5 с, ~60 с без связи).
            // Новый отказ — только по новому уведомлению от него или по застою; счётчик нарастания (`via_fails`) сохраняется.
            self.failed_via.lock().unwrap().remove(&(*dst, via));
        }
        self.warm(dst);
        true
    }

    /// Запускается только инициатором сквозного соединения, не транзитом.
    /// Бездействие без отправленных ack-eliciting кадров не считается застоем.
    /// Также отзывает подтверждение прямого IP, если сторожок iroh увёл трафик обратно на mesh.
    pub async fn watch_mesh_stall(self: Arc<Self>, conn: Connection) {
        let dst = *conn.remote_id().as_bytes();
        let mut watch = StallWatch::default();
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        let mut retry_until: Option<Instant> = None;
        let mut retry_at = Instant::now();
        let mut selected_ip: Option<std::net::SocketAddr> = None;
        let (mut rotated_rx, mut next_rotate) = (0u64, Instant::now());
        // (хоп, с какого момента, приём на тот момент, уже прощён): устойчивый приём через хоп снимает его прежние отказы
        let mut on_hop: Option<(Key, Instant, u64, bool)> = None;
        loop {
            tick.tick().await;
            if conn.close_reason().is_some() { break; }
            let now = Instant::now();
            if retry_until.is_some_and(|until| now < until) {
                if now >= retry_at {
                    self.warm(&dst);
                    retry_at = now + Duration::from_secs(1);
                }
            } else {
                retry_until = None;
            }
            let paths = conn.paths();
            if let Some(sa) = paths.iter().find(|p| p.is_selected()).and_then(|p| match p.remote_addr() {
                iroh::TransportAddr::Ip(sa) => Some(*sa),
                _ => None,
            }) {
                selected_ip = Some(sa);
            }
            let sample = paths.iter().find(|p| p.is_selected() && is_mesh_addr(p.remote_addr()))
                .map(|p| p.stats());
            let Some(st) = sample else { watch = StallWatch::default(); continue };
            if let Some(sa) = selected_ip.take() {
                // Трафик шёл напрямую по IP, но сторожок увёл соединение на mesh (DPI или обрыв):
                // прямому адресу требуется повторная проверка >1 МиБ перед следующим возвратом.
                self.revoke_direct(&sa);
            }
            let rx_now = st.frame_rx.authenticated_progress();
            match (self.hop_peer(&dst), on_hop.as_mut()) {
                (Some(h), Some((cur, since, rx0, done))) if *cur == h => {
                    if !*done && now.saturating_duration_since(*since) >= VIA_PROVEN_AFTER && rx_now > *rx0 && watch.pending_since.is_none() {
                        self.via_proven(&dst, &h);
                        *done = true;
                    }
                }
                (Some(h), _) => on_hop = Some((h, now, rx_now, false)),
                (None, _) => on_hop = None,
            }
            // После смены транзита новый сам ответил «нет пути», и данных через него не пришло: окно ожидания незачем досиживать.
            // Без условия на приём уведомление бросало бы рабочий транзит.
            let refused = retry_until.is_some() && now >= next_rotate && rx_now == rotated_rx
                && self.hop_peer(&dst).is_some_and(|hop| self.via_failed(&dst, &hop, now));
            if refused || (watch.observe(now, rx_now, st.frame_tx.ack_eliciting_progress(), st.rtt) && retry_until.is_none()) {
                let old = self.hop_peer(&dst);
                let gap = watch.pending_since.map_or(0, |s| now.saturating_duration_since(s).as_millis());
                let rotated = self.rotate_hop(&dst, !refused);
                on_hop = None;
                self.c.stall_rotations.fetch_add(1, Relaxed);
                self.push_hop_event(HopEvent { dst, old, new: None, why: "stall-detect",
                    detail: format!("{} без приёма {gap} мс, rtt {} мс, сменён={rotated}", if refused { "отказ транзита," } else { "застой:" }, st.rtt.as_millis()) });
                if rotated {
                    retry_until = Some(now + Duration::from_secs(6));
                    retry_at = now + Duration::from_secs(1);
                    rotated_rx = rx_now;
                    next_rotate = now + Duration::from_secs(1);
                }
                #[cfg(test)]
                eprintln!("mesh watchdog: rotate={rotated}, rx={}, tx={}, rtt_ms={}", st.frame_rx.authenticated_progress(), st.frame_tx.ack_eliciting_progress(), st.rtt.as_millis());
                #[cfg(not(test))]
                let _ = rotated;
                watch = StallWatch::default();
            }
        }
    }

    /// Фоновая проверка прямого IP-кандидата объёмом >1 МиБ параллельно работающему транзиту (`mesh`).
    /// Пока проверка не прошла, выбранный путь не переключается и VPN-трафик продолжает идти через транзит.
    pub async fn watch_direct_upgrade(self: Arc<Self>, conn: Connection) {
        let mut backoff = Duration::from_secs(30);
        let mut next_try = Instant::now() + Duration::from_millis(400);
        loop {
            // Закрытие — по событию, время попытки — до замка соединения: `close_reason()` берёт его, и опрос раз в 500 мс при паузе
            // в 30+ с был лишним ожиданием рабочего потока tokio на вытесненном драйвере соединения (fin1 10.11: до 2,2 с).
            tokio::select! {
                _ = conn.closed() => break,
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
            if Instant::now() < next_try { continue; }
            let paths = conn.paths();
            if !paths.iter().any(|p| p.is_selected() && is_mesh_addr(p.remote_addr())) {
                continue;
            }
            let candidate = paths.iter().find_map(|p| match p.remote_addr() {
                iroh::TransportAddr::Ip(sa) if !self.is_direct_confirmed(sa) => Some((p.id(), *sa)),
                _ => None,
            });
            let Some((path_id, sa)) = candidate else { continue };
            let nonce = {
                use rand_core::RngCore as _;
                rand_core::OsRng.next_u64()
            };
            if crate::qprobe::run_bulk_on_path(&conn, path_id, nonce).await.is_some() {
                self.confirm_direct(sa);
                backoff = Duration::from_secs(30);
                next_try = Instant::now() + backoff;
                for p in conn.paths().iter() {
                    if p.id() == path_id {
                        let _ = p.ping();
                    }
                }
            } else {
                next_try = Instant::now() + backoff;
                backoff = (backoff * 2).min(Duration::from_secs(300));
            }
        }
    }

    /// Альтернативный транзит к `dst`: узел с правом TRANSIT, не `dst`, с живым QUIC-носителем вне mesh; выбор стабилен (меньший `k xor dst`).
    /// Знания о том, видит ли транзит само `dst`, нет: если он `dst` не достаёт, он кадры отбросит, и путь не подтвердится (запасным он не станет).
    fn alt_transit(&self, dst: &Key, policy: &dyn Policy) -> Option<Key> {
        let mut c: Vec<Key> = policy.transit_candidates().into_iter().filter(|k| k != dst && k != &self.me && self.neighbor(k).is_ok()).collect();
        c.sort_by_key(|k| {
            let mut x = [0u8; 8];
            for i in 0..8 {
                x[i] = k[i] ^ dst[i];
            }
            u64::from_be_bytes(x)
        });
        c.dedup();
        if c.is_empty() {
            return None;
        }
        let rot = self.alt_rot.lock().unwrap().get(dst).copied().unwrap_or(0) as usize;
        Some(c[rot % c.len()])
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
        if d.len() < 2 || d[0] != TAG {
            c.drop_malformed.fetch_add(1, Relaxed);
            return;
        }
        let Some(policy) = self.policy() else {
            c.drop_no_policy.fetch_add(1, Relaxed);
            return;
        };
        self.sync_gen(policy.as_ref());
        if d.len() == migration::LEN && d[..3] == [TAG, 0, migration::KIND] {
            let now = Instant::now();
            if d[3..11] == id_of(&self.me) {
                self.accept_migration(now, prev, d, policy.as_ref());
            } else {
                self.forward_migration(now, prev, d, policy.as_ref());
            }
            return;
        }
        if d[1] == 0 && d.len() == 10 {
            let now = Instant::now();
            if self.rate_neighbor(now, prev) {
                let id: Id = d[2..10].try_into().unwrap();
                self.accept_unreachable(now, prev, &id, policy.as_ref());
            } else {
                c.drop_rate_neighbor.fetch_add(1, Relaxed);
            }
            return;
        }
        if d.len() < HDR {
            c.drop_malformed.fetch_add(1, Relaxed);
            return;
        }
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
        let is_local = dst_id == id_of(&self.me);
        let source = if is_local { self.local_source_key(now, &src_id, policy.as_ref()) } else { self.key_of(now, &src_id, policy.as_ref()) };
        let Some(src) = source else {
            c.drop_unknown_key.fetch_add(1, Relaxed);
            return;
        };
        if is_local {
            // последний хоп. Мой id8 обязан однозначно разрешаться в мой ключ
            if self.local_key(now, policy.as_ref()) != Some(self.me) {
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
            self.send_unreachable(now, prev, &dst);
            return;
        };
        if &next == prev {
            c.drop_uturn.fetch_add(1, Relaxed);
            self.send_unreachable(now, prev, &dst);
            return;
        }
        let conn = match self.neighbor(&next) {
            Ok(x) => x,
            Err(e) => {
                self.count_nbr_err(e);
                self.send_unreachable(now, prev, &dst);
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
            Err(e) => {
                c.drop_send_err.fetch_add(1, Relaxed);
                // Размер отдельного пакета не доказывает отказ маршрута.
                if matches!(e, iroh::endpoint::SendDatagramError::ConnectionLost(_)) {
                    self.send_unreachable(now, prev, &dst);
                }
            }
        }
    }

    /// Разрешить следующий хоп к `dst` целиком (политика, обратная таблица, соседи) и запомнить в `hops`. Вызывать НЕ из poll_send:
    /// берёт замки мультиплексоров и Trust. Безопасно из читателя датаграмм носителя, задач tokio и потока-разрешителя.
    pub fn warm(&self, dst: &Key) {
        let Some(policy) = self.policy() else { return };
        self.sync_gen(policy.as_ref());
        let now = Instant::now();
        let chosen = self.hop_origin_why(now, dst, policy.as_ref());
        let res = match chosen.map(|(k, _)| k) {
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
        let proof_hop = res.as_ref().ok().cloned();
        let old = h.get(dst).and_then(|e| e.res.as_ref().ok().map(|x| x.peer));
        h.insert(*dst, HopEntry { res, at: now });
        drop(h);
        if let (Some(hop), Some((_, why))) = (&proof_hop, chosen) {
            if old.is_some_and(|o| o != hop.peer) {
                self.c.hop_changes.fetch_add(1, Relaxed);
                self.push_hop_event(HopEvent { dst: *dst, old, new: Some(hop.peer), why, detail: String::new() });
            }
        }
        if let Some(hop) = proof_hop { self.send_migration(dst, &hop.peer, &hop.conn); }
    }

    fn push_hop_event(&self, e: HopEvent) {
        let mut q = self.hop_events.lock().unwrap();
        if q.len() >= HOP_EVENTS_MAX { q.pop_front(); }
        q.push_back(e);
    }

    /// Забрать накопленные события смены хопа (для журнала клиента). Ключи — только идентификаторы узлов, без адресов.
    pub fn take_hop_events(&self) -> Vec<HopEvent> {
        self.hop_events.lock().unwrap().drain(..).collect()
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

/// Смена первого хопа своих кадров к `dst` (или срабатывание сторожка застоя): для журнала клиента.
pub struct HopEvent {
    pub dst: Key,
    pub old: Option<Key>,
    pub new: Option<Key>,
    /// stall | verified | alt-direct | rns | alt | stall-detect
    pub why: &'static str,
    pub detail: String,
}

const HOP_EVENTS_MAX: usize = 32;

#[derive(Default)]
struct StallWatch {
    last_rx: Option<u64>,
    tx_baseline: u64,
    pending_since: Option<Instant>,
}

impl StallWatch {
    fn observe(&mut self, now: Instant, rx: u64, tx: u64, rtt: Duration) -> bool {
        if self.last_rx != Some(rx) {
            self.last_rx = Some(rx);
            self.tx_baseline = tx;
            self.pending_since = None;
            return false;
        }
        if tx > self.tx_baseline && self.pending_since.is_none() { self.pending_since = Some(now); }
        self.pending_since.is_some_and(|since| now.saturating_duration_since(since) >= Duration::from_secs(3).max(rtt.saturating_mul(3)))
            && tx.saturating_sub(self.tx_baseline) >= 2
    }
}

/// Сквозные соединения, начатые по mesh (помечены `mark_e2e`): они не соседи.
#[derive(Default)]
struct E2e {
    ids: std::collections::HashSet<usize>,
    /// TLS-сессия и последний принятый монотонный счётчик: replay отвергается
    /// в пределах сессии; после закрытия её exporter становится недействителен.
    conns: HashMap<usize, (Connection, migration::ReplayGuard)>,
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

/// IP - основной путь при начальном выборе; работающий mesh уступает место IP
/// только после фактической двусторонней передачи >1 МиБ через этот конкретный IP-адрес.
#[derive(Debug, Default)]
pub struct MeshBackupSelector(Option<std::sync::Weak<Mesh>>);

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
        // Наличие пути, handshake, RTT и малые зонды не доказывают передачу
        // данных через этот IP: переход с рабочего mesh разрешён только для
        // адреса, подтверждённого передачей >1 МиБ. Аварийный watchdog при
        // отказе текущего пути остаётся прежним.
        let current_mesh = cur.is_some_and(|p| matches!(p.remote(), iroh::endpoint::transports::Addr::Custom(ref c) if c.id() == MESH_ID));
        if current_mesh && cur_key.is_some() {
            let mesh = self.0.as_ref().and_then(|w| w.upgrade()).or_else(|| GLOBAL.get().cloned());
            let confirmed_ip = best.as_ref().is_some_and(|(bp, _)| match bp.network_path() {
                iroh::endpoint::transports::FourTuple::Ip { remote, .. } => {
                    mesh.as_ref().is_some_and(|m| m.is_direct_confirmed(remote))
                }
                _ => false,
            });
            if !confirmed_ip {
                return sel;
            }
        }
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

/// Custom-путь: туннель REALITY или mesh (других custom-транспортов нет).
fn custom_kind(c: &CustomAddr) -> &'static str {
    if c.id() == crate::reality_carrier::REALITY_ID { "reality" } else { "mesh" }
}

/// Состояние пути соединения для статуса: источник RTT и «как идёт» - сам QUIC (путь, статистика), а не пинги Link. `kind`: direct (IP) / mesh / relay;
/// `via` - диагностический префикс ключа транзита (4 байта hex, не destination RNS), `backup` - открытые запасные пути.
pub fn path_json(conn: &Connection, via: Option<Key>) -> serde_json::Value {
    use iroh::TransportAddr as T;
    let paths = conn.paths();
    let sel = paths.iter().find(|p| p.is_selected());
    let kind = match sel.as_ref().map(|p| p.remote_addr().clone()) {
        Some(T::Ip(_)) => "direct",
        Some(T::Custom(c)) => custom_kind(&c),
        Some(T::Relay(_)) => "relay",
        _ => "none",
    };
    let backups: Vec<&str> = paths
        .iter()
        .filter(|p| !p.is_selected())
        .map(|p| match p.remote_addr() {
            T::Ip(_) => "direct",
            T::Custom(c) => custom_kind(c),
            T::Relay(_) => "relay",
            _ => "other",
        })
        .collect();
    // выбранный путь IP по адресу не из глобальной сети - локальная сеть (P2P между контактами, ADR 0028 §2.4a)
    let lan = matches!(sel.as_ref().map(|p| p.remote_addr().clone()), Some(T::Ip(sa)) if crate::vpn::is_lan_ip(&sa.ip()));
    let st = conn.stats();
    let via = if kind == "mesh" { via.map(|k| k[..4].iter().map(|b| format!("{b:02x}")).collect::<String>()) } else { None };
    let path_desc = match kind {
        "direct" if lan => "прямой (локальная сеть)".to_string(),
        "direct" => "прямой (IP)".to_string(),
        "mesh" => via.as_ref().map(|v| format!("mesh через {v}")).unwrap_or_else(|| "mesh".to_string()),
        "relay" => "relay".to_string(),
        "reality" => "REALITY (TCP, маскировка под TLS)".to_string(),
        _ => "путь не выбран".to_string(),
    };
    let black_holes_detected: u64 = paths.iter().map(|p| p.stats().black_holes_detected).sum();
    // по каждому открытому пути: тип, выбран ли, MTU и счётчики MTUD (диагностика PMTU запасных путей)
    let paths_detail: Vec<serde_json::Value> = paths
        .iter()
        .map(|p| {
            let s = p.stats();
            serde_json::json!({
                "kind": match p.remote_addr() { T::Ip(_) => "direct", T::Custom(c) => custom_kind(c), T::Relay(_) => "relay", _ => "other" },
                "selected": p.is_selected(), "mtu": s.current_mtu,
                "probes_sent": s.sent_plpmtud_probes, "probes_lost": s.lost_plpmtud_probes, "black_holes": s.black_holes_detected,
            })
        })
        .collect();
    serde_json::json!({
        "paths_detail": paths_detail,
        "kind": kind,
        "connection_id": conn.stable_id(),
        "via": via, "path_desc": path_desc, "lan": lan,
        "rtt_ms": sel.as_ref().map(|p| (p.rtt().as_secs_f64() * 1000.0 * 100.0).round() / 100.0),
        "backup": backups, "lost_packets": st.lost_packets, "paths": paths.len(),
        "max_datagram_size": conn.max_datagram_size(),
        "current_mtu": sel.as_ref().map(|p| p.stats().current_mtu),
        "black_holes_detected": black_holes_detected,
        "datagram_mtu_drops": st.datagram_mtu_drops,
        "nat_probes_suppressed": st.nat_probes_suppressed,
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

/// Адрес пути - mesh (custom `MESH_ID`). Туннель REALITY (другой id custom-транспорта) и IP - нет.
pub(crate) fn is_mesh_addr(a: &iroh::TransportAddr) -> bool {
    matches!(a, iroh::TransportAddr::Custom(c) if c.id() == MESH_ID)
}

/// Выбранный путь соединения идёт через mesh (custom-транспорт), а не по IP.
pub fn selected_is_mesh(conn: &Connection) -> bool {
    conn.paths().iter().find(|p| p.is_selected()).is_some_and(|p| is_mesh_addr(p.remote_addr()))
}

#[cfg(test)]
mod tests;
