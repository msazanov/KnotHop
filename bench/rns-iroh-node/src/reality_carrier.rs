//! REALITY как последний уровень запасного пути (решение владельца 04.11; `bench/reality/DESIGN.md` §12).
//!
//! Свой `CustomTransport` iroh (id `REALITY_ID`, отличный от `mesh::MESH_ID`). Адрес `CustomAddr { id = REALITY_ID, data = 8 байт }` - номер туннеля
//! в ЭТОМ процессе (у клиента - исходящий, у узла - принятый); он нужен только для выбора туннеля при отправке и нигде не публикуется. Пакеты QUIC
//! идут кадрами `u16 длина | пакет` (`knothop_reality::carrier`) внутри TLS 1.3, который снаружи выглядит как соединение браузера с сайтом-прикрытием.
//!
//! Что здесь НЕ решается. REALITY - маскировка носителя и больше ничего: доверия он не даёт. Поверх туннеля идёт обычный QUIC iroh; ключ пира берётся
//! только из TLS этого QUIC (`Connection::remote_id()`), дальше всё как у любого QUIC-носителя - `Mux::add_quic`, Link RNS, `dataplane::bind`,
//! `on_link_packet`. До допуска Link данных VPN нет. Знание ключа REALITY и short_id доказывает лишь, что собеседник не зонд цензора.
//!
//! Подсказка клиенту (`RealityHint`, поле `rl` каталога) несёт ключ x25519 сервера, SNI, short_id и порт. Хоста в ней нет: клиент набирает те же
//! адреса, что и для QUIC/TCP (прошедшие фильтр `resolve_addrs`: только глобальные, кроме `KNOTHOP_ALLOW_PRIVATE_DIAL`), поэтому подсказка не может
//! направить его на новый адрес. Она путешествует там же, где адреса выходов (приватный каталог LXMF, `hints`), и в анонс RNS не попадает.
//!
//! Где защищает `protect()`: в этом проекте его нет. Петля носителя в собственный TUN на Android исключена тем, что `KnotHopVpnService`
//! привязывает ПРОЦЕСС к физической сети (`bindProcessToNetwork`): каждый сокет процесса, включая TCP этого носителя, идёт мимо VPN.
//!
//! Лимиты: туннелей от клиентов `MAX_IN`, исходящих `MAX_OUT`; кадр не больше `MAX_FRAME`; первый кадр за `FIRST_FRAME`, простой `IDLE`;
//! очередь отправки ограничена кадрами и временем (`max_queue_delay`, устаревшие кадры сбрасываются как потерянные UDP).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use bytes::Bytes;
use iroh::endpoint::transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit};
use iroh_base::CustomAddr;
use knothop_reality::carrier::{self as frames, FrameConfig, FrameLink, FrameSender};
use knothop_reality::server::{Accepted, IpNet, Listener, Server, ServerConfig};
use knothop_reality::{client, profile::Profile, Error as RError};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};

/// Идентификатор транспорта (не из реестра iroh; значение произвольное).
pub const REALITY_ID: u64 = 0x4B48_5254;
/// Туннелей от клиентов на узле одновременно (сверх - принятый туннель закрывается сразу).
pub const MAX_IN: usize = 64;
/// Исходящих туннелей (клиент и узел-сосед) одновременно.
pub const MAX_OUT: usize = 8;
/// Наибольший принимаемый кадр: UDP-пакет QUIC (MTU пути ≤ 1452). Больше - нарушение протокола, туннель закрывается.
pub const MAX_FRAME: usize = 1600;
/// Первый кадр QUIC должен прийти за это время после допуска туннеля, иначе слот освобождается.
const FIRST_FRAME: Duration = Duration::from_secs(20);
/// Простой туннеля (нет кадров от пира); QUIC держит путь keepalive-ами намного чаще.
const IDLE: Duration = Duration::from_secs(45);
/// Очередь локальной доставки кадров в `poll_recv` (общая на все туннели).
const DELIVER_QUEUE: usize = 2048;
/// Сколько сегментов GSO принимает наш sender (как у mesh: iroh берёт минимум по транспортам).
const MAX_SEGMENTS: usize = 64;
/// Проба сайта-прикрытия: повторять при ошибке и обновлять раз в 6 ч (сертификат сайта меняется).
const COVER_RETRY: Duration = Duration::from_secs(60);
const COVER_REFRESH: Duration = Duration::from_secs(6 * 3600);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    In,
    Out,
}

// ------------------------------------------------------------------------------------------------ подсказка

/// Параметры набора REALITY для клиента. Только то, что нужно, чтобы дойти до туннеля; хоста нет (см. шапку модуля).
#[derive(Clone, PartialEq, Eq)]
pub struct RealityHint {
    pub port: u16,
    pub sni: String,
    pub key: [u8; 32],
    pub sid: [u8; 8],
}

impl std::fmt::Debug for RealityHint {
    /// Ключ и short_id в журнал не попадают.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RealityHint {{ port: {}, sni: {:?}, .. }}", self.port, self.sni)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// SNI/имя сайта: нормальное DNS-имя (не IP), не длиннее 64 байт, хотя бы две метки.
pub fn sane_sni(s: &str) -> bool {
    s.len() <= 64
        && s.contains('.')
        && s.parse::<IpAddr>().is_err()
        && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

impl RealityHint {
    /// `{"p":443,"s":"sni","k":"<64 hex>","i":"<16 hex>"}`. Подсказка от пира недоверенная: разбор строгий, мусор отбрасывается.
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let port = u16::try_from(v["p"].as_u64()?).ok().filter(|p| *p != 0)?;
        let sni = v["s"].as_str().filter(|s| sane_sni(s))?.to_ascii_lowercase();
        let key: [u8; 32] = unhex(v["k"].as_str()?)?;
        let sid: [u8; 8] = unhex(v["i"].as_str()?)?;
        // нулевой ключ - не ключ (x25519 даст нулевой общий секрет)
        if key == [0u8; 32] {
            return None;
        }
        Some(RealityHint { port, sni, key, sid })
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"p": self.port, "s": self.sni, "k": hex(&self.key), "i": hex(&self.sid)})
    }
}

// ------------------------------------------------------------------------------------------------ конфиг и ключ узла

/// Настройки сервера REALITY на узле (из конфига/CLI).
#[derive(Clone, Debug)]
pub struct ServerConf {
    pub listen: SocketAddr,
    /// сайт-прикрытие `host:порт` (не на этом узле)
    pub dest: String,
    pub sni: Vec<String>,
    /// сети, от которых принимается PROXY v2 (Traefik); пусто - PROXY не ждём (прямое соединение, лаборатория)
    pub proxy_trusted: Vec<IpNet>,
    /// порт, под которым узел виден снаружи (Traefik :443); попадает в подсказку
    pub public_port: u16,
}

fn private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

impl ServerConf {
    /// Разбор и проверка. Отказ - ошибка запуска, а не молчаливое отключение.
    pub fn parse(listen: &str, dest: &str, sni: &[String], proxy_trusted: &[String], public_port: Option<u16>) -> Result<Self> {
        let listen: SocketAddr = listen.parse().with_context(|| format!("reality-listen {listen:?}: нужен адрес ip:порт"))?;
        let Some((dhost, dport)) = dest.rsplit_once(':') else { bail!("reality-dest {dest:?}: нужен host:порт") };
        if dhost.is_empty() || dport.parse::<u16>().ok().filter(|p| *p != 0).is_none() {
            bail!("reality-dest {dest:?}: нужен host:порт");
        }
        // сайт-прикрытие - внешний сайт: loopback/любой локальный адрес превратил бы relay в доступ к службам этого узла
        // исключение - явно включённая лаборатория (KNOTHOP_ALLOW_PRIVATE_DIAL): сайт-прикрытие там живёт в соседнем контейнере
        let lab = std::env::var("KNOTHOP_ALLOW_PRIVATE_DIAL").is_ok();
        let dhost_ip = dhost.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>();
        match dhost_ip {
            Ok(ip) if !lab && (private_or_loopback(ip) || ip.is_unspecified()) => bail!("reality-dest {dest:?}: адрес сайта-прикрытия не может быть локальным"),
            Err(_) if !lab && (dhost.eq_ignore_ascii_case("localhost") || dhost.ends_with(".localhost")) => bail!("reality-dest {dest:?}: localhost не годится"),
            _ => {}
        }
        let mut names: Vec<String> = Vec::new();
        for s in sni {
            let s = s.trim().to_ascii_lowercase();
            if s.is_empty() {
                continue;
            }
            if !sane_sni(&s) {
                bail!("reality-sni {s:?}: нужно DNS-имя");
            }
            if !names.contains(&s) {
                names.push(s);
            }
        }
        if names.is_empty() {
            // без списка принимался бы любой SNI; имя сайта-прикрытия - единственный разумный выбор по умолчанию
            if sane_sni(dhost) {
                names.push(dhost.to_ascii_lowercase());
            } else {
                bail!("reality-sni: список пуст, а имя в reality-dest не DNS-имя");
            }
        }
        let mut nets = Vec::new();
        for t in proxy_trusted {
            let t = t.trim();
            if t.is_empty() {
                continue;
            }
            let Some(n) = IpNet::parse(t) else { bail!("reality-proxy-trusted {t:?}: нужен ip или ip/префикс") };
            // PROXY v2 подделывает адрес клиента: доверять можно только своим локальным/частным сетям, не интернету
            if !private_or_loopback(n.ip) || (n.prefix < if n.ip.is_ipv4() { 8 } else { 7 }) {
                bail!("reality-proxy-trusted {t:?}: допускаются только loopback/частные сети (префикс не шире /8)");
            }
            nets.push(n);
        }
        Ok(ServerConf { listen, dest: dest.to_string(), sni: names, proxy_trusted: nets, public_port: public_port.unwrap_or(443) })
    }
}

/// Секрет x25519 узла: `state/reality.key`, 32 байта, режим 0600, создаётся при первом запуске атомарно (temp + rename).
/// Отдельный от ключа подписи identity: ротация независима. Секрет не печатается.
pub fn load_or_create_key(state: &Path) -> Result<[u8; 32]> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = state.join("reality.key");
    match std::fs::read(&path) {
        Ok(b) => {
            let key: [u8; 32] = b.as_slice().try_into().map_err(|_| anyhow::anyhow!("{}: ожидалось 32 байта", path.display()))?;
            if std::fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(key)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            use rand_core::RngCore;
            let mut key = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut key);
            let tmp = state.join(format!("reality.key.tmp{}", std::process::id()));
            let _ = std::fs::remove_file(&tmp);
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            f.write_all(&key)?;
            f.sync_all()?;
            drop(f);
            if let Err(e) = std::fs::rename(&tmp, &path) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e).context("reality.key: rename");
            }
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("{}", path.display())),
    }
}

/// short_id узла (MVP: один на узел). Выводится из секрета, поэтому отдельного файла нет.
/// Для выдачи на клиента нужен список в `trust.json` и горячая замена `Server` (DESIGN §12.4).
pub fn node_short_id(secret: &[u8; 32]) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"knothop-reality/node-short-id/1");
    h.update(secret);
    h.finalize()[..8].try_into().unwrap()
}

// ------------------------------------------------------------------------------------------------ носитель

#[derive(Default)]
struct Counters {
    srv_tunnels: AtomicU64,
    srv_over_limit: AtomicU64,
    out_dial_ok: AtomicU64,
    out_unreachable: AtomicU64,
    out_rejected: AtomicU64,
    out_over_limit: AtomicU64,
    tx_pkts: AtomicU64,
    tx_drop: AtomicU64,
    rx_pkts: AtomicU64,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    drop_stale: AtomicU64,
    drop_oversize: AtomicU64,
    rx_queue_full: AtomicU64,
    closed_idle: AtomicU64,
}

struct Tunnel {
    tx: FrameSender,
    stop: watch::Sender<bool>,
    /// становится true, когда туннель убран (для закрытия принятого поверх него QUIC)
    closed: watch::Receiver<bool>,
}

struct Inner {
    conns: RwLock<HashMap<u64, Tunnel>>,
    next: AtomicU64,
    active_in: AtomicUsize,
    active_out: AtomicUsize,
    c: Counters,
    rx_tx: mpsc::Sender<(Bytes, u64)>,
    rx: Mutex<Option<mpsc::Receiver<(Bytes, u64)>>>,
    local: n0_watcher::Watchable<Vec<CustomAddr>>,
    /// сервер узла (для статистики), если запущен
    server: Mutex<Option<Arc<Server>>>,
}

/// Процессный носитель REALITY. Один на endpoint.
#[derive(Clone)]
pub struct RealityCarrier(Arc<Inner>);

impl std::fmt::Debug for RealityCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RealityCarrier")
    }
}

pub fn addr_of(id: u64) -> CustomAddr {
    CustomAddr::from_parts(REALITY_ID, &id.to_be_bytes())
}

static GLOBAL: OnceLock<RealityCarrier> = OnceLock::new();

/// Процессный экземпляр (создаётся до endpoint-а: транспорт передаётся в `Builder::add_custom_transport`).
pub fn install() -> RealityCarrier {
    GLOBAL.get_or_init(RealityCarrier::new).clone()
}

pub fn global() -> Option<&'static RealityCarrier> {
    GLOBAL.get()
}

/// Результат набора REALITY клиентом.
pub enum Dial {
    /// туннель поднят и подтверждён сервером (ключ REALITY проверен клиентом)
    Up(TunnelHandle),
    /// TCP не соединился ни с одним адресом
    Unreachable,
    /// TCP соединился, туннель не поднят: подмена сервера (`Intercepted`), отказ, таймаут, лимит
    Rejected(&'static str),
}

/// Исходящий туннель: адрес для iroh и наблюдение за закрытием.
pub struct TunnelHandle {
    id: u64,
    carrier: RealityCarrier,
    closed: watch::Receiver<bool>,
}

impl TunnelHandle {
    pub fn addr(&self) -> CustomAddr {
        addr_of(self.id)
    }
    /// Завершается, когда туннель закрыт (с любой стороны, по лимиту или простою).
    pub async fn closed(&mut self) {
        while !*self.closed.borrow() {
            if self.closed.changed().await.is_err() {
                break;
            }
        }
    }
    pub fn close(&self) {
        self.carrier.close(self.id);
    }
}

impl RealityCarrier {
    pub fn new() -> RealityCarrier {
        let (rx_tx, rx) = mpsc::channel(DELIVER_QUEUE);
        RealityCarrier(Arc::new(Inner {
            conns: Default::default(),
            next: AtomicU64::new(1),
            active_in: AtomicUsize::new(0),
            active_out: AtomicUsize::new(0),
            c: Default::default(),
            rx_tx,
            rx: Mutex::new(Some(rx)),
            // локальный адрес нигде не публикуется
            local: n0_watcher::Watchable::new(vec![]),
            server: Mutex::new(None),
        }))
    }

    pub fn transport(&self) -> Arc<dyn CustomTransport> {
        Arc::new(self.clone())
    }

    fn close(&self, id: u64) {
        if let Some(t) = self.0.conns.write().unwrap().remove(&id) {
            let _ = t.stop.send(true);
        }
    }

    /// Поставить поток (после рукопожатия REALITY) на носитель. None - лимит туннелей.
    fn attach<S>(&self, stream: S, kind: Kind) -> Option<(u64, watch::Receiver<bool>)>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        let i = &self.0;
        let (active, max) = match kind {
            Kind::In => (&i.active_in, MAX_IN),
            Kind::Out => (&i.active_out, MAX_OUT),
        };
        // резервируем слот атомарно: гонка двух принятых туннелей не пробьёт предел
        if active.fetch_add(1, Relaxed) >= max {
            active.fetch_sub(1, Relaxed);
            match kind {
                Kind::In => i.c.srv_over_limit.fetch_add(1, Relaxed),
                Kind::Out => i.c.out_over_limit.fetch_add(1, Relaxed),
            };
            return None;
        }
        let id = i.next.fetch_add(1, Relaxed);
        let FrameLink { sender, mut rx, stats, .. } = frames::spawn(stream, FrameConfig { queue_frames: 1024, max_queue_delay: Duration::from_millis(150), rx_frames: 1024, batch_bytes: 16 * 1024 });
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let (closed_tx, closed_rx) = watch::channel(false);
        i.conns.write().unwrap().insert(id, Tunnel { tx: sender, stop: stop_tx, closed: closed_rx.clone() });
        let me = self.clone();
        tokio::spawn(async move {
            let mut got = false;
            loop {
                let limit = if got { IDLE } else { FIRST_FRAME };
                tokio::select! {
                    biased;
                    _ = stop_rx.changed() => break,
                    r = tokio::time::timeout(limit, rx.recv()) => match r {
                        Ok(Some(b)) => {
                            got = true;
                            if b.len() > MAX_FRAME {
                                me.0.c.drop_oversize.fetch_add(1, Relaxed);
                                break;
                            }
                            me.0.c.rx_pkts.fetch_add(1, Relaxed);
                            me.0.c.rx_bytes.fetch_add(b.len() as u64, Relaxed);
                            // очередь локальной доставки переполнена только при зависшем endpoint: кадр теряется как UDP, туннель не блокируется
                            if me.0.rx_tx.try_send((b, id)).is_err() {
                                me.0.c.rx_queue_full.fetch_add(1, Relaxed);
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            me.0.c.closed_idle.fetch_add(1, Relaxed);
                            break;
                        }
                    },
                }
            }
            // уборка: убрать запись (писатель кадров завершится, закроет TCP), учесть счётчики туннеля
            me.close(id);
            me.0.c.tx_bytes.fetch_add(stats.tx_bytes.load(Relaxed), Relaxed);
            me.0.c.drop_stale.fetch_add(stats.drop_stale.load(Relaxed), Relaxed);
            match kind {
                Kind::In => me.0.active_in.fetch_sub(1, Relaxed),
                Kind::Out => me.0.active_out.fetch_sub(1, Relaxed),
            };
            let _ = closed_tx.send(true);
        });
        Some((id, closed_rx))
    }

    /// Клиент (и узел-сосед): TCP к одному из `ips` на порт подсказки, рукопожатие REALITY, туннель на носитель.
    /// `ips` обязаны быть уже отфильтрованы вызывающим (глобальные адреса); порт берётся из подсказки.
    pub async fn dial(&self, ips: &[SocketAddr], hint: &RealityHint) -> Dial {
        let cfg = client::ClientConfig::new(hint.key, hint.sid, hint.sni.clone());
        let mut reached = false;
        let mut why: &'static str = "no tunnel";
        for ip in ips {
            let a = SocketAddr::new(ip.ip(), hint.port);
            let Ok(Ok(tcp)) = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(a)).await else { continue };
            reached = true;
            let _ = tcp.set_nodelay(true);
            match client::connect(tcp, &cfg).await {
                Ok(stream) => match self.attach(stream, Kind::Out) {
                    Some((id, closed)) => {
                        self.0.c.out_dial_ok.fetch_add(1, Relaxed);
                        return Dial::Up(TunnelHandle { id, carrier: self.clone(), closed });
                    }
                    None => why = "limit",
                },
                // перехват (настоящий сертификат сайта): данные не отправлены; прочие ошибки - сервер не принял токен или оборвал
                Err(RError::Intercepted(_)) => why = "intercepted",
                Err(RError::Timeout(_)) => why = "timeout",
                Err(_) => why = "handshake",
            }
        }
        if reached {
            self.0.c.out_rejected.fetch_add(1, Relaxed);
            Dial::Rejected(why)
        } else {
            self.0.c.out_unreachable.fetch_add(1, Relaxed);
            Dial::Unreachable
        }
    }

    /// Сервер на узле: слушает `conf.listen`, принимает туннели на носитель, не прошедшие проверку соединения уходят на сайт-прикрытие
    /// (`knothop_reality::server`). Возвращает подсказку для клиентов и адрес, который реально слушается.
    pub async fn start_server(&self, conf: &ServerConf, state: &Path, note: Arc<dyn Fn(String) + Send + Sync>) -> Result<(RealityHint, SocketAddr)> {
        let secret = load_or_create_key(state)?;
        let sid = node_short_id(&secret);
        let mut cfg = ServerConfig::new(secret, vec![sid], conf.dest.clone());
        cfg.server_names = conf.sni.clone();
        if !conf.proxy_trusted.is_empty() {
            cfg.proxy_protocol = true;
            cfg.proxy_trusted = conf.proxy_trusted.clone();
            // доверенные сети проверены в `ServerConf::parse` (только loopback/частные): подделать адрес клиента может лишь хост из этого списка
            cfg.allow_proxy_on_public = !conf.listen.ip().is_loopback();
        }
        let pubkey = cfg.public_key();
        let server = Server::new(cfg);
        let mut listener = Listener::bind(conf.listen, server.clone()).await.map_err(|e| anyhow::anyhow!("reality: bind {}: {e}", conf.listen))?;
        let local = listener.local_addr();
        *self.0.server.lock().unwrap() = Some(server.clone());
        let me = self.clone();
        let n2 = note.clone();
        tokio::spawn(async move {
            while let Some(ev) = listener.accept().await {
                // событие Forwarded/Dropped учитывает сам сервер (`Server::stats`); адреса клиентов и причины в журнал не пишем
                if let Accepted::Tunnel { stream, .. } = ev {
                    me.0.c.srv_tunnels.fetch_add(1, Relaxed);
                    if me.attach(stream, Kind::In).is_none() {
                        n2("reality: лимит туннелей, соединение закрыто".into());
                    }
                }
            }
        });
        // проба сайта-прикрытия: подгонка ответа под сайт; сбой не мешает работе (естественные размеры)
        let (srv, n3) = (server.clone(), note.clone());
        tokio::spawn(async move {
            let profile = Profile::chrome155();
            let mut ok_once = false;
            loop {
                let wait = match srv.refresh_cover(&profile).await {
                    Ok(_) => {
                        if !ok_once {
                            ok_once = true;
                            n3("reality: проба сайта-прикрытия выполнена".into());
                        }
                        COVER_REFRESH
                    }
                    Err(e) => {
                        if !ok_once {
                            n3(format!("reality: проба сайта-прикрытия не удалась ({e}), повтор через {} с", COVER_RETRY.as_secs()));
                        }
                        COVER_RETRY
                    }
                };
                tokio::time::sleep(wait).await;
            }
        });
        note(format!("reality: слушаю {local}, прикрытие {}, SNI {:?}, PROXY v2: {}", conf.dest, conf.sni, if conf.proxy_trusted.is_empty() { "нет" } else { "да" }));
        let hint = RealityHint { port: conf.public_port, sni: conf.sni[0].clone(), key: pubkey, sid };
        Ok((hint, local))
    }

    /// Счётчики для status.json. Адресов клиентов, ключей и причин отказа здесь нет.
    pub fn stats(&self) -> serde_json::Value {
        let i = &self.0;
        let c = &i.c;
        let srv = i.server.lock().unwrap().as_ref().map(|s| {
            serde_json::json!({
                "tunnels": s.stats.tunnels.load(Relaxed), "cover_forwarded": s.stats.forwarded.load(Relaxed),
                "cover_forwarded_noauth": s.stats.forwarded_noauth.load(Relaxed), "replays": s.stats.forwarded_replay.load(Relaxed),
                "dropped": s.stats.dropped.load(Relaxed), "handshake_failed": s.stats.handshake_failed.load(Relaxed),
            })
        });
        serde_json::json!({
            "server": srv,
            "tunnels_in": i.active_in.load(Relaxed), "tunnels_out": i.active_out.load(Relaxed),
            "accepted": c.srv_tunnels.load(Relaxed), "over_limit_in": c.srv_over_limit.load(Relaxed), "over_limit_out": c.out_over_limit.load(Relaxed),
            "dial_ok": c.out_dial_ok.load(Relaxed), "dial_unreachable": c.out_unreachable.load(Relaxed), "dial_rejected": c.out_rejected.load(Relaxed),
            "rx_pkts": c.rx_pkts.load(Relaxed), "rx_bytes": c.rx_bytes.load(Relaxed), "tx_pkts": c.tx_pkts.load(Relaxed), "tx_bytes_closed": c.tx_bytes.load(Relaxed),
            "tx_drop": c.tx_drop.load(Relaxed), "drop_stale": c.drop_stale.load(Relaxed), "drop_oversize": c.drop_oversize.load(Relaxed),
            "rx_queue_full": c.rx_queue_full.load(Relaxed), "closed_idle": c.closed_idle.load(Relaxed),
        })
    }

    #[cfg(test)]
    fn active(&self) -> (usize, usize) {
        (self.0.active_in.load(Relaxed), self.0.active_out.load(Relaxed))
    }
}

impl Default for RealityCarrier {
    fn default() -> Self {
        Self::new()
    }
}

/// Входящее соединение пришло по туннелю REALITY?
pub fn incoming_is_reality(a: &iroh::endpoint::IncomingAddr) -> bool {
    matches!(a, iroh::endpoint::IncomingAddr::Custom(c) if c.id() == REALITY_ID)
}

/// Закрывает принятое по туннелю REALITY QUIC-соединение вместе с туннелем (иначе оно висит слотом до таймаута простоя, а интерфейс пира держит мёртвый носитель).
/// Закрываем, только если выбранный путь всё ещё туннель: перешедшее на IP-путь соединение живёт дальше. Туннеля уже нет - закрываем сразу.
pub fn close_conn_with_tunnel(conn: iroh::endpoint::Connection) {
    if let Some(carrier) = GLOBAL.get() {
        carrier.close_conn_with_tunnel(conn);
    }
}

impl RealityCarrier {
    pub fn close_conn_with_tunnel(&self, conn: iroh::endpoint::Connection) {
        let tun_id = conn.paths().iter().find(|p| p.is_selected()).and_then(|p| match p.remote_addr() {
            iroh::TransportAddr::Custom(c) if c.id() == REALITY_ID => <[u8; 8]>::try_from(c.data()).ok().map(u64::from_be_bytes),
            _ => None,
        });
        let Some(id) = tun_id else { return };
        let rx = self.0.conns.read().unwrap().get(&id).map(|t| t.closed.clone());
        tokio::spawn(async move {
            if let Some(mut rx) = rx {
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
            }
            // путь туннеля после его закрытия мог уйти из выбранных вовсе: не закрываем только соединение, перешедшее на другой (IP) путь
            let moved = conn.paths().iter().find(|p| p.is_selected()).is_some_and(|p| !matches!(p.remote_addr(), iroh::TransportAddr::Custom(c) if c.id() == REALITY_ID));
            if !moved {
                conn.close(0u32.into(), b"reality tunnel closed");
            }
        });
    }
}

/// Выбранный путь соединения - туннель REALITY.
pub fn selected_is_reality(conn: &iroh::endpoint::Connection) -> bool {
    conn.paths().iter().find(|p| p.is_selected()).is_some_and(|p| matches!(p.remote_addr(), iroh::TransportAddr::Custom(c) if c.id() == REALITY_ID))
}

// -------------------------------------------------------------------- iroh

impl CustomTransport for RealityCarrier {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let rx = self.0.rx.lock().unwrap().take().ok_or_else(|| io::Error::other("reality endpoint already bound"))?;
        Ok(Box::new(Ep { c: self.clone(), rx }))
    }
}

#[derive(Debug)]
struct Ep {
    c: RealityCarrier,
    rx: mpsc::Receiver<(Bytes, u64)>,
}

impl CustomEndpoint for Ep {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.c.0.local.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(Sender(self.c.clone()))
    }

    fn poll_recv(&mut self, cx: &mut Context, bufs: &mut [io::IoSliceMut<'_>], metas: &mut [noq_udp::RecvMeta], infos: &mut [RecvInfo]) -> Poll<io::Result<usize>> {
        let mut n = 0;
        while n < bufs.len() {
            let (data, id) = if n == 0 {
                match self.rx.poll_recv(cx) {
                    Poll::Ready(Some(x)) => x,
                    Poll::Ready(None) => return Poll::Ready(Err(io::Error::other("reality closed"))),
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
            infos[n] = RecvInfo::new(addr_of(id), Some(addr_of(0)));
            n += 1;
        }
        Poll::Ready(Ok(n))
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(MAX_SEGMENTS).unwrap()
    }
}

#[derive(Debug)]
struct Sender(RealityCarrier);

impl CustomSender for Sender {
    fn is_valid_send_addr(&self, a: &CustomAddr) -> bool {
        a.id() == REALITY_ID && a.data().len() == 8
    }

    fn poll_send(&self, _cx: &mut Context, dst: &CustomAddr, _src: Option<&CustomAddr>, t: &Transmit<'_>) -> Poll<io::Result<()>> {
        let Ok(id) = <[u8; 8]>::try_from(dst.data()).map(u64::from_be_bytes) else { return Poll::Ready(Err(io::Error::other("bad reality address"))) };
        let i = &self.0.0;
        let tx = i.conns.read().unwrap().get(&id).map(|t| t.tx.clone());
        // UDP-семантика: потеря не ошибка (туннеля нет, очередь полна или кадр устарел) - QUIC её переживёт
        for seg in crate::mesh::segments(t.contents, t.segment_size) {
            match &tx {
                Some(tx) if tx.try_send(Bytes::copy_from_slice(seg)) => i.c.tx_pkts.fetch_add(1, Relaxed),
                _ => i.c.tx_drop.fetch_add(1, Relaxed),
            };
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests;
