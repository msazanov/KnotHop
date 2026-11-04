//! Сервер: читает PROXY v2 (если включено), первую запись ClientHello, проверяет токен.
//! Не прошёл - прозрачная пересылка всех байт на сайт-прикрытие (сервер становится relay). Прошёл - свой TLS 1.3 и туннель.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};

use crate::auth::{self, ReplayCache, ShortId, SID_OFF};
use crate::chello::{self, Record};
use crate::error::{Error, Result};
use crate::handshake::{self, CoverInfo, ServerParams};
use crate::kx;
use crate::profile::Profile;
use crate::proxy;
use crate::mimic::{self, Mimic};
use crate::stream::{Padding, RealityStream};
use crate::util;

/// Сеть для списка доверенных источников PROXY: адрес и длина префикса.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNet {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    pub fn new(ip: IpAddr, prefix: u8) -> IpNet {
        IpNet { ip, prefix }
    }
    /// "10.0.0.0/8", "127.0.0.1" (= /32), "::1"
    pub fn parse(s: &str) -> Option<IpNet> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let ip: IpAddr = a.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = p.unwrap_or(max);
        (prefix <= max).then_some(IpNet { ip, prefix })
    }
    pub fn contains(&self, ip: IpAddr) -> bool {
        let (a, b): (u128, u128) = match (self.ip, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => ((u32::from(a) as u128) << 96, (u32::from(b) as u128) << 96),
            (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b)),
            _ => return false,
        };
        let p = self.prefix as u32;
        if p == 0 {
            return true;
        }
        let mask = u128::MAX << (128 - p.min(128));
        (a & mask) == (b & mask)
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    /// одновременных соединений на этапе проверки и пересылки (выше - соединение закрывается сразу)
    pub max_concurrent: usize,
    /// одновременных соединений с одного адреса (по PROXY-адресу, если есть)
    pub max_per_ip: usize,
    /// ожидание первой записи ClientHello (по истечении байты уходят на сайт, как будто клиент замолчал)
    pub hello_timeout: Duration,
    /// ожидание завершения рукопожатия после допуска
    pub handshake_timeout: Duration,
    pub connect_cover_timeout: Duration,
    /// простой пересылки на сайт
    pub forward_idle: Duration,
    pub forward_max_life: Duration,
    /// предел байт на направление пересылки
    pub forward_max_bytes: u64,
    /// максимальная длина записи ClientHello (с заголовком)
    pub max_hello_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_concurrent: 256,
            max_per_ip: 16,
            hello_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            connect_cover_timeout: Duration::from_secs(5),
            forward_idle: Duration::from_secs(60),
            forward_max_life: Duration::from_secs(600),
            forward_max_bytes: 32 << 20,
            max_hello_len: 16 * 1024,
        }
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    /// статический секретный ключ x25519 сервера (32 Б); не печатать и не логировать
    pub static_secret: [u8; 32],
    pub short_ids: Vec<ShortId>,
    /// допустимые SNI; пусто - любой
    pub server_names: Vec<String>,
    /// сайт-прикрытие "host:port"
    pub dest: String,
    /// ждать заголовок PROXY v2 (за Traefik). Разрешено только на loopback, либо при `allow_proxy_on_public`.
    pub proxy_protocol: bool,
    pub allow_proxy_on_public: bool,
    /// от каких адресов принимать PROXY (по умолчанию loopback)
    pub proxy_trusted: Vec<IpNet>,
    pub skew: Duration,
    pub replay_cap: usize,
    pub limits: Limits,
    pub padding: Padding,
    /// начальный обмен «как h2 браузера» (+1 RTT) и форма первых записей; должно совпадать с настройкой клиента
    pub mimic: Mimic,
    /// начальные сведения о сайте (до пробы); пусто - естественные размеры, шифр 1301, группа по клиенту
    pub cover: CoverInfo,
    /// CN временного сертификата (виден только внутри шифрования)
    pub cn: String,
    /// сколько раз пробовать сайт-прикрытие для распределения размеров (1 - один образец)
    pub probe_samples: usize,
}

impl std::fmt::Debug for ServerConfig {
    /// Секретный ключ не печатается.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig").field("static_secret", &"<скрыт>").field("short_ids", &self.short_ids.len()).field("dest", &self.dest).field("server_names", &self.server_names).field("proxy_protocol", &self.proxy_protocol).finish_non_exhaustive()
    }
}

impl ServerConfig {
    pub fn new(static_secret: [u8; 32], short_ids: Vec<ShortId>, dest: impl Into<String>) -> Self {
        ServerConfig {
            static_secret,
            short_ids,
            server_names: vec![],
            dest: dest.into(),
            proxy_protocol: false,
            allow_proxy_on_public: false,
            proxy_trusted: vec![IpNet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32), IpNet::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128)],
            skew: Duration::from_secs(120),
            replay_cap: 8192,
            limits: Limits::default(),
            padding: Padding::default(),
            mimic: Mimic::default(),
            cover: CoverInfo::default(),
            cn: "localhost".into(),
            probe_samples: 8,
        }
    }
    pub fn public_key(&self) -> [u8; 32] {
        kx::x25519_public(&self.static_secret)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardReason {
    NotTls,
    Malformed,
    BadSni,
    NoToken,
    UnknownShortId,
    Stale,
    Replay,
    NoPlan,
    HelloTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    ProxyUntrusted,
    ProxyHeader,
    Limit,
    HandshakeFailed,
    CoverUnreachable,
}

pub enum Accepted<IO = TcpStream> {
    Tunnel { stream: RealityStream<IO>, peer: SocketAddr, short_id: ShortId, sni: String },
    Forwarded { peer: SocketAddr, reason: ForwardReason },
    Dropped { peer: SocketAddr, reason: DropReason },
}

#[derive(Default, Debug)]
pub struct Stats {
    pub tunnels: AtomicU64,
    pub forwarded: AtomicU64,
    pub dropped: AtomicU64,
    pub forwarded_replay: AtomicU64,
    pub forwarded_noauth: AtomicU64,
    pub handshake_failed: AtomicU64,
}

pub struct Server {
    pub cfg: ServerConfig,
    replay: ReplayCache,
    cover: RwLock<Arc<CoverInfo>>,
    sem: Arc<Semaphore>,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    pub stats: Stats,
}

pub enum Handled {
    Tunnel(Accepted),
    Forward(ForwardJob),
    Dropped(Accepted),
}

pub struct ForwardJob {
    pub peer: SocketAddr,
    pub reason: ForwardReason,
    buf: Vec<u8>,
    tcp: TcpStream,
    dest: String,
    limits: Limits,
    _guard: Guard,
}

struct Guard {
    srv: Arc<Server>,
    ip: IpAddr,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let mut m = self.srv.per_ip.lock().unwrap();
        if let Some(c) = m.get_mut(&self.ip) {
            *c -= 1;
            if *c == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

impl Server {
    pub fn new(cfg: ServerConfig) -> Arc<Server> {
        let ttl = cfg.skew * 2 + Duration::from_secs(5);
        Arc::new(Server {
            replay: ReplayCache::new(cfg.replay_cap, ttl),
            cover: RwLock::new(Arc::new(cfg.cover.clone())),
            sem: Arc::new(Semaphore::new(cfg.limits.max_concurrent)),
            per_ip: Mutex::new(HashMap::new()),
            stats: Stats::default(),
            cfg,
        })
    }

    pub fn cover_info(&self) -> Arc<CoverInfo> {
        self.cover.read().unwrap().clone()
    }

    pub fn set_cover_info(&self, c: CoverInfo) {
        *self.cover.write().unwrap() = Arc::new(c);
    }

    /// Проба сайта-прикрытия и обновление сведений. Вызывать при старте и периодически (сертификат сайта меняется).
    pub async fn refresh_cover(&self, profile: &Profile) -> Result<CoverInfo> {
        let sni = self.cfg.server_names.first().cloned().unwrap_or_else(|| self.cfg.dest.rsplit_once(':').map(|x| x.0.to_string()).unwrap_or_default());
        let c = crate::probe::probe_cover_samples(&self.cfg.dest, &sni, profile, Duration::from_secs(10), self.cfg.probe_samples).await?;
        self.set_cover_info(c.clone());
        Ok(c)
    }

    pub fn replay_cache(&self) -> &ReplayCache {
        &self.replay
    }

    fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<Guard> {
        let permit = self.sem.clone().try_acquire_owned().ok()?;
        let mut m = self.per_ip.lock().unwrap();
        let c = m.entry(ip).or_insert(0);
        if *c >= self.cfg.limits.max_per_ip {
            return None;
        }
        *c += 1;
        Some(Guard { srv: self.clone(), ip, _permit: permit })
    }

    /// Обрабатывает принятое TCP-соединение до решения: туннель, пересылка на сайт или отбрасывание.
    pub async fn handle(self: &Arc<Self>, mut tcp: TcpStream, socket_peer: SocketAddr) -> Handled {
        let lim = &self.cfg.limits;
        let drop_ = |peer, reason| Handled::Dropped(Accepted::Dropped { peer, reason });
        let _ = tcp.set_nodelay(true);
        // общий лимит до чтения чего-либо; при PROXY лимит по IP уточняется после заголовка
        let mut peer = socket_peer;
        if self.cfg.proxy_protocol {
            if !self.cfg.proxy_trusted.iter().any(|n| n.contains(socket_peer.ip())) {
                self.stats.dropped.fetch_add(1, Relaxed);
                return drop_(peer, DropReason::ProxyUntrusted);
            }
            match tokio::time::timeout(lim.hello_timeout, proxy::read_v2(&mut tcp)).await {
                Ok(Ok(Some(a))) => peer = a,
                Ok(Ok(None)) => {}
                _ => {
                    self.stats.dropped.fetch_add(1, Relaxed);
                    return drop_(peer, DropReason::ProxyHeader);
                }
            }
        }
        let Some(guard) = self.admit(peer.ip()) else {
            self.stats.dropped.fetch_add(1, Relaxed);
            return drop_(peer, DropReason::Limit);
        };

        // первая запись
        let mut buf: Vec<u8> = Vec::with_capacity(2048);
        let deadline = tokio::time::Instant::now() + lim.hello_timeout;
        let mut tmp = [0u8; 4096];
        let verdict = loop {
            match chello::check_record(&buf, lim.max_hello_len) {
                Record::Hello(n) => break Ok(n),
                Record::NotHello => break Err(if buf.first() != Some(&22) || buf.get(1).is_some_and(|b| *b != 3) { ForwardReason::NotTls } else { ForwardReason::Malformed }),
                Record::NeedMore(_) => {}
            }
            match tokio::time::timeout_at(deadline, tcp.read(&mut tmp)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break Err(ForwardReason::HelloTimeout),
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                Err(_) => break Err(ForwardReason::HelloTimeout),
            }
        };
        let rec_len = match verdict {
            Ok(n) => n,
            Err(r) => return self.forward(tcp, peer, buf, r, guard),
        };
        let msg = &buf[5..rec_len];
        let Some(hello) = chello::parse_hello(msg) else { return self.forward(tcp, peer, buf, ForwardReason::Malformed, guard) };
        if !self.cfg.server_names.is_empty() && !hello.sni.as_ref().is_some_and(|s| self.cfg.server_names.iter().any(|n| n.eq_ignore_ascii_case(s))) {
            return self.forward(tcp, peer, buf, ForwardReason::BadSni, guard);
        }
        if hello.session_id.len() != 32 {
            return self.forward(tcp, peer, buf, ForwardReason::NoToken, guard);
        }
        let Some(share) = hello.x25519_share() else { return self.forward(tcp, peer, buf, ForwardReason::NoToken, guard) };
        let sk = x25519_dalek::StaticSecret::from(self.cfg.static_secret);
        let Some(shared) = kx::x25519_dh(&sk, share) else { return self.forward(tcp, peer, buf, ForwardReason::NoToken, guard) };
        let ak = auth::derive_auth_key(&shared, hello.random);
        let mut zeroed = msg.to_vec();
        zeroed[SID_OFF..SID_OFF + 32].fill(0);
        let Some(tok) = auth::open_token(&ak, hello.random, &zeroed, hello.session_id) else {
            return self.forward(tcp, peer, buf, ForwardReason::NoToken, guard);
        };
        // дальше токен подлинный (знает ключ сервера); проверки политики
        if !auth::short_id_allowed(&self.cfg.short_ids, &tok.short_id) {
            return self.forward(tcp, peer, buf, ForwardReason::UnknownShortId, guard);
        }
        if !auth::time_ok(tok.time, handshake::now_unix(), self.cfg.skew.as_secs()) {
            return self.forward(tcp, peer, buf, ForwardReason::Stale, guard);
        }
        let sid: [u8; 32] = hello.session_id.try_into().unwrap();
        if !self.replay.insert(&sid, Instant::now()) {
            self.stats.forwarded_replay.fetch_add(1, Relaxed);
            return self.forward(tcp, peer, buf, ForwardReason::Replay, guard);
        }
        let cover = self.cover_info();
        let Some(plan) = handshake::plan(&hello, &cover) else { return self.forward(tcp, peer, buf, ForwardReason::NoPlan, guard) };
        let sni = hello.sni.clone().unwrap_or_default();
        let params = ServerParams { hello: &hello, hello_msg: msg, auth_key: ak, cover: &cover, plan, cn: &self.cfg.cn };
        let mut est = match tokio::time::timeout(lim.handshake_timeout, handshake::server_handshake(&mut tcp, params)).await {
            Ok(Ok(e)) => e,
            _ => {
                self.stats.handshake_failed.fetch_add(1, Relaxed);
                self.stats.dropped.fetch_add(1, Relaxed);
                return drop_(peer, DropReason::HandshakeFailed);
            }
        };
        let shape = if self.cfg.mimic.enabled {
            match tokio::time::timeout(lim.handshake_timeout, mimic::server_preface(&mut tcp, &mut est, &self.cfg.mimic.profile, &cover)).await {
                Ok(Ok(s)) => Some(s),
                _ => {
                    self.stats.handshake_failed.fetch_add(1, Relaxed);
                    self.stats.dropped.fetch_add(1, Relaxed);
                    return drop_(peer, DropReason::HandshakeFailed);
                }
            }
        } else {
            None
        };
        drop(guard);
        self.stats.tunnels.fetch_add(1, Relaxed);
        let mut stream = RealityStream::new(tcp, est, self.cfg.padding);
        if let Some(s) = shape {
            stream = stream.with_shape(s);
        }
        Handled::Tunnel(Accepted::Tunnel { stream, peer, short_id: tok.short_id, sni })
    }

    fn forward(self: &Arc<Self>, tcp: TcpStream, peer: SocketAddr, buf: Vec<u8>, reason: ForwardReason, guard: Guard) -> Handled {
        self.stats.forwarded.fetch_add(1, Relaxed);
        if reason != ForwardReason::Replay {
            self.stats.forwarded_noauth.fetch_add(1, Relaxed);
        }
        Handled::Forward(ForwardJob { peer, reason, buf, tcp, dest: self.cfg.dest.clone(), limits: self.cfg.limits.clone(), _guard: guard })
    }
}

impl ForwardJob {
    /// Подключается к сайту, отдаёт ему все уже прочитанные байты и перекачивает в обе стороны с лимитами.
    pub async fn run(self) -> std::result::Result<(), DropReason> {
        let ForwardJob { mut tcp, buf, dest, limits, .. } = self;
        let up = match tokio::time::timeout(limits.connect_cover_timeout, TcpStream::connect(&dest)).await {
            Ok(Ok(s)) => s,
            _ => return Err(DropReason::CoverUnreachable),
        };
        let _ = up.set_nodelay(true);
        let (mut ur, mut uw) = up.into_split();
        if !buf.is_empty() && uw.write_all(&buf).await.is_err() {
            return Err(DropReason::CoverUnreachable);
        }
        let (mut cr, mut cw) = tcp.split();
        let a = pump(&mut cr, &mut uw, limits.forward_idle, limits.forward_max_bytes);
        let b = pump(&mut ur, &mut cw, limits.forward_idle, limits.forward_max_bytes);
        let _ = tokio::time::timeout(limits.forward_max_life, async { tokio::join!(a, b) }).await;
        Ok(())
    }
}

async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(r: &mut R, w: &mut W, idle: Duration, cap: u64) {
    let mut b = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match tokio::time::timeout(idle, r.read(&mut b)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };
        total += n as u64;
        if total > cap || w.write_all(&b[..n]).await.is_err() {
            break;
        }
    }
    let _ = w.shutdown().await;
}

/// Слушатель: принимает TCP, обрабатывает каждое соединение в своей задаче, отдаёт события.
pub struct Listener {
    rx: mpsc::Receiver<Accepted>,
    local: SocketAddr,
    pub server: Arc<Server>,
}

impl Listener {
    pub async fn bind(addr: SocketAddr, server: Arc<Server>) -> Result<Listener> {
        if server.cfg.proxy_protocol && !addr.ip().is_loopback() && !server.cfg.allow_proxy_on_public {
            return Err(Error::Config("PROXY protocol разрешён только на loopback (иначе любой подделает адрес); allow_proxy_on_public снимает запрет".into()));
        }
        let l = TcpListener::bind(addr).await?;
        let local = l.local_addr()?;
        let (tx, rx) = mpsc::channel(1024);
        let srv = server.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, peer) = match l.accept().await {
                    Ok(x) => x,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                if tx.is_closed() {
                    break;
                }
                let (srv, tx) = (srv.clone(), tx.clone());
                tokio::spawn(async move {
                    match srv.handle(tcp, peer).await {
                        Handled::Tunnel(a) => {
                            let _ = tx.send(a).await;
                        }
                        Handled::Dropped(a) => {
                            let _ = tx.try_send(a);
                        }
                        Handled::Forward(job) => {
                            let _ = tx.try_send(Accepted::Forwarded { peer: job.peer, reason: job.reason });
                            let _ = job.run().await;
                        }
                    }
                });
            }
        });
        Ok(Listener { rx, local, server })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Следующее событие. None - слушатель остановлен.
    pub async fn accept(&mut self) -> Option<Accepted> {
        self.rx.recv().await
    }
}

#[allow(dead_code)]
fn _unused() {
    let _ = util::below;
}
