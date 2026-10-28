//! rns-iroh-node: RNS (leviculum) поверх iroh/QUIC с нативным адаптером.
//!
//! Один QUIC bidi-поток = один байтовый интерфейс RNS (`Node::spawn_byte_channel`, HDLC-кадры), как в Resilum,
//! но без TCP-мостов. Роли:
//!   e  выход: принимает QUIC, регистрирует destination `knothopbench.node`, анонсирует, принимает Resource;
//!   a  промежуточный RNS-транспорт (enable_transport): принимает QUIC от клиента, сам звонит на E;
//!   c  клиент: звонит на E и/или A, поднимает Link до E, шлёт Resource непрерывно, пишет результат.
//!
//! Обмен с оркестратором через каталог --state (файлы <name>.json, ready, go, fin, result-*.json).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use iroh::endpoint::{Connection, Controller, ControllerFactory, IncomingAddr, QuicTransportConfig, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey};
use leviculum_std::api::{
    Destination, DestinationHash, DestinationType, Direction, Identity, LinkId, Node, NodeBuilder, NodeEvent,
    ResourceStrategy,
};
use leviculum_std::interfaces::{ByteChannelOptions, PacketChannelOptions, PacketSink, PacketSource};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod meas;
mod vpn;
mod trust;
mod enroll;
mod tcpc;
mod relay;
mod health;
mod bgwrite;
pub mod mobile;
mod observations;
mod route;
mod host_acl;
mod qprobe;
pub use vpn::{VpnCli, VpnCmd};

/// Fixed non-shell admin CLI bridge used by the Android JNI wrapper.
pub fn admin_cli_json(command: &str, state_dir: &str) -> String {
    vpn::run_cli_json(command, state_dir)
}

/// Точка входа knothopd (узел, хаб, клиент, админ-команды).
pub async fn run_vpn(cli: VpnCli) -> Result<()> {
    match cli.cmd {
        VpnCmd::Node(a) => vpn::run_node(a).await,
        VpnCmd::Hub(a) => vpn::run_hub(a).await,
        VpnCmd::Client(a) => vpn::run_client13(a).await,
        other => vpn::run_admin(other),
    }
}

/// `--tun-fd`: узел без устройства TUN (Android, режим «в сети без VPN»); устройство подключается позже.
pub const TUN_DETACHED: i32 = -2;

/// ALPN QUIC виден в первом пакете: нейтральное значение без имени проекта (ADR 0016).
const ALPN: &[u8] = b"rns/0";
/// HDLC FLAG: безопасный «пустой кадр», чтобы поток QUIC стал виден принимающей стороне (QUIC объявляет поток пиру только при первой записи).
const HDLC_FLAG: u8 = 0x7e;

#[derive(Parser, Clone)]
pub struct Cli {
    /// e | a | c
    #[arg(long)]
    role: String,
    #[arg(long, default_value = "/shared")]
    state: PathBuf,
    /// IPv4 этого контейнера (для прямого адреса в файле состояния)
    #[arg(long)]
    ip: String,
    #[arg(long, default_value = "none")]
    relay: String,
    /// имена пиров (файлы <имя>.json в --state), к которым звонить: например "e" или "a,e"
    #[arg(long, default_value = "")]
    dial: String,
    /// не использовать прямые адреса при звонке (только relay)
    #[arg(long)]
    relay_only: bool,
    #[arg(long, default_value_t = 0)]
    path_idle_ms: u64,
    #[arg(long, default_value_t = 0)]
    path_keepalive_ms: u64,
    /// таймаут простоя ВСЕГО QUIC-соединения, мс (0 = умолчание iroh)
    #[arg(long, default_value_t = 0)]
    conn_idle_ms: u64,
    /// keepalive RNS Link, секунды (0 = умолчание leviculum)
    #[arg(long, default_value_t = 0)]
    link_keepalive_s: u64,
    /// вызывать Endpoint::network_change() каждые N мс
    #[arg(long, default_value_t = 0)]
    nc_ms: u64,
    /// HW_MTU байтового канала (0 = умолчание leviculum 1064; работает только с форком)
    #[arg(long, default_value_t = 0)]
    hw_mtu: u32,
    /// ёмкость каналов интерфейса, пакетов (0 = умолчание 64; только форк)
    #[arg(long, default_value_t = 0)]
    chan_buf: usize,
    /// буфер чтения интерфейса, байт (0 = умолчание 1024; только форк)
    #[arg(long, default_value_t = 0)]
    read_buf: usize,
    /// клиент: длительность непрерывной передачи, с
    #[arg(long, default_value_t = 30)]
    duration: u64,
    /// клиент: размер одного Resource
    #[arg(long, default_value_t = 262144)]
    bytes: usize,
    /// пакетов за одно пробуждение задачи интерфейса в каждую сторону (1 = как раньше)
    #[arg(long, default_value_t = 1)]
    burst: usize,
    /// число рабочих потоков tokio (0 = по числу ядер); читает оболочка, которая сама строит runtime
    #[arg(long, default_value_t = 0)]
    pub workers: usize,
    /// Android: готовый дескриптор TUN от VpnService (интерфейс, адрес и маршруты уже настроены системой); -1 = открыть /dev/net/tun самим
    #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
    tun_fd: i32,
    /// выход: интервал повторного анонса, с (в реальной сети анонсы редки; частые упираются в ограничитель частоты узлов)
    #[arg(long, default_value_t = 3)]
    announce_s: u64,
    /// выход: первые N секунд анонсировать каждые 3 с (пока соседи подключаются), дальше по --announce-s
    #[arg(long, default_value_t = 0)]
    announce_warmup_s: u64,
    /// отладка: транспортный узел печатает счётчики каждые 3 с
    #[arg(long)]
    relay_debug: bool,
    /// TUN-клиент: адрес выхода внутри туннеля (куда слать пробы живости)
    #[arg(long, default_value = "10.99.0.1")]
    exit_tun_ip: String,
    /// TUN-клиент: сколько мс молчания (после своей отправки) считать Link мёртвым и переподнимать
    #[arg(long, default_value_t = 3000)]
    fail_ms: u64,
    /// TUN-клиент: сколько мс ждать установления нового Link при смене маршрута
    #[arg(long, default_value_t = 5000)]
    relink_timeout_ms: u64,
    /// клиент: после сбоя убирать путь к E и просить новый (контроллер смены маршрута)
    #[arg(long)]
    controller: bool,
    /// сколько ждать одного Resource, с
    #[arg(long, default_value_t = 30)]
    resource_timeout: u64,
    /// клиент: режим нагрузки: "resource" (RNS Resource) или "stream" (LinkHandle::send, Channel - так ходит VPN-поток)
    #[arg(long, default_value = "resource")]
    mode: String,
    /// клиент, режим stream: размер одной записи LinkHandle::send, байт
    #[arg(long, default_value_t = 400)]
    chunk: usize,
    /// клиент, режим stream: сколько байт всего отправить (0 = не ограничивать, крутить до --duration)
    #[arg(long, default_value_t = 0)]
    stream_bytes: u64,
    /// режим stream: дополнительно сверить SHA-256 всего потока. Внимание: хеширование на
    /// обеих сторонах само съедает CPU (на выходе это была половина RUN-сэмплов),
    /// поэтому для замера скорости по умолчанию выключено - сверка идёт по шаблону.
    #[arg(long, default_value_t = false)]
    verify_sha: bool,
    /// Proof binding: "cipher" (safe default: CBC=hash, GCM=tag), "hash"
    /// (PacketHash for every Link), or explicit custom "tag" (both peers must agree;
    /// KnotHop-only for CBC).
    #[arg(long, default_value = "cipher", value_parser = ["cipher", "tag", "hash"])]
    proof_binding: String,
    /// Явный крипторежим Link; обе стороны должны совпадать.
    #[arg(long, default_value = "cbc", value_parser = ["cbc", "gcm"])]
    cipher: String,
    /// Лимит in-flight записей stream (0 = 128, меньше для низкой задержки).
    #[arg(long, default_value_t = 0)]
    send_window: usize,
    /// Оставить пейсинг QUIC, сохранив окно и ARQ RNS (только явный QUIC-профиль).
    #[arg(long)]
    window_only: bool,
    /// Параллельный малый echo по отдельному Link для RTT под нагрузкой.
    #[arg(long)]
    echo: bool,
    /// носитель RNS-интерфейса: "stream" (HDLC по потоку QUIC, надёжный и упорядоченный) или
    /// "datagram" (один RNS-пакет в одной датаграмме QUIC, без обрамления и без блокировки головы очереди)
    #[arg(long, default_value = "stream", value_parser = ["stream", "datagram"])]
    carrier: String,
    /// режим tun: имя TUN-интерфейса
    #[arg(long, default_value = "tun0")]
    tun_name: String,
    /// режим tun: адрес TUN-интерфейса с маской, например 10.99.0.2/24
    #[arg(long, default_value = "10.99.0.2/24")]
    tun_ip: String,
    /// режим tun: MTU TUN-интерфейса (не больше MDU Link, при HW_MTU 1400 это 1327)
    #[arg(long, default_value_t = 1300)]
    tun_mtu: u32,
    /// QUIC: начальный MTU пути, байт (0 = умолчание 1200). Размер датаграммы растёт только после обнаружения MTU
    #[arg(long, default_value_t = 0)]
    quic_initial_mtu: u16,
    /// QUIC: окно приёма на поток, байт (0 = умолчание noq 1 250 000: потолок скорости потока = окно ÷ RTT)
    #[arg(long, default_value_t = 0)]
    quic_stream_window: u64,
    /// QUIC: окно приёма на соединение, байт (0 = умолчание)
    #[arg(long, default_value_t = 0)]
    quic_conn_window: u64,
    /// QUIC: буфер отправки датаграмм, байт (0 = умолчание 1 МиБ); при переполнении теряются СТАРЕЙШИЕ датаграммы
    #[arg(long, default_value_t = 0)]
    quic_dg_send_buf: usize,
    /// QUIC: буфер приёма датаграмм, байт (0 = умолчание)
    #[arg(long, default_value_t = 0)]
    quic_dg_recv_buf: usize,
    /// режим tun: длина очереди передачи TUN, пакетов. Ядро кладёт в неё пачки TCP-окна; переполнение — потери и ретрансмиты
    #[arg(long, default_value_t = 1000)]
    tun_txqlen: u32,
    /// режим tun: дисциплина очереди TUN ("" = умолчание ядра, "fq_codel" = активное управление очередью)
    #[arg(long, default_value = "")]
    tun_qdisc: String,
    /// QUIC: управление перегрузкой носителя. "default" (Cubic) режет окно при случайных потерях и душит туннель;
    /// "bbr3" не реагирует на потери так резко; "tunnel" игнорирует потери и держит только потолок скорости
    /// (как WireGuard: перегрузкой управляют внутренние потоки)
    #[arg(long, default_value = "default", value_parser = ["default", "bbr3", "tunnel"])]
    quic_cc: String,
    /// QUIC: потолок скорости контроллера "tunnel", Мбит/с
    #[arg(long, default_value_t = 1000)]
    quic_cc_mbit: u64,
    /// HW_MTU пакетного интерфейса при --carrier datagram: наибольший RNS-пакет в одной датаграмме QUIC
    #[arg(long, default_value_t = 1400)]
    dgram_mtu: u32,
    /// ёмкость очереди событий данных приложения (0 = по умолчанию библиотеки)
    #[arg(long, default_value_t = 0)]
    data_cap: usize,
    /// режим dgram: целевое число пакетов в секунду (0 = как можно быстрее)
    #[arg(long, default_value_t = 0)]
    pps: u64,
    /// Секунды зондирования echo до `ready`: RTT ненагруженного пути.
    #[arg(long, default_value_t = 3)]
    idle_secs: u64,
    /// включить RNS-транспорт (для роли a включено всегда)
    #[arg(long)]
    transport: bool,
    #[arg(long, default_value_t = 4433)]
    port: u16,
}

fn parse_cli_proof_binding_policy(
    value: &str,
) -> anyhow::Result<leviculum_std::api::ProofBindingPolicy> {
    use leviculum_std::api::{ProofBinding, ProofBindingPolicy};
    match value {
        "cipher" => Ok(ProofBindingPolicy::ByCipher),
        "hash" => Ok(ProofBindingPolicy::Explicit(ProofBinding::PacketHash)),
        "tag" => Ok(ProofBindingPolicy::Explicit(ProofBinding::TokenTag)),
        other => bail!("unknown --proof-binding {other:?} (want cipher|hash|tag)"),
    }
}

#[derive(Serialize, Deserialize)]
struct PeerInfo {
    id: String,
    direct: String,
    relay: Option<String>,
    /// только у E
    dest_hash: Option<String>,
    signing_key: Option<String>,
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}

/// Потери пакетного интерфейса, которые больше нигде не видны: переполнение входящей очереди и отказы носителя.
fn pc_drops_json() -> serde_json::Value {
    let d = leviculum_std::interfaces::packet_channel_drops();
    serde_json::json!({"rx_queue_dropped": d.0, "tx_refused": d.1})
}

/// Счётчики системных вызовов UDP (только со сборкой `udp-stats` и патчем noq-udp).
fn udp_stats() -> serde_json::Value {
    #[cfg(feature = "udp-stats")]
    {
        use std::sync::atomic::Ordering::Relaxed;
        return serde_json::json!({"send_calls": noq_udp::SEND_CALLS.load(Relaxed), "send_dgrams": noq_udp::SEND_SEGS.load(Relaxed),
            "recv_calls": noq_udp::RECV_CALLS.load(Relaxed), "recv_dgrams": noq_udp::RECV_SEGS.load(Relaxed)});
    }
    #[allow(unreachable_code)]
    serde_json::Value::Null
}

static LOG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

const DGRAM_MAGIC: &[u8; 8] = b"KNOTDGRM";
const DGRAM_HDR: usize = 24;
const DGRAM_BUCKET_US: u64 = 50;
const DGRAM_BUCKETS: usize = 20_001;

fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

/// Приёмник датаграмм: потери, перестановки, одностороння задержка и джиттер. Часы общие (один хост).
struct DgramRx {
    received: u64,
    bytes: u64,
    highest: Option<u64>,
    reordered: u64,
    corrupt: u64,
    first_us: u64,
    last_us: u64,
    hist: Vec<u32>,
    prev_delay: Option<i64>,
    jitter_sum: f64,
    jitter_n: u64,
    min_delay: i64,
}

impl Default for DgramRx {
    fn default() -> Self {
        DgramRx { received: 0, bytes: 0, highest: None, reordered: 0, corrupt: 0, first_us: 0, last_us: 0,
            hist: vec![0; DGRAM_BUCKETS], prev_delay: None, jitter_sum: 0.0, jitter_n: 0, min_delay: i64::MAX }
    }
}

impl DgramRx {
    fn push(&mut self, data: &[u8]) {
        let t = now_us();
        let seq = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let sent = u64::from_le_bytes(data[16..24].try_into().unwrap());
        if self.received == 0 { self.first_us = t; }
        self.last_us = t;
        self.received += 1;
        self.bytes += data.len() as u64;
        match self.highest {
            Some(h) if seq < h => self.reordered += 1,
            _ => self.highest = Some(seq),
        }
        if pattern_check(&data[DGRAM_HDR..], 0).is_some() { self.corrupt += 1; }
        let delay = t as i64 - sent as i64;
        self.min_delay = self.min_delay.min(delay);
        let b = (delay.max(0) as u64 / DGRAM_BUCKET_US).min(DGRAM_BUCKETS as u64 - 1) as usize;
        self.hist[b] += 1;
        if let Some(p) = self.prev_delay { self.jitter_sum += (delay - p).abs() as f64; self.jitter_n += 1; }
        self.prev_delay = Some(delay);
    }
    fn pct_us(&self, p: f64) -> f64 {
        let total: u64 = self.hist.iter().map(|&c| c as u64).sum();
        if total == 0 { return 0.0; }
        let want = ((total as f64) * p / 100.0).ceil() as u64;
        let mut acc = 0u64;
        for (i, &c) in self.hist.iter().enumerate() {
            acc += c as u64;
            if acc >= want { return (i as u64 * DGRAM_BUCKET_US) as f64; }
        }
        0.0
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "received": self.received, "bytes": self.bytes, "highest_seq": self.highest,
            "reordered": self.reordered, "corrupt": self.corrupt,
            "first_us": self.first_us, "last_us": self.last_us,
            "delay_min_us": if self.min_delay == i64::MAX { 0 } else { self.min_delay },
            "delay_p50_us": self.pct_us(50.0), "delay_p95_us": self.pct_us(95.0), "delay_p99_us": self.pct_us(99.0),
            "jitter_us": if self.jitter_n > 0 { self.jitter_sum / self.jitter_n as f64 } else { 0.0 },
        })
    }
}

#[derive(Default)]
struct StreamRx {
    bytes: u64,
    first_ms: u128,
    last_ms: u128,
    mismatch_at: Option<u64>,
    msgs: u64,
    max_msg: usize,
}

/// Детерминированный шаблон потока: байт зависит только от абсолютного смещения.
/// Байт `o` потока — байт `o % 8` (little-endian) слова `(o / 8) * K`. Слово за раз:
/// побайтовый цикл стоил столько же CPU, сколько быстрый туннель, и искажал замер
/// на 1 ядре клиента (тот же шаблон и в bin/tcp-load.rs, там есть тест эквивалентности).
const PATTERN_K: u64 = 0x9E37_79B9_7F4A_7C15;
fn pattern_word(o: u64) -> u64 {
    (o / 8).wrapping_mul(PATTERN_K)
}

fn pattern_fill(buf: &mut [u8], off: u64) {
    let (mut o, mut i) = (off, 0);
    while i < buf.len() && o % 8 != 0 {
        buf[i] = (pattern_word(o) >> ((o % 8) * 8)) as u8;
        i += 1;
        o += 1;
    }
    let mut words = buf[i..].chunks_exact_mut(8);
    for chunk in &mut words {
        chunk.copy_from_slice(&pattern_word(o).to_le_bytes());
        o += 8;
    }
    for (j, b) in words.into_remainder().iter_mut().enumerate() {
        *b = (pattern_word(o) >> (j * 8)) as u8;
    }
}

fn pattern_check(buf: &[u8], off: u64) -> Option<u64> {
    let (mut o, mut i) = (off, 0);
    while i < buf.len() && o % 8 != 0 {
        if buf[i] != (pattern_word(o) >> ((o % 8) * 8)) as u8 {
            return Some(o);
        }
        i += 1;
        o += 1;
    }
    let mut words = buf[i..].chunks_exact(8);
    for chunk in &mut words {
        let expected = pattern_word(o).to_le_bytes();
        if chunk != expected {
            let j = chunk.iter().zip(expected).position(|(a, b)| *a != b).unwrap();
            return Some(o + j as u64);
        }
        o += 8;
    }
    for (j, b) in words.remainder().iter().enumerate() {
        if *b != (pattern_word(o) >> (j * 8)) as u8 {
            return Some(o + j as u64);
        }
    }
    None
}

/// Пиковый и текущий RSS этого процесса, КиБ.
fn proc_mem_kb() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |key: &str| {
        status.lines().find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0)
    };
    (field("VmHWM:"), field("VmRSS:"))
}

impl Shared {
    fn stream_rx(&self, data: &[u8]) {
        // hasher включается только при --verify-sha: он сам по себе нагружает CPU,
        // и в профиле выхода занимал больше половины времени в RUN.
        if let Some(h) = self.stream_hash.lock().unwrap().as_mut() {
            h.update(data);
        }
        let mut s = self.stream.lock().unwrap();
        let t = now_ms();
        if s.msgs == 0 { s.first_ms = t; }
        s.last_ms = t;
        if s.mismatch_at.is_none() {
            let off = s.bytes;
            s.mismatch_at = pattern_check(data, off);
        }
        s.bytes += data.len() as u64;
        s.msgs += 1;
        s.max_msg = s.max_msg.max(data.len());
    }
}

/// Лимит записей состояний Link (established/closed) и строк журнала в памяти: старые записи вытесняются.
const LINK_STATE_MAX: usize = 4096;
const LOG_MEM_MAX: usize = 2000;
/// размер log.txt, после которого файл уходит в log.txt.1 (одна старая копия)
const LOG_FILE_MAX: u64 = 5 << 20;
/// запись в log.txt: ротация и запись не должны перемешиваться между потоками
static LOG_IO: Mutex<()> = Mutex::new(());

/// Множество установленных Link с ограничением: сверх лимита вытесняется самая старая запись.
#[derive(Default)]
struct LinkSet {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl LinkSet {
    fn insert(&mut self, k: String) {
        if self.set.insert(k.clone()) {
            self.order.push_back(k);
        }
        while self.order.len() > LINK_STATE_MAX {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
    }
    fn contains(&self, k: &str) -> bool {
        self.set.contains(k)
    }
}

/// Словарь закрытых Link (причина закрытия) с тем же ограничением, что и `LinkSet`.
#[derive(Default)]
struct LinkClosedMap {
    map: HashMap<String, String>,
    order: VecDeque<String>,
}

impl LinkClosedMap {
    fn insert(&mut self, k: String, v: String) {
        if !self.map.contains_key(&k) {
            self.order.push_back(k.clone());
        }
        self.map.insert(k, v);
        while self.order.len() > LINK_STATE_MAX {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
    fn get(&self, k: &str) -> Option<&String> {
        self.map.get(k)
    }
    fn contains_key(&self, k: &str) -> bool {
        self.map.contains_key(k)
    }
}

/// Общая картина событий узла, заполняется задачей чтения событий.
#[derive(Default)]
struct Shared {
    echo_pending: Mutex<std::collections::HashMap<u64, tokio::sync::oneshot::Sender<()>>>,
    echo_rtt_ms: Mutex<Vec<f64>>,
    echo_idle_rtt_ms: Mutex<Vec<f64>>,
    echo_timeouts: Mutex<u64>,
    established: Mutex<LinkSet>,
    closed: Mutex<LinkClosedMap>,
    /// кольцевой журнал в памяти (последние LOG_MEM_MAX строк, см. `note`)
    log: Mutex<Vec<(u128, String)>>,
    received: Mutex<Vec<(u128, usize, String)>>,
    failed_resources: Mutex<u64>,
    /// приёмник stream: принято байт, первое/последнее время приёма (мс), первое расхождение шаблона
    stream: Mutex<StreamRx>,
    /// приёмник датаграмм (режим dgram)
    dgram: Mutex<DgramRx>,
    /// последняя статистика QUIC-соединения носителя (потери, перегрузка, окно), обновляется раз в 250 мс
    quic_stats: Mutex<String>,
    /// IP-туннель (режим tun): появляется после открытия TUN
    tun: std::sync::OnceLock<Arc<TunState>>,
    /// SHA-256 всего принятого потока на выходе, для сквозной сверки на больших объёмах
    stream_hash: Mutex<Option<Sha256>>,
    /// счётчик отвалившихся RNS-интерфейсов (QUIC-соединение закрыто); контроллер клиента ждёт его изменения
    detach: tokio::sync::watch::Sender<u64>,
    /// режим meas: клиентский приёмник пакетов замера и состояние выхода
    meas_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>,
    meas_exit: meas::ExitState,
    /// какие носители с какими пирами не работают (по собственным проверкам)
    health: health::Health,
}

impl Shared {
    fn new() -> Self {
        let (detach, _) = tokio::sync::watch::channel(0u64);
        Shared { detach, ..Default::default() }
    }
    fn note(&self, msg: impl Into<String>) {
        let msg = msg.into();
        eprintln!("[{}] {}", now_ms(), msg);
        // На Android stderr никуда не идёт: дублируем в файл, который читает оболочка приложения.
        if let Some(p) = LOG_PATH.get() {
            append_log(p, &format!("[{}] {}", now_ms(), msg));
        }
        let mut l = self.log.lock().unwrap();
        l.push((now_ms(), msg));
        if l.len() > LOG_MEM_MAX {
            // вытесняем старую половину: удаление пачкой, а не по одной строке
            let cut = l.len() - LOG_MEM_MAX / 2;
            l.drain(..cut);
        }
    }
}

/// Строки журнала файла, которые ждут потока записи (см. `append_log`).
const LOG_QUEUE_MAX: usize = 1024;
/// Строки, не поместившиеся в очередь журнала с начала последней записи; пишутся отдельной строкой.
static LOG_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LOG_QUEUE: std::sync::OnceLock<Option<std::sync::mpsc::SyncSender<(PathBuf, String)>>> = std::sync::OnceLock::new();

/// Дописать строку в журнал файла без ожидания диска: строка уходит в очередь потока журнала.
/// Открытие файла с O_CREAT на рабочем (async) потоке ждёт блокировку каталога `state/`, которую держит
/// `rename` фонового записывающего потока, а тот ждёт журнал диска (W72, fin1: tokio-rt-worker в D на
/// open(log.txt)). При переполнении очереди строка пропускается и учитывается в `LOG_DROPPED`.
fn append_log(p: &Path, line: &str) {
    let queue = LOG_QUEUE.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<(PathBuf, String)>(LOG_QUEUE_MAX);
        match std::thread::Builder::new().name("knothop-log".into()).spawn(move || log_writer(rx)) {
            Ok(_) => Some(tx),
            Err(_) => None,
        }
    });
    match queue {
        Some(tx) => {
            if tx.try_send((p.to_path_buf(), line.to_string())).is_err() {
                LOG_DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        None => append_log_sync(p, line),
    }
}

/// Поток журнала: пишет строки по порядку и сообщает о пропущенных при переполнении очереди.
fn log_writer(rx: std::sync::mpsc::Receiver<(PathBuf, String)>) {
    for (p, line) in rx {
        let dropped = LOG_DROPPED.swap(0, std::sync::atomic::Ordering::Relaxed);
        if dropped > 0 {
            append_log_sync(&p, &format!("[{}] журнал: пропущено строк при переполнении очереди: {dropped}", now_ms()));
        }
        append_log_sync(&p, &line);
    }
}

/// Дописать строку в журнал файла; при размере от LOG_FILE_MAX текущий файл переименовывается в `<имя>.1`.
/// Синхронно: вызывается из потока журнала (и напрямую в тестах).
fn append_log_sync(p: &Path, line: &str) {
    use std::io::Write;
    let _io = LOG_IO.lock().unwrap();
    if std::fs::metadata(p).is_ok_and(|m| m.len() >= LOG_FILE_MAX) {
        let mut old = p.as_os_str().to_owned();
        old.push(".1");
        let _ = std::fs::rename(p, old);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
        let _ = writeln!(f, "{line}");
    }
}

/// Учёт занятых слотов: всего и по адресу. Слот возвращается в `drop`, нулевые записи по адресам удаляются.
#[derive(Default)]
pub(crate) struct Slots {
    live: usize,
    per_ip: HashMap<IpAddr, usize>,
}

pub(crate) type SlotsRef = Arc<Mutex<Slots>>;

/// Занятый слот (соединение). Освобождается при уничтожении: задача соединения держит его до конца.
pub(crate) struct Slot {
    owner: SlotsRef,
    ip: Option<IpAddr>,
}

impl Slot {
    /// Занять слот, если всего занято меньше `max_live` и с адреса меньше `max_ip`. Без адреса (релей) действует только общий лимит.
    pub(crate) fn take(owner: &SlotsRef, ip: Option<IpAddr>, max_live: usize, max_ip: usize) -> Option<Slot> {
        let mut s = owner.lock().unwrap();
        let c = ip.and_then(|a| s.per_ip.get(&a).copied()).unwrap_or(0);
        if s.live >= max_live || (ip.is_some() && c >= max_ip) {
            return None;
        }
        s.live += 1;
        if let Some(a) = ip {
            *s.per_ip.entry(a).or_insert(0) += 1;
        }
        Some(Slot { owner: owner.clone(), ip })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut s = self.owner.lock().unwrap();
        s.live = s.live.saturating_sub(1);
        if let Some(a) = self.ip {
            if let Some(c) = s.per_ip.get_mut(&a) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    s.per_ip.remove(&a);
                }
            }
        }
    }
}

/// QUIC bidi-поток как один дуплекс для leviculum (AsyncRead + AsyncWrite).
struct IrohStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for IrohStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for IrohStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// (носитель-датаграммы, HW_MTU пакетного интерфейса)
static CARRIER: std::sync::OnceLock<(bool, u32)> = std::sync::OnceLock::new();
fn carrier() -> (bool, u32) {
    *CARRIER.get().unwrap_or(&(false, 1400))
}

/// Приёмная половина носителя: датаграммы QUIC. `read_datagram` отменяем без потерь данных.
struct QuicDgramSource {
    conn: Connection,
    /// счётчики и лимит магических датаграмм этого соединения (QAB-M5)
    filter: qprobe::Filter,
}
impl QuicDgramSource {
    fn new(conn: Connection) -> Self {
        Self { conn, filter: qprobe::Filter::new() }
    }
}
impl PacketSource for QuicDgramSource {
    fn try_recv(&mut self) -> Option<std::io::Result<Vec<u8>>> {
        // Один опрос с пустым waker: готовая датаграмма забирается сразу, иначе будущее отбрасывается (read_datagram безопасно к отмене).
        // Датаграммы теневого зонда (qprobe) обрабатываются здесь и в RNS не попадают. Работа за вызов ограничена `WORK_BUDGET`:
        // исчерпав его, возвращаем None - вызывающий возвращается к `recv` с настоящим waker и не теряет ожидание (QAB-M5).
        let mut cx = Context::from_waker(std::task::Waker::noop());
        loop {
            let mut fut = std::pin::pin!(self.conn.read_datagram());
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(Ok(b)) => {
                    if self.filter.intercept(&self.conn, &b) {
                        if self.filter.ate() {
                            return None;
                        }
                        continue;
                    }
                    self.filter.delivered();
                    return Some(Ok(b.to_vec()));
                }
                Poll::Ready(Err(e)) => return Some(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))),
                Poll::Pending => return None,
            }
        }
    }

    fn recv(&mut self) -> impl std::future::Future<Output = std::io::Result<Vec<u8>>> + Send {
        async move {
            loop {
                let b = self
                    .conn
                    .read_datagram()
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))?;
                if self.filter.intercept(&self.conn, &b) {
                    // поток magic не должен держать исполнителя и выбор между приёмом, исходящей очередью и остановом интерфейса
                    if self.filter.ate() {
                        tokio::task::yield_now().await;
                    }
                    continue;
                }
                self.filter.delivered();
                return Ok(b.to_vec());
            }
        }
    }
}

/// Передающая половина. Слишком большая датаграмма — потеря одного пакета, а не обрыв интерфейса;
/// отсутствие датаграмм у пира или потеря соединения — фатальны. Переполненный буфер QUIC сам отбрасывает
/// самые старые датаграммы, ошибки не будет.
struct QuicDgramSink(Connection);
impl PacketSink for QuicDgramSink {
    fn send(&mut self, packet: &[u8]) -> std::io::Result<()> {
        use iroh::endpoint::SendDatagramError as E;
        use std::io::{Error, ErrorKind};
        match self.0.send_datagram(bytes::Bytes::copy_from_slice(packet)) {
            Ok(()) => Ok(()),
            Err(E::TooLarge) => Err(Error::from(ErrorKind::InvalidInput)),
            Err(E::ConnectionLost(e)) => Err(Error::new(ErrorKind::BrokenPipe, e.to_string())),
            Err(e) => Err(Error::new(ErrorKind::Unsupported, e.to_string())),
        }
    }
}

static TUNING: std::sync::OnceLock<(u32, usize, usize)> = std::sync::OnceLock::new();
fn tuning() -> (u32, usize, usize) {
    *TUNING.get().unwrap_or(&(0, 0, 0))
}

fn path_kind(conn: &Connection) -> &'static str {
    for p in conn.paths().iter() {
        if p.is_selected() {
            return if p.is_relay() { "relay" } else { "direct" };
        }
    }
    "none"
}

/// Контроллер перегрузки для туннеля, который несёт ВНУТРЕННИЙ трафик с собственным управлением перегрузкой.
///
/// Вложенное управление (внутри TCP, снаружи Cubic QUIC) реагирует на одни и те же потери дважды: при 0,5% случайных
/// потерь внешний Cubic схлопывал окно, очередь датаграмм переполнялась и терялось 90% UDP. Здесь потери игнорируются,
/// скорость ограничена пейсером потолком `rate`, окно — запас к BDP. Внешний путь от этого не защищён так, как защищал
/// бы Cubic: внутренние TCP-потоки обязаны сами снижать скорость, внутренний UDP не снижает (как у любого VPN без CC).
#[derive(Debug, Clone)]
struct TunnelCc {
    rate: u64,
    window: u64,
    min_window: u64,
}
impl TunnelCc {
    fn new(rate: u64, mtu: u16) -> Self {
        let min_window = 64 * mtu as u64;
        TunnelCc { rate, window: (rate / 5).max(min_window), min_window }
    }
}
impl Controller for TunnelCc {
    fn on_ack(&mut self, _now: Instant, _sent: Instant, _bytes: u64, _pn: u64, _app_limited: bool, rtt: &iroh::endpoint::RttEstimator) {
        // 2 x BDP: с запасом, чтобы окно никогда не было узким местом
        self.window = ((self.rate as f64 * rtt.get().as_secs_f64() * 2.0) as u64).max(self.min_window);
    }
    fn on_congestion_event(&mut self, _now: Instant, _sent: Instant, _persistent: bool, _ecn: bool, _lost_bytes: u64, _pn: u64) {
        // намеренно ничего: потери не уменьшают скорость
    }
    fn on_mtu_update(&mut self, mtu: u16) {
        self.min_window = 64 * mtu as u64;
    }
    fn window(&self) -> u64 {
        self.window
    }
    fn metrics(&self) -> iroh::endpoint::ControllerMetrics {
        let mut m = iroh::endpoint::ControllerMetrics::default();
        m.congestion_window = self.window;
        m.pacing_rate = Some(self.rate);
        m
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }
    fn initial_window(&self) -> u64 {
        self.window
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}
struct TunnelCcFactory(u64);
impl ControllerFactory for TunnelCcFactory {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(TunnelCc::new(self.0, current_mtu))
    }
}
/// ("default"|"bbr3"|"tunnel", потолок Мбит/с)
static QUIC_CC: std::sync::OnceLock<(String, u64)> = std::sync::OnceLock::new();

/// (initial_mtu, stream_window, conn_window, dg_send_buf, dg_recv_buf): 0 = оставить умолчание
static QUIC_EXTRA: std::sync::OnceLock<(u16, u64, u64, usize, usize)> = std::sync::OnceLock::new();

fn transport(idle_ms: u64, keepalive_ms: u64, conn_idle_ms: u64) -> Option<QuicTransportConfig> {
    let extra = *QUIC_EXTRA.get().unwrap_or(&(0, 0, 0, 0, 0));
    let cc = QUIC_CC.get().cloned().unwrap_or(("default".into(), 0));
    if idle_ms == 0 && keepalive_ms == 0 && conn_idle_ms == 0 && extra == (0, 0, 0, 0, 0) && cc.0 == "default" {
        return None;
    }
    let mut b = QuicTransportConfig::builder();
    match cc.0.as_str() {
        "bbr3" => b = b.congestion_controller_factory(Arc::new(noq_proto::congestion::Bbr3Config::default())),
        "tunnel" => b = b.congestion_controller_factory(Arc::new(TunnelCcFactory(cc.1 * 1_000_000 / 8))),
        _ => {}
    }
    if extra.0 > 0 {
        b = b.initial_mtu(extra.0);
    }
    if extra.1 > 0 {
        if let Ok(v) = iroh::endpoint::VarInt::from_u64(extra.1) { b = b.stream_receive_window(v); }
    }
    if extra.2 > 0 {
        if let Ok(v) = iroh::endpoint::VarInt::from_u64(extra.2) { b = b.receive_window(v); }
    }
    if extra.3 > 0 {
        b = b.datagram_send_buffer_size(extra.3);
    }
    if extra.4 > 0 {
        b = b.datagram_receive_buffer_size(Some(extra.4));
    }
    if conn_idle_ms > 0 {
        if let Ok(t) = Duration::from_millis(conn_idle_ms).try_into() {
            b = b.max_idle_timeout(Some(t));
        }
    }
    if idle_ms > 0 {
        b = b.default_path_max_idle_timeout(Duration::from_millis(idle_ms));
    }
    if keepalive_ms > 0 {
        b = b
            .default_path_keep_alive_interval(Duration::from_millis(keepalive_ms))
            .keep_alive_interval(Duration::from_millis(keepalive_ms));
    }
    Some(b.build())
}

fn relay_mode(relay: &str) -> Result<RelayMode> {
    if relay == "none" {
        return Ok(RelayMode::Disabled);
    }
    Ok(RelayMode::custom([relay.parse::<RelayUrl>().context("relay url")?]))
}

async fn wait_file(p: &Path, secs: u64) -> Result<()> {
    let t0 = Instant::now();
    while !p.exists() {
        if t0.elapsed().as_secs() > secs {
            bail!("timeout waiting for {}", p.display());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// Присоединить поток QUIC как интерфейс RNS и держать его, пока жива QUIC-связь.
async fn attach_until_closed(node: Arc<Node>, sh: Arc<Shared>, name: String, conn: Connection, send: SendStream, recv: RecvStream) {
    let mut opts = ByteChannelOptions::default();
    let t = tuning();
    if t.0 > 0 { opts.hw_mtu = t.0; }
    if t.1 > 0 { opts.buffer_size = t.1; }
    if t.2 > 0 { opts.read_buf_size = t.2; }
    match node.spawn_byte_channel_with(&name, IrohStream { send, recv }, opts) {
        Ok(handle) => {
            sh.note(format!("interface attached: {name}"));
            let _ = conn.closed().await;
            drop(handle);
            sh.note(format!("interface detached (quic closed): {name}"));
            sh.detach.send_modify(|v| *v += 1);
        }
        Err(e) => sh.note(format!("spawn_byte_channel failed for {name}: {e}")),
    }
}

/// Присоединить датаграммы QUIC как пакетный интерфейс RNS и держать его, пока жива QUIC-связь.
async fn attach_datagrams_until_closed(node: Arc<Node>, sh: Arc<Shared>, name: String, conn: Connection) {
    let (_, mtu) = carrier();
    sh.note(format!("quic max datagram size at attach: {:?}", conn.max_datagram_size()));
    let t = tuning();
    let opts = PacketChannelOptions { hw_mtu: mtu, buffer_size: if t.1 > 0 { t.1 } else { 1024 } };
    // статистика QUIC раз в 250 мс; задача держит Connection, поэтому завершается вместе с соединением и при выходе ниже
    let stats = {
        let (c2, sh2) = (conn.clone(), sh.clone());
        tokio::spawn(async move {
            loop {
                let st = c2.stats();
                *sh2.quic_stats.lock().unwrap() = format!(
                    "lost_packets={} lost_bytes={}\nframe_tx={:?}\nframe_rx={:?}\nudp_tx={:?}\nudp_rx={:?}",
                    st.lost_packets, st.lost_bytes, st.frame_tx, st.frame_rx, st.udp_tx, st.udp_rx
                );
                tokio::select! {
                    _ = c2.closed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
            }
        })
    };
    match node.spawn_packet_channel(&name, QuicDgramSource::new(conn.clone()), QuicDgramSink(conn.clone()), opts) {
        Ok(handle) => {
            sh.note(format!("packet interface attached: {name} (hw_mtu {mtu})"));
            let _ = conn.closed().await;
            drop(handle);
            sh.note(format!("packet interface detached (quic closed): {name}"));
            sh.detach.send_modify(|v| *v += 1);
        }
        Err(e) => {
            sh.note(format!("spawn_packet_channel failed for {name}: {e}"));
            conn.close(0u32.into(), b"no packet channel");
        }
    }
    stats.abort();
}

/// Входящие QUIC до допуска: всего и с одного адреса. Слот держится, пока живо соединение.
const MAX_INCOMING: usize = 256;
const MAX_INCOMING_PER_IP: usize = 8;

async fn accept_loop(ep: Endpoint, node: Arc<Node>, sh: Arc<Shared>) {
    let mut n = 0u32;
    let slots: SlotsRef = Default::default();
    while let Some(incoming) = ep.accept().await {
        // релей не показывает адрес клиента: для него действует только общий лимит
        let ip = match incoming.remote_addr() {
            IncomingAddr::Ip(a) => Some(a.ip()),
            _ => None,
        };
        let Some(slot) = Slot::take(&slots, ip, MAX_INCOMING, MAX_INCOMING_PER_IP) else {
            incoming.refuse();
            continue;
        };
        let (node, sh) = (node.clone(), sh.clone());
        n += 1;
        let id = n;
        tokio::spawn(async move {
            let _slot = slot;
            let Ok(conn) = incoming.await else { return };
            let peer = conn.remote_id().fmt_short().to_string();
            sh.note(format!("quic accepted from {peer}"));
            if carrier().0 {
                attach_datagrams_until_closed(node, sh, format!("iroh-dg-in-{peer}-{id}"), conn).await;
                return;
            }
            loop {
                let Ok((send, recv)) = conn.accept_bi().await else { break };
                let (node, sh, conn) = (node.clone(), sh.clone(), conn.clone());
                tokio::spawn(attach_until_closed(node, sh, format!("iroh-in-{peer}-{id}"), conn, send, recv));
            }
        });
    }
}

async fn dial_loop(
    ep: Endpoint,
    node: Arc<Node>,
    sh: Arc<Shared>,
    state: PathBuf,
    peer: String,
    relay: String,
    relay_only: bool,
) {
    let info_path = state.join(format!("{peer}.json"));
    let mut n = 0u32;
    loop {
        let info: PeerInfo = match std::fs::read(&info_path).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
            Some(i) => i,
            None => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let Ok(id) = info.id.parse::<EndpointId>() else { return };
        let mut addr = EndpointAddr::new(id);
        if !relay_only {
            if let Ok(a) = info.direct.parse::<SocketAddr>() {
                addr = addr.with_ip_addr(a);
            }
        }
        if relay != "none" {
            if let Ok(u) = relay.parse::<RelayUrl>() {
                addr = addr.with_relay_url(u);
            }
        }
        let t0 = Instant::now();
        let conn = match tokio::time::timeout(Duration::from_secs(8), ep.connect(addr, ALPN)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                sh.note(format!("dial {peer} failed: {e}"));
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            Err(_) => {
                sh.note(format!("dial {peer} timeout"));
                continue;
            }
        };
        sh.note(format!("quic connected to {peer} in {} ms", t0.elapsed().as_millis()));
        // журнал смены выбранного пути этой связи
        let c2 = conn.clone();
        let (sh2, peer2) = (sh.clone(), peer.clone());
        let watcher = tokio::spawn(async move {
            let mut last = "";
            let mut last_mds: Option<usize> = None;
            let t_start = Instant::now();
            loop {
                let k = path_kind(&c2);
                if k != last {
                    last = k;
                    sh2.note(format!("quic path to {peer2}: {k}"));
                }
                // Размер датаграммы растёт по мере обнаружения MTU пути; пока он мал, крупные пакеты туннеля теряются.
                let m = c2.max_datagram_size();
                if m != last_mds {
                    last_mds = m;
                    sh2.note(format!("quic max_datagram_size={m:?} after {} ms", t_start.elapsed().as_millis()));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        if carrier().0 {
            n += 1;
            attach_datagrams_until_closed(node.clone(), sh.clone(), format!("iroh-dg-out-{peer}-{n}"), conn.clone()).await;
            watcher.abort();
            sh.note(format!("quic to {peer} ended; redialing"));
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }
        match conn.open_bi().await {
            Ok((mut send, recv)) => {
                if send.write_all(&[HDLC_FLAG]).await.is_ok() {
                    n += 1;
                    attach_until_closed(node.clone(), sh.clone(), format!("iroh-out-{peer}-{n}"), conn.clone(), send, recv).await;
                }
            }
            Err(e) => sh.note(format!("open_bi to {peer} failed: {e}")),
        }
        watcher.abort();
        sh.note(format!("quic to {peer} ended; redialing"));
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn event_loop(node: Arc<Node>, mut events: leviculum_std::driver::EventReceiver, sh: Arc<Shared>, auto_accept: bool) {
    while let Some(ev) = events.recv().await {
        match ev {
            NodeEvent::LinkEstablished { link_id, is_initiator, .. } => {
                let k = hex(link_id.as_bytes());
                sh.established.lock().unwrap().insert(k.clone());
                sh.note(format!("link established {} initiator={is_initiator}", &k[..8]));
                if auto_accept && !is_initiator {
                    let _ = node.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);
                }
            }
            NodeEvent::LinkClosed { link_id, reason, .. } => {
                let k = hex(link_id.as_bytes());
                sh.closed.lock().unwrap().insert(k.clone(), format!("{reason:?}"));
                sh.note(format!("link closed {} reason={reason:?}", &k[..8]));
            }
            NodeEvent::MessageReceived { link_id, data, .. } => {
                if data.len() == 16 && &data[..8] == b"KNOTECHO" {
                    if auto_accept {
                        let handle = node.engine().link_handle(&link_id);
                        tokio::spawn(async move { let _ = handle.send(&data).await; });
                    } else {
                        let seq = u64::from_le_bytes(data[8..].try_into().unwrap());
                        if let Some(tx) = sh.echo_pending.lock().unwrap().remove(&seq) {
                            let _ = tx.send(());
                        }
                    }
                } else {
                    sh.stream_rx(&data);
                }
            }
            NodeEvent::LinkDataReceived { link_id, data, .. } => {
                if meas::is_meas(&data) {
                    meas::on_packet(&node, &sh, link_id, &data);
                } else if let Some(t) = sh.tun.get() {
                    t.on_link_packet(&node, link_id, &data);
                } else if data.len() >= DGRAM_HDR && &data[..8] == DGRAM_MAGIC {
                    sh.dgram.lock().unwrap().push(&data);
                } else {
                    sh.stream_rx(&data);
                }
            }
            NodeEvent::ResourceCompleted { data, is_sender, .. } if !is_sender => {
                let mut h = Sha256::new();
                h.update(&data);
                sh.received.lock().unwrap().push((now_ms(), data.len(), hex(&h.finalize())));
            }
            NodeEvent::ResourceFailed { is_sender, error, .. } => {
                *sh.failed_resources.lock().unwrap() += 1;
                sh.note(format!("resource failed sender={is_sender}: {error:?}"));
            }
            NodeEvent::PathFound { destination_hash, hops, interface_index } => {
                sh.note(format!("path found {} hops={hops} iface={interface_index}", hex(&destination_hash.as_bytes()[..4])));
            }
            NodeEvent::PathLost { .. } => sh.note("path lost"),
            NodeEvent::PathRequestReceived { destination_hash } => sh.note(format!("path request received for {}", hex(&destination_hash.as_bytes()[..4]))),
            _ => {}
        }
    }
}

/// Лабораторный обход enforce для роли `e` с `--mode tun` (`KNOTHOP_LAB_EXIT_NO_ENFORCE=1`) есть только в отладочной сборке
/// либо в сборке с явным feature `lab-exit-no-enforce` (стенды замеров запускают release-бинарник `rns-iroh-node`).
/// Штатные release-сборки (knothopd, APK) его не содержат: ни проверки переменной, ни её имени.
///
/// Выход tun без enforce принимает пакеты с любого Link (нет закрепления адреса): только лаборатория, по явной переменной.
/// `env` - значение переменной обхода; в сборке без обхода игнорируется, роль `e` с tun отклоняется всегда.
#[cfg(any(debug_assertions, feature = "lab-exit-no-enforce"))]
fn exit_no_enforce_gate(role: &str, mode: &str, env: Option<&str>) -> std::result::Result<(), &'static str> {
    if role == "e" && mode == "tun" && env != Some("1") {
        return Err("роль e с --mode tun без enforce принимает трафик с любого Link; для лаборатории задайте KNOTHOP_LAB_EXIT_NO_ENFORCE=1 (VPN - knothopd, run_vpn)");
    }
    Ok(())
}
#[cfg(not(any(debug_assertions, feature = "lab-exit-no-enforce")))]
fn exit_no_enforce_gate(role: &str, mode: &str, _env: Option<&str>) -> std::result::Result<(), &'static str> {
    if role == "e" && mode == "tun" {
        return Err("роль e с --mode tun в этой сборке недоступна (VPN - knothopd, run_vpn)");
    }
    Ok(())
}

pub async fn run(cli: Cli) -> Result<()> {
    #[cfg(any(debug_assertions, feature = "lab-exit-no-enforce"))]
    let no_enforce_env = std::env::var("KNOTHOP_LAB_EXIT_NO_ENFORCE").ok();
    #[cfg(not(any(debug_assertions, feature = "lab-exit-no-enforce")))]
    let no_enforce_env: Option<String> = None;
    if let Err(why) = exit_no_enforce_gate(&cli.role, &cli.mode, no_enforce_env.as_deref()) {
        bail!(why);
    }
    // Диагностика: разрешить `eu-stack -p` / gdb от любого процесса того же пользователя
    // (yama ptrace_scope=1 иначе пускает только предков). Только при KNOTHOP_PTRACE_ANY=1.
    if std::env::var("KNOTHOP_PTRACE_ANY").as_deref() == Ok("1") {
        unsafe { libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY as libc::c_ulong, 0, 0, 0) };
    }
    std::fs::create_dir_all(&cli.state).context("create state dir")?;
    let _ = LOG_PATH.set(cli.state.join("log.txt"));
    let _ = TUNING.set((cli.hw_mtu, cli.chan_buf, cli.read_buf));
    let _ = CARRIER.set((cli.carrier == "datagram", cli.dgram_mtu));
    let _ = QUIC_CC.set((cli.quic_cc.clone(), cli.quic_cc_mbit));
    let _ = QUIC_EXTRA.set((cli.quic_initial_mtu, cli.quic_stream_window, cli.quic_conn_window, cli.quic_dg_send_buf, cli.quic_dg_recv_buf));
    leviculum_std::interfaces::set_packet_burst(cli.burst);
    let sh = Arc::new(Shared::new());
    sh.note(format!("run: role={} mode={}", cli.role, cli.mode));
    if cli.verify_sha {
        *sh.stream_hash.lock().unwrap() = Some(Sha256::new());
    }
    let is_exit = cli.role == "e";
    let is_transport = cli.role == "a" || cli.role == "b" || cli.transport;

    // --- leviculum node
    let identity: Identity = leviculum_std::api::generate_identity();
    // На Android нет /tmp: хранилище узла рядом с каталогом состояния.
    // (на телефоне /tmp бывает, но недоступен для записи, поэтому всегда в каталог состояния)
    let store = cli.state.join(format!("lev-{}", cli.role));
    let _ = std::fs::remove_dir_all(&store);
    std::fs::create_dir_all(&store)?;
    let mut nb = NodeBuilder::new().storage_path(store).enable_transport(is_transport);
    if cli.link_keepalive_s > 0 {
        nb = nb.link_keepalive(cli.link_keepalive_s);
    }
    let binding_policy = parse_cli_proof_binding_policy(&cli.proof_binding)?;
    nb = nb.proof_binding_policy(binding_policy);
    if cli.data_cap > 0 {
        nb = nb.data_channel_capacity(cli.data_cap);
    }
    nb = nb.link_cipher(match cli.cipher.as_str() {
        "gcm" => leviculum_std::api::LinkCipher::Gcm,
        _ => leviculum_std::api::LinkCipher::Cbc,
    });
    eprintln!("[{}] proof binding policy: {:?}", now_ms(), binding_policy);
    let mut node = nb.build().context("build node")?;
    sh.note("node built");
    node.start().await.context("start node")?;
    let events = node.take_event_receiver().context("event receiver")?;
    let node = Arc::new(node);

    // --- iroh endpoint
    let mut eb = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(relay_mode(&cli.relay).context("relay mode")?);
    if cli.role != "c" {
        eb = eb.bind_addr(SocketAddr::from(([0, 0, 0, 0], cli.port)))?;
    }
    if let Some(tc) = transport(cli.path_idle_ms, cli.path_keepalive_ms, cli.conn_idle_ms) {
        eb = eb.transport_config(tc);
    }
    sh.note("binding the iroh endpoint");
    let ep = eb.bind().await.context("bind iroh endpoint")?;
    sh.note("iroh endpoint bound");
    if cli.relay != "none" {
        tokio::time::timeout(Duration::from_secs(20), ep.online()).await.context("relay not reachable")?;
    }
    // Смена сети на телефоне (Wi-Fi <-> мобильная): оболочка кладёт файл `netchange`, сокеты QUIC пересоздаются.
    if cli.mode == "tun" && cli.role == "c" {
        let (ep2, f) = (ep.clone(), cli.state.join("netchange"));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if f.exists() {
                    let _ = std::fs::remove_file(&f);
                    ep2.network_change().await;
                }
            }
        });
    }
    if cli.nc_ms > 0 {
        let ep2 = ep.clone();
        let ms = cli.nc_ms;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                ep2.network_change().await;
            }
        });
    }

    // --- E: destination
    let mut info = PeerInfo {
        id: ep.id().to_string(),
        direct: format!("{}:{}", cli.ip, cli.port),
        relay: if cli.relay == "none" { None } else { Some(cli.relay.clone()) },
        dest_hash: None,
        signing_key: None,
    };
    let mut dest_hash_opt: Option<DestinationHash> = None;
    if is_exit {
        let sk = identity.ed25519_verifying().to_bytes();
        let dest = Destination::new(Some(identity), Direction::In, DestinationType::Single, "knothopbench", &["node"])
            .map_err(|e| anyhow::anyhow!("destination: {e:?}"))?;
        let h = *dest.hash();
        node.register_destination(dest);
        info.dest_hash = Some(hex(h.as_bytes()));
        info.signing_key = Some(hex(&sk));
        dest_hash_opt = Some(h);
    }
    std::fs::write(cli.state.join(format!("{}.json", cli.role)), serde_json::to_vec(&info)?)?;
    sh.note(format!("role={} iroh id={} ready", cli.role, info.id));

    tokio::spawn(event_loop(node.clone(), events, sh.clone(), is_exit));
    tokio::spawn(accept_loop(ep.clone(), node.clone(), sh.clone()));
    for peer in cli.dial.split(',').filter(|s| !s.is_empty()) {
        tokio::spawn(dial_loop(ep.clone(), node.clone(), sh.clone(), cli.state.clone(), peer.to_string(), cli.relay.clone(), cli.relay_only));
    }

    if cli.mode == "tun" && cli.role == "e" {
        let tun = TunState::open(&cli, true)?;
        let _ = sh.tun.set(tun.clone());
        tokio::spawn(tun_reader(tun, node.clone(), sh.clone()));
        sh.note(format!("tun {} up on the exit, mtu {}", cli.tun_name, cli.tun_mtu));
    }
    match cli.role.as_str() {
        "e" => {
            let h = dest_hash_opt.unwrap();
            let fin = cli.state.join("fin");
            let mut last_ann = Instant::now() - Duration::from_secs(10);
            let t_start = Instant::now();
            while !fin.exists() {
                let every = if t_start.elapsed() < Duration::from_secs(cli.announce_warmup_s) { 3 } else { cli.announce_s };
                if last_ann.elapsed() >= Duration::from_secs(every) {
                    let _ = node.announce(&h, Some(b"e")).await;
                    last_ann = Instant::now();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let rec = sh.received.lock().unwrap().clone();
            let sr = sh.stream.lock().unwrap();
            let stream_sha = sh.stream_hash.lock().unwrap().as_ref().map(|h| hex(&h.clone().finalize()));
            let stream = serde_json::json!({"bytes": sr.bytes, "first_ms": sr.first_ms as u64, "last_ms": sr.last_ms as u64,
                "mismatch_at": sr.mismatch_at, "msgs": sr.msgs, "max_msg": sr.max_msg, "sha256": stream_sha});
            drop(sr);
            let out = serde_json::json!({
                "stream": stream,
                "dgram": sh.dgram.lock().unwrap().to_json(),
                "tun": sh.tun.get().map(|t| t.stats()),
                "quic_stats": sh.quic_stats.lock().unwrap().clone(),
                "pc_drops": pc_drops_json(),
                "vm_hwm_kb": proc_mem_kb().0,
                "data_events_dropped": leviculum_std::data_events_dropped(),
                "resources": rec.iter().map(|(t, n, d)| serde_json::json!({"t_ms": *t as u64, "bytes": n, "sha256": d})).collect::<Vec<_>>(),
                "log": sh.log.lock().unwrap().iter().map(|(t, m)| serde_json::json!({"t_ms": *t as u64, "msg": m})).collect::<Vec<_>>(),
            });
            std::fs::write(cli.state.join("result-e.json"), serde_json::to_vec(&out)?)?;
        }
        "a" | "b" => {
            let fin = cli.state.join("fin");
            let mut last_dbg = Instant::now();
            while !fin.exists() {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if cli.relay_debug && last_dbg.elapsed() >= Duration::from_secs(3) {
                    last_dbg = Instant::now();
                    let st = node.engine().transport_stats();
                    sh.note(format!("dbg {:?} ifaces={:?}", st, node.engine().interface_stats()));
                }
            }
            std::fs::write(
                cli.state.join(format!("result-{}.json", cli.role)),
                serde_json::to_vec(&serde_json::json!({"log": sh.log.lock().unwrap().iter().map(|(t, m)| serde_json::json!({"t_ms": *t as u64, "msg": m})).collect::<Vec<_>>()}))?,
            )?;
        }
        "c" => client(&cli, node.clone(), sh.clone()).await?,
        r => bail!("unknown role {r}"),
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    ep.close().await;
    Ok(())
}

async fn open_link(cli: &Cli, node: &Arc<Node>, sh: &Arc<Shared>, dest: &DestinationHash, key: &[u8; 32]) -> Result<LinkId> {
    open_link_t(cli, node, sh, dest, key, Duration::from_secs(20)).await
}

async fn open_link_t(cli: &Cli, node: &Arc<Node>, sh: &Arc<Shared>, dest: &DestinationHash, key: &[u8; 32], est: Duration) -> Result<LinkId> {
    let t0 = Instant::now();
    if !node.wait_for_path(dest, Duration::from_secs(40), Duration::from_secs(1)).await? {
        bail!("no path to E");
    }
    let hops = node.hops_to(dest);
    sh.note(format!("path to E known, hops={hops:?} after {} ms", t0.elapsed().as_millis()));
    let handle = node.connect_with_key(dest, key).await?;
    let id = *handle.link_id();
    let k = hex(id.as_bytes());
    let t1 = Instant::now();
    loop {
        if sh.established.lock().unwrap().contains(&k) {
            break;
        }
        if sh.closed.lock().unwrap().contains_key(&k) {
            bail!("link closed before established");
        }
        if t1.elapsed() > est {
            let _ = node.engine().close_link(&id).await;
            bail!("link establishment timeout");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    sh.note(format!("link {} up in {} ms, hops={:?}", &k[..8], t1.elapsed().as_millis(), node.hops_to(dest)));
    let _ = cli;
    Ok(id)
}

async fn client(cli: &Cli, node: Arc<Node>, sh: Arc<Shared>) -> Result<()> {
    wait_file(&cli.state.join("e.json"), 60).await?;
    let e: PeerInfo = serde_json::from_slice(&std::fs::read(cli.state.join("e.json"))?)?;
    let dest = DestinationHash::new(unhex(e.dest_hash.as_deref().unwrap()).try_into().map_err(|_| anyhow::anyhow!("hash"))?);
    let key: [u8; 32] = unhex(e.signing_key.as_deref().unwrap()).try_into().map_err(|_| anyhow::anyhow!("key"))?;

    if cli.mode == "meas" {
        return meas::client_meas(cli, node, sh, &dest, &key).await;
    }
    if cli.mode == "tun" {
        return client_tun(cli, node, sh, &dest, &key).await;
    }
    if cli.mode == "dgram" {
        return client_dgram(cli, node, sh, &dest, &key).await;
    }
    if cli.mode == "stream" {
        return client_stream(cli, node, sh, &dest, &key).await;
    }
    let mut link = open_link(cli, &node, &sh, &dest, &key).await?;
    // прогрев: небольшая передача, чтобы стратегия приёма на E уже была выставлена
    let mut buf = vec![0u8; cli.bytes];
    rand_core::OsRng.fill_bytes(&mut buf);
    for _ in 0..3 {
        let (_, fut) = node.engine().send_resource_awaited(&link, &buf[..4096], None, false).await?;
        let _ = tokio::time::timeout(Duration::from_secs(10), fut).await;
    }
    sh.received.lock().unwrap().clear();
    std::fs::File::create(cli.state.join("ready"))?;
    wait_file(&cli.state.join("go"), 120).await?;
    sh.note("go");
    let t_go = Instant::now();
    let mut timeline = Vec::new();
    let mut expected: Vec<(usize, String)> = Vec::new();
    let mut relinks: Vec<serde_json::Value> = Vec::new();
    let mut seq: u64 = 0;
    let mut fail_since: Option<Instant> = None;
    let mut fail_unix: u128 = 0;
    while t_go.elapsed().as_secs() < cli.duration {
        seq += 1;
        buf[..8].copy_from_slice(&seq.to_le_bytes());
        let mut h = Sha256::new();
        h.update(&buf);
        let digest = hex(&h.finalize());
        let t_start = now_ms();
        let hops = node.hops_to(&dest);
        let mut detach_rx = sh.detach.subscribe();
        let base_detach = *detach_rx.borrow();
        let controller = cli.controller;
        let detached = async move {
            if !controller {
                std::future::pending::<()>().await;
            }
            loop {
                if detach_rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
                if *detach_rx.borrow() != base_detach {
                    break;
                }
            }
        };
        let res = match node.engine().send_resource_awaited(&link, &buf, None, false).await {
            Ok((_, fut)) => tokio::select! {
                r = tokio::time::timeout(Duration::from_secs(cli.resource_timeout), fut) => match r {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(e)) => Err(format!("{e:?}")),
                    Err(_) => Err("timeout".to_string()),
                },
                _ = detached => Err("interface detached".to_string()),
            },
            Err(e) => Err(format!("send: {e:?}")),
        };
        let ok = res.is_ok();
        let closed = sh.closed.lock().unwrap().get(&hex(link.as_bytes())).cloned();
        timeline.push(serde_json::json!({"t_start_ms": t_start as u64, "t_end_ms": now_ms() as u64, "ok": ok, "hops": hops,
            "error": res.as_ref().err(), "link_closed": closed}));
        if ok {
            expected.push((buf.len(), digest));
            if let Some(f) = fail_since.take() {
                sh.note(format!("transfers recovered after {} ms (same link)", f.elapsed().as_millis()));
                relinks.push(serde_json::json!({"kind": "same_link_recovered", "failed_at_ms": fail_unix as u64, "recovered_after_ms": f.elapsed().as_millis() as u64}));
            }
            continue;
        }
        if fail_since.is_none() {
            fail_since = Some(Instant::now());
            fail_unix = now_ms();
        }
        // Link закрыт или Resource не дошёл: переподнять Link (с контроллером - сначала сбросить путь).
        let dead = sh.closed.lock().unwrap().contains_key(&hex(link.as_bytes()));
        if dead || cli.controller {
            if cli.controller {
                // Link остаётся «живым» для RNS до Stale (~15 с), поэтому закрываем его сами и поднимаем новый по лучшему из оставшихся путей.
                let _ = node.engine().close_link(&link).await;
                sh.note("controller: closed old link, opening a new one");
            }
            match open_link(cli, &node, &sh, &dest, &key).await {
                Ok(id) => {
                    link = id;
                    if let Some(f) = fail_since.take() {
                        relinks.push(serde_json::json!({"kind": "new_link", "failed_at_ms": fail_unix as u64, "recovered_after_ms": f.elapsed().as_millis() as u64}));
                    }
                }
                Err(e) => {
                    sh.note(format!("relink failed: {e}"));
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        } else {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let secs = t_go.elapsed().as_secs_f64();
    // дать E дописать приём
    tokio::time::sleep(Duration::from_secs(2)).await;
    let ok_n = timeline.iter().filter(|t| t["ok"] == true).count();
    let out = serde_json::json!({
        "seconds": secs, "resource_bytes": cli.bytes, "resources_ok": ok_n, "resources_total": timeline.len(),
        "bytes_ok": ok_n * cli.bytes, "relinks": relinks, "timeline": timeline,
        "expected": expected.iter().map(|(n, d)| serde_json::json!({"bytes": n, "sha256": d})).collect::<Vec<_>>(),
        "controller": cli.controller,
        "log": sh.log.lock().unwrap().iter().map(|(t, m)| serde_json::json!({"t_ms": *t as u64, "msg": m})).collect::<Vec<_>>(),
    });
    std::fs::write(cli.state.join("result-c.json"), serde_json::to_vec(&out)?)?;
    Ok(())
}

/// Режим stream: непрерывная запись `LinkHandle::send` порциями `--chunk` байт, как это делает проксирование TCP-потока.
async fn client_stream(cli: &Cli, node: Arc<Node>, sh: Arc<Shared>, dest: &DestinationHash, key: &[u8; 32]) -> Result<()> {
    if !node.wait_for_path(dest, Duration::from_secs(40), Duration::from_secs(1)).await? {
        bail!("no path to E");
    }
    let handle = node.connect_with_key(dest, key).await?;
    let k = hex(handle.link_id().as_bytes());
    let t1 = Instant::now();
    while !sh.established.lock().unwrap().contains(&k) {
        if t1.elapsed() > Duration::from_secs(20) { bail!("link establishment timeout"); }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mdu = node.engine().link_mdu(handle.link_id());
    if cli.send_window > 0 { handle.set_send_window_limit(cli.send_window)?; }
    if cli.window_only { handle.set_send_pacing_enabled(false)?; }
    sh.note(format!("stream link {} up, link mdu={mdu:?}, chunk={}", &k[..8], cli.chunk));
    if cli.chunk == 0 { bail!("--chunk must be positive"); }
    let (echo_ready_tx, echo_ready_rx) = tokio::sync::oneshot::channel();
    let echo_task = if cli.echo {
        let echo_handle = node.connect_with_key(dest, key).await?;
        let sh = sh.clone();
        let echo_go = cli.state.join("go");
        let idle_secs = cli.idle_secs;
        Some(tokio::spawn(async move {
            let id = hex(echo_handle.link_id().as_bytes());
            while !sh.established.lock().unwrap().contains(&id) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let mut seq = 0u64;
            let mut warmup = Some(echo_ready_tx);
            loop {
                let (tx, rx) = tokio::sync::oneshot::channel();
                sh.echo_pending.lock().unwrap().insert(seq, tx);
                let mut data = [0u8; 16];
                data[..8].copy_from_slice(b"KNOTECHO");
                data[8..].copy_from_slice(&seq.to_le_bytes());
                let start = Instant::now();
                let result = tokio::time::timeout(Duration::from_secs(2), async {
                    echo_handle.send(&data).await?;
                    rx.await.map_err(|_| anyhow::anyhow!("echo channel closed"))?;
                    Ok::<_, anyhow::Error>(())
                }).await;
                if matches!(result, Ok(Ok(()))) {
                    if let Some(tx) = warmup.take() {
                        sh.echo_pending.lock().unwrap().remove(&seq);
                        seq += 1;
                        // RTT ненагруженного пути: до ready, вне окна замера CPU стенда.
                        let idle_until = Instant::now() + Duration::from_secs(idle_secs);
                        while Instant::now() < idle_until {
                            let (itx, irx) = tokio::sync::oneshot::channel();
                            sh.echo_pending.lock().unwrap().insert(seq, itx);
                            let mut d = [0u8; 16];
                            d[..8].copy_from_slice(b"KNOTECHO");
                            d[8..].copy_from_slice(&seq.to_le_bytes());
                            let t = Instant::now();
                            let ok = tokio::time::timeout(Duration::from_secs(2), async {
                                echo_handle.send(&d).await?;
                                irx.await.map_err(|_| anyhow::anyhow!("echo channel closed"))?;
                                Ok::<_, anyhow::Error>(())
                            }).await;
                            if matches!(ok, Ok(Ok(()))) {
                                sh.echo_idle_rtt_ms.lock().unwrap().push(t.elapsed().as_secs_f64() * 1000.0);
                            }
                            sh.echo_pending.lock().unwrap().remove(&seq);
                            seq += 1;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        let _ = tx.send(());
                        if wait_file(&echo_go, 120).await.is_err() { return; }
                        continue;
                    }
                    sh.echo_rtt_ms.lock().unwrap().push(start.elapsed().as_secs_f64() * 1000.0);
                } else {
                    if warmup.is_none() { *sh.echo_timeouts.lock().unwrap() += 1; }
                }
                sh.echo_pending.lock().unwrap().remove(&seq);
                seq += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }))
    } else { None };
    if cli.echo {
        tokio::time::timeout(Duration::from_secs(20), echo_ready_rx).await??;
    }
    std::fs::File::create(cli.state.join("ready"))?;
    wait_file(&cli.state.join("go"), 120).await?;
    sh.note("go");
    let mut buf = vec![0u8; cli.chunk];
    let mut off: u64 = 0;
    let target = cli.stream_bytes;
    let t0 = Instant::now();
    let mut send_err: Option<String> = None;
    let mut stalls = 0u64;
    let mut max_send_ms = 0u128;
    let mut hasher = Sha256::new();
    let mut t_mark = t0;
    let mut marks: Vec<serde_json::Value> = Vec::new();
    while t0.elapsed().as_secs() < cli.duration && (target == 0 || off < target) {
        let len = if target == 0 { buf.len() } else { (target - off).min(buf.len() as u64) as usize };
        let part = &mut buf[..len];
        pattern_fill(part, off);
        let ts = Instant::now();
        match handle.send(part).await {
            Ok(()) => {}
            Err(e) => { send_err = Some(format!("{e:?}")); break; }
        }
        if cli.verify_sha { hasher.update(&*part); }
        off += len as u64;
        let d = ts.elapsed().as_millis();
        if d > 50 { stalls += 1; }
        max_send_ms = max_send_ms.max(d);
        // раз в ~64 МиБ: скорость на разных участках прогона
        if off - marks.len() as u64 * (64 << 20) >= 64 << 20 {
            let now = t0.elapsed().as_secs_f64();
            let prev = marks.last().and_then(|m| m["bytes"].as_u64()).unwrap_or(0);
            marks.push(serde_json::json!({"bytes": off, "t_s": (now * 100.0).round() / 100.0,
                "mib_s": ((off - prev) as f64 / 1048576.0 / (now - marks.last().map(|m| m["t_s"].as_f64().unwrap_or(0.0)).unwrap_or(0.0).max(0.001))).round() * 100.0 / 100.0}));
            t_mark = t0;
        }
    }
    let _ = t_mark;
    let secs = t0.elapsed().as_secs_f64();
    if let Some(task) = echo_task {
        task.abort();
        let _ = task.await;
        sh.echo_pending.lock().unwrap().clear();
    }
    tokio::time::sleep(Duration::from_secs(3)).await; // дать E дочитать
    let out = serde_json::json!({
        "mode": "stream", "seconds": secs, "chunk": cli.chunk, "bytes_sent": off, "send_error": send_err,
        "cipher": cli.cipher, "send_window": cli.send_window,
        "window_only": cli.window_only,
        "sends_over_50ms": stalls, "max_send_ms": max_send_ms as u64, "link_mdu": mdu,
        "sha256": if cli.verify_sha { Some(hex(&Sha256::finalize(hasher))) } else { None }, "marks": marks,
        "echo_rtt_ms": *sh.echo_rtt_ms.lock().unwrap(),
        "echo_idle_rtt_ms": *sh.echo_idle_rtt_ms.lock().unwrap(),
        "vm_hwm_kb": proc_mem_kb().0, "vm_rss_kb": proc_mem_kb().1,
        "echo_timeouts": *sh.echo_timeouts.lock().unwrap(),
        "log": sh.log.lock().unwrap().iter().map(|(t, m)| serde_json::json!({"t_ms": *t as u64, "msg": m})).collect::<Vec<_>>(),
    });
    std::fs::write(cli.state.join("result-c.json"), serde_json::to_vec(&out)?)?;
    Ok(())
}

/// Режим dgram: непрерывная отправка IP-подобных пакетов по Link без Channel (`send_datagram`):
/// без окна, порядка, повторов и подтверждений. Пакет = [магия 8][seq 8][время отправки мкс 8][шаблон].
async fn client_dgram(cli: &Cli, node: Arc<Node>, sh: Arc<Shared>, dest: &DestinationHash, key: &[u8; 32]) -> Result<()> {
    if !node.wait_for_path(dest, Duration::from_secs(40), Duration::from_secs(1)).await? {
        bail!("no path to E");
    }
    let handle = node.connect_with_key(dest, key).await?;
    let k = hex(handle.link_id().as_bytes());
    let t1 = Instant::now();
    while !sh.established.lock().unwrap().contains(&k) {
        if t1.elapsed() > Duration::from_secs(20) { bail!("link establishment timeout"); }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mdu = node.engine().link_mdu(handle.link_id());
    let size = cli.chunk.max(DGRAM_HDR + 1);
    if let Some(m) = mdu { if size > m { bail!("--chunk {size} exceeds link mdu {m}"); } }
    sh.note(format!("dgram link {} up, link mdu={mdu:?}, packet={size}, pps={}", &k[..8], cli.pps));
    std::fs::File::create(cli.state.join("ready"))?;
    wait_file(&cli.state.join("go"), 120).await?;
    sh.note("go");

    let mut buf = vec![0u8; size];
    buf[..8].copy_from_slice(DGRAM_MAGIC);
    pattern_fill(&mut buf[DGRAM_HDR..], 0);
    let (mut sent, mut errors) = (0u64, 0u64);
    let t0 = Instant::now();
    let duration = Duration::from_secs(cli.duration);
    // Open loop: at a target rate send `pps/1000` packets per millisecond slot and catch up if late.
    let per_slot = if cli.pps > 0 { (cli.pps as f64 / 1000.0).max(1.0) } else { 0.0 };
    let mut owed = 0.0f64;
    let mut next_slot = Instant::now();
    while t0.elapsed() < duration {
        let burst = if cli.pps > 0 {
            owed += per_slot;
            let n = owed.floor() as u64;
            owed -= n as f64;
            n.max(1).min(4096)
        } else { 64 };
        for _ in 0..burst {
            buf[8..16].copy_from_slice(&sent.to_le_bytes());
            buf[16..24].copy_from_slice(&now_us().to_le_bytes());
            match handle.send_datagram(&buf).await {
                Ok(()) => sent += 1,
                Err(e) => { errors += 1; if errors == 1 { sh.note(format!("send_datagram error: {e:?}")); } if errors > 1000 { bail!("too many send errors"); } }
            }
        }
        if cli.pps > 0 {
            next_slot += Duration::from_millis(1);
            let now = Instant::now();
            if next_slot > now { tokio::time::sleep(next_slot - now).await; }
        } else {
            tokio::task::yield_now().await;
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    tokio::time::sleep(Duration::from_secs(3)).await; // дать приёмнику дочитать очередь
    let (hwm_kb, rss_kb) = proc_mem_kb();
    let out = serde_json::json!({
        "mode": "dgram", "seconds": secs, "packet": size, "pps_target": cli.pps, "sent": sent, "send_errors": errors,
        "link_mdu": mdu, "cipher": cli.cipher, "vm_hwm_kb": hwm_kb, "vm_rss_kb": rss_kb,
        "log": sh.log.lock().unwrap().iter().map(|(t, m)| serde_json::json!({"t_ms": *t as u64, "msg": m})).collect::<Vec<_>>(),
    });
    std::fs::write(cli.state.join("result-c.json"), serde_json::to_vec(&out)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Режим tun: IPv4-туннель. TUN <-> пакеты по Link (send_datagram), без Channel, без подтверждений.
// ---------------------------------------------------------------------------------------------

/// Файловый дескриптор TUN, пригодный для tokio::AsyncFd.
struct TunFd(std::os::fd::OwnedFd);
impl std::os::fd::AsRawFd for TunFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}
use std::os::fd::AsRawFd;

fn open_tun(name: &str) -> Result<TunFd> {
    use std::os::fd::{FromRawFd, OwnedFd};
    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    let nb = name.as_bytes();
    if nb.is_empty() || nb.len() >= 16 {
        bail!("bad tun name {name:?}");
    }
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        bail!("open /dev/net/tun: {}", std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut ifr = [0u8; 40];
    ifr[..nb.len()].copy_from_slice(nb);
    ifr[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    if unsafe { libc::ioctl(fd, TUNSETIFF as _, ifr.as_mut_ptr()) } < 0 {
        bail!("TUNSETIFF {name}: {}", std::io::Error::last_os_error());
    }
    Ok(TunFd(owned))
}

fn ip_cmd(args: &[&str]) -> Result<()> {
    let st = std::process::Command::new("ip").args(args).status().context("run ip")?;
    if !st.success() {
        bail!("ip {args:?} failed: {st}");
    }
    Ok(())
}

#[derive(Default)]
struct TunCounters {
    from_tun_pkts: std::sync::atomic::AtomicU64,
    from_tun_bytes: std::sync::atomic::AtomicU64,
    to_tun_pkts: std::sync::atomic::AtomicU64,
    to_tun_bytes: std::sync::atomic::AtomicU64,
    tun_write_drops: std::sync::atomic::AtomicU64,
    route_miss: std::sync::atomic::AtomicU64,
    send_errors: std::sync::atomic::AtomicU64,
    not_ipv4: std::sync::atomic::AtomicU64,
    probes: std::sync::atomic::AtomicU64,
    unauth_drops: std::sync::atomic::AtomicU64,
}

pub struct TunState {
    /// Устройство TUN. На Android клиент может работать без него (режим «в сети без VPN»); устройство подключается и снимается на лету
    /// (`set_device`), читатель следит за `dev_gen`.
    dev: std::sync::RwLock<Option<Arc<tokio::io::unix::AsyncFd<TunFd>>>>,
    dev_gen: tokio::sync::watch::Sender<u64>,
    is_exit: bool,
    /// клиент: текущий Link к выходу (None, пока идёт смена маршрута)
    client_link: std::sync::RwLock<Option<Arc<leviculum_std::LinkHandle>>>,
    /// клиент: время (мс unix) последнего пакета с Link и последней отправки в Link
    last_rx_ms: std::sync::atomic::AtomicU64,
    last_tx_ms: std::sync::atomic::AtomicU64,
    /// клиент: время первой отправки, на которую с тех пор не пришло ничего (0 - всё отвечено). Молчание считаем от неё, а не от
    /// последнего приёма: после простоя туннеля первый же пакет не должен выглядеть как «тишина с прошлого приёма».
    unanswered_since_ms: std::sync::atomic::AtomicU64,
    /// клиент: журнал смен маршрута
    failovers: std::sync::Mutex<Vec<serde_json::Value>>,
    /// выход: IPv4-адрес клиента (из src его пакетов) -> (Link, ручка)
    routes: std::sync::RwLock<HashMap<u32, (leviculum_std::api::LinkId, Arc<leviculum_std::LinkHandle>)>>,
    /// выход в режиме VPN: пакеты принимаются только по Link из этой таблицы и только с закреплённого за Link адреса источника
    enforce: std::sync::atomic::AtomicBool,
    allowed: std::sync::RwLock<HashMap<leviculum_std::api::LinkId, u32>>,
    host_access: std::sync::RwLock<HashSet<leviculum_std::api::LinkId>>,
    host_inventory: Arc<std::sync::RwLock<Option<Arc<host_acl::Inventory>>>>,
    host_acl_ready: Arc<std::sync::atomic::AtomicBool>,
    host_acl_started: std::sync::atomic::AtomicBool,
    health_echo_last: std::sync::Mutex<HashMap<leviculum_std::api::LinkId, Instant>>,
    c: TunCounters,
    /// клиент: раздельное туннелирование (route.rs); пока правил нет, `routing` = false и пакеты идут в основной Link без проверок
    routing: std::sync::atomic::AtomicBool,
    router: std::sync::RwLock<Arc<route::Router>>,
    /// клиент: дополнительные Link к выходам, на которые правила шлют часть трафика (dest -> Link)
    extra: std::sync::RwLock<HashMap<[u8; 16], ExtraLink>>,
    rt: RouteCounters,
    /// клиент: выход основного Link (для счётчиков)
    main_dest: std::sync::RwLock<[u8; 16]>,
}

/// Дополнительный Link к выходу для раздельного туннелирования.
#[derive(Clone)]
struct ExtraLink {
    id: leviculum_std::api::LinkId,
    handle: Arc<leviculum_std::LinkHandle>,
    /// время (мс unix) последнего пакета с этого Link
    last_rx_ms: Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Default)]
struct RouteCounters {
    /// пакеты, ушедшие по дополнительному Link
    extra_pkts: std::sync::atomic::AtomicU64,
    /// правило велело идти через выход, к которому Link ещё не поднят: пакет ушёл через основной
    fallback_pkts: std::sync::atomic::AtomicU64,
    /// правило велело идти мимо туннеля, но адрес известен только по домену: пакет ушёл через основной
    direct_fallback_pkts: std::sync::atomic::AtomicU64,
    /// отброшенные пакеты на порт 853 (DoT скрывает DNS-ответы от доменных правил)
    dot_dropped: std::sync::atomic::AtomicU64,
}

/// Bounded IPv4 header validation shared by both TUN directions. Fragments are accepted only
/// when each fragment is structurally valid; no transport-header assumptions are made.
fn valid_ipv4_packet(pkt: &[u8]) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 { return false; }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if !(20..=60).contains(&ihl) || ihl > pkt.len() { return false; }
    if pkt[8] == 0 { return false; }
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if total < ihl || total != pkt.len() { return false; }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x8000 != 0 || (frag & 0x4000 != 0 && frag & 0x3fff != 0) { return false; }
    let payload = total - ihl;
    if payload == 0 && (frag & 0x3fff != 0) { return false; }
    if frag & 0x2000 != 0 && payload % 8 != 0 { return false; }
    true
}

/// Верхняя граница числа допущенных клиентов (Link) и обратных маршрутов выхода.
const MAX_ALLOWED_CLIENTS: usize = 256;

/// Итог успешного допуска клиентского Link на выходе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Link и обратный маршрут занесены этим вызовом.
    Admitted,
    /// Тот же Link с тем же адресом уже был допущен: вызов идемпотентен, права HOST_ACCESS не тронуты.
    AlreadyAdmitted,
}

/// Устойчивая причина отказа `TunState::allow`; таблицы при отказе не меняются.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// Выход принудительный, а inventory/конфигурация host ACL не готова (fail-closed).
    AclNotReady,
    /// Достигнут предел допущенных клиентов или обратных маршрутов.
    Capacity,
    /// Адрес уже закреплён за другим Link.
    AddressInUse,
    /// Этот Link уже допущен с другим адресом.
    LinkAddressChanged,
}

impl AdmissionError {
    /// Стабильный короткий код (без адресов) для статуса и причины AUTH_FAIL.
    pub fn code(self) -> &'static str {
        match self {
            AdmissionError::AclNotReady => "host_acl_not_ready",
            AdmissionError::Capacity => "exit_client_capacity",
            AdmissionError::AddressInUse => "address_in_use",
            AdmissionError::LinkAddressChanged => "link_address_changed",
        }
    }
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.code()) }
}

impl std::error::Error for AdmissionError {}

type HostAccessSet = std::sync::RwLock<HashSet<leviculum_std::api::LinkId>>;
type AllowedMap = std::sync::RwLock<HashMap<leviculum_std::api::LinkId, u32>>;
type RouteMap<H> = std::sync::RwLock<HashMap<u32, (leviculum_std::api::LinkId, H)>>;

/// Единый порядок блокировок для всех записей: host_access -> allowed -> routes. Пакетный путь берёт каждую
/// отдельно и не вкладывает, поэтому взаимной блокировки с этим порядком нет.
/// Допуск атомарный (all-or-nothing): все проверки под тремя write-блокировками, до первой вставки.
#[cfg(test)]
fn admit_link<H>(
    host_access: &HostAccessSet, allowed: &AllowedMap, routes: &RouteMap<H>,
    link_id: leviculum_std::api::LinkId, ip: u32, handle: H,
) -> Result<Admission, AdmissionError> {
    admit_link_replacing(host_access, allowed, routes, link_id, ip, handle, &[])
}

/// То же, но владельца адреса можно вытеснить: только если он входит в `replaces` (вызывающий вычислил список как
/// живые Link той же аутентифицированной identity с тем же адресом) и таблица `allowed` подтверждает его адрес.
/// Любой другой владелец - `AddressInUse`. Все проверки идут до первой мутации; вытеснение (права, допуск, маршрут
/// прежнего Link) и вставка нового - в той же критической секции. Права HOST_ACCESS нового Link не наследуются.
fn admit_link_replacing<H>(
    host_access: &HostAccessSet, allowed: &AllowedMap, routes: &RouteMap<H>,
    link_id: leviculum_std::api::LinkId, ip: u32, handle: H, replaces: &[leviculum_std::api::LinkId],
) -> Result<Admission, AdmissionError> {
    let mut permissions = host_access.write().unwrap();
    let mut allowed = allowed.write().unwrap();
    let mut routes = routes.write().unwrap();
    if let Some(bound) = allowed.get(&link_id).copied() {
        if bound != ip { return Err(AdmissionError::LinkAddressChanged); }
        return match routes.get(&ip).map(|(owner, _)| *owner) {
            Some(owner) if owner == link_id => Ok(Admission::AlreadyAdmitted),
            Some(_) => Err(AdmissionError::AddressInUse),
            None => {
                // восстановление нарушенного инварианта: допущенный Link без маршрута
                if routes.len() >= MAX_ALLOWED_CLIENTS { return Err(AdmissionError::Capacity); }
                routes.insert(ip, (link_id, handle));
                Ok(Admission::AlreadyAdmitted)
            }
        };
    }
    let evict = match routes.get(&ip).map(|(owner, _)| *owner) {
        Some(owner) if owner != link_id => {
            if replaces.contains(&owner) && allowed.get(&owner) == Some(&ip) { Some(owner) } else { return Err(AdmissionError::AddressInUse); }
        }
        _ => None,
    };
    // вытесняемый Link освобождает по одному месту в allowed и routes
    let freed = usize::from(evict.is_some());
    if allowed.len() - freed >= MAX_ALLOWED_CLIENTS || routes.len() - freed >= MAX_ALLOWED_CLIENTS { return Err(AdmissionError::Capacity); }
    if let Some(owner) = evict {
        permissions.remove(&owner);
        allowed.remove(&owner);
        routes.remove(&ip);
    }
    allowed.insert(link_id, ip);
    routes.insert(ip, (link_id, handle));
    // новый допуск никогда не наследует остаток прав от прежнего состояния этого LinkId
    permissions.remove(&link_id);
    Ok(Admission::Admitted)
}

fn disallow_link<H>(host_access: &HostAccessSet, allowed: &AllowedMap, routes: &RouteMap<H>, link_id: &leviculum_std::api::LinkId) {
    let mut permissions = host_access.write().unwrap();
    let mut allowed = allowed.write().unwrap();
    let mut routes = routes.write().unwrap();
    permissions.remove(link_id);
    if let Some(ip) = allowed.remove(link_id) {
        if routes.get(&ip).is_some_and(|(owner, _)| owner == link_id) {
            routes.remove(&ip);
        }
    }
}

fn set_link_host_access(host_access: &HostAccessSet, allowed: &AllowedMap, link_id: &leviculum_std::api::LinkId, grant: bool) -> bool {
    let mut permissions = host_access.write().unwrap();
    if grant {
        if allowed.read().unwrap().contains_key(link_id) {
            permissions.insert(*link_id);
            return true;
        }
        permissions.remove(link_id);
        return false;
    }
    permissions.remove(link_id);
    true
}

/// Publish the current Trust decision without letting an older evaluator overwrite a revoke.
/// Evaluation uses this critical section; ordinary admission's promote_client_link retains the
/// same Trust guard through role/TUN/host publication. `inspect` is read-only/in-memory;
/// `publish` must only do the small TUN permission update (no I/O, admission, Link close or await).
/// Lock order: Trust -> host_access -> allowed. Neither packet processing nor TUN table writers
/// acquire Trust while holding these locks. In particular, never acquire the host commit gate here.
fn publish_host_access_decision<R>(
    authority: &Mutex<trust::Trust>, pk: &trust::Pk,
    inspect: impl FnOnce(&trust::Trust) -> R, publish: impl FnOnce(bool) -> bool,
) -> (R, bool) {
    let tr = authority.lock().unwrap();
    let granted = !tr.host_access_roots(pk, &tr.me_hash).is_empty();
    let result = inspect(&tr);
    let applied = publish(granted);
    // Keep the authority guard alive through the actual ACL write, not just the decision.
    drop(tr);
    (result, applied)
}

impl TunState {
    /// Load strict local ACL state and take an initial host-interface snapshot.
    /// Enforced traffic remains fail-closed until this succeeds.
    pub fn configure_host_acl(&self, state: &Path) -> Result<()> {
        use std::sync::atomic::Ordering::Release;
        self.host_acl_ready.store(false, Release);
        let snapshot = Arc::new(host_acl::build(state)?);
        *self.host_inventory.write().unwrap() = Some(snapshot);
        self.host_acl_ready.store(true, Release);
        if !self.host_acl_started.swap(true, Release) {
            let state = state.to_path_buf();
            let inventory = self.host_inventory.clone();
            let ready = self.host_acl_ready.clone();
            let refresh = std::thread::Builder::new().name("host-acl-refresh".into()).spawn(move || loop {
                std::thread::sleep(host_acl::refresh_interval());
                match host_acl::build(&state) {
                    Ok(next) => {
                        *inventory.write().unwrap() = Some(Arc::new(next));
                        ready.store(true, Release);
                    }
                    Err(_) => ready.store(false, Release),
                }
            });
            if let Err(error) = refresh {
                self.host_acl_ready.store(false, Release);
                self.host_acl_started.store(false, Release);
                return Err(error).context("start host ACL inventory refresh");
            }
        }
        Ok(())
    }

    /// HOST_ACCESS is opt-in, per admitted Link, and never inferred by allow(). Returns whether the requested state holds:
    /// a grant for a Link that is not admitted is refused (`false`, no permission recorded); a revoke always succeeds.
    pub fn set_host_access(&self, link_id: &leviculum_std::api::LinkId, allowed: bool) -> bool {
        set_link_host_access(&self.host_access, &self.allowed, link_id, allowed)
    }

    pub fn host_acl_ready(&self) -> bool {
        self.host_acl_ready.load(std::sync::atomic::Ordering::Acquire)
    }

    fn allow_health_echo(&self, link_id: leviculum_std::api::LinkId) -> bool {
        let now = Instant::now();
        let mut last = self.health_echo_last.lock().unwrap();
        if last.get(&link_id).is_some_and(|at| now.duration_since(*at) < Duration::from_secs(1)) { return false; }
        if last.len() >= 256 { last.retain(|_, at| now.duration_since(*at) < Duration::from_secs(5)); }
        if last.len() >= 256 && !last.contains_key(&link_id) { return false; }
        last.insert(link_id, now);
        true
    }

    fn build(is_exit: bool, dev: Option<tokio::io::unix::AsyncFd<TunFd>>) -> Arc<Self> {
        Arc::new(TunState {
            dev: std::sync::RwLock::new(dev.map(Arc::new)),
            dev_gen: tokio::sync::watch::channel(0).0,
            is_exit,
            client_link: std::sync::RwLock::new(None),
            last_rx_ms: Default::default(),
            last_tx_ms: Default::default(),
            unanswered_since_ms: Default::default(),
            failovers: std::sync::Mutex::new(Vec::new()),
            routes: std::sync::RwLock::new(HashMap::new()),
            enforce: Default::default(),
            allowed: std::sync::RwLock::new(HashMap::new()),
            host_access: std::sync::RwLock::new(HashSet::new()),
            host_inventory: Arc::new(std::sync::RwLock::new(None)),
            host_acl_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            host_acl_started: Default::default(),
            health_echo_last: std::sync::Mutex::new(HashMap::new()),
            c: TunCounters::default(),
            routing: Default::default(),
            router: std::sync::RwLock::new(Arc::new(route::Router::empty())),
            extra: std::sync::RwLock::new(HashMap::new()),
            rt: RouteCounters::default(),
            main_dest: std::sync::RwLock::new([0; 16]),
        })
    }

    fn open(cli: &Cli, is_exit: bool) -> Result<Arc<Self>> {
        if cli.tun_fd == TUN_DETACHED {
            // Android, режим «в сети без VPN»: устройство подключит `set_device`, пока пакеты некуда класть и неоткуда читать.
            return Ok(Self::build(is_exit, None));
        }
        if cli.tun_fd >= 0 {
            // Дескриптор принадлежит VpnService (Java держит свою копию и закроет её при остановке): берём собственную через dup.
            use std::os::fd::FromRawFd;
            let fd = unsafe { libc::fcntl(cli.tun_fd, libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                bail!("dup tun fd {}: {}", cli.tun_fd, std::io::Error::last_os_error());
            }
            unsafe {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
            let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
            return Ok(Self::build(is_exit, Some(tokio::io::unix::AsyncFd::new(TunFd(owned))?)));
        }
        let fd = open_tun(&cli.tun_name)?;
        ip_cmd(&["addr", "add", &cli.tun_ip, "dev", &cli.tun_name])?;
        ip_cmd(&["link", "set", "dev", &cli.tun_name, "mtu", &cli.tun_mtu.to_string(), "txqueuelen", &cli.tun_txqlen.to_string(), "up"])?;
        if !cli.tun_qdisc.is_empty() {
            // tc: `fq_codel` держит очередь короткой по времени ожидания и не рубит хвост пачки целиком,
            // чем лечит и потери в пачках TCP, и раздутые буферы одной мерой.
            let st = std::process::Command::new("tc")
                .args(["qdisc", "replace", "dev", &cli.tun_name, "root", &cli.tun_qdisc, "limit", &cli.tun_txqlen.to_string()])
                .status()
                .context("run tc")?;
            if !st.success() {
                bail!("tc qdisc {} failed: {st}", cli.tun_qdisc);
            }
        }
        Ok(Self::build(is_exit, Some(tokio::io::unix::AsyncFd::new(fd)?)))
    }

    fn device(&self) -> Option<Arc<tokio::io::unix::AsyncFd<TunFd>>> {
        self.dev.read().unwrap().clone()
    }

    /// Подключить (`Some`) или снять (`None`) устройство TUN на лету. Дескриптор переходит во владение узла: после снятия старое
    /// устройство закрывается, когда его отпустит читатель.
    pub(crate) fn set_device(&self, fd: Option<std::os::fd::OwnedFd>) -> Result<()> {
        let dev = match fd {
            Some(owned) => {
                use std::os::fd::AsRawFd;
                unsafe {
                    let fl = libc::fcntl(owned.as_raw_fd(), libc::F_GETFL);
                    libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
                }
                Some(Arc::new(tokio::io::unix::AsyncFd::new(TunFd(owned))?))
            }
            None => None,
        };
        *self.dev.write().unwrap() = dev;
        self.dev_gen.send_modify(|g| *g = g.wrapping_add(1));
        Ok(())
    }

    fn write_tun(&self, pkt: &[u8]) {
        use std::sync::atomic::Ordering::Relaxed;
        let Some(dev) = self.device() else {
            self.c.tun_write_drops.fetch_add(1, Relaxed);
            return;
        };
        let n = unsafe { libc::write(dev.get_ref().as_raw_fd(), pkt.as_ptr() as *const _, pkt.len()) };
        if n == pkt.len() as isize {
            self.c.to_tun_pkts.fetch_add(1, Relaxed);
            self.c.to_tun_bytes.fetch_add(pkt.len() as u64, Relaxed);
        } else {
            self.c.tun_write_drops.fetch_add(1, Relaxed);
        }
    }

    /// Пакет, пришедший по Link: на выходе запомнить, чей это IP, и положить в TUN.
    fn on_link_packet(&self, node: &Arc<Node>, link_id: leviculum_std::api::LinkId, pkt: &[u8]) {
        use std::sync::atomic::Ordering::Relaxed;
        if !valid_ipv4_packet(pkt) {
            self.c.not_ipv4.fetch_add(1, Relaxed);
            return;
        }
        if !self.is_exit {
            self.last_rx_ms.store(now_ms() as u64, Relaxed);
            self.unanswered_since_ms.store(0, Relaxed);
            if self.routing.load(Relaxed) {
                self.router.read().unwrap().snoop(pkt);
            }
        }
        if self.is_exit && self.enforce.load(Relaxed) {
            let src = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
            match self.allowed.read().unwrap().get(&link_id) {
                Some(ip) if *ip == src => {}
                _ => {
                    self.c.unauth_drops.fetch_add(1, Relaxed);
                    return;
                }
            }
            if !self.host_acl_ready.load(Relaxed) {
                self.c.unauth_drops.fetch_add(1, Relaxed);
                return;
            }
            let inventory = match self.host_inventory.read().unwrap().as_ref().cloned() {
                Some(snapshot) => snapshot,
                None => { self.c.unauth_drops.fetch_add(1, Relaxed); return; }
            };
            let dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
            match host_acl::classify_destination(dst, &inventory) {
                host_acl::DestinationDecision::Internet => {}
                host_acl::DestinationDecision::Deny => { self.c.unauth_drops.fetch_add(1, Relaxed); return; }
                host_acl::DestinationDecision::HostNeedsPermission => {
                    let granted = self.host_access.read().unwrap().contains(&link_id);
                    let health_echo = inventory.service_tun.contains(&dst) && is_icmp_echo_request(pkt)
                        && self.allow_health_echo(link_id);
                    if !inbound_host_access_allowed(pkt, self.host_acl_ready.load(Relaxed), &inventory, granted) && !health_echo {
                        self.c.unauth_drops.fetch_add(1, Relaxed);
                        return;
                    }
                }
            }
        } else if self.is_exit {
            let src = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
            let known = self.routes.read().unwrap().get(&src).map(|(id, _)| *id == link_id).unwrap_or(false);
            if !known {
                let handle = Arc::new(node.engine().link_handle(&link_id));
                self.routes.write().unwrap().insert(src, (link_id, handle));
            }
        }
        self.write_tun(pkt);
    }

    /// Пакет с дополнительного Link: живость основного он не отмечает (иначе молчание основного выхода осталось бы незамеченным).
    fn on_extra_packet(&self, pkt: &[u8]) {
        if !valid_ipv4_packet(pkt) {
            self.c.not_ipv4.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        self.write_tun(pkt);
    }

    /// Выход (режим VPN): пустить пакеты этого Link с адресом `ip` и вести к нему обратный маршрут.
    /// Результат авторитетный: `Ok` - Link и маршрут занесены (или уже были занесены с тем же адресом), `Err` - таблицы не изменены,
    /// и вызывающий не вправе слать AUTH_OK. Новый Link не наследует HOST_ACCESS.
    pub fn allow(&self, node: &Arc<Node>, link_id: leviculum_std::api::LinkId, ip: u32) -> Result<Admission, AdmissionError> {
        let handle = Arc::new(node.engine().link_handle(&link_id));
        self.allow_with_handle(link_id, ip, handle)
    }

    /// In-memory admission half: prepare the handle before taking Trust/Link-state guards.
    fn allow_with_handle(&self, link_id: LinkId, ip: u32, handle: Arc<leviculum_std::LinkHandle>) -> Result<Admission, AdmissionError> {
        self.allow_replacing_with_handle(link_id, ip, handle, &[])
    }

    /// Допуск, который может атомарно вытеснить прежний Link той же identity (`replaces`, см. `admit_link_replacing`).
    /// Список вычисляет вызывающий под guard Trust+links; здесь identity не известна и не проверяется.
    fn allow_replacing_with_handle(&self, link_id: LinkId, ip: u32, handle: Arc<leviculum_std::LinkHandle>, replaces: &[LinkId]) -> Result<Admission, AdmissionError> {
        use std::sync::atomic::Ordering::Acquire;
        // принимающий выход с неготовым ACL роняет весь трафик клиента: честный отказ вместо допуска в «чёрную дыру»
        if self.enforce.load(Acquire) && !self.host_acl_ready.load(Acquire) { return Err(AdmissionError::AclNotReady); }
        admit_link_replacing(&self.host_access, &self.allowed, &self.routes, link_id, ip, handle, replaces)
    }

    pub fn disallow(&self, link_id: &leviculum_std::api::LinkId) {
        disallow_link(&self.host_access, &self.allowed, &self.routes, link_id);
    }

    /// IP-пакеты TUN в обе стороны: клиент по росту счётчика отличает занятый выход от простаивающего.
    pub(crate) fn traffic_pkts(&self) -> u64 {
        use std::sync::atomic::Ordering::Relaxed;
        self.c.from_tun_pkts.load(Relaxed).wrapping_add(self.c.to_tun_pkts.load(Relaxed))
    }

    fn stats(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        serde_json::json!({
            "unauth_drops": self.c.unauth_drops.load(Relaxed),
            "host_acl_ready": self.host_acl_ready.load(std::sync::atomic::Ordering::Relaxed),
            "host_nft": crate::host_acl::nft_stats(),
            "from_tun_pkts": self.c.from_tun_pkts.load(Relaxed), "from_tun_bytes": self.c.from_tun_bytes.load(Relaxed),
            "to_tun_pkts": self.c.to_tun_pkts.load(Relaxed), "to_tun_bytes": self.c.to_tun_bytes.load(Relaxed),
            "tun_write_drops": self.c.tun_write_drops.load(Relaxed), "route_miss": self.c.route_miss.load(Relaxed),
            "send_errors": self.c.send_errors.load(Relaxed), "not_ipv4": self.c.not_ipv4.load(Relaxed), "probes": self.c.probes.load(Relaxed),
            "routes": self.routes.read().unwrap().len(),
            "failovers": self.failovers.lock().unwrap().clone(),
        })
    }
}

/// Читает пакеты из TUN и отправляет по Link датаграммами. Клиент: один Link. Выход: по адресу назначения.
async fn tun_reader(tun: Arc<TunState>, _node: Arc<Node>, sh: Arc<Shared>) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut buf = vec![0u8; 65536];
    let mut generation = tun.dev_gen.subscribe();
    loop {
        // Сначала отметить поколение как виденное, потом брать устройство: смена между этими шагами не потеряется.
        generation.borrow_and_update();
        let Some(dev) = tun.device() else {
            if generation.changed().await.is_err() { return; }
            continue;
        };
        let mut guard = tokio::select! {
            r = dev.readable() => match r {
                Ok(g) => g,
                Err(e) => {
                    sh.note(format!("tun reader stopped: {e}"));
                    return;
                }
            },
            _ = generation.changed() => continue,
        };
        // Вычерпываем всё готовое за одно пробуждение: меньше переключений на пакет.
        loop {
            let n = unsafe { libc::read(dev.get_ref().as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    break;
                }
                sh.note(format!("tun read error: {err}"));
                return;
            }
            let pkt = &buf[..n as usize];
            if !valid_ipv4_packet(pkt) {
                tun.c.not_ipv4.fetch_add(1, Relaxed);
                continue;
            }
            if tun.is_exit && tun.enforce.load(Relaxed) && !tun.response_allowed(pkt) {
                tun.c.unauth_drops.fetch_add(1, Relaxed);
                continue;
            }
            let mut on_main = true;
            let link = if tun.is_exit {
                let dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
                tun.routes.read().unwrap().get(&dst).map(|(_, h)| h.clone())
            } else {
                let mut l = None;
                if tun.routing.load(Relaxed) {
                    let dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
                    let act = {
                        let r = tun.router.read().unwrap();
                        if r.blocks_encrypted_dns(pkt) {
                            tun.rt.dot_dropped.fetch_add(1, Relaxed);
                            continue;
                        }
                        r.decide(dst)
                    };
                    match act {
                        route::Action::Exit(d) => match tun.extra.read().unwrap().get(&d) {
                            Some(x) => {
                                l = Some(x.handle.clone());
                                on_main = false;
                                tun.rt.extra_pkts.fetch_add(1, Relaxed);
                            }
                            None => {
                                if *tun.main_dest.read().unwrap() != d {
                                    tun.rt.fallback_pkts.fetch_add(1, Relaxed);
                                }
                            }
                        },
                        route::Action::Direct => {
                            tun.rt.direct_fallback_pkts.fetch_add(1, Relaxed);
                        }
                        route::Action::Default => {}
                    }
                }
                l.or_else(|| tun.client_link.read().unwrap().clone())
            };
            let Some(link) = link else {
                tun.c.route_miss.fetch_add(1, Relaxed);
                continue;
            };
            tun.c.from_tun_pkts.fetch_add(1, Relaxed);
            tun.c.from_tun_bytes.fetch_add(pkt.len() as u64, Relaxed);
            if link.send_datagram(pkt).await.is_err() {
                tun.c.send_errors.fetch_add(1, Relaxed);
            } else if !tun.is_exit && on_main {
                let t = now_ms() as u64;
                tun.last_tx_ms.store(t, Relaxed);
                let _ = tun.unanswered_since_ms.compare_exchange(0, t, Relaxed, Relaxed);
            }
        }
    }
}

impl TunState {
    /// Validate an exit-side host response against the client Link selected by dst.
    fn response_allowed(&self, pkt: &[u8]) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        if !self.host_acl_ready.load(Relaxed) { return false; }
        let inventory = match self.host_inventory.read().unwrap().as_ref().cloned() { Some(v) => v, None => return false };
        let dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
        let link = match self.routes.read().unwrap().get(&dst) { Some((link, _)) => *link, None => return false };
        if self.allowed.read().unwrap().get(&link) != Some(&dst) { return false; }
        let src = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
        match host_acl::classify_source(src, &inventory) {
            host_acl::SourceDecision::Public => true,
            host_acl::SourceDecision::Deny => false,
            host_acl::SourceDecision::HostNeedsPermission => {
                response_host_access_allowed(pkt, self.host_acl_ready.load(Relaxed), &inventory, self.host_access.read().unwrap().contains(&link))
            }
        }
    }
}

fn host_service_packet_valid(pkt: &[u8]) -> bool {
    if pkt.len() < 20 || (pkt[0] & 0x0f) != 5 { return false; }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x2000 != 0 || frag & 0x1fff != 0 { return false; }
    let payload = pkt.len() - 20;
    match pkt[9] {
        6 => payload >= 20 && usize::from(pkt[32] >> 4) * 4 >= 20
            && usize::from(pkt[32] >> 4) * 4 <= payload,
        17 => payload >= 8 && usize::from(u16::from_be_bytes([pkt[24], pkt[25]])) >= 8
            && usize::from(u16::from_be_bytes([pkt[24], pkt[25]])) <= payload,
        1 => payload >= 8,
        _ => false,
    }
}

fn is_icmp_echo_request(pkt: &[u8]) -> bool { pkt.len() >= 28 && pkt[9] == 1 && pkt[20] == 8 && pkt[21] == 0 }
fn is_icmp_echo_reply(pkt: &[u8]) -> bool { pkt.len() >= 28 && pkt[9] == 1 && pkt[20] == 0 && pkt[21] == 0 }

fn inbound_host_access_allowed(pkt: &[u8], ready: bool, inventory: &host_acl::Inventory, granted: bool) -> bool {
    let dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
    ready && host_acl::classify_destination(dst, inventory) == host_acl::DestinationDecision::HostNeedsPermission
        && ((granted && inventory.host_allow.contains(&dst))
            || (inventory.service_tun.contains(&dst) && is_icmp_echo_request(pkt)))
        && host_service_packet_valid(pkt)
}

fn response_host_access_allowed(pkt: &[u8], ready: bool, inventory: &host_acl::Inventory, granted: bool) -> bool {
    let src = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    ready && host_acl::classify_source(src, inventory) == host_acl::SourceDecision::HostNeedsPermission
        && ((granted && inventory.host_allow.contains(&src))
            || (inventory.service_tun.contains(&src) && is_icmp_echo_reply(pkt)))
        && host_service_packet_valid(pkt)
}

/// IPv4 ICMP echo request (src -> dst, 8 bytes of payload): проба живости туннеля. Выход отвечает ядром, как на обычный ping.
fn icmp_echo(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16) -> Vec<u8> {
    fn csum(b: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for c in b.chunks(2) {
            sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
    let mut p = vec![0u8; 36];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&36u16.to_be_bytes());
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6] = 0x40; // DF
    p[8] = 64;
    p[9] = 1;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    let h = csum(&p[..20]);
    p[10..12].copy_from_slice(&h.to_be_bytes());
    p[20] = 8; // echo request
    p[24..26].copy_from_slice(&id.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    p[28..36].copy_from_slice(b"knotprob");
    let c = csum(&p[20..]);
    p[22..24].copy_from_slice(&c.to_be_bytes());
    p
}

/// Следит за Link клиента и при отказе поднимает новый по лучшему из оставшихся путей RNS.
///
/// Отказом считается: (1) `LinkClosed` от самого RNS (keepalive/stale; срок задаёт `--link-keepalive-s`),
/// (2) молчание: после последней нашей отправки в Link дольше `--fail-ms` не пришло ни одного пакета.
/// Датаграммы не подтверждаются, поэтому второй признак нужен, чтобы не ждать stale RNS (~15 с).
/// Смена: закрыть старый Link, убрать мёртвую ручку, запросить путь (если пути нет) и установить новый Link.
/// Выход сам переучивает маршрут «IP клиента -> Link» по первому пакету с нового Link.
async fn tun_supervisor(cli: Cli, node: Arc<Node>, sh: Arc<Shared>, tun: Arc<TunState>, dest: DestinationHash, key: [u8; 32], mut link_id: LinkId) {
    use std::sync::atomic::Ordering::Relaxed;
    let parse = |t: &str| -> [u8; 4] {
        t.split('/').next().and_then(|a| a.parse::<std::net::Ipv4Addr>().ok()).map(|a| a.octets()).unwrap_or([10, 99, 0, 1])
    };
    let (my_ip, exit_ip) = (parse(&cli.tun_ip), parse(&cli.exit_tun_ip));
    let (mut last_probe, mut probe_seq) = (0u64, 0u16);
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = now_ms() as u64;
        let closed = sh.closed.lock().unwrap().get(&hex(link_id.as_bytes())).cloned();
        // Молчание: сколько мс назад мы отправили то, на что до сих пор ничего не пришло. Односторонний поток (UDP вверх) без
        // обратных пакетов отказом не считается: сначала проба (ping на адрес выхода в туннеле), отказ - если не вернулась и она.
        let since = tun.unanswered_since_ms.load(Relaxed);
        let quiet = if since == 0 { 0 } else { now.saturating_sub(since) };
        if quiet > cli.fail_ms / 2 && now.saturating_sub(last_probe) >= cli.fail_ms / 4 && closed.is_none() {
            last_probe = now;
            probe_seq = probe_seq.wrapping_add(1);
            let handle = tun.client_link.read().unwrap().clone();
            if let Some(h) = handle {
                let pkt = icmp_echo(my_ip, exit_ip, 0x7261, probe_seq);
                if h.send_datagram(&pkt).await.is_ok() {
                    tun.c.probes.fetch_add(1, Relaxed);
                }
            }
        }
        let silent = quiet > cli.fail_ms;
        let reason = match (&closed, silent) {
            (Some(r), _) => format!("link closed by RNS: {r}"),
            (None, true) => format!("silent {quiet} ms after our tx"),
            _ => continue,
        };
        let t0 = Instant::now();
        let at = now;
        let hops_before = node.hops_to(&dest);
        sh.note(format!("failover: {reason}; hops={hops_before:?}"));
        sh.note(format!("failover transport stats: {:?}", node.engine().transport_stats()));
        let link_iface = node.engine().link_stats(&link_id).and_then(|st| st.attached_interface());
        *tun.client_link.write().unwrap() = None;
        let _ = node.engine().close_link(&link_id).await;
        let mut attempts = 0u32;
        let mut bad: Vec<usize> = Vec::new();
        loop {
            attempts += 1;
            // Путь к E ведёт через узел, который только что подвёл. Забываем путь и спрашиваем заново, но не у того интерфейса:
            // соседний узел с оборванной связью до E держит в таблице старый путь и ответил бы первым (PATH_REQUEST отвечается
            // из таблицы путей). Лимит «один запрос на получателя в 20 с» здесь снят: это один запрос на отказ.
            // Подвёл тот интерфейс, на котором стоял Link (таблица путей могла уже перескочить на другой от свежего анонса).
            let failed_iface = if attempts == 1 { link_iface } else { None }
                .or_else(|| node.engine().get_path_clone(&dest).map(|p| p.interface_index));
            if let Some(i) = failed_iface {
                if !bad.contains(&i) {
                    bad.push(i);
                }
            }
            node.engine().remove_path(&dest);
            let online: Vec<usize> = node.engine().interface_stats().iter().filter(|i| i.online).map(|i| i.interface_id.0).collect();
            let mut ask: Vec<usize> = online.iter().copied().filter(|i| !bad.contains(i)).collect();
            if ask.is_empty() {
                bad.clear();
                ask = online.clone();
            }
            sh.note(format!("failover: path dropped (+{} ms), asking interfaces {ask:?}, avoiding {bad:?}", t0.elapsed().as_millis()));
            let wait_until = Instant::now() + Duration::from_millis(cli.relink_timeout_ms);
            let mut next_ask = Instant::now();
            let mut got = false;
            while Instant::now() < wait_until {
                if node.has_path(&dest) {
                    got = true;
                    break;
                }
                if Instant::now() >= next_ask {
                    let _ = node.engine().request_path_on(&dest, &ask).await;
                    next_ask = Instant::now() + Duration::from_millis(1000);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if !got {
                sh.note(format!("relink attempt {attempts}: no path answer"));
                continue;
            }
            sh.note(format!("failover: path answer after {} ms, hops={:?}", t0.elapsed().as_millis(), node.hops_to(&dest)));
            match open_link_t(&cli, &node, &sh, &dest, &key, Duration::from_millis(cli.relink_timeout_ms)).await {
                Ok(id) => {
                    let handle = Arc::new(node.engine().link_handle(&id));
                    *tun.client_link.write().unwrap() = Some(handle);
                    tun.last_rx_ms.store(now_ms() as u64, Relaxed);
                    tun.unanswered_since_ms.store(0, Relaxed);
                    link_id = id;
                    let hops_after = node.hops_to(&dest);
                    sh.note(format!("failover done in {} ms, attempts={attempts}, hops={hops_after:?}", t0.elapsed().as_millis()));
                    tun.failovers.lock().unwrap().push(serde_json::json!({"at_unix_ms": at, "reason": reason,
                        "recovered_after_ms": t0.elapsed().as_millis() as u64, "attempts": attempts, "hops_before": hops_before, "hops_after": hops_after}));
                    break;
                }
                Err(e) => {
                    sh.note(format!("relink attempt {attempts} failed: {e}"));
                    if attempts == 2 { sh.note(format!("transport stats: {:?}", node.engine().transport_stats())); }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
    }
}

/// Клиент туннеля: установить Link к выходу, открыть TUN, перекладывать пакеты до файла `fin`.
async fn client_tun(cli: &Cli, node: Arc<Node>, sh: Arc<Shared>, dest: &DestinationHash, key: &[u8; 32]) -> Result<()> {
    if !node.wait_for_path(dest, Duration::from_secs(40), Duration::from_secs(1)).await? {
        bail!("no path to E");
    }
    let handle = node.connect_with_key(dest, key).await?;
    let k = hex(handle.link_id().as_bytes());
    let t1 = Instant::now();
    while !sh.established.lock().unwrap().contains(&k) {
        if t1.elapsed() > Duration::from_secs(20) {
            bail!("link establishment timeout");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mdu = node.engine().link_mdu(handle.link_id());
    if let Some(m) = mdu {
        if cli.tun_mtu as usize > m {
            bail!("--tun-mtu {} exceeds link mdu {m}", cli.tun_mtu);
        }
    }
    let tun = TunState::open(cli, false)?;
    *tun.client_link.write().unwrap() = Some(Arc::new(handle));
    tun.last_rx_ms.store(now_ms() as u64, std::sync::atomic::Ordering::Relaxed);
    let _ = sh.tun.set(tun.clone());
    tokio::spawn(tun_reader(tun.clone(), node.clone(), sh.clone()));
    if cli.fail_ms > 0 {
        let (cli2, node2, sh2, tun2, dest2, key2) = (cli.clone(), node.clone(), sh.clone(), tun.clone(), *dest, *key);
        let first = *tun.client_link.read().unwrap().as_ref().unwrap().link_id();
        tokio::spawn(async move { tun_supervisor(cli2, node2, sh2, tun2, dest2, key2, first).await });
    }
    sh.note(format!("tun {} up on the client, link {} mdu={mdu:?} mtu {}", cli.tun_name, &k[..8], cli.tun_mtu));
    std::fs::File::create(cli.state.join("ready"))?;
    // Живой статус для оболочки приложения (раз в секунду, атомарно: временный файл + rename).
    {
        let (st, node2, tun2, dest2, p) = (cli.state.clone(), node.clone(), tun.clone(), *dest, cli.state.join("status.json"));
        let _ = st;
        tokio::spawn(async move {
            let t0 = Instant::now();
            loop {
                let state = if tun2.client_link.read().unwrap().is_some() { "up" } else { "relinking" };
                let j = serde_json::json!({"state": state, "up_s": t0.elapsed().as_secs(), "tun": tun2.stats(), "udp": udp_stats(), "hops": node2.hops_to(&dest2), "ts_ms": now_ms() as u64});
                let tmp = p.with_extension("tmp");
                if std::fs::write(&tmp, j.to_string()).is_ok() {
                    let _ = std::fs::rename(&tmp, &p);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
    wait_file(&cli.state.join("fin"), 10 * 365 * 86400).await?;
    let (hwm_kb, rss_kb) = proc_mem_kb();
    let out = serde_json::json!({
        "mode": "tun", "link_mdu": mdu, "tun_mtu": cli.tun_mtu, "tun": tun.stats(), "cipher": cli.cipher,
        "quic_stats": sh.quic_stats.lock().unwrap().clone(),
        "pc_drops": pc_drops_json(),
        "vm_hwm_kb": hwm_kb, "vm_rss_kb": rss_kb,
        "data_events_dropped": leviculum_std::data_events_dropped(),
        "log": sh.log.lock().unwrap().iter().map(|(t, m)| serde_json::json!({"t_ms": *t as u64, "msg": m})).collect::<Vec<_>>(),
    });
    std::fs::write(cli.state.join("result-c.json"), serde_json::to_vec(&out)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Обход enforce роли `e` существует только в debug/с явным feature; в штатном release роль e с tun отклоняется при любой переменной.
    #[test]
    fn lab_exit_no_enforce_gate_matches_build_kind() {
        let lab = cfg!(any(debug_assertions, feature = "lab-exit-no-enforce"));
        assert!(exit_no_enforce_gate("c", "tun", None).is_ok() && exit_no_enforce_gate("e", "tap", None).is_ok(), "прочие роли и режимы не затронуты");
        assert!(exit_no_enforce_gate("e", "tun", None).is_err(), "без переменной выход без enforce не стартует");
        assert!(exit_no_enforce_gate("e", "tun", Some("0")).is_err());
        assert_eq!(exit_no_enforce_gate("e", "tun", Some("1")).is_ok(), lab, "переменная действует только в сборке с обходом");
        if !lab {
            assert!(!exit_no_enforce_gate("e", "tun", Some("1")).unwrap_err().contains("KNOTHOP"), "release не называет переменную");
        }
    }

    fn acl_packet(src: &str, dst: &str, proto: u8, len: usize, icmp_type: Option<u8>) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&src.parse::<std::net::Ipv4Addr>().unwrap().octets());
        p[16..20].copy_from_slice(&dst.parse::<std::net::Ipv4Addr>().unwrap().octets());
        if proto == 6 { p[32] = 0x50; }
        if proto == 17 { p[24..26].copy_from_slice(&(len as u16 - 20).to_be_bytes()); }
        if let Some(kind) = icmp_type { p[20] = kind; }
        p
    }

    type Tables = (HostAccessSet, AllowedMap, RouteMap<()>);

    fn tables() -> Tables {
        (std::sync::RwLock::new(HashSet::new()), std::sync::RwLock::new(HashMap::new()), std::sync::RwLock::new(HashMap::new()))
    }

    fn lid(n: u8) -> leviculum_std::api::LinkId { leviculum_std::api::LinkId::new([n; 16]) }

    fn admit(t: &Tables, link: u8, ip: u32) -> Result<Admission, AdmissionError> {
        admit_link(&t.0, &t.1, &t.2, lid(link), ip, ())
    }

    fn snapshot(t: &Tables) -> (usize, usize, usize) {
        (t.0.read().unwrap().len(), t.1.read().unwrap().len(), t.2.read().unwrap().len())
    }

    // Synthetic authority; production Trust, HostCommit and TUN permission core, not an ACL model.
    struct HostPublicationFixture {
        authority: Arc<Mutex<trust::Trust>>,
        pk: trust::Pk,
        host_revoke: trust::HostAccessRecord,
        issuer_revoke: trust::Record,
    }

    fn host_publication_fixture() -> HostPublicationFixture {
        let root = leviculum_std::api::generate_identity();
        let admin = leviculum_std::api::generate_identity();
        let holder = leviculum_std::api::generate_identity();
        let pk = holder.public_key_bytes();
        let mut issuer = trust::Trust::new(root.clone(), None);
        let delegation = issuer.issue(*root.hash(), admin.public_key_bytes(), trust::ADD | trust::REMOVE | trust::USE).unwrap();
        let holder_record = issuer.issue(*root.hash(), pk, trust::USE).unwrap();
        let mut delegate = trust::Trust::new(admin.clone(), None);
        delegate.add_anchor(&root.public_key_bytes()).unwrap();
        assert_eq!(delegate.offer(delegation.clone()), trust::Offer::Added);
        let scoped_authority = issuer.sign_host_access(*root.hash(), *root.hash(), admin.public_key_bytes(), true).unwrap();
        let grant = delegate.sign_host_access(*root.hash(), *root.hash(), pk, true).unwrap();
        let host_revoke = delegate.sign_host_access(*root.hash(), *root.hash(), pk, false).unwrap();
        let issuer_revoke = issuer.issue(*root.hash(), admin.public_key_bytes(), 0).unwrap();
        let mut target = trust::Trust::new(root, None);
        assert_eq!(target.offer(delegation), trust::Offer::Added);
        assert_eq!(target.offer(holder_record), trust::Offer::Added);
        let authority = Arc::new(Mutex::new(target));
        for record in [scoped_authority, grant] {
            commit_publication_record(&authority, &record);
        }
        HostPublicationFixture { authority, pk, host_revoke, issuer_revoke }
    }

    fn commit_publication_record(authority: &Mutex<trust::Trust>, record: &trust::HostAccessRecord) {
        let commit = authority.lock().unwrap().prepare_host_access(record).unwrap();
        // Same split as the LXMF worker: commit gate/I/O never requested under Trust.
        commit.commit(authority).unwrap();
    }

    fn publish_acl(authority: &Mutex<trust::Trust>, pk: &trust::Pk, t: &Tables) -> bool {
        publish_host_access_decision(authority, pk, |_| (), |grant| set_link_host_access(&t.0, &t.1, &lid(1), grant)).1
    }

    #[test]
    fn host_publication_delayed_evaluator_cannot_restore_revoked_access() {
        use std::sync::mpsc::channel;
        // Ordinary authority revocation must work too; it need not change host_version.
        for revoke_issuer in [false, true] {
            let HostPublicationFixture { authority, pk, host_revoke, issuer_revoke } = host_publication_fixture();
            let t = Arc::new(tables());
            admit(&t, 1, 0xc6120107).unwrap();
            assert!(publish_acl(&authority, &pk, &t));
            assert!(t.0.read().unwrap().contains(&lid(1)));
            let (paused, ready) = channel();
            let (resume, resumed) = channel();
            let old_authority = authority.clone();
            let old_tables = t.clone();
            let old = std::thread::spawn(move || {
                // The former evaluator could carry this true across revoke/ACK. The actual
                // shared publisher accepts no snapshot; on resumption it must read Trust itself.
                let stale_true = {
                    let tr = old_authority.lock().unwrap();
                    !tr.host_access_roots(&pk, &tr.me_hash).is_empty()
                };
                paused.send(stale_true).unwrap();
                resumed.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(publish_acl(&old_authority, &pk, &old_tables));
            });
            assert!(ready.recv_timeout(Duration::from_secs(5)).unwrap());
            if revoke_issuer {
                assert_eq!(authority.lock().unwrap().offer(issuer_revoke), trust::Offer::Added);
            } else {
                commit_publication_record(&authority, &host_revoke);
            }
            assert!(publish_acl(&authority, &pk, &t)); // enforce_rights publication before ACK
            {
                let tr = authority.lock().unwrap();
                assert!(tr.host_access_roots(&pk, &tr.me_hash).is_empty()); // ACK effective=false
                assert_ne!(tr.rights(&pk) & trust::USE, 0, "holder USE survives host/issuer revoke");
            }
            assert!(!t.0.read().unwrap().contains(&lid(1)));
            resume.send(()).unwrap();
            old.join().unwrap();
            assert!(!t.0.read().unwrap().contains(&lid(1)), "old evaluator must not restore host access after revoke/ACK");
            assert_eq!(snapshot(&t), (0, 1, 1), "revoking host access does not revoke ordinary admission");
            let mut inventory = host_acl::Inventory::default();
            let host = u32::from(std::net::Ipv4Addr::new(10, 99, 0, 1));
            inventory.owned.insert(host);
            inventory.host_allow.insert(host);
            let granted = t.0.read().unwrap().contains(&lid(1));
            assert!(!inbound_host_access_allowed(&acl_packet("198.18.1.7", "10.99.0.1", 6, 40, None), true, &inventory, granted));
            assert!(!response_host_access_allowed(&acl_packet("10.99.0.1", "198.18.1.7", 6, 40, None), true, &inventory, granted));
        }
    }

    #[test]
    fn host_publication_holds_trust_through_delayed_setter() {
        use std::sync::{TryLockError, mpsc::channel};
        let HostPublicationFixture { authority, pk, host_revoke, .. } = host_publication_fixture();
        let t = Arc::new(tables());
        admit(&t, 1, 0xc6120107).unwrap();
        let revoke = authority.lock().unwrap().prepare_host_access(&host_revoke).unwrap();
        let (paused, ready) = channel();
        let (resume, resumed) = channel();
        let old_authority = authority.clone();
        let old_tables = t.clone();
        let old = std::thread::spawn(move || {
            publish_host_access_decision(&old_authority, &pk, |_| (), |grant| {
                paused.send(grant).unwrap();
                resumed.recv_timeout(Duration::from_secs(5)).unwrap();
                set_link_host_access(&old_tables.0, &old_tables.1, &lid(1), grant)
            })
        });
        assert!(ready.recv_timeout(Duration::from_secs(5)).unwrap());
        // This is the exact former TOCTOU boundary. Revoke cannot commit here, so cannot
        // publish false/ACK and then be overwritten by this already computed true.
        let guarded = matches!(authority.try_lock(), Err(TryLockError::WouldBlock));
        let (attempted, attempt) = channel();
        let (acked, ack) = channel();
        let new_authority = authority.clone();
        let new_tables = t.clone();
        let new = std::thread::spawn(move || {
            attempted.send(()).unwrap();
            revoke.commit(&new_authority).unwrap();
            assert!(publish_acl(&new_authority, &pk, &new_tables));
            let tr = new_authority.lock().unwrap();
            acked.send(!tr.host_access_roots(&pk, &tr.me_hash).is_empty()).unwrap();
        });
        attempt.recv_timeout(Duration::from_secs(5)).unwrap();
        let no_early_ack = matches!(ack.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty));
        resume.send(()).unwrap();
        assert_eq!(old.join().unwrap(), ((), true));
        assert!(!ack.recv_timeout(Duration::from_secs(5)).unwrap());
        new.join().unwrap();
        assert!(guarded, "Trust was dropped before the actual setter");
        assert!(no_early_ack, "revoke/ACK must wait for the in-flight publisher");
        assert!(!t.0.read().unwrap().contains(&lid(1)));
    }

    #[test]
    fn host_publication_preserves_root_union_and_authoritative_admission() {
        let HostPublicationFixture { authority, pk, host_revoke, .. } = host_publication_fixture();
        let t = tables();
        assert!(!publish_acl(&authority, &pk, &t), "a valid Trust grant cannot admit a Link");
        assert_eq!(snapshot(&t), (0, 0, 0));
        admit(&t, 1, 0xc6120107).unwrap();
        let other_root = leviculum_std::api::generate_identity();
        let mut other = trust::Trust::new(other_root.clone(), None);
        let holder_record = other.issue(*other_root.hash(), pk, trust::USE).unwrap();
        let grant = {
            let mut tr = authority.lock().unwrap();
            tr.add_anchor(&other_root.public_key_bytes()).unwrap();
            tr.allow_host_root(*other_root.hash(), 16);
            assert_eq!(tr.offer(holder_record), trust::Offer::Added);
            other.sign_host_access(*other_root.hash(), tr.me_hash, pk, true).unwrap()
        };
        commit_publication_record(&authority, &grant);
        commit_publication_record(&authority, &host_revoke);
        assert!(publish_acl(&authority, &pk, &t));
        assert!(t.0.read().unwrap().contains(&lid(1)), "another accepted root still grants HOST_ACCESS");
        disallow_link(&t.0, &t.1, &t.2, &lid(1));
        assert!(!publish_acl(&authority, &pk, &t), "a late evaluator cannot resurrect a closed Link");
        assert_eq!(snapshot(&t), (0, 0, 0));
    }

    #[test]
    fn admission_is_idempotent_for_same_link_and_address_and_keeps_grant() {
        let t = tables();
        assert_eq!(admit(&t, 1, 0x0a000002), Ok(Admission::Admitted));
        assert!(set_link_host_access(&t.0, &t.1, &lid(1), true));
        assert_eq!(admit(&t, 1, 0x0a000002), Ok(Admission::AlreadyAdmitted));
        assert!(t.0.read().unwrap().contains(&lid(1)), "repeat admission must not drop or add HOST_ACCESS");
        assert_eq!(snapshot(&t), (1, 1, 1));
        // нарушенный инвариант (допущен, маршрута нет) восстанавливается тем же вызовом
        t.2.write().unwrap().clear();
        assert_eq!(admit(&t, 1, 0x0a000002), Ok(Admission::AlreadyAdmitted));
        assert_eq!(t.2.read().unwrap().get(&0x0a000002).map(|(l, _)| *l), Some(lid(1)));
    }

    #[test]
    fn admission_refuses_ip_collision_and_address_change_without_mutation() {
        let t = tables();
        assert_eq!(admit(&t, 1, 0x0a000002), Ok(Admission::Admitted));
        let before = snapshot(&t);
        assert_eq!(admit(&t, 2, 0x0a000002), Err(AdmissionError::AddressInUse));
        assert_eq!(admit(&t, 1, 0x0a000003), Err(AdmissionError::LinkAddressChanged));
        assert_eq!(snapshot(&t), before, "refusal is all-or-nothing");
        assert!(!t.1.read().unwrap().contains_key(&lid(2)));
        assert!(!t.2.read().unwrap().contains_key(&0x0a000003));
        assert_eq!(t.1.read().unwrap().get(&lid(1)), Some(&0x0a000002));
    }

    fn admit_replacing(t: &Tables, link: u8, ip: u32, replaces: &[u8]) -> Result<Admission, AdmissionError> {
        let r: Vec<_> = replaces.iter().map(|n| lid(*n)).collect();
        admit_link_replacing(&t.0, &t.1, &t.2, lid(link), ip, (), &r)
    }

    #[test]
    fn replacing_admission_evicts_listed_owner_atomically_without_inheriting_host_access() {
        let t = tables();
        assert_eq!(admit(&t, 1, 0x0a000002), Ok(Admission::Admitted));
        assert!(set_link_host_access(&t.0, &t.1, &lid(1), true));
        assert_eq!(admit_replacing(&t, 2, 0x0a000002, &[1]), Ok(Admission::Admitted));
        assert_eq!(t.2.read().unwrap().get(&0x0a000002).map(|(l, _)| *l), Some(lid(2)));
        assert_eq!(t.1.read().unwrap().get(&lid(2)), Some(&0x0a000002));
        assert!(!t.1.read().unwrap().contains_key(&lid(1)), "evicted Link loses its admission");
        assert!(t.0.read().unwrap().is_empty(), "neither the evicted nor the new Link holds HOST_ACCESS");
        assert_eq!(snapshot(&t), (0, 1, 1));
        // поздний disallow вытесненного Link не снимает маршрут нового
        disallow_link(&t.0, &t.1, &t.2, &lid(1));
        assert_eq!(t.2.read().unwrap().get(&0x0a000002).map(|(l, _)| *l), Some(lid(2)));
        assert_eq!(snapshot(&t), (0, 1, 1));
    }

    #[test]
    fn replacing_admission_refuses_unlisted_owner_or_mismatched_address_without_mutation() {
        let t = tables();
        assert_eq!(admit(&t, 1, 0x0a000002), Ok(Admission::Admitted));
        assert!(set_link_host_access(&t.0, &t.1, &lid(1), true));
        let before = snapshot(&t);
        // владелец не в списке (в списке чужой Link)
        assert_eq!(admit_replacing(&t, 2, 0x0a000002, &[9]), Err(AdmissionError::AddressInUse));
        assert_eq!(admit_replacing(&t, 2, 0x0a000002, &[]), Err(AdmissionError::AddressInUse));
        assert_eq!(snapshot(&t), before);
        assert!(t.0.read().unwrap().contains(&lid(1)));
        // список ссылается на Link с другим адресом: он не владелец нужного адреса
        assert_eq!(admit(&t, 3, 0x0a000003), Ok(Admission::Admitted));
        let before = snapshot(&t);
        assert_eq!(admit_replacing(&t, 2, 0x0a000002, &[3]), Err(AdmissionError::AddressInUse));
        assert_eq!(snapshot(&t), before);
        assert_eq!(t.2.read().unwrap().get(&0x0a000002).map(|(l, _)| *l), Some(lid(1)));
        assert_eq!(t.2.read().unwrap().get(&0x0a000003).map(|(l, _)| *l), Some(lid(3)));
        // нарушенный инвариант: владелец маршрута без записи allowed на этот адрес не вытесняется
        t.1.write().unwrap().remove(&lid(1));
        let before = snapshot(&t);
        assert_eq!(admit_replacing(&t, 2, 0x0a000002, &[1]), Err(AdmissionError::AddressInUse));
        assert_eq!(snapshot(&t), before);
        // тот же Link, другой адрес и список вытеснения: по-прежнему LinkAddressChanged
        assert_eq!(admit_replacing(&t, 3, 0x0a000009, &[1]), Err(AdmissionError::LinkAddressChanged));
        // свободный адрес со списком вытеснения: обычный допуск, ничего лишнего не удалено
        assert_eq!(admit_replacing(&t, 4, 0x0a000004, &[3]), Ok(Admission::Admitted));
        assert_eq!(t.2.read().unwrap().get(&0x0a000003).map(|(l, _)| *l), Some(lid(3)));
    }

    #[test]
    fn replacing_admission_keeps_capacity_and_is_all_or_nothing() {
        let t = tables();
        for i in 0..MAX_ALLOWED_CLIENTS {
            assert_eq!(admit_link(&t.0, &t.1, &t.2, leviculum_std::api::LinkId::new([i as u8; 16]), 0x0a000100 + i as u32, ()), Ok(Admission::Admitted));
        }
        let before = snapshot(&t);
        let extra = leviculum_std::api::LinkId::new([0xee, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        // замена на полных таблицах: баланс нулевой
        assert_eq!(admit_link_replacing(&t.0, &t.1, &t.2, extra, 0x0a000100, (), &[lid(0)]), Ok(Admission::Admitted));
        assert_eq!(snapshot(&t), before);
        assert!(!t.1.read().unwrap().contains_key(&lid(0)));
        // не-замена на полных таблицах по-прежнему Capacity, никто не вытеснен
        let extra2 = leviculum_std::api::LinkId::new([0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(admit_link_replacing(&t.0, &t.1, &t.2, extra2, 0x0a020000, (), &[lid(1)]), Err(AdmissionError::Capacity));
        assert_eq!(snapshot(&t), before);
        assert!(t.1.read().unwrap().contains_key(&lid(1)));
    }

    #[test]
    fn admission_capacity_is_enforced_and_existing_links_stay_idempotent() {
        let t = tables();
        for i in 0..MAX_ALLOWED_CLIENTS {
            assert_eq!(admit_link(&t.0, &t.1, &t.2, leviculum_std::api::LinkId::new([i as u8; 16]), 0x0a000100 + i as u32, ()), Ok(Admission::Admitted));
        }
        let before = snapshot(&t);
        assert_eq!(before, (0, MAX_ALLOWED_CLIENTS, MAX_ALLOWED_CLIENTS));
        // заполненные Link имеют вид [i; 16]; этот заведомо иной
        let extra = leviculum_std::api::LinkId::new([0xee, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(admit_link(&t.0, &t.1, &t.2, extra, 0x0a010000, ()), Err(AdmissionError::Capacity));
        assert_eq!(snapshot(&t), before);
        assert!(!t.1.read().unwrap().contains_key(&extra));
        assert_eq!(admit_link(&t.0, &t.1, &t.2, leviculum_std::api::LinkId::new([0; 16]), 0x0a000100, ()), Ok(Admission::AlreadyAdmitted));
        // освобождённое место снова доступно
        disallow_link(&t.0, &t.1, &t.2, &leviculum_std::api::LinkId::new([0; 16]));
        assert_eq!(admit_link(&t.0, &t.1, &t.2, extra, 0x0a010000, ()), Ok(Admission::Admitted));
    }

    #[test]
    fn host_access_requires_admission_and_never_survives_disallow_or_readmission() {
        let t = tables();
        assert!(!set_link_host_access(&t.0, &t.1, &lid(1), true), "grant for an unadmitted Link is refused");
        assert!(t.0.read().unwrap().is_empty());
        admit(&t, 1, 0x0a000002).unwrap();
        assert!(!t.0.read().unwrap().contains(&lid(1)), "default is no HOST_ACCESS");
        assert!(set_link_host_access(&t.0, &t.1, &lid(1), true));
        assert!(t.0.read().unwrap().contains(&lid(1)));
        assert!(set_link_host_access(&t.0, &t.1, &lid(1), false));
        assert!(t.0.read().unwrap().is_empty());
        assert!(set_link_host_access(&t.0, &t.1, &lid(1), true));
        disallow_link(&t.0, &t.1, &t.2, &lid(1));
        assert_eq!(snapshot(&t), (0, 0, 0), "disallow removes permission, binding and route; freed IP is reusable");
        // устаревший остаток разрешения для неизвестного LinkId не переходит в новый допуск
        t.0.write().unwrap().insert(lid(1));
        assert_eq!(admit(&t, 1, 0x0a000002), Ok(Admission::Admitted));
        assert!(!t.0.read().unwrap().contains(&lid(1)));
        // disallow чужого маршрута не стирает маршрут нового владельца адреса
        disallow_link(&t.0, &t.1, &t.2, &lid(9));
        assert_eq!(t.2.read().unwrap().get(&0x0a000002).map(|(l, _)| *l), Some(lid(1)));
    }

    #[test]
    fn admission_error_codes_are_stable_and_address_free() {
        let all = [AdmissionError::AclNotReady, AdmissionError::Capacity, AdmissionError::AddressInUse, AdmissionError::LinkAddressChanged];
        let codes: HashSet<_> = all.iter().map(|e| e.code()).collect();
        assert_eq!(codes.len(), all.len());
        assert!(all.iter().all(|e| e.to_string() == e.code() && e.code().bytes().all(|b| b.is_ascii_lowercase() || b == b'_')));
    }

    #[test]
    fn host_acl_is_exact_grant_gated_and_preserves_public_internet() {
        let mut inventory = host_acl::Inventory::default();
        let own_public = u32::from(std::net::Ipv4Addr::new(8, 8, 4, 4));
        let own_private = u32::from(std::net::Ipv4Addr::new(10, 1, 2, 3));
        inventory.owned.extend([own_public, own_private, u32::from(std::net::Ipv4Addr::new(10, 99, 0, 1))]);
        inventory.host_allow.extend([own_public, own_private]);
        inventory.service_tun.insert(u32::from(std::net::Ipv4Addr::new(10, 99, 0, 1)));
        let tcp = |dst| acl_packet("198.18.1.7", dst, 6, 40, None);
        assert!(matches!(host_acl::classify_destination(u32::from(std::net::Ipv4Addr::new(1, 1, 1, 1)), &inventory), host_acl::DestinationDecision::Internet));
        assert!(!inbound_host_access_allowed(&tcp("8.8.4.4"), true, &inventory, false));
        assert!(inbound_host_access_allowed(&tcp("8.8.4.4"), true, &inventory, true));
        assert!(!inbound_host_access_allowed(&tcp("10.1.2.3"), true, &inventory, false));
        assert!(inbound_host_access_allowed(&tcp("10.1.2.3"), true, &inventory, true));
        assert!(!inbound_host_access_allowed(&tcp("10.1.2.4"), true, &inventory, true));
        assert!(!inbound_host_access_allowed(&tcp("172.17.0.1"), true, &inventory, true));
        assert!(!inbound_host_access_allowed(&tcp("198.18.0.2"), true, &inventory, true));
        assert!(!inbound_host_access_allowed(&tcp("8.8.4.4"), false, &inventory, true));
    }

    #[test]
    fn host_acl_fail_closed_on_unready_non_v4_options_and_fragments_and_revokes_responses() {
        let mut inventory = host_acl::Inventory::default();
        let client = "198.18.1.7";
        let host = u32::from(std::net::Ipv4Addr::new(10, 99, 0, 1));
        inventory.owned.insert(host);
        inventory.host_allow.insert(host);
        inventory.service_tun.insert(host);
        let reply = acl_packet("10.99.0.1", client, 6, 40, None);
        assert!(response_host_access_allowed(&reply, true, &inventory, true));
        assert!(!response_host_access_allowed(&reply, true, &inventory, false), "revocation applies to active-flow responses");
        let mut fragmented = acl_packet(client, "10.99.0.1", 6, 40, None);
        fragmented[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(!inbound_host_access_allowed(&fragmented, true, &inventory, true));
        let mut options = acl_packet(client, "10.99.0.1", 6, 40, None);
        options[0] = 0x46;
        assert!(!inbound_host_access_allowed(&options, true, &inventory, true));
        let non_v4 = vec![0x60; 40];
        assert!(!valid_ipv4_packet(&non_v4));
        assert!(!response_host_access_allowed(&reply, false, &host_acl::Inventory::default(), true));
    }

    #[test]
    fn service_tun_exception_is_only_echo_request_reply() {
        let mut inventory = host_acl::Inventory::default();
        let tun = u32::from(std::net::Ipv4Addr::new(10, 99, 0, 1));
        inventory.owned.insert(tun);
        inventory.service_tun.insert(tun);
        let mut request = acl_packet("198.18.1.7", "10.99.0.1", 1, 28, Some(8));
        request[21] = 0;
        assert!(inbound_host_access_allowed(&request, true, &inventory, false));
        request[20] = 3;
        assert!(!inbound_host_access_allowed(&request, true, &inventory, false));
        let mut reply = acl_packet("10.99.0.1", "198.18.1.7", 1, 28, Some(0));
        reply[21] = 0;
        assert!(response_host_access_allowed(&reply, true, &inventory, false));
    }

    #[test]
    fn ipv4_validation_rejects_truncation_bad_lengths_and_malformed_fragments() {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[8] = 64;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        assert!(valid_ipv4_packet(&p));
        assert!(!valid_ipv4_packet(&p[..27]));
        p[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert!(!valid_ipv4_packet(&p));
        p[2..4].copy_from_slice(&29u16.to_be_bytes());
        assert!(!valid_ipv4_packet(&p));
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(valid_ipv4_packet(&p));
        p[2..4].copy_from_slice(&27u16.to_be_bytes());
        assert!(!valid_ipv4_packet(&p), "non-final fragment payload must be an 8-byte multiple");
        p[6..8].copy_from_slice(&0x8000u16.to_be_bytes());
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        assert!(!valid_ipv4_packet(&p), "reserved fragment flag rejected");
    }

    #[test]
    fn proof_binding_cli_defaults_to_safe_cipher_policy_and_keeps_explicit_overrides() {
        let cli = Cli::try_parse_from(["rns-iroh-node", "--role", "c", "--ip", "127.0.0.1"])
            .unwrap();
        assert_eq!(cli.proof_binding, "cipher");
        assert_eq!(
            parse_cli_proof_binding_policy(&cli.proof_binding).unwrap(),
            leviculum_std::api::ProofBindingPolicy::ByCipher
        );
        assert_eq!(
            parse_cli_proof_binding_policy("hash").unwrap(),
            leviculum_std::api::ProofBindingPolicy::Explicit(
                leviculum_std::api::ProofBinding::PacketHash
            )
        );
        assert_eq!(
            parse_cli_proof_binding_policy("tag").unwrap(),
            leviculum_std::api::ProofBindingPolicy::Explicit(
                leviculum_std::api::ProofBinding::TokenTag
            )
        );
    }

    #[test]
    fn memory_log_is_bounded() {
        let sh = Shared::new();
        for i in 0..(LOG_MEM_MAX * 2 + 7) {
            sh.note(format!("строка {i}"));
        }
        let l = sh.log.lock().unwrap();
        assert!(l.len() <= LOG_MEM_MAX, "len {}", l.len());
        assert!(l.last().unwrap().1.ends_with(&format!("{}", LOG_MEM_MAX * 2 + 6)));
    }

    #[test]
    fn file_log_rotates_at_limit() {
        let dir = std::env::temp_dir().join(format!("knothop-log-test-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("log.txt");
        std::fs::write(&p, vec![b'x'; LOG_FILE_MAX as usize]).unwrap();
        append_log_sync(&p, "новая строка");
        let old = dir.join("log.txt.1");
        assert_eq!(std::fs::metadata(&old).unwrap().len(), LOG_FILE_MAX);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "новая строка\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn queued_log_lines_reach_the_file_in_order() {
        let dir = std::env::temp_dir().join(format!("knothop-log-queue-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("log.txt");
        append_log(&p, "первая");
        append_log(&p, "вторая");
        // поток журнала пишет асинхронно: ждём, пока вторая строка попадёт в файл
        for _ in 0..200 {
            if std::fs::read_to_string(&p).is_ok_and(|t| t.contains("вторая")) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "первая\nвторая\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn link_state_is_bounded() {
        let mut s = LinkSet::default();
        for i in 0..(LINK_STATE_MAX + 100) {
            s.insert(format!("{i:08x}"));
        }
        assert_eq!(s.set.len(), LINK_STATE_MAX);
        assert!(!s.contains(&format!("{:08x}", 0)));
        assert!(s.contains(&format!("{:08x}", LINK_STATE_MAX + 99)));

        let mut c = LinkClosedMap::default();
        for i in 0..(LINK_STATE_MAX + 100) {
            c.insert(format!("{i:08x}"), "x".into());
        }
        assert_eq!(c.map.len(), LINK_STATE_MAX);
        assert!(c.get(&format!("{:08x}", 0)).is_none());
    }

    #[test]
    fn slots_limit_per_ip_and_total() {
        let t: SlotsRef = Default::default();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let held: Vec<Slot> = (0..2).map(|_| Slot::take(&t, Some(a), 10, 2).unwrap()).collect();
        assert!(Slot::take(&t, Some(a), 10, 2).is_none());
        // релей без адреса считается только в общем лимите
        let relay = Slot::take(&t, None, 10, 2).unwrap();
        assert_eq!(t.lock().unwrap().live, 3);
        drop(held);
        drop(relay);
        let s = t.lock().unwrap();
        assert_eq!(s.live, 0);
        assert!(s.per_ip.is_empty());
    }
    // QAB-M5: поток магических датаграмм без разрешения не держит опрос источника дольше бюджета и не мешает настоящему пакету
    async fn dgram_pair() -> (Endpoint, Endpoint) {
        let mk = || async {
            Endpoint::builder(presets::Minimal)
                .secret_key(SecretKey::generate())
                .alpns(vec![b"rns/0".to_vec()])
                .relay_mode(RelayMode::Disabled)
                .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
                .unwrap()
                .bind()
                .await
                .unwrap()
        };
        (mk().await, mk().await)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn magic_flood_without_grant_is_bounded_per_poll_and_real_packet_still_arrives() {
        let (server, client) = dgram_pair().await;
        let port = server.bound_sockets()[0].port();
        let srv = server.clone();
        let accepted = tokio::spawn(async move { srv.accept().await.unwrap().await.unwrap() });
        let cconn = client.connect(EndpointAddr::new(server.id()).with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port))), b"rns/0").await.unwrap();
        let sconn = accepted.await.unwrap();
        let mut src = QuicDgramSource::new(sconn);

        let mut magic = qprobe::MAGIC.to_vec();
        magic.extend_from_slice(&[b'Q', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        magic.resize(40, 0);
        let sent = 200u64;
        for _ in 0..sent {
            let _ = cconn.send_datagram(bytes::Bytes::from(magic.clone()));
        }
        cconn.send_datagram(bytes::Bytes::from(vec![0x08u8; 64])).unwrap();

        // дать датаграммам дойти до очереди приёма
        tokio::time::sleep(Duration::from_millis(300)).await;

        // try_recv: за один вызов съедается не больше WORK_BUDGET магических датаграмм
        let mut real = None;
        for _ in 0..(sent as usize + 4) {
            let before = src.filter.seen;
            let r = src.try_recv();
            assert!(src.filter.seen - before <= qprobe::WORK_BUDGET as u64, "за вызов съедено {}", src.filter.seen - before);
            if let Some(r) = r {
                real = Some(r.unwrap());
                break;
            }
        }
        // остаток (если очередь приёма отбросила часть) доставляется через recv, который уступает исполнителю
        let got = match real {
            Some(b) => b,
            None => tokio::time::timeout(Duration::from_secs(3), src.recv()).await.expect("настоящий пакет не дошёл").unwrap(),
        };
        assert_eq!(got, vec![0x08u8; 64], "настоящий пакет не искажён и не потерян");
        assert!(src.filter.seen > 0, "магические датаграммы сняты фильтром");
        assert!(src.filter.dropped <= src.filter.seen, "отброшено не больше, чем снято");
        // эха нет: разрешения не выдавались
        let echoes = tokio::time::timeout(Duration::from_millis(300), cconn.read_datagram()).await;
        assert!(echoes.is_err(), "без разрешения эха нет");
        cconn.close(0u32.into(), b"done");
    }
}
