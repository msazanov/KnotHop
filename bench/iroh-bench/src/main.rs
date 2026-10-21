//! iroh-bench: измерение QUIC/iroh между двумя процессами.
//!
//! Что измеряется (всё через один двунаправленный QUIC-поток, как делает адаптер RNS->iroh):
//!   bulk-up   клиент отправляет N МиБ, сервер подтверждает итог (goodput по времени до подтверждения);
//!   bulk-down сервер отправляет N МиБ клиенту;
//!   echo      K запросов по 32 байта, RTT приложения;
//!   timed     непрерывная передача T секунд в выбранную сторону; приёмник пишет приём по 100 мс,
//!             выбранный путь (direct/relay) и проверяет целостность потока по детерминированному шаблону.
//!             Именно этот режим проверяет «поток пережил смену пути».
//!
//! Relay своей сети: `--relay http://host:3340` (iroh-relay --dev, обычный HTTP, только для локального стенда).
//! n0 (DNS, public relay, pkarr) не используется: preset Minimal, RelayMode::Custom/Disabled.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use iroh::endpoint::{Connection, QuicTransportConfig, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey};
use serde::{Deserialize, Serialize};

const ALPN: &[u8] = b"rawg/bench/0";
const CHUNK: usize = 64 * 1024;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Server {
        /// каталог обмена между процессами (server.json, результаты)
        #[arg(long, default_value = "/shared")]
        state: PathBuf,
        /// URL своего relay; "none" - relay отключён
        #[arg(long, default_value = "none")]
        relay: String,
        /// IPv4 адрес контейнера, который увидит клиент для прямого пути
        #[arg(long)]
        ip: String,
        #[arg(long, default_value_t = 4433)]
        port: u16,
        /// проверять целостность принятых данных (дороже по CPU)
        #[arg(long)]
        verify: bool,
        /// таймаут простоя пути, мс (по умолчанию iroh: 15000 для IP, 30000 для relay; больше нельзя)
        #[arg(long, default_value_t = 0)]
        path_idle_ms: u64,
        /// keep-alive пути, мс (по умолчанию iroh: 5000; больше нельзя)
        #[arg(long, default_value_t = 0)]
        path_keepalive_ms: u64,
    },
    Client {
        #[arg(long, default_value = "/shared")]
        state: PathBuf,
        #[arg(long, default_value = "none")]
        relay: String,
        /// bulk-up | bulk-down | echo | timed-up | timed-down
        #[arg(long)]
        mode: String,
        #[arg(long, default_value_t = 128)]
        mib: u64,
        #[arg(long, default_value_t = 200)]
        echo_n: u32,
        #[arg(long, default_value_t = 30)]
        secs: u64,
        /// не использовать прямые адреса сервера (только relay)
        #[arg(long)]
        relay_only: bool,
        #[arg(long)]
        verify: bool,
        /// метка результата
        #[arg(long, default_value = "run")]
        tag: String,
        #[arg(long, default_value_t = 0)]
        path_idle_ms: u64,
        #[arg(long, default_value_t = 0)]
        path_keepalive_ms: u64,
        /// вызывать Endpoint::network_change() каждые N мс (0 = не вызывать); так приложение
        /// Android сообщает iroh о смене сети, которую нативный код не видит сам
        #[arg(long, default_value_t = 0)]
        nc_ms: u64,
    },
    /// Серверная сторона моста: принимает QUIC-потоки iroh и соединяет каждый с локальным TCP-портом
    /// (там слушает RNS TCPServerInterface). RNS работает без изменений.
    BridgeServe {
        #[arg(long, default_value = "/shared")]
        state: PathBuf,
        #[arg(long, default_value = "none")]
        relay: String,
        #[arg(long)]
        ip: String,
        #[arg(long, default_value_t = 4433)]
        port: u16,
        /// локальный адрес RNS-сервера, например 127.0.0.1:4240
        #[arg(long)]
        tcp: String,
        #[arg(long, default_value_t = 0)]
        path_idle_ms: u64,
        #[arg(long, default_value_t = 0)]
        path_keepalive_ms: u64,
    },
    /// Клиентская сторона моста: слушает локальный TCP (туда подключается RNS TCPClientInterface)
    /// и пробрасывает каждое соединение в поток поверх ОДНОГО QUIC-соединения iroh.
    BridgeDial {
        #[arg(long, default_value = "/shared")]
        state: PathBuf,
        #[arg(long, default_value = "none")]
        relay: String,
        #[arg(long, default_value = "127.0.0.1:4240")]
        listen: String,
        #[arg(long)]
        relay_only: bool,
        #[arg(long, default_value_t = 0)]
        path_idle_ms: u64,
        #[arg(long, default_value_t = 0)]
        path_keepalive_ms: u64,
        #[arg(long, default_value_t = 0)]
        nc_ms: u64,
    },
}

fn unix_ms() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// Копирует байты между iroh-потоком и TCP в обе стороны, пока оба направления не завершатся.
async fn pump(mut send: iroh::endpoint::SendStream, mut recv: iroh::endpoint::RecvStream, tcp: tokio::net::TcpStream) {
    let (mut tr, mut tw) = tcp.into_split();
    let up = async { let r = tokio::io::copy(&mut tr, &mut send).await; let _ = send.finish(); r };
    let down = async { let r = tokio::io::copy(&mut recv, &mut tw).await; let _ = tokio::io::AsyncWriteExt::shutdown(&mut tw).await; r };
    let (a, b) = tokio::join!(up, down);
    eprintln!("[{}] pump finished up={:?} down={:?}", unix_ms(), a.map_err(|e| e.to_string()), b.map_err(|e| e.to_string()));
}

#[derive(Serialize, Deserialize)]
struct ServerInfo {
    id: String,
    relay: Option<String>,
    direct: String,
}

#[derive(Serialize, Default)]
struct Sample {
    t_ms: u64,
    bytes: u64,
    path: &'static str,
}

#[derive(Serialize, Default)]
struct RecvReport {
    total_bytes: u64,
    seconds: f64,
    integrity_ok: bool,
    first_mismatch_offset: Option<u64>,
    max_gap_ms: u64,
    /// самая длинная пауза внутри окна, когда приём прекращался (>=3 тиков по 100 мс подряд без байт)
    stall_windows: Vec<(u64, u64)>,
    path_changes: Vec<(u64, &'static str)>,
    samples: Vec<Sample>,
}

fn transport(idle_ms: u64, keepalive_ms: u64) -> Option<QuicTransportConfig> {
    if idle_ms == 0 && keepalive_ms == 0 {
        return None;
    }
    let mut b = QuicTransportConfig::builder();
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
    let url: RelayUrl = relay.parse().context("relay url")?;
    Ok(RelayMode::custom([url]))
}

/// Детерминированный шаблон: байт по абсолютному смещению.
fn fill(buf: &mut [u8], off: u64) {
    for (i, b) in buf.iter_mut().enumerate() {
        let o = off + i as u64;
        let word = (o / 8).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        *b = (word >> ((o % 8) * 8)) as u8;
    }
}

fn first_mismatch(buf: &[u8], off: u64) -> Option<u64> {
    let mut exp = vec![0u8; buf.len()];
    fill(&mut exp, off);
    buf.iter().zip(exp.iter()).position(|(a, b)| a != b).map(|p| off + p as u64)
}

fn path_kind(conn: &Connection) -> &'static str {
    let paths = conn.paths();
    for p in paths.iter() {
        if p.is_selected() {
            return if p.is_relay() { "relay" } else { "direct" };
        }
    }
    "none"
}

async fn read_report(
    mut recv: iroh::endpoint::RecvStream,
    conn: &Connection,
    verify: bool,
    limit_secs: Option<u64>,
) -> Result<RecvReport> {
    let start = Instant::now();
    let mut rep = RecvReport { integrity_ok: true, ..Default::default() };
    let mut buf = vec![0u8; CHUNK];
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_total = 0u64;
    let mut last_path = "";
    let mut zero_run = 0u64;
    let mut run_start = 0u64;
    loop {
        tokio::select! {
            r = recv.read(&mut buf) => {
                match r? {
                    Some(n) => {
                        if verify && rep.first_mismatch_offset.is_none() {
                            if let Some(m) = first_mismatch(&buf[..n], rep.total_bytes) {
                                rep.integrity_ok = false;
                                rep.first_mismatch_offset = Some(m);
                            }
                        }
                        rep.total_bytes += n as u64;
                    }
                    None => break,
                }
            }
            _ = tick.tick() => {
                let t = start.elapsed().as_millis() as u64;
                let p = path_kind(conn);
                if p != last_path {
                    rep.path_changes.push((t, p));
                    last_path = p;
                }
                let delta = rep.total_bytes - last_total;
                last_total = rep.total_bytes;
                if delta == 0 {
                    if zero_run == 0 { run_start = t; }
                    zero_run += 1;
                    if zero_run * 100 > rep.max_gap_ms { rep.max_gap_ms = zero_run * 100; }
                } else {
                    if zero_run >= 3 { rep.stall_windows.push((run_start, zero_run * 100)); }
                    zero_run = 0;
                }
                rep.samples.push(Sample { t_ms: t, bytes: delta, path: p });
                if let Some(l) = limit_secs { if t > (l + 15) * 1000 { bail!("receive timeout"); } }
            }
        }
    }
    if zero_run >= 3 { rep.stall_windows.push((run_start, zero_run * 100)); }
    rep.seconds = start.elapsed().as_secs_f64();
    Ok(rep)
}

async fn send_pattern(
    send: &mut iroh::endpoint::SendStream,
    total: Option<u64>,
    secs: Option<u64>,
) -> Result<u64> {
    let start = Instant::now();
    let mut off = 0u64;
    let mut buf = vec![0u8; CHUNK];
    loop {
        if let Some(t) = total { if off >= t { break; } }
        if let Some(s) = secs { if start.elapsed().as_secs() >= s { break; } }
        let n = match total { Some(t) => ((t - off).min(CHUNK as u64)) as usize, None => CHUNK };
        fill(&mut buf[..n], off);
        send.write_all(&buf[..n]).await?;
        off += n as u64;
    }
    Ok(off)
}

async fn serve_conn(conn: Connection, verify: bool, state: PathBuf) -> Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut hdr = [0u8; 17];
    recv.read_exact(&mut hdr).await?;
    let mode = hdr[0];
    let a = u64::from_le_bytes(hdr[1..9].try_into()?);
    let b = u64::from_le_bytes(hdr[9..17].try_into()?);
    match mode {
        // 0: приём N байт, ответ - принятый размер
        0 => {
            let mut total = 0u64;
            let mut buf = vec![0u8; CHUNK];
            while let Some(n) = recv.read(&mut buf).await? { total += n as u64; }
            send.write_all(&total.to_le_bytes()).await?;
            send.finish()?;
            conn.closed().await;
        }
        // 1: отправить N байт клиенту
        1 => {
            send_pattern(&mut send, Some(a), None).await?;
            send.finish()?;
            conn.closed().await;
        }
        // 2: echo, a сообщений по 32 байта
        2 => {
            let mut m = [0u8; 32];
            for _ in 0..a {
                recv.read_exact(&mut m).await?;
                send.write_all(&m).await?;
            }
            send.finish()?;
            conn.closed().await;
        }
        // 3: timed-up - приём с отчётом
        3 => {
            let rep = read_report(recv, &conn, verify, Some(b)).await?;
            std::fs::write(state.join("server-report.json"), serde_json::to_vec_pretty(&rep)?)?;
            send.write_all(&rep.total_bytes.to_le_bytes()).await?;
            send.finish()?;
            conn.closed().await;
        }
        // 4: timed-down - отправка a секунд
        4 => {
            let sent = send_pattern(&mut send, None, Some(a)).await?;
            send.finish()?;
            std::fs::write(state.join("server-sent.json"), serde_json::to_vec(&sent)?)?;
            conn.closed().await;
        }
        _ => bail!("unknown mode {mode}"),
    }
    Ok(())
}

fn header(mode: u8, a: u64, b: u64) -> [u8; 17] {
    let mut h = [0u8; 17];
    h[0] = mode;
    h[1..9].copy_from_slice(&a.to_le_bytes());
    h[9..17].copy_from_slice(&b.to_le_bytes());
    h
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Server { state, relay, ip, port, verify, path_idle_ms, path_keepalive_ms } => {
            let key = SecretKey::generate();
            let mut eb = Endpoint::builder(presets::Minimal)
                .secret_key(key)
                .alpns(vec![ALPN.to_vec()])
                .relay_mode(relay_mode(&relay)?)
                .bind_addr(SocketAddr::from(([0, 0, 0, 0], port)))?;
            if let Some(tc) = transport(path_idle_ms, path_keepalive_ms) { eb = eb.transport_config(tc); }
            let ep = eb.bind().await?;
            if relay != "none" {
                tokio::time::timeout(Duration::from_secs(20), ep.online()).await.context("relay not reachable")?;
            }
            let info = ServerInfo {
                id: ep.id().to_string(),
                relay: if relay == "none" { None } else { Some(relay.clone()) },
                direct: format!("{ip}:{port}"),
            };
            std::fs::write(state.join("server.json"), serde_json::to_vec(&info)?)?;
            println!("server ready id={} direct={} relay={}", info.id, info.direct, relay);
            while let Some(incoming) = ep.accept().await {
                let state = state.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            if let Err(e) = serve_conn(conn, verify, state).await { eprintln!("conn error: {e:#}"); }
                        }
                        Err(e) => eprintln!("accept error: {e:#}"),
                    }
                });
            }
        }
        Cmd::BridgeServe { state, relay, ip, port, tcp, path_idle_ms, path_keepalive_ms } => {
            let mut eb = Endpoint::builder(presets::Minimal)
                .secret_key(SecretKey::generate())
                .alpns(vec![ALPN.to_vec()])
                .relay_mode(relay_mode(&relay)?)
                .bind_addr(SocketAddr::from(([0, 0, 0, 0], port)))?;
            if let Some(tc) = transport(path_idle_ms, path_keepalive_ms) { eb = eb.transport_config(tc); }
            let ep = eb.bind().await?;
            if relay != "none" {
                tokio::time::timeout(Duration::from_secs(20), ep.online()).await.context("relay not reachable")?;
            }
            let info = ServerInfo {
                id: ep.id().to_string(),
                relay: if relay == "none" { None } else { Some(relay.clone()) },
                direct: format!("{ip}:{port}"),
            };
            std::fs::write(state.join("bridge.json"), serde_json::to_vec(&info)?)?;
            println!("bridge-serve ready id={} tcp={}", info.id, tcp);
            while let Some(incoming) = ep.accept().await {
                let tcp = tcp.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    eprintln!("[{}] quic connection accepted", unix_ms());
                    loop {
                        let Ok((send, recv)) = conn.accept_bi().await else { break };
                        let tcp = tcp.clone();
                        tokio::spawn(async move {
                            let mut stream = None;
                            for _ in 0..100 {
                                if let Ok(s) = tokio::net::TcpStream::connect(&tcp).await { stream = Some(s); break; }
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                            match stream {
                                Some(s) => { let _ = s.set_nodelay(true); pump(send, recv, s).await }
                                None => eprintln!("local RNS server not reachable at {tcp}"),
                            }
                        });
                    }
                    eprintln!("[{}] quic connection ended", unix_ms());
                });
            }
        }
        Cmd::BridgeDial { state, relay, listen, relay_only, path_idle_ms, path_keepalive_ms, nc_ms } => {
            let info: ServerInfo = loop {
                if let Ok(b) = std::fs::read(state.join("bridge.json")) {
                    if let Ok(i) = serde_json::from_slice(&b) { break i; }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            let id: EndpointId = info.id.parse().context("endpoint id")?;
            let mut addr = EndpointAddr::new(id);
            if !relay_only { addr = addr.with_ip_addr(info.direct.parse()?); }
            if relay != "none" { addr = addr.with_relay_url(relay.parse()?); }
            let mut eb = Endpoint::builder(presets::Minimal).relay_mode(relay_mode(&relay)?);
            if let Some(tc) = transport(path_idle_ms, path_keepalive_ms) { eb = eb.transport_config(tc); }
            let ep = eb.bind().await?;
            if relay != "none" {
                tokio::time::timeout(Duration::from_secs(20), ep.online()).await.context("relay not reachable")?;
            }
            if nc_ms > 0 {
                let ep2 = ep.clone();
                tokio::spawn(async move { loop { tokio::time::sleep(Duration::from_millis(nc_ms)).await; ep2.network_change().await; } });
            }
            let conn = ep.connect(addr.clone(), ALPN).await?;
            eprintln!("[{}] quic connected", unix_ms());
            // журнал смены выбранного пути (unix-время в мс) - для сопоставления с событиями оркестратора
            let c2 = conn.clone();
            let plog = state.join("bridge-path.log");
            tokio::spawn(async move {
                let mut last = "";
                loop {
                    let k = path_kind(&c2);
                    if k != last {
                        last = k;
                        let line = format!("{} {}\n", unix_ms(), k);
                        let _ = std::fs::OpenOptions::new().create(true).append(true).open(&plog)
                            .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            println!("bridge-dial listening on {listen}");
            let mut conn = conn;
            loop {
                let (tcp, _) = listener.accept().await?;
                let _ = tcp.set_nodelay(true);
                eprintln!("[{}] local RNS connected", unix_ms());
                let (send, recv) = match conn.open_bi().await {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("[{}] open_bi failed ({e}); reconnecting", unix_ms());
                        conn = ep.connect(addr.clone(), ALPN).await?;
                        conn.open_bi().await?
                    }
                };
                tokio::spawn(pump(send, recv, tcp));
            }
        }
        Cmd::Client { state, relay, mode, mib, echo_n, secs, relay_only, verify, tag, path_idle_ms, path_keepalive_ms, nc_ms } => {
            let info: ServerInfo = serde_json::from_slice(&std::fs::read(state.join("server.json"))?)?;
            let id: EndpointId = info.id.parse().context("endpoint id")?;
            let mut addr = EndpointAddr::new(id);
            if !relay_only {
                addr = addr.with_ip_addr(info.direct.parse()?);
            }
            if relay != "none" {
                addr = addr.with_relay_url(relay.parse()?);
            }
            let mut eb = Endpoint::builder(presets::Minimal).relay_mode(relay_mode(&relay)?);
            if let Some(tc) = transport(path_idle_ms, path_keepalive_ms) { eb = eb.transport_config(tc); }
            let ep = eb.bind().await?;
            if relay != "none" {
                tokio::time::timeout(Duration::from_secs(20), ep.online()).await.context("relay not reachable")?;
            }
            if nc_ms > 0 {
                let ep2 = ep.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(nc_ms)).await;
                        ep2.network_change().await;
                    }
                });
            }
            let t_conn = Instant::now();
            let conn = ep.connect(addr, ALPN).await?;
            let connect_ms = t_conn.elapsed().as_secs_f64() * 1000.0;
            let (mut send, mut recv) = conn.open_bi().await?;
            let mut out = serde_json::json!({"tag": tag, "mode": mode, "connect_ms": connect_ms});
            match mode.as_str() {
                "bulk-up" => {
                    let total = mib * 1024 * 1024;
                    send.write_all(&header(0, total, 0)).await?;
                    let t0 = Instant::now();
                    send_pattern(&mut send, Some(total), None).await?;
                    send.finish()?;
                    let mut ack = [0u8; 8];
                    recv.read_exact(&mut ack).await?;
                    let dt = t0.elapsed().as_secs_f64();
                    let got = u64::from_le_bytes(ack);
                    out["seconds"] = dt.into();
                    out["bytes_acked"] = got.into();
                    out["mib_s"] = (total as f64 / 1048576.0 / dt).into();
                    out["ok"] = (got == total).into();
                }
                "bulk-down" => {
                    let total = mib * 1024 * 1024;
                    send.write_all(&header(1, total, 0)).await?;
                    send.finish()?;
                    let t0 = Instant::now();
                    let mut n_total = 0u64;
                    let mut buf = vec![0u8; CHUNK];
                    while let Some(n) = recv.read(&mut buf).await? { n_total += n as u64; }
                    let dt = t0.elapsed().as_secs_f64();
                    out["seconds"] = dt.into();
                    out["bytes"] = n_total.into();
                    out["mib_s"] = (n_total as f64 / 1048576.0 / dt).into();
                    out["ok"] = (n_total == total).into();
                }
                "echo" => {
                    send.write_all(&header(2, echo_n as u64, 0)).await?;
                    let mut rtts = Vec::new();
                    let mut m = [7u8; 32];
                    let mut r = [0u8; 32];
                    for i in 0..echo_n {
                        m[0] = i as u8;
                        let t = Instant::now();
                        send.write_all(&m).await?;
                        recv.read_exact(&mut r).await?;
                        rtts.push(t.elapsed().as_secs_f64() * 1000.0);
                    }
                    rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
                    let q = |p: f64| rtts[((rtts.len() - 1) as f64 * p) as usize];
                    out["rtt_ms"] = serde_json::json!({"p50": q(0.5), "p95": q(0.95), "min": rtts[0], "max": rtts[rtts.len()-1], "n": rtts.len()});
                    out["ok"] = true.into();
                    send.finish()?;
                }
                "timed-up" => {
                    send.write_all(&header(3, 0, secs)).await?;
                    let sent = send_pattern(&mut send, None, Some(secs)).await;
                    match sent {
                        Ok(n) => {
                            send.finish()?;
                            let mut ack = [0u8; 8];
                            let r = tokio::time::timeout(Duration::from_secs(30), recv.read_exact(&mut ack)).await;
                            out["bytes_sent"] = n.into();
                            out["ack"] = match r { Ok(Ok(())) => u64::from_le_bytes(ack).into(), _ => serde_json::Value::Null };
                            out["ok"] = matches!(r, Ok(Ok(()))).into();
                        }
                        Err(e) => { out["ok"] = false.into(); out["error"] = format!("{e:#}").into(); }
                    }
                }
                "timed-down" => {
                    send.write_all(&header(4, secs, 0)).await?;
                    send.finish()?;
                    let rep = read_report(recv, &conn, verify, Some(secs)).await;
                    match rep {
                        Ok(r) => { out["ok"] = r.integrity_ok.into(); out["report"] = serde_json::to_value(&r)?; }
                        Err(e) => { out["ok"] = false.into(); out["error"] = format!("{e:#}").into(); }
                    }
                }
                m => bail!("unknown mode {m}"),
            }
            let paths: Vec<String> = conn.paths().iter().map(|p| format!("{:?} selected={} rtt={:?}", p.remote_addr(), p.is_selected(), p.rtt())).collect();
            out["final_paths"] = paths.into();
            let st = conn.stats();
            out["udp_tx_bytes"] = st.udp_tx.bytes.into();
            out["udp_rx_bytes"] = st.udp_rx.bytes.into();
            std::fs::write(state.join(format!("client-{tag}.json")), serde_json::to_vec_pretty(&out)?)?;
            println!("{}", serde_json::to_string(&out)?);
            conn.close(0u32.into(), b"done");
            ep.close().await;
        }
    }
    Ok(())
}
