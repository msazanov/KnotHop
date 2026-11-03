//! PoC стенд: два endpoint iroh, соединение по custom-адресу (TCP-носитель за REALITY) либо по прямому UDP для сравнения.
mod carrier;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use iroh::endpoint::{presets, Connection, QuicTransportConfig};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr};

const ALPN: &[u8] = b"rpoc/0";

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter().position(|x| x == k).and_then(|i| a.get(i + 1).cloned())
}

fn cpu_secs() -> f64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let f: Vec<&str> = s.rsplit(')').next().unwrap_or("").split_whitespace().collect();
    let ut: f64 = f.get(11).and_then(|x| x.parse().ok()).unwrap_or(0.0);
    let st: f64 = f.get(12).and_then(|x| x.parse().ok()).unwrap_or(0.0);
    (ut + st) / 100.0
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn tcfg() -> QuicTransportConfig {
    QuicTransportConfig::builder().datagram_send_buffer_size(8 << 20).datagram_receive_buffer_size(Some(8 << 20)).build()
}

#[derive(Default)]
struct SrvStats {
    d_rx: AtomicU64,
    d_max: AtomicU64,
    d_bytes: AtomicU64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if let Some(c) = arg(&a, "--cap") {
        let c: u16 = c.parse()?;
        if c > 0 {
            iroh::knothop::set_custom_path_max_udp(c);
        }
    }
    match a.get(1).map(|s| s.as_str()) {
        Some("srv") => srv(&a).await,
        Some("cli") => cli(&a).await,
        _ => bail!("usage: reality-poc srv|cli ..."),
    }
}

async fn srv(a: &[String]) -> Result<()> {
    let carrier = arg(a, "--carrier-listen").map(|x| carrier::Carrier::start(carrier::Role::Listen(x.parse().unwrap())));
    let mut b = Endpoint::builder(presets::Minimal).secret_key(SecretKey::generate()).alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled).transport_config(tcfg());
    if let Some(p) = arg(a, "--udp") {
        b = b.bind_addr(SocketAddr::from(([0, 0, 0, 0], p.parse::<u16>()?)))?;
    }
    if let Some(c) = &carrier {
        b = b.add_custom_transport(Arc::new(c.clone()));
    }
    let ep = b.bind().await?;
    let id = hex(ep.id().as_bytes());
    if let Some(f) = arg(a, "--id-file") {
        std::fs::write(f, &id)?;
    }
    eprintln!("srv: endpoint id {id}");
    let st = Arc::new(SrvStats::default());
    while let Some(inc) = ep.accept().await {
        let st = st.clone();
        tokio::spawn(async move {
            let Ok(acc) = inc.accept() else { return };
            let Ok(conn) = acc.await else { return };
            eprintln!("srv: connection from {:?}", conn.paths().iter().map(|p| format!("{:?}", p.remote_addr())).collect::<Vec<_>>());
            let c2 = conn.clone();
            let st2 = st.clone();
            tokio::spawn(async move {
                while let Ok(d) = c2.read_datagram().await {
                    match d.first() {
                        Some(b'P') => {
                            let _ = c2.send_datagram(d);
                        }
                        Some(b'D') if d.len() >= 9 => {
                            let seq = u64::from_be_bytes(d[1..9].try_into().unwrap());
                            st2.d_rx.fetch_add(1, Relaxed);
                            st2.d_max.fetch_max(seq + 1, Relaxed);
                            st2.d_bytes.fetch_add(d.len() as u64, Relaxed);
                        }
                        _ => {}
                    }
                }
            });
            while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
                let st = st.clone();
                tokio::spawn(async move {
                    let mut cmd = [0u8; 1];
                    if rx.read_exact(&mut cmd).await.is_err() {
                        return;
                    }
                    match cmd[0] {
                        b'U' => {
                            let t0 = Instant::now();
                            let mut n = 0u64;
                            let mut buf = vec![0u8; 256 * 1024];
                            while let Ok(Some(k)) = rx.read(&mut buf).await {
                                n += k as u64;
                            }
                            let _ = tx.write_all(format!("{n} {}", t0.elapsed().as_millis()).as_bytes()).await;
                            let _ = tx.finish();
                        }
                        b'W' => {
                            let mut s = [0u8; 4];
                            if rx.read_exact(&mut s).await.is_err() {
                                return;
                            }
                            let secs = u32::from_be_bytes(s);
                            let buf = vec![0xA5u8; 64 * 1024];
                            let t0 = Instant::now();
                            while t0.elapsed() < Duration::from_secs(secs as u64) {
                                if tx.write_all(&buf).await.is_err() {
                                    return;
                                }
                            }
                            let _ = tx.finish();
                            let _ = tx.stopped().await;
                        }
                        b'R' => {
                            st.d_rx.store(0, Relaxed);
                            st.d_max.store(0, Relaxed);
                            st.d_bytes.store(0, Relaxed);
                            let _ = tx.write_all(b"ok").await;
                            let _ = tx.finish();
                            let _ = tx.stopped().await;
                        }
                        b'S' => {
                            let _ = tx.write_all(format!("{} {} {}", st.d_rx.load(Relaxed), st.d_max.load(Relaxed), st.d_bytes.load(Relaxed)).as_bytes()).await;
                            let _ = tx.finish();
                            let _ = tx.stopped().await;
                        }
                        _ => {}
                    }
                });
            }
        });
    }
    Ok(())
}

async fn ctl(conn: &Connection, c: u8) -> Result<String> {
    let (mut tx, mut rx) = conn.open_bi().await?;
    tx.write_all(&[c]).await?;
    tx.finish()?;
    let v = rx.read_to_end(1024).await?;
    Ok(String::from_utf8_lossy(&v).into())
}

fn pctl(v: &mut Vec<f64>, p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 - 1.0) * p) as usize]
}

fn path_desc(conn: &Connection) -> String {
    conn.paths().iter().map(|p| format!("{}{:?}", if p.is_selected() { "*" } else { "" }, p.remote_addr())).collect::<Vec<_>>().join(",")
}

async fn dgram_load(conn: Connection, mbit: f64, size: usize, secs: f64) -> (u64, u64) {
    let (mut sent, mut err) = (0u64, 0u64);
    let t0 = Instant::now();
    let pps = mbit * 1e6 / 8.0 / size as f64;
    let mut seq = 0u64;
    while t0.elapsed().as_secs_f64() < secs {
        let due = (t0.elapsed().as_secs_f64() * pps) as u64;
        while seq < due {
            let mut b = vec![0u8; size];
            b[0] = b'D';
            b[1..9].copy_from_slice(&seq.to_be_bytes());
            match conn.send_datagram(Bytes::from(b)) {
                Ok(()) => sent += 1,
                Err(_) => err += 1,
            }
            seq += 1;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    (sent, err)
}

async fn cli(a: &[String]) -> Result<()> {
    let via = arg(a, "--via").context("--via custom:ADDR|udp:HOST:PORT")?;
    let id = EndpointId::from_bytes(&unhex(&arg(a, "--id").context("--id")?).try_into().map_err(|_| anyhow::anyhow!("id len"))?)?;
    let mut b = Endpoint::builder(presets::Minimal).secret_key(SecretKey::generate()).alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled).transport_config(tcfg());
    let addr;
    if let Some(c) = via.strip_prefix("custom:") {
        let car = carrier::Carrier::start(carrier::Role::Connect(c.parse()?));
        b = b.add_custom_transport(Arc::new(car)).clear_ip_transports();
        addr = EndpointAddr::from_parts(id, [TransportAddr::Custom(carrier::addr(0))]);
    } else if let Some(u) = via.strip_prefix("udp:") {
        addr = EndpointAddr::from_parts(id, [TransportAddr::Ip(u.parse()?)]);
    } else {
        bail!("bad --via");
    }
    let ep = b.bind().await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let t0 = Instant::now();
    let conn = tokio::time::timeout(Duration::from_secs(15), ep.connect(addr, ALPN)).await.context("connect timeout")??;
    println!("connected in {} ms; paths {}", t0.elapsed().as_millis(), path_desc(&conn));
    let secs: f64 = arg(a, "--secs").map(|s| s.parse().unwrap()).unwrap_or(10.0);
    let size: usize = arg(a, "--size").map(|s| s.parse().unwrap()).unwrap_or(1328);
    let test = arg(a, "--test").unwrap_or("rtt".into());
    // прогрев: MTUD
    for _ in 0..30 {
        let _ = conn.send_datagram(Bytes::from_static(b"P-warm"));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!("max_datagram_size={:?} path={}", conn.max_datagram_size(), path_desc(&conn));
    let c0 = cpu_secs();
    let w0 = Instant::now();
    match test.as_str() {
        "rtt" => {
            let bg: f64 = arg(a, "--bg-mbit").map(|s| s.parse().unwrap()).unwrap_or(0.0);
            let n = (secs * 20.0) as u64;
            let base = Instant::now();
            let rtts = Arc::new(std::sync::Mutex::new(Vec::<f64>::new()));
            let (c2, r2) = (conn.clone(), rtts.clone());
            let rd = tokio::spawn(async move {
                while let Ok(d) = c2.read_datagram().await {
                    if d.first() == Some(&b'P') && d.len() >= 9 {
                        let t = u64::from_be_bytes(d[1..9].try_into().unwrap());
                        r2.lock().unwrap().push((base.elapsed().as_nanos() as u64 - t) as f64 / 1e6);
                    }
                }
            });
            let bgt = if bg > 0.0 { Some(tokio::spawn(dgram_load(conn.clone(), bg, size, secs))) } else { None };
            for _ in 0..n {
                let mut b = vec![0u8; 100];
                b[0] = b'P';
                b[1..9].copy_from_slice(&(base.elapsed().as_nanos() as u64).to_be_bytes());
                let _ = conn.send_datagram(Bytes::from(b));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if let Some(t) = bgt {
                let _ = t.await;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            rd.abort();
            let mut v = rtts.lock().unwrap().clone();
            let got = v.len();
            println!("rtt: sent={n} got={got} loss={:.1}% p50={:.1} p95={:.1} p99={:.1} max={:.1} ms (bg {bg} Mbit/s)", 100.0 * (n as f64 - got as f64) / n as f64, pctl(&mut v, 0.5), pctl(&mut v, 0.95), pctl(&mut v, 0.99), pctl(&mut v, 1.0));
        }
        "dgram" => {
            let mbit: f64 = arg(a, "--rate-mbit").map(|s| s.parse().unwrap()).unwrap_or(20.0);
            ctl(&conn, b'R').await?;
            let (sent, err) = dgram_load(conn.clone(), mbit, size, secs).await;
            tokio::time::sleep(Duration::from_secs(3)).await;
            let s = ctl(&conn, b'S').await?;
            let f: Vec<u64> = s.split_whitespace().map(|x| x.parse().unwrap()).collect();
            println!("dgram: offered {mbit} Mbit/s size {size}: sent={sent} send_err={err} server_rx={} ({:.2} Mbit/s goodput) loss={:.2}%", f[0], f[2] as f64 * 8.0 / secs / 1e6, 100.0 * (sent as f64 - f[0] as f64) / sent as f64);
        }
        "up" => {
            let (mut tx, mut rx) = conn.open_bi().await?;
            tx.write_all(b"U").await?;
            let buf = vec![0x5Au8; 64 * 1024];
            let t = Instant::now();
            while t.elapsed().as_secs_f64() < secs {
                tx.write_all(&buf).await?;
            }
            tx.finish()?;
            let r = String::from_utf8_lossy(&rx.read_to_end(1024).await?).to_string();
            let f: Vec<u64> = r.split_whitespace().map(|x| x.parse().unwrap()).collect();
            println!("stream-up: {} bytes in {} ms = {:.1} Mbit/s", f[0], f[1], f[0] as f64 * 8.0 / (f[1] as f64 / 1000.0) / 1e6);
        }
        "down" => {
            let (mut tx, mut rx) = conn.open_bi().await?;
            tx.write_all(b"W").await?;
            tx.write_all(&(secs as u32).to_be_bytes()).await?;
            tx.finish()?;
            let mut buf = vec![0u8; 256 * 1024];
            let (mut n, t) = (0u64, Instant::now());
            while let Some(k) = rx.read(&mut buf).await? {
                n += k as u64;
            }
            println!("stream-down: {} bytes in {} ms = {:.1} Mbit/s", n, t.elapsed().as_millis(), n as f64 * 8.0 / t.elapsed().as_secs_f64() / 1e6);
        }
        _ => bail!("unknown test"),
    }
    let st = conn.stats();
    println!("cpu_client={:.2}s wall={:.1}s udp_tx={} udp_rx={} path_end={} max_datagram_size={:?}", cpu_secs() - c0, w0.elapsed().as_secs_f64(), st.udp_tx.datagrams, st.udp_rx.datagrams, path_desc(&conn), conn.max_datagram_size());
    conn.close(0u32.into(), b"done");
    ep.close().await;
    Ok(())
}
