//! Plain synthetic TCP workload for independent protocol comparators.
//! Same offset-dependent pattern as rns-iroh-node; no production data or keys.
use anyhow::{Result, bail};
use clap::Parser;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};
const ALPN: &[u8] = b"knothop/transport-bench/1";
trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
type Io = Box<dyn Duplex>;
type QuicHold = Option<(Endpoint, Connection)>;
struct QuicIo {
    send: SendStream,
    recv: RecvStream,
}
impl AsyncRead for QuicIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
impl AsyncWrite for QuicIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

#[derive(Parser)]
struct Args {
    #[arg(long, value_parser = ["server", "client", "forward"])]
    role: String,
    #[arg(long, default_value = "0.0.0.0")]
    ip: String,
    #[arg(long, default_value_t = 4241)]
    port: u16,
    #[arg(long)]
    peer: Option<String>,
    #[arg(long)]
    socks: Option<String>,
    #[arg(long, default_value = "/shared")]
    state: PathBuf,
    #[arg(long, default_value_t = 20)]
    duration: u64,
    #[arg(long, default_value_t = 0)]
    bytes: u64,
    #[arg(long, default_value_t = 64000)]
    chunk: usize,
    #[arg(long)]
    verify_sha: bool,
    #[arg(long, default_value = "tcp", value_parser = ["tcp", "iroh"])]
    transport: String,
    #[arg(long, default_value = "e")]
    quic_peer: String,
    /// Seconds of echo-only probing before `ready` (RTT of an unloaded path).
    #[arg(long, default_value_t = 3)]
    idle_secs: u64,
}

async fn endpoint(a: &Args, role: &str) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled);
    if role != "client" {
        builder = builder.bind_addr(format!("{}:3345", a.ip).parse::<SocketAddr>()?)?;
    }
    let endpoint = builder.bind().await?;
    if role != "client" {
        let name = if role == "forward" { "a" } else { "e" };
        save(
            a.state.join(format!("{name}.quic.json")),
            serde_json::json!({
            "id": endpoint.id().to_string(), "address": format!("{}:3345", a.ip)}),
        )?;
    }
    Ok(endpoint)
}

async fn quic_connect(endpoint: &Endpoint, a: &Args) -> Result<Connection> {
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(
        a.state.join(format!("{}.quic.json", a.quic_peer)),
    )?)?;
    let id: EndpointId = value["id"].as_str().unwrap().parse()?;
    let addr = EndpointAddr::new(id)
        .with_ip_addr(value["address"].as_str().unwrap().parse::<SocketAddr>()?);
    let connection = endpoint.connect(addr, ALPN).await?;
    eprintln!("QUIC connected to {}", a.quic_peer);
    Ok(connection)
}

async fn echo_server(mut socket: Io) {
    let mut packet = [0; 16];
    while socket.read_exact(&mut packet).await.is_ok() {
        if socket.write_all(&packet).await.is_err() {
            break;
        }
    }
}

async fn server_stream(a: &Args) -> Result<(Io, QuicHold)> {
    if a.transport == "iroh" {
        let endpoint = endpoint(a, "server").await?;
        std::fs::write(a.state.join("server-ready"), b"")?;
        let connection = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("QUIC accept stopped"))?
            .await?;
        let c = connection.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<Io>();
        tokio::spawn(async move {
            let mut tx = Some(tx);
            for _ in 0..2 {
                let Ok((send, recv)) = c.accept_bi().await else {
                    return;
                };
                let mut socket = QuicIo { send, recv };
                let Ok(kind) = socket.read_u8().await else {
                    return;
                };
                if kind == 0 {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(Box::new(socket));
                    }
                } else if kind == 1 {
                    tokio::spawn(echo_server(Box::new(socket)));
                }
            }
        });
        return Ok((rx.await?, Some((endpoint, connection))));
    }
    let data = TcpListener::bind(format!("{}:{}", a.ip, a.port)).await?;
    let echo = TcpListener::bind(format!("{}:{}", a.ip, a.port + 1)).await?;
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = echo.accept().await else {
                break;
            };
            let _ = socket.set_nodelay(true);
            tokio::spawn(echo_server(Box::new(socket)));
        }
    });
    std::fs::write(a.state.join("server-ready"), b"")?;
    let (socket, _) = data.accept().await?;
    socket.set_nodelay(true)?;
    Ok((Box::new(socket), None))
}

// Byte `o` of the stream is byte `o % 8` (little-endian) of `(o / 8) * K`.
// Producing a whole 8-byte word at a time keeps the generator and checker far
// below the cost of the transport under test: a per-byte loop here cost about
// as much CPU as a fast tunnel does and skewed 1-core client measurements.
const K: u64 = 0x9E37_79B9_7F4A_7C15;
fn word(o: u64) -> u64 {
    (o / 8).wrapping_mul(K)
}
fn pattern(buf: &mut [u8], off: u64) {
    let (mut o, mut i) = (off, 0);
    while i < buf.len() && o % 8 != 0 {
        buf[i] = (word(o) >> ((o % 8) * 8)) as u8;
        i += 1;
        o += 1;
    }
    let mut words = buf[i..].chunks_exact_mut(8);
    for chunk in &mut words {
        chunk.copy_from_slice(&word(o).to_le_bytes());
        o += 8;
    }
    for (j, b) in words.into_remainder().iter_mut().enumerate() {
        *b = (word(o) >> (j * 8)) as u8;
    }
}
fn check(buf: &[u8], off: u64) -> Option<u64> {
    let (mut o, mut i) = (off, 0);
    while i < buf.len() && o % 8 != 0 {
        if buf[i] != (word(o) >> ((o % 8) * 8)) as u8 {
            return Some(o);
        }
        i += 1;
        o += 1;
    }
    let mut words = buf[i..].chunks_exact(8);
    for chunk in &mut words {
        let expected = word(o).to_le_bytes();
        if chunk != expected {
            let j = chunk
                .iter()
                .zip(expected)
                .position(|(a, b)| *a != b)
                .unwrap();
            return Some(o + j as u64);
        }
        o += 8;
    }
    for (j, b) in words.remainder().iter().enumerate() {
        if *b != (word(o) >> (j * 8)) as u8 {
            return Some(o + j as u64);
        }
    }
    None
}
fn proc_mem_kb() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |key: &str| {
        status
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    (field("VmHWM:"), field("VmRSS:"))
}
async fn echo_roundtrip(echo: &mut Io, seq: u64) -> Result<f64> {
    let mut packet = [0u8; 16];
    packet[..8].copy_from_slice(b"KNOTECHO");
    packet[8..].copy_from_slice(&seq.to_le_bytes());
    let start = Instant::now();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        echo.write_all(&packet).await?;
        let mut response = [0u8; 16];
        echo.read_exact(&mut response).await?;
        if response != packet {
            bail!("echo mismatch");
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scalar(o: u64) -> u8 {
        ((o / 8).wrapping_mul(K) >> ((o % 8) * 8)) as u8
    }
    #[test]
    fn word_pattern_equals_the_per_byte_definition_at_every_alignment() {
        for off in [0u64, 1, 3, 7, 8, 9, 63999, 64000, 1 << 33] {
            for len in [0usize, 1, 2, 7, 8, 9, 15, 16, 17, 1000, 64000] {
                let mut buf = vec![0u8; len];
                pattern(&mut buf, off);
                for (i, b) in buf.iter().enumerate() {
                    assert_eq!(*b, scalar(off + i as u64), "off={off} len={len} i={i}");
                }
                assert_eq!(check(&buf, off), None);
                if len > 0 {
                    buf[len / 2] ^= 1;
                    assert_eq!(check(&buf, off), Some(off + (len / 2) as u64));
                }
            }
        }
    }
}
fn hash(h: Sha256) -> String {
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
fn save(path: PathBuf, value: serde_json::Value) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&value)?)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

async fn connect(a: &Args, port: u16) -> Result<TcpStream> {
    let target: SocketAddr = format!("{}:{port}", a.peer.as_ref().unwrap()).parse()?;
    let mut stream = TcpStream::connect(
        a.socks
            .as_deref()
            .map(str::to_owned)
            .unwrap_or_else(|| target.to_string()),
    )
    .await?;
    stream.set_nodelay(true)?;
    if a.socks.is_some() {
        stream.write_all(&[5, 1, 0]).await?;
        let mut response = [0; 2];
        stream.read_exact(&mut response).await?;
        if response != [5, 0] {
            bail!("SOCKS greeting rejected");
        }
        let std::net::IpAddr::V4(ip) = target.ip() else {
            bail!("benchmark requires IPv4");
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&ip.octets());
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await?;
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        if header[0] != 5 || header[1] != 0 {
            bail!("SOCKS CONNECT rejected: {}", header[1]);
        }
        let n = match header[3] {
            1 => 4,
            4 => 16,
            3 => stream.read_u8().await? as usize,
            _ => bail!("SOCKS address type"),
        };
        let mut tail = vec![0; n + 2];
        stream.read_exact(&mut tail).await?;
    }
    Ok(stream)
}

#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
    if a.chunk == 0 || a.chunk > 1 << 20 {
        bail!("invalid chunk");
    }
    if a.role == "forward" {
        if a.transport != "iroh" {
            bail!("forward requires iroh");
        }
        let endpoint = endpoint(&a, "forward").await?;
        let outgoing = quic_connect(&endpoint, &a).await?;
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("QUIC accept stopped"))?
            .await?;
        for _ in 0..2 {
            let (send, recv) = incoming.accept_bi().await?;
            let (out_send, out_recv) = outgoing.open_bi().await?;
            tokio::spawn(async move {
                let mut left = QuicIo { send, recv };
                let mut right = QuicIo {
                    send: out_send,
                    recv: out_recv,
                };
                let _ = tokio::io::copy_bidirectional(&mut left, &mut right).await;
            });
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    if a.role == "server" {
        let (mut socket, _quic_hold) = server_stream(&a).await?;
        eprintln!("bulk accepted");
        let mut hello = [0; 8];
        socket.read_exact(&mut hello).await?;
        if &hello != b"KNOTDATA" {
            bail!("invalid benchmark greeting");
        }
        socket.write_all(&[1]).await?;
        let mut received = 0u64;
        let mut mismatch = None;
        let mut digest = Sha256::new();
        let mut first = None;
        let mut last = Instant::now();
        loop {
            let len = socket.read_u32().await? as usize;
            if len == 0 {
                break;
            }
            if len > 1 << 20 {
                bail!("oversized record");
            }
            let mut buf = vec![0; len];
            socket.read_exact(&mut buf).await?;
            let now = Instant::now();
            first.get_or_insert(now);
            last = now;
            if mismatch.is_none() {
                mismatch = check(&buf, received);
            }
            if a.verify_sha {
                digest.update(&buf);
            }
            received += len as u64;
            if received / (64 << 20) != (received - len as u64) / (64 << 20) {
                eprintln!("received {received} bytes");
            }
        }
        let secs = first
            .map(|t| last.duration_since(t).as_secs_f64())
            .unwrap_or(0.0);
        save(
            a.state.join("server.json"),
            serde_json::json!({"bytes": received, "seconds": secs,
            "mismatch_at": mismatch, "sha256": if a.verify_sha { Some(hash(digest)) } else { None }}),
        )?;
        socket.write_all(&[1]).await?;
        // Remain available while the client finishes its final echo/report.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    let (mut data, mut echo, _quic_hold): (Io, Io, QuicHold) = if a.transport == "iroh" {
        let endpoint = endpoint(&a, "client").await?;
        let connection = quic_connect(&endpoint, &a).await?;
        let (send, recv) = connection.open_bi().await?;
        let mut data = QuicIo { send, recv };
        data.write_u8(0).await?;
        let (send, recv) = connection.open_bi().await?;
        let mut echo = QuicIo { send, recv };
        echo.write_u8(1).await?;
        (Box::new(data), Box::new(echo), Some((endpoint, connection)))
    } else {
        (
            Box::new(connect(&a, a.port).await?),
            Box::new(connect(&a, a.port + 1).await?),
            None,
        )
    };
    data.write_all(b"KNOTDATA").await?;
    if data.read_u8().await? != 1 {
        bail!("data warmup failed");
    }
    let hello = *b"KNOTECHO01234567";
    echo.write_all(&hello).await?;
    let mut reply = [0; 16];
    echo.read_exact(&mut reply).await?;
    if reply != hello {
        bail!("echo warmup failed");
    }
    // Unloaded-path RTT first, before the harness opens its measurement window,
    // so it costs neither CPU accounting nor throughput time.
    let mut idle = Vec::<f64>::new();
    let mut seq = 0u64;
    let idle_until = Instant::now() + std::time::Duration::from_secs(a.idle_secs);
    while Instant::now() < idle_until {
        idle.push(echo_roundtrip(&mut echo, seq).await?);
        seq += 1;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    std::fs::write(a.state.join("ready"), b"")?;
    while !a.state.join("go").exists() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let samples = Arc::new(Mutex::new(Vec::<f64>::new()));
    let timeouts = Arc::new(Mutex::new(0u64));
    let (s, t) = (samples.clone(), timeouts.clone());
    let echo_task = tokio::spawn(async move {
        loop {
            match echo_roundtrip(&mut echo, seq).await {
                Ok(ms) => s.lock().unwrap().push(ms),
                Err(_) => {
                    *t.lock().unwrap() += 1;
                    break;
                }
            }
            seq += 1;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });
    let mut sent = 0u64;
    let mut digest = Sha256::new();
    let mut record = vec![0; a.chunk + 4];
    let start = Instant::now();
    eprintln!("bulk go");
    while start.elapsed().as_secs() < a.duration && (a.bytes == 0 || sent < a.bytes) {
        let len = if a.bytes == 0 {
            a.chunk
        } else {
            (a.bytes - sent).min(a.chunk as u64) as usize
        };
        record[..4].copy_from_slice(&(len as u32).to_be_bytes());
        pattern(&mut record[4..4 + len], sent);
        data.write_all(&record[..4 + len]).await?;
        if a.verify_sha {
            digest.update(&record[4..4 + len]);
        }
        sent += len as u64;
        if sent / (64 << 20) != (sent - len as u64) / (64 << 20) {
            eprintln!("sent {sent} bytes");
        }
    }
    data.write_all(&[0; 4]).await?;
    eprintln!("bulk finished sending {sent} bytes; awaiting receipt");
    if data.read_u8().await? != 1 {
        bail!("missing final receipt");
    }
    let secs = start.elapsed().as_secs_f64();
    echo_task.abort();
    let _ = echo_task.await;
    let (hwm_kb, rss_kb) = proc_mem_kb();
    save(
        a.state.join("client.json"),
        serde_json::json!({"bytes": sent, "seconds": secs,
        "sha256": if a.verify_sha { Some(hash(digest)) } else { None },
        "echo_idle_rtt_ms": idle, "vm_hwm_kb": hwm_kb, "vm_rss_kb": rss_kb,
        "echo_rtt_ms": *samples.lock().unwrap(), "echo_timeouts": *timeouts.lock().unwrap()}),
    )?;
    Ok(())
}
