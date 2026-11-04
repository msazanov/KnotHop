//! Лабораторный мост REALITY: TCP <-> REALITY. Используется стендом (bench/reality/lab) вместо shoes; не часть knothopd.
//! keygen --out FILE | pub --key-file F | server ... | client ... | probe DEST SNI | ja4 SNI
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::time::Duration;

use knothop_reality::chello::{self, parse_hello};
use knothop_reality::client::{connect, ClientConfig};
use knothop_reality::profile::{build_hello, Profile};
use knothop_reality::server::{Accepted, Listener, Server, ServerConfig};
use knothop_reality::{kx, util};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter().position(|x| x == k).and_then(|i| a.get(i + 1).cloned())
}
fn flag(a: &[String], k: &str) -> bool {
    a.iter().any(|x| x == k)
}
fn must(a: &[String], k: &str) -> String {
    arg(a, k).unwrap_or_else(|| {
        eprintln!("нужен аргумент {k}");
        std::process::exit(2)
    })
}
fn key32(path: &str) -> [u8; 32] {
    let s = std::fs::read_to_string(path).expect("файл ключа");
    util::unhex(s.trim()).and_then(|v| v.try_into().ok()).expect("ключ: 64 hex-символа")
}
fn id8(s: &str) -> [u8; 8] {
    util::unhex(s).and_then(|v| v.try_into().ok()).expect("short_id: 16 hex-символов")
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("keygen") => {
            let out = must(&a, "--out");
            let k = util::random::<32>();
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&out).expect("создать файл ключа (не перезаписывается)");
            use std::io::Write;
            writeln!(f, "{}", util::hex(&k)).unwrap();
            println!("{}", util::hex(&kx::x25519_public(&k)));
        }
        Some("pub") => println!("{}", util::hex(&kx::x25519_public(&key32(&must(&a, "--key-file"))))),
        Some("ja4") => {
            let d = build_hello(&Profile::chrome155(), &a.get(2).cloned().unwrap_or("example.org".into()));
            let m = d.with_sid(&util::random::<32>());
            println!("{}", chello::ja4(&parse_hello(&m).unwrap()));
        }
        Some("probe") => {
            let r = knothop_reality::probe::probe_cover(&a[2], &a[3], &Profile::chrome155(), Duration::from_secs(10)).await;
            println!("{r:#?}");
        }
        Some("server") => server(&a).await,
        Some("client") => client(&a).await,
        _ => eprintln!("usage: reality-bridge keygen|pub|ja4|probe|server|client"),
    }
}

async fn server(a: &[String]) {
    let listen: SocketAddr = must(a, "--listen").parse().unwrap();
    let ids: Vec<[u8; 8]> = must(a, "--short-ids").split(',').map(id8).collect();
    let mut cfg = ServerConfig::new(key32(&must(a, "--key-file")), ids, must(a, "--dest"));
    cfg.server_names = vec![must(a, "--sni")];
    cfg.cn = cfg.server_names[0].clone();
    cfg.proxy_protocol = flag(a, "--proxy-protocol");
    cfg.allow_proxy_on_public = flag(a, "--allow-proxy-on-public");
    if let Some(n) = arg(a, "--proxy-trusted") {
        cfg.proxy_trusted = n.split(',').map(|x| knothop_reality::server::IpNet::parse(x).expect("сеть вида a.b.c.d/N")).collect();
    }
    if flag(a, "--no-h2") {
        cfg.mimic = knothop_reality::mimic::Mimic::disabled();
    }
    if let Some(p) = arg(a, "--pad-first") {
        cfg.padding.first_records = p.parse().unwrap();
    }
    let target = must(a, "--target");
    let srv = Server::new(cfg);
    if !flag(a, "--no-probe") {
        match srv.refresh_cover(&Profile::chrome155()).await {
            Ok(c) => eprintln!("cover: suite={:04x} group={:04x} alpn={:?} flight={:?} tickets={:?} ccs={}", c.suite, c.group, c.alpn.as_deref().map(String::from_utf8_lossy), c.flight, c.tickets, c.ccs),
            Err(e) => eprintln!("cover probe failed: {e}"),
        }
    }
    let mut l = Listener::bind(listen, srv.clone()).await.expect("bind");
    eprintln!("listening {}", l.local_addr());
    while let Some(ev) = l.accept().await {
        match ev {
            Accepted::Tunnel { mut stream, peer, .. } => {
                eprintln!("tunnel from {peer}");
                let target = target.clone();
                tokio::spawn(async move {
                    if let Ok(mut t) = TcpStream::connect(&target).await {
                        let _ = t.set_nodelay(true);
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut t).await;
                        let _ = t.shutdown().await;
                    }
                });
            }
            Accepted::Forwarded { peer, reason } => eprintln!("forwarded {peer}: {reason:?}"),
            Accepted::Dropped { peer, reason } => eprintln!("dropped {peer}: {reason:?}"),
        }
    }
}

async fn client(a: &[String]) {
    let listen = must(a, "--listen");
    let remote = must(a, "--connect");
    let pubkey: [u8; 32] = util::unhex(&must(a, "--pubkey")).and_then(|v| v.try_into().ok()).expect("pubkey");
    let mut cfg = ClientConfig::new(pubkey, id8(&must(a, "--short-id")), must(a, "--sni"));
    if flag(a, "--no-h2") {
        cfg.mimic = knothop_reality::mimic::Mimic::disabled();
    }
    if let Some(p) = arg(a, "--pad-first") {
        cfg.padding.first_records = p.parse().unwrap();
    }
    let cfg = Arc::new(cfg);
    let l = TcpListener::bind(&listen).await.expect("bind");
    eprintln!("client listening {listen} -> {remote}");
    loop {
        let Ok((mut local, _)) = l.accept().await else { continue };
        let (cfg, remote) = (cfg.clone(), remote.clone());
        tokio::spawn(async move {
            let _ = local.set_nodelay(true);
            let tcp = match TcpStream::connect(&remote).await {
                Ok(t) => t,
                Err(e) => return eprintln!("connect {remote}: {e}"),
            };
            let _ = tcp.set_nodelay(true);
            match connect(tcp, &cfg).await {
                Ok(mut s) => {
                    let _ = tokio::io::copy_bidirectional(&mut local, &mut s).await;
                }
                Err(e) => eprintln!("reality connect: {e}"),
            }
        });
    }
}
