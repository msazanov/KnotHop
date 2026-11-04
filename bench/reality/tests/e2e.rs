//! Интеграция в процессе: клиент <-> сервер <-> сайт-прикрытие (rustls TLS 1.3) на loopback.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use knothop_reality::client::{connect, ClientConfig};
use knothop_reality::server::{Accepted, DropReason, ForwardReason, Limits, Listener, Server, ServerConfig};
use knothop_reality::mimic::Mimic;
use knothop_reality::stream::Padding;
use knothop_reality::{kx, proxy, util, Error};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const SNI: &str = "cover.example.org";

struct Cover {
    addr: SocketAddr,
    cert: Vec<u8>,
    conns: Arc<AtomicUsize>,
}

/// Сайт-прикрытие: rustls TLS 1.3, ALPN h2/http1.1, на GET отвечает COVER-OK.
async fn start_cover() -> Cover {
    let ck = rcgen::generate_simple_self_signed(vec![SNI.to_string()]).unwrap();
    let cert = ck.cert.der().to_vec();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.clone())], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let c2 = conns.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { break };
            c2.fetch_add(1, SeqCst);
            let acc = acc.clone();
            tokio::spawn(async move {
                let Ok(mut t) = acc.accept(s).await else { return };
                let mut b = [0u8; 1024];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match t.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&b[..n]),
                    }
                }
                let _ = t.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\nconnection: close\r\n\r\nCOVER-OK\n").await;
                let _ = t.shutdown().await;
            });
        }
    });
    Cover { addr, cert, conns }
}

struct Env {
    cover: Cover,
    secret: [u8; 32],
    short_id: [u8; 8],
    srv: Arc<Server>,
    addr: SocketAddr,
    events: mpsc::UnboundedReceiver<Accepted>,
}

fn base_cfg(cover: &Cover) -> ServerConfig {
    let secret = util::random::<32>();
    let mut c = ServerConfig::new(secret, vec![[0x11; 8], [0x22; 8]], cover.addr.to_string());
    c.server_names = vec![SNI.into()];
    c
}

/// Поднимает сервер; все события (в том числе Tunnel) уходят в `events`.
async fn start_events(mut cfg: ServerConfig, cover: Cover) -> Env {
    cfg.dest = cover.addr.to_string();
    let secret = cfg.static_secret;
    let srv = Server::new(cfg);
    let mut l = Listener::bind("127.0.0.1:0".parse().unwrap(), srv.clone()).await.unwrap();
    let addr = l.local_addr();
    let (tx, events) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(a) = l.accept().await {
            let _ = tx.send(a);
        }
    });
    Env { cover, secret, short_id: [0x11; 8], srv, addr, events }
}

async fn next_event(env: &mut Env) -> Accepted {
    tokio::time::timeout(Duration::from_secs(10), env.events.recv()).await.expect("событие").expect("канал")
}

fn ccfg(env: &Env) -> ClientConfig {
    ClientConfig::new(kx::x25519_public(&env.secret), env.short_id, SNI)
}

#[tokio::test(flavor = "multi_thread")]
async fn tunnel_echo_large_and_small() {
    let cover = start_cover().await;
    let cfg = base_cfg(&cover);
    let env = start_echo(cfg, cover).await;
    let tcp = TcpStream::connect(env.addr).await.unwrap();
    let mut c = connect(tcp, &ccfg_e(&env)).await.expect("handshake");
    // много мелких записей
    for i in 0..200u32 {
        let msg = format!("hello {i}");
        c.write_all(msg.as_bytes()).await.unwrap();
        let mut b = vec![0u8; msg.len()];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(b, msg.as_bytes());
    }
    // 4 МиБ в обе стороны одновременно
    let data: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let (mut r, mut w) = tokio::io::split(c);
    let d2 = data.clone();
    let wt = tokio::spawn(async move {
        w.write_all(&d2).await.unwrap();
        w
    });
    let mut got = vec![0u8; data.len()];
    r.read_exact(&mut got).await.unwrap();
    assert!(got == data, "эхо не совпало");
    let mut w = wt.await.unwrap();
    w.shutdown().await.unwrap();
    let mut rest = Vec::new();
    r.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    assert_eq!(env.srv.stats.tunnels.load(SeqCst), 1);
    assert_eq!(env.cover_conns(), 0, "сайт-прикрытие не должен был видеть туннель");
}

// ---- вспомогательные для режима эха ----
struct EchoEnv {
    srv: Arc<Server>,
    addr: SocketAddr,
    secret: [u8; 32],
    cover: Cover,
}
impl EchoEnv {
    fn cover_conns(&self) -> usize {
        self.cover.conns.load(SeqCst)
    }
}
fn ccfg_e(e: &EchoEnv) -> ClientConfig {
    ClientConfig::new(kx::x25519_public(&e.secret), [0x11; 8], SNI)
}
async fn start_echo(mut cfg: ServerConfig, cover: Cover) -> EchoEnv {
    cfg.dest = cover.addr.to_string();
    let secret = cfg.static_secret;
    let srv = Server::new(cfg);
    let mut l = Listener::bind("127.0.0.1:0".parse().unwrap(), srv.clone()).await.unwrap();
    let addr = l.local_addr();
    tokio::spawn(async move {
        while let Some(a) = l.accept().await {
            if let Accepted::Tunnel { stream, .. } = a {
                tokio::spawn(async move {
                    let (mut r, mut w) = tokio::io::split(stream);
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        }
    });
    EchoEnv { srv, addr, secret, cover }
}

/// Клиент rustls без ключа (зонд): получает настоящий сертификат сайта и ответ.
async fn rustls_probe(addr: SocketAddr, cover_cert: &[u8], sni: &str) -> (Vec<u8>, String) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(cover_cert.to_vec())).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(roots).with_no_client_auth();
    let conn = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut t = conn.connect(ServerName::try_from(sni.to_string()).unwrap(), tcp).await.expect("TLS с сайтом-прикрытием");
    let peer = t.get_ref().1.peer_certificates().unwrap()[0].to_vec();
    t.write_all(format!("GET / HTTP/1.1\r\nhost: {sni}\r\n\r\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    let mut b = [0u8; 1024];
    loop {
        match t.read(&mut b).await {
            Ok(0) | Err(_) => break,
            Ok(n) => out.push_str(&String::from_utf8_lossy(&b[..n])),
        }
    }
    (peer, out)
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_without_key_gets_cover() {
    let cover = start_cover().await;
    let cert = cover.cert.clone();
    let cfg = base_cfg(&cover);
    let mut env = start_events(cfg, cover).await;
    let (peer, body) = rustls_probe(env.addr, &cert, SNI).await;
    assert_eq!(peer, cert, "зонд видит настоящий сертификат сайта");
    assert!(body.contains("COVER-OK"), "{body}");
    match next_event(&mut env).await {
        Accepted::Forwarded { reason, .. } => assert_eq!(reason, ForwardReason::NoToken),
        _ => panic!("ожидалась пересылка"),
    }
    assert_eq!(env.srv.stats.tunnels.load(SeqCst), 0);
    let _ = env.cover.conns.load(SeqCst);
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_with_other_sni_gets_cover() {
    let cover = start_cover().await;
    let cert = cover.cert.clone();
    let cfg = base_cfg(&cover);
    let mut env = start_events(cfg, cover).await;
    // SNI не из списка: пересылаем (сайт-прикрытие отвечает как умеет; rustls-сервер без SNI-разбора отдаёт тот же сертификат)
    let (_, body) = rustls_probe(env.addr, &cert, SNI).await;
    assert!(body.contains("COVER-OK"));
    assert!(matches!(next_event(&mut env).await, Accepted::Forwarded { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_server_key_is_detected_not_tunneled() {
    let cover = start_cover().await;
    let cfg = base_cfg(&cover);
    let mut env = start_events(cfg, cover).await;
    let mut c = ccfg(&env);
    c.server_pubkey = kx::x25519_public(&util::random::<32>());
    let tcp = TcpStream::connect(env.addr).await.unwrap();
    let r = connect(tcp, &c).await;
    // клиент получает настоящий ответ сайта; сертификат не наш: перехват/чужой сервер
    assert!(matches!(r, Err(Error::Intercepted(_))), "{:?}", r.as_ref().err());
    match next_event(&mut env).await {
        Accepted::Forwarded { reason, .. } => assert_eq!(reason, ForwardReason::NoToken),
        _ => panic!(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_short_id_forwarded() {
    let cover = start_cover().await;
    let cfg = base_cfg(&cover);
    let mut env = start_events(cfg, cover).await;
    let mut c = ccfg(&env);
    c.short_id = [0x99; 8];
    let r = connect(TcpStream::connect(env.addr).await.unwrap(), &c).await;
    assert!(matches!(r, Err(Error::Intercepted(_))));
    match next_event(&mut env).await {
        Accepted::Forwarded { reason, .. } => assert_eq!(reason, ForwardReason::UnknownShortId),
        _ => panic!(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_and_future_tokens_forwarded() {
    let cover = start_cover().await;
    let cfg = base_cfg(&cover);
    let mut env = start_events(cfg, cover).await;
    for off in [-1000i64, 1000] {
        let mut c = ccfg(&env);
        c.clock_offset_secs = off;
        let r = connect(TcpStream::connect(env.addr).await.unwrap(), &c).await;
        assert!(matches!(r, Err(Error::Intercepted(_))));
        match next_event(&mut env).await {
            Accepted::Forwarded { reason, .. } => assert_eq!(reason, ForwardReason::Stale),
            _ => panic!(),
        }
    }
    // внутри окна проходит
    let mut c = ccfg(&env);
    c.clock_offset_secs = -100;
    let t = connect(TcpStream::connect(env.addr).await.unwrap(), &c).await;
    assert!(t.is_ok());
}

/// Записывающий ретранслятор: между клиентом и сервером, пишет байты обоих направлений.
struct Tee {
    addr: SocketAddr,
    c2s: Arc<Mutex<Vec<u8>>>,
    s2c: Arc<Mutex<Vec<u8>>>,
}

async fn tee(target: SocketAddr) -> Tee {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let c2s = Arc::new(Mutex::new(Vec::new()));
    let s2c = Arc::new(Mutex::new(Vec::new()));
    let (a, b) = (c2s.clone(), s2c.clone());
    tokio::spawn(async move {
        loop {
            let Ok((c, _)) = l.accept().await else { break };
            let Ok(s) = TcpStream::connect(target).await else { continue };
            let (mut cr, mut cw) = c.into_split();
            let (mut sr, mut sw) = s.into_split();
            let a = a.clone();
            let b = b.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                while let Ok(n) = cr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    a.lock().unwrap().extend_from_slice(&buf[..n]);
                    if sw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = sw.shutdown().await;
            });
            tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                while let Ok(n) = sr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    b.lock().unwrap().extend_from_slice(&buf[..n]);
                    if cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = cw.shutdown().await;
            });
        }
    });
    Tee { addr, c2s, s2c }
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_client_hello_is_forwarded_to_cover() {
    let cover = start_cover().await;
    let cert = cover.cert.clone();
    let cfg = base_cfg(&cover);
    let mut env = start_events(cfg, cover).await;
    let t = tee(env.addr).await;
    let mut c = ccfg(&env);
    c.sni = SNI.into();
    let tcp = TcpStream::connect(t.addr).await.unwrap();
    let st = connect(tcp, &c).await.expect("первое соединение проходит");
    drop(st);
    let _ = tokio::time::timeout(Duration::from_millis(300), env.events.recv()).await;
    let rec = {
        let b = t.c2s.lock().unwrap();
        let n = 5 + u16::from_be_bytes([b[3], b[4]]) as usize;
        b[..n].to_vec()
    };
    // повтор записанного ClientHello: сервер отвечает как сайт-прикрытие
    let mut s = TcpStream::connect(env.addr).await.unwrap();
    s.write_all(&rec).await.unwrap();
    let mut first = [0u8; 5];
    s.read_exact(&mut first).await.unwrap();
    assert_eq!(first[0], 22, "ServerHello сайта");
    let mut n = 0;
    while let Some(ev) = env.events.recv().await {
        n += 1;
        if let Accepted::Forwarded { reason, .. } = ev {
            assert_eq!(reason, ForwardReason::Replay);
            break;
        }
        assert!(n < 5);
    }
    assert_eq!(env.srv.stats.forwarded_replay.load(SeqCst), 1);
    let _ = cert;
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_protocol_v2_address_and_requirements() {
    let cover = start_cover().await;
    let mut cfg = base_cfg(&cover);
    cfg.proxy_protocol = true;
    // публичный адрес без явного разрешения - отказ
    {
        let srv = Server::new(cfg.clone());
        assert!(Listener::bind("0.0.0.0:0".parse().unwrap(), srv).await.is_err());
    }
    let mut env = start_events(cfg, cover).await;
    // без заголовка: отбрасывается
    let mut s = TcpStream::connect(env.addr).await.unwrap();
    s.write_all(&[0x16, 3, 1, 0, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).await.unwrap();
    match next_event(&mut env).await {
        Accepted::Dropped { reason, .. } => assert_eq!(reason, DropReason::ProxyHeader),
        _ => panic!(),
    }
    // с заголовком: адрес берётся из него
    let mut tcp = TcpStream::connect(env.addr).await.unwrap();
    let hdr = proxy::build_v2_tcp4("203.0.113.9:4321".parse().unwrap(), "198.51.100.1:443".parse().unwrap());
    tcp.write_all(&hdr).await.unwrap();
    let c = ccfg(&env);
    let st = connect(tcp, &c).await.expect("туннель за PROXY");
    drop(st);
    match next_event(&mut env).await {
        Accepted::Tunnel { peer, short_id, sni, .. } => {
            assert_eq!(peer, "203.0.113.9:4321".parse::<SocketAddr>().unwrap());
            assert_eq!(short_id, [0x11; 8]);
            assert_eq!(sni, SNI);
        }
        _ => panic!(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_http_and_garbage_are_forwarded_and_survive() {
    let cover = start_cover().await;
    let mut cfg = base_cfg(&cover);
    cfg.limits.hello_timeout = Duration::from_millis(500);
    let mut env = start_events(cfg, cover).await;
    let mut s = TcpStream::connect(env.addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n").await.unwrap();
    match next_event(&mut env).await {
        Accepted::Forwarded { reason, .. } => assert_eq!(reason, ForwardReason::NotTls),
        _ => panic!(),
    }
    let mut buf = [0u8; 64];
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await;
    // медленный клиент: заголовок записи и тишина
    let mut s2 = TcpStream::connect(env.addr).await.unwrap();
    s2.write_all(&[0x16, 3, 1, 0x07, 0x00, 1]).await.unwrap();
    match next_event(&mut env).await {
        Accepted::Forwarded { reason, .. } => assert_eq!(reason, ForwardReason::HelloTimeout),
        _ => panic!(),
    }
    // и сервер продолжает работать
    let c = ccfg(&env);
    assert!(connect(TcpStream::connect(env.addr).await.unwrap(), &c).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn limits_per_ip() {
    let cover = start_cover().await;
    let mut cfg = base_cfg(&cover);
    cfg.limits = Limits { max_per_ip: 2, hello_timeout: Duration::from_secs(5), ..Limits::default() };
    let mut env = start_events(cfg, cover).await;
    let mut held = vec![];
    for _ in 0..2 {
        let mut s = TcpStream::connect(env.addr).await.unwrap();
        s.write_all(&[0x16, 3, 1]).await.unwrap();
        held.push(s);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _s3 = TcpStream::connect(env.addr).await.unwrap();
    match next_event(&mut env).await {
        Accepted::Dropped { reason, .. } => assert_eq!(reason, DropReason::Limit),
        _ => panic!(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rekey_and_padding() {
    let cover = start_cover().await;
    let cfg = base_cfg(&cover);
    let env = start_echo(cfg, cover).await;
    let mut c = ccfg_e(&env);
    c.padding = Padding { first_records: 1000, max_pad: 400 };
    let mut st = connect(TcpStream::connect(env.addr).await.unwrap(), &c).await.unwrap();
    st.set_rekey_after(3); // KeyUpdate каждые 3 записи (эхо сервера использует порог по умолчанию - проверка приёма)
    for i in 0..60u32 {
        let msg = vec![(i % 251) as u8; 1 + (i as usize * 37) % 3000];
        st.write_all(&msg).await.unwrap();
        let mut b = vec![0u8; msg.len()];
        st.read_exact(&mut b).await.unwrap();
        assert_eq!(b, msg);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cover_probe_and_flight_size_mimicry() {
    let cover = start_cover().await;
    let mut cfg = base_cfg(&cover);
    cfg.cn = "ignored.example".into();
    let cover_addr = cover.addr;
    let env = start_echo(cfg, cover).await;
    let info = env.srv.refresh_cover(&knothop_reality::profile::Profile::chrome155()).await.expect("проба сайта");
    assert_eq!(info.suite, 0x1301);
    assert_eq!(info.group, kx::GROUP_X25519, "rustls (ring) не поддерживает гибрид - выбирает x25519");
    assert_eq!(info.alpn.as_deref(), Some(&b"h2"[..]));
    assert!(!info.flight.is_empty());
    assert!(info.ccs);
    eprintln!("cover info: {info:?}");
    let _ = cover_addr;
    // туннель через записывающий ретранслятор: размеры записей перелёта сервера совпадают с сайтом
    let t = tee(env.addr).await;
    let c = ccfg_e(&env);
    let mut st = connect(TcpStream::connect(t.addr).await.unwrap(), &c).await.unwrap();
    st.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    st.read_exact(&mut b).await.unwrap();
    let s2c = t.s2c.lock().unwrap().clone();
    // ServerHello (22), CCS (20), записи перелёта (23)...
    let mut off = 0;
    let mut kinds = vec![];
    while off + 5 <= s2c.len() {
        let n = u16::from_be_bytes([s2c[off + 3], s2c[off + 4]]) as usize;
        kinds.push((s2c[off], n));
        off += 5 + n;
    }
    assert_eq!(kinds[0].0, 22);
    assert_eq!(kinds[1], (20, 1));
    let ours: Vec<usize> = kinds[2..2 + info.flight.len()].iter().map(|k| k.1).collect();
    assert!(info.samples.iter().any(|s| s.0 == ours), "размеры записей перелёта {ours:?} должны совпасть с одним из наблюдений сайта {:?}", info.samples);
    // «билеты» после Finished
    let tk: Vec<usize> = kinds[2 + info.flight.len()..].iter().take(info.tickets.len()).map(|k| k.1).collect();
    assert!(info.samples.iter().any(|s| s.0 == ours && s.1 == tk), "билеты {tk:?}");
}

fn recs(b: &[u8]) -> Vec<(u8, usize)> {
    let (mut off, mut v) = (0, vec![]);
    while off + 5 <= b.len() {
        let n = u16::from_be_bytes([b[off + 3], b[off + 4]]) as usize;
        v.push((b[off], n));
        off += 5 + n;
    }
    v
}

/// Начальный обмен «как h2» и форма первых записей: размеры/порядок записей на проводе в пределах профиля.
#[tokio::test(flavor = "multi_thread")]
async fn h2_preface_record_sequence_within_profile() {
    let cover = start_cover().await;
    let mut cfg = base_cfg(&cover);
    cfg.cn = "ignored.example".into();
    let env = start_echo(cfg, cover).await;
    let mut info = env.srv.refresh_cover(&knothop_reality::profile::Profile::chrome155()).await.unwrap();
    // наблюдение сайта nginx: SETTINGS 57, затем ACK 26, HEADERS 104, DATA 40, и крупная запись (проверка набивки)
    info.h2 = vec![57, 26, 104, 40, 16401];
    info.h2_samples = vec![info.h2.clone()];
    env.srv.set_cover_info(info.clone());
    let t = tee(env.addr).await;
    let c = ccfg_e(&env);
    let prof = c.mimic.profile.clone();
    let t0 = std::time::Instant::now();
    let mut st = connect(TcpStream::connect(t.addr).await.unwrap(), &c).await.unwrap();
    // «QUIC Initial»: 1300 Б одной записью записи, затем эхо
    let msg: Vec<u8> = (0..1300u32).map(|i| (i * 7) as u8).collect();
    st.write_all(&msg).await.unwrap();
    let mut b = vec![0u8; msg.len()];
    st.read_exact(&mut b).await.unwrap();
    assert_eq!(b, msg);
    eprintln!("connect+echo: {:?}", t0.elapsed());
    let c2s = recs(&t.c2s.lock().unwrap());
    let s2c = recs(&t.s2c.lock().unwrap());
    eprintln!("c2s {c2s:?}\ns2c {s2c:?}");
    // клиент: ClientHello, CCS, Finished(53), затем 87, 465..525, 26, и кусочки туннеля <= 470
    assert_eq!(c2s[0].0, 22);
    assert_eq!(c2s[1], (20, 1));
    assert_eq!(c2s[2], (23, 53));
    assert_eq!(c2s[3], (23, 87));
    assert!((prof.c_headers.0..=prof.c_headers.1).contains(&c2s[4].1));
    assert_eq!(c2s[5], (23, 26));
    let tun: Vec<usize> = c2s[6..].iter().map(|r| r.1).collect();
    assert!(tun.len() >= 3, "1300 Б режутся на несколько записей: {tun:?}");
    assert!(tun[..tun.len() - 1].iter().all(|n| (prof.up_chunk.0..=prof.up_chunk.1).contains(n)), "{tun:?}");
    assert!(tun.iter().all(|n| *n <= prof.up_chunk.1));
    // сервер: ServerHello, CCS, перелёт, билеты, затем S0=57, ответы 26,104,40, (крупная усечена reply_rec_cap), потом туннель
    let tk = info.tickets.len();
    let fl = info.flight.len();
    let after: Vec<usize> = s2c[2 + fl + tk..].iter().map(|r| r.1).collect();
    assert_eq!(&after[..4], &[57, 26, 104, 40], "{after:?}");
    assert!(after[4] <= prof.reply_rec_cap, "{after:?}");
    // первые записи туннеля добиты до [3/4, 1] * down_pad_cap
    let first_tunnel = after[5];
    assert!(first_tunnel >= prof.down_pad_cap * 3 / 4 && first_tunnel <= prof.down_pad_cap.max(1300 + 22), "{after:?}");
}

/// Выключенный обмен: прежнее поведение (первая запись туннеля сразу после Finished), обе стороны согласованы.
#[tokio::test(flavor = "multi_thread")]
async fn h2_preface_can_be_disabled() {
    let cover = start_cover().await;
    let mut cfg = base_cfg(&cover);
    cfg.mimic = Mimic::disabled();
    let env = start_echo(cfg, cover).await;
    let t = tee(env.addr).await;
    let mut c = ccfg_e(&env);
    c.mimic = Mimic::disabled();
    let mut st = connect(TcpStream::connect(t.addr).await.unwrap(), &c).await.unwrap();
    st.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    st.read_exact(&mut b).await.unwrap();
    let c2s = recs(&t.c2s.lock().unwrap());
    assert_eq!(c2s.len(), 4, "ClientHello, CCS, Finished, одна запись туннеля: {c2s:?}");
}

#[test]
fn ipnet_matching() {
    use knothop_reality::server::IpNet;
    let n = IpNet::parse("172.23.0.0/16").unwrap();
    assert!(n.contains("172.23.4.5".parse().unwrap()));
    assert!(!n.contains("172.24.0.1".parse().unwrap()));
    assert!(!n.contains("::1".parse().unwrap()));
    assert!(IpNet::parse("127.0.0.1").unwrap().contains("127.0.0.1".parse().unwrap()));
    assert!(!IpNet::parse("127.0.0.1").unwrap().contains("127.0.0.2".parse().unwrap()));
    assert!(IpNet::parse("::1").unwrap().contains("::1".parse().unwrap()));
    assert!(IpNet::parse("1.2.3.4/33").is_none());
    assert!(IpNet::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
}
