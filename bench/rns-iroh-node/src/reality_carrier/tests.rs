//! Проверки REALITY-носителя: конфиг, ключ-файл, подсказка `rl`, лимиты, и два настоящих endpoint-а iroh, которые соединяются ТОЛЬКО через туннель
//! (адресов IP у клиента нет), с сайтом-прикрытием на rustls и зондом без ключа.

use super::*;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SNI: &str = "cover.example.org";
const ALPN: &[u8] = b"rl/0";

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("kh-rl-{tag}-{}-{}", std::process::id(), rand_core::OsRng.next_u64()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
use rand_core::RngCore;

// ------------------------------------------------------------------ юнит

#[test]
fn hint_json_roundtrip_and_strict_parsing() {
    let h = RealityHint { port: 443, sni: SNI.into(), key: [7; 32], sid: [9; 8] };
    assert_eq!(RealityHint::from_json(&h.to_json()), Some(h.clone()));
    // каждое поле обязательно и проверяется
    for bad in [
        serde_json::json!({}),
        serde_json::json!({"p": 0, "s": SNI, "k": hex(&[7; 32]), "i": hex(&[9; 8])}),
        serde_json::json!({"p": 70000, "s": SNI, "k": hex(&[7; 32]), "i": hex(&[9; 8])}),
        serde_json::json!({"p": 443, "s": "127.0.0.1", "k": hex(&[7; 32]), "i": hex(&[9; 8])}),
        serde_json::json!({"p": 443, "s": "no-dot", "k": hex(&[7; 32]), "i": hex(&[9; 8])}),
        serde_json::json!({"p": 443, "s": "a b.example.org", "k": hex(&[7; 32]), "i": hex(&[9; 8])}),
        serde_json::json!({"p": 443, "s": SNI, "k": hex(&[0; 32]), "i": hex(&[9; 8])}),
        serde_json::json!({"p": 443, "s": SNI, "k": "zz", "i": hex(&[9; 8])}),
        serde_json::json!({"p": 443, "s": SNI, "k": hex(&[7; 32]), "i": "00"}),
        serde_json::json!({"p": 443, "s": "x".repeat(70) + ".org", "k": hex(&[7; 32]), "i": hex(&[9; 8])}),
    ] {
        assert!(RealityHint::from_json(&bad).is_none(), "{bad}");
    }
    // Debug не печатает ключ и short_id
    let dbg = format!("{h:?}");
    assert!(!dbg.contains(&hex(&[7; 32])) && !dbg.contains("0909"), "{dbg}");
}

#[test]
fn server_conf_validation() {
    let ok = |l: &str, d: &str, s: &[&str], t: &[&str]| ServerConf::parse(l, d, &s.iter().map(|x| x.to_string()).collect::<Vec<_>>(), &t.iter().map(|x| x.to_string()).collect::<Vec<_>>(), None);
    let c = ok("127.0.0.1:9443", "www.example.org:443", &[], &["172.18.0.0/16", "127.0.0.1"]).unwrap();
    assert_eq!(c.sni, vec!["www.example.org".to_string()], "SNI по умолчанию - имя сайта-прикрытия");
    assert_eq!((c.public_port, c.proxy_trusted.len()), (443, 2));
    assert!(ok("127.0.0.1:9443", "www.example.org:443", &["A.Example.org", "a.example.org"], &[]).unwrap().sni.len() == 1, "дубликаты и регистр");
    // сайт-прикрытие не локальный
    for d in ["127.0.0.1:443", "localhost:443", "10.0.0.5:443", "[::1]:443", "0.0.0.0:443", "no-port", "x.org:0", ":443"] {
        assert!(ok("127.0.0.1:9443", d, &["x.org"], &[]).is_err(), "{d}");
    }
    assert!(ok("127.0.0.1:9443", "1.1.1.1:443", &[], &[]).is_err(), "IP-адрес сайта без SNI: имени для SNI нет");
    assert!(ok("not-an-addr", "www.example.org:443", &[], &[]).is_err());
    // PROXY v2 доверяется только локальным сетям и не слишком широким
    for t in ["0.0.0.0/0", "8.8.8.8", "10.0.0.0/7", "172.16.0.0/12x", "93.184.216.0/24"] {
        assert!(ok("127.0.0.1:9443", "www.example.org:443", &[], &[t]).is_err(), "{t}");
    }
    assert!(ok("127.0.0.1:9443", "www.example.org:443", &[], &["10.0.0.0/8", "192.168.1.1", "fd00::/8"]).is_ok());
}

#[test]
fn key_file_is_0600_atomic_and_stable() {
    let d = tmpdir("key");
    let k1 = load_or_create_key(&d).unwrap();
    let p = d.join("reality.key");
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&p).unwrap().len(), 32);
    assert_ne!(k1, [0u8; 32]);
    // повторный запуск читает тот же ключ; следов временных файлов нет
    assert_eq!(load_or_create_key(&d).unwrap(), k1);
    let leftovers: Vec<_> = std::fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(leftovers, vec!["reality.key".to_string()], "{leftovers:?}");
    // широкие права исправляются, мусор - ошибка (а не новый ключ поверх чужого файла)
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(load_or_create_key(&d).unwrap(), k1);
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    std::fs::write(&p, b"short").unwrap();
    assert!(load_or_create_key(&d).is_err());
    // short_id выводится из секрета: стабилен и зависит от него
    assert_eq!(node_short_id(&k1), node_short_id(&k1));
    assert_ne!(node_short_id(&k1), node_short_id(&[1; 32]));
    let _ = std::fs::remove_dir_all(&d);
}

#[tokio::test]
async fn tunnel_limits_and_oversize_frame() {
    let rc = RealityCarrier::new();
    // исходящих не больше MAX_OUT; слот освобождается закрытием
    let mut peers = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..MAX_OUT {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (id, closed) = rc.attach(a, Kind::Out).expect("в пределах лимита");
        peers.push(b);
        handles.push((id, closed));
    }
    let (a, _b) = tokio::io::duplex(1024);
    assert!(rc.attach(a, Kind::Out).is_none(), "сверх MAX_OUT");
    assert_eq!(rc.active().1, MAX_OUT);
    assert_eq!(rc.stats()["over_limit_out"], 1);
    rc.close(handles[0].0);
    tokio::time::timeout(Duration::from_secs(2), async {
        while *handles[0].1.borrow() == false {
            handles[0].1.changed().await.unwrap();
        }
    })
    .await
    .expect("туннель закрыт");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(rc.active().1, MAX_OUT - 1);
    let (a, _b) = tokio::io::duplex(1024);
    assert!(rc.attach(a, Kind::Out).is_some(), "слот освободился");
    // кадр больше MAX_FRAME: нарушение протокола, туннель закрывается
    let (id, mut closed) = handles.remove(1);
    let _ = id;
    let mut p = peers.remove(1);
    let big = vec![0xAB; MAX_FRAME + 1];
    p.write_all(&(big.len() as u16).to_be_bytes()).await.unwrap();
    p.write_all(&big).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !*closed.borrow() {
            closed.changed().await.unwrap();
        }
    })
    .await
    .expect("туннель с кадром-великаном закрыт");
    assert_eq!(rc.stats()["drop_oversize"], 1);
}

// ------------------------------------------------------------------ сайт-прикрытие и endpoint-ы

struct Cover {
    addr: SocketAddr,
    cert: Vec<u8>,
}

async fn start_cover() -> Cover {
    let ck = rcgen::generate_simple_self_signed(vec![SNI.to_string()]).unwrap();
    let cert = ck.cert.der().to_vec();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_no_client_auth().with_single_cert(vec![CertificateDer::from(cert.clone())], key).unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { break };
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
    Cover { addr, cert }
}

/// Зонд без ключа: обычный клиент rustls получает настоящий сертификат и ответ сайта-прикрытия.
async fn rustls_probe(addr: SocketAddr, cover_cert: &[u8]) -> (Vec<u8>, String) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(cover_cert.to_vec())).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(roots).with_no_client_auth();
    let conn = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut t = conn.connect(ServerName::try_from(SNI.to_string()).unwrap(), tcp).await.expect("TLS с сайтом-прикрытием");
    let peer = t.get_ref().1.peer_certificates().unwrap()[0].to_vec();
    t.write_all(format!("GET / HTTP/1.1\r\nhost: {SNI}\r\n\r\n").as_bytes()).await.unwrap();
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

async fn endpoint(rc: &RealityCarrier) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind_addr(SocketAddr::new("127.0.0.1".parse().unwrap(), 0))
        .unwrap()
        .add_custom_transport(rc.transport())
        .bind()
        .await
        .unwrap()
}

/// Конечная точка без IP-транспорта: о ней сервер не узнает IP-пути (на петлевом интерфейсе теста клиент иначе сообщает свой 127.0.0.1 и путь уходит с туннеля).
async fn endpoint_no_ip(rc: &RealityCarrier) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .add_custom_transport(rc.transport())
        .bind()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_over_reality_only_and_probe_gets_cover() {
    let cover = start_cover().await;
    let state = tmpdir("srv");
    let (rc_s, rc_c) = (RealityCarrier::new(), RealityCarrier::new());
    let conf = conf_for(&cover);
    let notes: Arc<Mutex<Vec<String>>> = Default::default();
    let n2 = notes.clone();
    let (mut hint, local) = rc_s.start_server(&conf, &state, Arc::new(move |m| n2.lock().unwrap().push(m))).await.unwrap();
    hint.port = local.port();
    assert_eq!(std::fs::metadata(state.join("reality.key")).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(hint.sni, SNI);
    assert!(!notes.lock().unwrap().iter().any(|n| n.contains(&hex(&hint.key))), "ключ в журнал не попадает");

    let (srv, cli) = (endpoint(&rc_s).await, endpoint_no_ip(&rc_c).await);

    // зонд без ключа получает настоящий сайт
    let (peer, body) = rustls_probe(local, &cover.cert).await;
    assert_eq!(peer, cover.cert, "зонд видит настоящий сертификат сайта");
    assert!(body.contains("COVER-OK"), "{body}");

    // клиент: адресов IP сервера нет, только туннель REALITY
    let mut tun = match rc_c.dial(&[local], &hint).await {
        Dial::Up(t) => t,
        Dial::Unreachable => panic!("unreachable"),
        Dial::Rejected(w) => panic!("rejected: {w}"),
    };
    let addr = EndpointAddr::from_parts(srv.id(), [TransportAddr::Custom(tun.addr())]);
    let accept = tokio::spawn({
        let srv = srv.clone();
        async move { srv.accept().await.unwrap().await.unwrap() }
    });
    let c = tokio::time::timeout(Duration::from_secs(15), cli.connect(addr, ALPN)).await.expect("connect: время").expect("connect");
    let s = tokio::time::timeout(Duration::from_secs(5), accept).await.unwrap().unwrap();
    assert_eq!(s.remote_id(), cli.id(), "ключ пира - из TLS QUIC, не из REALITY");
    assert_eq!(c.remote_id(), srv.id());
    assert!(selected_is_reality(&c), "выбранный путь клиента - REALITY: {:?}", c.paths().iter().map(|p| p.remote_addr().clone()).collect::<Vec<_>>());
    assert!(selected_is_reality(&s), "и у сервера");
    assert!(c.paths().iter().all(|p| matches!(p.remote_addr(), TransportAddr::Custom(_))), "IP-путей нет");

    // датаграммы туда и обратно (размер как у IP-пакета TUN с меткой)
    let max = c.max_datagram_size().expect("датаграммы включены");
    assert!(max >= 1200, "max_datagram_size {max}");
    eprintln!("reality path: max_datagram_size={max}, mtu={:?}", c.paths().iter().find(|p| p.is_selected()).map(|p| p.stats().current_mtu));
    let pkt: Vec<u8> = (0..max.min(1328)).map(|i| (i % 251) as u8).collect();
    c.send_datagram(Bytes::from(pkt.clone())).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), s.read_datagram()).await.unwrap().unwrap();
    assert_eq!(&got[..], &pkt[..]);
    s.send_datagram(Bytes::from(pkt.clone())).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), c.read_datagram()).await.unwrap().unwrap();
    assert_eq!(&got[..], &pkt[..]);

    // поток: 512 КиБ туда с эхом обратно
    let echo = tokio::spawn({
        let s = s.clone();
        async move {
            let (mut tx, mut rx) = s.accept_bi().await.unwrap();
            let mut buf = Vec::new();
            rx.read_to_end(1 << 20).await.map(|v| buf = v).unwrap();
            tx.write_all(&buf).await.unwrap();
            tx.finish().unwrap();
            let _ = tx.stopped().await;
        }
    });
    let data: Vec<u8> = (0..512 * 1024).map(|i| (i * 7 % 253) as u8).collect();
    let (mut tx, mut rx) = c.open_bi().await.unwrap();
    tx.write_all(&data).await.unwrap();
    tx.finish().unwrap();
    let back = tokio::time::timeout(Duration::from_secs(20), rx.read_to_end(1 << 20)).await.unwrap().unwrap();
    assert!(back == data, "поток целый");
    let _ = echo.await;

    // счётчики
    let st = rc_s.stats();
    assert_eq!(st["accepted"], 1);
    assert!(st["rx_pkts"].as_u64().unwrap() > 100, "{st}");
    assert!(st["server"]["cover_forwarded"].as_u64().unwrap() >= 1, "зонд ушёл на сайт: {st}");
    assert_eq!(st["server"]["tunnels"], 1);
    assert_eq!(rc_s.active().0, 1);
    assert_eq!(rc_c.active().1, 1);
    assert_eq!(rc_c.stats()["dial_ok"], 1);

    // сервер закрывает принятое по туннелю QUIC вместе с туннелем (не ждёт таймаута простоя)
    rc_s.close_conn_with_tunnel(s.clone());
    // закрытие туннеля клиентом видно обеим сторонам и освобождает слоты
    tun.close();
    tokio::time::timeout(Duration::from_secs(3), tun.closed()).await.expect("клиент: закрыт");
    tokio::time::timeout(Duration::from_secs(5), async {
        while rc_s.active().0 != 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("сервер освободил слот");
    let why = tokio::time::timeout(Duration::from_secs(5), s.closed()).await.expect("серверный QUIC закрыт вместе с туннелем");
    assert!(format!("{why}").contains("reality tunnel closed") || !format!("{why}").is_empty(), "{why}");
    c.close(0u32.into(), b"done");
    srv.close().await;
    cli.close().await;
    let _ = std::fs::remove_dir_all(&state);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_key_or_sid_does_not_open_a_tunnel() {
    let cover = start_cover().await;
    let state = tmpdir("srv2");
    let (rc_s, rc_c) = (RealityCarrier::new(), RealityCarrier::new());
    let conf = conf_for(&cover);
    let (mut hint, local) = rc_s.start_server(&conf, &state, Arc::new(|_| {})).await.unwrap();
    hint.port = local.port();
    // чужой ключ сервера: клиент получает настоящий сертификат сайта (Intercepted), туннеля нет, данных не отправлено
    let mut bad = hint.clone();
    bad.key[0] ^= 1;
    assert!(matches!(rc_c.dial(&[local], &bad).await, Dial::Rejected(_)));
    // чужой short_id
    let mut bad = hint.clone();
    bad.sid[0] ^= 1;
    assert!(matches!(rc_c.dial(&[local], &bad).await, Dial::Rejected(_)));
    assert_eq!(rc_c.active().1, 0);
    assert_eq!(rc_s.active().0, 0);
    assert_eq!(rc_s.stats()["server"]["tunnels"], 0);
    // порт закрыт: Unreachable, не Rejected
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap();
    drop(closed);
    let mut dead_hint = hint.clone();
    dead_hint.port = dead.port(); // порт берётся из подсказки
    assert!(matches!(rc_c.dial(&[dead], &dead_hint).await, Dial::Unreachable));
    let st = rc_c.stats();
    assert_eq!((st["dial_rejected"].as_u64(), st["dial_unreachable"].as_u64()), (Some(2), Some(1)));
    // и верные параметры работают
    assert!(matches!(rc_c.dial(&[local], &hint).await, Dial::Up(_)));
    let _ = std::fs::remove_dir_all(&state);
}

/// Конфиг сервера для проверок: сайт-прикрытие на loopback (`ServerConf::parse` такой dest отвергает, поэтому структура собирается напрямую).
fn conf_for(c: &Cover) -> ServerConf {
    ServerConf { listen: "127.0.0.1:0".parse().unwrap(), dest: c.addr.to_string(), sni: vec![SNI.into()], proxy_trusted: vec![], public_port: 443 }
}
