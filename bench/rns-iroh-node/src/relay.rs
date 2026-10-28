//! Опциональный iroh-relay на нашем порту: нужен для hole punching между узлами без открытых портов (телефон-телефон, админ-удалённая нода).
//!
//! Что даёт relay: сигнальный канал, через который два узла находят друг друга и обмениваются кандидатами для пробивки NAT, и QAD (QUIC address
//! discovery) - узнать собственный публичный `ip:port`. Данные между конечными узлами остаются под сквозным TLS iroh, а поверх них - Link RNS:
//! relay ничего не читает и не подписывает. Это подсказка пути, а не доверие: допуск и права по-прежнему даёт RNS.
//!
//! Порты. TCP делится с носителем `tcpc` по первому байту (`0x16` - TLS ClientHello relay, `R` - маркер `RGT*`). UDP общим быть не может: порт
//! QUIC занят самим endpoint iroh, а QAD - отдельный QUIC-сервер со своим сертификатом, поэтому ему нужен свой UDP-порт.
//!
//! Сертификат. У relay самоподписанный сертификат Ed25519, сделанный из ключа ноды (`iroh_key_from_identity`), поэтому клиенту ничего не нужно
//! раздавать: он проверяет, что открытый ключ в сертификате равен ключу доверенной ноды (`PinVerifier`), и подпись рукопожатия. Имя хоста и сроки
//! не проверяются - пин ключа строже.

use anyhow::Result;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;

/// Префикс SubjectPublicKeyInfo Ed25519 (RFC 8410), после него идут 32 байта ключа.
const ED25519_SPKI: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// Решение «ключ ноды доверенный»: клиент проверяет им сертификат relay, сервер - допуск к relay.
pub type Trusted = Arc<dyn Fn(&[u8; 32]) -> bool + Send + Sync>;

/// Открытый ключ Ed25519 из сертификата; `None`, если сертификат не разбирается или ключ другого типа.
pub fn cert_ed25519_key(cert: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let ee = webpki::EndEntityCert::try_from(cert).ok()?;
    let spki = ee.subject_public_key_info();
    let b: &[u8] = spki.as_ref();
    (b.len() == ED25519_SPKI.len() + 32 && b[..ED25519_SPKI.len()] == ED25519_SPKI).then(|| b[ED25519_SPKI.len()..].try_into().unwrap())
}

/// Проверка сертификата relay/QAD по пину: допускается только ключ из `trusted`. Подпись рукопожатия проверяется по ключу сертификата,
/// поэтому подсунуть чужой сертификат с вложенным чужим ключом нельзя. TLS 1.2 запрещён.
struct PinVerifier {
    trusted: Trusted,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinVerifier")
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer));
        }
        let Some(key) = cert_ed25519_key(end_entity) else {
            return Err(rustls::Error::InvalidCertificate(CertificateError::BadEncoding));
        };
        if !(self.trusted)(&key) {
            return Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls13RequiredForQuic))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Настройка проверки сертификатов для `Endpoint::ca_tls_config`: только relay/QAD доверенных нод (по ключу).
pub fn pinned_ca(trusted: Trusted) -> iroh::tls::CaTlsConfig {
    iroh::tls::CaTlsConfig::custom_server_cert_verifier(Arc::new(move |provider| {
        Ok(Arc::new(PinVerifier { trusted: trusted.clone(), provider }) as Arc<dyn ServerCertVerifier>)
    }))
}

/// Что за соединение пришло на общий TCP-порт.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Kind {
    /// маркер `RGT1/RGT2` запасного носителя
    Carrier,
    /// TLS ClientHello: relay iroh
    Relay,
    /// молчит дольше срока, закрыл соединение или прислал что-то иное
    Other,
}

/// Определить назначение соединения по первому байту, не вычитывая его (`peek`), чтобы дальше поток разбирал нужный обработчик.
pub async fn classify(s: &tokio::net::TcpStream, wait: std::time::Duration) -> Kind {
    let mut b = [0u8; 1];
    match tokio::time::timeout(wait, s.peek(&mut b)).await {
        Ok(Ok(1)) => match b[0] {
            b'R' => Kind::Carrier,
            0x16 => Kind::Relay,
            _ => Kind::Other,
        },
        _ => Kind::Other,
    }
}

#[cfg(feature = "relay-server")]
mod server {
    use super::*;
    use iroh_relay::server::http_server::TlsConfig;
    use iroh_relay::server::{Access, AccessControl, ClientRateLimit, ClientRequest, ConnectionId, QuicConfig, RelayConfig, RelayService, Server, ServerConfig};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Не более столько одновременных клиентов relay и столько подключений с одного ключа.
    pub const MAX_CLIENTS: usize = 64;
    pub const MAX_PER_KEY: usize = 2;
    /// Скорость приёма от одного клиента (байт/с): relay нужен для сигнализации и запасного пути, а не как основной носитель VPN.
    const CLIENT_RX_BYTES_PER_SEC: u32 = 4 * 1024 * 1024;
    /// До перехода в протокол relay (TLS + WebSocket) соединение живёт не дольше этого.
    const ESTABLISH: Duration = Duration::from_secs(30);

    /// Допуск к relay: только ключи, которые одобрил `Trusted`, с ограничением числа подключений.
    struct Gate {
        trusted: Trusted,
        live: Mutex<HashMap<[u8; 32], usize>>,
    }

    impl std::fmt::Debug for Gate {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Gate")
        }
    }

    impl AccessControl for Gate {
        async fn on_connect(&self, request: &ClientRequest) -> Access {
            let key = *request.endpoint_id().as_bytes();
            if !(self.trusted)(&key) {
                return Access::Deny { reason: None };
            }
            let mut live = self.live.lock().unwrap();
            let total: usize = live.values().sum();
            let n = live.entry(key).or_insert(0);
            if *n >= MAX_PER_KEY || total >= MAX_CLIENTS {
                return Access::Deny { reason: None };
            }
            *n += 1;
            Access::Allow
        }

        fn on_disconnect(&self, endpoint_id: iroh::EndpointId, _connection_id: ConnectionId) {
            let mut live = self.live.lock().unwrap();
            let key = *endpoint_id.as_bytes();
            if let Some(n) = live.get_mut(&key) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    live.remove(&key);
                }
            }
        }
    }

    /// Самоподписанный сертификат Ed25519 из 32-байтового seed (PKCS#8, RFC 8410). Закрытый ключ наружу не отдаётся.
    pub(super) fn self_signed(seed: &[u8; 32]) -> Result<(CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>)> {
        let mut pkcs8 = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        pkcs8.extend_from_slice(seed);
        let der = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8);
        let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_ED25519)?;
        let params = rcgen::CertificateParams::new(vec!["knothop-relay".to_string()])?;
        let cert = params.self_signed(&pair)?;
        Ok((cert.der().clone(), rustls::pki_types::PrivateKeyDer::Pkcs8(der)))
    }

    /// Запущенный relay: HTTP-сервис на общем TCP-порту и QAD на своём UDP.
    pub struct Host {
        _server: Server,
        service: RelayService,
        tls: Arc<rustls::ServerConfig>,
        quic: SocketAddr,
    }

    impl Host {
        /// `seed` - ключ ноды (сертификат делается из него), `quic_bind` - UDP-порт QAD, `trusted` - кто допущен к relay.
        pub async fn start(seed: &[u8; 32], quic_bind: SocketAddr, trusted: Trusted) -> Result<Host> {
            let (cert, key) = self_signed(seed)?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let tls = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)?;
            // Собственный HTTP-слушатель iroh-relay привязан к loopback и нужен только внутри Server: клиенты приходят через общий порт.
            let mut relay = RelayConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
            relay.access = Arc::new(Gate { trusted, live: Mutex::new(HashMap::new()) });
            relay.limits.client_rx = Some(ClientRateLimit::new(std::num::NonZeroU32::new(CLIENT_RX_BYTES_PER_SEC).unwrap()));
            let mut quic = QuicConfig::new(quic_bind);
            quic.server_config = Some(tls.clone());
            let mut cfg = ServerConfig::default();
            cfg.relay = Some(relay);
            cfg.quic = Some(quic);
            let server = Server::spawn(cfg).await?;
            let service = server.relay_service().cloned().ok_or_else(|| anyhow::anyhow!("relay: сервис не запущен"))?;
            let quic = server.quic_addr().ok_or_else(|| anyhow::anyhow!("relay: QAD не запущен"))?;
            Ok(Host { _server: server, service, tls: Arc::new(tls), quic })
        }

        /// Адрес, на котором слушает QAD.
        pub fn quic_addr(&self) -> SocketAddr {
            self.quic
        }

        /// Обслужить принятое TCP-соединение (TLS + WebSocket relay).
        pub async fn serve(&self, stream: tokio::net::TcpStream) {
            let _ = stream.set_nodelay(true);
            let tls = TlsConfig::new(self.tls.clone());
            self.service.clone().handle_connection(stream, Some(tls), ESTABLISH).await;
        }
    }
}

#[cfg(feature = "relay-server")]
pub use server::Host;

/// Без feature `relay-server` (APK) сервера нет; тип нужен только для сигнатур.
#[cfg(not(feature = "relay-server"))]
pub struct Host;

#[cfg(not(feature = "relay-server"))]
impl Host {
    pub async fn start(_seed: &[u8; 32], _quic_bind: std::net::SocketAddr, _trusted: Trusted) -> Result<Host> {
        anyhow::bail!("сборка без relay-server")
    }
    pub async fn serve(&self, _stream: tokio::net::TcpStream) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pubkey(seed: &[u8; 32]) -> [u8; 32] {
        *iroh::SecretKey::from_bytes(seed).public().as_bytes()
    }

    fn only(keys: Vec<[u8; 32]>) -> Trusted {
        Arc::new(move |k: &[u8; 32]| keys.contains(k))
    }

    #[cfg(feature = "relay-server")]
    #[test]
    fn cert_key_is_the_node_key() {
        let seed = [7u8; 32];
        let (cert, _) = server::self_signed(&seed).unwrap();
        assert_eq!(cert_ed25519_key(&cert), Some(pubkey(&seed)));
        assert_eq!(cert_ed25519_key(&CertificateDer::from(vec![1, 2, 3])), None);
    }

    #[cfg(feature = "relay-server")]
    #[test]
    fn pin_verifier_accepts_only_trusted_key() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let name = ServerName::try_from("x").unwrap();
        let (good, _) = server::self_signed(&[1u8; 32]).unwrap();
        let (other, _) = server::self_signed(&[2u8; 32]).unwrap();
        let v = PinVerifier { trusted: only(vec![pubkey(&[1u8; 32])]), provider };
        assert!(v.verify_server_cert(&good, &[], &name, &[], UnixTime::now()).is_ok());
        assert!(v.verify_server_cert(&other, &[], &name, &[], UnixTime::now()).is_err());
        // промежуточные сертификаты не допускаются
        assert!(v.verify_server_cert(&good, &[other.clone()], &name, &[], UnixTime::now()).is_err());
    }

    #[tokio::test]
    async fn classify_by_first_byte() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        for (first, want) in [(b'R', Kind::Carrier), (0x16u8, Kind::Relay), (b'G', Kind::Other)] {
            let c = tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
                s.write_all(&[first, 0, 0, 0]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(300)).await;
            });
            let (s, _) = l.accept().await.unwrap();
            assert_eq!(classify(&s, Duration::from_secs(2)).await, want);
            // peek не съедает байт
            let mut b = [0u8; 1];
            assert_eq!(s.peek(&mut b).await.unwrap(), 1);
            assert_eq!(b[0], first);
            c.await.unwrap();
        }
        // молчание - не носитель и не relay
        let _silent = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (s, _) = l.accept().await.unwrap();
        assert_eq!(classify(&s, Duration::from_millis(200)).await, Kind::Other);
    }

    #[cfg(feature = "relay-server")]
    mod live {
        use super::*;
        use iroh::endpoint::presets;
        use iroh::{Endpoint, EndpointAddr, RelayMap, RelayMode, SecretKey};

        const ALPN: &[u8] = b"kh-relay-test/0";

        /// Общий TCP-порт: как в `tcpc::listen`, но только ветка relay.
        async fn serve_shared(host: Arc<Host>) -> std::net::SocketAddr {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let Ok((s, _)) = l.accept().await else { return };
                    let host = host.clone();
                    tokio::spawn(async move {
                        if classify(&s, Duration::from_secs(5)).await == Kind::Relay {
                            host.serve(s).await;
                        }
                    });
                }
            });
            addr
        }

        async fn endpoint(sk: SecretKey, map: RelayMap, server_key: [u8; 32]) -> Endpoint {
            Endpoint::builder(presets::Minimal)
                .secret_key(sk)
                .alpns(vec![ALPN.to_vec()])
                .relay_mode(RelayMode::Custom(map))
                .ca_tls_config(pinned_ca(only(vec![server_key])))
                .bind()
                .await
                .unwrap()
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn trusted_endpoints_meet_through_relay_and_stranger_is_refused() {
            let server_seed = [9u8; 32];
            let (a, b, c) = (SecretKey::generate(), SecretKey::generate(), SecretKey::generate());
            let allowed = only(vec![*a.public().as_bytes(), *b.public().as_bytes()]);
            let host = Arc::new(Host::start(&server_seed, "127.0.0.1:0".parse().unwrap(), allowed).await.unwrap());
            let tcp = serve_shared(host.clone()).await;
            let url: iroh::RelayUrl = format!("https://127.0.0.1:{}", tcp.port()).parse().unwrap();
            let cfg = iroh::RelayConfig::new(url.clone(), Some(iroh_relay::RelayQuicConfig::new(host.quic_addr().port())));
            let map = RelayMap::from(cfg);
            let sk = pubkey(&server_seed);

            let (ea, eb) = (endpoint(a, map.clone(), sk).await, endpoint(b, map.clone(), sk).await);
            let b_id = eb.id();
            // endpoint нельзя отдавать задаче целиком: его drop закрывает соединение
            let eb2 = eb.clone();
            let acc = tokio::spawn(async move { eb2.accept().await.unwrap().await.unwrap() });
            let conn = tokio::time::timeout(Duration::from_secs(20), ea.connect(EndpointAddr::new(b_id).with_relay_url(url.clone()), ALPN))
                .await
                .expect("соединение через relay за 20 с")
                .expect("connect");
            let theirs = acc.await.unwrap();
            assert_eq!(conn.remote_id(), b_id);
            assert_eq!(theirs.remote_id(), ea.id());
            // как в тестах iroh: по соединению идёт настоящий обмен
            let mut tx = conn.open_uni().await.unwrap();
            tx.write_all(b"hello").await.unwrap();
            tx.finish().unwrap();
            let got = tokio::time::timeout(Duration::from_secs(10), async {
                let mut rx = theirs.accept_uni().await.unwrap();
                rx.read_to_end(100).await.unwrap()
            })
            .await
            .expect("обмен по соединению за 10 с");
            assert_eq!(got, b"hello");
            // relay только свёл узлы: затем iroh пробивает прямой путь (здесь loopback, без NAT) и выбирает его
            let mut direct = false;
            for _ in 0..80 {
                if conn.paths().iter().any(|p| p.is_ip() && p.is_selected()) { direct = true; break; }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            assert!(direct, "прямой путь не выбран за 10 с");

            // чужой ключ не допущен к relay, значит не находит ноду
            let ec = endpoint(c, map, sk).await;
            let r = tokio::time::timeout(Duration::from_secs(8), ec.connect(EndpointAddr::new(b_id).with_relay_url(url), ALPN)).await;
            assert!(!matches!(r, Ok(Ok(_))), "недопущенный ключ не должен соединиться через relay");
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn client_rejects_relay_with_untrusted_certificate() {
            let a = SecretKey::generate();
            let host = Arc::new(Host::start(&[9u8; 32], "127.0.0.1:0".parse().unwrap(), only(vec![*a.public().as_bytes()])).await.unwrap());
            let tcp = serve_shared(host.clone()).await;
            let url: iroh::RelayUrl = format!("https://127.0.0.1:{}", tcp.port()).parse().unwrap();
            let map = RelayMap::from(iroh::RelayConfig::new(url.clone(), None));
            // клиент ждёт другой ключ relay
            let ea = endpoint(a, map, pubkey(&[1u8; 32])).await;
            let r = tokio::time::timeout(Duration::from_secs(8), ea.connect(EndpointAddr::new(SecretKey::generate().public()).with_relay_url(url), ALPN)).await;
            assert!(!matches!(r, Ok(Ok(_))));
        }
    }
}
