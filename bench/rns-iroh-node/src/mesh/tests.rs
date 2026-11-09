//! Проверки mesh на настоящих endpoint-ах iroh (loopback): рукопожатие, прозрачность для транзита, отказы, лимиты, возврат на прямой путь.
//! Узлы одного процесса; соседские соединения - обычные QUIC-соединения, кадры читает тестовый читатель (в узле это читатель датаграмм носителя).

use super::*;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
use std::collections::HashSet;
use std::net::SocketAddr;

const ALPN: &[u8] = b"rns/0";
const NBR: &[u8] = b"nbr/0";
const MARKER: &[u8] = b"SECRET-PLAINTEXT-MARKER-0123456789";

#[derive(Default)]
struct TP {
    rights: Mutex<HashSet<Key>>,
    routes: Mutex<HashMap<Key, Key>>,
    /// узел вправе пересылать (держит TRANSIT и не клиент)
    transit: AtomicBool,
    rgen: AtomicU64,
}

/// Ключи узлов с TRANSIT (общий набор процесса: ключи случайные, пересечений между тестами нет).
static TRANSIT_KEYS: std::sync::LazyLock<Mutex<HashSet<Key>>> = std::sync::LazyLock::new(Default::default);

impl TP {
    fn bump(&self) {
        self.rgen.fetch_add(1, Relaxed);
    }
}

impl Policy for TP {
    fn may_forward(&self, prev: &Key, src: &Key, dst: &Key) -> bool {
        let r = self.rights.lock().unwrap();
        self.transit.load(Relaxed) && r.contains(prev) && r.contains(src) && r.contains(dst)
    }
    fn holds_rights(&self, key: &Key) -> bool {
        self.rights.lock().unwrap().contains(key)
    }
    fn is_transit(&self, key: &Key) -> bool {
        self.rights.lock().unwrap().contains(key) && TRANSIT_KEYS.lock().unwrap().contains(key)
    }
    fn generation(&self) -> u64 {
        self.rgen.load(Relaxed)
    }
    fn transit_candidates(&self) -> Vec<Key> {
        let r = self.rights.lock().unwrap();
        TRANSIT_KEYS.lock().unwrap().iter().filter(|k| r.contains(*k)).copied().collect()
    }
    fn route(&self, dst: &Key) -> Option<Key> {
        self.routes.lock().unwrap().get(dst).copied()
    }
    /// как в Trust: неоднозначный id - None
    fn key_for_id(&self, id: &Id) -> Option<Key> {
        let r = self.rights.lock().unwrap();
        let mut it = r.iter().filter(|k| &id_of(k) == id);
        let first = it.next().copied()?;
        it.next().is_none().then_some(first)
    }
}

type Nbrs = Arc<RwLock<HashMap<Key, Connection>>>;

struct Node {
    ep: Endpoint,
    mesh: Arc<Mesh>,
    pol: Arc<TP>,
    nbrs: Nbrs,
    e2e: tokio::sync::Mutex<mpsc::UnboundedReceiver<Connection>>,
    /// транзит заметил открытый текст (проверка прозрачности)
    saw_plain: Arc<AtomicBool>,
    /// Только локальный тест: потерять каждую N-ю входящую mesh-датаграмму.
    drop_every: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl Node {
    fn id(&self) -> Key {
        *self.ep.id().as_bytes()
    }

    fn set_transit(&self, on: bool) {
        self.pol.transit.store(on, Relaxed);
        let mut s = TRANSIT_KEYS.lock().unwrap();
        if on {
            s.insert(self.id());
        } else {
            s.remove(&self.id());
        }
    }
}

async fn node() -> Node {
    node_with(true).await
}

async fn node_with(selector: bool) -> Node {
    node_bound(selector, std::net::IpAddr::from([127, 0, 0, 1])).await
}

async fn node_bound(selector: bool, bind: std::net::IpAddr) -> Node {
    node_bound_mode(selector, bind, false).await
}

#[derive(Debug)]
struct ForceMeshSelector;
impl PathSelector for ForceMeshSelector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let mut selection = PathSelection::none();
        if let Some(p) = ctx.paths().find(|p| matches!(p.network_path().addr_kind(), AddrKind::Custom(id) if id == MESH_ID)) {
            selection.set(&p);
        }
        selection
    }
}

async fn node_bound_mode(selector: bool, bind: std::net::IpAddr, force_mesh: bool) -> Node {
    let sk = SecretKey::generate();
    let me = *sk.public().as_bytes();
    let nbrs: Nbrs = Default::default();
    let n2 = nbrs.clone();
    let mesh = Mesh::with_carriers(me, true, Arc::new(move |k: &Key| n2.read().unwrap().get(k).cloned()));
    let pol = Arc::new(TP::default());
    mesh.set_policy(pol.clone());
    let mut b = Endpoint::builder(presets::Minimal)
        .secret_key(sk)
        .alpns(vec![ALPN.to_vec(), NBR.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind_addr(SocketAddr::new(bind, 0))
        .unwrap();
    if selector {
        b = b.add_custom_transport(mesh.transport());
        b = if force_mesh { b.path_selector(Arc::new(ForceMeshSelector)) } else { b.path_selector(mesh.selector()) };
    }
    let ep = b.bind().await.unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let saw_plain = Arc::new(AtomicBool::new(false));
    let n = Node { ep: ep.clone(), mesh: mesh.clone(), pol, nbrs, e2e: tokio::sync::Mutex::new(rx), saw_plain: saw_plain.clone(), drop_every: Arc::default(), dropped: Arc::default() };
    let (nbrs2, mesh2) = (n.nbrs.clone(), mesh.clone());
    let (drop_every, dropped) = (n.drop_every.clone(), n.dropped.clone());
    tokio::spawn(async move {
        while let Some(inc) = ep.accept().await {
            let (tx, nbrs, mesh, sp, every, drops) = (tx.clone(), nbrs2.clone(), mesh2.clone(), saw_plain.clone(), drop_every.clone(), dropped.clone());
            tokio::spawn(async move {
                let Ok(conn) = inc.await else { return };
                if conn.alpn() == NBR {
                    add_nbr(&nbrs, &mesh, conn, sp, every, drops);
                } else {
                    if matches!(conn.paths().iter().next().map(|p| p.remote_addr().clone()), Some(TransportAddr::Custom(_))) {
                        mesh.mark_e2e(&conn);
                    }
                    let _ = tx.send(conn);
                }
            });
        }
    });
    n
}

fn add_nbr(nbrs: &Nbrs, mesh: &Arc<Mesh>, conn: Connection, sp: Arc<AtomicBool>, every: Arc<AtomicU64>, dropped: Arc<AtomicU64>) {
    nbrs.write().unwrap().insert(*conn.remote_id().as_bytes(), conn.clone());
    let mesh = mesh.clone();
    tokio::spawn(async move {
        let mut seen = 0u64;
        while let Ok(d) = conn.read_datagram().await {
            if d.windows(MARKER.len()).any(|w| w == MARKER) {
                sp.store(true, Relaxed);
            }
            if d.first() == Some(&TAG) {
                seen += 1;
                let n = every.load(Relaxed);
                if n > 0 && seen % n == 0 { dropped.fetch_add(1, Relaxed); continue; }
                mesh.on_datagram(&conn, &d);
            }
        }
    });
}

fn ip(n: &Node) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], n.ep.bound_sockets()[0].port()))
}

/// Соседская связь a -> b по IP; обе стороны получают друг друга в таблицу носителей.
async fn link(a: &Node, b: &Node) {
    let conn = a.ep.connect(EndpointAddr::new(b.ep.id()).with_ip_addr(ip(b)), NBR).await.unwrap();
    add_nbr(&a.nbrs, &a.mesh, conn, a.saw_plain.clone(), a.drop_every.clone(), a.dropped.clone());
    let t = Instant::now();
    while !b.nbrs.read().unwrap().contains_key(&a.id()) {
        assert!(t.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn allow_all(nodes: &[&Node]) {
    let keys: Vec<Key> = nodes.iter().map(|n| n.id()).collect();
    for n in nodes {
        *n.pol.rights.lock().unwrap() = keys.iter().copied().collect();
    }
}

async fn e2e_connect(a: &Node, e: &Node) -> (Connection, Connection) {
    a.mesh.prepare(&e.id());
    let addr = endpoint_addr(&e.id()).unwrap();
    let acc = async { tokio::time::timeout(Duration::from_secs(10), e.e2e.lock().await.recv()).await.unwrap().unwrap() };
    let (c, s) = tokio::join!(tokio::time::timeout(Duration::from_secs(10), a.ep.connect(addr, ALPN)), acc);
    (c.expect("connect timed out").expect("connect failed"), s)
}

async fn stream_echo(a: &Connection, e: &Connection) {
    let (mut s, mut r) = a.open_bi().await.unwrap();
    s.write_all(MARKER).await.unwrap();
    s.finish().unwrap();
    let (mut es, mut er) = e.accept_bi().await.unwrap();
    assert_eq!(er.read_to_end(1024).await.unwrap(), MARKER);
    es.write_all(b"pong-stream").await.unwrap();
    es.finish().unwrap();
    assert_eq!(r.read_to_end(1024).await.unwrap(), b"pong-stream");
}

async fn echo(a: &Connection, e: &Connection) {
    stream_echo(a, e).await;
    let mut dg = MARKER.to_vec();
    dg.extend_from_slice(b"-dgram");
    a.send_datagram(Bytes::from(dg.clone())).unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), e.read_datagram()).await.unwrap().unwrap(), dg);
    e.send_datagram(Bytes::from_static(b"pong-dgram")).unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), a.read_datagram()).await.unwrap().unwrap(), &b"pong-dgram"[..]);
}

/// Подавить прямой путь: селектор лаборатории выбирает mesh, пока `FORCE` включён (iroh сам находит прямой адрес через NAT traversal).
fn mesh_selected(c: &Connection) -> bool {
    c.paths().iter().find(|p| p.is_selected()).is_some_and(|p| matches!(p.remote_addr(), TransportAddr::Custom(_)))
}

fn route(n: &Node, dst: &Node, via: &Node) {
    n.pol.routes.lock().unwrap().insert(dst.id(), via.id());
}

fn frame(ttl: u8, dst: &Key, src: &Key, body: &[u8]) -> Bytes {
    let mut f = vec![TAG, ttl];
    f.extend_from_slice(&id_of(dst));
    f.extend_from_slice(&id_of(src));
    f.extend_from_slice(body);
    Bytes::from(f)
}

/// Mesh без сети: политика и карта маршрутов без QUIC-соседей (кадры не уйдут, но решения и счётчики видны).
fn bare(transit: bool) -> (Arc<Mesh>, Arc<TP>) {
    let mesh = Mesh::with_carriers([9; 32], true, Arc::new(|_| None));
    let pol = Arc::new(TP::default());
    pol.transit.store(transit, Relaxed);
    pol.rights.lock().unwrap().insert([9; 32]);
    mesh.set_policy(pol.clone());
    (mesh, pol)
}

// ---------------------------------------------------------------- сквозное соединение

#[test]
fn stall_watch_requires_unanswered_traffic_and_respects_rtt() {
    let now = Instant::now();
    let mut watch = StallWatch::default();
    assert!(!watch.observe(now, 10, 20, Duration::from_secs(2)));
    // Долгий простой не превращается в застой при первом новом пакете.
    let resumed = now + Duration::from_secs(60);
    assert!(!watch.observe(resumed, 10, 21, Duration::from_secs(2)));
    assert!(!watch.observe(resumed + Duration::from_secs(5), 10, 22, Duration::from_secs(2)));
    assert!(watch.observe(resumed + Duration::from_secs(6), 10, 22, Duration::from_secs(2)));
    // Аутентифицированный ответ сбрасывает ожидание, даже если после него
    // проходит много времени без исходящего трафика.
    assert!(!watch.observe(resumed + Duration::from_secs(7), 11, 22, Duration::from_secs(2)));
    assert!(!watch.observe(resumed + Duration::from_secs(100), 11, 22, Duration::from_secs(2)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_hop_handshake_stream_and_datagrams_transit_sees_only_ciphertext() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    // A знает путь к E через T по таблице RNS; у E маршрута к A нет вовсе: ответы идут по обратной таблице, выученной из кадров A
    route(&a, &e, &t);
    let (ca, ce) = e2e_connect(&a, &e).await;
    assert_eq!(ca.remote_id(), e.ep.id());
    assert_eq!(ce.remote_id(), a.ep.id());
    assert!(mesh_selected(&ca) || ca.paths().iter().count() > 0);
    println!("max_datagram_size: {:?}, paths: {:?}", ca.max_datagram_size(), ca.paths().iter().map(|p| (p.remote_addr().clone(), p.is_selected(), p.stats().current_mtu)).collect::<Vec<_>>());
echo(&ca, &ce).await;
    assert!(t.mesh.c.fwd.load(Relaxed) > 0);
    assert!(e.mesh.c.delivered.load(Relaxed) > 0 && e.mesh.c.rev_learned.load(Relaxed) == 1, "ответы идут по обратной таблице");
    assert!(!t.saw_plain.load(Relaxed), "транзит увидел открытый текст");
    println!("A max_datagram_size={:?} E={:?}", ca.max_datagram_size(), ce.max_datagram_size());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_hops() {
    let (a, t1, t2, e) = (node().await, node().await, node().await, node().await);
    link(&a, &t1).await;
    link(&t1, &t2).await;
    link(&t2, &e).await;
    allow_all(&[&a, &t1, &t2, &e]);
    t1.set_transit(true);
    t2.set_transit(true);
    route(&a, &e, &t1);
    route(&t1, &e, &t2);
    let (ca, ce) = e2e_connect(&a, &e).await;
    echo(&ca, &ce).await;
    assert!(t1.mesh.c.fwd.load(Relaxed) > 0 && t2.mesh.c.fwd.load(Relaxed) > 0);
    assert!(!t1.saw_plain.load(Relaxed) && !t2.saw_plain.load(Relaxed));
    // ответ E -> A: t2 учил A через t1, E - через t2
    assert_eq!(e.mesh.c.rev_learned.load(Relaxed), 1);
}

/// Прямой путь закрыт, маршрута RNS через наш QUIC-носитель нет (путь идёт через TCP хаба): первым хопом берётся транзит с живым QUIC.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_rns_route_first_hop_is_alt_transit() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    // маршрута a -> e нет вовсе; у t прямой сосед e
    let (ca, ce) = e2e_connect(&a, &e).await;
    echo(&ca, &ce).await;
    assert!(a.mesh.c.alt_hops.load(Relaxed) > 0, "первый хоп выбран как альтернативный транзит");
    assert!(t.mesh.c.fwd.load(Relaxed) > 0);
    assert!(!t.saw_plain.load(Relaxed));
}

/// Выбранный транзит не видит выход: после неудачи следующая попытка идёт через другого кандидата.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_attempt_rotates_alt_transit() {
    let (a, t1, t2, e) = (node().await, node().await, node().await, node().await);
    link(&a, &t1).await;
    link(&a, &t2).await;
    link(&t2, &e).await;
    allow_all(&[&a, &t1, &t2, &e]);
    t1.set_transit(true);
    t2.set_transit(true);
    let mut ok = None;
    for _ in 0..3 {
        a.mesh.prepare(&e.id());
        let r = tokio::time::timeout(Duration::from_millis(2500), a.ep.connect(endpoint_addr(&e.id()).unwrap(), ALPN)).await;
        if let Ok(Ok(c)) = r {
            ok = Some(c);
            break;
        }
        a.mesh.rotate_alt(&e.id());
    }
    assert!(ok.is_some(), "после ротации соединение поднялось через транзит, который видит выход");
    assert!(t2.mesh.c.fwd.load(Relaxed) > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_rns_hop_falls_back_to_live_transit() {
    let (a, stale, live, e) = (node().await, node().await, node().await, node().await);
    link(&a, &stale).await;
    link(&a, &live).await;
    link(&live, &e).await;
    allow_all(&[&a, &stale, &live, &e]);
    stale.set_transit(true);
    live.set_transit(true);
    route(&a, &e, &stale);
    a.mesh.prepare(&e.id());
    assert_eq!(a.mesh.hop_peer(&e.id()), Some(stale.id()));
    // RNS ещё не удалил путь, но соседский QUIC-носитель уже пропал.
    a.nbrs.write().unwrap().remove(&stale.id());
    a.mesh.prepare(&e.id());
    assert_eq!(a.mesh.hop_peer(&e.id()), Some(live.id()), "устаревший RNS hop не должен блокировать альтернативу");
    let (ca, ce) = e2e_connect(&a, &e).await;
    tokio::time::timeout(Duration::from_secs(15), stream_echo(&ca, &ce)).await.expect("резервный путь должен передать поток в обе стороны");
    assert!(live.mesh.c.fwd.load(Relaxed) > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn established_mesh_survives_lost_transit_without_reconnect() {
    let (a, t1, t2, e) = (node_bound_mode(true, [127, 0, 0, 1].into(), true).await, node().await, node().await, node_bound_mode(true, [127, 0, 0, 1].into(), true).await);
    link(&a, &t1).await;
    link(&a, &t2).await;
    link(&t1, &e).await;
    link(&t2, &e).await;
    allow_all(&[&a, &t1, &t2, &e]);
    t1.set_transit(true);
    t2.set_transit(true);
    route(&a, &e, &t1);
    let (ca, ce) = e2e_connect(&a, &e).await;
    echo(&ca, &ce).await;
    assert!(mesh_selected(&ca), "испытание должно идти через mesh, а не прямой IP");
    assert!(mesh_selected(&ce), "обратное направление тоже должно идти через mesh");
    assert_eq!(a.mesh.hop_peer(&e.id()), Some(t1.id()));
    let old = a.nbrs.write().unwrap().remove(&t1.id()).expect("старый транзит");
    old.close(0u32.into(), b"test transit failure");
    a.mesh.prepare(&e.id());
    assert_eq!(a.mesh.hop_peer(&e.id()), Some(t2.id()));
    let result = tokio::time::timeout(Duration::from_secs(12), echo(&ca, &ce)).await;
    if result.is_err() {
        eprintln!("client={}; t1={}; t2={}; exit={}", a.mesh.stats(), t1.mesh.stats(), t2.mesh.stats(), e.mesh.stats());
        eprintln!("exit_reverse_to_client={:?}", e.mesh.rev.lock().unwrap().get(&a.id()).map(|(k, _)| if *k == t1.id() { "old" } else if *k == t2.id() { "new" } else { "other" }));
    }
    result.expect("действующее сквозное QUIC должно продолжить обмен через другой транзит");
    assert!(mesh_selected(&ca) && mesh_selected(&ce), "после переключения оба направления должны остаться на mesh");
    assert!(t2.mesh.c.fwd.load(Relaxed) > 0);
    assert!(t1.mesh.c.unreach_sent.load(Relaxed) > 0, "старый транзит сообщил об отказе");
    assert!(e.mesh.c.unreach_removed.load(Relaxed) > 0, "выход снял устаревшую обратную запись");
    // После смены транзита теряем каждую десятую входящую mesh-датаграмму на t2.
    // Проверяем надёжный сквозной поток, а не требуем доставки каждой QUIC DATAGRAM.
    t2.drop_every.store(10, Relaxed);
    tokio::time::timeout(Duration::from_secs(30), async {
        for _ in 0..20 {
            let (mut tx, mut rx) = ca.open_bi().await.unwrap();
            tx.write_all(MARKER).await.unwrap();
            tx.finish().unwrap();
            let (mut etx, mut erx) = ce.accept_bi().await.unwrap();
            assert_eq!(erx.read_to_end(1024).await.unwrap(), MARKER);
            etx.write_all(b"loss-survived").await.unwrap();
            etx.finish().unwrap();
            assert_eq!(rx.read_to_end(1024).await.unwrap(), b"loss-survived");
        }
    }).await.expect("надёжный поток должен пережить потери на новом транзите");
    assert!(t2.dropped.load(Relaxed) > 0, "проверка должна действительно отбросить датаграммы");
}

/// Носитель к транзиту жив и успешно принимает пакеты, но DPI/сеть их теряет
/// после приёма: это не `ConnectionLost` и не должно держать tunnel навсегда.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "требуется отдельный netns с разрешённым iptables"]
async fn established_mesh_recovers_from_silent_transit_blackhole() {
    let me_ns = std::fs::read_link("/proc/self/ns/net").unwrap();
    let host_ns = std::env::var("KNOTHOP_TEST_HOST_NETNS").expect("передайте inode сетевого пространства хоста до unshare");
    assert_ne!(me_ns.to_string_lossy(), host_ns, "правила разрешены только в отдельном netns");
    let (a, t1, t2, e) = (node_bound_mode(true, [127, 0, 0, 1].into(), true).await, node().await, node().await, node_bound_mode(true, [127, 0, 0, 1].into(), true).await);
    link(&a, &t1).await;
    link(&a, &t2).await;
    link(&t1, &e).await;
    link(&t2, &e).await;
    allow_all(&[&a, &t1, &t2, &e]);
    t1.set_transit(true);
    t2.set_transit(true);
    route(&a, &e, &t1);
    // Запретить только прямые UDP-пакеты endpoint A ↔ E в приватном netns,
    // иначе iroh может обойти поломанный mesh обычным loopback-IP.
    for aa in a.ep.bound_sockets() {
        for ee in e.ep.bound_sockets() {
            if aa.is_ipv4() != ee.is_ipv4() { continue; }
            let tool = if aa.is_ipv4() { "iptables" } else { "ip6tables" };
            let (ap, ep) = (aa.port().to_string(), ee.port().to_string());
            for (src, dst) in [(&ap, &ep), (&ep, &ap)] {
                assert!(std::process::Command::new(tool).args(["-I", "OUTPUT", "-p", "udp", "--sport", src, "--dport", dst, "-j", "DROP"]).status().unwrap().success());
            }
        }
    }
    let (ca, ce) = e2e_connect(&a, &e).await;
    assert!(a.mesh.mark_e2e(&ca));
    assert!(e.mesh.mark_e2e(&ce));
    stream_echo(&ca, &ce).await;
    assert!(mesh_selected(&ca) && mesh_selected(&ce));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before_a = a.mesh.c.tx.load(Relaxed);
    let before_e = e.mesh.c.delivered.load(Relaxed);
    let before_t1 = t1.mesh.c.fwd.load(Relaxed);
    t1.drop_every.store(1, Relaxed);
    // RNS продолжает указывать на старого соседа: хоп должен сменить сторожок.
    tokio::spawn(a.mesh.clone().watch_mesh_stall(ca.clone()));
    tokio::task::yield_now().await;
    let result = tokio::time::timeout(Duration::from_secs(20), stream_echo(&ca, &ce)).await;
    eprintln!("blackhole_dropped={}, second_transit_fwd={}, exit_conflicts={}", t1.dropped.load(Relaxed), t2.mesh.c.fwd.load(Relaxed), e.mesh.c.rev_conflict.load(Relaxed));
    eprintln!("a_tx_delta={}, t1_fwd_delta={}, exit_delivered_delta={}, a_paths={:?}, exit_paths={:?}",
        a.mesh.c.tx.load(Relaxed).saturating_sub(before_a), t1.mesh.c.fwd.load(Relaxed).saturating_sub(before_t1),
        e.mesh.c.delivered.load(Relaxed).saturating_sub(before_e),
        ca.paths().iter().map(|p| (p.remote_addr().clone(), p.is_selected(), p.stats().udp_tx.datagrams, p.stats().udp_rx.datagrams)).collect::<Vec<_>>(),
        ce.paths().iter().map(|p| (p.remote_addr().clone(), p.is_selected(), p.stats().udp_tx.datagrams, p.stats().udp_rx.datagrams)).collect::<Vec<_>>());
    eprintln!("a_hop_new={}, e_hop_new={}, e_verified_new={}, a_forced_new={}",
        a.mesh.hop_peer(&e.id()) == Some(t2.id()), e.mesh.hop_peer(&a.id()) == Some(t2.id()),
        e.mesh.verified_rev.lock().unwrap().get(&a.id()).is_some_and(|(via, _)| *via == t2.id()),
        a.mesh.stall_hops.lock().unwrap().get(&e.id()) == Some(&t2.id()));
    assert!(t1.dropped.load(Relaxed) > 0, "должна быть реальная потеря кадров");
    result.expect("сквозной поток должен восстановиться через второй транзит при молчаливой потере");
    assert_eq!(a.mesh.hop_peer(&e.id()), Some(t2.id()));
    assert!(mesh_selected(&ca) && mesh_selected(&ce), "прямой IP не должен подменить проверку mesh");
    assert!(t2.mesh.c.fwd.load(Relaxed) > 0);
    // После миграции транзит продолжает терять каждую десятую входящую
    // mesh-датаграмму. Проверяем несколько потоков в обе стороны, не только
    // сам факт открытия соединения или ответ на маленький зонд.
    t2.drop_every.store(10, Relaxed);
    let dropped_before = t2.dropped.load(Relaxed);
    tokio::time::timeout(Duration::from_secs(45), async {
        for _ in 0..20 { stream_echo(&ca, &ce).await; }
    }).await.expect("после смены транзита потоки должны пережить потери");
    let loss = t2.dropped.load(Relaxed) - dropped_before;
    eprintln!("post_migration_exchanges=20, second_transit_dropped={loss}");
    assert!(loss > 0, "проверка должна действительно потерять датаграммы");
    assert_eq!(a.mesh.hop_peer(&e.id()), Some(t2.id()));
    assert!(mesh_selected(&ca) && mesh_selected(&ce));
    let before = ca.paths().iter().find(|p| p.is_selected()).unwrap().stats();
    let started = Instant::now();
    const BULK: usize = 1_200_000;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (mut tx, mut rx) = ca.open_bi().await.unwrap();
        let client = async {
            tx.write_all(&vec![0x5a; BULK]).await.unwrap();
            tx.finish().unwrap();
            let response = rx.read_to_end(BULK + 1).await.unwrap();
            assert_eq!(response.len(), BULK);
            assert!(response.iter().all(|&b| b == 0xa5));
        };
        let server = async {
            let (mut tx, mut rx) = ce.accept_bi().await.unwrap();
            let request = rx.read_to_end(BULK + 1).await.unwrap();
            assert_eq!(request.len(), BULK);
            assert!(request.iter().all(|&b| b == 0x5a));
            tx.write_all(&vec![0xa5; BULK]).await.unwrap();
            tx.finish().unwrap();
        };
        tokio::join!(client, server);
    }).await.expect("двусторонняя передача после миграции должна пережить потери");
    let after = ca.paths().iter().find(|p| p.is_selected()).unwrap().stats();
    eprintln!("bulk_up={BULK}, bulk_down={BULK}, duration_ms={}, e2e_udp_tx_bytes={}, e2e_udp_rx_bytes={}, second_transit_drops_total={}",
        started.elapsed().as_millis(), after.udp_tx.bytes.saturating_sub(before.udp_tx.bytes),
        after.udp_rx.bytes.saturating_sub(before.udp_rx.bytes), t2.dropped.load(Relaxed));
    assert!(mesh_selected(&ca) && mesh_selected(&ce));
    // Учёт исходящих UDP каждого конца двух соседских соединений: каждый
    // переданный байт на обоих участках считается один раз, включая ACK.
    let carriers: Vec<Connection> = [(&a, &t2), (&t2, &a), (&t2, &e), (&e, &t2)].into_iter()
        .map(|(n, peer)| n.nbrs.read().unwrap().get(&peer.id()).unwrap().clone()).collect();
    let before_carriers: Vec<_> = carriers.iter().map(|c| c.stats().udp_tx).collect();
    let drop_start = t2.dropped.load(Relaxed);
    let started = Instant::now();
    let mut rounds = 0u64;
    const CHUNK: usize = 262_144;
    tokio::time::timeout(Duration::from_secs(60), async {
        while started.elapsed() < Duration::from_secs(30) {
            let (mut tx, mut rx) = ca.open_bi().await.unwrap();
            let client = async {
                tx.write_all(&vec![0x5a; CHUNK]).await.unwrap();
                tx.finish().unwrap();
                let data = rx.read_to_end(CHUNK + 1).await.unwrap();
                assert_eq!(data.len(), CHUNK);
                assert!(data.iter().all(|&b| b == 0xa5));
            };
            let server = async {
                let (mut tx, mut rx) = ce.accept_bi().await.unwrap();
                let data = rx.read_to_end(CHUNK + 1).await.unwrap();
                assert_eq!(data.len(), CHUNK);
                assert!(data.iter().all(|&b| b == 0x5a));
                tx.write_all(&vec![0xa5; CHUNK]).await.unwrap();
                tx.finish().unwrap();
            };
            tokio::join!(client, server);
            rounds += 1;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }).await.expect("длительная передача через новый транзит при потерях");
    let (mut udp_bytes, mut udp_datagrams) = (0u64, 0u64);
    for (conn, before) in carriers.iter().zip(before_carriers) {
        let after = conn.stats().udp_tx;
        udp_bytes += after.bytes.saturating_sub(before.bytes);
        udp_datagrams += after.datagrams.saturating_sub(before.datagrams);
    }
    eprintln!("sustained_seconds={:.2}, rounds={rounds}, payload_each_direction={}, carrier_udp_tx_bytes={udp_bytes}, carrier_udp_tx_datagrams={udp_datagrams}, transit_drops={}",
        started.elapsed().as_secs_f64(), rounds * CHUNK as u64, t2.dropped.load(Relaxed) - drop_start);
    assert!(rounds > 0 && t2.dropped.load(Relaxed) > drop_start);
    assert_eq!(a.mesh.hop_peer(&e.id()), Some(t2.id()));
    assert!(mesh_selected(&ca) && mesh_selected(&ce));

    // Отзыв во время настоящей передачи по тому же сквозному QUIC. После
    // отзыва не считаем уже поставленные в очереди байты доказательством утечки:
    // проверяем отказ новых входящих кадров и отсутствие маршрута на выходе.
    t2.drop_every.store(0, Relaxed);
    let ca_load = ca.clone();
    let ce_load = ce.clone();
    let completed = Arc::new(AtomicU64::new(0));
    let completed_task = completed.clone();
    let load = tokio::spawn(async move {
        loop {
            let Ok((mut tx, mut rx)) = ca_load.open_bi().await else { break };
            let client = async {
                tx.write_all(&vec![0x35; 65_536]).await?;
                tx.finish()?;
                rx.read_to_end(65_537).await.map_err(|_| io::Error::other("read failed"))
            };
            let server = async {
                let (mut tx, mut rx) = ce_load.accept_bi().await.map_err(|_| io::Error::other("accept failed"))?;
                let data = rx.read_to_end(65_537).await.map_err(|_| io::Error::other("read failed"))?;
                tx.write_all(&data).await?;
                tx.finish()?;
                Ok::<(), io::Error>(())
            };
            let (c, s) = tokio::join!(client, server);
            if !matches!(c, Ok(ref data) if data.len() == 65_536) || s.is_err() { break; }
            completed_task.fetch_add(1, Relaxed);
        }
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while completed.load(Relaxed) < 3 { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.expect("перед отзывом нагрузка должна реально передавать данные");
    e.pol.rights.lock().unwrap().remove(&t2.id());
    e.pol.bump();
    let denied_before = e.mesh.c.drop_policy.load(Relaxed);
    tokio::time::timeout(Duration::from_secs(10), async {
        while e.mesh.c.drop_policy.load(Relaxed) == denied_before { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.expect("после отзыва выход должен отвергать входящие mesh-кадры");
    tokio::time::sleep(Duration::from_millis(500)).await;
    e.mesh.sync_gen(e.pol.as_ref());
    assert!(e.mesh.verified_rev.lock().unwrap().get(&a.id()).is_none());
    assert_ne!(e.mesh.next_hop_origin(Instant::now(), &a.id(), e.pol.as_ref()), Some(t2.id()));
    eprintln!("revoke_under_load_completed_before_or_during={}, dropped_after_revoke={}", completed.load(Relaxed), e.mesh.c.drop_policy.load(Relaxed) - denied_before);
    load.abort();
    let _ = load.await;
}

async fn denied(setup: impl FnOnce(&Node, &Node, &Node)) -> (Node, Node, Node) {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    setup(&a, &t, &e);
    let addr = endpoint_addr(&e.id()).unwrap();
    let r = tokio::time::timeout(Duration::from_millis(2500), a.ep.connect(addr, ALPN)).await;
    assert!(!matches!(r, Ok(Ok(_))), "соединение не должно устанавливаться");
    assert_eq!(t.mesh.c.fwd.load(Relaxed), 0, "ни один кадр не переслан");
    assert!(t.mesh.c.drop_policy.load(Relaxed) + t.mesh.c.drop_unknown_key.load(Relaxed) > 0);
    (a, t, e)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_without_transit_right_and_for_client_role() {
    denied(|_, t, _| t.set_transit(false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_for_neighbor_without_rights() {
    denied(|a, t, _| {
        t.pol.rights.lock().unwrap().remove(&a.id());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_for_foreign_dst() {
    denied(|_, t, e| {
        t.pol.rights.lock().unwrap().remove(&e.id());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabled_mesh_neither_sends_nor_forwards() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    a.mesh.set_enabled(false);
    let r = tokio::time::timeout(Duration::from_millis(1500), a.ep.connect(endpoint_addr(&e.id()).unwrap(), ALPN)).await;
    assert!(!matches!(r, Ok(Ok(_))));
    assert!(a.mesh.c.drop_disabled.load(Relaxed) > 0 && a.mesh.c.tx.load(Relaxed) == 0);
    a.mesh.set_enabled(true);
    t.mesh.set_enabled(false);
    let r = tokio::time::timeout(Duration::from_millis(2500), a.ep.connect(endpoint_addr(&e.id()).unwrap(), ALPN)).await;
    assert!(!matches!(r, Ok(Ok(_))));
    assert!(t.mesh.c.drop_disabled.load(Relaxed) > 0 && t.mesh.c.fwd.load(Relaxed) == 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn narrow_neighbor_datagram_is_not_used() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    // соседская датаграмма заведомо уже требуемой: путь непригоден, соединение не поднимается
    a.mesh.set_min_nbr_dgram(1_000_000);
    let r = tokio::time::timeout(Duration::from_millis(1500), a.ep.connect(endpoint_addr(&e.id()).unwrap(), ALPN)).await;
    assert!(!matches!(r, Ok(Ok(_))));
    assert!(a.mesh.c.drop_mtu.load(Relaxed) > 0);
}

/// Обнаруженный IP остаётся кандидатом, пока его объём не подтверждён.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovered_ip_does_not_displace_working_mesh_without_bulk_proof() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, ce) = e2e_connect(&a, &e).await;
    echo(&ca, &ce).await;
    let t0 = Instant::now();
    while !ca.paths().iter().any(|p| matches!(p.remote_addr(), TransportAddr::Ip(_))) && t0.elapsed() < Duration::from_secs(15) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ca.paths().iter().any(|p| matches!(p.remote_addr(), TransportAddr::Ip(_))), "прямой кандидат должен быть найден");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(mesh_selected(&ca), "неподтверждённый IP не должен вытеснить mesh");
    echo(&ca, &ce).await;
}

/// IP-only подсказка не изолирует путь нового соединения: iroh хранит пути
/// на уровне пира и может открыть известный custom-адрес как запасной.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ip_only_dial_to_known_mesh_peer_is_not_proof_of_direct_only() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (existing, exit_existing) = e2e_connect(&a, &e).await;
    stream_echo(&existing, &exit_existing).await;
    let direct_hint = EndpointAddr::new(e.ep.id()).with_ip_addr(ip(&e));
    let (candidate, exit_candidate) = tokio::join!(
        a.ep.connect(direct_hint, ALPN),
        async { tokio::time::timeout(Duration::from_secs(10), e.e2e.lock().await.recv()).await.unwrap().unwrap() }
    );
    let candidate = candidate.unwrap();
    assert_ne!(existing.stable_id(), candidate.stable_id());
    tokio::time::timeout(Duration::from_secs(10), async {
        while !candidate.paths().iter().any(|p| is_mesh_addr(p.remote_addr())) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.expect("известный mesh может появиться на IP-only кандидате");
    stream_echo(&candidate, &exit_candidate).await;
    assert!(candidate.paths().iter().any(|p| is_mesh_addr(p.remote_addr())));
}

/// Проба прямого канала: VPN остаётся на mesh, а закреплённая датаграмма идёт
/// только по найденному IP-пути и принимается выходом именно по нему.
/// Прямой путь подтверждается параллельно работающему транзиту только передачей >1 МиБ
/// именно по IP-пути; при имитации DPI (обрыв на ~150 КБ) транзит не прерывается и IP не выбирается.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_direct_bulk_proof_requires_over_one_mib_and_keeps_mesh_until_proven() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, ce) = e2e_connect(&a, &e).await;
    stream_echo(&ca, &ce).await;
    let ip_path = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(p) = ca.paths().iter().find(|p| p.is_ip()) {
                if let TransportAddr::Ip(sa) = p.remote_addr() {
                    return (p.id(), *sa);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.expect("прямой кандидат должен появиться");
    assert!(mesh_selected(&ca), "до >1 МиБ трафик остаётся на mesh");

    // 1) Имитируем DPI, режущий прямой поток после ~150 КБ: проверка обязана вернуть None, mesh не тронут.
    let cut_after = Arc::new(AtomicU64::new(130));
    let cut_srv = cut_after.clone();
    let ce_srv = ce.clone();
    let ca_cli = ca.clone();
    let cli_rx = tokio::spawn(async move {
        let mut filter = crate::qprobe::Filter::new();
        while let Ok((b, pid)) = ca_cli.read_datagram_with_path().await {
            let _ = filter.intercept_on_path(&ca_cli, pid, &b);
        }
    });
    let srv_rx = tokio::spawn(async move {
        let mut filter = crate::qprobe::Filter::new();
        let mut echoed = 0u64;
        while let Ok((b, pid)) = ce_srv.read_datagram_with_path().await {
            if b.len() == crate::qprobe::HEAD && b[..8] == crate::qprobe::MAGIC && b[8] == crate::qprobe::KIND_BGREQ {
                assert!(ce_srv.paths().iter().any(|p| p.id() == pid && p.is_ip()), "запрос bulk обязан прийти по IP");
                let status = match crate::qprobe::grants().grant_bulk_path(&ce_srv, pid, [0x44; 32], Instant::now()) {
                    Ok(()) => 0,
                    Err(d) => d.code(),
                };
                let _ = ce_srv.send_datagram_on_path(pid, Bytes::from(crate::qprobe::grant_reply(status, &b[10..18])));
                echoed = 0;
                continue;
            }
            let cap = cut_srv.load(Relaxed);
            if cap > 0 && echoed >= cap {
                continue;
            }
            if filter.intercept_on_path(&ce_srv, pid, &b) {
                echoed += 1;
            }
        }
    });
    assert!(crate::qprobe::run_bulk_on_path(&ca, ip_path.0, 0x1111).await.is_none(), "DPI-обрезка на ~150 КБ не должна подтверждать прямой путь");
    assert!(!a.mesh.is_direct_confirmed(&ip_path.1));
    assert!(mesh_selected(&ca), "при неуспехе прямой пробы VPN остаётся на mesh");
    stream_echo(&ca, &ce).await;

    // 2) Полный проход >1 МиБ по прямому IP без потерь на mesh: прямой адрес подтверждается и выбирается, mesh остаётся запасным.
    // Сбрасываем кулдаун в новом окне для другого nonce? Нет: выдача на сервере ограничена GRANT_INTERVAL; проверим полный прогон на свежем узле E2.
    cli_rx.abort();
    srv_rx.abort();
    ca.close(0u32.into(), b"done");

    let (a2, e2) = (node().await, node().await);
    link(&a2, &t).await;
    link(&t, &e2).await;
    allow_all(&[&a2, &t, &e2]);
    route(&a2, &e2, &t);
    let (ca2, ce2) = e2e_connect(&a2, &e2).await;
    stream_echo(&ca2, &ce2).await;
    let ca2_cli = ca2.clone();
    let cli_rx2 = tokio::spawn(async move {
        let mut filter = crate::qprobe::Filter::new();
        while let Ok((b, pid)) = ca2_cli.read_datagram_with_path().await {
            let _ = filter.intercept_on_path(&ca2_cli, pid, &b);
        }
    });
    let ce2_srv = ce2.clone();
    let srv_rx2 = tokio::spawn(async move {
        let mut filter = crate::qprobe::Filter::new();
        while let Ok((b, pid)) = ce2_srv.read_datagram_with_path().await {
            if b.len() == crate::qprobe::HEAD && b[..8] == crate::qprobe::MAGIC && b[8] == crate::qprobe::KIND_BGREQ {
                assert!(ce2_srv.paths().iter().any(|p| p.id() == pid && p.is_ip()));
                let status = match crate::qprobe::grants().grant_bulk_path(&ce2_srv, pid, [0x77; 32], Instant::now()) {
                    Ok(()) => 0,
                    Err(d) => d.code(),
                };
                let _ = ce2_srv.send_datagram_on_path(pid, Bytes::from(crate::qprobe::grant_reply(status, &b[10..18])));
                continue;
            }
            let _ = filter.intercept_on_path(&ce2_srv, pid, &b);
        }
    });
    let mesh_dgram_before = ca2.paths().iter().find(|p| is_mesh_addr(p.remote_addr()))
        .map(|p| (p.stats().frame_tx.datagram, p.stats().frame_rx.datagram)).unwrap();
    tokio::spawn(a2.mesh.clone().watch_mesh_stall(ca2.clone()));
    tokio::spawn(a2.mesh.clone().watch_direct_upgrade(ca2.clone()));
    tokio::time::timeout(Duration::from_secs(15), async {
        while mesh_selected(&ca2) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.expect("после >1 МиБ по прямому IP соединение должно перейти на прямой путь");
    let mesh_dgram_after = ca2.paths().iter().find(|p| is_mesh_addr(p.remote_addr()))
        .map(|p| (p.stats().frame_tx.datagram, p.stats().frame_rx.datagram)).unwrap();
    assert_eq!(mesh_dgram_after, mesh_dgram_before, "ни одна датаграмма объёмной пробы не должна идти через mesh");
    let ip_st = ca2.paths().iter().find(|p| p.is_selected() && p.is_ip()).expect("выбран прямой IP").stats();
    assert!(ip_st.udp_tx.bytes > 1024 * 1024 && ip_st.udp_rx.bytes > 1024 * 1024,
        "прямой путь обязан реально передать >1 МиБ в каждую сторону: tx={}, rx={}", ip_st.udp_tx.bytes, ip_st.udp_rx.bytes);
    assert_eq!(ca2.paths().iter().filter(|p| is_mesh_addr(p.remote_addr())).count(), 1, "mesh остаётся тёплым запасным");
    stream_echo(&ca2, &ce2).await;
    cli_rx2.abort();
    srv_rx2.abort();
    ca2.close(0u32.into(), b"done");
    ce2.close(0u32.into(), b"done");
    ce.close(0u32.into(), b"done");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_probe_crosses_direct_path_while_mesh_keeps_traffic() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, ce) = e2e_connect(&a, &e).await;
    stream_echo(&ca, &ce).await;
    let ip_path = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(id) = ca.paths().iter().find(|p| matches!(p.remote_addr(), TransportAddr::Ip(_))).map(|p| p.id()) {
                return id;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.expect("прямой кандидат должен появиться");
    assert!(mesh_selected(&ca), "VPN остаётся на mesh");
    // Путь мог ещё не пройти валидацию: ждём готовности, не подменяя путь.
    let fwd_before = t.mesh.c.fwd.load(Relaxed);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !ca.send_datagram_on_path(ip_path, Bytes::from_static(b"direct-probe")).unwrap() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.expect("валидированный IP-путь должен принять пробу");
    let (data, path) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (d, p) = ce.read_datagram_with_path().await.unwrap();
            if &d[..] == b"direct-probe" { return (d, p); }
        }
    }).await.unwrap();
    assert_eq!(&data[..], b"direct-probe");
    assert!(ce.paths().iter().any(|p| p.id() == path && matches!(p.remote_addr(), TransportAddr::Ip(_))),
        "выход принял пробу по IP-пути, а не через транзит");
    assert!(mesh_selected(&ca), "проба не переключила VPN на непроверенный IP");
    eprintln!("transit_fwd_during_probe={}", t.mesh.c.fwd.load(Relaxed) - fwd_before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn received_datagram_reports_actual_mesh_path_end_to_end() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, ce) = e2e_connect(&a, &e).await;
    assert!(mesh_selected(&ca));
    ca.send_datagram(Bytes::from_static(b"path-evidence")).unwrap();
    let (data, path) = tokio::time::timeout(Duration::from_secs(5), ce.read_datagram_with_path()).await.unwrap().unwrap();
    assert_eq!(&data[..], b"path-evidence");
    assert!(ce.paths().iter().any(|p| p.id() == path && is_mesh_addr(p.remote_addr())),
        "путь принятой датаграммы должен быть реальным mesh, не оценкой по выбранному пути");
    assert!(t.mesh.c.fwd.load(Relaxed) > 0);
}

/// Прямой путь ещё не прошёл bulk-проверку: добровольно на него не переходим,
/// но при полном отказе единственного транзита аварийный fallback не должен
/// удерживать трафик на мёртвом mesh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_mesh_can_fail_over_to_unconfirmed_direct_emergency_path() {
    if std::env::var_os("KH_PATH_TRACE").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("noq_proto::connection=trace,rns_iroh_node::mesh::tests=info")
            .try_init();
    }
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, ce) = e2e_connect(&a, &e).await;
    stream_echo(&ca, &ce).await;
    tokio::time::timeout(Duration::from_secs(15), async {
        while !ca.paths().iter().any(|p| matches!(p.remote_addr(), TransportAddr::Ip(_))) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.expect("должен появиться прямой резерв");
    assert!(mesh_selected(&ca), "живой mesh не должен вытесняться малым зондом");
    t.drop_every.store(1, Relaxed);
    let started = Instant::now();
    tracing::info!("test blackhole enabled");
    let monitor_conn = ca.clone();
    let monitor = tokio::spawn(async move {
        let t0 = Instant::now();
        loop {
            let paths: Vec<_> = monitor_conn.paths().iter().map(|p| {
                let s = p.stats();
                (if matches!(p.remote_addr(), TransportAddr::Ip(_)) { "ip" } else { "mesh" }, p.is_selected(),
                 s.frame_tx.ack_eliciting_progress(), s.frame_rx.authenticated_progress(), s.udp_tx.datagrams, s.udp_rx.datagrams)
            }).collect();
            eprintln!("fallback_trace_ms={} paths={paths:?}", t0.elapsed().as_millis());
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let stream = async {
        let (mut tx, mut rx) = ca.open_bi().await.unwrap();
        tx.write_all(MARKER).await.unwrap();
        tx.finish().unwrap();
        let (mut etx, mut erx) = ce.accept_bi().await.unwrap();
        assert_eq!(erx.read_to_end(1024).await.unwrap(), MARKER);
        tracing::info!(elapsed_ms = started.elapsed().as_millis(), "test request received");
        eprintln!("emergency_request_received_ms={}", started.elapsed().as_millis());
        etx.write_all(b"pong-stream").await.unwrap();
        etx.finish().unwrap();
        assert_eq!(rx.read_to_end(1024).await.unwrap(), b"pong-stream");
    };
    tokio::time::timeout(Duration::from_secs(25), stream).await
        .expect("после отказа mesh данные должны пройти по прямому аварийному пути");
    monitor.abort();
    assert!(t.dropped.load(Relaxed) > 0, "отказ транзита должен действительно отбросить кадры");
    assert!(ca.paths().iter().any(|p| p.is_selected() && matches!(p.remote_addr(), TransportAddr::Ip(_))), "после отказа должен быть выбран IP");
    eprintln!("emergency_fallback_ms={}, blackhole_dropped={}", started.elapsed().as_millis(), t.dropped.load(Relaxed));
}

/// Соединение, начатое по mesh, не должно переходить на непроверенный IP под потоком.
/// В multipath подтверждения пакетов пути X могут идти по пути Y; сторожок не должен принимать это за застой X.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_started_connection_stays_on_mesh_under_traffic_without_bulk_proof() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, ce) = e2e_connect(&a, &e).await;
    echo(&ca, &ce).await;
    assert!(mesh_selected(&ca), "сначала используется mesh");
    // поток в обе стороны: A->E датаграммы, E отвечает эхом (как TCP: данные + обратный трафик)
    let echo_task = tokio::spawn({
        let ce = ce.clone();
        async move {
            while let Ok(Ok(d)) = tokio::time::timeout(Duration::from_secs(3), ce.read_datagram()).await {
                let _ = ce.send_datagram(d);
            }
        }
    });
    let rx = tokio::spawn({
        let ca = ca.clone();
        async move {
            let mut got = Vec::new();
            while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(3), ca.read_datagram()).await {
                got.push(Instant::now());
            }
            got
        }
    });
    let (start, mut switches, mut last_mesh, mut mesh_samples, mut samples) = (Instant::now(), 0, true, 0, 0);
    let mut seq = 0u32;
    while start.elapsed() < Duration::from_secs(20) {
        let _ = ca.send_datagram(Bytes::from(seq.to_be_bytes().to_vec()));
        seq += 1;
        let m = mesh_selected(&ca);
        samples += 1;
        mesh_samples += m as u32;
        if m != last_mesh {
            switches += 1;
            last_mesh = m;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let end = Instant::now();
    let got = rx.await.unwrap();
    echo_task.abort();
    let mut worst = Duration::ZERO;
    let mut last = start;
    for t in got.iter().filter(|t| **t <= end) {
        worst = worst.max(*t - last);
        last = *t;
    }
    println!("[mesh-start] sent={seq} echoed={} switches={switches} mesh_samples={mesh_samples}/{samples} worst_gap={worst:?}", got.len());
    assert_eq!(switches, 0, "непроверенный IP не должен вытеснить работающий mesh");
    assert_eq!(mesh_samples, samples);
    assert!(worst < Duration::from_millis(500), "провал доставки {worst:?}");
}

// ---------------------------------------------------------------- решения без сети

/// Потолок пакета сквозного QUIC на пути mesh: 1452 (MTU соседа) - 38 - HDR = 1396; пакет такого размера + HDR помещается в датаграмму соседа 1414.
#[test]
fn e2e_max_udp_fits_neighbor_datagram() {
    assert_eq!(e2e_max_udp(1452), 1396);
    assert_eq!(e2e_max_udp(1452) as usize + HDR, 1452 - 38);
    assert_eq!(e2e_max_udp(10), 0, "без переполнения");
}

#[test]
fn ttl_one_is_dropped_and_ttl_two_goes_on() {
    let (m, p) = bare(true);
    let (prev, src, dst) = ([1; 32], [2; 32], [3; 32]);
    p.rights.lock().unwrap().extend([prev, src, dst]);
    p.routes.lock().unwrap().insert(dst, [4; 32]);
    m.on_frame(&prev, &frame(1, &dst, &src, b"x"));
    assert_eq!((m.c.drop_ttl.load(Relaxed), m.c.drop_no_quic.load(Relaxed)), (1, 0));
    // ttl=2 доходит до выбора соседа (носителя в тесте нет)
    m.on_frame(&prev, &frame(2, &dst, &src, b"x"));
    assert_eq!((m.c.drop_ttl.load(Relaxed), m.c.drop_no_quic.load(Relaxed)), (1, 1));
}

#[test]
fn no_u_turn() {
    let (m, p) = bare(true);
    let (prev, src, dst) = ([1; 32], [2; 32], [3; 32]);
    p.rights.lock().unwrap().extend([prev, src, dst]);
    p.routes.lock().unwrap().insert(dst, prev);
    m.on_frame(&prev, &frame(5, &dst, &src, b"x"));
    assert_eq!((m.c.drop_uturn.load(Relaxed), m.c.fwd.load(Relaxed)), (1, 0));
}

#[test]
fn malformed_and_no_policy_and_foreign_prev() {
    let (m, _p) = bare(true);
    m.on_frame(&[1; 32], &Bytes::from_static(&[TAG, 8, 0]));
    assert_eq!(m.c.drop_malformed.load(Relaxed), 1);
    m.on_frame(&[1; 32], &frame(8, &[3; 32], &[2; 32], b"x"));
    assert_eq!(m.c.drop_unknown_key.load(Relaxed), 1, "id источника не принадлежит известному держателю - отказ");
    // (отказ по id кэшируется на 5 с: дальше другие ключи)
    _p.rights.lock().unwrap().extend([[4; 32], [5; 32]]);
    m.on_frame(&[1; 32], &frame(8, &[5; 32], &[4; 32], b"x"));
    assert_eq!(m.c.drop_policy.load(Relaxed), 1, "сосед без прав - отказ");
    let m2 = Mesh::with_carriers([9; 32], true, Arc::new(|_| None));
    m2.on_frame(&[1; 32], &frame(8, &[3; 32], &[2; 32], b"x"));
    assert_eq!(m2.c.drop_no_policy.load(Relaxed), 1, "без политики mesh закрыт");
}

#[test]
fn neighbor_and_pair_rate_limits() {
    let (m, p) = bare(true);
    let (prev, src, dst) = ([1; 32], [2; 32], [3; 32]);
    p.rights.lock().unwrap().extend([prev, src, dst]);
    p.routes.lock().unwrap().insert(dst, [4; 32]);
    m.set_limits(Limits { nbr_rate: 0.0, nbr_burst: 10.0, pair_rate: 0.0, pair_burst: 4.0 });
    for _ in 0..30 {
        m.on_frame(&prev, &frame(8, &dst, &src, b"x"));
    }
    assert_eq!(m.c.drop_rate_pair.load(Relaxed), 6, "10 прошли соседа, 4 - пару");
    assert_eq!(m.c.drop_rate_neighbor.load(Relaxed), 20);
}

#[test]
fn last_hop_is_fail_closed_and_budgeted() {
    let (m, p) = bare(false);
    let (prev, src) = ([1; 32], [2; 32]);
    let me = *m.me();
    p.rights.lock().unwrap().insert(src);
    // сосед без прав: кадр не доставляется
    m.on_frame(&prev, &frame(8, &me, &src, b"x"));
    assert_eq!((m.c.delivered.load(Relaxed), m.c.drop_policy.load(Relaxed)), (0, 1), "сосед без прав");
    // сосед с правами, но не источник и не TRANSIT: источник «за ним» недопустим
    p.rights.lock().unwrap().insert(prev);
    p.bump();
    m.on_frame(&prev, &frame(8, &me, &src, b"x"));
    assert_eq!((m.c.delivered.load(Relaxed), m.c.drop_policy.load(Relaxed), m.c.rev_learned.load(Relaxed)), (0, 2, 0));
    // сам источник - сосед с правами: доставка, обратной записи нет (он и так сосед)
    m.on_frame(&src, &frame(8, &me, &src, b"x"));
    assert_eq!((m.c.delivered.load(Relaxed), m.c.rev_learned.load(Relaxed)), (1, 0));
    // узел с TRANSIT: доставка и обратная запись (после успешной доставки)
    TRANSIT_KEYS.lock().unwrap().insert(prev);
    p.bump();
    m.on_frame(&prev, &frame(8, &me, &src, b"x"));
    assert_eq!((m.c.delivered.load(Relaxed), m.c.rev_learned.load(Relaxed)), (2, 1));
    TRANSIT_KEYS.lock().unwrap().remove(&prev);
    // очередь доставки ограничена
    for _ in 0..(DELIVER_QUEUE + 100) {
        m.on_frame(&src, &frame(8, &me, &src, b"x"));
    }
    assert!(m.c.deliver_queue_full.load(Relaxed) >= 99, "очередь доставки ограничена");
}

#[test]
fn local_delivery_has_pair_budget() {
    let (m, p) = bare(false);
    let (src, me) = ([2; 32], *m.me());
    p.rights.lock().unwrap().insert(src);
    m.set_limits(Limits { nbr_rate: 0.0, nbr_burst: 1000.0, pair_rate: 0.0, pair_burst: 5.0 });
    for _ in 0..20 {
        m.on_frame(&src, &frame(8, &me, &src, b"x"));
    }
    assert_eq!((m.c.delivered.load(Relaxed), m.c.drop_rate_pair.load(Relaxed)), (5, 15));
}

#[test]
fn ordinary_neighbor_cannot_poison_reverse_table() {
    let (m, p) = bare(false);
    // C - клиент с правами USE (не TRANSIT), X - чужой узел, под которого он подделывает src
    let (c, x, me) = ([1; 32], [2; 32], *m.me());
    p.rights.lock().unwrap().extend([c, x]);
    for _ in 0..3 {
        m.on_frame(&c, &frame(8, &me, &x, b"x"));
    }
    assert_eq!((m.c.delivered.load(Relaxed), m.c.rev_learned.load(Relaxed), m.rev.lock().unwrap().len()), (0, 0, 0));
    // и при пересылке через транзит: рядовой сосед не может провести чужой src
    let (t, dst) = ([7; 32], [3; 32]);
    let (m2, p2) = bare(true);
    p2.rights.lock().unwrap().extend([c, x, dst, t]);
    p2.routes.lock().unwrap().insert(dst, t);
    m2.on_frame(&c, &frame(8, &dst, &x, b"x"));
    assert_eq!(m2.c.drop_policy.load(Relaxed) + m2.c.drop_no_quic.load(Relaxed), 1);
    assert_eq!(m2.rev.lock().unwrap().len(), 0, "ничего не выучено до успешной пересылки");
}

#[test]
fn unreachable_notice_only_withdraws_sender_owned_reverse_route() {
    let (m, p) = bare(false);
    let old = *SecretKey::generate().public().as_bytes();
    let other = *SecretKey::generate().public().as_bytes();
    let src = *SecretKey::generate().public().as_bytes();
    p.rights.lock().unwrap().extend([old, other, src]);
    TRANSIT_KEYS.lock().unwrap().extend([old, other]);
    let now = Instant::now();
    m.rev.lock().unwrap().insert(src, (old, now));
    let mut notice = vec![TAG, 0];
    notice.extend_from_slice(&id_of(&src));
    let notice = Bytes::from(notice);
    m.on_frame(&other, &notice);
    assert_eq!(m.rev.lock().unwrap().get(&src).map(|x| x.0), Some(old), "посторонний транзит не отзывает чужой маршрут");
    TRANSIT_KEYS.lock().unwrap().remove(&old);
    m.on_frame(&old, &notice);
    assert_eq!(m.rev.lock().unwrap().get(&src).map(|x| x.0), Some(old), "сосед без TRANSIT не может отзывать обратный маршрут");
    TRANSIT_KEYS.lock().unwrap().insert(old);
    p.bump();
    m.sync_gen(p.as_ref());
    m.rev.lock().unwrap().insert(src, (old, now));
    m.on_frame(&old, &notice);
    assert!(!m.rev.lock().unwrap().contains_key(&src));
    m.rev.lock().unwrap().insert(src, (other, now));
    m.on_frame(&old, &notice);
    assert_eq!(m.rev.lock().unwrap().get(&src).map(|x| x.0), Some(other), "задержанный отказ старого транзита не портит новый путь");
    p.rights.lock().unwrap().remove(&other);
    p.bump();
    m.sync_gen(p.as_ref());
    m.rev.lock().unwrap().insert(src, (other, now));
    m.on_frame(&other, &notice);
    assert_eq!(m.rev.lock().unwrap().get(&src).map(|x| x.0), Some(other), "отозванный сосед не может менять маршруты");
    TRANSIT_KEYS.lock().unwrap().remove(&old);
    TRANSIT_KEYS.lock().unwrap().remove(&other);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_reverse_entry_is_not_overwritten_while_old_neighbor_is_alive() {
    let (a, b) = (node().await, node().await);
    link(&a, &b).await;
    let (x, other) = ([2u8; 32], [7u8; 32]);
    let now = Instant::now();
    a.mesh.learn(now, &x, &b.id());
    a.mesh.learn(now, &x, &other);
    assert_eq!(a.mesh.c.rev_conflict.load(Relaxed), 1);
    assert_eq!(a.mesh.rev.lock().unwrap().get(&x).map(|e| e.0), Some(b.id()));
    // то же сосед (обновление) - можно
    a.mesh.learn(now, &x, &b.id());
    assert_eq!(a.mesh.c.rev_conflict.load(Relaxed), 1);
}

#[test]
fn revocation_applies_to_the_very_next_frame() {
    let (m, p) = bare(true);
    let (prev, src, dst) = ([1; 32], [2; 32], [3; 32]);
    p.rights.lock().unwrap().extend([prev, src, dst]);
    p.routes.lock().unwrap().insert(dst, [4; 32]);
    m.on_frame(&prev, &frame(8, &dst, &src, b"x"));
    assert_eq!((m.c.drop_no_quic.load(Relaxed), m.c.drop_unknown_key.load(Relaxed), m.c.drop_policy.load(Relaxed)), (1, 0, 0));
    // отзыв назначения + смена поколения: следующий кадр отвергнут сразу, без ожидания TTL кэшей
    p.rights.lock().unwrap().remove(&dst);
    p.bump();
    m.on_frame(&prev, &frame(8, &dst, &src, b"x"));
    assert_eq!((m.c.drop_no_quic.load(Relaxed), m.c.drop_unknown_key.load(Relaxed)), (1, 1));
    assert_eq!(m.c.gen_resets.load(Relaxed), 1);
    // отзыв предыдущего хопа
    p.rights.lock().unwrap().insert(dst);
    p.bump();
    m.on_frame(&prev, &frame(8, &dst, &src, b"x"));
    assert_eq!(m.c.drop_no_quic.load(Relaxed), 2);
    p.rights.lock().unwrap().remove(&prev);
    p.bump();
    m.on_frame(&prev, &frame(8, &dst, &src, b"x"));
    assert_eq!(m.c.drop_policy.load(Relaxed), 1);
}

#[test]
fn ttl_above_max_is_dropped() {
    let (m, p) = bare(true);
    let (prev, src, dst) = ([1; 32], [2; 32], [3; 32]);
    p.rights.lock().unwrap().extend([prev, src, dst]);
    p.routes.lock().unwrap().insert(dst, [4; 32]);
    m.on_frame(&prev, &frame(MAX_TTL + 1, &dst, &src, b"x"));
    m.on_frame(&prev, &frame(255, &dst, &src, b"x"));
    m.on_frame(&prev, &frame(0, &dst, &src, b"x"));
    assert_eq!((m.c.drop_ttl.load(Relaxed), m.c.drop_no_quic.load(Relaxed)), (3, 0));
    m.on_frame(&prev, &frame(MAX_TTL, &dst, &src, b"x"));
    assert_eq!(m.c.drop_no_quic.load(Relaxed), 1);
}

#[test]
fn ambiguous_own_id8_is_not_delivered() {
    let (m, p) = bare(false);
    let me = *m.me();
    let mut twin = [1u8; 32];
    twin[..8].copy_from_slice(&me[..8]);
    let src = [2u8; 32];
    p.rights.lock().unwrap().extend([src, twin]);
    m.on_frame(&src, &frame(8, &me, &src, b"x"));
    assert_eq!((m.c.drop_id_ambiguous.load(Relaxed), m.c.delivered.load(Relaxed)), (1, 0));
}

/// Использует реальную rootless-таблицу как MeshPolicy: собственная identity не находится в peers.
#[test]
fn local_delivery_with_real_peers_keeps_source_and_revocation_checks() {
    use crate::peers::{self, Actor, Peers};
    use leviculum_std::api::Identity;

    struct TablePolicy(Mutex<Peers>);
    impl Policy for TablePolicy {
        fn may_forward(&self, p: &Key, s: &Key, d: &Key) -> bool { self.0.lock().unwrap().mesh_forward(p, s, d) }
        fn holds_rights(&self, k: &Key) -> bool { self.0.lock().unwrap().knows_key(k) }
        fn is_transit(&self, k: &Key) -> bool { self.0.lock().unwrap().roles_of_key(k) & peers::TRANSIT != 0 }
        fn transit_candidates(&self) -> Vec<Key> { vec![] }
        fn generation(&self) -> u64 { self.0.lock().unwrap().generation().load(Relaxed) }
        fn route(&self, _: &Key) -> Option<Key> { None }
        fn key_for_id(&self, id: &Id) -> Option<Key> { self.0.lock().unwrap().key_for_id8(id) }
        fn local_key_for_id(&self, id: &Id) -> Option<Key> { self.0.lock().unwrap().local_key_for_id8(id) }
    }

    let me_pk = Identity::generate(&mut rand_core::OsRng).public_key_bytes();
    let src_pk = Identity::generate(&mut rand_core::OsRng).public_key_bytes();
    let (me, src) = (peers::key_of(&me_pk), peers::key_of(&src_pk));
    let mut table = Peers::new(me_pk, None);
    table.peer_set(&Actor::Local, src_pk, peers::USE, "", 1_000, 1_000).unwrap();
    let p = Arc::new(TablePolicy(Mutex::new(table)));
    let m = Mesh::with_carriers(me, true, Arc::new(|_| None));
    m.set_policy(p.clone());
    m.on_frame(&src, &frame(8, &me, &src, b"test"));
    assert_eq!(m.c.delivered.load(Relaxed), 1, "известный сосед доставляет локальному ключу без self-peer");
    m.on_frame(&src, &frame(8, &me, &me, b"spoof"));
    assert_eq!(m.c.drop_unknown_key.load(Relaxed), 1, "свой ключ не разрешается как источник");
    let hash = peers::hash_of(&src_pk).unwrap();
    p.0.lock().unwrap().peer_remove(&Actor::Local, &hash, 1_001, 1_001).unwrap();
    m.on_frame(&src, &frame(8, &me, &src, b"revoked"));
    assert_eq!(m.c.delivered.load(Relaxed), 1, "отзыв не должен доставлять новые кадры");
}

#[test]
fn client_contact_delivery_respects_cache_invalidation_and_no_forwarding() {
    use crate::peers::{self, Actor, Peers};
    use leviculum_std::api::Identity;
    struct ClientPolicy(Mutex<Peers>);
    impl Policy for ClientPolicy {
        fn may_forward(&self, _: &Key, _: &Key, _: &Key) -> bool { false }
        fn holds_rights(&self, k: &Key) -> bool { self.0.lock().unwrap().mesh_knows_key(k) }
        fn is_transit(&self, k: &Key) -> bool {
            let t = self.0.lock().unwrap();
            t.mesh_knows_key(k) && t.roles_of_key(k) & peers::TRANSIT != 0
        }
        fn transit_candidates(&self) -> Vec<Key> { vec![] }
        fn generation(&self) -> u64 { self.0.lock().unwrap().generation().load(Relaxed) }
        fn route(&self, _: &Key) -> Option<Key> { None }
        fn key_for_id(&self, id: &Id) -> Option<Key> { self.0.lock().unwrap().key_for_id8(id) }
        fn local_key_for_id(&self, id: &Id) -> Option<Key> { self.0.lock().unwrap().local_key_for_id8(id) }
        fn local_source_key_for_id(&self, id: &Id) -> Option<Key> { self.0.lock().unwrap().client_mesh_source_for_id8(id) }
    }
    let identity = || Identity::generate(&mut rand_core::OsRng).public_key_bytes();
    let (me_pk, transit_pk, exit_pk, unknown_pk) = (identity(), identity(), identity(), identity());
    let (me, transit, exit, unknown) = (peers::key_of(&me_pk), peers::key_of(&transit_pk), peers::key_of(&exit_pk), peers::key_of(&unknown_pk));
    let mut table = Peers::new(me_pk, None);
    table.accepted(transit_pk, "", vec![], peers::USE, peers::TRANSIT, 1_000).unwrap();
    table.accepted(exit_pk, "", vec![], peers::USE, peers::EXIT, 1_000).unwrap();
    let policy = Arc::new(ClientPolicy(Mutex::new(table)));
    let mesh = Mesh::with_carriers(me, true, Arc::new(|_| None));
    mesh.set_policy(policy.clone());
    mesh.on_frame(&transit, &frame(8, &me, &exit, b"first"));
    assert_eq!(mesh.c.delivered.load(Relaxed), 1);
    mesh.on_frame(&transit, &frame(8, &me, &unknown, b"unknown"));
    mesh.on_frame(&transit, &frame(8, &exit, &exit, b"forward"));
    assert_eq!(mesh.c.delivered.load(Relaxed), 1);
    assert_eq!(mesh.c.fwd.load(Relaxed), 0);
    let hash = peers::hash_of(&exit_pk).unwrap();
    assert!(policy.0.lock().unwrap().set_contact_grant(&hash, 0));
    mesh.on_frame(&transit, &frame(8, &me, &exit, b"no-grant"));
    assert_eq!(mesh.c.delivered.load(Relaxed), 1, "смена контакта инвалидирует кэш источника");
    {
        let mut t = policy.0.lock().unwrap();
        assert!(t.set_contact_grant(&hash, peers::USE));
        t.peer_set(&Actor::Local, exit_pk, peers::USE, "", 1_000, 1_000).unwrap();
        t.peer_remove(&Actor::Local, &hash, 1_001, 1_001).unwrap();
    }
    mesh.on_frame(&transit, &frame(8, &me, &exit, b"revoked"));
    assert_eq!(mesh.c.delivered.load(Relaxed), 1, "отозванный peer не возвращается через contact");
}

/// Микроизмерение только горячего кэша разрешения источника; это не скорость VPN.
#[test]
#[ignore = "ручное микроизмерение overhead"]
fn local_source_cache_overhead() {
    use std::hint::black_box;
    let (mesh, policy) = bare(true);
    let source = [42; 32];
    let id = id_of(&source);
    policy.rights.lock().unwrap().insert(source);
    let now = Instant::now();
    assert_eq!(mesh.key_of(now, &id, policy.as_ref()), Some(source));
    assert_eq!(mesh.local_source_key(now, &id, policy.as_ref()), Some(source));
    const N: usize = 1_000_000;
    for _ in 0..3 {
        let start = Instant::now();
        for _ in 0..N { black_box(mesh.key_of(now, black_box(&id), policy.as_ref())); }
        let old = start.elapsed();
        let start = Instant::now();
        for _ in 0..N { black_box(mesh.local_source_key(now, black_box(&id), policy.as_ref())); }
        let new = start.elapsed();
        println!("source-cache N={N} baseline_ns={:.1} new_ns={:.1}", old.as_nanos() as f64 / N as f64, new.as_nanos() as f64 / N as f64);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rootless_tables_without_self_peer_complete_mesh_quic() {
    use crate::peers::{self, Actor, Peers};
    struct TablePolicy { table: Mutex<Peers>, routes: HashMap<Key, Key>, client: bool }
    impl Policy for TablePolicy {
        fn may_forward(&self, p: &Key, s: &Key, d: &Key) -> bool { self.table.lock().unwrap().mesh_forward(p, s, d) }
        fn holds_rights(&self, k: &Key) -> bool { self.table.lock().unwrap().mesh_knows_key(k) }
        fn is_transit(&self, k: &Key) -> bool {
            let t = self.table.lock().unwrap();
            t.mesh_knows_key(k) && t.roles_of_key(k) & peers::TRANSIT != 0
        }
        fn transit_candidates(&self) -> Vec<Key> {
            self.table.lock().unwrap().contact_list().into_iter()
                .filter(|c| c.roles & peers::TRANSIT != 0).map(|c| peers::key_of(&c.pk)).collect()
        }
        fn generation(&self) -> u64 { self.table.lock().unwrap().generation().load(Relaxed) }
        fn route(&self, dst: &Key) -> Option<Key> { self.routes.get(dst).copied() }
        fn key_for_id(&self, id: &Id) -> Option<Key> { self.table.lock().unwrap().key_for_id8(id) }
        fn local_key_for_id(&self, id: &Id) -> Option<Key> { self.table.lock().unwrap().local_key_for_id8(id) }
        fn local_source_key_for_id(&self, id: &Id) -> Option<Key> {
            let t = self.table.lock().unwrap();
            if self.client { t.client_mesh_source_for_id8(id) } else { t.key_for_id8(id) }
        }
    }
    fn pk(n: &Node) -> peers::Pk {
        let mut pk = [7u8; 64];
        pk[32..].copy_from_slice(&n.id());
        pk
    }
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    for n in [&a, &t, &e] {
        let mut table = Peers::new(pk(n), None);
        for other in [&a, &t, &e] {
            if n.id() != other.id() {
                if n.id() == a.id() {
                    // Телефон вступил по приглашению: серверы — контакты, не держатели прав на телефоне.
                    let roles = if other.id() == t.id() { peers::TRANSIT } else { peers::EXIT };
                    table.accepted(pk(other), "", vec![], peers::USE, roles, 1_000).unwrap();
                } else {
                    table.peer_set(&Actor::Local, pk(other), peers::USE, "", 1_000, 1_000).unwrap();
                }
            }
        }
        if n.id() != t.id() {
            table.accepted(pk(&t), "", vec![], peers::USE, peers::TRANSIT, 1_000).unwrap();
        } else {
            table.set_config(&Actor::Local, Some(true), None).unwrap();
        }
        assert_eq!(table.key_for_id8(&id_of(&n.id())), None, "своего ключа в peers нет");
        let mut routes = HashMap::new();
        if n.id() == a.id() { routes.insert(e.id(), t.id()); }
        n.mesh.set_policy(Arc::new(TablePolicy { table: Mutex::new(table), routes, client: n.id() == a.id() }));
    }
    let (ca, ce) = e2e_connect(&a, &e).await;
    assert_eq!(ca.remote_id().as_bytes(), &e.id(), "TLS клиента доказывает ключ выхода");
    assert_eq!(ce.remote_id().as_bytes(), &a.id(), "TLS выхода доказывает ключ клиента");
    echo(&ca, &ce).await;
    assert!(t.mesh.c.fwd.load(Relaxed) > 0);
    assert!(e.mesh.c.delivered.load(Relaxed) > 0);
    assert_eq!(e.mesh.c.drop_id_ambiguous.load(Relaxed), 0);
    assert!(!t.saw_plain.load(Relaxed), "транзит не видит открытый текст");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_transit_during_incoming_frame_and_migration_load_fails_closed() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, ce) = e2e_connect(&a, &e).await;
    assert!(e.mesh.mark_e2e(&ce));
    let mut secret = [0u8; 32];
    ca.export_keying_material(&mut secret, migration::LABEL, b"").unwrap();
    let (src, dst, via) = (a.id(), e.id(), t.id());
    let proof = Bytes::from(migration::encode(&secret, &src, &dst, &via, 1).unwrap());
    e.mesh.on_frame(&via, &proof);
    assert!(e.mesh.verified_rev.lock().unwrap().contains_key(&src));
    let m = e.mesh.clone();
    let running = Arc::new(AtomicBool::new(true));
    let running_task = running.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let load = tokio::spawn(async move {
        let packet = frame(MAX_TTL, &dst, &src, b"untrusted-test-ciphertext");
        let mut ready = Some(ready_tx);
        let mut seq = 2;
        while running_task.load(Relaxed) {
            m.on_frame(&via, &packet);
            let p = Bytes::from(migration::encode(&secret, &src, &dst, &via, seq).unwrap());
            m.on_frame(&via, &p);
            seq += 1;
            if let Some(tx) = ready.take() { let _ = tx.send(()); }
            tokio::task::yield_now().await;
        }
    });
    ready_rx.await.unwrap();
    e.pol.rights.lock().unwrap().remove(&via);
    e.pol.bump();
    e.mesh.sync_gen(e.pol.as_ref());
    let denied = e.mesh.c.drop_policy.load(Relaxed);
    tokio::time::timeout(Duration::from_secs(5), async {
        while e.mesh.c.drop_policy.load(Relaxed) == denied { tokio::task::yield_now().await; }
    }).await.expect("кадры от отозванного транзита должны отвергаться");
    running.store(false, Relaxed);
    load.await.unwrap();
    e.mesh.sync_gen(e.pol.as_ref());
    assert!(e.mesh.verified_rev.lock().unwrap().get(&src).is_none());
    assert_ne!(e.mesh.next_hop_origin(Instant::now(), &src, e.pol.as_ref()), Some(via));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_proof_is_sent_and_forwarded_over_neighbor_quic() {
    let (a, old, new, e) = (node().await, node().await, node().await, node().await);
    link(&a, &old).await;
    link(&old, &e).await;
    link(&a, &new).await;
    link(&new, &e).await;
    allow_all(&[&a, &old, &new, &e]);
    old.set_transit(true);
    new.set_transit(true);
    route(&a, &e, &old);
    let (ca, ce) = e2e_connect(&a, &e).await;
    assert!(a.mesh.mark_e2e(&ca));
    assert!(e.mesh.mark_e2e(&ce));
    let carrier = a.nbrs.read().unwrap().get(&new.id()).cloned().unwrap();
    a.mesh.send_migration(&e.id(), &new.id(), &carrier);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if e.mesh.verified_rev.lock().unwrap().get(&a.id()).is_some_and(|(via, _)| *via == new.id()) { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("migration proof not delivered");
    assert_eq!(e.mesh.next_hop_origin(Instant::now(), &a.id(), e.pol.as_ref()), Some(new.id()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_receiver_requires_session_mac_transit_and_fresh_sequence() {
    let (a, old, new, e) = (node().await, node().await, node().await, node().await);
    link(&a, &old).await;
    link(&old, &e).await;
    link(&new, &e).await;
    allow_all(&[&a, &old, &new, &e]);
    old.set_transit(true);
    new.set_transit(true);
    route(&a, &e, &old);
    let (ca, ce) = e2e_connect(&a, &e).await;
    assert!(e.mesh.mark_e2e(&ce));
    e.mesh.sync_gen(e.pol.as_ref());
    let mut secret = [0u8; 32];
    ca.export_keying_material(&mut secret, migration::LABEL, b"").unwrap();
    let proof = Bytes::from(migration::encode(&secret, &a.id(), &e.id(), &new.id(), 1).unwrap());
    // Другой сосед не может присвоить предназначенное новому транзиту доказательство.
    e.mesh.on_frame(&old.id(), &proof);
    assert!(e.mesh.verified_rev.lock().unwrap().get(&a.id()).is_none());
    e.mesh.on_frame(&new.id(), &proof);
    assert_eq!(e.mesh.verified_rev.lock().unwrap().get(&a.id()).copied(), Some((new.id(), ce.stable_id())));
    assert_eq!(e.mesh.next_hop_origin(Instant::now(), &a.id(), e.pol.as_ref()), Some(new.id()));
    // Отзыв транзита сбрасывает подтверждённый маршрут при новом поколении
    // прав, даже если сквозное TLS-соединение ещё открыто.
    e.pol.rights.lock().unwrap().remove(&new.id());
    e.pol.bump();
    e.mesh.sync_gen(e.pol.as_ref());
    assert!(e.mesh.verified_rev.lock().unwrap().get(&a.id()).is_none());
    assert_ne!(e.mesh.next_hop_origin(Instant::now(), &a.id(), e.pol.as_ref()), Some(new.id()));
    e.pol.rights.lock().unwrap().insert(new.id());
    e.pol.bump();
    e.mesh.sync_gen(e.pol.as_ref());
    // Повтор после удаления маршрута не создаёт его снова.
    e.mesh.verified_rev.lock().unwrap().remove(&a.id());
    e.mesh.on_frame(&new.id(), &proof);
    assert!(e.mesh.verified_rev.lock().unwrap().get(&a.id()).is_none());
    new.set_transit(false);
    let next = Bytes::from(migration::encode(&secret, &a.id(), &e.id(), &new.id(), 2).unwrap());
    e.mesh.on_frame(&new.id(), &next);
    assert!(e.mesh.verified_rev.lock().unwrap().get(&a.id()).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_hop_cache_never_sends_into_a_connection_that_rides_mesh() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, _ce) = e2e_connect(&a, &e).await;
    assert!(a.mesh.mark_e2e(&ca));
    // «устаревший» кэш хопа, указывающий на помеченное сквозное соединение
    a.mesh.hops.lock().unwrap().insert(e.id(), HopEntry { res: Ok(HopConn { sid: ca.stable_id(), peer: e.id(), conn: ca.clone() }), at: Instant::now() });
    let tx = a.mesh.c.tx.load(Relaxed);
    a.mesh.send_payload(&e.id(), b"x");
    assert_eq!((a.mesh.c.tx.load(Relaxed), a.mesh.c.drop_recursion.load(Relaxed)), (tx, 1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_table_overflow_fails_closed() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    a.mesh.set_e2e_max(1);
    let (ca, _ce) = e2e_connect(&a, &e).await;
    assert!(a.mesh.mark_e2e(&ca));
    let c2 = tokio::time::timeout(Duration::from_secs(10), a.ep.connect(EndpointAddr::new(t.ep.id()), NBR)).await.expect("timeout").expect("connect");
    assert!(!a.mesh.mark_e2e(&c2), "таблица заполнена - пометить нельзя, соединение должно быть закрыто вызывающим");
    assert_eq!(a.mesh.c.e2e_overflow.load(Relaxed), 1);
}

#[test]
fn reverse_table_is_bounded() {
    let (m, _p) = bare(false);
    let now = Instant::now();
    for i in 0..(REV_MAX + 50) {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&(i as u64).to_le_bytes());
        m.learn(now, &k, &[7; 32]);
    }
    assert_eq!(m.rev.lock().unwrap().len(), REV_MAX);
}

#[test]
fn gso_transmit_is_split_into_datagrams() {
    let data: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
    let segs: Vec<&[u8]> = segments(&data, Some(1000)).collect();
    assert_eq!(segs.iter().map(|s| s.len()).collect::<Vec<_>>(), vec![1000, 1000, 500]);
    assert_eq!(segs.concat(), data);
    assert_eq!(segments(&data, None).count(), 1);
    assert_eq!(segments(&[], None).count(), 0);
    // у IP-транспорта на Linux до 64 сегментов; меньшее значение у нашего sender отключило бы GSO прямому пути (iroh берёт минимум по транспортам)
    assert!(MAX_SEGMENTS >= 64);
}

// ---------------------------------------------------------------- GSO прямого IP-пути

fn udp_out_datagrams() -> u64 {
    let s = std::fs::read_to_string("/proc/net/snmp").unwrap();
    let mut it = s.lines().filter(|l| l.starts_with("Udp:"));
    let (h, v) = (it.next().unwrap(), it.next().unwrap());
    let i = h.split_whitespace().position(|x| x == "OutDatagrams").unwrap();
    v.split_whitespace().nth(i).unwrap().parse().unwrap()
}

/// Передать `mib` МиБ потоком A -> E по прямому IP; вернуть (пакетов QUIC отправлено, UDP-датаграмм ядра за передачу). Ядро считает GSO-пакет один раз
/// (`UDP_MIB_OUTDATAGRAMS` растёт до сегментации), поэтому отношение показывает среднее число сегментов на системный вызов.
async fn bulk_direct(with_mesh: bool, mib: usize) -> (u64, u64) {
    let (a, e) = (node_with(with_mesh).await, node_with(with_mesh).await);
    let conn = a.ep.connect(EndpointAddr::new(e.ep.id()).with_ip_addr(ip(&e)), ALPN).await.unwrap();
    let ce = e.e2e.lock().await.recv().await.unwrap();
    let before = udp_out_datagrams();
    let n = mib << 20;
    let mut s = conn.open_uni().await.unwrap();
    let wr = tokio::spawn(async move {
        let chunk = vec![7u8; 64 * 1024];
        for _ in 0..(n / chunk.len()) {
            s.write_all(&chunk).await.unwrap();
        }
        s.finish().unwrap();
    });
    let mut r = ce.accept_uni().await.unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let mut got = 0;
    while let Some(k) = r.read(&mut buf).await.unwrap() {
        got += k;
    }
    wr.await.unwrap();
    assert_eq!(got, n);
    let out = udp_out_datagrams() - before;
    (conn.stats().udp_tx.datagrams, out)
}

/// Запуск: `unshare -rn sh -c 'ip link set lo up; cargo test ... mesh::tests::gso -- --ignored --nocapture'` (чистый netns, иначе счётчики ядра шумят).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "нужен свободный netns: счётчик UDP ядра общий"]
async fn gso_of_direct_ip_path_is_not_reduced_by_mesh_transport() {
    let mut f = [(0.0f64, 0.0f64); 2];
    for round in 0..3 {
        for (i, mesh) in [false, true].into_iter().enumerate() {
            let (q, k) = bulk_direct(mesh, 64).await;
            let factor = q as f64 / k.max(1) as f64;
            println!("round {round} mesh={mesh}: quic_packets={q} kernel_udp_out={k} segments/syscall={factor:.2}");
            f[i].0 += factor;
            f[i].1 += 1.0;
        }
    }
    let (plain, with) = (f[0].0 / f[0].1, f[1].0 / f[1].1);
    println!("mean segments per kernel send: without mesh {plain:.2}, with mesh transport {with:.2}");
    assert!(plain > 1.5, "GSO в этом окружении не работает - сравнивать нечего");
    assert!(with >= plain * 0.85, "mesh-транспорт снизил GSO прямого пути: {plain:.2} -> {with:.2}");
}

/// iroh держит пути пира общими для всех соединений к его ключу: обычное соединение к выходу, открытое после mesh-соединения, идёт по mesh-пути и
/// не может считаться соседом (иначе кадры mesh попадали бы в соединение, которое само идёт по mesh).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_connection_to_mesh_peer_rides_mesh_and_is_not_a_neighbor() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, _ce) = e2e_connect(&a, &e).await;
    assert!(a.mesh.rides_mesh(&ca));
    // второе соединение к тому же ключу: адрес не задан, iroh берёт известные пути пира (mesh)
    let c2 = tokio::time::timeout(Duration::from_secs(10), a.ep.connect(EndpointAddr::new(e.ep.id()), ALPN)).await.expect("timeout").expect("connect");
    // c2 сначала едет по mesh, потом iroh находит прямой путь: в обоих случаях кадры mesh к E идут через T, а не в соединение к E
    // и ни одно из них не используется как сосед для кадров mesh
    a.nbrs.write().unwrap().insert(e.id(), c2.clone());
    a.mesh.warm(&e.id());
    let cached = {
        let hops = a.mesh.hops.lock().unwrap();
        match hops.get(&e.id()).map(|h| &h.res) {
            Some(Ok(h)) if h.peer == t.id() => "transit",
            Some(Ok(_)) => "other",
            Some(Err(HopErr::NoRoute)) => "no_route",
            Some(Err(HopErr::NoQuic)) => "no_quic",
            Some(Err(HopErr::TooSmall)) => "too_small",
            None => "missing",
        }
    };
    let before = a.mesh.c.tx.load(Relaxed);
    a.mesh.send_payload(&e.id(), b"x");
    let cached_after = {
        let hops = a.mesh.hops.lock().unwrap();
        match hops.get(&e.id()).map(|h| &h.res) {
            Some(Ok(h)) if h.peer == t.id() => "transit",
            Some(Ok(_)) => "other",
            Some(Err(HopErr::NoRoute)) => "no_route",
            Some(Err(HopErr::NoQuic)) => "no_quic",
            Some(Err(HopErr::TooSmall)) => "too_small",
            None => "missing",
        }
    };
    let t_conn = a.nbrs.read().unwrap().get(&t.id()).cloned().unwrap();
    let t_paths: Vec<_> = t_conn.paths().iter().map(|p| (p.is_selected(), p.stats().current_mtu, p.stats().rtt)).collect();
    assert_eq!(cached, "transit", "в кэше должен быть транзит, а не сквозной QUIC к выходу");
    // Счётчик общий: параллельное рукопожатие может отправить дополнительные
    // кадры между чтением `before` и проверкой, поэтому ровно +1 не гарантировано.
    assert!(a.mesh.c.tx.load(Relaxed) > before,
        "кадр уходит через T, а не в соединение к E: {}; cached={cached}, cached_after={cached_after}, neighbor_max_datagram={:?}, required={}, neighbor_paths={t_paths:?}",
        a.mesh.stats(), t_conn.max_datagram_size(), a.mesh.min_nbr_dgram.load(Relaxed));
}

/// Патч iroh (`bench/vendor/iroh/PATCH.md`): при соединении с IP-адресом И mesh-адресом mesh-путь открывается тёплым запасным (Backup), IP выбран основным.
/// Без патча IP выигрывает гонку рукопожатия, и mesh-путь не открывается вообще (тогда при блокировке прямого пути соединение умирает).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custom_address_opens_as_warm_backup_next_to_ip() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    a.mesh.prepare(&e.id());
    let addr = EndpointAddr::from_parts(e.ep.id(), [TransportAddr::Ip(ip(&e)), TransportAddr::Custom(addr_of(&e.id()))]);
    let acc = async { tokio::time::timeout(Duration::from_secs(10), e.e2e.lock().await.recv()).await.unwrap().unwrap() };
    let (c, s) = tokio::join!(tokio::time::timeout(Duration::from_secs(10), a.ep.connect(addr, ALPN)), acc);
    let (ca, ce) = (c.expect("timeout").expect("connect"), s);
    let t0 = Instant::now();
    let both = loop {
        let paths = ca.paths();
        let has_custom = paths.iter().any(|p| matches!(p.remote_addr(), TransportAddr::Custom(_)));
        let ip_sel = paths.iter().any(|p| p.is_selected() && p.is_ip());
        if has_custom && ip_sel {
            break true;
        }
        if t0.elapsed() > Duration::from_secs(8) {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(both, "paths: {:?}", ca.paths().iter().map(|p| (p.remote_addr().clone(), p.is_selected())).collect::<Vec<_>>());
    println!("max_datagram_size: {:?}, paths: {:?}", ca.max_datagram_size(), ca.paths().iter().map(|p| (p.remote_addr().clone(), p.is_selected(), p.stats().current_mtu)).collect::<Vec<_>>());
    // запасной путь действительно живой: по нему ходят кадры (валидация пути), а данные идут по IP
    echo(&ca, &ce).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(t.mesh.c.fwd.load(Relaxed) > 0, "по mesh-пути идут кадры валидации/keepalive");
}

/// Блокировка прямого UDP A<->E в приватном netns (`unshare -rn`, KH_NETNS=1): nft drop по портам сокетов A и E.
fn nft_block(a: &Node, e: &Node, on: bool) {
    assert!(std::env::var("KH_NETNS").is_ok(), "блокировку выполнять только в приватном netns");
    let ports = |n: &Node| n.ep.bound_sockets().iter().map(|s| s.port().to_string()).collect::<Vec<_>>().join(",");
    let (pa, pe) = (ports(a), ports(e));
    let script = if on {
        format!("add table inet lab\nadd chain inet lab c {{ type filter hook output priority 0; }}\nadd rule inet lab c udp sport {{ {pa} }} udp dport {{ {pe} }} drop\nadd rule inet lab c udp sport {{ {pe} }} udp dport {{ {pa} }} drop\n")
    } else {
        "delete table inet lab\n".to_string()
    };
    let mut ch = std::process::Command::new("nft").args(["-f", "-"]).stdin(std::process::Stdio::piped()).spawn().unwrap();
    use std::io::Write;
    ch.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
    assert!(ch.wait().unwrap().success());
}

/// Переключение на тёплый запасной путь: поток датаграмм A->E каждые 20 мс, блок прямого UDP, замер паузы в доставке; разблок - возврат на IP.
/// Запуск: `unshare -rn sh -c 'ip link set lo up; KH_NETNS=1 bash bench/cargo_fork.sh rns-iroh-node test --offline --locked --lib mesh::tests::failover -- --ignored --nocapture'`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "нужен приватный netns с nft"]
async fn failover_to_warm_backup_and_back() {
    assert!(std::env::var("KH_NETNS").is_ok());
    let cfgs: [(&str, Option<(u64, u64, u64)>); 1] = [("default", None)];
    for (name, _cfg) in cfgs {
        let (a, t, e) = (node().await, node().await, node().await);
        link(&a, &t).await;
        link(&t, &e).await;
        allow_all(&[&a, &t, &e]);
        t.set_transit(true);
        route(&a, &e, &t);
        a.mesh.prepare(&e.id());
        let addr = EndpointAddr::from_parts(e.ep.id(), [TransportAddr::Ip(ip(&e)), TransportAddr::Custom(addr_of(&e.id()))]);
        let acc = async { e.e2e.lock().await.recv().await.unwrap() };
        let (c, ce) = tokio::join!(a.ep.connect(addr, ALPN), acc);
        let ca = c.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let rx = tokio::spawn({
            let ce = ce.clone();
            async move {
                let mut got: Vec<(u32, Instant)> = Vec::new();
                while let Ok(Ok(d)) = tokio::time::timeout(Duration::from_secs(40), ce.read_datagram()).await {
                    got.push((u32::from_be_bytes(d[..4].try_into().unwrap()), Instant::now()));
                }
                got
            }
        });
        let start = Instant::now();
        let mut seq = 0u32;
        let (mut blocked_at, mut unblocked_at) = (None, None);
        let mut saw_mesh_during_block = false;
        while start.elapsed() < Duration::from_secs(40) {
            let el = start.elapsed();
            if blocked_at.is_none() && el > Duration::from_secs(5) {
                nft_block(&a, &e, true);
                blocked_at = Some(Instant::now());
            }
            if blocked_at.is_some() && unblocked_at.is_none() && el > Duration::from_secs(25) {
                nft_block(&a, &e, false);
                unblocked_at = Some(Instant::now());
            }
            if blocked_at.is_some() && unblocked_at.is_none() {
                saw_mesh_during_block |= ca.paths().iter().any(|p| p.is_selected() && matches!(p.remote_addr(), TransportAddr::Custom(_)));
            }
            let _ = ca.send_datagram(Bytes::from(seq.to_be_bytes().to_vec()));
            seq += 1;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(saw_mesh_during_block, "backup must actually become selected during the block");
        assert!(ca.paths().iter().any(|p| p.is_selected() && matches!(p.remote_addr(), TransportAddr::Ip(_))), "direct path must return");
        ca.close(0u32.into(), b"test complete");
        drop(ca);
        let got = rx.await.unwrap();
        let (b0, u0) = (blocked_at.unwrap(), unblocked_at.unwrap());
        // наибольшая пауза в доставке после блока и после разблока
        let gap = |from: Instant, to: Instant| {
            let mut last = from;
            let mut worst = Duration::ZERO;
            for (_, t) in got.iter().filter(|(_, t)| *t >= from && *t <= to) {
                worst = worst.max(*t - last);
                last = *t;
            }
            worst.max(to.saturating_duration_since(last))
        };
        {
            // диагностика до проверок: где именно провал доставки во время блока
            let win: Vec<Duration> = got.iter().filter(|(_, t)| *t >= b0 && *t <= u0).map(|(_, t)| *t - b0).collect();
            let mut gaps: Vec<(Duration, Duration)> = Vec::new();
            let mut last = Duration::ZERO;
            for &t in &win {
                if t - last > Duration::from_millis(250) {
                    gaps.push((last, t - last));
                }
                last = t;
            }
            println!("[{name}] block window {:?}: delivered {}, first at {:?}, last at {:?}, gaps>250ms (start, len): {gaps:?}", u0 - b0, win.len(), win.first(), win.last());
        }
        let unique: std::collections::HashSet<_> = got.iter().map(|(n, _)| *n).collect();
        assert_eq!(unique.len(), got.len(), "duplicate application datagrams");
        assert!(got.iter().any(|(_, t)| *t >= b0 && *t < u0), "delivery must continue via backup");
        assert!(got.iter().any(|(_, t)| *t >= u0), "delivery must continue after unblock");
        assert!(gap(b0, u0) < Duration::from_secs(2), "backup delivery stalled");
        let lost_block = (seq as usize).saturating_sub(unique.len());
        println!("[{name}] sent={seq} got={} lost={lost_block}; worst gap after block {:?}, after unblock {:?}", got.len(), gap(b0, u0), gap(u0, u0 + Duration::from_secs(10)));
    }
}

/// Потеря сети клиентом: nft режет весь UDP узла A (оба направления, любые пиры) на `outage`, затем возврат. `notify` - оболочка сообщает о возврате сети
/// (`Endpoint::network_change`, как `mobile::network_changed` в knothopd). Замер: пауза в доставке датаграмм A->E после возврата.
async fn network_loss_run(notify: bool, outage: Duration) -> (Duration, usize, usize) {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    a.mesh.prepare(&e.id());
    let addr = EndpointAddr::from_parts(e.ep.id(), [TransportAddr::Ip(ip(&e)), TransportAddr::Custom(addr_of(&e.id()))]);
    let acc = async { e.e2e.lock().await.recv().await.unwrap() };
    let (c, ce) = tokio::join!(a.ep.connect(addr, ALPN), acc);
    let ca = c.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let rx = tokio::spawn({
        let ce = ce.clone();
        async move {
            let mut got: Vec<(u32, Instant)> = Vec::new();
            while let Ok(Ok(d)) = tokio::time::timeout(Duration::from_secs(25), ce.read_datagram()).await {
                got.push((u32::from_be_bytes(d[..4].try_into().unwrap()), Instant::now()));
            }
            got
        }
    });
    let ports: Vec<String> = a.ep.bound_sockets().iter().map(|s| s.port().to_string()).collect();
    let p = ports.join(",");
    let nft = |s: String| {
        let mut ch = std::process::Command::new("nft").args(["-f", "-"]).stdin(std::process::Stdio::piped()).spawn().unwrap();
        use std::io::Write;
        ch.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
        assert!(ch.wait().unwrap().success());
    };
    let start = Instant::now();
    let (mut down_at, mut up_at) = (None, None);
    let mut seq = 0u32;
    let mut sent_after_up = 0usize;
    let mut first_seq_after_up = None;
    while start.elapsed() < outage + Duration::from_secs(14) {
        let el = start.elapsed();
        if down_at.is_none() && el > Duration::from_secs(3) {
            nft(format!("add table inet lab\nadd chain inet lab o {{ type filter hook output priority 0; }}\nadd chain inet lab i {{ type filter hook input priority 0; }}\nadd rule inet lab o udp sport {{ {p} }} drop\nadd rule inet lab o udp dport {{ {p} }} drop\nadd rule inet lab i udp dport {{ {p} }} drop\n"));
            down_at = Some(Instant::now());
        }
        if down_at.is_some() && up_at.is_none() && el > Duration::from_secs(3) + outage {
            nft("delete table inet lab\n".into());
            up_at = Some(Instant::now());
            first_seq_after_up = Some(seq);
            if notify {
                a.ep.network_change().await;
            }
        }
        let _ = ca.send_datagram(Bytes::from(seq.to_be_bytes().to_vec()));
        if up_at.is_some() {
            sent_after_up += 1;
        }
        seq += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    ca.close(0u32.into(), b"test complete");
    drop(ca);
    let got = rx.await.unwrap();
    let up = up_at.unwrap();
    let first_seq = first_seq_after_up.unwrap();
    let after: Vec<_> = got.iter().filter(|(n, t)| *n >= first_seq && *t >= up).collect();
    let first_after = after.first().map(|(_, t)| *t - up).unwrap_or(Duration::from_secs(99));
    let unique: std::collections::HashSet<_> = after.iter().map(|(n, _)| *n).collect();
    assert_eq!(unique.len(), after.len(), "duplicate application datagrams");
    (first_after, sent_after_up, unique.len())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "нужен приватный netns с nft"]
async fn network_loss_recovery() {
    assert!(std::env::var("KH_NETNS").is_ok());
    for outage in [Duration::from_secs(3), Duration::from_secs(8)] {
        for notify in [false, true] {
            let (first, sent, got) = network_loss_run(notify, outage).await;
            println!("[netloss] outage={outage:?} notify={notify}: first delivery after return {first:?}; sent after return {sent}, delivered {got}");
            assert!(first < Duration::from_secs(2), "fresh post-outage packet must arrive within 2 s");
            assert!(got <= sent && got * 10 >= sent * 9, "at least 90% of post-outage packets must arrive");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_json_reports_kind_rtt_and_backup_from_quic() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    a.mesh.prepare(&e.id());
    let addr = EndpointAddr::from_parts(e.ep.id(), [TransportAddr::Ip(ip(&e)), TransportAddr::Custom(addr_of(&e.id()))]);
    let acc = async { e.e2e.lock().await.recv().await.unwrap() };
    let (c, _ce) = tokio::join!(a.ep.connect(addr, ALPN), acc);
    let ca = c.unwrap();
    let t0 = Instant::now();
    let j = loop {
        let j = path_json(&ca, a.mesh.hop_peer(&e.id()));
        if (j["kind"] == "direct" && j["backup"].as_array().is_some_and(|b| b.iter().any(|x| x == "mesh"))) || t0.elapsed() > Duration::from_secs(8) {
            break j;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(j["kind"], "direct", "{j}");
    assert!(j["backup"].as_array().unwrap().iter().any(|x| x == "mesh"), "{j}");
    assert!(j["rtt_ms"].as_f64().is_some());
    assert_eq!(j["path_desc"], "прямой (IP)");
    assert!(j["current_mtu"].as_u64().is_some_and(|mtu| mtu >= 1200));
    assert!(j["max_datagram_size"].as_u64().is_some());
    assert!(j["datagram_mtu_drops"].as_u64().is_some());
    assert!(j["nat_probes_suppressed"].as_u64().is_some());
    assert!(j["black_holes_detected"].as_u64().is_some());
}

#[test]
fn private_and_special_addresses_are_not_global() {
    use iroh::knothop::is_global;
    for s in ["127.0.0.1", "10.1.2.3", "192.168.0.9", "172.16.5.5", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "198.18.0.5", "::1", "fe80::1", "fc00::5", "ff02::1", "::"] {
        assert!(!is_global(&s.parse().unwrap()), "{s}");
    }
    for s in ["8.8.8.8", "1.1.1.1", "1.1.1.1", "2606:4700:4700::1111"] {
        assert!(is_global(&s.parse().unwrap()), "{s}");
    }
}

// ---------------------------------------------------------------- клиент за NAT

fn sh_ok(cmd: &str) {
    let o = std::process::Command::new("sh").args(["-c", cmd]).output().unwrap();
    assert!(o.status.success(), "{cmd}: {}", String::from_utf8_lossy(&o.stderr));
}

/// Дочерний процесс-держатель netns (`unshare -n sleep`); убивается при drop.
struct NetNs(std::process::Child);

impl NetNs {
    fn new() -> NetNs {
        NetNs(std::process::Command::new("unshare").args(["-n", "sleep", "600"]).spawn().unwrap())
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
    /// Команда внутри netns (ждём, пока unshare выполнит exec sleep: у процесса появится свой netns).
    fn sh(&self, cmd: &str) {
        sh_ok(&format!("nsenter -t {} -n sh -c '{}'", self.pid(), cmd));
    }
}

impl Drop for NetNs {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Tokio-рантайм, все потоки которого находятся в netns процесса `pid` (потоки наследуют netns создателя).
fn runtime_in_netns(pid: u32) -> tokio::runtime::Runtime {
    std::thread::spawn(move || {
        use std::os::fd::AsRawFd;
        let f = std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap();
        assert_eq!(unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) }, 0, "setns");
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
    })
    .join()
    .unwrap()
}

/// Стенд NAT: клиент C (192.168.50.2) - роутер R (masquerade) - "публичная" сеть 93.184.216.0/24 (этот netns): T = .11, E = .10.
/// `one_to_one`: E стоит за 1:1 NAT (облачная ВМ: у интерфейса только частный адрес 10.99.0.10, публичный .10 проброшен на роутере) в своём netns.
struct NatLab {
    _r: NetNs,
    _c: NetNs,
    _s: Option<NetNs>,
    c_rt: Option<tokio::runtime::Runtime>,
    s_rt: Option<tokio::runtime::Runtime>,
}

fn nat_lab(one_to_one: bool) -> NatLab {
    assert!(std::env::var("KH_NETNS").is_ok(), "только в приватном netns");
    let (r, c) = (NetNs::new(), NetNs::new());
    let s = one_to_one.then(NetNs::new);
    std::thread::sleep(Duration::from_millis(300));
    sh_ok("ip link set lo up");
    sh_ok("ip link add name kp type veth peer name kr1");
    sh_ok(&format!("ip link set kr1 netns {}", r.pid()));
    sh_ok("ip addr add 93.184.216.11/24 dev kp; ip link set kp up");
    if !one_to_one {
        sh_ok("ip addr add 93.184.216.10/24 dev kp");
    }
    sh_ok("ip link add name kc type veth peer name kc1");
    sh_ok(&format!("ip link set kc netns {}", r.pid()));
    sh_ok(&format!("ip link set kc1 netns {}", c.pid()));
    r.sh("ip link set lo up; ip addr add 93.184.216.1/24 dev kr1; ip link set kr1 up; ip addr add 192.168.50.1/24 dev kc; ip link set kc up; sysctl -qw net.ipv4.ip_forward=1");
    r.sh("nft add table ip nat; nft add chain ip nat post { type nat hook postrouting priority 100 \\; }; nft add rule ip nat post ip saddr 192.168.50.0/24 snat to 93.184.216.1");
    c.sh("ip link set lo up; ip addr add 192.168.50.2/24 dev kc1; ip link set kc1 up; ip route add default via 192.168.50.1");
    if let Some(s) = &s {
        sh_ok("ip link add name ks type veth peer name ks1");
        sh_ok(&format!("ip link set ks netns {}", r.pid()));
        sh_ok(&format!("ip link set ks1 netns {}", s.pid()));
        r.sh("ip addr add 10.99.0.1/24 dev ks; ip link set ks up; ip addr add 93.184.216.10/32 dev kr1");
        s.sh("ip link set lo up; ip addr add 10.99.0.10/24 dev ks1; ip link set ks1 up; ip route add default via 10.99.0.1");
        // 1:1 NAT как у облачных ВМ: входящие на публичный адрес идут на частный, исходящие с частного получают публичный
        r.sh("nft add table ip one; nft add chain ip one pre { type nat hook prerouting priority -100 \\; }; nft add rule ip one pre ip daddr 93.184.216.10 dnat to 10.99.0.10; nft add chain ip one post { type nat hook postrouting priority 90 \\; }; nft add rule ip one post ip saddr 10.99.0.10 oifname kr1 snat to 93.184.216.10");
    }
    let c_rt = runtime_in_netns(c.pid());
    let s_rt = s.as_ref().map(|s| runtime_in_netns(s.pid()));
    NatLab { _r: r, _c: c, _s: s, c_rt: Some(c_rt), s_rt }
}

/// Клиент за NAT начинает соединение с выходом по mesh (транзит T). Возвращает время до ухода с mesh на IP (None - не ушёл за 45 с).
/// `hint`: к адресу добавлен проверенный публичный IP выхода (как в `dial_direct`), иначе только mesh (как делал `mesh_carrier`).
async fn nat_run(one_to_one: bool, hint: bool, late_hint: bool) -> Option<Duration> {
    let mut lab = nat_lab(one_to_one);
    iroh::knothop::set_block_private_egress(true);
    struct Off;
    impl Drop for Off {
        fn drop(&mut self) {
            iroh::knothop::set_block_private_egress(false);
        }
    }
    let _off = Off;
    let t = node_bound(true, "93.184.216.11".parse().unwrap()).await;
    let e = match &lab.s_rt {
        Some(rt) => rt.spawn(node_bound(true, "10.99.0.10".parse().unwrap())).await.unwrap(),
        None => node_bound(true, "93.184.216.10".parse().unwrap()).await,
    };
    let a = lab.c_rt.as_ref().unwrap().spawn(node_bound(true, "192.168.50.2".parse().unwrap())).await.unwrap();
    let pub_addr = |n: &Node, ipa: &str| SocketAddr::new(ipa.parse().unwrap(), n.ep.bound_sockets()[0].port());
    let e_pub = pub_addr(&e, "93.184.216.10");
    // соседские связи по IP: A -> T (через NAT), T -> E (публично)
    let conn = a.ep.connect(EndpointAddr::new(t.ep.id()).with_ip_addr(pub_addr(&t, "93.184.216.11")), NBR).await.unwrap();
    add_nbr(&a.nbrs, &a.mesh, conn, a.saw_plain.clone(), a.drop_every.clone(), a.dropped.clone());
    let conn = t.ep.connect(EndpointAddr::new(e.ep.id()).with_ip_addr(e_pub), NBR).await.unwrap();
    add_nbr(&t.nbrs, &t.mesh, conn, t.saw_plain.clone(), t.drop_every.clone(), t.dropped.clone());
    let w = Instant::now();
    while !(t.nbrs.read().unwrap().contains_key(&a.id()) && e.nbrs.read().unwrap().contains_key(&t.id())) {
        assert!(w.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    a.mesh.prepare(&e.id());
    let addr = if hint { endpoint_addr_with(&e.id(), &[e_pub]).unwrap() } else { endpoint_addr(&e.id()).unwrap() };
    let acc = async { tokio::time::timeout(Duration::from_secs(10), e.e2e.lock().await.recv()).await.unwrap().unwrap() };
    let tc = Instant::now();
    let conn_fut = async {
        let r = tokio::time::timeout(Duration::from_secs(10), a.ep.connect(addr, ALPN)).await;
        println!("[nat] connect result after {:?}: ok={}", tc.elapsed(), matches!(r, Ok(Ok(_))));
        r
    };
    let (c, ce) = tokio::join!(conn_fut, acc);
    let ca = c.expect("connect timed out").expect("connect failed");
    echo(&ca, &ce).await;
    let t0 = Instant::now();
    let mut upgraded = None;
    let mut probe_done = !late_hint;
    while t0.elapsed() < Duration::from_secs(45) {
        if !probe_done && t0.elapsed() > Duration::from_secs(5) {
            probe_done = true;
            // подсказка IP позже: отдельное короткое соединение с IP-адресом выхода (как проба достижимости)
            let r = tokio::time::timeout(Duration::from_secs(6), a.ep.connect(EndpointAddr::new(e.ep.id()).with_ip_addr(e_pub), ALPN)).await;
            println!("[nat] late hint probe: ok={}", matches!(r, Ok(Ok(_))));
            if let Ok(Ok(c2)) = r {
                c2.close(0u32.into(), b"probe");
            }
        }
        if !mesh_selected(&ca) {
            upgraded = Some(t0.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!(
        "[nat one_to_one={one_to_one} hint={hint} late={late_hint}] upgraded_after={upgraded:?} paths={:?} blocked_egress={}",
        ca.paths().iter().map(|p| (p.remote_addr().clone(), p.is_selected())).collect::<Vec<_>>(),
        iroh::knothop::blocked_egress()
    );
    if upgraded.is_some() {
        echo(&ca, &ce).await;
    }
    ca.close(0u32.into(), b"done");
    a.ep.close().await;
    e.ep.close().await;
    t.ep.close().await;
    // рантаймы с сокетами в чужих netns не гасим синхронно внутри async-контекста
    if let Some(rt) = lab.s_rt.take() {
        rt.shutdown_background();
    }
    lab.c_rt.take().unwrap().shutdown_background();
    upgraded
}

/// Дефект живого пилота 03.11: клиент за NAT начал соединение с выходом только по mesh; выход с публичным адресом на интерфейсе (NAT traversal работает).
/// Запуск: `unshare -rn sh -c 'ip link set lo up; KH_NETNS=1 bash bench/cargo_fork.sh rns-iroh-node test --offline --locked --lib mesh::tests::nat_ -- --ignored --nocapture --test-threads=1'`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "нужен приватный netns (unshare -rn), ip, nft, nsenter"]
async fn nat_client_mesh_start_public_exit_upgrades_to_ip() {
    let up = nat_run(false, false, false).await;
    assert!(up.is_some(), "клиент за NAT остался на mesh при публичном выходе");
}

/// Выход за 1:1 NAT (облако: на интерфейсе только частный адрес, публичный iroh не знает - нет relay/QAD). Только mesh: NAT traversal нечем.
/// Диагностика дефекта живого пилота: результат печатается, без утверждения (апгрейда нет - известное ограничение iroh без relay/QAD).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "нужен приватный netns (unshare -rn), ip, nft, nsenter"]
async fn nat_exit_behind_1to1_nat_mesh_only_has_no_upgrade() {
    let r = nat_run(true, false, false).await;
    println!("[nat] 1:1 NAT выход, только mesh: {r:?}");
}

/// То же, но с проверенной подсказкой публичного IP выхода в адресе соединения (как в `dial_direct`): прямой путь обязан быть.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "нужен приватный netns (unshare -rn), ip, nft, nsenter"]
async fn nat_exit_behind_1to1_nat_with_ip_hint_goes_direct() {
    let r = nat_run(true, true, false).await;
    assert!(r.is_some(), "с подсказкой IP клиент остался на mesh");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "нужен приватный netns (unshare -rn), ip, nft, nsenter"]
async fn nat_public_exit_with_ip_hint_goes_direct() {
    let r = nat_run(false, true, false).await;
    assert!(r.is_some(), "с подсказкой IP клиент остался на mesh");
}

#[test]
fn only_mesh_custom_addr_is_mesh() {
    // REALITY-путь (другой id custom-транспорта) не mesh: соединение по туннелю REALITY годится соседом
    let key = [7u8; 32];
    assert!(is_mesh_addr(&TransportAddr::Custom(addr_of(&key))));
    assert!(!is_mesh_addr(&TransportAddr::Custom(crate::reality_carrier::addr_of(1))));
    assert!(!is_mesh_addr(&TransportAddr::Ip("192.0.2.1:47001".parse().unwrap())));
}

/// Доказательство приходит примерно раз в секунду и при неизменном транзите. Сброс кэша хопа на
/// каждом из них отбрасывал исходящие кадры как `drop_no_route` до следующего пересчёта.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_migration_proof_keeps_hop_cache_and_traffic() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, ce) = e2e_connect(&a, &e).await;
    assert!(e.mesh.mark_e2e(&ce));
    e.mesh.sync_gen(e.pol.as_ref());
    let mut secret = [0u8; 32];
    ca.export_keying_material(&mut secret, migration::LABEL, b"").unwrap();
    let proof = |seq| Bytes::from(migration::encode(&secret, &a.id(), &e.id(), &t.id(), seq).unwrap());
    e.mesh.on_frame(&t.id(), &proof(1));
    assert_eq!(e.mesh.hop_peer(&a.id()), Some(t.id()), "смена транзита применяется без окна потерь");
    let drops = e.mesh.c.drop_no_route.load(Relaxed);
    e.mesh.on_frame(&t.id(), &proof(2));
    assert_eq!(e.mesh.hop_peer(&a.id()), Some(t.id()), "повтор доказательства не должен сбрасывать хоп");
    e.mesh.send_payload(&a.id(), b"x");
    assert_eq!(e.mesh.c.drop_no_route.load(Relaxed), drops, "кадр не должен теряться из-за повтора");
}

/// Инициатор решает, отвечающий следует за ним. Если следуют оба, разные начальные маршруты
/// заставляют стороны меняться транзитами друг за другом.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_sides_do_not_chase_each_other_between_transits() {
    let (a, t1, t2, e) = (node_bound_mode(true, [127, 0, 0, 1].into(), true).await, node().await, node().await, node_bound_mode(true, [127, 0, 0, 1].into(), true).await);
    link(&a, &t1).await;
    link(&a, &t2).await;
    link(&t1, &e).await;
    link(&t2, &e).await;
    allow_all(&[&a, &t1, &t2, &e]);
    t1.set_transit(true);
    t2.set_transit(true);
    route(&a, &e, &t1);
    route(&e, &a, &t2);
    let (ca, ce) = e2e_connect(&a, &e).await;
    assert!(a.mesh.mark_e2e(&ca));
    assert!(e.mesh.mark_e2e(&ce));
    let (mut a_changes, mut last) = (0, a.mesh.hop_peer(&e.id()));
    for _ in 0..50 {
        a.mesh.warm(&e.id());
        e.mesh.warm(&a.id());
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = a.mesh.hop_peer(&e.id());
        if now != last { a_changes += 1; last = now; }
    }
    assert_eq!(a_changes, 0, "первый хоп инициатора не должен следовать за отвечающим");
    assert_eq!(a.mesh.hop_peer(&e.id()), Some(t1.id()));
    assert_eq!(e.mesh.hop_peer(&a.id()), Some(t1.id()), "отвечающий идёт через транзит инициатора");
}
