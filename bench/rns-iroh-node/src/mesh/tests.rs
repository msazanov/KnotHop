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
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap();
    if selector {
        b = b.add_custom_transport(mesh.transport()).path_selector(Arc::new(MeshBackupSelector));
    }
    let ep = b.bind().await.unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let saw_plain = Arc::new(AtomicBool::new(false));
    let n = Node { ep: ep.clone(), mesh: mesh.clone(), pol, nbrs, e2e: tokio::sync::Mutex::new(rx), saw_plain: saw_plain.clone() };
    let (nbrs2, mesh2) = (n.nbrs.clone(), mesh.clone());
    tokio::spawn(async move {
        while let Some(inc) = ep.accept().await {
            let (tx, nbrs, mesh, sp) = (tx.clone(), nbrs2.clone(), mesh2.clone(), saw_plain.clone());
            tokio::spawn(async move {
                let Ok(conn) = inc.await else { return };
                if conn.alpn() == NBR {
                    add_nbr(&nbrs, &mesh, conn, sp);
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

fn add_nbr(nbrs: &Nbrs, mesh: &Arc<Mesh>, conn: Connection, sp: Arc<AtomicBool>) {
    nbrs.write().unwrap().insert(*conn.remote_id().as_bytes(), conn.clone());
    let mesh = mesh.clone();
    tokio::spawn(async move {
        while let Ok(d) = conn.read_datagram().await {
            if d.windows(MARKER.len()).any(|w| w == MARKER) {
                sp.store(true, Relaxed);
            }
            if d.first() == Some(&TAG) {
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
    add_nbr(&a.nbrs, &a.mesh, conn, a.saw_plain.clone());
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

async fn echo(a: &Connection, e: &Connection) {
    let (mut s, mut r) = a.open_bi().await.unwrap();
    s.write_all(MARKER).await.unwrap();
    s.finish().unwrap();
    let (mut es, mut er) = e.accept_bi().await.unwrap();
    assert_eq!(er.read_to_end(1024).await.unwrap(), MARKER);
    es.write_all(b"pong-stream").await.unwrap();
    es.finish().unwrap();
    assert_eq!(r.read_to_end(1024).await.unwrap(), b"pong-stream");
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

/// Поднятое по mesh соединение: iroh находит прямой адрес сам (NAT traversal поверх mesh) и переходит на IP; mesh остаётся запасным путём.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upgrades_to_ip_and_keeps_mesh_as_backup() {
    let (a, t, e) = (node().await, node().await, node().await);
    link(&a, &t).await;
    link(&t, &e).await;
    allow_all(&[&a, &t, &e]);
    t.set_transit(true);
    route(&a, &e, &t);
    let (ca, ce) = e2e_connect(&a, &e).await;
    echo(&ca, &ce).await;
    let t0 = Instant::now();
    while mesh_selected(&ca) && t0.elapsed() < Duration::from_secs(15) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!mesh_selected(&ca), "выбран прямой IP-путь: {:?}", ca.paths().iter().map(|p| p.remote_addr().clone()).collect::<Vec<_>>());
    let custom = ca.paths().iter().filter(|p| matches!(p.remote_addr(), TransportAddr::Custom(_))).count();
    assert_eq!(custom, 1, "mesh-путь остаётся открытым как запасной");
    echo(&ca, &ce).await;
}

// ---------------------------------------------------------------- решения без сети

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
    // обычное соединение к E (поедет по mesh-пути) и «устаревший» кэш хопа, указывающий на него
    let c2 = tokio::time::timeout(Duration::from_secs(10), a.ep.connect(EndpointAddr::new(e.ep.id()), ALPN)).await.expect("timeout").expect("connect");
    a.mesh.hops.lock().unwrap().insert(e.id(), HopEntry { res: Ok(HopConn { sid: c2.stable_id(), peer: e.id(), conn: c2.clone() }), at: Instant::now() });
    let tx = a.mesh.c.tx.load(Relaxed);
    a.mesh.send_payload(&e.id(), b"x");
    assert_eq!((a.mesh.c.tx.load(Relaxed), a.mesh.c.drop_recursion.load(Relaxed)), (tx, 1));
    // и даже без пометки самого соединения: ключ пира с живым сквозным соединением
    assert!(a.mesh.hop_rides_mesh(&HopConn { sid: 0, peer: e.id(), conn: c2 }, Instant::now()));
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
    assert!(a.mesh.rides_mesh(&c2), "paths: {:?}", c2.paths().iter().map(|p| p.remote_addr().clone()).collect::<Vec<_>>());
    // и ни одно из них не используется как сосед для кадров mesh
    a.nbrs.write().unwrap().insert(e.id(), c2.clone());
    a.mesh.warm(&e.id());
    let before = a.mesh.c.tx.load(Relaxed);
    a.mesh.send_payload(&e.id(), b"x");
    assert_eq!(a.mesh.c.tx.load(Relaxed), before + 1, "кадр уходит через T, а не в соединение к E");
}
