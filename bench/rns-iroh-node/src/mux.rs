//! Один пакетный интерфейс RNS на пира, носители (QUIC-датаграммы, TCP) подключаются к нему и отключаются, не затрагивая интерфейс.
//!
//! Link в RNS привязан к интерфейсу (`attached_interface`), а транзитные узлы держат записи link-table по паре интерфейсов. Если каждый носитель
//! - отдельный интерфейс, то смена носителя (потери UDP, возврат на QUIC, переподключение) рвёт Link на обоих концах и все Link, идущие через эту
//! пару транзитом. Здесь интерфейс живёт, пока у пира есть хотя бы один носитель (плюс короткая отсрочка `GRACE`), поэтому для RNS смена носителя
//! - просто потеря нескольких пакетов, которую Link переживает.
//!
//! Кто куда шлёт. Набирающая сторона (`follow = false`) явно назначает носитель (`add_quic`/`add_tcp` с `select`). Принимающая (`follow = true`) отвечает туда,
//! откуда в последний раз пришёл пакет данных: ей не нужен ни отдельный сигнал, ни доверие к чему-либо сверх того, что носитель привязан к
//! ключу пира (ключ iroh QUIC-соединения; для TCP - подпись в `tcpc::hello`). Датаграммы зонда `qprobe` данными не считаются.
//!
//! Что мультиплексор НЕ делает: не проверяет Link, не повышает права и не доверяет носителю. Подлинность и секретность по-прежнему даёт сам Link.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, Weak};

use super::*;

/// Сколько интерфейс живёт без единого носителя: Link за это время ещё может продолжить на вернувшемся носителе.
/// Больше окна «нет приёма» (12 с): Link, который не оживёт, закроет сам узел.
pub const GRACE: Duration = Duration::from_secs(20);
/// Интерфейс, от которого не пришло ни одного пакета (ключ без Link: сканер, мусор), держится после потери носителей лишь это время.
const GRACE_IDLE: Duration = Duration::from_secs(2);
/// Не больше стольких носителей одного пира одновременно (рабочий + кандидат).
const MAX_CARRIERS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Quic,
    Tcp,
}

enum Tx {
    Quic(Connection),
    Tcp(tokio::sync::mpsc::Sender<Vec<u8>>),
}

struct Car {
    id: u64,
    kind: Kind,
    tx: Tx,
}

/// Команды приёмной половине: новые носители подключаются к ней динамически.
enum Cmd {
    Quic(u64, Connection, [u8; 32]),
    Tcp(u64, tokio::sync::mpsc::Receiver<Vec<u8>>),
}

struct St {
    cars: Vec<Car>,
    next: u64,
    /// когда носителей не осталось (для отсрочки)
    empty_epoch: u64,
    /// с какого момента носителей нет (None - есть); нужно, чтобы вытеснять самые давние пустые интерфейсы
    empty_since: Option<Instant>,
}

pub struct Mux {
    pub name: String,
    follow: bool,
    st: Mutex<St>,
    /// носитель, на который идут данные (0 - нет)
    send_on: AtomicU64,
    cmd: tokio::sync::mpsc::UnboundedSender<Cmd>,
    closed: tokio::sync::watch::Sender<bool>,
    /// пакеты данных, ушедшие и пришедшие через интерфейс (диагностика)
    pub tx_pkts: AtomicU64,
    pub rx_pkts: AtomicU64,
    /// принимающая сторона: сколько подряд пакетов пришло не с рабочего носителя (носитель, число, время последнего)
    streak: Mutex<(u64, u32, Instant)>,
}

/// Принимающая сторона переходит на другой носитель после стольких подряд пакетов оттуда: одиночный запоздалый пакет прежнего носителя не переключает.
const FOLLOW_AFTER: u32 = 2;
const FOLLOW_WINDOW: Duration = Duration::from_secs(2);

impl Mux {
    /// Создать интерфейс RNS без носителей. Дальше `add_quic`/`add_tcp`. Интерфейс снимается через `GRACE` после потери последнего носителя
    /// или вызовом `close`.
    pub fn new(node: &Arc<Node>, sh: &Arc<Shared>, name: String, follow: bool) -> Result<Arc<Self>> {
        let (cmd, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (closed, mut closed_rx) = tokio::sync::watch::channel(false);
        let m = Arc::new(Mux {
            name: name.clone(),
            follow,
            st: Mutex::new(St { cars: Vec::new(), next: 1, empty_epoch: 0, empty_since: Some(Instant::now()) }),
            send_on: AtomicU64::new(0),
            cmd,
            closed,
            tx_pkts: AtomicU64::new(0),
            rx_pkts: AtomicU64::new(0),
            streak: Mutex::new((0, 0, Instant::now())),
        });
        let (_, mtu) = carrier();
        let t = tuning();
        let opts = PacketChannelOptions { hw_mtu: mtu, buffer_size: if t.1 > 0 { t.1 } else { 1024 } };
        let src = MuxSource { mux: Arc::downgrade(&m), cmd_rx, srcs: Vec::new(), rr: 0 };
        let sink = MuxSink { mux: m.clone() };
        let handle = node.spawn_packet_channel(&name, src, sink, opts).map_err(|e| anyhow::anyhow!("spawn_packet_channel {name}: {e}"))?;
        sh.note(format!("packet interface attached: {name} (mux, hw_mtu {mtu})"));
        let (sh2, name2) = (sh.clone(), name);
        tokio::spawn(async move {
            while !*closed_rx.borrow() {
                if closed_rx.changed().await.is_err() {
                    break;
                }
            }
            drop(handle);
            sh2.note(format!("packet interface detached (mux closed): {name2}"));
            sh2.detach.send_modify(|v| *v += 1);
        });
        Ok(m)
    }

    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// Закрыть интерфейс и его QUIC-носители: закрытый интерфейс не должен оставлять живое соединение, занимающее слот.
    pub fn close(&self) {
        let cars = {
            let mut st = self.st.lock().unwrap();
            let _ = self.closed.send(true);
            std::mem::take(&mut st.cars)
        };
        for c in cars {
            if let Tx::Quic(conn) = c.tx {
                conn.close(0u32.into(), b"mux closed");
            }
        }
    }

    /// Закрыть, если носителей всё ещё нет и с момента `epoch` ничего не подключалось. Проверка и закрытие под одним замком: `add` не успеет вклиниться.
    fn close_if_empty(&self, epoch: u64) {
        let mut st = self.st.lock().unwrap();
        if st.cars.is_empty() && st.empty_epoch == epoch {
            let _ = self.closed.send(true);
            st.empty_since = None;
        }
    }

    fn grace(&self) -> Duration {
        if self.rx_pkts.load(Relaxed) == 0 { GRACE_IDLE } else { GRACE }
    }

    fn empty_since(&self) -> Option<Instant> {
        self.st.lock().unwrap().empty_since
    }

    /// Подключить QUIC-соединение как носитель. `select` - сразу назначить его носителем данных (иначе только держим: зонд, запас).
    /// `owner` - по чему считается частота разрешений на зонд (принимающая сторона: адрес источника, см. `owner_key`).
    pub fn add_quic(self: &Arc<Self>, conn: Connection, select: bool, owner: [u8; 32]) -> Option<u64> {
        let id = self.add(Kind::Quic, Tx::Quic(conn.clone()), select)?;
        let _ = self.cmd.send(Cmd::Quic(id, conn.clone(), owner));
        let (m, c) = (self.clone(), conn);
        tokio::spawn(async move {
            let _ = c.closed().await;
            m.remove(id);
        });
        Some(id)
    }

    /// Подключить TCP-носитель: `out` - очередь кадров в сторону пира, `rx` - кадры от пира.
    pub fn add_tcp(self: &Arc<Self>, out: tokio::sync::mpsc::Sender<Vec<u8>>, rx: tokio::sync::mpsc::Receiver<Vec<u8>>, select: bool) -> Option<u64> {
        let id = self.add(Kind::Tcp, Tx::Tcp(out), select)?;
        let _ = self.cmd.send(Cmd::Tcp(id, rx));
        Some(id)
    }

    fn add(&self, kind: Kind, tx: Tx, select: bool) -> Option<u64> {
        let mut st = self.st.lock().unwrap();
        if self.is_closed() || st.cars.len() >= MAX_CARRIERS {
            return None;
        }
        let id = st.next;
        st.next += 1;
        let first = st.cars.is_empty();
        st.cars.push(Car { id, kind, tx });
        st.empty_epoch += 1;
        st.empty_since = None;
        drop(st);
        if select || first {
            self.send_on.store(id, Relaxed);
        }
        Some(id)
    }

    /// Носитель закончился. Если он был рабочим - данные переходят на оставшийся (QUIC предпочтительнее). Без носителей - отсрочка и снятие интерфейса.
    pub fn remove(self: &Arc<Self>, id: u64) {
        let mut st = self.st.lock().unwrap();
        let before = st.cars.len();
        st.cars.retain(|c| c.id != id);
        if st.cars.len() == before {
            return;
        }
        if self.send_on.load(Relaxed) == id {
            let next = st.cars.iter().find(|c| c.kind == Kind::Quic).or_else(|| st.cars.first()).map(|c| c.id).unwrap_or(0);
            self.send_on.store(next, Relaxed);
        }
        if st.cars.is_empty() {
            st.empty_epoch += 1;
            st.empty_since = Some(Instant::now());
            let epoch = st.empty_epoch;
            drop(st);
            let m = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(m.grace()).await;
                m.close_if_empty(epoch);
            });
        }
    }

    pub fn has(&self, id: u64) -> bool {
        self.st.lock().unwrap().cars.iter().any(|c| c.id == id)
    }

    fn send(&self, packet: &[u8]) {
        let id = self.send_on.load(Relaxed);
        let st = self.st.lock().unwrap();
        let Some(c) = st.cars.iter().find(|c| c.id == id).or_else(|| st.cars.first()) else { return };
        match &c.tx {
            Tx::Quic(conn) => {
                // слишком большая датаграмма или обрыв - потеря одного пакета; обрыв заметит `closed()`
                let _ = conn.send_datagram(bytes::Bytes::copy_from_slice(packet));
            }
            Tx::Tcp(tx) => {
                if packet.len() <= tcp_max_frame() {
                    let _ = tx.try_send(packet.to_vec());
                }
            }
        }
        self.tx_pkts.fetch_add(1, Relaxed);
    }

    fn rx_from(&self, id: u64) {
        self.rx_pkts.fetch_add(1, Relaxed);
        if !self.follow || self.send_on.load(Relaxed) == id {
            return;
        }
        let mut s = self.streak.lock().unwrap();
        let now = Instant::now();
        if s.0 == id && now.saturating_duration_since(s.2) <= FOLLOW_WINDOW {
            s.1 += 1;
        } else {
            *s = (id, 1, now);
        }
        s.2 = now;
        if s.1 >= FOLLOW_AFTER {
            drop(s);
            // носитель мог исчезнуть между приёмом и этим местом
            if self.has(id) {
                self.send_on.store(id, Relaxed);
            }
        }
    }

    /// У пира есть и другие носители, кроме `id`.
    fn has_other(&self, id: u64) -> bool {
        self.st.lock().unwrap().cars.iter().any(|c| c.id != id)
    }
}

fn tcp_max_frame() -> usize {
    tcpc::MAX_FRAME
}

struct MuxSink {
    mux: Arc<Mux>,
}

impl PacketSink for MuxSink {
    /// Ошибок нет: потеря пакета (нет носителя, переполнение очереди, слишком большая датаграмма) не должна снимать интерфейс - им управляет мультиплексор.
    fn send(&mut self, packet: &[u8]) -> std::io::Result<()> {
        self.mux.send(packet);
        Ok(())
    }
}

/// Ожидание следующей датаграммы: живёт между опросами, иначе waker нигде не остаётся зарегистрированным и приём идёт лишь по случайным пробуждениям.
type DgFut = std::pin::Pin<Box<dyn Future<Output = Option<bytes::Bytes>> + Send>>;

fn read_dg(conn: &Connection) -> DgFut {
    let c = conn.clone();
    Box::pin(async move { c.read_datagram().await.ok() })
}

enum Src {
    Quic { id: u64, conn: Connection, filter: qprobe::Filter, fut: DgFut, owner: [u8; 32] },
    Tcp { id: u64, rx: tokio::sync::mpsc::Receiver<Vec<u8>> },
}

enum Ev {
    Pkt(u64, Vec<u8>),
}

struct MuxSource {
    mux: Weak<Mux>,
    cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    srcs: Vec<Src>,
    rr: usize,
}

impl MuxSource {
    fn apply(&mut self, c: Cmd) {
        match c {
            Cmd::Quic(id, conn, owner) => { let fut = read_dg(&conn); self.srcs.push(Src::Quic { id, conn, filter: qprobe::Filter::new(), fut, owner }) }
            Cmd::Tcp(id, rx) => self.srcs.push(Src::Tcp { id, rx }),
        }
    }

    /// Один обход: команды, затем носители по кругу. Pending регистрирует waker у каждого источника.
    fn poll_once(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Vec<u8>>> {
        loop {
            while let Poll::Ready(Some(c)) = self.cmd_rx.poll_recv(cx) {
                self.apply(c);
            }
            let Some(mux) = self.mux.upgrade() else {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "mux dropped")));
            };
            if mux.is_closed() {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "mux closed")));
            }
            let n = self.srcs.len();
            let mut gone: Option<u64> = None;
            let mut got: Option<Ev> = None;
            let mut yielded = false;
            for k in 0..n {
                let i = (self.rr + k) % n;
                match &mut self.srcs[i] {
                    Src::Tcp { id, rx } => match rx.poll_recv(cx) {
                        Poll::Ready(Some(p)) => {
                            got = Some(Ev::Pkt(*id, p));
                        }
                        Poll::Ready(None) => gone = Some(*id),
                        Poll::Pending => {}
                    },
                    Src::Quic { id, conn, filter, fut, owner } => {
                        // магические датаграммы зонда съедаем здесь и читаем дальше; бюджет `ate` не даёт им занять исполнителя
                        loop {
                            match fut.as_mut().poll(cx) {
                                Poll::Ready(Some(b)) => {
                                    *fut = read_dg(conn);
                                    if is_grant_req(&b) {
                                        answer_grant(&mux, *id, conn, filter, owner, &b);
                                        if filter.ate() {
                                            yielded = true;
                                            break;
                                        }
                                        continue;
                                    }
                                    if filter.intercept(conn, &b) {
                                        if filter.ate() {
                                            yielded = true;
                                            break;
                                        }
                                        continue;
                                    }
                                    filter.delivered();
                                    got = Some(Ev::Pkt(*id, b.to_vec()));
                                }
                                Poll::Ready(None) => gone = Some(*id),
                                Poll::Pending => {}
                            }
                            break;
                        }
                    }
                }
                if got.is_some() || gone.is_some() {
                    self.rr = (i + 1) % n.max(1);
                    break;
                }
            }
            match (got, gone) {
                (Some(Ev::Pkt(id, p)), _) => {
                    mux.rx_from(id);
                    return Poll::Ready(Ok(p));
                }
                (_, Some(id)) => {
                    self.srcs.retain(|s| match s {
                        Src::Quic { id: x, .. } | Src::Tcp { id: x, .. } => *x != id,
                    });
                    mux.remove(id);
                    continue;
                }
                _ => {}
            }
            if yielded {
                // магический поток не держит исполнителя: уступаем и просим опросить снова
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
    }
}

impl PacketSource for MuxSource {
    fn try_recv(&mut self) -> Option<std::io::Result<Vec<u8>>> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        match self.poll_once(&mut cx) {
            Poll::Ready(r) => Some(r),
            Poll::Pending => None,
        }
    }

    fn recv(&mut self) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send {
        async move { std::future::poll_fn(|cx| self.poll_once(cx)).await }
    }
}

fn is_grant_req(b: &[u8]) -> bool {
    b.len() == qprobe::HEAD && b[..8] == qprobe::MAGIC && b[8] == qprobe::KIND_GREQ
}

/// Запрос разрешения на зонд QUIC по самой датаграммной связи кандидата (возврат TCP -> QUIC). Разрешение выдаётся только соединению, рядом с
/// которым у того же ключа iroh уже есть другой носитель (то есть возвращается пир с работающей связью), и в пределах общих лимитов `qprobe::Grants`.
/// Ответ - одна датаграмма `MAGIC | 'H' | status | nonce`; потеря запроса или ответа - обычный отказ, клиент повторит позже.
fn answer_grant(mux: &Mux, id: u64, conn: &Connection, filter: &mut qprobe::Filter, owner: &[u8; 32], req: &[u8]) {
    let now = Instant::now();
    if !filter.rate_ok(now) {
        return;
    }
    let status = if !mux.has_other(id) {
        qprobe::DENY_NO_CARRIER
    } else {
        let ep = *conn.remote_id().as_bytes();
        match qprobe::grants().grant(ep, *owner, now) {
            Ok(()) => 0,
            Err(d) => d.code(),
        }
    };
    let _ = conn.send_datagram(bytes::Bytes::from(qprobe::grant_reply(status, &req[10..18])));
}

/// Ключ «владельца» для частоты разрешений на зонд: адрес источника (IPv6 - сеть /64), а не ключ iroh: смена ключа лимит не обходит.
/// Без адреса (релей) - сам ключ iroh.
pub fn owner_key(ip: Option<IpAddr>, ep: &[u8; 32]) -> [u8; 32] {
    let mut k = [0u8; 32];
    match ip {
        Some(IpAddr::V4(a)) => {
            k[0] = 4;
            k[1..5].copy_from_slice(&a.octets());
        }
        Some(IpAddr::V6(a)) => {
            k[0] = 6;
            k[1..9].copy_from_slice(&a.octets()[..8]);
        }
        None => k = *ep,
    }
    k
}

/// Реестр интерфейсов принимающей стороны: ключ - ключ iroh пира (QUIC: из TLS; TCP: из подписи).
#[derive(Default)]
pub struct Registry {
    by_peer: Mutex<std::collections::HashMap<[u8; 32], Weak<Mux>>>,
}

static SEQ: AtomicU64 = AtomicU64::new(0);

impl Registry {
    /// Интерфейс этого пира: живой существующий или новый. Не больше `max` живых интерфейсов (иначе None - соединение отклоняется).
    pub fn get_or_create(&self, node: &Arc<Node>, sh: &Arc<Shared>, peer: [u8; 32], max: usize) -> Option<Arc<Mux>> {
        let mut m = self.by_peer.lock().unwrap();
        if let Some(x) = m.get(&peer).and_then(|w| w.upgrade()).filter(|x| !x.is_closed()) {
            return Some(x);
        }
        m.retain(|_, w| w.upgrade().is_some_and(|x| !x.is_closed()));
        if m.len() >= max {
            // Заполнено: вытесняем самый давний интерфейс без носителей, сначала те, от которых не было ни одного пакета (ключ без Link).
            // Живые интерфейсы не трогаем: поток новых ключей не должен выбивать работающих пиров и сам себя держать в реестре.
            let victim = m
                .iter()
                .filter_map(|(k, w)| {
                    let x = w.upgrade()?;
                    let t = x.empty_since()?;
                    Some(((x.rx_pkts.load(Relaxed) > 0, t), *k, x))
                })
                .min_by_key(|(rank, ..)| *rank);
            let (_, k, x) = victim?;
            x.close();
            m.remove(&k);
        }
        let short = EndpointId::from_bytes(&peer).map(|i| i.fmt_short().to_string()).unwrap_or_else(|_| "peer".into());
        let name = format!("iroh-dg-in-{short}-m{}", SEQ.fetch_add(1, Relaxed));
        let x = Mux::new(node, sh, name, true).ok()?;
        m.insert(peer, Arc::downgrade(&x));
        Some(x)
    }
}

pub fn next_name(prefix: &str, label: &str) -> String {
    format!("{prefix}-{label}-m{}", SEQ.fetch_add(1, Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_key_ignores_iroh_key_when_address_known() {
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        assert_eq!(owner_key(Some(ip), &[1; 32]), owner_key(Some(ip), &[2; 32]), "смена ключа не должна менять владельца");
        assert_ne!(owner_key(Some(ip), &[1; 32]), owner_key(Some("192.0.2.8".parse().unwrap()), &[1; 32]));
        assert_eq!(owner_key(None, &[5; 32]), [5; 32], "без адреса (релей) владелец - ключ iroh");
    }

    #[test]
    fn owner_key_counts_ipv6_by_slash_64() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(owner_key(Some(a), &[0; 32]), owner_key(Some(b), &[0; 32]));
        assert_ne!(owner_key(Some(a), &[0; 32]), owner_key(Some(c), &[0; 32]));
        assert_ne!(owner_key(Some("0.0.0.1".parse().unwrap()), &[0; 32]), owner_key(Some("::1".parse().unwrap()), &[0; 32]));
    }
}
