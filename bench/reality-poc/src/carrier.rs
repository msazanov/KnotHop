//! Custom transport iroh: кадры `u16 len | UDP-пакет QUIC` по потоку TCP (носитель: REALITY через shoes/Traefik).
//! Адрес `CustomAddr { id = RP_ID, data = 8 байт }`: у сервера - номер принятого TCP-соединения, у клиента - 0 (единственный носитель).
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use iroh::endpoint::transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit};
use iroh_base::CustomAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

pub const RP_ID: u64 = 0x5250_4F43;
const Q: usize = 4096;

#[derive(Default)]
pub struct Counters {
    pub tx: AtomicU64,
    pub rx: AtomicU64,
    pub drop_full: AtomicU64,
    pub drop_nocarrier: AtomicU64,
    pub tx_bytes: AtomicU64,
}

pub enum Role {
    /// слушаем TCP (за shoes-сервером REALITY)
    Listen(SocketAddr),
    /// подключаемся к локальному клиенту REALITY (shoes) либо прямо
    Connect(SocketAddr),
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Inner")
    }
}

struct Inner {
    conns: Mutex<HashMap<u64, mpsc::Sender<Bytes>>>,
    rx_tx: mpsc::Sender<(Bytes, u64)>,
    rx: Mutex<Option<mpsc::Receiver<(Bytes, u64)>>>,
    next: AtomicU64,
    pub c: Counters,
    local: n0_watcher::Watchable<Vec<CustomAddr>>,
}

#[derive(Clone)]
pub struct Carrier(Arc<Inner>);

impl std::fmt::Debug for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Carrier")
    }
}

pub fn addr(n: u64) -> CustomAddr {
    CustomAddr::from_parts(RP_ID, &n.to_be_bytes())
}

impl Carrier {
    pub fn counters(&self) -> &Counters {
        &self.0.c
    }

    pub fn start(role: Role) -> Carrier {
        let (rx_tx, rx) = mpsc::channel(Q);
        let inner = Arc::new(Inner {
            conns: Default::default(),
            rx_tx,
            rx: Mutex::new(Some(rx)),
            next: AtomicU64::new(1),
            c: Default::default(),
            local: n0_watcher::Watchable::new(vec![addr(0)]),
        });
        match role {
            Role::Listen(a) => {
                let i = inner.clone();
                tokio::spawn(async move {
                    let l = TcpListener::bind(a).await.expect("carrier listen");
                    loop {
                        match l.accept().await {
                            Ok((s, peer)) => {
                                let id = i.next.fetch_add(1, Relaxed);
                                eprintln!("carrier: accepted {peer} as #{id}");
                                run_conn(i.clone(), s, id);
                            }
                            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                        }
                    }
                });
            }
            Role::Connect(a) => {
                let i = inner.clone();
                tokio::spawn(async move {
                    loop {
                        match TcpStream::connect(a).await {
                            Ok(s) => {
                                eprintln!("carrier: connected to {a}");
                                let done = run_conn(i.clone(), s, 0);
                                let _ = done.await;
                                eprintln!("carrier: connection lost");
                            }
                            Err(e) => eprintln!("carrier: connect {a}: {e}"),
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                });
            }
        }
        Carrier(inner)
    }
}

/// запускает читатель и писатель; канал завершения срабатывает по закрытию
fn run_conn(i: Arc<Inner>, s: TcpStream, id: u64) -> tokio::sync::oneshot::Receiver<()> {
    let _ = s.set_nodelay(true);
    let (mut rd, mut wr) = s.into_split();
    let (tx, mut rxq) = mpsc::channel::<Bytes>(Q);
    i.conns.lock().unwrap().insert(id, tx);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let i2 = i.clone();
    tokio::spawn(async move {
        let mut hdr = [0u8; 2];
        let mut buf = BytesMut::with_capacity(65536);
        loop {
            if rd.read_exact(&mut hdr).await.is_err() {
                break;
            }
            let n = u16::from_be_bytes(hdr) as usize;
            buf.resize(n, 0);
            if rd.read_exact(&mut buf[..n]).await.is_err() {
                break;
            }
            i2.c.rx.fetch_add(1, Relaxed);
            let b = Bytes::copy_from_slice(&buf[..n]);
            if i2.rx_tx.send((b, id)).await.is_err() {
                break;
            }
        }
        i2.conns.lock().unwrap().remove(&id);
        let _ = done_tx.send(());
    });
    let i3 = i.clone();
    tokio::spawn(async move {
        let mut out = BytesMut::with_capacity(128 * 1024);
        while let Some(p) = rxq.recv().await {
            out.clear();
            let mut cnt = 0;
            let mut push = |p: &Bytes, out: &mut BytesMut| {
                out.extend_from_slice(&(p.len() as u16).to_be_bytes());
                out.extend_from_slice(p);
            };
            push(&p, &mut out);
            cnt += 1;
            while out.len() < 64 * 1024 {
                match rxq.try_recv() {
                    Ok(p) => {
                        push(&p, &mut out);
                        cnt += 1;
                    }
                    Err(_) => break,
                }
            }
            if wr.write_all(&out).await.is_err() {
                break;
            }
            i3.c.tx.fetch_add(cnt, Relaxed);
            i3.c.tx_bytes.fetch_add(out.len() as u64, Relaxed);
        }
        i3.conns.lock().unwrap().remove(&id);
    });
    done_rx
}

impl CustomTransport for Carrier {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let rx = self.0.rx.lock().unwrap().take().ok_or_else(|| io::Error::other("already bound"))?;
        Ok(Box::new(Ep { i: self.0.clone(), rx }))
    }
}

#[derive(Debug)]
struct Ep {
    i: Arc<Inner>,
    rx: mpsc::Receiver<(Bytes, u64)>,
}

impl CustomEndpoint for Ep {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.i.local.watch()
    }
    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(Sender(self.i.clone()))
    }
    fn poll_recv(&mut self, cx: &mut Context, bufs: &mut [io::IoSliceMut<'_>], metas: &mut [noq_udp::RecvMeta], infos: &mut [RecvInfo]) -> Poll<io::Result<usize>> {
        let mut n = 0;
        while n < bufs.len() {
            let (data, src) = if n == 0 {
                match self.rx.poll_recv(cx) {
                    Poll::Ready(Some(x)) => x,
                    Poll::Ready(None) => return Poll::Ready(Err(io::Error::other("closed"))),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match self.rx.try_recv() {
                    Ok(x) => x,
                    Err(_) => break,
                }
            };
            if data.len() > bufs[n].len() {
                continue;
            }
            bufs[n][..data.len()].copy_from_slice(&data);
            metas[n].len = data.len();
            metas[n].stride = data.len();
            metas[n].ecn = None;
            metas[n].dst_ip = None;
            infos[n] = RecvInfo::new(addr(src), Some(addr(0)));
            n += 1;
        }
        Poll::Ready(Ok(n))
    }
    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(64).unwrap()
    }
}

#[derive(Debug)]
struct Sender(Arc<Inner>);

impl CustomSender for Sender {
    fn is_valid_send_addr(&self, a: &CustomAddr) -> bool {
        a.id() == RP_ID && a.data().len() == 8
    }
    fn poll_send(&self, _cx: &mut Context, dst: &CustomAddr, _src: Option<&CustomAddr>, t: &Transmit<'_>) -> Poll<io::Result<()>> {
        let Ok(d) = <[u8; 8]>::try_from(dst.data()) else { return Poll::Ready(Err(io::Error::other("bad addr"))) };
        let id = u64::from_be_bytes(d);
        let tx = self.0.conns.lock().unwrap().get(&id).cloned();
        let Some(tx) = tx else {
            self.0.c.drop_nocarrier.fetch_add(1, Relaxed);
            return Poll::Ready(Ok(()));
        };
        let seg = t.segment_size.filter(|s| *s > 0).unwrap_or(t.contents.len().max(1));
        for s in t.contents.chunks(seg) {
            if tx.try_send(Bytes::copy_from_slice(s)).is_err() {
                self.0.c.drop_full.fetch_add(1, Relaxed);
            }
        }
        // семантика UDP: потеря не ошибка
        Poll::Ready(Ok(()))
    }
}
