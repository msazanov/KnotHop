//! Кадрирование для носителя iroh/QUIC поверх любого потока (обычно `RealityStream`): `u16 длина | пакет`.
//! Отправка неблокирующая (`try_send`, как у UDP: потеря - не ошибка). Очередь ограничена числом кадров и ВРЕМЕНЕМ:
//! кадр, простоявший в очереди дольше `max_queue_delay`, отбрасывается при извлечении (PoC показал рост очереди до секунд
//! при потерях/перегрузке TCP-носителя; QUIC лучше переживёт потерю, чем задержку).
//! Адаптер под `iroh::endpoint::transports::CustomTransport` (id носителя, `CustomAddr`) - в интеграции с knothopd, см. DESIGN.md.
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

pub const MAX_FRAME: usize = u16::MAX as usize;

#[derive(Clone, Debug)]
pub struct FrameConfig {
    /// ёмкость очереди отправки в кадрах
    pub queue_frames: usize,
    /// предельное время жизни кадра в очереди отправки
    pub max_queue_delay: Duration,
    /// ёмкость очереди приёма в кадрах
    pub rx_frames: usize,
    /// сколько байт склеивать в одну запись потока за раз (малое значение - меньше задержка, большое - меньше записей)
    pub batch_bytes: usize,
}

impl Default for FrameConfig {
    fn default() -> Self {
        FrameConfig { queue_frames: 1024, max_queue_delay: Duration::from_millis(150), rx_frames: 1024, batch_bytes: 16 * 1024 }
    }
}

#[derive(Default, Debug)]
pub struct FrameStats {
    pub tx_frames: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_frames: AtomicU64,
    pub rx_bytes: AtomicU64,
    /// отброшено: очередь заполнена
    pub drop_full: AtomicU64,
    /// отброшено: превышено время в очереди
    pub drop_stale: AtomicU64,
    /// отброшено: кадр больше MAX_FRAME или пуст
    pub drop_size: AtomicU64,
}

#[derive(Clone)]
pub struct FrameSender {
    q: mpsc::Sender<(Instant, Bytes)>,
    stats: Arc<FrameStats>,
}

impl FrameSender {
    /// true - принят в очередь; false - отброшен (очередь полна, кадр непригоден или канал закрыт).
    pub fn try_send(&self, p: Bytes) -> bool {
        if p.is_empty() || p.len() > MAX_FRAME {
            self.stats.drop_size.fetch_add(1, Relaxed);
            return false;
        }
        match self.q.try_send((Instant::now(), p)) {
            Ok(()) => true,
            Err(_) => {
                self.stats.drop_full.fetch_add(1, Relaxed);
                false
            }
        }
    }
    pub fn is_closed(&self) -> bool {
        self.q.is_closed()
    }
}

pub struct FrameLink {
    pub sender: FrameSender,
    pub rx: mpsc::Receiver<Bytes>,
    pub stats: Arc<FrameStats>,
    closed: watch::Receiver<bool>,
}

impl FrameLink {
    /// Завершается, когда поток закрыт (с любой стороны) или произошла ошибка.
    pub async fn closed(&mut self) {
        while !*self.closed.borrow() {
            if self.closed.changed().await.is_err() {
                break;
            }
        }
    }
}

/// Запускает читателя и писателя поверх потока.
pub fn spawn<S>(stream: S, cfg: FrameConfig) -> FrameLink
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let stats = Arc::new(FrameStats::default());
    let (rd, mut wr) = tokio::io::split(stream);
    let (q_tx, mut q_rx) = mpsc::channel::<(Instant, Bytes)>(cfg.queue_frames.max(1));
    let (rx_tx, rx) = mpsc::channel::<Bytes>(cfg.rx_frames.max(1));
    let (done_tx, done_rx) = watch::channel(false);
    let done_tx = Arc::new(done_tx);

    let (st, d2) = (stats.clone(), done_tx.clone());
    tokio::spawn(async move {
        let mut rd = rd;
        let mut hdr = [0u8; 2];
        let mut buf = BytesMut::with_capacity(MAX_FRAME);
        loop {
            if rd.read_exact(&mut hdr).await.is_err() {
                break;
            }
            let n = u16::from_be_bytes(hdr) as usize;
            if n == 0 {
                continue;
            }
            buf.resize(n, 0);
            if rd.read_exact(&mut buf[..n]).await.is_err() {
                break;
            }
            st.rx_frames.fetch_add(1, Relaxed);
            st.rx_bytes.fetch_add(n as u64, Relaxed);
            if rx_tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                break;
            }
        }
        let _ = d2.send(true);
    });

    let (st, d2) = (stats.clone(), done_tx);
    let (max_delay, batch) = (cfg.max_queue_delay, cfg.batch_bytes.max(2048));
    tokio::spawn(async move {
        let mut out = BytesMut::with_capacity(batch + MAX_FRAME);
        'outer: while let Some(first) = q_rx.recv().await {
            out.clear();
            let mut cnt = 0u64;
            let mut item = Some(first);
            while let Some((t, p)) = item.take() {
                if t.elapsed() > max_delay {
                    st.drop_stale.fetch_add(1, Relaxed);
                } else {
                    out.extend_from_slice(&(p.len() as u16).to_be_bytes());
                    out.extend_from_slice(&p);
                    cnt += 1;
                }
                if out.len() < batch {
                    item = q_rx.try_recv().ok();
                }
            }
            if out.is_empty() {
                continue;
            }
            if wr.write_all(&out).await.is_err() || wr.flush().await.is_err() {
                break 'outer;
            }
            st.tx_frames.fetch_add(cnt, Relaxed);
            st.tx_bytes.fetch_add(out.len() as u64, Relaxed);
        }
        let _ = wr.shutdown().await;
        let _ = d2.send(true);
    });

    FrameLink { sender: FrameSender { q: q_tx, stats: stats.clone() }, rx, stats, closed: done_rx }
}
