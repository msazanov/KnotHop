//! Packet-channel interface: one Reticulum packet per caller datagram, no framing at all.
//!
//! The datagram counterpart of the [byte channel](super::byte_channel). The byte channel wraps a *stream* in
//! HDLC; here the carrier already has packet boundaries (QUIC DATAGRAM frames, a UDP socket, a message bus),
//! so a packet is one datagram and nothing is added or searched for.
//!
//! Why it exists (rawg): an IPv4 tunnel carries IP packets, which are datagrams. Over a reliable ordered
//! stream a single lost carrier packet stalls every packet behind it (head-of-line blocking: measured p95
//! of 1.3 s on a 50 ms path at 0.5% loss), and the inner TCP/QUIC then sees delay spikes instead of loss.
//! A datagram carrier loses exactly the packet that was lost.
//!
//! The caller supplies the two halves, so the module knows nothing about the carrier:
//! * [`PacketSource`]: waits for the next whole datagram. **Must be cancel-safe**, it is raced against the
//!   outgoing queue and a shutdown signal and may be dropped half-way through a poll.
//! * [`PacketSink`]: sends one datagram without waiting. An error of kind `WouldBlock`, `InvalidInput`
//!   or `OutOfMemory` means "this packet was not sent" (too big, buffer full): it is counted and dropped, the
//!   interface stays up. Any other error means the carrier is gone and the interface detaches.

use std::future::Future;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use leviculum_core::transport::InterfaceId;
use tokio::sync::{mpsc, oneshot};

use super::{
    IncomingPacket, InterfaceCounters, InterfaceHandle, InterfaceInfo, OutgoingPacket, ReadySignal,
};

/// Datagrams dropped because the interface's incoming queue was full, i.e. the node's event loop did not keep
/// up with the carrier. Process-wide, monotonic. A datagram interface must drop here rather than stall the carrier,
/// but the loss is invisible anywhere else, so it is counted.
pub static RX_QUEUE_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Datagrams the carrier refused to send (too big for the current path MTU, send buffer full).
pub static TX_REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `(rx_queue_dropped, tx_refused)` since process start.
pub fn drop_counters() -> (u64, u64) {
    (RX_QUEUE_DROPPED.load(Ordering::Relaxed), TX_REFUSED.load(Ordering::Relaxed))
}

/// Tunables of a packet-channel interface.
#[derive(Debug, Clone, Copy)]
pub struct PacketChannelOptions {
    /// `HW_MTU`: the largest Reticulum packet the carrier can move in one datagram. It bounds link MTU
    /// negotiation, so the usable tunnel MTU is derived from it (minus the packet header and cipher
    /// overhead). Larger incoming datagrams are discarded.
    pub hw_mtu: u32,
    /// Capacity, in packets, of the incoming and outgoing queues.
    pub buffer_size: usize,
}

impl Default for PacketChannelOptions {
    fn default() -> Self {
        Self {
            hw_mtu: 1200,
            buffer_size: 1024,
        }
    }
}

/// Receiving half of the carrier.
pub trait PacketSource: Send + 'static {
    /// The next whole datagram. `Err` ends the interface. Must be cancel-safe.
    fn recv(&mut self) -> impl Future<Output = io::Result<Vec<u8>>> + Send;

    /// A datagram that is already waiting, without parking. `None` = nothing ready (or not supported).
    /// Lets the interface task move a burst through one wakeup instead of one per packet.
    fn try_recv(&mut self) -> Option<io::Result<Vec<u8>>> {
        None
    }
}

/// Sending half of the carrier.
pub trait PacketSink: Send + 'static {
    /// Send one datagram now, without waiting for the peer. See the module docs for the error contract.
    fn send(&mut self, packet: &[u8]) -> io::Result<()>;
}

/// Most packets moved per wakeup of the interface task, each way.
static BURST_MAX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(64);

/// Set the per-wakeup burst limit for interfaces created afterwards (1 = one packet per wakeup).
pub fn set_burst(n: usize) {
    BURST_MAX.store(n.max(1), std::sync::atomic::Ordering::Relaxed);
}

pub(crate) struct PacketChannelConfig {
    pub id: InterfaceId,
    pub name: String,
    pub buffer_size: usize,
    pub hw_mtu: u32,
    pub shutdown: Option<oneshot::Receiver<()>>,
}

async fn wait_shutdown(shutdown: &mut Option<oneshot::Receiver<()>>) {
    match shutdown.as_mut() {
        Some(rx) => {
            let _ = rx.await;
        }
        None => std::future::pending::<()>().await,
    }
}

fn is_drop_not_fatal(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::InvalidInput | io::ErrorKind::OutOfMemory
    )
}

pub(crate) fn spawn_packet_channel_interface<R, W>(
    config: PacketChannelConfig,
    mut source: R,
    mut sink: W,
) -> InterfaceHandle
where
    R: PacketSource,
    W: PacketSink,
{
    let (incoming_tx, incoming_rx) = mpsc::channel::<IncomingPacket>(config.buffer_size);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<OutgoingPacket>(config.buffer_size);
    let counters = Arc::new(InterfaceCounters::new());
    let ready = ReadySignal::new();

    let name = config.name.clone();
    let hw_mtu = config.hw_mtu as usize;
    let task_counters = Arc::clone(&counters);
    let task_ready = Arc::clone(&ready);
    let mut shutdown = config.shutdown;

    tokio::spawn(async move {
        task_ready.signal_ready();
        let burst = BURST_MAX.load(Ordering::Relaxed).max(1);
        loop {
            tokio::select! {
                _ = wait_shutdown(&mut shutdown) => {
                    tracing::debug!("Packet-channel interface {}: detached", name);
                    return;
                }
                received = source.recv() => match received {
                    Ok(data) => {
                        if data.len() > hw_mtu {
                            tracing::trace!("Packet-channel {}: datagram of {} B exceeds HW_MTU, discarded", name, data.len());
                            continue;
                        }
                        task_counters.rx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                        // A full queue drops the packet (this is a datagram interface), it never stalls the carrier.
                        match incoming_tx.try_send(IncomingPacket { data }) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                RX_QUEUE_DROPPED.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => return,
                        }
                        // Burst: whatever the carrier already holds goes through the same wakeup.
                        for _ in 1..burst {
                            match source.try_recv() {
                                Some(Ok(data)) if data.len() <= hw_mtu => {
                                    task_counters.rx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                                    match incoming_tx.try_send(IncomingPacket { data }) {
                                        Ok(()) => {}
                                        Err(mpsc::error::TrySendError::Full(_)) => {
                                            RX_QUEUE_DROPPED.fetch_add(1, Ordering::Relaxed);
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                                    }
                                }
                                Some(Ok(_)) => {}
                                Some(Err(_)) | None => break,
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Packet-channel interface {}: receive ended: {}", name, e);
                        return;
                    }
                },
                outgoing = outgoing_rx.recv() => match outgoing {
                    Some(first) => {
                        // Burst: the first packet plus everything already queued behind it, handed to the carrier back to back
                        // so it can coalesce them (QUIC builds one GSO send from several queued datagrams).
                        let mut next = Some(first);
                        let mut n = 0;
                        while let Some(pkt) = next.take() {
                            match sink.send(&pkt.data) {
                                Ok(()) => {
                                    task_counters.tx_bytes.fetch_add(pkt.data.len() as u64, Ordering::Relaxed);
                                }
                                Err(e) if is_drop_not_fatal(&e) => {
                                    TX_REFUSED.fetch_add(1, Ordering::Relaxed);
                                    task_counters.tx_queue_drops.fetch_add(1, Ordering::Relaxed);
                                    task_counters.tx_dropped_bytes.fetch_add(pkt.data.len() as u64, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    tracing::debug!("Packet-channel interface {}: send failed, detaching: {}", name, e);
                                    return;
                                }
                            }
                            n += 1;
                            if n < burst {
                                next = outgoing_rx.try_recv().ok();
                            }
                        }
                    }
                    None => return,
                },
            }
        }
    });

    InterfaceHandle {
        info: InterfaceInfo {
            id: config.id,
            name: config.name,
            hw_mtu: Some(config.hw_mtu),
            is_local_client: false,
            bitrate: None,
            announce_cap_bitrate: None,
            tx_jitter_max_ms: None,
            tx_hold_spread_max_ms: None,
            acquisition: None,
            frame_turnaround_ms: None,
            ifac: None,
            mode: leviculum_core::traits::InterfaceMode::default(),
            kind: leviculum_core::traits::InterfaceKind::Channel,
            ingress_control: None,
        },
        incoming: incoming_rx,
        outgoing: outgoing_tx,
        counters,
        // Reliable-or-not, the carrier does its own pacing (QUIC congestion control): no airtime budget.
        credit: None,
        ready,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leviculum_core::traits::Interface;
    use std::time::Duration;

    struct ChanSource(mpsc::Receiver<Vec<u8>>);
    impl PacketSource for ChanSource {
        fn recv(&mut self) -> impl Future<Output = io::Result<Vec<u8>>> + Send {
            async move {
                self.0
                    .recv()
                    .await
                    .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
    }
    struct ChanSink(mpsc::UnboundedSender<Vec<u8>>, Option<io::ErrorKind>);
    impl PacketSink for ChanSink {
        fn send(&mut self, packet: &[u8]) -> io::Result<()> {
            if let Some(kind) = self.1 {
                return Err(io::Error::from(kind));
            }
            self.0
                .send(packet.to_vec())
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    fn spawn(
        hw_mtu: u32,
        fail: Option<io::ErrorKind>,
    ) -> (
        InterfaceHandle,
        mpsc::Sender<Vec<u8>>,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let (to_iface, source_rx) = mpsc::channel(16);
        let (sink_tx, from_iface) = mpsc::unbounded_channel();
        let handle = spawn_packet_channel_interface(
            PacketChannelConfig {
                id: InterfaceId(0),
                name: "pc-test".into(),
                buffer_size: 16,
                hw_mtu,
                shutdown: None,
            },
            ChanSource(source_rx),
            ChanSink(sink_tx, fail),
        );
        (handle, to_iface, from_iface)
    }

    #[tokio::test]
    async fn packets_cross_unframed_in_both_directions() {
        let (mut handle, to_iface, mut from_iface) = spawn(1200, None);
        handle.ready.wait(Duration::from_secs(5)).await.unwrap();

        // Bytes that HDLC would have to escape travel verbatim: there is no framing to confuse.
        let packet = vec![0x7e, 0x7d, 0x00, 0xff, 0x7e];
        to_iface.send(packet.clone()).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), handle.incoming.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.data, packet);

        handle.try_send(&packet).unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), from_iface.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out, packet, "exactly one datagram per packet, byte for byte");
    }

    #[tokio::test]
    async fn oversize_incoming_is_dropped_and_the_interface_stays_up() {
        let (mut handle, to_iface, _out) = spawn(100, None);
        to_iface.send(vec![1u8; 101]).await.unwrap();
        to_iface.send(vec![2u8; 100]).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), handle.incoming.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.data, vec![2u8; 100], "the oversize datagram vanished, the next one arrived");
    }

    #[tokio::test]
    async fn a_refused_send_is_counted_and_not_fatal() {
        let (mut handle, to_iface, mut from_iface) = spawn(1200, Some(io::ErrorKind::WouldBlock));
        handle.try_send(&[1, 2, 3]).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while handle.counters.tx_queue_drops.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(handle.counters.tx_dropped_bytes.load(Ordering::Relaxed), 3);
        assert!(from_iface.try_recv().is_err());
        // Still alive: inbound traffic keeps flowing.
        to_iface.send(vec![9]).await.unwrap();
        assert_eq!(handle.incoming.recv().await.unwrap().data, vec![9]);
    }

    #[tokio::test]
    async fn a_dead_carrier_detaches_the_interface() {
        let (mut handle, to_iface, _out) = spawn(1200, None);
        drop(to_iface); // the source ends: BrokenPipe
        let closed = tokio::time::timeout(Duration::from_secs(5), handle.incoming.recv())
            .await
            .unwrap();
        assert!(closed.is_none(), "incoming channel closes when the carrier ends");
    }
}
