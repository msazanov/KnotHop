//! Byte-channel interface: HDLC-framed packets over a caller-supplied
//! `AsyncRead + AsyncWrite`, with no subprocess.
//!
//! The in-process counterpart to [`PipeInterface`](super::pipe) — the same HDLC
//! framing, but over any duplex the caller provides (e.g. an in-memory
//! [`tokio::io::duplex`] or a host-opened socket) instead of a subprocess's
//! stdin/stdout. The wire contract is identical, so the far side can be a plain
//! PipeInterface.

mod handle;
mod io;

use std::sync::Arc;

use leviculum_core::transport::InterfaceId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use super::{InterfaceCounters, InterfaceHandle, InterfaceInfo, ReadySignal};

pub use handle::ByteChannelHandle;

/// `HW_MTU` for a byte-channel interface, matching [`PipeInterface`](super::pipe)
/// so the two are wire-interchangeable.
pub(crate) const BYTE_CHANNEL_HW_MTU: u32 = 1064;

/// Default channel buffer size (packets), matching the pipe interface.
pub(crate) const BYTE_CHANNEL_DEFAULT_BUFFER_SIZE: usize = 64;

/// Default read buffer size (bytes) used to pull data off the caller's stream.
pub(crate) const BYTE_CHANNEL_DEFAULT_READ_BUF: usize = 1024;

/// Tunables of a byte-channel interface. [`Default`] reproduces the upstream
/// behaviour exactly (HW_MTU 1064, 64-packet channels, 1 KiB reads).
///
/// Fork addition (rawg tuning): the upstream values are sized for serial-like
/// pipes and cap throughput over a fast reliable stream such as QUIC.
#[derive(Debug, Clone, Copy)]
pub struct ByteChannelOptions {
    /// `HW_MTU` advertised for the interface (bounds link MTU negotiation).
    pub hw_mtu: u32,
    /// Capacity, in packets, of the incoming and outgoing channels.
    pub buffer_size: usize,
    /// Size of the buffer used for each read from the stream.
    pub read_buf_size: usize,
}

impl Default for ByteChannelOptions {
    fn default() -> Self {
        Self {
            hw_mtu: BYTE_CHANNEL_HW_MTU,
            buffer_size: BYTE_CHANNEL_DEFAULT_BUFFER_SIZE,
            read_buf_size: BYTE_CHANNEL_DEFAULT_READ_BUF,
        }
    }
}

/// Configuration for a byte-channel interface.
pub(crate) struct ByteChannelConfig {
    pub id: InterfaceId,
    pub name: String,
    pub buffer_size: usize,
    pub hw_mtu: u32,
    pub read_buf_size: usize,
    /// Fires to detach the interface: the task stops and closes its channels,
    /// so the event loop removes it from routing.
    pub shutdown: Option<oneshot::Receiver<()>>,
}

/// Spawn a byte-channel interface over a caller-supplied duplex.
///
/// Ready immediately; on stream EOF/error or `shutdown` the task ends and the
/// interface detaches. No respawn — the caller re-attaches if its stream drops.
pub(crate) fn spawn_byte_channel_interface<S>(
    config: ByteChannelConfig,
    stream: S,
) -> InterfaceHandle
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (incoming_tx, incoming_rx) = mpsc::channel(config.buffer_size);
    let (outgoing_tx, outgoing_rx) = mpsc::channel(config.buffer_size);
    let counters = Arc::new(InterfaceCounters::new());
    let ready = ReadySignal::new();

    let id = config.id;
    let name = config.name.clone();
    let task_counters = Arc::clone(&counters);
    let task_ready = Arc::clone(&ready);
    let shutdown = config.shutdown;
    let hw_mtu = config.hw_mtu;
    let read_buf_size = config.read_buf_size;

    tokio::spawn(async move {
        // No connect step — ready as soon as the stream is handed over.
        task_ready.signal_ready();
        let (read, write) = tokio::io::split(stream);
        io::run(
            name,
            read,
            write,
            incoming_tx,
            outgoing_rx,
            task_counters,
            shutdown,
            hw_mtu,
            read_buf_size,
        )
        .await;
    });

    InterfaceHandle {
        info: InterfaceInfo {
            id,
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
        // Reliable stream, no radio physics → no airtime budget (like TCP/pipe).
        credit: None,
        ready,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use leviculum_core::traits::Interface;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Attach the interface over one half of a `duplex` pair, echo the other
    /// half, and confirm a packet round-trips HDLC-framed — proving the framer
    /// and both I/O directions line up over a caller-supplied stream (payload
    /// includes FLAG/ESC bytes to exercise escaping).
    #[tokio::test]
    async fn duplex_loopback_round_trips_a_packet() {
        let (iface_side, mut peer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match peer.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) if peer.write_all(&buf[..n]).await.is_err() => return,
                    Ok(_) => {}
                }
            }
        });

        let mut handle = spawn_byte_channel_interface(
            ByteChannelConfig {
                id: InterfaceId(0),
                name: "bc-test".into(),
                buffer_size: BYTE_CHANNEL_DEFAULT_BUFFER_SIZE,
                hw_mtu: BYTE_CHANNEL_HW_MTU,
                read_buf_size: BYTE_CHANNEL_DEFAULT_READ_BUF,
                shutdown: None,
            },
            iface_side,
        );
        handle
            .ready
            .wait(Duration::from_secs(5))
            .await
            .expect("byte channel should become ready");

        let payload = vec![0x00, 0x7e, 0x7d, 0x11, 0x22, 0xff];
        handle.try_send(&payload).expect("send should succeed");

        let got = tokio::time::timeout(Duration::from_secs(5), handle.incoming.recv())
            .await
            .expect("incoming packet within timeout")
            .expect("channel open");
        assert_eq!(
            got.data, payload,
            "payload must survive the HDLC round-trip"
        );
    }
}
