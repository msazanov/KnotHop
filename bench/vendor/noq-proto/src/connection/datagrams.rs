use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::{Connection, PathId};
use crate::{
    FrameStats, TransportError,
    connection::PacketBuilder,
    frame::{Datagram, FrameStruct},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// KnotHop: queue a datagram for exactly one already validated path. It is
    /// never redirected to another path; queue and congestion limits still apply.
    pub fn send_on_path(&mut self, path_id: PathId, data: Bytes) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self.max_size().ok_or(SendDatagramError::UnsupportedByPeer)?;
        if data.len() > max.min(self.conn.config.datagram_send_buffer_size) {
            return Err(SendDatagramError::TooLarge);
        }
        if self.conn.is_handshaking() || self.conn.abandoned_paths.contains(&path_id)
            || !self.conn.paths.get(&path_id).is_some_and(|p| p.data.validated)
            || !self.conn.remote_cids.contains_key(&path_id)
            || self.conn.datagrams.pinned.len() >= 32
            || !self.conn.datagrams.has_send_buffer_space(data.len(), self.conn.config.datagram_send_buffer_size) {
            return Err(SendDatagramError::Blocked(data));
        }
        let path_max = (self.conn.path_data(path_id).current_mtu() as usize)
            .saturating_sub(self.conn.predict_1rtt_overhead_no_pn() + Datagram::SIZE_BOUND);
        if data.len() > path_max { return Err(SendDatagramError::TooLarge); }
        self.conn.datagrams.outgoing_total += data.len();
        self.conn.datagrams.pinned.push_back((path_id, Datagram { data }));
        Ok(())
    }
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        if data.len() > Ord::min(max, send_buffer_size) {
            return Err(SendDatagramError::TooLarge);
        }
        if drop {
            self.conn
                .datagrams
                .make_space_for(data.len(), send_buffer_size);
        } else if !self
            .conn
            .datagrams
            .has_send_buffer_space(data.len(), send_buffer_size)
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.outgoing_total += data.len();
        self.conn.datagrams.outgoing.push_back(Datagram { data });
        Ok(())
    }

    /// Queue many unreliable, unordered datagrams for transmission in a single call.
    ///
    /// This is the batch analogue of [`Self::send`], avoiding repeated connection checks.
    ///
    /// The batch is rejected atomically with the [`TooLarge`] error if any datagram
    /// in the batch is too large.
    ///
    /// `drop` selects the backpressure behaviour, matching [`Self::send`]:
    ///
    /// - `drop = true` drops the oldest queued datagrams to make room, so every element is queued
    ///   and `Ok(datagrams.len())` is returned.
    /// - `drop = false` queues elements until the send buffer is full, then stops and returns
    ///   `Ok(n)` for the `n` elements queued. The remaining elements are the caller's to retry once
    ///   space frees up.
    ///
    /// Returns `Err` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// [`TooLarge`]: SendDatagramError::TooLarge
    pub fn send_many(
        &mut self,
        datagrams: &[Bytes],
        drop: bool,
    ) -> Result<usize, SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        if datagrams
            .iter()
            .any(|data| data.len() > Ord::min(max, send_buffer_size))
        {
            return Err(SendDatagramError::TooLarge);
        }

        let mut queued = 0usize;
        for data in datagrams {
            if drop {
                self.conn
                    .datagrams
                    .make_space_for(data.len(), send_buffer_size);
            } else if !self
                .conn
                .datagrams
                .has_send_buffer_space(data.len(), send_buffer_size)
            {
                self.conn.datagrams.send_blocked = true;
                break;
            }
            self.conn.datagrams.outgoing_total += data.len();
            self.conn
                .datagrams
                .outgoing
                .push_back(Datagram { data: data.clone() });
            queued += 1;
        }

        Ok(queued)
    }

    /// Compute the maximum size of datagrams that may be passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// When multipath is enabled, this is calculated using the smallest MTU across all
    /// available paths.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.current_mtu() as usize
            - self.conn.predict_1rtt_overhead_no_pn()
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// KnotHop: получить датаграмму вместе с идентификатором QUIC-пути, на
    /// котором она прошла аутентификацию. Не выводит путь из выбранного адреса.
    pub fn recv_with_path(&mut self) -> Option<(Bytes, PathId)> {
        self.conn.datagrams.recv_with_path()
    }

    /// Drain up to `out.len()` buffered datagrams into `out`, in arrival order.
    ///
    /// This is the batch analogue of [`Self::recv`]: a single call takes many
    /// datagrams at once. `out` is filled from the front and overwritten in place;
    /// pass a slice of empty `Bytes` sized to the batch you want. Returns the number
    /// of datagrams written, which may be less than `out.len()` if fewer are buffered
    /// (0 if none). Any remaining datagrams stay queued for the next call.
    pub fn recv_many(&mut self, out: &mut [Bytes]) -> usize {
        self.conn.datagrams.recv_many(out)
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing_total)
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    max_payload: Option<usize>,
    pub(super) mtu_drops: u64,
    /// Number of bytes of datagrams that have been received by the local transport but not
    /// delivered to the application
    pub(super) recv_buffered: usize,
    pub(super) incoming: VecDeque<(Datagram, PathId)>,
    pub(super) outgoing: VecDeque<Datagram>,
    /// Bounded path-specific control/probe queue; never falls back to a different path.
    pub(super) pinned: VecDeque<(PathId, Datagram)>,
    pub(super) outgoing_total: usize,
    pub(super) send_blocked: bool,
}

impl DatagramState {
    /// Recheck the queue only when the usable budget changes, before scheduling.
    pub(super) fn update_max_payload(&mut self, max_payload: usize) -> bool {
        if self.max_payload == Some(max_payload) {
            return false;
        }
        self.max_payload = Some(max_payload);
        self.drop_oversized(max_payload)
    }

    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        path_id: PathId,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        if datagram.data.len() > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        let was_empty = self.recv_buffered == 0;
        while datagram.data.len() + self.recv_buffered > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.recv_buffered += datagram.data.len();
        self.incoming.push_back((datagram, path_id));
        Ok(was_empty)
    }

    fn make_space_for(&mut self, datagram_len: usize, send_buffer_size: usize) {
        while !self.has_send_buffer_space(datagram_len, send_buffer_size) {
            let prev = match self.outgoing.pop_front() {
                Some(datagram) => datagram,
                None => match self.pinned.pop_front() {
                    Some((_, datagram)) => datagram,
                    None => break,
                },
            };
            trace!(len = prev.data.len(), "dropping outgoing datagram");
            self.outgoing_total -= prev.data.len();
        }
    }

    fn has_send_buffer_space(&self, datagram_len: usize, send_buffer_size: usize) -> bool {
        let Some(total) = self.outgoing_total.checked_add(datagram_len) else {
            return false;
        };

        total <= send_buffer_size
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Returns whether any datagrams were dropped.
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let mut dropped_any = false;
        self.outgoing.retain(|datagram| {
            let result = datagram.data.len() <= max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.data.len(),
                    max_payload
                );
                self.outgoing_total -= datagram.data.len();
                self.mtu_drops = self.mtu_drops.saturating_add(1);
                dropped_any = true;
            }
            result
        });
        self.pinned.retain(|(_, datagram)| {
            if datagram.data.len() <= max_payload { return true; }
            self.outgoing_total -= datagram.data.len();
            self.mtu_drops = self.mtu_drops.saturating_add(1);
            dropped_any = true;
            false
        });
        dropped_any
    }

    pub(super) fn drop_pinned_path(&mut self, path_id: PathId) {
        self.pinned.retain(|(id, datagram)| {
            if *id != path_id { return true; }
            self.outgoing_total -= datagram.data.len();
            false
        });
    }

    pub(super) fn drop_pinned_oversized(&mut self, path_id: PathId, max_payload: usize) {
        self.pinned.retain(|(id, datagram)| {
            if *id != path_id || datagram.data.len() <= max_payload { return true; }
            self.outgoing_total -= datagram.data.len();
            self.mtu_drops = self.mtu_drops.saturating_add(1);
            false
        });
    }

    pub(super) fn pinned_ready(&self, path_id: PathId, max_size: usize) -> bool {
        self.pinned.iter().any(|(id, d)| *id == path_id && d.size(true) <= max_size)
    }

    pub(super) fn write_pinned(&mut self, path_id: PathId, buf: &mut PacketBuilder<'_, '_>, stat: &mut FrameStats) -> bool {
        let Some(index) = self.pinned.iter().position(|(id, d)| *id == path_id && d.size(true) <= buf.frame_space_remaining()) else { return false };
        let (_, datagram) = self.pinned.remove(index).expect("index obtained from queue");
        self.outgoing_total -= datagram.data.len();
        buf.write_frame(datagram, stat);
        true
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write<'a, 'b>(
        &mut self,
        buf: &mut PacketBuilder<'a, 'b>,
        stat: &mut FrameStats,
    ) -> bool {
        let Some(datagram) = self.outgoing.pop_front() else {
            return false;
        };

        if buf.frame_space_remaining() < datagram.size(true) {
            self.outgoing.push_front(datagram);
            return false;
        }

        self.outgoing_total -= datagram.data.len();
        buf.write_frame(datagram, stat);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        self.recv_with_path().map(|(data, _)| data)
    }

    fn recv_with_path(&mut self) -> Option<(Bytes, PathId)> {
        let (datagram, path) = self.incoming.pop_front()?;
        let x = datagram.data;
        self.recv_buffered -= x.len();
        Some((x, path))
    }

    /// Drain up to `out.len()` buffered datagrams into `out`, in arrival order.
    ///
    /// Returns the number of datagrams written into `out` (which may be less than
    /// `out.len()` if fewer are buffered). Remaining datagrams stay queued.
    pub(super) fn recv_many(&mut self, out: &mut [Bytes]) -> usize {
        let n = out.len().min(self.incoming.len());
        let mut received_bytes = 0;
        for (i, (d, _)) in self.incoming.drain(..n).enumerate() {
            received_bytes += d.data.len();
            out[i] = d.data;
        }
        self.recv_buffered -= received_bytes;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_queue_pruning_preserves_boundary_and_unblocks_smaller_datagrams() {
        let mut state = DatagramState::default();
        for size in [1328, 1162, 32] {
            state.outgoing.push_back(Datagram { data: Bytes::from(vec![0; size]) });
            state.outgoing_total += size;
        }
        assert!(!state.update_max_payload(1414));
        assert!(state.update_max_payload(1162));
        assert_eq!(state.outgoing.iter().map(|d| d.data.len()).collect::<Vec<_>>(), [1162, 32]);
        assert_eq!(state.outgoing_total, 1194);
        assert_eq!(state.mtu_drops, 1);
        assert!(!state.update_max_payload(1162));
        assert_eq!(state.mtu_drops, 1);
    }

    #[test]
    fn make_space_for_accounts_for_new_datagram() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0; 7]),
        });
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0; 2]),
        });
        state.outgoing_total = 9;

        state.make_space_for(4, 10);

        assert_eq!(state.outgoing.len(), 1);
        assert_eq!(state.outgoing[0].data.len(), 2);
        assert_eq!(state.outgoing_total, 2);
    }

    #[test]
    fn make_space_for_handles_overflowing_capacity_check() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0]),
        });
        state.outgoing_total = usize::MAX - 1;

        state.make_space_for(2, usize::MAX);

        assert!(state.outgoing.is_empty());
        assert_eq!(state.outgoing_total, usize::MAX - 2);
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}
