//! Discovery coordination only: RNS still selects the route.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) const REQUEST_INTERVAL: Duration = Duration::from_secs(20);

#[derive(Default)]
struct Entry {
    pending: bool,
    last: Option<Instant>,
}

#[derive(Default)]
pub(super) struct PathGate(Mutex<HashMap<[u8; 16], Entry>>);

pub(super) struct Pending<'a> {
    gate: &'a PathGate,
    dest: [u8; 16],
}

impl PathGate {
    /// One discovery owner per destination. Followers may observe paths but not send.
    /// Dropping the lease (including cancellation) releases ownership, not the rate limit.
    pub(super) fn begin(&self, dest: [u8; 16], now: Instant) -> Option<Pending<'_>> {
        let mut entries = self.0.lock().unwrap();
        entries.retain(|_, e| e.pending || e.last.map(|t| now.saturating_duration_since(t) < REQUEST_INTERVAL).unwrap_or(false));
        let e = entries.entry(dest).or_default();
        if e.pending { return None; }
        e.pending = true;
        Some(Pending { gate: self, dest })
    }
}

impl Pending<'_> {
    /// Reserve a request timestamp BEFORE awaiting dispatch. Call only with nonempty egress.
    /// Applies to ordinary and forced requests, across all interface scopes.
    pub(super) fn request_due(&self, now: Instant) -> bool {
        let mut entries = self.gate.0.lock().unwrap();
        let e = entries.get_mut(&self.dest).unwrap();
        if e.last.map(|t| now.saturating_duration_since(t) < REQUEST_INTERVAL).unwrap_or(false) {
            return false;
        }
        e.last = Some(now);
        true
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if let Some(e) = self.gate.0.lock().unwrap().get_mut(&self.dest) { e.pending = false; }
    }
}

pub(super) fn acceptable(iface: Option<usize>, allowed: &[usize], avoid: Option<usize>) -> bool {
    iface.map(|i| Some(i) != avoid && allowed.contains(&i)).unwrap_or(false)
}

/// Modern exits need authorization, not a warm path cache. Legacy eligibility stays unchanged.
pub(super) fn eligible(modern_authorized: Option<bool>, legacy_reachable: bool, lost: bool) -> bool {
    !lost && modern_authorized.unwrap_or(legacy_reachable)
}

pub(super) fn link_timed_out(now: Instant, authenticated_rx: Option<Instant>, timeout: Duration) -> bool {
    authenticated_rx.map(|t| now.saturating_duration_since(t) > timeout).unwrap_or(true)
}

/// После первого допуска сохраняем конечную ноду. Отказ пути не разрешает подставлять другой выход.
pub(super) fn primary_target(manual: Option<[u8;16]>, established: Option<[u8;16]>) -> Option<[u8;16]> {
    manual.or(established)
}

/// Отступ относится к выходу, а не к текущему запасному Link. Истечение паузы
/// разрешает пробу, но само по себе не доказывает восстановление выхода.
#[derive(Default)]
pub(super) struct ExitBackoff(HashMap<[u8; 16], (u64, Instant)>);

/// Запоминаем именно интерфейс неудачной попытки, а не новый путь,
/// который RNS мог успеть найти, пока устанавливался Link.
#[derive(Debug)]
pub(super) struct FailedPath {
    pub(super) iface: usize,
    pub(super) why: String,
}

impl std::fmt::Display for FailedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.why) }
}

impl std::error::Error for FailedPath {}

pub(super) fn forget_failed_path(failed: usize, current: Option<usize>) -> bool {
    current == Some(failed)
}

impl ExitBackoff {
    pub(super) fn failed(&mut self, dest: [u8; 16], now: Instant) -> Duration {
        let secs = self.0.get(&dest).map(|(s, _)| s.saturating_mul(2).min(300)).unwrap_or(10);
        self.0.insert(dest, (secs, now + Duration::from_secs(secs)));
        Duration::from_secs(secs)
    }

    pub(super) fn ready(&self, dest: &[u8; 16], now: Instant) -> bool {
        self.remaining(dest, now).is_zero()
    }

    pub(super) fn remaining(&self, dest: &[u8; 16], now: Instant) -> Duration {
        self.0.get(dest).map(|(_, until)| until.saturating_duration_since(now)).unwrap_or_default()
    }

    pub(super) fn succeeded(&mut self, dest: &[u8; 16]) {
        self.0.remove(dest);
    }

    pub(super) fn healthy(&mut self, dest: &[u8; 16], connected: Instant, now: Instant) {
        // Короткий всплеск связи не обнуляет историю флапа: иначе AUTH_OK/один
        // pong снова превращают отказ через секунды в бесконечный отступ 10 с.
        if now.saturating_duration_since(connected) >= Duration::from_secs(300) {
            self.succeeded(dest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_backoff_doubles_caps_and_does_not_reset_when_pause_expires() {
        let mut b = ExitBackoff::default();
        let mut t = Instant::now();
        let d = [1; 16];
        for secs in [10, 20, 40, 80, 160, 300, 300] {
            assert!(b.ready(&d, t));
            assert_eq!(b.failed(d, t), Duration::from_secs(secs));
            assert!(!b.ready(&d, t + Duration::from_secs(secs - 1)));
            t += Duration::from_secs(secs);
            assert!(b.ready(&d, t));
        }
    }

    #[test]
    fn exit_backoff_success_is_per_exit_and_restores_fast_retry() {
        let mut b = ExitBackoff::default();
        let t = Instant::now();
        b.failed([1; 16], t);
        b.failed([1; 16], t);
        b.failed([2; 16], t);
        b.succeeded(&[1; 16]);
        assert!(b.ready(&[1; 16], t));
        assert!(!b.ready(&[2; 16], t));
        assert_eq!(b.failed([1; 16], t), Duration::from_secs(10));
        assert_eq!(b.remaining(&[2; 16], t + Duration::from_secs(4)), Duration::from_secs(6));
    }

    #[test]
    fn failed_transit_path_is_invalidated_but_replacement_is_kept() {
        assert!(forget_failed_path(2, Some(2)));
        assert!(!forget_failed_path(2, Some(3)));
        assert!(!forget_failed_path(2, None));
        assert!(!acceptable(Some(2), &[2, 3], Some(2)));
        assert!(acceptable(Some(3), &[2, 3], Some(2)));
    }

    #[test]
    fn flapping_exit_keeps_failure_history_until_stable_success() {
        let mut b = ExitBackoff::default();
        let t = Instant::now();
        let d = [3; 16];
        b.failed(d, t);
        b.healthy(&d, t + Duration::from_secs(10), t + Duration::from_secs(100));
        assert_eq!(b.failed(d, t + Duration::from_secs(100)), Duration::from_secs(20));
        let connected = t + Duration::from_secs(120);
        b.healthy(&d, connected, connected + Duration::from_secs(299));
        assert_eq!(b.failed(d, connected + Duration::from_secs(299)), Duration::from_secs(40));
        b.healthy(&d, connected, connected + Duration::from_secs(300));
        assert_eq!(b.failed(d, connected + Duration::from_secs(301)), Duration::from_secs(10));
    }

    #[test]
    fn one_owner_and_shared_twenty_second_budget() {
        let gate = PathGate::default();
        let t = Instant::now();
        let p = gate.begin([1; 16], t).unwrap();
        assert!(p.request_due(t));
        assert!(gate.begin([1; 16], t).is_none());
        assert!(!p.request_due(t + Duration::from_secs(2)));
        drop(p);
        let retry = gate.begin([1; 16], t + Duration::from_secs(19)).unwrap();
        assert!(!retry.request_due(t + Duration::from_secs(19)));
        assert!(retry.request_due(t + REQUEST_INTERVAL));
        assert!(gate.begin([2; 16], t).unwrap().request_due(t));
    }

    #[test]
    fn cancellation_before_send_does_not_consume_budget() {
        let gate = PathGate::default();
        let t = Instant::now();
        drop(gate.begin([1; 16], t).unwrap());
        assert!(gate.begin([1; 16], t).unwrap().request_due(t));
    }

    #[test]
    fn late_avoided_public_offline_and_missing_paths_are_rejected() {
        assert!(acceptable(Some(2), &[2, 3], Some(1)));
        assert!(!acceptable(Some(1), &[1, 2], Some(1)));
        assert!(!acceptable(Some(9), &[2, 3], None));
        assert!(!acceptable(None, &[2, 3], None));
        assert!(!acceptable(Some(2), &[], None));
    }

    #[test]
    fn cold_exit_requires_authorization_not_addresses_or_cached_path() {
        assert!(eligible(Some(true), false, false));
        assert!(!eligible(Some(false), true, false));
        assert!(!eligible(Some(true), true, true));
        assert!(!eligible(None, false, false));
        assert!(eligible(None, true, false));
    }

    #[test]
    fn link_timeout_uses_authenticated_receive_and_handles_missing_link() {
        let t = Instant::now();
        let dead = Duration::from_secs(12);
        assert!(!link_timed_out(t + dead, Some(t), dead));
        assert!(link_timed_out(t + dead + Duration::from_millis(1), Some(t), dead));
        // A fresh authenticated control/ping keeps the Link, even when no pong arrived.
        assert!(!link_timed_out(t + Duration::from_secs(30), Some(t + Duration::from_secs(29)), dead));
        assert!(link_timed_out(t, None, dead));
    }

    #[test]
    fn simultaneous_callers_have_one_discovery_owner() {
        let gate = PathGate::default();
        let barrier = std::sync::Barrier::new(8);
        let owners = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    barrier.wait();
                    let lease = gate.begin([1; 16], Instant::now());
                    if lease.is_some() { owners.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                    barrier.wait();
                    drop(lease);
                });
            }
        });
        assert_eq!(owners.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
