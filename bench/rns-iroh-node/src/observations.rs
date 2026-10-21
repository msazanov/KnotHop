//! Bounded, advisory neighbour observations. Missing evidence is unknown, never a global death certificate.
use serde_json::{Value, json};
use std::time::{Duration, Instant};

pub const MAX_NEIGHBORS: usize = 32;
pub const FOREGROUND_PERIOD: Duration = Duration::from_secs(30);
pub const BACKGROUND_PERIOD: Duration = Duration::from_secs(180);
pub const REPORT_TTL: Duration = Duration::from_secs(90);

pub fn presence(authenticated_contact: bool, reporters: usize) -> &'static str {
    if authenticated_contact { "alive" } else if reporters > 0 { "reported" } else { "unknown" }
}

/// Per admitted client; a hidden UI needs no continuous topology/RTT updates.
pub struct Subscription {
    visible: bool,
    last_sent: Option<Instant>,
    signature: Vec<(String, String)>,
    refresh: bool,
    requested: bool,
}

impl Default for Subscription {
    fn default() -> Self {
        Self { visible: true, last_sent: None, signature: Vec::new(), refresh: false, requested: false }
    }
}

impl Subscription {
    pub fn set_visible(&mut self, visible: bool) {
        // First explicit request follows client-side EXIT validation. The unsolicited
        // admission snapshot may have arrived too early; reply once immediately.
        if !self.requested { self.last_sent = None; self.requested = true; }
        self.visible = visible;
        self.refresh = true;
    }

    pub fn ttl(&self) -> u64 {
        if self.visible { 90 } else { 210 }
    }

    /// Changes in RTT alone do not trigger a full report. Explicit requests are limited too.
    pub fn due(&mut self, now: Instant, entries: &[Value]) -> bool {
        let signature: Vec<_> = entries.iter().take(MAX_NEIGHBORS)
            .map(|v| (v["d"].as_str().unwrap_or("").to_owned(), v["n"].as_str().unwrap_or("").to_owned())).collect();
        let elapsed = self.last_sent.map(|t| now.saturating_duration_since(t));
        if let Some(age) = elapsed {
            if age < Duration::from_secs(5) { return false; }
            let period = if self.visible { FOREGROUND_PERIOD } else { BACKGROUND_PERIOD };
            if !self.refresh && age < period && (!self.visible || signature == self.signature) { return false; }
        }
        self.last_sent = Some(now);
        self.signature = signature;
        self.refresh = false;
        true
    }
}

/// Fit the negotiated Channel body budget. A truncated observation never asserts absence.
pub fn encode_report(entries: &[Value], ttl: u64, budget: usize) -> Option<Vec<u8>> {
    let mut n = Vec::new();
    for e in entries.iter().take(MAX_NEIGHBORS) {
        n.push(e.clone());
        if serde_json::to_vec(&json!({"n": n, "ttl": ttl, "complete": false})).ok()?.len() > budget {
            n.pop();
            break;
        }
    }
    let body = serde_json::to_vec(&json!({"complete": n.len() == entries.len(), "n": n, "ttl": ttl})).ok()?;
    (body.len() <= budget).then_some(body)
}

pub fn report_ttl(v: &Value) -> Duration {
    Duration::from_secs(v["ttl"].as_u64().unwrap_or(REPORT_TTL.as_secs()).clamp(30, 210))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_or_expired_observations_never_mean_dead() {
        assert_eq!(presence(false, 0), "unknown");
        assert_eq!(presence(false, 1), "reported");
        assert_eq!(presence(true, 0), "alive");
        let received = Instant::now();
        let ttl = report_ttl(&json!({}));
        assert!((received + Duration::from_secs(89)).duration_since(received) < ttl);
        assert!(!((received + Duration::from_secs(90)).duration_since(received) < ttl));
        assert_eq!(presence(false, usize::from(Duration::from_secs(90) < ttl)), "unknown");
        assert_eq!(report_ttl(&json!({"ttl": u64::MAX})), Duration::from_secs(210));
    }

    #[test]
    fn rtt_jitter_and_hidden_topology_do_not_generate_continuous_reports() {
        let t = Instant::now();
        let a = vec![json!({"d":"a", "n":"A", "r":4})];
        let jitter = vec![json!({"d":"a", "n":"A", "r":5})];
        let mut sub = Subscription::default();
        assert!(sub.due(t, &a));
        assert!(!sub.due(t + Duration::from_secs(10), &jitter));
        assert!(sub.due(t + Duration::from_secs(30), &jitter));
        sub.set_visible(false);
        assert!(sub.due(t + Duration::from_secs(40), &a));
        assert!(!sub.due(t + Duration::from_secs(100), &[]));
        assert!(sub.due(t + Duration::from_secs(220), &[]));
        sub.set_visible(true);
        assert!(!sub.due(t + Duration::from_secs(221), &a));
        assert!(sub.due(t + Duration::from_secs(225), &a));
    }

    #[test]
    fn unicode_reports_respect_real_channel_budget_and_mark_truncation() {
        let entries: Vec<_> = (0..32).map(|i| json!({"d":format!("{i:032x}"), "n":"🛰".repeat(32), "r":1})).collect();
        for budget in [180, 400, 1300] {
            let body = encode_report(&entries, 90, budget).unwrap();
            assert!(body.len() <= budget);
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["complete"], false);
            assert!(v["n"].as_array().unwrap().len() < 32);
        }
        let body = encode_report(&entries[..1], 90, 400).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["complete"], true);
        assert!(encode_report(&entries, 90, 1).is_none());
    }
}
