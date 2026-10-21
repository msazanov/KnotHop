//! Android lifecycle signals. They change observation work, never VPN/Link lifetimes.
//! watch retains the latest value even when the JNI call precedes the Tokio runtime.
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::watch;

pub const STATUS_FOREGROUND: Duration = Duration::from_secs(1);
pub const STATUS_BACKGROUND: Duration = Duration::from_secs(30);

fn visibility() -> &'static watch::Sender<bool> {
    static VALUE: OnceLock<watch::Sender<bool>> = OnceLock::new();
    VALUE.get_or_init(|| watch::channel(!cfg!(target_os = "android")).0)
}

pub fn set_ui_visible(visible: bool) {
    visibility().send_if_modified(|value| {
        if *value == visible { return false; }
        *value = visible;
        true
    });
}

pub fn ui_changes() -> watch::Receiver<bool> {
    visibility().subscribe()
}

pub fn ui_visible() -> bool {
    *visibility().borrow()
}

pub fn status_interval(visible: bool) -> Duration {
    if visible { STATUS_FOREGROUND } else { STATUS_BACKGROUND }
}

pub async fn next_status(visibility: &mut watch::Receiver<bool>) {
    let interval = status_interval(*visibility.borrow_and_update());
    tokio::select! {
        _ = tokio::time::sleep(interval) => {},
        _ = visibility.changed() => {},
    }
}

fn network() -> &'static watch::Sender<u64> {
    static VALUE: OnceLock<watch::Sender<u64>> = OnceLock::new();
    VALUE.get_or_init(|| watch::channel(0).0)
}

pub fn network_changed() {
    network().send_modify(|generation| *generation = generation.wrapping_add(1));
}

pub fn network_changes() -> watch::Receiver<u64> {
    network().subscribe()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn visibility_survives_runtime_subscription_and_only_wakes_on_change() {
        // Exercise the same watch operations on an isolated channel (no process-global races).
        let tx = watch::channel(false).0;
        tx.send_replace(true);
        let mut rx = tx.subscribe();
        assert!(*rx.borrow_and_update());
        assert_eq!(status_interval(*rx.borrow()), Duration::from_secs(1));
        tx.send_replace(false);
        rx.changed().await.unwrap();
        assert_eq!(status_interval(*rx.borrow_and_update()), Duration::from_secs(30));
        assert!(!rx.has_changed().unwrap());
        // Returning to the UI must interrupt the real background snapshot scheduler.
        let wake = async {
            tokio::task::yield_now().await;
            tx.send_replace(true);
        };
        let (r, _) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(1), next_status(&mut rx)), wake
        );
        assert!(r.is_ok(), "returning to UI waited for the background interval");
    }
}
