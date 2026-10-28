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

/// Почтовый ящик устройства TUN: Java подключает и снимает VPN, не перезапуская узел. В ящике дескриптор лежит только до того, как его
/// заберёт клиент (иначе процесс держал бы интерфейс после остановки приложением).
fn tun_mailbox() -> &'static std::sync::Mutex<Option<std::os::fd::OwnedFd>> {
    static VALUE: OnceLock<std::sync::Mutex<Option<std::os::fd::OwnedFd>>> = OnceLock::new();
    VALUE.get_or_init(|| std::sync::Mutex::new(None))
}

fn tun_changed() -> &'static watch::Sender<u64> {
    static VALUE: OnceLock<watch::Sender<u64>> = OnceLock::new();
    VALUE.get_or_init(|| watch::channel(0).0)
}

/// `fd >= 0` - подключить TUN (берём свой дубликат, Java держит и закрывает свой), `fd < 0` - снять.
pub fn set_tun_fd(fd: i32) -> bool {
    use std::os::fd::FromRawFd;
    let owned = if fd >= 0 {
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if dup < 0 { return false; }
        Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(dup) })
    } else {
        None
    };
    *tun_mailbox().lock().unwrap() = owned;
    tun_changed().send_modify(|g| *g = g.wrapping_add(1));
    true
}

/// Забрать последнее выставленное устройство (`None` - снять или не выставлялось).
pub(crate) fn take_tun() -> Option<std::os::fd::OwnedFd> {
    tun_mailbox().lock().unwrap().take()
}

pub(crate) fn tun_commands() -> watch::Receiver<u64> {
    tun_changed().subscribe()
}

/// Выход клиента: брошенный непринятый дескриптор не должен держать интерфейс.
pub(crate) fn clear_tun() {
    let _ = take_tun();
}

/// Просьбы пользователя (потяни-чтобы-обновить): 0 - внеочередной анонс, 1 - проверка связи со всеми нодами. Без опроса файлов:
/// узел просыпается только по просьбе, периоды анонсов не меняются.
pub const KICK_ANNOUNCE: i32 = 0;
pub const KICK_PING: i32 = 1;

fn kicks() -> &'static [watch::Sender<u64>; 2] {
    static VALUE: OnceLock<[watch::Sender<u64>; 2]> = OnceLock::new();
    VALUE.get_or_init(|| [watch::channel(0).0, watch::channel(0).0])
}

pub fn kick(kind: i32) -> bool {
    match usize::try_from(kind).ok().and_then(|k| kicks().get(k)) {
        Some(tx) => { tx.send_modify(|g| *g = g.wrapping_add(1)); true }
        None => false,
    }
}

pub(crate) fn kick_rx(kind: i32) -> watch::Receiver<u64> {
    kicks()[kind as usize].subscribe()
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
