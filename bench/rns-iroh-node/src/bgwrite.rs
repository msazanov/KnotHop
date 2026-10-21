//! Фоновая запись периодических диагностических файлов (`status.json`, `neighbors.json`).
//!
//! Запись + `rename` на медленном или деградирующем диске блокируются секундами (fin1: до 2,6 с, W48). Если делать это в async-задаче,
//! а воркеров по квоте CPU один, встаёт весь рантайм: пинги и ответы не обрабатываются, соседи признаются мёртвыми разом.
//! Здесь запись идёт из собственного потока, по каждому пути хранится только последнее значение, не чаще `min_interval`,
//! и неизменившееся содержимое пропускается. Для файлов, которые должны пережить сбой (права, отзывы, ключи), это не годится.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

/// Не больше стольких разных путей: вызывающие код фиксированный, предел только страхует от утечки.
const MAX_SLOTS: usize = 32;

struct Slot {
    /// ещё не записанное значение
    pending: Option<Vec<u8>>,
    /// последнее записанное содержимое (для пропуска повторов) и время записи
    written: Option<(Vec<u8>, Instant)>,
    min_interval: Duration,
}

struct Queue {
    slots: Mutex<HashMap<PathBuf, Slot>>,
    wake: Condvar,
}

static QUEUE: OnceLock<Queue> = OnceLock::new();
static STARTED: Once = Once::new();

fn queue() -> &'static Queue {
    let q = QUEUE.get_or_init(|| Queue { slots: Mutex::new(HashMap::new()), wake: Condvar::new() });
    STARTED.call_once(|| {
        if std::thread::Builder::new().name("rawg-writer".into()).spawn(writer_loop).is_err() {
            eprintln!("bgwrite: не удалось создать поток записи");
        }
    });
    q
}

/// Поставить файл на запись. Не блокирует: значение заменяет ещё не записанное предыдущее.
/// Первая запись по пути - сразу, следующие - не раньше чем через `min_interval` после предыдущей записи.
pub fn put(path: &Path, data: Vec<u8>, min_interval: Duration) {
    let q = queue();
    let mut m = q.slots.lock().unwrap_or_else(|e| e.into_inner());
    if !m.contains_key(path) && m.len() >= MAX_SLOTS {
        return;
    }
    let s = m.entry(path.to_path_buf()).or_insert_with(|| Slot { pending: None, written: None, min_interval });
    s.min_interval = min_interval;
    s.pending = Some(data);
    drop(m);
    q.wake.notify_one();
}

fn write_file(p: &Path, data: &[u8]) {
    let tmp = p.with_extension("tmp");
    if std::fs::write(&tmp, data).is_ok() {
        let _ = std::fs::rename(&tmp, p);
    }
}

fn writer_loop() {
    let q = QUEUE.get().expect("очередь создаётся до потока");
    loop {
        let mut due: Vec<(PathBuf, Vec<u8>)> = Vec::new();
        let mut next: Option<Instant> = None;
        {
            let mut m = q.slots.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            for (path, s) in m.iter_mut() {
                let Some(data) = s.pending.as_ref() else { continue };
                if s.written.as_ref().map_or(false, |(old, _)| old == data) {
                    s.pending = None; // содержимое то же: диск не трогаем
                    continue;
                }
                let at = s.written.as_ref().map(|(_, t)| *t + s.min_interval);
                match at {
                    Some(t) if t > now => next = Some(next.map_or(t, |n| n.min(t))),
                    _ => due.push((path.clone(), s.pending.take().unwrap())),
                }
            }
            if due.is_empty() {
                let wait = next.map(|t| t.saturating_duration_since(now)).unwrap_or(Duration::from_secs(3600));
                let _ = q.wake.wait_timeout(m, wait.max(Duration::from_millis(1)));
                continue;
            }
        }
        // запись вне блокировки: put() не должен ждать диск
        for (path, data) in due {
            write_file(&path, &data);
            let mut m = q.slots.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(s) = m.get_mut(&path) {
                s.written = Some((data, Instant::now()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rawg-bgwrite-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn wait_for(p: &Path, want: &[u8]) -> bool {
        for _ in 0..200 {
            if std::fs::read(p).map(|b| b == want).unwrap_or(false) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn first_write_is_immediate_and_later_ones_are_throttled_to_latest() {
        let d = tmp("throttle");
        let p = d.join("a.json");
        put(&p, b"1".to_vec(), Duration::from_millis(400));
        assert!(wait_for(&p, b"1"), "первая запись должна пройти сразу");
        put(&p, b"2".to_vec(), Duration::from_millis(400));
        put(&p, b"3".to_vec(), Duration::from_millis(400));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(std::fs::read(&p).unwrap(), b"1", "в пределах интервала файл не меняется");
        assert!(wait_for(&p, b"3"), "после интервала записывается последнее значение, промежуточное (2) пропускается");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn identical_content_does_not_touch_the_disk() {
        let d = tmp("same");
        let p = d.join("b.json");
        put(&p, b"x".to_vec(), Duration::from_millis(0));
        assert!(wait_for(&p, b"x"));
        let m0 = std::fs::metadata(&p).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(30));
        put(&p, b"x".to_vec(), Duration::from_millis(0));
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(std::fs::metadata(&p).unwrap().modified().unwrap(), m0, "повтор того же содержимого не пишется");
        put(&p, b"y".to_vec(), Duration::from_millis(0));
        assert!(wait_for(&p, b"y"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn put_does_not_block_on_a_missing_directory() {
        let d = tmp("nodir");
        let p = d.join("no/such/dir/c.json");
        let t = Instant::now();
        put(&p, b"z".to_vec(), Duration::from_millis(0));
        assert!(t.elapsed() < Duration::from_millis(100));
        std::thread::sleep(Duration::from_millis(50));
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
