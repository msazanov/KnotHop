//! Сторож рантайма tokio: отличает голодание CPU от блокировки внутри процесса (без perf на хосте).
//!
//! Задача tokio раз в 100 мс отмечает «сердцебиение». Отдельный поток ОС (вне tokio) раз в 250 мс сверяет его возраст и
//! снимает `/proc/self/task/*/schedstat` (время на CPU и в очереди планировщика, нс). Когда сердцебиение пропало дольше
//! `STALL`, по возвращении в журнал идёт одна строка: длительность замирания и по группам потоков (по `comm`) — сколько
//! они за это время были на CPU, ждали в очереди (голодание) и сколько спали (≈ блокировка: замок, канал, ввод-вывод).
use std::{collections::HashMap, sync::{Arc, atomic::{AtomicU64, Ordering::Relaxed}}, time::{Duration, Instant}};

const STALL: Duration = Duration::from_secs(2);
const BEAT: Duration = Duration::from_millis(100);
const SAMPLE: Duration = Duration::from_millis(250);

/// (cpu_ns, runq_wait_ns) по tid и имя потока.
fn snapshot() -> HashMap<u32, (String, u64, u64)> {
    let mut m = HashMap::new();
    let Ok(dir) = std::fs::read_dir("/proc/self/task") else { return m };
    for e in dir.flatten() {
        let Some(tid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let p = e.path();
        let comm = std::fs::read_to_string(p.join("comm")).unwrap_or_default().trim().to_string();
        let ss = std::fs::read_to_string(p.join("schedstat")).unwrap_or_default();
        let mut it = ss.split_whitespace().map(|v| v.parse::<u64>().unwrap_or(0));
        let (cpu, wait) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
        m.insert(tid, (comm, cpu, wait));
    }
    m
}

/// Сводка по группам потоков между двумя снимками: (имя, потоков, cpu_ms, очередь_ms).
pub(crate) fn summarize(a: &HashMap<u32, (String, u64, u64)>, b: &HashMap<u32, (String, u64, u64)>) -> Vec<(String, usize, u64, u64)> {
    let mut g: HashMap<String, (usize, u64, u64)> = HashMap::new();
    for (tid, (comm, cpu1, w1)) in b {
        let (cpu0, w0) = a.get(tid).map_or((*cpu1, *w1), |(_, c, w)| (*c, *w));
        let e = g.entry(comm.clone()).or_default();
        e.0 += 1;
        e.1 += cpu1.saturating_sub(cpu0) / 1_000_000;
        e.2 += w1.saturating_sub(w0) / 1_000_000;
    }
    let mut v: Vec<_> = g.into_iter().map(|(k, (n, c, w))| (k, n, c, w)).collect();
    v.sort_by(|x, y| (y.2 + y.3).cmp(&(x.2 + x.3)).then(x.0.cmp(&y.0)));
    v
}

pub(crate) fn start(note: Arc<dyn Fn(String) + Send + Sync>) {
    let beat = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let b = beat.clone();
    tokio::spawn(async move {
        loop {
            b.store(t0.elapsed().as_millis() as u64, Relaxed);
            tokio::time::sleep(BEAT).await;
        }
    });
    let _ = std::thread::Builder::new().name("rt-watch".into()).spawn(move || {
        // снимки последних ~3 с: база — снимок, ближайший к началу замирания (обнаруживается на STALL позже)
        let mut ring: std::collections::VecDeque<(Instant, HashMap<u32, (String, u64, u64)>)> = Default::default();
        let mut stall: Option<(Instant, HashMap<u32, (String, u64, u64)>)> = None;
        loop {
            std::thread::sleep(SAMPLE);
            let age = Duration::from_millis((t0.elapsed().as_millis() as u64).saturating_sub(beat.load(Relaxed)));
            let now = snapshot();
            match (&stall, age >= STALL) {
                (None, true) => {
                    let start = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
                    let base = ring.iter().rev().find(|(t, _)| *t <= start).or(ring.front()).map(|(_, s)| s.clone()).unwrap_or_default();
                    stall = Some((start, base));
                }
                (Some((since, base)), false) => {
                    let dur = since.elapsed();
                    let groups = summarize(base, &now);
                    let top: Vec<String> = groups.iter().filter(|g| g.2 + g.3 >= 50).take(6)
                        .map(|(k, n, c, w)| format!("{k}×{n}: cpu {c} мс, очередь {w} мс")).collect();
                    note(format!("рантайм стоял {} мс: {}; {}", dur.as_millis(), top.join("; "), crate::host_pressure()));
                    stall = None;
                }
                _ => {}
            }
            ring.push_back((Instant::now(), now));
            while ring.len() > 12 { ring.pop_front(); }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_groups_threads_and_separates_cpu_from_runqueue_wait() {
        let a: HashMap<u32, (String, u64, u64)> = [(1, ("tokio-rt-worker".into(), 0, 0)), (2, ("tokio-rt-worker".into(), 0, 0)), (3, ("reticulum-node".into(), 0, 0))].into();
        let b: HashMap<u32, (String, u64, u64)> = [(1, ("tokio-rt-worker".into(), 100_000_000, 3_000_000_000)), (2, ("tokio-rt-worker".into(), 0, 0)),
            (3, ("reticulum-node".into(), 4_000_000_000, 0)), (4, ("new".into(), 5_000_000, 0))].into();
        let s = summarize(&a, &b);
        assert_eq!(s[0], ("reticulum-node".into(), 1, 4000, 0), "занят на CPU");
        assert_eq!(s[1], ("tokio-rt-worker".into(), 2, 100, 3000), "ждали в очереди — голодание");
        assert_eq!(s[2], ("new".into(), 1, 0, 0), "новый поток без базы не даёт ложного прироста");
    }

    #[test]
    fn snapshot_reads_own_threads() {
        let s = snapshot();
        assert!(!s.is_empty(), "/proc/self/task доступен");
    }
}
