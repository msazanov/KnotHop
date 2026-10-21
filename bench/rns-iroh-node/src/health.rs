//! Память о носителях, которые с данным пиром заведомо не работают (DPI, чёрная дыра на пути).
//!
//! Записывается только то, что подтверждено своей проверкой: TCP соединился, но данные не доставлены (`tcpc::connect`), либо QUIC не
//! соединяется при живом хосте. Адреса, имена и подсказки каталога не участвуют: ключ - EndpointId пира. Запись живёт ограниченное время
//! (5 мин, затем втрое дольше за каждую следующую неудачу, до 6 ч) и стирается первой успешной проверкой, поэтому снятая блокировка
//! обнаруживается сама. Пока заблокированы оба носителя, прямой интерфейс к пиру не поднимается и RNS строит путь через другие узлы.
//! Хранилище ограничено по числу записей: ключи берутся из анонсов, а записи появляются только после собственных неудач.

use super::*;

const MAX_ENTRIES: usize = 256;
const MAX_FILE: u64 = 256 * 1024;
const FIRST: u64 = 5 * 60_000;
const CAP: u64 = 6 * 3_600_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Tcp,
    Quic,
}

#[derive(Clone, Copy, Default, serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct Bad {
    /// подряд неудачных проверок
    fails: u32,
    /// до какого момента (unix, мс) носитель считается неработающим
    until_ms: u64,
}

#[derive(Clone, Copy, Default, serde::Serialize, serde::Deserialize, Debug)]
struct Entry {
    tcp: Bad,
    quic: Bad,
}

impl Entry {
    fn slot(&mut self, k: Kind) -> &mut Bad {
        match k {
            Kind::Tcp => &mut self.tcp,
            Kind::Quic => &mut self.quic,
        }
    }
    fn get(&self, k: Kind) -> Bad {
        match k {
            Kind::Tcp => self.tcp,
            Kind::Quic => self.quic,
        }
    }
}

/// Срок памяти после `fails`-й подряд неудачи, мс.
fn backoff_ms(fails: u32) -> u64 {
    let mut d = FIRST;
    for _ in 1..fails.max(1) {
        d = d.saturating_mul(3);
        if d >= CAP {
            return CAP;
        }
    }
    d.min(CAP)
}

#[derive(Default)]
pub struct Health {
    path: Mutex<Option<PathBuf>>,
    m: Mutex<std::collections::HashMap<String, Entry>>,
}

impl Health {
    /// Подключить файл и загрузить его. Без вызова хранилище только в памяти (клиент: сеть телефона меняется, помнить дольше процесса нельзя).
    pub fn init(&self, path: PathBuf) {
        if let Ok(md) = std::fs::metadata(&path) {
            if md.len() <= MAX_FILE {
                if let Ok(s) = std::fs::read_to_string(&path) {
                    if let Ok(mut v) = serde_json::from_str::<std::collections::HashMap<String, Entry>>(&s) {
                        while v.len() > MAX_ENTRIES {
                            let Some(k) = v.iter().min_by_key(|(_, e)| e.tcp.until_ms.max(e.quic.until_ms)).map(|(k, _)| k.clone()) else { break };
                            v.remove(&k);
                        }
                        *self.m.lock().unwrap() = v;
                    }
                }
            }
        }
        *self.path.lock().unwrap() = Some(path);
    }

    fn save(&self, m: &std::collections::HashMap<String, Entry>) {
        let Some(p) = self.path.lock().unwrap().clone() else { return };
        let Ok(data) = serde_json::to_vec(m) else { return };
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, data).is_ok() {
            let _ = std::fs::rename(&tmp, &p);
        }
    }

    /// Сколько ещё носитель считается неработающим.
    pub fn remaining(&self, peer: &str, k: Kind) -> Option<Duration> {
        let b = self.m.lock().unwrap().get(peer)?.get(k);
        let now = now_ms() as u64;
        (b.until_ms > now).then(|| Duration::from_millis(b.until_ms - now))
    }

    pub fn is_bad(&self, peer: &str, k: Kind) -> bool {
        self.remaining(peer, k).is_some()
    }

    /// Проверка не прошла: запомнить. Возвращает срок памяти.
    pub fn fail(&self, peer: &str, k: Kind) -> Duration {
        let mut m = self.m.lock().unwrap();
        if !m.contains_key(peer) && m.len() >= MAX_ENTRIES {
            if let Some(old) = m.iter().min_by_key(|(_, e)| e.tcp.until_ms.max(e.quic.until_ms)).map(|(k, _)| k.clone()) {
                m.remove(&old);
            }
        }
        let b = m.entry(peer.to_string()).or_default().slot(k);
        b.fails = b.fails.saturating_add(1);
        let d = backoff_ms(b.fails);
        b.until_ms = now_ms() as u64 + d;
        self.save(&m);
        Duration::from_millis(d)
    }

    /// Проверка прошла: забыть.
    pub fn ok(&self, peer: &str, k: Kind) {
        let mut m = self.m.lock().unwrap();
        let Some(e) = m.get_mut(peer) else { return };
        if *e.slot(k) == Bad::default() {
            return;
        }
        *e.slot(k) = Bad::default();
        if e.tcp == Bad::default() && e.quic == Bad::default() {
            m.remove(peer);
        }
        self.save(&m);
    }

    /// Пока оба носителя помечены, меньший остаток: через сколько стоит проверить пару снова.
    pub fn blocked_for(&self, peer: &str) -> Option<Duration> {
        let (t, q) = (self.remaining(peer, Kind::Tcp)?, self.remaining(peer, Kind::Quic)?);
        Some(t.min(q))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_ms(1), 5 * 60_000);
        assert_eq!(backoff_ms(2), 15 * 60_000);
        assert_eq!(backoff_ms(3), 45 * 60_000);
        assert_eq!(backoff_ms(4), 135 * 60_000);
        assert_eq!(backoff_ms(5), CAP);
        assert_eq!(backoff_ms(500), CAP);
    }

    #[test]
    fn fail_ok_and_pair_block() {
        let h = Health::default();
        assert!(!h.is_bad("p", Kind::Tcp));
        h.fail("p", Kind::Tcp);
        assert!(h.is_bad("p", Kind::Tcp) && !h.is_bad("p", Kind::Quic));
        assert!(h.blocked_for("p").is_none());
        h.fail("p", Kind::Quic);
        assert!(h.blocked_for("p").is_some());
        h.ok("p", Kind::Tcp);
        assert!(h.blocked_for("p").is_none() && h.is_bad("p", Kind::Quic));
        h.ok("p", Kind::Quic);
        assert!(h.m.lock().unwrap().is_empty());
    }

    #[test]
    fn repeated_failures_escalate() {
        let h = Health::default();
        let a = h.fail("p", Kind::Tcp);
        let b = h.fail("p", Kind::Tcp);
        assert!(b > a);
    }

    #[test]
    fn entries_are_bounded_and_persist() {
        let dir = std::env::temp_dir().join(format!("rawg-health-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("carrier_health.json");
        let _ = std::fs::remove_file(&p);
        let h = Health::default();
        h.init(p.clone());
        for i in 0..MAX_ENTRIES + 50 {
            h.fail(&format!("peer{i}"), Kind::Tcp);
        }
        assert!(h.m.lock().unwrap().len() <= MAX_ENTRIES);
        h.fail("x", Kind::Quic);
        let h2 = Health::default();
        h2.init(p.clone());
        assert!(h2.is_bad("x", Kind::Quic));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_or_oversized_file_is_ignored() {
        let dir = std::env::temp_dir().join(format!("rawg-health-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("carrier_health.json");
        std::fs::write(&p, b"{not json").unwrap();
        let h = Health::default();
        h.init(p);
        assert!(!h.is_bad("p", Kind::Tcp));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
