//! Режим `meas`: замер канала «телефон ↔ ноутбук» без TUN и без прав VPN.
//!
//! Ходят пакеты по Link-датаграммам (тот же тракт, что у IP-туннеля: `send_datagram`, без Channel и подтверждений),
//! поэтому цифры относятся к тракту KnotHop, а не к TCP. Клиент (телефон) сам проходит лесенку тестов и пишет результат в
//! `result-c.json`, ход — в `progress.txt` (его читает оболочка приложения).
//!
//! Формат пакета (всё little-endian): `KNOTMEAS`(8) тип(1) 0(3) id_теста(4) seq(8) время_отправителя_мкс(8) [тело...].
//! Тесты:
//!   echo  — клиент шлёт ECHO_REQ, выход зеркалит ECHO_REP с тем же временем: RTT по часам клиента;
//!   up    — клиент шлёт UP_DATA с заданной частотой, потом просит UP_REPORT: выход считает принятое;
//!   down  — клиент шлёт DOWN_START {pps, size, secs}; выход льёт DOWN_DATA, в конце DOWN_END{seq = отправлено}.
//! Во время up/down параллельно идёт echo 10 Гц: задержка под нагрузкой.

use super::*;

const MAGIC: &[u8; 8] = b"KNOTMEAS";
const HDR: usize = 32;

const ECHO_REQ: u8 = 1;
const ECHO_REP: u8 = 2;
const UP_DATA: u8 = 3;
const UP_REPORT_REQ: u8 = 4;
const UP_REPORT: u8 = 5;
const DOWN_START: u8 = 6;
const DOWN_DATA: u8 = 7;
const DOWN_END: u8 = 8;

pub fn is_meas(d: &[u8]) -> bool {
    d.len() >= HDR && &d[..8] == MAGIC
}

fn build(ty: u8, test: u32, seq: u64, size: usize) -> Vec<u8> {
    let mut b = vec![0u8; size.max(HDR)];
    b[..8].copy_from_slice(MAGIC);
    b[8] = ty;
    b[12..16].copy_from_slice(&test.to_le_bytes());
    b[16..24].copy_from_slice(&seq.to_le_bytes());
    b[24..32].copy_from_slice(&now_us().to_le_bytes());
    b
}

fn ty(d: &[u8]) -> u8 {
    d[8]
}
fn test_id(d: &[u8]) -> u32 {
    u32::from_le_bytes(d[12..16].try_into().unwrap())
}
fn seq_of(d: &[u8]) -> u64 {
    u64::from_le_bytes(d[16..24].try_into().unwrap())
}
fn ts_of(d: &[u8]) -> u64 {
    u64::from_le_bytes(d[24..32].try_into().unwrap())
}

// ------------------------------------------------------------------------------------------------ выход (ноутбук)

#[derive(Default, Clone)]
struct UpStat {
    pkts: u64,
    bytes: u64,
    max_seq: u64,
    first_us: u64,
    last_us: u64,
    reorder: u64,
}

#[derive(Default)]
pub struct ExitState {
    up: Mutex<HashMap<u32, UpStat>>,
    down_started: Mutex<HashSet<u32>>,
}

/// Пакет замера, пришедший по Link. Выход отвечает; клиент отдаёт пакет своему приёмнику.
pub fn on_packet(node: &Arc<Node>, sh: &Arc<Shared>, link_id: leviculum_std::api::LinkId, d: &[u8]) {
    if let Some(tx) = sh.meas_tx.lock().unwrap().as_ref() {
        let _ = tx.send(d.to_vec());
        return;
    }
    let t = test_id(d);
    match ty(d) {
        UP_DATA => {
            let now = now_us();
            let mut m = sh.meas_exit.up.lock().unwrap();
            let s = m.entry(t).or_default();
            if s.pkts == 0 {
                s.first_us = now;
            }
            s.last_us = now;
            s.pkts += 1;
            s.bytes += d.len() as u64;
            let q = seq_of(d);
            if q < s.max_seq {
                s.reorder += 1;
            }
            s.max_seq = s.max_seq.max(q);
        }
        ECHO_REQ => {
            let mut r = d.to_vec();
            r[8] = ECHO_REP;
            let h = node.engine().link_handle(&link_id);
            tokio::spawn(async move {
                let _ = h.send_datagram(&r).await;
            });
        }
        UP_REPORT_REQ => {
            let s = sh.meas_exit.up.lock().unwrap().get(&t).cloned().unwrap_or_default();
            let body = serde_json::json!({"pkts": s.pkts, "bytes": s.bytes, "max_seq": s.max_seq, "first_us": s.first_us,
                "last_us": s.last_us, "reorder": s.reorder}).to_string();
            let mut r = build(UP_REPORT, t, 0, HDR);
            r.extend_from_slice(body.as_bytes());
            let h = node.engine().link_handle(&link_id);
            tokio::spawn(async move {
                let _ = h.send_datagram(&r).await;
            });
        }
        DOWN_START if d.len() >= HDR + 8 => {
            if !sh.meas_exit.down_started.lock().unwrap().insert(t) {
                return; // повтор запроса: поток уже идёт
            }
            let pps = u32::from_le_bytes(d[HDR..HDR + 4].try_into().unwrap()) as u64;
            let size = u16::from_le_bytes(d[HDR + 4..HDR + 6].try_into().unwrap()) as usize;
            let secs = u16::from_le_bytes(d[HDR + 6..HDR + 8].try_into().unwrap()) as u64;
            let h = node.engine().link_handle(&link_id);
            tokio::spawn(async move {
                let sent = flood(&h, DOWN_DATA, t, pps, size, Duration::from_secs(secs)).await.0;
                for _ in 0..4 {
                    let _ = h.send_datagram(&build(DOWN_END, t, sent, HDR)).await;
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            });
        }
        _ => {}
    }
}

/// Открытый цикл с частотой `pps`: пачки по слотам в 1 мс, догоняем отставание. Возвращает (отправлено, ошибок).
async fn flood(h: &leviculum_std::LinkHandle, kind: u8, test: u32, pps: u64, size: usize, dur: Duration) -> (u64, u64) {
    let mut buf = build(kind, test, 0, size);
    let (mut sent, mut errors) = (0u64, 0u64);
    let per_slot = (pps as f64 / 1000.0).max(0.001);
    let mut owed = 0.0f64;
    let t0 = Instant::now();
    let mut next = Instant::now();
    while t0.elapsed() < dur {
        owed += per_slot;
        let n = owed.floor() as u64;
        owed -= n as f64;
        for _ in 0..n.min(4096) {
            buf[16..24].copy_from_slice(&sent.to_le_bytes());
            buf[24..32].copy_from_slice(&now_us().to_le_bytes());
            match h.send_datagram(&buf).await {
                Ok(()) => sent += 1,
                Err(_) => {
                    errors += 1;
                    if errors > 20000 {
                        return (sent, errors);
                    }
                }
            }
        }
        next += Duration::from_millis(1);
        let now = Instant::now();
        if next > now {
            tokio::time::sleep(next - now).await;
        } else if now - next > Duration::from_millis(50) {
            next = now; // не копить бесконечный долг, если процессор не успевает
        }
    }
    (sent, errors)
}

// ------------------------------------------------------------------------------------------------ клиент (телефон)

#[derive(Default)]
struct DownStat {
    pkts: u64,
    bytes: u64,
    max_seq: u64,
    first_us: u64,
    last_us: u64,
    reorder: u64,
    per_sec: Vec<u64>,
}

#[derive(Default)]
struct ClientRx {
    rtt_us: Mutex<HashMap<u32, Vec<u64>>>,
    down: Mutex<HashMap<u32, DownStat>>,
    down_sent: Mutex<HashMap<u32, u64>>,
    reports: Mutex<HashMap<u32, serde_json::Value>>,
}

fn proc_cpu_s() -> f64 {
    let Ok(s) = std::fs::read_to_string("/proc/self/stat") else { return 0.0 };
    // поле comm может содержать пробелы: считать после последней ')'
    let Some(rest) = s.rfind(')').map(|i| &s[i + 2..]) else { return 0.0 };
    let f: Vec<&str> = rest.split_whitespace().collect();
    let (ut, st) = (f.get(11).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0), f.get(12).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0));
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    (ut + st) / hz
}

fn fm(v: &serde_json::Value) -> String {
    v.as_f64().map(|x| format!("{x:.2}")).unwrap_or_else(|| "-".into())
}

fn pct(sorted: &[u64], p: usize) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    Some(sorted[((sorted.len() * p + 99) / 100).saturating_sub(1).min(sorted.len() - 1)] as f64 / 1000.0)
}

fn rtt_json(rx: &ClientRx, test: u32, sent: u64) -> serde_json::Value {
    let mut v = rx.rtt_us.lock().unwrap().get(&test).cloned().unwrap_or_default();
    v.sort_unstable();
    serde_json::json!({"sent": sent, "received": v.len(), "loss_pct": if sent > 0 { 100.0 * (sent as f64 - v.len() as f64).max(0.0) / sent as f64 } else { 0.0 },
        "p50_ms": pct(&v, 50), "p95_ms": pct(&v, 95), "max_ms": v.last().map(|x| *x as f64 / 1000.0), "min_ms": v.first().map(|x| *x as f64 / 1000.0)})
}

async fn dispatcher(mut rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>, st: Arc<ClientRx>) {
    let t_start = Instant::now();
    while let Some(d) = rx.recv().await {
        let t = test_id(&d);
        match ty(&d) {
            ECHO_REP => {
                let rtt = now_us().saturating_sub(ts_of(&d));
                st.rtt_us.lock().unwrap().entry(t).or_default().push(rtt);
            }
            DOWN_DATA => {
                let now = now_us();
                let mut m = st.down.lock().unwrap();
                let s = m.entry(t).or_default();
                if s.pkts == 0 {
                    s.first_us = now;
                }
                s.last_us = now;
                s.pkts += 1;
                s.bytes += d.len() as u64;
                let q = seq_of(&d);
                if q < s.max_seq {
                    s.reorder += 1;
                }
                s.max_seq = s.max_seq.max(q);
                let sec = ((now - s.first_us) / 1_000_000) as usize;
                if s.per_sec.len() <= sec {
                    s.per_sec.resize(sec + 1, 0);
                }
                s.per_sec[sec] += d.len() as u64;
            }
            DOWN_END => {
                st.down_sent.lock().unwrap().insert(t, seq_of(&d));
            }
            UP_REPORT => {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&d[HDR..]) {
                    st.reports.lock().unwrap().insert(t, v);
                }
            }
            _ => {}
        }
    }
    let _ = t_start;
}

struct Ctx {
    h: Arc<leviculum_std::LinkHandle>,
    st: Arc<ClientRx>,
    state: PathBuf,
    sh: Arc<Shared>,
    next_id: u32,
}

impl Ctx {
    fn prog(&self, msg: &str) {
        self.sh.note(msg.to_string());
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.state.join("progress.txt")) {
            let _ = writeln!(f, "{msg}");
        }
    }
    fn id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    /// Эхо 10 Гц, пока не поднят флаг остановки. Возвращает счётчик отправленного.
    fn echo_bg(&self, test: u32, stop: Arc<std::sync::atomic::AtomicBool>) -> tokio::task::JoinHandle<u64> {
        let h = self.h.clone();
        tokio::spawn(async move {
            let mut n = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if h.send_datagram(&build(ECHO_REQ, test, n, 64)).await.is_ok() {
                    n += 1;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            n
        })
    }

    async fn echo_phase(&mut self, size: usize, n: u64, interval_ms: u64) -> serde_json::Value {
        let t = self.id();
        let mut sent = 0;
        for i in 0..n {
            if self.h.send_datagram(&build(ECHO_REQ, t, i, size)).await.is_ok() {
                sent += 1;
            }
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let mut j = rtt_json(&self.st, t, sent);
        j["size"] = size.into();
        j
    }

    async fn up_step(&mut self, pps: u64, size: usize, secs: u64) -> serde_json::Value {
        let (t, te) = (self.id(), self.id());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let echo = self.echo_bg(te, stop.clone());
        let (cpu0, w0) = (proc_cpu_s(), Instant::now());
        let (sent, errors) = flood(&self.h, UP_DATA, t, pps, size, Duration::from_secs(secs)).await;
        let (cpu, wall) = (proc_cpu_s() - cpu0, w0.elapsed().as_secs_f64());
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let echo_sent = echo.await.unwrap_or(0);
        let mut report = None;
        for _ in 0..12 {
            let _ = self.h.send_datagram(&build(UP_REPORT_REQ, t, 0, HDR)).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            if let Some(r) = self.st.reports.lock().unwrap().get(&t).cloned() {
                report = Some(r);
                break;
            }
        }
        let mut out = serde_json::json!({"dir": "up", "pps_target": pps, "size": size, "secs": wall, "sent": sent, "send_errors": errors,
            "sent_mbit_s": sent as f64 * size as f64 * 8.0 / wall / 1e6, "cpu_s": cpu, "cpu_pct_of_wall": 100.0 * cpu / wall,
            "cpu_us_per_pkt": if sent > 0 { cpu * 1e6 / sent as f64 } else { 0.0 }, "rtt_loaded": rtt_json(&self.st, te, echo_sent)});
        if let Some(r) = report {
            let (rp, rb) = (r["pkts"].as_u64().unwrap_or(0), r["bytes"].as_u64().unwrap_or(0));
            let dur = (r["last_us"].as_u64().unwrap_or(0).saturating_sub(r["first_us"].as_u64().unwrap_or(0))) as f64 / 1e6;
            out["rx_pkts"] = rp.into();
            out["loss_pct"] = (if sent > 0 { 100.0 * (sent as f64 - rp as f64).max(0.0) / sent as f64 } else { 0.0 }).into();
            out["goodput_mbit_s"] = (if dur > 0.0 { rb as f64 * 8.0 / dur / 1e6 } else { 0.0 }).into();
            out["reorder"] = r["reorder"].clone();
        } else {
            out["report"] = "no report from the exit".into();
        }
        out
    }

    async fn down_step(&mut self, pps: u64, size: usize, secs: u64) -> serde_json::Value {
        let (t, te) = (self.id(), self.id());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let echo = self.echo_bg(te, stop.clone());
        let mut body = build(DOWN_START, t, 0, HDR + 8);
        body[HDR..HDR + 4].copy_from_slice(&(pps as u32).to_le_bytes());
        body[HDR + 4..HDR + 6].copy_from_slice(&(size as u16).to_le_bytes());
        body[HDR + 6..HDR + 8].copy_from_slice(&(secs as u16).to_le_bytes());
        let (cpu0, w0) = (proc_cpu_s(), Instant::now());
        for _ in 0..4 {
            let _ = self.h.send_datagram(&body).await;
            tokio::time::sleep(Duration::from_millis(120)).await;
            if self.st.down.lock().unwrap().contains_key(&t) {
                break;
            }
        }
        let deadline = Instant::now() + Duration::from_secs(secs + 5);
        while Instant::now() < deadline && !self.st.down_sent.lock().unwrap().contains_key(&t) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (cpu, wall) = (proc_cpu_s() - cpu0, w0.elapsed().as_secs_f64());
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let echo_sent = echo.await.unwrap_or(0);
        let d = self.st.down.lock().unwrap().remove(&t).unwrap_or_default();
        let sent = self.st.down_sent.lock().unwrap().get(&t).copied();
        let dur = d.last_us.saturating_sub(d.first_us) as f64 / 1e6;
        serde_json::json!({"dir": "down", "pps_target": pps, "size": size, "rx_pkts": d.pkts, "rx_bytes": d.bytes, "sent_by_exit": sent,
            "loss_pct": sent.map(|s| if s > 0 { 100.0 * (s as f64 - d.pkts as f64).max(0.0) / s as f64 } else { 0.0 }),
            "goodput_mbit_s": if dur > 0.0 { d.bytes as f64 * 8.0 / dur / 1e6 } else { 0.0 }, "reorder": d.reorder,
            "per_sec_mbit": d.per_sec.iter().map(|b| (*b as f64 * 8.0 / 1e6 * 10.0).round() / 10.0).collect::<Vec<_>>(),
            "secs": wall, "cpu_s": cpu, "cpu_pct_of_wall": 100.0 * cpu / wall,
            "cpu_us_per_pkt": if d.pkts > 0 { cpu * 1e6 / d.pkts as f64 } else { 0.0 }, "rtt_loaded": rtt_json(&self.st, te, echo_sent)})
    }
}

/// Лесенка частот: с каждым шагом нагрузка выше, пока канал или процессор не упрутся (потери > 30% или клиент не успевает слать).
const LADDER: &[u64] = &[1000, 2000, 4000, 8000, 12000, 16000, 24000, 32000];

pub async fn client_meas(cli: &Cli, node: Arc<Node>, sh: Arc<Shared>, dest: &DestinationHash, key: &[u8; 32]) -> Result<()> {
    let _ = std::fs::remove_file(cli.state.join("progress.txt"));
    let _ = std::fs::remove_file(cli.state.join("result-c.json"));
    let note = |m: &str| {
        sh.note(m.to_string());
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(cli.state.join("progress.txt")) {
            let _ = writeln!(f, "{m}");
        }
    };
    note("ищу путь до ноутбука");
    if !node.wait_for_path(dest, Duration::from_secs(40), Duration::from_secs(1)).await? {
        bail!("нет пути до выхода за 40 с");
    }
    let t0 = Instant::now();
    let handle = node.connect_with_key(dest, key).await?;
    let k = hex(handle.link_id().as_bytes());
    while !sh.established.lock().unwrap().contains(&k) {
        if t0.elapsed() > Duration::from_secs(20) {
            bail!("Link не установился за 20 с");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mdu = node.engine().link_mdu(handle.link_id());
    note(&format!("Link установлен за {} мс, MDU {mdu:?}", t0.elapsed().as_millis()));

    let st = Arc::new(ClientRx::default());
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    *sh.meas_tx.lock().unwrap() = Some(tx);
    tokio::spawn(dispatcher(rx, st.clone()));
    let size = 1200usize.min(mdu.unwrap_or(1200));
    let mut c = Ctx { h: Arc::new(handle), st, state: cli.state.clone(), sh: sh.clone(), next_id: ((now_us() / 1000) as u32) & 0x7fff_ff00 };
    let total_cpu0 = proc_cpu_s();
    let t_all = Instant::now();

    // Простой: связь установлена, ничего не шлём. Фоновая цена соединения (keepalive, таймеры, опрос), отдельно от потока.
    c.prog("простой 6 с (замер фонового CPU)");
    let (ci, wi) = (proc_cpu_s(), Instant::now());
    tokio::time::sleep(Duration::from_secs(6)).await;
    let idle_cpu_pct = 100.0 * (proc_cpu_s() - ci) / wi.elapsed().as_secs_f64();
    c.prog(&format!("  фоновый CPU {idle_cpu_pct:.1}% одного ядра"));

    c.prog("эхо 64 Б, 5 с");
    let echo64 = c.echo_phase(64, 100, 50).await;
    c.prog(&format!("  RTT p50 {} мс, p95 {} мс, потери {}%", fm(&echo64["p50_ms"]), fm(&echo64["p95_ms"]), fm(&echo64["loss_pct"])));
    c.prog("эхо 1200 Б, 5 с");
    let echo_big = c.echo_phase(size, 100, 50).await;
    c.prog(&format!("  RTT p50 {} мс, p95 {} мс, потери {}%", fm(&echo_big["p50_ms"]), fm(&echo_big["p95_ms"]), fm(&echo_big["loss_pct"])));

    let secs = 6u64;
    let mut up = Vec::new();
    for &pps in LADDER {
        c.prog(&format!("вверх: {} пак/с x {} Б ({:.0} Мбит/с)", pps, size, pps as f64 * size as f64 * 8.0 / 1e6));
        let r = c.up_step(pps, size, secs).await;
        c.prog(&format!("  принято {:.1} Мбит/с, потери {:.2}%, CPU {:.0}%, {:.1} мкс/пакет, RTT под нагрузкой p50 {} мс",
            r["goodput_mbit_s"].as_f64().unwrap_or(0.0), r["loss_pct"].as_f64().unwrap_or(100.0), r["cpu_pct_of_wall"].as_f64().unwrap_or(0.0),
            r["cpu_us_per_pkt"].as_f64().unwrap_or(0.0), fm(&r["rtt_loaded"]["p50_ms"])));
        let stop = r["loss_pct"].as_f64().unwrap_or(100.0) > 30.0 || r["sent_mbit_s"].as_f64().unwrap_or(0.0) < 0.7 * pps as f64 * size as f64 * 8.0 / 1e6;
        up.push(r);
        if stop {
            c.prog("  предел достигнут, дальше не повышаю");
            break;
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
    }
    let mut down = Vec::new();
    for &pps in LADDER {
        c.prog(&format!("вниз: {} пак/с x {} Б ({:.0} Мбит/с)", pps, size, pps as f64 * size as f64 * 8.0 / 1e6));
        let r = c.down_step(pps, size, secs).await;
        c.prog(&format!("  принято {:.1} Мбит/с, потери {:.2}%, CPU {:.0}%, {:.1} мкс/пакет, RTT под нагрузкой p50 {} мс",
            r["goodput_mbit_s"].as_f64().unwrap_or(0.0), r["loss_pct"].as_f64().unwrap_or(100.0), r["cpu_pct_of_wall"].as_f64().unwrap_or(0.0),
            r["cpu_us_per_pkt"].as_f64().unwrap_or(0.0), fm(&r["rtt_loaded"]["p50_ms"])));
        let stop = r["loss_pct"].as_f64().unwrap_or(100.0) > 30.0;
        down.push(r);
        if stop {
            c.prog("  предел достигнут, дальше не повышаю");
            break;
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
    }

    let best = |v: &[serde_json::Value]| v.iter().filter(|r| r["loss_pct"].as_f64().unwrap_or(100.0) < 1.0).map(|r| r["goodput_mbit_s"].as_f64().unwrap_or(0.0)).fold(0.0f64, f64::max);
    let (best_up, best_down) = (best(&up), best(&down));
    c.prog(&format!("ИТОГ: вверх (потери <1%) {best_up:.1} Мбит/с, вниз {best_down:.1} Мбит/с"));
    let (hwm_kb, rss_kb) = proc_mem_kb();
    let out = serde_json::json!({
        "mode": "meas", "idle_cpu_pct": idle_cpu_pct, "link_mdu": mdu, "packet": size, "cipher": cli.cipher, "echo_64": echo64, "echo_big": echo_big,
        "up": up, "down": down, "best_up_mbit_s": best_up, "best_down_mbit_s": best_down,
        "total_cpu_s": proc_cpu_s() - total_cpu0, "total_wall_s": t_all.elapsed().as_secs_f64(), "vm_hwm_kb": hwm_kb, "vm_rss_kb": rss_kb,
        "quic_stats": sh.quic_stats.lock().unwrap().clone(), "data_events_dropped": leviculum_std::data_events_dropped(),
        "pc_drops": pc_drops_json(),
        "log": sh.log.lock().unwrap().iter().map(|(t, m)| serde_json::json!({"t_ms": *t as u64, "msg": m})).collect::<Vec<_>>(),
    });
    std::fs::write(cli.state.join("result-c.json"), serde_json::to_vec(&out)?)?;
    note("готово");
    Ok(())
}
