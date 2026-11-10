//! Очередь служебных LXMF-сообщений ноды (`node.inv/1`, `node.cmd/1`, ADR 0028) и PN-движок сервера.
//! Транспортный Delivered не означает применение: отправитель повторяет сообщение до прикладного ACK
//! (ответ адресата с тем же `tag`), с ограниченными TTL/очередью; копии через PN расписаны в `lxmf_admin`.
use std::{collections::HashMap, path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock, mpsc}};
use leviculum_std::api::Identity;

pub type Pk = [u8; 64];

pub const TITLE_INV: &[u8] = b"node.inv/1";
pub const TITLE_CMD: &[u8] = b"node.cmd/1";
pub const LIMIT: usize = 64;
/// Срок сообщения по умолчанию, секунды; команды и приглашения задают свой (до 7 сут).
pub const TTL: u64 = 600;
/// Срок хранения письма на PN: команды и приглашения живут до 7 суток.
pub const MESSAGE_EXPIRY_S: u64 = 7 * 24 * 3600;
pub static TX_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static RX_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static TX_MESSAGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static RX_MESSAGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// `Some(true)` — слать, `Some(false)` — снять, `None` — подождать (не блокироваться на замке в потоке ядра).
pub type Gate = Arc<dyn Fn() -> Option<bool> + Send + Sync>;

/// Получатель: полный ключ (шифруем сразу) либо только хеш identity из приглашения (ключ берётся из анонса RNS, хеш сверяется).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target { Pk(Pk), Hash([u8; 16]) }

impl Target {
    pub fn hash(&self) -> Option<[u8; 16]> {
        match self { Target::Pk(pk) => crate::peers::hash_of(pk), Target::Hash(h) => Some(*h) }
    }
    pub fn destination(&self) -> Option<[u8; 16]> { self.hash().map(|h| crate::peers::lxmf_destination(&h)) }
}

#[derive(Clone)]
pub struct Outbound {
    pub title: Vec<u8>,
    pub target: Target,
    pub content: Vec<u8>,
    pub gate: Gate,
    /// конец срока, секунды Unix
    pub exp: u64,
    /// ключ дедупликации и прикладного ACK (`Acknowledged`)
    pub tag: String,
    /// true: сообщение само ответ/квитанция — повторов и копий на PN не нужно
    pub ack: bool,
}

pub enum Command { Send(Outbound), Acknowledged { source: [u8; 16], tag: String } }
pub type Sender = mpsc::SyncSender<Command>;
static RUNTIMES: OnceLock<Mutex<HashMap<PathBuf, Sender>>> = OnceLock::new();

pub struct Guard(PathBuf);
impl Drop for Guard {
    fn drop(&mut self) { if let Some(r) = RUNTIMES.get() { r.lock().unwrap().remove(&self.0); } }
}
fn key(state: &Path) -> PathBuf { state.canonicalize().unwrap_or_else(|_| state.into()) }
pub fn register(state: &Path, sender: Sender) -> Guard {
    let key = key(state);
    RUNTIMES.get_or_init(Default::default).lock().unwrap().insert(key.clone(), sender);
    Guard(key)
}
pub(super) fn submit(state: &Path, command: Command) -> bool {
    RUNTIMES.get().and_then(|r| r.lock().unwrap().get(&key(state)).cloned())
        .is_some_and(|s| s.try_send(command).is_ok())
}

pub fn always() -> Gate { Arc::new(|| Some(true)) }

/// Поставить служебное сообщение в очередь доставки. Получатель принимает его только по своим правилам; доставка ≠ применение.
pub fn send(state: &Path, title: &[u8], target: Target, content: Vec<u8>, tag: &str, exp: u64, gate: Gate) -> bool {
    if content.len() > super::lxmf_admin::MAX_ADMIN_CONTENT { return false; }
    submit(state, Command::Send(Outbound { title: title.to_vec(), target, content, gate, exp, tag: tag.to_string(), ack: false }))
}

/// Ответ/квитанция: одна попытка прямой доставки (повтор запроса вызовет новый ответ).
pub fn reply(state: &Path, title: &[u8], target: Target, content: Vec<u8>, tag: &str) -> bool {
    if content.len() > super::lxmf_admin::MAX_ADMIN_CONTENT { return false; }
    submit(state, Command::Send(Outbound { title: title.to_vec(), target, content, gate: always(), exp: super::now_ms() as u64 / 1000 + TTL, tag: tag.to_string(), ack: true }))
}

/// Пришёл прикладной ответ на сообщение с `tag` от `source` (LXMF-адрес): снять повторы и копии на PN.
pub fn acknowledged(state: &Path, source: [u8; 16], tag: &str) {
    submit(state, Command::Acknowledged { source, tag: tag.to_string() });
}

pub fn public_identity(pk: &Pk) -> Option<Identity> { Identity::from_public_key_bytes(pk).ok() }

/// У builder один слот CoreProcessor: второй вызов заменил бы LXMF delivery.
pub struct Processors<A, B>(pub A, pub B);
impl<A: leviculum_std::api::CoreProcessor, B: leviculum_std::api::CoreProcessor> leviculum_std::api::CoreProcessor for Processors<A,B> {
    fn on_event(&mut self, core:&mut leviculum_std::api::StdNodeCore, event:&leviculum_std::api::NodeEvent) -> leviculum_std::api::TickOutput {
        let mut out = self.0.on_event(core, event);
        out.merge(self.1.on_event(core, event));
        out
    }
    fn on_tick(&mut self, core:&mut leviculum_std::api::StdNodeCore, now:u64) -> leviculum_std::api::TickOutput {
        let mut out = self.0.on_tick(core, now);
        out.merge(self.1.on_tick(core, now));
        out
    }
}

/// Потолок PN-хранилища. Медиана записи ≈272 Б (T_REC/T_POL, закрытия, proof), т. е. ≈7,7 тыс. сообщений;
/// при переполнении движок сам вытесняет (`make_room`), корректность прав от PN не зависит (trust.json, enroll Store).
pub const PN_CAP_BYTES: u64 = 2 * 1024 * 1024;
/// Сколько файлов вообще имеет смысл открывать: потолок / минимально реальная запись (≈256 Б). Остальное удаляется по имени, без чтения.
pub const PN_MAX_FILES: usize = 8192;
/// Верхняя граница автоподбора: 100 МиБ ≈ 6 суток трафика зачислений; больше публичному буферу не нужно.
pub const PN_CAP_AUTO_MAX: u64 = 100 * 1024 * 1024;
/// Файлов при большом потолке: фоновая загрузка читает каждый файл (на вращающемся диске ≈165 файлов/с),
/// а трафик за срок хранения (48 ч) укладывается примерно в 40 тыс. записей.
const PN_MAX_FILES_LARGE: usize = 65_536;
static PN_CAP_OVERRIDE_MB: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `pn_cap_mb` из node.json: 0/нет — автоподбор по свободному месту.
pub fn set_pn_cap_mb(mb: Option<u64>) { PN_CAP_OVERRIDE_MB.store(mb.unwrap_or(0), std::sync::atomic::Ordering::Relaxed); }

/// Потолок хранилища PN и число файлов, которое имеет смысл открывать.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PnLimits { pub cap_bytes: u64, pub max_files: usize }

impl Default for PnLimits { fn default() -> Self { Self { cap_bytes: PN_CAP_BYTES, max_files: PN_MAX_FILES } } }

impl PnLimits {
    pub fn for_cap(cap_bytes: u64) -> Self {
        Self { cap_bytes, max_files: ((cap_bytes / 256) as usize).clamp(PN_MAX_FILES, PN_MAX_FILES_LARGE) }
    }
    /// Явный `pn_cap_mb` (1…4096 МиБ), иначе 1% свободного места каталога состояния в пределах 2…100 МиБ:
    /// узлам с малым диском достаётся малый буфер без отдельной настройки.
    pub fn auto(state: &Path) -> Self {
        let mb = PN_CAP_OVERRIDE_MB.load(std::sync::atomic::Ordering::Relaxed);
        if mb > 0 { return Self::for_cap(mb.clamp(1, 4096) * 1024 * 1024); }
        Self::for_cap(free_bytes(state).map_or(PN_CAP_BYTES, |free| (free / 100).clamp(PN_CAP_BYTES, PN_CAP_AUTO_MAX)))
    }
}

/// Свободно для непривилегированного процесса в файловой системе `path` (или ближайшего существующего родителя).
fn free_bytes(path: &Path) -> Option<u64> {
    let mut probe = Some(path);
    while let Some(p) = probe {
        if let Ok(c) = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) {
            let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0 {
                return Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64));
            }
        }
        probe = p.parent();
    }
    None
}
const PN_LOADING: u8 = 1;
const PN_READY: u8 = 2;
const PN_FAILED: u8 = 3;

/// Состояние PN для status.json. Пишет фоновая загрузка и процессор, читает только статус (не горячий путь).
#[derive(Default)]
pub struct PnStatus {
    state: std::sync::atomic::AtomicU8,
    load_ms: std::sync::atomic::AtomicU64,
    trimmed: std::sync::atomic::AtomicU64,
    files: std::sync::atomic::AtomicU64,
    bytes: std::sync::atomic::AtomicU64,
    cap: std::sync::atomic::AtomicU64,
}
static PN_CURRENT: Mutex<Option<Arc<PnStatus>>> = Mutex::new(None);

/// Поля `pn_*` для блока `pol` в status.json.
pub fn pn_status() -> serde_json::Value {
    use std::sync::atomic::Ordering::Relaxed;
    let current = PN_CURRENT.lock().ok().and_then(|g| g.clone());
    let Some(s) = current else { return serde_json::json!({"pn_state":"off","pn_ready":false,"pn_load_ms":0,"pn_trimmed":0,"pn_files":0,"pn_bytes":0,"pn_cap_bytes":0}) };
    let state = s.state.load(Relaxed);
    serde_json::json!({"pn_state":match state { PN_LOADING=>"loading", PN_READY=>"ready", PN_FAILED=>"failed", _=>"off" },
        "pn_ready":state == PN_READY, "pn_load_ms":s.load_ms.load(Relaxed), "pn_trimmed":s.trimmed.load(Relaxed),
        "pn_files":s.files.load(Relaxed), "pn_bytes":s.bytes.load(Relaxed), "pn_cap_bytes":s.cap.load(Relaxed)})
}

/// (received_at, sequence) из имени файла хранилища `<64hex>_<received_at>[_<stamp>[_<seq>]]`; чужие имена — `None`.
fn name_key(name: &str) -> Option<(u64, u64)> {
    let mut parts = name.split('_');
    let id = parts.next()?;
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) { return None; }
    let raw = parts.next()?;
    let ts = match raw.parse::<u64>() {
        Ok(t) => t,
        Err(_) => { let f = raw.parse::<f64>().ok()?; if !f.is_finite() || f < 0.0 || f >= u64::MAX as f64 { return None; } f.trunc() as u64 }
    };
    let _stamp = parts.next();
    let seq = parts.next().map_or(Some(0), |s| s.parse::<u64>().ok())?;
    parts.next().is_none().then_some((ts, seq))
}

/// Предварительная чистка каталога по ИМЕНАМ, без чтения и stat: просроченные (`expiry`) и самые старые сверх `max_files`.
/// `FilePropagationStore::open` читает каждый файл (на вращающемся диске ≈165 файл/с), поэтому лишнее удаляется до него.
/// Непарсящиеся имена (временные, маркер, чужие) не трогаются. Возвращает число удалённых файлов.
fn trim_by_name(dir: &Path, now: u64, expiry: u64, max_files: usize) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let (mut keep, mut removed) = (Vec::new(), 0);
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else { continue };
        let Some((ts, seq)) = name_key(&name) else { continue };
        if now.saturating_sub(ts) > expiry {
            if std::fs::remove_file(entry.path()).is_ok() { removed += 1; }
        } else { keep.push((ts, seq, entry.path())); }
    }
    if keep.len() > max_files {
        keep.sort_unstable();
        for (_, _, path) in &keep[..keep.len() - max_files] { if std::fs::remove_file(path).is_ok() { removed += 1; } }
    }
    removed
}

/// Вытеснить самые старые записи, пока сумма размеров > `cap`. Сумму считаем сами: `free_space()` при `used > capacity`
/// у файлового хранилища вычитает с переполнением, а `open` потолок не проверяет.
fn fit<S: leviculum_lxmf::propagation_store::PropagationStore>(store: &mut S, cap: u64) -> usize {
    let (mut used, mut all) = (0u64, Vec::new());
    let _ = store.for_each(&mut |m| { used += m.size as u64; all.push((m.received_at, m.sequence, m.transient_id, m.size)); });
    if used <= cap { return 0; }
    all.sort_unstable_by_key(|e| (e.0, e.1));
    let mut purged = 0;
    for (_, _, id, size) in all {
        if used <= cap { break; }
        // purge убирает запись из индекса и при ошибке удаления файла: учёт верен в обоих случаях
        let _ = store.purge(&id);
        used -= size as u64;
        purged += 1;
    }
    purged
}

struct Loaded { engine: lnpnd::engine::Engine<leviculum_std::FilePropagationStore>, events: mpsc::Receiver<lnpnd::engine::EngineEvent> }
enum PnPhase { Loading(mpsc::Receiver<Loaded>), Ready(Box<Loaded>), Failed }

/// PN-движок, собираемый в фоне: `FilePropagationStore::open` читает каждый файл, на вращающемся диске это минуты
/// и раньше блокировало старт узла (W110). Пока движок не готов, события и тики PN-части пропускаются; на горячем пути
/// только `try_recv` без блокировок.
pub struct PnProcessor { phase: PnPhase, status: Arc<PnStatus> }
impl PnProcessor {
    /// Забрать готовый движок, если фон закончил. `true` — PN обслуживает события.
    pub fn poll_ready(&mut self) -> bool {
        if let PnPhase::Loading(rx) = &self.phase {
            let got = rx.try_recv();
            match got {
                Ok(loaded) => { self.phase = PnPhase::Ready(Box::new(loaded)); self.status.state.store(PN_READY, std::sync::atomic::Ordering::Relaxed); }
                Err(mpsc::TryRecvError::Empty) => return false,
                Err(mpsc::TryRecvError::Disconnected) => { self.phase = PnPhase::Failed; self.status.state.store(PN_FAILED, std::sync::atomic::Ordering::Relaxed); }
            }
        }
        matches!(self.phase, PnPhase::Ready(_))
    }
    #[cfg(test)]
    fn status(&self) -> Arc<PnStatus> { self.status.clone() }
}
impl leviculum_std::api::CoreProcessor for PnProcessor {
    fn on_event(&mut self, core: &mut leviculum_std::api::StdNodeCore, event: &leviculum_std::api::NodeEvent) -> leviculum_std::api::TickOutput {
        if !self.poll_ready() { return leviculum_std::api::TickOutput::empty(); }
        let PnPhase::Ready(l) = &mut self.phase else { return leviculum_std::api::TickOutput::empty() };
        let out = l.engine.on_event(core, event);
        while l.events.try_recv().is_ok() {}
        out
    }
    fn on_tick(&mut self, core: &mut leviculum_std::api::StdNodeCore, now: u64) -> leviculum_std::api::TickOutput {
        if !self.poll_ready() { return leviculum_std::api::TickOutput::empty(); }
        let PnPhase::Ready(l) = &mut self.phase else { return leviculum_std::api::TickOutput::empty() };
        let out = l.engine.on_tick(core, now);
        while l.events.try_recv().is_ok() {}
        out
    }
}

/// Наибольшая стоимость ключа пиринга, которую объявивший её PN может потребовать от нас. Ключ подбирается перебором SHA-256
/// (~2^cost попыток) в отдельном потоке; штатный предел 26 на сервере с 1 CPU отнимал у транзита VPN до половины процессора
/// часами (perf на uae 10.11: 41 % — `sha256_compress` потока добычи). 18 — стоимость Python LXMF по умолчанию, наши PN объявляют 1.
pub const PN_REMOTE_PEERING_COST_MAX: u8 = 18;

/// Таблица пиров PN на диске: добытые ключи пиринга переживают перезапуск (раньше `MemoryPeerStore` — перебор заново
/// после каждого рестарта и каждого релиза автообновления). Файл не читается — таблица пустая, как в памяти.
fn peer_store(dir: &Path) -> Box<dyn leviculum_lxmf::peering::PeerStore + Send> {
    match dir.parent().map(|p| p.join("pn-peers.msgpack")).map(leviculum_std::FilePeerStore::open) {
        Some(Ok(s)) => Box::new(s),
        _ => Box::new(leviculum_lxmf::peering::MemoryPeerStore::default()),
    }
}

/// Фоновая работа PN (загрузка хранилища, проверка штампов входящих сообщений, добыча ключа пиринга) — с наименьшим приоритетом
/// внутри процесса: потоки движка порождаются из этого и в Linux наследуют nice. На fin1 (2 CPU, PSI 60–90 %) проверка штампов
/// после рестарта брала 31 % CPU knothopd, а главный цикл и пересылка туннеля опаздывали на секунды. Приоритет службы не меняется.
fn background_priority() {
    // which=PRIO_PROCESS, who=0 — вызывающий поток (в Linux nice поточный); повышение nice не требует прав
    unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 19); }
}

/// Штатный PN engine, а не ещё один протокол хранилища. Только серверы; постоянный store вне стираемого lev-role,
/// `PN_CAP_BYTES`, bounded transfer/fetch. Возвращается сразу: хранилище открывается и подрезается в потоке `lxmf-pn-load`.
pub fn propagation_processor(state: &Path, identity: Identity) -> anyhow::Result<PnProcessor> { spawn_pn(state, identity, PnLimits::auto(state), None) }

/// `hold` — тестовые ворота: фон не начинает загрузку, пока не придёт сигнал (или не закроется канал).
fn spawn_pn(state: &Path, identity: Identity, limits: PnLimits, hold: Option<mpsc::Receiver<()>>) -> anyhow::Result<PnProcessor> {
    use lnpnd::engine::{Engine, EngineConfig};
    use leviculum_lxmf::{PropagationNodeConfig, peering::PeeringConfig};
    use leviculum_std::FilePropagationStore;
    use std::{os::unix::fs::PermissionsExt, sync::atomic::Ordering::Relaxed};
    let dir = state.join("lxmf/propagation");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let status = Arc::new(PnStatus::default());
    status.state.store(PN_LOADING, Relaxed);
    status.cap.store(limits.cap_bytes, Relaxed);
    if let Ok(mut current) = PN_CURRENT.lock() { *current = Some(status.clone()); }
    let (tx, rx) = mpsc::sync_channel(1);
    let st = status.clone();
    std::thread::Builder::new().name("lxmf-pn-load".into()).spawn(move || {
        background_priority();
        if let Some(hold) = hold { let _ = hold.recv(); }
        let t0 = std::time::Instant::now();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let mut trimmed = trim_by_name(&dir, now, MESSAGE_EXPIRY_S, limits.max_files);
        let mut store = match FilePropagationStore::open(&dir, limits.cap_bytes) {
            Ok(store) => store,
            Err(_) => { st.state.store(PN_FAILED, Relaxed); return; }
        };
        trimmed += fit(&mut store, limits.cap_bytes);
        let (mut files, mut bytes) = (0u64, 0u64);
        let _ = leviculum_lxmf::propagation_store::PropagationStore::for_each(&store, &mut |m| { files += 1; bytes += m.size as u64; });
        let (engine, events) = Engine::new(EngineConfig {
            identity, store,
            node_config: PropagationNodeConfig { transfer_limit_kb:16, sync_limit_kb:64,
                serve_cap_bytes:Some(64*1024), message_expiry_secs:MESSAGE_EXPIRY_S, name:None, ..Default::default() },
            announce_interval_secs:600, announce_delay_secs:if cfg!(test) {2} else {20}, announce_at_start:false,
            peering:PeeringConfig { max_peers:8, max_inbound_syncs:2, remote_peering_cost_max:PN_REMOTE_PEERING_COST_MAX, ..Default::default() },
            peer_store:peer_store(&dir), control_allowed:vec![], auth_allowed:None,
            mailbox:None, store_limit_bytes:limits.cap_bytes, delivery_limit_kb:8,
        });
        st.trimmed.store(trimmed as u64, Relaxed);
        st.files.store(files, Relaxed);
        st.bytes.store(bytes, Relaxed);
        st.load_ms.store(t0.elapsed().as_millis() as u64, Relaxed);
        let _ = tx.send(Loaded { engine, events });
    })?;
    Ok(PnProcessor { phase: PnPhase::Loading(rx), status })
}

#[cfg(test)]
mod tests {
    use super::*;
    use leviculum_std::api::generate_identity;
    use sha2::{Digest, Sha256};
    use leviculum_lxmf::DeliveryMethod;
    use std::time::{Duration, Instant};

    fn now_secs() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() }

    /// `n` файлов хранилища по 272 Б: `ago` секунд назад, ещё по секунде на запись (разный порядок), валидные имена и тело.
    fn prefill(dir: &Path, n: usize, now: u64, ago: u64) {
        std::fs::create_dir_all(dir).unwrap();
        for i in 0..n {
            let id = Sha256::digest((i as u64).to_le_bytes());
            let mut body = vec![(i % 251) as u8; 272];
            body[..16].copy_from_slice(&[7u8; 16]);
            let name = format!("{}_{}_0_{}", super::super::hex(&id), now - ago - (n - i) as u64, i + 1);
            std::fs::write(dir.join(name), body).unwrap();
        }
    }

    fn dir_totals(dir: &Path) -> (usize, u64) {
        std::fs::read_dir(dir).unwrap().flatten().filter(|e| name_key(&e.file_name().to_string_lossy()).is_some())
            .fold((0, 0), |(n, b), e| (n + 1, b + e.metadata().unwrap().len()))
    }

    #[test]
    fn pn_limits_follow_free_space_and_override() {
        // свободное место определяется; нет каталога — берётся ближайший существующий родитель
        assert!(free_bytes(&std::env::temp_dir().join("kh-no-such/dir")).is_some());
        let big = PnLimits::for_cap(PN_CAP_AUTO_MAX);
        assert_eq!((big.cap_bytes, big.max_files), (PN_CAP_AUTO_MAX, PN_MAX_FILES_LARGE));
        assert_eq!(PnLimits::for_cap(PN_CAP_BYTES), PnLimits::default());
        let auto = PnLimits::auto(&std::env::temp_dir());
        assert!(auto.cap_bytes >= PN_CAP_BYTES && auto.cap_bytes <= PN_CAP_AUTO_MAX);
    }

    #[test]
    fn pn_background_priority_is_inherited_by_engine_threads() {
        let nice = || unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        let (own, child) = std::thread::spawn(move || {
            background_priority();
            let own = nice();
            (own, std::thread::spawn(move || nice()).join().unwrap())
        }).join().unwrap();
        assert_eq!(own, 19, "поток PN — наименьший приоритет");
        assert_eq!(child, 19, "потоки движка (проверка штампов, добыча ключа) наследуют nice");
        assert!(nice() < 19, "остальные потоки процесса не затронуты");
    }

    #[test]
    fn pn_peering_keys_survive_restart_and_cost_is_capped() {
        use leviculum_lxmf::peering::{PeerRecord, PeerTraffic};
        assert!(PN_REMOTE_PEERING_COST_MAX <= 18, "дорогой ключ пиринга отнимает CPU у транзита на 1-CPU узлах");
        let tmp = std::env::temp_dir().join(format!("kh-pn-peers-{}-{}", std::process::id(), now_secs()));
        let dir = tmp.join("lxmf/propagation");
        std::fs::create_dir_all(&dir).unwrap();
        let rec = PeerRecord {
            destination_hash: [5; 16], identity_hash: Some([6; 16]), public_keys: Some([7; 64]),
            peering_key: Some(([9; 32], 18)), transfer_limit_kb: 4, sync_limit_kb: 32, stamp_cost: 16,
            stamp_cost_flexibility: 3, peering_cost: 18, peering_timebase: 1, last_heard: 2, cursor: 0,
            is_static: false, traffic: PeerTraffic::default(),
        };
        {
            let mut s = peer_store(&dir);
            s.save(&rec).unwrap();
        } // Drop дописывает файл
        let got = peer_store(&dir).load_all().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].peering_key, Some(([9; 32], 18)), "добытый ключ пиринга не должен теряться при рестарте");
        assert!(tmp.join("lxmf/pn-peers.msgpack").is_file());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn name_key_parses_store_names_only() {
        let id = "ab".repeat(32);
        assert_eq!(name_key(&format!("{id}_100_0_5")), Some((100, 5)));
        assert_eq!(name_key(&format!("{id}_100.75_3_9")), Some((100, 9)));
        assert_eq!(name_key(&format!("{id}_100")), Some((100, 0)));
        for bad in [".tmp-x".to_string(), ".stamp-values-true".into(), "garbage".into(), format!("{id}_x_0_1"), format!("{id}_1_0_1_2"), format!("{}_1_0_1", "ab".repeat(31))] {
            assert_eq!(name_key(&bad), None, "{bad}");
        }
    }

    #[test]
    fn trim_by_name_drops_expired_then_oldest_and_keeps_foreign_names() {
        let dir = std::env::temp_dir().join(format!("kh-pn-trim-{}", now_secs() ^ std::process::id() as u64));
        let _ = std::fs::remove_dir_all(&dir);
        let now = 10_000_000;
        prefill(&dir, 5, now, 600_000); // просрочены при expiry 500 000 с
        prefill(&dir, 10, now, 0); // свежие: ts = now-10 .. now-1
        for foreign in [".tmp-abc", ".stamp-values-true", "notes.txt"] { std::fs::write(dir.join(foreign), b"x").unwrap(); }
        assert_eq!(trim_by_name(&dir, now, 500_000, 6), 5 + 4, "5 просроченных + 4 самых старых сверх лимита 6");
        let keep: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().filter_map(|e| name_key(&e.file_name().to_string_lossy())).collect();
        assert_eq!(keep.len(), 6);
        assert!(keep.iter().all(|(ts, _)| *ts >= now - 6), "остались самые новые: {keep:?}");
        for foreign in [".tmp-abc", ".stamp-values-true", "notes.txt"] { assert!(dir.join(foreign).exists(), "{foreign}"); }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fit_evicts_oldest_down_to_cap_when_opened_over_capacity() {
        use leviculum_std::FilePropagationStore;
        use leviculum_lxmf::propagation_store::PropagationStore;
        let dir = std::env::temp_dir().join(format!("kh-pn-fit-{}", now_secs() ^ std::process::id() as u64));
        let _ = std::fs::remove_dir_all(&dir);
        prefill(&dir, 100, now_secs(), 0);
        // open ёмкость не проверяет: 100 × 272 Б при потолке 10 КБ даёт used > capacity (free_space() здесь переполнялся бы)
        let mut store = FilePropagationStore::open(&dir, 10_000).unwrap();
        assert_eq!(fit(&mut store, 10_000), 100 - 36);
        assert_eq!(store.free_space(), 10_000 - 36 * 272);
        let (files, bytes) = dir_totals(&dir);
        assert_eq!((files, bytes), (36, 36 * 272));
        let mut oldest = u64::MAX;
        store.for_each(&mut |m| oldest = oldest.min(m.sequence)).unwrap();
        assert_eq!(oldest, 100 - 36 + 1, "вытеснены самые старые");
        assert_eq!(fit(&mut store, 10_000), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Построение процессора не ждёт загрузки хранилища: при удержанном фоне оно уже возвращено, PN ещё не готов
    /// и события пропускает; после снятия ворот фон подрезает 12 тыс. файлов до потолка и отдаёт движок.
    #[test]
    fn pn_processor_returns_before_store_load_and_becomes_ready() {
        let base = std::env::temp_dir().join(format!("kh-pn-bg-{}", now_secs() ^ std::process::id() as u64));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("lxmf/propagation");
        prefill(&dir, 12_000, now_secs(), 0);
        let (gate_tx, gate_rx) = mpsc::channel();
        let t0 = Instant::now();
        let mut pn = spawn_pn(&base, generate_identity(), PnLimits::default(), Some(gate_rx)).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(5), "конструктор ждал загрузки");
        assert!(!pn.poll_ready());
        let status = pn.status();
        assert_eq!(status.state.load(std::sync::atomic::Ordering::Relaxed), PN_LOADING);
        assert_eq!(dir_totals(&dir).0, 12_000, "до сигнала фон ничего не трогает");
        gate_tx.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(60);
        while !pn.poll_ready() { assert!(Instant::now() < until, "PN не стал готов"); std::thread::sleep(Duration::from_millis(10)); }
        assert_eq!(status.state.load(std::sync::atomic::Ordering::Relaxed), PN_READY);
        let (files, bytes) = dir_totals(&dir);
        assert!(files <= PN_MAX_FILES && bytes <= PN_CAP_BYTES, "{files} файлов, {bytes} Б");
        assert_eq!(status.files.load(std::sync::atomic::Ordering::Relaxed) as usize, files);
        assert_eq!(status.bytes.load(std::sync::atomic::Ordering::Relaxed), bytes);
        assert_eq!(status.trimmed.load(std::sync::atomic::Ordering::Relaxed) as usize, 12_000 - files);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn pn_processor_goes_failed_when_loader_dies() {
        let base = std::env::temp_dir().join(format!("kh-pn-fail-{}", now_secs() ^ std::process::id() as u64));
        let _ = std::fs::remove_dir_all(&base);
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let mut pn = spawn_pn(&base, generate_identity(), PnLimits::default(), Some(gate_rx)).unwrap();
        // каталог-файл вместо каталога: open() вернёт ошибку, узел при этом не падает
        std::fs::remove_dir_all(base.join("lxmf/propagation")).unwrap();
        std::fs::write(base.join("lxmf/propagation"), b"x").unwrap();
        gate_tx.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(!pn.poll_ready());
            if matches!(pn.phase, PnPhase::Failed) { break; }
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(pn.status().state.load(std::sync::atomic::Ordering::Relaxed), PN_FAILED);
        let _ = std::fs::remove_dir_all(&base);
    }

    fn peers_with_pn(me: &Identity, pn: &Identity) -> Arc<Mutex<crate::peers::Peers>> {
        let mut t = crate::peers::Peers::new(me.public_key_bytes(), None);
        // сервер объявил себя PN (роль TRANSIT в `accept`): доверенный кандидат PN
        t.contact_set(pn.public_key_bytes(), "pn", vec![], "local", crate::peers::USE, crate::peers::TRANSIT, 1).unwrap();
        Arc::new(Mutex::new(t))
    }

    /// Офлайн-доставка служебной команды: адресат подключается к сети уже после отправки, письмо ждёт на PN доверенного сервера.
    /// Получатель задан хешем identity, повтор до прикладного ACK идёт через PN.
    #[tokio::test(flavor="multi_thread", worker_threads=4)]
    async fn pn_delivers_service_message_to_recipient_that_connects_later() {
        let (sender, recipient, server) = (generate_identity(), generate_identity(), generate_identity());
        let base = std::env::temp_dir().join(format!("kh-pn-offline-{}", crate::hex(sender.hash())));
        let _ = std::fs::remove_dir_all(&base);
        prefill(&base.join("server/lxmf/propagation"), 12_000, now_secs(), 0);
        let (pa, ra) = crate::lxmf_admin::AdminProcessor::new(sender.clone());
        let (pb, rb) = crate::lxmf_admin::AdminProcessor::new(recipient.clone());
        let (ps, _rs) = crate::lxmf_admin::AdminProcessor::new(server.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let pn = propagation_processor(&base.join("server"), server.clone()).unwrap();
        let mut srv = leviculum_std::api::NodeBuilder::new().storage_path(base.join("server")).add_tcp_server(addr).core_processor(Processors(ps, pn)).build().unwrap();
        srv.start().await.unwrap();
        ra.pn.set_source(peers_with_pn(&sender, &server));
        let mut a = leviculum_std::api::NodeBuilder::new().storage_path(base.join("a")).add_tcp_client(addr).core_processor(pa).build().unwrap();
        a.start().await.unwrap();
        let _guard = register(&base, ra.sync.clone());
        let payload = b"{\"v\":1,\"ops\":[]}".to_vec();
        let exp = crate::now_ms() as u64 / 1000 + 600;
        assert!(send(&base, TITLE_CMD, Target::Pk(recipient.public_key_bytes()), payload.clone(), "t-offline", exp, always()));
        // адресат ещё не в сети: прямая доставка невозможна, письмо должно уйти на PN
        tokio::time::sleep(Duration::from_secs(12)).await;
        assert!(rb.inbound.try_recv().is_err());
        rb.pn.set_source(peers_with_pn(&recipient, &server));
        let mut b = leviculum_std::api::NodeBuilder::new().storage_path(base.join("b")).add_tcp_client(addr).core_processor(pb).build().unwrap();
        b.start().await.unwrap();
        let until = Instant::now() + Duration::from_secs(90);
        let message = loop {
            if let Ok(message) = rb.inbound.try_recv() { break message; }
            assert!(Instant::now() < until, "письмо с PN не дошло до адресата");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(message.method, DeliveryMethod::Propagated);
        assert_eq!(message.title, TITLE_CMD);
        assert_eq!(message.content, payload);
        assert!(crate::lxmf_admin::signed_by_trusted_source(&message, &sender.public_key_bytes()));
        a.stop().await.unwrap();
        b.stop().await.unwrap();
        srv.stop().await.unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }
}
