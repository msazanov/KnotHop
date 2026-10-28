//! Подписанные записи Trust по LXMF. Транспортный Delivered не означает применение:
//! отправитель повторяет пакет до прикладного ACK (после save), с ограниченными TTL/очередью.
use std::{collections::HashMap, path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock, mpsc}};
use leviculum_lxmf::{Message, DeliveryMethod, Verification};
use leviculum_std::api::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::trust::{self, Record, Policy, Pk};

pub const TITLE: &[u8] = b"trust.sync/1";
pub const LIMIT: usize = 32;
pub const TTL: u64 = 600;
/// Записей каталога в одном сообщении (как прежний DIR_MAX).
pub const DIR_LIMIT: usize = 16;
pub static TX_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static RX_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static TX_MESSAGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static RX_MESSAGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub type Gate = Arc<dyn Fn() -> Option<bool> + Send + Sync>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Wire {
    v: u8,
    pub records: Vec<String>,
    pub policies: Vec<String>,
    pub ack: Option<String>,
    /// Приватный каталог нод (бывший T_DIR): адреса — только подсказки для дозвона, не права; в анонс они не попадают (ADR 0016).
    /// Взаимоисключимо с записями и политиками; разбор и фильтр адресов — `parse_dir` на приёме.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dir: Vec<serde_json::Value>,
    /// Запрос свежего каталога, независимый от срока/полноты приглашения. Не выдаёт прав.
    #[serde(default, skip_serializing_if = "is_false")]
    pub get_dir: bool,
}

fn is_false(value: &bool) -> bool { !value }

impl Wire {
    pub fn decode(message: &Message) -> Option<Self> {
        if message.title != TITLE || message.verification != Verification::Valid
            || !matches!(message.method, DeliveryMethod::Direct | DeliveryMethod::Propagated) || message.content.len() > super::lxmf_admin::MAX_ADMIN_CONTENT { return None; }
        let wire: Self = serde_json::from_slice(&message.content).ok()?;
        if wire.v != 1 || wire.records.len() + wire.policies.len() > 16 || wire.dir.len() > DIR_LIMIT { return None; }
        if wire.get_dir {
            return (wire.records.is_empty() && wire.policies.is_empty() && wire.dir.is_empty() && wire.ack.is_none()).then_some(wire);
        }
        if !wire.dir.is_empty() && (!wire.records.is_empty() || !wire.policies.is_empty() || wire.ack.is_some() || !wire.dir.iter().all(|e| e.is_object())) { return None; }
        if let Some(ack) = &wire.ack {
            if ack.len() != 64 || !ack.bytes().all(|b| b.is_ascii_hexdigit()) || !wire.records.is_empty() || !wire.policies.is_empty() { return None; }
        } else if wire.records.is_empty() && wire.policies.is_empty() && wire.dir.is_empty() { return None; }
        Some(wire)
    }
}

#[derive(Clone)]
pub struct Outbound {
    pub title: Vec<u8>,
    pub pk: Pk,
    pub content: Vec<u8>,
    pub gate: Gate,
    pub exp: u64,
    pub ack: bool,
}

pub enum Command { Send(Outbound), Acknowledged { source: [u8;16], digest: String } }
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
pub fn digest(content: &[u8]) -> String { super::hex(&Sha256::digest(content)) }

/// Ограниченная пачка; цепочки передаются в исходном порядке. Gate повторно
/// проверяется процессором непосредственно перед enqueue/retry, без ожидания mutex.
pub fn send(state: &Path, pk: Pk, records: &[Record], policies: &[Policy], gate: Gate) -> bool {
    if records.len() + policies.len() > 16 || (records.is_empty() && policies.is_empty()) { return false; }
    let wire = Wire { v:1, records:records.iter().map(|r| super::hex(&r.wire())).collect(),
        policies:policies.iter().map(|p| super::hex(&p.wire())).collect(), ack:None, dir:vec![], get_dir:false };
    let Ok(content) = serde_json::to_vec(&wire) else { return false };
    if content.len() > super::lxmf_admin::MAX_ADMIN_CONTENT { return false; }
    submit(state, Command::Send(Outbound { title:TITLE.to_vec(), pk, content, gate, exp:super::now_ms() as u64/1000+TTL, ack:false }))
}

/// Каталог нод одним сообщением. Gate проверяет, что получатель всё ещё допустимый адресат: без ожидания mutex, как у записей.
pub fn send_dir(state: &Path, pk: Pk, mut dir: Vec<serde_json::Value>, gate: Gate) -> bool {
    dir.truncate(DIR_LIMIT);
    // хвост каталога отбрасываем, пока сообщение не уложится в лимит администрирования
    let content = loop {
        if dir.is_empty() { return false; }
        let Ok(content) = serde_json::to_vec(&Wire { v:1, records:vec![], policies:vec![], ack:None, dir:dir.clone(), get_dir:false }) else { return false };
        if content.len() <= super::lxmf_admin::MAX_ADMIN_CONTENT { break content; }
        dir.pop();
    };
    submit(state, Command::Send(Outbound { title:TITLE.to_vec(), pk, content, gate, exp:super::now_ms() as u64/1000+TTL, ack:false }))
}

/// Подписанный LXMF-запрос каталога у уже авторизованной ноды. Получатель повторно проверяет членство и ограничивает частоту.
pub fn request_dir(state: &Path, pk: Pk, gate: Gate) -> bool {
    let wire = Wire { v:1, records:vec![], policies:vec![], ack:None, dir:vec![], get_dir:true };
    let Ok(content) = serde_json::to_vec(&wire) else { return false };
    submit(state, Command::Send(Outbound { title:TITLE.to_vec(), pk, content, gate, exp:super::now_ms() as u64/1000+TTL, ack:false }))
}

pub fn policy_visible(tr: &trust::Trust, p: &Policy, peer: &Pk) -> bool {
    let Some(h) = trust::hash_of(peer) else { return false };
    let rights = tr.rights_in(&p.root, &h);
    (rights != 0 || p.hh == h)
        && (rights & (trust::TRANSIT|trust::ADD|trust::REMOVE|trust::CONFIG) != 0
            || p.hh == h || p.hh == tr.me_hash || tr.rights_in(&p.root, &p.hh) & trust::EXIT != 0)
        && tr.export_policies(super::now_ms() as u64).contains(p)
}

pub fn queue(state: &Path, authority: Arc<Mutex<trust::Trust>>, pk: Pk, records: Vec<Record>, policies: Vec<Policy>) -> bool {
    // В очереди ещё нет сетевой передачи; проверка в core перед enqueue обязательна.
    let mut ok = true;
    let entries: Vec<_> = records.iter().map(|r| (Some(r.clone()), None))
        .chain(policies.iter().map(|p| (None, Some(p.clone())))).collect();
    for chunk in entries.chunks(16) {
        let recs: Vec<_> = chunk.iter().filter_map(|(r, _)| r.clone()).collect();
        let pols: Vec<_> = chunk.iter().filter_map(|(_, p)| p.clone()).collect();
        let (check_recs, check_pols, authority) = (recs.clone(), pols.clone(), authority.clone());
        let gate: Gate = Arc::new(move || {
            let tr = match authority.try_lock() {
                Ok(tr) => tr,
                Err(std::sync::TryLockError::WouldBlock) => return None,
                Err(_) => return Some(false),
            };
            Some(check_recs.iter().all(|r| tr.record_visible_to(r, &pk))
                && check_pols.iter().all(|p| policy_visible(&tr, p, &pk)))
        });
        ok &= send(state, pk, &recs, &pols, gate);
    }
    ok
}

/// Ключ берётся не из метки Verification, а из Trust/проверенного Link/приглашения.
pub fn authenticated(message: &Message, me: &[u8;16], pk: &Pk) -> bool {
    message.destination_hash == super::lxmf_admin::lxmf_destination(me)
        && super::lxmf_admin::signed_by_trusted_source(message, pk)
}

pub fn acknowledge(state: &Path, message: &Message, pk: Pk) {
    let content = serde_json::to_vec(&Wire { v:1, records:vec![], policies:vec![], ack:Some(digest(&message.content)), dir:vec![], get_dir:false }).unwrap();
    submit(state, Command::Send(Outbound { title:TITLE.to_vec(), pk, content, gate:Arc::new(|| Some(true)), exp:super::now_ms() as u64/1000+TTL, ack:true }));
}
pub fn received_ack(state: &Path, source: [u8;16], digest: String) {
    submit(state, Command::Acknowledged { source, digest });
}

/// Проверка записей остаётся в Trust; повторные/устаревшие записи идемпотентны.
pub fn parsed(wire: &Wire) -> Option<(Vec<Record>, Vec<Policy>)> {
    let records: Option<Vec<_>> = wire.records.iter().map(|s| Record::parse(&super::unhex(s))).collect();
    let policies: Option<Vec<_>> = wire.policies.iter().map(|s| Policy::parse(&super::unhex(s))).collect();
    Some((records?, policies?))
}

pub fn source_key(message: &Message, tr: &trust::Trust, peers: impl IntoIterator<Item=Pk>, invited: Option<Pk>) -> Option<Pk> {
    tr.identity_for_lxmf_source(&message.source_hash).or_else(|| peers.into_iter().chain(invited)
        .find(|pk| trust::hash_of(pk).is_some_and(|h| super::lxmf_admin::lxmf_destination(&h) == message.source_hash)))
        .or_else(|| {
            // Собственное доказательство может опередить identify на отдельном
            // Link. Это ключ проверки LXMF-подписи, НЕ новый якорь.
            let wire = Wire::decode(message)?;
            let (records, _) = parsed(&wire)?;
            records.into_iter().map(|r| r.holder).find(|pk| trust::hash_of(pk)
                .is_some_and(|h| super::lxmf_admin::lxmf_destination(&h) == message.source_hash))
        })
}

/// Собственное доказательство identity — отдельный bootstrap, не снимок чужих
/// участников. Как прежний chain_for(me) после identify, оно не требует уже
/// установленной роли, иначе два участника без кэша друг друга не обменяются
/// цепочками. Включает только собственную цепочку, не общее хранилище.
pub fn queue_proof(state: &Path, authority: Arc<Mutex<trust::Trust>>, me: Pk, peer: Pk) -> bool {
    let records = authority.lock().unwrap().chain_for(&me);
    let mut ok = true;
    for chunk in records.chunks(16) {
        let check = chunk.to_vec();
        let tr = authority.clone();
        let gate: Gate = Arc::new(move || {
            let tr = match tr.try_lock() { Ok(tr) => tr, Err(std::sync::TryLockError::WouldBlock) => return None, Err(_) => return Some(false) };
            let chain = tr.chain_for(&me);
            Some(check.iter().all(|r| chain.contains(r)))
        });
        ok &= send(state, peer, chunk, &[], gate);
    }
    ok
}

// Используется также тестами протокола, без доверия к самодекларированной source.
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
}
static PN_CURRENT: Mutex<Option<Arc<PnStatus>>> = Mutex::new(None);

/// Поля `pn_*` для блока `pol` в status.json.
pub fn pn_status() -> serde_json::Value {
    use std::sync::atomic::Ordering::Relaxed;
    let current = PN_CURRENT.lock().ok().and_then(|g| g.clone());
    let Some(s) = current else { return serde_json::json!({"pn_state":"off","pn_ready":false,"pn_load_ms":0,"pn_trimmed":0,"pn_files":0,"pn_bytes":0}) };
    let state = s.state.load(Relaxed);
    serde_json::json!({"pn_state":match state { PN_LOADING=>"loading", PN_READY=>"ready", PN_FAILED=>"failed", _=>"off" },
        "pn_ready":state == PN_READY, "pn_load_ms":s.load_ms.load(Relaxed), "pn_trimmed":s.trimmed.load(Relaxed),
        "pn_files":s.files.load(Relaxed), "pn_bytes":s.bytes.load(Relaxed)})
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

/// Штатный PN engine, а не ещё один протокол хранилища. Только серверы; постоянный store вне стираемого lev-role,
/// `PN_CAP_BYTES`, bounded transfer/fetch. Возвращается сразу: хранилище открывается и подрезается в потоке `lxmf-pn-load`.
pub fn propagation_processor(state: &Path, identity: Identity) -> anyhow::Result<PnProcessor> { spawn_pn(state, identity, None) }

/// `hold` — тестовые ворота: фон не начинает загрузку, пока не придёт сигнал (или не закроется канал).
fn spawn_pn(state: &Path, identity: Identity, hold: Option<mpsc::Receiver<()>>) -> anyhow::Result<PnProcessor> {
    use lnpnd::engine::{Engine, EngineConfig};
    use leviculum_lxmf::{PropagationNodeConfig, peering::{PeeringConfig, MemoryPeerStore}};
    use leviculum_std::FilePropagationStore;
    use std::{os::unix::fs::PermissionsExt, sync::atomic::Ordering::Relaxed};
    let dir = state.join("lxmf/propagation");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let status = Arc::new(PnStatus::default());
    status.state.store(PN_LOADING, Relaxed);
    if let Ok(mut current) = PN_CURRENT.lock() { *current = Some(status.clone()); }
    let (tx, rx) = mpsc::sync_channel(1);
    let st = status.clone();
    std::thread::Builder::new().name("lxmf-pn-load".into()).spawn(move || {
        if let Some(hold) = hold { let _ = hold.recv(); }
        let t0 = std::time::Instant::now();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let mut trimmed = trim_by_name(&dir, now, crate::enroll::TTL, PN_MAX_FILES);
        let mut store = match FilePropagationStore::open(&dir, PN_CAP_BYTES) {
            Ok(store) => store,
            Err(_) => { st.state.store(PN_FAILED, Relaxed); return; }
        };
        trimmed += fit(&mut store, PN_CAP_BYTES);
        let (mut files, mut bytes) = (0u64, 0u64);
        let _ = leviculum_lxmf::propagation_store::PropagationStore::for_each(&store, &mut |m| { files += 1; bytes += m.size as u64; });
        let (engine, events) = Engine::new(EngineConfig {
            identity, store,
            node_config: PropagationNodeConfig { transfer_limit_kb:16, sync_limit_kb:64,
                serve_cap_bytes:Some(64*1024), message_expiry_secs:crate::enroll::TTL, name:None, ..Default::default() },
            announce_interval_secs:600, announce_delay_secs:if cfg!(test) {2} else {20}, announce_at_start:false,
            peering:PeeringConfig { max_peers:8, max_inbound_syncs:2, ..Default::default() },
            peer_store:Box::new(MemoryPeerStore::default()), control_allowed:vec![], auth_allowed:None,
            mailbox:None, store_limit_bytes:PN_CAP_BYTES, delivery_limit_kb:8,
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
    use leviculum_std::api::{generate_identity, NodeBuilder};
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
        let mut pn = spawn_pn(&base, generate_identity(), Some(gate_rx)).unwrap();
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
        let mut pn = spawn_pn(&base, generate_identity(), Some(gate_rx)).unwrap();
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

    #[test]
    fn sync_codec_signature_and_scope_are_not_authority() {
        let (actor, target, attacker) = (generate_identity(), generate_identity(), generate_identity());
        let wire = Wire { v:1, records:vec![], policies:vec![], ack:Some("11".repeat(32)), dir:vec![], get_dir:false };
        let make = |identity:&Identity| Message::create(super::super::lxmf_admin::lxmf_destination(target.hash()),
            super::super::lxmf_admin::lxmf_destination(actor.hash()), identity, 1.0,
            TITLE.to_vec(), serde_json::to_vec(&wire).unwrap(), vec![], DeliveryMethod::Direct).unwrap();
        assert!(Wire::decode(&make(&actor)).is_some());
        assert!(authenticated(&make(&actor), target.hash(), &actor.public_key_bytes()));
        assert!(!authenticated(&make(&attacker), target.hash(), &actor.public_key_bytes()));
        assert!(!authenticated(&make(&actor), attacker.hash(), &actor.public_key_bytes()));
        let mut malformed = make(&actor);
        malformed.content = serde_json::to_vec(&Wire { ack:Some("not-a-digest".into()), ..wire }).unwrap();
        assert!(Wire::decode(&malformed).is_none());
    }

    #[test]
    fn directory_wire_is_exclusive_bounded_and_object_only() {
        let (actor, target) = (generate_identity(), generate_identity());
        let make = |wire: &Wire| Message::create(super::super::lxmf_admin::lxmf_destination(target.hash()),
            super::super::lxmf_admin::lxmf_destination(actor.hash()), &actor, 1.0,
            TITLE.to_vec(), serde_json::to_vec(wire).unwrap(), vec![], DeliveryMethod::Direct).unwrap();
        let entry = serde_json::json!({"d": "00", "k": "00", "a": ["203.0.113.7:47001"], "n": "x"});
        let base = Wire { v:1, records:vec![], policies:vec![], ack:None, dir:vec![entry.clone()], get_dir:false };
        let decoded = Wire::decode(&make(&base)).expect("каталог из объектов");
        assert_eq!(decoded.dir, vec![entry.clone()]);
        // каталог не смешивается с записями, политиками и ACK
        assert!(Wire::decode(&make(&Wire { records:vec!["00".into()], ..base.clone() })).is_none());
        assert!(Wire::decode(&make(&Wire { policies:vec!["00".into()], ..base.clone() })).is_none());
        assert!(Wire::decode(&make(&Wire { ack:Some("11".repeat(32)), ..base.clone() })).is_none());
        // не больше DIR_LIMIT и только объекты
        assert!(Wire::decode(&make(&Wire { dir:vec![entry.clone(); DIR_LIMIT], ..base.clone() })).is_some());
        assert!(Wire::decode(&make(&Wire { dir:vec![entry.clone(); DIR_LIMIT + 1], ..base.clone() })).is_none());
        assert!(Wire::decode(&make(&Wire { dir:vec![serde_json::json!("203.0.113.7:47001")], ..base.clone() })).is_none());
        // пустое сообщение по-прежнему не принимается
        assert!(Wire::decode(&make(&Wire { dir:vec![], ..base })).is_none());
    }

    #[test]
    fn directory_request_is_exclusive_and_small() {
        let (actor, target) = (generate_identity(), generate_identity());
        let make = |wire: &Wire| Message::create(super::super::lxmf_admin::lxmf_destination(target.hash()),
            super::super::lxmf_admin::lxmf_destination(actor.hash()), &actor, 1.0,
            TITLE.to_vec(), serde_json::to_vec(wire).unwrap(), vec![], DeliveryMethod::Direct).unwrap();
        let wire = Wire { v:1, records:vec![], policies:vec![], ack:None, dir:vec![], get_dir:true };
        let msg = make(&wire);
        assert!(Wire::decode(&msg).unwrap().get_dir);
        assert!(msg.content.len() < 100, "request is control traffic, not an enrollment payload");
        assert!(Wire::decode(&make(&Wire { dir:vec![serde_json::json!({})], ..wire.clone() })).is_none());
        assert!(Wire::decode(&make(&Wire { records:vec!["00".into()], ..wire.clone() })).is_none());
        assert!(Wire::decode(&make(&Wire { policies:vec!["00".into()], ..wire.clone() })).is_none());
        assert!(Wire::decode(&make(&Wire { ack:Some("11".repeat(32)), ..wire })).is_none());
    }

    #[test]
    fn directory_control_payload_budget_for_eight_nodes() {
        let entries = (0..8).map(|i| serde_json::json!({"d":format!("{i:032x}"),"k":"11".repeat(64),"e":"22".repeat(32),
            "a":[format!("203.0.113.{}:47001",i+1)],"n":format!("node-{i}")})).collect::<Vec<_>>();
        let request = serde_json::to_vec(&Wire { v:1, records:vec![], policies:vec![], ack:None, dir:vec![], get_dir:true }).unwrap();
        let reply = serde_json::to_vec(&Wire { v:1, records:vec![], policies:vec![], ack:None, dir:entries, get_dir:false }).unwrap();
        assert!(request.len() < 100 && reply.len() < 4096);
        eprintln!("directory serialized control payload: request={} B, eight-node reply={} B, two peers / 120s={} B/s (no transport/ACK/records)",
            request.len(), reply.len(), 2 * (request.len() + reply.len()) / 120);
    }

    #[test]
    fn sync_gate_is_root_scoped_and_rechecks_revocation_without_blocking() {
        let (node, peer, outsider, holder) = (generate_identity(), generate_identity(), generate_identity(), generate_identity());
        let mut tr = trust::Trust::new(node.clone(), None);
        tr.issue(*node.hash(), peer.public_key_bytes(), trust::TRANSIT).unwrap();
        let rec = tr.issue(*node.hash(), holder.public_key_bytes(), trust::USE).unwrap();
        let authority = Arc::new(Mutex::new(tr));
        let state = std::env::temp_dir().join(format!("kh-sync-gate-{}", super::super::hex(node.hash())));
        let (tx, rx) = mpsc::sync_channel(LIMIT);
        let _guard = register(&state, tx);
        assert!(queue(&state, authority.clone(), peer.public_key_bytes(), vec![rec.clone()], vec![]));
        let Command::Send(request) = rx.recv().unwrap() else { panic!() };
        assert_eq!((request.gate)(), Some(true));
        let mut tr = authority.lock().unwrap();
        assert_eq!((request.gate)(), None, "core не ждёт Trust под mutex");
        tr.issue(*node.hash(), peer.public_key_bytes(), 0).unwrap();
        drop(tr);
        assert_eq!((request.gate)(), Some(false), "отзыв между queue и enqueue");
        assert!(queue(&state, authority, outsider.public_key_bytes(), vec![rec], vec![]));
        let Command::Send(request) = rx.recv().unwrap() else { panic!() };
        assert_eq!((request.gate)(), Some(false));
    }

    #[test]
    fn own_proof_is_not_a_foreign_participant_snapshot() {
        let (root, node, peer, user) = (generate_identity(), generate_identity(), generate_identity(), generate_identity());
        let mut issuer = trust::Trust::new(root.clone(), None);
        let own = issuer.issue(*root.hash(), node.public_key_bytes(), trust::TRANSIT).unwrap();
        let other = issuer.issue(*root.hash(), user.public_key_bytes(), trust::USE).unwrap();
        let mut tr = trust::Trust::new(node.clone(), None);
        tr.add_anchor(&root.public_key_bytes()).unwrap();
        assert_eq!(tr.offer(own.clone()), trust::Offer::Added);
        assert_eq!(tr.offer(other), trust::Offer::Added);
        let state = std::env::temp_dir().join(format!("kh-sync-proof-{}", super::super::hex(node.hash())));
        let (tx, rx) = mpsc::sync_channel(LIMIT);
        let _guard = register(&state, tx);
        assert!(queue_proof(&state, Arc::new(Mutex::new(tr)), node.public_key_bytes(), peer.public_key_bytes()));
        let Command::Send(request) = rx.recv().unwrap() else { panic!() };
        assert_eq!((request.gate)(), Some(true));
        let wire: Wire = serde_json::from_slice(&request.content).unwrap();
        assert_eq!(parsed(&wire).unwrap().0, vec![own]);
    }

    #[test]
    fn signed_envelope_byte_overhead() {
        let (sender, target) = (generate_identity(), generate_identity());
        let mut tr = trust::Trust::new(sender.clone(), None);
        let rec = tr.issue(*sender.hash(), target.public_key_bytes(), trust::TRANSIT).unwrap();
        for n in [1, 16] {
            let content = serde_json::to_vec(&Wire { v:1, records:vec![super::super::hex(&rec.wire());n], policies:vec![], ack:None, dir:vec![], get_dir:false }).unwrap();
            let message = Message::create(super::super::lxmf_admin::lxmf_destination(target.hash()),
                super::super::lxmf_admin::lxmf_destination(sender.hash()), &sender, 1.0,
                TITLE.to_vec(), content, vec![], DeliveryMethod::Direct).unwrap();
            println!("LXMF_SYNC_BYTES records={n} old_channel_app={} lxmf_signed={} content={} (без Link/Resource/носителя и ACK)",
                n*(trust::REC_LEN+1), message.pack().len(), message.content.len());
            assert!(message.pack().len() <= super::super::lxmf_admin::MAX_ADMIN_CONTENT);
        }
        let ack_content = serde_json::to_vec(&Wire { v:1, records:vec![], policies:vec![], ack:Some("00".repeat(32)), dir:vec![], get_dir:false }).unwrap();
        let ack = Message::create(super::super::lxmf_admin::lxmf_destination(sender.hash()),
            super::super::lxmf_admin::lxmf_destination(target.hash()), &target, 1.0,
            TITLE.to_vec(), ack_content, vec![], DeliveryMethod::Direct).unwrap();
        println!("LXMF_SYNC_ACK_BYTES lxmf_signed={} content={} (без Link/Resource/носителя)", ack.pack().len(), ack.content.len());
    }

    /// Офлайн-доставка: адресат подключается к сети уже после отправки, письмо ждёт на PN доверенного сервера.
    #[tokio::test(flavor="multi_thread", worker_threads=4)]
    async fn pn_delivers_signed_records_to_recipient_that_connects_later() {
        let (sender, recipient, server) = (generate_identity(), generate_identity(), generate_identity());
        let base = std::env::temp_dir().join(format!("kh-pn-offline-{}", super::super::hex(sender.hash())));
        let _ = std::fs::remove_dir_all(&base);
        // как на ES: накопленное хранилище сверх потолка; фон должен подрезать его, а PN после этого - принять и отдать письмо
        prefill(&base.join("server/lxmf/propagation"), 12_000, now_secs(), 0);
        let (pa, ra) = super::super::lxmf_admin::AdminProcessor::new(sender.clone());
        let (pb, rb) = super::super::lxmf_admin::AdminProcessor::new(recipient.clone());
        let (ps, _rs) = super::super::lxmf_admin::AdminProcessor::new(server.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let pn = propagation_processor(&base.join("server"), server.clone()).unwrap();
        let mut srv = NodeBuilder::new().storage_path(base.join("server")).add_tcp_server(addr).core_processor(Processors(ps, pn)).build().unwrap();
        srv.start().await.unwrap();
        // отправитель: сервер получает TRANSIT, поэтому его PN - выбираемый; адресат получает TRANSIT, но PN у него нет
        let mut tr_a = trust::Trust::new(sender.clone(), None);
        tr_a.issue(*sender.hash(), server.public_key_bytes(), trust::TRANSIT).unwrap();
        tr_a.issue(*sender.hash(), recipient.public_key_bytes(), trust::TRANSIT).unwrap();
        let rec = tr_a.issue(*sender.hash(), generate_identity().public_key_bytes(), trust::USE).unwrap();
        let authority = Arc::new(Mutex::new(tr_a));
        ra.pn.set_source(authority.clone());
        let mut a = NodeBuilder::new().storage_path(base.join("a")).add_tcp_client(addr).core_processor(pa).build().unwrap();
        a.start().await.unwrap();
        let _guard = register(&base, ra.sync.clone());
        assert!(queue(&base, authority, recipient.public_key_bytes(), vec![rec.clone()], vec![]));
        // адресат ещё не в сети: прямая доставка невозможна, письмо должно уйти на PN
        tokio::time::sleep(Duration::from_secs(12)).await;
        assert!(rb.inbound.try_recv().is_err());
        let mut tr_b = trust::Trust::new(recipient.clone(), None);
        tr_b.issue(*recipient.hash(), server.public_key_bytes(), trust::TRANSIT).unwrap();
        tr_b.issue(*recipient.hash(), sender.public_key_bytes(), trust::USE).unwrap();
        rb.pn.set_source(Arc::new(Mutex::new(tr_b)));
        let mut b = NodeBuilder::new().storage_path(base.join("b")).add_tcp_client(addr).core_processor(pb).build().unwrap();
        b.start().await.unwrap();
        let until = Instant::now() + Duration::from_secs(90);
        let message = loop {
            if let Ok(message) = rb.inbound.try_recv() { break message; }
            assert!(Instant::now() < until, "письмо с PN не дошло до адресата");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(message.method, DeliveryMethod::Propagated);
        assert!(authenticated(&message, recipient.hash(), &sender.public_key_bytes()));
        assert_eq!(parsed(&Wire::decode(&message).unwrap()).unwrap().0, vec![rec]);
        a.stop().await.unwrap();
        b.stop().await.unwrap();
        srv.stop().await.unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor="multi_thread", worker_threads=2)]
    async fn direct_lxmf_sync_local_smoke() {
        let (sender, recipient) = (generate_identity(), generate_identity());
        let base = std::env::temp_dir().join(format!("kh-sync-smoke-{}", super::super::hex(sender.hash())));
        let (p1, r1) = super::super::lxmf_admin::AdminProcessor::new(sender.clone());
        let (p2, r2) = super::super::lxmf_admin::AdminProcessor::new(recipient.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let pn = propagation_processor(&base.join("server"), recipient.clone()).unwrap();
        let mut server = NodeBuilder::new().storage_path(base.join("server")).add_tcp_server(addr).core_processor(Processors(p2, pn)).build().unwrap();
        server.start().await.unwrap();
        let mut client = NodeBuilder::new().storage_path(base.join("client")).add_tcp_client(addr).core_processor(p1).build().unwrap();
        client.start().await.unwrap();
        let _guard = register(&base, r1.sync.clone());
        let mut tr = trust::Trust::new(sender.clone(), None);
        tr.issue(*sender.hash(), recipient.public_key_bytes(), trust::TRANSIT).unwrap();
        let rec = tr.issue(*sender.hash(), generate_identity().public_key_bytes(), trust::USE).unwrap();
        let authority = Arc::new(Mutex::new(tr));
        assert!(queue(&base, authority, recipient.public_key_bytes(), vec![rec.clone()], vec![]));
        let until = Instant::now()+Duration::from_secs(20);
        let message = loop {
            if let Ok(message) = r2.inbound.try_recv() { break message; }
            assert!(Instant::now()<until, "LXMF message not delivered over local TCP");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(authenticated(&message, recipient.hash(), &sender.public_key_bytes()));
        let wire = Wire::decode(&message).unwrap();
        assert_eq!(parsed(&wire).unwrap().0, vec![rec]);
        // Транспортная доставка сама не создаёт прикладной ACK.
        assert!(r1.inbound.try_recv().is_err());
        let _server_guard = register(&base.join("server"), r2.sync.clone());
        acknowledge(&base.join("server"), &message, sender.public_key_bytes());
        let ack = loop {
            if let Ok(message) = r1.inbound.try_recv() { break message; }
            assert!(Instant::now()<until, "application ACK not delivered");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(authenticated(&ack, sender.hash(), &recipient.public_key_bytes()));
        assert_eq!(Wire::decode(&ack).unwrap().ack, Some(digest(&message.content)));
        // Каталог запрашивается тем же LXMF router, независимо от наличия enrollment/приглашения.
        assert!(request_dir(&base, recipient.public_key_bytes(), Arc::new(|| Some(true))));
        let request = loop {
            if let Ok(message) = r2.inbound.try_recv() {
                if Wire::decode(&message).is_some_and(|w| w.get_dir) { break message; }
            }
            assert!(Instant::now()<until, "directory request not delivered");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(authenticated(&request, recipient.hash(), &sender.public_key_bytes()));
        let entries = (0..8).map(|i| serde_json::json!({"n":format!("node-{i}"),"a":[format!("203.0.113.{}:47001",i+1)]})).collect::<Vec<_>>();
        assert!(send_dir(&base.join("server"), sender.public_key_bytes(), entries.clone(), Arc::new(|| Some(true))));
        let reply = loop {
            if let Ok(message) = r1.inbound.try_recv() {
                if Wire::decode(&message).is_some_and(|w| !w.dir.is_empty()) { break message; }
            }
            assert!(Instant::now()<until, "directory reply not delivered");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(authenticated(&reply, sender.hash(), &recipient.public_key_bytes()));
        assert_eq!(Wire::decode(&reply).unwrap().dir, entries);
        assert!(parsed(&Wire::decode(&reply).unwrap()).unwrap().0.is_empty(), "каталог не создаёт записей о правах");
        assert!(base.join("server/lxmf/propagation").is_dir());
        client.stop().await.unwrap();
        server.stop().await.unwrap();
    }
}
