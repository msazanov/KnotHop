//! Direct, addressed LXMF transport for the node-scoped administration slice.
//!
//! LXMF's Sans-I/O node/router are driven from ReticulumNode's in-driver
//! CoreProcessor tap. Application work and filesystem commits run on a bounded
//! worker outside the core lock; replies return through a bounded channel.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::os::unix::fs::MetadataExt;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, Ordering}};

use anyhow::{Context, Result, bail};
use leviculum_lxmf::router::{LxmfRouter, PropagationClientConfig, RouterConfig, RouterEvent, RouterOutput};
use leviculum_lxmf::{BuiltResource, CooperativeStamper, DeliveryMethod, LxmfNode, LxmfNodeConfig, Message, PendingResourceBuild, PropagationStampRequest, PropagationTransport, StampCancel, Verification, announce};
use leviculum_std::api::{CoreProcessor, Destination, DestinationHash, Identity, NodeEvent, StdNodeCore, TickOutput};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_ADMIN_CONTENT: usize = 8 * 1024;
pub const MAX_ADMIN_QUEUE: usize = 32;
pub const ADMIN_TTL_SECS: u64 = 10 * 60;
/// Небольшой положительный дрейф часов клиента не должен отвергать свежую команду.
const ADMIN_CLOCK_SKEW_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminWireRequest {
    pub v: u8,
    pub requestid: String,
    /// KnotHop identity hash of the target, not its RNS destination hash.
    pub target_identity: String,
    pub root: String,
    pub scope: String,
    pub op: String,
    pub exp: u64,
    pub holder: Option<String>,
    pub rights: u16,
    pub host_record: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminWireReply {
    pub v: u8,
    pub requestid: String,
    pub target_identity: String,
    pub root: String,
    pub state: String,
    pub durable_ack: bool,
    pub code: Option<String>,
    pub revision: u64,
    pub capabilities: Option<serde_json::Value>,
    pub authority: Option<serde_json::Value>,
    pub participants: Option<Vec<serde_json::Value>>,
    /// Подписанная запись сохранена на диске узла (для rights.*). Отсутствует в ответах старого формата.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_committed: Option<bool>,
    /// Действующее решение узла о HOST_ACCESS держателя после применения: «доступ отозван» показывать
    /// только когда оно `false`, «доступ выдан» - когда `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_host_allowed: Option<bool>,
    /// Изменилось ли действующее решение этой командой.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct AdminOutbound {
    pub requestid: String,
    pub destination: [u8; 16],
    pub title: Vec<u8>,
    pub content: Vec<u8>,
    pub exp: u64,
}

#[derive(Debug, Clone)]
pub enum TransportEvent {
    Delivered { requestid: String },
    Failed { requestid: String },
    Expired { requestid: String },
    ReceiverUnavailable,
}

/// Прямая доставка без ответа дольше этого срока дублируется через PN сети (офлайн-доставка).
const PN_FALLBACK_SECS: u64 = if cfg!(test) { 3 } else { 30 };
/// Копия на PN, которая не ушла из очереди роутера дольше этого срока, считается зависшей: PN не отвечает.
const PN_COPY_STUCK_SECS: u64 = 180;
/// Исход копии (ушла из очереди, события нет) выясняется не позже этого срока, иначе PN отмечается плохим.
const PN_COPY_OUTCOME_SECS: u64 = 10;
/// Выдержка плохого PN и интервал между копиями: 60, 120, 240, 480, 960, затем 1800 с.
const PN_BACKOFF_BASE_SECS: u64 = if cfg!(test) { 1 } else { 60 };
const PN_BACKOFF_MAX_SECS: u64 = if cfg!(test) { 16 } else { 1800 };
/// Копий одного сообщения через PN (≈10 ч при расписании выше); дальше остаётся только прямая доставка до `exp`.
const PN_MAX_COPIES: u8 = 32;
/// Плановая выборка почты с PN: по расписанию анонса, без новых пробуждений телефона.
const PN_FETCH_MS: u64 = 600_000;
/// Узлы-серверы (постоянная связь, без батареи) забирают почту чаще: закрытие зачисления между нодами иначе ждёт до 10 минут.
pub const PN_FETCH_SERVER_MS: u64 = 120_000;
/// Не чаще раза в 30 с, как бы ни менялся выбор PN.
const PN_FETCH_SPACING_MS: u64 = 30_000;
const PN_REFRESH_MS: u64 = 5_000;
/// Стоимость stamp, которую готовы майнить: чужой анонс не должен сжигать CPU (особенно телефона).
const PN_MAX_STAMP_COST: u8 = 16;
const PN_KEYS_MAX: usize = 256;

/// PN этой сети и известные ключи сети. Анонс PN сам по себе не полномочие: выбирается только
/// `lxmf.propagation` ключей, которым Trust даёт TRANSIT; подписи LXMF по-прежнему проверяются в Trust.
#[derive(Default)]
pub struct PnShared {
    trust: Mutex<Option<Arc<Mutex<crate::trust::Trust>>>>,
}

pub struct PnView { pub nodes: BTreeSet<DestinationHash>, pub keys: Vec<crate::trust::Pk> }

impl PnShared {
    pub fn set_source(&self, trust: Arc<Mutex<crate::trust::Trust>>) { *self.trust.lock().unwrap() = Some(trust); }

    /// `None`, пока Trust занят: прежний выбор остаётся (без ожидания mutex в потоке ядра).
    fn view(&self, now_ms: u64) -> Option<PnView> {
        let source = self.trust.lock().ok()?.clone()?;
        let tr = source.try_lock().ok()?;
        let nodes = tr.holders_with(crate::trust::TRANSIT).into_iter()
            .filter(|pk| tr.effective(pk, now_ms) & crate::trust::TRANSIT != 0)
            .filter_map(|pk| pn_destination(&pk)).map(DestinationHash::new).take(32).collect();
        // ключи сети нужны, чтобы проверить подпись сообщения, полученного с PN, когда отправителя в сети давно не слышно
        let mut keys: Vec<_> = tr.anchors().into_iter().map(|(_, pk)| pk).collect();
        keys.extend(tr.holders_with(u16::MAX));
        keys.truncate(PN_KEYS_MAX);
        Some(PnView { nodes, keys })
    }
}

/// Назначение `lxmf.propagation` identity с ключом `pk`.
pub fn pn_destination(pk: &crate::trust::Pk) -> Option<[u8; 16]> {
    let hash = crate::trust::hash_of(pk)?;
    Some(*Destination::compute_destination_hash(&Destination::compute_name_hash("lxmf", &["propagation"]), &hash).as_bytes())
}

pub struct AdminRuntime {
    pub pn: Arc<PnShared>,
    pub inbound: Receiver<Message>,
    pub outbound: SyncSender<AdminOutbound>,
    pub transport_events: Receiver<TransportEvent>,
    pub ready: Arc<AtomicBool>,
    pub sync: super::lxmf_sync::Sender,
}

struct RegisteredClient {
    outbound: SyncSender<AdminOutbound>,
    ready: Arc<AtomicBool>,
}

static CLIENT_RUNTIMES: OnceLock<Mutex<HashMap<PathBuf, RegisteredClient>>> = OnceLock::new();

pub struct ClientRuntimeGuard { state: PathBuf }

impl Drop for ClientRuntimeGuard {
    fn drop(&mut self) {
        if let Some(registry) = CLIENT_RUNTIMES.get() { registry.lock().unwrap().remove(&self.state); }
    }
}

pub fn register_client_runtime(state: &Path, runtime: &AdminRuntime) -> ClientRuntimeGuard {
    let key = state.canonicalize().unwrap_or_else(|_| state.to_path_buf());
    CLIENT_RUNTIMES.get_or_init(Default::default).lock().unwrap().insert(key.clone(), RegisteredClient {
        outbound: runtime.outbound.clone(), ready: runtime.ready.clone(),
    });
    ClientRuntimeGuard { state: key }
}

fn client_runtime(state: &Path) -> Option<RegisteredClient> {
    let key = state.canonicalize().unwrap_or_else(|_| state.to_path_buf());
    CLIENT_RUNTIMES.get()?.lock().unwrap().get(&key).map(|r| RegisteredClient { outbound: r.outbound.clone(), ready: r.ready.clone() })
}

pub fn client_runtime_ready(state: &Path) -> bool {
    client_runtime(state).is_some_and(|r| r.ready.load(Ordering::Acquire))
}

pub struct AdminProcessor {
    identity: Identity,
    outbound: Receiver<AdminOutbound>,
    inbound: SyncSender<Message>,
    transport_events: SyncSender<TransportEvent>,
    ready: Arc<AtomicBool>,
    resource_jobs: SyncSender<PendingResourceBuild>,
    resource_results: Receiver<ResourceBuildResult>,
    last_announce_ms: u64,
    state: ProcessorState,
    sync: Receiver<super::lxmf_sync::Command>,
    sync_pending: HashMap<String, PendingSync>,
    pn: Arc<PnShared>,
    pn_nodes: BTreeSet<DestinationHash>,
    pn_checked_ms: u64,
    pn_fetch_due: bool,
    pn_health: PnHealth,
    /// исходы копий на PN, собранные из событий роутера (`absorb`), разбираются в `sync_tick`
    pn_outcomes: Vec<([u8; 32], leviculum_lxmf::router::MessageState)>,
    last_fetch_ms: u64,
    fetch_ms: u64,
    stamp_jobs: SyncSender<PropagationStampRequest>,
    stamp_results: Receiver<(PropagationStampRequest, [u8; 32])>,
}

struct PendingSync {
    request: super::lxmf_sync::Outbound,
    last_try: Option<u64>,
    first_try: Option<u64>,
    transport: Option<[u8;32]>,
    /// копия для офлайн-доставки через PN (только если нужен прикладной ACK)
    pn_copy: Option<[u8;32]>,
    /// PN, которому отдана текущая копия, и время отдачи (с)
    pn_node: Option<DestinationHash>,
    pn_since: u64,
    /// PN принял копию (`AwaitingCollection`); хранит ли он её до сих пор, отправитель узнать не может
    pn_held: bool,
    pn_copies: u8,
    /// не раньше этого времени (с): новая копия или повтор принятой, но не подтверждённой адресатом
    pn_retry_at: u64,
}

impl PendingSync {
    fn new(request: super::lxmf_sync::Outbound) -> Self {
        Self { request, last_try: None, first_try: None, transport: None, pn_copy: None, pn_node: None, pn_since: 0, pn_held: false, pn_copies: 0, pn_retry_at: 0 }
    }
}

/// Отправитель не может спросить PN, хранит ли он письмо (в LXMF такого запроса для не-адресата нет), поэтому PN
/// оценивается по исходу загрузки и по отсутствию прикладного ACK адресата: подозрительный PN откладывается с
/// нарастающей выдержкой, копия уходит через другой PN.
#[derive(Default)]
struct PnHealth {
    /// PN → (до какого времени избегать (с), число подряд неудач)
    bad: BTreeMap<DestinationHash, (u64, u8)>,
}

impl PnHealth {
    fn backoff(strikes: u8) -> u64 { (PN_BACKOFF_BASE_SECS << strikes.min(8)).min(PN_BACKOFF_MAX_SECS) }
    fn strike(&mut self, pn: DestinationHash, now: u64) {
        let entry = self.bad.entry(pn).or_insert((0, 0));
        entry.0 = now + Self::backoff(entry.1);
        entry.1 = entry.1.saturating_add(1);
    }
    fn forgive(&mut self, pn: &DestinationHash) { self.bad.remove(pn); }
    fn is_bad(&self, pn: &DestinationHash, now: u64) -> bool { self.bad.get(pn).is_some_and(|(until, _)| *until > now) }
    /// Выдержка истекла давно: счётчик неудач не копится вечно, таблица не растёт
    fn prune(&mut self, now: u64, keep: &BTreeSet<DestinationHash>) {
        self.bad.retain(|pn, (until, _)| keep.contains(pn) && until.saturating_add(PN_BACKOFF_MAX_SECS * 2) > now);
    }
    /// Пауза до следующей копии: 60, 120, 240 … с, по числу уже отданных копий
    fn copy_wait(copies: u8) -> u64 { Self::backoff(copies.saturating_sub(1)) }
    /// Лучший PN без выдержки: услышанный анонс, затем ближайший по хопам. Все в выдержке — тот, у кого она кончится раньше.
    fn pick(&self, nodes: &BTreeSet<DestinationHash>, now: u64, rank: impl Fn(&DestinationHash) -> (bool, u8)) -> Option<DestinationHash> {
        nodes.iter().filter(|n| !self.is_bad(n, now)).min_by_key(|n| (rank(n), **n)).copied()
            .or_else(|| nodes.iter().min_by_key(|n| (self.bad.get(*n).map_or(0, |b| b.0), **n)).copied())
    }
}

enum ResourceBuildResult { Ready(Box<BuiltResource>), Failed([u8;32]) }

enum ProcessorState {
    Unregistered,
    Ready {
        router: LxmfRouter,
        outbound_ids: HashMap<[u8; 32], TrackedDelivery>,
    },
    Failed,
}

#[derive(Clone)]
struct TrackedDelivery { requestid: String, exp: u64 }

impl AdminProcessor {
    pub fn new(identity: Identity) -> (Self, AdminRuntime) {
        let (sync_tx, sync_rx) = mpsc::sync_channel(super::lxmf_sync::LIMIT);
        let (out_tx, out_rx) = mpsc::sync_channel(MAX_ADMIN_QUEUE);
        let (in_tx, in_rx) = mpsc::sync_channel(MAX_ADMIN_QUEUE);
        let (event_tx, event_rx) = mpsc::sync_channel(MAX_ADMIN_QUEUE);
        let (jobs_tx,jobs_rx)=mpsc::sync_channel::<PendingResourceBuild>(MAX_ADMIN_QUEUE);
        let (result_tx,result_rx)=mpsc::sync_channel::<ResourceBuildResult>(MAX_ADMIN_QUEUE);
        std::thread::Builder::new().name("knothop-lxmf-resource-build".into()).spawn(move || {
            while let Ok(job)=jobs_rx.recv() {
                let id=job.message_id();
                let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||job.build(&mut rand_core::OsRng)));
                let item=match result {Ok(Ok(built))=>ResourceBuildResult::Ready(Box::new(built)),_=>ResourceBuildResult::Failed(id)};
                if result_tx.send(item).is_err(){break}
            }
        }).ok();
        let (stamp_tx, stamp_rx) = mpsc::sync_channel::<PropagationStampRequest>(4);
        let (stamp_out_tx, stamp_out_rx) = mpsc::sync_channel::<(PropagationStampRequest, [u8; 32])>(4);
        // Майнинг stamp - чистый CPU: отдельный поток со своим однопоточным runtime, вне блокировки ядра.
        std::thread::Builder::new().name("knothop-lxmf-pn-stamp".into()).spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
            while let Ok(request) = stamp_rx.recv() {
                let mut executor = CooperativeStamper::cooperative(rand_core::OsRng);
                let cancel = StampCancel::new();
                if let Ok(stamp) = runtime.block_on(request.generate_with(&mut executor, &cancel)) {
                    if stamp_out_tx.send((request, stamp)).is_err() { break }
                }
            }
        }).ok();
        let pn = Arc::new(PnShared::default());
        let ready = Arc::new(AtomicBool::new(false));
        let processor = Self {
            identity,
            outbound: out_rx,
            inbound: in_tx,
            transport_events: event_tx,
            ready: ready.clone(),
            resource_jobs:jobs_tx,
            resource_results:result_rx,
            last_announce_ms: 0,
            state: ProcessorState::Unregistered,
            sync: sync_rx,
            sync_pending: HashMap::new(),
            pn: pn.clone(),
            pn_nodes: BTreeSet::new(),
            pn_checked_ms: 0,
            pn_fetch_due: false,
            pn_health: PnHealth::default(),
            pn_outcomes: Vec::new(),
            last_fetch_ms: 0,
            fetch_ms: PN_FETCH_MS,
            stamp_jobs: stamp_tx,
            stamp_results: stamp_out_rx,
        };
        (processor, AdminRuntime { pn, inbound: in_rx, outbound: out_tx, transport_events: event_rx, ready, sync:sync_tx })
    }

    /// Период плановой выборки почты с PN (по умолчанию `PN_FETCH_MS`).
    pub fn with_fetch_ms(mut self, ms: u64) -> Self { self.fetch_ms = ms; self }

    fn register(&mut self, core: &mut StdNodeCore, out: &mut TickOutput) -> Result<ProcessorState> {
        let destination = LxmfNode::delivery_destination(self.identity.clone()).map_err(|e| anyhow::anyhow!("LXMF delivery destination: {e:?}"))?;
        let lxmf = LxmfNode::register(core, destination, LxmfNodeConfig {
            max_incoming_resource_size: Some(MAX_ADMIN_CONTENT as u64),
            max_outgoing_delivery_size: Some(MAX_ADMIN_CONTENT as u64),
            auto_compress_resources: false,
        }).context("register LXMF delivery destination")?;
        let destination_hash = DestinationHash::new(*lxmf.delivery_destination_hash().as_bytes());
        let mut router = LxmfRouter::new(lxmf, *self.identity.hash(), RouterConfig {
            max_outbound: 16,
            max_snapshot_bytes: 256 * 1024,
            enforce_stamps: false,
            inbound_stamp_cost: None,
            defer_resource_builds: true,
            ..RouterConfig::default()
        });
        // PN-клиент: то же назначение `lxmf.propagation`, что у встроенного PN сервера. Есть оно уже в ядре - присоединяемся
        // и возвращаем приём Link серверу; нет - регистрируем (PN-движок позже заменит запись, хеш тот же).
        let pn_destination = PropagationTransport::destination(self.identity.clone()).map_err(|e| anyhow::anyhow!("LXMF propagation destination: {e:?}"))?;
        let pn_hash = *pn_destination.hash();
        let transport = if core.destination_mut(&pn_hash).is_some() {
            let transport = PropagationTransport::attach(core, pn_hash).map_err(|e| anyhow::anyhow!("attach PN client: {e:?}"))?;
            if let Some(existing) = core.destination_mut(&pn_hash) { existing.set_accepts_links(true); }
            transport
        } else {
            PropagationTransport::register(core, pn_destination).map_err(|e| anyhow::anyhow!("register PN client: {e:?}"))?
        };
        router.enable_propagation_client(transport, PropagationClientConfig::default()).map_err(|e| anyhow::anyhow!("enable PN client: {e:?}"))?;
        let app_data = announce::DeliveryAnnounce::new(None, None).map_err(|e| anyhow::anyhow!("LXMF announce: {e}"))?.encode();
        match core.announce_destination(&destination_hash, Some(&app_data)) {
            Ok(output) => self.absorb(&mut router, &mut HashMap::new(), core, RouterOutput { core: output, events: Vec::new() }, out),
            Err(e) => bail!("announce LXMF delivery destination: {e:?}"),
        }
        self.ready.store(true, Ordering::Release);
        self.last_announce_ms = core.now_ms();
        Ok(ProcessorState::Ready { router, outbound_ids: HashMap::new() })
    }

    fn absorb(&mut self, router: &mut LxmfRouter, outbound_ids: &mut HashMap<[u8; 32], TrackedDelivery>, core: &mut StdNodeCore, first: RouterOutput, out: &mut TickOutput) {
        let mut queue = std::collections::VecDeque::from([first]);
        let mut rounds = 0usize;
        while let Some(mut item) = queue.pop_front() {
            let mut events = std::mem::take(&mut item.events);
            let mut core_out = item.core;
            let node_events = std::mem::take(&mut core_out.events);
            out.merge(core_out);
            for event in events.drain(..) {
                match event {
                    RouterEvent::MessageReceived(message) => {
                        let message = *message;
                        // Propagated - почта с PN сети; подпись и права всё равно проверяет Trust
                        if (message.verification != Verification::Valid && message.title != super::enroll_net::TITLE) || !matches!(message.method, DeliveryMethod::Direct | DeliveryMethod::Propagated)
                            || message.content.len() > MAX_ADMIN_CONTENT {
                            continue;
                        }
                        let _ = self.inbound.try_send(message);
                    }
                    RouterEvent::PropagationStampPending(request) => {
                        if request.target_cost <= PN_MAX_STAMP_COST { let _ = self.stamp_jobs.try_send(request); }
                    }
                    RouterEvent::MessageState { message_id, state } => {
                        use leviculum_lxmf::router::MessageState as S;
                        if matches!(state, S::AwaitingCollection | S::Failed | S::Rejected | S::Cancelled) && self.pn_outcomes.len() < 64 {
                            self.pn_outcomes.push((message_id, state));
                        }
                        if let Some(tracked) = outbound_ids.get(&message_id).cloned() {
                            match state {
                                leviculum_lxmf::router::MessageState::Delivered => {
                                    let _ = self.transport_events.try_send(TransportEvent::Delivered { requestid:tracked.requestid });
                                    outbound_ids.remove(&message_id);
                                }
                                leviculum_lxmf::router::MessageState::Failed | leviculum_lxmf::router::MessageState::Rejected => {
                                    let _ = self.transport_events.try_send(TransportEvent::Failed { requestid:tracked.requestid });
                                    outbound_ids.remove(&message_id);
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            rounds += 1;
            for event in node_events {
                if rounds <= 8 {
                    if let Ok(next) = router.handle_event(core, &event) { queue.push_back(next); }
                }
                out.events.push(event);
            }
        }
        for pending in router.take_resource_builds() {
            // Queue capacity equals the maximum number of application outbounds;
            // overflow leaves the signed request pending and no delivery ACK is emitted.
            let _ = self.resource_jobs.try_send(pending);
        }
    }

    fn process(&mut self, core: &mut StdNodeCore, out: &mut TickOutput, run_scheduler: bool) {
        let state = std::mem::replace(&mut self.state, ProcessorState::Failed);
        let mut state = match state {
            ProcessorState::Unregistered => match self.register(core, out) {
                Ok(state) => state,
                Err(_) => {
                    self.ready.store(false, Ordering::Release);
                    let _ = self.transport_events.try_send(TransportEvent::ReceiverUnavailable);
                    ProcessorState::Failed
                }
            },
            other => other,
        };
        if run_scheduler {
            let mut outputs = Vec::new();
            if let ProcessorState::Ready { router, outbound_ids } = &mut state {
                self.pn_tick(core, router, &mut outputs);
                self.sync_tick(core, router, out, &mut outputs);
                for result in self.resource_results.try_iter() {
                    match result {
                        ResourceBuildResult::Ready(built) => if let Ok(output)=router.commit_resource_build(core,*built) { outputs.push(output); },
                        ResourceBuildResult::Failed(_id) => {},
                    }
                }
                for _ in 0..1 {
                    let request = match self.outbound.try_recv() { Ok(x) => x, Err(_) => break };
                    if request.exp <= super::now_ms() as u64 / 1000 {
                        let _=self.transport_events.try_send(TransportEvent::Expired{requestid:request.requestid});
                        continue;
                    }
                    if request.content.len() > MAX_ADMIN_CONTENT {
                        let _=self.transport_events.try_send(TransportEvent::Failed{requestid:request.requestid});
                        continue;
                    }
                    let message = match router.create_message(core, request.destination, request.title, request.content, Vec::new(), DeliveryMethod::Direct) {
                        Ok(x) => x,
                        Err(_) => { let _=self.transport_events.try_send(TransportEvent::Failed{requestid:request.requestid}); continue; },
                    };
                    let id = message.message_id;
                    match router.enqueue(core, message) {
                        Ok(output) => {
                            outbound_ids.insert(id, TrackedDelivery { requestid:request.requestid, exp:request.exp });
                            outputs.push(output);
                        }
                        Err(_) => { let _=self.transport_events.try_send(TransportEvent::Failed{requestid:request.requestid}); }
                    }
                }
            }
            if let ProcessorState::Ready { router, outbound_ids } = &mut state {
                for output in outputs { self.absorb(router, outbound_ids, core, output, out); }
                let now = super::now_ms() as u64 / 1000;
                let expired: Vec<[u8;32]> = outbound_ids.iter().filter_map(|(id,d)| (d.exp <= now).then_some(*id)).collect();
                for id in expired {
                    if let Some(delivery)=outbound_ids.remove(&id) {
                        if let Ok(output)=router.cancel(core,&id) { self.absorb(router,outbound_ids,core,output,out); }
                        let _ = self.transport_events.try_send(TransportEvent::Expired { requestid:delivery.requestid });
                    }
                }
                if core.now_ms().saturating_sub(self.last_announce_ms) >= 600_000 {
                    let data=announce::DeliveryAnnounce::new(None,None).map(|a|a.encode()).unwrap_or_default();
                    let dest=router.node().delivery_destination_hash();
                    if let Ok(output)=core.announce_destination(&dest,Some(&data)) { out.merge(output); }
                    self.last_announce_ms=core.now_ms();
                }
                if let Ok(output) = router.tick(core) { self.absorb(router, outbound_ids, core, output, out); }
            }
        }
        self.state = state;
    }

    /// Выбор PN из доверенных серверов, stamp для загрузки на PN и выборка почты. Без новых таймеров: идёт в штатный tick.
    fn pn_tick(&mut self, core: &mut StdNodeCore, router: &mut LxmfRouter, outputs: &mut Vec<RouterOutput>) {
        let now = core.now_ms();
        if self.pn_checked_ms == 0 || now.saturating_sub(self.pn_checked_ms) >= PN_REFRESH_MS {
            if let Some(view) = self.pn.view(super::now_ms() as u64) {
                self.pn_checked_ms = now.max(1);
                for pk in &view.keys {
                    if let Some(identity) = super::lxmf_sync::public_identity(pk) {
                        core.remember_identity(DestinationHash::new(lxmf_destination(identity.hash())), identity);
                    }
                }
                self.pn_nodes = view.nodes;
            }
        }
        router.retain_known_propagation_nodes(&self.pn_nodes);
        let wall = super::now_ms() as u64 / 1000;
        self.pn_health.prune(wall, &self.pn_nodes);
        // выбранный вслепую узел (анонса не слышали) уступает узлу с услышанным анонсом PN
        let blind = router.outbound_propagation_node().is_some_and(|c| router.known_propagation_node(&c).is_none())
            && router.known_propagation_nodes().next().is_some();
        if blind || router.outbound_propagation_node().is_some_and(|c| !self.pn_nodes.contains(&c)) {
            if let Ok(output) = router.set_outbound_propagation_node(core, None) { outputs.push(output); }
        }
        // PN нет или текущий в выдержке (не принимает загрузки / письма на нём не подтверждаются): берём лучший без выдержки.
        // Сначала услышанный анонс PN, затем ближайший по хопам; не услышанный выбирается вслепую (путь запросит роутер).
        let current = router.outbound_propagation_node();
        if !self.pn_nodes.is_empty() && current.is_none_or(|c| self.pn_health.is_bad(&c, wall)) {
            let rank = |n: &DestinationHash| (router.known_propagation_node(n).is_none(), core.hops_to(n).unwrap_or(u8::MAX));
            if let Some(best) = self.pn_health.pick(&self.pn_nodes, wall, rank) {
                if Some(best) != current && (current.is_none() || !self.pn_health.is_bad(&best, wall)) {
                    if let Ok(output) = router.select_outbound_propagation_node(core, Some(best)) { outputs.push(output); self.pn_fetch_due = true; }
                }
            }
        }
        for (request, stamp) in self.stamp_results.try_iter().take(4) {
            if let Ok(output) = router.set_outbound_propagation_stamp_result(&request, stamp, now) { outputs.push(output); }
        }
        let periodic = now.saturating_sub(self.last_fetch_ms) >= self.fetch_ms;
        if router.outbound_propagation_node().is_some() && (self.pn_fetch_due || periodic)
            && (self.last_fetch_ms == 0 || now.saturating_sub(self.last_fetch_ms) >= PN_FETCH_SPACING_MS) {
            if let Ok(output) = router.request_messages_from_propagation_node(core, None) { outputs.push(output); }
            self.pn_fetch_due = false;
            self.last_fetch_ms = now.max(1);
        }
    }

    fn sync_tick(&mut self, core: &mut StdNodeCore, router: &mut LxmfRouter, out: &mut TickOutput, outputs: &mut Vec<RouterOutput>) {
        use super::lxmf_sync::{self, Command};
        let now = super::now_ms() as u64 / 1000;
        for command in self.sync.try_iter().take(lxmf_sync::LIMIT) {
            match command {
                Command::Send(request) => {
                    let id = format!("{}:{}", super::hex(&request.pk), lxmf_sync::digest(&request.content));
                    if self.sync_pending.len() < lxmf_sync::LIMIT && !self.sync_pending.contains_key(&id) {
                        self.sync_pending.insert(id, PendingSync::new(request));
                    }
                }
                Command::Acknowledged { source, digest } => {
                    self.sync_pending.retain(|_, p| {
                        let matched = lxmf_sync::public_identity(&p.request.pk)
                            .is_some_and(|i| lxmf_destination(i.hash()) == source) && lxmf_sync::digest(&p.request.content) == digest;
                        if matched {
                            for transport in [p.transport, p.pn_copy].into_iter().flatten() {
                                if let Ok(output) = router.cancel(core, &transport) { out.merge(output.core); }
                            }
                        }
                        !matched
                    });
                }
            }
        }
        use leviculum_lxmf::router::MessageState as S;
        for (id, state) in std::mem::take(&mut self.pn_outcomes) {
            let Some(p) = self.sync_pending.values_mut().find(|p| p.pn_copy == Some(id)) else { continue };
            match (state, p.pn_node) {
                (S::AwaitingCollection, node) => {
                    // PN принял копию. Судьба письма дальше решается только прикладным ACK адресата.
                    p.pn_held = true;
                    p.pn_since = now;
                    if let Some(node) = node { self.pn_health.forgive(&node); }
                }
                (_, node) => {
                    // PN не принял (Failed после исчерпания повторов роутера, Rejected): в выдержку, копия уйдёт на другой PN.
                    if let Some(node) = node { self.pn_health.strike(node, now); }
                    p.pn_copy = None;
                    p.pn_held = false;
                }
            }
        }
        let mut remove = Vec::new();
        // Не более одной новой передачи за tick; retry ограничен пятью секундами.
        let mut enqueued = false;
        let mut pn_enqueued = false;
        for (id, pending) in &mut self.sync_pending {
            let permission = (pending.request.gate)();
            if pending.request.exp <= now || permission == Some(false) {
                for transport in [pending.transport.take(), pending.pn_copy.take()].into_iter().flatten() {
                    if let Ok(output) = router.cancel(core, &transport) { out.merge(output.core); }
                }
                remove.push(id.clone());
                continue;
            }
            // Копия на PN: прямая доставка без ACK дольше PN_FALLBACK_SECS, адресат заберёт письмо при подключении.
            // Принятое PN письмо может быть вытеснено или потеряно, а спросить об этом PN нельзя: пока нет ACK адресата,
            // копия повторяется через другой PN с растущей паузой (60 с … 30 мин), не больше PN_MAX_COPIES.
            if !pending.request.ack && permission == Some(true) {
                if let Some(copy) = pending.pn_copy {
                    let age = now.saturating_sub(pending.pn_since);
                    let queued = router.outbound().contains_key(&copy);
                    let lapse = if pending.pn_held { now >= pending.pn_retry_at }
                        else if queued { age >= PN_COPY_STUCK_SECS }
                        else { age >= PN_COPY_OUTCOME_SECS };
                    if lapse {
                        if queued { if let Ok(output) = router.cancel(core, &copy) { out.merge(output.core); } }
                        if let Some(node) = pending.pn_node { self.pn_health.strike(node, now); }
                        pending.pn_copy = None;
                        pending.pn_held = false;
                    }
                }
                let node = router.outbound_propagation_node();
                // PN в выдержке пропускается, пока есть другой; единственный PN используется снова после паузы
                let usable = node.is_some_and(|n| !self.pn_health.is_bad(&n, now)
                    || !self.pn_nodes.iter().any(|o| *o != n && !self.pn_health.is_bad(o, now)));
                if pending.pn_copy.is_none() && !pn_enqueued && usable && pending.pn_copies < PN_MAX_COPIES && now >= pending.pn_retry_at
                    && pending.first_try.is_some_and(|t| now.saturating_sub(t) >= PN_FALLBACK_SECS) {
                    if let Some(identity) = lxmf_sync::public_identity(&pending.request.pk) {
                        let destination = lxmf_destination(identity.hash());
                        core.remember_identity(DestinationHash::new(destination), identity);
                        if let Ok(message) = router.create_message(core, destination, pending.request.title.clone(), pending.request.content.clone(), Vec::new(), DeliveryMethod::Propagated) {
                            let copy = message.message_id;
                            if let Ok(output) = router.enqueue(core, message) {
                                outputs.push(output);
                                pending.pn_copy = Some(copy);
                                pending.pn_node = node;
                                pending.pn_since = now;
                                pending.pn_held = false;
                                pending.pn_copies += 1;
                                pending.pn_retry_at = now + PnHealth::copy_wait(pending.pn_copies);
                                pn_enqueued = true;
                            }
                        }
                    }
                }
            }
            if permission.is_none() || enqueued || pending.last_try.is_some_and(|t| now.saturating_sub(t) < 5) { continue; }
            // Повторы и бюджет незавершённой доставки принадлежат LXMF/RNS.
            // Прикладной retry не обрывает ещё идущий Resource/поиск пути.
            if pending.transport.is_some_and(|id| router.outbound().contains_key(&id)) { continue; }
            if let Some(transport) = pending.transport.take() {
                if let Ok(output) = router.cancel(core, &transport) { out.merge(output.core); }
            }
            let Some(identity) = lxmf_sync::public_identity(&pending.request.pk) else { remove.push(id.clone()); continue };
            let destination = lxmf_destination(identity.hash());
            core.remember_identity(DestinationHash::new(destination), identity);
            if let Ok(message) = router.create_message(core, destination, pending.request.title.clone(), pending.request.content.clone(), Vec::new(), DeliveryMethod::Direct) {
                let transport = message.message_id;
                let bytes = message.pack().len() as u64;
                if let Ok(output) = router.enqueue(core, message) {
                    lxmf_sync::TX_BYTES.fetch_add(bytes, Ordering::Relaxed);
                    lxmf_sync::TX_MESSAGES.fetch_add(1, Ordering::Relaxed);
                    if let Ok(wire) = serde_json::from_slice::<serde_json::Value>(&pending.request.content) {
                        let n = wire["policies"].as_array().map_or(0, |p| p.len()) as u64;
                        super::POL_TX.fetch_add(n * crate::trust::POL_LEN as u64, Ordering::Relaxed);
                        super::POL_TX_N.fetch_add(n, Ordering::Relaxed);
                    }
                    out.merge(output.core);
                    pending.transport = Some(transport);
                    if pending.request.ack { remove.push(id.clone()); }
                }
            }
            pending.last_try = Some(now);
            pending.first_try.get_or_insert(now);
            enqueued = true;
        }
        for id in remove { self.sync_pending.remove(&id); }
    }
}

impl CoreProcessor for AdminProcessor {
    fn on_event(&mut self, core: &mut StdNodeCore, event: &NodeEvent) -> TickOutput {
        let mut out = TickOutput::empty();
        self.process(core, &mut out, false);
        let mut state = std::mem::replace(&mut self.state, ProcessorState::Failed);
        if let ProcessorState::Ready { router, outbound_ids } = &mut state {
            if let Ok(output) = router.handle_event(core, event) { self.absorb(router, outbound_ids, core, output, &mut out); }
        }
        self.state = state;
        out
    }

    fn on_tick(&mut self, core: &mut StdNodeCore, _now_ms: u64) -> TickOutput {
        let mut out = TickOutput::empty();
        self.process(core, &mut out, true);
        out
    }
}

pub fn lxmf_destination(identity_hash: &[u8; 16]) -> [u8; 16] {
    *Destination::compute_destination_hash(&Destination::compute_name_hash("lxmf", &["delivery"]), identity_hash).as_bytes()
}

/// Не полагаться только на identity cache транспорта: полномочия привязаны к ключу из Trust.
pub(super) fn signed_by_trusted_source(message: &Message, pk: &crate::trust::Pk) -> bool {
    let Some(hash) = crate::trust::hash_of(pk) else { return false };
    if message.source_hash != lxmf_destination(&hash) { return false; }
    let Ok(source) = Identity::from_public_key_bytes(pk) else { return false };
    let Ok(checked) = Message::unpack(&message.pack(), None, Some(&source), DeliveryMethod::Direct) else { return false };
    checked.verification == Verification::Valid && checked.source_hash == message.source_hash
        && checked.destination_hash == message.destination_hash && checked.content == message.content
}

pub fn encode_request(request: &AdminWireRequest) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > MAX_ADMIN_CONTENT { bail!("admin request too large"); }
    Ok(bytes)
}

pub fn decode_request(message: &Message) -> Result<AdminWireRequest> {
    if message.verification != Verification::Valid || message.method != DeliveryMethod::Direct || message.content.len() > MAX_ADMIN_CONTENT {
        bail!("invalid LXMF direct message envelope");
    }
    let request: AdminWireRequest = serde_json::from_slice(&message.content).context("decode admin request")?;
    if request.v != 1 || request.requestid.len() != 32 || request.requestid.bytes().any(|b| !b.is_ascii_hexdigit())
        || request.scope != "NODE" { bail!("invalid admin request schema"); }
    Ok(request)
}

fn command_path(state: &Path, id: &str) -> PathBuf { admin_dir(state).join("client").join(format!("{id}.json")) }

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, max: u64) -> Result<T> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let meta = file.metadata()?;
    let euid = unsafe { libc::geteuid() };
    if !meta.is_file() || meta.len() > max || meta.mode() & 0o077 != 0 || (meta.uid() != 0 && meta.uid() != euid) {
        bail!("private admin record has invalid type, owner, size, or mode");
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max { bail!("private admin record exceeds limit"); }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    write_private_atomic(path, &serde_json::to_vec(value)? )
}

pub fn submit_from_cli(a: &super::AdminSubmitArgs) -> Result<serde_json::Value> {
    let state = &a.state;
    let runtime = client_runtime(state).ok_or_else(|| anyhow::anyhow!("unsupported_offline"))?;
    if !runtime.ready.load(Ordering::Acquire) { bail!("lxmf_runtime_not_ready"); }
    let target_dest: [u8;16] = super::unhex(&a.target).try_into().map_err(|_| anyhow::anyhow!("invalid_target"))?;
    let root: [u8;16] = super::unhex(&a.root).try_into().map_err(|_| anyhow::anyhow!("invalid_root"))?;
    let request_id: [u8;16] = super::unhex(&a.request_id).try_into().map_err(|_| anyhow::anyhow!("invalid_request_id"))?;
    if a.scope != "NODE" { bail!("scope_must_be_NODE"); }
    if !matches!(a.op.as_str(), "status.get" | "rights.grant" | "rights.revoke") { bail!("unsupported_operation"); }
    let identity = super::load_identity_strict(state)?;
    let trust = crate::trust::Trust::load(identity.clone(), state)?;
    let status_bytes = fs::read(state.join("status.json")).context("local status unavailable")?;
    if status_bytes.len() > 2 * 1024 * 1024 { bail!("local status snapshot exceeds limit"); }
    let status: serde_json::Value = serde_json::from_slice(&status_bytes).context("parse local status snapshot")?;
    let exit = status["exits"].as_array().and_then(|arr| arr.iter().find(|x| x["d"].as_str() == Some(&a.target))).ok_or_else(|| anyhow::anyhow!("target_not_in_authenticated_snapshot"))?;
    let target_identity: [u8;16] = super::unhex(exit["id"].as_str().unwrap_or("")).try_into().map_err(|_| anyhow::anyhow!("target_identity_unknown"))?;
    let target_pk = trust.public_key_in(&root, &target_identity).ok_or_else(|| anyhow::anyhow!("target_not_in_selected_root"))?;
    if super::dest_from_pub_tag(&target_pk, super::T13_TAG) != target_dest { bail!("target_identity_destination_mismatch"); }
    if a.op != "status.get" {
        let cached=authenticated_target_view(state,&a.target,&trust)?.ok_or_else(||anyhow::anyhow!("target_capability_unknown"))?;
        let reply=&cached["reply"];
        if super::now_ms() as u64/1000 > cached["seen"].as_u64().unwrap_or(0).saturating_add(600) { bail!("target_capability_stale"); }
        if reply["target_identity"].as_str()!=Some(&super::hex(&target_identity))
            || reply["authority"]["root"].as_str()!=Some(&super::hex(&root))
            || reply["capabilities"]["host_access"]!=true {
            if reply["capabilities"]["reason"].as_str()==Some("no_host_authority") { bail!("target_no_host_authority"); }
            bail!("target_host_access_unavailable");
        }
        let required = if a.op == "rights.grant" {"can_grant"} else {"can_revoke"};
        if reply["authority"][required]!=true { bail!("target_authority_changed"); }
    }
    let request_id_hex = super::hex(&request_id);
    let path = command_path(state, &request_id_hex);
    let now = super::now_ms() as u64 / 1000;
    if path.exists() {
        let mut old: ClientCommandRecord = read_json(&path, 32 * 1024)?;
        let same_action = old.target_destination == super::hex(&target_dest)
            && old.request.target_identity == super::hex(&target_identity)
            && old.request.root == super::hex(&root)
            && old.request.op == a.op
            && old.request.rights == a.rights.unwrap_or(0)
            && old.request.holder.as_deref() == a.holder.as_deref();
        if !same_action { bail!("request_id_conflict"); }
        if old.durable_ack { return Ok(serde_json::json!({"version":1,"accepted":true,"requestid":request_id_hex,"queued":false,"state":old.status})); }
        if old.request.exp <= now { bail!("expired"); }
        let content=encode_request(&old.request)?;
        match runtime.outbound.try_send(AdminOutbound { requestid:request_id_hex.clone(),destination:lxmf_destination(&target_identity),title:b"KnotHop admin v1".to_vec(),content,exp:old.request.exp }) {
            Ok(()) => { old.status="pending".into(); old.updated=now; write_json(&path,&old)?; return Ok(serde_json::json!({"version":1,"accepted":true,"requestid":request_id_hex,"queued":true,"state":"pending"})); }
            Err(_) => bail!("lxmf_send_queue_full"),
        }
    }
    let actor_hash = *identity.hash();
    let mine = trust.my_rights_in(&root);
    let (holder, host_record) = match a.op.as_str() {
        "status.get" => {
            if mine & (crate::trust::ADD | crate::trust::REMOVE | crate::trust::CONFIG) == 0 { bail!("no_status_authority"); }
            (Some(super::hex(&actor_hash)), None)
        }
        "rights.grant" | "rights.revoke" => {
            let rights = a.rights.unwrap_or(0);
            if rights & crate::trust::HOST_ACCESS == 0 || rights & !crate::trust::KNOWN != 0 { bail!("host_access_mask_must_include_64_and_known_bits_only"); }
            if a.op == "rights.revoke" && rights != crate::trust::HOST_ACCESS { bail!("host_access_revoke_mask_must_be_exactly_64"); }
            let holder_raw = super::unhex(a.holder.as_deref().ok_or_else(|| anyhow::anyhow!("invalid_holder"))?);
            let holder_hash: [u8;16] = holder_raw.try_into().map_err(|_| anyhow::anyhow!("invalid_holder"))?;
            let holder_pk = trust.public_key_in(&root, &holder_hash).ok_or_else(|| anyhow::anyhow!("holder_not_known_in_selected_root"))?;
            let allowed = a.op == "rights.grant";
            let need = if allowed { crate::trust::ADD } else { crate::trust::REMOVE };
            if mine & need == 0 { bail!("insufficient_scoped_authority"); }
            let rec = trust.sign_host_access(root, target_identity, holder_pk, allowed)?;
            (Some(super::hex(&holder_hash)), Some(super::hex(&rec.wire())))
        }
        _ => unreachable!(),
    };
    let exp = (super::now_ms() as u64 / 1000).saturating_add(ADMIN_TTL_SECS);
    let request = AdminWireRequest {
        v:1, requestid:super::hex(&request_id), target_identity:super::hex(&target_identity), root:super::hex(&root),
        scope:"NODE".into(), op:a.op.clone(), exp, holder, rights:a.rights.unwrap_or(0), host_record,
    };
    let content = encode_request(&request)?;
    let record = ClientCommandRecord {
        v:1, request:request.clone(), target_destination:super::hex(&target_dest),
        target_lxmf_destination:super::hex(&lxmf_destination(&target_identity)), target_public_key:super::hex(&target_pk),
        status:"pending".into(), durable_ack:false, result:None, authenticated_envelope:None, created:now, updated:now,
    };
    let path = command_path(state, &request.requestid);
    ensure_admin_dir(state)?;
    fs::create_dir_all(path.parent().unwrap())?;
    prune_client_journal(path.parent().unwrap(), now);
    if !path.exists() {
        let mut active=0usize;
        let mut bytes=0u64;
        if let Ok(entries)=fs::read_dir(path.parent().unwrap()) {
            for entry in entries.flatten() {
                if let Ok(meta)=entry.metadata() { bytes=bytes.saturating_add(meta.len()); }
                if let Ok(existing)=read_json::<ClientCommandRecord>(&entry.path(),32*1024) {
                    if !existing.durable_ack && existing.request.exp > now { active+=1; }
                }
            }
        }
        if active>=MAX_ADMIN_QUEUE || bytes>256*1024 { bail!("client_admin_queue_full"); }
    }
    if path.exists() {
        let old: ClientCommandRecord = read_json(&path, 32 * 1024)?;
        if serde_json::to_vec(&old.request)? != serde_json::to_vec(&request)? { bail!("request_id_conflict"); }
        if old.durable_ack { return Ok(serde_json::json!({"version":1,"accepted":true,"requestid":request.requestid,"queued":false,"state":old.status})); }
    } else {
        write_json(&path, &record)?;
    }
    match runtime.outbound.try_send(AdminOutbound { requestid:request.requestid.clone(), destination:lxmf_destination(&target_identity), title:b"KnotHop admin v1".to_vec(), content, exp:request.exp }) {
        Ok(()) => Ok(serde_json::json!({"version":1,"accepted":true,"requestid":request.requestid,"queued":true,"state":"pending"})),
        Err(_) => {
            let mut rejected = record;
            rejected.status = "rejected".into();
            rejected.result = Some(serde_json::json!({"code":"lxmf_send_queue_full"}));
            rejected.updated = now;
            write_json(&path, &rejected)?;
            Ok(serde_json::json!({"version":1,"accepted":false,"requestid":request.requestid,"queued":false,"rejected":"lxmf_send_queue_full"}))
        }
    }
}

fn prune_client_journal(dir:&Path,now:u64) {
    let Ok(entries)=fs::read_dir(dir) else {return};
    for entry in entries.flatten() {
        if let Ok(record)=read_json::<ClientCommandRecord>(&entry.path(),32*1024) {
            if record.request.exp.saturating_add(24*3600)<now { let _=fs::remove_file(entry.path()); }
        }
    }
}

pub fn status_json(state: &Path, request_id: &str) -> Result<serde_json::Value> {
    let path = command_path(state, request_id);
    if !path.exists() { return Ok(serde_json::json!({"version":1,"requestid":request_id,"state":"unknown","durable_ack":false,"result":null})); }
    let mut record: ClientCommandRecord = read_json(&path, 32 * 1024)?;
    if !record.durable_ack && record.request.exp <= super::now_ms() as u64 / 1000 {
        record.status="expired".into();
        record.updated=super::now_ms() as u64/1000;
        write_json(&path,&record)?;
    }
    Ok(serde_json::json!({"version":1,"requestid":request_id,"target":record.target_destination,"state":record.status,"durable_ack":record.durable_ack,"result":record.result}))
}

pub fn client_transport_event(state: &Path, event: TransportEvent) {
    let failed=matches!(&event,TransportEvent::Failed{..});
    let (requestid, status) = match event {
        TransportEvent::Delivered { requestid } => (requestid, "delivered"),
        TransportEvent::Failed { requestid } => (requestid, "pending"),
        TransportEvent::Expired { requestid } => (requestid, "expired"),
        TransportEvent::ReceiverUnavailable => return,
    };
    let path = command_path(state, &requestid);
    if let Ok(mut record) = read_json::<ClientCommandRecord>(&path, 32 * 1024) {
        // Транспортное событие не затирает окончательные недолговечные статусы (`unknown`, `rejected`): иначе
        // «delivered» вернул бы команду в повторную отправку.
        if !record.durable_ack && matches!(record.status.as_str(),"pending"|"delivered") {
            record.status = status.into();
            if failed { record.result=Some(serde_json::json!({"code":"direct_transport_retry"})); }
            record.updated = super::now_ms() as u64 / 1000;
            let _ = write_json(&path, &record);
        }
    }
}

/// Синхронный обработчик дисковых commit работает вне async-потока, но применяющий
/// права код может ставить задачи в уже существующий Tokio runtime.
fn spawn_runtime_worker(
    name: &str,
    operation: impl FnOnce() + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let handle = tokio::runtime::Handle::try_current()
        .map_err(|_| std::io::Error::other("LXMF worker requires an active Tokio runtime"))?;
    std::thread::Builder::new().name(name.into()).spawn(move || {
        let _runtime = handle.enter();
        operation();
    })
}

pub fn spawn_node_worker(runtime: AdminRuntime, ctx: Arc<super::NodeCtx>) {
    let state = ctx.state.clone();
    let reporter = ctx.clone();
    if let Err(error) = spawn_runtime_worker("knothop-lxmf-admin-node", move || {
        let AdminRuntime { inbound, outbound, transport_events, .. } = runtime;
        let mut global=std::collections::VecDeque::<std::time::Instant>::new();
        let mut per_actor=HashMap::<[u8;16],std::collections::VecDeque<std::time::Instant>>::new();
        loop {
            match inbound.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(message) => {
                    if message.title == super::enroll_net::TITLE {
                        super::enroll_net::on_lxmf(&state, &message);
                        ctx.enforce_rights();
                        continue;
                    }
                    if message.title == super::lxmf_sync::TITLE {
                        super::on_sync_node(&ctx, &message);
                        continue;
                    }
                    if !admin_rate_allowed(&ctx,&message,&mut global,&mut per_actor) { continue; }
                    if let Some(reply) = handle_node_message(&state, &ctx, &message) {
                        let content = serde_json::to_vec(&reply).unwrap_or_default();
                        if content.len() <= MAX_ADMIN_CONTENT {
                            let _ = outbound.try_send(AdminOutbound {
                                requestid: reply.requestid.clone(),
                                destination: message.source_hash,
                                title: b"KnotHop admin result".to_vec(),
                                content,
                                exp: (super::now_ms() as u64 / 1000).saturating_add(ADMIN_TTL_SECS),
                            });
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            while transport_events.try_recv().is_ok() {}
        }
    }) {
        reporter.sh.note(format!("не удалось запустить LXMF admin worker: {error}"));
    }
}

fn admin_rate_allowed(ctx:&Arc<super::NodeCtx>,message:&Message,global:&mut std::collections::VecDeque<std::time::Instant>,per_actor:&mut HashMap<[u8;16],std::collections::VecDeque<std::time::Instant>>)->bool {
    let Some(t) = &ctx.t13 else { return false };
    let actor = {
        let trust = t.trust.lock().unwrap();
        authorized_rate_actor(&trust, &ctx.my_id, message)
    };
    charge_admin_rate(actor, global, per_actor)
}

/// Знакомая identity без прав администратора не может занимать бюджет отзывов/настроек.
/// Это ранний фильтр; executor всё равно заново проверяет полномочия при применении.
fn authorized_rate_actor(trust: &crate::trust::Trust, me: &[u8;16], message: &Message) -> Option<[u8;16]> {
    let request = decode_request(message).ok()?;
    if message.destination_hash != lxmf_destination(me) || request.target_identity != super::hex(me) { return None; }
    // Срок проверяет executor, чтобы авторизованный клиент получил диагностику
    // expired/expiry_out_of_bounds, а не молчаливое истечение ожидания.
    let root: [u8;16] = super::unhex(&request.root).try_into().ok()?;
    if !trust.has_anchor(&root) { return None; }
    let pk = trust.identity_for_lxmf_source(&message.source_hash)?;
    if !signed_by_trusted_source(message, &pk) { return None; }
    let actor = crate::trust::hash_of(&pk)?;
    (trust.rights_in(&root, &actor) & (crate::trust::ADD | crate::trust::REMOVE | crate::trust::CONFIG) != 0).then_some(actor)
}

fn charge_admin_rate(actor: Option<[u8;16]>,global:&mut std::collections::VecDeque<std::time::Instant>,per_actor:&mut HashMap<[u8;16],std::collections::VecDeque<std::time::Instant>>)->bool {
    let Some(actor) = actor else { return false };
    let now=std::time::Instant::now();
    global.retain(|at|now.duration_since(*at)<std::time::Duration::from_secs(60));
    per_actor.retain(|_, recent| {
        recent.retain(|at| now.duration_since(*at) < std::time::Duration::from_secs(60));
        !recent.is_empty()
    });
    if global.len()>=60 { return false; }
    let recent=per_actor.entry(actor).or_default();
    if recent.len()>=10 {return false}
    global.push_back(now);recent.push_back(now);true
}

/// Журнал исполнителя: `server/<actor>/<requestid>.json`. Долговечные записи получают только авторизованные
/// администраторы (известная identity, принятый корень, ADD|REMOVE|CONFIG), поэтому поток чужих запросов
/// квоту законных команд не съедает. Лимиты ограничивают и одного актора, и число актор-каталогов, и всё вместе.
const MAX_JOURNAL_ACTORS: usize = 32;
const MAX_JOURNAL_PER_ACTOR: usize = 64;
const MAX_JOURNAL_TOTAL: usize = 2048;
const MAX_JOURNAL_SCAN: usize = 4096;
/// Запись старше этого возраста (по mtime) удаляется, читается она или нет. Запрос живёт не дольше
/// ADMIN_TTL_SECS и отвергается как просроченный, поэтому его повтор после удаления не исполнится заново.
const JOURNAL_PRUNE_SECS: u64 = 25 * 3600;
const JOURNAL_TMP_STALE_SECS: u64 = 600;

fn server_dir(state: &Path, actor: &str) -> PathBuf { admin_dir(state).join("server").join(actor) }
fn server_path(state: &Path, actor: &str, id: &str) -> PathBuf { server_dir(state, actor).join(format!("{id}.json")) }

#[derive(Serialize, Deserialize)]
struct ServerJournal { v:u8, digest:String, retain_until:u64, reply:AdminWireReply }

enum JournalEntry { Fresh, Stored(Box<ServerJournal>), Unreadable }

/// Нет файла - команда ещё не исполнялась. Файл есть, но не читается или не соответствует запросу - исход
/// неизвестен: исполнять заново нельзя, а остальные запросы это не затрагивает.
fn journal_entry(path: &Path, requestid: &str) -> JournalEntry {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => JournalEntry::Fresh,
        Err(_) => JournalEntry::Unreadable,
        Ok(_) => match read_json::<ServerJournal>(path, 32 * 1024) {
            Ok(j) if j.v == 1 && j.reply.requestid == requestid => JournalEntry::Stored(Box::new(j)),
            _ => JournalEntry::Unreadable,
        },
    }
}

fn file_age_secs(meta: &fs::Metadata) -> u64 {
    meta.modified().ok().and_then(|m| m.elapsed().ok()).map_or(0, |d| d.as_secs())
}

/// Чистит по возрасту (не удаляя то, что ещё нужно для идемпотентности) и проверяет, поместится ли
/// новая долговечная запись актора. Нечитаемые файлы считаются по имени: они занимают квоту, но не отключают журнал.
fn journal_has_slot(state: &Path, actor: &str) -> bool {
    let root = admin_dir(state).join("server");
    if fs::create_dir_all(&root).is_err() { return false; }
    let Ok(dirs) = fs::read_dir(&root) else { return false };
    let (mut total, mut mine, mut actors, mut mine_exists) = (0usize, 0usize, 0usize, false);
    for entry in dirs.flatten().take(MAX_JOURNAL_SCAN) {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else { continue };
        if !meta.is_dir() { continue; }
        let is_mine = entry.file_name().to_str() == Some(actor);
        let mut kept = 0usize;
        if let Ok(files) = fs::read_dir(&path) {
            for file in files.flatten().take(MAX_JOURNAL_SCAN) {
                let Ok(fmeta) = fs::symlink_metadata(file.path()) else { continue };
                let name = file.file_name();
                let tmp = name.to_string_lossy().contains(".tmp-");
                let age = file_age_secs(&fmeta);
                if age >= if tmp { JOURNAL_TMP_STALE_SECS } else { JOURNAL_PRUNE_SECS } {
                    let _ = fs::remove_file(file.path());
                } else if !tmp {
                    kept += 1;
                }
            }
        }
        // remove_dir не удалит каталог с живым temp-файлом
        if kept == 0 && !is_mine && fs::remove_dir(&path).is_ok() { continue; }
        actors += 1;
        total += kept;
        if is_mine { mine = kept; mine_exists = true; }
    }
    total < MAX_JOURNAL_TOTAL && mine < MAX_JOURNAL_PER_ACTOR && (mine_exists || actors < MAX_JOURNAL_ACTORS)
}

fn reply_base(request: &AdminWireRequest, target: &str, status: &str, durable: bool, code: Option<String>, revision: u64) -> AdminWireReply {
    AdminWireReply { v:1, requestid:request.requestid.clone(), target_identity:target.into(), root:request.root.clone(),
        state:status.into(), durable_ack:durable, code, revision, capabilities:None, authority:None, participants:None,
        record_committed:None, effective_host_allowed:None, changed:None }
}

/// Долговечный ответ сначала пишется в журнал, и только потом уходит; без записи ответа нет.
fn emit(reply: AdminWireReply, journal: Option<(&Path, &str, u64)>) -> Option<AdminWireReply> {
    if let Some((path, digest, exp)) = journal {
        let entry = ServerJournal { v:1, digest:digest.into(), retain_until:exp.saturating_add(24*3600), reply:reply.clone() };
        write_json(path, &entry).ok()?;
    }
    Some(reply)
}

struct Auth { rights:u16, host_allowed:bool, can_grant:bool, can_revoke:bool, single_root:bool }

/// Список участников раскрывается, только когда у ноды один сетевой корень и это выбранный актором корень.
/// Собственная identity ноды всегда лежит в якорях, поэтому она не считается сетевым корнем; иначе у любой
/// зачисленной ноды (собственная + админская) экспорт был бы выключен всегда.
fn participants_export_allowed(trust: &crate::trust::Trust, root: &[u8;16]) -> bool {
    let mut network = trust.anchors().into_iter().map(|(h, _)| h).filter(|h| *h != trust.me_hash);
    match (network.next(), network.next()) {
        (None, _) => *root == trust.me_hash,
        (Some(only), None) => only == *root,
        _ => false,
    }
}

fn actor_auth(trust: &crate::trust::Trust, root: &[u8;16], actor: &[u8;16], me: &[u8;16]) -> Auth {
    let rights = trust.rights_in(root, actor);
    let scoped = trust.has_host_authority(root, actor, me);
    Auth { rights, host_allowed: trust.host_root_allowed(root),
        can_grant: rights & crate::trust::ADD != 0 && scoped, can_revoke: rights & crate::trust::REMOVE != 0 && scoped,
        single_root: participants_export_allowed(trust, root) }
}

fn authority_json(root: &[u8;16], auth: &Auth) -> serde_json::Value {
    let mut v = serde_json::json!({
        "root":super::hex(root),"trusted":true,"scope":"NODE","rights":auth.rights,
        "can_status":auth.rights & (crate::trust::ADD|crate::trust::REMOVE|crate::trust::CONFIG) != 0,
        "can_grant":auth.can_grant,"can_revoke":auth.can_revoke,
        "grantable_rights":if auth.can_grant {crate::trust::HOST_ACCESS} else {0},
        "revocable_rights":if auth.can_revoke {crate::trust::HOST_ACCESS} else {0}
    });
    if !auth.host_allowed { v["reason"] = "NO_HOST_AUTHORITY".into(); }
    v
}

/// `host_access` включается только когда и ACL готов, и локальная политика узла разрешает этот корень.
fn capabilities_json(auth: &Auth, tun_ready: bool) -> serde_json::Value {
    let mut v = serde_json::json!({"host_access":tun_ready && auth.host_allowed,"admin_commands":true,"status_get":true,
        "participants_export":auth.single_root,"rights_grant":auth.can_grant,"rights_revoke":auth.can_revoke});
    if !auth.host_allowed { v["reason"] = "no_host_authority".into(); }
    v
}

type Verdict = std::result::Result<Prepared, (&'static str, String, bool)>;
struct Prepared { commit: Option<crate::trust::HostCommit>, holder_pk: crate::trust::Pk, before: bool }

/// Тот же union корней, который NodeCtx использует при выставлении per-Link HOST_ACCESS.
fn effective_host_allowed(trust: &crate::trust::Trust, holder: &crate::trust::Pk, target: &[u8;16]) -> bool {
    !trust.host_access_roots(holder, target).is_empty()
}

fn mutation_effect(reply: &mut AdminWireReply, before: bool, after: bool, want_allow: bool) {
    reply.record_committed = Some(true);
    reply.effective_host_allowed = Some(after);
    reply.changed = Some(after != before);
    if after != want_allow { reply.code = Some("record_committed_not_effective".into()); }
}

fn request_expiry_error(exp: u64, now: u64) -> Option<&'static str> {
    if exp < now { Some("expired") }
    else if exp > now.saturating_add(ADMIN_TTL_SECS + ADMIN_CLOCK_SKEW_SECS) { Some("expiry_out_of_bounds") }
    else { None }
}

fn host_grant_matches_snapshot(requested: u16, current: u16) -> bool {
    use crate::trust::{HOST_ACCESS, KNOWN};
    requested & HOST_ACCESS != 0 && requested & !KNOWN == 0
        // Ровно 64 — отдельная scoped-операция; обычные права не запрашиваются и не меняются.
        && (requested == HOST_ACCESS || requested & !HOST_ACCESS == current)
}

fn handle_node_message(state: &Path, ctx: &Arc<super::NodeCtx>, message: &Message) -> Option<AdminWireReply> {
    use crate::trust::{HostAccessRecord, HostCommitError, HOST_ACCESS, KNOWN};
    let request = decode_request(message).ok()?;
    if message.destination_hash != lxmf_destination(&ctx.my_id) { return None; }
    let root: [u8;16] = super::unhex(&request.root).try_into().ok()?;
    let target: [u8;16] = super::unhex(&request.target_identity).try_into().ok()?;
    let t13 = ctx.t13.as_ref()?;
    let actor_pk = {
        let trust = t13.trust.lock().unwrap();
        trust.identity_for_lxmf_source(&message.source_hash)?
    };
    let actor_hash = crate::trust::hash_of(&actor_pk)?;
    if !signed_by_trusted_source(message, &actor_pk) { return None; }
    let actor_hex = super::hex(&actor_hash);
    let local_target = super::hex(&ctx.my_id);
    let digest = super::hex(&Sha256::digest(&message.content));
    let path = server_path(state, &actor_hex, &request.requestid);
    let now = super::now_ms() as u64 / 1000;
    let plain = |status: &str, code: &str| Some(reply_base(&request, &local_target, status, false, Some(code.into()), 0));

    match journal_entry(&path, &request.requestid) {
        JournalEntry::Stored(stored) => {
            if stored.digest == digest { return Some(stored.reply); }
            // Строка `(actor, requestid)` доказывает, что идентификатор уже занят: детерминированный отказ безопасен при повторе.
            return Some(reply_base(&request, &local_target, "rejected", true, Some("request_id_conflict".into()), 0));
        }
        // Результат этой команды неизвестен: не исполнять заново и не гадать. Остальные запросы продолжают работать.
        JournalEntry::Unreadable => return plain("unknown", "journal_unreadable"),
        JournalEntry::Fresh => {}
    }

    // До авторизации ничего долговечного не пишем: такие отказы уходят без записи в журнал.
    if request.target_identity != local_target || target != ctx.my_id { return plain("rejected", "wrong_target_or_scope"); }
    if let Some(code) = request_expiry_error(request.exp, now) {
        return plain(if code == "expired" { "expired" } else { "rejected" }, code);
    }
    let tun_ready = ctx.tun.as_ref().is_some_and(|tun| tun.host_acl_ready());

    if request.op == "status.get" {
        // Только чтение: ответ окончательный, но в журнал (и в его квоту) не попадает; повтор безопасен.
        let trust = t13.trust.lock().unwrap();
        if !trust.has_anchor(&root) { return plain("rejected", "root_not_accepted"); }
        let auth = actor_auth(&trust, &root, &actor_hash, &ctx.my_id);
        if auth.rights & (crate::trust::ADD|crate::trust::REMOVE|crate::trust::CONFIG) == 0 {
            return plain("rejected", "unsupported_operation_or_authority");
        }
        let mut reply = reply_base(&request, &local_target, "applied", true, (!tun_ready).then(|| "host_acl_unavailable".into()), trust.host_access_revision(&root));
        reply.authority = Some(authority_json(&root, &auth));
        reply.capabilities = Some(capabilities_json(&auth, tun_ready));
        reply.participants = auth.single_root.then(|| trust.participants_in_root(&root, 12).into_iter().map(|(holder, rights)| {
            let host_access = trust.public_key_in(&root, &holder).is_some_and(|pk| trust.host_access_roots(&pk, &trust.me_hash).contains(&root));
            serde_json::json!({"holder":super::hex(&holder),"rights":rights,"host_access":host_access})
        }).collect());
        return Some(reply);
    }
    if !matches!(request.op.as_str(), "rights.grant" | "rights.revoke") {
        return plain("rejected", "unsupported_operation_or_authority");
    }

    // Нужна авторизация, чтобы вообще занять долговечную запись.
    {
        let trust = t13.trust.lock().unwrap();
        if !trust.has_anchor(&root) { return plain("rejected", "root_not_accepted"); }
        let auth = actor_auth(&trust, &root, &actor_hash, &ctx.my_id);
        if auth.rights & (crate::trust::ADD|crate::trust::REMOVE|crate::trust::CONFIG) == 0 {
            return plain("rejected", "unsupported_operation_or_authority");
        }
    }
    if !journal_has_slot(state, &actor_hex) { return plain("rejected", "journal_quota_exceeded"); }
    let journal = (path.as_path(), digest.as_str(), request.exp);

    let want_allow = request.op == "rights.grant";
    let raw = request.host_record.as_deref().map(super::unhex);

    // Решение принимается под блокировкой trust, но без диска: там только проверки и подготовка байт.
    let (auth, revision, verdict) = {
        let trust = t13.trust.lock().unwrap();
        let auth = actor_auth(&trust, &root, &actor_hash, &ctx.my_id);
        let revision = trust.host_access_revision(&root);
        let verdict: Verdict = (|| -> Verdict {
            let Some(raw) = raw.as_deref() else { return Err(("rejected", "missing_host_record".into(), true)) };
            let Some(rec) = HostAccessRecord::parse(raw) else { return Err(("rejected", "invalid_host_record".into(), true)) };
            let expected = if want_allow { HOST_ACCESS } else { 0 };
            let holder = request.holder.as_deref().and_then(|h| <Result<[u8;16],_>>::from(super::unhex(h).try_into()).ok());
            if rec.root != root || rec.scope != ctx.my_id || rec.issuer != actor_hash || rec.rights != expected
                || request.rights & HOST_ACCESS == 0 || request.rights & !KNOWN != 0
                || request.op == "rights.revoke" && request.rights != HOST_ACCESS
                || holder != Some(rec.hh) {
                return Err(("rejected", "host_record_binding_mismatch".into(), true));
            }
            if !auth.host_allowed { return Err(("rejected", "no_host_authority".into(), true)); }
            // Временные сбои не журналируются, чтобы тот же requestid можно было повторить.
            if !tun_ready { return Err(("rejected", "host_acl_unavailable".into(), false)); }
            // Полномочия актора проверяются заново ДО ветки восстановления: право, отозванное после первой попытки, возврата не даёт.
            if want_allow && !auth.can_grant || !want_allow && !auth.can_revoke {
                return Err(("rejected", "authority_insufficient".into(), true));
            }
            if want_allow && !host_grant_matches_snapshot(request.rights, trust.rights_in(&root, &rec.hh)) {
                return Err(("stale", "stale_rights_snapshot".into(), true));
            }
            let Some(holder_pk) = trust.public_key_in(&root, &rec.hh) else { return Err(("rejected", "holder_not_known".into(), true)) };
            let before = effective_host_allowed(&trust, &holder_pk, &ctx.my_id);
            let commit = if trust.has_host_record(&rec) {
                // Восстановление: запись легла на диск, а журнал результата не успел записаться.
                None
            } else {
                match trust.prepare_host_access(&rec) {
                    Ok(commit) => Some(commit),
                    Err(HostCommitError::Rejected(why)) => return Err(("rejected", why.into(), true)),
                    Err(HostCommitError::Stale) => return Err(("stale", "stale_host_record".into(), true)),
                    Err(HostCommitError::Io) => return Err(("rejected", "host_commit_failed".into(), false)),
                }
            };
            Ok(Prepared { commit, holder_pk, before })
        })();
        (auth, revision, verdict)
    };
    let authority = authority_json(&root, &auth);
    let mut reply = reply_base(&request, &local_target, "applied", true, None, revision);
    reply.authority = Some(authority);
    reply.capabilities = Some(capabilities_json(&auth, tun_ready));
    let prepared = match verdict {
        Ok(p) => p,
        Err((status, code, durable)) => {
            reply.state = status.into();
            reply.code = Some(code);
            reply.durable_ack = durable;
            return emit(reply, durable.then_some(journal));
        }
    };
    let transient = |mut reply: AdminWireReply| {
        reply.state = "rejected".into();
        reply.code = Some("host_commit_failed".into());
        reply.durable_ack = false;
        Some(reply)
    };
    if let Some(commit) = prepared.commit {
        // Снимок проверяется под commit gate ДО записи; fsync выполняется без блокировки trust.
        // Успешная запись всегда согласуется с памятью, Stale после записи больше невозможен.
        if commit.commit(&t13.trust).is_err() { return transient(reply); }
    }
    // Ответ о применении идёт только после того, как действующие Link приведены в соответствие новым правам.
    ctx.enforce_rights();
    let (after, revision_now) = {
        let trust = t13.trust.lock().unwrap();
        (effective_host_allowed(&trust, &prepared.holder_pk, &ctx.my_id), trust.host_access_revision(&root))
    };
    reply.revision = revision_now;
    // Не только выбранный root: другой разрешённый корень также может сохранять доступ.
    mutation_effect(&mut reply, prepared.before, after, want_allow);
    emit(reply, Some(journal))
}
pub fn spawn_client_worker(runtime: AdminRuntime, ctx: Arc<super::ClientCtx>, trust: Arc<Mutex<crate::trust::Trust>>) {
    // Поток держит клиента только слабой ссылкой: `ClientCtx` владеет узлом, узел владеет процессором, а процессор - отправителем `inbound`,
    // на котором поток ждёт. Сильная ссылка замыкала бы цикл: после остановки VPN узел и дубликат дескриптора TUN жили бы до конца процесса.
    let (state, identity, ctx) = (ctx.state.clone(), ctx.identity.clone(), Arc::downgrade(&ctx));
    spawn_runtime_worker("knothop-lxmf-admin-client", move || {
        let AdminRuntime { inbound, outbound, transport_events, .. } = runtime;
        requeue_pending(&state,&outbound);
        let mut retry_after=std::time::Instant::now()+std::time::Duration::from_secs(5);
        loop {
            if ctx.strong_count() == 0 { break; }
            match inbound.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(message) => {
                    let Some(ctx) = ctx.upgrade() else { break };
                    if message.title == super::enroll_net::TITLE {
                        super::enroll_net::on_lxmf(&state, &message); ctx.refresh_servers13(); super::start_dialers(&ctx);
                    }
                    else if message.title == super::lxmf_sync::TITLE { super::on_sync_client(&ctx, &message); }
                    else { handle_client_reply(&state, &identity, &trust, &message); }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            while let Ok(event) = transport_events.try_recv() { client_transport_event(&state, event); }
            if std::time::Instant::now()>=retry_after {
                retry_delivered(&state,&outbound);
                retry_after=std::time::Instant::now()+std::time::Duration::from_secs(5);
            }
        }
    }).ok();
}

fn requeue_pending(state:&Path,outbound:&SyncSender<AdminOutbound>) {
    let dir=admin_dir(state).join("client");
    let Ok(entries)=fs::read_dir(&dir) else {return};
    let now=super::now_ms() as u64/1000;
    for entry in entries.flatten().take(MAX_ADMIN_QUEUE) {
        let Ok(mut record)=read_json::<ClientCommandRecord>(&entry.path(),32*1024) else {continue};
        if record.durable_ack || !matches!(record.status.as_str(),"pending"|"delivered") {continue}
        if record.request.exp<=now {
            record.status="expired".into(); record.updated=now; let _=write_json(&entry.path(),&record); continue;
        }
        let Ok(target)=<Result<[u8;16],_>>::from(super::unhex(&record.request.target_identity).try_into()) else {continue};
        let Ok(content)=encode_request(&record.request) else {continue};
        if outbound.try_send(AdminOutbound { requestid:record.request.requestid.clone(),destination:lxmf_destination(&target),title:b"KnotHop admin v1".to_vec(),content,exp:record.request.exp }).is_ok() {
            record.status="pending".into(); record.updated=now; let _=write_json(&entry.path(),&record);
        }
    }
}

fn retry_delivered(state:&Path,outbound:&SyncSender<AdminOutbound>) {
    let dir=admin_dir(state).join("client");
    let Ok(entries)=fs::read_dir(&dir) else {return};
    let now=super::now_ms() as u64/1000;
    for entry in entries.flatten().take(MAX_ADMIN_QUEUE) {
        let Ok(mut record)=read_json::<ClientCommandRecord>(&entry.path(),32*1024) else {continue};
        let retry_failed=record.result.as_ref().and_then(|v|v["code"].as_str())==Some("direct_transport_retry");
        if record.durable_ack || !(record.status=="delivered" || retry_failed) {continue}
        if record.request.exp<=now {record.status="expired".into();record.updated=now;let _=write_json(&entry.path(),&record);continue}
        if now.saturating_sub(record.updated)<5 {continue}
        let Ok(target)=<Result<[u8;16],_>>::from(super::unhex(&record.request.target_identity).try_into()) else {continue};
        let Ok(content)=encode_request(&record.request) else {continue};
        if outbound.try_send(AdminOutbound {requestid:record.request.requestid.clone(),destination:lxmf_destination(&target),title:b"KnotHop admin v1".to_vec(),content,exp:record.request.exp}).is_ok() {
            record.status="pending".into();record.result=None;record.updated=now;let _=write_json(&entry.path(),&record);
        }
    }
}

/// Статус команды у клиента по ответу узла и признак долговечного подтверждения.
fn client_status(op:&str,reply:&AdminWireReply)->(String,bool) {
    if reply.durable_ack && matches!(reply.state.as_str(),"applied"|"rejected"|"stale"|"expired") {
        // Запись сохранена, но действующее решение не совпало с намерением команды: не «применено».
        let wanted=op=="rights.grant";
        let not_effective=matches!(op,"rights.grant"|"rights.revoke")
            && (reply.code.as_deref()==Some("record_committed_not_effective") || reply.effective_host_allowed.is_some_and(|e|e!=wanted));
        if reply.state=="applied" && not_effective { return ("applied_not_effective".into(),true); }
        (reply.state.clone(),true)
    } else if reply.state=="unknown" && !reply.durable_ack {
        // Исход неизвестен: автоматического повтора нет, решение остаётся за оператором.
        ("unknown".into(),false)
    } else { ("rejected".into(),false) }
}

fn handle_client_reply(state:&Path, identity:&Identity, trust:&Mutex<crate::trust::Trust>, message:&Message) {
    if message.verification != Verification::Valid || message.method != DeliveryMethod::Direct || message.content.len()>MAX_ADMIN_CONTENT { return; }
    if message.destination_hash!=lxmf_destination(identity.hash()) { return; }
    let Ok(reply)=serde_json::from_slice::<AdminWireReply>(&message.content) else { return };
    let path=command_path(state,&reply.requestid);
    let Ok(mut command)=read_json::<ClientCommandRecord>(&path,32*1024) else { return };
    if command.request.requestid!=reply.requestid || command.request.root!=reply.root || command.request.target_identity!=reply.target_identity { return; }
    let Ok(target_hash)=<Result<[u8;16],_>>::from(super::unhex(&reply.target_identity).try_into()) else { return };
    if command.target_lxmf_destination!=super::hex(&message.source_hash) { return; }
    let Some(pk)=trust.lock().unwrap().identity_for_lxmf_source(&message.source_hash) else { return };
    if crate::trust::hash_of(&pk)!=Some(target_hash) || !signed_by_trusted_source(message, &pk) { return; }
    // Окончательный долговечный итог не перезаписывается повторным или запоздавшим ответом.
    if command.durable_ack { return; }
    let (status,durable)=client_status(&command.request.op,&reply);
    command.status=status;
    command.durable_ack=durable;
    command.result=serde_json::to_value(&reply).ok();
    command.authenticated_envelope=Some(super::hex(&message.pack()));
    command.updated=super::now_ms() as u64/1000;
    let _=write_json(&path,&command);
    let _=identity;
}

pub fn authenticated_target_view(state:&Path,target:&str,trust:&crate::trust::Trust)->Result<Option<serde_json::Value>> {
    let dir=admin_dir(state).join("client");
    let target_id: Option<[u8;16]>=std::fs::read(state.join("status.json")).ok().and_then(|b|serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v|v["exits"].as_array().and_then(|xs|xs.iter().find(|x|x["d"].as_str()==Some(target)).and_then(|x|x["id"].as_str().map(str::to_string))))
        .and_then(|s|super::unhex(&s).try_into().ok());
    let Some(target_id)=target_id else {return Ok(None)};
    let mut best: Option<ClientCommandRecord>=None;
    if let Ok(rd)=fs::read_dir(dir) {
        for entry in rd.flatten().take(128) {
            let Ok(record)=read_json::<ClientCommandRecord>(&entry.path(),32*1024) else {continue};
            if record.request.op!="status.get" || !record.durable_ack || record.request.target_identity!=super::hex(&target_id) {continue}
            if best.as_ref().is_none_or(|b|record.updated>b.updated) {best=Some(record)}
        }
    }
    let Some(record)=best else {return Ok(None)};
    let Some(wire)=record.authenticated_envelope.as_deref().map(super::unhex) else {return Ok(None)};
    let root: [u8;16]=super::unhex(&record.request.root).try_into().map_err(|_|anyhow::anyhow!("cached root malformed"))?;
    let target_hash: [u8;16]=super::unhex(&record.request.target_identity).try_into().map_err(|_|anyhow::anyhow!("cached target malformed"))?;
    let Some(pk)=trust.public_key_in(&root,&target_hash) else {return Ok(None)};
    if super::dest_from_pub_tag(&pk,super::T13_TAG)!=super::dest32(target).unwrap_or([0;16]) {return Ok(None)}
    let source=Identity::from_public_key_bytes(&pk).map_err(|_|anyhow::anyhow!("cached target identity malformed"))?;
    let message=Message::unpack(&wire,None,Some(&source),DeliveryMethod::Direct).map_err(|_|anyhow::anyhow!("cached admin reply signature invalid"))?;
    if message.verification!=Verification::Valid || message.source_hash!=lxmf_destination(&target_hash) || message.content.len()>MAX_ADMIN_CONTENT {return Ok(None)}
    let reply: AdminWireReply=serde_json::from_slice(&message.content).map_err(|_|anyhow::anyhow!("cached admin reply malformed"))?;
    if reply.requestid!=record.request.requestid || reply.target_identity!=record.request.target_identity || reply.root!=record.request.root || !reply.durable_ack || reply.state!="applied" {return Ok(None)}
    Ok(Some(serde_json::json!({"reply":reply,"seen":record.updated})))
}

pub fn commands_for_target(state:&Path,target:&str)->Vec<serde_json::Value> {
    let mut out=Vec::new();
    if let Ok(rd)=fs::read_dir(admin_dir(state).join("client")) {
        for entry in rd.flatten().take(128) {
            let Ok(record)=read_json::<ClientCommandRecord>(&entry.path(),32*1024) else {continue};
            if record.target_destination==target {
                out.push(serde_json::json!({"requestid":record.request.requestid,"op":record.request.op,"state":record.status,"durable_ack":record.durable_ack,"updated":record.updated,"result":record.result}));
            }
        }
    }
    out.sort_by_key(|v|std::cmp::Reverse(v["updated"].as_u64().unwrap_or(0)));
    out.truncate(32);
    out
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCommandRecord {
    pub v: u8,
    pub request: AdminWireRequest,
    pub target_destination: String,
    pub target_lxmf_destination: String,
    pub target_public_key: String,
    pub status: String,
    pub durable_ack: bool,
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub authenticated_envelope: Option<String>,
    pub created: u64,
    pub updated: u64,
}

pub fn admin_dir(state: &Path) -> PathBuf { state.join("admin") }

pub fn ensure_admin_dir(state: &Path) -> Result<PathBuf> {
    let dir = admin_dir(state);
    fs::create_dir_all(&dir).context("create admin state directory")?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).context("protect admin state directory")?;
    }
    Ok(dir)
}

pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("state path has no parent"))?;
    fs::create_dir_all(parent).context("create private state parent")?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).context("protect private state parent")?;
    }
    static TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let temp = path.with_extension(format!("tmp-{}-{}", std::process::id(), TEMP.fetch_add(1, Ordering::Relaxed)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file = options.open(&temp).context("create private temporary state")?;
    if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) { let _ = fs::remove_file(&temp); return Err(e).context("write private state"); }
    fs::rename(&temp, path).context("replace private state")?;
    #[cfg(unix)] if let Ok(dir) = fs::File::open(parent) { let _ = dir.sync_all(); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // PN этой сети выбираются только из ключей с эффективным TRANSIT; USE-держатель и чужая identity не дают PN
    #[test]
    fn pn_candidates_are_only_trusted_transit_holders() {
        use crate::trust;
        let me = leviculum_std::api::generate_identity();
        let (transit, user, stranger) = (leviculum_std::api::generate_identity(), leviculum_std::api::generate_identity(), leviculum_std::api::generate_identity());
        let mut tr = trust::Trust::new(me.clone(), None);
        tr.issue(*me.hash(), transit.public_key_bytes(), trust::TRANSIT).unwrap();
        tr.issue(*me.hash(), user.public_key_bytes(), trust::USE).unwrap();
        let shared = PnShared::default();
        assert!(shared.view(crate::now_ms() as u64).is_none(), "без источника Trust выбора нет");
        shared.set_source(Arc::new(Mutex::new(tr)));
        let view = shared.view(crate::now_ms() as u64).unwrap();
        let pn = |i: &Identity| DestinationHash::new(pn_destination(&i.public_key_bytes()).unwrap());
        assert_eq!(view.nodes, BTreeSet::from([pn(&transit)]));
        assert!(!view.nodes.contains(&pn(&user)) && !view.nodes.contains(&pn(&stranger)));
        // ключи сети для проверки подписи с PN: держатели и якоря, но не чужие
        assert!(view.keys.contains(&user.public_key_bytes()) && !view.keys.contains(&stranger.public_key_bytes()));
        // Trust занят: прежний выбор остаётся
        let busy = Arc::new(Mutex::new(trust::Trust::new(me.clone(), None)));
        shared.set_source(busy.clone());
        let _held = busy.lock().unwrap();
        assert!(shared.view(crate::now_ms() as u64).is_none());
    }
    use leviculum_std::api::generate_identity;

    fn pn(i: u8) -> DestinationHash { DestinationHash::new([i; 16]) }

    // PN, на котором письмо не подтвердилось, откладывается с растущей выдержкой; выбор уходит на другой PN
    #[test]
    fn pn_health_switches_to_another_node_and_backs_off() {
        let nodes = BTreeSet::from([pn(1), pn(2), pn(3)]);
        let mut health = PnHealth::default();
        let rank = |n: &DestinationHash| (false, n.as_bytes()[0]);
        assert_eq!(health.pick(&nodes, 100, rank), Some(pn(1)));
        health.strike(pn(1), 100);
        assert!(health.is_bad(&pn(1), 100) && !health.is_bad(&pn(2), 100));
        assert_eq!(health.pick(&nodes, 100, rank), Some(pn(2)));
        // выдержка растёт при повторных неудачах и ограничена
        let first = health.bad[&pn(1)].0 - 100;
        health.strike(pn(1), 100);
        assert!(health.bad[&pn(1)].0 - 100 > first);
        for _ in 0..20 { health.strike(pn(1), 100); }
        assert_eq!(health.bad[&pn(1)].0 - 100, PN_BACKOFF_MAX_SECS);
        // после выдержки узел снова доступен; удачная загрузка снимает неудачи
        assert!(!health.is_bad(&pn(1), 100 + PN_BACKOFF_MAX_SECS));
        health.forgive(&pn(1));
        assert!(!health.is_bad(&pn(1), 100));
    }

    // Все PN в выдержке: берётся тот, у кого она кончится раньше (письмо не остаётся без PN); один PN используется снова после паузы
    #[test]
    fn pn_health_falls_back_to_earliest_expiring_node() {
        let nodes = BTreeSet::from([pn(1), pn(2)]);
        let mut health = PnHealth::default();
        health.strike(pn(1), 100);
        health.strike(pn(2), 100);
        health.strike(pn(2), 100);
        let rank = |_: &DestinationHash| (false, 0);
        assert_eq!(health.pick(&nodes, 100, rank), Some(pn(1)));
        assert_eq!(health.pick(&BTreeSet::new(), 100, rank), None);
        // узлы, пропавшие из доверенных, и давно забытые неудачи вычищаются
        health.prune(100, &BTreeSet::from([pn(2)]));
        assert!(!health.bad.contains_key(&pn(1)) && health.bad.contains_key(&pn(2)));
        health.prune(100 + PN_BACKOFF_MAX_SECS * 4, &nodes);
        assert!(health.bad.is_empty());
    }

    // Пауза между копиями растёт 60, 120, 240 … и упирается в потолок: копий мало, а охват по времени большой
    #[test]
    fn pn_copy_schedule_grows_and_is_capped() {
        let waits: Vec<u64> = (1..=8).map(PnHealth::copy_wait).collect();
        assert!(waits.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(*waits.last().unwrap(), PN_BACKOFF_MAX_SECS);
        assert_eq!(waits[0], PN_BACKOFF_BASE_SECS);
        let total: u64 = (1..=PN_MAX_COPIES).map(PnHealth::copy_wait).sum();
        assert!(total >= PN_BACKOFF_MAX_SECS * 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn node_worker_can_schedule_revocation_and_process_next_operation() {
        let (sent, received) = tokio::sync::oneshot::channel();
        let worker = spawn_runtime_worker("knothop-lxmf-runtime-test", move || {
            // enforce_rights ставит закрытие Link через tokio::spawn. Без enter
            // обычный std-поток паникует до следующей операции и отправки ACK.
            let revoked = tokio::spawn(async { "revoked" });
            sent.send((revoked, "next operation processed")).unwrap();
        }).unwrap();
        let (revoked, next) = received.await.expect("воркер не паникует вне Tokio context");
        assert_eq!(revoked.await.unwrap(), "revoked");
        assert_eq!(next, "next operation processed");
        worker.join().unwrap();
    }

    #[test]
    fn node_worker_refuses_to_start_without_runtime() {
        let error = spawn_runtime_worker("knothop-lxmf-no-runtime-test", || {}).unwrap_err();
        assert!(error.to_string().contains("Tokio runtime"));
    }

    #[test]
    fn lxmf_delivery_hash_is_not_knothop_node_destination() {
        let identity=generate_identity();
        let pk=identity.public_key_bytes();
        let lxmf=lxmf_destination(identity.hash());
        let knot=super::super::dest_from_pub_tag(&pk,super::super::T13_TAG);
        assert_ne!(lxmf,knot,"LXMF delivery destination and KnotHop NODE target are different name-hash domains");
        assert_eq!(Destination::compute_destination_hash(&Destination::compute_name_hash("lxmf", &["delivery"]), identity.hash()).as_bytes(), &lxmf);
    }

    #[test]
    fn wire_codec_requires_explicit_node_scope_and_bounds_content() {
        let request=AdminWireRequest {v:1,requestid:"00".repeat(16),target_identity:"11".repeat(16),root:"22".repeat(16),scope:"NODE".into(),op:"status.get".into(),exp:123,holder:Some("33".repeat(16)),rights:0,host_record:None};
        let wire=encode_request(&request).unwrap();
        let message=Message::create([0;16],[0;16],&generate_identity(),1.0,b"a".to_vec(),wire,Vec::new(),DeliveryMethod::Direct).unwrap();
        assert_eq!(decode_request(&message).unwrap().scope,"NODE");
        let huge=AdminWireRequest {host_record:Some("ff".repeat(MAX_ADMIN_CONTENT)),..request};
        assert!(encode_request(&huge).is_err());
    }

    fn tmp_state(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("knothop-{tag}-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample_request(id: &str, op: &str) -> AdminWireRequest {
        AdminWireRequest { v: 1, requestid: id.into(), target_identity: "11".repeat(16), root: "22".repeat(16), scope: "NODE".into(),
            op: op.into(), exp: super::super::now_ms() as u64 / 1000 + 60, holder: None, rights: 0, host_record: None }
    }

    #[test]
    fn admin_expiry_tolerates_bounded_client_clock_skew_but_not_unbounded_lifetime() {
        let now = 10_000;
        assert_eq!(request_expiry_error(now + ADMIN_TTL_SECS, now), None);
        assert_eq!(request_expiry_error(now + ADMIN_TTL_SECS + 1, now), None);
        assert_eq!(request_expiry_error(now + ADMIN_TTL_SECS + ADMIN_CLOCK_SKEW_SECS, now), None);
        assert_eq!(request_expiry_error(now + ADMIN_TTL_SECS + ADMIN_CLOCK_SKEW_SECS + 1, now), Some("expiry_out_of_bounds"));
        assert_eq!(request_expiry_error(now - 1, now), Some("expired"));
    }

    #[test]
    fn standalone_host_grant_does_not_require_exporting_ordinary_rights() {
        use crate::trust::{HOST_ACCESS, USE, EXIT};
        assert!(host_grant_matches_snapshot(HOST_ACCESS, USE), "ручной holder без экспорта участников");
        assert!(host_grant_matches_snapshot(HOST_ACCESS, USE | EXIT));
        assert!(host_grant_matches_snapshot(HOST_ACCESS | USE, USE), "старый UI с полным снимком совместим");
        assert!(!host_grant_matches_snapshot(HOST_ACCESS | USE, USE | EXIT), "полный снимок по-прежнему проверяется");
        assert!(!host_grant_matches_snapshot(USE, USE));
        assert!(!host_grant_matches_snapshot(HOST_ACCESS | 128, USE));
    }

    #[test]
    fn direct_envelope_must_verify_with_the_trusted_actor_key() {
        let (actor, attacker) = (generate_identity(), generate_identity());
        let source = lxmf_destination(actor.hash());
        let request = sample_request(&"01".repeat(16), "status.get");
        let destination = lxmf_destination(&[1;16]);
        let genuine = Message::create(destination, source, &actor, 1.0, b"a".to_vec(),
            encode_request(&request).unwrap(), Vec::new(), DeliveryMethod::Direct).unwrap();
        assert!(signed_by_trusted_source(&genuine, &actor.public_key_bytes()));
        // Message::create помечает Valid даже если подпись сделана другим ключом:
        // такая метка сама по себе не доказывает соответствие ключу, известному Trust.
        let forged = Message::create(destination, source, &attacker, 1.0, b"a".to_vec(),
            encode_request(&request).unwrap(), Vec::new(), DeliveryMethod::Direct).unwrap();
        assert_eq!(forged.verification, Verification::Valid);
        assert!(!signed_by_trusted_source(&forged, &actor.public_key_bytes()));
        assert!(!signed_by_trusted_source(&forged, &attacker.public_key_bytes()), "даже валидная подпись не заменяет source binding");
    }

    #[test]
    fn known_non_admins_cannot_consume_administrative_rate_budget() {
        let node = generate_identity();
        let mut trust = crate::trust::Trust::new(node.clone(), None);
        let root = *node.hash();
        let admin = generate_identity();
        trust.issue(root, admin.public_key_bytes(), crate::trust::ADD | crate::trust::REMOVE).unwrap();
        let mut request = sample_request(&"01".repeat(16), "status.get");
        request.target_identity = super::super::hex(&root);
        request.root = super::super::hex(&root);
        let mut global = std::collections::VecDeque::new();
        let mut per_actor = HashMap::new();
        for _ in 0..6 {
            let user = generate_identity();
            trust.issue(root, user.public_key_bytes(), crate::trust::USE).unwrap();
            let message = Message::create(lxmf_destination(&root), lxmf_destination(user.hash()), &user,
                1.0, b"a".to_vec(), encode_request(&request).unwrap(), Vec::new(), DeliveryMethod::Direct).unwrap();
            for _ in 0..10 {
                assert!(!charge_admin_rate(authorized_rate_actor(&trust, &root, &message), &mut global, &mut per_actor));
            }
        }
        assert!(global.is_empty() && per_actor.is_empty());
        let mut message = Message::create(lxmf_destination(&root), lxmf_destination(admin.hash()), &admin,
            1.0, b"a".to_vec(), encode_request(&request).unwrap(), Vec::new(), DeliveryMethod::Direct).unwrap();
        assert!(charge_admin_rate(authorized_rate_actor(&trust, &root, &message), &mut global, &mut per_actor));
        // Известный админ своего корня не имеет прав в произвольном чужом root.
        request.root = "ff".repeat(16);
        message.content = encode_request(&request).unwrap();
        assert!(authorized_rate_actor(&trust, &root, &message).is_none());
        assert_eq!(global.len(), 1);
    }

    #[test]
    fn admin_rate_limit_still_bounds_authorized_actors_and_prunes_idle_entries() {
        let mut global = std::collections::VecDeque::new();
        let mut per_actor = HashMap::new();
        for actor in 0u8..6 {
            for _ in 0..10 { assert!(charge_admin_rate(Some([actor;16]), &mut global, &mut per_actor)); }
            assert!(!charge_admin_rate(Some([actor;16]), &mut global, &mut per_actor));
        }
        assert!(!charge_admin_rate(Some([7;16]), &mut global, &mut per_actor));
        assert_eq!(per_actor.len(), 6, "переполненный бюджет не создаёт пустых записей новых акторов");
        let old = std::time::Instant::now() - std::time::Duration::from_secs(61);
        for at in &mut global { *at = old; }
        for recent in per_actor.values_mut() { for at in recent { *at = old; } }
        assert!(charge_admin_rate(Some([7;16]), &mut global, &mut per_actor));
        assert_eq!(per_actor.len(), 1);
        assert_eq!(global.len(), 1);
    }

    #[test]
    fn revoke_ack_uses_union_of_roots_just_like_packet_authorization() {
        let (node, other_root, holder) = (generate_identity(), generate_identity(), generate_identity());
        let mut target = crate::trust::Trust::new(node.clone(), None);
        let root = *node.hash();
        target.issue(root, holder.public_key_bytes(), crate::trust::USE).unwrap();
        let mut other = crate::trust::Trust::new(other_root.clone(), None);
        target.add_anchor(&other_root.public_key_bytes()).unwrap();
        target.allow_host_root(*other_root.hash(), 8);
        target.offer(other.issue(*other_root.hash(), holder.public_key_bytes(), crate::trust::USE).unwrap());
        target.accept_host_access(target.sign_host_access(root, root, holder.public_key_bytes(), true).unwrap()).unwrap();
        target.accept_host_access(other.sign_host_access(*other_root.hash(), root, holder.public_key_bytes(), true).unwrap()).unwrap();
        let before = effective_host_allowed(&target, &holder.public_key_bytes(), &root);
        target.accept_host_access(target.sign_host_access(root, root, holder.public_key_bytes(), false).unwrap()).unwrap();
        assert!(!target.host_access_roots(&holder.public_key_bytes(), &root).contains(&root));
        let after = effective_host_allowed(&target, &holder.public_key_bytes(), &root);
        let mut reply = reply_base(&sample_request(&"01".repeat(16), "rights.revoke"), "t", "applied", true, None, 1);
        mutation_effect(&mut reply, before, after, false);
        assert_eq!(reply.record_committed, Some(true));
        assert_eq!(reply.effective_host_allowed, Some(true), "другой корень продолжает разрешать доступ");
        assert_eq!(reply.changed, Some(false));
        assert_eq!(client_status("rights.revoke", &reply).0, "applied_not_effective");
        target.accept_host_access(other.sign_host_access(*other_root.hash(), root, holder.public_key_bytes(), false).unwrap()).unwrap();
        let after_final = effective_host_allowed(&target, &holder.public_key_bytes(), &root);
        let mut final_reply = reply_base(&sample_request(&"02".repeat(16), "rights.revoke"), "t", "applied", true, None, 2);
        mutation_effect(&mut final_reply, after, after_final, false);
        assert_eq!(final_reply.effective_host_allowed, Some(false));
        assert_eq!(final_reply.changed, Some(true));
        assert_eq!(client_status("rights.revoke", &final_reply).0, "applied");
    }

    #[test]
    fn participants_export_counts_only_foreign_network_roots() {
        let (node, admin, second) = (generate_identity(), generate_identity(), generate_identity());
        let (own, admin_root, second_root) = (*node.hash(), *admin.hash(), *second.hash());
        let mut trust = crate::trust::Trust::new(node, None);
        assert!(participants_export_allowed(&trust, &own), "только собственный корень");
        assert!(!participants_export_allowed(&trust, &admin_root));
        trust.add_anchor(&admin.public_key_bytes()).unwrap();
        assert_eq!(trust.anchors().len(), 2, "собственная identity + один сетевой корень");
        assert!(participants_export_allowed(&trust, &admin_root), "own+1: список раскрывается");
        assert!(!participants_export_allowed(&trust, &own), "чужой корень не раскрывает список под собственным");
        assert!(!participants_export_allowed(&trust, &second_root), "корень, которого нет, не раскрывает");
        trust.add_anchor(&second.public_key_bytes()).unwrap();
        assert_eq!(trust.anchors().len(), 3);
        assert!(!participants_export_allowed(&trust, &admin_root), "own+2: приватность, список скрыт");
        assert!(!participants_export_allowed(&trust, &second_root));
    }

    fn set_age(path: &Path, secs: u64) {
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
        fs::OpenOptions::new().write(true).open(path).unwrap().set_modified(when).unwrap();
    }

    #[test]
    fn journal_quota_is_per_actor_and_a_bad_file_isolates_only_its_own_id() {
        let state = tmp_state("jquota");
        let (a, b) = ("aa".repeat(16), "bb".repeat(16));
        fs::create_dir_all(server_dir(&state, &a)).unwrap();
        for i in 0..MAX_JOURNAL_PER_ACTOR {
            fs::write(server_dir(&state, &a).join(format!("{i:032x}.json")), b"garbage").unwrap();
        }
        assert!(!journal_has_slot(&state, &a), "нечитаемые файлы занимают квоту своего актора по имени");
        assert!(journal_has_slot(&state, &b), "квота одного актора не отключает журнал другого");

        let bad = format!("{:032x}", 0);
        assert!(matches!(journal_entry(&server_path(&state, &a, &bad), &bad), JournalEntry::Unreadable), "битая запись: исход неизвестен, не пустая выдача");
        let fresh = format!("{:032x}", 99_999);
        assert!(matches!(journal_entry(&server_path(&state, &a, &fresh), &fresh), JournalEntry::Fresh), "остальные идентификаторы живы");

        let (ok_id, other_id) = ("cd".repeat(16), "ef".repeat(16));
        let path = server_path(&state, &b, &ok_id);
        let reply = reply_base(&sample_request(&ok_id, "rights.grant"), "t", "applied", true, None, 7);
        let emitted = emit(reply, Some((&path, "digest", 1))).unwrap();
        assert_eq!(emitted.revision, 7);
        match journal_entry(&path, &ok_id) {
            JournalEntry::Stored(j) => { assert_eq!(j.digest, "digest"); assert_eq!(j.reply.state, "applied"); }
            _ => panic!("записанный ответ должен читаться"),
        }
        assert!(matches!(journal_entry(&path, &other_id), JournalEntry::Unreadable), "запись с чужим requestid не принимается за результат");
        // правдоподобный по размеру файл с мусором внутри и правильным режимом: тоже только его id
        fs::write(server_dir(&state, &b).join(format!("{other_id}.json")), b"{not json").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(server_dir(&state, &b).join(format!("{other_id}.json")), fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(journal_entry(&server_path(&state, &b, &other_id), &other_id), JournalEntry::Unreadable));
        assert!(matches!(journal_entry(&path, &ok_id), JournalEntry::Stored(_)));
        fs::remove_dir_all(&state).unwrap();
    }

    #[test]
    fn journal_prunes_by_age_and_stale_temp_files_never_block() {
        let state = tmp_state("jprune");
        let actor = "cc".repeat(16);
        let dir = server_dir(&state, &actor);
        fs::create_dir_all(&dir).unwrap();
        let (old, fresh, tmp_old, tmp_new) = (dir.join("old.json"), dir.join("fresh.json"), dir.join("x.tmp-1-1"), dir.join("y.tmp-1-2"));
        for p in [&old, &fresh, &tmp_old, &tmp_new] { fs::write(p, b"x").unwrap(); }
        set_age(&old, JOURNAL_PRUNE_SECS + 60);
        set_age(&tmp_old, JOURNAL_TMP_STALE_SECS + 60);
        assert!(journal_has_slot(&state, &actor));
        assert!(!old.exists() && !tmp_old.exists(), "просроченные записи и брошенные temp удаляются");
        assert!(fresh.exists() && tmp_new.exists(), "свежая запись и живой temp остаются");
        fs::remove_dir_all(&state).unwrap();
    }

    #[test]
    fn journal_actor_directories_are_bounded_and_empty_ones_do_not_count() {
        let state = tmp_state("jactors");
        for i in 0..MAX_JOURNAL_ACTORS {
            let dir = server_dir(&state, &format!("{i:032x}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("a.json"), b"x").unwrap();
        }
        let newcomer = "ff".repeat(16);
        assert!(!journal_has_slot(&state, &newcomer), "число актор-каталогов ограничено");
        assert!(journal_has_slot(&state, &format!("{:032x}", 3)), "уже известный актор не теряет доступ");
        let empty = server_dir(&state, &"ee".repeat(16));
        fs::create_dir_all(&empty).unwrap();
        fs::remove_file(server_dir(&state, &format!("{:032x}", 5)).join("a.json")).unwrap();
        assert!(journal_has_slot(&state, &newcomer), "пустые каталоги чужих акторов убираются и места не занимают");
        assert!(!empty.exists());
        fs::remove_dir_all(&state).unwrap();
    }

    #[test]
    fn reply_codec_is_compatible_and_client_never_reports_ineffective_revoke_as_revoked() {
        let old = r#"{"v":1,"requestid":"a","target_identity":"b","root":"c","state":"applied","durable_ack":true,"code":null,"revision":0,"capabilities":null,"authority":null,"participants":null}"#;
        let parsed: AdminWireReply = serde_json::from_str(old).unwrap();
        assert!(parsed.effective_host_allowed.is_none() && parsed.record_committed.is_none() && parsed.changed.is_none());
        let encoded = serde_json::to_string(&parsed).unwrap();
        assert!(!encoded.contains("effective_host_allowed") && !encoded.contains("record_committed"), "старый формат не раздувается пустыми полями");

        let req = sample_request(&"01".repeat(16), "rights.revoke");
        let mut reply = reply_base(&req, "t", "applied", true, None, 1);
        assert_eq!(client_status("rights.revoke", &reply), ("applied".into(), true));
        reply.effective_host_allowed = Some(true);
        assert_eq!(client_status("rights.revoke", &reply), ("applied_not_effective".into(), true), "отзыв записан, но доступ действует");
        assert_eq!(client_status("rights.grant", &reply), ("applied".into(), true));
        reply.effective_host_allowed = Some(false);
        assert_eq!(client_status("rights.revoke", &reply), ("applied".into(), true));
        assert_eq!(client_status("rights.grant", &reply), ("applied_not_effective".into(), true), "выдача записана, но доступа нет");
        reply.effective_host_allowed = None;
        reply.code = Some("record_committed_not_effective".into());
        assert_eq!(client_status("rights.revoke", &reply).0, "applied_not_effective");
        assert_eq!(client_status("status.get", &reply).0, "applied", "status.get не затрагивается");

        let unknown = reply_base(&req, "t", "unknown", false, Some("journal_unreadable".into()), 0);
        assert_eq!(client_status("rights.grant", &unknown), ("unknown".into(), false), "исход неизвестен: без автоповтора и без долговечного итога");
        let transient = reply_base(&req, "t", "rejected", false, Some("host_commit_failed".into()), 0);
        assert_eq!(client_status("rights.grant", &transient), ("rejected".into(), false));
    }

    async fn wait_for<T>(timeout: std::time::Duration, mut poll: impl FnMut() -> Option<T>) -> Option<T> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if let Some(x) = poll() { return Some(x); }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        None
    }

    /// Local-only smoke: two in-process nodes on 127.0.0.1 (no public RNS, no
    /// pilot). Proves announce -> direct LXMF delivery -> reply -> Delivered
    /// through the real LxmfNode/LxmfRouter hooked as CoreProcessor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_direct_lxmf_request_reply_and_delivered_event() {
        use leviculum_std::api::NodeBuilder;
        let base = std::env::temp_dir().join(format!("knothop-lxmf-smoke-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let port = { let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); l.local_addr().unwrap().port() };
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let (id_a, id_b) = (generate_identity(), generate_identity());
        let (proc_a, rt_a) = AdminProcessor::new(id_a.clone());
        let (proc_b, rt_b) = AdminProcessor::new(id_b.clone());
        let mut node_a = NodeBuilder::new().identity(id_a.clone()).storage_path(base.join("a"))
            .enable_transport(true).add_tcp_server(addr).core_processor(proc_a).build().expect("build A");
        let mut node_b = NodeBuilder::new().identity(id_b.clone()).storage_path(base.join("b"))
            .enable_transport(false).add_tcp_client(addr).core_processor(proc_b).build().expect("build B");
        node_a.start().await.expect("start A");
        node_b.start().await.expect("start B");

        let step = std::time::Duration::from_secs(30);
        assert!(wait_for(step, || rt_a.ready.load(Ordering::Acquire).then_some(())).await.is_some(), "A LXMF processor not ready");
        assert!(wait_for(step, || rt_b.ready.load(Ordering::Acquire).then_some(())).await.is_some(), "B LXMF processor not ready");

        let exp = super::super::now_ms() as u64 / 1000 + 120;
        let request = AdminWireRequest { v: 1, requestid: "ab".repeat(16), target_identity: hex_of(id_a.hash()), root: "22".repeat(16),
            scope: "NODE".into(), op: "status.get".into(), exp, holder: None, rights: 0, host_record: None };
        let content = encode_request(&request).unwrap();
        // B -> A; resend until A answers, because announce propagation order is not controlled here
        let mut received = None;
        for attempt in 0..6u32 {
            rt_b.outbound.try_send(AdminOutbound { requestid: format!("{attempt:032x}"), destination: lxmf_destination(id_a.hash()),
                title: b"knothop".to_vec(), content: content.clone(), exp }).unwrap();
            received = wait_for(std::time::Duration::from_secs(10), || rt_a.inbound.try_recv().ok()).await;
            if received.is_some() { break; }
        }
        let message = received.expect("A did not receive the direct LXMF request from B (see test output for transport events)");
        assert_eq!(message.verification, Verification::Valid);
        assert_eq!(message.method, DeliveryMethod::Direct);
        assert_eq!(message.destination_hash, lxmf_destination(id_a.hash()));
        assert_eq!(message.source_hash, lxmf_destination(id_b.hash()), "LXMF source binds to B's identity");
        let decoded = decode_request(&message).expect("decode on A");
        assert_eq!(decoded.op, "status.get");

        // delivery proof reaches B as a transport event (transport ACK, not an app ACK)
        let mut delivered = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < deadline && !delivered {
            while let Ok(ev) = rt_b.transport_events.try_recv() { if matches!(ev, TransportEvent::Delivered { .. }) { delivered = true; } }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(delivered, "B got no TransportEvent::Delivered for the request");

        // reply A -> B
        let reply = AdminWireReply { v: 1, requestid: decoded.requestid.clone(), target_identity: decoded.target_identity.clone(), root: decoded.root.clone(),
            state: "applied".into(), durable_ack: true, code: None, revision: 0, capabilities: None, authority: None, participants: None,
            record_committed: None, effective_host_allowed: None, changed: None };
        rt_a.outbound.try_send(AdminOutbound { requestid: decoded.requestid.clone(), destination: message.source_hash, title: b"knothop".to_vec(),
            content: serde_json::to_vec(&reply).unwrap(), exp }).unwrap();
        let got = wait_for(std::time::Duration::from_secs(30), || rt_b.inbound.try_recv().ok()).await.expect("B did not receive the reply");
        assert_eq!(got.source_hash, lxmf_destination(id_a.hash()));
        let parsed: AdminWireReply = serde_json::from_slice(&got.content).unwrap();
        assert_eq!((parsed.state.as_str(), parsed.durable_ack), ("applied", true));

        node_b.stop().await.ok();
        node_a.stop().await.ok();
        let _ = std::fs::remove_dir_all(&base);
    }

    fn hex_of(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
}
