//! Служебный LXMF ноды (ADR 0028): доставка `node.inv/1` и `node.cmd/1` прямо и через PN, PN-клиент, повтор до прикладного ACK.
//!
//! Sans-I/O LXMF node/router работают в CoreProcessor внутри драйвера ReticulumNode. Прикладная работа и запись на диск —
//! в ограниченном воркере вне замка ядра (`spawn_worker`): один и тот же для сервера, ПК и телефона.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

use anyhow::{Context, Result, bail};
use leviculum_lxmf::router::{LxmfRouter, PropagationClientConfig, RouterConfig, RouterEvent, RouterOutput};
use leviculum_lxmf::{BuiltResource, CooperativeStamper, DeliveryMethod, LxmfNode, LxmfNodeConfig, Message, PendingResourceBuild, PropagationStampRequest, PropagationTransport, StampCancel, Verification, announce};
use leviculum_std::api::{CoreProcessor, Destination, DestinationHash, Identity, NodeEvent, StdNodeCore, TickOutput};

use crate::peers::Pk;

pub const MAX_ADMIN_CONTENT: usize = 8 * 1024;
pub const MAX_ADMIN_QUEUE: usize = 32;

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
/// Пересборка списка PN (доверенные + до 24 услышанных публичных) не чаще.
const PN_LIST_MS: u64 = 5_000;
/// Стоимость stamp, которую готовы майнить: чужой анонс не должен сжигать CPU (особенно телефона).
const PN_MAX_STAMP_COST: u8 = 16;
const PN_KEYS_MAX: usize = 256;

/// Кандидаты PN и ключи для проверки подписей (ADR 0028 §3.5). Анонс PN сам по себе не полномочие:
/// доверенные = контакты с ролью TRANSIT (сами объявили себя PN-серверами), публичные услышаны из анонсов RNS.
/// Публичные годятся только для служебных LXMF, VPN-данных через них нет.
#[derive(Default)]
pub struct PnShared {
    peers: Mutex<Option<Arc<Mutex<crate::peers::Peers>>>>,
}

pub struct PnView { pub nodes: BTreeSet<DestinationHash>, pub keys: Vec<Pk> }

impl PnShared {
    pub fn set_source(&self, peers: Arc<Mutex<crate::peers::Peers>>) { *self.peers.lock().unwrap() = Some(peers); }

    /// `None`, пока таблица занята: прежний выбор остаётся (без ожидания mutex в потоке ядра).
    fn view(&self) -> Option<PnView> {
        let source = self.peers.lock().ok()?.clone()?;
        let p = source.try_lock().ok()?;
        let nodes = p.contact_list().into_iter().filter(|c| c.roles & crate::peers::TRANSIT != 0).map(|c| c.pk)
            .filter_map(|pk| pn_destination(&pk)).map(DestinationHash::new).take(32).collect();
        let mut keys: Vec<Pk> = p.peer_list().into_iter().filter(|e| e.rights != 0).map(|e| e.pk).collect();
        keys.extend(p.contact_list().into_iter().map(|c| c.pk));
        keys.truncate(PN_KEYS_MAX);
        Some(PnView { nodes, keys })
    }
}

/// Назначение `lxmf.propagation` identity с ключом `pk`.
pub fn pn_destination(pk: &Pk) -> Option<[u8; 16]> {
    let hash = crate::peers::hash_of(pk)?;
    Some(*Destination::compute_destination_hash(&Destination::compute_name_hash("lxmf", &["propagation"]), &hash).as_bytes())
}

pub struct AdminRuntime {
    pub pn: Arc<PnShared>,
    pub inbound: Receiver<Message>,
    pub ready: Arc<AtomicBool>,
    pub sync: super::lxmf_sync::Sender,
}

pub struct AdminProcessor {
    identity: Identity,
    inbound: SyncSender<Message>,
    ready: Arc<AtomicBool>,
    resource_jobs: SyncSender<PendingResourceBuild>,
    resource_results: Receiver<ResourceBuildResult>,
    last_announce_ms: u64,
    /// Момент регистрации и число прогревочных повторов анонса (см. `ANNOUNCE_WARMUP_MS`).
    registered_ms: u64,
    warmup_done: usize,
    state: ProcessorState,
    sync: Receiver<super::lxmf_sync::Command>,
    sync_pending: HashMap<String, PendingSync>,
    pn: Arc<PnShared>,
    /// кандидаты PN: доверенные (контакты с ролью TRANSIT) ∪ публичные, услышанные из анонсов RNS (≤24); доверенные ранжируются раньше
    pn_nodes: BTreeSet<DestinationHash>,
    pn_trusted: BTreeSet<DestinationHash>,
    pn_checked_ms: u64,
    pn_list_ms: u64,
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
    /// число прямых попыток: пауза растёт 5 → 300 с (недоступный адресат не заваливает путь запросами)
    tries: u32,
}

impl PendingSync {
    fn new(request: super::lxmf_sync::Outbound) -> Self {
        Self { request, last_try: None, first_try: None, transport: None, pn_copy: None, pn_node: None, pn_since: 0, pn_held: false, pn_copies: 0, pn_retry_at: 0, tries: 0 }
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
    fn pick(&self, nodes: &BTreeSet<DestinationHash>, now: u64, rank: impl Fn(&DestinationHash) -> (bool, bool, u8)) -> Option<DestinationHash> {
        nodes.iter().filter(|n| !self.is_bad(n, now)).min_by_key(|n| (rank(n), **n)).copied()
            .or_else(|| nodes.iter().min_by_key(|n| (self.bad.get(*n).map_or(0, |b| b.0), **n)).copied())
    }
}

enum ResourceBuildResult { Ready(Box<BuiltResource>), Failed([u8;32]) }

enum ProcessorState {
    Unregistered,
    Ready {
        router: LxmfRouter,
    },
    Failed,
}


impl AdminProcessor {
    pub fn new(identity: Identity) -> (Self, AdminRuntime) {
        let (sync_tx, sync_rx) = mpsc::sync_channel(super::lxmf_sync::LIMIT);
        let (in_tx, in_rx) = mpsc::sync_channel(MAX_ADMIN_QUEUE);
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
            inbound: in_tx,
            ready: ready.clone(),
            resource_jobs:jobs_tx,
            resource_results:result_rx,
            last_announce_ms: 0,
            registered_ms: 0,
            warmup_done: 0,
            state: ProcessorState::Unregistered,
            sync: sync_rx,
            sync_pending: HashMap::new(),
            pn: pn.clone(),
            pn_nodes: BTreeSet::new(),
            pn_trusted: BTreeSet::new(),
            pn_checked_ms: 0,
            pn_list_ms: 0,
            pn_fetch_due: false,
            pn_health: PnHealth::default(),
            pn_outcomes: Vec::new(),
            last_fetch_ms: 0,
            fetch_ms: PN_FETCH_MS,
            stamp_jobs: stamp_tx,
            stamp_results: stamp_out_rx,
        };
        (processor, AdminRuntime { pn, inbound: in_rx, ready, sync:sync_tx })
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
            Ok(output) => self.absorb(&mut router, core, RouterOutput { core: output, events: Vec::new() }, out),
            Err(e) => bail!("announce LXMF delivery destination: {e:?}"),
        }
        self.ready.store(true, Ordering::Release);
        self.last_announce_ms = core.now_ms();
        self.registered_ms = self.last_announce_ms;
        Ok(ProcessorState::Ready { router })
    }

    fn absorb(&mut self, router: &mut LxmfRouter, core: &mut StdNodeCore, first: RouterOutput, out: &mut TickOutput) {
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
                        // Propagated - почта с PN сети. Приглашения и команды могут прийти от ещё не известного источника
                        // (подпись по ключу из тела проверяет обработчик); остальное не принимается.
                        let service = message.title == super::lxmf_sync::TITLE_INV || message.title == super::lxmf_sync::TITLE_CMD;
                        if !service || !matches!(message.method, DeliveryMethod::Direct | DeliveryMethod::Propagated) || message.content.len() > MAX_ADMIN_CONTENT {
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
                    ProcessorState::Failed
                }
            },
            other => other,
        };
        if run_scheduler {
            let mut outputs = Vec::new();
            if let ProcessorState::Ready { router } = &mut state {
                self.pn_tick(core, router, &mut outputs);
                self.sync_tick(core, router, out, &mut outputs);
                for result in self.resource_results.try_iter() {
                    match result {
                        ResourceBuildResult::Ready(built) => if let Ok(output)=router.commit_resource_build(core,*built) { outputs.push(output); },
                        ResourceBuildResult::Failed(_id) => {},
                    }
                }
            }
            if let ProcessorState::Ready { router } = &mut state {
                for output in outputs { self.absorb(router, core, output, out); }
                // Первый анонс уходит на первом тике, когда публичные интерфейсы RNS ещё не подключены, и дальше молчание
                // 600 с: адресат (админ, ждущий вступления сервера) недостижим. Поэтому в начале работы — несколько повторов.
                let now_ms = core.now_ms();
                let warm = ANNOUNCE_WARMUP_MS.get(self.warmup_done).is_some_and(|d| now_ms.saturating_sub(self.registered_ms) >= *d);
                if warm { self.warmup_done += 1; }
                if warm || now_ms.saturating_sub(self.last_announce_ms) >= 600_000 {
                    let data=announce::DeliveryAnnounce::new(None,None).map(|a|a.encode()).unwrap_or_default();
                    let dest=router.node().delivery_destination_hash();
                    if let Ok(output)=core.announce_destination(&dest,Some(&data)) { out.merge(output); }
                    self.last_announce_ms=core.now_ms();
                }
                if let Ok(output) = router.tick(core) { self.absorb(router, core, output, out); }
            }
        }
        self.state = state;
    }

    /// Выбор PN из доверенных серверов, stamp для загрузки на PN и выборка почты. Без новых таймеров: идёт в штатный tick.
    fn pn_tick(&mut self, core: &mut StdNodeCore, router: &mut LxmfRouter, outputs: &mut Vec<RouterOutput>) {
        let now = core.now_ms();
        if self.pn_checked_ms == 0 || now.saturating_sub(self.pn_checked_ms) >= PN_REFRESH_MS {
            if let Some(view) = self.pn.view() {
                self.pn_checked_ms = now.max(1);
                for pk in &view.keys {
                    if let Some(identity) = super::lxmf_sync::public_identity(pk) {
                        core.remember_identity(DestinationHash::new(lxmf_destination(identity.hash())), identity);
                    }
                }
                self.pn_trusted = view.nodes;
                self.pn_list_ms = 0;
            }
        }
        // публичные PN годятся только для служебных LXMF (шифротекст + stamp); их список ограничен, чужой анонс не вытесняет доверенных.
        // Пересборка — не чаще раза в PN_LIST_MS: обход всех известных PN публичной сети на каждом такте ядра стоил CPU
        // перегруженного выхода (fin1 10.11), а список меняется только с анонсами PN (раз в минуты).
        let wall = super::now_ms() as u64 / 1000;
        let first_public = self.pn_nodes.len() <= self.pn_trusted.len() && router.known_propagation_nodes().next().is_some();
        if self.pn_list_ms == 0 || first_public || now.saturating_sub(self.pn_list_ms) >= PN_LIST_MS {
            self.pn_list_ms = now.max(1);
            let own = DestinationHash::new(own_pn_destination(&self.identity));
            let public: Vec<DestinationHash> = router.known_propagation_nodes().map(|k| k.destination).filter(|n| *n != own && !self.pn_trusted.contains(n)).take(24).collect();
            self.pn_nodes = self.pn_trusted.iter().copied().chain(public).collect();
            self.pn_health.prune(wall, &self.pn_nodes);
        }
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
            let rank = |n: &DestinationHash| (!self.pn_trusted.contains(n), router.known_propagation_node(n).is_none(), core.hops_to(n).unwrap_or(u8::MAX));
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
                    let Some(dest) = request.target.destination() else { continue };
                    let id = format!("{}:{}", super::hex(&dest), request.tag);
                    if self.sync_pending.len() < lxmf_sync::LIMIT && !self.sync_pending.contains_key(&id) {
                        self.sync_pending.insert(id, PendingSync::new(request));
                    }
                }
                Command::Acknowledged { source, tag } => {
                    self.sync_pending.retain(|_, p| {
                        let matched = p.request.target.destination() == Some(source) && p.request.tag == tag;
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
                    if let Some(destination) = recipient(core, &pending.request.target) {
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
            if permission.is_none() || enqueued || pending.last_try.is_some_and(|t| now.saturating_sub(t) < (5u64 << pending.tries.min(6)).min(300)) { continue; }
            // Повторы и бюджет незавершённой доставки принадлежат LXMF/RNS.
            // Прикладной retry не обрывает ещё идущий Resource/поиск пути.
            if pending.transport.is_some_and(|id| router.outbound().contains_key(&id)) {
                continue;
            }
            if let Some(transport) = pending.transport.take() {
                if let Ok(output) = router.cancel(core, &transport) { out.merge(output.core); }
            }
            // Хеш из приглашения: ключ берётся из анонса RNS и обязан дать тот же хеш; пока анонса нет — ждём (не снимаем)
            let Some(destination) = recipient(core, &pending.request.target) else { remove.push(id.clone()); continue };
            // Новая нода ждёт анонс адресата в публичной RNS; не дожидаясь периода анонса (600 с), просим путь штатным запросом RNS
            // (адресат отвечает анонсом). Ядро ограничивает частоту запросов само.
            if !core.has_path(&DestinationHash::new(destination)) {
                out.merge(core.request_path(&DestinationHash::new(destination)));
            }
            // Служебные сообщения идут и через публичную RNS: чужие транспорты пропускают только стандартный CBC. Заголовки обеих
            // служебных групп обязаны быть в условии (пропуск уже ломал пилот); тело зашифровано LXMF на получателя и подписано.
            if pending.request.title == lxmf_sync::TITLE_INV || pending.request.title == lxmf_sync::TITLE_CMD {
                router.node_mut().use_cbc_links_to(DestinationHash::new(destination));
            }
            if let Ok(message) = router.create_message(core, destination, pending.request.title.clone(), pending.request.content.clone(), Vec::new(), DeliveryMethod::Direct) {
                let transport = message.message_id;
                let bytes = message.pack().len() as u64;
                if let Ok(output) = router.enqueue(core, message) {
                    lxmf_sync::TX_BYTES.fetch_add(bytes, Ordering::Relaxed);
                    lxmf_sync::TX_MESSAGES.fetch_add(1, Ordering::Relaxed);
                    out.merge(output.core);
                    pending.transport = Some(transport);
                    if pending.request.ack { remove.push(id.clone()); }
                }
            }
            pending.last_try = Some(now);
            pending.tries = pending.tries.saturating_add(1);
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
        if let ProcessorState::Ready { router } = &mut state {
            if let Ok(output) = router.handle_event(core, event) { self.absorb(router, core, output, &mut out); }
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

/// Адрес доставки получателя и, если известен полный ключ, его identity. По одному хешу identity берётся из кэша анонсов
/// самим роутером (`create_message` вернёт ошибку, пока анонса нет): destination hash криптографически привязан к ключу,
/// поэтому подмена ключа под известным хешем невозможна.
fn recipient(core: &mut StdNodeCore, t: &super::lxmf_sync::Target) -> Option<[u8; 16]> {
    let dest = t.destination()?;
    if let super::lxmf_sync::Target::Pk(pk) = t {
        core.remember_identity(DestinationHash::new(dest), super::lxmf_sync::public_identity(pk)?);
    }
    Some(dest)
}

fn own_pn_destination(identity: &Identity) -> [u8; 16] {
    *Destination::compute_destination_hash(&Destination::compute_name_hash("lxmf", &["propagation"]), identity.hash()).as_bytes()
}

pub fn lxmf_destination(identity_hash: &[u8; 16]) -> [u8; 16] {
    *Destination::compute_destination_hash(&Destination::compute_name_hash("lxmf", &["delivery"]), identity_hash).as_bytes()
}

/// Не полагаться только на identity cache транспорта: полномочия привязаны к ключу из Trust.
pub(super) fn signed_by_trusted_source(message: &Message, pk: &Pk) -> bool {
    let Some(hash) = crate::peers::hash_of(pk) else { return false };
    if message.source_hash != lxmf_destination(&hash) { return false; }
    let Ok(source) = Identity::from_public_key_bytes(pk) else { return false };
    let Ok(checked) = Message::unpack(&message.pack(), None, Some(&source), DeliveryMethod::Direct) else { return false };
    checked.verification == Verification::Valid && checked.source_hash == message.source_hash
        && checked.destination_hash == message.destination_hash && checked.content == message.content
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

/// Повторы анонса `lxmf.delivery` после старта (мс от регистрации); дальше обычный период 600 с (AGENTS п.9).
const ANNOUNCE_WARMUP_MS: [u64; 3] = [15_000, 45_000, 120_000];

/// Воркер служебного LXMF: один для сервера, ПК и телефона. Принимает сообщения от процессора и ведёт таймеры ядра
/// (`Core::tick`: сроки и погашение, `cmd_tick`: повтор команд, статус-пуши).
pub fn spawn_worker(runtime: AdminRuntime, core: Arc<super::invite::Core>) -> std::io::Result<std::thread::JoinHandle<()>> {
    spawn_runtime_worker("knothop-lxmf-core", move || {
        let AdminRuntime { inbound, .. } = runtime;
        let mut next_tick = std::time::Instant::now();
        loop {
            match inbound.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(message) => {
                    super::lxmf_sync::RX_MESSAGES.fetch_add(1, Ordering::Relaxed);
                    super::lxmf_sync::RX_BYTES.fetch_add(message.content.len() as u64, Ordering::Relaxed);
                    core.on_message(&message);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            core.ctl_poll();
            if std::time::Instant::now() >= next_tick {
                core.tick();
                core.cmd_tick();
                next_tick = std::time::Instant::now() + std::time::Duration::from_secs(2);
            }
        }
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use leviculum_std::api::generate_identity;

    fn pn(i: u8) -> DestinationHash { DestinationHash::new([i; 16]) }

    // PN, на котором письмо не подтвердилось, откладывается с растущей выдержкой; выбор уходит на другой PN
    #[test]
    fn pn_health_switches_to_another_node_and_backs_off() {
        let nodes = BTreeSet::from([pn(1), pn(2), pn(3)]);
        let mut health = PnHealth::default();
        let rank = |n: &DestinationHash| (false, false, n.as_bytes()[0]);
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
        let rank = |_: &DestinationHash| (false, false, 0);
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


    async fn wait_for<T>(timeout: std::time::Duration, mut poll: impl FnMut() -> Option<T>) -> Option<T> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if let Some(x) = poll() { return Some(x); }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        None
    }

    /// Локально (127.0.0.1, без публичной RNS): анонс → хеш из приглашения → ключ из анонса → прямая доставка `node.cmd/1`;
    /// ответ и прикладной ACK. Получатель задан ТОЛЬКО хешем (`Target::Hash`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_delivery_by_hash_only_and_application_ack() {
        use leviculum_std::api::NodeBuilder;
        use super::super::lxmf_sync::{self, Target};
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
        assert!(wait_for(step, || rt_a.ready.load(Ordering::Acquire).then_some(())).await.is_some());
        assert!(wait_for(step, || rt_b.ready.load(Ordering::Acquire).then_some(())).await.is_some());
        let (sa, sb) = (base.join("sa"), base.join("sb"));
        let _ga = lxmf_sync::register(&sa, rt_a.sync.clone());
        let _gb = lxmf_sync::register(&sb, rt_b.sync.clone());
        let exp = super::super::now_ms() as u64 / 1000 + 120;
        let hello = b"{\"v\":1,\"hello\":1}".to_vec();
        assert!(lxmf_sync::send(&sa, lxmf_sync::TITLE_CMD, Target::Hash(*id_b.hash()), hello.clone(), "t1", exp, lxmf_sync::always()));
        let got = wait_for(std::time::Duration::from_secs(60), || rt_b.inbound.try_recv().ok()).await.expect("сообщение не дошло");
        assert_eq!(got.title, lxmf_sync::TITLE_CMD);
        assert_eq!(got.content, hello);
        assert!(signed_by_trusted_source(&got, &id_a.public_key_bytes()));
        let ans = b"{\"v\":1,\"state\":\"applied\"}".to_vec();
        assert!(lxmf_sync::reply(&sb, lxmf_sync::TITLE_CMD, Target::Pk(id_a.public_key_bytes()), ans.clone(), "r1"));
        let back = wait_for(std::time::Duration::from_secs(60), || rt_a.inbound.try_recv().ok()).await.expect("ответ не дошёл");
        assert_eq!(back.content, ans);
        lxmf_sync::acknowledged(&sa, lxmf_destination(id_b.hash()), "t1");
        node_a.stop().await.ok();
        node_b.stop().await.ok();
        let _ = std::fs::remove_dir_all(&base);
    }
}
