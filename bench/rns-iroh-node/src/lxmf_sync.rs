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
}

impl Wire {
    pub fn decode(message: &Message) -> Option<Self> {
        if message.title != TITLE || message.verification != Verification::Valid
            || message.method != DeliveryMethod::Direct || message.content.len() > super::lxmf_admin::MAX_ADMIN_CONTENT { return None; }
        let wire: Self = serde_json::from_slice(&message.content).ok()?;
        if wire.v != 1 || wire.records.len() + wire.policies.len() > 16 { return None; }
        if let Some(ack) = &wire.ack {
            if ack.len() != 64 || !ack.bytes().all(|b| b.is_ascii_hexdigit()) || !wire.records.is_empty() || !wire.policies.is_empty() { return None; }
        } else if wire.records.is_empty() && wire.policies.is_empty() { return None; }
        Some(wire)
    }
}

#[derive(Clone)]
pub struct Outbound {
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
fn submit(state: &Path, command: Command) -> bool {
    RUNTIMES.get().and_then(|r| r.lock().unwrap().get(&key(state)).cloned())
        .is_some_and(|s| s.try_send(command).is_ok())
}
pub fn digest(content: &[u8]) -> String { super::hex(&Sha256::digest(content)) }

/// Ограниченная пачка; цепочки передаются в исходном порядке. Gate повторно
/// проверяется процессором непосредственно перед enqueue/retry, без ожидания mutex.
pub fn send(state: &Path, pk: Pk, records: &[Record], policies: &[Policy], gate: Gate) -> bool {
    if records.len() + policies.len() > 16 || (records.is_empty() && policies.is_empty()) { return false; }
    let wire = Wire { v:1, records:records.iter().map(|r| super::hex(&r.wire())).collect(),
        policies:policies.iter().map(|p| super::hex(&p.wire())).collect(), ack:None };
    let Ok(content) = serde_json::to_vec(&wire) else { return false };
    if content.len() > super::lxmf_admin::MAX_ADMIN_CONTENT { return false; }
    submit(state, Command::Send(Outbound { pk, content, gate, exp:super::now_ms() as u64/1000+TTL, ack:false }))
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
    let content = serde_json::to_vec(&Wire { v:1, records:vec![], policies:vec![], ack:Some(digest(&message.content)) }).unwrap();
    submit(state, Command::Send(Outbound { pk, content, gate:Arc::new(|| Some(true)), exp:super::now_ms() as u64/1000+TTL, ack:true }));
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

/// Штатный PN engine, а не ещё один протокол хранилища. Только серверы;
/// постоянный store вне стираемого lev-role, 8 МиБ, bounded transfer/fetch.
pub fn propagation_processor(state: &Path, identity: Identity) -> anyhow::Result<impl leviculum_std::api::CoreProcessor> {
    use lnpnd::engine::{Engine, EngineConfig};
    use leviculum_lxmf::{PropagationNodeConfig, peering::{PeeringConfig, MemoryPeerStore}};
    use leviculum_std::{FilePropagationStore, api::{CoreProcessor, StdNodeCore, NodeEvent, TickOutput}};
    let dir = state.join("lxmf/propagation");
    std::fs::create_dir_all(&dir)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let store = FilePropagationStore::open(&dir, 8*1024*1024).map_err(|e| anyhow::anyhow!("LXMF PN store: {e:?}"))?;
    let (engine, events) = Engine::new(EngineConfig {
        identity, store,
        node_config: PropagationNodeConfig { transfer_limit_kb:16, sync_limit_kb:64,
            serve_cap_bytes:Some(64*1024), name:None, ..Default::default() },
        announce_interval_secs:600, announce_delay_secs:20, announce_at_start:false,
        peering:PeeringConfig { max_peers:8, max_inbound_syncs:2, ..Default::default() },
        peer_store:Box::new(MemoryPeerStore::default()), control_allowed:vec![], auth_allowed:None,
        mailbox:None, store_limit_bytes:8*1024*1024, delivery_limit_kb:8,
    });
    struct Processor { engine:Engine<FilePropagationStore>, events:mpsc::Receiver<lnpnd::engine::EngineEvent> }
    impl CoreProcessor for Processor {
        fn on_event(&mut self, core:&mut StdNodeCore, event:&NodeEvent) -> TickOutput {
            let out = self.engine.on_event(core, event);
            while self.events.try_recv().is_ok() {}
            out
        }
        fn on_tick(&mut self, core:&mut StdNodeCore, now:u64) -> TickOutput {
            let out = self.engine.on_tick(core, now);
            while self.events.try_recv().is_ok() {}
            out
        }
    }
    Ok(Processor { engine, events })
}

#[cfg(test)]
mod tests {
    use super::*;
    use leviculum_std::api::{generate_identity, NodeBuilder};
    use std::time::{Duration, Instant};

    #[test]
    fn sync_codec_signature_and_scope_are_not_authority() {
        let (actor, target, attacker) = (generate_identity(), generate_identity(), generate_identity());
        let wire = Wire { v:1, records:vec![], policies:vec![], ack:Some("11".repeat(32)) };
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
            let content = serde_json::to_vec(&Wire { v:1, records:vec![super::super::hex(&rec.wire());n], policies:vec![], ack:None }).unwrap();
            let message = Message::create(super::super::lxmf_admin::lxmf_destination(target.hash()),
                super::super::lxmf_admin::lxmf_destination(sender.hash()), &sender, 1.0,
                TITLE.to_vec(), content, vec![], DeliveryMethod::Direct).unwrap();
            println!("LXMF_SYNC_BYTES records={n} old_channel_app={} lxmf_signed={} content={} (без Link/Resource/носителя и ACK)",
                n*(trust::REC_LEN+1), message.pack().len(), message.content.len());
            assert!(message.pack().len() <= super::super::lxmf_admin::MAX_ADMIN_CONTENT);
        }
        let ack_content = serde_json::to_vec(&Wire { v:1, records:vec![], policies:vec![], ack:Some("00".repeat(32)) }).unwrap();
        let ack = Message::create(super::super::lxmf_admin::lxmf_destination(sender.hash()),
            super::super::lxmf_admin::lxmf_destination(target.hash()), &target, 1.0,
            TITLE.to_vec(), ack_content, vec![], DeliveryMethod::Direct).unwrap();
        println!("LXMF_SYNC_ACK_BYTES lxmf_signed={} content={} (без Link/Resource/носителя)", ack.pack().len(), ack.content.len());
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
        assert!(base.join("server/lxmf/propagation").is_dir());
        client.stop().await.unwrap();
        server.stop().await.unwrap();
    }
}
