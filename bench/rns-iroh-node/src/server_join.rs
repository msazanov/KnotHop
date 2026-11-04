//! ADR 0027: вступление серверной ноды в сеть по коду администратора (`khs-…`).
//!
//! Код — bearer-секрет: публичный ключ корня, права, срок, число слотов и pin 24 Б. Сервер ставит якорь корня
//! из кода (только на пустом trust) и просит записи прав у админа по LXMF. Админ — владелец корня, держит
//! состояние кода в `<state>/server-codes/<id>.json` (0600) и выпускает обычные записи Record v1 от корня.
//! Права сервера проверяет обычный `Trust::offer`, а не доверие к каналу. Pin в открытом виде по сети не идёт:
//! запрос несёт HMAC-SHA256 над id кода, ключом сервера и именем.
use crate::enroll::{hex, raw, write};
use crate::trust::{self, Hash, Pk, Record, Trust};
use super::{lxmf_admin, lxmf_sync};
use crate::{now_ms, Identity};
use anyhow::{bail, Context, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use leviculum_lxmf::Message;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const PREFIX: &str = "khs-";
pub const TITLE: &[u8] = b"server.join/1";
/// Срок кода, как у приглашения клиента (0019).
pub const TTL: u64 = 48 * 3600;
pub const DEFAULT_MAX: u8 = 16;
pub const MAX_SLOTS: u8 = 64;
/// Сервер получает только эти права; ADD/REMOVE/CONFIG кодом не выдаются.
pub const ALLOWED: u16 = trust::USE | trust::TRANSIT | trust::EXIT;
pub const DEFAULT_RIGHTS: u16 = trust::TRANSIT | trust::EXIT;
/// Не больше одновременно действующих кодов на админа.
const MAX_ACTIVE_CODES: usize = 8;
const BODY_LEN: usize = 1 + 64 + 2 + 8 + 8 + 1 + 24;
const CODE_LEN: usize = BODY_LEN + 4;
/// Запись об ответе админа: не больше стольких чужих записей в одном ответе (остальное придёт обычной синхронизацией).
const PEER_RECORDS: usize = 15;
const MAX_REQ: usize = 2048;
const MAX_REPLY: usize = 7 * 1024;
const GC_AFTER: u64 = 7 * 24 * 3600;

type HmacSha256 = Hmac<Sha256>;

fn digest(domain: &[u8], data: &[u8]) -> [u8; 32] { Sha256::digest([domain, data].concat()).into() }
fn now_s() -> u64 { now_ms() as u64 / 1000 }
fn is_hex(s: &str, len: usize) -> bool { s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit()) }

// ------------------------------------------------------------------------------------------------ формат кода

/// Код приглашения сервера. Строка: `khs-` + base64url без padding (150 символов), тело 108 Б + checksum 4 Б.
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    pub root: Pk,
    pub rights: u16,
    pub issued: u64,
    pub expires: u64,
    pub max: u8,
    pub pin: [u8; 24],
}

impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "Code(id={}, секрет скрыт)", hex(&self.id())) }
}

impl Code {
    pub fn new(root: Pk, rights: u16, max: u8, now: u64) -> Result<Self> {
        let mut pin = [0u8; 24];
        rand_core::OsRng.fill_bytes(&mut pin);
        let code = Self { root, rights, issued: now, expires: now + TTL, max, pin };
        code.check()?;
        Ok(code)
    }

    fn check(&self) -> Result<()> {
        if self.root == [0u8; 64] || trust::hash_of(&self.root).is_none() { bail!("код: ключ корня не разобран"); }
        if self.rights == 0 || self.rights & !ALLOWED != 0 { bail!("код: права сервера только USE, TRANSIT, EXIT"); }
        if self.max == 0 || self.max > MAX_SLOTS { bail!("код: число серверов 1..={MAX_SLOTS}"); }
        if self.expires <= self.issued || self.expires - self.issued > TTL { bail!("код: неверный срок"); }
        if self.pin == [0u8; 24] { bail!("код: нулевой pin"); }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(BODY_LEN);
        b.push(1);
        b.extend_from_slice(&self.root);
        b.extend_from_slice(&self.rights.to_le_bytes());
        b.extend_from_slice(&self.issued.to_le_bytes());
        b.extend_from_slice(&self.expires.to_le_bytes());
        b.push(self.max);
        b.extend_from_slice(&self.pin);
        b
    }

    pub fn encode(&self) -> Result<String> {
        self.check()?;
        let mut b = self.body();
        let sum = digest(b"knothop-server-code-v1", &b);
        b.extend_from_slice(&sum[..4]);
        Ok(format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)))
    }

    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 4096 { bail!("код слишком длинный"); }
        let s: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let tail = s.strip_prefix(PREFIX).ok_or_else(|| anyhow::anyhow!("нужен код сервера khs-"))?;
        if tail.len() > 160 { bail!("код сервера: неверная длина"); }
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(tail).map_err(|_| anyhow::anyhow!("код сервера: неверная строка"))?;
        if b.len() != CODE_LEN { bail!("код сервера: неверная длина"); }
        let (body, sum) = b.split_at(BODY_LEN);
        if digest(b"knothop-server-code-v1", body)[..4] != *sum { bail!("код сервера: контрольная сумма не сошлась (ошибка копирования)"); }
        if body[0] != 1 { bail!("код сервера: версия не поддерживается"); }
        let code = Self {
            root: body[1..65].try_into()?,
            rights: u16::from_le_bytes(body[65..67].try_into()?),
            issued: u64::from_le_bytes(body[67..75].try_into()?),
            expires: u64::from_le_bytes(body[75..83].try_into()?),
            max: body[83],
            pin: body[84..108].try_into()?,
        };
        code.check()?;
        Ok(code)
    }

    pub fn root_hash(&self) -> Hash { trust::hash_of(&self.root).unwrap_or([0; 16]) }
    /// Идентификатор кода: по нему админ находит состояние. Из него pin не восстановить.
    pub fn id(&self) -> Hash { digest(b"knothop-server-code-id-v1", &self.pin)[..16].try_into().unwrap() }

    /// Доказательство владения pin: HMAC над id кода, ключом сервера и именем. Pin наружу не уходит.
    pub fn mac(&self, server: &Pk, name: &str) -> [u8; 32] {
        let key = digest(b"knothop-server-join-key-v1", &self.pin);
        let mut m = HmacSha256::new_from_slice(&key).expect("hmac key");
        m.update(b"knothop-server-join-req-v1");
        m.update(&self.id());
        m.update(server);
        m.update(name.as_bytes());
        m.finalize().into_bytes().into()
    }

    fn mac_ok(&self, server: &Pk, name: &str, got: &[u8]) -> bool {
        let key = digest(b"knothop-server-join-key-v1", &self.pin);
        let mut m = HmacSha256::new_from_slice(&key).expect("hmac key");
        m.update(b"knothop-server-join-req-v1");
        m.update(&self.id());
        m.update(server);
        m.update(name.as_bytes());
        m.verify_slice(got).is_ok()
    }
}

/// Имя в запросе: печатные символы, до 40 знаков (для списка у админа; не права и не адрес).
pub fn clean_name(name: &str) -> String {
    name.chars().filter(|c| !c.is_control()).take(40).collect::<String>().trim().to_string()
}

// ------------------------------------------------------------------------------------------------ сообщения

#[derive(Serialize, Deserialize)]
struct Msg {
    v: u8,
    op: String,
    code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    mac: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    rec: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    peers: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    reason: String,
}

fn msg(op: &str, code: &Hash) -> Msg {
    Msg { v: 1, op: op.into(), code: hex(code), server: String::new(), name: String::new(), mac: String::new(), rec: String::new(), peers: vec![], reason: String::new() }
}

/// Журнал шагов вступления (редкие события; только короткие префиксы хешей, без pin/кода/ключей).
pub fn jlog(msg: impl AsRef<str>) { eprintln!("[{}] вступление: {}", now_ms(), msg.as_ref()); }
fn short(h: &[u8]) -> String { hex(&h[..h.len().min(4)]) }

fn send(state: &Path, pk: Pk, m: &Msg) -> bool {
    let Ok(content) = serde_json::to_vec(m) else { return false };
    if content.len() > lxmf_admin::MAX_ADMIN_CONTENT { return false; }
    let ok = lxmf_sync::submit(state, lxmf_sync::Command::Send(lxmf_sync::Outbound {
        title: TITLE.to_vec(), pk, content, gate: Arc::new(|| Some(true)), exp: now_s() + lxmf_sync::TTL, ack: false,
    }));
    let to = trust::hash_of(&pk).map(|h| short(&h)).unwrap_or_default();
    jlog(format!("{} -> {}: {}", m.op, to, if ok { "передано в очередь LXMF" } else { "очередь LXMF недоступна (нет воркера или переполнена)" }));
    ok
}

fn parse_msg(message: &Message, me: &Hash, max: usize) -> Option<Msg> {
    if message.title != TITLE || message.content.len() > max || message.destination_hash != lxmf_admin::lxmf_destination(me) { return None; }
    let m: Msg = serde_json::from_slice(&message.content).ok()?;
    (m.v == 1 && is_hex(&m.code, 32)).then_some(m)
}

// ------------------------------------------------------------------------------------------------ лимиты приёма

struct Rate { global: VecDeque<Instant>, per: HashMap<[u8; 16], VecDeque<Instant>> }
fn rate() -> &'static Mutex<Rate> {
    static R: OnceLock<Mutex<Rate>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Rate { global: VecDeque::new(), per: HashMap::new() }))
}
/// Запросы недоверенные: до любой подписи и диска — не больше 6 в минуту с одного источника и 30 в минуту всего.
fn rate_ok(source: [u8; 16]) -> bool {
    let mut r = rate().lock().unwrap_or_else(|e| e.into_inner());
    let minute = Duration::from_secs(60);
    r.global.retain(|t| t.elapsed() < minute);
    r.per.retain(|_, v| { v.retain(|t| t.elapsed() < minute); !v.is_empty() });
    if r.global.len() >= 30 || r.per.get(&source).is_some_and(|v| v.len() >= 6) { return false; }
    if r.per.len() >= 256 && !r.per.contains_key(&source) { return false; }
    r.global.push_back(Instant::now());
    r.per.entry(source).or_default().push_back(Instant::now());
    true
}
#[cfg(test)]
fn rate_reset() { let mut r = rate().lock().unwrap(); r.global.clear(); r.per.clear(); }

// ------------------------------------------------------------------------------------------------ админ: состояние кодов

#[derive(Clone, Serialize, Deserialize)]
pub struct Joined { pub key: String, pub hash: String, pub name: String, pub at: u64 }
#[derive(Clone, Serialize, Deserialize)]
struct CodeFile { v: u8, code: String, revoked: bool, servers: Vec<Joined> }

fn codes_dir(state: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let d = state.join("server-codes");
    std::fs::create_dir_all(&d)?;
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
    Ok(d)
}
fn code_path(state: &Path, id: &Hash) -> Result<PathBuf> { Ok(codes_dir(state)?.join(format!("{}.json", hex(id)))) }
fn read_file(p: &Path) -> Result<CodeFile> {
    use std::io::Read;
    let f = std::fs::File::open(p)?;
    let mut b = Vec::new();
    f.take(64 * 1024 + 1).read_to_end(&mut b)?;
    if b.len() > 64 * 1024 { bail!("файл кода слишком велик"); }
    Ok(serde_json::from_slice(&b)?)
}
fn admin_gate() -> &'static Mutex<()> { static G: OnceLock<Mutex<()>> = OnceLock::new(); G.get_or_init(|| Mutex::new(())) }

fn gc(state: &Path) {
    let Ok(d) = codes_dir(state) else { return };
    for e in std::fs::read_dir(d).into_iter().flatten().flatten().take(256) {
        let p = e.path();
        if let Ok(f) = read_file(&p) {
            if Code::parse(&f.code).is_ok_and(|c| c.expires + GC_AFTER < now_s()) { let _ = std::fs::remove_file(&p); }
        }
    }
}

/// Создать код от корня `identity` (админ — сам корень). Возвращает строку `khs-…`.
pub fn create(state: &Path, identity: &Identity, rights: u16, max: u8) -> Result<String> {
    let _g = admin_gate().lock().unwrap_or_else(|e| e.into_inner());
    gc(state);
    let active = list_files(state).iter().filter(|(c, f)| !f.revoked && c.expires > now_s()).count();
    if active >= MAX_ACTIVE_CODES { bail!("уже {MAX_ACTIVE_CODES} действующих кодов: отзовите ненужные"); }
    let code = Code::new(identity.public_key_bytes(), rights, max, now_s())?;
    let text = code.encode()?;
    let file = CodeFile { v: 1, code: text.clone(), revoked: false, servers: vec![] };
    write(&code_path(state, &code.id())?, &serde_json::to_vec(&file)?)?;
    Ok(text)
}

fn list_files(state: &Path) -> Vec<(Code, CodeFile)> {
    let Ok(d) = codes_dir(state) else { return vec![] };
    let mut v: Vec<_> = std::fs::read_dir(d).into_iter().flatten().flatten().take(256)
        .filter_map(|e| { let f = read_file(&e.path()).ok()?; Some((Code::parse(&f.code).ok()?, f)) }).collect();
    v.sort_by_key(|(c, _)| std::cmp::Reverse(c.issued));
    v
}

/// Состояние кодов для экрана админа. Pin и сама строка кода не включаются.
pub fn list(state: &Path) -> serde_json::Value {
    let now = now_s();
    let items: Vec<_> = list_files(state).into_iter().map(|(c, f)| {
        let st = if f.revoked { "revoked" } else if c.expires <= now { "expired" } else if f.servers.len() >= c.max as usize { "full" } else { "active" };
        serde_json::json!({"id": hex(&c.id()), "rights": c.rights, "rights_text": trust::rights_text(c.rights), "issued": c.issued, "expires": c.expires,
            "max": c.max, "joined": f.servers.len(), "state": st,
            "servers": f.servers.iter().map(|s| serde_json::json!({"hash": s.hash, "name": s.name, "at": s.at})).collect::<Vec<_>>()})
    }).collect();
    serde_json::json!({"version": 1, "codes": items})
}

/// Строка кода для повторного показа (только админу, в закрытый файл вызывающего).
pub fn show(state: &Path, id: &str) -> Result<String> {
    if !is_hex(id, 32) { bail!("id кода: 32 hex"); }
    let f = read_file(&codes_dir(state)?.join(format!("{id}.json"))).context("код не найден")?;
    Ok(f.code)
}

/// Отозвать код: новые серверы не вступают. Уже вступившие остаются (их права снимает обычный отзыв записи).
pub fn revoke(state: &Path, id: &str) -> Result<()> {
    if !is_hex(id, 32) { bail!("id кода: 32 hex"); }
    let _g = admin_gate().lock().unwrap_or_else(|e| e.into_inner());
    let p = codes_dir(state)?.join(format!("{id}.json"));
    let mut f = read_file(&p).context("код не найден")?;
    f.revoked = true;
    write(&p, &serde_json::to_vec(&f)?)
}

// ------------------------------------------------------------------------------------------------ админ: приём запроса

fn own_chain_record(tr: &Trust, holder: &Pk, root: &Hash) -> Option<Record> {
    tr.chain_for(holder).into_iter().find(|r| r.root == *root && r.issuer == *root && r.holder == *holder && r.rights != 0)
}

/// Запрос сервера. Возвращает истину, если trust админа изменился.
fn on_join(state: &Path, identity: &Identity, trust: &Arc<Mutex<Trust>>, message: &Message, m: Msg) -> bool {
    if m.op != "join" || !is_hex(&m.server, 128) || !is_hex(&m.mac, 64) || m.name.len() > 160 || m.name.chars().count() > 40 { return false; }
    jlog(format!("получен запрос join от {}", short(&message.source_hash)));
    if !rate_ok(message.source_hash) { jlog("запрос отброшен: лимит частоты"); return false; }
    let Ok(server) = raw(&m.server).and_then(|b| <Pk>::try_from(b).map_err(|_| anyhow::anyhow!("pk"))) else { return false };
    let Some(server_hash) = trust::hash_of(&server) else { return false };
    if !lxmf_admin::signed_by_trusted_source(message, &server) { return false; }
    let Some(id) = raw(&m.code).ok().and_then(|b| Hash::try_from(b).ok()) else { return false };
    let path = match code_path(state, &id) { Ok(p) => p, Err(_) => return false };
    let _g = admin_gate().lock().unwrap_or_else(|e| e.into_inner());
    let Ok(mut file) = read_file(&path) else { return false };
    let Ok(code) = Code::parse(&file.code) else { return false };
    let Some(mac) = raw(&m.mac).ok() else { return false };
    // неверный pin: молчим (ни оракула, ни ответа тому, кто pin не знает)
    if code.id() != id || code.root != identity.public_key_bytes() || !code.mac_ok(&server, &m.name, &mac) { jlog("запрос отброшен: код/HMAC не сошлись"); return false; }
    let reply_to = |reply: Msg| { send(state, server, &reply); lxmf_sync::acknowledge(state, message, server); };
    let deny = |why: &str| { jlog(format!("отказ серверу {}: {why}", short(&server_hash))); let mut r = msg("deny", &id); r.reason = why.into(); reply_to(r); };
    let root = code.root_hash();
    if code.expires <= now_s() { deny("expired"); return false; }
    if file.revoked { deny("revoked"); return false; }
    if server_hash == *identity.hash() { deny("invalid"); return false; }
    let key_hex = hex(&server);
    let in_roster = file.servers.iter().any(|s| s.key == key_hex);
    let (record, changed, roster_pks) = {
        let mut tr = trust.lock().unwrap_or_else(|e| e.into_inner());
        let has = tr.rights_in(&root, &server_hash) & code.rights == code.rights;
        if in_roster && !has { drop(tr); deny("revoked"); return false; }
        let mut changed = false;
        if !has {
            if file.servers.len() >= code.max as usize { drop(tr); deny("full"); return false; }
            if tr.issue(root, server, code.rights).is_err() || tr.save().is_err() { drop(tr); deny("busy"); return false; }
            changed = true;
        }
        let Some(rec) = own_chain_record(&tr, &server, &root) else { drop(tr); deny("busy"); return false; };
        let peers: Vec<Pk> = file.servers.iter().rev().filter(|s| s.key != key_hex).filter_map(|s| raw(&s.key).ok()?.try_into().ok()).collect();
        (rec, changed, peers)
    };
    if !in_roster {
        file.servers.push(Joined { key: key_hex, hash: hex(&server_hash), name: clean_name(&m.name), at: now_s() });
        if write(&path, &serde_json::to_vec(&file).unwrap_or_default()).is_err() { return changed; }
    }
    let mut reply = msg("grant", &id);
    reply.rec = hex(&record.wire());
    {
        let tr = trust.lock().unwrap_or_else(|e| e.into_inner());
        for pk in roster_pks.iter().take(PEER_RECORDS) {
            if let Some(r) = own_chain_record(&tr, pk, &root) { reply.peers.push(hex(&r.wire())); }
        }
    }
    while serde_json::to_vec(&reply).map_or(0, |b| b.len()) > MAX_REPLY && reply.peers.pop().is_some() {}
    jlog(format!("сервер {} принят ({}), отправляю grant", short(&server_hash), if changed { "права выданы" } else { "права уже были" }));
    reply_to(reply);
    // уже вступившие серверы узнают нового сами: иначе они не увидят его TRANSIT и не откроют соседство
    if changed || !in_roster {
        for pk in roster_pks {
            lxmf_sync::queue(state, trust.clone(), pk, vec![record.clone()], vec![]);
        }
    }
    changed
}

// ------------------------------------------------------------------------------------------------ сервер: состояние вступления

#[derive(Serialize, Deserialize, Clone)]
pub struct JoinState {
    pub v: u8,
    pub code: String,
    pub root: String,
    pub rights: u16,
    pub expires: u64,
    /// pending | joined | denied | expired
    pub state: String,
    #[serde(default)]
    pub reason: String,
}

pub fn join_state_path(state: &Path) -> PathBuf { state.join("server-join.json") }
pub fn read_join_state(state: &Path) -> Option<JoinState> {
    use std::io::Read;
    let f = std::fs::File::open(join_state_path(state)).ok()?;
    let mut b = Vec::new();
    f.take(4097).read_to_end(&mut b).ok()?;
    if b.len() > 4096 { return None; }
    serde_json::from_slice(&b).ok()
}
fn put_join_state(state: &Path, code: &Code, st: &str, reason: &str) {
    let s = JoinState { v: 1, code: hex(&code.id()), root: hex(&code.root), rights: code.rights, expires: code.expires, state: st.into(), reason: reason.into() };
    if let Ok(b) = serde_json::to_vec(&s) { let _ = write(&join_state_path(state), &b); }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Adopt { Fresh, Already }

/// Поставить якорь корня из кода. Только на пустом trust (свой корень без записей); чужой якорь — отказ, ничего не меняется.
pub fn adopt(tr: &mut Trust, code: &Code, now: u64) -> Result<Adopt> {
    let h = code.root_hash();
    if h == tr.me_hash { bail!("код создан этой же нодой: он нужен для серверов, а не для неё"); }
    if tr.has_anchor(&h) { return Ok(Adopt::Already); }
    if now >= code.expires { bail!("срок кода истёк: создайте новый"); }
    if tr.anchors().len() > 1 || tr.record_count() > 0 {
        bail!("нода уже привязана к другой сети ({} якорей, {} записей): код не применён; чтобы сменить сеть, очистите state", tr.anchors().len() - 1, tr.record_count());
    }
    tr.add_anchor(&code.root)?;
    tr.save()?;
    Ok(Adopt::Fresh)
}

/// Цикл запросов сервера: пока записи нет — повторять с растущей паузой (5 с … 5 мин) до срока кода.
pub fn spawn_join(state: PathBuf, identity: Identity, trust: Arc<Mutex<Trust>>, code: Code, name: String, code_file: Option<PathBuf>, note: Arc<dyn Fn(String) + Send + Sync>) {
    tokio::spawn(async move {
        let (me_pk, me_hash, root) = (identity.public_key_bytes(), *identity.hash(), code.root_hash());
        let name = clean_name(&name);
        let mut wait = 5u64;
        let mut announced = false;
        let mut attempt = 1u32;
        loop {
            let has = trust.lock().unwrap_or_else(|e| e.into_inner()).rights_in(&root, &me_hash) & code.rights == code.rights;
            if has {
                if read_join_state(&state).is_none_or(|s| s.state != "joined" || s.code != hex(&code.id())) {
                    put_join_state(&state, &code, "joined", "");
                    note(format!("вступление по коду: права от корня {} получены", &hex(&root)[..8]));
                }
                // код — bearer-секрет с оставшимися слотами: файл после вступления не нужен (отсутствие файла при старте — не ошибка)
                if let Some(f) = &code_file { if std::fs::remove_file(f).is_ok() { note("файл кода сервера удалён после вступления".into()); } }
                return;
            }
            if let Some(s) = read_join_state(&state) {
                if s.code == hex(&code.id()) && s.state == "denied" { return; }
            }
            if now_s() >= code.expires { put_join_state(&state, &code, "expired", ""); note("вступление по коду: срок кода истёк".into()); return; }
            if !announced || read_join_state(&state).is_none_or(|s| s.code != hex(&code.id())) { put_join_state(&state, &code, "pending", ""); announced = true; }
            let mut m = msg("join", &code.id());
            m.server = hex(&me_pk);
            m.name = name.clone();
            m.mac = hex(&code.mac(&me_pk, &name));
            let queued = send(&state, code.root, &m);
            note(format!("вступление: запрос join #{attempt} к админу {} {}; следующий через {wait} с", &hex(&root)[..8], if queued { "в очереди LXMF" } else { "НЕ поставлен в очередь" }));
            attempt += 1;
            tokio::time::sleep(Duration::from_secs(wait)).await;
            wait = (wait * 2).min(300);
        }
    });
}

/// Ответ админа. Истина — trust сервера изменился (нужно пересчитать роли Link).
fn on_reply(state: &Path, identity: &Identity, trust: &Arc<Mutex<Trust>>, message: &Message, m: Msg) -> bool {
    if !matches!(m.op.as_str(), "grant" | "deny") { return false; }
    jlog(format!("получен ответ {} от {}", m.op, short(&message.source_hash)));
    let Some(st) = read_join_state(state) else { return false };
    if st.state != "pending" || st.code != m.code { jlog("ответ проигнорирован: нет ожидающего вступления с этим кодом"); return false; }
    let Some(root_pk) = raw(&st.root).ok().and_then(|b| Pk::try_from(b).ok()) else { return false };
    let Some(root) = trust::hash_of(&root_pk) else { return false };
    if !rate_ok(message.source_hash) || !lxmf_admin::signed_by_trusted_source(message, &root_pk) { jlog("ответ отброшен: лимит или подпись не корня из кода"); return false; }
    let ack = || lxmf_sync::acknowledge(state, message, root_pk);
    if m.op == "deny" {
        let reason: String = m.reason.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
        let s = JoinState { state: "denied".into(), reason: reason.clone(), ..st };
        if let Ok(b) = serde_json::to_vec(&s) { let _ = write(&join_state_path(state), &b); }
        ack();
        return false;
    }
    let me = identity.public_key_bytes();
    let Some(rec) = raw(&m.rec).ok().and_then(|b| Record::parse(&b)) else { return false };
    // права ровно из кода, от корня, на наш ключ
    if rec.holder != me || rec.root != root || rec.issuer != root || rec.rights != st.rights { return false; }
    let ok = {
        let mut tr = trust.lock().unwrap_or_else(|e| e.into_inner());
        if !tr.has_anchor(&root) { return false; }
        if matches!(tr.offer(rec), trust::Offer::Rejected(_)) { return false; }
        for p in m.peers.iter().take(PEER_RECORDS + 1) {
            if let Some(r) = raw(p).ok().and_then(|b| Record::parse(&b)) {
                if r.root == root && r.issuer == root { let _ = tr.offer(r); }
            }
        }
        tr.rights_in(&root, identity.hash()) & st.rights == st.rights && tr.save().is_ok()
    };
    if !ok { jlog("grant отклонён проверкой записи (holder/права/подпись/якорь)"); return false; }
    jlog("grant принят, права получены");
    let s = JoinState { state: "joined".into(), reason: String::new(), ..st };
    if let Ok(b) = serde_json::to_vec(&s) { let _ = write(&join_state_path(state), &b); }
    ack();
    true
}

/// Вход для LXMF-воркеров узла и клиента. Истина — trust изменился.
pub fn on_lxmf(state: &Path, identity: &Identity, trust: &Arc<Mutex<Trust>>, message: &Message) -> bool {
    let Some(m) = parse_msg(message, identity.hash(), lxmf_admin::MAX_ADMIN_CONTENT) else { return false };
    match m.op.as_str() {
        "join" if message.content.len() <= MAX_REQ => on_join(state, identity, trust, message, m),
        "grant" | "deny" => on_reply(state, identity, trust, message, m),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leviculum_lxmf::DeliveryMethod;

    fn id() -> Identity { leviculum_std::api::generate_identity() }
    fn tmp(tag: &str) -> PathBuf {
        let mut r = [0u8; 6];
        rand_core::OsRng.fill_bytes(&mut r);
        let p = std::env::temp_dir().join(format!("kh-sj-{tag}-{}", hex(&r)));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn fresh_code(root: &Identity) -> Code { Code::new(root.public_key_bytes(), DEFAULT_RIGHTS, 2, now_s()).unwrap() }

    #[test]
    fn code_roundtrip_length_and_no_secret_in_debug() {
        let root = id();
        let c = fresh_code(&root);
        let s = c.encode().unwrap();
        assert_eq!(s.len(), PREFIX.len() + 150);
        assert_eq!(Code::parse(&s).unwrap(), c);
        assert_eq!(Code::parse(&format!(" {} \n", &s)).unwrap(), c, "пробелы и перенос при вставке");
        assert!(!format!("{c:?}").contains(&hex(&c.pin)));
        assert!(Invite_parse_rejects(&s), "код сервера не принимается как приглашение клиента");
    }
    #[allow(non_snake_case)]
    fn Invite_parse_rejects(s: &str) -> bool { crate::enroll::Invite::parse(s).is_err() }

    #[test]
    fn code_rejects_tamper_wrong_rights_slots_expiry_and_garbage() {
        let root = id();
        let c = fresh_code(&root);
        let s = c.encode().unwrap();
        let mut t = s.clone().into_bytes();
        t[20] = if t[20] == b'A' { b'B' } else { b'A' };
        assert!(Code::parse(std::str::from_utf8(&t).unwrap()).is_err(), "контрольная сумма");
        assert!(Code::parse(&format!("{s}A")).is_err(), "хвост");
        assert!(Code::parse(&s[..s.len() - 2]).is_err());
        assert!(Code::parse("kh-AAAA").is_err());
        assert!(Code::parse(&"x".repeat(5000)).is_err());
        for rights in [0, trust::ADD, trust::USE | trust::CONFIG, trust::ALL, trust::HOST_ACCESS] {
            assert!(Code::new(root.public_key_bytes(), rights, 1, now_s()).is_err(), "права {rights}");
        }
        for max in [0, MAX_SLOTS + 1] { assert!(Code::new(root.public_key_bytes(), DEFAULT_RIGHTS, max, now_s()).is_err()); }
        let mut late = c.clone();
        late.expires = late.issued + TTL + 1;
        assert!(late.encode().is_err());
        let mut zero = c.clone();
        zero.pin = [0; 24];
        assert!(zero.encode().is_err());
        let mut badroot = c.clone();
        badroot.root = [0; 64];
        assert!(badroot.encode().is_err());
    }

    #[test]
    fn mac_binds_code_server_and_name_and_never_contains_pin() {
        let (root, a, b) = (id(), id(), id());
        let c = fresh_code(&root);
        let mac = c.mac(&a.public_key_bytes(), "es");
        assert!(c.mac_ok(&a.public_key_bytes(), "es", &mac));
        assert!(!c.mac_ok(&b.public_key_bytes(), "es", &mac), "другой сервер");
        assert!(!c.mac_ok(&a.public_key_bytes(), "nl", &mac), "другое имя");
        let other = fresh_code(&root);
        assert!(!other.mac_ok(&a.public_key_bytes(), "es", &mac), "другой код");
        assert!(!mac.windows(8).any(|w| c.pin.windows(8).any(|p| p == w)));
        assert!(!c.mac_ok(&a.public_key_bytes(), "es", &mac[..31]));
    }

    #[test]
    fn adopt_sets_anchor_only_on_empty_trust_and_refuses_foreign_or_own() {
        let (root, server, other) = (id(), id(), id());
        let code = fresh_code(&root);
        let dir = tmp("adopt");
        let mut tr = Trust::new(server.clone(), Some(dir.join("trust.json")));
        assert_eq!(adopt(&mut tr, &code, now_s()).unwrap(), Adopt::Fresh);
        assert!(tr.has_anchor(root.hash()));
        assert_eq!(adopt(&mut tr, &code, now_s()).unwrap(), Adopt::Already, "повтор после перезапуска");
        let restored = Trust::load(server.clone(), &dir).unwrap();
        assert!(restored.has_anchor(root.hash()), "якорь пережил перезапуск");
        // другой код, другой корень: отказ, якоря не меняются
        let foreign = fresh_code(&other);
        let before = tr.anchors().len();
        assert!(adopt(&mut tr, &foreign, now_s()).unwrap_err().to_string().contains("другой сети"));
        assert_eq!(tr.anchors().len(), before);
        assert!(!tr.has_anchor(other.hash()));
        // код этой же ноды
        let mut own = Trust::new(root.clone(), None);
        assert!(adopt(&mut own, &code, now_s()).is_err());
        // записи уже есть (нода была админом): отказ
        let mut admin = Trust::new(server.clone(), None);
        admin.issue(*server.hash(), other.public_key_bytes(), trust::USE).unwrap();
        assert!(adopt(&mut admin, &code, now_s()).is_err());
        assert!(!admin.has_anchor(root.hash()));
        // срок
        let mut fresh = Trust::new(id(), None);
        assert!(adopt(&mut fresh, &code, code.expires).unwrap_err().to_string().contains("срок"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn message(from: &Identity, to: &Identity, m: &Msg) -> Message {
        let mut content = serde_json::to_vec(m).unwrap();
        content.truncate(lxmf_admin::MAX_ADMIN_CONTENT);
        Message::create(lxmf_admin::lxmf_destination(to.hash()), lxmf_admin::lxmf_destination(from.hash()), from, now_ms() as f64 / 1000.0,
            TITLE.to_vec(), content, vec![], DeliveryMethod::Direct).unwrap()
    }

    fn join_msg(code: &Code, server: &Identity, name: &str) -> Msg {
        let mut m = msg("join", &code.id());
        m.server = hex(&server.public_key_bytes());
        m.name = name.into();
        m.mac = hex(&code.mac(&server.public_key_bytes(), name));
        m
    }

    struct Fixture { root: Identity, dir: PathBuf, tr: Arc<Mutex<Trust>>, code: Code, text: String }
    fn admin_fixture(max: u8) -> Fixture {
        rate_reset();
        let root = id();
        let dir = tmp("admin");
        let tr = Arc::new(Mutex::new(Trust::new(root.clone(), Some(dir.join("trust.json")))));
        let text = create(&dir, &root, DEFAULT_RIGHTS, max).unwrap();
        let code = Code::parse(&text).unwrap();
        Fixture { root, dir, tr, code, text }
    }

    #[test]
    fn admin_issues_exactly_code_rights_once_per_server_and_enforces_slots() {
        let f = admin_fixture(2);
        let (s1, s2, s3) = (id(), id(), id());
        let _ = &f.text;
        for (s, n) in [(&s1, "a"), (&s2, "b")] {
            let changed = on_join(&f.dir, &f.root, &f.tr, &message(s, &f.root, &join_msg(&f.code, s, n)), join_msg(&f.code, s, n));
            assert!(changed);
            assert_eq!(f.tr.lock().unwrap().rights_in(f.root.hash(), s.hash()), DEFAULT_RIGHTS, "ровно права из кода, без USE/ADD");
        }
        // повтор того же сервера: слот не тратится, trust не меняется
        let again = on_join(&f.dir, &f.root, &f.tr, &message(&s1, &f.root, &join_msg(&f.code, &s1, "a")), join_msg(&f.code, &s1, "a"));
        assert!(!again);
        let v = list(&f.dir);
        assert_eq!(v["codes"][0]["joined"], 2);
        assert_eq!(v["codes"][0]["state"], "full");
        // третий сверх лимита: прав нет
        on_join(&f.dir, &f.root, &f.tr, &message(&s3, &f.root, &join_msg(&f.code, &s3, "c")), join_msg(&f.code, &s3, "c"));
        assert_eq!(f.tr.lock().unwrap().rights_in(f.root.hash(), s3.hash()), 0, "сверх лимита отказ");
        assert_eq!(list(&f.dir)["codes"][0]["joined"], 2);
        assert!(!serde_json::to_string(&list(&f.dir)).unwrap().contains(&hex(&f.code.pin)), "список без pin");
        std::fs::remove_dir_all(f.dir).unwrap();
    }

    #[test]
    fn admin_ignores_wrong_pin_foreign_code_unknown_code_expired_and_revoked() {
        let f = admin_fixture(4);
        let (s, other_root) = (id(), id());
        // неверный pin
        let mut bad = f.code.clone();
        bad.pin[0] ^= 1;
        let m = join_msg(&bad, &s, "x");
        let m = Msg { code: hex(&f.code.id()), ..m };
        assert!(!on_join(&f.dir, &f.root, &f.tr, &message(&s, &f.root, &m), m));
        assert_eq!(f.tr.lock().unwrap().rights_in(f.root.hash(), s.hash()), 0);
        assert_eq!(list(&f.dir)["codes"][0]["joined"], 0);
        // неизвестный код
        let unknown = fresh_code(&f.root);
        let m = join_msg(&unknown, &s, "x");
        assert!(!on_join(&f.dir, &f.root, &f.tr, &message(&s, &f.root, &m), m));
        // сообщение подписано другим ключом, чем заявленный сервер
        let impostor = id();
        let m = join_msg(&f.code, &s, "x");
        assert!(!on_join(&f.dir, &f.root, &f.tr, &message(&impostor, &f.root, &m), m));
        assert_eq!(f.tr.lock().unwrap().rights_in(f.root.hash(), s.hash()), 0);
        // код чужого корня на этом админе
        let foreign = fresh_code(&other_root);
        let m = join_msg(&foreign, &s, "x");
        assert!(!on_join(&f.dir, &f.root, &f.tr, &message(&s, &f.root, &m), m));
        // отозван: даже верный pin не вступает
        revoke(&f.dir, &hex(&f.code.id())).unwrap();
        assert_eq!(list(&f.dir)["codes"][0]["state"], "revoked");
        let m = join_msg(&f.code, &s, "x");
        assert!(!on_join(&f.dir, &f.root, &f.tr, &message(&s, &f.root, &m), m));
        assert_eq!(f.tr.lock().unwrap().rights_in(f.root.hash(), s.hash()), 0);
        std::fs::remove_dir_all(f.dir).unwrap();
    }

    #[test]
    fn admin_refuses_expired_code_and_removed_server_does_not_rejoin() {
        let f = admin_fixture(4);
        let s = id();
        // сервер вступил и затем отозван корнем: повтор запроса не возвращает права
        let m = join_msg(&f.code, &s, "x");
        assert!(on_join(&f.dir, &f.root, &f.tr, &message(&s, &f.root, &m), m));
        f.tr.lock().unwrap().issue(*f.root.hash(), s.public_key_bytes(), 0).unwrap();
        let m = join_msg(&f.code, &s, "x");
        assert!(!on_join(&f.dir, &f.root, &f.tr, &message(&s, &f.root, &m), m));
        assert_eq!(f.tr.lock().unwrap().rights_in(f.root.hash(), s.hash()), 0, "отозванный не вступает повторно тем же кодом");
        // просроченный код
        let p = code_path(&f.dir, &f.code.id()).unwrap();
        let mut file = read_file(&p).unwrap();
        let mut old = f.code.clone();
        old.issued -= TTL + 10;
        old.expires -= TTL + 10;
        file.code = old.encode().unwrap();
        let s2 = id();
        let moved = code_path(&f.dir, &old.id()).unwrap();
        assert_eq!(moved, p, "id зависит только от pin");
        write(&p, &serde_json::to_vec(&file).unwrap()).unwrap();
        let m = join_msg(&old, &s2, "y");
        assert!(!on_join(&f.dir, &f.root, &f.tr, &message(&s2, &f.root, &m), m));
        assert_eq!(f.tr.lock().unwrap().rights_in(f.root.hash(), s2.hash()), 0, "срок вышел");
        std::fs::remove_dir_all(f.dir).unwrap();
    }

    #[test]
    fn admin_rate_limit_drops_before_any_signature_work() {
        let f = admin_fixture(4);
        let s = id();
        let m = join_msg(&f.code, &s, "x");
        let msg_ = message(&s, &f.root, &m);
        let mut passed = 0;
        for _ in 0..20 { if rate_ok(msg_.source_hash) { passed += 1; } }
        assert_eq!(passed, 6, "6 в минуту с источника");
        rate_reset();
        std::fs::remove_dir_all(f.dir).unwrap();
    }

    #[test]
    fn code_creation_is_bounded_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        rate_reset();
        let root = id();
        let dir = tmp("limits");
        for _ in 0..MAX_ACTIVE_CODES { create(&dir, &root, DEFAULT_RIGHTS, 1).unwrap(); }
        assert!(create(&dir, &root, DEFAULT_RIGHTS, 1).is_err());
        let d = codes_dir(&dir).unwrap();
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        for e in std::fs::read_dir(&d).unwrap().flatten() { assert_eq!(e.metadata().unwrap().permissions().mode() & 0o777, 0o600); }
        let first = list(&dir)["codes"][0]["id"].as_str().unwrap().to_string();
        assert!(Code::parse(&show(&dir, &first).unwrap()).is_ok());
        assert!(show(&dir, "../etc/passwd").is_err() && revoke(&dir, "zz").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn server_applies_grant_only_exact_rights_from_code_root_and_own_key() {
        let f = admin_fixture(4);
        let (server, other) = (id(), id());
        let sdir = tmp("server");
        let str_ = Arc::new(Mutex::new(Trust::new(server.clone(), Some(sdir.join("trust.json")))));
        adopt(&mut str_.lock().unwrap(), &f.code, now_s()).unwrap();
        put_join_state(&sdir, &f.code, "pending", "");
        // админ выдаёт запись серверу
        let m = join_msg(&f.code, &server, "es");
        on_join(&f.dir, &f.root, &f.tr, &message(&server, &f.root, &m), m);
        let rec = own_chain_record(&f.tr.lock().unwrap(), &server.public_key_bytes(), f.root.hash()).unwrap();
        let grant = |rec: &Record| { let mut g = msg("grant", &f.code.id()); g.rec = hex(&rec.wire()); g };
        // запись на чужой ключ: не принимается
        let for_other = f.tr.lock().unwrap().issue(*f.root.hash(), other.public_key_bytes(), DEFAULT_RIGHTS).unwrap();
        let g = grant(&for_other);
        assert!(!on_reply(&sdir, &server, &str_, &message(&f.root, &server, &g), g));
        // запись с другими правами (шире кода)
        let wide = Record::sign(&f.root, *f.root.hash(), server.public_key_bytes(), trust::ALL, now_ms() as u64 + 5).unwrap();
        let g = grant(&wide);
        assert!(!on_reply(&sdir, &server, &str_, &message(&f.root, &server, &g), g));
        assert_eq!(str_.lock().unwrap().rights_in(f.root.hash(), server.hash()), 0);
        // ответ не от корня (подпись чужая)
        let g = grant(&rec);
        assert!(!on_reply(&sdir, &server, &str_, &message(&other, &server, &g), g));
        // верный ответ
        let g = grant(&rec);
        assert!(on_reply(&sdir, &server, &str_, &message(&f.root, &server, &g), g));
        assert_eq!(str_.lock().unwrap().rights_in(f.root.hash(), server.hash()), DEFAULT_RIGHTS);
        assert_eq!(read_join_state(&sdir).unwrap().state, "joined");
        let restored = Trust::load(server.clone(), &sdir).unwrap();
        assert_eq!(restored.rights_in(f.root.hash(), server.hash()), DEFAULT_RIGHTS, "права пережили перезапуск");
        // deny закрывает попытки
        put_join_state(&sdir, &f.code, "pending", "");
        let mut d = msg("deny", &f.code.id());
        d.reason = "full".into();
        on_reply(&sdir, &server, &str_, &message(&f.root, &server, &d), d);
        assert_eq!(read_join_state(&sdir).unwrap().state, "denied");
        std::fs::remove_dir_all(f.dir).unwrap();
        std::fs::remove_dir_all(sdir).unwrap();
    }

    #[test]
    fn grant_without_pending_state_or_for_other_code_is_ignored() {
        let f = admin_fixture(4);
        let server = id();
        let sdir = tmp("nostate");
        let str_ = Arc::new(Mutex::new(Trust::new(server.clone(), Some(sdir.join("trust.json")))));
        let rec = f.tr.lock().unwrap().issue(*f.root.hash(), server.public_key_bytes(), DEFAULT_RIGHTS).unwrap();
        let mut g = msg("grant", &f.code.id());
        g.rec = hex(&rec.wire());
        assert!(!on_reply(&sdir, &server, &str_, &message(&f.root, &server, &g), g), "нет pending: якорь не из кода, ничего не принимаем");
        assert!(!str_.lock().unwrap().has_anchor(f.root.hash()));
        std::fs::remove_dir_all(f.dir).unwrap();
        std::fs::remove_dir_all(sdir).unwrap();
    }

    // ---------------------------------------------------------------- сквозной сценарий по настоящему LXMF/RNS на loopback

    use leviculum_std::api::NodeBuilder;

    struct Peer { id: Identity, dir: PathBuf, trust: Arc<Mutex<Trust>>, _keep: Vec<Box<dyn std::any::Any>> }

    async fn peer(name: &str, base: &Path, id: Identity, hub: std::net::SocketAddr) -> Peer {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let trust = Arc::new(Mutex::new(Trust::load(id.clone(), &dir).unwrap()));
        let (processor, rt) = lxmf_admin::AdminProcessor::new(id.clone());
        let mut node = NodeBuilder::new().identity(id.clone()).storage_path(dir.join("transport")).add_tcp_client(hub)
            .accept_cbc_links(true).core_processor(processor).build().unwrap();
        node.start().await.unwrap();
        let sync = lxmf_sync::register(&dir, rt.sync.clone());
        let (d, i, t) = (dir.clone(), id.clone(), trust.clone());
        std::thread::spawn(move || {
            while let Ok(m) = rt.inbound.recv() {
                if m.title == TITLE { on_lxmf(&d, &i, &t, &m); }
                else if m.title == lxmf_sync::TITLE {
                    // минимальный приём trust.sync (в узле это on_sync_node): ack и записи; подпись записи проверяет Trust::offer
                    let Some(w) = lxmf_sync::Wire::decode(&m) else { continue };
                    if let Some(a) = w.ack { lxmf_sync::received_ack(&d, m.source_hash, a); continue; }
                    if let Some((recs, _)) = lxmf_sync::parsed(&w) {
                        let mut tr = t.lock().unwrap();
                        for r in recs { let _ = tr.offer(r); }
                        let _ = tr.save();
                    }
                }
            }
        });
        Peer { id, dir, trust, _keep: vec![Box::new(node), Box::new(sync)] }
    }

    async fn wait_until(secs: u64, mut f: impl FnMut() -> bool) -> bool {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            if f() { return true; }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        false
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_servers_join_by_one_code_become_neighbors_and_third_over_limit_is_denied() {
        rate_reset();
        let base = tmp("e2e");
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        // «публичная RNS»: транспортный узел без прав и без LXMF
        let hub_id = id();
        let mut hub = NodeBuilder::new().identity(hub_id).storage_path(base.join("hub")).enable_transport(true).add_tcp_server(addr).build().unwrap();
        hub.start().await.unwrap();
        let admin = peer("admin", &base, id(), addr).await;
        let (s1, s2, s3) = (id(), id(), id());
        let text = create(&admin.dir, &admin.id, DEFAULT_RIGHTS, 2).unwrap();
        let code = Code::parse(&text).unwrap();
        let root = *admin.id.hash();
        let note: Arc<dyn Fn(String) + Send + Sync> = Arc::new(|_| {});
        let mut servers = vec![];
        for (n, sid) in [("s1", &s1), ("s2", &s2)] {
            let p = peer(n, &base, sid.clone(), addr).await;
            adopt(&mut p.trust.lock().unwrap(), &code, now_s()).unwrap();
            spawn_join(p.dir.clone(), p.id.clone(), p.trust.clone(), code.clone(), n.into(), None, note.clone());
            let (t, h) = (p.trust.clone(), *sid.hash());
            assert!(wait_until(90, || t.lock().unwrap().rights_in(&root, &h) == DEFAULT_RIGHTS).await, "сервер {n} не получил права по коду");
            let d = p.dir.clone();
            assert!(wait_until(10, || read_join_state(&d).is_some_and(|s| s.state == "joined")).await);
            servers.push(p);
        }
        // второй сервер получил запись первого в ответе, первый — запись второго через sync админа
        let (p1, p2) = (&servers[0], &servers[1]);
        assert_eq!(p2.trust.lock().unwrap().rights_in(&root, s1.hash()), DEFAULT_RIGHTS, "ответ несёт записи ранее вступивших");
        let (t1, h2) = (p1.trust.clone(), *s2.hash());
        assert!(wait_until(60, || t1.lock().unwrap().rights_in(&root, &h2) == DEFAULT_RIGHTS).await, "первый сервер не узнал о втором");
        let now = now_ms() as u64;
        assert!(p1.trust.lock().unwrap().common_with(&s2.public_key_bytes(), trust::TRANSIT, trust::TRANSIT, true, true, now), "s1 видит s2 соседом");
        assert!(p2.trust.lock().unwrap().common_with(&s1.public_key_bytes(), trust::TRANSIT, trust::TRANSIT, true, true, now), "s2 видит s1 соседом");
        // права ровно из кода: ни USE, ни ADD
        for p in &servers { assert_eq!(p.trust.lock().unwrap().rights_in(&root, p.id.hash()) & !DEFAULT_RIGHTS, 0); }
        // третий сверх лимита
        let p3 = peer("s3", &base, s3.clone(), addr).await;
        adopt(&mut p3.trust.lock().unwrap(), &code, now_s()).unwrap();
        spawn_join(p3.dir.clone(), p3.id.clone(), p3.trust.clone(), code.clone(), "s3".into(), None, note.clone());
        let d3 = p3.dir.clone();
        assert!(wait_until(90, || read_join_state(&d3).is_some_and(|s| s.state == "denied")).await, "отказ сверх лимита не дошёл");
        assert_eq!(read_join_state(&p3.dir).unwrap().reason, "full");
        assert_eq!(p3.trust.lock().unwrap().rights_in(&root, s3.hash()), 0);
        let v = list(&admin.dir);
        assert_eq!(v["codes"][0]["joined"], 2);
        assert_eq!(v["codes"][0]["servers"][0]["name"], "s1");
        // после перезапуска сервера права берутся из trust.json, запросов больше нет
        let restored = Trust::load(s1.clone(), &p1.dir).unwrap();
        assert_eq!(restored.rights_in(&root, s1.hash()), DEFAULT_RIGHTS);
        drop(servers);
        drop(p3);
        drop(admin);
        drop(hub);
        let _ = std::fs::remove_dir_all(base);
    }
}
