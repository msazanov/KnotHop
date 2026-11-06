//! Приглашения (ADR 0028 §2): строка «стопка пар хеш+пин», погашение `redeem → accept → ack` между нодами по LXMF,
//! `pending-invite.json` получателя. Один модуль и один обработчик для сервера, ПК и телефона (`Core`).
//!
//! Строка не несёт ни прав, ни ключей, ни срока: это только «где (хеш ноды) и чем доказать (пин)». Пин в сеть не уходит —
//! только HMAC от него внутри LXMF, зашифрованного на ноду, которая пин и так знает (оракула нет: неверное — молчание).

use super::*;
use anyhow::anyhow;
use crate::lxmf_sync::{self, Target};
use crate::peers::{self, Hash, Peers, Pid, Pk, Redeem};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use leviculum_lxmf::Message;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MAX_PAIRS: usize = 8;
const MAX_STRING: usize = 4096;
/// Локальный срок ожидания погашения у получателя (требование 10).
pub const PENDING_TTL_MS: u64 = 7 * 24 * 3600 * 1000;
const MAX_PENDING_PAIRS: usize = 64;
const MAX_SOURCES: usize = 256;
const REENQUEUE_S: u64 = 60;

// ------------------------------------------------------------------------------------------------ строка

fn ck(body: &[u8]) -> [u8; 4] {
    Sha256::digest([b"knothop-invite-v5".as_slice(), body].concat())[..4].try_into().unwrap()
}

/// Строка приглашения: `ver(1)=1 | n(1) | n × [hash(16) | pin(16)] | ck(4)`, base64url без `=` и префикса.
/// Пары сортируются по хешу; хеши различны; пин не нулевой.
pub fn encode(pairs: &[(Hash, [u8; 16])]) -> Result<String> {
    if pairs.is_empty() || pairs.len() > MAX_PAIRS {
        bail!("приглашение: от 1 до {MAX_PAIRS} нод");
    }
    let mut v = pairs.to_vec();
    v.sort_by_key(|p| p.0);
    if v.windows(2).any(|w| w[0].0 == w[1].0) || v.iter().any(|p| p.1 == [0; 16]) {
        bail!("приглашение: повтор хеша или нулевой пин");
    }
    let mut body = vec![1u8, v.len() as u8];
    for (h, pin) in &v {
        body.extend_from_slice(h);
        body.extend_from_slice(pin);
    }
    let c = ck(&body);
    body.extend_from_slice(&c);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body))
}

pub fn decode(s: &str) -> Result<Vec<(Hash, [u8; 16])>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.is_empty() || s.len() > MAX_STRING {
        bail!("приглашение: пусто или длиннее {MAX_STRING} знаков");
    }
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.as_bytes()).map_err(|_| anyhow!("приглашение: не base64url"))?;
    if b.len() < 2 + 4 || b[0] != 1 {
        bail!("приглашение: неверная версия или длина");
    }
    let n = b[1] as usize;
    if n == 0 || n > MAX_PAIRS || b.len() != 2 + n * 32 + 4 {
        bail!("приглашение: неверное число нод или длина");
    }
    let (body, tail) = b.split_at(b.len() - 4);
    if ck(body) != tail {
        bail!("приглашение: контрольная сумма не сошлась (опечатка?)");
    }
    let mut out: Vec<(Hash, [u8; 16])> = Vec::new();
    for c in body[2..].chunks(32) {
        let (h, pin): (Hash, [u8; 16]) = (c[..16].try_into().unwrap(), c[16..].try_into().unwrap());
        if pin == [0; 16] || out.iter().any(|p| p.0 == h) {
            bail!("приглашение: нулевой пин или повтор хеша");
        }
        out.push((h, pin));
    }
    if !out.windows(2).all(|w| w[0].0 < w[1].0) {
        bail!("приглашение: пары не отсортированы");
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ MAC

fn mac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn mac_ok(key: &[u8; 32], parts: &[&[u8]], tag: &[u8]) -> bool {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        m.update(p);
    }
    m.verify_slice(tag).is_ok()
}

/// Nonce стороны H детерминирован: повтор `accept` и проверка `ack` не требуют состояния.
fn h_nonce(key: &[u8; 32], pk_n: &Pk, n_nonce: &[u8; 16]) -> [u8; 16] {
    mac(key, &[b"hn", pk_n, n_nonce])[..16].try_into().unwrap()
}

fn rights_bytes(rights: u16, roles: u16) -> [u8; 4] {
    let mut b = [0u8; 4];
    b[0..2].copy_from_slice(&rights.to_le_bytes());
    b[2..4].copy_from_slice(&roles.to_le_bytes());
    b
}

fn fixed<const N: usize>(j: &serde_json::Value, k: &str) -> Option<[u8; N]> {
    unhex(j[k].as_str()?).try_into().ok()
}

/// Подсказки адресов от пира: строки ≤80 Б, прошедшие тот же фильтр, что и при наборе (глобальные IP или нормальное имя; частные - только
/// с `KNOTHOP_ALLOW_PRIVATE_DIAL`), не больше трёх и с минимум одним адресом каждого семейства IP. Фильтр получателя не зависит от отправителя.
///
/// `lan` (только нода-клиент): дополнительно принимаются литеральные частные IPv4 и ULA IPv6 (`vpn::sane_hint_addr_lan`). Это синтаксис;
/// решение «набирать ли» принимается позже, на момент набора, по подсетям текущих интерфейсов (ADR 0028 §2.4a, п.5 AGENTS).
pub(crate) fn clean_hints(v: &serde_json::Value, lan: bool) -> Vec<String> {
    let ok = |s: &str| if lan { crate::vpn::sane_hint_addr_lan(s) } else { crate::vpn::sane_hint_addr(s) };
    let all: Vec<String> = v.as_array().map(|a| a.iter().filter_map(|s| s.as_str()).filter(|s| s.len() <= 80 && ok(s)).map(String::from).collect()).unwrap_or_default();
    peers::balance_hints(all, peers::MAX_CONTACT_HINTS)
}

// ------------------------------------------------------------------------------------------------ pending-invite.json

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairState {
    /// погашение ещё не завершено
    None,
    Settled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub pk_h: Pk,
    pub rights: u16,
    pub roles: u16,
    pub name_h: String,
    pub hints: Vec<String>,
    /// подсказка REALITY выдавшей ноды; подсказка, не полномочие
    pub rl: serde_json::Value,
    /// выдавшая нода объявила себя клиентом (телефон)
    pub client: bool,
}

#[derive(Clone, Debug)]
pub struct Pair {
    pub h: Hash,
    pub pin: [u8; 16],
    pub n_nonce: [u8; 16],
    pub state: PairState,
    pub acc: Option<Accepted>,
    /// 0 - обычное вступление; `ADOPT_IF_EMPTY` / `ADOPT_FORCE` - первый запуск сервера по `--invite-file`: после проверенного `accept`
    /// выдавший записывается управляющим (только если у ноды ещё нет управляющих / при `--accept-manage`)
    pub adopt: u8,
}

pub const ADOPT_IF_EMPTY: u8 = 1;
pub const ADOPT_FORCE: u8 = 2;

impl Pair {
    fn new(h: Hash, pin: [u8; 16]) -> Pair {
        let mut n = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut n);
        Pair { h, pin, n_nonce: n, state: PairState::None, acc: None, adopt: 0 }
    }
    fn pid(&self) -> Pid {
        peers::pin_id(&self.pin)
    }
    fn key(&self) -> [u8; 32] {
        peers::pin_key(&self.pin)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Pending {
    pub created: u64,
    pub pairs: Vec<Pair>,
}

fn pending_path(state: &Path) -> PathBuf {
    state.join("pending-invite.json")
}

fn load_pending(state: &Path) -> Result<Pending> {
    let Some(b) = peers::read_private(&pending_path(state), 256 * 1024)? else { return Ok(Pending::default()) };
    let v: serde_json::Value = serde_json::from_slice(&b).context("pending-invite.json")?;
    let mut p = Pending { created: v["created"].as_u64().unwrap_or(0), pairs: vec![] };
    for x in v["pairs"].as_array().ok_or_else(|| anyhow!("pending-invite.json: pairs"))? {
        let acc = if x["acc"].is_object() {
            let a = &x["acc"];
            Some(Accepted {
                pk_h: fixed(a, "pk_h").ok_or_else(|| anyhow!("pending-invite.json: pk_h"))?, rights: a["rights"].as_u64().unwrap_or(0) as u16,
                roles: a["roles"].as_u64().unwrap_or(0) as u16,
                name_h: a["name_h"].as_str().unwrap_or("").to_string(), hints: a["hints"].as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).take(3).collect()).unwrap_or_default(),
                rl: a["rl"].clone(), client: a["client"].as_bool().unwrap_or(false),
            })
        } else { None };
        p.pairs.push(Pair {
            h: fixed(x, "h").ok_or_else(|| anyhow!("pending-invite.json: h"))?, pin: fixed(x, "pin").ok_or_else(|| anyhow!("pending-invite.json: pin"))?,
            n_nonce: fixed(x, "n").ok_or_else(|| anyhow!("pending-invite.json: n"))?,
            state: match x["state"].as_str() { Some("settled") => PairState::Settled, _ => PairState::None }, acc,
            adopt: x["adopt"].as_u64().unwrap_or(0).min(ADOPT_FORCE as u64) as u8,
        });
    }
    Ok(p)
}

fn save_pending(state: &Path, p: &Pending) -> Result<()> {
    let path = pending_path(state);
    if p.pairs.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    let pairs: Vec<_> = p.pairs.iter().map(|x| {
        let mut j = serde_json::json!({"h": hex(&x.h), "pin": hex(&x.pin), "n": hex(&x.n_nonce), "state": match x.state { PairState::None => "none", PairState::Settled => "settled" }, "adopt": x.adopt});
        if let Some(a) = &x.acc {
            j["acc"] = serde_json::json!({"pk_h": hex(&a.pk_h), "rights": a.rights, "roles": a.roles, "name_h": a.name_h, "hints": a.hints, "rl": a.rl, "client": a.client});
        }
        j
    }).collect();
    crate::lxmf_admin::write_private_atomic(&path, &serde_json::to_vec(&serde_json::json!({"v": 1, "created": p.created, "pairs": pairs}))?)
}

/// Добавить пары новой строки к неоконченной стопке. Уже имеющаяся пара (тот же хеш и пин) не дублируется и не сбрасывается:
/// погашенные (`Settled`) и открытые пары остаются как есть. Лимит считается только по новым парам, так что повтор той же
/// строки при полной стопке - не ошибка. Срок 7 суток отсчитывается от последнего добавления (хранится один `created` на стопку).
/// Возвращает число добавленных пар.
fn merge_pairs(pend: &mut Pending, pairs: &[(Hash, [u8; 16])], me: &Hash, now: u64, adopt: u8) -> Result<usize> {
    if pairs.iter().any(|(h, _)| h == me) {
        bail!("приглашение выпущено этой же нодой");
    }
    let fresh: Vec<&(Hash, [u8; 16])> = pairs.iter().filter(|(h, pin)| !pend.pairs.iter().any(|x| x.h == *h && x.pin == *pin)).collect();
    if pend.pairs.len() + fresh.len() > MAX_PENDING_PAIRS {
        bail!("слишком много неоконченных приглашений");
    }
    for (h, pin) in &fresh {
        let mut p = Pair::new(*h, *pin);
        p.adopt = adopt;
        pend.pairs.push(p);
    }
    if !fresh.is_empty() {
        pend.created = now;
    }
    Ok(fresh.len())
}

fn pending_json(p: &Pending) -> serde_json::Value {
    serde_json::json!({
        "created": p.created, "expires": p.created + PENDING_TTL_MS,
        "pairs": p.pairs.iter().map(|x| serde_json::json!({"h": hex(&x.h), "state": match x.state { PairState::None => "waiting", PairState::Settled => "done" },
            "rights": x.acc.as_ref().map(|a| a.rights), "name": x.acc.as_ref().map(|a| a.name_h.clone())})).collect::<Vec<_>>(),
    })
}

/// Вступление при выключенной «Сети» (ноды в процессе нет): пары дописываются в `pending-invite.json`, нода погасит их при запуске.
/// Только когда ядра этого state в процессе нет - иначе писать должно оно (`Core::join`).
pub fn join_offline(state: &Path, me: &Hash, s: &str) -> Result<(Vec<Hash>, usize)> {
    let pairs = decode(s)?;
    let mut pend = load_pending(state)?;
    let added = merge_pairs(&mut pend, &pairs, me, now_ms() as u64, 0)?;
    if added > 0 {
        save_pending(state, &pend)?;
    }
    Ok((pairs.iter().map(|p| p.0).collect(), added))
}

/// Ожидающие пары с диска (для приложения при выключенной ноде); нечитаемый файл - пустое представление.
pub fn pending_view_offline(state: &Path) -> serde_json::Value {
    pending_json(&load_pending(state).unwrap_or_default())
}

// ------------------------------------------------------------------------------------------------ лимиты

/// Лимит частоты до подписи и диска: ≤`per` в минуту с источника, ≤`total` всего, ≤256 источников.
pub struct Rate {
    per: usize,
    total: usize,
    global: VecDeque<Instant>,
    src: HashMap<[u8; 16], VecDeque<Instant>>,
}

impl Rate {
    pub fn new(per: usize, total: usize) -> Rate {
        Rate { per, total, global: VecDeque::new(), src: HashMap::new() }
    }
    pub fn allow(&mut self, source: [u8; 16]) -> bool {
        let now = Instant::now();
        let w = Duration::from_secs(60);
        self.global.retain(|t| now.duration_since(*t) < w);
        self.src.retain(|_, q| { q.retain(|t| now.duration_since(*t) < w); !q.is_empty() });
        if self.global.len() >= self.total || (!self.src.contains_key(&source) && self.src.len() >= MAX_SOURCES) {
            return false;
        }
        let q = self.src.entry(source).or_default();
        if q.len() >= self.per {
            return false;
        }
        q.push_back(now);
        self.global.push_back(now);
        true
    }
}

/// Задержка источника после неверного пруфа известного pid: `min(60 с, 0,5 с·k²)`.
#[derive(Default)]
pub struct Fail2Ban {
    m: HashMap<[u8; 16], (u32, Instant)>,
}

impl Fail2Ban {
    pub fn banned(&self, s: &[u8; 16]) -> bool {
        self.m.get(s).is_some_and(|(_, until)| *until > Instant::now())
    }
    pub fn fail(&mut self, s: [u8; 16]) {
        if self.m.len() >= MAX_SOURCES && !self.m.contains_key(&s) {
            let now = Instant::now();
            self.m.retain(|_, (_, u)| *u > now);
            if self.m.len() >= MAX_SOURCES {
                return;
            }
        }
        let e = self.m.entry(s).or_insert((0, Instant::now()));
        e.0 = e.0.saturating_add(1);
        e.1 = Instant::now() + Duration::from_millis(((e.0 as u64).pow(2) * 500).min(60_000));
    }
}

// ------------------------------------------------------------------------------------------------ ядро

/// Исходящее сообщение ядра: по умолчанию в очередь LXMF `lxmf_sync`; тесты подменяют.
pub type Sink = Arc<dyn Fn(&[u8], Target, Vec<u8>, &str, u64, bool) + Send + Sync>;

pub struct Core {
    pub state: PathBuf,
    pub me_pk: Pk,
    pub me_hash: Hash,
    pub peers: Arc<Mutex<Peers>>,
    sink: Sink,
    /// нода-клиент (телефон): объявляет это в `accept`/`ack` (`cl`); управления собой никому не даёт
    pub is_client: bool,
    name: Mutex<String>,
    rl: Mutex<serde_json::Value>,
    hints: Box<dyn Fn() -> Vec<String> + Send + Sync>,
    on_change: Box<dyn Fn() + Send + Sync>,
    log: Box<dyn Fn(String) + Send + Sync>,
    pending: Mutex<Pending>,
    rate_inv: Mutex<Rate>,
    pub(crate) rate_cmd: Mutex<Rate>,
    f2b: Mutex<Fail2Ban>,
    enq: Mutex<HashMap<String, Instant>>,
    /// когда последний раз проверяли свои адреса и какие разослали контактам (`addr`)
    last_addr: Mutex<(Option<Instant>, Vec<String>)>,
    pub(crate) cmd: crate::ncmd::State,
}

static CORES: std::sync::OnceLock<Mutex<HashMap<PathBuf, std::sync::Weak<Core>>>> = std::sync::OnceLock::new();

/// Реестр ядер процесса по каталогу состояния: приложение (JNI) и CLI-обвязка находят живое ядро без файлового канала.
pub fn register(core: &Arc<Core>) {
    let k = core.state.canonicalize().unwrap_or_else(|_| core.state.clone());
    CORES.get_or_init(Default::default).lock().unwrap().insert(k, Arc::downgrade(core));
}

pub fn lookup(state: &Path) -> Option<Arc<Core>> {
    let k = state.canonicalize().unwrap_or_else(|_| state.to_path_buf());
    CORES.get()?.lock().unwrap().get(&k)?.upgrade()
}

pub fn now_s() -> u64 {
    now_ms() as u64 / 1000
}

impl Core {
    pub fn new(state: &Path, identity: Identity, peers: Arc<Mutex<Peers>>, is_client: bool, hints: Box<dyn Fn() -> Vec<String> + Send + Sync>,
               on_change: Box<dyn Fn() + Send + Sync>, log: Box<dyn Fn(String) + Send + Sync>) -> Result<Arc<Core>> {
        let st = state.to_path_buf();
        let sink: Sink = Arc::new(move |title, target, content, tag, exp, ack| {
            if ack { lxmf_sync::reply(&st, title, target, content, tag); } else { lxmf_sync::send(&st, title, target, content, tag, exp, lxmf_sync::always()); }
        });
        let pending = load_pending(state)?;
        let me_pk = identity.public_key_bytes();
        let me_hash = peers::hash_of(&me_pk).ok_or_else(|| anyhow!("identity"))?;
        Ok(Arc::new(Core {
            state: state.to_path_buf(), me_pk, me_hash, peers, sink, is_client, name: Mutex::new(String::new()), rl: Mutex::new(serde_json::Value::Null), hints, on_change, log,
            pending: Mutex::new(pending), rate_inv: Mutex::new(Rate::new(6, 30)), rate_cmd: Mutex::new(Rate::new(12, 60)), f2b: Mutex::new(Fail2Ban::default()),
            enq: Mutex::new(HashMap::new()), last_addr: Mutex::new((None, Vec::new())), cmd: crate::ncmd::State::load(state),
        }))
    }

    /// Подсказка REALITY этой ноды: едет в `accept`, адресов в ней нет.
    pub fn set_rl(&self, rl: serde_json::Value) {
        *self.rl.lock().unwrap() = rl;
    }

    pub fn set_name(&self, n: &str) {
        *self.name.lock().unwrap() = n.chars().filter(|c| !c.is_control()).take(48).collect();
    }
    fn name(&self) -> String {
        self.name.lock().unwrap().clone()
    }
    #[cfg(test)]
    pub fn with_sink(self: Arc<Self>, sink: Sink) -> Arc<Core> {
        // только для тестов: Core ещё никем не разделён
        let mut c = Arc::try_unwrap(self).ok().expect("Core уже разделён");
        c.sink = sink;
        Arc::new(c)
    }
    pub(crate) fn send(&self, title: &[u8], target: Target, content: Vec<u8>, tag: &str, exp: u64, ack: bool) {
        (self.sink)(title, target, content, tag, exp, ack);
    }
    pub(crate) fn changed(&self) {
        (self.on_change)();
    }
    pub(crate) fn note(&self, s: String) {
        (self.log)(s);
    }

    // -------------------------------------------------------------------------------------------- вход сообщений

    /// Единая точка входа служебных LXMF: приглашения и команды. Лимиты — до разбора и подписи.
    pub fn on_message(&self, m: &Message) {
        if m.destination_hash != peers::lxmf_destination(&self.me_hash) {
            return;
        }
        if m.title == lxmf_sync::TITLE_INV {
            self.on_inv(m);
        } else if m.title == lxmf_sync::TITLE_CMD {
            self.on_cmd(m);
        }
    }

    fn on_inv(&self, m: &Message) {
        if m.content.len() > crate::lxmf_admin::MAX_ADMIN_CONTENT || !self.rate_inv.lock().unwrap().allow(m.source_hash) {
            return;
        }
        if self.f2b.lock().unwrap().banned(&m.source_hash) {
            return;
        }
        let Ok(j) = serde_json::from_slice::<serde_json::Value>(&m.content) else { return };
        if j["v"].as_u64() != Some(1) {
            return;
        }
        match j["op"].as_str() {
            Some("redeem") => self.on_redeem(m, &j),
            Some("accept") => self.on_accept(m, &j),
            Some("ack") => self.on_ack(m, &j),
            Some("deny") => self.on_deny(m, &j),
            Some("addr") => self.on_addr(m, &j),
            _ => {}
        }
    }

    /// Обновление адресов известного контакта (сменился IP/порт): подписанное LXMF от ключа контакта. Меняются только подсказки
    /// (после того же фильтра, что и у `accept`); права и роли не затрагиваются. Незнакомый источник - молчание.
    fn on_addr(&self, m: &Message, j: &serde_json::Value) {
        let hints = clean_hints(&j["hints"], self.is_client);
        if hints.is_empty() {
            return;
        }
        let changed = {
            let mut p = self.peers.lock().unwrap();
            let Some(pk) = p.pk_for_lxmf_source(&m.source_hash) else { return };
            let Some(h) = peers::hash_of(&pk) else { return };
            if p.contact(&h).is_none() || !crate::lxmf_admin::signed_by_trusted_source(m, &pk) {
                return;
            }
            p.contact_set_hints(&h, hints) && p.save().is_ok()
        };
        if changed {
            self.changed();
        }
    }

    /// Раз в ≈30 с: если мои адреса сменились, разослать `addr` контактам, которых я набираю (им разрешено использовать меня либо я им).
    fn announce_addrs(&self) {
        {
            let mut l = self.last_addr.lock().unwrap();
            if l.0.is_some_and(|t| t.elapsed() < Duration::from_secs(30)) {
                return;
            }
            l.0 = Some(Instant::now());
        }
        let now = peers::balance_hints((self.hints)(), peers::MAX_CONTACT_HINTS);
        if now.is_empty() {
            return;
        }
        let targets: Vec<Pk> = {
            let mut l = self.last_addr.lock().unwrap();
            if l.1 == now {
                return;
            }
            l.1 = now.clone();
            let p = self.peers.lock().unwrap();
            p.contact_list().into_iter().filter(|c| c.they_grant & peers::USE != 0 || p.rights_pk(&c.pk) != 0).map(|c| c.pk).take(32).collect()
        };
        let body = serde_json::json!({"v": 1, "op": "addr", "hints": now}).to_string();
        let ver = hex(&Sha256::digest(body.as_bytes())[..4]);
        for pk in targets {
            let tag = format!("inv:addr:{}:{ver}", &hex(&peers::hash_of(&pk).unwrap_or([0; 16]))[..8]);
            self.send(lxmf_sync::TITLE_INV, Target::Pk(pk), body.clone().into_bytes(), &tag, now_s() + 3600, false);
        }
    }

    /// Роль H: получатель погасил приглашение на мне.
    fn on_redeem(&self, m: &Message, j: &serde_json::Value) {
        let (Some(pid), Some(n_nonce), Some(pk_n), Some(proof)) = (fixed::<8>(j, "pid"), fixed::<16>(j, "n_nonce"), fixed::<64>(j, "pk_n"), fixed::<32>(j, "proof")) else { return };
        let name = j["name"].as_str().unwrap_or("").to_string();
        if name.len() > 96 || !crate::lxmf_admin::signed_by_trusted_source(m, &pk_n) {
            return;
        }
        let me = self.me_hash;
        let outcome = {
            let mut p = self.peers.lock().unwrap();
            p.redeem(&pid, &pk_n, &name, now_ms() as u64, |key| mac_ok(key, &[b"redeem", &me, &pk_n, &n_nonce, name.as_bytes()], &proof))
        };
        match outcome {
            Redeem::Accepted { rights, fresh, .. } => {
                let (key, exp, roles) = {
                    let p = self.peers.lock().unwrap();
                    let inv = p.invite(&pid).cloned();
                    (inv.as_ref().map(|i| i.key), inv.map_or(0, |i| i.expires / 1000), p.roles())
                };
                let Some(key) = key else { return };
                let hn = h_nonce(&key, &pk_n, &n_nonce);
                let tag_mac = mac(&key, &[b"accept", &me, &pk_n, &n_nonce, &hn, &rights_bytes(rights, roles)]);
                let body = serde_json::json!({"v": 1, "op": "accept", "pid": hex(&pid), "n_nonce": hex(&n_nonce), "h_nonce": hex(&hn), "pk_h": hex(&self.me_pk),
                    "rights": rights, "roles": roles, "name_h": self.name(), "hints": peers::balance_hints((self.hints)(), peers::MAX_CONTACT_HINTS), "rl": self.rl.lock().unwrap().clone(), "cl": self.is_client, "mac": hex(&tag_mac)});
                let exp = exp.max(now_s() + 600);
                self.send(lxmf_sync::TITLE_INV, Target::Pk(pk_n), serde_json::to_vec(&body).unwrap(), &format!("inv:accept:{}", hex(&pid)), exp, false);
                if fresh {
                    self.note(format!("приглашение {} погашено узлом {}", hex(&pid), &hex(&peers::hash_of(&pk_n).unwrap_or([0; 16]))[..8]));
                    self.changed();
                }
            }
            Redeem::Used => {
                // пруф верен, значит отправитель знает пин; чужим — молчание
                let mut key = None;
                if let Some(i) = self.peers.lock().unwrap().invite(&pid) { key = Some(i.key); }
                if let Some(key) = key {
                    let t = mac(&key, &[b"deny", &pid, &n_nonce]);
                    let body = serde_json::json!({"v": 1, "op": "deny", "pid": hex(&pid), "n_nonce": hex(&n_nonce), "reason": "used", "mac": hex(&t)});
                    self.send(lxmf_sync::TITLE_INV, Target::Pk(pk_n), serde_json::to_vec(&body).unwrap(), &format!("inv:deny:{}", hex(&pid)), now_s() + 600, true);
                }
            }
            Redeem::BadProof => self.f2b.lock().unwrap().fail(m.source_hash),
            Redeem::Silent => {}
        }
    }

    /// Роль N: H подтвердил погашение и сообщил права.
    fn on_accept(&self, m: &Message, j: &serde_json::Value) {
        let (Some(pid), Some(n_nonce), Some(hn), Some(pk_h), Some(tag)) =
            (fixed::<8>(j, "pid"), fixed::<16>(j, "n_nonce"), fixed::<16>(j, "h_nonce"), fixed::<64>(j, "pk_h"), fixed::<32>(j, "mac")) else { return };
        let (rights, roles) = (j["rights"].as_u64().unwrap_or(0) as u16 & peers::KNOWN, j["roles"].as_u64().unwrap_or(0) as u16);
        let Some(h) = peers::hash_of(&pk_h) else { return };
        let mut pend = self.pending.lock().unwrap();
        let Some(idx) = pend.pairs.iter().position(|x| x.h == h && x.pid() == pid && x.n_nonce == n_nonce) else { return };
        let pair = pend.pairs[idx].clone();
        let key = pair.key();
        if !crate::lxmf_admin::signed_by_trusted_source(m, &pk_h)
            || !mac_ok(&key, &[b"accept", &h, &self.me_pk, &n_nonce, &hn, &rights_bytes(rights, roles)], &tag) {
            return;
        }
        let acc = Accepted {
            pk_h, rights, roles, name_h: j["name_h"].as_str().unwrap_or("").chars().take(48).collect(),
            hints: clean_hints(&j["hints"], self.is_client),
            rl: j["rl"].clone(), client: j["cl"].as_bool().unwrap_or(false),
        };
        match pair.state {
            PairState::Settled => {
                drop(pend);
                self.send_ack(&pair, &hn);
            }
            _ => {
                if self.settle(&mut pend, idx, acc, &hn) {
                    drop(pend);
                    self.changed();
                }
            }
        }
    }

    /// Применить `accept` на получателе: контакт (и управляющий - только для помеченной при `--invite-file` пары сервера), на диск, затем `ack`. false — не записалось, повторится.
    fn settle(&self, pend: &mut Pending, idx: usize, acc: Accepted, hn: &[u8; 16]) -> bool {
        let pair = pend.pairs[idx].clone();
        let mut adopted = false;
        {
            let mut p = self.peers.lock().unwrap();
            if p.accepted(acc.pk_h, &acc.name_h, acc.hints.clone(), acc.rights, acc.roles, now_ms() as u64).is_err() {
                return false;
            }
            // управление - свойство запуска, а не приглашения (ADR 0028 §2.5): только сервер, только по помеченной паре, и только если
            // таблица ещё без управляющих (или явный --accept-manage). Подпись LXMF и MAC `accept` уже проверены в `on_accept`.
            if !self.is_client && pair.adopt != 0 && (pair.adopt == ADOPT_FORCE || !p.has_controllers()) {
                if p.adopt_controller(acc.pk_h, &acc.name_h, now_ms() as u64).is_err() {
                    return false;
                }
                adopted = true;
            }
            p.contact_rl(&acc.pk_h, &acc.rl);
            if let Some(h) = peers::hash_of(&acc.pk_h) { p.set_contact_client(&h, acc.client); }
            if p.save().is_err() {
                return false;
            }
        }
        self.note(format!("приглашение принято: нода {} ({}) разрешает мне {}{}", &hex(&pair.h)[..8], acc.name_h, peers::rights_text(acc.rights),
            if adopted { "; он записан управляющим этой нодой (первый запуск по приглашению)" } else { "" }));
        pend.pairs[idx].state = PairState::Settled;
        pend.pairs[idx].acc = None;
        let _ = save_pending(&self.state, pend);
        self.send_ack(&pair, hn);
        lxmf_sync::acknowledged(&self.state, peers::lxmf_destination(&pair.h), &format!("inv:redeem:{}", hex(&pair.pid())));
        if pend.pairs.iter().all(|x| x.state == PairState::Settled) {
            // все пары погашены: пины больше нигде не хранятся
            pend.pairs.clear();
            let _ = save_pending(&self.state, pend);
        }
        true
    }

    fn send_ack(&self, pair: &Pair, hn: &[u8; 16]) {
        // ответные подсказки: мои адреса и имя едут выдавшему в том же шифрованном LXMF (для обратного дозвона); права от них не меняются
        let body = serde_json::json!({"v": 1, "op": "ack", "pid": hex(&pair.pid()), "n_nonce": hex(&pair.n_nonce), "mac2": hex(&mac(&pair.key(), &[b"ack", hn])),
            "name": self.name(), "cl": self.is_client, "hints": peers::balance_hints((self.hints)(), peers::MAX_CONTACT_HINTS)});
        self.send(lxmf_sync::TITLE_INV, Target::Hash(pair.h), serde_json::to_vec(&body).unwrap(), &format!("inv:ack:{}", hex(&pair.pid())), now_s() + 600, true);
    }

    /// Роль H: получатель подтвердил, приглашение закрыто.
    fn on_ack(&self, m: &Message, j: &serde_json::Value) {
        let (Some(pid), Some(mac2)) = (fixed::<8>(j, "pid"), fixed::<32>(j, "mac2")) else { return };
        let (key, pk) = {
            let p = self.peers.lock().unwrap();
            match p.invite(&pid) {
                Some(peers::Invite { key, state: peers::InviteState::Redeemed { pk, .. }, .. }) => (*key, *pk),
                _ => return,
            }
        };
        if !crate::lxmf_admin::signed_by_trusted_source(m, &pk) {
            return;
        }
        // n_nonce в ack нет: h_nonce восстанавливается из сохранённого погашения только вместе с n_nonce, поэтому проверяем по всем
        // повторно присланным accept: MAC ack привязан к h_nonce, который получатель мог знать только из нашего accept.
        let Some(n_nonce) = fixed::<16>(j, "n_nonce") else { return };
        let hn = h_nonce(&key, &pk, &n_nonce);
        if !mac_ok(&key, &[b"ack", &hn], &mac2) {
            return;
        }
        let hints = clean_hints(&j["hints"], self.is_client);
        let name: String = j["name"].as_str().unwrap_or("").chars().filter(|c| !c.is_control()).take(48).collect();
        let ok = {
            let mut p = self.peers.lock().unwrap();
            let r = p.invite_settle(&pid, &pk);
            // запись контакта о получателе (обратный дозвон): права `peers` не трогаются; уже известный контакт (взаимное знакомство)
            // сохраняет свои they_grant/роли, обновляются только адреса
            if r {
                if let Some(h) = peers::hash_of(&pk) {
                    if p.contact(&h).is_some() { p.contact_set_hints(&h, hints); } else { let _ = p.contact_set(pk, &name, hints, "invite", 0, 0, now_ms() as u64); }
                    p.set_contact_client(&h, j["cl"].as_bool().unwrap_or(false));
                }
            }
            r && p.save().is_ok()
        };
        if ok {
            lxmf_sync::acknowledged(&self.state, m.source_hash, &format!("inv:accept:{}", hex(&pid)));
            self.changed();
        }
    }

    fn on_deny(&self, m: &Message, j: &serde_json::Value) {
        let (Some(pid), Some(n_nonce), Some(tag)) = (fixed::<8>(j, "pid"), fixed::<16>(j, "n_nonce"), fixed::<32>(j, "mac")) else { return };
        let mut pend = self.pending.lock().unwrap();
        let Some(idx) = pend.pairs.iter().position(|x| x.pid() == pid && x.n_nonce == n_nonce && peers::lxmf_destination(&x.h) == m.source_hash) else { return };
        if !mac_ok(&pend.pairs[idx].key(), &[b"deny", &pid, &n_nonce], &tag) {
            return;
        }
        let h = pend.pairs[idx].h;
        pend.pairs.remove(idx);
        let _ = save_pending(&self.state, &pend);
        lxmf_sync::acknowledged(&self.state, peers::lxmf_destination(&h), &format!("inv:redeem:{}", hex(&pid)));
        self.note(format!("приглашение для {} уже использовано другим узлом", &hex(&h)[..8]));
    }

    // -------------------------------------------------------------------------------------------- получатель: вступление

    /// Разобрать и запомнить строку (первый старт сервера, «Вступить» на телефоне). Возвращает хеши нод. Пины пишутся только в
    /// `pending-invite.json` (0600) до полного погашения.
    pub fn join(&self, s: &str) -> Result<Vec<Hash>> {
        self.join_stat(s).map(|r| r.0)
    }

    /// То же, что `join`, плюс число действительно добавленных пар (повторная вставка той же строки добавляет 0).
    /// Новая строка ДОБАВЛЯЕТСЯ к незавершённой стопке: погашенные и открытые пары не теряются, живое соединение ноды не трогается.
    pub fn join_stat(&self, s: &str) -> Result<(Vec<Hash>, usize)> {
        self.join_adopt(s, 0)
    }

    /// `join_stat` для первого запуска сервера (`--invite-file`): пары помечаются `adopt` (`ADOPT_IF_EMPTY` / `ADOPT_FORCE`).
    pub fn join_adopt(&self, s: &str, adopt: u8) -> Result<(Vec<Hash>, usize)> {
        let pairs = decode(s)?;
        let mut pend = self.pending.lock().unwrap();
        let added = merge_pairs(&mut pend, &pairs, &self.me_hash, now_ms() as u64, adopt)?;
        if added > 0 {
            save_pending(&self.state, &pend)?;
        }
        Ok((pairs.iter().map(|p| p.0).collect(), added))
    }

    /// Команда `invite.redeem {hash, pin}`: знакомство нод (§2.7), та же очередь.
    pub fn pending_add(&self, h: Hash, pin: [u8; 16]) -> std::result::Result<(), peers::Reject> {
        if h == self.me_hash || pin == [0; 16] {
            return Err("bad_target");
        }
        let mut pend = self.pending.lock().unwrap();
        if pend.pairs.iter().any(|x| x.h == h && x.pin == pin) {
            return Ok(());
        }
        if pend.pairs.len() >= MAX_PENDING_PAIRS {
            return Err("full");
        }
        if pend.pairs.is_empty() {
            pend.created = now_ms() as u64;
        }
        pend.pairs.push(Pair::new(h, pin));
        save_pending(&self.state, &pend).map_err(|_| "io")?;
        Ok(())
    }

    pub fn pending_view(&self) -> serde_json::Value {
        pending_json(&self.pending.lock().unwrap())
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.lock().unwrap().pairs.is_empty()
    }

    /// Периодически (≈2 с): срок приглашений, повторная постановка погашения в очередь, срок ожидания получателя.
    pub fn tick(&self) {
        let now = now_ms() as u64;
        {
            let mut p = self.peers.lock().unwrap();
            if p.gc(now) {
                let _ = p.save();
            }
        }
        self.announce_addrs();
        let mut enq = self.enq.lock().unwrap();
        let mut pend = self.pending.lock().unwrap();
        if !pend.pairs.is_empty() && now > pend.created + PENDING_TTL_MS {
            self.note("приглашение не погашено за 7 суток: снято".into());
            pend.pairs.clear();
            let _ = save_pending(&self.state, &pend);
            return;
        }
        let exp = (pend.created + PENDING_TTL_MS) / 1000;
        let name = self.name();
        for x in pend.pairs.iter().filter(|x| x.state == PairState::None) {
            let tag = format!("inv:redeem:{}", hex(&x.pid()));
            if enq.get(&tag).is_some_and(|t| t.elapsed() < Duration::from_secs(REENQUEUE_S)) {
                continue;
            }
            let proof = mac(&x.key(), &[b"redeem", &x.h, &self.me_pk, &x.n_nonce, name.as_bytes()]);
            let body = serde_json::json!({"v": 1, "op": "redeem", "pid": hex(&x.pid()), "n_nonce": hex(&x.n_nonce), "pk_n": hex(&self.me_pk), "name": name, "proof": hex(&proof)});
            self.send(lxmf_sync::TITLE_INV, Target::Hash(x.h), serde_json::to_vec(&body).unwrap(), &tag, exp, false);
            enq.insert(tag, Instant::now());
        }
        enq.retain(|_, t| t.elapsed() < Duration::from_secs(3600));
    }

    // -------------------------------------------------------------------------------------------- выдача
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use leviculum_lxmf::DeliveryMethod;
    use leviculum_std::api::generate_identity;

    type Outbox = Arc<Mutex<Vec<(Vec<u8>, Target, Vec<u8>, String)>>>;

    pub struct Node {
        pub core: Arc<Core>,
        pub identity: Identity,
        pub out: Outbox,
    }

    pub fn node(tag: &str, consent: bool) -> Node {
        node_h(tag, consent, vec!["203.0.113.5:47001".into()])
    }

    /// Нода с заданными адресами-подсказками (то, что она объявит в accept/ack/addr).
    pub fn node_h(tag: &str, consent: bool, hints: Vec<String>) -> Node {
        let id = generate_identity();
        let dir = std::env::temp_dir().join(format!("kh-inv-{tag}-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let peers = Arc::new(Mutex::new(Peers::load(id.public_key_bytes(), &dir).unwrap()));
        let out: Outbox = Arc::new(Mutex::new(Vec::new()));
        let o = out.clone();
        let core = Core::new(&dir, id.clone(), peers, consent, Box::new(move || hints.clone()), Box::new(|| {}), Box::new(|_| {})).unwrap();
        let core = core.with_sink(Arc::new(move |title, target, content, tag, _exp, _ack| { o.lock().unwrap().push((title.to_vec(), target, content, tag.to_string())); }));
        core.set_name(tag);
        Node { core, identity: id, out }
    }

    pub fn issue_self(core: &Arc<Core>, rights: u16, ttl: u64) -> String {
        core.issue_stack(&[(core.me_hash, rights)], ttl).unwrap().0
    }

    /// Доставляет всё из очереди `from` получателю `to` как настоящие подписанные LXMF-сообщения.
    pub fn deliver(from: &Node, to: &Node) -> usize {
        let items: Vec<_> = std::mem::take(&mut *from.out.lock().unwrap());
        let mut n = 0;
        for (title, target, content, _tag) in items {
            if target.hash() != Some(to.core.me_hash) {
                from.out.lock().unwrap().push((title, target, content, _tag));
                continue;
            }
            let m = Message::create(peers::lxmf_destination(&to.core.me_hash), peers::lxmf_destination(&from.core.me_hash), &from.identity, 1.0, title, content, vec![], DeliveryMethod::Direct).unwrap();
            to.core.on_message(&m);
            n += 1;
        }
        n
    }

    #[test]
    fn string_roundtrip_sorted_and_sizes() {
        let a = ([2u8; 16], [7u8; 16]);
        let b = ([1u8; 16], [9u8; 16]);
        let s = encode(&[a, b]).unwrap();
        assert_eq!(decode(&s).unwrap(), vec![b, a], "пары сортируются по хешу");
        let one = encode(&[a]).unwrap();
        assert_eq!(one.len(), 51);
        let eight: Vec<_> = (0..8u8).map(|i| ([i + 1; 16], [i + 1; 16])).collect();
        assert_eq!(encode(&eight).unwrap().len(), 350);
        assert_eq!(encode(&eight[..4]).unwrap().len(), 179);
    }

    #[test]
    fn string_rejects_typos_dupes_zero_pin_and_garbage() {
        let a = ([2u8; 16], [7u8; 16]);
        let s = encode(&[a]).unwrap();
        let mut bad = s.clone().into_bytes();
        bad[10] = if bad[10] == b'A' { b'B' } else { b'A' };
        assert!(decode(std::str::from_utf8(&bad).unwrap()).is_err());
        assert!(encode(&[a, a]).is_err() && encode(&[([1; 16], [0; 16])]).is_err() && encode(&[]).is_err());
        assert!(encode(&(0..9u8).map(|i| ([i + 1; 16], [1; 16])).collect::<Vec<_>>()).is_err());
        assert!(decode("").is_err() && decode("AAAA").is_err() && decode(&"A".repeat(5000)).is_err());
        assert!(decode(&format!("  {}\n", s)).is_ok(), "пробелы и переводы строк при вставке не мешают");
    }

    #[test]
    fn full_redeem_accept_ack_flow_between_two_nodes() {
        let (h, n) = (node("h", false), node("n", false));
        let s = issue_self(&h.core, peers::USE, peers::INVITE_DEFAULT_MS);
        n.core.join(&s).unwrap();
        n.core.tick();
        assert_eq!(deliver(&n, &h), 1, "redeem ушёл");
        assert_eq!(h.core.peers.lock().unwrap().rights(&n.core.me_hash), peers::USE, "H записал N до ответа");
        assert_eq!(deliver(&h, &n), 1, "accept ушёл");
        assert_eq!(n.core.peers.lock().unwrap().contact(&h.core.me_hash).unwrap().they_grant, peers::USE);
        assert!(!n.core.has_pending(), "всё погашено: пины стёрты");
        assert!(!pending_path(&n.core.state).exists());
        assert_eq!(deliver(&n, &h), 1, "ack ушёл");
        let st = h.core.peers.lock().unwrap().invite_list();
        assert_eq!(st[0].state, peers::InviteState::Settled);
    }

    /// Прогнать вступление `n` -> `h` до конца (redeem, accept, ack).
    fn run_join(n: &Node, h: &Node) {
        n.core.tick();
        deliver(n, h);
        deliver(h, n);
        deliver(n, h);
    }

    #[test]
    fn server_first_start_makes_issuer_controller_only_by_launch_adoption() {
        let (admin, server) = (node("admin", true), node("srv", false));
        let s = issue_self(&admin.core, peers::USE, peers::INVITE_DEFAULT_MS);
        server.core.join_adopt(&s, ADOPT_IF_EMPTY).unwrap();
        run_join(&server, &admin);
        assert_eq!(server.core.peers.lock().unwrap().rights(&admin.core.me_hash), peers::PRESET_ADMIN);
        assert_eq!(server.core.peers.lock().unwrap().controllers(), vec![admin.core.me_pk]);
        assert_eq!(admin.core.peers.lock().unwrap().rights(&server.core.me_hash), peers::USE, "права = только то, что принявший получил на выдавшей ноде");
        assert!(server.core.peers.lock().unwrap().contact(&admin.core.me_hash).is_some());
    }

    #[test]
    fn plain_join_never_makes_controller_and_managed_node_needs_force() {
        // обычное вступление (без пометки запуска): выдавший - только контакт
        let (admin, srv) = (node("admin2", true), node("srv5", false));
        let s = issue_self(&admin.core, peers::USE, peers::INVITE_DEFAULT_MS);
        srv.core.join(&s).unwrap();
        run_join(&srv, &admin);
        assert_eq!(srv.core.peers.lock().unwrap().rights(&admin.core.me_hash), 0);
        assert!(srv.core.peers.lock().unwrap().controllers().is_empty());
        // уже управляемая нода: IF_EMPTY не усыновляет, FORCE (--accept-manage) - да
        let (a1, a2, managed) = (node("a1", true), node("a2", true), node("man", false));
        managed.core.peers.lock().unwrap().peer_set(&peers::Actor::Local, a1.core.me_pk, peers::PRESET_ADMIN, "a1", 1, 1).unwrap();
        managed.core.join_adopt(&issue_self(&a2.core, peers::USE, peers::INVITE_DEFAULT_MS), ADOPT_IF_EMPTY).unwrap();
        run_join(&managed, &a2);
        assert_eq!(managed.core.peers.lock().unwrap().rights(&a2.core.me_hash), 0, "без --accept-manage второй админ не появляется");
        let a3 = node("a3", true);
        managed.core.join_adopt(&issue_self(&a3.core, peers::USE, peers::INVITE_DEFAULT_MS), ADOPT_FORCE).unwrap();
        run_join(&managed, &a3);
        assert_eq!(managed.core.peers.lock().unwrap().rights(&a3.core.me_hash), peers::PRESET_ADMIN);
    }

    #[test]
    fn phone_never_gives_management_even_if_pair_is_marked_adopt() {
        let (srv, phone) = (node("srv2", false), node("phone", true));
        let s = issue_self(&srv.core, peers::USE, peers::INVITE_DEFAULT_MS);
        phone.core.join_adopt(&s, ADOPT_FORCE).unwrap();
        run_join(&phone, &srv);
        assert_eq!(phone.core.peers.lock().unwrap().rights(&srv.core.me_hash), 0);
        assert!(phone.core.peers.lock().unwrap().controllers().is_empty());
        assert!(phone.core.peers.lock().unwrap().contact(&srv.core.me_hash).is_some(), "контакт есть, управления нет");
        assert!(!phone.core.has_pending());
    }

    #[test]
    fn forged_accept_cannot_smuggle_management() {
        // accept с лишним полем mgmt и верной подписью пина не существует: MAC покрывает только rights и roles, поле игнорируется
        let (srv, phone) = (node("srv6", false), node("phone6", true));
        let s = issue_self(&srv.core, peers::USE, peers::INVITE_DEFAULT_MS);
        phone.core.join(&s).unwrap();
        phone.core.tick();
        deliver(&phone, &srv);
        let items: Vec<_> = std::mem::take(&mut *srv.out.lock().unwrap());
        for (title, target, content, _) in items {
            let mut j: serde_json::Value = serde_json::from_slice(&content).unwrap();
            j["mgmt"] = peers::PRESET_ADMIN.into();
            let m = Message::create(peers::lxmf_destination(&phone.core.me_hash), peers::lxmf_destination(&srv.core.me_hash), &srv.identity, 1.0, title, serde_json::to_vec(&j).unwrap(), vec![], DeliveryMethod::Direct).unwrap();
            let _ = target;
            phone.core.on_message(&m);
        }
        assert_eq!(phone.core.peers.lock().unwrap().rights(&srv.core.me_hash), 0);
    }

    #[test]
    fn wrong_pin_gets_silence_and_bans_source_then_right_pin_after_pause_state_unchanged() {
        let (h, n) = (node("h4", false), node("n4", false));
        let s = issue_self(&h.core, peers::USE, peers::INVITE_DEFAULT_MS);
        let mut pairs = decode(&s).unwrap();
        let real = pairs[0].1;
        pairs[0].1 = [0x55; 16]; // неверный пин
        n.core.join(&encode(&pairs).unwrap()).unwrap();
        n.core.tick();
        deliver(&n, &h);
        assert!(h.out.lock().unwrap().is_empty(), "неверный пин (неизвестный pid): молчание");
        assert_eq!(h.core.peers.lock().unwrap().live().count(), 0);
        // известный pid, неверный пруф: тоже молчание, состояние не меняется
        let pid = peers::pin_id(&real);
        let body = serde_json::json!({"v":1,"op":"redeem","pid":hex(&pid),"n_nonce":hex(&[1u8;16]),"pk_n":hex(&n.core.me_pk),"name":"x","proof":hex(&[0u8;32])});
        let m = Message::create(peers::lxmf_destination(&h.core.me_hash), peers::lxmf_destination(&n.core.me_hash), &n.identity, 1.0, lxmf_sync::TITLE_INV.to_vec(), serde_json::to_vec(&body).unwrap(), vec![], DeliveryMethod::Direct).unwrap();
        h.core.on_message(&m);
        assert!(h.out.lock().unwrap().is_empty());
        assert_eq!(h.core.peers.lock().unwrap().invite_list()[0].state, peers::InviteState::Open);
        assert!(h.core.f2b.lock().unwrap().banned(&peers::lxmf_destination(&n.core.me_hash)));
    }

    #[test]
    fn second_recipient_with_the_pin_is_denied_and_first_keeps_rights() {
        let (h, a, b) = (node("h5", false), node("a5", false), node("b5", false));
        let s = issue_self(&h.core, peers::USE, peers::INVITE_DEFAULT_MS);
        a.core.join(&s).unwrap();
        b.core.join(&s).unwrap();
        a.core.tick();
        b.core.tick();
        deliver(&a, &h);
        deliver(&b, &h);
        assert_eq!(h.core.peers.lock().unwrap().live().count(), 1);
        assert_eq!(h.core.peers.lock().unwrap().rights(&a.core.me_hash), peers::USE);
        assert_eq!(h.core.peers.lock().unwrap().rights(&b.core.me_hash), 0);
        deliver(&h, &b);
        assert!(!b.core.has_pending(), "B получил deny и снял пару");
        assert!(b.core.peers.lock().unwrap().contact(&h.core.me_hash).is_none());
    }

    #[test]
    fn forged_accept_without_pin_is_ignored() {
        let (h, n) = (node("h6", false), node("n6", false));
        let evil = node("evil", false);
        let s = issue_self(&h.core, peers::USE, peers::INVITE_DEFAULT_MS);
        n.core.join(&s).unwrap();
        let pid = decode(&s).unwrap()[0].1;
        let pid = peers::pin_id(&pid);
        let pend_nonce = n.core.pending.lock().unwrap().pairs[0].n_nonce;
        // злоумышленник знает pid и n_nonce (подслушал бы только шифротекст — но допустим), но не пин
        let body = serde_json::json!({"v":1,"op":"accept","pid":hex(&pid),"n_nonce":hex(&pend_nonce),"h_nonce":hex(&[0u8;16]),"pk_h":hex(&evil.core.me_pk),
            "rights":peers::PRESET_ADMIN,"roles":0,"name_h":"evil","hints":[],"mac":hex(&[0u8;32])});
        let m = Message::create(peers::lxmf_destination(&n.core.me_hash), peers::lxmf_destination(&evil.core.me_hash), &evil.identity, 1.0, lxmf_sync::TITLE_INV.to_vec(), serde_json::to_vec(&body).unwrap(), vec![], DeliveryMethod::Direct).unwrap();
        n.core.on_message(&m);
        assert!(n.core.peers.lock().unwrap().contact(&evil.core.me_hash).is_none());
        assert_eq!(n.core.peers.lock().unwrap().rights(&evil.core.me_hash), 0);
    }

    #[test]
    fn expired_and_unknown_invites_are_ignored_and_rate_limit_precedes_parsing() {
        let h = node("h7", false);
        let mut r = Rate::new(6, 30);
        assert!((0..6).all(|_| r.allow([1; 16])) && !r.allow([1; 16]));
        let mut r = Rate::new(6, 30);
        assert!((0..30).all(|i| r.allow([i as u8; 16])) && !r.allow([99; 16]), "общий потолок");
        let mut f = Fail2Ban::default();
        f.fail([1; 16]);
        assert!(f.banned(&[1; 16]) && !f.banned(&[2; 16]));
        // мусор не роняет и не оставляет следов
        let m = Message::create(peers::lxmf_destination(&h.core.me_hash), [3; 16], &h.identity, 1.0, lxmf_sync::TITLE_INV.to_vec(), b"not json".to_vec(), vec![], DeliveryMethod::Direct).unwrap();
        h.core.on_message(&m);
        assert!(h.out.lock().unwrap().is_empty());
    }

    fn v6_of(hints: &[String]) -> bool {
        hints.iter().any(|h| h.parse::<std::net::SocketAddr>().is_ok_and(|s| s.is_ipv6()))
    }

    #[test]
    fn accept_and_ack_carry_hints_both_ways_filtered_and_dual_stack() {
        // выдавший A: три IPv4, один глобальный IPv6 и частный адрес; получатель B: IPv4 + IPv6
        let a_hints: Vec<String> = ["8.8.8.8:47001", "8.8.4.4:47002", "1.1.1.1:47003", "[2606:4700::1111]:47004", "10.0.0.5:47005"].iter().map(|s| s.to_string()).collect();
        let b_hints: Vec<String> = ["9.9.9.9:5001", "[2a00:1450::1]:5002", "192.168.1.9:5003"].iter().map(|s| s.to_string()).collect();
        let (a, b) = (node_h("p2p-a", false, a_hints), node_h("p2p-b", true, b_hints));
        let s = issue_self(&a.core, peers::USE, peers::INVITE_DEFAULT_MS);
        b.core.join(&s).unwrap();
        b.core.tick();
        deliver(&b, &a);
        deliver(&a, &b);
        // B (клиент) получил подсказки A: лимит контакта 6, IPv6 не вытеснен IPv4; литеральный частный адрес клиент принимает (набор
        // решит проверка подсети в момент набора), сервер такие адреса отбрасывает (ниже, у A)
        let ha = b.core.peers.lock().unwrap().contact(&a.core.me_hash).unwrap().hints.clone();
        assert_eq!(ha.len(), 5, "{ha:?}");
        assert!(v6_of(&ha), "IPv6 сохранён при лимите: {ha:?}");
        assert!(ha.iter().any(|h| h.starts_with("10.")), "клиент принимает LAN-подсказку: {ha:?}");
        deliver(&b, &a); // ack с адресами B
        // A получил контакт B для обратного дозвона; права на A не изменились, никаких they_grant/ролей не появилось
        let p = a.core.peers.lock().unwrap();
        let cb = p.contact(&b.core.me_hash).expect("контакт получателя у выдавшего");
        assert_eq!(cb.hints, vec!["9.9.9.9:5001".to_string(), "[2a00:1450::1]:5002".to_string()], "сервер: частный 192.168.* отброшен");
        assert_eq!((cb.they_grant, cb.roles, cb.intro_by.as_str()), (0, 0, "invite"));
        assert!(cb.client, "B объявил себя клиентом (телефон)");
        assert_eq!(p.rights(&b.core.me_hash), peers::USE, "права B на A прежние");
    }

    #[test]
    fn addr_update_from_known_contact_only_changes_hints() {
        let (a, b) = (node_h("addr-a", false, vec!["8.8.8.8:1".into()]), node_h("addr-b", false, vec!["9.9.9.9:2".into()]));
        let s = issue_self(&a.core, peers::USE, peers::INVITE_DEFAULT_MS);
        b.core.join(&s).unwrap();
        b.core.tick();
        deliver(&b, &a);
        deliver(&a, &b);
        deliver(&b, &a);
        let send_addr = |from: &Node, to: &Node, hints: serde_json::Value| {
            let body = serde_json::json!({"v":1,"op":"addr","hints":hints});
            let m = Message::create(peers::lxmf_destination(&to.core.me_hash), peers::lxmf_destination(&from.core.me_hash), &from.identity, 1.0, lxmf_sync::TITLE_INV.to_vec(), serde_json::to_vec(&body).unwrap(), vec![], DeliveryMethod::Direct).unwrap();
            to.core.on_message(&m);
        };
        send_addr(&b, &a, serde_json::json!(["4.4.4.4:9", "[2001:4860::8888]:9", "10.1.1.1:9"]));
        let h = a.core.peers.lock().unwrap().contact(&b.core.me_hash).unwrap().hints.clone();
        assert_eq!(h, vec!["4.4.4.4:9".to_string(), "[2001:4860::8888]:9".to_string()]);
        assert_eq!(a.core.peers.lock().unwrap().rights(&b.core.me_hash), peers::USE);
        // чужой (нет контакта): молчание, подсказки не меняются
        let stranger = node("addr-x", false);
        send_addr(&stranger, &a, serde_json::json!(["5.5.5.5:9"]));
        assert_eq!(a.core.peers.lock().unwrap().contact(&b.core.me_hash).unwrap().hints, h);
        assert!(a.core.peers.lock().unwrap().contact(&stranger.core.me_hash).is_none());
        // только частные адреса - пустой список после фильтра, ничего не меняется
        send_addr(&b, &a, serde_json::json!(["192.168.0.2:1"]));
        assert_eq!(a.core.peers.lock().unwrap().contact(&b.core.me_hash).unwrap().hints, h);
    }

    #[test]
    fn announce_addrs_sends_only_on_change_to_dialable_contacts() {
        let (a, b) = (node_h("an-a", false, vec!["8.8.8.8:1".into()]), node("an-b", false));
        let s = issue_self(&a.core, peers::USE, peers::INVITE_DEFAULT_MS);
        b.core.join(&s).unwrap();
        b.core.tick();
        deliver(&b, &a);
        deliver(&a, &b);
        deliver(&b, &a);
        a.out.lock().unwrap().clear();
        a.core.announce_addrs();
        let sent = a.out.lock().unwrap().iter().filter(|m| m.3.starts_with("inv:addr:")).count();
        assert_eq!(sent, 1, "первая проверка рассылает адреса контакту");
        a.core.last_addr.lock().unwrap().0 = None; // обойти 30-секундный темп
        a.out.lock().unwrap().clear();
        a.core.announce_addrs();
        assert!(a.out.lock().unwrap().is_empty(), "адреса не менялись - не рассылаем");
    }

    #[test]
    fn join_refuses_own_hash_and_persists_only_in_private_file() {
        let n = node("n8", false);
        let s = encode(&[(n.core.me_hash, [5; 16])]).unwrap();
        assert!(n.core.join(&s).is_err());
        let s = encode(&[([8; 16], [5; 16])]).unwrap();
        n.core.join(&s).unwrap();
        let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(pending_path(&n.core.state)).unwrap());
        assert_eq!(mode & 0o777, 0o600);
        let back = load_pending(&n.core.state).unwrap();
        assert_eq!(back.pairs.len(), 1);
        assert_eq!(back.pairs[0].pin, [5; 16]);
    }

    #[test]
    fn join_appends_to_pending_without_losing_or_duplicating() {
        let n = node("n9", false);
        let s1 = encode(&[([8; 16], [5; 16])]).unwrap();
        assert_eq!(n.core.join_stat(&s1).unwrap().1, 1);
        // первая пара уже погашена и ждёт ack: вторая строка не должна её потерять
        {
            let mut p = n.core.pending.lock().unwrap();
            p.pairs[0].state = PairState::Settled;
            p.created = 1;
        }
        let s2 = encode(&[([9; 16], [6; 16]), ([10; 16], [7; 16])]).unwrap();
        assert_eq!(n.core.join_stat(&s2).unwrap().1, 2);
        {
            let p = n.core.pending.lock().unwrap();
            assert_eq!(p.pairs.len(), 3);
            assert_eq!(p.pairs[0].state, PairState::Settled, "погашенная пара не сброшена");
            assert!(p.created > 1, "срок стопки отсчитывается от последнего добавления");
        }
        // повтор любой из строк ничего не добавляет и не дублирует
        assert_eq!(n.core.join_stat(&s1).unwrap().1, 0);
        assert_eq!(n.core.join_stat(&s2).unwrap().1, 0);
        // тот же хеш, другой пин (второе приглашение от той же ноды) - отдельная пара
        let s3 = encode(&[([8; 16], [11; 16])]).unwrap();
        assert_eq!(n.core.join_stat(&s3).unwrap().1, 1);
        let back = load_pending(&n.core.state).unwrap();
        assert_eq!(back.pairs.len(), 4);
        assert_eq!(back.pairs[0].state, PairState::Settled);
        assert_eq!(n.core.pending_view()["pairs"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn join_limit_counts_only_new_pairs() {
        let mut pend = Pending::default();
        for i in 0..MAX_PENDING_PAIRS {
            pend.pairs.push(Pair::new([(i + 1) as u8; 16], [9; 16]));
        }
        let me = [0xee; 16];
        // стопка полна: повтор имеющейся пары - не ошибка, новая пара - отказ
        assert_eq!(merge_pairs(&mut pend, &[([1; 16], [9; 16])], &me, 5, 0).unwrap(), 0);
        assert!(merge_pairs(&mut pend, &[([200; 16], [9; 16])], &me, 5, 0).is_err());
        assert_eq!(pend.pairs.len(), MAX_PENDING_PAIRS);
        assert!(merge_pairs(&mut pend, &[(me, [9; 16])], &me, 5, 0).is_err(), "собственный хеш");
    }

    #[test]
    fn join_offline_appends_to_file_and_view_shows_it() {
        let n = node("n10", false);
        let st = n.core.state.clone();
        let s1 = encode(&[([8; 16], [5; 16])]).unwrap();
        let s2 = encode(&[([9; 16], [6; 16])]).unwrap();
        assert_eq!(join_offline(&st, &n.core.me_hash, &s1).unwrap().1, 1);
        assert_eq!(join_offline(&st, &n.core.me_hash, &s2).unwrap().1, 1);
        assert_eq!(join_offline(&st, &n.core.me_hash, &s2).unwrap().1, 0);
        assert!(join_offline(&st, &n.core.me_hash, &encode(&[(n.core.me_hash, [5; 16])]).unwrap()).is_err());
        let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(pending_path(&st)).unwrap());
        assert_eq!(mode & 0o777, 0o600);
        let v = pending_view_offline(&st);
        assert_eq!(v["pairs"].as_array().unwrap().len(), 2);
        assert_eq!(v["pairs"][0]["state"], "waiting");
        // нода, стартовавшая позже, подхватывает обе пары
        let fresh = Core::new(&st, n.identity.clone(), n.core.peers.clone(), false, Box::new(Vec::new), Box::new(|| {}), Box::new(|_| {})).unwrap();
        assert_eq!(fresh.pending_view()["pairs"].as_array().unwrap().len(), 2);
    }
}
