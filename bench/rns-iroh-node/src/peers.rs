//! Таблица прав на ноде (ADR 0028): кому что разрешено НА ЭТОЙ ноде (`peers`), кого нода знает (`contacts`), какие
//! приглашения на ней открыты (`invites`). Корней, якорей, подписанных записей и цепочек нет: таблица — локальный факт
//! ноды, а не переносимое свидетельство. Вся запись в один файл `peers.json` (0600, атомарно); нечитаемый файл — ошибка
//! запуска, а не пустая таблица (fail-closed, S4 ревью 19.10).
//!
//! Модуль не знает про сеть и LXMF: данные, проверки полномочий актора и файл. Всё, что пришло от пира, — недоверенный ввод.

use super::*;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use anyhow::anyhow;

pub type Pk = [u8; 64];
pub type Hash = [u8; 16];
pub type Pid = [u8; 8];

pub const USE: u16 = 1;
pub const TRANSIT: u16 = 2;
pub const EXIT: u16 = 4;
pub const ADD: u16 = 8;
pub const REMOVE: u16 = 16;
pub const CONFIG: u16 = 32;
pub const HOST_ACCESS: u16 = 64;
pub const KNOWN: u16 = 127;
/// Права, которые не выдаёт ADD/REMOVE-актор: только держатель CONFIG или локальный владелец.
const CONFIG_ONLY: u16 = CONFIG | HOST_ACCESS;
/// Наборы (что нода разрешает соседу, ADR 0028 §1.5). TRANSIT/EXIT — права САМОЙ ноды (`transit_enabled`/`exit_enabled`), не пользователя.
pub const PRESET_USER: u16 = USE;
pub const PRESET_SERVER: u16 = USE;
pub const PRESET_ADMIN: u16 = CONFIG | ADD | REMOVE | USE;

pub const MAX_PEERS: usize = 512;
pub const MAX_CONTACTS: usize = 512;
pub const MAX_CONFIG_HOLDERS: usize = 16;
pub const MAX_INVITES_OPEN: usize = 64;
pub const MAX_INVITES_PER_ISSUER: usize = 16;
pub const INVITE_DEFAULT_MS: u64 = 48 * 3600 * 1000;
pub const INVITE_MAX_MS: u64 = 7 * 24 * 3600 * 1000;
/// Закрытые приглашения хранятся для аудита, потом GC.
pub const INVITE_AUDIT_MS: u64 = 7 * 24 * 3600 * 1000;
/// seq — время в мс; запись из далёкого будущего не принимаем (иначе актор мог бы заранее занять слот записи).
pub const SEQ_FUTURE_MS: u64 = 10 * 60 * 1000;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_HINTS: usize = 3;
const MAX_NAME: usize = 48;

/// Подсказок на контакт (глобальные IPv4/IPv6 и локальная сеть IPv4/ULA); у серверов и в анонсе остаётся `MAX_HINTS`.
pub const MAX_CONTACT_HINTS: usize = 6;

/// Не больше `max` адресов-подсказок с сохранением порядка, но минимум по одному адресу каждого вида (IPv4/IPv6 × глобальный/локальная
/// сеть), если они есть: иначе три глобальных IPv4 вытесняют IPv6, а он часто единственный путь без NAT, и локальный адрес не доезжает.
/// Имена `host:порт` идут как глобальный IPv4. Порядок отправителя сохраняется (глобальные у него первыми).
pub fn balance_hints(list: Vec<String>, max: usize) -> Vec<String> {
    let kind = |a: &str| -> u8 {
        match a.parse::<std::net::SocketAddr>() {
            Ok(s) => (s.is_ipv6() as u8) | (!crate::vpn::is_global_ip(&s.ip()) as u8) << 1,
            Err(_) => 0,
        }
    };
    let mut seen = std::collections::HashSet::new();
    let list: Vec<String> = list.into_iter().filter(|a| seen.insert(a.clone())).collect();
    if list.len() <= max || max < 2 {
        return list.into_iter().take(max).collect();
    }
    let mut keep: Vec<usize> = Vec::new();
    let mut kinds = std::collections::HashSet::new();
    for (i, a) in list.iter().enumerate() {
        if keep.len() < max && kinds.insert(kind(a)) { keep.push(i); }
    }
    for i in 0..list.len() {
        if keep.len() >= max { break; }
        if !keep.contains(&i) { keep.push(i); }
    }
    keep.sort_unstable();
    keep.into_iter().map(|i| list[i].clone()).collect()
}

pub fn rights_text(r: u16) -> String {
    if r == 0 {
        return "-".into();
    }
    let mut v = Vec::new();
    for (b, n) in [(USE, "USE"), (TRANSIT, "TRANSIT"), (EXIT, "EXIT"), (ADD, "ADD"), (REMOVE, "REMOVE"), (CONFIG, "CONFIG"), (HOST_ACCESS, "HOST_ACCESS")] {
        if r & b != 0 {
            v.push(n);
        }
    }
    v.join("+")
}

/// `user`, `server`, `admin`, число или список через `+`/`,` (`USE+EXIT`).
pub fn parse_rights(s: &str) -> Result<u16> {
    let t = s.trim().to_lowercase();
    match t.as_str() {
        "user" => return Ok(PRESET_USER),
        "server" => return Ok(PRESET_SERVER),
        "admin" => return Ok(PRESET_ADMIN),
        "none" | "-" => return Ok(0),
        _ => {}
    }
    if let Ok(n) = t.parse::<u16>() {
        if n & !KNOWN != 0 {
            bail!("права: лишние биты в {n}");
        }
        return Ok(n);
    }
    let mut r = 0u16;
    for p in t.split(|c| c == '+' || c == ',').filter(|p| !p.is_empty()) {
        r |= match p {
            "use" => USE,
            "transit" => TRANSIT,
            "exit" => EXIT,
            "add" => ADD,
            "remove" => REMOVE,
            "config" => CONFIG,
            "host_access" => HOST_ACCESS,
            _ => bail!("неизвестное право {p:?} (user, server, admin, USE, TRANSIT, EXIT, ADD, REMOVE, CONFIG, HOST_ACCESS)"),
        };
    }
    Ok(r)
}

pub fn hash_of(pk: &Pk) -> Option<Hash> {
    Identity::from_public_key_bytes(pk).ok().map(|i| *i.hash())
}

/// LXMF-адрес доставки identity (не назначение VPN-узла).
pub fn lxmf_destination(identity_hash: &Hash) -> [u8; 16] {
    use leviculum_std::api::Destination;
    *Destination::compute_destination_hash(&Destination::compute_name_hash("lxmf", &["delivery"]), identity_hash).as_bytes()
}

pub fn key_of(pk: &Pk) -> [u8; 32] {
    pk[32..64].try_into().unwrap()
}

/// Идентификатор приглашения на ноде: из него пин не восстановить.
pub fn pin_id(pin: &[u8; 16]) -> Pid {
    let d = Sha256::digest([b"knothop-pin-id-v1".as_slice(), pin].concat());
    d[..8].try_into().unwrap()
}

/// Ключ HMAC проверки пруфа; нода хранит его вместо пина.
pub fn pin_key(pin: &[u8; 16]) -> [u8; 32] {
    Sha256::digest([b"knothop-pin-key-v1".as_slice(), pin].concat()).into()
}

fn sane_name(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(MAX_NAME).collect()
}

// ------------------------------------------------------------------------------------------------ файл

pub(crate) fn write_atomic(p: &Path, data: &[u8]) -> Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("state");
    let tmp = p.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
    let res = (|| -> Result<()> {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).with_context(|| format!("{name}: временный файл"))?;
        f.write_all(data).and_then(|_| f.sync_all()).with_context(|| format!("{name}: запись"))?;
        std::fs::rename(&tmp, p).with_context(|| format!("{name}: замена"))?;
        if let Some(d) = p.parent() {
            if let Ok(f) = std::fs::File::open(d) {
                let _ = f.sync_all();
            }
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Читает файл состояния с проверкой: обычный файл, не symlink, владелец, не шире 0600, размер.
pub fn read_private(p: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("{}: не открыть", p.display())),
    };
    let m = f.metadata()?;
    let euid = unsafe { libc::geteuid() };
    if !m.is_file() || m.len() > max || m.mode() & 0o077 != 0 || (m.uid() != euid && m.uid() != 0) {
        bail!("{}: не обычный файл, больше {max} Б, права шире 0600 или чужой владелец", p.display());
    }
    let mut b = Vec::with_capacity(m.len() as usize);
    std::io::Read::read_to_end(&mut std::io::Read::take(f, max + 1), &mut b)?;
    if b.len() as u64 > max {
        bail!("{}: больше {max} Б", p.display());
    }
    Ok(Some(b))
}

// ------------------------------------------------------------------------------------------------ данные

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub pk: Pk,
    /// 0 = отозвано (надгробие)
    pub rights: u16,
    /// кто выдал: `local`, hex хеша актора, `invite:<pid>`
    pub by: String,
    pub seq: u64,
    pub at: u64,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub pk: Pk,
    pub name: String,
    pub hints: Vec<String>,
    /// кто познакомил: `invite`, `local`, hex хеша контроллера
    pub intro_by: String,
    /// что он разрешает мне (кэш из accept; не полномочие)
    pub they_grant: u16,
    /// роли самой ноды по её сведениям (`TRANSIT`/`EXIT` = `transit_enabled`/`exit_enabled`): подсказка выбора выхода, не полномочие
    pub roles: u16,
    pub at: u64,
    /// подсказка REALITY этой ноды (`accept`): подсказка, не полномочие; разбирает и проверяет `RealityHint::from_json` при использовании
    pub rl: serde_json::Value,
    /// нода сама объявила, что она клиент (телефон/ПК с согласием на управление): сервер не делает её соседом-транзитом; набирают её только клиенты (P2P)
    pub client: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InviteState {
    Open,
    Redeemed { pk: Pk, at: u64 },
    Settled,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub pid: Pid,
    pub key: [u8; 32],
    /// что получит принявший на этой ноде
    pub rights: u16,
    pub created: u64,
    pub expires: u64,
    /// `local` или hex хеша админа, сообщившего «ожидай»
    pub issuer: String,
    pub state: InviteState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NodeConfig {
    pub transit_enabled: bool,
    pub exit_enabled: bool,
}

/// Кто просит изменить таблицу. `Local` — процесс/CLI/UI на самой ноде (ключа нет, полномочие даёт доступ к файлам и сокету).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    Local,
    Peer(Hash),
}

impl Actor {
    pub fn label(&self) -> String {
        match self {
            Actor::Local => "local".into(),
            Actor::Peer(h) => hex(h),
        }
    }
}

/// Код отказа для ответа `rejected(code)`.
pub type Reject = &'static str;

#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    Changed,
    Unchanged,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Redeem {
    /// Приглашение погашено сейчас (или повтор тем же ключом): отправить `accept`.
    Accepted { rights: u16, name: String, fresh: bool },
    /// Пруф верен, но пин уже погашен другим ключом.
    Used,
    /// Известный pid, неверный пруф: считается в fail2ban, состояние не меняется.
    BadProof,
    /// Всё прочее (нет pid, закрыто, просрочено, чужое): молчание, оракула нет.
    Silent,
}

pub struct Snapshot {
    peers: BTreeMap<Hash, Peer>,
    contacts: BTreeMap<Hash, Contact>,
    invites: BTreeMap<Pid, Invite>,
    cfg: NodeConfig,
}

pub struct Peers {
    path: Option<PathBuf>,
    pub me_pk: Pk,
    pub me_hash: Hash,
    peers: BTreeMap<Hash, Peer>,
    contacts: BTreeMap<Hash, Contact>,
    invites: BTreeMap<Pid, Invite>,
    cfg: NodeConfig,
    /// Растёт при любом изменении `peers`/`cfg`; кэши решений mesh и relay сверяют его (отзыв без задержки кэша).
    rgen: Arc<AtomicU64>,
}

fn is_hash_str(s: &str) -> bool {
    s == "local" || s.starts_with("invite:") || (s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl Peers {
    pub fn new(me_pk: Pk, path: Option<PathBuf>) -> Peers {
        let me_hash = hash_of(&me_pk).unwrap_or([0; 16]);
        Peers { path, me_pk, me_hash, peers: BTreeMap::new(), contacts: BTreeMap::new(), invites: BTreeMap::new(), cfg: NodeConfig::default(), rgen: Arc::new(AtomicU64::new(1)) }
    }

    pub fn file(state: &Path) -> PathBuf {
        state.join("peers.json")
    }

    /// Нет файла — пустая таблица. Есть, но нечитаем/повреждён/слишком велик/широкие права — ошибка: нода не стартует приём.
    pub fn load(me_pk: Pk, state: &Path) -> Result<Peers> {
        let path = Self::file(state);
        let mut t = Peers::new(me_pk, Some(path.clone()));
        let Some(bytes) = read_private(&path, MAX_FILE_BYTES)? else { return Ok(t) };
        let v: serde_json::Value = serde_json::from_slice(&bytes).context("peers.json: разбор")?;
        if v["v"].as_u64() != Some(1) {
            bail!("peers.json: неизвестная версия");
        }
        let pk_of = |s: &serde_json::Value| -> Result<Pk> {
            let b = unhex(s.as_str().ok_or_else(|| anyhow!("peers.json: ключ не строка"))?);
            let pk: Pk = b.try_into().map_err(|_| anyhow!("peers.json: ключ не 64 Б"))?;
            hash_of(&pk).ok_or_else(|| anyhow!("peers.json: ключ не identity"))?;
            Ok(pk)
        };
        let s = |x: &serde_json::Value, k: &str| x[k].as_str().unwrap_or("").to_string();
        for p in v["peers"].as_array().ok_or_else(|| anyhow!("peers.json: нет peers"))? {
            let pk = pk_of(&p["pk"])?;
            let rights = p["rights"].as_u64().and_then(|r| u16::try_from(r).ok()).ok_or_else(|| anyhow!("peers.json: rights вне u16"))?; // SA-26: не усекать молча
            if rights & !KNOWN != 0 || !is_hash_str(&s(p, "by")) {
                bail!("peers.json: запись права/by");
            }
            let e = Peer { pk, rights, by: s(p, "by"), seq: p["seq"].as_u64().unwrap_or(0), at: p["at"].as_u64().unwrap_or(0), name: sane_name(&s(p, "name")) };
            if t.peers.insert(hash_of(&pk).unwrap(), e).is_some() {
                bail!("peers.json: повтор записи");
            }
        }
        for c in v["contacts"].as_array().ok_or_else(|| anyhow!("peers.json: нет contacts"))? {
            let pk = pk_of(&c["pk"])?;
            let hints = c["hints"].as_array().map(|a| balance_hints(a.iter().filter_map(|x| x.as_str().map(String::from)).collect(), MAX_CONTACT_HINTS)).unwrap_or_default();
            let e = Contact { pk, name: sane_name(&s(c, "name")), hints, intro_by: s(c, "intro_by"), they_grant: (c["they_grant"].as_u64().unwrap_or(0) as u16) & KNOWN, roles: (c["roles"].as_u64().unwrap_or(0) as u16) & (TRANSIT | EXIT), rl: c["rl"].clone(), at: c["at"].as_u64().unwrap_or(0), client: c["client"].as_bool().unwrap_or(false) };
            t.contacts.insert(hash_of(&pk).unwrap(), e);
        }
        for i in v["invites"].as_array().ok_or_else(|| anyhow!("peers.json: нет invites"))? {
            let pid: Pid = unhex(&s(i, "pid")).try_into().map_err(|_| anyhow!("peers.json: pid"))?;
            let key: [u8; 32] = unhex(&s(i, "key")).try_into().map_err(|_| anyhow!("peers.json: key"))?;
            let state = match i["state"].as_str() {
                Some("open") => InviteState::Open,
                Some("redeemed") => InviteState::Redeemed { pk: pk_of(&i["pk"])?, at: i["rat"].as_u64().unwrap_or(0) },
                Some("settled") => InviteState::Settled,
                Some("cancelled") => InviteState::Cancelled,
                Some("expired") => InviteState::Expired,
                _ => bail!("peers.json: state приглашения"),
            };
            let inv = Invite {
                pid, key, rights: i["rights"].as_u64().and_then(|r| u16::try_from(r).ok()).ok_or_else(|| anyhow!("peers.json: rights приглашения вне u16"))? & KNOWN,
                created: i["created"].as_u64().unwrap_or(0), expires: i["expires"].as_u64().unwrap_or(0), issuer: s(i, "issuer"), state,
            };
            if !is_hash_str(&inv.issuer) || t.invites.insert(pid, inv).is_some() {
                bail!("peers.json: приглашение");
            }
        }
        t.cfg = NodeConfig { transit_enabled: v["cfg"]["transit_enabled"].as_bool().unwrap_or(false), exit_enabled: v["cfg"]["exit_enabled"].as_bool().unwrap_or(false) };
        if t.peers.len() > MAX_PEERS || t.contacts.len() > MAX_CONTACTS || t.invites.len() > 4 * MAX_INVITES_OPEN {
            bail!("peers.json: записей больше предела");
        }
        Ok(t)
    }

    fn to_json(&self) -> serde_json::Value {
        let peers: Vec<_> = self.peers.values().map(|p| serde_json::json!({"pk": hex(&p.pk), "rights": p.rights, "by": p.by, "seq": p.seq, "at": p.at, "name": p.name})).collect();
        let contacts: Vec<_> = self.contacts.values().map(|c| serde_json::json!({"pk": hex(&c.pk), "name": c.name, "hints": c.hints, "intro_by": c.intro_by, "they_grant": c.they_grant, "roles": c.roles, "at": c.at, "rl": c.rl, "client": c.client})).collect();
        let invites: Vec<_> = self.invites.values().map(|i| {
            let mut j = serde_json::json!({"pid": hex(&i.pid), "key": hex(&i.key), "rights": i.rights, "created": i.created, "expires": i.expires, "issuer": i.issuer});
            match &i.state {
                InviteState::Open => j["state"] = "open".into(),
                InviteState::Redeemed { pk, at } => { j["state"] = "redeemed".into(); j["pk"] = hex(pk).into(); j["rat"] = (*at).into(); }
                InviteState::Settled => j["state"] = "settled".into(),
                InviteState::Cancelled => j["state"] = "cancelled".into(),
                InviteState::Expired => j["state"] = "expired".into(),
            }
            j
        }).collect();
        serde_json::json!({"v": 1, "peers": peers, "contacts": contacts, "invites": invites,
            "cfg": {"transit_enabled": self.cfg.transit_enabled, "exit_enabled": self.cfg.exit_enabled}})
    }

    pub fn save(&self) -> Result<()> {
        let Some(p) = &self.path else { return Ok(()) };
        write_atomic(p, &serde_json::to_vec(&self.to_json())?)
    }

    pub fn generation(&self) -> Arc<AtomicU64> {
        self.rgen.clone()
    }

    fn bump(&self) {
        self.rgen.fetch_add(1, Ordering::SeqCst);
    }

    // -------------------------------------------------------------------------------------------- чтение

    pub fn config(&self) -> NodeConfig {
        self.cfg
    }

    /// Роли самой ноды как биты `TRANSIT`/`EXIT` (для `accept` и статуса).
    pub fn roles(&self) -> u16 {
        (if self.cfg.transit_enabled { TRANSIT } else { 0 }) | (if self.cfg.exit_enabled { EXIT } else { 0 })
    }

    /// Снимок для отката пакета правок, если запись на диск не удалась.
    pub fn checkpoint(&self) -> Snapshot {
        Snapshot { peers: self.peers.clone(), contacts: self.contacts.clone(), invites: self.invites.clone(), cfg: self.cfg }
    }

    pub fn restore(&mut self, s: Snapshot) {
        self.peers = s.peers;
        self.contacts = s.contacts;
        self.invites = s.invites;
        self.cfg = s.cfg;
        self.bump();
    }

    pub fn rights(&self, h: &Hash) -> u16 {
        self.peers.get(h).map_or(0, |p| p.rights)
    }

    pub fn rights_pk(&self, pk: &Pk) -> u16 {
        hash_of(pk).map_or(0, |h| self.peers.get(&h).filter(|p| &p.pk == pk).map_or(0, |p| p.rights))
    }

    pub fn peer(&self, h: &Hash) -> Option<&Peer> {
        self.peers.get(h)
    }

    pub fn peer_list(&self) -> Vec<Peer> {
        self.peers.values().cloned().collect()
    }

    /// Живые записи (права ≠ 0): надгробия остаются в таблице, но не участвуют.
    pub fn live(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values().filter(|p| p.rights != 0)
    }

    /// Держатели CONFIG («админы», ADR §1.2); отдельной таблицы нет.
    pub fn controllers(&self) -> Vec<Pk> {
        self.live().filter(|p| p.rights & CONFIG != 0).map(|p| p.pk).collect()
    }

    pub fn has_controllers(&self) -> bool {
        self.live().any(|p| p.rights & CONFIG != 0)
    }

    /// Полномочия актора по изменению таблицы: ADD/REMOVE/CONFIG из его записи (Local — все).
    pub fn authority(&self, a: &Actor) -> u16 {
        match a {
            Actor::Local => ADD | REMOVE | CONFIG | HOST_ACCESS | USE | TRANSIT | EXIT,
            Actor::Peer(h) => self.rights(h) & (ADD | REMOVE | CONFIG | USE | EXIT | TRANSIT | HOST_ACCESS),
        }
    }

    /// Ключ LXMF-источника по хешу назначения доставки (подпись проверяет вызывающий): среди `peers` и `contacts`.
    pub fn pk_for_lxmf_source(&self, source: &[u8; 16]) -> Option<Pk> {
        self.peers.values().map(|p| &p.pk).chain(self.contacts.values().map(|c| &c.pk))
            .find(|pk| hash_of(pk).is_some_and(|h| lxmf_destination(&h) == *source)).copied()
    }

    pub fn pk_of_hash(&self, h: &Hash) -> Option<Pk> {
        self.peers.get(h).map(|p| p.pk).or_else(|| self.contacts.get(h).map(|c| c.pk))
    }

    pub fn contact(&self, h: &Hash) -> Option<&Contact> {
        self.contacts.get(h)
    }

    pub fn contact_list(&self) -> Vec<Contact> {
        self.contacts.values().cloned().collect()
    }

    pub fn invite(&self, pid: &Pid) -> Option<&Invite> {
        self.invites.get(pid)
    }

    #[cfg(test)]
    pub fn invite_list(&self) -> Vec<Invite> {
        self.invites.values().cloned().collect()
    }

    // -------------------------------------------------------------------------------------------- mesh, relay, допуск

    /// Ключ iroh держит живые права на этой ноде (для relay и транзита).
    pub fn key_holds_any(&self, key: &[u8; 32]) -> bool {
        self.live().any(|p| &key_of(&p.pk) == key)
    }

    /// Ключ известен таблице: живая запись `peers` либо контакт (последний хоп mesh принимает кадры только от знакомых).
    pub fn knows_key(&self, key: &[u8; 32]) -> bool {
        self.key_holds_any(key) || self.contacts.values().any(|c| &key_of(&c.pk) == key)
    }

    /// Местный получатель mesh: отозванный ключ не может вернуться через запись contact.
    pub fn mesh_knows_key(&self, key: &[u8; 32]) -> bool {
        if self.peers.values().any(|p| p.rights == 0 && &key_of(&p.pk) == key) { return false; }
        self.key_holds_any(key) || self.contacts.values().any(|c| {
            let trusted = c.intro_by == "invite" || c.intro_by == "local" || c.intro_by.len() == 32;
            &key_of(&c.pk) == key && trusted && c.they_grant & USE != 0
        })
    }

    /// Роли ноды по ключу iroh из её собственных сведений (`accept`): подсказка выбора транзита/выхода, не полномочие.
    pub fn roles_of_key(&self, key: &[u8; 32]) -> u16 {
        self.contacts.values().find(|c| &key_of(&c.pk) == key).map_or(0, |c| c.roles)
    }

    /// Ключ Ed25519 по первым 8 байтам среди живых записей; неоднозначный id — None.
    pub fn key_for_id8(&self, id: &[u8; 8]) -> Option<[u8; 32]> {
        let mut found: Option<[u8; 32]> = None;
        for p in self.live() {
            let k = key_of(&p.pk);
            if &k[..8] == id && found != Some(k) {
                if found.is_some() {
                    return None;
                }
                found = Some(k);
            }
        }
        found
    }

    /// Только для проверки местного назначения mesh, не для разрешения источника или выдачи прав.
    /// Собственная identity не хранится в peers; живая коллизия префикса всё равно fail-closed.
    pub fn local_key_for_id8(&self, id: &[u8; 8]) -> Option<[u8; 32]> {
        let own = key_of(&self.me_pk);
        if &own[..8] != id {
            return None;
        }
        let peers = self.live().map(|p| key_of(&p.pk));
        let contacts = self.contacts.values().map(|c| key_of(&c.pk)).filter(|k| self.mesh_knows_key(k));
        if peers.chain(contacts).any(|k| &k[..8] == id && k != own) {
            return None;
        }
        Some(own)
    }

    /// Источник кадра, адресованного клиенту: живой peer либо проверенный контакт,
    /// который разрешил нам USE. Только для конца сквозного QUIC, не для транзита.
    pub fn client_mesh_source_for_id8(&self, id: &[u8; 8]) -> Option<[u8; 32]> {
        if &key_of(&self.me_pk)[..8] == id { return None; }
        let mut found = None;
        let keys = self.live().map(|p| key_of(&p.pk)).filter(|k| self.mesh_knows_key(k)).chain(self.contacts.iter().filter_map(|(_, c)| {
            let trusted = c.intro_by == "invite" || c.intro_by == "local" || c.intro_by.len() == 32;
            let key = key_of(&c.pk);
            let revoked = self.peers.values().any(|p| p.rights == 0 && key_of(&p.pk) == key);
            (trusted && !revoked && c.they_grant & USE != 0).then_some(key)
        }));
        for k in keys {
            if &k[..8] == id && found != Some(k) {
                if found.is_some() { return None; }
                found = Some(k);
            }
        }
        found
    }

    /// Полный ключ по ключу iroh: только известные таблице (peers, потом contacts).
    pub fn pk_for_key(&self, key: &[u8; 32]) -> Option<Pk> {
        self.live().map(|p| p.pk).chain(self.contacts.values().map(|c| c.pk)).find(|pk| &key_of(pk) == key)
    }

    /// Нода-транзит: эта нода вправе пересылать (`transit_enabled`), знает и не отозвала `prev`, `src`, `dst` (ADR §3.1).
    pub fn mesh_forward(&self, prev: &[u8; 32], src: &[u8; 32], dst: &[u8; 32]) -> bool {
        self.cfg.transit_enabled && self.key_holds_any(prev) && self.key_holds_any(src) && self.key_holds_any(dst)
    }

    /// Допуск соседа-сервера (Link между нодами): таблица знает его с ненулевыми правами, и хотя бы одна сторона - транзит
    /// (у нас включён `transit_enabled` либо он сам объявил роль TRANSIT в `accept`).
    pub fn admits_server(&self, pk: &Pk) -> bool {
        self.rights_pk(pk) != 0 && (self.cfg.transit_enabled || self.roles_of_key(&key_of(pk)) & TRANSIT != 0)
    }

    /// Допуск VPN-клиента (ADR 0028 §3.2): на этой ноде включён `exit_enabled`, а у клиента есть USE.
    pub fn admits_client(&self, pk: &Pk) -> bool {
        self.cfg.exit_enabled && self.rights_pk(pk) & USE != 0
    }

    /// Relay iroh: нода сама имеет право быть relay и ключ известен таблице (ADR §3.4).
    pub fn relay_allows(&self, key: &[u8; 32]) -> bool {
        self.cfg.transit_enabled && self.key_holds_any(key)
    }

    // -------------------------------------------------------------------------------------------- правки peers

    fn check_seq(&self, h: &Hash, seq: u64, author: &str, now: u64) -> std::result::Result<(), Reject> {
        if seq > now + SEQ_FUTURE_MS {
            return Err("seq_future");
        }
        if let Some(old) = self.peers.get(h) {
            if seq < old.seq || (seq == old.seq && author.as_bytes() >= old.by.as_bytes()) {
                return Err("stale");
            }
        }
        Ok(())
    }

    fn config_holders(&self) -> usize {
        self.live().filter(|p| p.rights & CONFIG != 0).count()
    }

    /// Создать или изменить запись. ADD-актор только создаёт/повышает в пределах своих прав; CONFIG и Local — любое
    /// (HOST_ACCESS и CONFIG выдают только они). Права 0 — через `peer_remove`.
    pub fn peer_set(&mut self, actor: &Actor, pk: Pk, rights: u16, name: &str, seq: u64, now: u64) -> std::result::Result<Applied, Reject> {
        let Some(h) = hash_of(&pk) else { return Err("bad_target") };
        if h == self.me_hash {
            return Err("bad_target");
        }
        if rights == 0 || rights & !KNOWN != 0 {
            return Err("bad_rights");
        }
        let auth = self.authority(actor);
        let full = *actor == Actor::Local || auth & CONFIG != 0;
        if !full {
            if auth & ADD == 0 {
                return Err("no_authority");
            }
            if rights & CONFIG_ONLY != 0 || rights & !auth != 0 {
                return Err("rights_exceed");
            }
            if let Some(old) = self.peers.get(&h) {
                // ADD только повышает и не трогает чужие записи выше своих прав
                if old.rights & !rights != 0 {
                    return Err("no_authority");
                }
                // надгробие (отзыв) снимает только CONFIG/Local: ADD не «воскрешает» отозванного (SA-13)
                if old.rights == 0 {
                    return Err("no_authority");
                }
            }
        }
        if let Some(old) = self.peers.get(&h) {
            if old.pk != pk {
                return Err("bad_target");
            }
        } else if self.peers.len() >= MAX_PEERS {
            return Err("full");
        }
        if rights & CONFIG != 0 && self.peers.get(&h).is_none_or(|o| o.rights & CONFIG == 0) && self.config_holders() >= MAX_CONFIG_HOLDERS {
            return Err("too_many_config");
        }
        let author = actor.label();
        self.check_seq(&h, seq, &author, now)?;
        let same = self.peers.get(&h).is_some_and(|o| o.rights == rights);
        let name = sane_name(name);
        let keep_name = self.peers.get(&h).map(|o| o.name.clone()).filter(|n| name.is_empty() && !n.is_empty());
        self.peers.insert(h, Peer { pk, rights, by: author, seq, at: now, name: keep_name.unwrap_or(name) });
        self.bump();
        Ok(if same { Applied::Unchanged } else { Applied::Changed })
    }

    /// Понизить до надгробия (`rights = 0`). REMOVE-актор — только записи с правами ⊆ своих.
    pub fn peer_remove(&mut self, actor: &Actor, h: &Hash, seq: u64, now: u64) -> std::result::Result<Applied, Reject> {
        let auth = self.authority(actor);
        let full = *actor == Actor::Local || auth & CONFIG != 0;
        let Some(old) = self.peers.get(h).cloned() else { return Err("unknown") };
        if !full && (auth & REMOVE == 0 || old.rights & !auth != 0) {
            return Err("no_authority");
        }
        let author = actor.label();
        self.check_seq(h, seq, &author, now)?;
        if old.rights == 0 {
            return Ok(Applied::Unchanged);
        }
        self.peers.insert(*h, Peer { rights: 0, by: author, seq, at: now, ..old });
        self.bump();
        Ok(Applied::Changed)
    }

    /// Каскад «отозвать всё, выданное X» (X — `local`, hex хеша или `invite:<pid>`): замена транзитивных цепочек.
    pub fn revoke_by(&mut self, actor: &Actor, issuer: &str, seq: u64, now: u64) -> std::result::Result<usize, Reject> {
        if *actor != Actor::Local && self.authority(actor) & CONFIG == 0 {
            return Err("no_authority");
        }
        if !is_hash_str(issuer) || seq > now + SEQ_FUTURE_MS {
            return Err("bad_args");
        }
        let author = actor.label();
        let mut n = 0;
        for p in self.peers.values_mut() {
            if p.rights != 0 && p.by == issuer && (seq > p.seq || (seq == p.seq && author.as_bytes() < p.by.as_bytes())) {
                p.rights = 0;
                p.by = author.clone();
                p.seq = seq;
                p.at = now;
                n += 1;
            }
        }
        if n > 0 {
            self.bump();
        }
        Ok(n)
    }

    pub fn set_config(&mut self, actor: &Actor, transit: Option<bool>, exit: Option<bool>) -> std::result::Result<Applied, Reject> {
        if *actor != Actor::Local && self.authority(actor) & CONFIG == 0 {
            return Err("no_authority");
        }
        let mut c = self.cfg;
        if let Some(t) = transit {
            c.transit_enabled = t;
        }
        if let Some(e) = exit {
            c.exit_enabled = e;
        }
        if c == self.cfg {
            return Ok(Applied::Unchanged);
        }
        self.cfg = c;
        self.bump();
        Ok(Applied::Changed)
    }

    // -------------------------------------------------------------------------------------------- приглашения

    fn open_count(&self, issuer: Option<&str>) -> usize {
        self.invites.values().filter(|i| matches!(i.state, InviteState::Open | InviteState::Redeemed { .. }) && issuer.is_none_or(|x| i.issuer == x)).count()
    }

    /// Выпуск приглашения на этой ноде: Local — сам, иначе `invite.add` от актора с ADD/CONFIG (`rights ⊆` своих).
    /// Повтор с тем же ключом идемпотентен; тот же pid с другим ключом отвергается.
    pub fn invite_add(&mut self, actor: &Actor, pid: Pid, key: [u8; 32], rights: u16, expires_in_ms: u64, now: u64) -> std::result::Result<Applied, Reject> {
        let auth = self.authority(actor);
        if *actor != Actor::Local && auth & (ADD | CONFIG) == 0 {
            return Err("no_authority");
        }
        let full = *actor == Actor::Local || auth & CONFIG != 0;
        if rights == 0 || rights & !KNOWN != 0 {
            return Err("bad_rights");
        }
        if !full && (rights & CONFIG_ONLY != 0 || rights & !auth != 0) {
            return Err("rights_exceed");
        }
        let issuer = actor.label();
        if let Some(old) = self.invites.get(&pid) {
            return if old.key == key && old.rights == rights && old.issuer == issuer { Ok(Applied::Unchanged) } else { Err("exists") };
        }
        if self.open_count(None) >= MAX_INVITES_OPEN || self.open_count(Some(&issuer)) >= MAX_INVITES_PER_ISSUER || self.invites.len() >= 4 * MAX_INVITES_OPEN {
            return Err("full");
        }
        let ttl = expires_in_ms.clamp(60_000, INVITE_MAX_MS);
        self.invites.insert(pid, Invite { pid, key, rights, created: now, expires: now + ttl, issuer, state: InviteState::Open });
        Ok(Applied::Changed)
    }

    /// Отмена: выдавший (`issuer`) или CONFIG/Local. Погашенное остаётся погашенным.
    pub fn invite_cancel(&mut self, actor: &Actor, pid: &Pid) -> std::result::Result<Applied, Reject> {
        let auth = self.authority(actor);
        let Some(inv) = self.invites.get_mut(pid) else { return Err("unknown") };
        if *actor != Actor::Local && auth & CONFIG == 0 && inv.issuer != actor.label() {
            return Err("no_authority");
        }
        if inv.state != InviteState::Open {
            return Ok(Applied::Unchanged);
        }
        inv.state = InviteState::Cancelled;
        Ok(Applied::Changed)
    }

    /// Погашение. Всё под одной блокировкой (вызывающий держит `&mut`): проверка состояния, пруфа, запись в `peers`, на диск —
    /// раньше ответа. Любая неудача, кроме неверного пруфа известного pid и использованного пина, — молчание.
    /// Ошибка записи на диск откатывает таблицу и даёт `Silent`: получатель повторит.
    pub fn redeem(&mut self, pid: &Pid, pk_n: &Pk, name: &str, now: u64, proof_ok: impl FnOnce(&[u8; 32]) -> bool) -> Redeem {
        let Some(h) = hash_of(pk_n) else { return Redeem::Silent };
        if h == self.me_hash {
            return Redeem::Silent;
        }
        let Some(inv) = self.invites.get(pid).cloned() else { return Redeem::Silent };
        match &inv.state {
            InviteState::Open | InviteState::Redeemed { .. } | InviteState::Settled => {}
            _ => return Redeem::Silent,
        }
        // повтор уже погашенным ключом допустим и после expires, пока приглашение не закрыто: идемпотентный accept
        let same = matches!(&inv.state, InviteState::Redeemed { pk, .. } if pk == pk_n) ;
        if inv.state == InviteState::Open && now >= inv.expires {
            return Redeem::Silent;
        }
        if !proof_ok(&inv.key) {
            return Redeem::BadProof;
        }
        let name = sane_name(name);
        if same {
            return Redeem::Accepted { rights: inv.rights, name, fresh: false };
        }
        if inv.state != InviteState::Open {
            return Redeem::Used;
        }
        // атомарно: записать и сохранить; при ошибке диска откатить
        let saved_peers = self.peers.clone();
        let old = self.peers.get(&h).cloned();
        if old.is_none() && self.peers.len() >= MAX_PEERS {
            return Redeem::Silent;
        }
        // отозванный ключ (надгробие) поднимает только приглашение, выпущенное после отзыва держателем CONFIG (или локально):
        // утёкшее старое приглашение или выпущенное держателем одного ADD отзыв не отменяет (SA-13)
        if let Some(o) = old.as_ref().filter(|o| o.rights == 0) {
            let by_config = inv.issuer == "local"
                || unhex(&inv.issuer).try_into().ok().is_some_and(|ih: Hash| self.rights(&ih) & CONFIG != 0);
            if inv.created <= o.at || !by_config {
                return Redeem::Used;
            }
        }
        let rights = inv.rights | old.as_ref().map_or(0, |o| o.rights);
        let seq = old.as_ref().map_or(now, |o| now.max(o.seq + 1));
        let keep = old.as_ref().filter(|o| o.rights == rights).is_some();
        let by = if keep { old.as_ref().unwrap().by.clone() } else { format!("invite:{}", hex(pid)) };
        self.peers.insert(h, Peer { pk: *pk_n, rights, by, seq, at: now, name: old.as_ref().map(|o| o.name.clone()).filter(|n| name.is_empty() && !n.is_empty()).unwrap_or_else(|| name.clone()) });
        if let Some(i) = self.invites.get_mut(pid) {
            i.state = InviteState::Redeemed { pk: *pk_n, at: now };
        }
        if self.save().is_err() {
            self.peers = saved_peers;
            if let Some(i) = self.invites.get_mut(pid) {
                i.state = InviteState::Open;
            }
            return Redeem::Silent;
        }
        self.bump();
        Redeem::Accepted { rights: inv.rights, name, fresh: true }
    }

    /// `ack` получателя: погашено полностью. Возвращает, изменилось ли состояние.
    pub fn invite_settle(&mut self, pid: &Pid, pk: &Pk) -> bool {
        match self.invites.get_mut(pid) {
            Some(i) if matches!(&i.state, InviteState::Redeemed { pk: p, .. } if p == pk) => {
                i.state = InviteState::Settled;
                true
            }
            _ => false,
        }
    }

    /// Срок приглашений и удаление закрытых старше `INVITE_AUDIT_MS`. Возвращает, нужна ли запись.
    pub fn gc(&mut self, now: u64) -> bool {
        let mut dirty = false;
        for i in self.invites.values_mut() {
            if i.state == InviteState::Open && now >= i.expires {
                i.state = InviteState::Expired;
                dirty = true;
            }
        }
        let before = self.invites.len();
        self.invites.retain(|_, i| match &i.state {
            InviteState::Open => true,
            InviteState::Redeemed { at, .. } => now < i.expires.max(*at) + INVITE_AUDIT_MS,
            _ => now < i.expires + INVITE_AUDIT_MS,
        });
        dirty || self.invites.len() != before
    }

    // -------------------------------------------------------------------------------------------- contacts

    pub fn contact_set(&mut self, pk: Pk, name: &str, hints: Vec<String>, intro_by: &str, they_grant: u16, roles: u16, now: u64) -> std::result::Result<(), Reject> {
        let Some(h) = hash_of(&pk) else { return Err("bad_target") };
        if h == self.me_hash {
            return Err("bad_target");
        }
        if !self.contacts.contains_key(&h) && self.contacts.len() >= MAX_CONTACTS {
            return Err("full");
        }
        let old = self.contacts.get(&h);
        let rl = old.map_or(serde_json::Value::Null, |o| o.rl.clone());
        let client = old.is_some_and(|o| o.client);
        let name = sane_name(name);
        let name = if name.is_empty() { old.map(|o| o.name.clone()).unwrap_or_default() } else { name };
        let hints = if hints.is_empty() { old.map(|o| o.hints.clone()).unwrap_or_default() } else { balance_hints(hints, MAX_CONTACT_HINTS) };
        let intro_by = old.filter(|o| o.intro_by != "invite" && intro_by == "invite").map_or(intro_by.to_string(), |o| o.intro_by.clone());
        let auth_changed = old.is_none_or(|o| o.pk != pk || o.intro_by != intro_by || o.they_grant != they_grant & KNOWN || o.roles != roles & (TRANSIT | EXIT));
        self.contacts.insert(h, Contact { pk, name, hints, intro_by, they_grant: they_grant & KNOWN, roles: roles & (TRANSIT | EXIT), at: now, rl, client });
        if auth_changed { self.bump(); }
        Ok(())
    }

    /// Пометка «нода - клиент» (по её же сообщению `accept`/`ack`): подсказка, не полномочие.
    pub fn set_contact_client(&mut self, h: &Hash, client: bool) {
        if let Some(c) = self.contacts.get_mut(h) { c.client = client; }
    }

    /// Роли контакта по его собственному статусу; false - контакта нет или роли не изменились.
    pub fn set_contact_roles(&mut self, h: &Hash, roles: u16) -> bool {
        let changed = match self.contacts.get_mut(h) {
            Some(c) if c.roles != roles & (TRANSIT | EXIT) => { c.roles = roles & (TRANSIT | EXIT); true }
            _ => false,
        };
        if changed { self.bump(); }
        changed
    }

    /// Подсказка от самой ноды о правах на ней; окончательный допуск решает нода.
    pub fn set_contact_grant(&mut self, h: &Hash, rights: u16) -> bool {
        let changed = match self.contacts.get_mut(h) {
            Some(c) if c.they_grant != rights & KNOWN => { c.they_grant = rights & KNOWN; true }
            _ => false,
        };
        if changed { self.bump(); }
        changed
    }

    /// Новые адреса-подсказки известного контакта (сообщение `addr`). false - контакта нет, список пуст или не изменился.
    pub fn contact_set_hints(&mut self, h: &Hash, hints: Vec<String>) -> bool {
        let hints = balance_hints(hints, MAX_CONTACT_HINTS);
        match self.contacts.get_mut(h) {
            Some(c) if !hints.is_empty() && c.hints != hints => { c.hints = hints; true }
            _ => false,
        }
    }

    /// Убрать контакт: только подсказки и выбор, `peers` (что разрешено ему) не меняется (ADR §1.3).
    pub fn contact_remove(&mut self, h: &Hash) -> bool {
        let changed = self.contacts.remove(h).is_some();
        if changed { self.bump(); }
        changed
    }

    /// Запомнить подсказку REALITY контакта. Ограничена по размеру; нет контакта или слишком большая — ничего не меняется.
    pub fn contact_rl(&mut self, pk: &Pk, rl: &serde_json::Value) {
        if rl.is_null() || rl.to_string().len() > 256 { return; }
        if let Some(c) = hash_of(pk).and_then(|h| self.contacts.get_mut(&h)) { c.rl = rl.clone(); }
    }

    /// Результат погашения у ПОЛУЧАТЕЛЯ (`accept` проверен): только контакт. Телефон и клиент никому управления собой не дают.
    /// Управляющий появляется лишь через `adopt_controller` (сервер, первый запуск с `--invite-file`).
    pub fn accepted(&mut self, pk_h: Pk, name: &str, hints: Vec<String>, they_grant: u16, roles: u16, now: u64) -> std::result::Result<(), Reject> {
        self.contact_set(pk_h, name, hints, "invite", they_grant, roles, now)
    }

    /// Сервер при первом запуске по приглашению: выдавший становится управляющим (`PRESET_ADMIN`). Вызывает только `invite::settle`
    /// после проверки подписи LXMF и MAC `accept`, и только для пар, помеченных при `--invite-file`.
    pub fn adopt_controller(&mut self, pk_h: Pk, name: &str, now: u64) -> std::result::Result<(), Reject> {
        let h = hash_of(&pk_h).ok_or("bad_target")?;
        let seq = self.peers.get(&h).map_or(now, |o| o.seq + 1).max(now);
        self.peers.insert(h, Peer { pk: pk_h, rights: PRESET_ADMIN & KNOWN, by: "invite:accept".into(), seq, at: now, name: sane_name(name) });
        self.bump();
        Ok(())
    }

    pub fn status(&self, now: u64) -> serde_json::Value {
        let list = |f: &dyn Fn(&Peer) -> bool| -> Vec<serde_json::Value> {
            self.peers.iter().filter(|(_, p)| f(p)).map(|(h, p)| serde_json::json!({"hash": hex(h), "pk": hex(&p.pk), "rights": p.rights, "by": p.by, "seq": p.seq, "name": p.name})).collect()
        };
        serde_json::json!({
            "me": hex(&self.me_hash),
            "controllers": self.controllers().iter().filter_map(|p| hash_of(p)).map(|h| hex(&h)).collect::<Vec<_>>(),
            "peers": list(&|_| true),
            "invites": self.invites.values().map(|i| serde_json::json!({
                "pid": hex(&i.pid), "rights": i.rights, "expires": i.expires, "issuer": i.issuer, "left_s": i.expires.saturating_sub(now) / 1000,
                "state": match &i.state { InviteState::Open => "open", InviteState::Redeemed { .. } => "redeemed", InviteState::Settled => "settled", InviteState::Cancelled => "cancelled", InviteState::Expired => "expired" },
                "by": match &i.state { InviteState::Redeemed { pk, .. } => hash_of(pk).map(|h| hex(&h)), _ => None },
            })).collect::<Vec<_>>(),
            "contacts": self.contacts.iter().map(|(h, c)| serde_json::json!({"hash": hex(h), "name": c.name, "they_grant": c.they_grant, "roles": c.roles, "intro_by": c.intro_by, "hints": c.hints.len()})).collect::<Vec<_>>(),
            "transit_enabled": self.cfg.transit_enabled, "exit_enabled": self.cfg.exit_enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use std::sync::Mutex;

    fn ident() -> (Identity, Pk) {
        let i = Identity::generate(&mut rand_core::OsRng);
        let pk = i.public_key_bytes();
        (i, pk)
    }
    fn table() -> (Peers, Pk) {
        let (_, me) = ident();
        (Peers::new(me, None), me)
    }
    fn hh(pk: &Pk) -> Hash {
        hash_of(pk).unwrap()
    }
    const T0: u64 = 1_000_000_000_000;

    fn admin_in(t: &mut Peers) -> (Pk, Actor) {
        let (_, a) = ident();
        t.peer_set(&Actor::Local, a, PRESET_ADMIN, "adm", T0, T0).unwrap();
        (a, Actor::Peer(hh(&a)))
    }
    fn open_invite(t: &mut Peers, rights: u16) -> ([u8; 16], Pid) {
        let pin = [7u8; 16];
        let pid = pin_id(&pin);
        t.invite_add(&Actor::Local, pid, pin_key(&pin), rights, INVITE_DEFAULT_MS, T0).unwrap();
        (pin, pid)
    }
    fn good(pin: [u8; 16]) -> impl FnOnce(&[u8; 32]) -> bool {
        move |k| *k == pin_key(&pin)
    }

    #[test]
    fn balance_hints_keeps_one_address_per_family_within_the_limit() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // три IPv4 раньше вытесняли IPv6 (`take(3)`): теперь v6 остаётся, порядок сохраняется
        let out = balance_hints(s(&["1.1.1.1:1", "2.2.2.2:1", "3.3.3.3:1", "[2606::1]:1"]), 3);
        assert_eq!(out, s(&["1.1.1.1:1", "2.2.2.2:1", "[2606::1]:1"]));
        // только v4 или только v6 - просто первые три; повторы убираются
        assert_eq!(balance_hints(s(&["1.1.1.1:1", "1.1.1.1:1", "2.2.2.2:1", "3.3.3.3:1", "4.4.4.4:1"]), 3).len(), 3);
        assert_eq!(balance_hints(s(&["[2606::1]:1", "[2606::2]:1", "[2606::3]:1", "[2606::4]:1"]), 3), s(&["[2606::1]:1", "[2606::2]:1", "[2606::3]:1"]));
        // v6 вперёд в списке: v4 всё равно сохраняется
        let out = balance_hints(s(&["[2606::1]:1", "[2606::2]:1", "[2606::3]:1", "9.9.9.9:1"]), 3);
        assert!(out.contains(&"9.9.9.9:1".to_string()) && out.contains(&"[2606::1]:1".to_string()) && out.len() == 3);
        assert!(balance_hints(vec![], 3).is_empty());
    }

    #[test]
    fn contact_hints_update_is_idempotent_and_persisted_balanced() {
        let (mut t, _) = table();
        let (_, c) = ident();
        t.contact_set(c, "c", s_hints(&["1.1.1.1:1"]), "invite", 0, 0, T0).unwrap();
        let h = hh(&c);
        assert!(!t.contact_set_hints(&h, vec![]), "пустой список не затирает");
        assert!(t.contact_set_hints(&h, s_hints(&["2.2.2.2:1", "3.3.3.3:1", "4.4.4.4:1", "[2606::1]:1"])));
        assert!(t.contact(&h).unwrap().hints.iter().any(|a| a.starts_with('[')), "v6 не вытеснен");
        assert!(!t.contact_set_hints(&h, t.contact(&h).unwrap().hints.clone()), "без изменений - false");
        assert!(!t.contact_set_hints(&[7; 16], s_hints(&["1.1.1.1:1"])), "нет контакта");
    }

    fn s_hints(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn redeem_marks_peer_and_is_idempotent_for_same_key() {
        let (mut t, _) = table();
        let (pin, pid) = open_invite(&mut t, USE | EXIT);
        let (_, n) = ident();
        let r = t.redeem(&pid, &n, "phone", T0 + 1, good(pin));
        assert_eq!(r, Redeem::Accepted { rights: USE | EXIT, name: "phone".into(), fresh: true });
        assert_eq!(t.rights(&hh(&n)), USE | EXIT);
        assert_eq!(t.redeem(&pid, &n, "phone", T0 + 2, good(pin)), Redeem::Accepted { rights: USE | EXIT, name: "phone".into(), fresh: false });
        assert!(t.invite_settle(&pid, &n));
        assert_eq!(t.invite(&pid).unwrap().state, InviteState::Settled);
    }

    #[test]
    fn second_redeemer_with_valid_proof_gets_used_and_no_rights() {
        let (mut t, _) = table();
        let (pin, pid) = open_invite(&mut t, USE);
        let (_, a) = ident();
        let (_, b) = ident();
        assert!(matches!(t.redeem(&pid, &a, "a", T0 + 1, good(pin)), Redeem::Accepted { .. }));
        assert_eq!(t.redeem(&pid, &b, "b", T0 + 2, good(pin)), Redeem::Used);
        assert_eq!(t.rights(&hh(&b)), 0);
    }

    #[test]
    fn concurrent_redeem_exactly_one_wins() {
        let (t, _) = table();
        let t = Arc::new(Mutex::new(t));
        let pin = [9u8; 16];
        let pid = pin_id(&pin);
        t.lock().unwrap().invite_add(&Actor::Local, pid, pin_key(&pin), USE, INVITE_DEFAULT_MS, T0).unwrap();
        let wins = Arc::new(AtomicU64::new(0));
        let hs: Vec<_> = (0..16).map(|_| {
            let (t, wins) = (t.clone(), wins.clone());
            std::thread::spawn(move || {
                let (_, n) = ident();
                if matches!(t.lock().unwrap().redeem(&pid, &n, "x", T0 + 5, good(pin)), Redeem::Accepted { fresh: true, .. }) {
                    wins.fetch_add(1, Ordering::SeqCst);
                }
            })
        }).collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(wins.load(Ordering::SeqCst), 1);
        assert_eq!(t.lock().unwrap().live().count(), 1);
    }

    #[test]
    fn bad_proof_changes_nothing_unknown_pid_and_expired_are_silent() {
        let (mut t, _) = table();
        let (pin, pid) = open_invite(&mut t, USE);
        let (_, n) = ident();
        assert_eq!(t.redeem(&pid, &n, "n", T0 + 1, |_| false), Redeem::BadProof);
        assert_eq!(t.invite(&pid).unwrap().state, InviteState::Open);
        assert_eq!(t.rights(&hh(&n)), 0);
        assert_eq!(t.redeem(&[1; 8], &n, "n", T0 + 1, good(pin)), Redeem::Silent);
        assert_eq!(t.redeem(&pid, &n, "n", T0 + INVITE_DEFAULT_MS + 1, good(pin)), Redeem::Silent);
        // после BadProof честный получатель всё ещё гасит
        assert!(matches!(t.redeem(&pid, &n, "n", T0 + 2, good(pin)), Redeem::Accepted { fresh: true, .. }));
    }

    #[test]
    fn cancelled_invite_and_self_redeem_are_silent() {
        let (mut t, me) = table();
        let (pin, pid) = open_invite(&mut t, USE);
        assert_eq!(t.redeem(&pid, &me, "me", T0 + 1, good(pin)), Redeem::Silent);
        assert_eq!(t.invite_cancel(&Actor::Local, &pid), Ok(Applied::Changed));
        let (_, n) = ident();
        assert_eq!(t.redeem(&pid, &n, "n", T0 + 1, good(pin)), Redeem::Silent);
    }

    #[test]
    fn redeem_never_lowers_existing_rights() {
        let (mut t, _) = table();
        let (a, _) = admin_in(&mut t);
        let (pin, pid) = open_invite(&mut t, USE);
        assert!(matches!(t.redeem(&pid, &a, "adm", T0 + 1, good(pin)), Redeem::Accepted { .. }));
        assert_eq!(t.rights(&hh(&a)), PRESET_ADMIN);
    }

    /// SA-13: надгробие снимает только CONFIG/Local; старое приглашение и приглашение держателя одного ADD отзыв не отменяют.
    #[test]
    fn tombstone_is_lifted_only_by_config_or_a_fresh_config_invite() {
        let (mut t, _) = table();
        let (_, n) = ident();
        let h = hh(&n);
        let (pin_old, pid_old) = open_invite(&mut t, USE);
        t.peer_set(&Actor::Local, n, USE, "ph", T0 + 1, T0 + 1).unwrap();
        t.peer_remove(&Actor::Local, &h, T0 + 2, T0 + 2).unwrap();
        // держатель ADD (без CONFIG) не воскрешает
        let (_, ad) = ident();
        t.peer_set(&Actor::Local, ad, USE | ADD, "ad", T0 + 3, T0 + 3).unwrap();
        assert_eq!(t.peer_set(&Actor::Peer(hh(&ad)), n, USE, "", T0 + 4, T0 + 4), Err("no_authority"));
        // приглашение, выпущенное до отзыва
        assert_eq!(t.redeem(&pid_old, &n, "ph", T0 + 5, good(pin_old)), Redeem::Used);
        // свежее приглашение держателя одного ADD
        let pin_a = [9u8; 16];
        t.invite_add(&Actor::Peer(hh(&ad)), pin_id(&pin_a), pin_key(&pin_a), USE, INVITE_DEFAULT_MS, T0 + 6).unwrap();
        assert_eq!(t.redeem(&pin_id(&pin_a), &n, "ph", T0 + 7, good(pin_a)), Redeem::Used);
        assert_eq!(t.rights(&h), 0, "отзыв устоял");
        // свежее приглашение Local (админ ноды) — поднимает
        let pin_l = [10u8; 16];
        t.invite_add(&Actor::Local, pin_id(&pin_l), pin_key(&pin_l), USE, INVITE_DEFAULT_MS, T0 + 8).unwrap();
        assert!(matches!(t.redeem(&pin_id(&pin_l), &n, "ph", T0 + 9, good(pin_l)), Redeem::Accepted { .. }));
        assert_eq!(t.rights(&h), USE);
    }

    #[test]
    fn redeem_rolls_back_when_disk_write_fails() {
        let dir = tmp("rollback");
        let (_, me) = ident();
        let mut t = Peers::new(me, Some(dir.join("no-such-dir/peers.json")));
        let (pin, pid) = open_invite(&mut t, USE);
        let (_, n) = ident();
        assert_eq!(t.redeem(&pid, &n, "n", T0 + 1, good(pin)), Redeem::Silent);
        assert_eq!(t.invite(&pid).unwrap().state, InviteState::Open);
        assert_eq!(t.rights(&hh(&n)), 0);
    }

    #[test]
    fn seq_orders_edits_old_grant_does_not_undo_new_revoke() {
        let (mut t, _) = table();
        let (_, adm) = admin_in(&mut t);
        let (_, p) = ident();
        assert_eq!(t.peer_set(&adm, p, USE, "p", T0 + 10, T0 + 10), Ok(Applied::Changed));
        assert_eq!(t.peer_remove(&adm, &hh(&p), T0 + 20, T0 + 20), Ok(Applied::Changed));
        // задержанный в PN старый grant (seq 15) не воскрешает
        assert_eq!(t.peer_set(&adm, p, USE, "p", T0 + 15, T0 + 30), Err("stale"));
        assert_eq!(t.rights(&hh(&p)), 0);
        // равный seq от того же автора — тоже stale; новее — принимается
        assert_eq!(t.peer_set(&adm, p, USE, "p", T0 + 20, T0 + 30), Err("stale"));
        assert_eq!(t.peer_set(&adm, p, USE, "p", T0 + 21, T0 + 30), Ok(Applied::Changed));
    }

    #[test]
    fn equal_seq_tie_breaks_by_smaller_author_hash() {
        let (mut t, _) = table();
        let (_, a1) = ident();
        let (_, a2) = ident();
        t.peer_set(&Actor::Local, a1, PRESET_ADMIN, "", T0, T0).unwrap();
        t.peer_set(&Actor::Local, a2, PRESET_ADMIN, "", T0, T0).unwrap();
        let (_, p) = ident();
        let (lo, hi) = if hex(&hh(&a1)) < hex(&hh(&a2)) { (a1, a2) } else { (a2, a1) };
        t.peer_set(&Actor::Peer(hh(&hi)), p, USE, "", T0 + 5, T0 + 5).unwrap();
        // тот же seq: побеждает меньший хеш автора
        assert_eq!(t.peer_remove(&Actor::Peer(hh(&lo)), &hh(&p), T0 + 5, T0 + 5), Ok(Applied::Changed));
        assert_eq!(t.peer_set(&Actor::Peer(hh(&hi)), p, USE, "", T0 + 5, T0 + 5), Err("stale"));
    }

    #[test]
    fn future_seq_is_rejected_and_tombstone_survives_reload() {
        let dir = tmp("tomb");
        let (_, me) = ident();
        let mut t = Peers::new(me, Some(Peers::file(&dir)));
        let (_, p) = ident();
        assert_eq!(t.peer_set(&Actor::Local, p, USE, "", T0 + SEQ_FUTURE_MS + 1, T0), Err("seq_future"));
        t.peer_set(&Actor::Local, p, USE | EXIT, "tel", T0, T0).unwrap();
        t.peer_remove(&Actor::Local, &hh(&p), T0 + 1, T0 + 1).unwrap();
        t.save().unwrap();
        let t2 = Peers::load(me, &dir).unwrap();
        assert_eq!(t2.rights(&hh(&p)), 0);
        assert_eq!(t2.peer(&hh(&p)).unwrap().seq, T0 + 1, "надгробие хранит seq и не пропадает");
        let mut t2 = t2;
        assert_eq!(t2.peer_set(&Actor::Local, p, USE, "", T0, T0 + 2), Err("stale"));
    }

    #[test]
    fn load_is_fail_closed() {
        let dir = tmp("failclosed");
        let (_, me) = ident();
        assert!(Peers::load(me, &dir).unwrap().peer_list().is_empty(), "нет файла — пустая таблица");
        let f = Peers::file(&dir);
        std::fs::write(&f, b"{ not json").unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert!(Peers::load(me, &dir).is_err(), "повреждён");
        std::fs::write(&f, br#"{"v":1,"peers":[{"pk":"00","rights":1,"by":"local"}],"contacts":[],"invites":[]}"#).unwrap();
        assert!(Peers::load(me, &dir).is_err(), "плохой ключ не пропускается молча");
        let mut t = Peers::new(me, Some(f.clone()));
        t.save().unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        assert!(Peers::load(me, &dir).is_err(), "права шире 0600");
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let link = dir.join("l");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(read_private(&link, 1024).is_err(), "symlink не читаем");
        assert!(Peers::load(me, &dir).is_ok());
    }

    #[test]
    fn saved_file_is_0600_and_roundtrips_invites_and_contacts() {
        let dir = tmp("roundtrip");
        let (_, me) = ident();
        let mut t = Peers::new(me, Some(Peers::file(&dir)));
        let (pin, pid) = open_invite(&mut t, USE | EXIT);
        let (_, n) = ident();
        t.redeem(&pid, &n, "ph", T0 + 1, good(pin));
        t.contact_set(n, "ph", vec!["1.2.3.4:5".into()], "local", USE, EXIT, T0).unwrap();
        // подсказка REALITY: переживает файл и повторный contact_set, слишком большая не принимается
        let rl = serde_json::json!({"p": 443, "s": "www.example.org", "k": "ab", "i": "cd"});
        t.contact_rl(&n, &rl);
        t.contact_rl(&n, &serde_json::json!({"s": "x".repeat(400)}));
        t.contact_set(n, "ph", vec![], "local", USE, EXIT, T0).unwrap();
        assert_eq!(t.contact(&hash_of(&n).unwrap()).unwrap().rl, rl);
        t.set_config(&Actor::Local, Some(true), None).unwrap();
        t.save().unwrap();
        let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(Peers::file(&dir)).unwrap());
        assert_eq!(mode & 0o777, 0o600);
        let t2 = Peers::load(me, &dir).unwrap();
        assert_eq!(t2.invite_list(), t.invite_list());
        assert_eq!(t2.contact_list(), t.contact_list());
        assert_eq!(t2.peer_list(), t.peer_list());
        assert!(t2.config().transit_enabled);
        assert!(!std::fs::read_to_string(Peers::file(&dir)).unwrap().contains(&hex(&pin)), "пин на ноде не хранится");
    }

    #[test]
    fn add_actor_only_creates_or_raises_within_own_rights() {
        let (mut t, _) = table();
        let (_, adder) = ident();
        t.peer_set(&Actor::Local, adder, USE | EXIT | ADD, "", T0, T0).unwrap();
        let a = Actor::Peer(hh(&adder));
        let (_, p) = ident();
        assert_eq!(t.peer_set(&a, p, USE, "", T0 + 1, T0 + 1), Ok(Applied::Changed));
        assert_eq!(t.peer_set(&a, p, USE | EXIT, "", T0 + 2, T0 + 2), Ok(Applied::Changed));
        assert_eq!(t.peer_set(&a, p, USE, "", T0 + 3, T0 + 3), Err("no_authority"), "ADD не понижает");
        assert_eq!(t.peer_set(&a, p, USE | EXIT | TRANSIT, "", T0 + 4, T0 + 4), Err("rights_exceed"));
        assert_eq!(t.peer_set(&a, p, USE | HOST_ACCESS, "", T0 + 4, T0 + 4), Err("rights_exceed"));
        assert_eq!(t.peer_remove(&a, &hh(&p), T0 + 5, T0 + 5), Err("no_authority"), "без REMOVE");
        // чужая запись выше своих прав не трогается даже повышением
        let (_, boss) = ident();
        t.peer_set(&Actor::Local, boss, USE | TRANSIT, "", T0, T0).unwrap();
        assert_eq!(t.peer_set(&a, boss, USE | TRANSIT | EXIT, "", T0 + 9, T0 + 9), Err("rights_exceed"));
    }

    #[test]
    fn remove_actor_limited_to_subset_config_any_and_host_access_only_config() {
        let (mut t, _) = table();
        let (_, rm) = ident();
        t.peer_set(&Actor::Local, rm, USE | EXIT | REMOVE, "", T0, T0).unwrap();
        let r = Actor::Peer(hh(&rm));
        let (_, low) = ident();
        let (_, high) = ident();
        t.peer_set(&Actor::Local, low, USE, "", T0, T0).unwrap();
        t.peer_set(&Actor::Local, high, USE | TRANSIT, "", T0, T0).unwrap();
        assert_eq!(t.peer_remove(&r, &hh(&high), T0 + 1, T0 + 1), Err("no_authority"));
        assert_eq!(t.peer_remove(&r, &hh(&low), T0 + 1, T0 + 1), Ok(Applied::Changed));
        let (_, adm) = ident();
        t.peer_set(&Actor::Local, adm, PRESET_ADMIN, "", T0, T0).unwrap();
        let ac = Actor::Peer(hh(&adm));
        assert_eq!(t.peer_remove(&ac, &hh(&high), T0 + 2, T0 + 2), Ok(Applied::Changed));
        assert_eq!(t.peer_set(&ac, high, USE | HOST_ACCESS, "", T0 + 3, T0 + 3), Ok(Applied::Changed));
        assert_eq!(t.peer_set(&r, low, USE | HOST_ACCESS, "", T0 + 3, T0 + 3), Err("no_authority"), "у REMOVE-актора нет ADD");
        // стороннего актора без записи нет
        let (_, stranger) = ident();
        assert_eq!(t.peer_set(&Actor::Peer(hh(&stranger)), low, USE, "", T0 + 9, T0 + 9), Err("no_authority"));
    }

    #[test]
    fn admins_are_equal_and_may_remove_each_other_node_keeps_table() {
        let (mut t, _) = table();
        let (a, aa) = admin_in(&mut t);
        let (b, bb) = admin_in(&mut t);
        assert_eq!(t.peer_remove(&aa, &hh(&b), T0 + 1, T0 + 1), Ok(Applied::Changed));
        // B уже не админ в момент применения: полномочия проверяются при применении
        assert_eq!(t.peer_remove(&bb, &hh(&a), T0 + 2, T0 + 2), Err("no_authority"));
        assert!(t.has_controllers());
        assert_eq!(t.peer_remove(&aa, &hh(&a), T0 + 3, T0 + 3), Ok(Applied::Changed));
        assert!(!t.has_controllers(), "последнего снять можно: сеть живёт, правок нет");
        let (_, p) = ident();
        assert_eq!(t.peer_set(&aa, p, USE, "", T0 + 4, T0 + 4), Err("no_authority"));
    }

    #[test]
    fn revoke_by_cascades_only_for_that_issuer() {
        let (mut t, _) = table();
        let (_, a1) = admin_in(&mut t);
        let (_, a2) = admin_in(&mut t);
        let (_, p1) = ident();
        let (_, p2) = ident();
        t.peer_set(&a1, p1, USE, "", T0 + 1, T0 + 1).unwrap();
        t.peer_set(&a2, p2, USE, "", T0 + 1, T0 + 1).unwrap();
        let Actor::Peer(h1) = a1 else { unreachable!() };
        assert_eq!(t.revoke_by(&a2, &hex(&h1), T0 + 5, T0 + 5), Ok(1));
        assert_eq!(t.rights(&hh(&p1)), 0);
        assert_eq!(t.rights(&hh(&p2)), USE);
        assert_eq!(t.revoke_by(&Actor::Peer([9; 16]), &hex(&h1), T0 + 6, T0 + 6), Err("no_authority"));
    }

    #[test]
    fn limits_peers_config_holders_and_invite_quotas() {
        let (mut t, _) = table();
        for i in 0..MAX_CONFIG_HOLDERS {
            let (_, a) = ident();
            t.peer_set(&Actor::Local, a, CONFIG, "", T0 + i as u64, T0 + i as u64).unwrap_or_else(|e| panic!("{i}: {e}"));
        }
        let (_, a) = ident();
        assert_eq!(t.peer_set(&Actor::Local, a, CONFIG, "", T0, T0), Err("too_many_config"));
        let (mut t, _) = table();
        for _ in 0..MAX_PEERS {
            let (_, p) = ident();
            t.peer_set(&Actor::Local, p, USE, "", T0, T0).unwrap();
        }
        let (_, p) = ident();
        assert_eq!(t.peer_set(&Actor::Local, p, USE, "", T0, T0), Err("full"));
        let (mut t, _) = table();
        let (_, adder) = ident();
        t.peer_set(&Actor::Local, adder, USE | ADD, "", T0, T0).unwrap();
        let a = Actor::Peer(hh(&adder));
        for i in 0..MAX_INVITES_PER_ISSUER {
            let pid = [i as u8 + 1; 8];
            t.invite_add(&a, pid, [1; 32], USE, 1000, T0).unwrap();
        }
        assert_eq!(t.invite_add(&a, [99; 8], [1; 32], USE, 1000, T0), Err("full"));
        for k in 0..(MAX_INVITES_OPEN / MAX_INVITES_PER_ISSUER - 1) {
            let (_, more) = ident();
            t.peer_set(&Actor::Local, more, USE | ADD, "", T0, T0).unwrap();
            for i in 0..MAX_INVITES_PER_ISSUER {
                t.invite_add(&Actor::Peer(hh(&more)), [(100 + k * 20 + i) as u8; 8], [1; 32], USE, 1000, T0).unwrap();
            }
        }
        assert_eq!(t.invite_add(&Actor::Local, [250; 8], [1; 32], USE, 1000, T0), Err("full"));
    }

    #[test]
    fn invite_add_rules_exists_rights_and_ttl_cap() {
        let (mut t, _) = table();
        let (_, adder) = ident();
        t.peer_set(&Actor::Local, adder, USE | ADD, "", T0, T0).unwrap();
        let a = Actor::Peer(hh(&adder));
        assert_eq!(t.invite_add(&a, [1; 8], [1; 32], USE | EXIT, 1000, T0), Err("rights_exceed"));
        assert_eq!(t.invite_add(&a, [1; 8], [1; 32], USE, u64::MAX, T0), Ok(Applied::Changed));
        assert_eq!(t.invite([1; 8].as_ref().try_into().as_ref().unwrap()).unwrap().expires, T0 + INVITE_MAX_MS);
        assert_eq!(t.invite_add(&a, [1; 8], [1; 32], USE, 1000, T0), Ok(Applied::Unchanged), "повтор команды идемпотентен");
        assert_eq!(t.invite_add(&a, [1; 8], [2; 32], USE, 1000, T0), Err("exists"), "тот же pid, другой ключ");
        let (_, stranger) = ident();
        assert_eq!(t.invite_add(&Actor::Peer(hh(&stranger)), [2; 8], [1; 32], USE, 1000, T0), Err("no_authority"));
        // отмена: выдавший или CONFIG
        assert_eq!(t.invite_cancel(&Actor::Peer(hh(&stranger)), &[1; 8]), Err("no_authority"));
        assert_eq!(t.invite_cancel(&a, &[1; 8]), Ok(Applied::Changed));
    }

    #[test]
    fn gc_expires_then_drops_after_audit_window() {
        let (mut t, _) = table();
        let (_, pid) = open_invite(&mut t, USE);
        assert!(t.gc(T0 + INVITE_DEFAULT_MS + 1));
        assert_eq!(t.invite(&pid).unwrap().state, InviteState::Expired);
        assert!(!t.gc(T0 + INVITE_DEFAULT_MS + 2));
        assert!(t.gc(T0 + INVITE_DEFAULT_MS + INVITE_AUDIT_MS + 1));
        assert!(t.invite(&pid).is_none());
    }

    #[test]
    fn mesh_forward_is_local_predicate_and_revocation_applies_via_generation() {
        let (mut t, _) = table();
        let (_, a) = ident();
        let (_, b) = ident();
        let (_, c) = ident();
        for p in [a, b] {
            t.peer_set(&Actor::Local, p, USE, "", T0, T0).unwrap();
        }
        let rgen = t.generation();
        let g0 = rgen.load(Ordering::SeqCst);
        assert!(!t.mesh_forward(&key_of(&a), &key_of(&a), &key_of(&b)), "transit_enabled выключен");
        t.set_config(&Actor::Local, Some(true), None).unwrap();
        assert!(t.mesh_forward(&key_of(&a), &key_of(&a), &key_of(&b)));
        assert!(!t.mesh_forward(&key_of(&a), &key_of(&a), &key_of(&c)), "неизвестный dst");
        assert!(!t.mesh_forward(&key_of(&c), &key_of(&a), &key_of(&b)), "неизвестный prev");
        t.peer_remove(&Actor::Local, &hh(&b), T0 + 1, T0 + 1).unwrap();
        assert!(rgen.load(Ordering::SeqCst) > g0);
        assert!(!t.mesh_forward(&key_of(&a), &key_of(&a), &key_of(&b)), "отозванный dst");
        assert!(t.relay_allows(&key_of(&a)) && !t.relay_allows(&key_of(&b)));
    }

    #[test]
    fn key_for_id8_ignores_tombstones_and_ambiguity() {
        let (mut t, _) = table();
        let (_, a) = ident();
        t.peer_set(&Actor::Local, a, USE, "", T0, T0).unwrap();
        let k = key_of(&a);
        assert_eq!(t.key_for_id8(&k[..8].try_into().unwrap()), Some(k));
        assert_eq!(t.pk_for_key(&k), Some(a));
        t.peer_remove(&Actor::Local, &hh(&a), T0 + 1, T0 + 1).unwrap();
        assert_eq!(t.key_for_id8(&k[..8].try_into().unwrap()), None);
    }

    #[test]
    fn key_for_id8_resolves_self_without_granting_rights() {
        let (t, me) = table();
        let key = key_of(&me);
        let id = key[..8].try_into().unwrap();
        assert_eq!(t.local_key_for_id8(&id), Some(key));
        assert_eq!(t.key_for_id8(&id), None, "свой ключ не становится допустимым источником");
        assert!(!t.key_holds_any(&key), "распознавание себя не выдаёт права");
        assert!(!t.mesh_forward(&key, &key, &key));
    }

    #[test]
    fn key_for_id8_rejects_live_collision_with_self_but_ignores_revoked() {
        let (mut t, me) = table();
        let key = key_of(&me);
        let id: [u8; 8] = key[..8].try_into().unwrap();
        let (_, mut other) = ident();
        // Синтетическая коллизия: только проверка разрешения префикса, не пригодный ключ для связи.
        other[32..40].copy_from_slice(&id);
        other[63] = key[31] ^ 1;
        t.peers.insert([7; 16], Peer { pk: other, rights: USE, by: "local".into(), seq: 1, at: 1, name: String::new() });
        assert_eq!(t.local_key_for_id8(&id), None, "живую коллизию нельзя разрешать в свой ключ");
        t.peers.get_mut(&[7; 16]).unwrap().rights = 0;
        assert_eq!(t.local_key_for_id8(&id), Some(key), "отозванный ключ не участвует в разрешении");
    }

    #[test]
    fn local_mesh_id_rejects_collision_with_known_contact() {
        let (mut t, me) = table();
        let key = key_of(&me);
        let id: [u8; 8] = key[..8].try_into().unwrap();
        let (_, mut other) = ident();
        other[32..40].copy_from_slice(&id);
        other[63] = key[31] ^ 1;
        // Синтетический префикс может не кодировать валидную точку Ed25519;
        // проверяем именно коллизию кэша, как соседний тест с `peers`.
        t.contacts.insert([7; 16], Contact { pk: other, name: String::new(), hints: vec![], intro_by: "local".into(), they_grant: USE, roles: EXIT, at: T0, rl: serde_json::Value::Null, client: false });
        assert_eq!(t.local_key_for_id8(&id), None);
        assert_eq!(t.client_mesh_source_for_id8(&id), None);
    }

    #[test]
    fn client_mesh_source_requires_trusted_contact_and_respects_revocation() {
        let (mut t, me) = table();
        let (_, remote) = ident();
        let key = key_of(&remote);
        let id = key[..8].try_into().unwrap();
        let hash = hh(&remote);
        t.accepted(remote, "", vec![], USE, EXIT, T0).unwrap();
        assert_eq!(t.key_for_id8(&id), None, "контакт не получает права транзита");
        assert_eq!(t.client_mesh_source_for_id8(&id), Some(key));
        assert!(t.mesh_knows_key(&key));
        let g = t.generation();
        let before = g.load(Ordering::SeqCst);
        assert!(t.set_contact_grant(&hash, 0));
        assert!(g.load(Ordering::SeqCst) > before, "отзыв подсказки инвалидирует кэш");
        assert_eq!(t.client_mesh_source_for_id8(&id), None);
        assert!(t.set_contact_grant(&hash, USE));
        t.peer_set(&Actor::Local, remote, USE, "", T0, T0).unwrap();
        t.peer_remove(&Actor::Local, &hash, T0 + 1, T0 + 1).unwrap();
        assert_eq!(t.client_mesh_source_for_id8(&id), None, "контакт не обходит локальный отзыв");
        assert!(!t.mesh_knows_key(&key), "контакт не обходит отзыв соседа");
        let own_id = key_of(&me)[..8].try_into().unwrap();
        assert_eq!(t.client_mesh_source_for_id8(&own_id), None, "свой id — не удалённый источник");
        let (_, untrusted) = ident();
        t.contact_set(untrusted, "", vec![], "untrusted", USE, EXIT, T0).unwrap();
        let untrusted_id = key_of(&untrusted)[..8].try_into().unwrap();
        assert_eq!(t.client_mesh_source_for_id8(&untrusted_id), None);
    }

    #[test]
    fn contact_removal_keeps_what_i_granted_and_adopt_makes_issuer_controller() {
        let (mut t, _) = table();
        let (_, h) = ident();
        t.accepted(h, "srv", vec![], USE, EXIT, T0).unwrap();
        assert_eq!(t.rights(&hh(&h)), 0, "accepted сам управления не даёт");
        t.adopt_controller(h, "srv", T0).unwrap();
        assert_eq!(t.rights(&hh(&h)), PRESET_ADMIN, "выдавший управляет принявшим");
        assert_eq!(t.contact(&hh(&h)).unwrap().they_grant, USE);
        assert_eq!(t.contact(&hh(&h)).unwrap().roles, EXIT);
        assert!(t.contact_remove(&hh(&h)));
        assert_eq!(t.rights(&hh(&h)), PRESET_ADMIN, "peers не меняется при удалении контакта");
    }

    #[test]
    fn proof_helper_matches_wire_formula() {
        // HMAC-SHA256(key, "redeem" ‖ h ‖ pk_n ‖ n_nonce ‖ name) считается на обеих сторонах одним кодом (invite.rs); тут только ключ
        let pin = [3u8; 16];
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&pin_key(&pin)).unwrap();
        m.update(b"x");
        assert_ne!(pin_id(&pin).as_slice(), &pin_key(&pin)[..8], "pid и key — разные производные");
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kh-peers-{tag}-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
