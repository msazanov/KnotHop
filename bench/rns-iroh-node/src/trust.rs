//! Модель доверия 0013 (docs/decisions/0013-peer-groups-and-rights.md): индивидуальные права на identity, якоря доверия,
//! подписанные записи с цепочкой до якоря, приглашения `kh-` с одноразовым pin.
//!
//! Модуль не знает про сеть: только данные, проверки и файлы состояния. Всё, что пришло от пира, здесь недоверенный ввод:
//! запись принимается лишь с верной подписью издателя, чей ключ уже известен, и под корнем, который нода сама признаёт якорем;
//! права же вычисляются при запросе по цепочке до корня, поэтому отзыв звена сразу обесценивает выданное им.

use super::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub const USE: u16 = 1;
pub const TRANSIT: u16 = 2;
pub const EXIT: u16 = 4;
pub const ADD: u16 = 8;
pub const REMOVE: u16 = 16;
pub const CONFIG: u16 = 32;
pub const HOST_ACCESS: u16 = 64;
pub const KNOWN: u16 = 127;
pub const ALL: u16 = 63;

/// Готовые наборы. Пользователь = USE, реле = USE+TRANSIT+EXIT+ADD, админ = всё.
pub const PRESET_USER: u16 = USE;
pub const PRESET_RELAY: u16 = USE | TRANSIT | EXIT | ADD;
pub const PRESET_ADMIN: u16 = ALL;

pub type Pk = [u8; 64];
pub type Hash = [u8; 16];

/// Глубина цепочки до корня и бюджет шагов одной проверки (при превышении права считаются нулевыми: отказ по умолчанию).
pub const MAX_DEPTH: usize = 8;
const STEP_BUDGET: u32 = 20_000;
/// Инвариант 6: всё ограничено.
pub const MAX_RECS_PER_ROOT: usize = 512;
const MAX_ENROLL_RECS: usize = 512;
/// Не больше записей одного издателя в корне (кроме самого корня): одиночный участник не забивает хранилище (H1).
pub const MAX_RECS_PER_ISSUER: usize = 64;
pub const MAX_ROOTS: usize = 8;
/// seq - время в мс; запись из далёкого будущего не принимаем (иначе издатель мог бы заранее занять свой слот).
const SEQ_FUTURE_MS: u64 = 10 * 60 * 1000;

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

/// `user`, `relay`, `admin`, число или список через `+`/`,` (`USE+EXIT`).
pub fn parse_rights(s: &str) -> Result<u16> {
    let t = s.trim().to_lowercase();
    match t.as_str() {
        "user" => return Ok(PRESET_USER),
        "relay" => return Ok(PRESET_RELAY),
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
            _ => bail!("неизвестное право {p:?} (user, relay, admin, USE, TRANSIT, EXIT, ADD, REMOVE, CONFIG)"),
        };
    }
    Ok(r)
}

pub fn hash_of(pk: &Pk) -> Option<Hash> {
    Identity::from_public_key_bytes(pk).ok().map(|i| *i.hash())
}

/// Короткий тег корня для анонса и поиска соседей (не секрет, 6 байт): по нему нода понимает, что анонс из знакомой ей сети.
pub fn root_tag(root: &Hash) -> String {
    let d = Sha256::digest([b"knothop-root-tag-v1".as_slice(), root].concat());
    hex(&d[..6])
}


/// Создать новый файл только для владельца (0600) и только если его ещё нет: O_EXCL не проходит по symlink.
fn create_private(p: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p)
}

/// Записать новый файл целиком и сбросить на диск; при ошибке записи уже созданный файл убираем.
fn write_new(p: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = create_private(p)?;
    let r = f.write_all(data).and_then(|_| f.sync_all());
    if r.is_err() {
        drop(f);
        let _ = std::fs::remove_file(p);
    }
    r
}

fn sync_dir(d: &Path) {
    if let Ok(f) = std::fs::File::open(d) {
        let _ = f.sync_all();
    }
}

/// Атомарная замена: уникальный temp рядом (pid + счётчик, create_new), 0600, fsync файла до rename.
fn write_atomic(p: &Path, data: &[u8]) -> Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("state");
    let tmp = p.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
    let res = (|| -> Result<()> {
        write_new(&tmp, data).context("атомарная запись файла состояния")?;
        std::fs::rename(&tmp, p).context("атомарная замена файла состояния")?;
        if let Some(d) = p.parent() {
            sync_dir(d);
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

// ------------------------------------------------------------------------------------------------ запись о правах

const REC_MSG: &[u8] = b"knothop-rec-v1";
const PAYLOAD_LEN: usize = 1 + 2 + 8 + 16 + 64 + 16;
pub const REC_LEN: usize = PAYLOAD_LEN + 64;

/// Подписанное утверждение «`issuer` даёт `holder` права `rights` в сети с корнем `root`».
/// payload: v(1)=1 | rights(2 LE) | seq(8 LE) | root(16) | holder(64) | issuer(16); подпись ed25519 над `knothop-rec-v1 || payload`.
/// Корень внутри подписи: запись нельзя перенести в другое дерево, где тот же издатель тоже админ.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub rights: u16,
    pub seq: u64,
    pub root: Hash,
    pub holder: Pk,
    pub issuer: Hash,
    pub sig: [u8; 64],
    /// хеш identity держателя (вычисляется при разборе/подписи)
    pub hh: Hash,
}

const HOST_REC_MSG: &[u8] = b"knothop-host-access-v1";
const HOST_REC_PAYLOAD_LEN: usize = 1 + 16 + 16 + 2 + 8 + 64 + 16;
pub const HOST_REC_LEN: usize = HOST_REC_PAYLOAD_LEN + 64;

/// Node-scoped HOST_ACCESS assertion. Unlike Record v1, scope is signed and may never be
/// interpreted as a root-wide grant. Rights are exactly HOST_ACCESS or zero (revoke).
#[derive(Clone, Debug, PartialEq)]
pub struct HostAccessRecord {
    pub root: Hash,
    pub scope: Hash,
    pub rights: u16,
    pub seq: u64,
    pub holder: Pk,
    pub issuer: Hash,
    pub sig: [u8; 64],
    pub hh: Hash,
}

impl HostAccessRecord {
    fn payload(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HOST_REC_PAYLOAD_LEN);
        b.push(1);
        b.extend_from_slice(&self.root);
        b.extend_from_slice(&self.scope);
        b.extend_from_slice(&self.rights.to_le_bytes());
        b.extend_from_slice(&self.seq.to_le_bytes());
        b.extend_from_slice(&self.holder);
        b.extend_from_slice(&self.issuer);
        b
    }
    pub fn wire(&self) -> Vec<u8> { let mut b = self.payload(); b.extend_from_slice(&self.sig); b }
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() != HOST_REC_LEN || b[0] != 1 { return None; }
        let rights = u16::from_le_bytes(b[33..35].try_into().ok()?);
        if rights != 0 && rights != HOST_ACCESS { return None; }
        let holder: Pk = b[43..107].try_into().ok()?;
        Some(Self { root: b[1..17].try_into().ok()?, scope: b[17..33].try_into().ok()?, rights,
            seq: u64::from_le_bytes(b[35..43].try_into().ok()?), hh: hash_of(&holder)?, holder,
            issuer: b[107..123].try_into().ok()?, sig: b[123..187].try_into().ok()? })
    }
    fn sig_ok(&self, issuer: &Pk) -> bool {
        let mut msg = HOST_REC_MSG.to_vec(); msg.extend_from_slice(&self.payload());
        Identity::from_public_key_bytes(issuer).ok().and_then(|i| i.verify(&msg, &self.sig).ok()).unwrap_or(false)
    }
}

impl Record {
    fn payload(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(PAYLOAD_LEN);
        b.push(1);
        b.extend_from_slice(&self.rights.to_le_bytes());
        b.extend_from_slice(&self.seq.to_le_bytes());
        b.extend_from_slice(&self.root);
        b.extend_from_slice(&self.holder);
        b.extend_from_slice(&self.issuer);
        b
    }

    pub fn wire(&self) -> Vec<u8> {
        let mut b = self.payload();
        b.extend_from_slice(&self.sig);
        b
    }

    /// Разбор без проверки подписи (она нужна ключа издателя; см. `Trust::offer`).
    pub fn parse(b: &[u8]) -> Option<Record> {
        if b.len() != REC_LEN || b[0] != 1 {
            return None;
        }
        let rights = u16::from_le_bytes(b[1..3].try_into().ok()?);
        // Record v1 has no scope field, so HOST_ACCESS may only travel in
        // HostAccessRecord. Unknown bits and unscoped bit 64 reject the whole record.
        if rights & !ALL != 0 {
            return None;
        }
        let holder: Pk = b[27..91].try_into().ok()?;
        Some(Record {
            rights,
            seq: u64::from_le_bytes(b[3..11].try_into().ok()?),
            root: b[11..27].try_into().ok()?,
            hh: hash_of(&holder)?,
            holder,
            issuer: b[91..107].try_into().ok()?,
            sig: b[107..171].try_into().ok()?,
        })
    }

    pub fn sign(issuer: &Identity, root: Hash, holder: Pk, rights: u16, seq: u64) -> Result<Record> {
        if rights & !ALL != 0 { bail!("Record v1: unknown or unscoped rights; HOST_ACCESS requires scoped record"); }
        let hh = hash_of(&holder).ok_or_else(|| anyhow::anyhow!("ключ держателя не разобран"))?;
        let mut r = Record { rights, seq, root, holder, issuer: *issuer.hash(), sig: [0u8; 64], hh };
        let mut m = REC_MSG.to_vec();
        m.extend_from_slice(&r.payload());
        r.sig = issuer.sign(&m).map_err(|e| anyhow::anyhow!("подпись записи: {e:?}"))?;
        Ok(r)
    }

    fn sig_ok(&self, issuer_pk: &Pk) -> bool {
        let mut m = REC_MSG.to_vec();
        m.extend_from_slice(&self.payload());
        Identity::from_public_key_bytes(issuer_pk).ok().and_then(|i| i.verify(&m, &self.sig).ok()).unwrap_or(false)
    }
}

#[derive(Debug, PartialEq)]
pub enum Offer {
    Added,
    /// уже есть такая или более свежая запись того же издателя для того же держателя
    Stale,
    Rejected(&'static str),
}

// ------------------------------------------------------------------------------------------------ политика ноды (0015)

const POL_MSG: &[u8] = b"knothop-pol-v1";
const POL_PAYLOAD_LEN: usize = 1 + 2 + 8 + 8 + 16 + 64;
pub const POL_LEN: usize = POL_PAYLOAD_LEN + 64;
/// Срок жизни политики (решение владельца 0015: 48 ч). Дольше срок не принимается.
pub const POLICY_TTL_MS: u64 = 48 * 3600 * 1000;
/// Источник переподписывает политику, когда ей больше этого возраста (0015: запас на два пропущенных обновления).
pub const POLICY_REFRESH_MS: u64 = 12 * 3600 * 1000;
/// Права, при наличии любого из которых нода видна другим (0015, п.4: остальные скрыты).
#[cfg(test)]
const VISIBLE_BITS: u16 = USE | TRANSIT | EXIT;

/// Подписанное самой нодой «что я согласна делать» в сети с корнем `root`. Только сужает выдачу: действующие права = выдача ∩ offer.
/// payload: v(1)=1 | offer(2 LE) | seq(8 LE) | valid_until(8 LE, мс) | root(16) | holder(64); подпись держателя над `knothop-pol-v1 || payload`.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub offer: u16,
    pub seq: u64,
    pub valid_until: u64,
    pub root: Hash,
    pub holder: Pk,
    pub sig: [u8; 64],
    pub hh: Hash,
}

impl Policy {
    fn payload(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(POL_PAYLOAD_LEN);
        b.push(1);
        b.extend_from_slice(&self.offer.to_le_bytes());
        b.extend_from_slice(&self.seq.to_le_bytes());
        b.extend_from_slice(&self.valid_until.to_le_bytes());
        b.extend_from_slice(&self.root);
        b.extend_from_slice(&self.holder);
        b
    }

    pub fn wire(&self) -> Vec<u8> {
        let mut b = self.payload();
        b.extend_from_slice(&self.sig);
        b
    }

    /// Разбор без проверки подписи (см. `Policy::sig_ok`).
    pub fn parse(b: &[u8]) -> Option<Policy> {
        if b.len() != POL_LEN || b[0] != 1 {
            return None;
        }
        let offer = u16::from_le_bytes(b[1..3].try_into().ok()?);
        if offer & !KNOWN != 0 {
            return None;
        }
        let holder: Pk = b[35..99].try_into().ok()?;
        Some(Policy {
            offer,
            seq: u64::from_le_bytes(b[3..11].try_into().ok()?),
            valid_until: u64::from_le_bytes(b[11..19].try_into().ok()?),
            root: b[19..35].try_into().ok()?,
            hh: hash_of(&holder)?,
            holder,
            sig: b[99..163].try_into().ok()?,
        })
    }

    pub fn sign(holder: &Identity, root: Hash, offer: u16, seq: u64, valid_until: u64) -> Result<Policy> {
        if offer & !KNOWN != 0 {
            bail!("политика: лишние биты");
        }
        let pk = holder.public_key_bytes();
        let hh = hash_of(&pk).ok_or_else(|| anyhow::anyhow!("ключ держателя не разобран"))?;
        let mut p = Policy { offer, seq, valid_until, root, holder: pk, sig: [0u8; 64], hh };
        let mut m = POL_MSG.to_vec();
        m.extend_from_slice(&p.payload());
        p.sig = holder.sign(&m).map_err(|e| anyhow::anyhow!("подпись политики: {e:?}"))?;
        Ok(p)
    }

    /// Подпись проверяется ключом самого держателя, он лежит в записи.
    pub fn sig_ok(&self) -> bool {
        let mut m = POL_MSG.to_vec();
        m.extend_from_slice(&self.payload());
        Identity::from_public_key_bytes(&self.holder).ok().and_then(|i| i.verify(&m, &self.sig).ok()).unwrap_or(false)
    }
}

// ------------------------------------------------------------------------------------------------ хранилище

/// Состояние доверия ноды: чьим подписям она подчиняется (якоря) и все принятые записи.
pub struct Trust {
    path: Option<PathBuf>,
    me: Identity,
    pub me_pk: Pk,
    pub me_hash: Hash,
    /// корень -> его ключ. Собственный всегда есть: нода без приглашения сама себе админ и никому больше.
    anchors: BTreeMap<Hash, Pk>,
    /// (корень, хеш держателя, хеш издателя) -> последняя запись
    recs: HashMap<(Hash, Hash, Hash), Record>,
    /// ADR 0019: (root, holder, issuing node). Never a delegation source for Record v1.
    enroll_recs: BTreeMap<(Hash, Hash, Hash), crate::enroll::Proof>,
    /// (корень, хеш) -> полный ключ: из записей, чтобы проверять подписи издателей
    holders: HashMap<(Hash, Hash), Pk>,
    /// (корень, хеш держателя) -> последняя политика (0015). Число ограничено числом известных держателей, то есть записями корня.
    /// Просроченные остаются: они сужают права до USE, а не возвращают выдачу целиком.
    pols: HashMap<(Hash, Hash), Policy>,
    /// что эта нода сама согласна делать в каждом корне (её собственная настройка; из неё подписывается и обновляется политика)
    my_offer: BTreeMap<Hash, u16>,
    /// Explicitly scoped host grants; stored separately from legacy Record v1.
    host_recs: BTreeMap<(Hash, Hash, Hash), HostAccessRecord>,
    /// Локальная политика оператора: какие принятые корни вообще могут давать HOST_ACCESS на этой ноде
    /// (корень -> потолок числа держателей). Собственный корень разрешён всегда; принятие якоря само по себе
    /// доступа к хосту не даёт. Меняется только файлом `host-policy.json` и перезапуском.
    host_policy: BTreeMap<Hash, usize>,
    /// Растёт при каждом изменении `host_recs`; сверяется ДО записи заранее подготовленного снимка на диск.
    /// Файл host-access.json пишет только commit host-записей, общий `save()` его не трогает.
    host_version: u64,
    /// Сериализует проверку версии, запись на диск и применение host-коммита в памяти.
    host_commit: Arc<Mutex<()>>,
    /// Сериализует все trust.json writers (обычный save и prerequisite flush перед host commit).
    /// HostCommit никогда не держит этот gate при повторном захвате Trust.
    io_gate: Arc<Mutex<()>>,
    /// Версия durable trust.json, увеличивается под io_gate на каждой попытке записи.
    /// HostCommit не перезаписывает snapshot, если с момента его съёма другой writer успел пройти.
    disk_generation: Arc<AtomicU64>,
}

/// Верхняя граница размера файлов host-access.json / host-policy.json: читаем не больше, чем разрешено, до выделения памяти.
pub const MAX_HOST_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Всего host-записей (включая отзывы) в хранилище и в файле.
pub const MAX_HOST_RECS_TOTAL: usize = MAX_RECS_PER_ROOT * MAX_ROOTS;
/// Запас под отзывы: новые выдачи упираются в потолок раньше, чем отзывы.
pub const HOST_REVOKE_RESERVE_TOTAL: usize = 512;
pub const HOST_REVOKE_RESERVE_PER_ROOT: usize = 64;
/// Разных издателей на одного держателя в корне, записей одного издателя, держателей по умолчанию на корень политики.
pub const MAX_HOST_ISSUERS_PER_HOLDER: usize = 8;
pub const MAX_HOST_RECS_PER_ISSUER: usize = 256;
pub const DEFAULT_HOST_HOLDERS_PER_ROOT: usize = 64;

/// Заранее проверенная и сериализованная host-запись: пишется на диск вне блокировки `Trust`.
pub struct HostCommit {
    key: (Hash, Hash, Hash),
    rec: HostAccessRecord,
    base_version: u64,
    /// None - хранилище без файла (тесты): запись в память без диска.
    path: Option<PathBuf>,
    bytes: Vec<u8>,
    gate: Arc<Mutex<()>>,
}

impl HostCommit {
    /// Проверить снимок ДО записи под общей блокировкой коммитов. Единственный production-путь
    /// записи host-access.json: после успешной записи нет отказа Stale и расхождения памяти с диском.
    /// Порядок блокировок: gate -> Trust; fsync выполняется без блокировки Trust.
    pub fn commit(self, store: &Mutex<Trust>) -> std::result::Result<(), HostCommitError> {
        self.commit_with_writer(store, Self::write)
    }

    fn commit_with_writer(
        self,
        store: &Mutex<Trust>,
        write: impl FnOnce(&Self) -> Result<()>,
    ) -> std::result::Result<(), HostCommitError> {
        let gate = self.gate.clone();
        let _guard = gate.lock().unwrap_or_else(|e| e.into_inner());
        let (ordinary_path, ordinary_bytes, snapshot_generation, io_gate, disk_generation) = {
            let trust = store.lock().unwrap();
            if !Arc::ptr_eq(&gate, &trust.host_commit) {
                return Err(HostCommitError::Rejected("wrong_host_store"));
            }
            if self.base_version != trust.host_version { return Err(HostCommitError::Stale); }
            // Обычная цепочка прав могла измениться после prepare (не меняя host_version).
            trust.prepare_host_access(&self.rec)?;
            let bytes = trust.serialize_ordinary().map_err(|_| HostCommitError::Io)?;
            (trust.path.clone(), bytes, trust.disk_generation.load(Ordering::Acquire),
                trust.io_gate.clone(), trust.disk_generation.clone())
        };
        {
            let _io = io_gate.lock().unwrap_or_else(|e| e.into_inner());
            // An ordinary save may have won the gate after our Trust snapshot.
            // Never overwrite that newer state with the now-stale snapshot.
            if disk_generation.load(Ordering::Acquire) != snapshot_generation {
                return Err(HostCommitError::Stale);
            }
            disk_generation.fetch_add(1, Ordering::AcqRel);
            if let Some(path) = ordinary_path {
                write_atomic(&path, &ordinary_bytes).map_err(|_| HostCommitError::Io)?;
            }
            // Persist issuer keys/chain before a host record that depends on them.
            // Any failure here leaves host-access.json and in-memory host state unchanged.
            write(&self).map_err(|_| HostCommitError::Io)?;
        }
        // Lock order is deliberate: no Trust reacquisition while io_gate is held.
        store.lock().unwrap().finish_host_access(self);
        Ok(())
    }

    /// Атомарная запись с fsync. Приватна: version check/gate нельзя обойти из executor.
    fn write(&self) -> Result<()> {
        match &self.path {
            Some(p) => write_atomic(p, &self.bytes),
            None => Ok(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HostCommitError {
    /// Запись отвергнута по существу (подпись, полномочия, лимиты, политика): детерминированный отказ.
    Rejected(&'static str),
    /// Старая запись (seq не новее имеющейся).
    Stale,
    /// Запись на диск не удалась: состояние не менялось, повтор возможен.
    Io,
}

fn read_host_file(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > MAX_HOST_FILE_BYTES {
        return Err(std::io::Error::other("file exceeds size limit"));
    }
    let mut b = Vec::with_capacity(len as usize);
    f.take(MAX_HOST_FILE_BYTES + 1).read_to_end(&mut b)?;
    if b.len() as u64 > MAX_HOST_FILE_BYTES {
        return Err(std::io::Error::other("file exceeds size limit"));
    }
    Ok(b)
}

impl Trust {
    pub fn new(me: Identity, path: Option<PathBuf>) -> Trust {
        let me_pk = me.public_key_bytes();
        let me_hash = *me.hash();
        let mut anchors = BTreeMap::new();
        anchors.insert(me_hash, me_pk);
        Trust { path, me, me_pk, me_hash, anchors, recs: HashMap::new(), enroll_recs: BTreeMap::new(), holders: HashMap::new(), pols: HashMap::new(), my_offer: BTreeMap::new(), host_recs: BTreeMap::new(),
            host_policy: BTreeMap::new(), host_version: 0, host_commit: Arc::new(Mutex::new(())), io_gate: Arc::new(Mutex::new(())),
            disk_generation: Arc::new(AtomicU64::new(0)) }
    }

    /// Разрешить принятому корню давать HOST_ACCESS на этой ноде (после явного решения оператора).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn allow_host_root(&mut self, root: Hash, max_holders: usize) {
        self.host_policy.insert(root, max_holders.clamp(1, MAX_RECS_PER_ROOT));
    }

    /// Корень вправе давать HOST_ACCESS на этой ноде: собственный всегда, чужой принятый - только по локальной политике.
    pub fn host_root_allowed(&self, root: &Hash) -> bool {
        self.anchors.contains_key(root) && (*root == self.me_hash || self.host_policy.contains_key(root))
    }

    fn host_policy_cap(&self, root: &Hash) -> usize {
        if *root == self.me_hash { MAX_RECS_PER_ROOT } else { self.host_policy.get(root).copied().unwrap_or(0) }
    }

    /// `host-policy.json`: {"v":1,"roots":[{"root":"<hex16>","max_holders":N}]}. Ошибка разбора - отказ загрузки (fail-closed).
    fn load_host_policy(&mut self, dir: &Path) -> Result<()> {
        let bytes = match read_host_file(&dir.join("host-policy.json")) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => bail!("host-policy.json: read failed: {e}"),
        };
        let v: serde_json::Value = serde_json::from_slice(&bytes).context("host-policy.json: parse")?;
        if v["v"].as_u64() != Some(1) { bail!("host-policy.json: unsupported version"); }
        let roots = v["roots"].as_array().ok_or_else(|| anyhow::anyhow!("host-policy.json: roots missing"))?;
        if roots.len() > MAX_ROOTS { bail!("host-policy.json: too many roots"); }
        for item in roots {
            let root: Hash = unhex(item["root"].as_str().unwrap_or("")).try_into().map_err(|_| anyhow::anyhow!("host-policy.json: bad root"))?;
            let max = item["max_holders"].as_u64().map(|n| n as usize).unwrap_or(DEFAULT_HOST_HOLDERS_PER_ROOT);
            if max == 0 || max > MAX_RECS_PER_ROOT { bail!("host-policy.json: max_holders out of range"); }
            self.host_policy.insert(root, max);
        }
        Ok(())
    }

    /// Загрузить из `trust.json` в каталоге состояния (если он есть).
    /// Загрузка fail-closed (S4): отсутствие файла - пустое состояние; любая ошибка чтения, разбора или проверки записи - отказ,
    /// без молчаливого пропуска. Повреждённый отзыв не должен вернуть права, поэтому частичная загрузка не допускается.
    pub fn load(me: Identity, state: &Path) -> Result<Trust> {
        let path = state.join("trust.json");
        let mut t = Trust::new(me, Some(path.clone()));
        let b = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => br#"{"v":1,"anchors":[],"recs":[],"pols":[],"mypol":{}}"#.to_vec(),
            Err(e) => bail!("trust.json: чтение не удалось: {e}"),
        };
        let v: serde_json::Value = serde_json::from_slice(&b).context("trust.json: разбор")?;
        if v["v"].as_u64() != Some(1) {
            bail!("trust.json: версия формата не поддерживается");
        }
        for a in v["anchors"].as_array().cloned().unwrap_or_default() {
            let pk: Pk = unhex(a.as_str().unwrap_or("")).try_into().map_err(|_| anyhow::anyhow!("trust.json: якорь"))?;
            t.add_anchor(&pk)?;
        }
        let mut pending: Vec<Record> = Vec::new();
        let mut broken = 0usize;
        for x in v["recs"].as_array().cloned().unwrap_or_default() {
            match Record::parse(&unhex(x.as_str().unwrap_or(""))) {
                Some(r) => pending.push(r),
                None => broken += 1,
            }
        }
        if broken > 0 {
            bail!("trust.json: {broken} записей не разобраны (файл повреждён, не загружен)");
        }
        // издатель должен быть известен до записи, которую он подписал: прогоняем, пока что-то принимается.
        // Срок seq здесь не проверяем: запись уже была принята раньше, а часы могли откатиться.
        loop {
            let before = pending.len();
            let mut next = Vec::new();
            for r in pending {
                match t.offer_checked(r.clone(), false) {
                    Offer::Added => {}
                    Offer::Rejected("неизвестный издатель") => next.push(r),
                    other => bail!("trust.json: запись не прошла проверку ({other:?}); файл повреждён или подменён"),
                }
            }
            pending = next;
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        if !pending.is_empty() {
            bail!("trust.json: {} записей с неизвестным издателем (файл повреждён, не загружен)", pending.len());
        }
        // политики (0015) - подсказки, не полномочия: непроверяемые пропускаем, они вернутся при следующей сверке. Срок здесь не смотрим.
        for x in v["pols"].as_array().cloned().unwrap_or_default() {
            if let Some(pol) = Policy::parse(&unhex(x.as_str().unwrap_or(""))) {
                let _ = t.offer_policy_checked(pol, 0, false);
            }
        }
        if let Some(m) = v["mypol"].as_object() {
            for (k, o) in m {
                let (Ok(root), Some(offer)) = (<Result<Hash, _>>::from(unhex(k).try_into()), o.as_u64()) else { continue };
                if t.anchors.contains_key(&root) && offer <= KNOWN as u64 {
                    t.my_offer.insert(root, offer as u16);
                }
            }
        }
        t.prune_policies();
        if let Some(dir) = path.parent() {
            t.load_host_policy(dir)?;
            let hp = dir.join("host-access.json");
            match read_host_file(&hp) {
                Ok(bytes) => {
                    let hv: serde_json::Value = serde_json::from_slice(&bytes).context("host-access.json: parse")?;
                    if hv["v"].as_u64() != Some(1) { bail!("host-access.json: unsupported version"); }
                    let arr = hv["records"].as_array().ok_or_else(|| anyhow::anyhow!("host-access.json: records missing"))?;
                    if arr.len() > MAX_HOST_RECS_TOTAL { bail!("host-access.json: too many records"); }
                    for item in arr {
                        let wire = unhex(item.as_str().unwrap_or(""));
                        let rec = HostAccessRecord::parse(&wire).ok_or_else(|| anyhow::anyhow!("host-access.json: malformed record"))?;
                        if rec.scope != t.me_hash || !t.anchors.contains_key(&rec.root) { bail!("host-access.json: wrong scope or untrusted root"); }
                        let issuer_pk = t.pub_of(&rec.root, &rec.issuer).ok_or_else(|| anyhow::anyhow!("host-access.json: unknown issuer"))?;
                        if !rec.sig_ok(&issuer_pk) { bail!("host-access.json: bad signature"); }
                        // Загружаем подписанную историю, включая отзывы и записи уже отозванных
                        // издателей. Текущие полномочия проверяет host_access_roots при использовании,
                        // после загрузки ВСЕХ scoped-записей. Record v1 намеренно не несёт бит 64:
                        // право делегата задаётся отдельной записью корня на эту конкретную ноду.
                        // Проверка rights_in здесь и ломала перезапуск, и зависела от порядка файла.
                        let key = (rec.root, rec.hh, rec.issuer);
                        if t.host_recs.get(&key).is_some_and(|old| old.seq >= rec.seq) { bail!("host-access.json: stale/duplicate record"); }
                        // Лимиты те же, что при приёме (жёсткие, с учётом запаса под отзывы): превышение значит повреждённый файл.
                        // Отзывы не выкидываются ради лимита - файл с превышением не загружается целиком.
                        if let Err(why) = t.host_rec_limits(&rec, false) { bail!("host-access.json: {why}"); }
                        t.host_recs.insert(key, rec);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => bail!("host-access.json: read failed: {e}"),
            }
        }
        let ep = state.join("enroll-records.json");
        match std::fs::read(&ep) {
            Ok(bytes) => {
                if bytes.len() > 16*1024*1024 { bail!("enroll-records.json: too large"); }
                let wires: Vec<String> = serde_json::from_slice(&bytes).context("enroll-records.json")?;
                if wires.len() > 512 { bail!("enroll-records.json: quota"); }
                for wire in wires {
                    let proof = crate::enroll::Proof::parse(&crate::enroll::raw(&wire)?)?;
                    t.offer_enrollment_checked(proof, false).context("enroll-records.json: invalid evidence")?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(e).context("enroll-records.json"),
        }
        Ok(t)
    }

    fn serialize_ordinary(&self) -> Result<Vec<u8>> {
        let anchors: Vec<String> = self.anchors.iter().filter(|(h, _)| **h != self.me_hash).map(|(_, pk)| hex(pk)).collect();
        let recs: Vec<String> = self.export_all().iter().map(|r| hex(&r.wire())).collect();
        let mut pk: Vec<&Policy> = self.pols.values().collect();
        pk.sort_by_key(|p| (p.root, p.hh));
        let pols: Vec<String> = pk.iter().map(|p| hex(&p.wire())).collect();
        let mypol: serde_json::Map<String, serde_json::Value> = self.my_offer.iter().map(|(r, o)| (hex(r), serde_json::json!(o))).collect();
        Ok(serde_json::to_vec(&serde_json::json!({"v": 1, "anchors": anchors, "recs": recs, "pols": pols, "mypol": mypol}))?)
    }

    pub fn save(&self) -> Result<()> {
        let Some(p) = &self.path else { return Ok(()) };
        let bytes = self.serialize_ordinary()?;
        let _io = self.io_gate.lock().unwrap_or_else(|e| e.into_inner());
        self.disk_generation.fetch_add(1, Ordering::AcqRel);
        write_atomic(p, &bytes)?;
        let scoped: Vec<String> = self.enroll_recs.values().map(|p| crate::enroll::hex(&p.wire())).collect();
        write_atomic(&p.with_file_name("enroll-records.json"), &serde_json::to_vec(&scoped)?)?;
        // host-access.json пишет только commit host-записей (prepare/finish): так общий save() под блокировкой trust
        // не конкурирует с записью, идущей вне блокировки, и не перезаписывает файл более старым состоянием.
        Ok(())
    }

    pub fn anchors(&self) -> Vec<(Hash, Pk)> {
        self.anchors.iter().map(|(h, p)| (*h, *p)).collect()
    }

    pub fn has_anchor(&self, h: &Hash) -> bool {
        self.anchors.contains_key(h)
    }

    /// Public key for a holder known inside one accepted root. Never searches
    /// other roots or unions their authority.
    pub fn public_key_in(&self, root: &Hash, holder: &Hash) -> Option<Pk> {
        self.pub_of(root, holder)
    }

    /// Map an LXMF `lxmf.delivery` destination hash to a known identity public
    /// key. LXMF source hashes are destination hashes, not KnotHop identity
    /// hashes; candidate keys are limited to this trust store.
    pub fn identity_for_lxmf_source(&self, source: &Hash) -> Option<Pk> {
        let name = Destination::compute_name_hash("lxmf", &["delivery"]);
        let mut candidates = std::collections::HashSet::new();
        candidates.extend(self.anchors.values().copied());
        candidates.extend(self.holders.values().copied());
        candidates.extend(self.host_recs.values().map(|r| r.holder));
        candidates.into_iter().find(|pk| {
            hash_of(pk).is_some_and(|ih| *Destination::compute_destination_hash(&name, &ih).as_bytes() == *source)
        })
    }

    /// Добавить якорь (принять приглашение другого админа). Ложь - уже был.
    pub fn add_anchor(&mut self, pk: &Pk) -> Result<bool> {
        let h = hash_of(pk).ok_or_else(|| anyhow::anyhow!("ключ якоря не разобран"))?;
        if self.anchors.contains_key(&h) {
            return Ok(false);
        }
        if self.anchors.len() >= MAX_ROOTS {
            bail!("слишком много якорей (не больше {MAX_ROOTS})");
        }
        self.anchors.insert(h, *pk);
        Ok(true)
    }

    /// Теги корней, которые нода объявляет в анонсе (по ним соседи узнают «свою» сеть).
    #[cfg(test)]
    pub fn tags(&self) -> Vec<String> {
        self.anchors.keys().map(root_tag).collect()
    }

    pub fn record_count(&self) -> usize {
        self.recs.len() + self.enroll_recs.len()
    }

    pub fn enrollment_proofs(&self, holder: &Pk) -> Vec<crate::enroll::Proof> {
        self.enroll_recs.values().filter(|p| p.rec.holder == *holder).cloned().collect()
    }

    pub fn offer_enrollment(&mut self, p: crate::enroll::Proof) -> Result<bool> {
        self.offer_enrollment_checked(p, true)
    }

    fn offer_enrollment_checked(&mut self, p: crate::enroll::Proof, fresh: bool) -> Result<bool> {
        let hh = hash_of(&p.rec.holder).ok_or_else(||anyhow::anyhow!("enrollment holder"))?;
        let key = (p.grant.root, hh, p.rec.scope);
        if self.enroll_recs.get(&key) == Some(&p) { return Ok(false); }
        if !self.has_anchor(&p.grant.root) || self.pub_of(&p.grant.root, &p.grant.root) != Some(p.root) { bail!("enrollment root not anchored"); }
        p.authority(&self.me)?;
        if fresh && !p.grant.fresh(now_ms() as u64 / 1000) { bail!("enrollment first seen after expiry; no rights"); }
        for r in &p.chain { if r.root != p.grant.root { bail!("cross-root enrollment chain"); } }
        for _ in 0..=MAX_DEPTH { for r in &p.chain { self.offer(r.clone()); } }
        if fresh { p.verify(self)?; }
        if let Some(old) = self.enroll_recs.get(&key) {
            if old.rec.seq >= p.rec.seq { return Ok(false); }
        } else if !self.enrollment_room(&key.0) { bail!("enrollment record quota"); }
        self.holders.insert((p.grant.root, hh), p.rec.holder);
        self.holders.insert((p.grant.root, p.rec.scope), p.rec.node);
        self.enroll_recs.insert(key, p);
        Ok(true)
    }

    /// R-2 «Забыть профиль»: оставить только собственный корень. Чужие якоря, их записи, доказательства зачисления, политики,
    /// host-записи и потолки удаляются из памяти; `save()` перепишет `trust.json` и `enroll-records.json`, а `host-access.json`
    /// переписывается здесь без чужих записей. Записи собственного корня (админа этого устройства) не трогаются. Возвращает число
    /// забытых якорей. Вызывать только при остановленном узле: файл держит живой процесс.
    pub fn forget_foreign_roots(&mut self) -> Result<usize> {
        let me = self.me_hash;
        let before = self.anchors.len();
        self.anchors.retain(|h, _| *h == me);
        self.recs.retain(|(r, _, _), _| *r == me);
        self.enroll_recs.retain(|(r, _, _), _| *r == me);
        self.holders.retain(|(r, _), _| *r == me);
        self.pols.retain(|(r, _), _| *r == me);
        self.my_offer.retain(|r, _| *r == me);
        self.host_recs.retain(|(r, _, _), _| *r == me);
        self.host_policy.retain(|r, _| *r == me);
        self.host_version += 1;
        self.save()?;
        if let Some(dir) = self.path.as_ref().and_then(|p| p.parent()) {
            let hp = dir.join("host-access.json");
            if hp.exists() {
                let records: Vec<String> = self.host_recs.values().map(|r| hex(&r.wire())).collect();
                write_atomic(&hp, &serde_json::to_vec(&serde_json::json!({"v":1,"records":records}))?)?;
            }
        }
        Ok(before - self.anchors.len())
    }

    /// Тест: забить хранилище копиями одного доказательства под разными ключами (без проверок, ради скорости).
    #[cfg(test)]
    pub(crate) fn test_fill_enrollments(&mut self, p: &crate::enroll::Proof, n: usize) {
        for i in 0..n { let mut h = [0u8; 16]; h[..8].copy_from_slice(&(i as u64).to_le_bytes()); self.enroll_recs.insert((p.grant.root, h, p.rec.scope), p.clone()); }
    }

    /// Есть ли место под новое доказательство зачисления в корне `root` (общий предел 512 и предел корня). При нехватке вытесняет
    /// доказательства, которые сейчас ничего не дают (подписант выдачи потерял ADD/глубину или цепочка разорвана отзывом).
    /// Действующие записи и отзывы не трогает (AGENTS, правило 3). Вызывать ДО необратимого погашения приглашения (R-4).
    pub fn enrollment_room(&mut self, root: &Hash) -> bool {
        while self.enroll_recs.len() >= MAX_ENROLL_RECS || self.root_count(root) >= MAX_RECS_PER_ROOT {
            if !self.evict_dead_enrollment() { return false; }
        }
        true
    }

    fn evict_dead_enrollment(&mut self) -> bool {
        // Подпись grant проверяется один раз на (grant, подписант): у одного приглашения до 8 записей, у одного админа их много.
        let mut alive: HashMap<([u8; 64], Pk), bool> = HashMap::new();
        let dead = self.enroll_recs.iter()
            .filter(|(_, p)| !*alive.entry((p.grant.sig, p.admin)).or_insert_with(|| p.grant.verify(self, &p.admin).is_ok()))
            .min_by_key(|(_, p)| p.rec.seq).map(|(k, _)| *k);
        dead.is_some_and(|k| self.enroll_recs.remove(&k).is_some())
    }

    /// Rights of holder h AT endpoint scope. ALL alone remains the delegation source.
    pub fn rights_at(&self, root: &Hash, h: &Hash, scope: &Hash) -> u16 {
        let all = self.rights_in(root, h);
        let Some(p) = self.enroll_recs.get(&(*root,*h,*scope)) else { return all };
        let Ok(depth) = p.grant.verify(self, &p.admin) else { return all };
        let mut budget = STEP_BUDGET;
        if self.best(root,h,&mut Vec::new(),&mut budget).is_some_and(|(r,d)| r.rights==0 && d.saturating_add(1)<=depth) { return 0; }
        all | p.rec.rights
    }

    fn pub_of(&self, root: &Hash, h: &Hash) -> Option<Pk> {
        if h == root {
            return self.anchors.get(root).copied();
        }
        self.holders.get(&(*root, *h)).copied()
    }

    /// Принять чужую запись. Права при этом не проверяются (они вычисляются при запросе, чтобы порядок прихода не влиял на итог):
    /// проверяется только, что корень наш, что издатель известен и что подпись верна.
    pub fn offer(&mut self, rec: Record) -> Offer {
        self.offer_checked(rec, true)
    }

    fn offer_checked(&mut self, rec: Record, check_future: bool) -> Offer {
        if !self.anchors.contains_key(&rec.root) {
            return Offer::Rejected("чужой корень");
        }
        if rec.hh == rec.issuer {
            return Offer::Rejected("издатель выдаёт сам себе");
        }
        if check_future && rec.seq > now_ms() as u64 + SEQ_FUTURE_MS {
            return Offer::Rejected("seq из будущего");
        }
        let Some(ipk) = self.pub_of(&rec.root, &rec.issuer) else { return Offer::Rejected("неизвестный издатель") };
        let key = (rec.root, rec.hh, rec.issuer);
        let known = self.recs.get(&key).map(|o| o.seq);
        // квоту проверяем до подписи: сверх квоты недоверенный поток не должен требовать проверок Ed25519.
        // Права издателя здесь не смотрим (порядок прихода не должен менять итог), но его записи ограничены квотой.
        if known.is_none() && rec.issuer != rec.root && self.issuer_count(&rec.root, &rec.issuer) >= MAX_RECS_PER_ISSUER {
            return Offer::Rejected("квота издателя исчерпана");
        }
        if !rec.sig_ok(&ipk) {
            return Offer::Rejected("подпись");
        }
        match known {
            Some(seq) if seq >= rec.seq => return Offer::Stale,
            Some(_) => {}
            None => {
                if self.root_count(&rec.root) >= MAX_RECS_PER_ROOT && !self.evict_invalid(&rec.root) {
                    return Offer::Rejected("хранилище корня заполнено");
                }
            }
        }
        self.holders.insert((rec.root, rec.hh), rec.holder);
        self.recs.insert(key, rec);
        Offer::Added
    }

    fn root_count(&self, root: &Hash) -> usize {
        self.recs.keys().filter(|k| k.0 == *root).count() + self.enroll_recs.keys().filter(|k| k.0 == *root).count()
    }

    fn issuer_count(&self, root: &Hash, issuer: &Hash) -> usize {
        self.recs.keys().filter(|k| k.0 == *root && k.2 == *issuer).count()
    }

    /// Освободить место в корне (H1): вытеснить самую старую недействительную запись. Недействительна выдача, чей издатель сейчас
    /// не имеет ADD или выдаёт шире своих прав, и отзыв, чей издатель не имеет REMOVE (такой отзыв ничего не отзывает; иначе
    /// пользователь с USE забил бы корень «отзывами»). Выданное корнем и действительные отзывы не трогаем (AGENTS, правило 3).
    /// Возвращает false, если вытеснить нечего.
    fn evict_invalid(&mut self, root: &Hash) -> bool {
        let mut ir_of: HashMap<Hash, u16> = HashMap::new();
        let mut victim: Option<((Hash, Hash, Hash), u64)> = None;
        for (k, r) in self.recs.iter() {
            if k.0 != *root || r.issuer == *root {
                continue;
            }
            let ir = *ir_of.entry(r.issuer).or_insert_with(|| {
                let mut budget = STEP_BUDGET;
                self.eff(root, &r.issuer, &mut Vec::new(), &mut budget).map(|(x, _)| x).unwrap_or(0)
            });
            let valid = if r.rights == 0 { ir & REMOVE != 0 } else { ir & ADD != 0 && r.rights & !ir == 0 };
            if valid {
                continue;
            }
            if victim.map_or(true, |(_, s)| r.seq < s) {
                victim = Some((*k, r.seq));
            }
        }
        match victim {
            Some((k, _)) => {
                self.recs.remove(&k);
                true
            }
            None => false,
        }
    }

    // ----------------------------------------------------------------- вычисление прав

    /// Действующая запись для (корень, держатель): среди записей с верной цепочкой побеждает та, чей издатель ближе к корню;
    /// при равной глубине отзыв побеждает выдачу (H2: отзыв на том же уровне окончателен), затем более свежая, затем по байтам издателя.
    /// Подчинённый админ поэтому не перекрывает запись вышестоящего.
    fn best<'a>(&'a self, root: &Hash, h: &Hash, vis: &mut Vec<Hash>, budget: &mut u32) -> Option<(&'a Record, u8)> {
        let mut win: Option<(&Record, u8)> = None;
        for ((r, hh, _), rec) in self.recs.iter() {
            if r != root || hh != h {
                continue;
            }
            let Some((ir, depth)) = self.eff(root, &rec.issuer, vis, budget) else { continue };
            let need = if rec.rights == 0 { REMOVE } else { ADD };
            if ir & need == 0 || rec.rights & !ir != 0 {
                continue;
            }
            // ключ: глубина, затем отзыв (rights==0) раньше выдачи, затем свежесть, затем издатель
            let better = match &win {
                None => true,
                Some((w, wd)) => {
                    (depth, rec.rights != 0, std::cmp::Reverse(rec.seq), rec.issuer)
                        < (*wd, w.rights != 0, std::cmp::Reverse(w.seq), w.issuer)
                }
            };
            if better {
                win = Some((rec, depth));
            }
        }
        win.map(|(r, d)| (r, d))
    }

    /// Права `h` в корне `root` и глубина его цепочки (корень = 0). None - нет действующей записи.
    fn eff(&self, root: &Hash, h: &Hash, vis: &mut Vec<Hash>, budget: &mut u32) -> Option<(u16, u8)> {
        if h == root {
            return Some((KNOWN, 0));
        }
        if vis.len() >= MAX_DEPTH || vis.contains(h) || *budget == 0 {
            return None;
        }
        *budget -= 1;
        vis.push(*h);
        // издатель победившей записи уже вычислен внутри best: его глубина + 1
        let res = self.best(root, h, vis, budget).and_then(|(rec, _)| {
            let d = self.depth_of_issuer(root, &rec.issuer, vis, budget)?;
            Some((rec.rights, d + 1))
        });
        vis.pop();
        res
    }

    fn depth_of_issuer(&self, root: &Hash, issuer: &Hash, vis: &mut Vec<Hash>, budget: &mut u32) -> Option<u8> {
        self.eff(root, issuer, vis, budget).map(|(_, d)| d)
    }

    /// Права ключа в одном корне.
    pub fn rights_in(&self, root: &Hash, h: &Hash) -> u16 {
        if !self.anchors.contains_key(root) {
            return 0;
        }
        let mut budget = STEP_BUDGET;
        self.eff(root, h, &mut Vec::new(), &mut budget).map(|(r, _)| r).unwrap_or(0)
    }

    /// Глубина действующей цепочки (корень = 0); отсутствующая или чрезмерно глубокая цепь — None.
    pub fn depth_in(&self, root: &Hash, h: &Hash) -> Option<u8> {
        if !self.anchors.contains_key(root) { return None; }
        let mut budget = STEP_BUDGET;
        self.eff(root, h, &mut Vec::new(), &mut budget).map(|(_, d)| d)
    }

    /// Права ключа: объединение по всем якорям ноды.
    pub fn rights(&self, pk: &Pk) -> u16 {
        let Some(h) = hash_of(pk) else { return 0 };
        self.anchors.keys().fold(0, |a, root| a | self.rights_at(root, &h, &self.me_hash))
    }

    /// Есть ли корень, в котором у меня есть право `mine`, а у собеседника - `theirs`: так сосед-транзит (TRANSIT/TRANSIT)
    /// и выход для клиента (EXIT у сервера, USE у клиента) проверяются внутри одной сети, а не по объединению чужих.
    pub fn common(&self, peer: &Pk, mine: u16, theirs: u16) -> bool {
        let Some(h) = hash_of(peer) else { return false };
        self.anchors.keys().any(|root| self.rights_in(root, &self.me_hash) & mine != 0 && self.rights_in(root, &h) & theirs != 0)
    }

    /// Как `common`, но с политиками (0015): `my_eff`/`their_eff` - брать для меня/для собеседника действующие права (выдача ∩ политика) вместо выдачи.
    /// Исполняя отказ, нода берёт свою политику (`my_eff`), а чужую не требует: чужие права она проверяет по выдаче. Для выбора выхода и звонка
    /// берут обе, чтобы не стучаться в ноду, которая уже отказалась.
    pub fn common_with(&self, peer: &Pk, mine: u16, theirs: u16, my_eff: bool, their_eff: bool, now: u64) -> bool {
        let Some(h) = hash_of(peer) else { return false };
        self.anchors.keys().any(|root| {
            // A client presents USE scoped to the exit, NOT USE scoped to itself.
            let endpoint = if mine == USE && theirs == EXIT { h } else { self.me_hash };
            let m = if mine == USE { self.rights_at(root, &self.me_hash, &endpoint) } else { self.rights_in(root, &self.me_hash) };
            let t = self.rights_at(root, &h, &endpoint);
            let m = if my_eff { m & self.offer_in(root, &self.me_hash, now) } else { m };
            let t = if their_eff { t & self.offer_in(root, &h, now) } else { t };
            m & mine != 0 && t & theirs != 0
        })
    }

    /// Мои права в корне (для выдачи).
    pub fn my_rights_in(&self, root: &Hash) -> u16 {
        self.rights_in(root, &self.me_hash)
    }

    /// Sign a HOST_ACCESS grant/revoke scoped to one target node. No root-wide fallback exists.
    pub fn sign_host_access(&self, root: Hash, scope: Hash, holder: Pk, allowed: bool) -> Result<HostAccessRecord> {
        if !self.anchors.contains_key(&root) { bail!("корень не из принятых якорей"); }
        if scope == [0;16] { bail!("пустой scope запрещён"); }
        let hh = hash_of(&holder).ok_or_else(|| anyhow::anyhow!("ключ держателя не разобран"))?;
        if hh == self.me_hash { bail!("себе HOST_ACCESS не выдаётся"); }
        let mine = self.rights_in(&root, &self.me_hash);
        let need = if allowed { ADD } else { REMOVE };
        if mine & need == 0 {
            bail!("нужно {} в выбранном принятом корне", rights_text(need));
        }
        let key = (root, hh, self.me_hash);
        static HOST_SEQ: AtomicU64 = AtomicU64::new(0);
        let floor = self.host_recs.get(&key).map(|r| r.seq.saturating_add(1)).unwrap_or(0);
        let mut seq = (now_ms() as u64).max(floor);
        loop {
            let old = HOST_SEQ.load(Ordering::Relaxed);
            seq = seq.max(old.saturating_add(1));
            if HOST_SEQ.compare_exchange_weak(old, seq, Ordering::Relaxed, Ordering::Relaxed).is_ok() { break; }
        }
        let mut rec = HostAccessRecord { root, scope, rights: if allowed { HOST_ACCESS } else { 0 }, seq,
            holder, issuer: self.me_hash, sig: [0;64], hh };
        let mut msg = HOST_REC_MSG.to_vec(); msg.extend_from_slice(&rec.payload());
        rec.sig = self.me.sign(&msg).map_err(|e| anyhow::anyhow!("HOST_ACCESS signature: {e:?}"))?;
        Ok(rec)
    }

    /// Apply a received scoped record only on its exact target, after rechecking current chain authority.
    #[cfg(test)]
    pub fn accept_host_access(&mut self, rec: HostAccessRecord) -> Result<()> {
        // Только однопоточный тестовый путь. Не ждать gate под внешней блокировкой Trust.
        let gate = self.host_commit.clone();
        let _guard = gate.try_lock().map_err(|_| anyhow::anyhow!("HOST_ACCESS commit already in progress"))?;
        let commit = self.prepare_host_access(&rec).map_err(|e| anyhow::anyhow!("HOST_ACCESS record not accepted: {e:?}"))?;
        commit.write().map_err(|_| anyhow::anyhow!("HOST_ACCESS record not saved"))?;
        self.finish_host_access(commit);
        Ok(())
    }

    /// Разрешены ли новые ключи записи с учётом лимитов (замена существующего ключа не растёт и разрешена всегда).
    /// `reserve`: выдачи упираются в потолок раньше (запас под отзывы) и в потолок держателей политики корня.
    fn host_rec_limits(&self, rec: &HostAccessRecord, reserve: bool) -> std::result::Result<(), &'static str> {
        let key = (rec.root, rec.hh, rec.issuer);
        if self.host_recs.contains_key(&key) { return Ok(()); }
        let grant = reserve && rec.rights != 0;
        let (mut total_cap, mut root_cap) = (MAX_HOST_RECS_TOTAL, MAX_RECS_PER_ROOT);
        if grant {
            total_cap -= HOST_REVOKE_RESERVE_TOTAL;
            root_cap = (root_cap - HOST_REVOKE_RESERVE_PER_ROOT).min(self.host_policy_cap(&rec.root));
        }
        let (mut total, mut in_root, mut for_holder, mut by_issuer) = (0usize, 0usize, 0usize, 0usize);
        for (r, h, i) in self.host_recs.keys() {
            total += 1;
            if *r == rec.root {
                in_root += 1;
                if *h == rec.hh { for_holder += 1; }
                if *i == rec.issuer { by_issuer += 1; }
            }
        }
        if total >= total_cap { return Err("host record store full"); }
        if in_root >= root_cap { return Err("host record quota for root exhausted"); }
        if for_holder >= MAX_HOST_ISSUERS_PER_HOLDER { return Err("too many host records for holder"); }
        if by_issuer >= MAX_HOST_RECS_PER_ISSUER { return Err("host record quota for issuer exhausted"); }
        Ok(())
    }

    /// Полная проверка записи и сериализация нового файла без записи на диск и без изменения состояния.
    /// Снимок может устареть; `HostCommit::commit` проверит его версию ДО записи, а не после.
    pub fn prepare_host_access(&self, rec: &HostAccessRecord) -> std::result::Result<HostCommit, HostCommitError> {
        use HostCommitError::{Io, Rejected, Stale};
        if rec.rights != 0 && rec.rights != HOST_ACCESS { return Err(Rejected("unsupported_rights")); }
        if rec.scope != self.me_hash { return Err(Rejected("wrong_scope")); }
        if rec.seq > now_ms() as u64 + SEQ_FUTURE_MS { return Err(Rejected("seq_future")); }
        if !self.anchors.contains_key(&rec.root) { return Err(Rejected("root_not_accepted")); }
        if !self.host_root_allowed(&rec.root) { return Err(Rejected("root_not_allowed_by_host_policy")); }
        if rec.hh == rec.issuer { return Err(Rejected("self_grant")); }
        let issuer_pk = self.pub_of(&rec.root, &rec.issuer).ok_or(Rejected("unknown_issuer"))?;
        if !rec.sig_ok(&issuer_pk) { return Err(Rejected("bad_signature")); }
        let ir = self.rights_in(&rec.root, &rec.issuer);
        let need = if rec.rights == 0 { REMOVE } else { ADD };
        if ir & need == 0 || !self.has_host_authority(&rec.root, &rec.issuer, &rec.scope) {
            return Err(Rejected("authority_insufficient"));
        }
        let key = (rec.root, rec.hh, rec.issuer);
        if self.host_recs.get(&key).is_some_and(|old| old.seq >= rec.seq) { return Err(Stale); }
        // Держатель должен быть известен в корне. Отзыв неизвестного допустим только если на него уже есть запись.
        let holder_known = self.pub_of(&rec.root, &rec.hh).is_some()
            || (rec.rights == 0 && self.host_recs.keys().any(|(r, h, _)| *r == rec.root && *h == rec.hh));
        if !holder_known { return Err(Rejected("holder_not_known")); }
        self.host_rec_limits(rec, true).map_err(Rejected)?;
        let path = self.path.as_ref().and_then(|p| p.parent()).map(|d| d.join("host-access.json"));
        let mut next = self.host_recs.clone();
        next.insert(key, rec.clone());
        let records = next.values().map(|r| hex(&r.wire())).collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&serde_json::json!({"v":1,"records":records})).map_err(|_| Io)?;
        if bytes.len() as u64 > MAX_HOST_FILE_BYTES { return Err(Rejected("host record store full")); }
        Ok(HostCommit { key, rec: rec.clone(), base_version: self.host_version, path, bytes, gate: self.host_commit.clone() })
    }

    /// Приватное завершение под gate: версия не может измениться между pre-write check и finish.
    fn finish_host_access(&mut self, commit: HostCommit) {
        assert_eq!(commit.base_version, self.host_version, "host commit gate invariant");
        self.host_recs.insert(commit.key, commit.rec);
        self.host_version += 1;
    }

    /// Independent per-root decision; callers must retain the root that authorized access.
    pub fn host_access_roots(&self, holder: &Pk, target: &Hash) -> Vec<Hash> {
        let Some(hh) = hash_of(holder) else { return Vec::new() };
        if target != &self.me_hash { return Vec::new(); }
        // корень без разрешения локальной политики не даёт доступа к хосту, даже если его записи лежат в хранилище
        self.anchors.keys().filter(|root| self.host_root_allowed(root)).filter_map(|root| {
            let mut winner: Option<(&HostAccessRecord, u8)> = None;
            for ((r, h, issuer), rec) in &self.host_recs {
                if r != root || *h != hh || rec.scope != *target { continue; }
                let authority = self.rights_in(root, issuer);
                let need = if rec.rights == 0 { REMOVE } else { ADD };
                let Some(issuer_pk) = self.pub_of(root, issuer) else { continue };
                let Some(depth) = self.depth_in(root, issuer) else { continue };
                if authority & need == 0 || !self.has_host_authority(root, issuer, target) || !rec.sig_ok(&issuer_pk) { continue; }
                let better = winner.map_or(true, |(old, old_depth)|
                    (depth, rec.rights != 0, std::cmp::Reverse(rec.seq), rec.issuer)
                        < (old_depth, old.rights != 0, std::cmp::Reverse(old.seq), old.issuer));
                if better { winner = Some((rec, depth)); }
            }
            winner.filter(|(rec, _)| rec.rights == HOST_ACCESS).map(|_| *root)
        }).collect()
    }

    /// Root-scoped delegation ceiling for HOST_ACCESS on one exact target.
    /// A non-root admin needs a current root-signed scoped record granting bit
    /// 64 to that admin at this node; ordinary root-wide Records cannot supply it.
    pub fn has_host_authority(&self, root: &Hash, actor: &Hash, target: &Hash) -> bool {
        if !self.host_root_allowed(root) || target != &self.me_hash { return false; }
        if actor == root { return true; }
        let Some(rec) = self.host_recs.get(&(*root, *actor, *root)) else { return false };
        if rec.scope != *target || rec.rights != HOST_ACCESS { return false; }
        let Some(root_pk) = self.pub_of(root, root) else { return false };
        rec.sig_ok(&root_pk) && self.rights_in(root, root) & HOST_ACCESS != 0
    }

    /// Exact record equality for idempotent recovery when a crash happened
    /// after the signed scoped record reached durable state but before the
    /// operation-result journal was replaced.
    pub fn has_host_record(&self, rec: &HostAccessRecord) -> bool {
        self.host_recs.get(&(rec.root, rec.hh, rec.issuer)) == Some(rec)
    }

    pub fn host_access_revision(&self, root: &Hash) -> u64 {
        self.host_recs.values().filter(|r| &r.root == root).map(|r| r.seq).max().unwrap_or(0)
    }

    /// Bounded holder/right projection for one root; never includes public keys or aliases.
    pub fn participants_in_root(&self, root: &Hash, limit: usize) -> Vec<(Hash, u16)> {
        if !self.anchors.contains_key(root) { return Vec::new(); }
        let mut holders: Vec<Hash> = self.holders.keys().filter(|(r, h)| r == root && *h != self.me_hash).map(|(_, h)| *h).collect();
        holders.sort_unstable();
        holders.dedup();
        holders.into_iter().filter_map(|h| {
            let rights = self.rights_in(root, &h);
            (rights != 0).then_some((h, rights))
        }).take(limit.min(32)).collect()
    }

    /// Все держатели с правом `bit` (кроме нас самих) и их ключи: например, выходы для клиента.
    pub fn holders_with(&self, bit: u16) -> Vec<Pk> {
        let mut out: Vec<Pk> = Vec::new();
        for ((root, hh, _), rec) in self.recs.iter() {
            if *hh == self.me_hash || out.contains(&rec.holder) {
                continue;
            }
            if self.rights_in(root, hh) & bit != 0 {
                out.push(rec.holder);
            }
        }
        out.sort();
        for p in self.enroll_recs.values() {
            if p.rec.holder != self.me_pk && self.rights_at(&p.grant.root, &hash_of(&p.rec.holder).unwrap(), &self.me_hash) & bit != 0 && !out.contains(&p.rec.holder) { out.push(p.rec.holder); }
        }
        out
    }

    // ----------------------------------------------------------------- выдача и отзыв

    /// Подписать и принять запись от своего имени. Права проверяются так же, как у чужих: выдать можно только подмножество своих.
    pub fn issue(&mut self, root: Hash, holder: Pk, rights: u16) -> Result<Record> {
        if !self.anchors.contains_key(&root) {
            bail!("корень не из моих якорей");
        }
        let hh = hash_of(&holder).ok_or_else(|| anyhow::anyhow!("ключ держателя не разобран"))?;
        if hh == self.me_hash {
            bail!("себе права не выдают");
        }
        let mine = self.my_rights_in(&root);
        let need = if rights == 0 { REMOVE } else { ADD };
        if mine & need == 0 {
            bail!("у меня нет права {} в этом корне", rights_text(need));
        }
        if rights & !mine != 0 {
            bail!("можно выдать только подмножество своих прав (у меня {}, просят {})", rights_text(mine), rights_text(rights));
        }
        let depth = self.depth_in(&root, &self.me_hash).ok_or_else(|| anyhow::anyhow!("глубина моей цепочки не подтверждена"))?;
        if depth as usize + 1 > MAX_DEPTH {
            bail!("выдача превысит максимальную глубину цепочки {MAX_DEPTH}");
        }
        let prior_key = (root, hh, self.me_hash);
        let prior = self.recs.get(&prior_key).cloned();
        let prior_holder = self.holders.get(&(root, hh)).copied();
        let prev = prior.as_ref().map(|r| r.seq).unwrap_or(0);
        let seq = (now_ms() as u64).max(prev + 1);
        let rec = Record::sign(&self.me, root, holder, rights, seq)?;
        match self.offer(rec.clone()) {
            Offer::Added => {
                if self.rights_in(&root, &hh) != rights {
                    if let Some(old) = prior { self.recs.insert(prior_key, old); } else { self.recs.remove(&prior_key); }
                    if let Some(old_pk) = prior_holder { self.holders.insert((root, hh), old_pk); }
                    else if !self.recs.keys().any(|(r, h, _)| *r == root && *h == hh) { self.holders.remove(&(root, hh)); }
                    bail!("выданные права не действуют после проверки цепочки");
                }
                Ok(rec)
            }
            other => bail!("запись не принята: {other:?}"),
        }
    }

    // ----------------------------------------------------------------- политика (0015)

    /// Принять политику. Проверяет корень, что держатель нам известен и имеет выдачу, срок, свежесть и подпись держателя.
    /// Политика не может ничего расширить: она влияет только через `effective_in`, где пересекается с выдачей.
    pub fn offer_policy(&mut self, pol: Policy, now: u64) -> Offer {
        self.offer_policy_checked(pol, now, true)
    }

    fn offer_policy_checked(&mut self, pol: Policy, now: u64, check_time: bool) -> Offer {
        if !self.anchors.contains_key(&pol.root) {
            return Offer::Rejected("чужой корень");
        }
        if self.pub_of(&pol.root, &pol.hh) != Some(pol.holder) {
            return Offer::Rejected("неизвестный держатель");
        }
        if self.rights_in(&pol.root, &pol.hh) == 0 {
            return Offer::Rejected("нет выдачи в корне");
        }
        if check_time {
            if pol.seq > now.saturating_add(SEQ_FUTURE_MS) {
                return Offer::Rejected("seq из будущего");
            }
            if pol.valid_until <= now {
                return Offer::Rejected("политика истекла");
            }
            if pol.valid_until > now.saturating_add(POLICY_TTL_MS).saturating_add(SEQ_FUTURE_MS) {
                return Offer::Rejected("срок политики слишком велик");
            }
        }
        let key = (pol.root, pol.hh);
        if self.pols.get(&key).map_or(false, |o| o.seq >= pol.seq) {
            return Offer::Stale;
        }
        if !pol.sig_ok() {
            return Offer::Rejected("подпись");
        }
        self.pols.insert(key, pol);
        Offer::Added
    }

    /// Убрать политики держателей, у которых выдачи больше нет (отзыв).
    pub fn prune_policies(&mut self) {
        let dead: Vec<(Hash, Hash)> = self.pols.keys().filter(|(r, h)| self.rights_in(r, h) == 0).copied().collect();
        for k in dead {
            self.pols.remove(&k);
        }
    }

    /// Действующие права `h` в корне: выдача ∩ политика. Нет политики - выдача целиком (нода без поддержки 0015).
    /// Просроченная политика сужает до USE: устаревшее «EXIT включён» не должно жить вечно, а возврат к выдаче расширил бы права.
    pub fn effective_in(&self, root: &Hash, h: &Hash, now: u64) -> u16 {
        let grant = self.rights_at(root, h, &self.me_hash);
        grant & self.offer_in(root, h, now)
    }

    fn offer_in(&self, root: &Hash, h: &Hash, now: u64) -> u16 {
        match self.pols.get(&(*root, *h)) {
            None => KNOWN,
            Some(p) if p.valid_until > now => p.offer,
            Some(_) => USE,
        }
    }

    /// Действующие права ключа: объединение по всем якорям.
    pub fn effective(&self, pk: &Pk, now: u64) -> u16 {
        let Some(h) = hash_of(pk) else { return 0 };
        self.anchors.keys().fold(0, |a, root| a | self.effective_in(root, &h, now))
    }

    /// Видна ли нода другим: есть действующие USE, TRANSIT или EXIT хотя бы в одном корне.
    #[cfg(test)]
    pub fn visible(&self, pk: &Pk, now: u64) -> bool {
        self.effective(pk, now) & VISIBLE_BITS != 0
    }

    /// Мои политики (подписаны мной): их клиент отдаёт выходу при подключении.
    pub fn my_policies(&self, now: u64) -> Vec<Policy> {
        let mut v: Vec<Policy> = self.pols.values().filter(|p| p.hh == self.me_hash && p.valid_until > now).cloned().collect();
        v.sort_by_key(|p| p.root);
        v
    }

    /// Для экрана «Мои права»: по каждой сети, где мне что-то выдано, - (корень, выдано, согласна ли я на что-то: настройка, действует).
    pub fn policy_view(&self, now: u64) -> Vec<(Hash, u16, Option<u16>, u16)> {
        let mut v: Vec<(Hash, u16, Option<u16>, u16)> = self
            .anchors
            .keys()
            .filter_map(|root| {
                let g = self.rights_in(root, &self.me_hash);
                (g != 0).then(|| (*root, g, self.my_offer.get(root).copied(), self.effective_in(root, &self.me_hash, now)))
            })
            .collect();
        v.sort_by_key(|x| x.0);
        v
    }

    /// Моя настройка в корне, если задана.
    pub fn my_policy_offer(&self, root: &Hash) -> Option<u16> {
        self.my_offer.get(root).copied()
    }

    /// Задать, что я согласна делать в корне, и подписать новую политику. Поверх выдачи ничего не добавляется.
    pub fn set_my_policy(&mut self, root: Hash, offer: u16, now: u64) -> Result<Policy> {
        if !self.anchors.contains_key(&root) {
            bail!("корень не из моих якорей");
        }
        if offer & !KNOWN != 0 {
            bail!("политика: лишние биты");
        }
        if self.my_rights_in(&root) == 0 {
            bail!("в этом корне у меня нет выдачи");
        }
        let pol = self.sign_my_policy(root, offer, now)?;
        self.my_offer.insert(root, offer);
        Ok(pol)
    }

    fn sign_my_policy(&mut self, root: Hash, offer: u16, now: u64) -> Result<Policy> {
        let prev = self.pols.get(&(root, self.me_hash)).map(|p| p.seq).unwrap_or(0);
        let pol = Policy::sign(&self.me, root, offer, now.max(prev + 1), now + POLICY_TTL_MS)?;
        match self.offer_policy(pol.clone(), now) {
            Offer::Added => Ok(pol),
            other => bail!("политика не принята: {other:?}"),
        }
    }

    /// Переподписать мои политики, которым больше `POLICY_REFRESH_MS` (или которых ещё нет). Вызывать периодически; результат разослать.
    pub fn refresh_my_policies(&mut self, now: u64) -> Vec<Policy> {
        let mut out = Vec::new();
        for (root, offer) in self.my_offer.clone() {
            if !self.anchors.contains_key(&root) {
                continue;
            }
            let due = match self.pols.get(&(root, self.me_hash)) {
                Some(p) => p.valid_until.saturating_add(POLICY_REFRESH_MS) <= now.saturating_add(POLICY_TTL_MS),
                None => true,
            };
            if due {
                if let Ok(p) = self.sign_my_policy(root, offer, now) {
                    out.push(p);
                }
            }
        }
        out
    }

    /// Все не истёкшие политики держателей с выдачей, детерминированно упорядоченные. Скрытых нод тоже: чтобы соблюдать скрытие
    /// (не называть ноду в каталоге и таблицах), сосед должен знать, что она отказалась; выдача этой ноды у него и так есть.
    pub fn export_policies(&self, now: u64) -> Vec<Policy> {
        let mut v: Vec<Policy> = self.pols.values().filter(|p| p.valid_until > now && self.rights_in(&p.root, &p.hh) != 0).cloned().collect();
        v.sort_by_key(|p| (p.root, p.hh));
        v
    }

    /// Что отдать пиру: члены с TRANSIT/ADD/REMOVE/CONFIG получают все; пользователь с одним USE - политики держателей выхода (по выдаче,
    /// ровно тех, чьи записи он получает) и свою.
    pub fn export_policies_for(&self, peer_rights: u16, peer: &Pk, now: u64) -> Vec<Policy> {
        let all = self.export_policies(now);
        if peer_rights & (TRANSIT | ADD | REMOVE | CONFIG) != 0 {
            return all;
        }
        let peer_h = hash_of(peer);
        all.into_iter().filter(|p| Some(p.hh) == peer_h || self.rights_in(&p.root, &p.hh) & EXIT != 0).collect()
    }

    // ----------------------------------------------------------------- выгрузка для рассылки

    /// Все записи, по возрастанию глубины издателя: получатель всегда знает ключ издателя раньше записи.
    pub fn export_all(&self) -> Vec<Record> {
        let mut budget = STEP_BUDGET;
        let mut v: Vec<(u8, &Record)> = self.recs.values().map(|r| {
            let d = self.eff(&r.root, &r.issuer, &mut Vec::new(), &mut budget).map(|(_, d)| d).unwrap_or(250);
            (d, r)
        }).collect();
        v.sort_by_key(|(d, r)| (*d, r.root, r.seq, r.hh));
        v.into_iter().map(|(_, r)| r.clone()).collect()
    }

    /// Цепочка ключа до корней (его записи и записи его издателей), корень первым: этим нода предъявляет себя собеседнику.
    pub fn chain_for(&self, pk: &Pk) -> Vec<Record> {
        let Some(h) = hash_of(pk) else { return vec![] };
        let all = self.export_all();
        let mut need: Vec<(Hash, Hash)> = self.anchors.keys().map(|r| (*r, h)).collect();
        let mut out: Vec<Record> = Vec::new();
        let mut i = 0;
        while i < need.len() && need.len() < 64 {
            let (root, who) = need[i];
            i += 1;
            for r in all.iter().filter(|r| r.root == root && r.hh == who) {
                if !out.contains(r) {
                    out.push(r.clone());
                }
                let nx = (root, r.issuer);
                if r.issuer != root && !need.contains(&nx) {
                    need.push(nx);
                }
            }
        }
        out.sort_by_key(|r| all.iter().position(|a| a == r).unwrap_or(usize::MAX));
        out
    }

    /// То, что нода отдаёт собеседнику после проверки его прав: члены с TRANSIT/ADD/REMOVE/CONFIG видят всё хранилище,
    /// пользователь с одним USE - только цепочки выходов и свою (чужих пользователей не раскрываем).
    #[cfg(test)]
    pub fn export_for(&self, peer_rights: u16, peer: &Pk) -> Vec<Record> {
        if peer_rights & (TRANSIT | ADD | REMOVE | CONFIG) != 0 {
            return self.export_all();
        }
        let mut out = self.chain_for(peer);
        for ex in self.holders_with(EXIT) {
            for r in self.chain_for(&ex) {
                if !out.contains(&r) {
                    out.push(r);
                }
            }
        }
        let all = self.export_all();
        out.sort_by_key(|r| all.iter().position(|a| a == r).unwrap_or(usize::MAX));
        out
    }

    /// Root-scoped T_REC projection. Rights are derived independently for every
    /// accepted root; no caller-supplied scalar or cross-root union is used.
    /// Privileged members retain the existing full-root export policy, while a
    /// USE-only peer receives only its own and EXIT-holder chains in that root.
    pub fn records_visible_to(&self, peer: &Pk) -> Vec<Record> {
        let Some(peer_hash) = hash_of(peer) else { return Vec::new() };
        let mut visible: HashSet<(Hash, Hash, Hash)> = HashSet::new();
        for root in self.anchors.keys() {
            visible.extend(self.visible_record_keys_in_root(root, &peer_hash));
        }
        self.export_all().into_iter().filter(|r| visible.contains(&(r.root, r.hh, r.issuer))).collect()
    }

    /// Same root-scoped policy as `records_visible_to`, for live T_REC push.
    /// Requires the exact record to be present in this Trust store.
    pub fn record_visible_to(&self, rec: &Record, peer: &Pk) -> bool {
        let Some(peer_hash) = hash_of(peer) else { return false };
        if self.recs.get(&(rec.root, rec.hh, rec.issuer)) != Some(rec) { return false; }
        self.visible_record_keys_in_root(&rec.root, &peer_hash).contains(&(rec.root, rec.hh, rec.issuer))
    }

    fn visible_record_keys_in_root(&self, root: &Hash, peer: &Hash) -> HashSet<(Hash, Hash, Hash)> {
        let rights = self.rights_at(root, peer, &self.me_hash);
        if rights & (TRANSIT | ADD | REMOVE | CONFIG) != 0 {
            return self.recs.keys().filter(|(r, _, _)| r == root).copied().collect();
        }
        let Some(peer_pk) = self.pub_of(root, peer) else { return HashSet::new() };
        let mut visible = HashSet::new();
        for rec in self.chain_for_root(root, &peer_pk) {
            visible.insert((rec.root, rec.hh, rec.issuer));
        }
        // A known peer may learn its own signed revoke even after losing USE.
        // It must not retain the EXIT/sibling visibility of its former role.
        if rights & USE == 0 { return visible; }
        let exits: HashSet<Hash> = self.recs.keys().filter(|(r, hh, _)| r == root && self.rights_in(root, hh) & EXIT != 0)
            .map(|(_, hh, _)| *hh).collect();
        for exit in exits {
            let Some(exit_pk) = self.pub_of(root, &exit) else { continue };
            for rec in self.chain_for_root(root, &exit_pk) {
                visible.insert((rec.root, rec.hh, rec.issuer));
            }
        }
        visible
    }

    fn chain_for_root(&self, root: &Hash, pk: &Pk) -> Vec<Record> {
        let Some(h) = hash_of(pk) else { return Vec::new() };
        if !self.anchors.contains_key(root) { return Vec::new() }
        let all = self.export_all();
        let mut need = vec![*root, h];
        let mut out = Vec::new();
        let mut i = 0;
        while i < need.len() && need.len() < 64 {
            let who = need[i];
            i += 1;
            for rec in all.iter().filter(|r| r.root == *root && r.hh == who) {
                if !out.contains(rec) { out.push(rec.clone()); }
                if rec.issuer != *root && !need.contains(&rec.issuer) { need.push(rec.issuer); }
            }
        }
        out.sort_by_key(|r| all.iter().position(|a| a == r).unwrap_or(usize::MAX));
        out
    }
}


pub use crate::enroll::Invite;

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> Identity {
        leviculum_std::api::generate_identity()
    }

    fn tr(id: &Identity) -> Trust {
        Trust::new(id.clone(), None)
    }

    #[test]
    fn rights_parse_and_text() {
        assert_eq!(parse_rights("user").unwrap(), USE);
        assert_eq!(parse_rights("relay").unwrap(), USE | TRANSIT | EXIT | ADD);
        assert_eq!(parse_rights("admin").unwrap(), ALL);
        assert_eq!(parse_rights("host_access").unwrap(), HOST_ACCESS);
        assert_eq!(parse_rights("64").unwrap(), HOST_ACCESS);
        assert!(parse_rights("192").is_err(), "неизвестные биты отклоняются целиком");
        assert_eq!(parse_rights("use+exit").unwrap(), USE | EXIT);
        assert_eq!(parse_rights("12").unwrap(), 12);
        assert!(parse_rights("root").is_err());
        assert_eq!(rights_text(HOST_ACCESS), "HOST_ACCESS");
        assert_eq!(rights_text(USE | EXIT), "USE+EXIT");
        assert_eq!(rights_text(0), "-");
    }

    #[test]
    fn record_roundtrip_and_tamper() {
        let a = ident();
        let h = ident();
        let r = Record::sign(&a, *a.hash(), h.public_key_bytes(), USE | EXIT, 5).unwrap();
        let w = r.wire();
        assert_eq!(w.len(), REC_LEN);
        let p = Record::parse(&w).unwrap();
        assert_eq!(p, r);
        assert!(p.sig_ok(&a.public_key_bytes()));
        assert!(!p.sig_ok(&h.public_key_bytes()), "чужой ключ подпись не проверит");
        // любой бит payload ломает подпись
        for i in [1usize, 3, 11, 27, 91] {
            let mut x = w.clone();
            x[i] ^= 1;
            if let Some(q) = Record::parse(&x) {
                assert!(!q.sig_ok(&a.public_key_bytes()), "байт {i}");
            }
        }
        assert!(Record::parse(&w[..w.len() - 1]).is_none());
        assert!(Record::sign(&a, *a.hash(), h.public_key_bytes(), HOST_ACCESS, 6).is_err(), "Record v1 cannot carry an unscoped host grant");
        let unscoped = Record::sign(&a, *a.hash(), h.public_key_bytes(), USE, 7).unwrap();
        let mut unscoped_wire = unscoped.wire();
        unscoped_wire[1..3].copy_from_slice(&HOST_ACCESS.to_le_bytes());
        assert!(Record::parse(&unscoped_wire).is_none(), "Record v1 rejects HOST_ACCESS as an unscoped bit");
        let mut bad = w.clone();
        bad[1] = 0xff; // лишние биты прав
        assert!(Record::parse(&bad).is_none());
    }

    #[test]
    fn host_access_record_is_scoped_and_rechecks_delegation() {
        let (root_id, holder, target_a, target_b) = (ident(), ident(), ident(), ident());
        let root = *root_id.hash();
        let mut issuer = tr(&root_id);
        let holder_rec = issuer.issue(root, holder.public_key_bytes(), USE).unwrap();
        let rec = issuer.sign_host_access(root, *target_a.hash(), holder.public_key_bytes(), true).unwrap();
        assert_eq!(HostAccessRecord::parse(&rec.wire()).unwrap(), rec);

        let mut target = tr(&target_a);
        target.add_anchor(&root_id.public_key_bytes()).unwrap();
        assert!(target.accept_host_access(rec.clone()).is_err(), "принятие якоря само по себе HOST_ACCESS не даёт: нужна локальная политика");
        target.allow_host_root(root, 16);
        assert!(target.accept_host_access(rec.clone()).is_err(), "держатель должен быть известен в корне");
        assert_eq!(target.offer(holder_rec), Offer::Added);
        target.accept_host_access(rec.clone()).unwrap();
        assert_eq!(target.host_access_roots(&holder.public_key_bytes(), target_a.hash()), vec![root]);
        assert!(target.host_access_roots(&holder.public_key_bytes(), target_b.hash()).is_empty());
        let revoke = issuer.sign_host_access(root, *target_a.hash(), holder.public_key_bytes(), false).unwrap();
        target.accept_host_access(revoke).unwrap();
        assert!(target.host_access_roots(&holder.public_key_bytes(), target_a.hash()).is_empty());

        let mut other = tr(&target_b);
        other.add_anchor(&root_id.public_key_bytes()).unwrap();
        other.allow_host_root(root, 16);
        assert!(other.accept_host_access(rec).is_err(), "scoped grant cannot migrate to a different node");

        let mut delegated = tr(&ident());
        assert!(delegated.add_anchor(&root_id.public_key_bytes()).is_ok());
        assert!(delegated.sign_host_access(root, *target_a.hash(), holder.public_key_bytes(), true).is_err(), "foreign self-root is not authority");
    }

    #[test]
    fn network_admin_needs_root_signed_node_scoped_host_authority() {
        let (root_id, admin, holder, target_id) = (ident(), ident(), ident(), ident());
        let root = *root_id.hash();
        let mut root_trust = tr(&root_id);
        let delegate = root_trust.issue(root, admin.public_key_bytes(), ADD | REMOVE | USE).unwrap();
        let holder_rec = root_trust.issue(root, holder.public_key_bytes(), USE).unwrap();
        let mut admin_trust=tr(&admin);
        admin_trust.add_anchor(&root_id.public_key_bytes()).unwrap();
        assert_eq!(admin_trust.offer(delegate.clone()),Offer::Added);
        let mut target = tr(&target_id);
        target.add_anchor(&root_id.public_key_bytes()).unwrap();
        target.allow_host_root(root, 16);
        assert_eq!(target.offer(delegate), Offer::Added);
        assert_eq!(target.offer(holder_rec), Offer::Added);
        assert!(!target.has_host_authority(&root, admin.hash(), target_id.hash()));

        let authority = root_trust.sign_host_access(root, *target_id.hash(), admin.public_key_bytes(), true).unwrap();
        target.accept_host_access(authority).unwrap();
        assert!(target.has_host_authority(&root, admin.hash(), target_id.hash()));
        let grant = admin_trust.sign_host_access(root, *target_id.hash(), holder.public_key_bytes(), true).unwrap();
        target.accept_host_access(grant).unwrap();
        assert_eq!(target.host_access_roots(&holder.public_key_bytes(), target_id.hash()), vec![root]);
        let authority_revoke = root_trust.sign_host_access(root, *target_id.hash(), admin.public_key_bytes(), false).unwrap();
        target.accept_host_access(authority_revoke).unwrap();
        assert!(target.host_access_roots(&holder.public_key_bytes(), target_id.hash()).is_empty(), "root-scoped authority revocation disables descendant host grants immediately");
    }

    #[test]
    fn delegated_host_access_survives_reload_and_revoked_issuer_stays_inactive() {
        let dir = std::env::temp_dir().join(format!(
            "knothop-host-reload-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (root_id, admin, holder, target_id) = (ident(), ident(), ident(), ident());
        let root = *root_id.hash();
        let mut root_trust = tr(&root_id);
        let delegation = root_trust.issue(root, admin.public_key_bytes(), ADD | REMOVE | USE).unwrap();
        let holder_rec = root_trust.issue(root, holder.public_key_bytes(), USE).unwrap();
        let mut admin_trust = tr(&admin);
        admin_trust.add_anchor(&root_id.public_key_bytes()).unwrap();
        assert_eq!(admin_trust.offer(delegation.clone()), Offer::Added);
        std::fs::write(dir.join("host-policy.json"), format!("{{\"v\":1,\"roots\":[{{\"root\":\"{}\",\"max_holders\":16}}]}}", hex(&root))).unwrap();
        let mut target = Trust::new(target_id.clone(), Some(dir.join("trust.json")));
        target.add_anchor(&root_id.public_key_bytes()).unwrap();
        target.allow_host_root(root, 16);
        assert_eq!(target.offer(delegation), Offer::Added);
        assert_eq!(target.offer(holder_rec), Offer::Added);
        target.save().unwrap();
        let authority = root_trust.sign_host_access(root, *target_id.hash(), admin.public_key_bytes(), true).unwrap();
        target.accept_host_access(authority).unwrap();
        let grant = admin_trust.sign_host_access(root, *target_id.hash(), holder.public_key_bytes(), true).unwrap();
        target.accept_host_access(grant).unwrap();

        // Порядок записей в файле не задаёт порядок делегирования.
        let path = dir.join("host-access.json");
        let mut saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        saved["records"].as_array_mut().unwrap().sort_by_key(|wire| {
            HostAccessRecord::parse(&unhex(wire.as_str().unwrap())).unwrap().issuer == root
        });
        std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        let mut target = Trust::load(target_id.clone(), &dir).expect("делегированный грант загружается до записи полномочий корня");
        assert_eq!(target.host_access_roots(&holder.public_key_bytes(), target_id.hash()), vec![root]);

        let revoke = admin_trust.sign_host_access(root, *target_id.hash(), holder.public_key_bytes(), false).unwrap();
        target.accept_host_access(revoke).unwrap();
        let mut target = Trust::load(target_id.clone(), &dir).expect("отзыв делегата сохраняется после перезапуска");
        assert!(target.host_access_roots(&holder.public_key_bytes(), target_id.hash()).is_empty());

        let grant = admin_trust.sign_host_access(root, *target_id.hash(), holder.public_key_bytes(), true).unwrap();
        target.accept_host_access(grant).unwrap();
        let revoke_issuer = root_trust.issue(root, admin.public_key_bytes(), 0).unwrap();
        assert_eq!(target.offer(revoke_issuer), Offer::Added);
        target.save().unwrap();
        let target = Trust::load(target_id.clone(), &dir).expect("отозванный издатель не делает хранилище незагружаемым");
        assert!(target.host_access_roots(&holder.public_key_bytes(), target_id.hash()).is_empty(), "сохранённый грант не оживает после отзыва издателя");

        let mut saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut wire = unhex(saved["records"][0].as_str().unwrap());
        let last = wire.len() - 1;
        wire[last] ^= 1;
        saved["records"][0] = serde_json::json!(hex(&wire));
        std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        assert!(Trust::load(target_id, &dir).is_err(), "испорченная подпись остаётся фатальной ошибкой загрузки");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn host_tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "knothop-{tag}-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn host_policy_is_explicit_per_root_and_fail_closed() {
        let dir = host_tmp("hostpol");
        let (root_id, target_id, holder) = (ident(), ident(), ident());
        let root = *root_id.hash();
        let mut root_trust = tr(&root_id);
        let holder_rec = root_trust.issue(root, holder.public_key_bytes(), USE).unwrap();
        let mut target = Trust::new(target_id.clone(), Some(dir.join("trust.json")));
        target.add_anchor(&root_id.public_key_bytes()).unwrap();
        assert_eq!(target.offer(holder_rec), Offer::Added);
        target.save().unwrap();
        let grant = root_trust.sign_host_access(root, *target_id.hash(), holder.public_key_bytes(), true).unwrap();
        assert!(!target.host_root_allowed(&root), "принятый якорь без политики HOST_ACCESS не даёт");
        assert!(target.host_root_allowed(&target.me_hash), "собственный корень разрешён всегда");
        assert!(target.accept_host_access(grant.clone()).is_err());
        assert!(!target.has_host_authority(&root, &root, target_id.hash()), "даже сам чужой корень не имеет полномочий без политики");

        let policy = dir.join("host-policy.json");
        std::fs::write(&policy, format!("{{\"v\":1,\"roots\":[{{\"root\":\"{}\",\"max_holders\":4}}]}}", hex(&root))).unwrap();
        let mut target = Trust::load(target_id.clone(), &dir).unwrap();
        assert!(target.host_root_allowed(&root));
        target.accept_host_access(grant).unwrap();
        assert_eq!(target.host_access_roots(&holder.public_key_bytes(), target_id.hash()), vec![root]);

        // убрали политику: подписанная история остаётся в файле, но доступ неактивен
        std::fs::remove_file(&policy).unwrap();
        let target = Trust::load(target_id.clone(), &dir).unwrap();
        assert!(target.host_access_roots(&holder.public_key_bytes(), target_id.hash()).is_empty());

        let hexroot = hex(&root);
        let bad = [
            "not json".to_string(),
            r#"{"v":2,"roots":[]}"#.to_string(),
            r#"{"v":1}"#.to_string(),
            r#"{"v":1,"roots":[{"root":"zz","max_holders":1}]}"#.to_string(),
            format!("{{\"v\":1,\"roots\":[{{\"root\":\"{hexroot}\",\"max_holders\":0}}]}}"),
            format!("{{\"v\":1,\"roots\":[{{\"root\":\"{hexroot}\",\"max_holders\":100000}}]}}"),
            format!("{{\"v\":1,\"roots\":[{}]}}", vec![format!("{{\"root\":\"{hexroot}\"}}"); MAX_ROOTS + 1].join(",")),
        ];
        for body in bad {
            std::fs::write(&policy, body.as_bytes()).unwrap();
            assert!(Trust::load(target_id.clone(), &dir).is_err(), "битая политика должна быть отказом загрузки: {body}");
        }
        std::fs::write(&policy, vec![b' '; MAX_HOST_FILE_BYTES as usize + 1]).unwrap();
        assert!(Trust::load(target_id, &dir).is_err(), "файл политики больше лимита не читается");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn host_store_limits_reject_new_grants_but_never_block_revocations() {
        let (root_id, target_id) = (ident(), ident());
        let root = *root_id.hash();
        let mut root_trust = tr(&root_id);
        let holders: Vec<Identity> = (0..6).map(|_| ident()).collect();
        let mut target = tr(&target_id);
        target.add_anchor(&root_id.public_key_bytes()).unwrap();
        target.allow_host_root(root, 3);
        for h in &holders {
            let r = root_trust.issue(root, h.public_key_bytes(), USE).unwrap();
            assert_eq!(target.offer(r), Offer::Added);
        }
        let scope = *target_id.hash();
        for h in &holders[..3] {
            let g = root_trust.sign_host_access(root, scope, h.public_key_bytes(), true).unwrap();
            target.accept_host_access(g).unwrap();
        }
        let over = root_trust.sign_host_access(root, scope, holders[3].public_key_bytes(), true).unwrap();
        assert!(target.accept_host_access(over).is_err(), "на потолке держателей новая выдача отвергается");
        assert!(target.host_access_roots(&holders[3].public_key_bytes(), &scope).is_empty());

        // отзыв известного держателя проходит из запаса, замена существующего ключа не растёт
        let rv_new = root_trust.sign_host_access(root, scope, holders[4].public_key_bytes(), false).unwrap();
        target.accept_host_access(rv_new).unwrap();
        let rv_same = root_trust.sign_host_access(root, scope, holders[0].public_key_bytes(), false).unwrap();
        target.accept_host_access(rv_same).unwrap();
        assert!(target.host_access_roots(&holders[0].public_key_bytes(), &scope).is_empty(), "отзыв на потолке применился");
        let regrant = root_trust.sign_host_access(root, scope, holders[0].public_key_bytes(), true).unwrap();
        target.accept_host_access(regrant).unwrap();
        assert_eq!(target.host_access_roots(&holders[0].public_key_bytes(), &scope), vec![root]);

        // отзыв держателя, о котором нода ничего не знает, не принимается: хранилище не копит чужие ключи
        let stranger = ident();
        let unknown = root_trust.sign_host_access(root, scope, stranger.public_key_bytes(), false).unwrap();
        assert!(target.accept_host_access(unknown).is_err());
        // выдача самому себе отвергается
        let mut self_rec = root_trust.sign_host_access(root, scope, holders[1].public_key_bytes(), true).unwrap();
        self_rec.issuer = self_rec.hh;
        assert_eq!(target.prepare_host_access(&self_rec).err(), Some(HostCommitError::Rejected("self_grant")));
    }

    #[test]
    fn host_file_is_size_and_count_bounded_before_use() {
        let dir = host_tmp("hostsize");
        let target_id = ident();
        let path = dir.join("host-access.json");
        std::fs::write(&path, vec![b'x'; MAX_HOST_FILE_BYTES as usize + 1]).unwrap();
        assert!(Trust::load(target_id.clone(), &dir).is_err(), "файл больше лимита отвергается до разбора");
        let items = vec!["\"\""; MAX_HOST_RECS_TOTAL + 1].join(",");
        std::fs::write(&path, format!("{{\"v\":1,\"records\":[{items}]}}")).unwrap();
        let err = Trust::load(target_id, &dir).err().expect("слишком много записей").to_string();
        assert!(err.contains("too many records"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn host_commit_is_prepared_outside_lock_and_stale_commit_is_refused() {
        let dir = host_tmp("hostcommit");
        let (root_id, target_id, h1, h2) = (ident(), ident(), ident(), ident());
        let root = *root_id.hash();
        let mut root_trust = tr(&root_id);
        let mut target = Trust::new(target_id.clone(), Some(dir.join("trust.json")));
        target.add_anchor(&root_id.public_key_bytes()).unwrap();
        target.allow_host_root(root, 8);
        for h in [&h1, &h2] {
            assert_eq!(target.offer(root_trust.issue(root, h.public_key_bytes(), USE).unwrap()), Offer::Added);
        }
        target.save().unwrap();
        let scope = *target_id.hash();
        let g1 = root_trust.sign_host_access(root, scope, h1.public_key_bytes(), true).unwrap();
        let g2 = root_trust.sign_host_access(root, scope, h2.public_key_bytes(), true).unwrap();

        // prepare не меняет ни память, ни диск
        let c1 = target.prepare_host_access(&g1).unwrap();
        let c2 = target.prepare_host_access(&g2).unwrap();
        assert!(target.host_access_roots(&h1.public_key_bytes(), &scope).is_empty());
        assert!(!dir.join("host-access.json").exists());

        // запись, не удавшаяся на диске, не меняет память (finish не вызывается)
        let missing = host_tmp("hostcommit-gone");
        std::fs::remove_dir_all(&missing).unwrap();
        let mut broken = Trust::new(target_id.clone(), Some(missing.join("trust.json")));
        broken.add_anchor(&root_id.public_key_bytes()).unwrap();
        broken.allow_host_root(root, 8);
        broken.offer(root_trust.issue(root, h1.public_key_bytes(), USE).unwrap());
        let cb = broken.prepare_host_access(&g1).unwrap();
        let broken = Mutex::new(broken);
        assert_eq!(cb.commit(&broken), Err(HostCommitError::Io));
        assert!(broken.lock().unwrap().host_access_roots(&h1.public_key_bytes(), &scope).is_empty());

        let target = Mutex::new(target);
        c1.commit(&target).unwrap();
        assert_eq!(target.lock().unwrap().host_access_roots(&h1.public_key_bytes(), &scope), vec![root]);
        // c2 подготовлен до c1: проверка версии обязана отказать ДО перезаписи файла.
        let committed_bytes = std::fs::read(dir.join("host-access.json")).unwrap();
        assert_eq!(c2.commit(&target), Err(HostCommitError::Stale));
        assert_eq!(std::fs::read(dir.join("host-access.json")).unwrap(), committed_bytes);
        assert!(target.lock().unwrap().host_access_roots(&h2.public_key_bytes(), &scope).is_empty());
        let restarted = Trust::load(target_id.clone(), &dir).unwrap();
        assert!(restarted.has_host_record(&g1), "stale commit must not erase the durable first grant");
        assert!(!restarted.has_host_record(&g2), "rejected stale commit must not take effect after restart");
        let c2 = target.lock().unwrap().prepare_host_access(&g2).unwrap();
        c2.commit(&target).unwrap();

        // политика живёт в файле оператора, а не в памяти: без него загруженная история неактивна
        let without_policy = Trust::load(target_id.clone(), &dir).unwrap();
        assert!(without_policy.host_access_roots(&h1.public_key_bytes(), &scope).is_empty());
        std::fs::write(dir.join("host-policy.json"), format!("{{\"v\":1,\"roots\":[{{\"root\":\"{}\",\"max_holders\":8}}]}}", hex(&root))).unwrap();
        let reloaded = Trust::load(target_id, &dir).unwrap();
        assert_eq!(reloaded.host_access_roots(&h1.public_key_bytes(), &scope), vec![root]);
        assert_eq!(reloaded.host_access_roots(&h2.public_key_bytes(), &scope), vec![root]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_host_commits_validate_before_io_and_do_not_lock_trust_during_write() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = host_tmp("hostcommit-concurrent");
        let (node, h1, h2) = (ident(), ident(), ident());
        let mut target = Trust::new(node.clone(), Some(dir.join("trust.json")));
        let root = target.me_hash;
        for h in [&h1, &h2] { target.issue(root, h.public_key_bytes(), USE).unwrap(); }
        target.save().unwrap();
        let g1 = target.sign_host_access(root, root, h1.public_key_bytes(), true).unwrap();
        let g2 = target.sign_host_access(root, root, h2.public_key_bytes(), true).unwrap();
        let c1 = target.prepare_host_access(&g1).unwrap();
        let c2 = target.prepare_host_access(&g2).unwrap();
        let store = Arc::new(Mutex::new(target));
        let (started_tx, started_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let (save_started_tx, save_started_rx) = mpsc::channel();
        let (save_done_tx, save_done_rx) = mpsc::channel();
        let worker_store = store.clone();
        let first = std::thread::spawn(move || c1.commit_with_writer(&worker_store, |commit| {
            started_tx.send(()).unwrap();
            resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            commit.write()
        }));
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        {
            let trust = store.try_lock().expect("disk I/O must not hold the hot trust lock");
            assert!(!trust.has_host_record(&g1), "unwritten candidate is not active");
            assert!(!dir.join("host-access.json").exists());
        }
        // An ordinary writer serializes on io_gate. It may hold Trust while
        // waiting, so the host writer must release io_gate before reacquiring
        // Trust to finish its in-memory commit.
        let save_store = store.clone();
        let save_thread = std::thread::spawn(move || {
            let trust = save_store.lock().unwrap();
            save_started_tx.send(()).unwrap();
            let result = trust.save();
            save_done_tx.send(result.is_ok()).unwrap();
        });
        save_started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(save_done_rx.recv_timeout(Duration::from_millis(50)).is_err(), "save is serialized behind host prerequisite+host writes");
        let second_store = store.clone();
        let stale_writer_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_called = stale_writer_called.clone();
        let second = std::thread::spawn(move || c2.commit_with_writer(&second_store, |commit| {
            second_called.store(true, Ordering::Release);
            commit.write()
        }));
        resume_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap(), Ok(()));
        assert!(save_done_rx.recv_timeout(Duration::from_secs(10)).unwrap(), "ordinary save completes after host I/O gate release");
        save_thread.join().unwrap();
        assert_eq!(second.join().unwrap(), Err(HostCommitError::Stale));
        assert!(!stale_writer_called.load(Ordering::Acquire), "stale snapshots never reach the writer");
        let reloaded = Trust::load(node, &dir).unwrap();
        let trust = store.lock().unwrap();
        assert!(trust.has_host_record(&g1) && reloaded.has_host_record(&g1));
        assert!(!trust.has_host_record(&g2) && !reloaded.has_host_record(&g2));
        assert_eq!(trust.host_access_roots(&h1.public_key_bytes(), &root), reloaded.host_access_roots(&h1.public_key_bytes(), &root));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn host_commit_rechecks_authority_and_rejects_a_different_store_before_io() {
        let (root_id, admin, holder, node) = (ident(), ident(), ident(), ident());
        let root = *root_id.hash();
        let mut issuer = tr(&root_id);
        let delegation = issuer.issue(root, admin.public_key_bytes(), ADD | REMOVE | USE).unwrap();
        let mut actor = tr(&admin);
        actor.add_anchor(&root_id.public_key_bytes()).unwrap();
        actor.offer(delegation.clone());
        let mut target = tr(&node);
        target.add_anchor(&root_id.public_key_bytes()).unwrap();
        target.allow_host_root(root, 8);
        target.offer(delegation);
        target.offer(issuer.issue(root, holder.public_key_bytes(), USE).unwrap());
        target.accept_host_access(issuer.sign_host_access(root, *node.hash(), admin.public_key_bytes(), true).unwrap()).unwrap();
        let grant = actor.sign_host_access(root, *node.hash(), holder.public_key_bytes(), true).unwrap();
        let wrong_store_commit = target.prepare_host_access(&grant).unwrap();
        assert_eq!(wrong_store_commit.commit(&Mutex::new(tr(&node))), Err(HostCommitError::Rejected("wrong_host_store")));

        let commit = target.prepare_host_access(&grant).unwrap();
        // Изменение обычной цепочки не увеличивает host_version, но запрещает применение старого prepare.
        target.offer(issuer.issue(root, admin.public_key_bytes(), 0).unwrap());
        let target = Mutex::new(target);
        let mut writer_called = false;
        assert_eq!(commit.commit_with_writer(&target, |_| {
            writer_called = true;
            Ok(())
        }), Err(HostCommitError::Rejected("authority_insufficient")));
        assert!(!writer_called);
        assert!(!target.lock().unwrap().has_host_record(&grant));
    }

    #[test]
    fn host_commit_flushes_unsaved_ordinary_issuer_chain_before_scoped_records() {
        let dir = host_tmp("host-prerequisite-flush");
        let (root_id, delegate, holder, target_id) = (ident(), ident(), ident(), ident());
        let root = *root_id.hash();
        std::fs::write(dir.join("host-policy.json"), format!(
            "{{\"v\":1,\"roots\":[{{\"root\":\"{}\",\"max_holders\":16}}]}}", hex(&root)
        )).unwrap();

        let mut root_trust = tr(&root_id);
        let delegation = root_trust.issue(root, delegate.public_key_bytes(), USE | ADD | REMOVE).unwrap();
        let holder_rec = root_trust.issue(root, holder.public_key_bytes(), USE).unwrap();
        let mut target = Trust::new(target_id.clone(), Some(dir.join("trust.json")));
        target.add_anchor(&root_id.public_key_bytes()).unwrap();
        target.allow_host_root(root, 16);
        assert_eq!(target.offer(holder_rec), Offer::Added);
        target.save().unwrap();

        // Mirrors accept_rec: the signed ordinary delegation is accepted in
        // memory, but the common two-second trust flush has not run.
        assert_eq!(target.offer(delegation.clone()), Offer::Added);
        let before_commit = Trust::load(target_id.clone(), &dir).unwrap();
        assert_eq!(before_commit.public_key_in(&root, delegate.hash()), None,
            "control: ordinary delegation is genuinely unsaved");

        let store = Mutex::new(target);
        let root_authority = root_trust.sign_host_access(root, *target_id.hash(), delegate.public_key_bytes(), true).unwrap();
        let root_commit = store.lock().unwrap().prepare_host_access(&root_authority).unwrap();
        root_commit.commit(&store).unwrap();
        let after_root_commit = Trust::load(target_id.clone(), &dir).expect(
            "root scoped host record must not outlive its unsaved ordinary issuer key"
        );
        assert_eq!(after_root_commit.rights_in(&root, delegate.hash()), USE | ADD | REMOVE);
        assert!(after_root_commit.has_host_authority(&root, delegate.hash(), target_id.hash()));

        let mut delegate_trust = tr(&delegate);
        delegate_trust.add_anchor(&root_id.public_key_bytes()).unwrap();
        assert_eq!(delegate_trust.offer(delegation), Offer::Added);
        let delegated_grant = delegate_trust.sign_host_access(root, *target_id.hash(), holder.public_key_bytes(), true).unwrap();
        let delegated_commit = store.lock().unwrap().prepare_host_access(&delegated_grant).unwrap();
        delegated_commit.commit(&store).unwrap();

        // Reload before any later/common save(): both ordinary signer chain and
        // root/delegate scoped records must already form a valid store.
        let reloaded = Trust::load(target_id.clone(), &dir).expect("delegated grant reloads before common flush");
        assert!(reloaded.has_host_authority(&root, delegate.hash(), target_id.hash()));
        assert_eq!(reloaded.host_access_roots(&holder.public_key_bytes(), target_id.hash()), vec![root]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lower_ranked_revoke_is_committed_but_not_effective() {
        let (root_id, admin, holder, target_id) = (ident(), ident(), ident(), ident());
        let root = *root_id.hash();
        let mut root_trust = tr(&root_id);
        let delegation = root_trust.issue(root, admin.public_key_bytes(), ADD | REMOVE | USE).unwrap();
        let holder_rec = root_trust.issue(root, holder.public_key_bytes(), USE).unwrap();
        let mut admin_trust = tr(&admin);
        admin_trust.add_anchor(&root_id.public_key_bytes()).unwrap();
        assert_eq!(admin_trust.offer(delegation.clone()), Offer::Added);
        let mut target = tr(&target_id);
        target.add_anchor(&root_id.public_key_bytes()).unwrap();
        target.allow_host_root(root, 8);
        assert_eq!(target.offer(delegation), Offer::Added);
        assert_eq!(target.offer(holder_rec), Offer::Added);
        let scope = *target_id.hash();
        target.accept_host_access(root_trust.sign_host_access(root, scope, admin.public_key_bytes(), true).unwrap()).unwrap();
        // корень выдал держателю доступ напрямую; делегат пытается отозвать - запись валидна, но глубина ниже
        target.accept_host_access(root_trust.sign_host_access(root, scope, holder.public_key_bytes(), true).unwrap()).unwrap();
        let revoke = admin_trust.sign_host_access(root, scope, holder.public_key_bytes(), false).unwrap();
        target.accept_host_access(revoke.clone()).unwrap();
        assert!(target.has_host_record(&revoke), "запись отзыва зафиксирована");
        assert_eq!(target.host_access_roots(&holder.public_key_bytes(), &scope), vec![root],
            "но эффективный доступ не изменился: выдача корня старше отзыва делегата");
    }

    #[test]
    fn founder_is_own_admin_and_nobody_elses() {
        let a = ident();
        let t = tr(&a);
        assert_eq!(t.my_rights_in(&t.me_hash), KNOWN);
        let stranger = ident();
        assert_eq!(t.rights(&stranger.public_key_bytes()), 0);
    }

    #[test]
    fn issue_and_subset_rule() {
        let a = ident();
        let b = ident();
        let c = ident();
        let mut ta = tr(&a);
        let root = ta.me_hash;
        ta.issue(root, b.public_key_bytes(), PRESET_RELAY).unwrap();
        assert_eq!(ta.rights(&b.public_key_bytes()), PRESET_RELAY);
        // другая нода видит ту же запись только если корень её якорь
        let mut tb = tr(&b);
        assert_eq!(tb.offer(ta.export_all()[0].clone()), Offer::Rejected("чужой корень"));
        tb.add_anchor(&a.public_key_bytes()).unwrap();
        assert_eq!(tb.offer(ta.export_all()[0].clone()), Offer::Added);
        assert_eq!(tb.my_rights_in(&root), PRESET_RELAY);
        // B может выдать подмножество: пользователю USE
        let rc = tb.issue(root, c.public_key_bytes(), USE).unwrap();
        // но не больше своих прав и не то, чего у него нет (REMOVE нет)
        assert!(tb.issue(root, c.public_key_bytes(), ALL).is_err());
        assert!(tb.issue(root, ident().public_key_bytes(), USE | CONFIG).is_err());
        assert!(tb.issue(root, c.public_key_bytes(), 0).is_err(), "REMOVE у B нет");
        // A принимает запись C от B: издатель B ему известен
        assert_eq!(ta.offer(rc), Offer::Added);
        assert_eq!(ta.rights(&c.public_key_bytes()), USE);
        // себе права не выдают
        assert!(ta.issue(root, a.public_key_bytes(), USE).is_err());
    }

    #[test]
    fn revoke_cascades_through_chain() {
        let (a, b, c) = (ident(), ident(), ident());
        let mut ta = tr(&a);
        let root = ta.me_hash;
        ta.issue(root, b.public_key_bytes(), PRESET_ADMIN).unwrap();
        let mut tb = tr(&b);
        tb.add_anchor(&a.public_key_bytes()).unwrap();
        for r in ta.export_all() {
            tb.offer(r);
        }
        let rc = tb.issue(root, c.public_key_bytes(), PRESET_USER).unwrap();
        ta.offer(rc);
        assert_eq!(ta.rights(&c.public_key_bytes()), USE);
        // корень отзывает B: выданное B теряет силу без отдельного отзыва
        ta.issue(root, b.public_key_bytes(), 0).unwrap();
        assert_eq!(ta.rights(&b.public_key_bytes()), 0);
        assert_eq!(ta.rights(&c.public_key_bytes()), 0, "каскад");
        // запись об отзыве не стирается (инвариант 13)
        assert!(ta.export_all().iter().any(|r| r.hh == hash_of(&b.public_key_bytes()).unwrap() && r.rights == 0));
    }

    #[test]
    fn subordinate_cannot_override_higher_authority() {
        let (a, b, x) = (ident(), ident(), ident());
        let mut ta = tr(&a);
        let root = ta.me_hash;
        ta.issue(root, b.public_key_bytes(), PRESET_ADMIN).unwrap();
        ta.issue(root, x.public_key_bytes(), PRESET_USER).unwrap();
        let mut tb = tr(&b);
        tb.add_anchor(&a.public_key_bytes()).unwrap();
        for r in ta.export_all() {
            tb.offer(r);
        }
        // B пытается отозвать X, которого выдал корень, и подписывает позже
        std::thread::sleep(Duration::from_millis(3));
        assert!(tb.issue(root, x.public_key_bytes(), 0).is_err(), "постпроверка не оставляет недействующий отзыв");
        // у B запись B->X побеждать не должна: корень ближе
        assert_eq!(tb.rights(&x.public_key_bytes()), USE, "запись корня сильнее подчинённого");
        assert_eq!(ta.rights(&x.public_key_bytes()), USE);
        // корень сам может отозвать
        ta.issue(root, x.public_key_bytes(), 0).unwrap();
        assert_eq!(ta.rights(&x.public_key_bytes()), 0);
    }

    #[test]
    fn result_does_not_depend_on_arrival_order() {
        let (a, b, c, d) = (ident(), ident(), ident(), ident());
        let mut ta = tr(&a);
        let root = ta.me_hash;
        ta.issue(root, b.public_key_bytes(), PRESET_ADMIN).unwrap();
        let mut tb = tr(&b);
        tb.add_anchor(&a.public_key_bytes()).unwrap();
        for r in ta.export_all() {
            tb.offer(r);
        }
        tb.issue(root, c.public_key_bytes(), PRESET_USER).unwrap();
        tb.issue(root, d.public_key_bytes(), USE | EXIT).unwrap();
        std::thread::sleep(Duration::from_millis(3));
        ta.issue(root, c.public_key_bytes(), 0).unwrap();
        let mut all = tb.export_all();
        all.extend(ta.export_all());
        let expect = |t: &Trust| (t.rights(&b.public_key_bytes()), t.rights(&c.public_key_bytes()), t.rights(&d.public_key_bytes()));
        let mut results = Vec::new();
        for shift in 0..all.len() {
            let mut t = tr(&ident());
            t.add_anchor(&a.public_key_bytes()).unwrap();
            let mut rec = all.clone();
            rec.rotate_left(shift);
            // порядок прихода любой: недошедшие из-за неизвестного издателя досылаются повтором
            for _ in 0..4 {
                for r in rec.clone() {
                    t.offer(r);
                }
            }
            results.push(expect(&t));
        }
        let first = results[0];
        assert!(results.iter().all(|r| *r == first), "{results:?}");
        assert_eq!(first, (ALL, 0, USE | EXIT));
    }

    #[test]
    fn forged_and_foreign_records_rejected() {
        let (a, b, evil) = (ident(), ident(), ident());
        let mut ta = tr(&a);
        let root = ta.me_hash;
        // подпись левого ключа за корень
        let forged = Record::sign(&evil, root, b.public_key_bytes(), ALL, 1).unwrap();
        assert_eq!(ta.offer(forged), Offer::Rejected("неизвестный издатель"));
        // издатель известен, но подпись чужая: подменили issuer
        ta.issue(root, b.public_key_bytes(), PRESET_ADMIN).unwrap();
        let mut f2 = Record::sign(&evil, root, ident().public_key_bytes(), USE, 9).unwrap();
        f2.issuer = *b.hash();
        assert_eq!(ta.offer(f2), Offer::Rejected("подпись"));
        // издатель-самозванец с известным ключом, но без права: запись принята как данные, права не дают
        let (c, d) = (ident(), ident());
        let ac = Record::sign(&b, root, c.public_key_bytes(), USE, 5).unwrap(); // у B есть ADD
        ta.offer(ac);
        assert_eq!(ta.rights(&c.public_key_bytes()), USE);
        ta.issue(root, b.public_key_bytes(), PRESET_USER).unwrap(); // B понижен до пользователя
        assert_eq!(ta.rights(&c.public_key_bytes()), 0, "после понижения B запись C недействительна");
        let bd = Record::sign(&b, root, d.public_key_bytes(), USE, 9).unwrap();
        ta.offer(bd);
        assert_eq!(ta.rights(&d.public_key_bytes()), 0, "у пользователя нет ADD");
    }

    #[test]
    fn record_is_bound_to_its_root() {
        // B админ в сетях A и Z. Запись «X получает USE», подписанная B для корня A, не должна работать в Z
        let (a, z, b, x) = (ident(), ident(), ident(), ident());
        let mut ta = tr(&a);
        let mut tz = tr(&z);
        ta.issue(ta.me_hash, b.public_key_bytes(), PRESET_ADMIN).unwrap();
        tz.issue(tz.me_hash, b.public_key_bytes(), PRESET_ADMIN).unwrap();
        let rec = Record::sign(&b, *a.hash(), x.public_key_bytes(), USE, 7).unwrap();
        ta.offer(rec.clone());
        assert_eq!(ta.rights(&x.public_key_bytes()), USE);
        tz.add_anchor(&a.public_key_bytes()).unwrap();
        // нода Z признаёт и корень A, но права X там зависят от цепочки в A, где у Z нет записи B
        assert_eq!(tz.offer(rec), Offer::Rejected("неизвестный издатель"));
        assert_eq!(tz.rights(&x.public_key_bytes()), 0);
    }

    #[test]
    fn two_anchors_union_and_isolation() {
        // моя identity: корень в своей сети и пользователь в чужой
        let (me, admin_b, u) = (ident(), ident(), ident());
        let mut tme = tr(&me);
        let mut tb = tr(&admin_b);
        tb.issue(tb.me_hash, me.public_key_bytes(), PRESET_USER).unwrap();
        tme.add_anchor(&admin_b.public_key_bytes()).unwrap();
        for r in tb.export_all() {
            tme.offer(r);
        }
        assert_eq!(tme.my_rights_in(&tme.me_hash), KNOWN, "в своей сети я админ (корень включает известный бит HOST_ACCESS)");
        assert_eq!(tme.my_rights_in(&admin_b.hash().clone()), USE, "в чужой - пользователь");
        // выдавать в чужой сети я не могу
        assert!(tme.issue(*admin_b.hash(), u.public_key_bytes(), USE).is_err());
        // а в своей могу и даже могу добавить его админа пользователем
        tme.issue(tme.me_hash, admin_b.public_key_bytes(), PRESET_USER).unwrap();
        assert_eq!(tme.rights_in(&tme.me_hash, admin_b.hash()), USE);
        // в объединении по якорям B остаётся админом собственного дерева
        assert_eq!(tme.rights(&admin_b.public_key_bytes()), KNOWN);
    }

    #[test]
    fn limits_hold() {
        let a = ident();
        let mut t = tr(&a);
        let root = t.me_hash;
        for _ in 0..MAX_RECS_PER_ROOT {
            t.issue(root, ident().public_key_bytes(), USE).unwrap();
        }
        assert!(t.issue(root, ident().public_key_bytes(), USE).is_err(), "корень заполнен");
        let mut t2 = tr(&ident());
        for _ in 0..MAX_ROOTS - 1 {
            t2.add_anchor(&ident().public_key_bytes()).unwrap();
        }
        assert!(t2.add_anchor(&ident().public_key_bytes()).is_err());
        // seq из будущего
        let (x, y) = (ident(), ident());
        let far = Record::sign(&x, *x.hash(), y.public_key_bytes(), USE, now_ms() as u64 + 30 * 24 * 3600 * 1000).unwrap();
        let mut tx = tr(&x);
        assert_eq!(tx.offer(far), Offer::Rejected("seq из будущего"));
    }

    #[test]
    fn persistence_roundtrip_with_chain() {
        let dir = std::env::temp_dir().join(format!("knothop-trust-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b, c, me) = (ident(), ident(), ident(), ident());
        let mut ta = tr(&a);
        let root = ta.me_hash;
        ta.issue(root, b.public_key_bytes(), PRESET_ADMIN).unwrap();
        ta.issue(root, me.public_key_bytes(), PRESET_RELAY).unwrap();
        let mut tb = tr(&b);
        tb.add_anchor(&a.public_key_bytes()).unwrap();
        for r in ta.export_all() {
            tb.offer(r);
        }
        let rc = tb.issue(root, c.public_key_bytes(), USE).unwrap();
        let mut t = Trust::new(me.clone(), Some(dir.join("trust.json")));
        t.add_anchor(&a.public_key_bytes()).unwrap();
        for r in ta.export_all() {
            t.offer(r);
        }
        t.offer(rc);
        t.save().unwrap();
        let t2 = Trust::load(me.clone(), &dir).unwrap();
        assert_eq!(t2.anchors().len(), 2);
        assert_eq!(t2.rights(&c.public_key_bytes()), USE);
        assert_eq!(t2.my_rights_in(&root), PRESET_RELAY);
        assert_eq!(t2.record_count(), t.record_count());
        // повреждённый файл не принимается молча (S4): ошибка загрузки, а не пустое состояние
        std::fs::write(dir.join("trust.json"), br#"{"v":1,"anchors":[],"recs":["00"]}"#).unwrap();
        assert!(Trust::load(me, &dir).is_err(), "мусорная запись роняет загрузку");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_and_exports_by_rights() {
        let (a, b, ex, u, me) = (ident(), ident(), ident(), ident(), ident());
        let mut ta = tr(&a);
        let root = ta.me_hash;
        ta.issue(root, b.public_key_bytes(), PRESET_ADMIN).unwrap();
        ta.issue(root, ex.public_key_bytes(), PRESET_RELAY).unwrap();
        ta.issue(root, u.public_key_bytes(), PRESET_USER).unwrap();
        ta.issue(root, me.public_key_bytes(), PRESET_USER).unwrap();
        // EXIT есть у реле и у админа (ALL)
        let mut exits = vec![ex.public_key_bytes(), b.public_key_bytes()];
        exits.sort();
        assert_eq!(ta.holders_with(EXIT), exits);
        // клиент с одним USE видит выходы и себя, но не чужих пользователей
        let for_user = ta.export_for(USE, &me.public_key_bytes());
        let hs: Vec<Hash> = for_user.iter().map(|r| r.hh).collect();
        assert!(hs.contains(&hash_of(&ex.public_key_bytes()).unwrap()));
        assert!(hs.contains(&hash_of(&me.public_key_bytes()).unwrap()));
        assert!(!hs.contains(&hash_of(&u.public_key_bytes()).unwrap()));
        // реле видит всё
        assert_eq!(ta.export_for(PRESET_RELAY, &ex.public_key_bytes()).len(), 4);
        // цепочка человека с делегированным издателем содержит запись издателя первой
        let mut tb = tr(&b);
        tb.add_anchor(&a.public_key_bytes()).unwrap();
        for r in ta.export_all() {
            tb.offer(r);
        }
        let ru = tb.issue(root, ident().public_key_bytes(), USE).unwrap();
        ta.offer(ru.clone());
        let ch = ta.chain_for(&ru.holder);
        assert_eq!(ch.len(), 2);
        assert_eq!(ch[0].hh, hash_of(&b.public_key_bytes()).unwrap());
        assert_eq!(ch[1], ru);
    }

    #[test]
    fn root_scoped_record_visibility_preserves_use_chains_and_blocks_foreign_root_export() {
        let (root_r, root_s, delegate, exit, user, sibling, sender) =
            (ident(), ident(), ident(), ident(), ident(), ident(), ident());
        let r = *root_r.hash();
        let s = *root_s.hash();

        let mut issuer_r = tr(&root_r);
        let delegate_rec = issuer_r.issue(r, delegate.public_key_bytes(), USE | ADD | REMOVE).unwrap();
        let exit_rec = issuer_r.issue(r, exit.public_key_bytes(), PRESET_RELAY).unwrap();
        let user_rec = issuer_r.issue(r, user.public_key_bytes(), PRESET_USER).unwrap();
        let sibling_rec = issuer_r.issue(r, sibling.public_key_bytes(), PRESET_USER).unwrap();
        let mut delegate_trust = tr(&delegate);
        delegate_trust.add_anchor(&root_r.public_key_bytes()).unwrap();
        for rec in issuer_r.export_all() { assert_eq!(delegate_trust.offer(rec), Offer::Added); }
        let late_user = ident();
        let late_rec = delegate_trust.issue(r, late_user.public_key_bytes(), PRESET_USER).unwrap();

        let mut issuer_s = tr(&root_s);
        let foreign_rec = issuer_s.issue(s, ident().public_key_bytes(), PRESET_ADMIN).unwrap();

        // This Trust store represents a multi-root node that forwards records
        // to the delegated client. The peer has admin rights only in R.
        let mut source = tr(&sender);
        source.add_anchor(&root_r.public_key_bytes()).unwrap();
        source.add_anchor(&root_s.public_key_bytes()).unwrap();
        for rec in [delegate_rec.clone(), exit_rec.clone(), user_rec.clone(), sibling_rec.clone()] {
            assert_eq!(source.offer(rec), Offer::Added);
        }
        assert_eq!(source.offer(foreign_rec.clone()), Offer::Added);

        let before_late = source.records_visible_to(&delegate.public_key_bytes());
        assert!(!before_late.contains(&late_rec), "late ordinary record is not in the initial snapshot");
        assert_eq!(source.offer(late_rec.clone()), Offer::Added, "late T_REC is accepted after client admission");
        let admin_snapshot = source.records_visible_to(&delegate.public_key_bytes());
        let admin_keys: HashSet<(Hash, Hash, Hash)> = admin_snapshot.iter().map(|x| (x.root, x.hh, x.issuer)).collect();
        assert!(admin_keys.contains(&(r, user_rec.hh, user_rec.issuer)), "ADD peer sees ordinary holder in its root");
        assert!(admin_keys.contains(&(r, late_rec.hh, late_rec.issuer)), "late accepted T_REC is visible to ADD peer");
        assert!(!admin_keys.contains(&(s, foreign_rec.hh, foreign_rec.issuer)), "ADD in R must not export foreign-root S");
        assert!(source.record_visible_to(&late_rec, &delegate.public_key_bytes()), "live predicate matches snapshot");
        assert!(!source.record_visible_to(&foreign_rec, &delegate.public_key_bytes()), "live predicate is root-scoped");
        assert_eq!(source.records_visible_to(&delegate.public_key_bytes()), admin_snapshot, "reconnect snapshot is deterministic");
        let late_pos = admin_snapshot.iter().position(|x| x == &late_rec).unwrap();
        let issuer_pos = admin_snapshot.iter().position(|x| x == &delegate_rec).unwrap();
        assert!(issuer_pos < late_pos, "issuer record remains before its delegated holder record");

        let user_snapshot = source.records_visible_to(&user.public_key_bytes());
        let user_keys: HashSet<(Hash, Hash, Hash)> = user_snapshot.iter().map(|x| (x.root, x.hh, x.issuer)).collect();
        assert!(user_keys.contains(&(r, user_rec.hh, user_rec.issuer)), "USE peer gets its own chain");
        assert!(user_keys.contains(&(r, exit_rec.hh, exit_rec.issuer)), "USE peer gets EXIT chain");
        assert!(!user_keys.contains(&(r, sibling_rec.hh, sibling_rec.issuer)), "USE peer does not get sibling users");
        assert!(!user_keys.contains(&(r, delegate_rec.hh, delegate_rec.issuer)), "USE peer does not get unrelated admin record");
        assert!(!user_keys.contains(&(s, foreign_rec.hh, foreign_rec.issuer)), "USE peer does not get foreign-root records");
        assert!(!source.record_visible_to(&late_rec, &user.public_key_bytes()), "live USE predicate matches privacy filter");

        // Legacy scalar API intentionally remains for enrollment callers; this
        // assertion documents why it must not replace the root-scoped API.
        assert!(source.export_for(ADD, &delegate.public_key_bytes()).contains(&foreign_rec));

        // The former administrator must still receive its OWN signed revoke.
        // Losing privileges must hide sibling/EXIT records, not hide its own tombstone.
        let revoked = issuer_r.issue(r, delegate.public_key_bytes(), 0).unwrap();
        assert_eq!(source.offer(revoked.clone()), Offer::Added);
        assert!(source.record_visible_to(&revoked, &delegate.public_key_bytes()), "live sync must not hide the peer's own revoke");
        let revoked_snapshot = source.records_visible_to(&delegate.public_key_bytes());
        assert!(revoked_snapshot.contains(&revoked));
        assert!(!revoked_snapshot.contains(&user_rec));
        assert!(!revoked_snapshot.contains(&exit_rec));
        assert!(!revoked_snapshot.contains(&foreign_rec));
    }

    #[test]
    fn common_rights_are_checked_inside_one_root() {
        let (a, r1, r2, u) = (ident(), ident(), ident(), ident());
        let mut ta = tr(&a);
        let root = ta.me_hash;
        ta.issue(root, r1.public_key_bytes(), PRESET_RELAY).unwrap();
        ta.issue(root, r2.public_key_bytes(), PRESET_RELAY).unwrap();
        ta.issue(root, u.public_key_bytes(), PRESET_USER).unwrap();
        // админ и реле видят друг друга транзитом; пользователь - нет
        assert!(ta.common(&r1.public_key_bytes(), TRANSIT, TRANSIT));
        assert!(!ta.common(&u.public_key_bytes(), TRANSIT, TRANSIT));
        // выход для клиента: у меня EXIT, у него USE
        assert!(ta.common(&u.public_key_bytes(), EXIT, USE));
        // реле r1 с точки зрения своего дерева: админ a - корень (ALL), r2 в нём тоже реле
        let mut t1 = tr(&r1);
        t1.add_anchor(&a.public_key_bytes()).unwrap();
        for r in ta.export_all() {
            t1.offer(r);
        }
        assert!(t1.common(&r2.public_key_bytes(), TRANSIT, TRANSIT));
        assert!(t1.common(&a.public_key_bytes(), TRANSIT, TRANSIT));
        // чужой, которого в деревьях нет
        assert!(!t1.common(&ident().public_key_bytes(), TRANSIT, TRANSIT));
        // права в чужих деревьях не складываются: пользователь без записей в моём корне ни с кем не общий
        let mut tu = tr(&u);
        tu.add_anchor(&a.public_key_bytes()).unwrap();
        for r in ta.export_all() {
            tu.offer(r);
        }
        assert!(!tu.common(&r1.public_key_bytes(), TRANSIT, TRANSIT));
        assert!(tu.common(&r1.public_key_bytes(), USE, EXIT));
    }

















    #[test]
    fn issue_requires_add_subset_and_depth_budget() {
        let root_id = ident(); let root = *root_id.hash(); let target = ident();
        let mut root_trust = tr(&root_id);
        let no_add = ident();
        root_trust.issue(root, no_add.public_key_bytes(), USE).unwrap();
        let mut user = tr(&no_add); user.add_anchor(&root_id.public_key_bytes()).unwrap();
        for r in root_trust.export_all() { user.offer(r); }
        assert!(user.issue(root, target.public_key_bytes(), USE).unwrap_err().to_string().contains("ADD"));
        assert_eq!(root_trust.rights_in(&root, &hash_of(&target.public_key_bytes()).unwrap()), 0);
        let with_add = ident(); root_trust.issue(root, with_add.public_key_bytes(), USE | ADD).unwrap();
        let mut limited = tr(&with_add); limited.add_anchor(&root_id.public_key_bytes()).unwrap();
        for r in root_trust.export_all() { limited.offer(r); }
        assert!(limited.issue(root, target.public_key_bytes(), ALL).unwrap_err().to_string().contains("подмножество"), "права шире своих");

        let chain: Vec<Identity> = (0..8).map(|_| ident()).collect();
        root_trust.issue(root, chain[0].public_key_bytes(), ALL).unwrap();
        for i in 1..8 {
            let mut issuer = tr(&chain[i - 1]); issuer.add_anchor(&root_id.public_key_bytes()).unwrap();
            for r in root_trust.export_all() { issuer.offer(r); }
            let rec = issuer.issue(root, chain[i].public_key_bytes(), ALL).unwrap();
            root_trust.offer(rec);
            assert_eq!(root_trust.depth_in(&root, &hash_of(&chain[i].public_key_bytes()).unwrap()), Some((i + 1) as u8));
        }
        let mut deepest = tr(chain.last().unwrap()); deepest.add_anchor(&root_id.public_key_bytes()).unwrap();
        for r in root_trust.export_all() { deepest.offer(r); }
        let e = deepest.issue(root, ident().public_key_bytes(), USE).unwrap_err().to_string();
        assert!(e.contains("глубин"), "понятная ошибка глубины: {e}");
    }





    #[test]
    fn tags_cover_all_anchors() {
        let (me, other) = (ident(), ident());
        let mut t = tr(&me);
        assert_eq!(t.tags(), vec![root_tag(me.hash())]);
        t.add_anchor(&other.public_key_bytes()).unwrap();
        let tags = t.tags();
        assert_eq!(tags.len(), 2);
        assert!(tags.contains(&root_tag(other.hash())));
        assert_eq!(root_tag(me.hash()).len(), 12);
    }

    /// H2: отзыв издателя с REMOVE на той же глубине, что и выдача издателя с ADD, побеждает независимо от seq и порядка прихода.
    #[test]
    fn same_level_revoke_beats_later_grant() {
        let (a, b, r, x) = (ident(), ident(), ident(), ident());
        let mut ta = tr(&a);
        let root = ta.me_hash;
        ta.issue(root, b.public_key_bytes(), USE | ADD | REMOVE).unwrap();
        ta.issue(root, r.public_key_bytes(), USE | ADD).unwrap();
        let mut tb = tr(&b);
        tb.add_anchor(&a.public_key_bytes()).unwrap();
        for rec in ta.export_all() {
            tb.offer(rec);
        }
        let rev = tb.issue(root, x.public_key_bytes(), 0).unwrap();
        std::thread::sleep(Duration::from_millis(3));
        let mut tq = tr(&r);
        tq.add_anchor(&a.public_key_bytes()).unwrap();
        for rec in ta.export_all() {
            tq.offer(rec);
        }
        let grant = tq.issue(root, x.public_key_bytes(), USE).unwrap();
        assert!(grant.seq > rev.seq);
        let base = ta.export_all();
        let eval = |extra: Vec<Record>| {
            let mut t = tr(&ident());
            t.add_anchor(&a.public_key_bytes()).unwrap();
            let mut all = base.clone();
            all.extend(extra);
            for _ in 0..3 {
                for rec in all.clone() {
                    t.offer(rec);
                }
            }
            t.rights(&x.public_key_bytes())
        };
        assert_eq!(eval(vec![rev.clone(), grant.clone()]), 0);
        assert_eq!(eval(vec![grant.clone(), rev.clone()]), 0, "порядок прихода не меняет итог");
        // корень сильнее обоих: его выдача возвращает права
        ta.offer(rev);
        ta.offer(grant);
        assert_eq!(ta.rights(&x.public_key_bytes()), 0);
        ta.issue(root, x.public_key_bytes(), USE).unwrap();
        assert_eq!(ta.rights(&x.public_key_bytes()), USE);
    }

    /// H1: участник с одним USE подписывает сверх квоты и заполняет корень; законная выдача корнем всё равно проходит.
    #[test]
    fn user_flood_does_not_block_root_issue() {
        let a = ident();
        let mut ta = tr(&a);
        let root = ta.me_hash;
        let members: Vec<Identity> = (0..8).map(|_| ident()).collect();
        for m in &members {
            ta.issue(root, m.public_key_bytes(), PRESET_USER).unwrap();
        }
        let seq = now_ms() as u64;
        // общий пул держателей (ключи и подписи дорогие в debug): у каждого издателя свои 120 различных, квота 64 превышена
        let pool: Vec<Pk> = (0..120).map(|_| ident().public_key_bytes()).collect();
        for m in &members {
            for (j, h) in pool.iter().enumerate() {
                let _ = ta.offer(Record::sign(m, root, *h, USE, seq + j as u64).unwrap());
            }
            assert!(ta.issuer_count(&root, m.hash()) <= MAX_RECS_PER_ISSUER, "квота издателя");
        }
        assert_eq!(ta.record_count(), MAX_RECS_PER_ROOT, "корень заполнен, вытеснение работает");
        let l = ident();
        ta.issue(root, l.public_key_bytes(), USE).expect("законная выдача корнем проходит");
        assert_eq!(ta.rights(&l.public_key_bytes()), USE);
        assert_eq!(ta.rights(&pool[0]), 0, "выдачи без ADD не действуют");
    }

    /// H1: «отзывы» от участников без REMOVE тоже вытесняются - иначе корень забивается ими.
    #[test]
    fn user_revoke_flood_does_not_block_root_issue() {
        let a = ident();
        let mut ta = tr(&a);
        let root = ta.me_hash;
        let members: Vec<Identity> = (0..8).map(|_| ident()).collect();
        for m in &members {
            ta.issue(root, m.public_key_bytes(), PRESET_USER).unwrap();
        }
        let seq = now_ms() as u64;
        let pool: Vec<Pk> = (0..120).map(|_| ident().public_key_bytes()).collect();
        for m in &members {
            for (j, h) in pool.iter().enumerate() {
                let _ = ta.offer(Record::sign(m, root, *h, 0, seq + j as u64).unwrap());
            }
        }
        let l = ident();
        ta.issue(root, l.public_key_bytes(), USE).expect("законная выдача корнем проходит и после потока «отзывов»");
        assert_eq!(ta.rights(&l.public_key_bytes()), USE);
    }

    /// H1: вытеснение не трогает выдачи действующего подчинённого админа.
    #[test]
    fn eviction_keeps_valid_subordinate_records() {
        let a = ident();
        let mut ta = tr(&a);
        let root = ta.me_hash;
        let b = ident();
        ta.issue(root, b.public_key_bytes(), PRESET_RELAY).unwrap();
        let kept = ident();
        let seq = now_ms() as u64;
        assert_eq!(ta.offer(Record::sign(&b, root, kept.public_key_bytes(), USE, seq).unwrap()), Offer::Added);
        let pool: Vec<Pk> = (0..120).map(|_| ident().public_key_bytes()).collect();
        for _ in 0..8 {
            let m = ident();
            ta.issue(root, m.public_key_bytes(), PRESET_USER).unwrap();
            for (j, h) in pool.iter().enumerate() {
                let _ = ta.offer(Record::sign(&m, root, *h, USE, seq + j as u64).unwrap());
            }
        }
        assert_eq!(ta.record_count(), MAX_RECS_PER_ROOT);
        assert_eq!(ta.rights(&kept.public_key_bytes()), USE, "запись действующего админа не вытеснена");
    }

    /// H1: запись, отвергнутая квотой, не должна менять итог при повторной доставке.
    #[test]
    fn quota_rejects_without_side_effects() {
        let a = ident();
        let mut ta = tr(&a);
        let root = ta.me_hash;
        let m = ident();
        ta.issue(root, m.public_key_bytes(), PRESET_USER).unwrap();
        let seq = now_ms() as u64;
        for j in 0..MAX_RECS_PER_ISSUER as u64 {
            assert_eq!(ta.offer(Record::sign(&m, root, ident().public_key_bytes(), USE, seq + j).unwrap()), Offer::Added);
        }
        let extra = Record::sign(&m, root, ident().public_key_bytes(), USE, seq).unwrap();
        assert_eq!(ta.offer(extra), Offer::Rejected("квота издателя исчерпана"));
        assert_eq!(ta.issuer_count(&root, m.hash()), MAX_RECS_PER_ISSUER);
    }

    /// S4: повреждённая подпись отзыва не должна вернуть права: загрузка падает целиком.
    #[test]
    fn load_fails_closed_on_broken_revoke() {
        let dir = std::env::temp_dir().join(format!("knothop-trust-fc-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b, x) = (ident(), ident(), ident());
        let mut ta = Trust::new(a.clone(), Some(dir.join("trust.json")));
        let root = ta.me_hash;
        ta.issue(root, b.public_key_bytes(), PRESET_ADMIN).unwrap();
        let mut tb = tr(&b);
        tb.add_anchor(&a.public_key_bytes()).unwrap();
        for rec in ta.export_all() {
            tb.offer(rec);
        }
        ta.offer(tb.issue(root, x.public_key_bytes(), USE).unwrap());
        ta.issue(root, x.public_key_bytes(), 0).unwrap();
        ta.save().unwrap();
        assert_eq!(Trust::load(a.clone(), &dir).unwrap().rights(&x.public_key_bytes()), 0);
        // портим подпись только у отзыва
        let p = dir.join("trust.json");
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let recs: Vec<serde_json::Value> = v["recs"].as_array().unwrap().iter().map(|s| {
            let mut b = unhex(s.as_str().unwrap());
            if Record::parse(&b).unwrap().rights == 0 {
                b[REC_LEN - 1] ^= 1;
            }
            serde_json::Value::String(hex(&b))
        }).collect();
        v["recs"] = serde_json::Value::Array(recs);
        std::fs::write(&p, v.to_string()).unwrap();
        assert!(Trust::load(a.clone(), &dir).err().is_some(), "повреждённый отзыв роняет загрузку, права не восстанавливаются");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S6: файлы состояния 0600, каталог pin 0700.
    #[cfg(unix)]


    /// S1: восемь держателей стартуют одновременно с одним pin: ровно один получает New, остальные Spent.


    /// H8: если выдача после New не удалась, pin возвращается; откат чужим держателем не действует.


    /// Погашенный pin помнится в пределах срока (повтор держателя), после срока уборка его убирает.




    #[cfg(unix)]


    // ----------------------------------------------------------------- политика (0015)

    /// Сеть: админ A (корень), реле R (USE+TRANSIT+EXIT+ADD), пользователь U (USE). Все знают всех.
    fn net() -> (Identity, Identity, Identity, Trust, Hash) {
        let (a, r, u) = (ident(), ident(), ident());
        let mut ta = tr(&a);
        let root = ta.me_hash;
        ta.issue(root, r.public_key_bytes(), PRESET_RELAY).unwrap();
        ta.issue(root, u.public_key_bytes(), PRESET_USER).unwrap();
        (a, r, u, ta, root)
    }

    fn view(me: &Identity, a: &Identity, ta: &Trust) -> Trust {
        let mut t = tr(me);
        t.add_anchor(&a.public_key_bytes()).unwrap();
        for r in ta.export_all() {
            t.offer(r);
        }
        t
    }

    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn policy_roundtrip_and_tamper() {
        let h = ident();
        let root = [7u8; 16];
        let p = Policy::sign(&h, root, USE | EXIT, 5, NOW).unwrap();
        let w = p.wire();
        assert_eq!(w.len(), POL_LEN);
        let q = Policy::parse(&w).unwrap();
        assert_eq!(q, p);
        assert!(q.sig_ok());
        for i in [1usize, 3, 11, 19, 35] {
            let mut x = w.clone();
            x[i] ^= 1;
            if let Some(t) = Policy::parse(&x) {
                assert!(!t.sig_ok(), "бит {i} должен ломать подпись");
            }
        }
        let mut bad = w.clone();
        bad[1] = 0xff;
        bad[2] = 0xff;
        assert!(Policy::parse(&bad).is_none(), "лишние биты прав не разбираются");
        assert!(Policy::parse(&w[..w.len() - 1]).is_none());
    }

    #[test]
    fn policy_only_narrows_the_grant() {
        let (a, r, u, mut ta, root) = net();
        // без политики действует выдача целиком (нода без поддержки 0015)
        assert_eq!(ta.effective(&r.public_key_bytes(), NOW), PRESET_RELAY);
        // реле отказывается от EXIT и TRANSIT
        let mut tr_ = view(&r, &a, &ta);
        let pol = tr_.set_my_policy(root, USE | ADD, NOW).unwrap();
        assert_eq!(ta.offer_policy(pol, NOW), Offer::Added);
        assert_eq!(ta.effective(&r.public_key_bytes(), NOW), USE | ADD);
        assert!(ta.holders_with(EXIT).contains(&r.public_key_bytes()), "выдача сама не меняется");
        // пользователь просит всё: получает только свою выдачу
        let mut tu = view(&u, &a, &ta);
        let pol = tu.set_my_policy(root, ALL, NOW).unwrap();
        assert_eq!(ta.offer_policy(pol, NOW), Offer::Added);
        assert_eq!(ta.effective(&u.public_key_bytes(), NOW), USE);
        assert_eq!(ta.effective_in(&root, &hash_of(&u.public_key_bytes()).unwrap(), NOW) & (ADD | REMOVE | CONFIG | EXIT | TRANSIT), 0);
    }

    #[test]
    fn common_with_honours_own_refusal_but_checks_peer_by_grant() {
        let (a, r, u, ta, root) = net();
        let mut tr_ = view(&r, &a, &ta);
        let up = u.public_key_bytes();
        assert!(tr_.common_with(&up, EXIT, USE, true, false, NOW));
        let pol = tr_.set_my_policy(root, USE | TRANSIT, NOW).unwrap();
        assert!(!tr_.common_with(&up, EXIT, USE, true, false, NOW), "я отказалась от EXIT");
        assert!(tr_.common_with(&up, EXIT, USE, false, false, NOW), "по выдаче EXIT у меня остался");
        // клиент отказавшегося выхода не выбирает
        let mut tu = view(&u, &a, &ta);
        tu.offer_policy(pol, NOW);
        assert!(!tu.common_with(&r.public_key_bytes(), USE, EXIT, false, true, NOW));
        assert!(tu.common_with(&r.public_key_bytes(), USE, EXIT, false, false, NOW));
    }

    #[test]
    fn founder_toggles_own_bits_freely() {
        let a = ident();
        let mut ta = tr(&a);
        let root = ta.me_hash;
        let pol = ta.set_my_policy(root, EXIT, NOW).unwrap();
        assert_eq!(pol.offer, EXIT);
        assert_eq!(ta.effective(&a.public_key_bytes(), NOW), EXIT);
        ta.set_my_policy(root, ALL, NOW + 1).unwrap();
        // политика покрывает только шесть сетевых битов; HOST_ACCESS (64) задан узловой записью, а не офертой
        assert_eq!(ta.effective(&a.public_key_bytes(), NOW + 1), ALL);
        assert_eq!(ta.my_policy_offer(&root), Some(ALL));
    }

    #[test]
    fn policy_rejections() {
        let (a, r, u, ta, root) = net();
        let mut t = view(&u, &a, &ta);
        let mk = |id: &Identity, root: Hash, seq: u64, vu: u64| Policy::sign(id, root, USE, seq, vu).unwrap();
        // чужой корень
        assert_eq!(t.offer_policy(mk(&r, [9u8; 16], NOW, NOW + 1000), NOW), Offer::Rejected("чужой корень"));
        // неизвестный держатель
        assert_eq!(t.offer_policy(mk(&ident(), root, NOW, NOW + 1000), NOW), Offer::Rejected("неизвестный держатель"));
        // seq из будущего, истекла, слишком длинный срок
        assert_eq!(t.offer_policy(mk(&r, root, NOW + 3_600_000, NOW + 1000), NOW), Offer::Rejected("seq из будущего"));
        assert_eq!(t.offer_policy(mk(&r, root, NOW, NOW), NOW), Offer::Rejected("политика истекла"));
        assert_eq!(t.offer_policy(mk(&r, root, NOW, NOW + POLICY_TTL_MS + 3_600_000), NOW), Offer::Rejected("срок политики слишком велик"));
        // подпись: запись реле, но подписанная чужим ключом, с подставленным ключом реле
        let mut forged = mk(&u, root, NOW, NOW + 1000);
        forged.holder = r.public_key_bytes();
        forged.hh = hash_of(&forged.holder).unwrap();
        assert_eq!(t.offer_policy(forged, NOW), Offer::Rejected("подпись"));
        // отозванный (выдача 0) не может принять политику
        let mut ta2 = view(&a, &a, &ta);
        ta2.issue(root, u.public_key_bytes(), 0).unwrap();
        assert_eq!(ta2.offer_policy(mk(&u, root, NOW, NOW + 1000), NOW), Offer::Rejected("нет выдачи в корне"));
        assert_eq!(t.offer_policy(mk(&r, root, NOW, NOW + 1000), NOW), Offer::Added);
    }

    #[test]
    fn older_policy_cannot_roll_back_a_newer_one() {
        let (a, r, _u, mut ta, root) = net();
        let new = Policy::sign(&r, root, USE, NOW + 10, NOW + 1000).unwrap();
        let old = Policy::sign(&r, root, USE | EXIT, NOW + 5, NOW + 1000).unwrap();
        assert_eq!(ta.offer_policy(new, NOW), Offer::Added);
        assert_eq!(ta.offer_policy(old, NOW), Offer::Stale);
        assert_eq!(ta.effective(&r.public_key_bytes(), NOW), USE);
        let _ = a;
    }

    #[test]
    fn expired_policy_narrows_to_use_not_back_to_grant() {
        let (_a, r, _u, mut ta, root) = net();
        ta.offer_policy(Policy::sign(&r, root, USE | EXIT, NOW, NOW + 1000).unwrap(), NOW);
        assert_eq!(ta.effective(&r.public_key_bytes(), NOW + 500), USE | EXIT);
        assert_eq!(ta.effective(&r.public_key_bytes(), NOW + 1000), USE, "после срока - только USE");
        assert!(ta.export_policies(NOW + 1000).is_empty(), "просроченную не рассылаем");
    }

    #[test]
    fn revocation_voids_policy_and_prunes_it() {
        let (a, r, _u, mut ta, root) = net();
        ta.offer_policy(Policy::sign(&r, root, USE | EXIT, NOW, NOW + 1000).unwrap(), NOW);
        let _ = a;
        ta.issue(root, r.public_key_bytes(), 0).unwrap();
        assert_eq!(ta.effective(&r.public_key_bytes(), NOW), 0);
        ta.prune_policies();
        assert!(ta.pols.is_empty());
    }

    #[test]
    fn refresh_resigns_only_when_due_with_growing_seq() {
        let (a, r, _u, ta, root) = net();
        let mut t = view(&r, &a, &ta);
        assert!(t.refresh_my_policies(NOW).is_empty(), "настройки нет - подписывать нечего");
        let first = t.set_my_policy(root, USE | TRANSIT, NOW).unwrap();
        assert!(t.refresh_my_policies(NOW + POLICY_REFRESH_MS - 1).is_empty());
        let again = t.refresh_my_policies(NOW + POLICY_REFRESH_MS);
        assert_eq!(again.len(), 1);
        assert!(again[0].seq > first.seq);
        assert_eq!(again[0].offer, USE | TRANSIT);
        assert_eq!(again[0].valid_until, NOW + POLICY_REFRESH_MS + POLICY_TTL_MS);
    }

    #[test]
    fn hidden_nodes_are_not_shown_but_their_refusal_reaches_servers() {
        let (a, r, u, mut ta, root) = net();
        let w = ident();
        ta.issue(root, w.public_key_bytes(), USE | TRANSIT).unwrap();
        let admin_only = ident();
        ta.issue(root, admin_only.public_key_bytes(), ADD | REMOVE).unwrap(); // ни USE, ни TRANSIT, ни EXIT
        for id in [&r, &u, &w, &admin_only] {
            ta.offer_policy(Policy::sign(id, root, ALL, NOW, NOW + 1000).unwrap(), NOW);
        }
        assert!(!ta.visible(&admin_only.public_key_bytes(), NOW), "без USE/TRANSIT/EXIT нода скрыта");
        assert!(ta.visible(&u.public_key_bytes(), NOW));
        assert_eq!(ta.export_policies(NOW).len(), 4);
        // пользователь с одним USE: политики держателей выхода и своя; чужие пользователи и транзиты без EXIT - нет
        let for_u = ta.export_policies_for(USE, &u.public_key_bytes(), NOW);
        let hu: Vec<Hash> = for_u.iter().map(|p| p.hh).collect();
        assert!(hu.contains(&hash_of(&r.public_key_bytes()).unwrap()));
        assert!(hu.contains(&hash_of(&u.public_key_bytes()).unwrap()));
        assert!(!hu.contains(&hash_of(&w.public_key_bytes()).unwrap()));
        // реле получает все
        assert_eq!(ta.export_policies_for(PRESET_RELAY, &r.public_key_bytes(), NOW).len(), 4);
        // отказ от всего скрывает бывшее реле, и об этом узнают остальные серверы
        let off = Policy::sign(&r, root, 0, NOW + 1, NOW + 1000).unwrap();
        ta.offer_policy(off.clone(), NOW);
        assert!(!ta.visible(&r.public_key_bytes(), NOW));
        assert!(ta.export_policies_for(PRESET_RELAY, &w.public_key_bytes(), NOW).contains(&off));
        // отозванный не рассылается
        ta.issue(root, w.public_key_bytes(), 0).unwrap();
        assert!(ta.export_policies(NOW).iter().all(|p| p.hh != hash_of(&w.public_key_bytes()).unwrap()));
        let _ = a;
    }

    #[test]
    fn policies_and_own_setting_survive_restart_and_old_files_load() {
        let dir = std::env::temp_dir().join(format!("knothop-pol-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, r, _u, ta, root) = net();
        let rh = hash_of(&r.public_key_bytes()).unwrap();
        let mut t = Trust::new(r.clone(), Some(dir.join("trust.json")));
        t.add_anchor(&a.public_key_bytes()).unwrap();
        for x in ta.export_all() {
            t.offer(x);
        }
        t.set_my_policy(root, USE, NOW).unwrap();
        t.save().unwrap();
        let t2 = Trust::load(r.clone(), &dir).unwrap();
        assert_eq!(t2.my_policy_offer(&root), Some(USE));
        assert_eq!(t2.effective_in(&root, &rh, NOW), USE);
        // просроченная политика после перезапуска всё ещё сужает
        assert_eq!(t2.effective_in(&root, &rh, NOW + POLICY_TTL_MS + 1), USE);
        // файл прежнего формата (без pols/mypol) грузится
        let old = serde_json::json!({"v": 1, "anchors": [hex(&a.public_key_bytes())], "recs": ta.export_all().iter().map(|x| hex(&x.wire())).collect::<Vec<_>>()});
        std::fs::write(dir.join("trust.json"), serde_json::to_vec(&old).unwrap()).unwrap();
        let t3 = Trust::load(r.clone(), &dir).unwrap();
        assert_eq!(t3.effective_in(&root, &rh, NOW), PRESET_RELAY);
        // повреждённая политика не роняет загрузку и ничего не расширяет
        let mut bad = old.clone();
        bad["pols"] = serde_json::json!(["00ff"]);
        std::fs::write(dir.join("trust.json"), serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(Trust::load(r, &dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
