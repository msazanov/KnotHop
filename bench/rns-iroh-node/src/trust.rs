//! Модель доверия 0013 (docs/decisions/0013-peer-groups-and-rights.md): индивидуальные права на identity, якоря доверия,
//! подписанные записи с цепочкой до якоря, приглашения `rawgi-` с одноразовым pin.
//!
//! Модуль не знает про сеть: только данные, проверки и файлы состояния. Всё, что пришло от пира, здесь недоверенный ввод:
//! запись принимается лишь с верной подписью издателя, чей ключ уже известен, и под корнем, который нода сама признаёт якорем;
//! права же вычисляются при запросе по цепочке до корня, поэтому отзыв звена сразу обесценивает выданное им.

use super::*;
use hmac::{Hmac, Mac};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub const USE: u16 = 1;
pub const TRANSIT: u16 = 2;
pub const EXIT: u16 = 4;
pub const ADD: u16 = 8;
pub const REMOVE: u16 = 16;
pub const CONFIG: u16 = 32;
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
/// Не больше записей одного издателя в корне (кроме самого корня): одиночный участник не забивает хранилище (H1).
pub const MAX_RECS_PER_ISSUER: usize = 64;
pub const MAX_ROOTS: usize = 8;
pub const MAX_PINS: usize = 64;
/// Срок приглашения и неиспользованного pin: 30 дней (0014 R6, решение владельца).
pub const INVITE_TTL_S: u64 = 30 * 24 * 3600;
/// seq - время в мс; запись из далёкого будущего не принимаем (иначе издатель мог бы заранее занять свой слот).
const SEQ_FUTURE_MS: u64 = 10 * 60 * 1000;

pub fn rights_text(r: u16) -> String {
    if r == 0 {
        return "-".into();
    }
    let mut v = Vec::new();
    for (b, n) in [(USE, "USE"), (TRANSIT, "TRANSIT"), (EXIT, "EXIT"), (ADD, "ADD"), (REMOVE, "REMOVE"), (CONFIG, "CONFIG")] {
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
        if n & !ALL != 0 {
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
    let d = Sha256::digest([b"rawg-root-tag-v1".as_slice(), root].concat());
    hex(&d[..6])
}

fn hmac32(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
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

const REC_MSG: &[u8] = b"rawg-rec-v1";
const PAYLOAD_LEN: usize = 1 + 2 + 8 + 16 + 64 + 16;
pub const REC_LEN: usize = PAYLOAD_LEN + 64;

/// Подписанное утверждение «`issuer` даёт `holder` права `rights` в сети с корнем `root`».
/// payload: v(1)=1 | rights(2 LE) | seq(8 LE) | root(16) | holder(64) | issuer(16); подпись ed25519 над `rawg-rec-v1 || payload`.
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
        let hh = hash_of(&holder).ok_or_else(|| anyhow::anyhow!("ключ держателя не разобран"))?;
        let mut r = Record { rights, seq, root, holder, issuer: *issuer.hash(), sig: [0u8; 64], hh };
        let mut m = REC_MSG.to_vec();
        m.extend_from_slice(&r.payload());
        r.sig = issuer.sign(&m).map_err(|e| anyhow::anyhow!("подпись записи: {e:?}"))?;
        Ok(r)
    }

    /// Подписана ли запись этим ключом (для завершения зачисления: ключ админа ещё не в якорях).
    pub fn signed_by(&self, issuer_pk: &Pk) -> bool {
        self.sig_ok(issuer_pk)
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

const POL_MSG: &[u8] = b"rawg-pol-v1";
const POL_PAYLOAD_LEN: usize = 1 + 2 + 8 + 8 + 16 + 64;
pub const POL_LEN: usize = POL_PAYLOAD_LEN + 64;
/// Срок жизни политики (решение владельца 0015: 48 ч). Дольше срок не принимается.
pub const POLICY_TTL_MS: u64 = 48 * 3600 * 1000;
/// Источник переподписывает политику, когда ей больше этого возраста (0015: запас на два пропущенных обновления).
pub const POLICY_REFRESH_MS: u64 = 12 * 3600 * 1000;
/// Права, при наличии любого из которых нода видна другим (0015, п.4: остальные скрыты).
const VISIBLE_BITS: u16 = USE | TRANSIT | EXIT;

/// Подписанное самой нодой «что я согласна делать» в сети с корнем `root`. Только сужает выдачу: действующие права = выдача ∩ offer.
/// payload: v(1)=1 | offer(2 LE) | seq(8 LE) | valid_until(8 LE, мс) | root(16) | holder(64); подпись держателя над `rawg-pol-v1 || payload`.
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
        if offer & !ALL != 0 {
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
        if offer & !ALL != 0 {
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
    /// (корень, хеш) -> полный ключ: из записей, чтобы проверять подписи издателей
    holders: HashMap<(Hash, Hash), Pk>,
    /// (корень, хеш держателя) -> последняя политика (0015). Число ограничено числом известных держателей, то есть записями корня.
    /// Просроченные остаются: они сужают права до USE, а не возвращают выдачу целиком.
    pols: HashMap<(Hash, Hash), Policy>,
    /// что эта нода сама согласна делать в каждом корне (её собственная настройка; из неё подписывается и обновляется политика)
    my_offer: BTreeMap<Hash, u16>,
}

impl Trust {
    pub fn new(me: Identity, path: Option<PathBuf>) -> Trust {
        let me_pk = me.public_key_bytes();
        let me_hash = *me.hash();
        let mut anchors = BTreeMap::new();
        anchors.insert(me_hash, me_pk);
        Trust { path, me, me_pk, me_hash, anchors, recs: HashMap::new(), holders: HashMap::new(), pols: HashMap::new(), my_offer: BTreeMap::new() }
    }

    /// Загрузить из `trust.json` в каталоге состояния (если он есть).
    /// Загрузка fail-closed (S4): отсутствие файла - пустое состояние; любая ошибка чтения, разбора или проверки записи - отказ,
    /// без молчаливого пропуска. Повреждённый отзыв не должен вернуть права, поэтому частичная загрузка не допускается.
    pub fn load(me: Identity, state: &Path) -> Result<Trust> {
        let path = state.join("trust.json");
        let mut t = Trust::new(me, Some(path.clone()));
        let b = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(t),
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
                if t.anchors.contains_key(&root) && offer <= ALL as u64 {
                    t.my_offer.insert(root, offer as u16);
                }
            }
        }
        t.prune_policies();
        Ok(t)
    }

    pub fn save(&self) -> Result<()> {
        let Some(p) = &self.path else { return Ok(()) };
        let anchors: Vec<String> = self.anchors.iter().filter(|(h, _)| **h != self.me_hash).map(|(_, pk)| hex(pk)).collect();
        let recs: Vec<String> = self.export_all().iter().map(|r| hex(&r.wire())).collect();
        let mut pk: Vec<&Policy> = self.pols.values().collect();
        pk.sort_by_key(|p| (p.root, p.hh));
        let pols: Vec<String> = pk.iter().map(|p| hex(&p.wire())).collect();
        let mypol: serde_json::Map<String, serde_json::Value> = self.my_offer.iter().map(|(r, o)| (hex(r), serde_json::json!(o))).collect();
        write_atomic(p, &serde_json::to_vec(&serde_json::json!({"v": 1, "anchors": anchors, "recs": recs, "pols": pols, "mypol": mypol}))?)
    }

    pub fn anchors(&self) -> Vec<(Hash, Pk)> {
        self.anchors.iter().map(|(h, p)| (*h, *p)).collect()
    }

    pub fn has_anchor(&self, h: &Hash) -> bool {
        self.anchors.contains_key(h)
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
    pub fn tags(&self) -> Vec<String> {
        self.anchors.keys().map(root_tag).collect()
    }

    pub fn record_count(&self) -> usize {
        self.recs.len()
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
        self.recs.keys().filter(|k| k.0 == *root).count()
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
            return Some((ALL, 0));
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
        self.anchors.keys().fold(0, |a, root| a | self.rights_in(root, &h))
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
            let m = if my_eff { self.effective_in(root, &self.me_hash, now) } else { self.rights_in(root, &self.me_hash) };
            let t = if their_eff { self.effective_in(root, &h, now) } else { self.rights_in(root, &h) };
            m & mine != 0 && t & theirs != 0
        })
    }

    /// Мои права в корне (для выдачи).
    pub fn my_rights_in(&self, root: &Hash) -> u16 {
        self.rights_in(root, &self.me_hash)
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
        let grant = self.rights_in(root, h);
        match self.pols.get(&(*root, *h)) {
            None => grant,
            Some(p) if p.valid_until > now => grant & p.offer,
            Some(_) => grant & USE,
        }
    }

    /// Действующие права ключа: объединение по всем якорям.
    pub fn effective(&self, pk: &Pk, now: u64) -> u16 {
        let Some(h) = hash_of(pk) else { return 0 };
        self.anchors.keys().fold(0, |a, root| a | self.effective_in(root, &h, now))
    }

    /// Видна ли нода другим: есть действующие USE, TRANSIT или EXIT хотя бы в одном корне.
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
        if offer & !ALL != 0 {
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
}

/// Проверить временную цепочку зачисления до заданного корня, не изменяя постоянное состояние.
pub fn verify_enrollment(me: &Identity, root_pk: &Pk, created: u64, cand: &Record, chain: &[Record]) -> Result<Vec<Record>> {
    let root = hash_of(root_pk).ok_or_else(|| anyhow::anyhow!("ключ корня не разобран"))?;
    let me_pk = me.public_key_bytes();
    let me_hash = *me.hash();
    if root == me_hash || cand.holder != me_pk || cand.root != root || cand.rights == 0
        || cand.seq < created.saturating_mul(1000)
    {
        bail!("запись зачисления не соответствует приглашению");
    }
    let mut t = Trust::new(me.clone(), None);
    t.add_anchor(root_pk)?;
    // Просматриваем вход без полной копии и повторяем проходы для записей в любом порядке.
    // Число принятых издателей ограничено глубиной цепочки; присланный мусор не съедает квоту.
    for _ in 0..=MAX_DEPTH {
        let mut changed = false;
        for r in chain.iter().chain(std::iter::once(cand)).filter(|r| r.root == root) {
            let equivocation = chain.iter().chain(std::iter::once(cand)).any(|other|
                other.root == root && other.issuer == r.issuer && other.hh == r.hh && other.seq == r.seq && other.rights != r.rights);
            if equivocation { continue; }
            let known_issuers = t.recs.keys().filter(|(rt, _, _)| *rt == root).map(|(_, _, issuer)| *issuer)
                .collect::<std::collections::HashSet<_>>();
            if known_issuers.len() >= MAX_DEPTH && !known_issuers.contains(&r.issuer) { continue; }
            if t.offer(r.clone()) == Offer::Added { changed = true; }
        }
        if !changed { break; }
    }
    let rights = t.rights_in(&root, &me_hash);
    if rights == 0 || cand.rights & !rights != 0 { bail!("цепочка не подтверждает выданные права"); }
    Ok(t.chain_for(&me_pk))
}

// ------------------------------------------------------------------------------------------------ приглашение

/// `rawgi-` + base64url(v=3 | flags(bit0=delegated) | inviter(64) | [root_pk(64)] | pin(16) | rights(2 LE) | created(8 BE) | адреса | число нод(0..8)+хеши(16) | sha256[..4]).
/// Не содержит ключей приёмника: нода генерирует свою identity сама. pin одноразовый и гасится админом.
#[derive(Clone, Debug, PartialEq)]
pub struct Invite {
    pub admin: Pk,
    /// Публичный ключ корня только для делегированного приглашения; None означает корень-приглашающего.
    pub root_pk: Option<Pk>,
    pub pin: [u8; 16],
    pub rights: u16,
    pub created: u64,
    pub addrs: Vec<String>,
    /// identity-хеши нод, выбранных приглашающим как входные: пусто — к любой ноде корня.
    pub nodes: Vec<Hash>,
}

pub const MAX_INVITE_NODES: usize = 8;

fn b64e(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn b64d(s: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim()).map_err(|e| anyhow::anyhow!("base64: {e}"))
}

impl Invite {
    /// Строка для сервера и QR: `rawgi-` + base64url (совместимость; серверы отдают только её).
    pub fn encode(&self) -> Result<String> {
        Ok(format!("rawgi-{}", b64e(&self.body()?)))
    }

    /// Та же полезная нагрузка, что и в `encode`, но эмодзи (самая короткая текстовая форма, для чатов).
    pub fn encode_emoji(&self) -> Result<String> {
        Ok(crate::emoji::encode(&self.body()?))
    }

    /// Любая принятая форма (`rawgi-…` или эмодзи) -> каноническая `rawgi-…`, с проверкой контрольной суммы и разбора.
    pub fn to_base64(s: &str) -> Result<String> {
        Invite::parse(s)?.encode()
    }

    /// Любая принятая форма -> эмодзи.
    pub fn to_emoji(s: &str) -> Result<String> {
        Invite::parse(s)?.encode_emoji()
    }

    fn body(&self) -> Result<Vec<u8>> {
        if self.rights & !ALL != 0 { bail!("приглашение: неизвестные права"); }
        if self.nodes.len() > MAX_INVITE_NODES { bail!("приглашение: число нод больше {MAX_INVITE_NODES}"); }
        if self.nodes.iter().collect::<std::collections::HashSet<_>>().len() != self.nodes.len() {
            bail!("приглашение: повтор ноды");
        }
        if self.addrs.len() > 4 { bail!("приглашение: не более 4 адресов"); }
        if self.addrs.iter().any(|a| a.len() > 200) { bail!("приглашение: адрес длиннее 200 байт"); }
        let admin_hash = hash_of(&self.admin).ok_or_else(|| anyhow::anyhow!("ключ приглашающего не разобран"))?;
        if let Some(root) = &self.root_pk {
            let rh = hash_of(root).ok_or_else(|| anyhow::anyhow!("ключ корня не разобран"))?;
            if rh == admin_hash { bail!("делегированный корень совпадает с приглашающим"); }
        }
        let nodes: Vec<&Hash> = self.nodes.iter().collect();
        let mut b = vec![3u8, u8::from(self.root_pk.is_some())];
        b.extend_from_slice(&self.admin);
        if let Some(root_pk) = &self.root_pk { b.extend_from_slice(root_pk); }
        b.extend_from_slice(&self.pin);
        b.extend_from_slice(&self.rights.to_le_bytes());
        b.extend_from_slice(&self.created.to_be_bytes());
        let addrs: Vec<&String> = self.addrs.iter().collect();
        b.push(addrs.len() as u8);
        for a in addrs {
            b.push(a.len() as u8);
            b.extend_from_slice(a.as_bytes());
        }
        b.push(nodes.len() as u8);
        for h in nodes { b.extend_from_slice(h); }
        let ck = Sha256::digest(&b);
        b.extend_from_slice(&ck[..4]);
        Ok(b)
    }

    pub fn parse(s: &str) -> Result<Invite> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let b = match s.strip_prefix("rawgi-") {
            Some(body) => b64d(body)?,
            None if crate::emoji::looks_like(&s) => crate::emoji::decode(&s)?,
            None => bail!("не приглашение (нужен префикс rawgi- или строка из эмодзи)"),
        };
        if b.len() < 2 + 64 + 16 + 2 + 8 + 1 + 1 + 4 {
            bail!("приглашение слишком короткое");
        }
        let (j, ck) = b.split_at(b.len() - 4);
        if Sha256::digest(j)[..4] != *ck {
            bail!("контрольная сумма приглашения не сошлась (строка повреждена при копировании?)");
        }
        if j[0] != 3 {
            bail!("версия приглашения не поддерживается");
        }
        if j[1] & !1 != 0 { bail!("приглашение: неизвестные флаги"); }
        let delegated = j[1] & 1 != 0;
        let admin: Pk = j[2..66].try_into().unwrap();
        hash_of(&admin).ok_or_else(|| anyhow::anyhow!("ключ админа в приглашении не разобран"))?;
        let mut i = 66;
        let root_pk = if delegated {
            let pk: Pk = j.get(i..i+64).ok_or_else(|| anyhow::anyhow!("приглашение обрезано"))?.try_into().unwrap();
            let rh = hash_of(&pk).ok_or_else(|| anyhow::anyhow!("ключ корня в приглашении не разобран"))?;
            if rh == hash_of(&admin).unwrap() { bail!("делегированный корень совпадает с приглашающим"); }
            i += 64;
            Some(pk)
        } else { None };
        let pin: [u8; 16] = j.get(i..i+16).ok_or_else(|| anyhow::anyhow!("приглашение обрезано"))?.try_into().unwrap(); i += 16;
        let rights = u16::from_le_bytes(j.get(i..i+2).ok_or_else(|| anyhow::anyhow!("приглашение обрезано"))?.try_into().unwrap()); i += 2;
        if rights & !ALL != 0 {
            bail!("приглашение: неизвестные права");
        }
        let created = u64::from_be_bytes(j.get(i..i+8).ok_or_else(|| anyhow::anyhow!("приглашение обрезано"))?.try_into().unwrap()); i += 8;
        let n = *j.get(i).ok_or_else(|| anyhow::anyhow!("приглашение обрезано"))? as usize; i += 1;
        if n > 4 { bail!("приглашение: слишком много адресов"); }
        let mut addrs = Vec::new();
        for _ in 0..n {
            let l = *j.get(i).ok_or_else(|| anyhow::anyhow!("приглашение обрезано"))? as usize;
            if l > 200 { bail!("приглашение: адрес длиннее 200 байт"); }
            let a = j.get(i + 1..i + 1 + l).ok_or_else(|| anyhow::anyhow!("приглашение обрезано"))?;
            addrs.push(String::from_utf8(a.to_vec()).context("адрес в приглашении")?);
            i += 1 + l;
        }
        let mut nodes: Vec<Hash> = Vec::new();
        {
            let m = *j.get(i).ok_or_else(|| anyhow::anyhow!("приглашение обрезано"))? as usize;
            i += 1;
            if m > MAX_INVITE_NODES {
                bail!("приглашение: число нод больше {MAX_INVITE_NODES}");
            }
            for _ in 0..m {
                let h: Hash = j.get(i..i + 16).ok_or_else(|| anyhow::anyhow!("приглашение обрезано"))?.try_into().unwrap();
                if nodes.contains(&h) {
                    bail!("приглашение: повтор ноды");
                }
                nodes.push(h);
                i += 16;
            }
        }
        if i != j.len() {
            bail!("лишние данные в приглашении");
        }
        Ok(Invite { admin, root_pk, pin, rights, created, addrs, nodes })
    }

    /// Свежее ли приглашение: ставим окно в обе стороны (часы телефона бывают неточными).
    pub fn fresh(&self, now_s: u64) -> bool {
        self.created <= now_s.saturating_add(3600) && self.created.saturating_add(INVITE_TTL_S) > now_s
    }

    /// Доказательство владения pin, привязанное к ключу приёмника и админу: pin по сети не ходит.
    pub fn mac(&self, holder: &Pk) -> Result<[u8; 32]> {
        Ok(pair_mac(&self.pin, holder, &self.admin, &self.root()?))
    }

    pub fn root(&self) -> Result<Hash> {
        hash_of(self.root_pk.as_ref().unwrap_or(&self.admin)).ok_or_else(|| anyhow::anyhow!("ключ корня приглашения не разобран"))
    }
    pub fn root_pk(&self) -> Result<Pk> { let pk = self.root_pk.unwrap_or(self.admin); hash_of(&pk).ok_or_else(|| anyhow::anyhow!("ключ корня приглашения не разобран"))?; Ok(pk) }

    /// Дешёвый фильтр записи-кандидата до проверки полной цепочки.
    pub fn enroll_hit(&self, me: &Pk, rec: &Record) -> bool {
        rec.holder == *me && self.root().map(|root| rec.root == root).unwrap_or(false)
            && self.admin_hash().map(|h| rec.issuer == h).unwrap_or(false)
            && rec.signed_by(&self.admin) && rec.rights != 0 && rec.rights & !self.rights == 0
            && rec.seq >= self.created.saturating_mul(1000)
    }

    pub fn admin_hash(&self) -> Result<Hash> {
        hash_of(&self.admin).ok_or_else(|| anyhow::anyhow!("ключ приглашающего не разобран"))
    }
}

pub fn pair_mac(pin: &[u8; 16], holder: &Pk, admin: &Pk, root: &Hash) -> [u8; 32] {
    hmac32(pin, &[b"rawg-pair-v3", holder, admin, root])
}

pub fn mac_eq(key_pin: &[u8; 16], holder: &Pk, admin: &Pk, root: &Hash, tag: &[u8]) -> bool {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key_pin).expect("hmac key");
    m.update(b"rawg-pair-v3");
    m.update(holder);
    m.update(admin);
    m.update(root);
    m.verify_slice(tag).is_ok()
}

// ------------------------------------------------------------------------------------------------ учёт pin у админа

/// Что нашлось на запрос зачисления.
#[derive(Debug, PartialEq)]
pub enum Claim {
    /// pin свежий и только что погашен за этим держателем; права из приглашения
    New { rights: u16, root: Hash },
    /// тот же держатель повторяет уже погашенный pin (потерян ответ): запись пересылается, права не повышаются
    Repeat { root: Hash },
    /// pin уже погашен другим
    Spent,
    Expired,
    Unknown,
}

fn pins_dir(state: &Path) -> PathBuf {
    state.join("pins")
}

/// Замок учёта pin в процессе: погашение и создание pin идут по одному (S1). Межпроцессная гонка закрыта `create_new`
/// на файле `.spent`: второй захват получает `AlreadyExists`.
static PIN_LOCK: Mutex<()> = Mutex::new(());

fn pin_lock() -> std::sync::MutexGuard<'static, ()> {
    PIN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Каталог pin закрытый (0700): имя файла содержит pin, а это секрет.
fn ensure_pins_dir(state: &Path) -> Result<PathBuf> {
    let dir = pins_dir(state);
    let created = match std::fs::create_dir(&dir) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(e).context("создание закрытого каталога pin"),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if created {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).context("настройка прав каталога pin")?;
        } else if std::fs::metadata(&dir).map(|m| m.permissions().mode() & 0o777).ok() != Some(0o700) {
            bail!("каталог pin должен иметь права 0700");
        }
    }
    Ok(dir)
}

/// Убрать неиспользованные pin старше срока (иначе просроченные файлы вечно занимают слоты MAX_PINS).
/// Погашенные (`.spent`) держим в пределах того же срока: в это время возможен повтор держателя. Остатки временных файлов тоже убираем.
fn pin_sweep(state: &Path, now_s: u64) {
    let Ok(rd) = std::fs::read_dir(pins_dir(state)) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let field = match p.extension().and_then(|x| x.to_str()) {
            Some("json") => "c",
            Some("spent") => "t",
            Some("tmp") => {
                let _ = std::fs::remove_file(&p);
                continue;
            }
            _ => continue,
        };
        let stamp = std::fs::read(&p).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v[field].as_u64()).unwrap_or(0);
        if now_s > stamp.saturating_add(INVITE_TTL_S) {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// Создать одноразовый pin (файл `pins/<hex>.json`): запущенная нода подхватывает его при зачислении.
pub fn pin_create(state: &Path, root: &Hash, rights: u16, label: &str, now_s: u64) -> Result<[u8; 16]> {
    if rights & !ALL != 0 { bail!("приглашение: неизвестные права"); }
    let _g = pin_lock();
    let dir = ensure_pins_dir(state)?;
    pin_sweep(state, now_s);
    let open = std::fs::read_dir(&dir)?.flatten().filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false)).count();
    if open >= MAX_PINS {
        bail!("слишком много неиспользованных приглашений (не больше {MAX_PINS}): отзовите лишние");
    }
    let mut pin = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut pin);
    let body = serde_json::json!({"c": now_s, "r": rights, "l": label.chars().take(64).collect::<String>(), "root": hex(root)});
    write_atomic(&dir.join(format!("{}.json", hex(&pin))), body.to_string().as_bytes())?;
    Ok(pin)
}

/// Найти pin по доказательству `tag` и погасить за `holder`. Гашение атомарно: `.spent` создаётся с `create_new`,
/// поэтому выиграть может только один захват. Повторное предъявление тем же держателем - `Repeat`, другим - `Spent`.
/// Если выдача записи после `New` не удалась, вызывающий обязан вызвать `pin_unclaim` с теми же аргументами.
pub fn pin_claim(state: &Path, admin: &Pk, holder: &Pk, tag: &[u8], now_s: u64) -> Claim {
    let _g = pin_lock();
    let dir = pins_dir(state);
    let Ok(rd) = std::fs::read_dir(&dir) else { return Claim::Unknown };
    for e in rd.flatten() {
        let p = e.path();
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
        if ext != "json" && ext != "spent" {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()).map(String::from) else { continue };
        let Ok(pin): std::result::Result<[u8; 16], _> = unhex(&stem).try_into() else { continue };
        let Some(v) = std::fs::read(&p).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()) else { continue };
        let Ok(root): std::result::Result<Hash, _> = unhex(v["root"].as_str().unwrap_or("")).try_into() else { continue };
        if !mac_eq(&pin, holder, admin, &root, tag) { continue; }
        let spent = dir.join(format!("{stem}.spent"));
        if spent.exists() {
            let who = std::fs::read(&spent).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v["h"].as_str().map(String::from)).unwrap_or_default();
            let created = std::fs::read(&spent).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v["c"].as_u64()).unwrap_or(0);
            if now_s > created.saturating_add(INVITE_TTL_S) { return Claim::Expired; }
            return if who == hex(holder) { Claim::Repeat { root } } else { Claim::Spent };
        }
        let open = dir.join(format!("{stem}.json"));
        let created = v["c"].as_u64().unwrap_or(0);
        if now_s.saturating_add(3600) < created || now_s > created.saturating_add(INVITE_TTL_S) {
            return Claim::Expired;
        }
        let rights = v["r"].as_u64().unwrap_or(0) as u16 & ALL;
        // в метке сохраняем срок создания: при откате pin вернётся с тем же сроком
        let mark = serde_json::json!({"h": hex(holder), "t": now_s, "c": created, "r": rights, "l": v["l"], "root": hex(&root)});
        match write_new(&spent, mark.to_string().as_bytes()) {
            Ok(()) => {}
            // другой процесс погасил раньше
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Claim::Spent,
            Err(_) => return Claim::Unknown,
        }
        sync_dir(&dir);
        let _ = std::fs::remove_file(&open);
        return Claim::New { rights, root };
    }
    Claim::Unknown
}

/// Откат гашения (H8): если выдача не удалась либо после `Repeat` ещё не найдена запись, pin возвращается.
/// Возвращает `true` только если откат выполнен для того же держателя, который погасил pin.
pub fn pin_unclaim(state: &Path, admin: &Pk, holder: &Pk, tag: &[u8]) -> bool {
    let _g = pin_lock();
    let dir = pins_dir(state);
    let Ok(rd) = std::fs::read_dir(&dir) else { return false };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("spent") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()).map(String::from) else { continue };
        let Ok(pin): std::result::Result<[u8; 16], _> = unhex(&stem).try_into() else { continue };
        let Some(v) = std::fs::read(&p).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()) else { return false };
        let Ok(root): std::result::Result<Hash, _> = unhex(v["root"].as_str().unwrap_or("")).try_into() else { continue };
        if !mac_eq(&pin, holder, admin, &root, tag) { continue; }
        if v["h"].as_str() != Some(hex(holder).as_str()) {
            return false;
        }
        // сначала возвращаем открытый файл, потом снимаем метку: при сбое между шагами pin остаётся погашенным (безопасная сторона)
        let body = serde_json::json!({"c": v["c"], "r": v["r"], "l": v["l"], "root": hex(&root)});
        match write_new(&dir.join(format!("{stem}.json")), body.to_string().as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return false,
        }
        sync_dir(&dir);
        if std::fs::remove_file(&p).is_err() {
            // При частичном откате сохраняем погашенное состояние: оно всегда имеет приоритет над открытым файлом.
            let _ = std::fs::remove_file(dir.join(format!("{stem}.json")));
            sync_dir(&dir);
            return false;
        }
        sync_dir(&dir);
        return true;
    }
    false
}

/// Сводка pin для `list`: (hex pin без середины, состояние, метка).
pub fn pin_list(state: &Path) -> Vec<(String, &'static str, String)> {
    let _g = pin_lock();
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(pins_dir(state)) {
        for e in rd.flatten() {
            let p = e.path();
            let st = if p.extension().map(|x| x == "spent").unwrap_or(false) { "погашен" } else { "свежий" };
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let label = std::fs::read(&p).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()).and_then(|v| v["l"].as_str().map(String::from)).unwrap_or_default();
            out.push((format!("{}…", &stem[..8.min(stem.len())]), st, label));
        }
    }
    out.sort();
    out
}

/// Корни со свежими, ещё не погашенными приглашениями. Ошибочные файлы пропускаются.
pub fn pin_roots_fresh(state: &Path) -> Vec<Hash> {
    let _g = pin_lock();
    let now_s = now_ms() as u64 / 1000;
    let mut roots = Vec::new();
    if let Ok(rd) = std::fs::read_dir(pins_dir(state)) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "json").unwrap_or(false) {
                if p.with_extension("spent").exists() { continue; }
                let root = std::fs::read(&p).ok()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .and_then(|v| {
                        let created = v["c"].as_u64()?;
                        if now_s > created.saturating_add(INVITE_TTL_S) { return None; }
                        <[u8; 16]>::try_from(unhex(v["root"].as_str()?)).ok()
                    });
                if let Some(root) = root {
                    if !roots.contains(&root) { roots.push(root); }
                }
            }
        }
    }
    roots.sort();
    roots
}

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
        assert_eq!(parse_rights("use+exit").unwrap(), USE | EXIT);
        assert_eq!(parse_rights("12").unwrap(), 12);
        assert!(parse_rights("64").is_err());
        assert!(parse_rights("root").is_err());
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
        let mut bad = w.clone();
        bad[1] = 0xff; // лишние биты прав
        assert!(Record::parse(&bad).is_none());
    }

    #[test]
    fn founder_is_own_admin_and_nobody_elses() {
        let a = ident();
        let t = tr(&a);
        assert_eq!(t.my_rights_in(&t.me_hash), ALL);
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
        assert_eq!(tme.my_rights_in(&tme.me_hash), ALL, "в своей сети я админ");
        assert_eq!(tme.my_rights_in(&admin_b.hash().clone()), USE, "в чужой - пользователь");
        // выдавать в чужой сети я не могу
        assert!(tme.issue(*admin_b.hash(), u.public_key_bytes(), USE).is_err());
        // а в своей могу и даже могу добавить его админа пользователем
        tme.issue(tme.me_hash, admin_b.public_key_bytes(), PRESET_USER).unwrap();
        assert_eq!(tme.rights_in(&tme.me_hash, admin_b.hash()), USE);
        // в объединении по якорям B остаётся админом собственного дерева
        assert_eq!(tme.rights(&admin_b.public_key_bytes()), ALL);
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
        let dir = std::env::temp_dir().join(format!("rawg-trust-{}-{}", std::process::id(), now_ms()));
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
    fn invite_roundtrip_checksum_and_ttl() {
        let a = ident();
        let inv = Invite { admin: a.public_key_bytes(), root_pk: None, pin: [7; 16], rights: PRESET_RELAY, created: 1_000_000, addrs: vec!["203.0.113.5:47001".into(), "example.org:47001".into()], nodes: vec![] };
        let s = inv.encode().unwrap();
        assert!(s.starts_with("rawgi-"));
        assert_eq!(Invite::parse(&s).unwrap(), inv);
        assert_eq!(Invite::parse(&format!(" {}\n", s.replace("-", "-"))).unwrap(), inv);
        let mut bad = s.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert!(Invite::parse(&bad).is_err());
        assert!(Invite::parse("rawgi-").is_err());
        assert!(Invite::parse("rawga-AAAA").is_err());
        assert!(inv.fresh(1_000_000 + 10));
        assert!(!inv.fresh(1_000_000 + INVITE_TTL_S + 1));
        assert!(!inv.fresh(1_000_000 - 7200), "из будущего");
        let far_future = Invite { created: u64::MAX, ..inv.clone() };
        assert!(!far_future.fresh(1_000_000), "переполнение не делает дальнее будущее свежим");
        // pin в строке есть, но MAC от него не раскрывает pin
        let m = inv.mac(&ident().public_key_bytes()).unwrap();
        assert_ne!(&m[..16], &inv.pin);
    }

    #[test]
    fn invite_emoji_roundtrip_equals_base64() {
        let a = ident();
        let inv = Invite { admin: a.public_key_bytes(), root_pk: None, pin: [9; 16], rights: PRESET_USER, created: 5_000_000, addrs: vec![], nodes: vec![[1; 16], [2; 16], [3; 16]] };
        let b64 = inv.encode().unwrap();
        let em = inv.encode_emoji().unwrap();
        assert!(!em.is_ascii());
        assert!(em.chars().count() < b64.len(), "эмодзи короче base64: {} против {}", em.chars().count(), b64.len());
        assert_eq!(Invite::parse(&b64).unwrap(), inv);
        assert_eq!(Invite::to_base64(&em).unwrap(), b64);
        assert_eq!(Invite::to_emoji(&b64).unwrap(), em);
        // повреждённая эмодзи-строка не проходит по контрольной сумме
        let mut chars: Vec<char> = em.chars().collect();
        let k = chars.len() / 2;
        chars[k] = if chars[k] == '😀' { '😃' } else { '😀' };
        assert!(Invite::parse(&chars.into_iter().collect::<String>()).is_err());
        // Приглашение v3 без узлов тоже содержит длину списка (ноль).
        let v1 = Invite { nodes: vec![], ..inv.clone() };
        assert_eq!(Invite::parse(&v1.encode_emoji().unwrap()).unwrap(), v1);
    }

    #[test]
    fn invite_v3_nodes_roundtrip_and_limits() {
        let a = ident();
        let mut inv = Invite { admin: a.public_key_bytes(), root_pk: None, pin: [9; 16], rights: PRESET_USER, created: 5_000_000, addrs: vec![], nodes: vec![[1; 16], [2; 16]] };
        let s = inv.encode().unwrap();
        assert_eq!(Invite::parse(&s).unwrap(), inv);
        assert_eq!(Invite::parse(&s).unwrap().nodes.len(), 2);
        // Без нод формат остаётся v3 с обязательным нулевым счётчиком.
        inv.nodes.clear();
        let v1 = inv.encode().unwrap();
        assert_eq!(Invite::parse(&v1).unwrap(), inv);
        assert!(v1.len() < s.len());
        // больше 8 нод не обрезается молча
        inv.nodes = (0..12u8).map(|i| [i + 1; 16]).collect();
        assert!(inv.encode().is_err());
        // повтор ноды отклоняется (собираем строку вручную)
        let mut b = vec![2u8];
        b.extend_from_slice(&inv.admin);
        b.extend_from_slice(&inv.pin);
        b.extend_from_slice(&inv.rights.to_le_bytes());
        b.extend_from_slice(&inv.created.to_be_bytes());
        b.push(0);
        b.push(2);
        b.extend_from_slice(&[3; 16]);
        b.extend_from_slice(&[3; 16]);
        let ck = Sha256::digest(&b);
        b.extend_from_slice(&ck[..4]);
        assert!(Invite::parse(&format!("rawgi-{}", b64e(&b))).is_err());
    }

    #[test]
    fn invite_v3_delegated_worst_case_and_rejections() {
        let admin = ident();
        let root_id = ident();
        let inv = Invite {
            admin: admin.public_key_bytes(), root_pk: Some(root_id.public_key_bytes()), pin: [8; 16], rights: ALL,
            created: 9_000_000, addrs: vec!["x".repeat(200); 4], nodes: (1..=8).map(|x| [x; 16]).collect(),
        };
        let b64 = inv.encode().unwrap();
        let em = inv.encode_emoji().unwrap();
        assert!(em.chars().count() <= crate::emoji::MAX_CHARS);
        assert_eq!(Invite::parse(&b64).unwrap(), inv);
        assert_eq!(Invite::parse(&em).unwrap(), inv);
        assert_eq!(inv.root().unwrap(), *root_id.hash());
        assert_eq!(inv.root_pk().unwrap(), root_id.public_key_bytes());

        fn packed(mut b: Vec<u8>) -> String {
            let n = b.len();
            b.truncate(n - 4);
            let ck = Sha256::digest(&b);
            b.extend_from_slice(&ck[..4]);
            format!("rawgi-{}", b64e(&b))
        }
        let own = Invite { root_pk: None, addrs: vec![], nodes: vec![], ..inv.clone() };
        let base = own.body().unwrap();
        for version in [1, 2] {
            let mut b = base.clone(); b[0] = version;
            assert!(Invite::parse(&packed(b)).is_err());
        }
        let mut b = base.clone(); b[1] = 2; assert!(Invite::parse(&packed(b)).is_err(), "лишние флаги");
        let mut b = inv.body().unwrap(); b[66..130].copy_from_slice(&inv.admin); assert!(Invite::parse(&packed(b)).is_err(), "корень совпал с приглашающим");
        let invalid = (0..=255u8).map(|x| [x; 64]).find(|pk| hash_of(pk).is_none()).expect("найдётся некорректный Ed25519-ключ");
        let mut b = inv.body().unwrap(); b[66..130].copy_from_slice(&invalid);
        assert!(Invite::parse(&packed(b)).is_err(), "неразбираемый root_pk");
        let mut b = base.clone(); b.truncate(b.len() - 5); assert!(Invite::parse(&packed(b)).is_err(), "обрезка");
        let mut b = base.clone(); b.insert(b.len() - 4, 0); assert!(Invite::parse(&packed(b)).is_err(), "лишние данные");
        let mut b = base.clone(); b[82] = 0xff; b[83] = 0xff; assert!(Invite::parse(&packed(b)).is_err(), "лишние биты прав");
        let mut b = base.clone(); b[base.len() - 5] = 9; assert!(Invite::parse(&packed(b)).is_err(), "больше 8 нод");
        let duplicate_nodes = Invite { nodes: vec![[4;16], [4;16]], ..own.clone() };
        assert!(duplicate_nodes.encode().is_err(), "повтор ноды");
        let mut b = base.clone(); *b.last_mut().unwrap() ^= 1; assert!(Invite::parse(&format!("rawgi-{}", b64e(&b))).is_err(), "контрольная сумма");
    }

    #[test]
    fn pair_mac_v3_binds_root_admin_holder_and_rejects_v1() {
        let admin = ident().public_key_bytes(); let h = ident().public_key_bytes();
        let (r1, r2) = ([1;16], [2;16]); let pin = [7;16];
        let tag = pair_mac(&pin, &h, &admin, &r1);
        assert!(mac_eq(&pin, &h, &admin, &r1, &tag));
        assert!(!mac_eq(&pin, &h, &admin, &r2, &tag));
        let h2 = ident().public_key_bytes(); assert!(!mac_eq(&pin, &h2, &admin, &r1, &tag));
        let a2 = ident().public_key_bytes(); assert!(!mac_eq(&pin, &h, &a2, &r1, &tag));
        let old = hmac32(&pin, &[b"rawg-pair-v1", &h, &admin]);
        assert!(!mac_eq(&pin, &h, &admin, &r1, &old));
    }

    #[test]
    fn delegated_enrollment_checks_full_chain_and_order() {
        let (root_id, d, n) = (ident(), ident(), ident());
        let root = *root_id.hash();
        let mut rt = tr(&root_id);
        let rd = rt.issue(root, d.public_key_bytes(), USE | ADD).unwrap();
        let mut dt = tr(&d); dt.add_anchor(&root_id.public_key_bytes()).unwrap(); dt.offer(rd.clone());
        let created = now_ms() as u64 / 1000;
        let cand = dt.issue(root, n.public_key_bytes(), USE).unwrap();
        assert!(cand.seq >= created.saturating_mul(1000));
        let accepted = verify_enrollment(&n, &root_id.public_key_bytes(), 0, &cand, &[rd.clone()]).unwrap();
        assert_eq!(accepted.len(), 2);
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &cand, &[]).is_err(), "нет R→D");
        let mut wrong = cand.clone(); wrong.root = *ident().hash();
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &wrong, &[rd.clone()]).is_err());
        let mut shuffled = vec![cand.clone(), rd.clone()];
        assert_eq!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &cand, &shuffled).unwrap(), accepted);
        shuffled.clear();
        let inv = Invite { admin: d.public_key_bytes(), root_pk: Some(root_id.public_key_bytes()), pin: [1;16], rights: USE, created, addrs: vec![], nodes: vec![] };
        assert!(inv.enroll_hit(&n.public_key_bytes(), &cand));
        assert!(!inv.enroll_hit(&ident().public_key_bytes(), &cand));
        let forged = Record::sign(&ident(), root, n.public_key_bytes(), USE, cand.seq + 1).unwrap();
        assert!(!inv.enroll_hit(&n.public_key_bytes(), &forged));

        let (d1, d2, n2) = (ident(), ident(), ident());
        let mut rtrust = tr(&root_id); let rd1 = rtrust.issue(root, d1.public_key_bytes(), ALL).unwrap();
        let mut d1trust = tr(&d1); d1trust.add_anchor(&root_id.public_key_bytes()).unwrap(); d1trust.offer(rd1.clone());
        let rd2 = d1trust.issue(root, d2.public_key_bytes(), USE | ADD).unwrap();
        let mut d2trust = tr(&d2); d2trust.add_anchor(&root_id.public_key_bytes()).unwrap();
        d2trust.offer(rd1.clone()); d2trust.offer(rd2.clone());
        let cand2 = d2trust.issue(root, n2.public_key_bytes(), USE).unwrap();
        assert!(verify_enrollment(&n2, &root_id.public_key_bytes(), 0, &cand2, &[rd2.clone(), rd1.clone()]).is_ok(), "R→D1→D2→N, обратный порядок");
    }

    #[test]
    fn enrollment_binds_holder_root_age_and_rejects_equivocation() {
        let (root_id, d, n) = (ident(), ident(), ident());
        let root = *root_id.hash();
        let mut rt = tr(&root_id);
        let rd = rt.issue(root, d.public_key_bytes(), USE | ADD).unwrap();
        let created = now_ms() as u64 / 1000;
        let cand = Record::sign(&d, root, n.public_key_bytes(), USE, now_ms() as u64).unwrap();
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), created, &cand, &[rd.clone()]).is_ok());
        let mut noisy_chain = vec![rd.clone()];
        for _ in 0..20 { noisy_chain.push(rt.issue(root, ident().public_key_bytes(), USE).unwrap()); }
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), created, &cand, &noisy_chain).is_ok(),
            "много проверенных записей одного издателя не блокируют действующую цепочку");
        assert!(verify_enrollment(&root_id, &root_id.public_key_bytes(), created, &cand, &[rd.clone()]).is_err(), "собственный root не может быть принят как зачисление");
        assert!(verify_enrollment(&ident(), &root_id.public_key_bytes(), created, &cand, &[rd.clone()]).is_err(), "держатель обязан совпасть с identity");
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), created + 1, &cand, &[rd.clone()]).is_err(), "seq ниже created");
        let future = Record::sign(&d, root, n.public_key_bytes(), USE, now_ms() as u64 + SEQ_FUTURE_MS + 10_000).unwrap();
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), created, &future, &[rd.clone()]).is_err(), "seq из будущего");
        let conflicting = Record::sign(&d, root, n.public_key_bytes(), USE | ADD, cand.seq).unwrap();
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), created, &cand, &[rd, conflicting]).is_err(), "одна версия с разными правами отвергается целиком");
    }

    #[test]
    fn invite_vectors_for_jvm_parser() {
        let a = Identity::from_private_key_bytes(&[0x31; 64]).expect("только синтетический тестовый ключ");
        let root = Identity::from_private_key_bytes(&[0x52; 64]).expect("только синтетический тестовый ключ");
        let own = Invite { admin: a.public_key_bytes(), root_pk: None, pin: [0x11; 16], rights: USE, created: 1_800_000_000, addrs: vec![], nodes: vec![] };
        let delegated = Invite { admin: a.public_key_bytes(), root_pk: Some(root.public_key_bytes()), pin: [0x22; 16], rights: USE | ADD,
            created: 1_800_000_001, addrs: vec![], nodes: vec![] };
        let content = format!("own\t{}\ndelegated\t{}\n", own.encode().unwrap(), delegated.encode().unwrap());
        assert_eq!(Invite::parse(&own.encode().unwrap()).unwrap(), own);
        assert_eq!(Invite::parse(&delegated.encode().unwrap()).unwrap(), delegated);
        // Экспорт синтетических векторов нужен только внешней JVM-проверке.
        // Обычный тест не зависит от доступности каталога конкретной сессии агента.
        if let Some(path) = std::env::var_os("RAWG_JVM_VECTORS") {
            let path = Path::new(&path);
            if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).unwrap(); }
            std::fs::write(path, content).unwrap();
        }
    }

    #[test]
    fn enrollment_rejects_missing_authority_wrong_signature_and_revocation() {
        let (root_id, d, n) = (ident(), ident(), ident()); let root = *root_id.hash();
        let mut rt = tr(&root_id);
        let no_add = rt.issue(root, d.public_key_bytes(), USE).unwrap();
        let forged_grant = Record::sign(&d, root, n.public_key_bytes(), USE, now_ms() as u64).unwrap();
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &forged_grant, &[no_add]).is_err(), "издателю нужен ADD");

        let rd = rt.issue(root, d.public_key_bytes(), USE | ADD).unwrap();
        let cand = Record::sign(&d, root, n.public_key_bytes(), USE, now_ms() as u64).unwrap();
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &cand, &[rd.clone()]).is_ok());
        let overgrant = Record::sign(&d, root, n.public_key_bytes(), EXIT, now_ms() as u64).unwrap();
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &overgrant, &[rd.clone()]).is_err(), "D не имеет EXIT");
        assert!(verify_enrollment(&n, &ident().public_key_bytes(), 0, &cand, &[rd.clone()]).is_err(), "не тот root_pk");
        let mut bad_sig = cand.clone(); bad_sig.sig[0] ^= 1;
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &bad_sig, &[rd.clone()]).is_err());
        let mut bad_issuer = cand.clone(); bad_issuer.issuer = *root_id.hash();
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &bad_issuer, &[rd.clone()]).is_err());
        let too_old = Record::sign(&d, root, n.public_key_bytes(), USE, 1).unwrap();
        let inv = Invite { admin: d.public_key_bytes(), root_pk: Some(root_id.public_key_bytes()), pin: [0;16], rights: USE,
            created: now_ms() as u64 / 1000, addrs: vec![], nodes: vec![] };
        assert!(!inv.enroll_hit(&n.public_key_bytes(), &too_old), "seq раньше приглашения");

        rt.issue(root, d.public_key_bytes(), 0).unwrap();
        let mut chain = rt.export_all(); chain.push(rd.clone());
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &cand, &chain).is_err(), "свежий отзыв D корнем");
        rt.issue(root, n.public_key_bytes(), 0).unwrap();
        let mut chain = rt.export_all(); chain.push(rd.clone());
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &cand, &chain).is_err(), "корневой отзыв N перекрывает выдачу D");
        let noise_root = ident(); let noise_holder = ident();
        let noise = Record::sign(&noise_root, *noise_root.hash(), noise_holder.public_key_bytes(), USE, 5).unwrap();
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &cand, &[rd.clone(), noise]).is_ok(), "посторонняя сеть игнорируется");

        let ids: Vec<Identity> = (0..9).map(|_| ident()).collect();
        let mut deep = Vec::new();
        deep.push(Record::sign(&root_id, root, ids[0].public_key_bytes(), ALL, now_ms() as u64).unwrap());
        for i in 1..ids.len() {
            deep.push(Record::sign(&ids[i - 1], root, ids[i].public_key_bytes(), ALL, now_ms() as u64 + i as u64).unwrap());
        }
        let deep_cand = Record::sign(ids.last().unwrap(), root, n.public_key_bytes(), USE, now_ms() as u64 + 20).unwrap();
        assert!(verify_enrollment(&n, &root_id.public_key_bytes(), 0, &deep_cand, &deep).is_err(), "цепочка глубины 9 недействительна");
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
    fn pins_spend_once_and_repeat_only_for_same_holder() {
        let dir = std::env::temp_dir().join(format!("rawg-pins-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let admin = ident();
        let (n1, n2) = (ident(), ident());
        let now = 5_000_000u64;
        let root = *admin.hash();
        let pin = pin_create(&dir, &root, PRESET_RELAY, "n1", now).unwrap();
        let inv = Invite { admin: admin.public_key_bytes(), root_pk: None, pin, rights: PRESET_RELAY, created: now, addrs: vec![], nodes: vec![] };
        let (p1, p2) = (n1.public_key_bytes(), n2.public_key_bytes());
        let missing_root_pin = pin_create(&dir, &root, USE, "missing-root", now).unwrap();
        let missing_path = pins_dir(&dir).join(format!("{}.json", hex(&missing_root_pin)));
        let mut missing: serde_json::Value = serde_json::from_slice(&std::fs::read(&missing_path).unwrap()).unwrap();
        missing.as_object_mut().unwrap().remove("root");
        std::fs::write(&missing_path, missing.to_string()).unwrap();
        let missing_mac = pair_mac(&missing_root_pin, &p1, &inv.admin, &root);
        assert_eq!(pin_claim(&dir, &inv.admin, &p1, &missing_mac, now), Claim::Unknown, "старый pin без корня отвергается");
        // неверный pin
        let wrong = pair_mac(&[1; 16], &p1, &inv.admin, &root);
        assert_eq!(pin_claim(&dir, &inv.admin, &p1, &wrong, now), Claim::Unknown);
        // доказательство привязано к держателю: чужой MAC не сойдётся
        assert_eq!(pin_claim(&dir, &inv.admin, &p2, &inv.mac(&p1).unwrap(), now), Claim::Unknown);
        assert_eq!(pin_claim(&dir, &inv.admin, &p1, &inv.mac(&p1).unwrap(), now), Claim::New { rights: PRESET_RELAY, root });
        // второй сервер с тем же приглашением (свой ключ) - отказ
        assert_eq!(pin_claim(&dir, &inv.admin, &p2, &inv.mac(&p2).unwrap(), now), Claim::Spent);
        // тот же держатель повторяет - пересылка записи
        assert_eq!(pin_claim(&dir, &inv.admin, &p1, &inv.mac(&p1).unwrap(), now), Claim::Repeat { root });
        // просроченный
        let old = pin_create(&dir, &root, USE, "old", now).unwrap();
        let inv2 = Invite { pin: old, ..inv.clone() };
        assert_eq!(pin_claim(&dir, &inv2.admin, &p2, &inv2.mac(&p2).unwrap(), now + INVITE_TTL_S + 10), Claim::Expired);
        assert!(pin_list(&dir).iter().any(|(_, st, l)| *st == "погашен" && l == "n1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_unspent_pins_free_slots() {
        let dir = std::env::temp_dir().join(format!("rawg-pinsweep-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let t0 = 5_000_000u64;
        // заполняем все слоты, затем срок истёк: новый pin создаётся, старые неиспользованные удалены
        let root = [0x55; 16];
        for _ in 0..MAX_PINS {
            pin_create(&dir, &root, USE, "old", t0).unwrap();
        }
        assert!(pin_create(&dir, &root, USE, "full", t0).is_err());
        let later = t0 + INVITE_TTL_S + 10;
        let fresh = pin_create(&dir, &root, USE, "new", later).unwrap();
        let open = std::fs::read_dir(pins_dir(&dir)).unwrap().flatten().filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false)).count();
        assert_eq!(open, 1);
        assert!(pin_list(&dir).iter().any(|(s, st, l)| *st == "свежий" && l == "new" && s.starts_with(&hex(&fresh)[..8])));
        let _ = std::fs::remove_dir_all(&dir);
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
        let dir = std::env::temp_dir().join(format!("rawg-trust-fc-{}-{}", std::process::id(), now_ms()));
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
    #[test]
    fn state_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rawg-trust-mode-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = ident();
        let t = Trust::new(a.clone(), Some(dir.join("trust.json")));
        t.save().unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join("trust.json")), 0o600);
        pin_create(&dir, &[9; 16], USE, "m", 5_000_000).unwrap();
        assert_eq!(mode(&pins_dir(&dir)), 0o700);
        let f = std::fs::read_dir(pins_dir(&dir)).unwrap().flatten().next().unwrap().path();
        assert_eq!(mode(&f), 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S1: восемь держателей стартуют одновременно с одним pin: ровно один получает New, остальные Spent.
    #[test]
    fn concurrent_claims_give_one_pin_to_one_holder() {
        let dir = std::env::temp_dir().join(format!("rawg-pin-race-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let admin = ident();
        let now = 5_000_000u64;
        let root = *admin.hash();
        let pin = pin_create(&dir, &root, PRESET_USER, "race", now).unwrap();
        let inv = Invite { admin: admin.public_key_bytes(), root_pk: None, pin, rights: PRESET_USER, created: now, addrs: vec![], nodes: vec![] };
        let holders: Vec<Pk> = (0..8).map(|_| ident().public_key_bytes()).collect();
        let barrier = std::sync::Barrier::new(holders.len());
        let res: Vec<Claim> = std::thread::scope(|s| {
            let hs: Vec<_> = holders.iter().map(|h| {
                let (dir, inv, barrier) = (&dir, &inv, &barrier);
                s.spawn(move || {
                    let tag = inv.mac(h).unwrap();
                    barrier.wait();
                    pin_claim(dir, &inv.admin, h, &tag, now)
                })
            }).collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(res.iter().filter(|c| matches!(c, Claim::New { .. })).count(), 1, "{res:?}");
        assert_eq!(res.iter().filter(|c| **c == Claim::Spent).count(), holders.len() - 1, "{res:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// H8: если выдача после New не удалась, pin возвращается; откат чужим держателем не действует.
    #[test]
    fn unclaim_returns_pin_after_failed_issue() {
        let dir = std::env::temp_dir().join(format!("rawg-pin-unclaim-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let admin = ident();
        let (n1, n2) = (ident(), ident());
        let now = 5_000_000u64;
        let root = *admin.hash();
        let pin = pin_create(&dir, &root, PRESET_USER, "u", now).unwrap();
        let inv = Invite { admin: admin.public_key_bytes(), root_pk: None, pin, rights: PRESET_USER, created: now, addrs: vec![], nodes: vec![] };
        let (p1, p2) = (n1.public_key_bytes(), n2.public_key_bytes());
        assert_eq!(pin_claim(&dir, &inv.admin, &p1, &inv.mac(&p1).unwrap(), now), Claim::New { rights: PRESET_USER, root });
        assert!(!pin_unclaim(&dir, &inv.admin, &p2, &inv.mac(&p2).unwrap()), "чужой держатель откатить не может");
        assert_eq!(pin_claim(&dir, &inv.admin, &p1, &inv.mac(&p1).unwrap(), now), Claim::Repeat { root }, "имитация падения до issue");
        assert!(pin_unclaim(&dir, &inv.admin, &p1, &inv.mac(&p1).unwrap()));
        assert_eq!(pin_claim(&dir, &inv.admin, &p2, &inv.mac(&p2).unwrap(), now), Claim::New { rights: PRESET_USER, root });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Погашенный pin помнится в пределах срока (повтор держателя), после срока уборка его убирает.
    #[test]
    fn spent_pin_repeat_within_ttl_then_dropped() {
        let dir = std::env::temp_dir().join(format!("rawg-pin-ttl-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let admin = ident();
        let n1 = ident().public_key_bytes();
        let now = 5_000_000u64;
        let root = *admin.hash();
        let pin = pin_create(&dir, &root, PRESET_USER, "t", now).unwrap();
        let inv = Invite { admin: admin.public_key_bytes(), root_pk: None, pin, rights: PRESET_USER, created: now, addrs: vec![], nodes: vec![] };
        assert!(matches!(pin_claim(&dir, &inv.admin, &n1, &inv.mac(&n1).unwrap(), now), Claim::New { .. }));
        assert_eq!(pin_claim(&dir, &inv.admin, &n1, &inv.mac(&n1).unwrap(), now + 60), Claim::Repeat { root });
        assert_eq!(pin_claim(&dir, &inv.admin, &n1, &inv.mac(&n1).unwrap(), now + INVITE_TTL_S + 1), Claim::Expired,
            "Repeat после срока не должен оживлять приглашение");
        pin_create(&dir, &root, USE, "sweep", now + INVITE_TTL_S + 10).unwrap();
        assert_eq!(pin_claim(&dir, &inv.admin, &n1, &inv.mac(&n1).unwrap(), now + INVITE_TTL_S + 10), Claim::Unknown);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invite_encoding_is_strict_and_pin_rights_are_bounded() {
        let admin = ident();
        let invalid = Invite { admin: admin.public_key_bytes(), root_pk: None, pin: [1; 16], rights: USE, created: 1,
            addrs: vec!["a".into(); 5], nodes: vec![] };
        assert!(invalid.encode().unwrap_err().to_string().contains("4 адресов"));
        let invalid = Invite { addrs: vec!["x".repeat(201)], ..invalid.clone() };
        assert!(invalid.encode().is_err());
        let dir = std::env::temp_dir().join(format!("rawg-pin-rights-{}-{}", std::process::id(), now_ms()));
        assert!(pin_create(&dir, admin.hash(), ALL | 0x8000, "bad", 5_000_000).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn pin_errors_do_not_disclose_pin_filename() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rawg-pin-redact-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = [0x73; 16];
        let pin = pin_create(&dir, &root, USE, "safe", 5_000_000).unwrap();
        std::fs::set_permissions(pins_dir(&dir), std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = pin_create(&dir, &root, USE, "failure", 5_000_001).unwrap_err();
        let rendered = format!("{err:#}");
        assert!(!rendered.contains(&hex(&pin)), "ошибка не должна раскрывать hex имени pin");
        std::fs::set_permissions(pins_dir(&dir), std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        let dir = std::env::temp_dir().join(format!("rawg-pol-{}-{}", std::process::id(), now_ms()));
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
