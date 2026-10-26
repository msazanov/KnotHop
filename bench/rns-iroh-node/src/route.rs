//! Раздельное туннелирование клиента: правила по спискам (формат geoip.dat/geosite.dat проекта v2ray) и ручные списки.
//!
//! Конфиг `state/routing.json` пишет приложение, клиент перечитывает его при изменении. Решение принимается по IPv4-адресу назначения:
//! подсети (geoip, ручные CIDR/IP) сопоставляются сразу, домены (geosite, ручные) - по DNS-ответам, которые проходят через туннель
//! (адрес из ответа получает действие правила, совпавшего с именем). Каждое правило имеет ранг (ручные - выше списков, дальше по порядку),
//! побеждает наименьший. Действие `Direct` для подсетей исполняется вне туннеля (исключённые маршруты Android), поэтому в туннель такие
//! пакеты не попадают; адрес, ставший «прямым» только по домену, уходит через основной выход (обойти туннель из TUN нельзя).
//! Весь вход недоверенный: файлы правил и DNS-ответы разбираются с ограничением размеров, без паник.

use super::*;
use std::io::{BufReader, Read, Seek, SeekFrom};

/// Не больше доменов и подсетей на одну категорию: больше телефон не удержит в памяти.
pub const MAX_DOMAINS: usize = 400_000;
pub const MAX_CIDRS: usize = 300_000;
const MAX_RULES: usize = 64;
const MAX_MANUAL: usize = 2_000;
const DNS_MAP_MAX: usize = 32_768;
/// Срок жизни адреса из DNS-ответа: не короче 5 мин (соединения живут дольше TTL), не длиннее часа.
const DNS_MIN: u32 = 300;
const DNS_MAX: u32 = 3_600;
const RANK_LIST: u32 = 1_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// основной выход (ручной select либо автоматический выбор supervisor)
    Default,
    /// мимо туннеля
    Direct,
    /// через указанный выход
    Exit([u8; 16]),
}

impl Action {
    pub fn parse(s: &str) -> Option<Action> {
        match s {
            "default" => Some(Action::Default),
            "direct" => Some(Action::Direct),
            _ => {
                let h = s.strip_prefix("exit:")?;
                if h.len() != 32 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                let v = unhex(h);
                Some(Action::Exit(v.try_into().ok()?))
            }
        }
    }
}

// ---------- формат .dat (protobuf) ----------

enum Val<'a> {
    Var(u64),
    Bytes(&'a [u8]),
}

struct Fields<'a> {
    b: &'a [u8],
    i: usize,
}

fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let (mut n, mut s) = (0u64, 0u32);
    loop {
        let c = *b.get(*i)?;
        *i += 1;
        if s >= 64 {
            return None;
        }
        n |= u64::from(c & 0x7f) << s;
        s += 7;
        if c < 0x80 {
            return Some(n);
        }
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = (u32, Val<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        let tag = varint(self.b, &mut self.i)?;
        let (f, wt) = ((tag >> 3) as u32, tag & 7);
        match wt {
            0 => Some((f, Val::Var(varint(self.b, &mut self.i)?))),
            2 => {
                let n = varint(self.b, &mut self.i)? as usize;
                let end = self.i.checked_add(n)?;
                let s = self.b.get(self.i..end)?;
                self.i = end;
                Some((f, Val::Bytes(s)))
            }
            // фиксированные поля в этих файлах не встречаются: разбор прекращаем
            _ => None,
        }
    }
}

fn rd_varint<R: Read>(r: &mut R) -> Option<u64> {
    let (mut n, mut s) = (0u64, 0u32);
    loop {
        let mut c = [0u8; 1];
        r.read_exact(&mut c).ok()?;
        if s >= 64 {
            return None;
        }
        n |= u64::from(c[0] & 0x7f) << s;
        s += 7;
        if c[0] < 0x80 {
            return Some(n);
        }
    }
}

/// Запись верхнего уровня: имя категории, смещение и длина тела.
pub struct Entry {
    pub name: String,
    off: u64,
    pub len: u64,
}

/// Оглавление файла `.dat`: читает только заголовки записей, тела пропускает.
pub fn scan(path: &Path) -> Result<Vec<Entry>> {
    let f = std::fs::File::open(path)?;
    let size = f.metadata()?.len();
    let mut r = BufReader::with_capacity(1 << 16, f);
    let mut out = Vec::new();
    loop {
        let Some(tag) = rd_varint(&mut r) else { break };
        if tag & 7 != 2 {
            bail!("неожиданный формат файла");
        }
        let Some(len) = rd_varint(&mut r) else { break };
        let off = r.stream_position()?;
        if off.checked_add(len).map(|e| e > size).unwrap_or(true) {
            bail!("файл обрезан");
        }
        let mut head = vec![0u8; len.min(96) as usize];
        r.read_exact(&mut head)?;
        let name = Fields { b: &head, i: 0 }.find_map(|(f, v)| match (f, v) {
            (1, Val::Bytes(s)) => Some(String::from_utf8_lossy(s).into_owned()),
            _ => None,
        });
        if let Some(name) = name {
            if out.len() < 20_000 {
                out.push(Entry { name, off, len });
            }
        }
        r.seek_relative(len as i64 - head.len() as i64)?;
    }
    Ok(out)
}

fn read_body(path: &Path, e: &Entry) -> Result<Vec<u8>> {
    if e.len > 256 * 1024 * 1024 {
        bail!("категория слишком большая");
    }
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(e.off))?;
    let mut v = vec![0u8; e.len as usize];
    f.read_exact(&mut v)?;
    Ok(v)
}

/// IPv4-подсети категории geoip: (адрес, длина префикса). IPv6 отбрасывается (туннель переносит только IPv4).
pub fn load_cidrs(path: &Path, e: &Entry) -> Result<Vec<(u32, u8)>> {
    let body = read_body(path, e)?;
    let mut out = Vec::new();
    for (f, v) in (Fields { b: &body, i: 0 }) {
        let (2, Val::Bytes(c)) = (f, v) else { continue };
        let (mut ip, mut pre) = (None, 0u64);
        for (cf, cv) in (Fields { b: c, i: 0 }) {
            match (cf, cv) {
                (1, Val::Bytes(b)) if b.len() == 4 => ip = Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                (2, Val::Var(p)) => pre = p,
                _ => {}
            }
        }
        if let Some(ip) = ip {
            if pre <= 32 {
                if out.len() >= MAX_CIDRS {
                    bail!("в категории больше {MAX_CIDRS} подсетей");
                }
                out.push((ip, pre as u8));
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DKind {
    Plain,
    Regex,
    Domain,
    Full,
}

/// Домены категории geosite: (вид, значение в нижнем регистре).
pub fn load_domains(path: &Path, e: &Entry) -> Result<Vec<(DKind, String)>> {
    let body = read_body(path, e)?;
    let mut out = Vec::new();
    for (f, v) in (Fields { b: &body, i: 0 }) {
        let (2, Val::Bytes(d)) = (f, v) else { continue };
        let (mut k, mut val) = (DKind::Plain, None);
        for (df, dv) in (Fields { b: d, i: 0 }) {
            match (df, dv) {
                (1, Val::Var(t)) => k = match t { 0 => DKind::Plain, 1 => DKind::Regex, 2 => DKind::Domain, _ => DKind::Full },
                (2, Val::Bytes(s)) => val = Some(String::from_utf8_lossy(s).to_lowercase()),
                _ => {}
            }
        }
        if let Some(v) = val {
            if out.len() >= MAX_DOMAINS {
                bail!("в категории больше {MAX_DOMAINS} доменов");
            }
            out.push((k, v));
        }
    }
    Ok(out)
}

// ---------- конфиг ----------

#[derive(Clone, Debug, PartialEq)]
pub struct RuleCfg {
    /// "geosite" | "geoip"
    pub kind: String,
    pub name: String,
    pub action: Action,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ManualCfg {
    pub value: String,
    pub action: Action,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cfg {
    /// "auto" | "rules"; legacy "priority" configs normalize to "auto".
    pub mode: String,
    pub priority: Vec<[u8; 16]>,
    pub rules: Vec<RuleCfg>,
    pub manual: Vec<ManualCfg>,
}

impl Default for Cfg {
    fn default() -> Cfg {
        Cfg { mode: "auto".into(), priority: Vec::new(), rules: Vec::new(), manual: Vec::new() }
    }
}

impl Cfg {
    pub fn parse(s: &str) -> Cfg {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(s) else { return Cfg::default() };
        let mode = if v["mode"].as_str() == Some("rules") { "rules".to_string() } else { "auto".to_string() };
        // Retain the legacy field in the in-memory type for source compatibility, but do not parse
        // or export user exit rankings. Rules remain independent and keep their own precedence.
        let priority = Vec::new();
        let rules = v["rules"].as_array().map(|a| a.iter().filter_map(|x| {
            let kind = x["t"].as_str().filter(|t| *t == "geosite" || *t == "geoip")?.to_string();
            let name = x["n"].as_str().filter(|n| !n.is_empty() && n.len() <= 80)?.to_string();
            Some(RuleCfg { kind, name, action: Action::parse(x["a"].as_str()?)? })
        }).take(MAX_RULES).collect()).unwrap_or_default();
        let manual = v["manual"].as_array().map(|a| a.iter().filter_map(|x| {
            let value = x["v"].as_str().map(str::trim).filter(|n| !n.is_empty() && n.len() <= 253)?.to_string();
            Some(ManualCfg { value, action: Action::parse(x["a"].as_str()?)? })
        }).take(MAX_MANUAL).collect()).unwrap_or_default();
        Cfg { mode, priority, rules, manual }
    }

    pub fn load(state: &Path) -> Cfg {
        match std::fs::metadata(state.join("routing.json")) {
            Ok(m) if m.len() <= 512 * 1024 => Cfg::parse(&std::fs::read_to_string(state.join("routing.json")).unwrap_or_default()),
            _ => Cfg::default(),
        }
    }

    /// Выходы, на которые правила шлют трафик (не считая основного).
    pub fn exits(&self) -> Vec<[u8; 16]> {
        let mut v: Vec<[u8; 16]> = Vec::new();
        let acts = self.manual.iter().map(|m| m.action).chain(self.rules.iter().map(|r| r.action));
        for a in acts {
            if let Action::Exit(d) = a {
                if !v.contains(&d) {
                    v.push(d);
                }
            }
        }
        v
    }

}

// ---------- сопоставление ----------

#[derive(Default)]
struct Doms {
    full: HashMap<String, u32>,
    suffix: HashMap<String, u32>,
    plain: Vec<(String, u32)>,
}

fn put_min(m: &mut HashMap<String, u32>, k: String, rank: u32) {
    let e = m.entry(k).or_insert(rank);
    if rank < *e {
        *e = rank;
    }
}

impl Doms {
    fn add(&mut self, k: DKind, v: String, rank: u32) {
        match k {
            DKind::Full => put_min(&mut self.full, v, rank),
            DKind::Domain => put_min(&mut self.suffix, v, rank),
            DKind::Plain => self.plain.push((v, rank)),
            // регулярные выражения не поддерживаются (нужна отдельная зависимость и защита от тяжёлых выражений)
            DKind::Regex => {}
        }
    }

    fn lookup(&self, name: &str) -> Option<u32> {
        let mut best: Option<u32> = self.full.get(name).copied();
        let mut s = name;
        loop {
            if let Some(r) = self.suffix.get(s) {
                best = Some(best.map_or(*r, |b| b.min(*r)));
            }
            match s.find('.') {
                Some(i) => s = &s[i + 1..],
                None => break,
            }
        }
        for (p, r) in &self.plain {
            if name.contains(p.as_str()) {
                best = Some(best.map_or(*r, |b| b.min(*r)));
            }
        }
        best
    }

    fn is_empty(&self) -> bool {
        self.full.is_empty() && self.suffix.is_empty() && self.plain.is_empty()
    }
}

/// Диапазоны [start, end] по возрастанию, слитые.
fn merge(mut v: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    v.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(l) if u64::from(s) <= u64::from(l.1) + 1 => l.1 = l.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

fn cidr_range(ip: u32, pre: u8) -> (u32, u32) {
    let mask = if pre == 0 { 0 } else { u32::MAX << (32 - u32::from(pre)) };
    (ip & mask, (ip & mask) | !mask)
}

fn contains(v: &[(u32, u32)], x: u32) -> bool {
    match v.binary_search_by(|r| if r.1 < x { std::cmp::Ordering::Less } else if r.0 > x { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Equal }) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Минимальный набор подсетей, покрывающий диапазоны.
pub fn ranges_to_cidrs(ranges: &[(u32, u32)]) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    for &(s, e) in ranges {
        let (mut s, e) = (u64::from(s), u64::from(e));
        while s <= e {
            let mut bits = if s == 0 { 32 } else { s.trailing_zeros().min(32) };
            while (1u64 << bits) > e - s + 1 {
                bits -= 1;
            }
            out.push((s as u32, (32 - bits) as u8));
            s += 1u64 << bits;
        }
    }
    out
}

pub struct Router {
    actions: Vec<Action>,
    /// (ранг, слитые диапазоны), по возрастанию ранга
    ips: Vec<(u32, Vec<(u32, u32)>)>,
    doms: Doms,
    dns: std::sync::RwLock<HashMap<u32, (u32, Instant)>>,
    pub warnings: Vec<String>,
    /// сколько записей загружено по каждому правилу: (имя, доменов, подсетей)
    pub stats: Vec<(String, usize, usize)>,
}

impl Router {
    pub fn empty() -> Router {
        Router { actions: Vec::new(), ips: Vec::new(), doms: Doms::default(), dns: Default::default(), warnings: Vec::new(), stats: Vec::new() }
    }

    /// Собрать по конфигу; категории читаются из `rules_dir/geoip.dat` и `geosite.dat`.
    pub fn build(cfg: &Cfg, rules_dir: &Path) -> Router {
        let mut r = Router::empty();
        let mut ip_rank: HashMap<u32, Vec<(u32, u32)>> = HashMap::new();
        let rank_of = |r: &mut Router, a: Action| -> u32 {
            r.actions.push(a);
            (r.actions.len() - 1) as u32
        };
        // ручные списки: ранги 0.., выше любых категорий
        for m in &cfg.manual {
            let rank = rank_of(&mut r, m.action);
            let v = m.value.to_lowercase();
            if let Some((ip, pre)) = parse_cidr(&v) {
                ip_rank.entry(rank).or_default().push(cidr_range(ip, pre));
                continue;
            }
            let (k, val) = match v.split_once(':') {
                Some(("full", x)) => (DKind::Full, x),
                Some(("domain", x)) => (DKind::Domain, x),
                Some(("keyword", x)) => (DKind::Plain, x),
                _ => (DKind::Domain, v.as_str()),
            };
            let val = val.trim().trim_start_matches("*.").trim_matches('.');
            if val.is_empty() || !val.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b >= 0x80) {
                r.warnings.push(format!("ручной список: не разобрано «{}»", m.value.chars().take(40).collect::<String>()));
                continue;
            }
            r.doms.add(k, val.to_string(), rank);
        }
        // категории: ранги RANK_LIST+i (пустые слоты в actions заполняются Default, чтобы индекс совпадал с рангом)
        let manual_n = r.actions.len() as u32;
        if manual_n > RANK_LIST {
            r.warnings.push("слишком много ручных записей".into());
        }
        while (r.actions.len() as u32) < RANK_LIST {
            r.actions.push(Action::Default);
        }
        let mut toc: HashMap<&'static str, Option<Vec<Entry>>> = HashMap::new();
        for (i, rule) in cfg.rules.iter().enumerate() {
            let rank = RANK_LIST + i as u32;
            r.actions.push(rule.action);
            let file = if rule.kind == "geoip" { "geoip.dat" } else { "geosite.dat" };
            let key: &'static str = if rule.kind == "geoip" { "geoip" } else { "geosite" };
            let path = rules_dir.join(file);
            let entries = toc.entry(key).or_insert_with(|| scan(&path).ok());
            let Some(entries) = entries else {
                r.warnings.push(format!("{}: нет файла списков, скачайте их", rule.name));
                continue;
            };
            let Some(e) = entries.iter().find(|e| e.name.eq_ignore_ascii_case(&rule.name)) else {
                r.warnings.push(format!("{}: нет такой категории", rule.name));
                continue;
            };
            if rule.kind == "geoip" {
                match load_cidrs(&path, e) {
                    Ok(c) => {
                        r.stats.push((rule.name.clone(), 0, c.len()));
                        ip_rank.entry(rank).or_default().extend(c.into_iter().map(|(ip, p)| cidr_range(ip, p)));
                    }
                    Err(x) => r.warnings.push(format!("{}: {x}", rule.name)),
                }
            } else {
                match load_domains(&path, e) {
                    Ok(d) => {
                        r.stats.push((rule.name.clone(), d.len(), 0));
                        for (k, v) in d {
                            r.doms.add(k, v, rank);
                        }
                    }
                    Err(x) => r.warnings.push(format!("{}: {x}", rule.name)),
                }
            }
        }
        let mut ranks: Vec<u32> = ip_rank.keys().copied().collect();
        ranks.sort_unstable();
        for k in ranks {
            r.ips.push((k, merge(ip_rank.remove(&k).unwrap_or_default())));
        }
        r
    }

    pub fn has_domains(&self) -> bool {
        !self.doms.is_empty()
    }

    fn action(&self, rank: u32) -> Action {
        self.actions.get(rank as usize).copied().unwrap_or(Action::Default)
    }

    /// Действие для адреса назначения.
    pub fn decide(&self, dst: u32) -> Action {
        let mut best: Option<u32> = None;
        for (rank, v) in &self.ips {
            if contains(v, dst) {
                best = Some(*rank);
                break;
            }
        }
        if self.doms.is_empty() {
            return best.map(|r| self.action(r)).unwrap_or(Action::Default);
        }
        if let Some((rank, until)) = self.dns.read().unwrap().get(&dst) {
            if *until > Instant::now() && best.map_or(true, |b| *rank < b) {
                best = Some(*rank);
            }
        }
        best.map(|r| self.action(r)).unwrap_or(Action::Default)
    }

    /// Ранг домена (для проверки и DNS-ответов).
    fn domain_rank(&self, name: &str) -> Option<u32> {
        self.doms.lookup(name)
    }

    /// Подсети, которые правила велят отправлять мимо туннеля: для исключённых маршрутов.
    pub fn direct_cidrs(&self) -> Vec<(u32, u8)> {
        let mut all: Vec<(u32, u32)> = Vec::new();
        for (rank, v) in &self.ips {
            if self.action(*rank) == Action::Direct {
                all.extend(v.iter().copied());
            }
        }
        ranges_to_cidrs(&merge(all))
    }

    /// Предупреждение, если подсетей «мимо туннеля» больше, чем принимает система (см. `MAX_EXCLUDED`).
    pub fn cap_note(&self) -> Option<String> {
        let all = self.direct_cidrs();
        let total = all.len();
        if total <= MAX_EXCLUDED {
            return None;
        }
        let (_, covered) = cap_cidrs(all, MAX_EXCLUDED);
        Some(format!("подсетей «мимо VPN» {total}, система принимает не больше {MAX_EXCLUDED}: самые мелкие блоки ({:.1}% адресов) пойдут через VPN", (1.0 - covered) * 100.0))
    }

    /// DNS-over-TLS/QUIC (порт 853) скрывает ответы от `snoop`. Пока есть доменные правила, такие пакеты отбрасываются: автоматический
    /// «Частный DNS» Android после неудачной проверки откатывается на обычный DNS, который виден. Явно заданный пользователем DoT-сервер
    /// так не обойти, это ограничение доменных правил.
    pub fn blocks_encrypted_dns(&self, pkt: &[u8]) -> bool {
        if self.doms.is_empty() || pkt.len() < 24 || (pkt[9] != 6 && pkt[9] != 17) {
            return false;
        }
        let ihl = usize::from(pkt[0] & 15) * 4;
        // непервый фрагмент порта не содержит
        if ihl < 20 || pkt.len() < ihl + 4 || u16::from_be_bytes([pkt[6] & 0x1f, pkt[7]]) != 0 {
            return false;
        }
        u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]) == 853
    }

    /// DNS-ответ, пришедший через туннель: адреса из него получают действие правила, совпавшего с именем.
    pub fn snoop(&self, pkt: &[u8]) {
        if self.doms.is_empty() || pkt.len() < 40 || pkt[9] != 17 {
            return;
        }
        let ihl = usize::from(pkt[0] & 15) * 4;
        if ihl < 20 || pkt.len() < ihl + 8 + 12 || u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]) != 53 {
            return;
        }
        let _ = self.parse_dns(&pkt[ihl + 8..]);
    }

    fn parse_dns(&self, d: &[u8]) -> Option<()> {
        let flags = u16::from_be_bytes([d[2], d[3]]);
        if flags & 0x8000 == 0 || flags & 0xf != 0 {
            return None;
        }
        let (qd, an) = (u16::from_be_bytes([d[4], d[5]]), u16::from_be_bytes([d[6], d[7]]));
        if qd == 0 || qd > 4 || an == 0 || an > 64 {
            return None;
        }
        let mut i = 12usize;
        let mut rank: Option<u32> = None;
        let note = |n: &str, rank: &mut Option<u32>| {
            if let Some(r) = self.domain_rank(n) {
                *rank = Some(rank.map_or(r, |b| b.min(r)));
            }
        };
        for _ in 0..qd {
            let (n, ni) = dns_name(d, i)?;
            note(&n, &mut rank);
            i = ni.checked_add(4)?;
        }
        let mut addrs: Vec<(u32, u32)> = Vec::new();
        for _ in 0..an {
            let (n, ni) = dns_name(d, i)?;
            note(&n, &mut rank);
            let h = d.get(ni..ni + 10)?;
            let (typ, ttl, rdlen) = (u16::from_be_bytes([h[0], h[1]]), u32::from_be_bytes([h[4], h[5], h[6], h[7]]), usize::from(u16::from_be_bytes([h[8], h[9]])));
            let rd = d.get(ni + 10..ni + 10 + rdlen)?;
            if typ == 1 && rdlen == 4 {
                addrs.push((u32::from_be_bytes([rd[0], rd[1], rd[2], rd[3]]), ttl));
            } else if typ == 5 {
                // цель CNAME тоже может быть в списке (сам ответ на неё идёт отдельной записью с её именем)
                if let Some((t, _)) = dns_name(d, ni + 10) {
                    note(&t, &mut rank);
                }
            }
            i = ni + 10 + rdlen;
        }
        let rank = rank?;
        let now = Instant::now();
        let mut m = self.dns.write().unwrap();
        if m.len() + addrs.len() > DNS_MAP_MAX {
            m.retain(|_, (_, u)| *u > now);
            if m.len() + addrs.len() > DNS_MAP_MAX {
                m.clear();
            }
        }
        for (ip, ttl) in addrs {
            m.insert(ip, (rank, now + Duration::from_secs(u64::from(ttl.clamp(DNS_MIN, DNS_MAX)))));
        }
        Some(())
    }

    #[cfg(test)]
    fn learned(&self) -> usize {
        self.dns.read().unwrap().len()
    }
}

/// Имя из DNS-сообщения (со сжатием), в нижнем регистре; возвращает и позицию после имени в основном потоке.
fn dns_name(d: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end: Option<usize> = None;
    for _ in 0..40 {
        let l = usize::from(*d.get(i)?);
        if l == 0 {
            return Some((out, end.unwrap_or(i + 1)));
        }
        if l & 0xc0 == 0xc0 {
            let p = ((l & 0x3f) << 8) | usize::from(*d.get(i + 1)?);
            end.get_or_insert(i + 2);
            if p >= i {
                return None;
            }
            i = p;
            continue;
        }
        if l > 63 {
            return None;
        }
        let lab = d.get(i + 1..i + 1 + l)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(lab).to_lowercase());
        if out.len() > 253 {
            return None;
        }
        i += 1 + l;
    }
    None
}

/// "1.2.3.4" или "1.2.3.0/24".
pub fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (a, p) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok().filter(|p| *p <= 32)?),
        None => (s, 32),
    };
    Some((u32::from(a.parse::<std::net::Ipv4Addr>().ok()?), p))
}

fn put(p: &Path, data: &[u8]) {
    let tmp = p.with_extension("tmp");
    if std::fs::write(&tmp, data).is_ok() {
        let _ = std::fs::rename(&tmp, p);
    }
}

/// Каталог файлов списков: рядом с каталогом состояния (приложение кладёт туда geoip.dat и geosite.dat).
pub fn rules_dir(state: &Path) -> PathBuf {
    state.parent().unwrap_or(state).join("rules")
}

/// `rules-list`: оглавление скачанных файлов для интерфейса (имя категории и размер записи в байтах как мера величины).
pub fn cmd_list(state: &Path) -> Result<()> {
    let d = rules_dir(state);
    let mut j = serde_json::Map::new();
    for (k, f) in [("geosite", "geosite.dat"), ("geoip", "geoip.dat")] {
        let v: Vec<serde_json::Value> = match scan(&d.join(f)) {
            Ok(t) => t.iter().map(|e| serde_json::json!([e.name, e.len])).collect(),
            Err(_) => Vec::new(),
        };
        j.insert(k.into(), v.into());
    }
    std::fs::create_dir_all(state)?;
    put(&state.join("rules-cats.json"), serde_json::Value::Object(j).to_string().as_bytes());
    Ok(())
}

/// `rules-compile`: подсети для исключённых маршрутов VpnService (правила с действием «мимо туннеля») и отчёт о загрузке.
/// Сколько исключённых маршрутов принимает VpnService: список передаётся одной Binder-транзакцией (~84 байта на маршрут, предел около 1 МБ;
/// 13 029 маршрутов дали TransactionTooLargeException на 1 095 020 байтах). Берём запас.
pub const MAX_EXCLUDED: usize = 10_000;

/// Оставляет не больше `max` подсетей, отбрасывая самые мелкие: их адреса пойдут через VPN (безопасная сторона), а не мимо него.
/// Возвращает оставленные подсети и долю адресов, которую они покрывают.
pub fn cap_cidrs(mut v: Vec<(u32, u8)>, max: usize) -> (Vec<(u32, u8)>, f64) {
    let size = |p: u8| 1u64 << (32 - u32::from(p));
    let total: u64 = v.iter().map(|c| size(c.1)).sum();
    if v.len() > max {
        v.sort_by_key(|c| (c.1, c.0));
        v.truncate(max);
        v.sort();
    }
    let kept: u64 = v.iter().map(|c| size(c.1)).sum();
    (v, if total == 0 { 1.0 } else { kept as f64 / total as f64 })
}

/// `rules-compile`: подсети для исключённых маршрутов VpnService (правила с действием «мимо туннеля») и отчёт о загрузке.
pub fn cmd_compile(state: &Path) -> Result<()> {
    let cfg = Cfg::load(state);
    let r = if cfg.mode == "rules" { Router::build(&cfg, &rules_dir(state)) } else { Router::empty() };
    let all = r.direct_cidrs();
    let total = all.len();
    let (cidrs, covered) = cap_cidrs(all, MAX_EXCLUDED);
    let mut t = String::new();
    for (ip, p) in &cidrs {
        t.push_str(&format!("{}/{p}\n", std::net::Ipv4Addr::from(*ip)));
    }
    std::fs::create_dir_all(state)?;
    put(&state.join("direct.cidr"), t.as_bytes());
    let mut warnings = r.warnings.clone();
    warnings.extend(r.cap_note());
    let rep = serde_json::json!({"warnings": warnings, "stats": r.stats, "direct": cidrs.len(), "direct_total": total, "covered": covered});
    put(&state.join("rules-report.json"), rep.to_string().as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pb_len(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let mut n = body.len();
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                v.push(b);
                break;
            }
            v.push(b | 0x80);
        }
        v.extend_from_slice(body);
        v
    }

    fn geosite(cats: &[(&str, Vec<(u8, &str)>)]) -> Vec<u8> {
        let mut file = Vec::new();
        for (name, doms) in cats {
            let mut e = pb_len(0x0a, name.as_bytes());
            for (t, d) in doms {
                let mut dm = vec![0x08, *t];
                dm.extend(pb_len(0x12, d.as_bytes()));
                e.extend(pb_len(0x12, &dm));
            }
            file.extend(pb_len(0x0a, &e));
        }
        file
    }

    fn geoip(cats: &[(&str, Vec<([u8; 4], u8)>)]) -> Vec<u8> {
        let mut file = Vec::new();
        for (name, nets) in cats {
            let mut e = pb_len(0x0a, name.as_bytes());
            for (ip, p) in nets {
                let mut c = pb_len(0x0a, ip);
                c.extend([0x10, *p]);
                e.extend(pb_len(0x12, &c));
            }
            file.extend(pb_len(0x0a, &e));
        }
        file
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("knothop-route-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn exit_a() -> Action {
        Action::Exit([0xaa; 16])
    }

    fn dns_reply(q: &str, ips: &[[u8; 4]]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, ips.len() as u8, 0, 0, 0, 0];
        for l in q.split('.') {
            m.push(l.len() as u8);
            m.extend(l.as_bytes());
        }
        m.extend([0, 0, 1, 0, 1]);
        for ip in ips {
            m.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            m.extend(ip);
        }
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 8, 8, 8, 8, 10, 0, 0, 2];
        let ulen = (8 + m.len()) as u16;
        p.extend([0, 53, 0x80, 0, (ulen >> 8) as u8, ulen as u8, 0, 0]);
        p.extend(m);
        p
    }

    #[test]
    fn dat_scan_and_load() {
        let d = tmp("scan");
        std::fs::write(d.join("geosite.dat"), geosite(&[("YOUTUBE", vec![(2, "youtube.com"), (3, "yt.be"), (0, "ytimg")]), ("EMPTY", vec![])])).unwrap();
        std::fs::write(d.join("geoip.dat"), geoip(&[("RU", vec![([10, 0, 0, 0], 8), ([192, 168, 1, 0], 24)])])).unwrap();
        let t = scan(&d.join("geosite.dat")).unwrap();
        assert_eq!(t.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["YOUTUBE", "EMPTY"]);
        let doms = load_domains(&d.join("geosite.dat"), &t[0]).unwrap();
        assert_eq!(doms.len(), 3);
        assert_eq!(doms[0], (DKind::Domain, "youtube.com".to_string()));
        let ti = scan(&d.join("geoip.dat")).unwrap();
        assert_eq!(load_cidrs(&d.join("geoip.dat"), &ti[0]).unwrap(), vec![(0x0a000000, 8), (0xc0a80100, 24)]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn broken_dat_does_not_panic() {
        let d = tmp("broken");
        for junk in [vec![0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f], vec![0x0a, 0x05, 1, 2], vec![0x08, 0x01], vec![0xff; 40], vec![]] {
            std::fs::write(d.join("x.dat"), &junk).unwrap();
            let _ = scan(&d.join("x.dat"));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ranks_manual_beats_lists_and_order_matters() {
        let d = tmp("rank");
        std::fs::write(d.join("geoip.dat"), geoip(&[("RU", vec![([10, 0, 0, 0], 8)]), ("BIG", vec![([10, 1, 0, 0], 16)])])).unwrap();
        let cfg = Cfg {
            mode: "rules".into(),
            priority: vec![],
            rules: vec![
                RuleCfg { kind: "geoip".into(), name: "ru".into(), action: Action::Direct },
                RuleCfg { kind: "geoip".into(), name: "BIG".into(), action: exit_a() },
            ],
            manual: vec![ManualCfg { value: "10.1.2.3".into(), action: Action::Default }],
        };
        let r = Router::build(&cfg, &d);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let ip = |a: [u8; 4]| u32::from_be_bytes(a);
        assert_eq!(r.decide(ip([10, 1, 2, 3])), Action::Default, "ручной выше списков");
        assert_eq!(r.decide(ip([10, 1, 9, 9])), Action::Direct, "первое правило списка побеждает");
        assert_eq!(r.decide(ip([10, 200, 0, 1])), Action::Direct);
        assert_eq!(r.decide(ip([8, 8, 8, 8])), Action::Default);
        assert_eq!(r.direct_cidrs(), vec![(0x0a000000, 8)]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn domains_from_dns_answers() {
        let d = tmp("dns");
        std::fs::write(d.join("geosite.dat"), geosite(&[("YOUTUBE", vec![(2, "youtube.com"), (3, "yt.be")])])).unwrap();
        let cfg = Cfg {
            mode: "rules".into(),
            priority: vec![],
            rules: vec![RuleCfg { kind: "geosite".into(), name: "youtube".into(), action: exit_a() }],
            manual: vec![ManualCfg { value: "domain:example.org".into(), action: Action::Direct }],
        };
        let r = Router::build(&cfg, &d);
        assert!(r.has_domains());
        r.snoop(&dns_reply("www.youtube.com", &[[1, 2, 3, 4], [1, 2, 3, 5]]));
        r.snoop(&dns_reply("other.net", &[[9, 9, 9, 9]]));
        r.snoop(&dns_reply("sub.example.org", &[[7, 7, 7, 7]]));
        let ip = |a: [u8; 4]| u32::from_be_bytes(a);
        assert_eq!(r.decide(ip([1, 2, 3, 4])), exit_a());
        assert_eq!(r.decide(ip([1, 2, 3, 5])), exit_a());
        assert_eq!(r.decide(ip([9, 9, 9, 9])), Action::Default);
        assert_eq!(r.decide(ip([7, 7, 7, 7])), Action::Direct);
        assert_eq!(r.learned(), 3);
        // «yt.be» только точное совпадение
        r.snoop(&dns_reply("a.yt.be", &[[5, 5, 5, 5]]));
        assert_eq!(r.decide(ip([5, 5, 5, 5])), Action::Default);
        r.snoop(&dns_reply("yt.be", &[[6, 6, 6, 6]]));
        assert_eq!(r.decide(ip([6, 6, 6, 6])), exit_a());
        // DoT: 853 по TCP и UDP отбрасывается, обычный трафик и порт 53 - нет
        let pk = |proto: u8, port: u16, frag: u16| {
            let mut p = vec![0u8; 40];
            p[0] = 0x45;
            p[6..8].copy_from_slice(&frag.to_be_bytes());
            p[9] = proto;
            p[22..24].copy_from_slice(&port.to_be_bytes());
            p
        };
        assert!(r.blocks_encrypted_dns(&pk(6, 853, 0)));
        assert!(r.blocks_encrypted_dns(&pk(17, 853, 0x4000)));
        assert!(!r.blocks_encrypted_dns(&pk(6, 443, 0)));
        assert!(!r.blocks_encrypted_dns(&pk(17, 53, 0)));
        assert!(!r.blocks_encrypted_dns(&pk(6, 853, 0x0010)), "непервый фрагмент");
        assert!(!r.blocks_encrypted_dns(&pk(1, 853, 0)), "ICMP");
        assert!(!Router::empty().blocks_encrypted_dns(&pk(6, 853, 0)), "без доменных правил DoT не трогаем");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cap_drops_smallest_blocks_first() {
        let v = vec![(0x0a000000, 8), (0x0b000000, 24), (0x0c000000, 16), (0x0d000000, 24)];
        let (k, cov) = cap_cidrs(v.clone(), 2);
        assert_eq!(k, vec![(0x0a000000, 8), (0x0c000000, 16)]);
        assert!(cov > 0.999 && cov < 1.0);
        let (k, cov) = cap_cidrs(v.clone(), 10);
        assert_eq!(k.len(), 4);
        assert_eq!(cov, 1.0);
        assert_eq!(cap_cidrs(vec![], 5), (vec![], 1.0));
    }

    #[test]
    fn hostile_dns_is_ignored() {
        let d = tmp("hostile");
        std::fs::write(d.join("geosite.dat"), geosite(&[("X", vec![(2, "x.com")])])).unwrap();
        let cfg = Cfg { mode: "rules".into(), rules: vec![RuleCfg { kind: "geosite".into(), name: "X".into(), action: exit_a() }], ..Default::default() };
        let r = Router::build(&cfg, &d);
        let good = dns_reply("x.com", &[[1, 1, 1, 1]]);
        for cut in 0..good.len() {
            r.snoop(&good[..cut]);
        }
        // петля сжатия указателем на себя
        let mut bad = good.clone();
        let l = bad.len();
        bad[l - 16] = 0xc0;
        bad[l - 15] = 0x1c;
        r.snoop(&bad);
        let mut junk = good.clone();
        for i in 28..junk.len() {
            junk[i] = junk[i].wrapping_mul(31).wrapping_add(7);
            r.snoop(&junk);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cidr_cover_is_exact() {
        let c = ranges_to_cidrs(&[(0x0a000001, 0x0a000006), (0, 0), (0xffffffff, 0xffffffff)]);
        let mut cov: Vec<(u32, u32)> = c.iter().map(|(ip, p)| cidr_range(*ip, *p)).collect();
        cov.sort();
        assert_eq!(merge(cov), vec![(0, 0), (0x0a000001, 0x0a000006), (0xffffffff, 0xffffffff)]);
    }

    #[test]
    fn config_parse_is_tolerant() {
        let e = "a".repeat(32);
        let j = format!(r#"{{"mode":"rules","priority":["{e}","zz","{e}"],"rules":[{{"t":"geosite","n":"YOUTUBE","a":"exit:{e}"}},{{"t":"x","n":"a","a":"direct"}},{{"t":"geoip","n":"RU","a":"bogus"}}],"manual":[{{"v":" a.com ","a":"direct"}},{{"v":"","a":"direct"}}]}}"#);
        let c = Cfg::parse(&j);
        assert_eq!(c.mode, "rules");
        assert_eq!(c.rules.len(), 1);
        assert_eq!(c.manual.len(), 1);
        assert_eq!(c.manual[0].value, "a.com");
        assert_eq!(c.exits(), vec![[0xaa; 16]]);
        assert_eq!(Cfg::parse("{not json").mode, "auto");
        assert!(c.priority.is_empty(), "legacy rankings are ignored");
        let legacy = Cfg::parse(r#"{"mode":"priority","priority":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"#);
        assert_eq!(legacy.mode, "auto");
        assert!(legacy.priority.is_empty());
    }

    #[test]
    fn java_routingcfg_json_activates_only_enabled_rules_and_preserves_order() {
        // Shape emitted by RoutingCfg.toJson(): disabled and migration metadata are UI-only.
        const JAVA_JSON: &str = r#"{
          "mode":"rules","priority":[],
          "rules":[
            {"t":"geoip","n":"FIRST","a":"exit:11111111111111111111111111111111"},
            {"t":"geoip","n":"SECOND","a":"direct"}],
          "manual":[{"v":"10.1.2.3","a":"default"}],
          "off_rules":[{"t":"geoip","n":"DISABLED","a":"direct","i":1}],
          "off_manual":[{"v":"10.2.3.4","a":"direct","i":0}],
          "ui_legacy":[{"mode":"priority","priority":[],"ack":true}],
          "future_ui_metadata":{"x":1}
        }"#;
        let cfg = Cfg::parse(JAVA_JSON);
        assert_eq!(cfg.mode, "rules");
        assert!(cfg.priority.is_empty());
        assert_eq!(cfg.rules.len(), 2, "off_rules must never become active native rules");
        assert_eq!(cfg.rules[0].name, "FIRST");
        assert_eq!(cfg.rules[1].name, "SECOND");
        assert_eq!(cfg.manual.len(), 1, "off_manual is UI metadata");
        assert_eq!(cfg.exits(), vec![[0x11; 16]], "only active rule actions are loaded");

        let d = tmp("java-routingcfg");
        std::fs::write(d.join("geoip.dat"), geoip(&[
            ("FIRST", vec![([10, 0, 0, 0], 8)]),
            ("SECOND", vec![([10, 0, 0, 0], 8)]),
            ("DISABLED", vec![([10, 0, 0, 0], 8)]),
        ])).unwrap();
        let router = Router::build(&cfg, &d);
        let ip = |a: [u8; 4]| u32::from_be_bytes(a);
        assert_eq!(router.decide(ip([10, 1, 2, 3])), Action::Default, "active manual entry remains above list rules");
        assert_eq!(router.decide(ip([10, 9, 8, 7])), Action::Exit([0x11; 16]), "first active list rule wins; disabled rule is ignored");
        let _ = std::fs::remove_dir_all(&d);

        let old = Cfg::parse(r#"{"mode":"priority","priority":["11111111111111111111111111111111"],"rules":[{"t":"geoip","n":"FIRST","a":"direct"}]}"#);
        assert_eq!(old.mode, "auto");
        assert!(old.priority.is_empty(), "old exit ranking never affects selection");
        assert_eq!(old.rules.len(), 1, "legacy mode does not delete the rule data");
    }

    /// Ручная проверка на настоящих файлах: KNOTHOP_RULES_DIR=/путь cargo test --lib real_files -- --ignored --nocapture
    #[test]
    #[ignore]
    fn real_files() {
        let d = PathBuf::from(std::env::var("KNOTHOP_RULES_DIR").unwrap());
        let t0 = Instant::now();
        let gs = scan(&d.join("geosite.dat")).unwrap();
        let gi = scan(&d.join("geoip.dat")).unwrap();
        eprintln!("scan: {} + {} категорий за {:?}", gs.len(), gi.len(), t0.elapsed());
        for n in ["YOUTUBE", "CATEGORY-RU", "RU-BLOCKED", "TELEGRAM", "GOOGLE"] {
            eprintln!("geosite {n}: {}", gs.iter().any(|e| e.name == n));
        }
        for n in ["RU", "BY", "RU-BLOCKED", "PRIVATE", "TELEGRAM"] {
            eprintln!("geoip {n}: {}", gi.iter().any(|e| e.name == n));
        }
        let cfg = Cfg {
            mode: "rules".into(),
            priority: vec![],
            rules: vec![
                RuleCfg { kind: "geoip".into(), name: "RU".into(), action: Action::Direct },
                RuleCfg { kind: "geosite".into(), name: "YOUTUBE".into(), action: exit_a() },
            ],
            manual: vec![],
        };
        let t1 = Instant::now();
        let r = Router::build(&cfg, &d);
        eprintln!("build за {:?}: {:?} {:?}, direct cidr: {}", t1.elapsed(), r.warnings, r.stats, r.direct_cidrs().len());
        for m in [10_000, 8_000, 5_000] {
            let (k, cov) = cap_cidrs(r.direct_cidrs(), m);
            eprintln!("кап {m}: {} подсетей покрывают {:.4}% адресов", k.len(), cov * 100.0);
        }
    }
}
