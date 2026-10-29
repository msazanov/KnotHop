//! Хаб Reticulum Relay Chat (RRC 0.1.3, https://rrc.kc1awv.net) на серверных узлах.
//!
//! Совместим с обычными клиентами RRC: CBOR-конверты идут обычными пакетами Link (контекст None, не Channel).
//! Хаб не хранит сообщений и не федерируется: комната живёт, пока в ней есть участники.
//!
//! Это публичная точка входа: Link принимается от любой identity RNS (решение владельца 29.10), поэтому
//! всё от клиента недоверенно и ограничено: число сессий, комнат, размеры, частота, время до HELLO.
//! Назначение `rrc.hub` анонсируется с пустым app_data раз в 600 с; в анонсе нет имён сети и меток VPN.
//! Хаб не касается VPN-допуска: его Link не попадают в `links` VPN и не занимают его лимиты.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use leviculum_std::api::{CoreProcessor, Destination, DestinationHash, DestinationType, Direction, Identity, LinkId, NodeEvent, StdNodeCore, TickOutput};
use rand_core::{OsRng, RngCore};

/// Одновременных сессий хаба (Link, прошедших рукопожатие). Сверх лимита новый Link закрывается.
pub const MAX_SESSIONS: usize = 48;
/// Сессий одной identity: один клиент с несколькими устройствами допустим, но не бесконечно.
const MAX_PER_IDENTITY: usize = 4;
const MAX_ROOMS_PER_SESSION: usize = 8;
const MAX_ROOMS: usize = 128;
const MAX_ROOM_BYTES: usize = 64;
const MAX_NICK_BYTES: usize = 32;
/// Тело сообщения в закодированном виде (спецификация: бюджет 350 байт данных + заголовок).
const MAX_BODY_BYTES: usize = 354;
/// Входящий пакет: больше MTU Reticulum не бывает; всё сверх — мусор.
const MAX_PACKET: usize = 500;
/// Список участников в JOINED ограничен размером пакета (17 байт на участника).
const MAX_MEMBERS_LISTED: usize = 12;
const MSGS_PER_MINUTE: u64 = 30;
/// До WELCOME клиент обязан прислать HELLO и идентифицироваться.
const HELLO_TIMEOUT_MS: u64 = 30_000;
/// Молчащая сессия получает PING раз в 10 минут; без единого пакета 60 минут - закрывается.
const PING_EVERY_MS: u64 = 600_000;
const IDLE_CLOSE_MS: u64 = 3_600_000;
/// Свободное место для новичка освобождается за счёт сессии без комнат, молчащей дольше этого срока.
const EVICT_IDLE_MS: u64 = 600_000;
const MAX_STRIKES: u8 = 6;
const STRIKE_WINDOW_MS: u64 = 60_000;
const FIRST_ANNOUNCE_MS: u64 = if cfg!(test) { 1_000 } else { 25_000 };
/// Штатный период анонса RNS (AGENTS.md, п. 9): не уменьшать.
const ANNOUNCE_MS: u64 = 600_000;

const T_HELLO: u64 = 1;
const T_WELCOME: u64 = 2;
const T_JOIN: u64 = 10;
const T_JOINED: u64 = 11;
const T_PART: u64 = 12;
const T_PARTED: u64 = 13;
const T_MSG: u64 = 20;
const T_ACTION: u64 = 22;
const T_PING: u64 = 30;
const T_PONG: u64 = 31;
const T_ERROR: u64 = 40;

// --- настройка и состояние для status.json и vpn.rs ---

static ENABLED: AtomicBool = AtomicBool::new(true);
static NAME: Mutex<Option<String>> = Mutex::new(None);
static RUNNING: AtomicBool = AtomicBool::new(false);
static SESSIONS: AtomicUsize = AtomicUsize::new(0);
static ROOMS: AtomicUsize = AtomicUsize::new(0);
static MSGS: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static REFUSED: AtomicU64 = AtomicU64::new(0);
static ANNOUNCES: AtomicU64 = AtomicU64::new(0);
/// Link хаба. vpn.rs не отдаёт их в разбор VPN-пакетов: события Link приходят всем потребителям ядра.
static LINKS: RwLock<Option<HashSet<LinkId>>> = RwLock::new(None);

/// `rrc` и `rrc_name` из node.json: хаб включён по умолчанию, `false` отключает.
pub fn configure(enabled: Option<bool>, name: Option<String>) {
    ENABLED.store(enabled.unwrap_or(true), Relaxed);
    *NAME.lock().unwrap() = name;
}

pub fn enabled() -> bool { ENABLED.load(Relaxed) }

/// Принадлежит ли Link хабу RRC.
pub fn is_hub_link(link: &LinkId) -> bool {
    LINKS.read().ok().is_some_and(|g| g.as_ref().is_some_and(|s| s.contains(link)))
}

fn links_set(link: LinkId, on: bool) {
    if let Ok(mut g) = LINKS.write() {
        let s = g.get_or_insert_with(HashSet::new);
        if on { s.insert(link); } else { s.remove(&link); }
    }
}

/// Поля `rrc_*` для status.json.
pub fn status() -> serde_json::Value {
    serde_json::json!({"rrc_on": RUNNING.load(Relaxed), "rrc_sessions": SESSIONS.load(Relaxed), "rrc_rooms": ROOMS.load(Relaxed),
        "rrc_msgs": MSGS.load(Relaxed), "rrc_dropped": DROPPED.load(Relaxed), "rrc_refused": REFUSED.load(Relaxed), "rrc_announces": ANNOUNCES.load(Relaxed)})
}

fn hub_name() -> String {
    let name = NAME.lock().unwrap().clone().unwrap_or_default();
    let name: String = name.chars().filter(|c| !c.is_control()).collect();
    if name.is_empty() || name.len() > 32 { "hub".into() } else { name }
}

// --- минимальный CBOR (RFC 8949): ровно то, что нужно конверту RRC ---

fn put_head(o: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 { o.push(m | n as u8); }
    else if n <= 0xff { o.push(m | 24); o.push(n as u8); }
    else if n <= 0xffff { o.push(m | 25); o.extend((n as u16).to_be_bytes()); }
    else if n <= 0xffff_ffff { o.push(m | 26); o.extend((n as u32).to_be_bytes()); }
    else { o.push(m | 27); o.extend(n.to_be_bytes()); }
}
fn put_uint(o: &mut Vec<u8>, n: u64) { put_head(o, 0, n); }
fn put_bytes(o: &mut Vec<u8>, b: &[u8]) { put_head(o, 2, b.len() as u64); o.extend(b); }
fn put_text(o: &mut Vec<u8>, s: &str) { put_head(o, 3, s.len() as u64); o.extend(s.as_bytes()); }

/// Глубина вложенности при пропуске чужих значений (тело сообщения непрозрачно, но обязано быть корректным CBOR).
const MAX_DEPTH: u8 = 8;

struct Rd<'a> { b: &'a [u8], i: usize }
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }
    /// (старший тип, аргумент). Неопределённая длина и зарезервированные коды отвергаются.
    fn head(&mut self) -> Option<(u8, u64)> {
        let first = *self.b.get(self.i)?;
        self.i += 1;
        let ai = first & 31;
        let n = match ai {
            0..=23 => ai as u64,
            24 => self.take(1)?[0] as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().ok()?) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().ok()?) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().ok()?),
            _ => return None,
        };
        Some((first >> 5, n))
    }
    fn skip(&mut self, depth: u8) -> Option<()> {
        if depth > MAX_DEPTH { return None; }
        let (major, n) = self.head()?;
        match major {
            0 | 1 | 7 => Some(()),
            2 | 3 => { self.take(usize::try_from(n).ok()?)?; Some(()) }
            // каждый элемент занимает не меньше байта, поэтому цикл ограничен длиной пакета
            4 => { for _ in 0..n { self.skip(depth + 1)?; } Some(()) }
            5 => { for _ in 0..n { self.skip(depth + 1)?; self.skip(depth + 1)?; } Some(()) }
            6 => self.skip(depth + 1),
            _ => None,
        }
    }
    fn uint(&mut self) -> Option<u64> { match self.head()? { (0, n) => Some(n), _ => None } }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        match self.head()? { (2, n) => self.take(usize::try_from(n).ok()?), _ => None }
    }
    fn text(&mut self) -> Option<&'a str> {
        match self.head()? { (3, n) => std::str::from_utf8(self.take(usize::try_from(n).ok()?)?).ok(), _ => None }
    }
}

/// Разобранный конверт. Ссылки указывают в исходный пакет.
struct Env<'a> {
    typ: u64,
    mid: Option<&'a [u8]>,
    sender: Option<&'a [u8]>,
    room: Option<&'a str>,
    /// Закодированный CBOR-элемент тела, байты не меняются.
    body: Option<&'a [u8]>,
    nick: Option<&'a str>,
}

/// `None` - пакет неверен (неверный CBOR, версия, повтор поля). Неизвестные ключи пропускаются.
fn parse(b: &[u8]) -> Option<Env<'_>> {
    let mut r = Rd { b, i: 0 };
    let (major, n) = r.head()?;
    if major != 5 || n > 16 { return None; }
    let (mut ver, mut typ, mut seen) = (None, None, 0u8);
    let mut env = Env { typ: 0, mid: None, sender: None, room: None, body: None, nick: None };
    for _ in 0..n {
        let key = r.uint()?;
        if key < 8 {
            if seen & (1 << key) != 0 { return None; }
            seen |= 1 << key;
        }
        match key {
            0 => ver = Some(r.uint()?),
            1 => typ = Some(r.uint()?),
            2 => env.mid = Some(r.bytes()?),
            3 => { r.uint()?; }
            4 => env.sender = Some(r.bytes()?),
            5 => env.room = Some(r.text()?),
            6 => { let start = r.i; r.skip(0)?; env.body = Some(&b[start..r.i]); }
            7 => env.nick = Some(r.text()?),
            _ => r.skip(0)?,
        }
    }
    if r.i != b.len() || ver != Some(1) { return None; }
    env.typ = typ?;
    Some(env)
}

fn now_wall_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64) }

/// Конверт от имени `sender`: поля 0-4, затем необязательные комната (5) и тело (6, уже закодированный CBOR).
fn build(sender: &[u8; 16], typ: u64, room: Option<&str>, body: Option<&[u8]>) -> Vec<u8> {
    let mut o = Vec::with_capacity(96);
    put_head(&mut o, 5, 5 + room.is_some() as u64 + body.is_some() as u64);
    put_uint(&mut o, 0); put_uint(&mut o, 1);
    put_uint(&mut o, 1); put_uint(&mut o, typ);
    let mut mid = [0u8; 8];
    OsRng.fill_bytes(&mut mid);
    put_uint(&mut o, 2); put_bytes(&mut o, &mid);
    put_uint(&mut o, 3); put_uint(&mut o, now_wall_ms());
    put_uint(&mut o, 4); put_bytes(&mut o, sender);
    if let Some(r) = room { put_uint(&mut o, 5); put_text(&mut o, r); }
    if let Some(b) = body { put_uint(&mut o, 6); o.extend(b); }
    o
}

fn text_item(s: &str) -> Vec<u8> { let mut o = Vec::new(); put_text(&mut o, s); o }
fn bytes_item(b: &[u8]) -> Vec<u8> { let mut o = Vec::new(); put_bytes(&mut o, b); o }

/// Ключи WELCOME и пределов числовые, как в rrcd (B_WELCOME_*, B_LIMIT_*); текстовые ключи клиенты не понимают.
fn welcome_body(name: &str) -> Vec<u8> {
    let mut o = Vec::new();
    put_head(&mut o, 5, 4);
    put_uint(&mut o, 0); put_text(&mut o, name);
    put_uint(&mut o, 1); put_text(&mut o, env!("CARGO_PKG_VERSION"));
    // возможности: ACTION (1) ретранслируется
    put_uint(&mut o, 2); put_head(&mut o, 5, 1); put_uint(&mut o, 1); o.push(0xf5);
    put_uint(&mut o, 3);
    put_head(&mut o, 5, 5);
    for (k, v) in [(0u64, MAX_NICK_BYTES), (1, MAX_ROOM_BYTES), (2, MAX_BODY_BYTES - 4), (3, MAX_ROOMS_PER_SESSION), (4, MSGS_PER_MINUTE as usize)] {
        put_uint(&mut o, k); put_uint(&mut o, v as u64);
    }
    o
}

fn members_body(ids: &[[u8; 16]]) -> Vec<u8> {
    let mut o = Vec::new();
    put_head(&mut o, 4, ids.len() as u64);
    for id in ids { put_bytes(&mut o, id); }
    o
}

/// Имя комнаты без учёта регистра; пустые, длинные и с управляющими символами отвергаются.
fn norm_room(s: &str) -> Option<String> {
    let r = s.to_lowercase();
    (!r.is_empty() && r.len() <= MAX_ROOM_BYTES && !r.chars().any(char::is_control)).then_some(r)
}

// --- ограничение частоты ---

struct Bucket { tokens: f64, cap: f64, per_ms: f64, last: u64 }
impl Bucket {
    fn new(cap: f64, per_s: f64, now: u64) -> Self { Bucket { tokens: cap, cap, per_ms: per_s / 1000.0, last: now } }
    fn take(&mut self, now: u64) -> bool {
        self.tokens = (self.tokens + now.saturating_sub(self.last) as f64 * self.per_ms).min(self.cap);
        self.last = now;
        if self.tokens >= 1.0 { self.tokens -= 1.0; true } else { false }
    }
}

// --- состояние хаба ---

struct Session {
    since: u64,
    last_rx: u64,
    last_ping: u64,
    ident: Option<[u8; 16]>,
    hello: bool,
    welcomed: bool,
    rooms: Vec<String>,
    pkts: Bucket,
    msgs: Bucket,
    ctl: Bucket,
    ping: Bucket,
    strikes: u8,
    strikes_at: u64,
}

impl Session {
    fn new(now: u64) -> Self {
        Session { since: now, last_rx: now, last_ping: now, ident: None, hello: false, welcomed: false, rooms: Vec::new(),
            pkts: Bucket::new(20.0, 2.0, now), msgs: Bucket::new(10.0, MSGS_PER_MINUTE as f64 / 60.0, now), ctl: Bucket::new(6.0, 10.0 / 60.0, now), ping: Bucket::new(10.0, 20.0 / 60.0, now),
            strikes: 0, strikes_at: now }
    }
}

enum Ev<'a> { Open(LinkId), Ident(LinkId, [u8; 16]), Data(LinkId, &'a [u8]), Closed(LinkId), Tick }
#[derive(Debug, PartialEq)]
enum Act { Send(LinkId, Vec<u8>), Close(LinkId) }

struct Hub {
    id: [u8; 16],
    name: String,
    sessions: HashMap<LinkId, Session>,
    rooms: HashMap<String, Vec<LinkId>>,
    /// Общая очередь пересылки: сообщения всех клиентов, каждое размножается на участников комнаты.
    fanout: Bucket,
}

impl Hub {
    fn new(id: [u8; 16], name: String) -> Self { Hub { id, name, sessions: HashMap::new(), rooms: HashMap::new(), fanout: Bucket::new(20.0, 10.0, 0) } }

    fn step(&mut self, now: u64, ev: Ev<'_>) -> Vec<Act> {
        let mut acts = Vec::new();
        match ev {
            Ev::Open(l) => {
                if self.sessions.len() >= MAX_SESSIONS && !self.evict_idle(now, &mut acts) {
                    REFUSED.fetch_add(1, Relaxed);
                    acts.push(Act::Close(l));
                } else {
                    self.sessions.insert(l, Session::new(now));
                    links_set(l, true);
                }
            }
            Ev::Ident(l, h) => {
                let Some(s) = self.sessions.get_mut(&l) else { return acts };
                if s.ident.is_none() {
                    s.ident = Some(h);
                    if s.hello && !s.welcomed { self.welcome(l, &mut acts); }
                }
            }
            Ev::Data(l, d) => self.data(l, d, now, &mut acts),
            Ev::Closed(l) => self.drop_session(l),
            Ev::Tick => self.tick(now, &mut acts),
        }
        self.publish();
        acts
    }

    fn publish(&self) {
        SESSIONS.store(self.sessions.len(), Relaxed);
        ROOMS.store(self.rooms.len(), Relaxed);
    }

    fn drop_session(&mut self, l: LinkId) {
        if let Some(s) = self.sessions.remove(&l) {
            for r in s.rooms { self.leave_room(&r, l); }
        }
        links_set(l, false);
    }

    fn leave_room(&mut self, room: &str, l: LinkId) {
        if let Some(m) = self.rooms.get_mut(room) {
            m.retain(|x| *x != l);
            if m.is_empty() { self.rooms.remove(room); }
        }
    }

    fn send(&self, acts: &mut Vec<Act>, l: LinkId, typ: u64, room: Option<&str>, body: Option<&[u8]>) {
        acts.push(Act::Send(l, build(&self.id, typ, room, body)));
    }

    fn error(&self, acts: &mut Vec<Act>, l: LinkId, text: &str) { self.send(acts, l, T_ERROR, None, Some(&text_item(text))); }

    fn error_close(&mut self, acts: &mut Vec<Act>, l: LinkId, text: &str) {
        self.error(acts, l, text);
        acts.push(Act::Close(l));
        self.drop_session(l);
    }

    /// Нарушение: пакет отброшен; при повторных нарушениях за минуту Link закрывается.
    fn strike(&mut self, l: LinkId, now: u64, acts: &mut Vec<Act>) {
        DROPPED.fetch_add(1, Relaxed);
        let Some(s) = self.sessions.get_mut(&l) else { return };
        if now.saturating_sub(s.strikes_at) > STRIKE_WINDOW_MS { s.strikes = 0; s.strikes_at = now; }
        s.strikes += 1;
        if s.strikes >= MAX_STRIKES { self.error_close(acts, l, "too many errors"); }
    }

    fn welcome(&mut self, l: LinkId, acts: &mut Vec<Act>) {
        let Some(ident) = self.sessions.get(&l).and_then(|s| s.ident) else { return };
        if self.sessions.values().filter(|s| s.ident == Some(ident)).count() > MAX_PER_IDENTITY {
            return self.error_close(acts, l, "too many sessions");
        }
        if let Some(s) = self.sessions.get_mut(&l) { s.welcomed = true; }
        self.send(acts, l, T_WELCOME, None, Some(&welcome_body(&self.name)));
    }

    fn data(&mut self, l: LinkId, d: &[u8], now: u64, acts: &mut Vec<Act>) {
        let Some(s) = self.sessions.get_mut(&l) else { return };
        s.last_rx = now;
        if !s.pkts.take(now) || d.len() > MAX_PACKET { return self.strike(l, now, acts); }
        let Some(env) = parse(d) else { return self.strike(l, now, acts) };
        if env.typ == T_HELLO {
            s.hello = true;
            if !s.welcomed && s.ident.is_some() { self.welcome(l, acts); }
            return;
        }
        // до WELCOME хаб кроме HELLO ничего не обслуживает
        if !s.welcomed { return; }
        let Some(ident) = s.ident else { return };
        match env.typ {
            T_JOIN | T_PART => {
                if !s.ctl.take(now) { return self.strike(l, now, acts); }
                if env.typ == T_JOIN { self.join(l, &ident, &env, acts) } else { self.part(l, &ident, &env, acts) }
            }
            // клиенты (rrc-tui) пингуют раз в 5 с: PING идёт отдельной корзиной, лишнее молча отбрасывается
            // (поток всё равно ограничен корзиной пакетов)
            T_PING => {
                if s.ping.take(now) { self.send(acts, l, T_PONG, None, env.body) } else { DROPPED.fetch_add(1, Relaxed); }
            }
            T_MSG | T_ACTION => {
                if !s.msgs.take(now) { return self.strike(l, now, acts); }
                self.relay(l, &ident, &env, d, now, acts);
            }
            // PONG, NOTICE, ERROR от клиента и неизвестные типы игнорируются
            _ => {}
        }
    }

    fn join(&mut self, l: LinkId, ident: &[u8; 16], env: &Env<'_>, acts: &mut Vec<Act>) {
        let Some(room) = env.room.and_then(norm_room) else { return self.error(acts, l, "bad room") };
        let member = self.sessions.get(&l).is_some_and(|s| s.rooms.contains(&room));
        if !member {
            if self.sessions.get(&l).map_or(true, |s| s.rooms.len() >= MAX_ROOMS_PER_SESSION) { return self.error(acts, l, "too many rooms"); }
            if !self.rooms.contains_key(&room) && self.rooms.len() >= MAX_ROOMS { return self.error(acts, l, "hub is full"); }
            // остальные участники узнают о новичке (как в rrcd): JOINED с identity в списке
            let others: Vec<LinkId> = self.rooms.get(&room).cloned().unwrap_or_default();
            for m in others { self.send(acts, m, T_JOINED, Some(&room), Some(&members_body(&[*ident]))); }
            self.rooms.entry(room.clone()).or_default().push(l);
            if let Some(s) = self.sessions.get_mut(&l) { s.rooms.push(room.clone()); }
        }
        let mut ids: Vec<[u8; 16]> = Vec::new();
        for m in self.rooms.get(&room).into_iter().flatten() {
            if let Some(i) = self.sessions.get(m).and_then(|s| s.ident) {
                if !ids.contains(&i) && ids.len() < MAX_MEMBERS_LISTED { ids.push(i); }
            }
        }
        self.send(acts, l, T_JOINED, Some(&room), Some(&members_body(&ids)));
    }

    fn part(&mut self, l: LinkId, ident: &[u8; 16], env: &Env<'_>, acts: &mut Vec<Act>) {
        let Some(room) = env.room.and_then(norm_room) else { return };
        let Some(s) = self.sessions.get_mut(&l) else { return };
        let Some(pos) = s.rooms.iter().position(|r| *r == room) else { return };
        s.rooms.remove(pos);
        self.leave_room(&room, l);
        let rest: Vec<LinkId> = self.rooms.get(&room).cloned().unwrap_or_default();
        for m in rest { self.send(acts, m, T_PARTED, Some(&room), Some(&members_body(&[*ident]))); }
        self.send(acts, l, T_PARTED, Some(&room), Some(&members_body(&[*ident])));
    }

    /// Пересылка всем участникам комнаты, включая отправителя (эхо = подтверждение для клиента): байты конверта не меняются.
    fn relay(&mut self, l: LinkId, ident: &[u8; 16], env: &Env<'_>, raw: &[u8], now: u64, acts: &mut Vec<Act>) {
        if env.sender != Some(&ident[..]) { self.error(acts, l, "sender mismatch"); return self.strike(l, now, acts); }
        let Some(room) = env.room.and_then(norm_room) else { return self.error(acts, l, "bad room") };
        if !self.sessions.get(&l).is_some_and(|s| s.rooms.contains(&room)) { return self.error(acts, l, "not in room"); }
        let Some(body) = env.body else { return self.error(acts, l, "no body") };
        if body.len() > MAX_BODY_BYTES || env.nick.is_some_and(|n| n.len() > MAX_NICK_BYTES) { return self.error(acts, l, "too long"); }
        if !self.fanout.take(now) { DROPPED.fetch_add(1, Relaxed); return; }
        MSGS.fetch_add(1, Relaxed);
        // отправителю тоже: так делает rrcd, и клиенты (rrc-tui) принимают собственное эхо за подтверждение доставки
        for m in self.rooms.get(&room).into_iter().flatten() {
            acts.push(Act::Send(*m, raw.to_vec()));
        }
    }

    /// Освободить место за счёт самой давно молчащей сессии без комнат.
    fn evict_idle(&mut self, now: u64, acts: &mut Vec<Act>) -> bool {
        let victim = self.sessions.iter()
            .filter(|(_, s)| s.rooms.is_empty() && now.saturating_sub(s.last_rx) > EVICT_IDLE_MS)
            .max_by_key(|(_, s)| now.saturating_sub(s.last_rx)).map(|(l, _)| *l);
        let Some(l) = victim else { return false };
        acts.push(Act::Close(l));
        self.drop_session(l);
        true
    }

    fn tick(&mut self, now: u64, acts: &mut Vec<Act>) {
        let ids: Vec<LinkId> = self.sessions.keys().copied().collect();
        for l in ids {
            let Some(s) = self.sessions.get_mut(&l) else { continue };
            if !s.welcomed {
                if now.saturating_sub(s.since) > HELLO_TIMEOUT_MS {
                    if s.hello { self.error_close(acts, l, "identify first"); } else { acts.push(Act::Close(l)); self.drop_session(l); }
                }
            } else if now.saturating_sub(s.last_rx) > IDLE_CLOSE_MS {
                acts.push(Act::Close(l));
                self.drop_session(l);
            } else if now.saturating_sub(s.last_rx) > PING_EVERY_MS && now.saturating_sub(s.last_ping) > PING_EVERY_MS {
                s.last_ping = now;
                self.send(acts, l, T_PING, None, None);
            }
        }
    }
}

/// Процессор ядра: принимает Link на `rrc.hub`, анонсирует его и передаёт события в `Hub`.
pub struct HubProcessor {
    identity: Identity,
    epoch: Instant,
    dest: Option<DestinationHash>,
    broken: bool,
    next_announce_ms: u64,
    hub: Hub,
}

impl HubProcessor {
    pub fn new(identity: Identity) -> Self {
        RUNNING.store(true, Relaxed);
        let id = *identity.hash();
        HubProcessor { identity, epoch: Instant::now(), dest: None, broken: false, next_announce_ms: 0, hub: Hub::new(id, hub_name()) }
    }

    fn now(&self) -> u64 { self.epoch.elapsed().as_millis() as u64 }

    fn register(&mut self, core: &mut StdNodeCore) {
        match Destination::new(Some(self.identity.clone()), Direction::In, DestinationType::Single, "rrc", &["hub"]) {
            Ok(d) => {
                self.dest = Some(*d.hash());
                core.register_destination(d);
                self.next_announce_ms = self.now() + FIRST_ANNOUNCE_MS;
            }
            Err(e) => { eprintln!("RRC: назначение не создано: {e:?}"); self.broken = true; RUNNING.store(false, Relaxed); }
        }
    }

    fn apply(core: &mut StdNodeCore, acts: Vec<Act>, out: &mut TickOutput) {
        for a in acts {
            match a {
                Act::Send(l, b) => { if let Ok((_, o)) = core.send_packet_on_link(&l, &b) { out.merge(o); } }
                Act::Close(l) => out.merge(core.close_link(&l)),
            }
        }
    }
}

impl CoreProcessor for HubProcessor {
    fn on_event(&mut self, core: &mut StdNodeCore, event: &NodeEvent) -> TickOutput {
        let mut out = TickOutput::empty();
        let Some(dest) = self.dest else { return out };
        let now = self.now();
        let acts = match event {
            NodeEvent::LinkEstablished { link_id, is_initiator: false, destination_hash } if *destination_hash == dest => self.hub.step(now, Ev::Open(*link_id)),
            NodeEvent::LinkIdentified { link_id, identity_hash } => self.hub.step(now, Ev::Ident(*link_id, *identity_hash)),
            NodeEvent::LinkDataReceived { link_id, data } => self.hub.step(now, Ev::Data(*link_id, data)),
            NodeEvent::LinkClosed { link_id, .. } => self.hub.step(now, Ev::Closed(*link_id)),
            _ => return out,
        };
        Self::apply(core, acts, &mut out);
        out
    }

    fn on_tick(&mut self, core: &mut StdNodeCore, _now_ms: u64) -> TickOutput {
        let mut out = TickOutput::empty();
        if self.broken { return out; }
        if self.dest.is_none() {
            self.register(core);
            return out;
        }
        let now = self.now();
        if let Some(d) = self.dest.filter(|_| now >= self.next_announce_ms) {
            self.next_announce_ms = now + ANNOUNCE_MS;
            if let Ok(o) = core.announce_destination(&d, None) { ANNOUNCES.fetch_add(1, Relaxed); out.merge(o); }
        }
        let acts = self.hub.step(now, Ev::Tick);
        Self::apply(core, acts, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [0xa1; 16];
    const B: [u8; 16] = [0xb2; 16];
    const C: [u8; 16] = [0xc3; 16];

    fn lid(n: u8) -> LinkId { LinkId::new([n; 16]) }
    fn hub() -> Hub { Hub::new([0x77; 16], "hub".into()) }
    /// Конверт клиента: те же поля, что строит хаб.
    fn msg(from: &[u8; 16], typ: u64, room: Option<&str>, body: Option<&[u8]>) -> Vec<u8> { build(from, typ, room, body) }
    fn sends(acts: &[Act]) -> Vec<(LinkId, Vec<u8>)> { acts.iter().filter_map(|a| if let Act::Send(l, b) = a { Some((*l, b.clone())) } else { None }).collect() }
    fn typ_of(b: &[u8]) -> u64 { parse(b).unwrap().typ }

    /// Клиент `n` с identity `who` открыл Link, идентифицировался, прислал HELLO и получил WELCOME.
    fn connect(h: &mut Hub, n: u8, who: [u8; 16], now: u64) -> LinkId {
        let l = lid(n);
        h.step(now, Ev::Open(l));
        h.step(now, Ev::Ident(l, who));
        let acts = h.step(now, Ev::Data(l, &msg(&who, T_HELLO, None, None)));
        let s = sends(&acts);
        assert_eq!(s.len(), 1);
        assert_eq!(typ_of(&s[0].1), T_WELCOME);
        l
    }

    fn join(h: &mut Hub, l: LinkId, who: &[u8; 16], room: &str, now: u64) -> Vec<Act> { h.step(now, Ev::Data(l, &msg(who, T_JOIN, Some(room), None))) }

    #[test]
    fn envelope_roundtrip_and_opaque_body() {
        // тело - вложенная структура: хаб не интерпретирует его и пересылает байт в байт
        let mut body = Vec::new();
        put_head(&mut body, 5, 2);
        put_uint(&mut body, 0); put_text(&mut body, "привет");
        put_uint(&mut body, 9); put_head(&mut body, 4, 2); put_uint(&mut body, 1); put_bytes(&mut body, &[1, 2, 3]);
        let e = msg(&A, T_MSG, Some("Lobby"), Some(&body));
        let p = parse(&e).unwrap();
        assert_eq!((p.typ, p.room, p.body, p.sender), (T_MSG, Some("Lobby"), Some(&body[..]), Some(&A[..])));
        assert_eq!(p.mid.unwrap().len(), 8);
    }

    #[test]
    fn parse_ignores_unknown_keys_and_rejects_bad_envelopes() {
        // неизвестные ключи 8 и 50 пропускаются
        let mut e = Vec::new();
        put_head(&mut e, 5, 4);
        put_uint(&mut e, 0); put_uint(&mut e, 1);
        put_uint(&mut e, 1); put_uint(&mut e, T_PING);
        put_uint(&mut e, 8); put_text(&mut e, "x");
        put_uint(&mut e, 50); put_head(&mut e, 5, 1); put_uint(&mut e, 1); put_uint(&mut e, 2);
        assert_eq!(parse(&e).unwrap().typ, T_PING);
        // версия 2, нет типа, повтор ключа, хвост, неопределённая длина, не карта
        let mut v2 = Vec::new(); put_head(&mut v2, 5, 2); put_uint(&mut v2, 0); put_uint(&mut v2, 2); put_uint(&mut v2, 1); put_uint(&mut v2, 1);
        let mut notype = Vec::new(); put_head(&mut notype, 5, 1); put_uint(&mut notype, 0); put_uint(&mut notype, 1);
        let mut dup = Vec::new(); put_head(&mut dup, 5, 3); for _ in 0..2 { put_uint(&mut dup, 0); put_uint(&mut dup, 1); } put_uint(&mut dup, 1); put_uint(&mut dup, 1);
        let mut tail = msg(&A, T_PING, None, None); tail.push(0);
        for bad in [&v2[..], &notype[..], &dup[..], &tail[..], &[0xbf, 0xff][..], &[0x80][..], &[][..]] { assert!(parse(bad).is_none(), "{bad:?}"); }
    }

    #[test]
    fn parse_never_panics_on_garbage_or_truncation() {
        let good = msg(&A, T_MSG, Some("room"), Some(&text_item("hello")));
        for n in 0..good.len() { let _ = parse(&good[..n]); }
        let mut x = 0x1234_5678u32;
        for _ in 0..20_000 {
            let mut buf = good.clone();
            for _ in 0..3 {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let i = (x >> 8) as usize % buf.len();
                buf[i] = (x >> 24) as u8;
            }
            let _ = parse(&buf);
        }
        // огромные заявленные длины не вызывают ни выделений, ни зацикливания
        let _ = parse(&[0xa1, 0x06, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let _ = parse(&[0xa1, 0x06, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let deep: Vec<u8> = [vec![0xa1, 0x06], vec![0x81; 200]].concat();
        assert!(parse(&deep).is_none());
    }

    #[test]
    fn room_names_are_normalized() {
        assert_eq!(norm_room("Lobby").as_deref(), Some("lobby"));
        assert!(norm_room("").is_none());
        assert!(norm_room("a\u{7}b").is_none());
        assert!(norm_room(&"x".repeat(65)).is_none());
        assert!(norm_room(&"x".repeat(64)).is_some());
    }

    #[test]
    fn welcome_requires_hello_and_identity_in_any_order() {
        let mut h = hub();
        let l = lid(1);
        h.step(0, Ev::Open(l));
        // HELLO раньше идентификации: WELCOME ждёт LinkIdentified
        assert!(sends(&h.step(0, Ev::Data(l, &msg(&A, T_HELLO, None, None)))).is_empty());
        let s = sends(&h.step(1, Ev::Ident(l, A)));
        assert_eq!(s.len(), 1);
        let w = parse(&s[0].1).unwrap();
        assert_eq!((w.typ, w.sender), (T_WELCOME, Some(&[0x77u8; 16][..])));
        assert!(w.body.is_some());
    }

    #[test]
    fn nothing_but_hello_is_served_before_welcome() {
        let mut h = hub();
        let l = lid(1);
        h.step(0, Ev::Open(l));
        h.step(0, Ev::Ident(l, A));
        assert!(join(&mut h, l, &A, "lobby", 0).is_empty());
        assert_eq!(h.rooms.len(), 0);
    }

    #[test]
    fn message_is_relayed_unchanged_to_room_members_only() {
        let mut h = hub();
        let (a, b, c) = (connect(&mut h, 1, A, 0), connect(&mut h, 2, B, 0), connect(&mut h, 3, C, 0));
        let ja = sends(&join(&mut h, a, &A, "Lobby", 1));
        assert_eq!(typ_of(&ja[0].1), T_JOINED);
        join(&mut h, b, &B, "lobby", 1);
        join(&mut h, c, &C, "other", 1);
        // JOINED второго содержит обоих
        let jb = sends(&join(&mut h, b, &B, "LOBBY", 2));
        assert!(jb.is_empty() || jb.iter().all(|(l, _)| *l == b), "повторный JOIN не рассылается другим");
        let list = parse(&jb[0].1).unwrap().body.unwrap().to_vec();
        assert_eq!(list[0], 0x82);
        let mut body = text_item("hi");
        body.shrink_to_fit();
        let m = msg(&A, T_MSG, Some("lobby"), Some(&body));
        let acts = h.step(3, Ev::Data(a, &m));
        assert_eq!(acts, vec![Act::Send(a, m.clone()), Act::Send(b, m)]);
    }

    #[test]
    fn spoofed_sender_not_in_room_and_missing_body_are_refused() {
        let mut h = hub();
        let (a, b) = (connect(&mut h, 1, A, 0), connect(&mut h, 2, B, 0));
        join(&mut h, a, &A, "lobby", 0);
        join(&mut h, b, &B, "lobby", 0);
        let body = text_item("x");
        // чужая identity в поле 4
        let s = sends(&h.step(1, Ev::Data(a, &msg(&B, T_MSG, Some("lobby"), Some(&body)))));
        assert_eq!((s.len(), s[0].0, typ_of(&s[0].1)), (1, a, T_ERROR));
        // комната, в которой нет
        let s = sends(&h.step(1, Ev::Data(a, &msg(&A, T_MSG, Some("secret"), Some(&body)))));
        assert_eq!((s.len(), typ_of(&s[0].1)), (1, T_ERROR));
        // без тела
        let s = sends(&h.step(1, Ev::Data(a, &msg(&A, T_MSG, Some("lobby"), None))));
        assert_eq!(typ_of(&s[0].1), T_ERROR);
        // слишком длинное тело
        let big = text_item(&"x".repeat(400));
        let s = sends(&h.step(1, Ev::Data(a, &msg(&A, T_MSG, Some("lobby"), Some(&big)))));
        assert_eq!(typ_of(&s[0].1), T_ERROR);
    }

    #[test]
    fn part_ping_and_close_update_membership() {
        let mut h = hub();
        let (a, b) = (connect(&mut h, 1, A, 0), connect(&mut h, 2, B, 0));
        join(&mut h, a, &A, "lobby", 0);
        join(&mut h, b, &B, "lobby", 0);
        let s = sends(&h.step(1, Ev::Data(a, &msg(&A, T_PART, Some("lobby"), None))));
        // оставшиеся узнают об уходе, ушедший получает подтверждение; в обоих случаях тело - список identity
        assert_eq!(s.iter().map(|(l, b)| (*l, typ_of(b))).collect::<Vec<_>>(), vec![(b, T_PARTED), (a, T_PARTED)]);
        assert_eq!(parse(&s[1].1).unwrap().body, Some(&members_body(&[A])[..]));
        assert_eq!(h.rooms["lobby"], vec![b]);
        // PING: тело возвращается без изменений
        let payload = bytes_item(&[1, 2, 3]);
        let s = sends(&h.step(2, Ev::Data(b, &msg(&B, T_PING, None, Some(&payload)))));
        let pong = parse(&s[0].1).unwrap();
        assert_eq!((pong.typ, pong.body), (T_PONG, Some(&payload[..])));
        // закрытие Link снимает членство без уведомлений, пустая комната исчезает
        assert!(h.step(3, Ev::Closed(b)).is_empty());
        assert!(h.rooms.is_empty());
    }

    #[test]
    fn newcomer_is_announced_to_members_and_pings_do_not_strike() {
        let mut h = hub();
        let (a, b) = (connect(&mut h, 1, A, 0), connect(&mut h, 2, B, 0));
        join(&mut h, a, &A, "lobby", 0);
        let s = sends(&join(&mut h, b, &B, "lobby", 1));
        assert_eq!(s.iter().map(|(l, x)| (*l, typ_of(x))).collect::<Vec<_>>(), vec![(a, T_JOINED), (b, T_JOINED)]);
        assert_eq!(parse(&s[0].1).unwrap().body, Some(&members_body(&[B])[..]));
        // клиент пингует раз в 5 с, час подряд: ни ошибок, ни закрытия
        for i in 0..720u64 {
            let acts = h.step(10_000 + i * 5_000, Ev::Data(b, &msg(&B, T_PING, None, None)));
            assert_eq!(acts.len(), 1, "PONG на каждый PING {i}");
        }
        assert!(h.sessions.contains_key(&b));
    }

    #[test]
    fn welcome_uses_numeric_keys_like_rrcd() {
        let mut r = Rd { b: &welcome_body("x"), i: 0 };
        assert_eq!(r.head(), Some((5, 4)));
        assert_eq!((r.uint(), r.text()), (Some(0), Some("x")));
        assert_eq!(r.uint(), Some(1)); r.text().unwrap();
        assert_eq!(r.uint(), Some(2)); r.skip(0).unwrap();
        assert_eq!((r.uint(), r.head()), (Some(3), Some((5, 5))));
        for (k, v) in [(0u64, 32u64), (1, 64), (2, 350), (3, 8), (4, 30)] { assert_eq!((r.uint(), r.uint()), (Some(k), Some(v))); }
        assert_eq!(r.i, r.b.len());
    }

    #[test]
    fn rooms_and_sessions_are_capped() {
        let mut h = hub();
        let a = connect(&mut h, 1, A, 0);
        for i in 0..MAX_ROOMS_PER_SESSION {
            let s = sends(&join(&mut h, a, &A, &format!("r{i}"), 100_000 * (i as u64 + 1)));
            assert_eq!(typ_of(&s[0].1), T_JOINED);
        }
        let s = sends(&join(&mut h, a, &A, "one-too-many", 10_000_000));
        assert_eq!(typ_of(&s[0].1), T_ERROR);
        assert_eq!(h.sessions[&a].rooms.len(), MAX_ROOMS_PER_SESSION);

        let mut h = hub();
        for n in 0..MAX_SESSIONS as u8 { h.step(0, Ev::Open(lid(n))); }
        let acts = h.step(1, Ev::Open(lid(200)));
        assert_eq!(acts, vec![Act::Close(lid(200))]);
        assert_eq!(h.sessions.len(), MAX_SESSIONS);
    }

    #[test]
    fn one_identity_gets_limited_sessions() {
        let mut h = hub();
        for n in 0..MAX_PER_IDENTITY as u8 { connect(&mut h, n, A, 0); }
        let l = lid(100);
        h.step(0, Ev::Open(l));
        h.step(0, Ev::Ident(l, A));
        let acts = h.step(0, Ev::Data(l, &msg(&A, T_HELLO, None, None)));
        assert!(matches!(acts.last(), Some(Act::Close(x)) if *x == l));
        assert!(!h.sessions.contains_key(&l));
    }

    #[test]
    fn flooding_closes_the_link_and_the_fanout_is_bounded() {
        let mut h = hub();
        let (a, b) = (connect(&mut h, 1, A, 0), connect(&mut h, 2, B, 0));
        join(&mut h, a, &A, "lobby", 0);
        join(&mut h, b, &B, "lobby", 0);
        let m = msg(&A, T_MSG, Some("lobby"), Some(&text_item("spam")));
        let (mut relayed, mut closed) = (0, false);
        for _ in 0..200 {
            for act in h.step(5, Ev::Data(a, &m)) {
                match act { Act::Send(l, b2) if l == b && b2 == m => relayed += 1, Act::Close(l) if l == a => closed = true, _ => {} }
            }
        }
        assert!(closed, "поток без пауз закрывает Link");
        assert!(relayed <= 20, "ёмкость корзины ограничивает пересылку: {relayed}");
        assert!(!h.sessions.contains_key(&a) && h.rooms["lobby"] == vec![b]);
    }

    #[test]
    fn silent_sessions_are_pinged_and_dropped() {
        let mut h = hub();
        let a = connect(&mut h, 1, A, 0);
        let half = sends(&h.step(PING_EVERY_MS + 1, Ev::Tick));
        assert_eq!((half.len(), half[0].0, typ_of(&half[0].1)), (1, a, T_PING));
        // повторный PING не раньше чем через период
        assert!(h.step(PING_EVERY_MS + 2, Ev::Tick).is_empty());
        let acts = h.step(IDLE_CLOSE_MS + 1, Ev::Tick);
        assert!(acts.contains(&Act::Close(a)));
        assert!(h.sessions.is_empty());
    }

    #[test]
    fn unwelcomed_links_time_out() {
        let mut h = hub();
        h.step(0, Ev::Open(lid(1)));
        let l2 = lid(2);
        h.step(0, Ev::Open(l2));
        h.step(0, Ev::Data(l2, &msg(&A, T_HELLO, None, None)));
        let acts = h.step(HELLO_TIMEOUT_MS + 1, Ev::Tick);
        assert!(acts.contains(&Act::Close(lid(1))) && acts.contains(&Act::Close(l2)));
        // тем, кто прислал HELLO без идентификации, сообщается причина
        assert!(sends(&acts).iter().any(|(l, b)| *l == l2 && typ_of(b) == T_ERROR));
        assert!(h.sessions.is_empty());
    }

    /// Клиент теста: шлёт обычные пакеты Link из очереди (как клиенты RRC), остальное читает из событий ноды.
    struct Probe(std::sync::Arc<Mutex<Vec<(LinkId, Vec<u8>)>>>);
    impl CoreProcessor for Probe {
        fn on_event(&mut self, _core: &mut StdNodeCore, _event: &NodeEvent) -> TickOutput { TickOutput::empty() }
        fn on_tick(&mut self, core: &mut StdNodeCore, _now_ms: u64) -> TickOutput {
            let mut out = TickOutput::empty();
            for (l, b) in self.0.lock().unwrap().drain(..) {
                if let Ok((_, o)) = core.send_packet_on_link(&l, &b) { out.merge(o); }
            }
            out
        }
    }

    type Outbox = std::sync::Arc<Mutex<Vec<(LinkId, Vec<u8>)>>>;
    struct Client { node: leviculum_std::api::Node, events: leviculum_std::driver::EventReceiver, outbox: Outbox, link: LinkId, who: [u8; 16] }

    impl Client {
        async fn recv(&mut self, secs: u64) -> Option<Vec<u8>> {
            let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
            loop {
                let left = end.checked_duration_since(std::time::Instant::now())?;
                match tokio::time::timeout(left, self.events.recv()).await {
                    Ok(Some(NodeEvent::LinkDataReceived { data, .. })) => return Some(data),
                    Ok(Some(_)) => {}
                    _ => return None,
                }
            }
        }
        fn say(&self, typ: u64, room: Option<&str>, body: Option<&[u8]>) {
            self.outbox.lock().unwrap().push((self.link, build(&self.who, typ, room, body)));
        }
    }

    async fn connect_client(addr: std::net::SocketAddr, dir: std::path::PathBuf, id: Identity, hub: &Identity) -> Client {
        use leviculum_std::api::NodeBuilder;
        let outbox: Outbox = Default::default();
        let mut node = NodeBuilder::new().storage_path(dir).add_tcp_client(addr).core_processor(Probe(outbox.clone())).build().unwrap();
        node.start().await.unwrap();
        let mut events = node.take_event_receiver().unwrap();
        let dest = *Destination::new(Some(Identity::from_public_key_bytes(&hub.public_key_bytes()).unwrap()), Direction::Out, DestinationType::Single, "rrc", &["hub"]).unwrap().hash();
        assert!(node.wait_for_path(&dest, std::time::Duration::from_secs(30), std::time::Duration::from_secs(2)).await.unwrap(), "путь к rrc.hub не найден");
        let handle = node.connect_with_key(&dest, &hub.ed25519_verifying().to_bytes()).await.unwrap();
        let link = *handle.link_id();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let left = until.checked_duration_since(std::time::Instant::now()).expect("Link к хабу не установился");
            if let Ok(Some(NodeEvent::LinkEstablished { is_initiator: true, .. })) = tokio::time::timeout(left, events.recv()).await { break; }
        }
        node.identify_link(&link, &id).await.unwrap();
        Client { node, events, outbox, link, who: *id.hash() }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chat_between_real_nodes_over_plain_link_packets() {
        use leviculum_std::api::{generate_identity, NodeBuilder};
        let (hub_id, a_id, b_id) = (generate_identity(), generate_identity(), generate_identity());
        let base = std::env::temp_dir().join(format!("kh-rrc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let mut hub = NodeBuilder::new().storage_path(base.join("hub")).add_tcp_server(addr).core_processor(HubProcessor::new(hub_id.clone())).build().unwrap();
        hub.start().await.unwrap();
        let mut a = connect_client(addr, base.join("a"), a_id, &hub_id).await;
        let mut b = connect_client(addr, base.join("b"), b_id, &hub_id).await;

        // HELLO -> WELCOME: хаб называет себя и объявляет пределы
        a.say(T_HELLO, None, None);
        let w = a.recv(15).await.expect("WELCOME не пришёл");
        let w = parse(&w).unwrap();
        assert_eq!((w.typ, w.sender), (T_WELCOME, Some(&hub_id.hash()[..])));
        b.say(T_HELLO, None, None);
        assert_eq!(parse(&b.recv(15).await.expect("WELCOME не пришёл")).unwrap().typ, T_WELCOME);

        a.say(T_JOIN, Some("Lobby"), None);
        assert_eq!(parse(&a.recv(15).await.expect("JOINED")).unwrap().typ, T_JOINED);
        b.say(T_JOIN, Some("lobby"), None);
        assert_eq!(parse(&b.recv(15).await.expect("JOINED")).unwrap().typ, T_JOINED);
        // первый участник узнаёт о втором
        let note = a.recv(15).await.expect("JOINED другому участнику");
        assert_eq!((parse(&note).unwrap().typ, parse(&note).unwrap().body), (T_JOINED, Some(&members_body(&[b.who])[..])));

        // сообщение доходит до второго участника теми же байтами; отправитель получает эхо (подтверждение)
        let body = text_item("привет");
        let sent = build(&a.who, T_MSG, Some("lobby"), Some(&body));
        a.outbox.lock().unwrap().push((a.link, sent.clone()));
        assert_eq!(b.recv(15).await.expect("MSG не дошёл"), sent);
        assert_eq!(a.recv(15).await.expect("эхо отправителю"), sent);
        assert!(a.recv(2).await.is_none(), "эхо одно");

        // PING -> PONG с тем же телом
        let payload = bytes_item(&[7, 7, 7]);
        b.say(T_PING, None, Some(&payload));
        let pong = b.recv(15).await.expect("PONG");
        assert_eq!((parse(&pong).unwrap().typ, parse(&pong).unwrap().body), (T_PONG, Some(&payload[..])));

        a.node.stop().await.unwrap();
        b.node.stop().await.unwrap();
        hub.stop().await.unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Стенд интероперабельности (только локально): хаб на 127.0.0.1:$KH_RRC_PORT без иных интерфейсов, хеш назначения
    /// пишется в $KH_RRC_OUT, работает $KH_RRC_SECS секунд. К нему подключаются Python-клиенты (rrc-tui) из изолированного конфига RNS.
    /// `cargo test --lib rrc_interop_server -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn rrc_interop_server() {
        use leviculum_std::api::{generate_identity, NodeBuilder};
        let port: u16 = std::env::var("KH_RRC_PORT").ok().and_then(|v| v.parse().ok()).expect("KH_RRC_PORT");
        let secs: u64 = std::env::var("KH_RRC_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
        let hub_id = generate_identity();
        let dir = std::env::temp_dir().join(format!("kh-rrc-interop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dest = *Destination::new(Some(hub_id.clone()), Direction::In, DestinationType::Single, "rrc", &["hub"]).unwrap().hash();
        if let Ok(out) = std::env::var("KH_RRC_OUT") { std::fs::write(out, dest.to_string()).unwrap(); }
        let mut hub = NodeBuilder::new().storage_path(dir.clone()).add_tcp_server(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
            .core_processor(HubProcessor::new(hub_id)).build().unwrap();
        hub.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        eprintln!("rrc status: {}", status());
        hub.stop().await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_session_without_rooms_makes_room_for_a_newcomer() {
        let mut h = hub();
        for n in 0..MAX_SESSIONS as u8 { connect(&mut h, n, [n.wrapping_add(1); 16], 0); }
        // все свежие: место не освобождается
        assert_eq!(h.step(1, Ev::Open(lid(250))), vec![Act::Close(lid(250))]);
        // через EVICT_IDLE_MS молчащие без комнат уступают место
        let acts = h.step(EVICT_IDLE_MS + 1, Ev::Open(lid(251)));
        assert_eq!(acts.len(), 1);
        assert!(h.sessions.contains_key(&lid(251)) && h.sessions.len() == MAX_SESSIONS);
    }
}
