//! rawgd: серверный узел группы, хаб и клиент VPN с авторизацией по identity (решение D2 v2, docs/decisions/0004).
//!
//! Роли:
//!   hub     - узел-ретранслятор RNS без группы: в лаборатории изображает публичную сеть RNS (только связность и обнаружение);
//!   node    - сервер группы: постоянная identity, анонс по тегу группы, взаимная проверка по серверному секрету с соседями,
//!             таблица соседей (забывает потерявшихся), реестр клиентов (синхронизируется), выход в интернет (TUN + NAT);
//!   client  - клиент: профиль-строка, закреплённые серверы, выбор выхода, смена выхода при отказе.
//!
//! Управляющие сообщения идут по Channel Link: [тип u8][тело]. Пакеты туннеля - датаграммы Link (контекст Tunnel), как раньше.
//! Секреты не попадают в журнал и в аргументы: серверный секрет читается из файла, профиль - из файла.

use super::*;
use base64::Engine as _;
use clap::{Args, Subcommand};
use hmac::{Hmac, Mac};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

#[path = "vpn_path.rs"]
mod path;

type HmacSha = Hmac<Sha256>;

// ------------------------------------------------------------------------------------------------ команды

#[derive(Parser, Clone)]
#[command(name = "rawgd", about = "rawg: серверный узел, хаб и клиент VPN")]
pub struct VpnCli {
    #[command(subcommand)]
    pub cmd: VpnCmd,
}

#[derive(Subcommand, Clone)]
pub enum VpnCmd {
    /// сервер группы (выход, сосед, реестр клиентов)
    Node(NodeArgs),
    /// ретранслятор RNS без группы (лабораторная «публичная сеть»)
    Hub(HubArgs),
    /// клиент VPN (читает профиль из файла)
    Client(ClientArgs),
    /// выдать профиль клиента (локальная админ-команда сервера, работающего с этим каталогом состояния)
    Issue(IssueArgs),
    /// отозвать клиента
    Revoke(RevokeArgs),
    /// показать реестр клиентов и таблицу соседей
    List(StateArg),
    /// создать серверный секрет группы (>= 128 бит) и записать в файл
    Keygen(KeygenArgs),
    /// выпустить приглашение `rawgi-…` для новой ноды (локальная команда админа)
    Invite(InviteArgs),
    /// выдать или изменить права ноды (запись подписывается identity из --state)
    Grant(GrantArgs),
    /// что эта нода согласна делать в сети (0015): политика подписывается ею самой и сужает выданные права; нода применит за несколько секунд
    Policy(PolicyArgs),
    /// синтетический бенч пути RNS до соседа с живым Link (0014 R10): запрос кладётся файлом, нода меряет и пишет результат
    Bench(BenchArgs),
    /// создать identity, если её ещё нет, и записать `whoami.json` (хеш и адрес в туннеле): приложению адрес нужен до создания TUN
    Whoami(StateArg),
    /// список категорий скачанных geoip.dat/geosite.dat в `rules-cats.json` (раздельное туннелирование)
    RulesList(StateArg),
    /// подсети правил «мимо туннеля» в `direct.cidr` и отчёт `rules-report.json`
    RulesCompile(StateArg),
}

#[derive(Args, Clone)]
pub struct PolicyArgs {
    #[arg(long)]
    pub state: PathBuf,
    /// корень сети (хеш identity админа, 32 hex); по умолчанию свой
    #[arg(long)]
    pub root: Option<String>,
    /// что согласна делать: число или список (use+exit+transit); none - ничего. Шире выданного это не сделает
    #[arg(long)]
    pub rights: String,
}

#[derive(Args, Clone)]
pub struct StateArg {
    #[arg(long)]
    pub state: PathBuf,
}

#[derive(Args, Clone)]
pub struct KeygenArgs {
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args, Clone, Default)]
pub struct NodeArgs {
    /// JSON-файл настроек узла (поля как в флагах ниже, кроме --state); при его наличии флаги name/group/secret-file/advertise/seed игнорируются
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long, default_value = "-")]
    pub state: PathBuf,
    /// имя группы (тег группы выводится из него; не секрет)
    #[arg(long, default_value = "")]
    pub group: String,
    /// файл серверного секрета группы (rawgd keygen)
    #[arg(long, default_value = "-")]
    pub secret_file: PathBuf,
    /// имя узла для таблиц и интерфейса; по умолчанию - имя хоста (так один и тот же конфиг годится для всех узлов)
    #[arg(long, default_value = "")]
    pub name: String,
    #[arg(long, default_value_t = 47001)]
    pub port: u16,
    /// адреса, по которым узла можно достать (ip:порт через запятую). По умолчанию пусто: узел сам находит свои глобально маршрутизируемые адреса интерфейсов
    #[arg(long, default_value = "")]
    pub advertise: String,
    /// считать объявляемыми и частные адреса интерфейсов (лаборатория; в бою не нужно)
    #[arg(long)]
    pub advertise_private: bool,
    /// прямые соседи для входа в сеть: `id@ip:порт` (id - ключ узла из его server.json), через запятую; у узла, который не виден напрямую, это его видимый сосед
    #[arg(long, default_value = "")]
    pub seed: String,
    /// файл со списком публичных узлов RNS (по строке `host:порт`, `#` - комментарий); подключаются как TCP-клиенты только для анонсов и связности
    #[arg(long)]
    pub public_rns_file: Option<PathBuf>,
    /// режим интерфейсов к публичным узлам (roaming: мы не транзит между публичными узлами)
    #[arg(long, default_value = "roaming")]
    pub public_mode: String,
    /// без выхода в интернет (только сосед/ретранслятор)
    #[arg(long)]
    pub no_exit: bool,
    /// период анонса, с. При публичной сети анонсы дороги для чужих узлов: после трёх стартовых (0, 20, 40 с) идёт этот период
    #[arg(long, default_value_t = 600)]
    pub announce_s: u64,
    /// сосед без ответа на пинг дольше этого срока считается потерянным
    #[arg(long, default_value_t = 12)]
    pub dead_s: u64,
    #[arg(long, default_value_t = 500)]
    pub quic_cc_mbit: u64,
    #[arg(long, default_value_t = 0)]
    pub workers: usize,
    /// имя интерфейса TUN выхода; NAT и forwarding настраивает развёртывание, не узел
    #[arg(long, default_value = "tun0")]
    pub tun_name: String,
    /// подсеть адресов клиентов; одинакова на всех узлах группы и не должна пересекаться с сетями узлов
    #[arg(long, default_value = "198.18.0.0/15")]
    pub client_net: String,
    /// модель 0013: приглашение `rawgi-…` (одноразовое; после зачисления игнорируется). Без приглашения нода сама себе админ
    #[arg(long, default_value = "")]
    pub invite: String,
    /// то же приглашение из файла
    #[arg(long)]
    pub invite_file: Option<PathBuf>,
}

/// Файл настроек узла: имя, группа и файл секрета обязательны, остальное по умолчанию.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct NodeConf {
    name: String,
    group: String,
    secret_file: PathBuf,
    port: Option<u16>,
    advertise: Vec<String>,
    advertise_private: bool,
    seeds: Vec<String>,
    public_rns: Vec<String>,
    public_rns_file: Option<PathBuf>,
    public_mode: Option<String>,
    no_exit: bool,
    announce_s: Option<u64>,
    dead_s: Option<u64>,
    quic_cc_mbit: Option<u64>,
    workers: Option<usize>,
    tun_name: Option<String>,
    client_net: Option<String>,
    /// модель 0013: приглашение rawgi- (одноразовое; после зачисления игнорируется)
    invite: Option<String>,
    invite_file: Option<PathBuf>,
}

/// Минимальный HTTP GET по 80 порту без зависимостей: тело ответа или None.
async fn http_get(host: &str, path: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::time::timeout(Duration::from_secs(4), tokio::net::TcpStream::connect((host, 80))).await.ok()?.ok()?;
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: rawgd\r\nConnection: close\r\n\r\n").as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), s.take(8192).read_to_end(&mut buf)).await.ok()?.ok()?;
    let t = String::from_utf8_lossy(&buf).to_string();
    if !t.starts_with("HTTP/1.") || !t.contains(" 200") {
        return None;
    }
    t.split_once("\r\n\r\n").map(|x| x.1.trim().to_string())
}

/// Двухбуквенный код страны узла по его внешнему IP: несколько сервисов по очереди, результат кэшируется в каталоге состояния.
/// Порядок: RAWGD_REGION (задаёт оператор/стенд) -> сервисы -> кэш -> "XX".
async fn detect_region(state: &Path) -> String {
    let ok = |c: &str| c.len() == 2 && c.chars().all(|x| x.is_ascii_alphabetic());
    if let Ok(r) = std::env::var("RAWGD_REGION") {
        let r = r.trim().to_uppercase();
        if ok(&r) {
            return r;
        }
    }
    let cache = state.join("region.txt");
    // (хост, путь, как достать код из тела)
    let svcs: [(&str, &str, fn(&str) -> String); 3] = [
        ("ip-api.com", "/line/?fields=countryCode", |b| b.lines().next().unwrap_or("").trim().to_string()),
        ("ipinfo.io", "/country", |b| b.lines().next().unwrap_or("").trim().to_string()),
        ("ifconfig.co", "/country-iso", |b| b.lines().next().unwrap_or("").trim().to_string()),
    ];
    for (host, path, f) in svcs {
        if let Some(body) = http_get(host, path).await {
            let c = f(&body).to_uppercase();
            if ok(&c) {
                let _ = std::fs::write(&cache, &c);
                return c;
            }
        }
    }
    let c = std::fs::read_to_string(&cache).unwrap_or_default().trim().to_uppercase();
    if ok(&c) { c } else { "XX".into() }
}

/// Имя узла от допущенного пира: до 32 знаков без управляющих; код страны `cc` (две латинские буквы) нужен интерфейсу для флага.
/// Имя вида `knothop-XX-…` не трогаем, прочее заворачиваем в него (интерфейс разбирает только эту форму).
/// Символ допустим в отображаемом имени от пира: без управляющих и без невидимых/меняющих направление текста (подмена имени в UI).
fn name_char_ok(c: char) -> bool {
    !c.is_control() && !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

fn norm_peer_name(name: &str, cc: &str) -> Option<String> {
    let name: String = name.chars().filter(|c| name_char_ok(*c)).take(32).collect();
    let name = name.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let cc = cc.trim().to_uppercase();
    let cc_ok = cc.len() == 2 && cc.chars().all(|x| x.is_ascii_alphabetic());
    let parts: Vec<&str> = name.splitn(3, '-').collect();
    if parts.len() == 3 && parts[0] == "knothop" && parts[1].len() == 2 {
        return Some(name);
    }
    Some(if cc_ok { format!("knothop-{cc}-{name}") } else { name })
}

/// Тип узла, три значения: «android», «ios», «server» (rawgd node или приложение на Windows/Linux/macOS).
/// Только по допущенному Link, не в анонсе (ADR 0016).
fn platform() -> &'static str {
    match std::env::consts::OS {
        "android" => "android",
        "ios" => "ios",
        _ => "server",
    }
}

/// Тип платформы одним байтом (в приглашении) и обратно.
/// Имя клиента для сети: телефон - «телефон-XXXXXX» по хешу identity. Имя и тип узла раздаёт сам узел
/// (клиент сообщает их выходу в T_USE, выход передаёт дальше в T_NBRS); приглашение их не переносит.
fn client_display_name(identity: &Identity) -> String {
    match trust::hash_of(&identity.public_key_bytes()) {
        Some(h) => format!("телефон-{}", &hex(&h)[..6]),
        None => "телефон".into(),
    }
}

/// Тело T_USE от клиента: тип и имя узла, чтобы выход раздал их другим клиентам.
fn client_info_body(identity: &Identity) -> Vec<u8> {
    let name = client_display_name(identity);
    let pl = platform();
    let mut b = Vec::with_capacity(2 + pl.len() + name.len());
    b.push(pl.len() as u8);
    b.extend_from_slice(pl.as_bytes());
    b.push(name.len() as u8);
    b.extend_from_slice(name.as_bytes());
    b
}

/// Ключ - узел сети (якорь или права TRANSIT/EXIT), а не рядовой пользователь: только таких раскрываем другим клиентам.
fn node_like(tr: &trust::Trust, pk: &[u8; 64]) -> bool {
    trust::hash_of(pk).map(|h| tr.has_anchor(&h)).unwrap_or(false) || tr.rights(pk) & (trust::TRANSIT | trust::EXIT) != 0
}

/// T_CINFO от соседа-сервера: клиенты-узлы с именем и типом. Права каждого ключа проверяем сами; заявке соседа не верим.
fn on_cinfo(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    let Some(t) = &ctx.t13 else { return };
    if body.len() > 4096 || !ctx.links.lock().unwrap().get(&link).map(|l| matches!(l.role, Role::Server { .. })).unwrap_or(false) {
        return;
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else { return };
    let Some(arr) = v["c"].as_array() else { return };
    let mut got: Vec<([u8; 16], String, &'static str)> = Vec::new();
    {
        let tr = t.trust.lock().unwrap();
        for x in arr.iter().take(16) {
            let Some(pk) = x["k"].as_str().filter(|k| k.len() == 128 && k.bytes().all(|b| b.is_ascii_hexdigit())).and_then(|k| <[u8; 64]>::try_from(unhex(k)).ok()) else { continue };
            let Some(pl) = x["pl"].as_str().and_then(|p| parse_platform(p.as_bytes())) else { continue };
            let name: String = x["n"].as_str().unwrap_or("").chars().filter(|c| name_char_ok(*c)).take(32).collect();
            if name.is_empty() || !node_like(&tr, &pk) {
                continue;
            }
            got.push((dest_from_pub_tag(&pk, T13_TAG), name, pl));
        }
    }
    let mut pc = ctx.peer_clients.lock().unwrap();
    pc.retain(|_, v| v.2.elapsed() < CINFO_TTL);
    for (d, n, pl) in got {
        if pc.len() < CINFO_MAX || pc.contains_key(&d) {
            pc.insert(d, (n, pl, Instant::now()));
        }
    }
}

/// Разбор тела T_USE клиента: (имя, тип). None - клиент ничего не сообщил или прислал мусор.
fn parse_client_info(body: &[u8]) -> Option<(String, &'static str)> {
    let pl_len = *body.first()? as usize;
    let pl = body.get(1..1 + pl_len)?;
    let name_len = *body.get(1 + pl_len)? as usize;
    if body.len() != 2 + pl_len + name_len {
        return None;
    }
    let name = std::str::from_utf8(&body[2 + pl_len..]).ok()?;
    let name: String = name.chars().filter(|c| name_char_ok(*c)).take(32).collect();
    Some((name, parse_platform(pl)?))
}

/// Тип от пира: только значения из списка (произвольную строку не храним и не показываем).
fn parse_platform(b: &[u8]) -> Option<&'static str> {
    const ALL: [&str; 3] = ["android", "ios", "server"];
    let t = std::str::from_utf8(b).ok()?.trim();
    ALL.iter().copied().find(|x| *x == t)
}

fn hostname() -> String {
    let mut b = [0u8; 256];
    if unsafe { libc::gethostname(b.as_mut_ptr() as *mut _, b.len()) } != 0 {
        return String::new();
    }
    let n = b.iter().position(|c| *c == 0).unwrap_or(0);
    String::from_utf8_lossy(&b[..n]).chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(32).collect()
}

/// Глобально маршрутизируемый адрес? (не частный, не loopback, не link-local, не CGNAT, не multicast, не служебный/документационный)
fn is_global_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            let o = v.octets();
            let bits = u32::from(*v);
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_multicast() || v.is_broadcast() || v.is_unspecified()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) || o[0] == 0 || o[0] >= 240
                || (o[0] == 198 && (o[1] & 0xfe) == 18) || (o[0] == 192 && o[1] == 0 && o[2] <= 2)
                || V4_SPECIAL.iter().any(|&(net, len)| v4_in(bits, net, len)))
        }
        std::net::IpAddr::V6(v) => {
            // IPv4-mapped (::ffff:0:0/96): решает встроенный IPv4 тем же фильтром
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_global_ip(&std::net::IpAddr::V4(v4));
            }
            let bits = u128::from(*v);
            (v.segments()[0] & 0xe000) == 0x2000 // 2000::/3
                && !V6_SPECIAL.iter().any(|&(net, len)| v6_in(bits, net, len))
        }
    }
}

/// S7: служебные IPv4-диапазоны сверх встроенных проверок: документационные, 6to4-relay anycast, зарезервированные 240/4, широковещательный.
const V4_SPECIAL: &[(u32, u32)] = &[
    (0xC000_0000, 24), // 192.0.0.0/24
    (0xC000_0200, 24), // 192.0.2.0/24 (TEST-NET-1)
    (0xC058_6300, 24), // 192.88.99.0/24
    (0xC633_6400, 24), // 198.51.100.0/24 (TEST-NET-2)
    (0xCB00_7100, 24), // 203.0.113.0/24 (TEST-NET-3)
    (0xF000_0000, 4), // 240.0.0.0/4
    (0xFFFF_FFFF, 32), // 255.255.255.255
];

/// S7: служебные IPv6-диапазоны внутри 2000::/3 и NAT64/100:: (последние уже вне 2000::/3, перечислены явно).
const V6_SPECIAL: &[(u128, u32)] = &[
    (0x2001_0db8 << 96, 32), // 2001:db8::/32 (документация)
    (0x2001_0000 << 96, 32), // 2001::/32 (Teredo)
    (0x2002 << 112, 16), // 2002::/16 (6to4)
    (0x0064_ff9b << 96, 96), // 64:ff9b::/96 (NAT64)
    (0x0100 << 112, 64), // 100::/64 (discard-only)
];

fn v4_in(bits: u32, net: u32, len: u32) -> bool {
    let m = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    bits & m == net & m
}

fn v6_in(bits: u128, net: u128, len: u32) -> bool {
    let m = if len == 0 { 0 } else { u128::MAX << (128 - len) };
    bits & m == net & m
}

/// Адреса интерфейсов, по которым узла можно достать: глобальные (или любые не служебные при `allow_private`). IPv4 вперёд, не более 3.
fn local_addrs(port: u16, allow_private: bool, skip_iface: &str) -> Vec<String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return vec![];
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            let up = ifa.ifa_flags & (libc::IFF_UP as u32) != 0;
            // свой туннель (и loopback) никогда не точка входа: пакеты носителя не должны идти внутрь него
            let iname = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
            if up && !ifa.ifa_addr.is_null() && iname != skip_iface && iname != "lo" {
                match (*ifa.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                        let ok = if allow_private { !(ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()) } else { is_global_ip(&std::net::IpAddr::V4(ip)) };
                        if ok {
                            v4.push(SocketAddr::new(ip.into(), port).to_string());
                        }
                    }
                    libc::AF_INET6 => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
                        if is_global_ip(&std::net::IpAddr::V6(ip)) {
                            v6.push(SocketAddr::new(ip.into(), port).to_string());
                        }
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    v4.extend(v6);
    v4.dedup();
    v4.truncate(3);
    v4
}

fn load_public_list(file: &Option<PathBuf>, inline: &[String]) -> Vec<String> {
    let mut v: Vec<String> = inline.to_vec();
    if let Some(f) = file {
        if let Ok(t) = std::fs::read_to_string(f) {
            v.extend(t.lines().map(|l| l.split('#').next().unwrap_or("").trim().to_string()).filter(|l| !l.is_empty()));
        }
    }
    v.sort();
    v.dedup();
    v
}

#[derive(Args, Clone)]
pub struct HubArgs {
    #[arg(long)]
    pub state: PathBuf,
    #[arg(long, default_value_t = 47000)]
    pub port: u16,
    /// TCP-порт интерфейса RNS (изображает публичный узел сети RNS: к нему подключаются как к узлам из каталога)
    #[arg(long, default_value_t = 4242)]
    pub tcp_port: u16,
}

#[derive(Args, Clone)]
pub struct ClientArgs {
    #[arg(long)]
    pub state: PathBuf,
    /// файл с профилем легаси-модели (строка rawg2-...); без него клиент работает по модели 0013 (своя identity в --state, права записями)
    #[arg(long)]
    pub profile_file: Option<PathBuf>,
    /// модель 0013: приглашение `rawgi-…` (одноразовое; после зачисления игнорируется)
    #[arg(long, default_value = "")]
    pub invite: String,
    #[arg(long)]
    pub invite_file: Option<PathBuf>,
    /// модель 0013: файл списка публичных RNS-узлов (анонсы и первый Link; данные через них не идут)
    #[arg(long)]
    pub public_rns_file: Option<PathBuf>,
    /// дескриптор TUN от VpnService
    #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
    pub tun_fd: i32,
    /// без ответа на пинг дольше этого срока (мс) выход считается мёртвым
    #[arg(long, default_value_t = 3000)]
    pub fail_ms: u64,
    #[arg(long, default_value_t = 500)]
    pub quic_cc_mbit: u64,
    #[arg(long, default_value_t = 4)]
    pub workers: usize,
}

#[derive(Args, Clone)]
pub struct IssueArgs {
    #[arg(long)]
    pub state: PathBuf,
    /// метка клиента (для списка; не секрет)
    #[arg(long)]
    pub client_name: String,
    /// сколько серверов положить в профиль (закреплённые); остальных клиент узнает от них сам
    #[arg(long, default_value_t = 3)]
    pub servers: usize,
    /// не больше стольких адресов на сервер (профиль короче)
    #[arg(long)]
    pub max_addrs: Option<usize>,
}

#[derive(Args, Clone)]
pub struct RevokeArgs {
    #[arg(long)]
    pub state: PathBuf,
    /// идентификатор клиента (из `list`)
    #[arg(long)]
    pub id: String,
}

#[derive(Args, Clone)]
pub struct InviteArgs {
    /// каталог состояния ноды-админа (identity и trust.json там же)
    #[arg(long)]
    pub state: PathBuf,
    /// права приглашаемого: user | relay | admin, число или список (USE+EXIT)
    #[arg(long, default_value = "user")]
    pub rights: String,
    /// корень сети (хеш identity, 32 hex); по умолчанию свой
    #[arg(long)]
    pub root: Option<String>,
    /// метка для списка (не секрет)
    #[arg(long, default_value = "")]
    pub label: String,
    /// адрес админа для первого дозвона (ip:порт), можно несколько; по умолчанию - адреса из server.json
    #[arg(long = "addr")]
    pub addrs: Vec<String>,
    /// записать приглашение в файл (для оболочки Android, у которой нет stdout), права 0600
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// входные ноды: identity-хеши (32 hex), через запятую, не более 8; приглашённый обратится за зачислением только к ним
    #[arg(long, value_delimiter = ',')]
    pub nodes: Vec<String>,
}

#[derive(Args, Clone)]
pub struct GrantArgs {
    #[arg(long)]
    pub state: PathBuf,
    /// корень (хеш identity админа, 32 hex); по умолчанию свой
    #[arg(long)]
    pub root: Option<String>,
    /// держатель: публичный ключ (128 hex) или префикс хеша уже известного держателя
    #[arg(long)]
    pub holder: String,
    /// user | relay | admin, число или список; none - снять права
    #[arg(long)]
    pub rights: String,
}

#[derive(Args, Clone)]
pub struct BenchArgs {
    /// каталог состояния запрашивающей ноды (запрос кладётся в его bench/)
    #[arg(long)]
    pub state: PathBuf,
    /// имя соседа, dest (32 hex) или его префикс не короче 8 hex
    #[arg(long)]
    pub to: String,
    /// сколько МБ (10^6 байт) тянуть, от 1 до 100
    #[arg(long)]
    pub mb: u64,
    /// сколько ждать результата, с (10..900)
    #[arg(long, default_value_t = 120)]
    pub timeout: u64,
}

// ------------------------------------------------------------------------------------------------ вспомогательное

const T_SRV1: u8 = 1;
const T_SRV2: u8 = 2;
const T_SRV3: u8 = 3;
const T_SRV4: u8 = 4;
const T_PING: u8 = 5;
const T_PONG: u8 = 6;
const T_TABLE: u8 = 7;
const T_REGISTRY: u8 = 8;
const T_AUTH_OK: u8 = 9;
const T_AUTH_FAIL: u8 = 10;
// модель прав (решение 0013): записи о правах, зачисление по приглашению
const T_REC: u8 = 11;      // одна подписанная запись о правах (171 Б)
const T_PAIR1: u8 = 12;    // нода -> админ: holder pub(64) | mac32(pin); ответ админа - обычная T_REC с записью новой ноды
const T_PAIR_NO: u8 = 13;  // админ -> нода: отказ в зачислении (тело - причина)
const T_USE: u8 = 14;      // клиент -> сервер: «я пришёл за выходом» (иначе Link - сосед-транзит)
const T_PAIRQ: u8 = 15;    // новичок -> нода-посредник -> (соседи) -> админ: root(16) | inviter(16) | holder pub(64) | mac32(pin)
const T_NBRS: u8 = 16;     // выход -> клиент: соседи с живым Link {"n":[{"d","r"}]} (0014 R3); список выходов не меняет
const T_DIR: u8 = 17;      // посредник -> новичок: каталог нод {"n":[{"d","k","e","a","n"}]} (0014 R6); только подсказки адресов
/// Advisory observations are bounded by both count and negotiated Channel MDU.
const NBRS_MAX: usize = crate::observations::MAX_NEIGHBORS;
const T_OBSERVE: u8 = 21; // admitted client -> exit: UI visible (one byte 0/1), request fresh T_NBRS
/// сосед-сервер -> сосед-сервер: клиенты-узлы (якорь/TRANSIT/EXIT) с их именем и типом {"c":[{"k","n","pl"}]};
/// получатель проверяет права ключа по своим записям, держит не дольше CINFO_TTL; только для отображения
const T_CINFO: u8 = 22;
const CINFO_TTL: Duration = Duration::from_secs(60);
const CINFO_MAX: usize = 64;
/// T_DIR: не более DIR_MAX записей каталога, кусками не длиннее DIR_CHUNK Б
const DIR_MAX: usize = 16;
/// книга адресов нод с правами (addr-book.json): не больше стольких записей
const BOOK_MAX: usize = 32;
static BOOK_LAST: Mutex<String> = Mutex::new(String::new());
const DIR_CHUNK: usize = 700;
/// 0015: подписанная политика ноды (`trust::Policy`, 163 Б). Принимается только на допущенном Link (сосед или клиент); верна по подписи самой ноды,
/// поэтому путь доставки не важен. Ничего не расширяет: действующие права = выдача ∩ политика.
const T_POL: u8 = 20;
/// R10: бенч. T_BENCH по Channel: запрос {"id","n","sz"}, ответы {"id","busy"|"rate"|"done"}. T_BENCH_DATA - датаграмма Link
/// [19][id u32 LE][seq u32 LE][t_ms u64 LE][заполнение]: первый байт не совпадает с IPv4 (0x4_) и с RGP ('R').
const T_BENCH: u8 = 18;
const T_BENCH_DATA: u8 = 19;
/// Объём бенча до 1000 МБ (решение владельца 21.10: объём тестов выбирает агент, прежний предел 100 МБ снят).
const BENCH_MAX_MB: u64 = 1000;
const BENCH_MAX_N: u64 = BENCH_MAX_MB * 1_000_000;
/// n counts wire bytes including the 17-byte header; final datagram pads to 17 bytes, so n_sent may exceed n by at most 16.
/// минимальный размер датаграммы бенча (заголовок 17 байт + заполнение)
const BENCH_SZ_MIN: usize = 32;
const BENCH_HDR: usize = 17;
/// не чаще раза в эту пору на пира отдаём бенч
const BENCH_RATE: Duration = Duration::from_secs(60);
const BENCH_RATE_MAX: usize = 256;
/// нет ни одного пакета столько - блокировка (0 байт)
const BENCH_BLOCK: Duration = Duration::from_secs(30);
/// пауза между пакетами не меньше этой - остановка
const BENCH_STALL: Duration = Duration::from_secs(10);
/// после done ждём опоздавших датаграмм столько
const BENCH_GRACE: Duration = Duration::from_secs(3);

const UNAUTH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_UNAUTH_LINKS: usize = 64;
/// H10: неаутентифицированных Link через один интерфейс носителя (глобально - MAX_UNAUTH_LINKS).
const MAX_UNAUTH_PER_IFACE: usize = 8;
/// H10: управляющие сообщения на Link (MessageReceived): ведро CTRL_RATE/с, запас CTRL_BURST. Сверх - отбрасываются.
/// Непрерывное нарушение CTRL_VIOLATION_CLOSE подряд - Link закрывается. LinkDataReceived (VPN, бенч) сюда не относится.
const CTRL_RATE: f64 = 50.0;
const CTRL_BURST: f64 = 100.0;
const CTRL_VIOLATION_CLOSE: Duration = Duration::from_secs(10);
/// C13 (клиент): попытки зачисления (`enroll_try`): записи старше TTL выкидываем, новых ключей сверх MAX не вставляем.
const ENROLL_TRY_TTL: Duration = Duration::from_secs(600);
const ENROLL_TRY_MAX: usize = 64;
/// B (клиент): ведро управляющих сообщений заводим не более чем на столько Link; сообщения с новых Link сверх лимита отбрасываются.
const CLIENT_CTRL_LINKS: usize = 64;
const MAX_NEIGHBORS: usize = 64;
/// S2/S3: записи соседей без TRANSIT по записям и без живого Link. Отдельный лимит, чтобы публичные анонсы не заняли таблицу.
const MAX_UNTRUSTED_NEIGHBORS: usize = 32;
const MAX_REGISTRY: usize = 4096;
/// H9: буфер `early` - всего и на один Link; новые запросы на pairq - на один Link за 60 с. Мусор одного пира не вытесняет чужое.
const EARLY_MAX: usize = 64;
const EARLY_PER_LINK: usize = EARLY_MAX;
const PAIRQ_PER_LINK: usize = 8;

fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn b64d(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim()).map_err(|e| anyhow::anyhow!("base64: {e}"))
}

fn mac32(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <HmacSha as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn mac_ok(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    let mut m = <HmacSha as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        m.update(p);
    }
    m.verify_slice(tag).is_ok() // постоянное время
}

fn rand16() -> [u8; 16] {
    let mut b = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

/// Тег группы: не секрет, по нему узлы группы отличают свои анонсы.
fn group_tag(group: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"rawg-group-v1\0");
    h.update(group.as_bytes());
    hex(&h.finalize()[..8])
}

/// Ключ серверной аутентификации: выводится из серверного секрета и имени группы; клиентам не передаётся.
fn server_auth_key(secret: &[u8], group: &str) -> [u8; 32] {
    mac32(secret, &[b"rawg-server-auth-v1\0", group.as_bytes()])
}

fn read_secret(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read secret {}", path.display()))?;
    let secret = b64d(raw.trim())?;
    if secret.len() < 16 {
        bail!("серверный секрет слишком короткий (нужно >= 128 бит, rawgd keygen)");
    }
    Ok(secret)
}

/// Подсеть адресов клиентов (одна на всю группу: клиент сохраняет адрес при смене выхода). Задаётся в конфиге узла (`client_net`),
/// выбирается так, чтобы не пересекаться с сетями узлов (на ru1 10.130.0.0/24 попадает в 10.128.0.0/10 - для пилота 198.18.0.0/15).
static CLIENT_NET: std::sync::OnceLock<(u32, u8)> = std::sync::OnceLock::new();
/// Двухбуквенный код страны этого узла (по внешнему IP или RAWGD_REGION); уходит только допущенным по Link (в анонсе его нет, ADR 0016).
static REGION: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn parse_net(t: &str) -> Result<(u32, u8)> {
    let (a, p) = t.split_once('/').ok_or_else(|| anyhow::anyhow!("client_net: нужен вид a.b.c.d/N"))?;
    let ip: std::net::Ipv4Addr = a.parse().context("client_net: адрес")?;
    let p: u8 = p.parse().context("client_net: длина")?;
    if !(8..=24).contains(&p) {
        bail!("client_net: длина префикса 8..24");
    }
    Ok((u32::from(ip) & (u32::MAX << (32 - p)), p))
}

/// Подсеть клиентов по умолчанию. Должна совпадать с `client_net` узлов и с правилом masquerade на них, иначе ответы из интернета
/// не вернутся: пакет уйдёт с адресом, который NAT не переписывает. 198.18.0.0/15 взят из пилота - не пересекается с внутренними
/// сетями узлов (на ru1 10.130.0.0/24 попадал в 10.128.0.0/10).
fn client_net() -> (u32, u8) {
    *CLIENT_NET.get().unwrap_or(&(0xc612_0000, 15))
}

fn net_str() -> String {
    let (b, p) = client_net();
    format!("{}/{p}", std::net::Ipv4Addr::from(b))
}

/// Адрес клиента внутри туннеля выводится из его identity (без DHCP): хвост хеша в подсети `client_net`, не нулевой и не широковещательный.
fn client_ip(id: &[u8; 16]) -> u32 {
    let (base, p) = client_net();
    let host_mask = if p >= 32 { 0 } else { u32::MAX >> p };
    let mut host = u32::from_be_bytes([id[0], id[1], id[2], id[3]]) & host_mask;
    if host == 0 {
        host = 1;
    }
    if host == host_mask {
        host -= 1;
    }
    base | host
}

fn ip_str(ip: u32) -> String {
    std::net::Ipv4Addr::from(ip).to_string()
}

fn load_names(state: &Path) -> HashMap<[u8; 16], String> {
    let Ok(t) = std::fs::read_to_string(state.join("names.json")) else { return HashMap::new() };
    let Ok(m) = serde_json::from_str::<HashMap<String, String>>(&t) else { return HashMap::new() };
    m.into_iter().take(64).filter_map(|(d, n)| Some((dest32(&d)?, norm_peer_name(&n, "")?))).collect()
}

fn write_atomic(p: &Path, data: &[u8]) {
    let tmp = p.with_extension("tmp");
    if std::fs::write(&tmp, data).is_ok() {
        let _ = std::fs::rename(&tmp, p);
    }
}

fn secure_write(p: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(p)?;
    f.write_all(data)?;
    Ok(())
}

fn load_or_create_identity(state: &Path) -> Result<Identity> {
    let p = state.join("identity.key");
    if let Ok(t) = std::fs::read_to_string(&p) {
        let id = Identity::from_private_key_bytes(&unhex(t.trim())).map_err(|e| anyhow::anyhow!("identity.key: {e:?}"))?;
        return Ok(id);
    }
    let id = leviculum_std::api::generate_identity();
    secure_write(&p, hex(&id.private_key_bytes().map_err(|e| anyhow::anyhow!("{e:?}"))?).as_bytes())?;
    Ok(id)
}

/// Ключ QUIC узла = ключ подписи его identity RNS: EndpointId совпадает с закреплённым в профиле ключом, отдельный id не нужен.
/// Цена: один ключ в двух протоколах (TLS 1.3 и подписи RNS); контексты подписи различаются. См. O45.
fn iroh_key_from_identity(id: &Identity) -> Result<SecretKey> {
    let prv = id.private_key_bytes().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let seed: [u8; 32] = prv[32..64].try_into().unwrap();
    Ok(SecretKey::from_bytes(&seed))
}

fn dest32(d: &str) -> Option<[u8; 16]> {
    unhex(d).try_into().ok()
}

// ------------------------------------------------------------------------------------------------ профиль клиента

/// Закреплённый сервер: хеш назначения и ключ подписи (он же iroh EndpointId узла: узел использует свой ключ RNS для QUIC).
#[derive(Clone, Debug, PartialEq)]
pub struct ProfServer {
    pub n: String,
    pub d: [u8; 16],
    pub k: [u8; 32],
    /// `ip:порт` или `имя:порт`; имена разрешаются при каждом дозвоне (у узла может быть динамический IP)
    pub a: Vec<String>,
}

/// Профиль клиента. Содержит секрет (seed ключа клиента): профиль - секрет целиком.
#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub group: String,
    /// 32 случайных байта; из них выводятся оба ключа identity клиента (`client_identity`)
    pub seed: [u8; 32],
    /// адрес клиента в туннеле (выведен из identity, хранится ради приложения, которое не считает ключи)
    pub ip: u32,
    pub s: Vec<ProfServer>,
}

/// Identity клиента из seed: два независимых ключа через HMAC (X25519 и Ed25519), так что в профиле 32 байта вместо 64.
fn client_identity(seed: &[u8; 32]) -> Result<Identity> {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&mac32(seed, &[b"rawg-client-x25519-v1"]));
    b[32..].copy_from_slice(&mac32(seed, &[b"rawg-client-ed25519-v1"]));
    Identity::from_private_key_bytes(&b).map_err(|e| anyhow::anyhow!("identity клиента: {e:?}"))
}

/// Формат (v2, бинарный, затем base64url): `rawg2-` + base64(
///   версия(1)=2 | seed(32) | ip(4) | len+имя группы | n(1) | n x [ len+имя | d(16) | k(32) | m(1) | m x (тип(1)=4|6, ip, порт u16 BE) ] | sha256[..4] ).
pub fn encode_profile(p: &Profile) -> String {
    let mut b = vec![2u8];
    b.extend_from_slice(&p.seed);
    b.extend_from_slice(&p.ip.to_be_bytes());
    b.push(p.group.len().min(255) as u8);
    b.extend_from_slice(&p.group.as_bytes()[..p.group.len().min(255)]);
    b.push(p.s.len().min(255) as u8);
    for s in p.s.iter().take(255) {
        b.push(s.n.len().min(255) as u8);
        b.extend_from_slice(&s.n.as_bytes()[..s.n.len().min(255)]);
        b.extend_from_slice(&s.d);
        b.extend_from_slice(&s.k);
        b.push(s.a.len().min(255) as u8);
        for a in s.a.iter().take(255) {
            match a.parse::<SocketAddr>() {
                Ok(SocketAddr::V4(v)) => {
                    b.push(4);
                    b.extend_from_slice(&v.ip().octets());
                    b.extend_from_slice(&v.port().to_be_bytes());
                }
                Ok(SocketAddr::V6(v)) => {
                    b.push(6);
                    b.extend_from_slice(&v.ip().octets());
                    b.extend_from_slice(&v.port().to_be_bytes());
                }
                Err(_) => {
                    // имя: тип 3, длина, `имя:порт` как есть
                    let t = a.as_bytes();
                    b.push(3);
                    b.push(t.len().min(255) as u8);
                    b.extend_from_slice(&t[..t.len().min(255)]);
                }
            }
        }
    }
    let ck = Sha256::digest(&b);
    b.extend_from_slice(&ck[..4]);
    format!("rawg2-{}", b64e(&b))
}

pub fn decode_profile(s: &str) -> Result<Profile> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let body = s.strip_prefix("rawg2-").ok_or_else(|| anyhow::anyhow!("не профиль rawg (нет префикса rawg2-)"))?;
    let b = b64d(body)?;
    if b.len() < 8 {
        bail!("профиль слишком короткий");
    }
    let (j, ck) = b.split_at(b.len() - 4);
    if Sha256::digest(j)[..4] != *ck {
        bail!("контрольная сумма профиля не сошлась (строка повреждена при копировании?)");
    }
    let mut r = Rd { b: j, i: 0 };
    if r.u8()? != 2 {
        bail!("версия профиля не поддерживается");
    }
    let seed: [u8; 32] = r.take(32)?.try_into().unwrap();
    let ip = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
    let gl = r.u8()? as usize;
    let group = String::from_utf8(r.take(gl)?.to_vec()).context("имя группы")?;
    let n = r.u8()? as usize;
    let mut servers = Vec::new();
    for _ in 0..n {
        let nl = r.u8()? as usize;
        let name = String::from_utf8(r.take(nl)?.to_vec()).context("имя сервера")?;
        let d: [u8; 16] = r.take(16)?.try_into().unwrap();
        let k: [u8; 32] = r.take(32)?.try_into().unwrap();
        let m = r.u8()? as usize;
        let mut a = Vec::new();
        for _ in 0..m {
            match r.u8()? {
                4 => {
                    let ip = std::net::IpAddr::from(<[u8; 4]>::try_from(r.take(4)?).unwrap());
                    a.push(SocketAddr::new(ip, u16::from_be_bytes(r.take(2)?.try_into().unwrap())).to_string());
                }
                6 => {
                    let ip = std::net::IpAddr::from(<[u8; 16]>::try_from(r.take(16)?).unwrap());
                    a.push(SocketAddr::new(ip, u16::from_be_bytes(r.take(2)?.try_into().unwrap())).to_string());
                }
                3 => {
                    let l = r.u8()? as usize;
                    a.push(String::from_utf8(r.take(l)?.to_vec()).context("адрес-имя")?);
                }
                _ => bail!("тип адреса в профиле"),
            }
        }
        servers.push(ProfServer { n: name, d, k, a });
    }
    if r.i != j.len() {
        bail!("лишние данные в профиле");
    }
    Ok(Profile { group, seed, ip, s: servers })
}

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.i + n > self.b.len() {
            bail!("профиль обрезан");
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn platform_allowlist() {
        assert_eq!(parse_platform(b"android"), Some("android"));
        assert_eq!(parse_platform(b" server\n"), Some("server"));
        assert_eq!(parse_platform(b"ios"), Some("ios"));
        assert_eq!(parse_platform(b""), None);
        assert_eq!(parse_platform(b"app/android"), None);
        assert_eq!(parse_platform(b"<script>"), None);
        assert_eq!(parse_platform(&[0xff, 0xfe]), None);
        assert!(parse_platform(platform().as_bytes()).is_some());
    }

    #[test]
    fn client_info_roundtrip_and_garbage() {
        let id = leviculum_std::api::generate_identity();
        let (name, pl) = parse_client_info(&client_info_body(&id)).unwrap();
        assert!(name.starts_with("телефон-"));
        assert_eq!(pl, platform());
        assert_eq!(parse_client_info(b""), None);
        assert_eq!(parse_client_info(&[7, b'a', b'n', b'd']), None, "обрезано");
        assert_eq!(parse_client_info(&[3, b'i', b'o', b's', 1, b'x', b'y']), None, "лишний хвост");
        assert_eq!(parse_client_info(&[4, b'm', b'a', b'c', b'x', 0]), None, "тип вне списка");
        assert_eq!(parse_client_info(&[3, b'i', b'o', b's', 2, b'a', 0x07]), Some(("a".into(), "ios")), "управляющие символы вырезаны");
        let mut b = vec![3, b'i', b'o', b's'];
        let nm = "a\u{202E}b";
        b.push(nm.len() as u8);
        b.extend_from_slice(nm.as_bytes());
        assert_eq!(parse_client_info(&b), Some(("ab".into(), "ios")), "смена направления текста вырезана");
    }

    #[test]
    fn peer_name_normalized() {
        assert_eq!(norm_peer_name("knothop-FI-ubuntu24", "").as_deref(), Some("knothop-FI-ubuntu24"));
        assert_eq!(norm_peer_name("legacy-FI-ubuntu24", "").as_deref(), Some("legacy-FI-ubuntu24"));
        assert_eq!(norm_peer_name("Home", "fi").as_deref(), Some("knothop-FI-Home"));
        assert_eq!(norm_peer_name("Home", "").as_deref(), Some("Home"));
        assert_eq!(norm_peer_name("Home", "F1").as_deref(), Some("Home"));
        assert_eq!(norm_peer_name("  \n\t ", "FI"), None);
        assert_eq!(norm_peer_name(&"я".repeat(80), "").unwrap().chars().count(), 32);
    }

    use super::*;

    #[test]
    fn profile_roundtrip_and_size() {
        let mk = |n: &str, i: u8| ProfServer { n: n.into(), d: [i; 16], k: [i + 1; 32], a: vec!["203.0.113.7:47001".into(), "[2001:db8::1]:47001".into(), "ru1.example.org:47001".into()] };
        let p = Profile { group: "lab".into(), seed: [9; 32], ip: 0x0a8a0102, s: vec![mk("de", 1), mk("ru1", 2), mk("nl1", 3)] };
        let s = encode_profile(&p);
        assert_eq!(decode_profile(&s).unwrap(), p);
        assert!(s.len() < 600, "profile {} chars", s.len());
        // порча одного символа ловится контрольной суммой
        let mut bad = s.clone().into_bytes();
        let n = bad.len() - 5;
        bad[n] = if bad[n] == b'A' { b'B' } else { b'A' };
        assert!(decode_profile(std::str::from_utf8(&bad).unwrap()).is_err());
        assert!(decode_profile("rawg1-xxxx").is_err());
    }

    #[test]
    fn bench_req_token() {
        // req= необязателен; кривой токен отвергает весь запрос (ответ без совпадения id не должен выглядеть как чужой)
        assert_eq!(parse_bench_req("100MB req=ab-12_X"), Some((None, 100, Some("ab-12_X".to_string()))));
        assert_eq!(parse_bench_req("req=abc 5MB").map(|x| x.2), Some(Some("abc".to_string())));
        assert!(parse_bench_req("5MB req=").is_none());
        assert!(parse_bench_req("5MB req=a.b").is_none());
        assert!(parse_bench_req(&format!("5MB req={}", "x".repeat(33))).is_none());
        assert!(parse_bench_req(&format!("5MB req={}", "x".repeat(32))).is_some());
        assert!(!bench_req_ok(""));
    }

    #[test]
    fn global_ip_special_ranges() {
        let g = |s: &str| is_global_ip(&s.parse().unwrap());
        // публичные адреса проходят
        assert!(g("8.8.8.8"));
        assert!(g("1.1.1.1"));
        assert!(g("2606:4700::1111"));
        assert!(g("2a00:1450::1"));
        // IPv4 служебные и документационные (S7)
        for s in ["192.0.0.1", "192.0.2.1", "192.88.99.1", "198.51.100.1", "203.0.113.5", "240.1.1.1", "255.255.255.255", "10.0.0.1", "100.64.0.1", "127.0.0.1"] {
            assert!(!g(s), "{s} должен быть отвергнут");
        }
        // IPv6: документация, Teredo, 6to4, NAT64, discard-only (S7)
        for s in ["2001:db8::1", "2001:0:4136:e378::1", "2002:808:808::1", "64:ff9b::808:808", "100::1"] {
            assert!(!g(s), "{s} должен быть отвергнут");
        }
        // IPv4-mapped: решает встроенный IPv4
        assert!(g("::ffff:8.8.8.8"));
        assert!(!g("::ffff:10.0.0.1"));
        assert!(!g("::ffff:192.0.2.1"));
        assert!(!g("::ffff:127.0.0.1"));
        // loopback и link-local
        assert!(!g("::1"));
        assert!(!g("fe80::1"));
    }

    #[test]
    fn ctrl_bucket_rate_and_close() {
        let t0 = Instant::now();
        let mut b = CtrlBucket::new(t0);
        // запас CTRL_BURST проходит без задержки
        for _ in 0..(CTRL_BURST as usize) {
            assert_eq!(b.take(t0), CtrlVerdict::Pass);
        }
        // дальше одно отбрасывание, с пометкой начала серии
        assert_eq!(b.take(t0), CtrlVerdict::Drop { first: true });
        assert_eq!(b.take(t0), CtrlVerdict::Drop { first: false });
        // через секунду пополнилось CTRL_RATE токенов: снова пропускаем
        assert_eq!(b.take(t0 + Duration::from_secs(1)), CtrlVerdict::Pass);
        // непрерывная серия дольше 10 с (200 сообщений/с при лимите 50/с) - закрыть
        let mut t = t0 + Duration::from_secs(1);
        let mut closed = false;
        'run: for _ in 0..300 {
            t += Duration::from_millis(100);
            for _ in 0..20 {
                if b.take(t) == CtrlVerdict::Close {
                    closed = true;
                    break 'run;
                }
            }
        }
        assert!(closed);
    }

    #[test]
    fn ctrl_bucket_pause_resets_run() {
        let t0 = Instant::now();
        let mut b = CtrlBucket::new(t0);
        for _ in 0..(CTRL_BURST as usize) {
            b.take(t0);
        }
        assert_eq!(b.take(t0), CtrlVerdict::Drop { first: true });
        // через 20 с запас снова полный; после его исчерпания серия новая (first), без закрытия
        let t1 = t0 + Duration::from_secs(20);
        for _ in 0..(CTRL_BURST as usize) {
            assert_eq!(b.take(t1), CtrlVerdict::Pass);
        }
        assert_eq!(b.take(t1), CtrlVerdict::Drop { first: true });
    }

    #[test]
    fn enroll_try_limit_and_ttl() {
        let t0 = Instant::now();
        let mut t: HashMap<[u8; 16], Instant> = HashMap::new();
        // полная таблица свежих записей: новый ключ не вставляется, размер не растёт
        for i in 0..ENROLL_TRY_MAX as u8 {
            assert!(enroll_try_put(&mut t, [i; 16], t0));
        }
        assert!(!enroll_try_put(&mut t, [200; 16], t0));
        assert_eq!(t.len(), ENROLL_TRY_MAX);
        // известный ключ обновляется и на предел не влияет
        assert!(enroll_try_put(&mut t, [0; 16], t0 + Duration::from_secs(1)));
        assert_eq!(t.len(), ENROLL_TRY_MAX);
        // через TTL записи выкидываются, место освобождается
        assert!(enroll_try_put(&mut t, [200; 16], t0 + ENROLL_TRY_TTL + Duration::from_secs(1)));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn client_ctrl_bucket_per_link_and_link_cap() {
        let t0 = Instant::now();
        let mut m: HashMap<u8, CtrlBucket> = HashMap::new();
        // ведро на Link: запас CTRL_BURST, затем отбрасывание с отметкой начала серии
        for _ in 0..(CTRL_BURST as usize) {
            assert_eq!(client_ctrl_pass(&mut m, 1, t0), Some(CtrlVerdict::Pass));
        }
        assert_eq!(client_ctrl_pass(&mut m, 1, t0), Some(CtrlVerdict::Drop { first: true }));
        assert_eq!(client_ctrl_pass(&mut m, 1, t0), Some(CtrlVerdict::Drop { first: false }));
        // у другого Link свой запас
        assert_eq!(client_ctrl_pass(&mut m, 2, t0), Some(CtrlVerdict::Pass));
        // заполняем до CLIENT_CTRL_LINKS: новый Link без ведра (None), старые продолжают работать по своим ведрам
        for k in 3..=(CLIENT_CTRL_LINKS as u8) {
            assert!(client_ctrl_pass(&mut m, k, t0).is_some());
        }
        assert_eq!(m.len(), CLIENT_CTRL_LINKS);
        assert_eq!(client_ctrl_pass(&mut m, 200, t0), None);
        assert_eq!(m.len(), CLIENT_CTRL_LINKS);
        assert_eq!(client_ctrl_pass(&mut m, 1, t0 + Duration::from_secs(1)), Some(CtrlVerdict::Pass));
    }

    #[test]
    fn neighbor_room_protects_trusted() {
        let now = Instant::now();
        let d = |i: u8| [i; 16];
        // свободно, пока таблица не полна и незащищённых меньше лимита
        let few: Vec<_> = (0..10u8).map(|i| (d(i), false, now)).collect();
        assert_eq!(neighbor_room(&few, false), NeighborRoom::Free);
        // незащищённые на лимите: вытесняется самый давний незащищённый, защищённый при этом не трогаем
        let mut full: Vec<_> = (0..MAX_UNTRUSTED_NEIGHBORS as u8).map(|i| (d(i), false, now + Duration::from_secs(i as u64))).collect();
        assert_eq!(neighbor_room(&full, false), NeighborRoom::Evict(d(0)));
        // новый защищённый при полной таблице из незащищённых: вытесняем незащищённого (защищённых нет)
        for i in 0..(MAX_NEIGHBORS - MAX_UNTRUSTED_NEIGHBORS) as u8 {
            full.push((d(100 + i), true, now));
        }
        assert_eq!(full.len(), MAX_NEIGHBORS);
        assert_eq!(neighbor_room(&full, true), NeighborRoom::Evict(d(0)));
        // все записи защищены: новый анонс без права и с правом - места нет
        let all_prot: Vec<_> = (0..MAX_NEIGHBORS as u8).map(|i| (d(i), true, now)).collect();
        assert_eq!(neighbor_room(&all_prot, false), NeighborRoom::Full);
        assert_eq!(neighbor_room(&all_prot, true), NeighborRoom::Full);
        // таблица из 72 защищённых (больше MAX_NEIGHBORS): ни новый защищённый, ни незащищённый не вытесняет их
        let prot_only: Vec<_> = (0..MAX_UNTRUSTED_NEIGHBORS as u8 + 40).map(|i| (d(i), true, now)).collect();
        assert_eq!(neighbor_room(&prot_only, false), NeighborRoom::Full);
    }

    #[test]
    fn holder_prefix_is_strict() {
        let a: trust::Pk = [1; 64];
        let b: trust::Pk = [2; 64];
        let known = vec![("aaaaaaaa11".to_string(), a), ("aaaaaaaa22".to_string(), b), ("bbbbbbbb33".to_string(), b)];
        // короче 8 hex - отказ, даже если однозначно
        assert!(holder_by_prefix("bbbbbbb", &known).is_err());
        assert!(holder_by_prefix("", &known).is_err());
        assert!(holder_by_prefix("zzzzzzzz", &known).is_err());
        // общий префикс двух держателей - неоднозначно
        assert!(holder_by_prefix("aaaaaaaa", &known).is_err());
        // один держатель, даже с двумя записями (два издателя), однозначен
        assert_eq!(holder_by_prefix("aaaaaaaa1", &known).unwrap(), a);
        assert_eq!(holder_by_prefix("bbbbbbbb", &known).unwrap(), b);
        assert!(holder_by_prefix("cccccccc", &known).is_err());
    }

    #[test]
    fn early_buffer_has_per_link_quota() {
        let rec = trust::Record { rights: 0, seq: 0, root: [0; 16], holder: [0; 64], issuer: [0; 16], sig: [0; 64], hh: [0; 16] };
        let other = [1; 16];
        let (l1, l2) = (LinkId::new([1; 16]), LinkId::new([2; 16]));
        let mut buf = Vec::new();
        for _ in 0..EARLY_PER_LINK {
            assert!(early_push(&mut buf, l1, rec.clone(), &rec.root));
        }
        // мусор от одного Link упёрся в квоту, а чужой Link ещё может записать
        assert!(early_push(&mut buf, l1, rec.clone(), &rec.root));
        assert!(early_push(&mut buf, l2, rec.clone(), &rec.root));
        assert!(!early_push(&mut buf, l2, rec.clone(), &other));
        for i in 3..=(EARLY_MAX as u8) {
            let _ = early_push(&mut buf, LinkId::new([i; 16]), rec.clone(), &rec.root);
        }
        assert_eq!(buf.len(), EARLY_MAX);
        assert!(!early_push(&mut buf, LinkId::new([200; 16]), rec.clone(), &other));
        assert!(early_push(&mut buf, LinkId::new([200; 16]), rec, &[0; 16]));
    }

    #[test]
    fn relay_match_uses_invite_root_and_node_allowlist() {
        let root = leviculum_std::api::generate_identity();
        let inviter = leviculum_std::api::generate_identity();
        let relay = leviculum_std::api::generate_identity();
        let other = leviculum_std::api::generate_identity();
        let root_h = *root.hash();
        let inv = trust::Invite { admin: inviter.public_key_bytes(), root_pk: Some(root.public_key_bytes()), pin: [0; 16],
            rights: trust::USE, created: 1, addrs: vec![], nodes: vec![*relay.hash()] };
        let tag = trust::root_tag(&root_h);
        assert!(relay_match(&inv, &relay.public_key_bytes(), &[tag.clone()]));
        assert!(!relay_match(&inv, &inviter.public_key_bytes(), &[tag.clone()]));
        assert!(!relay_match(&inv, &other.public_key_bytes(), &[tag]));
        let mut direct = inv.clone();
        direct.addrs.push("203.0.113.2:47001".into());
        assert!(!relay_match(&direct, &relay.public_key_bytes(), &[trust::root_tag(&root_h)]));
    }

    #[test]
    fn pairq_v3_roundtrip_and_exact_length() {
        let root = [1; 16];
        let inviter = [2; 16];
        let holder = [3; 64];
        let mac = [4; 32];
        let body = pairq_body(root, inviter, &holder, &mac);
        assert_eq!(body.len(), 128);
        assert_eq!(parse_pairq(&body), Some((root, inviter, holder, mac)));
        assert!(parse_pairq(&body[..127]).is_none());
        let mut long = body.clone(); long.push(0);
        assert!(parse_pairq(&long).is_none());
    }

    #[test]
    fn pairq_client_rejects_foreign_inviter_and_root_substitution() {
        let me = [1; 16];
        let other = [2; 16];
        let root = [3; 16];
        let requested = [4; 16];
        assert!(pairq_client_matches(&me, &me, &root, &root));
        assert!(!pairq_client_matches(&other, &me, &root, &root));
        assert!(!pairq_client_matches(&me, &me, &requested, &root));
    }

    #[test]
    fn invite_rights_require_add_subset_anchor_and_depth() {
        let root_id = leviculum_std::api::generate_identity();
        let mut root = trust::Trust::new(root_id.clone(), None);
        let root_h = *root_id.hash();
        assert!(validate_invite_rights(&root, &root_h, trust::USE).is_ok());
        let no_add = leviculum_std::api::generate_identity();
        root.issue(root_h, no_add.public_key_bytes(), trust::USE).unwrap();
        let mut no_add_trust = trust::Trust::new(no_add.clone(), None);
        no_add_trust.add_anchor(&root_id.public_key_bytes()).unwrap();
        for r in root.export_all() { no_add_trust.offer(r); }
        assert!(validate_invite_rights(&no_add_trust, &root_h, trust::USE).is_err(), "нет ADD");
        let member = leviculum_std::api::generate_identity();
        root.issue(root_h, member.public_key_bytes(), trust::USE | trust::ADD).unwrap();
        let mut member_trust = trust::Trust::new(member.clone(), None);
        member_trust.add_anchor(&root_id.public_key_bytes()).unwrap();
        for r in root.export_all() { member_trust.offer(r); }
        assert!(validate_invite_rights(&member_trust, &root_h, trust::ALL).is_err(), "нельзя делегировать шире своих прав");
        assert!(validate_invite_rights(&member_trust, &[0x44; 16], trust::USE).is_err(), "неякорный корень");

        let ids: Vec<_> = (0..8).map(|_| leviculum_std::api::generate_identity()).collect();
        let mut net = trust::Trust::new(root_id.clone(), None);
        let mut previous = root_id.clone();
        for id in &ids {
            let mut issuer = trust::Trust::new(previous.clone(), None);
            if previous.hash() != root_id.hash() { issuer.add_anchor(&root_id.public_key_bytes()).unwrap(); }
            for r in net.export_all() { issuer.offer(r); }
            let rec = issuer.issue(root_h, id.public_key_bytes(), trust::ALL).unwrap();
            net.offer(rec);
            previous = id.clone();
        }
        let mut deepest = trust::Trust::new(previous.clone(), None);
        deepest.add_anchor(&root_id.public_key_bytes()).unwrap();
        for r in net.export_all() { deepest.offer(r); }
        assert_eq!(deepest.depth_in(&root_h, &deepest.me_hash), Some(8));
        assert!(validate_invite_rights(&deepest, &root_h, trust::USE).is_err(), "глубина 8 не может породить ещё одно звено");
    }

    #[test]
    fn delegated_invite_used_check_binds_root_inviter_holder_and_time() {
        let root = leviculum_std::api::generate_identity();
        let inviter = leviculum_std::api::generate_identity();
        let me = leviculum_std::api::generate_identity();
        let inv = trust::Invite { admin: inviter.public_key_bytes(), root_pk: Some(root.public_key_bytes()), pin: [0; 16],
            rights: trust::USE, created: 10, addrs: vec![], nodes: vec![] };
        let mut rec = trust::Record { rights: trust::USE, seq: 10_000, root: inv.root().unwrap(), holder: me.public_key_bytes(),
            issuer: inv.admin_hash().unwrap(), sig: [0; 64], hh: *me.hash() };
        assert!(invite_used(&inv, &me.public_key_bytes(), &[rec.clone()]));
        rec.root = *inviter.hash();
        assert!(!invite_used(&inv, &me.public_key_bytes(), &[rec.clone()]));
        rec.root = inv.root().unwrap(); rec.holder = inviter.public_key_bytes();
        assert!(!invite_used(&inv, &me.public_key_bytes(), &[rec.clone()]));
        rec.holder = me.public_key_bytes(); rec.seq -= 1;
        assert!(!invite_used(&inv, &me.public_key_bytes(), &[rec]));
    }

    #[test]
    fn delegated_repeat_returns_chain_until_revocation() {
        let (root_id, delegate, holder) = (leviculum_std::api::generate_identity(), leviculum_std::api::generate_identity(), leviculum_std::api::generate_identity());
        let root = *root_id.hash();
        let mut authority = trust::Trust::new(root_id.clone(), None);
        let rd = authority.issue(root, delegate.public_key_bytes(), trust::USE | trust::ADD).unwrap();
        let mut dt = trust::Trust::new(delegate.clone(), None);
        dt.add_anchor(&root_id.public_key_bytes()).unwrap();
        dt.offer(rd.clone());
        let dn = dt.issue(root, holder.public_key_bytes(), trust::USE).unwrap();
        authority.offer(dn);
        let mut receiver = trust::Trust::new(leviculum_std::api::generate_identity(), None);
        receiver.add_anchor(&root_id.public_key_bytes()).unwrap();
        for r in authority.export_all() { receiver.offer(r); }
        let chain = repeat_record(&receiver, &root, &holder.public_key_bytes(), delegate.hash()).unwrap();
        assert_eq!(chain.issuer, *delegate.hash());
        assert!(receiver.chain_for(&holder.public_key_bytes()).len() >= 2, "в ответе есть делегирующая цепочка до корня");
        authority.issue(root, delegate.public_key_bytes(), 0).unwrap();
        let mut revoked = trust::Trust::new(leviculum_std::api::generate_identity(), None);
        revoked.add_anchor(&root_id.public_key_bytes()).unwrap();
        for r in authority.export_all() { revoked.offer(r); }
        assert!(repeat_record(&revoked, &root, &holder.public_key_bytes(), delegate.hash()).is_none(), "отозванный участник не получает Repeat");
    }

    #[test]
    fn bench_acc_counts_loss_reorder_dup() {
        let mut a = BenchAcc::default();
        for s in [0u32, 1, 3, 2, 2, 5] {
            a.expected = 6;
            a.on_pkt(s, BENCH_HDR, BENCH_SZ_MIN);
        }
        assert_eq!((a.uniq, a.dup, a.reord), (5, 1, 1)); // 2 пришёл после 3 (перестановка), второй 2 - дубль
        assert_eq!(a.lost(7), 2); // из 0..7 не пришли 4 и 6
        assert!(!a.on_pkt(BENCH_MAX_PKTS, BENCH_HDR, BENCH_SZ_MIN));
        assert_eq!(a.bad, 1);
    }

    #[test]
    fn bench_req_and_match() {
        assert_eq!(parse_bench_req("100 MB"), Some((None, 100, None)));
        let d = "0123456789abcdef0123456789abcdef";
        let (dest, mb, _) = parse_bench_req(&format!("{d} 7MB")).unwrap();
        assert_eq!((dest.map(|x| hex(&x)), mb), (Some(d.to_string()), 7));
        assert!(parse_bench_req("hello").is_none());
        let b: [u8; 16] = unhex(d).try_into().unwrap();
        assert!(bench_match("knothop-ru-1", "knothop-ru-1", &b));
        assert!(bench_match("01234567", "x", &b));
        assert!(!bench_match("0123", "x", &b)); // короткий префикс не годится
        assert!(!bench_match("ffffffff", "x", &b));
        assert_eq!(bench_id(&serde_json::json!({"id": u32::MAX})), Some(u32::MAX));
        assert_eq!(bench_id(&serde_json::json!({"id": u64::from(u32::MAX) + 1})), None);
        assert_eq!(bench_id(&serde_json::json!({"id": -1})), None);
        assert_eq!(parse_bench_req("0MB"), None);
        assert_eq!(parse_bench_req("1000MB"), Some((None, 1000, None)));
        assert_eq!(parse_bench_req("1001MB"), None);
        assert!(bench_done_valid(1_000_000, 1400, 715, 1400, 1_000_000));
        assert!(!bench_done_valid(1_000_000, 1400, 715, 1401, 1_000_000));
        assert!(!bench_done_valid(1_000_000, 1400, 715, 1400, 2_000_000));
        let now = Instant::now();
        let mut done = None;
        bench_note_done(&mut done, 10, now);
        bench_note_done(&mut done, 10, now + Duration::from_secs(2));
        assert_eq!(done.unwrap().1, now);
        assert!(bench_timeout_reached(now, now + Duration::from_secs(11), Duration::from_secs(10)));
        let mut bounded = BenchAcc::default();
        bounded.expected = 2;
        assert!(!bounded.on_pkt(2, BENCH_HDR, BENCH_SZ_MIN));
        assert!(!bounded.on_pkt(1, BENCH_HDR - 1, BENCH_SZ_MIN));
        assert_eq!(bounded.seen.len(), 0);
        assert_eq!(bounded.bad, 2);
        let mut rate = HashMap::new();
        for i in 0..BENCH_RATE_MAX { rate.insert([i as u8; 16], now); }
        assert!(!bench_rate_admit(&mut rate, [255; 16], now));
        assert!(bench_rate_admit(&mut rate, [255; 16], now + BENCH_RATE));
    }

    #[test]
    fn dial_filter_rejects_internal_ranges() {
        for bad in ["127.0.0.1", "10.1.2.3", "172.17.0.1", "172.31.255.1", "192.168.0.1", "100.64.0.1", "169.254.1.1", "198.18.0.5", "198.19.255.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fd00::1", "::"] {
            assert!(!is_global_ip(&bad.parse().unwrap()), "{bad} должен быть отклонён");
        }
        for good in ["1.1.1.1", "1.1.1.1", "8.8.8.8", "2a0d:6c2:26:4f0::"] {
            assert!(is_global_ip(&good.parse().unwrap()), "{good} должен проходить");
        }
    }

    #[test]
    fn client_ip_stays_in_net() {
        let _ = CLIENT_NET.set(parse_net("198.18.0.0/15").unwrap());
        for b in 0..=255u8 {
            let ip = client_ip(&[b, b.wrapping_mul(7), 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(ip >> 17, 0xc612_0000u32 >> 17, "{}", ip_str(ip)); // 198.18.0.0/15
            assert!(ip & 0x1ffff != 0 && ip & 0x1ffff != 0x1ffff);
        }
        assert!(parse_net("10.130.0.0/4").is_err());
    }

    #[test]
    fn client_identity_is_deterministic_and_distinct() {
        let a = client_identity(&[1; 32]).unwrap();
        let b = client_identity(&[1; 32]).unwrap();
        let c = client_identity(&[2; 32]).unwrap();
        assert_eq!(a.hash(), b.hash());
        assert_ne!(a.hash(), c.hash());
    }

    #[test]
    fn link_acceptance_hint_only_controls_neighbor_planning() {
        // A client with inherited TRANSIT is still a leaf; a real NAT relay remains eligible.
        assert!(!plan_transit_neighbor(false, true));
        assert!(plan_transit_neighbor(true, true));
        assert!(!plan_transit_neighbor(false, false));
        // Older v1 announcements omitted the hint and retain the former behavior.
        let old: serde_json::Value = serde_json::json!({"v": 1});
        assert!(old["lc"].as_bool().unwrap_or(true));
    }

    #[test]
    fn server_promotion_guards_enrollment_and_link_opt_out() {
        // The guard is also applied by delayed promotion callbacks.
        assert!(!server_promotion_allowed(true, Some(true), true));
        assert!(!server_promotion_allowed(false, Some(false), true));
        assert!(!server_promotion_allowed(false, Some(false), false));
        // Relay and ordinary transit Links remain eligible only with actual TRANSIT rights.
        assert!(server_promotion_allowed(false, Some(true), true));
        assert!(server_promotion_allowed(false, None, true));
        assert!(!server_promotion_allowed(false, None, false));
    }

    #[test]
    fn iroh_key_equals_rns_signing_key() {
        let id = leviculum_std::api::generate_identity();
        let sk = iroh_key_from_identity(&id).unwrap();
        assert_eq!(sk.public().as_bytes(), &id.ed25519_verifying().to_bytes());
    }

    #[test]
    fn t13_dest_name_is_neutral_and_legacy_unchanged() {
        let id = leviculum_std::api::generate_identity();
        let pk = id.public_key_bytes();
        let t13 = dest_from_pub_tag(&pk, T13_TAG);
        let old_name = Destination::new(Some(Identity::from_public_key_bytes(&pk).unwrap()), Direction::Out, DestinationType::Single, "rawgvpn", &["node", T13_TAG]).unwrap();
        assert_ne!(t13, *old_name.hash().as_bytes(), "0013 больше не использует имя rawgvpn");
        let legacy = Destination::new(Some(Identity::from_public_key_bytes(&pk).unwrap()), Direction::Out, DestinationType::Single, "rawgvpn", &["node", "grp"]).unwrap();
        assert_eq!(dest_from_pub_tag(&pk, "grp"), *legacy.hash().as_bytes());
    }

    #[test]
    fn hints_migrate_from_old_dest_name() {
        let id = leviculum_std::api::generate_identity();
        let pk = id.public_key_bytes();
        let mut h: HashMap<String, Vec<String>> = HashMap::new();
        h.insert(hex(&old_dest13(&pk)), vec!["203.0.113.7:47001".into()]);
        migrate_hints(&mut h, std::iter::once(pk));
        assert_eq!(h.len(), 1);
        assert_eq!(h.get(&hex(&dest_from_pub_tag(&pk, T13_TAG))), Some(&vec!["203.0.113.7:47001".to_string()]));
    }

    #[test]
    fn dir_entry_with_old_dest_name_is_rejected() {
        let id = leviculum_std::api::generate_identity();
        let pk = id.public_key_bytes();
        let body = |d: [u8; 16]| serde_json::json!({"n": [{"d": hex(&d), "k": hex(&pk), "e": "", "a": ["203.0.113.7:47001"], "n": "x"}]}).to_string().into_bytes();
        assert!(parse_dir(&body(old_dest13(&pk)), T13_TAG).is_empty(), "каталог со старым именем не принимаем");
        assert_eq!(parse_dir(&body(dest_from_pub_tag(&pk, T13_TAG)), T13_TAG).len(), 1);
    }

    #[test]
    fn dest_from_pub_tag_matches_ancillary_dst() {
        let id = leviculum_std::api::generate_identity();
        let pk = id.public_key_bytes();
        let d1 = dest_from_pub_tag(&pk, "lab");
        let direct = new_dest(id, Direction::Out, "lab").unwrap();
        assert_eq!(d1, *direct.hash().as_bytes());
    }
}


// ------------------------------------------------------------------------------------------------ реестр клиентов

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ClientRec {
    /// хеш identity клиента (16 Б, hex) - ключ записи
    id: String,
    /// публичный ключ (64 Б, hex)
    pk: String,
    name: String,
    /// кто выдал (хеш назначения сервера)
    issuer: String,
    /// active | revoked (revoked необратим: иначе отставший сервер вернул бы запись)
    status: String,
    ts: u64,
}

#[derive(Default)]
struct Registry {
    recs: HashMap<String, ClientRec>,
}

impl Registry {
    fn load(path: &Path) -> Self {
        let mut r = Registry::default();
        if let Ok(b) = std::fs::read(path) {
            if let Ok(v) = serde_json::from_slice::<Vec<ClientRec>>(&b) {
                for x in v {
                    r.recs.insert(x.id.clone(), x);
                }
            }
        }
        r
    }

    fn save(&self, path: &Path) {
        let v: Vec<&ClientRec> = self.recs.values().collect();
        // реестр содержит имена клиентов: 0600, как и остальное состояние узла
        let tmp = path.with_extension("tmp");
        if secure_write(&tmp, &serde_json::to_vec(&v).unwrap()).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    /// Слияние как у 2P-set: новая запись добавляется, active -> revoked переходит, обратного пути нет. Возвращает, изменилось ли что-то.
    fn merge(&mut self, incoming: &[ClientRec]) -> bool {
        let mut changed = false;
        for r in incoming {
            if r.id.len() != 32 || r.pk.len() != 128 || r.name.len() > 64 {
                continue;
            }
            match self.recs.get_mut(&r.id) {
                None => {
                    if self.recs.len() >= MAX_REGISTRY {
                        continue;
                    }
                    self.recs.insert(r.id.clone(), r.clone());
                    changed = true;
                }
                Some(have) => {
                    if have.status == "active" && r.status == "revoked" {
                        have.status = "revoked".into();
                        changed = true;
                    }
                }
            }
        }
        changed
    }

    fn active(&self, id: &str) -> Option<&ClientRec> {
        self.recs.get(id).filter(|r| r.status == "active")
    }

    fn all(&self) -> Vec<ClientRec> {
        self.recs.values().cloned().collect()
    }
}

// ------------------------------------------------------------------------------------------------ общий запуск

struct Base {
    node: Arc<Node>,
    events: leviculum_std::driver::EventReceiver,
    ep: Endpoint,
    sh: Arc<Shared>,
    cli: Cli,
}

/// Узел RNS + конечная точка QUIC. Общие настройки носителя те же, что у стенда (датаграммы QUIC, GCM на Link).
async fn start_base(role: &str, state: &Path, transport: bool, port: Option<u16>, key: SecretKey, mbit: u64, extra: &[&str], tcp: Option<u16>) -> Result<Base> {
    std::fs::create_dir_all(state).context("create state dir")?;
    let mut args: Vec<String> = ["rawgd", "--role", role, "--ip", "0.0.0.0", "--relay", "none", "--mode", "tun", "--carrier", "datagram", "--dgram-mtu",
        "1400", "--cipher", "gcm", "--data-cap", "4096", "--chan-buf", "4096", "--quic-initial-mtu", "1452", "--quic-cc", "tunnel", "--quic-cc-mbit"]
        .iter().map(|s| s.to_string()).collect();
    args.push(mbit.to_string());
    // стенд: глубина очередей (по умолчанию 4096 пакетов; очередь интерфейса - на каждый Link-носитель) - для замеров W43
    for (env, flag) in [("RAWGD_CHAN_BUF", "--chan-buf"), ("RAWGD_DATA_CAP", "--data-cap")] {
        if let Some(v) = std::env::var(env).ok().filter(|v| v.parse::<usize>().map(|n| (16..=65536).contains(&n)).unwrap_or(false)) {
            if let Some(i) = args.iter().position(|x| x == flag) {
                args[i + 1] = v;
            }
        }
    }
    args.push("--state".into());
    args.push(state.display().to_string());
    args.extend(extra.iter().map(|s| s.to_string()));
    let cli = Cli::try_parse_from(&args).context("внутренние параметры")?;
    let _ = LOG_PATH.set(state.join("log.txt"));
    let _ = TUNING.set((cli.hw_mtu, cli.chan_buf, cli.read_buf));
    let _ = CARRIER.set((true, cli.dgram_mtu));
    let _ = QUIC_CC.set((cli.quic_cc.clone(), cli.quic_cc_mbit));
    let _ = QUIC_EXTRA.set((cli.quic_initial_mtu, cli.quic_stream_window, cli.quic_conn_window, cli.quic_dg_send_buf, cli.quic_dg_recv_buf));
    let sh = Arc::new(Shared::new());

    let store = state.join(format!("lev-{role}"));
    let _ = std::fs::remove_dir_all(&store);
    std::fs::create_dir_all(&store)?;
    let mut nb = NodeBuilder::new()
        .storage_path(store)
        .enable_transport(transport)
        .proof_binding(leviculum_std::api::ProofBinding::TokenTag)
        .data_channel_capacity(cli.data_cap)
        .link_cipher(leviculum_std::api::LinkCipher::Gcm)
        // ADR 0016: Link зачисления идёт через чужие транспорты RNS и может быть только стандартным CBC; такой Link допускается лишь на зачисление
        .accept_cbc_links(true);
    if let Some(tp) = tcp {
        nb = nb.add_tcp_server(SocketAddr::from(([0, 0, 0, 0], tp)));
    }
    let mut node = nb.build().context("build node")?;
    node.start().await.context("start node")?;
    let events = node.take_event_receiver().context("event receiver")?;
    let node = Arc::new(node);

    let mut eb = Endpoint::builder(presets::Minimal).secret_key(key).alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled);
    if let Some(p) = port {
        eb = eb.bind_addr(SocketAddr::from(([0, 0, 0, 0], p)))?;
    }
    if let Some(tc) = transport_cfg(&cli) {
        eb = eb.transport_config(tc);
    }
    let ep = eb.bind().await.context("bind iroh endpoint")?;
    // Сокет должен реально слушать порт: отсутствие слушателя - явная ошибка (systemd перезапустит), а не тихое состояние.
    if let Some(p) = port {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let socks = ep.bound_sockets();
            if socks.iter().any(|a| a.port() == p) {
                sh.note(format!("слушаю UDP: {socks:?}"));
                break;
            }
            if Instant::now() > until {
                bail!("UDP-сокет порта {p} не открыт (bound_sockets={socks:?})");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    Ok(Base { node, events, ep, sh, cli })
}

fn transport_cfg(cli: &Cli) -> Option<QuicTransportConfig> {
    transport(cli.path_idle_ms, cli.path_keepalive_ms, cli.conn_idle_ms)
}

fn parse_peer(s: &str) -> Option<(EndpointId, Vec<String>)> {
    let (id, addrs) = s.split_once('@')?;
    let id = id.parse::<EndpointId>().ok()?;
    let a: Vec<String> = addrs.split('|').filter(|x| !x.is_empty()).map(String::from).collect();
    Some((id, a))
}

/// Выбор носителя для одного пира. `prefer_tcp` выставляет монитор качества (потери пингов по QUIC), снимает сам дозвон после паузы.
pub struct CarrierCtl {
    pub prefer_tcp: AtomicBool,
    /// "quic" | "tcp": чем сейчас соединены
    pub mode: Mutex<&'static str>,
    pub switches: std::sync::atomic::AtomicU32,
    /// растёт при каждом подключении/отключении носителя: Link, созданный на прежнем носителе, больше не годится и закрывается сразу
    pub generation: std::sync::atomic::AtomicU32,
    /// подряд неудачных подключений к этому пиру (клиент): две подряд на QUIC - пробуем TCP
    pub fails: std::sync::atomic::AtomicU32,
    /// RTT от этого устройства до пира по текущему QUIC-пути, мкс (0 = неизвестно: нет QUIC или ещё не измерен)
    pub rtt_us: std::sync::atomic::AtomicU32,
    /// имя, под которым узел набран (оно входит в название интерфейса); имя в таблице может быть другим (в профиле старое), поэтому сверять нужно по нему
    pub label: Mutex<String>,
}

impl CarrierCtl {
    fn new() -> Arc<Self> {
        Arc::new(Self { prefer_tcp: AtomicBool::new(false), mode: Mutex::new("none"), switches: Default::default(), generation: Default::default(), fails: Default::default(), rtt_us: Default::default(), label: Mutex::new(String::new()) })
    }
    fn set_mode(&self, m: &'static str) {
        *self.mode.lock().unwrap() = m;
        self.generation.fetch_add(1, Relaxed);
    }
    fn is_quic(&self) -> bool {
        *self.mode.lock().unwrap() == "quic"
    }
}

/// Окно последних пингов: доля не вернувшихся среди «созревших» (старше `age`).
#[derive(Default)]
struct LossWin {
    v: std::collections::VecDeque<(u32, Instant, bool)>,
}

impl LossWin {
    fn sent(&mut self, seq: u32) {
        self.v.push_back((seq, Instant::now(), false));
        while self.v.len() > 16 {
            self.v.pop_front();
        }
    }
    fn ack(&mut self, seq: u32) {
        if let Some(e) = self.v.iter_mut().find(|e| e.0 == seq) {
            e.2 = true;
        }
    }
    fn clear(&mut self) {
        self.v.clear();
    }
    /// Доля потерь, если набралось не меньше `min_n` созревших пингов.
    fn loss(&self, age: Duration, min_n: usize) -> Option<f64> {
        let m: Vec<_> = self.v.iter().filter(|e| e.1.elapsed() >= age).collect();
        if m.len() < min_n {
            return None;
        }
        Some(m.iter().filter(|e| !e.2).count() as f64 / m.len() as f64)
    }
}

/// Адреса одного пира, общие для диалера и приёма анонсов: диалер берёт их на каждой попытке, анонс обновляет (0014 R4).
struct Addrs {
    v: Mutex<Vec<String>>,
    /// будит паузу диалера, если адреса сменились
    changed: tokio::sync::Notify,
}

impl Addrs {
    fn new(v: Vec<String>) -> Arc<Self> {
        Arc::new(Self { v: Mutex::new(v), changed: Default::default() })
    }
    fn get(&self) -> Vec<String> {
        self.v.lock().unwrap().clone()
    }
    fn is_empty(&self) -> bool {
        self.v.lock().unwrap().is_empty()
    }
    /// Заменить адреса; true - список изменился.
    fn set(&self, v: Vec<String>) -> bool {
        let mut cur = self.v.lock().unwrap();
        if *cur == v {
            return false;
        }
        *cur = v;
        self.changed.notify_one();
        true
    }
    /// Пауза диалера: до `d`, но не дольше, чем до смены адресов.
    async fn pause(&self, d: Duration) {
        let _ = tokio::time::timeout(d, self.changed.notified()).await;
    }
}

/// Разрешить адрес `host:порт` (IP или доменное имя) в список сокетов; IPv4 вперёд. Вызывается при каждой попытке, поэтому смена IP у домена подхватывается.
async fn resolve_addrs(addrs: &[String]) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in addrs {
        if let Ok(sa) = a.parse::<SocketAddr>() {
            out.push(sa);
            continue;
        }
        if let Ok(Ok(it)) = tokio::time::timeout(Duration::from_secs(4), tokio::net::lookup_host(a.as_str())).await {
            out.extend(it);
        }
    }
    // Адреса приходят из анонсов (набор по тегу группы доступен любому) и из таблиц: набирать loopback, частные и служебные сети нельзя -
    // иначе чужой анонс превращает узел в сканер внутренней сети хоста (SSRF). Лаборатория включает RAWGD_ALLOW_PRIVATE_DIAL=1.
    if std::env::var("RAWGD_ALLOW_PRIVATE_DIAL").is_err() {
        out.retain(|a| is_global_ip(&a.ip()));
    }
    out.sort_by_key(|a| a.is_ipv6());
    out.dedup();
    out
}

/// Держит исходящую связь с узлом и подключает её как интерфейс RNS; переподключается, пока `alive`. Адреса - IP или имена из общего хранилища `book`
/// (анонс его обновляет): разрешаются заново при каждой попытке, новые адреса подхватываются без перезапуска (0014 R4).
/// Носитель: QUIC (датаграммы), а если он не соединяется или монитор качества нашёл потери UDP - TCP. Из TCP возвращаемся на QUIC, когда прошла
/// пауза `back_off` (120 с, удваивается до 30 мин) от момента перехода на TCP, даже если TCP-сессии рвались. Если UDP всё ещё плох, монитор снова переключит за ~30 с.
async fn dial_direct(ep: Endpoint, node: Arc<Node>, sh: Arc<Shared>, label: String, id: EndpointId, book: Arc<Addrs>, alive: Arc<AtomicBool>, ctl: Arc<CarrierCtl>) {
    let mut n = 0u32;
    let mut quic_fail = 0u32;
    let mut tcp_fail = 0u32;
    // подряд TCP-сессий, закрытых за секунды после подключения
    let mut short_tcp = 0u32;
    // первая пауза до попытки вернуться на QUIC; растёт вдвое до 30 минут (RAWGD_TCP_BACKOFF_S - для стенда)
    let first_back: u64 = std::env::var("RAWGD_TCP_BACKOFF_S").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
    let mut back_off = first_back;
    // с какого момента носитель TCP: замечаем по флагу в цикле, в том числе когда флаг выставил монитор извне
    let mut tcp_since: Option<Instant> = None;
    // память о неработающих носителях к этому пиру (health.rs): ключ - EndpointId, не имя и не адрес
    let peer = id.to_string();
    // QUIC дважды не соединился: если TCP при этом работает (или тоже режется при живом хосте), QUIC запоминается как неработающий
    let mut quic_suspect = false;
    let mut announced_block = false;
    while alive.load(Relaxed) {
        let quic_bad = sh.health.is_bad(&peer, health::Kind::Quic);
        let tcp_bad = sh.health.is_bad(&peer, health::Kind::Tcp);
        if let Some(rem) = sh.health.blocked_for(&peer) {
            // оба носителя проверены и не работают: прямой интерфейс не поднимаем, путь к пиру найдёт RNS через другие узлы; позже проверим снова
            if !announced_block {
                announced_block = true;
                sh.note(format!("{label}: прямой путь заблокирован (QUIC и TCP не проходят), не подключаюсь, повторная проверка через {} мин", rem.as_secs() / 60 + 1));
            }
            book.pause(rem.min(Duration::from_secs(60))).await;
            continue;
        }
        announced_block = false;
        if tcp_bad {
            ctl.prefer_tcp.store(false, Relaxed);
        }
        if ctl.prefer_tcp.load(Relaxed) {
            let since = *tcp_since.get_or_insert_with(Instant::now);
            if !quic_bad && since.elapsed() >= Duration::from_secs(back_off) {
                // пауза вышла: пробуем QUIC снова; если UDP всё ещё плох, монитор переключит обратно, а пауза вырастет
                ctl.prefer_tcp.store(false, Relaxed);
                tcp_since = None;
                back_off = (back_off * 2).min(1800);
                sh.note(format!("{label}: пробую вернуться на QUIC"));
            }
        } else {
            tcp_since = None;
        }
        let cur = book.get();
        let resolved = resolve_addrs(&cur).await;
        if resolved.is_empty() {
            sh.note(format!("{label}: адрес {cur:?} не разрешился"));
            book.pause(Duration::from_secs(5)).await;
            continue;
        }
        if !(ctl.prefer_tcp.load(Relaxed) || quic_bad) {
            let mut addr = EndpointAddr::new(id);
            for a in &resolved {
                addr = addr.with_ip_addr(*a);
            }
            match tokio::time::timeout(Duration::from_secs(6), ep.connect(addr, ALPN)).await {
                Ok(Ok(conn)) => {
                    n += 1;
                    quic_fail = 0;
                    quic_suspect = false;
                    sh.health.ok(&peer, health::Kind::Quic);
                    ctl.set_mode("quic");
                    sh.note(format!("quic connected to {label}"));
                    let c2 = conn.clone();
                    let (ctl2, alive2) = (ctl.clone(), alive.clone());
                    let watch = tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            if let Some(p) = c2.paths().iter().find(|p| p.is_selected()) {
                                ctl2.rtt_us.store(p.rtt().as_micros().min(u32::MAX as u128) as u32, Relaxed);
                            }
                            if ctl2.prefer_tcp.load(Relaxed) || !alive2.load(Relaxed) {
                                c2.close(0u32.into(), b"switch carrier");
                                break;
                            }
                        }
                    });
                    attach_datagrams_until_closed(node.clone(), sh.clone(), format!("iroh-dg-out-{label}-{n}"), conn).await;
                    watch.abort();
                    ctl.set_mode("none");
                    ctl.rtt_us.store(0, Relaxed);
                    sh.note(format!("quic to {label} ended"));
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                _ => {
                    quic_fail += 1;
                    if quic_fail >= 2 {
                        quic_fail = 0;
                        if tcp_bad {
                            // TCP уже признан неработающим при живом хосте: если хост отвечает и сейчас, QUIC не проходит тоже
                            if tcpc::reachable(&resolved).await {
                                let d = sh.health.fail(&peer, health::Kind::Quic);
                                sh.note(format!("{label}: QUIC не соединяется при живом хосте, запоминаю на {} мин", d.as_secs() / 60));
                            }
                        } else {
                            sh.note(format!("{label}: QUIC не соединяется 2 раза подряд, переключаюсь на TCP"));
                            ctl.prefer_tcp.store(true, Relaxed);
                            ctl.switches.fetch_add(1, Relaxed);
                            quic_suspect = true;
                        }
                    }
                    book.pause(Duration::from_secs(2)).await;
                }
            }
        } else {
            match tcpc::connect(&resolved).await {
                tcpc::Dial::Up(stream) => {
                    n += 1;
                    tcp_fail = 0;
                    sh.health.ok(&peer, health::Kind::Tcp);
                    if std::mem::take(&mut quic_suspect) {
                        let d = sh.health.fail(&peer, health::Kind::Quic);
                        sh.note(format!("{label}: QUIC не проходит, а TCP работает: запоминаю QUIC как неработающий на {} мин", d.as_secs() / 60));
                    }
                    ctl.set_mode("tcp");
                    let deadline = tcp_since.unwrap_or_else(Instant::now) + Duration::from_secs(back_off);
                    sh.note(format!("tcp connected to {label} (носитель TCP, возврат на QUIC через {back_off} с от перехода)"));
                    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
                    let (alive2, st2) = (alive.clone(), stop_tx.clone());
                    let watch = tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            if !alive2.load(Relaxed) || Instant::now() >= deadline {
                                let _ = st2.send(true);
                                break;
                            }
                        }
                    });
                    let started = Instant::now();
                    tcpc::attach(node.clone(), sh.clone(), format!("tcp-out-{label}-{n}"), stream, true, stop_rx).await;
                    watch.abort();
                    ctl.set_mode("none");
                    // Сессия умерла сразу после рукопожатия (данные пира не доходят: чёрная дыра на пути): повтор каждые 0,5 с лишь рвёт Link,
                    // поднятый встречным соединением, при каждой смене носителя. Паузу растим 1,5 -> 3 -> ... -> 60 с, живая сессия её сбрасывает.
                    if started.elapsed() < Duration::from_secs(15) && alive.load(Relaxed) {
                        short_tcp = (short_tcp + 1).min(6);
                        let pause = Duration::from_millis((1500u64 << (short_tcp - 1)).min(60_000));
                        if short_tcp == 3 {
                            sh.note(format!("{label}: TCP-сессии рвутся сразу после подключения, пауза между попытками растёт до 60 с"));
                        }
                        book.pause(pause).await;
                    } else {
                        short_tcp = 0;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                tcpc::Dial::Blackhole => {
                    // хост отвечает, но данные не доходят: запоминаем; QUIC, не прошедший перед этим, запоминается вместе с ним (пара заблокирована)
                    let d = sh.health.fail(&peer, health::Kind::Tcp);
                    sh.note(format!("{label}: TCP соединяется, но данные не доходят (DPI или чёрная дыра), запоминаю на {} мин", d.as_secs() / 60));
                    if std::mem::take(&mut quic_suspect) {
                        sh.health.fail(&peer, health::Kind::Quic);
                    }
                    ctl.prefer_tcp.store(false, Relaxed);
                    tcp_since = None;
                }
                tcpc::Dial::Unreachable => {
                    // хост не отвечает: это не признак блокировки, ничего не запоминаем
                    quic_suspect = false;
                    tcp_fail += 1;
                    if tcp_fail >= 3 {
                        // TCP тоже не идёт: не застреваем, пробуем QUIC
                        ctl.prefer_tcp.store(false, Relaxed);
                        tcp_fail = 0;
                    }
                    book.pause(Duration::from_secs(2)).await;
                }
            }
        }
    }
}

/// Байты T_POL (тип + тело) с запуска: отправлено / принято. Для замера издержек синхронизации политик (0015), видны в status.json.
static POL_TX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static POL_RX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static POL_TX_N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static POL_RX_N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn pol_counters() -> serde_json::Value {
    serde_json::json!({"tx_b": POL_TX.load(Relaxed), "tx_n": POL_TX_N.load(Relaxed), "rx_b": POL_RX.load(Relaxed), "rx_n": POL_RX_N.load(Relaxed)})
}

async fn send_ctl(node: &Arc<Node>, link: LinkId, ty: u8, body: &[u8]) {
    if ty == T_POL {
        POL_TX.fetch_add(1 + body.len() as u64, Relaxed);
        POL_TX_N.fetch_add(1, Relaxed);
    }
    let mut m = Vec::with_capacity(1 + body.len());
    m.push(ty);
    m.extend_from_slice(body);
    let h = node.engine().link_handle(&link);
    let _ = h.send(&m).await;
}

/// Пинг/понг датаграммой Link (ненадёжно, без Channel): потеря пинга остаётся потерей и видна монитору качества носителя.
/// Формат 16 байт: `RGP` + 'P'|'R' + seq(u32 LE) + время отправителя (мкс, u64 LE).
fn dgram_ping(seq: u32, ts: u64, kind: u8) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[..3].copy_from_slice(b"RGP");
    b[3] = kind;
    b[4..8].copy_from_slice(&seq.to_le_bytes());
    b[8..16].copy_from_slice(&ts.to_le_bytes());
    b
}

fn is_rgp(d: &[u8]) -> bool {
    d.len() == 16 && &d[..3] == b"RGP" && (d[3] == b'P' || d[3] == b'R')
}

fn spawn_dgram(node: &Arc<Node>, link: LinkId, data: Vec<u8>) {
    let h = node.engine().link_handle(&link);
    tokio::spawn(async move {
        let _ = h.send_datagram(&data).await;
    });
}

fn spawn_ctl(node: &Arc<Node>, link: LinkId, ty: u8, body: Vec<u8>) {
    let node = node.clone();
    tokio::spawn(async move { send_ctl(&node, link, ty, &body).await });
}

// ------------------------------------------------------------------------------------------------ бенч (0014 R10)

/// Больше пакетов в одном бенче не бывает: 100 МБ при размере 32 Б.
const BENCH_MAX_PKTS: u32 = 40_000_000;

/// Учёт пакетов бенча по seq: уникальные, дубли, перестановки, потери. Без сети, для теста.
#[derive(Default)]
struct BenchAcc {
    /// битмап принятых seq
    seen: Vec<u64>,
    uniq: u64,
    dup: u64,
    /// пришёл раньше уже принятого большего seq
    reord: u64,
    /// seq вне диапазона - не учитываем
    bad: u64,
    max_seq: Option<u32>,
    expected: u32,
    sizes: Vec<u16>,
}

impl BenchAcc {
    /// Учесть пакет; true - пакет новый.
    fn on_pkt(&mut self, seq: u32, len: usize, max_len: usize) -> bool {
        if seq >= self.expected || seq >= BENCH_MAX_PKTS || len < BENCH_HDR || len > max_len {
            self.bad += 1;
            return false;
        }
        let (w, bit) = ((seq / 64) as usize, 1u64 << (seq % 64));
        if self.seen.len() <= w {
            self.seen.resize(w + 1, 0);
        }
        if self.seen[w] & bit != 0 {
            self.dup += 1;
            return false;
        }
        self.seen[w] |= bit;
        if self.sizes.len() <= seq as usize { self.sizes.resize(seq as usize + 1, 0); }
        self.sizes[seq as usize] = len.min(u16::MAX as usize) as u16;
        self.uniq += 1;
        if self.max_seq.map_or(true, |m| seq > m) {
            self.max_seq = Some(seq);
        } else {
            self.reord += 1;
        }
        true
    }

    /// Потери относительно числа отправленных (total из done).
    fn lost(&self, total: u64) -> u64 {
        total.saturating_sub(self.uniq)
    }
}

/// Сессия запроса бенча на стороне запрашивающего: нода (файл из CLI) или телефон (`bench-req`). Одна за раз.
struct BenchSess {
    id: u32,
    link: LinkId,
    dest: [u8; 16],
    /// имя (или dest8) для результата
    to: String,
    /// байт запрошено
    n: u64,
    /// размер датаграммы бенча
    sz: u64,
    timeout: Duration,
    started: Instant,
    first: Option<Instant>,
    last: Option<Instant>,
    /// байт уникальных пакетов
    bytes: u64,
    acc: BenchAcc,
    stalls: u64,
    stall_ms: u64,
    /// total из done и когда пришёл
    done: Option<(u64, Instant)>,
    drain_timed_out: bool,
    n_sent: Option<u64>,
    negotiated_sz: u64,
    requested_total: u32,
    /// busy | rate - отказ отвечающей стороны
    reply: Option<&'static str>,
    rtt_idle: Option<f64>,
    rtt_load: Vec<f64>,
    rtt_at: Instant,
    /// путь до узла (hops, vis) для результата
    path: serde_json::Value,
    /// `req=` из файла запроса, возвращается в результате как есть
    req: Option<String>,
}

fn r3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

impl BenchSess {
    /// `mb` - миллионы байт (10^6), `sz` - размер датаграммы (не больше MDU Link).
    fn new(id: u32, link: LinkId, dest: [u8; 16], to: String, mb: u64, sz: u64, timeout: Duration) -> Self {
        let now = Instant::now();
        let n = mb * 1_000_000;
        let total = n.div_ceil(sz.max(1));
        let mut acc = BenchAcc::default();
        acc.expected = n.div_ceil(BENCH_SZ_MIN as u64).min(BENCH_MAX_PKTS as u64) as u32;
        BenchSess { id, link, dest, to, n, sz, timeout, started: now, first: None, last: None, bytes: 0, acc,
            stalls: 0, stall_ms: 0, done: None, drain_timed_out: false, n_sent: None, negotiated_sz: sz,
            requested_total: total.min(BENCH_MAX_PKTS as u64) as u32, reply: None, rtt_idle: None, rtt_load: Vec::new(), rtt_at: now, path: serde_json::Value::Null, req: None }
    }

    fn on_pkt(&mut self, now: Instant, seq: u32, len: usize) {
        if seq >= self.acc.expected || len < BENCH_HDR || len > self.sz as usize { self.acc.bad += 1; return; }
        if let Some(l) = self.last {
            let gap = now.duration_since(l);
            if gap >= BENCH_STALL {
                self.stalls += 1;
                self.stall_ms += gap.as_millis() as u64;
            }
        }
        self.first.get_or_insert(now);
        self.last = Some(now);
        if self.acc.on_pkt(seq, len, self.sz as usize) {
            self.bytes += len as u64;
        }
    }

    /// Решение на тике: None - идём дальше; Some(вердикт) - сессия закончена.
    fn poll(&mut self, now: Instant, closed: bool, rtt: Option<f64>) -> Option<&'static str> {
        // RTT под нагрузкой: пинги идут по тому же Link, их ответы стоят в очереди за данными; берём раз в 2 с
        if now.duration_since(self.rtt_at) >= Duration::from_secs(2) {
            self.rtt_at = now;
            if let Some(r) = rtt {
                self.rtt_load.push(r);
            }
        }
        if let Some(r) = self.reply {
            return Some(r);
        }
        if bench_timeout_reached(self.started, now, self.timeout) {
            self.drain_timed_out = self.done.is_some() && self.acc.uniq < self.done.map(|d| d.0).unwrap_or(0);
            if let Some((total, _)) = self.done {
                return Some(if self.acc.uniq == total { "ok" } else { "timeout" });
            }
            return Some("timeout");
        }
        if let Some((total, at)) = self.done {
            if self.acc.uniq >= total || now.duration_since(at) >= BENCH_GRACE {
                self.drain_timed_out = self.acc.uniq < total;
                return Some(if self.acc.uniq == total && self.stalls == 0 { "ok" } else { "partial" });
            }
            return None;
        }
        if self.first.is_none() && now.duration_since(self.started) >= BENCH_BLOCK {
            return Some("blocked");
        }
        if closed {
            return Some(if self.first.is_none() { "no-link" } else { "stalled" });
        }
        None
    }

    /// Итог (0014 R10). Непришедшие пакеты считаются от done, а без него - от ожидаемого числа по n и sz.
    fn result(&self, now: Instant, verdict: &str) -> serde_json::Value {
        let secs = match (self.first, self.last) {
            (Some(a), Some(b)) => b.duration_since(a).as_secs_f64(),
            _ => 0.0,
        };
        let total = self.done.map(|d| d.0).unwrap_or(self.requested_total as u64);
        // тишина от последнего пакета до конца считается остановкой, если done не пришёл
        let (mut stalls, mut stall_ms) = (self.stalls, self.stall_ms);
        if self.done.is_none() {
            if let Some(l) = self.last {
                let gap = now.duration_since(l);
                if gap >= BENCH_STALL {
                    stalls += 1;
                    stall_ms += gap.as_millis() as u64;
                }
            }
        }
        let mut rl = self.rtt_load.clone();
        rl.sort_by(|a, b| a.total_cmp(b));
        let rtt_load = rl.get(rl.len() / 2).map(|x| r3(*x));
        let per_s = |x: f64| if secs > 0.0 { r3(x / secs) } else { 0.0 };
        serde_json::json!({
            "id": self.id, "req": self.req.clone(), "to": self.to.clone(), "verdict": verdict, "path": self.path.clone(),
            "n_req": self.n, "n_sent": self.n_sent, "bytes_payload": self.bytes.saturating_sub(self.acc.uniq * BENCH_HDR as u64), "sz": self.negotiated_sz, "done": self.done.is_some(),
            "bytes_rx": self.bytes, "pkts_rx": self.acc.uniq, "dup": self.acc.dup, "pkts_lost": self.done.map(|_| self.acc.lost(total)), "reordered": self.acc.reord,
            "complete": self.done.is_some() && self.acc.uniq == total, "drain_timeout": self.drain_timed_out,
            "partial": (self.first.is_some() || self.done.is_some()) && !(self.done.is_some() && self.acc.uniq == total), "rate_unreliable": secs < 1.0,
            "secs": r3(secs), "mbps": per_s(self.bytes as f64 / 1e6), "pps": per_s(self.acc.uniq as f64),
            "ttfb_ms": self.first.map(|f| f.duration_since(self.started).as_millis() as u64),
            "rtt_ms_idle": self.rtt_idle.map(r3), "rtt_ms_load": rtt_load,
            "stalls": stalls, "stall_s": r3(stall_ms as f64 / 1000.0),
        })
    }
}

/// Датаграмма бенча у запрашивающего: учитываем только пакеты его сессии (тот же Link и id).
fn bench_rx(slot: &Mutex<Option<BenchSess>>, link: LinkId, d: &[u8]) {
    if d.len() < BENCH_HDR {
        return;
    }
    let id = u32::from_le_bytes(d[1..5].try_into().unwrap());
    let seq = u32::from_le_bytes(d[5..9].try_into().unwrap());
    let mut g = slot.lock().unwrap();
    if let Some(s) = g.as_mut().filter(|s| s.link == link && s.id == id) {
        s.on_pkt(Instant::now(), seq, d.len());
    }
}

/// Ответ отвечающей стороны на наш запрос: busy, rate или done (число отправленных пакетов).
fn bench_msg(slot: &Mutex<Option<BenchSess>>, link: LinkId, v: &serde_json::Value) {
    let mut g = slot.lock().unwrap();
    let Some(s) = g.as_mut().filter(|s| s.link == link && Some(s.id as u64) == v["id"].as_u64()) else { return };
    if v["busy"].as_bool() == Some(true) {
        s.reply = Some("busy");
    } else if v["rate"].as_bool() == Some(true) {
        s.reply = Some("rate");
    } else if v["error"].is_string() {
        s.reply = Some("invalid-request");
    } else if let Some(d) = v["done"].as_u64() {
        if s.done.is_some() { return; }
        let sz = v["sz"].as_u64().unwrap_or(0);
        if !bench_done_valid(s.n, s.sz, d, sz, v["n_sent"].as_u64().unwrap_or(0)) { return; }
        let expected = s.n.div_ceil(sz);
        if d != expected { return; }
        let tail = s.n.saturating_sub(d.saturating_sub(1).saturating_mul(sz)).max(BENCH_HDR as u64);
        let n_sent = d.saturating_sub(1).saturating_mul(sz).saturating_add(tail);
        if v["n_sent"].as_u64() != Some(n_sent) { return; }
        let mut uniq = 0u64;
        let mut bytes = 0u64;
        for seq in 0..s.acc.sizes.len() {
            let w = seq / 64;
            let bit = 1u64 << (seq % 64);
            let received = s.acc.seen.get(w).is_some_and(|bits| bits & bit != 0);
            let expected_len = if seq + 1 == d as usize { tail as usize } else { sz as usize };
            if seq >= d as usize || (received && s.acc.sizes[seq] as usize != expected_len) {
                if received { s.acc.seen[w] &= !bit; }
                s.acc.sizes[seq] = 0;
            } else if s.acc.sizes[seq] != 0 {
                uniq += 1;
                bytes += s.acc.sizes[seq] as u64;
            }
        }
        s.acc.uniq = uniq;
        s.bytes = bytes;
        s.acc.expected = d as u32;
        s.negotiated_sz = sz;
        s.n_sent = Some(n_sent);
        bench_note_done(&mut s.done, d, Instant::now());
    }
}

/// Опрос сессии на тике: закончена - снимаем её и отдаём итог (записывает вызывающий).
fn bench_finish(slot: &Mutex<Option<BenchSess>>, sh: &Shared, rtt: Option<f64>) -> Option<serde_json::Value> {
    let mut g = slot.lock().unwrap();
    let s = g.as_mut()?;
    let closed = sh.closed.lock().unwrap().contains_key(&hex(s.link.as_bytes()));
    let now = Instant::now();
    let verdict = s.poll(now, closed, rtt)?;
    let j = s.result(now, verdict);
    sh.note(format!("бенч {}: {verdict}, {} МБ/с", s.to, j["mbps"]));
    *g = None;
    Some(j)
}

/// Имя, полный dest (32 hex) или префикс dest не короче 8 hex. `to` - в нижнем регистре.
fn bench_match(to: &str, name: &str, dest: &[u8; 16]) -> bool {
    name.eq_ignore_ascii_case(to) || (to.len() >= 8 && to.chars().all(|c| c.is_ascii_hexdigit()) && hex(dest).starts_with(to))
}

fn bench_fail(id: u32, to: &str, why: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "to": to, "verdict": "no-link", "why": why})
}

fn write_bench_res(dir: &Path, j: &serde_json::Value) {
    let _ = std::fs::create_dir_all(dir);
    write_atomic(&dir.join(format!("res-{}.json", j["id"])), j.to_string().as_bytes());
}

/// Файл запроса телефона: "<N MB>" или "<dest32> <N MB>", необязательно `req=<id>` (вернётся в результате, по нему сверяет запрашивающий).
fn parse_bench_req(t: &str) -> Option<(Option<[u8; 16]>, u64, Option<String>)> {
    let (mut dest, mut mb, mut req) = (None, None, None);
    for w in t.split_whitespace() {
        if let Some(r) = w.strip_prefix("req=") {
            if !bench_req_ok(r) {
                return None;
            }
            req = Some(r.to_string());
        } else if w.len() == 32 && w.chars().all(|c| c.is_ascii_hexdigit()) {
            dest = <[u8; 16]>::try_from(unhex(&w.to_lowercase()).as_slice()).ok();
        } else if let Ok(x) = w.trim_end_matches(|c: char| c.is_ascii_alphabetic()).parse::<u64>() {
            mb = Some(x);
        }
    }
    let mb = mb?;
    (1..=BENCH_MAX_MB).contains(&mb).then_some((dest, mb, req))
}

/// Токен запроса бенча: 1..32 символа [A-Za-z0-9_-].
fn bench_req_ok(r: &str) -> bool {
    (1..=32).contains(&r.len()) && r.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn bench_id(v: &serde_json::Value) -> Option<u32> {
    let n = v["id"].as_u64()?;
    u32::try_from(n).ok()
}

fn bench_done_valid(n: u64, requested_sz: u64, total: u64, sz: u64, n_sent: u64) -> bool {
    if sz < BENCH_SZ_MIN as u64 || sz > requested_sz || total > BENCH_MAX_PKTS as u64 || total != n.div_ceil(sz) { return false; }
    let tail = n.saturating_sub(total.saturating_sub(1).saturating_mul(sz)).max(BENCH_HDR as u64);
    n_sent == total.saturating_sub(1).saturating_mul(sz).saturating_add(tail)
}

fn bench_note_done(done: &mut Option<(u64, Instant)>, total: u64, now: Instant) {
    if done.is_none() { *done = Some((total, now)); }
}

fn bench_timeout_reached(started: Instant, now: Instant, timeout: Duration) -> bool {
    now.duration_since(started) >= timeout
}

fn bench_rate_admit(rate: &mut HashMap<[u8; 16], Instant>, peer: [u8; 16], now: Instant) -> bool {
    rate.retain(|_, at| now.duration_since(*at) < BENCH_RATE);
    if rate.contains_key(&peer) || rate.len() >= BENCH_RATE_MAX { return false; }
    rate.insert(peer, now);
    true
}

struct BenchServingGuard(Arc<NodeCtx>);
impl Drop for BenchServingGuard {
    fn drop(&mut self) { self.0.bench_serving.store(false, Relaxed); }
}

/// Запрос бенча (с полем "n") на Link с ролью Server или Client. Ответ - rate/busy или пакеты и done.
fn on_bench_req(ctx: &Arc<NodeCtx>, link: LinkId, v: &serde_json::Value) {
    let peer = match ctx.links.lock().unwrap().get(&link).map(|l| &l.role) {
        Some(Role::Server { dest }) => *dest,
        Some(Role::Client { id, .. }) => *id,
        _ => return, // неавторизованный Link бенч не обслуживает
    };
    let Some(id) = bench_id(v) else { return };
    let n = v["n"].as_u64();
    let Some(n) = n.filter(|n| (1..=BENCH_MAX_N).contains(n)) else {
        spawn_ctl(&ctx.node, link, T_BENCH, serde_json::json!({"id": id, "error": "invalid n"}).to_string().into_bytes());
        return;
    };
    let mdu = ctx.node.engine().link_mdu(&link).unwrap_or(0);
    if mdu < BENCH_SZ_MIN {
        spawn_ctl(&ctx.node, link, T_BENCH, serde_json::json!({"id": id, "error": "link MDU below minimum"}).to_string().into_bytes());
        return;
    }
    let requested_sz = v["sz"].as_u64().and_then(|x| usize::try_from(x).ok()).unwrap_or(mdu);
    if requested_sz < BENCH_SZ_MIN {
        spawn_ctl(&ctx.node, link, T_BENCH, serde_json::json!({"id": id, "error": "invalid sz"}).to_string().into_bytes());
        return;
    }
    let sz = requested_sz.min(mdu);
    if ctx.bench_serving.swap(true, Relaxed) {
        spawn_ctl(&ctx.node, link, T_BENCH, serde_json::json!({"id": id, "busy": true}).to_string().into_bytes());
        return;
    }
    if !bench_rate_admit(&mut ctx.bench_rate.lock().unwrap(), peer, Instant::now()) {
        ctx.bench_serving.store(false, Relaxed);
        spawn_ctl(&ctx.node, link, T_BENCH, serde_json::json!({"id": id, "rate": true}).to_string().into_bytes());
        return;
    }
    ctx.sh.note(format!("бенч: отдаю {n} Б пиру {} (датаграмма {sz} Б)", &hex(&peer)[..8]));
    let c = ctx.clone();
    let guard = BenchServingGuard(ctx.clone());
    tokio::spawn(async move { let _guard = guard; bench_send(c, link, id, n, sz).await });
}

/// Отправка пакетов бенча тем же путём, что IP-пакеты туннеля: `send_datagram` без окна и подтверждений, без своего пейсинга.
/// Backpressure даёт сам `send_datagram` (ждёт место в очереди отправки). При ошибке ждём, пока Link жив, не дольше BENCH_BLOCK.
async fn bench_send(ctx: Arc<NodeCtx>, link: LinkId, id: u32, n: u64, sz: usize) {
    let h = ctx.node.engine().link_handle(&link);
    let key = hex(link.as_bytes());
    let total = n.div_ceil(sz as u64);
    let (mut seq, mut ok_at, mut aborted) = (0u64, Instant::now(), false);
    let deadline = Instant::now() + Duration::from_secs(900);
    while seq < total {
        let now = Instant::now();
        if h.is_closed() || ctx.sh.closed.lock().unwrap().contains_key(&key) || ok_at.elapsed() >= BENCH_BLOCK || now >= deadline { aborted = true; break; }
        let remaining = n.saturating_sub(seq.saturating_mul(sz as u64));
        let packet_len = if seq + 1 == total { remaining.max(BENCH_HDR as u64) as usize } else { sz };
        let mut pkt = vec![0xa5u8; packet_len];
        pkt[0] = T_BENCH_DATA;
        pkt[1..5].copy_from_slice(&id.to_le_bytes());
        pkt[5..9].copy_from_slice(&(seq as u32).to_le_bytes());
        pkt[9..17].copy_from_slice(&(now_ms() as u64).to_le_bytes());
        match tokio::time::timeout(BENCH_BLOCK.min(deadline.saturating_duration_since(now)), h.send_datagram(&pkt)).await {
            Ok(Ok(())) => {
                seq += 1;
                ok_at = Instant::now();
                if seq % 64 == 0 {
                    tokio::task::yield_now().await;
                }
            }
            Ok(Err(_)) | Err(_) => {
                if h.is_closed() || ctx.sh.closed.lock().unwrap().contains_key(&key) || ok_at.elapsed() > BENCH_BLOCK {
                    aborted = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }
    if !aborted {
        let n_sent = seq.saturating_sub(1).saturating_mul(sz as u64).saturating_add(n.saturating_sub(seq.saturating_sub(1).saturating_mul(sz as u64)).max(BENCH_HDR as u64));
        send_ctl(&ctx.node, link, T_BENCH, &serde_json::json!({"id": id, "done": seq, "sz": sz, "n_sent": n_sent}).to_string().into_bytes()).await;
    }
    ctx.sh.note(format!("бенч: отправлено {seq} из {total} пакетов{}", if aborted { ", прервано" } else { "" }));
}

/// T_BENCH: с полем "n" - запрос на отдачу, иначе - ответ на наш запрос.
fn on_bench_ctl(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else { return };
    if v.get("n").is_some() {
        on_bench_req(ctx, link, &v);
    } else {
        bench_msg(&ctx.bench_sess, link, &v);
    }
}

/// RTT до соседа, с которым идёт бенч (из пингов).
fn node_bench_rtt(ctx: &NodeCtx) -> Option<f64> {
    let dest = ctx.bench_sess.lock().unwrap().as_ref()?.dest;
    let neigh = ctx.neigh.lock().unwrap();
    let n = neigh.get(&dest)?;
    n.last_heard.elapsed().lt(&Duration::from_secs(5)).then_some(n.rtt_ms).flatten()
}

/// Запрос от ноды (`bench/req-<id>.json`, кладёт `rawgd bench`): сосед с живым Link с ролью сервера, одна сессия за раз.
fn bench_node_start(ctx: &Arc<NodeCtx>, id: u32, to: &str, mb: u64, timeout: u64) -> std::result::Result<(), String> {
    if mb == 0 || mb > BENCH_MAX_MB {
        return Err(format!("объём: от 1 до {BENCH_MAX_MB} МБ"));
    }
    let found: Vec<([u8; 16], String, Option<f64>, LinkId)> = {
        let links = ctx.links.lock().unwrap();
        let neigh = ctx.neigh.lock().unwrap();
        neigh.values()
            .filter_map(|nb| nb.link.filter(|l| matches!(links.get(l).map(|x| &x.role), Some(Role::Server { .. }))).map(|l| (nb.dest, nb.name.clone(), nb.rtt_ms, l)))
            .filter(|(d, n, _, _)| bench_match(to, n, d))
            .collect()
    };
    let (dest, name, rtt, link) = match found.len() {
        0 => return Err("нет живого Link с этим соседом (бенч - по Link соседа с ролью сервера)".into()),
        1 => found[0].clone(),
        _ => return Err("неоднозначно: уточните dest".into()),
    };
    let mdu = ctx.node.engine().link_mdu(&link).unwrap_or(0);
    if mdu < BENCH_SZ_MIN { return Err("Link MDU меньше минимального размера бенча".into()); }
    let mut s = BenchSess::new(id, link, dest, name.clone(), mb, mdu as u64, Duration::from_secs(timeout));
    s.rtt_idle = rtt;
    s.path = serde_json::json!({"hops": ctx.node.hops_to(&DestinationHash::new(dest))});
    *ctx.bench_sess.lock().unwrap() = Some(s);
    spawn_ctl(&ctx.node, link, T_BENCH, serde_json::json!({"id": id, "n": mb * 1_000_000, "sz": mdu}).to_string().into_bytes());
    ctx.sh.note(format!("бенч к {name}: {mb} МБ, запрос отправлен"));
    Ok(())
}

/// Берём файлы запроса (по одному за тик), пока нет своей сессии; файл удаляем сразу, плохой запрос даёт результат с причиной.
fn take_bench_req(ctx: &Arc<NodeCtx>) {
    if ctx.bench_sess.lock().unwrap().is_some() {
        return;
    }
    let dir = ctx.state.join("bench");
    let Ok(rd) = std::fs::read_dir(&dir) else { return };
    let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("req-") && n.ends_with(".json")).unwrap_or(false))
        .collect();
    files.sort();
    let Some(p) = files.first().cloned() else { return };
    let txt = std::fs::read_to_string(&p);
    let _ = std::fs::remove_file(&p);
    let Ok(txt) = txt else { return };
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
    let Some(id) = bench_id(&v) else {
        write_bench_res(&dir, &bench_fail(0, "", "id must be u32"));
        return;
    };
    let to = v["to"].as_str().unwrap_or("").to_lowercase();
    let mb = v["mb"].as_u64().unwrap_or(0);
    let timeout = v["timeout"].as_u64().unwrap_or(120).clamp(10, 900);
    if let Err(why) = bench_node_start(ctx, id, &to, mb, timeout) {
        write_bench_res(&dir, &bench_fail(id, &to, &why));
    }
}

/// Телефон: запрос из `bench-req` (кладёт приложение или интент стенда). Мерим только текущий выход: Link к другим у телефона нет.
fn client_bench_start(ctx: &Arc<ClientCtx>, txt: &str) -> std::result::Result<(), String> {
    let (dest, mb, req) = parse_bench_req(txt).ok_or("bench-req: нужно «<N MB>» или «<dest32> <N MB>», req=<id> необязателен")?;
    if mb == 0 || mb > BENCH_MAX_MB {
        return Err(format!("объём: от 1 до {BENCH_MAX_MB} МБ"));
    }
    let cur = *ctx.cur.lock().unwrap();
    let Some((cd, link, _)) = cur else { return Err("выхода нет: бенч мерит только текущий выход".into()) };
    if dest.is_some_and(|d| d != cd) {
        return Err("выбранный узел не текущий выход: Link к нему нет".into());
    }
    let name = ctx.servers.lock().unwrap().iter().find(|s| s.dest == cd).map(|s| s.name.clone()).unwrap_or_else(|| hex(&cd)[..8].to_string());
    let mdu = ctx.node.engine().link_mdu(&link).unwrap_or(0);
    if mdu < BENCH_SZ_MIN { return Err("Link MDU меньше минимального размера бенча".into()); }
    let id = u32::from_le_bytes(rand16()[..4].try_into().unwrap());
    // таймаут растёт с объёмом (1000 МБ на медленном пути - минуты), но не больше срока отдачи на сервере (900 с)
    let mut s = BenchSess::new(id, link, cd, name.clone(), mb, mdu as u64, Duration::from_secs((mb * 2).clamp(120, 900)));
    s.req = req;
    s.rtt_idle = *ctx.rtt_ms.lock().unwrap();
    let vis = ctx.vis.lock().unwrap().get(&cd).map(|x| x.0);
    s.path = serde_json::json!({"hops": ctx.node.hops_to(&DestinationHash::new(cd)), "vis": vis});
    *ctx.bench_sess.lock().unwrap() = Some(s);
    spawn_ctl(&ctx.node, link, T_BENCH, serde_json::json!({"id": id, "n": mb * 1_000_000, "sz": mdu}).to_string().into_bytes());
    ctx.sh.note(format!("бенч к {name}: {mb} МБ"));
    Ok(())
}

fn client_bench_save(ctx: &ClientCtx, j: serde_json::Value) {
    write_atomic(&ctx.state.join("bench-res.json"), j.to_string().as_bytes());
    *ctx.bench_last.lock().unwrap() = Some(j);
}

/// Телефон (0014 R10): запрос из файла `bench-req` (только по нему, сам бенч не запускается); итог - bench-res.json и поле `bench` в status.json.
async fn client_bench(ctx: Arc<ClientCtx>) {
    let (req, fin) = (ctx.state.join("bench-req"), ctx.state.join("fin"));
    while !fin.exists() {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let fresh = now_ms().saturating_sub(ctx.rtt_pong.load(Relaxed) as u128) < 5_000;
        let rtt = if fresh { *ctx.rtt_ms.lock().unwrap() } else { None };
        if let Some(j) = bench_finish(&ctx.bench_sess, &ctx.sh, rtt) {
            client_bench_save(&ctx, j);
            continue;
        }
        if ctx.bench_sess.lock().unwrap().is_some() {
            continue;
        }
        let Ok(txt) = std::fs::read_to_string(&req) else { continue };
        let _ = std::fs::remove_file(&req);
        if let Err(why) = client_bench_start(&ctx, &txt) {
            let mut j = bench_fail(0, "", &why);
            if let Some(r) = txt.split_whitespace().find_map(|w| w.strip_prefix("req=")).filter(|r| bench_req_ok(r)) {
                j["req"] = r.into();
            }
            client_bench_save(&ctx, j);
        }
    }
}

// ------------------------------------------------------------------------------------------------ сервер

enum Role {
    /// только что пришёл, ещё не доказал себя
    Unknown,
    /// мы инициатор серверного рукопожатия
    SrvInit { dest: [u8; 16], nonce_i: [u8; 16], pub_i: [u8; 64], mac_sent: bool },
    /// мы отвечаем в серверном рукопожатии
    SrvResp { nonce_i: [u8; 16], nonce_r: [u8; 16], pub_i: [u8; 64] },
    /// взаимно проверенный сервер
    Server { dest: [u8; 16] },
    /// клиент из реестра
    Client { id: [u8; 16], ip: u32 },
}

struct LinkInfo {
    role: Role,
    since: Instant,
    last_heard: Instant,
    /// публичный ключ пира (0013): у инициатора - закреплённый анонсом (RNS identity ответчика не хранит), у ответчика - доказанный identify
    peer_pk: Option<[u8; 64]>,
    /// пир прислал T_USE: он пришёл за выходом, а не как сосед
    want_use: bool,
    /// Этот Link открыт только для прямого зачисления к администратору приглашения.
    /// Не повышать его до Server после погашения приглашения.
    enroll_only: bool,
    /// H10: интерфейс носителя, через который пришёл Link (лимит неаутентифицированных на интерфейс)
    iface: Option<usize>,
    /// H10: частота управляющих сообщений
    ctrl: CtrlBucket,
    observation: crate::observations::Subscription,
}

struct Neighbor {
    dest: [u8; 16],
    key: [u8; 32],
    pk: [u8; 64],
    name: String,
    ep: String,
    /// адреса для диалера: общие с ним, анонс обновляет (0014 R4)
    addrs: Arc<Addrs>,
    /// теги корней из анонса (0013): чьи сети соседа
    tags: Vec<String>,
    /// Announce scheduling hint only: whether this peer accepts incoming RNS Links. Missing on older v1 announces means true.
    accepts_links: bool,
    last_announce: Instant,
    link: Option<LinkId>,
    last_heard: Instant,
    rtt_ms: Option<f64>,
    connecting: bool,
    dialer: Option<Arc<AtomicBool>>,
    first_seen: Instant,
    last_try: Instant,
    ctl: Arc<CarrierCtl>,
    loss: LossWin,
    ping_seq: u32,
    /// когда текущий Link допущен: потери считаются только по пингам этого Link (старый Link на отключённом интерфейсе даёт ложные потери)
    admitted_at: Instant,
    seen_gen: u32,
}

struct NodeCtx {
    node: Arc<Node>,
    sh: Arc<Shared>,
    ep: Endpoint,
    state: PathBuf,
    name: String,
    group: String,
    tag: String,
    akey: [u8; 32],
    /// полная RNS identity узла (для identify_link в модели 0012)
    identity: Identity,
    my_pk: [u8; 64],
    my_id: [u8; 16],
    my_dest: [u8; 16],
    my_key: [u8; 32],
    ep_id: String,
    /// объявляемые адреса (без явного advertise меняются вслед за интерфейсами: см. adv_auto)
    advertise: Mutex<Vec<String>>,
    /// адреса взяты с интерфейсов (нет явного advertise): (частные разрешены, свой туннель) для перепроверки раз в 60 с; None - адрес задан явно
    adv_auto: Option<(bool, String)>,
    announce_s: u64,
    dead: Duration,
    path_gate: path::PathGate,
    /// имя и тип клиента из T_USE (Link -> (имя, «android»/«ios»/«server»)); раздаются дальше в T_NBRS; не больше 256 записей
    client_info: Mutex<HashMap<LinkId, (String, &'static str)>>,
    /// клиенты-узлы соседей по T_CINFO: dest -> (имя, тип, когда); не больше CINFO_MAX, живут CINFO_TTL
    peer_clients: Mutex<HashMap<[u8; 16], (String, &'static str, Instant)>>,
    links: Mutex<HashMap<LinkId, LinkInfo>>,
    pending_nr: Mutex<HashMap<LinkId, [u8; 16]>>,
    neigh: Mutex<HashMap<[u8; 16], Neighbor>>,
    reg: Mutex<Registry>,
    tun: Option<Arc<TunState>>,
    started: Instant,
    /// когда (мс unix) выдать внеочередной анонс; 0 - не нужно. Внеочередной анонс не чаще раза в минуту.
    announce_at: std::sync::atomic::AtomicU64,
    last_trigger: Mutex<Instant>,
    ours_online: std::sync::atomic::AtomicUsize,
    listen_port: u16,
    /// идентификаторы интерфейсов публичной сети RNS (их выдаёт spawn_interface; по имени узнавать нельзя: интерфейс называется `tcp_client_N`)
    public_ids: Mutex<HashSet<usize>>,
    /// модель 0013 (права и якоря доверия); None - legacy общий секрет
    t13: Option<T13>,
    /// R10: бенч, который запросила эта нода (одна сессия за раз)
    bench_sess: Mutex<Option<BenchSess>>,
    /// R10: этот узел сейчас отдаёт бенч (один на ноду)
    bench_serving: AtomicBool,
    /// R10: когда последний раз отдали бенч пиру (ключ - dest сервера или id клиента), не чаще раза в минуту
    bench_rate: Mutex<HashMap<[u8; 16], Instant>>,
}

/// Состояние модели 0013 на узле.
struct T13 {
    /// записи о правах и якоря; порядок блокировок: invite, затем trust
    trust: Mutex<trust::Trust>,
    /// приглашение, по которому нода ещё не зачислена; после зачисления None
    invite: Mutex<Option<trust::Invite>>,
    /// Link, по которым T_PAIR1 уже отправлен (по одному разу на Link)
    pair_sent: Mutex<HashSet<LinkId>>,
    /// пересланные T_PAIRQ (mac -> когда и с какого Link): повтор раньше 8 с не рассылается, петли в mesh гаснут
    pairq_seen: Mutex<HashMap<[u8; 32], (Instant, LinkId)>>,
    /// записи, пришедшие раньше якоря админа (посредник шлёт выгрузку до записи о нас): применяются после зачисления
    early: Mutex<Vec<(LinkId, trust::Record)>>,
    /// H1: записи от пиров есть в памяти, но не на диске; пишет `flush_trust` не чаще раза в 2 с
    trust_dirty: AtomicBool,
    /// когда в последний раз виден анонс админа приглашения (0014 R6а): по нему решаем, просимся ли через посредника
    admin_seen: Mutex<Option<Instant>>,
    /// попытки зачисления через посредника (dest посредника -> когда): каждому не чаще раза в 60 с
    relay_try: Mutex<HashMap<[u8; 16], Instant>>,
    /// T_DIR: когда последний раз слали каталог на Link (не чаще раза в 60 с)
    dir_sent: Mutex<HashMap<LinkId, Instant>>,
}

impl NodeCtx {
    /// Индексы интерфейсов, не относящихся к публичной сети RNS (QUIC-связи с нашими узлами и клиентами).
    fn our_ifaces(&self) -> Vec<usize> {
        let p = self.public_ids.lock().unwrap();
        self.node.engine().interface_stats().iter().filter(|i| i.online && !p.contains(&i.interface_id.0)).map(|i| i.interface_id.0).collect()
    }

    fn iface_is_public(&self, idx: usize) -> bool {
        self.public_ids.lock().unwrap().contains(&idx)
    }

    /// Link пришёл (или ушёл) через публичную сеть RNS? Наши узлы и клиенты общаются только по нашим интерфейсам.
    /// S12: носитель неизвестен (Link не найден или не привязан) - считаем публичным, fail-closed.
    fn link_is_public(&self, link: &LinkId) -> bool {
        self.node.engine().link_stats(link).and_then(|s| s.attached_interface()).map(|i| self.iface_is_public(i)).unwrap_or(true)
    }

    /// Link установлен стандартным CBC (не нашим GCM)? Шифр неизвестен - да (fail-closed).
    fn link_is_cbc(&self, link: &LinkId) -> bool {
        self.node.engine().link_stats(link).map(|s| s.cipher() != leviculum_std::api::LinkCipher::Gcm).unwrap_or(true)
    }

    /// H10: управляющее сообщение на Link в пределах частоты? `false` - отбросить; затяжное нарушение - Link закрывается.
    fn ctrl_pass(self: &Arc<Self>, link: LinkId) -> bool {
        let verdict = {
            let mut l = self.links.lock().unwrap();
            match l.get_mut(&link) {
                Some(info) => info.ctrl.take(Instant::now()),
                None => return true,
            }
        };
        match verdict {
            CtrlVerdict::Pass => true,
            CtrlVerdict::Drop { first } => {
                if first {
                    self.sh.note(format!("link {}: управляющие сообщения сверх частоты, отбрасываю", &hex(link.as_bytes())[..8]));
                }
                false
            }
            CtrlVerdict::Close => {
                self.close_link(link, "управляющие сообщения сверх частоты 10 с");
                false
            }
        }
    }

    /// S2/S3: защищена ли запись соседа: TRANSIT по записям (общий корень) или живой Link. Без записей (легаси) - защищены все, как раньше.
    /// Блокировка trust берётся отдельно: таблицу соседей при этом удерживать нельзя.
    fn neighbor_protected(&self, pk: &[u8; 64], link: bool) -> bool {
        let Some(t) = &self.t13 else { return true };
        link || t.trust.lock().unwrap().common_with(pk, trust::TRANSIT, trust::TRANSIT, true, true, now_ms() as u64)
    }

    /// S2/S3: место для новой записи соседа с ключом `pk`. Вызывать без удержания `neigh`.
    fn neighbor_room_for(&self, pk: &[u8; 64]) -> NeighborRoom {
        let snap: Vec<([u8; 16], [u8; 64], bool, Instant)> = self.neigh.lock().unwrap().values()
            .map(|e| (e.dest, e.pk, e.link.is_some(), e.last_announce)).collect();
        let entries: Vec<([u8; 16], bool, Instant)> = snap.into_iter()
            .map(|(d, p, link, t)| (d, self.neighbor_protected(&p, link), t)).collect();
        neighbor_room(&entries, self.neighbor_protected(pk, false))
    }

    /// S2/S3: вытеснить незащищённую запись соседа и остановить её дозвон.
    fn evict_neighbor(&self, dest: &[u8; 16]) {
        if let Some(nb) = self.neigh.lock().unwrap().remove(dest) {
            if let Some(a) = nb.dialer {
                a.store(false, Relaxed);
            }
        }
    }

    /// Внеочередной анонс (новый участник группы, новая QUIC-связь): через 1-6 с, не чаще раза в минуту.
    fn trigger_announce(&self) {
        let mut l = self.last_trigger.lock().unwrap();
        if l.elapsed() < Duration::from_secs(60) {
            return;
        }
        *l = Instant::now();
        let jitter = u64::from(rand16()[0]) * 5000 / 255;
        self.announce_at.store(now_ms() as u64 + 1000 + jitter, Relaxed);
    }

    /// Теги корней, в чьих сетях мы состоим, плюс сеть админа из ожидающего приглашения (чтобы админ нас нашёл).
    fn t13_tags(&self) -> Vec<String> {
        let Some(t) = &self.t13 else { return vec![] };
        let mut v = t.trust.lock().unwrap().tags();
        if let Some(inv) = t.invite.lock().unwrap().as_ref() {
            let Ok(inv_root) = inv.root() else { return v };
            let tg = trust::root_tag(&inv_root);
            if !v.contains(&tg) {
                v.push(tg);
            }
        }
        v
    }

    /// Текущие объявляемые адреса (копия).
    fn adv(&self) -> Vec<String> {
        self.advertise.lock().unwrap().clone()
    }

    fn announce_data(&self) -> Vec<u8> {
        if self.t13.is_some() {
            // ADR 0016: как у обычного узла RNS - только теги корней ("r": по пересечению с моими якорями сосед узнаёт знакомую сеть).
            // Адресов, имени и endpoint id нет: они приходят по допущенному Link (T_DIR) и из приглашения.
            serde_json::to_vec(&serde_json::json!({"r": self.t13_tags()})).unwrap()
        } else {
            serde_json::to_vec(&serde_json::json!({"v": 1, "t": self.tag, "n": self.name, "e": self.ep_id, "a": self.adv()})).unwrap()
        }
    }

    fn self_json(&self) -> serde_json::Value {
        serde_json::json!({"n": self.name, "d": hex(&self.my_dest), "k": hex(&self.my_key), "e": self.ep_id, "a": self.adv(), "g": self.group, "t": self.tag, "cn": net_str()})
    }

    /// Таблица для клиента и для файла neighbors.json: только живые серверы + мы сами.
    fn table(&self, for_client: bool) -> serde_json::Value {
        let now = Instant::now();
        let mut ex = vec![serde_json::json!({"n": self.name, "d": hex(&self.my_dest), "k": hex(&self.my_key), "e": self.ep_id, "a": self.adv(),
            "h": 0, "r": 0.0, "s": "up", "self": true})];
        let n = self.neigh.lock().unwrap();
        for nb in n.values() {
            let up = nb.link.is_some() && now.duration_since(nb.last_heard) < self.dead;
            if for_client && !up {
                continue;
            }
            let hops = self.node.hops_to(&DestinationHash::new(nb.dest));
            if for_client {
                ex.push(serde_json::json!({"n": nb.name, "d": hex(&nb.dest), "k": hex(&nb.key), "e": nb.ep, "a": nb.addrs.get(), "h": hops, "r": nb.rtt_ms, "c": *nb.ctl.mode.lock().unwrap(), "s": "up"}));
            } else {
                ex.push(serde_json::json!({"n": nb.name, "d": hex(&nb.dest), "k": hex(&nb.key), "e": nb.ep, "a": nb.addrs.get(), "h": hops, "r": nb.rtt_ms,
                    "c": *nb.ctl.mode.lock().unwrap(), "sw": nb.ctl.switches.load(Relaxed), "s": if up { "up" } else { "seen" }, "age_s": now.duration_since(nb.last_announce).as_secs(), "heard_s": now.duration_since(nb.last_heard).as_secs()}));
            }
        }
        serde_json::json!({"exits": ex, "ts": now_ms() as u64})
    }

    /// Таблица для клиента кусками (одна запись на ~330 Б; вся таблица на 6 узлов ~2 КБ и не помещается в одно сообщение Link, W30).
    /// Каждый кусок: {"exits":[...], "i":номер, "n":всего}. Клиент применяет «забыть отсутствующих» только после последнего куска.
    fn table_chunks(&self) -> Vec<Vec<u8>> {
        let t = self.table(true);
        let ex = t["exits"].as_array().cloned().unwrap_or_default();
        let mut groups: Vec<Vec<serde_json::Value>> = Vec::new();
        let mut cur: Vec<serde_json::Value> = Vec::new();
        for e in ex {
            cur.push(e);
            if cur.len() > 1 && serde_json::to_vec(&serde_json::json!({"exits": cur, "i": 99, "n": 99})).map(|v| v.len()).unwrap_or(0) > 700 {
                let last = cur.pop().unwrap();
                groups.push(std::mem::take(&mut cur));
                cur.push(last);
            }
        }
        if !cur.is_empty() {
            groups.push(cur);
        }
        let n = groups.len();
        groups.into_iter().enumerate().map(|(i, g)| serde_json::to_vec(&serde_json::json!({"exits": g, "i": i, "n": n})).unwrap()).collect()
    }

    fn send_table(self: &Arc<Self>, link: LinkId) {
        let chunks = self.table_chunks();
        let node = self.node.clone();
        tokio::spawn(async move {
            for c in chunks {
                send_ctl(&node, link, T_TABLE, &c).await;
            }
        });
    }

    /// Соседи с живым Link (роль Server) для клиента, 0013 (0014 R3): {"n":[{"d","r"}]}, по порядку dest, не более `NBRS_MAX` записей.
    fn nbr_entries(&self) -> Vec<serde_json::Value> {
        let server_links: HashSet<LinkId> = self.links.lock().unwrap().iter().filter(|(_, l)| matches!(l.role, Role::Server { .. })).map(|(k, _)| *k).collect();
        let mut v: Vec<([u8; 16], Option<f64>, String)> = self.neigh.lock().unwrap().values()
            .filter(|nb| nb.link.map(|l| server_links.contains(&l)).unwrap_or(false))
            .map(|nb| (nb.dest, nb.rtt_ms, nb.name.clone()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        // имя соседа - подсказка для отображения: клиент без Link к соседу узнаёт, какой он страны; идёт только допущенному клиенту
        // соседи-транзиты - серверы (телефон транзитом пока не бывает)
        let mut out: Vec<serde_json::Value> = v.iter().take(NBRS_MAX)
            .map(|(d, r, nm)| serde_json::json!({"d": hex(d), "r": r.map(|x| x.round() as i64), "n": nm.chars().take(32).collect::<String>(), "pl": "server"})).collect();
        // Клиенты с правами узла сети (якорь, TRANSIT или EXIT), например телефон-админ - свои и сообщённые соседями (T_CINFO):
        // только имя и тип ("c":1), ребром соседа они не становятся. Рядовых пользователей (только USE) другим клиентам не раскрываем.
        let mut cl: Vec<([u8; 16], String, &'static str)> = self.node_clients().into_iter().map(|(pk, n, pl)| (dest_from_pub_tag(&pk, T13_TAG), n, pl)).collect();
        {
            let mut pc = self.peer_clients.lock().unwrap();
            pc.retain(|_, v| v.2.elapsed() < CINFO_TTL);
            for (d, (n, pl, _)) in pc.iter() {
                if !cl.iter().any(|c| c.0 == *d) {
                    cl.push((*d, n.clone(), *pl));
                }
            }
        }
        cl.sort_by(|a, b| a.0.cmp(&b.0));
        out.extend(cl.into_iter().take(NBRS_MAX.saturating_sub(out.len())).map(|(d, n, pl)| serde_json::json!({"d": hex(&d), "c": 1, "n": n, "pl": pl})));
        out
    }

    /// Допущенные напрямую клиенты с правами узла сети (якорь, TRANSIT или EXIT): (ключ, имя, тип) из их T_USE.
    fn node_clients(&self) -> Vec<([u8; 64], String, &'static str)> {
        let Some(t) = &self.t13 else { return vec![] };
        let info = self.client_info.lock().unwrap().clone();
        let peers: Vec<(LinkId, [u8; 64])> = self.links.lock().unwrap().iter()
            .filter(|(_, l)| matches!(l.role, Role::Client { .. }) && !l.enroll_only)
            .filter_map(|(k, l)| l.peer_pk.map(|pk| (*k, pk))).collect();
        let tr = t.trust.lock().unwrap();
        let mut v: Vec<([u8; 64], String, &'static str)> = peers.iter().filter_map(|(link, pk)| {
            let (name, pl) = info.get(link)?;
            node_like(&tr, pk).then(|| (*pk, name.clone(), *pl))
        }).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v.dedup_by(|a, b| a.0 == b.0);
        v
    }

    /// Раз в 10 с: своих клиентов-узлов - соседям-серверам (T_CINFO), кусками в пределах MDU Link.
    fn push_cinfo(&self) {
        let mine = self.node_clients();
        if mine.is_empty() {
            return;
        }
        let servers: Vec<LinkId> = self.links.lock().unwrap().iter().filter(|(_, l)| matches!(l.role, Role::Server { .. })).map(|(k, _)| *k).collect();
        for link in servers {
            let budget = self.node.engine().link_mdu(&link).unwrap_or(0).saturating_sub(7).min(4096);
            let mut c: Vec<serde_json::Value> = Vec::new();
            for (pk, n, pl) in &mine {
                c.push(serde_json::json!({"k": hex(pk), "n": n, "pl": pl}));
                if serde_json::json!({"c": c}).to_string().len() > budget {
                    c.pop();
                    break;
                }
            }
            if c.is_empty() {
                continue;
            }
            let body = serde_json::json!({"c": c}).to_string().into_bytes();
            let node = self.node.clone();
            tokio::spawn(async move { send_ctl(&node, link, T_CINFO, &body).await; });
        }
    }

    /// Раз в 10 с: если список соседей изменился с прошлой рассылки, отправить его всем клиентам.
    fn push_nbrs_changed(&self) {
        let clients: Vec<LinkId> = self.links.lock().unwrap().iter().filter(|(_, l)| matches!(l.role, Role::Client { .. })).map(|(k, _)| *k).collect();
        for l in clients {
            self.send_nbrs(l);
        }
    }

    fn send_nbrs(&self, link: LinkId) {
        let entries = self.nbr_entries();
        let ttl = {
            let mut links = self.links.lock().unwrap();
            let Some(l) = links.get_mut(&link) else { return };
            if !matches!(l.role, Role::Client { .. }) || l.enroll_only || !l.observation.due(Instant::now(), &entries) { return; }
            l.observation.ttl()
        };
        // Channel envelope (6 bytes) + message type (1), from negotiated Link MDU.
        let budget = self.node.engine().link_mdu(&link).unwrap_or(0).saturating_sub(7).min(4096);
        let Some(body) = crate::observations::encode_report(&entries, ttl, budget) else { return };
        let (node, sh) = (self.node.clone(), self.sh.clone());
        tokio::spawn(async move {
            let mut data = vec![T_NBRS];
            data.extend_from_slice(&body);
            if let Err(e) = node.engine().link_handle(&link).send(&data).await {
                sh.note(format!("T_NBRS не отправлен: {e:?}"));
            }
        });
    }

    /// Реестр кусками: каждый кусок - отдельное сообщение Link (JSON-массив записей) не длиннее `CHUNK_BYTES`.
    /// Одним сообщением реестр перестаёт помещаться в MDU Link уже при ~5 клиентах (W27): синхронизация молча ломалась.
    fn registry_chunks(&self) -> Vec<Vec<u8>> {
        const CHUNK_BYTES: usize = 900;
        let mut all = self.reg.lock().unwrap().all();
        all.sort_by(|a, b| a.id.cmp(&b.id));
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut cur: Vec<ClientRec> = Vec::new();
        for r in all {
            cur.push(r);
            if serde_json::to_vec(&cur).map(|v| v.len()).unwrap_or(0) > CHUNK_BYTES && cur.len() > 1 {
                let last = cur.pop().unwrap();
                out.push(serde_json::to_vec(&cur).unwrap());
                cur = vec![last];
            }
        }
        if !cur.is_empty() {
            out.push(serde_json::to_vec(&cur).unwrap());
        }
        out
    }

    /// Отправить реестр по Link всем кусками по порядку (одна задача, чтобы порядок не терялся).
    fn send_registry(self: &Arc<Self>, link: LinkId, delay_ms: u64) {
        if self.t13.is_some() {
            return; // в модели 0013 реестра клиентов нет: права ходят записями T_REC
        }
        let chunks = self.registry_chunks();
        let node = self.node.clone();
        tokio::spawn(async move {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            for c in chunks {
                send_ctl(&node, link, T_REGISTRY, &c).await;
            }
        });
    }

    fn broadcast_registry(self: &Arc<Self>) {
        let links: Vec<LinkId> = self.links.lock().unwrap().iter().filter(|(_, l)| matches!(l.role, Role::Server { .. })).map(|(k, _)| *k).collect();
        for l in links {
            self.send_registry(l, 0);
        }
    }

    fn close_link(self: &Arc<Self>, link: LinkId, why: &str) {
        self.sh.note(format!("close link {} ({why})", &hex(link.as_bytes())[..8]));
        self.drop_link_state(&link);
        let node = self.node.clone();
        tokio::spawn(async move {
            let _ = node.engine().close_link(&link).await;
        });
    }

    fn drop_link_state(&self, link: &LinkId) {
        if let Some(t) = &self.tun {
            t.disallow(link);
        }
        if let Some(t) = &self.t13 {
            t.pair_sent.lock().unwrap().remove(link);
            t.dir_sent.lock().unwrap().remove(link);
        }
        let removed = self.links.lock().unwrap().remove(link);
        if let Some(l) = removed {
            // неудавшееся серверное рукопожатие: следующий анонс соседа запустит новую попытку
            if let Role::SrvInit { dest, .. } = l.role {
                if let Some(nb) = self.neigh.lock().unwrap().get_mut(&dest) {
                    nb.connecting = false;
                }
            }
            if let Role::Server { dest } = l.role {
                if let Some(nb) = self.neigh.lock().unwrap().get_mut(&dest) {
                    if nb.link == Some(*link) {
                        nb.link = None;
                        nb.rtt_ms = None;
                    }
                }
            }
        }
    }
}

fn mac_srv(akey: &[u8; 32], label: &[u8], id_i: &[u8; 16], id_r: &[u8; 16], ni: &[u8; 16], nr: &[u8; 16], link: &LinkId) -> [u8; 32] {
    mac32(akey, &[label, id_i, id_r, ni, nr, link.as_bytes()])
}

fn id_of_pub(pk: &[u8; 64]) -> Option<[u8; 16]> {
    Identity::from_public_key_bytes(pk).ok().map(|i| *i.hash())
}

/// Запуск узла: модель допуска определяется --secret-file (legacy) или его отсутствием (0013).
pub async fn run_node(a: NodeArgs) -> Result<()> {
    node_main(a).await
}

async fn node_main(mut a: NodeArgs) -> Result<()> {
    let mut public_inline: Vec<String> = Vec::new();
    if let Some(cf) = a.config.clone() {
        let c: NodeConf = serde_json::from_slice(&std::fs::read(&cf).with_context(|| format!("config {}", cf.display()))?).context("разбор конфига узла")?;
        a.name = c.name;
        a.group = c.group;
        a.secret_file = c.secret_file;
        a.port = c.port.unwrap_or(a.port);
        a.advertise = c.advertise.join(",");
        a.advertise_private = c.advertise_private;
        a.seed = c.seeds.join(",");
        public_inline = c.public_rns;
        a.public_rns_file = c.public_rns_file.or(a.public_rns_file);
        a.public_mode = c.public_mode.unwrap_or(a.public_mode);
        a.no_exit = c.no_exit;
        a.announce_s = c.announce_s.unwrap_or(a.announce_s);
        a.dead_s = c.dead_s.unwrap_or(a.dead_s);
        a.quic_cc_mbit = c.quic_cc_mbit.unwrap_or(a.quic_cc_mbit);
        a.workers = c.workers.unwrap_or(a.workers);
        a.tun_name = c.tun_name.unwrap_or(a.tun_name);
        a.client_net = c.client_net.unwrap_or(a.client_net);
        a.invite = c.invite.unwrap_or(a.invite.clone());
        a.invite_file = c.invite_file.or(a.invite_file.clone());
    }
    let _ = CLIENT_NET.set(parse_net(&a.client_net)?);
    let region = detect_region(&a.state).await;
    let _ = REGION.set(region.clone());
    if a.name.is_empty() {
        // имя вида knothop-<РЕГИОН>-<что угодно>: регион по внешнему IP, хвост - имя хоста (или RAWGD_NAME_SUFFIX)
        let suffix = std::env::var("RAWGD_NAME_SUFFIX").ok().filter(|v| !v.is_empty()).unwrap_or_else(hostname);
        a.name = format!("knothop-{region}-{suffix}").chars().take(48).collect();
    }
    // Модель допуска: 0013 (права и якоря доверия; без --secret-file) или legacy (общий серверный секрет). Смешивать нельзя.
    let legacy = a.secret_file.as_os_str() != "-" && a.secret_file.as_os_str().to_str() != Some("");
    if a.state == Path::new("-") {
        bail!("нужен --state (флагом или в --config)");
    }
    if legacy && a.group.is_empty() {
        bail!("для --secret-file (legacy) нужна group");
    }
    let invite_raw = match &a.invite_file {
        // отсутствующий файл приглашения - не ошибка: нода уже зачислена и pin погашен (0013: приглашение после зачисления не используется)
        Some(f) => match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("invite-file {}", f.display())),
        },
        None => a.invite.clone(),
    };
    if legacy && !invite_raw.trim().is_empty() {
        bail!("нельзя смешивать --invite и --secret-file: у ноды одна модель допуска");
    }
    let secret = if legacy { read_secret(&a.secret_file)? } else { Vec::new() };
    if !legacy {
        // тег назначения един для всей модели: нода находит соседей по тегам корней в анонсе, а не по имени группы
        a.group = String::new();
    }
    let identity = load_or_create_identity(&a.state)?;
    let key = iroh_key_from_identity(&identity)?;
    let exit_args = ["--tun-mtu", "1327", "--tun-ip", "10.99.0.1/24", "--tun-txqlen", "10240", "--tun-qdisc", "fq_codel", "--tun-name", a.tun_name.as_str()];
    let b = start_base("n", &a.state, true, Some(a.port), key, a.quic_cc_mbit, if a.no_exit { &[] } else { &exit_args[..] }, None).await?;
    let (node, sh, ep, cli, events) = (b.node.clone(), b.sh.clone(), b.ep.clone(), b.cli.clone(), b.events);

    let tag = if legacy { group_tag(&a.group) } else { T13_TAG.to_string() };
    let my_pk = identity.public_key_bytes();
    let my_key = identity.ed25519_verifying().to_bytes();
    let my_id = *identity.hash();
    let node_identity = identity.clone();
    let dest = new_dest(identity, Direction::In, &tag).map_err(|e| anyhow::anyhow!("destination: {e:?}"))?;
    let my_dest = *dest.hash().as_bytes();
    node.register_destination(dest);

    // модель 0013: права, якоря доверия и (до зачисления) приглашение
    let t13 = if legacy {
        None
    } else {
        let tr = trust::Trust::load(node_identity.clone(), &a.state).context("trust.json")?;
        let mut inv = None;
        if !invite_raw.trim().is_empty() {
            match trust::Invite::parse(&invite_raw) {
                Ok(i) => {
                    if i.root().ok() == Some(my_id) || i.admin == my_pk {
                        bail!("приглашение не может зачислить эту identity или выдано ею самой");
                    } else if i.root().map(|root| tr.has_anchor(&root)).unwrap_or(false) {
                        sh.note("приглашение игнорируется: этот админ уже в якорях".to_string());
                    } else if !i.fresh(now_ms() as u64 / 1000) {
                        bail!("приглашение просрочено или датировано будущим: попросите новое у админа");
                    } else {
                        inv = Some(i);
                    }
                }
                Err(e) if tr.anchors().len() > 1 || tr.record_count() > 0 => {
                    // нода уже зачислена: приглашение ей больше не нужно (pin погашен), мусорный файл не должен мешать старту
                    sh.note(format!("приглашение не разобрано ({e:#}), но нода уже зачислена - продолжаю без него"));
                }
                Err(e) => {
                    return Err(e).context("приглашение");
                }
            }
        }
        Some(T13 { trust: Mutex::new(tr), invite: Mutex::new(inv), pair_sent: Mutex::new(HashSet::new()), pairq_seen: Mutex::new(HashMap::new()),
            early: Mutex::new(Vec::new()), trust_dirty: AtomicBool::new(false), admin_seen: Mutex::new(None), relay_try: Mutex::new(HashMap::new()), dir_sent: Mutex::new(HashMap::new()) })
    };

    let tun = if a.no_exit {
        None
    } else {
        let t = TunState::open(&cli, true)?;
        t.enforce.store(true, Relaxed);
        // обратный маршрут для адресов клиентов; NAT выхода настраивает окружение (контейнер/хост)
        let _ = std::process::Command::new("ip").args(["route", "replace", &net_str(), "dev", &cli.tun_name]).status();
        let _ = sh.tun.set(t.clone());
        tokio::spawn(tun_reader(t.clone(), node.clone(), sh.clone()));
        Some(t)
    };

    // Адрес узла: флаг/конфиг, затем переменная RAWGD_ADVERTISE (единственное, что может отличаться на узле при одинаковом конфиге;
    // для динамического IP - доменное имя `host:порт`), иначе автоопределение глобальных адресов интерфейсов.
    let env_adv = std::env::var("RAWGD_ADVERTISE").unwrap_or_default();
    let mut advertise: Vec<String> = [a.advertise.as_str(), env_adv.as_str()].iter().flat_map(|t| t.split(',')).map(str::trim).filter(|s| !s.is_empty()).map(String::from).take(3).collect();
    let mut adv_auto = None;
    if advertise.is_empty() {
        advertise = local_addrs(a.port, a.advertise_private, &a.tun_name);
        adv_auto = Some((a.advertise_private, a.tun_name.clone()));
    }
    sh.note(format!("объявляемые адреса: {advertise:?}"));
    // узел стационарный: что не работает на его путях, помним и после перезапуска (клиент хранит только в памяти)
    sh.health.init(a.state.join("carrier_health.json"));
    let ctx = Arc::new(NodeCtx {
        node: node.clone(), sh: sh.clone(), ep: ep.clone(), state: a.state.clone(), name: a.name.clone(), group: a.group.clone(), tag: tag.clone(),
        identity: node_identity, akey: server_auth_key(&secret, &a.group), my_pk, my_id, my_dest, my_key, ep_id: ep.id().to_string(), advertise: Mutex::new(advertise), adv_auto,
        announce_s: a.announce_s, dead: Duration::from_secs(a.dead_s), path_gate: path::PathGate::default(), client_info: Mutex::new(HashMap::new()), peer_clients: Mutex::new(HashMap::new()),
        links: Mutex::new(HashMap::new()), pending_nr: Mutex::new(HashMap::new()), neigh: Mutex::new(HashMap::new()), reg: Mutex::new(Registry::load(&a.state.join("clients.json"))),
        tun, started: Instant::now(), announce_at: Default::default(), last_trigger: Mutex::new(Instant::now() - Duration::from_secs(3600)),
        ours_online: Default::default(), listen_port: a.port, public_ids: Mutex::new(HashSet::new()),
        t13,
        bench_sess: Mutex::new(None), bench_serving: AtomicBool::new(false), bench_rate: Mutex::new(HashMap::new()),
    });
    if let Some(t) = &ctx.t13 {
        let tr = t.trust.lock().unwrap();
        let inv = t.invite.lock().unwrap();
        sh.note(format!("модель 0013: якорей {}, записей {}{}", tr.anchors().len(), tr.record_count(),
            if inv.is_some() { ", жду зачисления по приглашению" } else { "" }));
        // админ приглашения ещё не знаком: заводим соседа из приглашения, чтобы дозвониться, не дожидаясь его анонса
        if let Some(i) = inv.as_ref() {
            let mut key = [0u8; 32];
            key.copy_from_slice(&i.admin[32..64]);
            let dest = dest_from_pub_tag(&i.admin, &ctx.tag);
            let ep = EndpointId::from_bytes(&key).map(|e| e.to_string()).unwrap_or_default();
            ctx.neigh.lock().unwrap().insert(dest, Neighbor { dest, key, pk: i.admin, name: "admin".into(), ep, addrs: Addrs::new(i.addrs.clone()), tags: vec![], accepts_links: true, last_announce: Instant::now(),
                link: None, last_heard: Instant::now() - Duration::from_secs(3600), rtt_ms: None, connecting: false, dialer: None, first_seen: Instant::now(),
                last_try: Instant::now() - Duration::from_secs(3600), ctl: CarrierCtl::new(), loss: LossWin::default(), ping_seq: 0, admitted_at: Instant::now(), seen_gen: 0 });
        }
    }
    ctx.book_load();
    write_atomic(&a.state.join("server.json"), ctx.self_json().to_string().as_bytes());
    sh.note(format!("node {} group {} tag {} dest {} iroh {}", ctx.name, ctx.group, tag, hex(&my_dest), ctx.ep_id));

    tokio::spawn(accept_loop(ep.clone(), node.clone(), sh.clone()));
    tokio::spawn(tcpc::listen(node.clone(), sh.clone(), a.port));
    for s in a.seed.split(',').filter(|s| !s.is_empty()) {
        if let Some((id, addrs)) = parse_peer(s) {
            tokio::spawn(dial_direct(ep.clone(), node.clone(), sh.clone(), format!("seed-{}", id.fmt_short()), id, Addrs::new(addrs), Arc::new(AtomicBool::new(true)), CarrierCtl::new()));
        } else {
            sh.note(format!("bad --seed entry {s:?} (want id@ip:port)"));
        }
    }
    // Публичная сеть RNS: только анонсы и связность. Ручки держим до конца работы (сброс ручки отключает интерфейс).
    let public = load_public_list(&a.public_rns_file, &public_inline);
    let mut public_handles = Vec::new();
    for e in &public {
        let Some((host, port)) = e.rsplit_once(':').and_then(|(h, p)| Some((h.trim_matches(|c| c == '[' || c == ']'), p.parse::<u16>().ok()?))) else {
            sh.note(format!("публичный узел {e:?}: нужен host:порт"));
            continue;
        };
        let conf: leviculum_std::api::InterfaceConfig = serde_json::from_value(serde_json::json!({
            "name": format!("pub-{host}"), "type": "TCPClientInterface", "target_host": host, "target_port": port, "mode": a.public_mode}))
            .map_err(|e| anyhow::anyhow!("интерфейс {host}: {e}"))?;
        match node.spawn_interface(conf) {
            Ok(ids) => {
                ctx.public_ids.lock().unwrap().extend(ids.iter().map(|i| i.0));
                public_handles.push(ids)
            }
            Err(e) => sh.note(format!("публичный узел {host}:{port}: {e}")),
        }
    }
    sh.note(format!("публичных узлов RNS подключено: {} из {}", public_handles.len(), public.len()));
    tokio::spawn(node_events(ctx.clone(), events));
    tokio::spawn(node_housekeeping(ctx.clone()));

    // анонс: с прогревом, пока соседи подключаются
    let mut last = Instant::now() - Duration::from_secs(3600);
    let t0 = Instant::now();
    let fin = a.state.join("fin");
    let mut announces = 0u32;
    while !fin.exists() {
        // Без публичной сети (лаборатория) - частые анонсы на прогреве. С публичной - три стартовых (0, 20, 40 с), дальше период:
        // чужие узлы не обязаны переносить наши анонсы каждые несколько секунд.
        let every = if public.is_empty() {
            if t0.elapsed() < Duration::from_secs(30) { 3.min(a.announce_s) } else { a.announce_s }
        } else if announces < 3 {
            [0, 20, 20][announces as usize]
        } else {
            a.announce_s
        };
        let at = ctx.announce_at.load(Relaxed);
        let triggered = at != 0 && now_ms() as u64 >= at;
        if last.elapsed() >= Duration::from_secs(every) || triggered {
            if triggered {
                ctx.announce_at.store(0, Relaxed);
            }
            let _ = node.announce(&DestinationHash::new(my_dest), Some(&ctx.announce_data())).await;
            last = Instant::now();
            announces += 1;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    drop(public_handles);
    tokio::time::sleep(Duration::from_millis(300)).await;
    ep.close().await;
    Ok(())
}

async fn node_events(ctx: Arc<NodeCtx>, mut events: leviculum_std::driver::EventReceiver) {
    while let Some(ev) = events.recv().await {
        match ev {
            NodeEvent::AnnounceReceived { announce, .. } => on_announce(&ctx, &announce),
            NodeEvent::LinkEstablished { link_id, is_initiator, .. } => {
                ctx.sh.established.lock().unwrap().insert(hex(link_id.as_bytes()));
                if !is_initiator {
                    if std::env::var("RAWG_DEBUG").is_ok() {
                        ctx.sh.note(format!("входящий Link {}", &hex(link_id.as_bytes())[..8]));
                    }
                    // H10: интерфейс носителя известен из состояния Link (если его ещё нет - лимит на интерфейс не применяем, общий работает)
                    let stats = ctx.node.engine().link_stats(&link_id);
                    let iface = stats.as_ref().and_then(|s| s.attached_interface());
                    // fail-closed: шифр неизвестен - считаем стандартным CBC
                    let cbc = stats.as_ref().map(|s| s.cipher() != leviculum_std::api::LinkCipher::Gcm).unwrap_or(true);
                    let mut l = ctx.links.lock().unwrap();
                    let unauth = l.values().filter(|x| matches!(x.role, Role::Unknown)).count();
                    let unauth_iface = l.values().filter(|x| matches!(x.role, Role::Unknown) && iface.is_some() && x.iface == iface).count();
                    if unauth >= MAX_UNAUTH_LINKS || unauth_iface >= MAX_UNAUTH_PER_IFACE {
                        drop(l);
                        ctx.close_link(link_id, "слишком много неавторизованных link");
                        continue;
                    }
                    l.insert(link_id, LinkInfo { role: Role::Unknown, since: Instant::now(), last_heard: Instant::now(), peer_pk: None, want_use: false, enroll_only: cbc, iface, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default() });
                }
            }
            NodeEvent::LinkClosed { link_id, reason, .. } => {
                ctx.sh.closed.lock().unwrap().insert(hex(link_id.as_bytes()), format!("{reason:?}"));
                ctx.drop_link_state(&link_id);
            }
            NodeEvent::LinkIdentified { link_id, identity_hash } => on_identified(&ctx, link_id, identity_hash),
            NodeEvent::MessageReceived { link_id, data, .. } => {
                if ctx.ctrl_pass(link_id) {
                    on_control(&ctx, link_id, &data);
                }
            }
            NodeEvent::LinkDataReceived { link_id, .. } if ctx.link_is_cbc(&link_id) => {}
            NodeEvent::LinkDataReceived { link_id, data, .. } if data.first() == Some(&T_BENCH_DATA) => bench_rx(&ctx.bench_sess, link_id, &data),
            NodeEvent::LinkDataReceived { link_id, data, .. } => {
                if is_rgp(&data) {
                    on_rgp(&ctx, link_id, &data);
                } else if let Some(t) = &ctx.tun {
                    t.on_link_packet(&ctx.node, link_id, &data);
                }
            }
            _ => {}
        }
    }
}

fn on_announce(ctx: &Arc<NodeCtx>, ann: &leviculum_std::ReceivedAnnounce) {
    if std::env::var("RAWG_DEBUG").is_ok() {
        ctx.sh.note(format!("announce from {} path_response={} data={}", hex(&ann.destination_hash().as_bytes()[..4]), ann.is_path_response(), String::from_utf8_lossy(ann.app_data()).chars().take(60).collect::<String>()));
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(ann.app_data()) else { return };
    if ctx.t13.is_some() {
        if !v["r"].is_array() {
            return; // не наш формат (0013: анонс = только теги корней)
        }
    } else if v["v"] != 1 || v["t"].as_str() != Some(ctx.tag.as_str()) {
        return; // чужая группа или не наш формат
    }
    let dest = *ann.destination_hash().as_bytes();
    if dest == ctx.my_dest {
        return;
    }
    let pk = *ann.public_key();
    let mut key = [0u8; 32];
    key.copy_from_slice(&pk[32..64]);
    // 0013 (ADR 0016): имени и endpoint id в анонсе нет; EndpointId QUIC = ключ подписи identity, имя придёт по T_DIR
    let name: Option<String> = v["n"].as_str().and_then(|n| norm_peer_name(n, ""));
    let ep = match v["e"].as_str() {
        Some(e) => e.to_string(),
        None => EndpointId::from_bytes(&key).map(|e| e.to_string()).unwrap_or_default(),
    };
    let addrs: Vec<String> = v["a"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).take(3).collect()).unwrap_or_default();
    let tags: Vec<String> = v["r"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.chars().take(16).collect())).take(9).collect()).unwrap_or_default();
    // Versioned announce field (v=1): advisory planning capability, never authorization. Legacy peers default to true.
    let accepts_links = v["lc"].as_bool().unwrap_or(true);
    // Админ/делегат приглашения распознаётся по ключу до фильтра тегов: анонс остаётся нейтральным.
    if let Some(t) = &ctx.t13 {
        if t.invite.lock().unwrap().as_ref().map(|i| i.admin == pk).unwrap_or(false) {
            *t.admin_seen.lock().unwrap() = Some(Instant::now());
            ctx.trigger_announce();
        }
    }
    if ctx.t13.is_some() {
        // 0013: интересны только анонсы из знакомых нам сетей (пересечение тегов корней с моими якорями или с сетью админа моего приглашения)
        let mine = ctx.t13_tags();
        if !tags.iter().any(|t| mine.contains(t)) {
            return;
        }
    }
    // S2/S3: новая запись нужна место; защищённых соседей (TRANSIT по записям или Link) публичный анонс не вытесняет
    let is_new = !ctx.neigh.lock().unwrap().contains_key(&dest);
    if is_new {
        match ctx.neighbor_room_for(&pk) {
            NeighborRoom::Full => return,
            NeighborRoom::Evict(v) => ctx.evict_neighbor(&v),
            NeighborRoom::Free => {}
        }
    }
    {
        let mut n = ctx.neigh.lock().unwrap();
        let e = n.entry(dest).or_insert_with(|| Neighbor { dest, key, pk, name: name.clone().unwrap_or_else(|| "?".into()), ep: ep.clone(), addrs: Addrs::new(addrs.clone()), tags: tags.clone(), accepts_links, last_announce: Instant::now(),
            link: None, last_heard: Instant::now() - Duration::from_secs(3600), rtt_ms: None, connecting: false, dialer: None, first_seen: Instant::now(),
            last_try: Instant::now() - Duration::from_secs(3600), ctl: CarrierCtl::new(), loss: LossWin::default(), ping_seq: 0, admitted_at: Instant::now(), seen_gen: 0 });
        if let Some(n) = name.clone() {
            e.name = n;
        }
        e.ep = ep;
        if !addrs.is_empty() || ctx.t13.is_none() {
            // 0013: анонс без адресов (нода за NAT) не стирает адрес из приглашения; работающий диалер получит новые адреса через общее хранилище
            e.addrs.set(addrs);
        }
        e.tags = tags;
        e.accepts_links = accepts_links;
        e.last_announce = Instant::now();
    }
    // lc=false is an opt-out from being selected as a server neighbor, not a grant or
    // revocation of rights. If a delayed announce arrives after promotion, remove only
    // the Server Link for this identity; never disturb a client VPN Link.
    if !accepts_links {
        let links: Vec<LinkId> = ctx.links.lock().unwrap().iter()
            .filter(|(_, l)| l.peer_pk == Some(pk) && matches!(l.role, Role::Server { .. }))
            .map(|(id, _)| *id).collect();
        for link in links {
            ctx.close_link(link, "пир отказался принимать соседские Link");
        }
    }
    // Новый участник группы: ответить анонсом, чтобы он быстро узнал нас (иначе ждать период анонса); дальше им занимается housekeeping (дозвон, Link).
    if is_new {
        ctx.sh.note(format!("новый участник группы {} ({})", name_of(ctx, &dest), &hex(&dest)[..8]));
        ctx.trigger_announce();
    }
}

fn name_of(ctx: &Arc<NodeCtx>, dest: &[u8; 16]) -> String {
    ctx.neigh.lock().unwrap().get(dest).map(|n| n.name.clone()).unwrap_or_default()
}

/// Прямое QUIC-соединение к соседу, если у него есть адрес. Набирает один из двух: тот, у кого хеш меньше, либо тот, у кого нет своих адресов
/// (его иначе не достать); если за 15 с никто не набрал - набираем в любом случае. Так для пары не создаётся два соединения, а за NAT всё равно работает.
fn maybe_dial(ctx: &Arc<NodeCtx>, dest: [u8; 16]) {
    // админ ожидаемого приглашения набирается сразу: иначе зачисление ждало бы лишние 15 с
    let invite_admin = ctx.t13.as_ref().and_then(|t| t.invite.lock().unwrap().as_ref().map(|i| i.admin));
    // открытое приглашение без адресов админа: посредник зачисления набирается сразу (R7), не ждёт очереди
    let open_inv = ctx.t13.as_ref().and_then(|t| t.invite.lock().unwrap().clone()).filter(|i| i.addrs.is_empty());
    let (id, sa, label) = {
        let mut n = ctx.neigh.lock().unwrap();
        let Some(nb) = n.get_mut(&dest) else { return };
        if nb.dialer.is_some() || nb.addrs.is_empty() {
            return;
        }
        // Link уже поднят напрямую (сосед сам набрал нас): встречный дозвон лишь сменил бы носитель и оборвал Link
        if nb.link.is_some() && ctx.node.hops_to(&DestinationHash::new(dest)) == Some(1) {
            return;
        }
        let relay = open_inv.as_ref().map(|i| relay_match(i, &nb.pk, &nb.tags)).unwrap_or(false);
        let may = ctx.my_dest < dest || ctx.adv().is_empty() || nb.first_seen.elapsed() > Duration::from_secs(15) || invite_admin == Some(nb.pk) || relay;
        let Ok(id) = nb.ep.parse::<EndpointId>() else { return };
        if !may {
            return;
        }
        let alive = Arc::new(AtomicBool::new(true));
        nb.dialer = Some(alive.clone());
        let sa: Vec<String> = nb.addrs.get();
        tokio::spawn({
            let (ep, node, sh, label, cc, book) = (ctx.ep.clone(), ctx.node.clone(), ctx.sh.clone(), nb.name.clone(), nb.ctl.clone(), nb.addrs.clone());
            async move { dial_direct(ep, node, sh, label, id, book, alive, cc).await }
        });
        (id, sa, nb.name.clone())
    };
    ctx.sh.note(format!("дозвон до {label} ({}): {sa:?}", id.fmt_short()));
}

async fn connect_neighbor(ctx: Arc<NodeCtx>, dest: [u8; 16]) {
    let (key, pk, label) = {
        let n = ctx.neigh.lock().unwrap();
        let Some(nb) = n.get(&dest) else { return };
        (nb.key, nb.pk, nb.name.clone())
    };
    let dh = DestinationHash::new(dest);
    let res: Result<LinkId> = async {
        // Тот же порядок, что у клиента к выходу: прямой путь (1 хоп) по нашему носителю, иначе транзит через наши ноды.
        wait_our_path(&ctx.node, &ctx.path_gate, &dh, || own_carrier_ifaces(&ctx.node), || out_carrier_iface(&ctx.node, &label), None, 20).await;
        if !scoped_path(&ctx.node, &dh, &own_carrier_ifaces(&ctx.node), None) {
            bail!("нет пути через наши узлы");
        }
        // интерфейс пути, по которому уходит запрос Link: у ожидающего Link attached_interface ещё нет (появляется с proof)
        let used_iface = ctx.node.engine().get_path_clone(&dh).map(|p| p.interface_index);
        let handle = ctx.node.connect_with_key(&dh, &key).await?;
        let id = *handle.link_id();
        let k = hex(id.as_bytes());
        let t = Instant::now();
        while !ctx.sh.established.lock().unwrap().contains(&k) {
            if t.elapsed() > Duration::from_secs(8) {
                let _ = ctx.node.engine().close_link(&id).await;
                if used_iface.is_some() && ctx.node.engine().get_path_clone(&dh).map(|p| p.interface_index) == used_iface {
                    ctx.node.engine().remove_path(&dh);
                }
                bail!("link не установился");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // гонка изменения таблицы путей во время connect: установленный Link обязан идти через наш носитель
        if !path::acceptable(ctx.node.engine().link_stats(&id).and_then(|s| s.attached_interface()), &own_carrier_ifaces(&ctx.node), None) {
            let _ = ctx.node.engine().close_link(&id).await;
            bail!("Link выбрал интерфейс вне наших носителей");
        }
        Ok(id)
    }
    .await;
    match res {
        Ok(id) => {
            if ctx.t13.is_some() {
                // 0013: роль не зависит от инициативы. Сначала identify (ответчик узнаёт нас), затем обе стороны обмениваются цепочками прав
                ctx.links.lock().unwrap().insert(id, LinkInfo { role: Role::Unknown, since: Instant::now(), last_heard: Instant::now(), peer_pk: Some(pk), want_use: false, enroll_only: false, iface: None, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default() });
                let c = ctx.clone();
                tokio::spawn(async move {
                    let my_id = c.identity.clone();
                    if c.node.identify_link(&id, &my_id).await.is_err() {
                        c.close_link(id, "identify не завершён");
                        return;
                    }
                    on_peer_ready(&c, id, pk);
                });
            } else {
                let nonce_i = rand16();
                ctx.links.lock().unwrap().insert(id, LinkInfo { role: Role::SrvInit { dest, nonce_i, pub_i: ctx.my_pk, mac_sent: false }, since: Instant::now(), last_heard: Instant::now(), peer_pk: None, want_use: false, enroll_only: false, iface: None, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default() });
                let mut body = Vec::new();
                body.extend_from_slice(&nonce_i);
                body.extend_from_slice(&ctx.my_pk);
                send_ctl(&ctx.node, id, T_SRV1, &body).await;
                // _pk закреплён анонсом: сверяется в SRV2
                let _ = pk;
            }
        }
        Err(e) => {
            ctx.sh.note(format!("neighbor {label}: {e:#}"));
            if let Some(nb) = ctx.neigh.lock().unwrap().get_mut(&dest) {
                nb.connecting = false;
                nb.last_try = Instant::now(); // backoff starts at failure, not before the 20 s wait
            }
        }
    }
}

fn on_identified(ctx: &Arc<NodeCtx>, link: LinkId, idh: [u8; 16]) {
    let ok = matches!(ctx.links.lock().unwrap().get(&link).map(|l| &l.role), Some(Role::Unknown));
    if !ok {
        return;
    }
    // модель 0013: допуск решают записи о правах (on_peer_ready -> evaluate); реестра клиентов нет
    if ctx.t13.is_some() {
        if let Some(i) = ctx.node.get_remote_identity(&link) {
            if *i.hash() == idh {
                on_peer_ready(ctx, link, i.public_key_bytes());
            }
        }
        return;
    }
    let idhex = hex(&idh);
    let rec = ctx.reg.lock().unwrap().active(&idhex).cloned();
    let Some(rec) = rec else {
        spawn_ctl(&ctx.node, link, T_AUTH_FAIL, b"unknown or revoked identity".to_vec());
        let c = ctx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            c.close_link(link, "клиент не в реестре или отозван");
        });
        return;
    };
    // identify подтверждает владение ключом; сверяем ещё и с записью реестра
    let pk_ok = ctx.node.get_remote_identity(&link).map(|i| hex(&i.public_key_bytes()) == rec.pk).unwrap_or(false);
    if !pk_ok {
        ctx.close_link(link, "ключ не совпал с реестром");
        return;
    }
    if ctx.link_is_public(&link) {
        ctx.close_link(link, "клиент через публичную сеть RNS");
        return;
    }
    let ip = client_ip(&idh);
    // один адрес - один активный клиент: чужой Link с тем же адресом не вытесняется
    let clash = ctx.links.lock().unwrap().iter().any(|(k, l)| *k != link && matches!(l.role, Role::Client { ip: p, id, .. } if p == ip && id != idh));
    if clash {
        spawn_ctl(&ctx.node, link, T_AUTH_FAIL, b"address clash".to_vec());
        ctx.close_link(link, "конфликт адреса клиента");
        return;
    }
    // та же identity с нового Link (смена маршрута): старый Link закрываем
    let old: Vec<LinkId> = ctx.links.lock().unwrap().iter().filter(|(k, l)| **k != link && matches!(l.role, Role::Client { id, .. } if id == idh)).map(|(k, _)| *k).collect();
    for o in old {
        ctx.close_link(o, "новый Link той же identity");
    }
    if let Some(l) = ctx.links.lock().unwrap().get_mut(&link) {
        l.role = Role::Client { id: idh, ip };
    }
    if let Some(t) = &ctx.tun {
        t.allow(&ctx.node, link, ip);
    }
    ctx.sh.note(format!("client {} ({}) admitted on {}", rec.name, &idhex[..8], &hex(link.as_bytes())[..8]));
    let ok = serde_json::json!({"name": ctx.name, "ip": ip_str(ip), "cc": REGION.get().cloned().unwrap_or_default(), "pl": platform()});
    let c2 = ctx.clone();
    let body = ok.to_string().into_bytes();
    tokio::spawn(async move {
        send_ctl(&c2.node, link, T_AUTH_OK, &body).await;
        c2.send_table(link);   // таблица сразу после допуска, кусками
    });
}

fn on_rgp(ctx: &Arc<NodeCtx>, link: LinkId, d: &[u8]) {
    let role_srv = {
        let mut l = ctx.links.lock().unwrap();
        match l.get_mut(&link) {
            Some(info) => {
                info.last_heard = Instant::now();
                match info.role {
                    Role::Server { dest } => Some(Some(dest)),
                    Role::Client { .. } => Some(None),
                    _ => None,
                }
            }
            None => None,
        }
    };
    let Some(srv) = role_srv else { return }; // пинг от неавторизованного Link не обслуживаем
    if d[3] == b'P' {
        let mut r = d.to_vec();
        r[3] = b'R';
        spawn_dgram(&ctx.node, link, r);
    } else if let Some(dest) = srv {
        let seq = u32::from_le_bytes(d[4..8].try_into().unwrap());
        let ts = u64::from_le_bytes(d[8..16].try_into().unwrap());
        if let Some(nb) = ctx.neigh.lock().unwrap().get_mut(&dest) {
            nb.rtt_ms = Some(now_us().saturating_sub(ts) as f64 / 1000.0);
            nb.last_heard = Instant::now();
            nb.loss.ack(seq);
        }
    }
}

fn on_control(ctx: &Arc<NodeCtx>, link: LinkId, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let (ty, body) = (data[0], &data[1..]);
    if let Some(l) = ctx.links.lock().unwrap().get_mut(&link) {
        l.last_heard = Instant::now();
    }
    // Стандартный CBC-Link несёт только зачисление (записи прав, каталог, отказ, просьба через посредника); админ, политика, допуск и данные ему недоступны
    if ctx.link_is_cbc(&link) && !matches!(ty, T_REC | T_DIR | T_PAIR_NO | T_PAIRQ) {
        return;
    }
    match ty {
        T_CINFO => on_cinfo(ctx, link, body),
        T_OBSERVE if matches!(body, [0] | [1]) => {
            {
                let mut links = ctx.links.lock().unwrap();
                let Some(l) = links.get_mut(&link) else { return };
                if !matches!(l.role, Role::Client { .. }) || l.enroll_only { return; }
                l.observation.set_visible(body[0] == 1);
            }
            ctx.send_nbrs(link);
        }
        T_SRV1 if body.len() == 16 + 64 => {
            // в модели 0013 T_SRV (общий секрет) не используется: молча игнорировать нечестно - вежливо закрываем
            if ctx.t13.is_some() {
                ctx.close_link(link, "узел на старой модели допуска (общий секрет); нужны права/0013");
                return;
            }
            // мы отвечаем: нонс шлём сразу, MAC - только после доказательства контрагента
            let mut l = ctx.links.lock().unwrap();
            let Some(info) = l.get_mut(&link) else { return };
            if !matches!(info.role, Role::Unknown) {
                return;
            }
            let (mut ni, mut pi) = ([0u8; 16], [0u8; 64]);
            ni.copy_from_slice(&body[..16]);
            pi.copy_from_slice(&body[16..]);
            let nr = rand16();
            info.role = Role::SrvResp { nonce_i: ni, nonce_r: nr, pub_i: pi };
            drop(l);
            let mut out = Vec::new();
            out.extend_from_slice(&nr);
            out.extend_from_slice(&ctx.my_pk);
            spawn_ctl(&ctx.node, link, T_SRV2, out);
        }
        T_SRV2 if body.len() == 16 + 64 => {
            let mut l = ctx.links.lock().unwrap();
            let Some(info) = l.get_mut(&link) else { return };
            let (d, ni, pi) = match &info.role {
                Role::SrvInit { dest, nonce_i, pub_i, mac_sent: false } => (*dest, *nonce_i, *pub_i),
                _ => return,
            };
            let mut nr = [0u8; 16];
            nr.copy_from_slice(&body[..16]);
            let mut pr = [0u8; 64];
            pr.copy_from_slice(&body[16..]);
            let (Some(id_r), Some(id_i)) = (id_of_pub(&pr), id_of_pub(&pi)) else { return };
            // identity ответчика должна совпасть с закреплённой в анонсе
            let announced_ok = ctx.neigh.lock().unwrap().get(&d).map(|n| n.pk == pr).unwrap_or(false);
            if !announced_ok {
                drop(l);
                ctx.close_link(link, "identity ответчика не совпала с анонсом");
                return;
            }
            let mac = mac_srv(&ctx.akey, b"initiator", &id_i, &id_r, &ni, &nr, &link);
            info.role = Role::SrvInit { dest: d, nonce_i: ni, pub_i: pi, mac_sent: true };
            ctx.pending_nr.lock().unwrap().insert(link, nr);
            drop(l);
            spawn_ctl(&ctx.node, link, T_SRV3, mac.to_vec());
        }
        T_SRV3 if body.len() == 32 => {
            let mut l = ctx.links.lock().unwrap();
            let Some(info) = l.get_mut(&link) else { return };
            let Role::SrvResp { nonce_i, nonce_r, pub_i } = &info.role else { return };
            let (ni, nr, pi) = (*nonce_i, *nonce_r, *pub_i);
            let (Some(id_i), Some(id_r)) = (id_of_pub(&pi), id_of_pub(&ctx.my_pk)) else { return };
            if !mac_ok(&ctx.akey, &[b"initiator", &id_i, &id_r, &ni, &nr, link.as_bytes()], body) {
                drop(l);
                ctx.sh.note("серверное рукопожатие: доказательство инициатора неверно, link закрыт".to_string());
                ctx.close_link(link, "неверный серверный секрет");
                return;
            }
            let mac = mac_srv(&ctx.akey, b"responder", &id_i, &id_r, &ni, &nr, &link);
            // кто это: по identity ищем соседа из анонсов (может ещё не быть - тогда создадим с его ключом)
            let dest = {
                let n = ctx.neigh.lock().unwrap();
                n.values().find(|x| x.pk == pi).map(|x| x.dest)
            };
            let dest = dest.unwrap_or_else(|| {
                let mut d = [0u8; 16];
                if let Ok(idn) = Identity::from_public_key_bytes(&pi) {
                    if let Ok(dd) = new_dest(idn, Direction::Out, &ctx.tag) {
                        d = *dd.hash().as_bytes();
                    }
                }
                d
            });
            info.role = Role::Server { dest };
            drop(l);
            ctx.admit_neighbor(link, dest, &pi);
            spawn_ctl(&ctx.node, link, T_SRV4, mac.to_vec());
        }
        T_SRV4 if body.len() == 32 => {
            let mut l = ctx.links.lock().unwrap();
            let Some(info) = l.get_mut(&link) else { return };
            let (d, ni, pi) = match &info.role {
                Role::SrvInit { dest, nonce_i, pub_i, mac_sent: true } => (*dest, *nonce_i, *pub_i),
                _ => return,
            };
            let Some(nr) = ctx.pending_nr.lock().unwrap().remove(&link) else { return };
            let pr = ctx.neigh.lock().unwrap().get(&d).map(|n| n.pk);
            let (Some(id_i), Some(pr)) = (id_of_pub(&pi), pr) else { return };
            let Some(id_r) = id_of_pub(&pr) else { return };
            if !mac_ok(&ctx.akey, &[b"responder", &id_i, &id_r, &ni, &nr, link.as_bytes()], body) {
                drop(l);
                ctx.close_link(link, "ответчик не доказал знание серверного секрета");
                return;
            }
            info.role = Role::Server { dest: d };
            drop(l);
            ctx.admit_neighbor(link, d, &pr);
        }
        T_PING => {
            let is_ok = matches!(ctx.links.lock().unwrap().get(&link).map(|l| &l.role), Some(Role::Server { .. }) | Some(Role::Client { .. }));
            if is_ok {
                spawn_ctl(&ctx.node, link, T_PONG, body.to_vec());
            }
        }
        T_PONG if body.len() >= 12 => {
            let ts = u64::from_le_bytes(body[4..12].try_into().unwrap());
            let rtt = now_us().saturating_sub(ts) as f64 / 1000.0;
            let l = ctx.links.lock().unwrap();
            if let Some(Role::Server { dest }) = l.get(&link).map(|x| &x.role) {
                if let Some(nb) = ctx.neigh.lock().unwrap().get_mut(dest) {
                    nb.rtt_ms = Some(rtt);
                    nb.last_heard = Instant::now();
                    nb.loss.ack(u32::from_le_bytes(body[..4].try_into().unwrap()));
                }
            }
        }
        T_REGISTRY => {
            let is_srv = matches!(ctx.links.lock().unwrap().get(&link).map(|l| &l.role), Some(Role::Server { .. }));
            if !is_srv {
                return; // реестр принимается только от взаимно проверенного сервера
            }
            if ctx.t13.is_some() {
                return; // в модели 0013 реестра нет: права ходят записями T_REC
            }
            if let Ok(v) = serde_json::from_slice::<Vec<ClientRec>>(body) {
                let changed = ctx.reg.lock().unwrap().merge(&v);
                if changed {
                    ctx.reg.lock().unwrap().save(&ctx.state.join("clients.json"));
                    ctx.enforce_revocations();
                    ctx.sh.note(format!("реестр клиентов обновлён от соседа ({} записей)", ctx.reg.lock().unwrap().recs.len()));
                }
            }
        }
        T_REC => on_rec(ctx, link, body),
        T_POL => on_pol(ctx, link, body),
        T_DIR => on_dir_node(ctx, link, body),
        T_BENCH => on_bench_ctl(ctx, link, body),
        T_PAIR1 => {
            let b = body.to_vec();
            let c = ctx.clone();
            tokio::spawn(async move { on_pair1(c, link, b).await });
        }
        T_PAIR_NO => on_pair_no(ctx, link, body),
        T_PAIRQ => on_pairq(ctx, link, body),
        T_USE => {
            if let Some(l) = ctx.links.lock().unwrap().get_mut(&link) {
                l.want_use = true;
            }
            if let Some((name, pl)) = parse_client_info(body) {
                let live: HashSet<LinkId> = ctx.links.lock().unwrap().keys().copied().collect();
                let mut m = ctx.client_info.lock().unwrap();
                m.retain(|l, _| live.contains(l));
                if m.len() < 256 || m.contains_key(&link) {
                    m.insert(link, (name, pl));
                }
            }
            ctx.evaluate(link);
        }
        _ => {}
    }
}

// ------------------------------------------------------------------ модель 0013: права, допуск, зачисление

/// Аспект назначения узлов 0013 один на всех: соседей находят по тегам корней в анонсе, а не по имени группы.
const T13_TAG: &str = "t13";

/// Имя назначения RNS. Модель 0013 (ADR 0016): нейтральное, без `rawg`/`vpn` - хеш имени виден в каждом анонсе, и по строке
/// наблюдатель узнал бы наши узлы. Легаси оставляет прежнее имя `rawgvpn.node.<тег группы>`.
fn new_dest(id: Identity, dir: Direction, tag: &str) -> Result<Destination, String> {
    let r = if tag == T13_TAG {
        Destination::new(Some(id), dir, DestinationType::Single, "node", &["mesh"])
    } else {
        Destination::new(Some(id), dir, DestinationType::Single, "rawgvpn", &["node", tag])
    };
    r.map_err(|e| format!("{e:?}"))
}

/// dest по публичному ключу: анонс мог не дойти - достраиваем сами.
fn dest_of_pub(ctx: &NodeCtx, pk: &[u8; 64]) -> [u8; 16] {
    {
        let n = ctx.neigh.lock().unwrap();
        if let Some(x) = n.values().find(|x| x.pk == *pk) {
            return x.dest;
        }
    }
    dest_from_pub_tag(pk, &ctx.tag)
}

/// Нулевой dest - не найден.
fn dest_from_pub_tag(pk: &[u8; 64], tag: &str) -> [u8; 16] {
    let mut d = [0u8; 16];
    if let Ok(idn) = Identity::from_public_key_bytes(pk) {
        if let Ok(dd) = new_dest(idn, Direction::Out, tag) {
            d = *dd.hash().as_bytes();
        }
    }
    d
}

/// Прежнее (до ADR 0016) имя назначения модели 0013: `rawgvpn.node.t13`. Нужно только для переноса сохранённых адресов.
fn old_dest13(pk: &[u8; 64]) -> [u8; 16] {
    let mut d = [0u8; 16];
    if let Ok(idn) = Identity::from_public_key_bytes(pk) {
        if let Ok(dd) = Destination::new(Some(idn), Direction::Out, DestinationType::Single, "rawgvpn", &["node", T13_TAG]) {
            d = *dd.hash().as_bytes();
        }
    }
    d
}

/// Адреса выходов хранятся по хешу назначения; после смены имени (ADR 0016) старые ключи перекладываем на новые по известным ключам нод.
fn migrate_hints(hints: &mut HashMap<String, Vec<String>>, pks: impl Iterator<Item = [u8; 64]>) {
    for pk in pks {
        let (old, new) = (hex(&old_dest13(&pk)), hex(&dest_from_pub_tag(&pk, T13_TAG)));
        if let Some(a) = hints.remove(&old) {
            hints.entry(new).or_insert(a);
        }
    }
}

/// Announced link capability is only a scheduler hint; it never participates in authorization.
fn plan_transit_neighbor(accepts_links: bool, has_transit_rights: bool) -> bool {
    accepts_links && has_transit_rights
}

/// Guard for actual Server promotion (including delayed callbacks). An announce can only opt
/// its own known identity out; authorization still comes exclusively from the trust records.
fn server_promotion_allowed(enroll_only: bool, accepts_links: Option<bool>, has_transit_rights: bool) -> bool {
    !enroll_only && accepts_links != Some(false) && has_transit_rights
}

fn peer_of(ctx: &NodeCtx, link: &LinkId) -> Option<[u8; 64]> {
    ctx.links.lock().unwrap().get(link).and_then(|l| l.peer_pk)
}

impl NodeCtx {
    /// (нужен ли сосед, наша ли очередь открывать Link). Нужны: админ приглашения (открываем мы), соседи-транзиты по записям
    /// (открывает меньший dest) и кандидаты на зачисление (только несём носитель QUIC: Link откроет сам приглашённый).
    fn neighbor_policy(&self, d: &[u8; 16]) -> (bool, bool) {
        let Some(t) = &self.t13 else { return (true, self.my_dest < *d) };
        // stalled: сосед известен дольше 30 с, Link к нему нет (0014 R1: тупик меньшего dest, который не звонит)
        let (pk, tags, stalled) = {
            let n = self.neigh.lock().unwrap();
            match n.get(d) {
                Some(nb) => (nb.pk, nb.tags.clone(), nb.link.is_none() && nb.first_seen.elapsed() > Duration::from_secs(30)),
                None => return (false, false),
            }
        };
        // админ приглашения с адресом - звоним сами; без адреса (телефон) входящих Link он не принимает: только через посредника (R7)
        if t.invite.lock().unwrap().as_ref().map(|i| i.admin == pk).unwrap_or(false) {
            let direct = t.invite.lock().unwrap().as_ref().map(|i| !i.addrs.is_empty()).unwrap_or(false);
            return (direct, direct);
        }
        // Do not plan mesh Links to a leaf, even when an anchor grants it TRANSIT.
        // This announce bit is a scheduling hint only; evaluate() remains the authorization gate.
        let accepts_links = self.neigh.lock().unwrap().get(d).map(|n| n.accepts_links).unwrap_or(true);
        if !accepts_links {
            return (false, false);
        }
        // посредник зачисления (R7): носитель QUIC к нему поднимаем (maybe_dial), Link открывает node_relay_tick
        if t.invite.lock().unwrap().as_ref().map(|i| relay_match(i, &pk, &tags)).unwrap_or(false) {
            return (true, false);
        }
        let (transit, unknown) = {
            let tr = t.trust.lock().unwrap();
            (tr.common_with(&pk, trust::TRANSIT, trust::TRANSIT, true, true, now_ms() as u64), tr.rights(&pk) == 0)
        };
        if plan_transit_neighbor(accepts_links, transit) {
            // своя очередь, либо сосед не открыл Link за 30 с: открываем сами (встречный Link снимает admit_neighbor)
            return (true, self.my_dest < *d || stalled);
        }
        let pending_roots = trust::pin_roots_fresh(&self.state);
        if unknown && pending_roots.iter().any(|root| tags.contains(&trust::root_tag(root))) {
            return (true, false);
        }
        // записей, кроме своей, нет (соседи ещё не обменялись цепочками), сосед с тегом нашего якоря: открываем Link, допуск решит evaluate
        if stalled {
            let tr = t.trust.lock().unwrap();
            let anchor_hit = tr.anchors().iter().any(|(h, _)| tags.contains(&trust::root_tag(h)));
            if anchor_hit && tr.export_all().iter().all(|r| r.hh == tr.me_hash) {
                return (true, true);
            }
        }
        (false, false)
    }

    fn save_trust(&self) -> bool {
        if let Some(t) = &self.t13 {
            if let Err(e) = t.trust.lock().unwrap().save() {
                self.sh.note(format!("trust.json не записан: {e:#}"));
                return false;
            }
            return true;
        }
        false
    }

    /// H1: отложенная запись trust.json (записи от пиров); вызывает housekeeping раз в 2 с. При ошибке флаг возвращается.
    fn flush_trust(&self) {
        let Some(t) = &self.t13 else { return };
        if t.trust_dirty.swap(false, Relaxed) {
            if let Err(e) = t.trust.lock().unwrap().save() {
                t.trust_dirty.store(true, Relaxed);
                self.sh.note(format!("trust.json не записан: {e:#}"));
            }
        }
    }

    /// Отправить записи пиру по порядку (одна задача: порядок важен, издатель раньше подписанной им записи).
    fn send_recs(self: &Arc<Self>, link: LinkId, recs: Vec<trust::Record>) {
        self.send_recs_pols(link, recs, Vec::new());
    }

    /// Записи, затем политики - одной задачей: политика проверяется по записи держателя, раньше неё её отклонили бы как «неизвестный держатель».
    fn send_recs_pols(self: &Arc<Self>, link: LinkId, recs: Vec<trust::Record>, pols: Vec<trust::Policy>) {
        if recs.is_empty() && pols.is_empty() {
            return;
        }
        let node = self.node.clone();
        tokio::spawn(async move {
            for r in recs {
                send_ctl(&node, link, T_REC, &r.wire()).await;
            }
            for p in pols {
                send_ctl(&node, link, T_POL, &p.wire()).await;
            }
        });
    }

    /// Принять запись (от пира или из inbox13). Новая: сохранить, переслать, пересчитать роли открытых Link.
    fn accept_rec(self: &Arc<Self>, rec: trust::Record, from: Option<LinkId>) -> trust::Offer {
        let Some(t) = &self.t13 else { return trust::Offer::Rejected("нет модели 0013") };
        let off = t.trust.lock().unwrap().offer(rec.clone());
        if off == trust::Offer::Added {
            // запись на диск - через flush_trust (пачкой); take_inbox13 сохраняет сам перед удалением файла
            t.trust_dirty.store(true, Relaxed);
            self.forward_rec(&rec, from);
            self.enforce_rights();
        }
        off
    }

    /// Посредник (R6, T_DIR): каталог нод новичку - соседи с правом TRANSIT и адресом, не более DIR_MAX записей, кусками по DIR_CHUNK Б.
    /// Не чаще раза в 60 с на Link (инвариант 6). Адреса - подсказки: допуск по-прежнему по записям.
    fn send_dir(self: &Arc<Self>, link: LinkId) {
        let Some(t) = &self.t13 else { return };
        {
            let mut s = t.dir_sent.lock().unwrap();
            if s.get(&link).map(|x| x.elapsed() < Duration::from_secs(60)).unwrap_or(false) {
                return;
            }
            s.retain(|_, x| x.elapsed() < Duration::from_secs(60));
            if s.len() >= 256 {
                return;
            }
            s.insert(link, Instant::now());
        }
        let list: Vec<serde_json::Value> = {
            let tr = t.trust.lock().unwrap();
            let n = self.neigh.lock().unwrap();
            // ADR 0016: анонс адресов не несёт, поэтому первой строкой каталога - сама нода (адрес и имя из первых рук)
            let mut v: Vec<serde_json::Value> = Vec::new();
            let mine = self.adv();
            if !mine.is_empty() {
                v.push(serde_json::json!({"d": hex(&self.my_dest), "k": hex(&self.my_pk), "e": self.ep_id, "a": mine, "n": self.name}));
            }
            v.extend(n.values()
                .filter(|nb| !nb.addrs.is_empty() && tr.effective(&nb.pk, now_ms() as u64) & trust::TRANSIT != 0)
                .take(DIR_MAX - v.len())
                .map(|nb| {
                    let a: Vec<String> = nb.addrs.get().into_iter().take(3).collect();
                    serde_json::json!({"d": hex(&nb.dest), "k": hex(&nb.pk), "e": nb.ep, "a": a, "n": nb.name})
                }));
            v
        };
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut cur: Vec<serde_json::Value> = Vec::new();
        for e in list {
            cur.push(e);
            if cur.len() > 1 && serde_json::json!({"n": cur}).to_string().len() > DIR_CHUNK {
                let last = cur.pop().unwrap();
                chunks.push(serde_json::json!({"n": cur}).to_string().into_bytes());
                cur = vec![last];
            }
        }
        if !cur.is_empty() {
            chunks.push(serde_json::json!({"n": cur}).to_string().into_bytes());
        }
        if chunks.is_empty() {
            return;
        }
        let node = self.node.clone();
        tokio::spawn(async move {
            for c in chunks {
                send_ctl(&node, link, T_DIR, &c).await;
            }
        });
    }

    /// Посредник: запись о новичке пришла от админа. Новичку (его Link без прав, ключ известен по identify) - сразу запись и каталог.
    fn to_newcomer(self: &Arc<Self>, rec: &trust::Record) {
        let chain = self.t13.as_ref().map(|t| t.trust.lock().unwrap().chain_for(&rec.holder)).unwrap_or_default();
        let links: Vec<LinkId> = self.links.lock().unwrap().iter()
            .filter(|(_, l)| matches!(l.role, Role::Unknown) && l.peer_pk == Some(rec.holder))
            .map(|(k, _)| *k)
            .collect();
        for l in links {
            self.send_recs(l, chain.clone());
            self.send_dir(l);
        }
    }

    /// Соседям-серверам - всё; клиентам - только то, что вошло бы в их выгрузку (чужих пользователей клиенту не раскрываем).
    fn forward_rec(self: &Arc<Self>, rec: &trust::Record, except: Option<LinkId>) {
        let Some(t) = &self.t13 else { return };
        let targets: Vec<(LinkId, Option<[u8; 64]>)> = self.links.lock().unwrap().iter()
            .filter(|(k, _)| Some(**k) != except)
            .filter_map(|(k, i)| match i.role {
                Role::Server { .. } => Some((*k, None)),
                Role::Client { .. } => i.peer_pk.map(|p| (*k, Some(p))),
                _ => None,
            }).collect();
        if targets.is_empty() {
            return;
        }
        let send: Vec<LinkId> = {
            let tr = t.trust.lock().unwrap();
            targets.into_iter().filter(|(_, pk)| match pk {
                None => true,
                Some(p) => tr.export_for(trust::USE, p).contains(rec),
            }).map(|(k, _)| k).collect()
        };
        for l in send {
            spawn_ctl(&self.node, l, T_REC, rec.wire());
        }
    }

    /// Принять политику (от пира или свою). Новая: сохранить, переслать допущенным Link, пересчитать роли открытых Link.
    fn accept_pol(self: &Arc<Self>, pol: trust::Policy, from: Option<LinkId>) -> trust::Offer {
        let Some(t) = &self.t13 else { return trust::Offer::Rejected("нет модели 0013") };
        let off = t.trust.lock().unwrap().offer_policy(pol.clone(), now_ms() as u64);
        if off == trust::Offer::Added {
            t.trust_dirty.store(true, Relaxed);
            self.forward_pol(&pol, from);
            self.enforce_rights();
        }
        off
    }

    /// Допущенным Link (соседям и клиентам) - то, что вошло бы в их выгрузку политик. Цикл гасится проверкой `seq` при приёме.
    fn forward_pol(self: &Arc<Self>, pol: &trust::Policy, except: Option<LinkId>) {
        let Some(t) = &self.t13 else { return };
        let targets: Vec<(LinkId, u16, [u8; 64])> = self.links.lock().unwrap().iter()
            .filter(|(k, _)| Some(**k) != except)
            .filter_map(|(k, i)| match (&i.role, i.peer_pk) {
                (Role::Server { .. }, Some(p)) => Some((*k, trust::TRANSIT, p)),
                (Role::Client { .. }, Some(p)) => Some((*k, trust::USE, p)),
                _ => None,
            }).collect();
        if targets.is_empty() {
            return;
        }
        let now = now_ms() as u64;
        let send: Vec<LinkId> = {
            let tr = t.trust.lock().unwrap();
            targets.into_iter().filter(|(_, r, p)| tr.export_policies_for(*r, p, now).contains(pol)).map(|(k, _, _)| k).collect()
        };
        for l in send {
            spawn_ctl(&self.node, l, T_POL, pol.wire());
        }
    }

    /// Раз в несколько секунд: применить настройку, переподписать устаревающую политику и разослать.
    fn policy_tick(self: &Arc<Self>) {
        let Some(t) = &self.t13 else { return };
        let (pols, notes) = policy_step(&mut t.trust.lock().unwrap(), &self.state, false, now_ms() as u64);
        for n in notes {
            self.sh.note(n);
        }
        if pols.is_empty() {
            return;
        }
        t.trust_dirty.store(true, Relaxed);
        for p in &pols {
            self.forward_pol(p, None);
        }
        self.enforce_rights();
    }

    /// Переоценить все Link по текущим записям: права сняты - закрыть, права появились - допустить.
    fn enforce_rights(self: &Arc<Self>) {
        let ids: Vec<LinkId> = self.links.lock().unwrap().keys().copied().collect();
        for l in ids {
            self.evaluate(l);
        }
    }

    /// Роль Link определяют права пира, а не заявленная роль: сосед-транзит - взаимный TRANSIT в общем корне,
    /// клиент (прислал T_USE) - USE у него и EXIT у нас в общем корне.
    fn evaluate(self: &Arc<Self>, link: LinkId) {
        let Some(t) = &self.t13 else { return };
        let (pk, kind, want_use, enroll_only) = {
            let l = self.links.lock().unwrap();
            let Some(i) = l.get(&link) else { return };
            let Some(pk) = i.peer_pk else { return };
            let kind = match i.role {
                Role::Unknown => 0,
                Role::Server { .. } => 1,
                Role::Client { .. } => 2,
                _ => return,
            };
            (pk, kind, i.want_use, i.enroll_only)
        };
        if enroll_only {
            return;
        }
        // 0015: своё согласие (политика) учитывается, чужие права - по выдаче (чужой отказ исполняет он сам)
        let now = now_ms() as u64;
        let (srv_ok, cli_ok, cli_granted) = {
            let tr = t.trust.lock().unwrap();
            (tr.common_with(&pk, trust::TRANSIT, trust::TRANSIT, true, false, now), tr.common_with(&pk, trust::EXIT, trust::USE, true, false, now),
             tr.common(&pk, trust::EXIT, trust::USE))
        };
        match kind {
            1 => {
                if !srv_ok {
                    self.close_link(link, "права транзита сняты");
                }
            }
            2 => {
                if !cli_ok {
                    self.close_link(link, if cli_granted { "политика ноды: выход выключен" } else { "право USE снято" });
                }
            }
            _ => {
                if want_use {
                    if cli_ok {
                        self.admit_client13(link, pk);
                    } else if cli_granted {
                        // право есть, но нода сама выключила выход: клиент должен сразу перейти к другому, а не ждать таймаута.
                        // Политики выходов отдаём до отказа: иначе клиент не узнает, что другой выход снова включён, и застрянет без выбора
                        let pols = t.trust.lock().unwrap().export_policies_for(trust::USE, &pk, now);
                        let c = self.clone();
                        tokio::spawn(async move {
                            for p in pols {
                                send_ctl(&c.node, link, T_POL, &p.wire()).await;
                            }
                            send_ctl(&c.node, link, T_AUTH_FAIL, b"exit disabled by node policy").await;
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            c.close_link(link, "политика ноды: выход выключен");
                        });
                    }
                } else if srv_ok && !cli_ok {
                    // права однозначно соседские (транзит есть, USE нет) - сразу
                    self.admit_server13(link, pk);
                } else if srv_ok {
                    // Пир с обоими правами (например, телефон-админ с полными): сосед он или клиент - решает T_USE, а он может
                    // прийти позже identify из-за порядка доставки. Даём доле секунды и только затем берём его соседом.
                    let ctx = self.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        ctx.admit_server13(link, pk);
                    });
                }
            }
        }
    }

    fn admit_server13(self: &Arc<Self>, link: LinkId, pk: [u8; 64]) {
        let Some(t) = &self.t13 else { return };
        let dest = dest_of_pub(self, &pk);
        let opted_out = {
            let mut l = self.links.lock().unwrap();
            let Some(i) = l.get_mut(&link) else { return };
            if !matches!(i.role, Role::Unknown) || i.enroll_only {
                return;
            }
            // Check the latest known announcement while holding the role lock. If an
            // announce changes to lc=false immediately afterward, on_announce waits for this
            // lock and then closes the newly promoted Server Link.
            let accepts_links = self.neigh.lock().unwrap().values().find(|n| n.pk == pk).map(|n| n.accepts_links);
            if !server_promotion_allowed(i.enroll_only, accepts_links, true) {
                true
            } else {
                i.role = Role::Server { dest };
                false
            }
        };
        if opted_out {
            self.close_link(link, "пир отказался принимать соседские Link");
            return;
        }
        self.admit_neighbor(link, dest, &pk);
        let (recs, pols) = {
            let tr = t.trust.lock().unwrap();
            (tr.export_all(), tr.export_policies_for(trust::TRANSIT, &pk, now_ms() as u64))
        };
        self.send_recs_pols(link, recs, pols);
        self.send_dir(link);
        // Пир мог принять каталог раньше, чем присвоил Link роль Server (записи ещё обрабатываются): повтор через 5 с, помимо лимита 60 с
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Some(t) = &me.t13 {
                t.dir_sent.lock().unwrap().remove(&link);
            }
            if me.links.lock().unwrap().get(&link).map(|i| matches!(i.role, Role::Server { .. })).unwrap_or(false) {
                me.send_dir(link);
            }
        });
    }

    /// Книга адресов (ADR 0016): анонс адресов не несёт, поэтому адреса нод с правами хранятся на диске и переживают перезапуск.
    /// Не секрет и не право: подсказка для дозвона; допуск по-прежнему только по записям. Пишем, лишь когда содержимое изменилось.
    fn book_save(&self) {
        let Some(t) = &self.t13 else { return };
        let mut list: Vec<serde_json::Value> = {
            let tr = t.trust.lock().unwrap();
            let n = self.neigh.lock().unwrap();
            n.values()
                .filter(|nb| !nb.addrs.is_empty() && (tr.rights(&nb.pk) != 0 || trust::hash_of(&nb.pk).map(|h| tr.has_anchor(&h)).unwrap_or(false)))
                .map(|nb| serde_json::json!({"d": hex(&nb.dest), "k": hex(&nb.pk), "e": nb.ep, "a": nb.addrs.get().into_iter().take(3).collect::<Vec<_>>(), "n": nb.name}))
                .collect()
        };
        list.sort_by_key(|v| v["d"].as_str().unwrap_or("").to_string());
        list.truncate(BOOK_MAX);
        let body = serde_json::json!({"n": list}).to_string();
        let mut last = BOOK_LAST.lock().unwrap();
        if *last != body {
            write_atomic(&self.state.join("addr-book.json"), body.as_bytes());
            *last = body;
        }
    }

    fn book_load(&self) {
        let Some(t) = &self.t13 else { return };
        let Ok(body) = std::fs::read(self.state.join("addr-book.json")) else { return };
        if body.len() > 64 * 1024 {
            return;
        }
        let tr = t.trust.lock().unwrap();
        let mut n = self.neigh.lock().unwrap();
        for e in parse_dir_max(&body, &self.tag, BOOK_MAX) {
            if e.pk == self.my_pk || n.contains_key(&e.dest) || (tr.rights(&e.pk) == 0 && !trust::hash_of(&e.pk).map(|h| tr.has_anchor(&h)).unwrap_or(false)) {
                continue;
            }
            let key: [u8; 32] = e.pk[32..64].try_into().unwrap();
            n.insert(e.dest, Neighbor { dest: e.dest, key, pk: e.pk, name: e.name, ep: e.ep, addrs: Addrs::new(e.addrs), tags: vec![], accepts_links: true, last_announce: Instant::now(),
                link: None, last_heard: Instant::now() - Duration::from_secs(3600), rtt_ms: None, connecting: false, dialer: None, first_seen: Instant::now(),
                last_try: Instant::now() - Duration::from_secs(3600), ctl: CarrierCtl::new(), loss: LossWin::default(), ping_seq: 0, admitted_at: Instant::now(), seen_gen: 0 });
        }
    }

    /// Раз в 5 минут: каталог (адреса, имена) допущенным соседям-серверам. Анонс адресов не несёт (ADR 0016).
    fn dir_tick(self: &Arc<Self>) {
        let ids: Vec<LinkId> = self.links.lock().unwrap().iter().filter(|(_, l)| matches!(l.role, Role::Server { .. })).map(|(k, _)| *k).collect();
        for l in ids {
            self.send_dir(l);
        }
    }

    fn admit_client13(self: &Arc<Self>, link: LinkId, pk: [u8; 64]) {
        let Some(t) = &self.t13 else { return };
        if self.link_is_public(&link) {
            self.close_link(link, "клиент через публичную сеть RNS");
            return;
        }
        let Some(tun) = self.tun.clone() else {
            spawn_ctl(&self.node, link, T_AUTH_FAIL, b"no exit".to_vec());
            let c = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                c.close_link(link, "на этой ноде выход выключен");
            });
            return;
        };
        let Some(idh) = id_of_pub(&pk) else { return };
        let ip = client_ip(&idh);
        // H16: проверка адреса и назначение роли - под одной блокировкой links, иначе между ними другой Link займёт адрес
        let (clash, old): (bool, Vec<LinkId>) = {
            let mut l = self.links.lock().unwrap();
            // один адрес - один активный клиент: чужой Link с тем же адресом не вытесняется
            let clash = l.iter().any(|(k, i)| *k != link && matches!(i.role, Role::Client { ip: p, id, .. } if p == ip && id != idh));
            if clash {
                (true, Vec::new())
            } else {
                match l.get_mut(&link) {
                    Some(i) if matches!(i.role, Role::Unknown) => i.role = Role::Client { id: idh, ip },
                    _ => return,
                }
                // та же identity с нового Link (смена маршрута): старый Link закрываем
                let old = l.iter().filter(|(k, i)| **k != link && matches!(i.role, Role::Client { id, .. } if id == idh)).map(|(k, _)| *k).collect();
                (false, old)
            }
        };
        if clash {
            spawn_ctl(&self.node, link, T_AUTH_FAIL, b"address clash".to_vec());
            self.close_link(link, "конфликт адреса клиента");
            return;
        }
        for o in old {
            self.close_link(o, "новый Link той же identity");
        }
        tun.allow(&self.node, link, ip);
        let pl = self.client_info.lock().unwrap().get(&link).map(|(_, p)| *p).unwrap_or("?");
        self.sh.note(format!("client {} ({pl}) admitted on {}", &hex(&idh)[..8], &hex(link.as_bytes())[..8]));
        let recs = t.trust.lock().unwrap().export_for(trust::USE, &pk);
        let pols = t.trust.lock().unwrap().export_policies_for(trust::USE, &pk, now_ms() as u64);
        let ok = serde_json::json!({"name": self.name, "ip": ip_str(ip), "cc": REGION.get().cloned().unwrap_or_default(), "pl": platform()}).to_string().into_bytes();
        let c = self.clone();
        tokio::spawn(async move {
            send_ctl(&c.node, link, T_AUTH_OK, &ok).await;
            // новому клиенту соседей шлём всегда (0014 R3)
            c.send_nbrs(link);
            c.send_recs_pols(link, recs, pols);
        });
    }

    /// Записи, подписанные командами grant/revoke: файлы hex в inbox13 (CLI не владеет сетью, подписывает только identity из state).
    /// H15: принятая или уже известная (Added/Stale) запись сохраняется на диск и только потом удаляется файл; отвергнутая
    /// переименовывается в `.rejected` с причиной в note, чтобы отзыв не терялся молча. Такие файлы не удаляются (AGENTS: отзывы не удалять).
    fn take_inbox13(self: &Arc<Self>) {
        let Ok(rd) = std::fs::read_dir(self.state.join("inbox13")) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "tmp" || x == "rejected").unwrap_or(false) {
                continue;
            }
            let rec = std::fs::read_to_string(&p).ok().and_then(|txt| trust::Record::parse(&unhex(txt.trim())));
            let off = match rec {
                Some(rec) => self.accept_rec(rec, None),
                None => trust::Offer::Rejected("файл не прочитан или не разобран"),
            };
            match off {
                trust::Offer::Rejected(why) => {
                    self.sh.note(format!("inbox13: запись отклонена: {why}"));
                    let _ = std::fs::rename(&p, p.with_extension("rejected"));
                }
                off => {
                    self.sh.note(format!("inbox13: запись {off:?}"));
                    self.save_trust();
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
}

/// H10: ведро частоты управляющих сообщений одного Link.
struct CtrlBucket {
    tokens: f64,
    at: Instant,
    /// начало текущей серии отбрасываний (серия не прерывается паузой больше секунды)
    run_start: Option<Instant>,
    last_drop: Option<Instant>,
}

/// Решение ведра по одному управляющему сообщению.
#[derive(Debug, PartialEq)]
enum CtrlVerdict {
    Pass,
    /// `first` - первое отбрасывание серии (по нему одна запись в журнал)
    Drop { first: bool },
    Close,
}

impl CtrlBucket {
    fn new(now: Instant) -> Self {
        Self { tokens: CTRL_BURST, at: now, run_start: None, last_drop: None }
    }

    fn take(&mut self, now: Instant) -> CtrlVerdict {
        let el = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + el * CTRL_RATE).min(CTRL_BURST);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return CtrlVerdict::Pass;
        }
        let first = self.last_drop.map(|t| now.saturating_duration_since(t) > Duration::from_secs(1)).unwrap_or(true);
        if first {
            self.run_start = Some(now);
        }
        self.last_drop = Some(now);
        let start = self.run_start.unwrap_or(now);
        if now.saturating_duration_since(start) >= CTRL_VIOLATION_CLOSE {
            return CtrlVerdict::Close;
        }
        CtrlVerdict::Drop { first }
    }
}

/// B (клиент): вердикт ведра для Link (тот же `CtrlBucket`, что у ноды). Новый Link сверх `CLIENT_CTRL_LINKS` ведра не получает - `None`, сообщение отбросить.
/// Link при этом не закрываем: на клиенте это может быть текущий выход, а закрытие оборвало бы VPN; лишние управляющие сообщения просто не обрабатываются.
fn client_ctrl_pass<K: Eq + std::hash::Hash>(m: &mut HashMap<K, CtrlBucket>, key: K, now: Instant) -> Option<CtrlVerdict> {
    if !m.contains_key(&key) && m.len() >= CLIENT_CTRL_LINKS {
        return None;
    }
    Some(m.entry(key).or_insert_with(|| CtrlBucket::new(now)).take(now))
}

/// S2/S3: решение о месте для новой записи соседа.
#[derive(Debug, PartialEq)]
enum NeighborRoom {
    Free,
    /// вытеснить эту запись (всегда без права и без Link)
    Evict([u8; 16]),
    /// места нет: защищённые записи не вытесняются
    Full,
}

/// S2/S3: `entries` - (dest, защищена, last_announce) по всем записям. Защищена запись с TRANSIT по записям или с живым Link:
/// её не вытесняем никогда. Незащищённых не более MAX_UNTRUSTED_NEIGHBORS; при полной таблице или переполнении незащищённых
/// вытесняется самая давняя по анонсу незащищённая запись. Новый анонс без права не вытесняет защищённого соседа.
fn neighbor_room(entries: &[([u8; 16], bool, Instant)], new_protected: bool) -> NeighborRoom {
    let untrusted = entries.iter().filter(|e| !e.1).count();
    let oldest = entries.iter().filter(|e| !e.1).min_by_key(|e| e.2).map(|e| e.0);
    if !new_protected && untrusted >= MAX_UNTRUSTED_NEIGHBORS {
        return oldest.map(NeighborRoom::Evict).unwrap_or(NeighborRoom::Full);
    }
    if entries.len() < MAX_NEIGHBORS {
        return NeighborRoom::Free;
    }
    oldest.map(NeighborRoom::Evict).unwrap_or(NeighborRoom::Full)
}

/// H9: запись в буфер `early` с квотой на Link; `false` - квота исчерпана, запись отброшена.
fn early_push(buf: &mut Vec<(LinkId, trust::Record)>, link: LinkId, rec: trust::Record, root: &trust::Hash) -> bool {
    if rec.root != *root { return false; }
    if buf.len() >= EARLY_MAX {
        // Буфер содержит только неподтверждённые записи. Вытесняем старейшую,
        // чтобы посторонние записи того же корня не блокировали нужную цепочку.
        buf.remove(0);
    }
    if buf.iter().filter(|(l, _)| *l == link).count() >= EARLY_PER_LINK {
        if let Some(i) = buf.iter().position(|(l, _)| *l == link) { buf.remove(i); }
    }
    buf.push((link, rec));
    true
}

const PAIRQ_LEN: usize = 16 + 16 + 64 + 32;

fn pairq_body(root: trust::Hash, inviter: trust::Hash, holder: &[u8; 64], mac: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(PAIRQ_LEN);
    body.extend_from_slice(&root);
    body.extend_from_slice(&inviter);
    body.extend_from_slice(holder);
    body.extend_from_slice(mac);
    body
}

fn parse_pairq(body: &[u8]) -> Option<(trust::Hash, trust::Hash, [u8; 64], [u8; 32])> {
    if body.len() != PAIRQ_LEN { return None; }
    Some((body[..16].try_into().ok()?, body[16..32].try_into().ok()?,
        body[32..96].try_into().ok()?, body[96..128].try_into().ok()?))
}

fn pairq_client_matches(inviter: &trust::Hash, me: &trust::Hash, root: &trust::Hash, pin_root: &trust::Hash) -> bool {
    inviter == me && root == pin_root
}

fn enrollment_proof(me: &Identity, inv: &trust::Invite, records: &[trust::Record]) -> Option<Vec<trust::Record>> {
    let root = inv.root().ok()?;
    records.iter().filter(|r| inv.enroll_hit(&me.public_key_bytes(), r)).find_map(|cand| {
        // Передаём только ветки, влияющие на кандидата: его выдачи/отзывы и цепочки издателей.
        // Сортировка делает результат независимым от порядка прихода T_REC.
        let mut relevant = vec![cand.clone()];
        let mut wanted = vec![cand.issuer];
        let mut issuers = HashSet::from([cand.issuer]);
        for r in records.iter().filter(|r| r.root == root && r.hh == cand.hh) {
            if issuers.contains(&r.issuer) {
                if !relevant.contains(r) { relevant.push(r.clone()); }
            } else if issuers.len() < trust::MAX_DEPTH {
                issuers.insert(r.issuer);
                relevant.push(r.clone());
            }
            if r.issuer != root && !wanted.contains(&r.issuer) { wanted.push(r.issuer); }
        }
        let mut i = 0;
        while i < wanted.len() && issuers.len() <= trust::MAX_DEPTH {
            let who = wanted[i]; i += 1;
            for r in records.iter().filter(|r| r.root == root && r.hh == who) {
                if !relevant.contains(r) && (issuers.contains(&r.issuer) || issuers.len() < trust::MAX_DEPTH) {
                    issuers.insert(r.issuer);
                    relevant.push(r.clone());
                    if r.issuer != root && !wanted.contains(&r.issuer) { wanted.push(r.issuer); }
                }
            }
        }
        relevant.sort_by_key(|r| (r.issuer, r.hh, r.seq, r.rights));
        let root_pk = inv.root_pk().ok()?;
        trust::verify_enrollment(me, &root_pk, inv.created, cand, &relevant).ok()
    })
}

fn invite_used(inv: &trust::Invite, me: &trust::Pk, records: &[trust::Record]) -> bool {
    let (Ok(root), Ok(admin)) = (inv.root(), inv.admin_hash()) else { return false };
    records.iter().any(|r| r.root == root && r.issuer == admin && r.holder == *me
        && r.seq >= inv.created.saturating_mul(1000))
}

/// Повтор отдаёт именно свою выдачу только пока участник имеет действующие права в заданном корне.
fn repeat_record(tr: &trust::Trust, root: &trust::Hash, holder: &trust::Pk, issuer: &trust::Hash) -> Option<trust::Record> {
    let hh = trust::hash_of(holder)?;
    if tr.rights_in(root, &hh) == 0 { return None; }
    tr.chain_for(holder).into_iter().find(|r| r.root == *root && r.hh == hh && r.holder == *holder
        && r.issuer == *issuer && r.rights != 0)
}

/// Посредник зачисления (R7): открыто приглашение без адресов админа, пир несёт тег корня админа (и входит в nodes приглашения, если они заданы).
/// Сам админ посредником не бывает. Адрес посредника проверяет вызывающий.
fn relay_match(inv: &trust::Invite, pk: &[u8; 64], tags: &[String]) -> bool {
    let Ok(root) = inv.root() else { return false };
    if !inv.addrs.is_empty() || *pk == inv.admin || !tags.contains(&trust::root_tag(&root)) {
        return false;
    }
    inv.nodes.is_empty() || trust::hash_of(pk).map(|h| inv.nodes.contains(&h)).unwrap_or(false)
}

/// R7 (0014): нода с приглашением без адресов админа просится к нему через посредника (сосед с тегом корня админа и адресом).
/// Попытка: если анонс админа виден за 15 мин - каждому посреднику не чаще раза в 60 с; иначе - не чаще раза в 10 мин (запасной вариант).
/// Link открывает connect_neighbor (путь через наши узлы); дальше on_peer_ready шлёт T_PAIRQ.
fn node_relay_tick(ctx: &Arc<NodeCtx>) {
    let Some(t) = &ctx.t13 else { return };
    let Some(inv) = t.invite.lock().unwrap().clone() else { return };
    if !inv.addrs.is_empty() {
        return; // адрес админа известен: прямой T_PAIR1 (on_peer_ready)
    }
    let fresh = t.admin_seen.lock().unwrap().map(|x| x.elapsed() < Duration::from_secs(15 * 60)).unwrap_or(false);
    let last_any = t.relay_try.lock().unwrap().values().max().copied();
    if !fresh && last_any.map(|x| x.elapsed() < Duration::from_secs(600)).unwrap_or(false) {
        return;
    }
    // на посредника, с которым Link уже есть (или строится), вторую попытку не открываем
    let linked: HashSet<[u8; 64]> = ctx.links.lock().unwrap().values().filter_map(|l| l.peer_pk).collect();
    let cand = {
        let n = ctx.neigh.lock().unwrap();
        let tries = t.relay_try.lock().unwrap();
        n.values()
            .filter(|nb| relay_match(&inv, &nb.pk, &nb.tags) && !nb.addrs.is_empty() && nb.link.is_none() && !linked.contains(&nb.pk))
            .filter(|nb| tries.get(&nb.dest).map(|x| x.elapsed() >= Duration::from_secs(60)).unwrap_or(true))
            .min_by_key(|nb| tries.get(&nb.dest).copied())
            .map(|nb| (nb.dest, nb.name.clone()))
    };
    let Some((dest, name)) = cand else { return };
    t.relay_try.lock().unwrap().insert(dest, Instant::now());
    ctx.sh.note(format!("зачисление: прошусь к админу через посредника {name} ({})", &hex(&dest)[..8]));
    let c = ctx.clone();
    tokio::spawn(async move { connect_neighbor(c, dest).await });
}

/// Запрос зачисления через посредника: T_PAIRQ раз в 6 с, до 24 с или до зачисления (Link без прав живёт до 30 с, см. node_housekeeping).
async fn relay_pairq(ctx: Arc<NodeCtx>, link: LinkId, inv: trust::Invite) {
    let Some(t) = &ctx.t13 else { return };
    let (Ok(root), Ok(admin), Ok(mac)) = (inv.root(), inv.admin_hash(), inv.mac(&ctx.my_pk)) else { return };
    let body = pairq_body(root, admin, &ctx.my_pk, &mac);
    let t0 = Instant::now();
    let mut last = Instant::now() - Duration::from_secs(60);
    while t0.elapsed() < Duration::from_secs(24) {
        if t.invite.lock().unwrap().is_none() {
            break;
        }
        if last.elapsed() >= Duration::from_secs(6) {
            last = Instant::now();
            send_ctl(&ctx.node, link, T_PAIRQ, &body).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Запись каталога T_DIR: подсказка адреса (недоверенная). Допуск - только по записям о правах.
struct DirEnt {
    dest: [u8; 16],
    pk: [u8; 64],
    ep: String,
    addrs: Vec<String>,
    name: String,
    /// тип платформы узла («android»/«ios»/«server») - для значка в интерфейсе
    pl: Option<String>,
}

/// Разбор T_DIR: не более DIR_MAX записей; dest обязан совпасть с ключом (тег `tag`); без адресов запись бесполезна.
fn parse_dir(body: &[u8], tag: &str) -> Vec<DirEnt> {
    parse_dir_max(body, tag, DIR_MAX)
}

fn parse_dir_max(body: &[u8], tag: &str, max: usize) -> Vec<DirEnt> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else { return vec![] };
    let arr = v["n"].as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for x in arr.iter().take(max) {
        let Some(pk) = x["k"].as_str().and_then(|k| <[u8; 64]>::try_from(unhex(k)).ok()) else { continue };
        let Some(dest) = x["d"].as_str().and_then(dest32) else { continue };
        if dest_from_pub_tag(&pk, tag) != dest {
            continue;
        }
        let addrs: Vec<String> = x["a"].as_array().map(|a| a.iter().filter_map(|s| s.as_str().filter(|s| s.len() <= 64).map(String::from)).take(3).collect()).unwrap_or_default();
        if addrs.is_empty() {
            continue;
        }
        let ep = x["e"].as_str().filter(|s| s.len() <= 64).unwrap_or("").to_string();
        let name: String = x["n"].as_str().unwrap_or("?").chars().take(32).collect();
        let pl = x["pl"].as_str().and_then(|s| parse_platform(s.as_bytes())).map(String::from);
        out.push(DirEnt { dest, pk, ep, addrs, name, pl });
    }
    out
}

/// T_DIR от посредника зачисления (R6): адреса нод каталога - подсказки для диалера. Принимаем только от Link, через который сами просимся.
fn on_dir_node(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    let Some(t) = &ctx.t13 else { return };
    // Принимаем от посредника, к которому сами просимся, и от допущенного соседа-сервера (роль Server даётся только за взаимный TRANSIT).
    let sender = ctx.links.lock().unwrap().get(&link).and_then(|i| if matches!(i.role, Role::Server { .. }) { i.peer_pk } else { None });
    if body.len() > 1024 || !(sender.is_some() || t.pair_sent.lock().unwrap().contains(&link)) {
        return;
    }
    for e in parse_dir(body, &ctx.tag) {
        if e.pk == ctx.my_pk {
            continue;
        }
        // S2/S3: каталог не занимает место защищённых соседей (см. neighbor_room)
        {
            let mut n = ctx.neigh.lock().unwrap();
            if let Some(nb) = n.get_mut(&e.dest) {
                // адрес ноды, пришедший от неё самой по её Link, актуальнее прежнего; о третьих лицах - только если своего нет
                let own = sender == Some(e.pk);
                if nb.addrs.is_empty() || own {
                    nb.addrs.set(e.addrs);
                }
                if (own || nb.name == "?") && e.name != "?" {
                    nb.name = e.name;
                }
                if nb.ep.is_empty() {
                    nb.ep = e.ep;
                }
                continue;
            }
        }
        match ctx.neighbor_room_for(&e.pk) {
            NeighborRoom::Full => break,
            NeighborRoom::Evict(v) => ctx.evict_neighbor(&v),
            NeighborRoom::Free => {}
        }
        let mut n = ctx.neigh.lock().unwrap();
        let key: [u8; 32] = e.pk[32..64].try_into().unwrap();
        // соседство решают записи (neighbor_policy/evaluate), не этот каталог; tags пусты до анонса; срок забывания - от now
        n.insert(e.dest, Neighbor { dest: e.dest, key, pk: e.pk, name: e.name, ep: e.ep, addrs: Addrs::new(e.addrs), tags: vec![], accepts_links: true, last_announce: Instant::now(),
            link: None, last_heard: Instant::now() - Duration::from_secs(3600), rtt_ms: None, connecting: false, dialer: None, first_seen: Instant::now(),
            last_try: Instant::now() - Duration::from_secs(3600), ctl: CarrierCtl::new(), loss: LossWin::default(), ping_seq: 0, admitted_at: Instant::now(), seen_gen: 0 });
    }
}

/// Пир доказал свой ключ (identify): предъявляем свою цепочку прав, при ожидающем приглашении просимся к его админу, оцениваем роль.
fn on_peer_ready(ctx: &Arc<NodeCtx>, link: LinkId, pk: [u8; 64]) {
    let Some(t) = &ctx.t13 else { return };
    let inv = t.invite.lock().unwrap().clone();
    let direct_enrollment = inv.as_ref().map(|i| i.admin == pk).unwrap_or(false);
    {
        let mut l = ctx.links.lock().unwrap();
        let Some(i) = l.get_mut(&link) else { return };
        i.peer_pk = Some(pk);
        // Set before sending records or evaluating rights: invite cleanup must not turn this
        // direct pairing Link into a persistent Server neighbor.
        i.enroll_only |= direct_enrollment;
    }
    let chain = t.trust.lock().unwrap().chain_for(&ctx.my_pk);
    ctx.send_recs(link, chain);
    if let Some(inv) = inv {
        if inv.admin == pk && t.pair_sent.lock().unwrap().insert(link) {
            let mut body = ctx.my_pk.to_vec();
            let Ok(mac) = inv.mac(&ctx.my_pk) else { return };
            body.extend_from_slice(&mac);
            spawn_ctl(&ctx.node, link, T_PAIR1, body);
            ctx.sh.note("зачисление: запрос отправлен админу приглашения".to_string());
            // анонс адреса не несёт (ADR 0016): админ узнаёт его здесь, по зашифрованному Link, и сможет сделать ноду выходом
            ctx.send_dir(link);
        }
        // R7: админ без адреса - просимся к нему через посредника (сосед с тегом корня админа)
        let tags = ctx.neigh.lock().unwrap().values().find(|n| n.pk == pk).map(|n| n.tags.clone()).unwrap_or_default();
        if relay_match(&inv, &pk, &tags) && t.pair_sent.lock().unwrap().insert(link) {
            tokio::spawn(relay_pairq(ctx.clone(), link, inv.clone()));
        }
    }
    ctx.evaluate(link);
}

/// T_POL: политика приходит только по допущенному Link (сосед или клиент). Проверки - в `Trust::offer_policy`; число политик ограничено числом
/// держателей с выдачей, частота - ведром `CtrlBucket`.
fn on_pol(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    POL_RX.fetch_add(1 + body.len() as u64, Relaxed);
    POL_RX_N.fetch_add(1, Relaxed);
    if ctx.t13.is_none() || body.len() != trust::POL_LEN {
        return;
    }
    let admitted = matches!(ctx.links.lock().unwrap().get(&link).map(|l| &l.role), Some(Role::Server { .. } | Role::Client { .. }));
    if !admitted {
        return;
    }
    let Some(pol) = trust::Policy::parse(body) else { return };
    if let trust::Offer::Rejected(why) = ctx.accept_pol(pol, Some(link)) {
        ctx.sh.note(format!("политика отклонена: {why}"));
    }
}

fn on_rec(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    let Some(t) = &ctx.t13 else { return };
    if body.len() != trust::REC_LEN {
        return;
    }
    if peer_of(ctx, &link).is_none() {
        return;
    }
    let Some(rec) = trust::Record::parse(body) else { return };
    let pending_inv = t.invite.lock().unwrap().clone();
    let mut done = false;
    if let Some(inv) = pending_inv.as_ref() {
        if inv.root().ok() == Some(rec.root) {
            let mut early = t.early.lock().unwrap();
            let _ = early_push(&mut early, link, rec.clone(), &rec.root);
            let records: Vec<trust::Record> = early.iter().map(|(_, r)| r.clone()).collect();
            if let Some(proof) = enrollment_proof(&ctx.identity, inv, &records) {
                let Ok(root_pk) = inv.root_pk() else { return };
                let mut tr = t.trust.lock().unwrap();
                if tr.add_anchor(&root_pk).is_ok() {
                    for r in proof { let _ = tr.offer(r); }
                    *t.invite.lock().unwrap() = None;
                    done = true;
                }
            }
        }
    }
    let off = if pending_inv.as_ref().and_then(|i| i.root().ok()) == Some(rec.root) && !done {
        trust::Offer::Rejected("чужой корень")
    } else {
        ctx.accept_rec(rec.clone(), Some(link))
    };
    if done {
        // После проверки цепочки якорь уже добавлен; буферизованные записи того же корня теперь можно принять.
        let early = std::mem::take(&mut *t.early.lock().unwrap());
        for (_, r) in early {
            ctx.accept_rec(r, Some(link));
        }
        ctx.save_trust();
        ctx.sh.note("зачисление подтверждено цепочкой до корня приглашения; приглашение больше не используется".to_string());
        ctx.trigger_announce();
        let enroll_only = ctx.links.lock().unwrap().get(&link).map(|i| i.enroll_only).unwrap_or(false);
        if enroll_only {
            // Drain the signed record chain before closing this direct pairing Link. Check the
            // same LinkId and role at expiry so a valid relay/server Link is never torn down.
            let c = ctx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let pairing_unknown = c.links.lock().unwrap().get(&link)
                    .map(|i| i.enroll_only && matches!(i.role, Role::Unknown))
                    .unwrap_or(false);
                if pairing_unknown {
                    c.close_link(link, "прямое зачисление завершено");
                }
            });
        }
    }
    if off == trust::Offer::Added {
        // если это посредник (новичок ждёт на Link без прав) - запись о новичке и каталог ему сразу
        ctx.to_newcomer(&rec);
    }
    ctx.evaluate(link);
}

/// Админ: нода просится по приглашению. pin гасится за её ключом; тот же ключ повторно получает ту же запись, другой - отказ.
async fn on_pair1(ctx: Arc<NodeCtx>, link: LinkId, body: Vec<u8>) {
    let Some(t) = &ctx.t13 else { return };
    if body.len() != 64 + 32 {
        return;
    }
    let Some(peer) = peer_of(&ctx, &link) else { return };
    let holder: [u8; 64] = body[..64].try_into().unwrap();
    if holder != peer || ctx.link_is_public(&link) {
        ctx.close_link(link, "зачисление: ключ не совпал с identify или link через публичную сеть");
        return;
    }
    let now_s = now_ms() as u64 / 1000;
    let claim = trust::pin_claim(&ctx.state, &ctx.my_pk, &holder, &body[64..], now_s);
    let my_hash = ctx.my_id;
    let Some(hh) = id_of_pub(&holder) else { return };
    let rec = match claim {
        trust::Claim::New { rights, root } => {
            let r = t.trust.lock().unwrap().issue(root, holder, rights);
            match r {
                Ok(r) => {
                    if !ctx.save_trust() {
                        trust::pin_unclaim(&ctx.state, &ctx.my_pk, &holder, &body[64..]);
                        return;
                    }
                    ctx.sh.note(format!("зачисление: {} получила права {}", &hex(&hh)[..8], trust::rights_text(r.rights)));
                    Some(r)
                }
                Err(e) => {
                    // H8: выдача не удалась - возвращаем pin, приглашение не сгорает
                    trust::pin_unclaim(&ctx.state, &ctx.my_pk, &holder, &body[64..]);
                    ctx.sh.note(format!("зачисление: запись не выдана: {e:#}"));
                    None
                }
            }
        }
        trust::Claim::Repeat { root } => {
            let tr = t.trust.lock().unwrap();
            let found = repeat_record(&tr, &root, &holder, &my_hash);
            if found.is_none() {
                drop(tr);
                trust::pin_unclaim(&ctx.state, &ctx.my_pk, &holder, &body[64..]);
                ctx.sh.note("зачисление: незавершённое погашение возвращено; повторите запрос".to_string());
                return;
            }
            found
        }
        other => {
            let why = match other {
                trust::Claim::Spent => "приглашение уже использовано",
                trust::Claim::Expired => "приглашение просрочено",
                _ => "приглашение неизвестно этому админу",
            };
            ctx.sh.note(format!("зачисление отклонено: {why}"));
            spawn_ctl(&ctx.node, link, T_PAIR_NO, why.as_bytes().to_vec());
            tokio::time::sleep(Duration::from_millis(500)).await;
            ctx.close_link(link, why);
            return;
        }
    };
    let Some(rec) = rec else {
        spawn_ctl(&ctx.node, link, T_PAIR_NO, "запись не выдана".as_bytes().to_vec());
        return;
    };
    // Сначала полная цепочка R→…→D→N, затем остальная выгрузка по правам.
    let (chain, rest) = {
        let tr = t.trust.lock().unwrap();
        let chain = tr.chain_for(&holder);
        let rest: Vec<trust::Record> = tr.export_for(rec.rights, &holder).into_iter().filter(|r| !chain.contains(r)).collect();
        (chain, rest)
    };
    ctx.send_recs(link, chain);
    ctx.send_recs(link, rest);
    ctx.forward_rec(&rec, Some(link));
    ctx.evaluate(link);
    // Link под зачисление нужен только на это; если новичок не стал соседом-транзитом, закрываем
    tokio::time::sleep(Duration::from_secs(2)).await;
    if matches!(ctx.links.lock().unwrap().get(&link).map(|l| &l.role), Some(Role::Unknown)) {
        ctx.close_link(link, "зачисление завершено");
    }
}

/// Нода: админ приглашения отказал. Приглашение одноразовое, повтор не поможет - завершаемся.
fn on_pair_no(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    let Some(t) = &ctx.t13 else { return };
    let Some(peer) = peer_of(ctx, &link) else { return };
    if !t.invite.lock().unwrap().as_ref().map(|i| i.admin == peer).unwrap_or(false) {
        return;
    }
    let why: String = String::from_utf8_lossy(body).chars().take(80).collect();
    ctx.sh.note(format!("зачисление отклонено админом: {why}"));
    eprintln!("зачисление отклонено админом: {why}");
    std::process::exit(3);
}

/// Посредник зачисления пользователя. Админ (телефон) и новичок оба за NAT и друг до друга не дозвонятся, поэтому новичок приходит к любой
/// ноде, признающей этого админа якорем. Запись о новичке уже есть - отдаём её с выгрузкой выходов; иначе пересылаем запрос клиентскому Link
/// админа и соседям-серверам. Подлинность проверяет только админ: mac привязан к pin, holder и ключу админа, нода его проверить не может.
fn on_pairq(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    let Some(t) = &ctx.t13 else { return };
    let Some((root, inviter_h, holder, mac)) = parse_pairq(body) else { return };
    let (from_user, from_server) = {
        let l = ctx.links.lock().unwrap();
        let Some(i) = l.get(&link) else { return };
        (matches!(i.role, Role::Unknown) && i.peer_pk == Some(holder), matches!(i.role, Role::Server { .. }))
    };
    if !from_user && !from_server {
        return;
    }
    let Some(hh) = id_of_pub(&holder) else { return };
    {
        let tr = t.trust.lock().unwrap();
        if !tr.has_anchor(&root) {
            return;
        }
        if from_user {
            let rights = tr.rights_in(&root, &hh);
            if rights != 0 {
                let mut recs = tr.export_for(rights, &holder);
                drop(tr);
                // запись о самом новичке первой: по ней он признаёт админа якорем, остальные записи до этого отклонил бы как чужой корень
                recs.sort_by_key(|r| !(r.holder == holder && r.root == root));
                ctx.sh.note(format!("зачисление пользователя {}: запись уже есть, отдаю", &hex(&hh)[..8]));
                ctx.send_recs(link, recs);
                ctx.send_dir(link);
                return;
            }
        }
    }
    {
        let mut seen = t.pairq_seen.lock().unwrap();
        seen.retain(|_, (w, _)| w.elapsed() < Duration::from_secs(60));
        if seen.get(&mac).map(|(w, _)| w.elapsed() < Duration::from_secs(8)).unwrap_or(false) || seen.len() >= 256 {
            return;
        }
        // H9: новых запросов с одного Link - не больше PAIRQ_PER_LINK за 60 с, чтобы мусор одного пира не вытеснял чужие
        let from_link = seen.values().filter(|(_, l)| *l == link).count();
        if !seen.contains_key(&mac) && from_link >= PAIRQ_PER_LINK {
            return;
        }
        seen.insert(mac, (Instant::now(), link));
    }
    let targets: Vec<LinkId> = ctx.links.lock().unwrap().iter()
        .filter(|(k, _)| **k != link)
        .filter(|(_, i)| match i.role {
            Role::Server { .. } => true,
            Role::Client { id, .. } => id == inviter_h,
            _ => false,
        }).map(|(k, _)| *k).collect();
    if from_user {
        ctx.sh.note(format!("зачисление пользователя {}: пересылаю админу ({} Link)", &hex(&hh)[..8], targets.len()));
    }
    for l in targets {
        spawn_ctl(&ctx.node, l, T_PAIRQ, body.to_vec());
    }
}

impl NodeCtx {
    fn admit_neighbor(self: &Arc<Self>, link: LinkId, dest: [u8; 16], pk: &[u8; 64]) {
        if self.link_is_public(&link) {
            self.sh.note("серверный Link пришёл через публичную сеть RNS: отклонён (пути между нашими узлами только через наши узлы)".to_string());
            self.close_link(link, "link через публичную сеть");
            return;
        }
        {
            let mut n = self.neigh.lock().unwrap();
            let mut key = [0u8; 32];
            key.copy_from_slice(&pk[32..64]);
            let e = n.entry(dest).or_insert_with(|| Neighbor { dest, key, pk: *pk, name: "?".into(), ep: String::new(), addrs: Addrs::new(vec![]), tags: vec![], accepts_links: true, last_announce: Instant::now(),
                link: None, last_heard: Instant::now(), rtt_ms: None, connecting: false, dialer: None, first_seen: Instant::now(), last_try: Instant::now() - Duration::from_secs(3600), ctl: CarrierCtl::new(), loss: LossWin::default(), ping_seq: 0, admitted_at: Instant::now(), seen_gen: 0 });
            // второй Link от того же соседа (встречное рукопожатие): оставляем с меньшим идентификатором, второй закрываем
            if let Some(old) = e.link {
                if old != link {
                    let keep_new = link.as_bytes() < old.as_bytes();
                    let drop_id = if keep_new { old } else { link };
                    if keep_new {
                        e.link = Some(link);
                    }
                    e.connecting = false;
                    e.last_heard = Instant::now();
                    drop(n);
                    self.close_link(drop_id, "дубликат серверного link");
                    self.broadcast_registry();
                    return;
                }
            }
            e.link = Some(link);
            e.connecting = false;
            e.last_heard = Instant::now();
            e.admitted_at = Instant::now();
            e.loss.clear();
            self.sh.note(format!("сосед {} допущен ({})", e.name, if self.t13.is_some() { "права транзита подтверждены записями" } else { "серверный секрет подтверждён взаимно" }));
        }
        // с задержкой: реестр не должен обогнать SRV4 на стороне инициатора (там сообщение принимается только от допущенного сервера)
        self.send_registry(link, 400);
    }

    /// Отозванных клиентов отключаем сразу: закрываем их открытые Link.
    fn enforce_revocations(self: &Arc<Self>) {
        let revoked: Vec<LinkId> = {
            let reg = self.reg.lock().unwrap();
            self.links.lock().unwrap().iter().filter(|(_, l)| matches!(l.role, Role::Client { id, .. } if reg.active(&hex(&id)).is_none())).map(|(k, _)| *k).collect()
        };
        for l in revoked {
            self.close_link(l, "клиент отозван");
        }
    }
}

async fn node_housekeeping(ctx: Arc<NodeCtx>) {
    let mut tick = 0u64;
    let mut lost_listener = 0u32;
    let mut last_ping = Instant::now();
    let mut last_table = Instant::now();
    let inbox = ctx.state.join("inbox");
    let _ = std::fs::create_dir_all(&inbox);
    let _ = std::fs::create_dir_all(ctx.state.join("bench"));
    let fin = ctx.state.join("fin");
    while !fin.exists() {
        tokio::time::sleep(Duration::from_millis(500)).await;
        tick += 1;
        let now = Instant::now();

        // сторож слушателя: если сокет пропал (смена сетевых интерфейсов и т. п.), завершаемся - systemd перезапустит
        if tick % 10 == 0 {
            if !ctx.ep.bound_sockets().iter().any(|a| a.port() == ctx.listen_port) {
                lost_listener += 1;
                if lost_listener >= 3 {
                    ctx.sh.note(format!("UDP-сокет порта {} пропал, выход для перезапуска", ctx.listen_port));
                    std::process::exit(2);
                }
            } else {
                lost_listener = 0;
            }
        }
        // смена носителя у пира: Link на прежнем носителе закрываем сразу и переподключаемся без ожидания таймаута «сосед не отвечает»
        let flipped: Vec<(LinkId, String)> = {
            let mut n = ctx.neigh.lock().unwrap();
            let mut v = Vec::new();
            for nb in n.values_mut() {
                let g = nb.ctl.generation.load(Relaxed);
                if g != nb.seen_gen {
                    nb.seen_gen = g;
                    nb.loss.clear();
                    if let Some(l) = nb.link.take() {
                        nb.rtt_ms = None;
                        nb.last_try = Instant::now() - Duration::from_secs(3600);
                        nb.connecting = false;
                        v.push((l, nb.name.clone()));
                    }
                }
            }
            v
        };
        for (l, name) in flipped {
            ctx.sh.note(format!("{name}: носитель сменился, Link закрыт, переподключаюсь"));
            ctx.close_link(l, "смена носителя");
        }
        // соседи для клиентов (0014 R3): раз в 10 с, рассылка только при изменении
        if ctx.t13.is_some() && tick % 20 == 0 {
            ctx.push_cinfo();
            ctx.push_nbrs_changed();
        }
        // R7: зачисление через посредника (нода с приглашением без адресов админа), проверка раз в 2 с
        if ctx.t13.is_some() && tick % 4 == 0 {
            node_relay_tick(&ctx);
        }
        // дозвон и повтор подключения к соседям: никакого списка, только то, что узнали из анонсов
        let dests: Vec<[u8; 16]> = ctx.neigh.lock().unwrap().keys().copied().collect();
        for d in dests {
            let (want, init) = ctx.neighbor_policy(&d);
            if !want {
                continue;
            }
            maybe_dial(&ctx, d);
            let go = {
                let mut n = ctx.neigh.lock().unwrap();
                match n.get_mut(&d) {
                    Some(nb) if nb.link.is_none() && !nb.connecting && init && nb.last_try.elapsed() >= Duration::from_secs(3) => {
                        nb.connecting = true;
                        nb.last_try = Instant::now();
                        true
                    }
                    _ => false,
                }
            };
            if go {
                let c = ctx.clone();
                tokio::spawn(async move { connect_neighbor(c, d).await });
            }
        }
        // появился новый наш интерфейс (QUIC-связь): сообщить о себе
        let n_ours = ctx.our_ifaces().len();
        if n_ours > ctx.ours_online.swap(n_ours, Relaxed) {
            ctx.trigger_announce();
        }
        // адреса с интерфейсов (нет явного advertise): раз в 60 с перепроверяем, при смене IP объявляем заново (0014 R4)
        if tick % 120 == 0 {
            if let Some((allow_private, skip)) = &ctx.adv_auto {
                let now_adv = local_addrs(ctx.listen_port, *allow_private, skip);
                let changed = {
                    let mut cur = ctx.advertise.lock().unwrap();
                    if !now_adv.is_empty() && *cur != now_adv {
                        *cur = now_adv.clone();
                        true
                    } else {
                        false
                    }
                };
                if changed {
                    ctx.sh.note(format!("объявляемые адреса изменились: {now_adv:?}"));
                    ctx.trigger_announce();
                }
            }
        }

        // неавторизованные Link не живут дольше срока (в модели 0013 обмен цепочками и зачисление дольше - окно шире)
        let deadline = if ctx.t13.is_some() { Duration::from_secs(30) } else { UNAUTH_TIMEOUT };
        let stale: Vec<LinkId> = ctx.links.lock().unwrap().iter()
            .filter(|(_, l)| !matches!(l.role, Role::Server { .. } | Role::Client { .. }) && now.duration_since(l.since) > deadline).map(|(k, _)| *k).collect();
        for l in stale {
            ctx.close_link(l, "авторизация не завершена вовремя");
        }

        // модель 0013: записи, подписанные командами grant/revoke (кладут файлы в inbox13), и открытие на этом Link
        if ctx.t13.is_some() && tick % 2 == 0 {
            ctx.take_inbox13();
        }
        // 0015: политика этой ноды (файл policy-want.json, переподпись по возрасту) и её рассылка, раз в 4 с
        if ctx.t13.is_some() && tick % 8 == 3 {
            ctx.policy_tick();
        }
        if ctx.t13.is_some() && tick % 600 == 301 {
            ctx.dir_tick();
        }
        if ctx.t13.is_some() && tick % 120 == 17 {
            ctx.book_save();
        }
        // H1: записи от пиров на диск не чаще раза в 2 с (тик 500 мс)
        if tick % 4 == 0 {
            ctx.flush_trust();
        }

        // очередь админ-команд (issue/revoke кладут файлы)
        if tick % 2 == 0 {
            let mut changed = false;
            if let Ok(rd) = std::fs::read_dir(&inbox) {
                for e in rd.flatten() {
                    if let Ok(b) = std::fs::read(e.path()) {
                        if let Ok(v) = serde_json::from_slice::<Vec<ClientRec>>(&b) {
                            let mut reg = ctx.reg.lock().unwrap();
                            // отзыв из inbox применяется напрямую (merge не повышает active->revoked для чужого issuer, но здесь это локальная админ-операция)
                            for r in &v {
                                if r.status == "revoked" {
                                    if let Some(h) = reg.recs.get_mut(&r.id) {
                                        if h.status != "revoked" {
                                            h.status = "revoked".into();
                                            changed = true;
                                        }
                                    }
                                }
                            }
                            changed |= reg.merge(&v);
                        }
                    }
                    let _ = std::fs::remove_file(e.path());
                }
            }
            if changed {
                ctx.reg.lock().unwrap().save(&ctx.state.join("clients.json"));
                ctx.enforce_revocations();
                ctx.broadcast_registry();
            }
        }

        // R10: бенч по файлу-запросу (`rawgd bench`); итог - bench/res-<id>.json
        if tick % 2 == 0 {
            take_bench_req(&ctx);
        }
        if let Some(j) = bench_finish(&ctx.bench_sess, &ctx.sh, node_bench_rtt(&ctx)) {
            write_bench_res(&ctx.state.join("bench"), &j);
        }

        // пинги соседям и клиентам-проверка живости
        if now.duration_since(last_ping) >= Duration::from_secs(2) {
            last_ping = now;
            let links: Vec<(LinkId, [u8; 16])> = ctx.links.lock().unwrap().iter().filter_map(|(k, l)| match l.role { Role::Server { dest } => Some((*k, dest)), _ => None }).collect();
            for (l, dest) in links {
                let seq = {
                    let mut n = ctx.neigh.lock().unwrap();
                    let Some(nb) = n.get_mut(&dest) else { continue };
                    nb.ping_seq = nb.ping_seq.wrapping_add(1);
                    nb.loss.sent(nb.ping_seq);
                    // монитор качества: потери пингов >= 30% при >= 8 созревших на QUIC -> TCP (набирает дозвон этого пира; принимающая сторона следует за ним)
                    if nb.ctl.is_quic() && !nb.ctl.prefer_tcp.load(Relaxed) && nb.admitted_at.elapsed() > Duration::from_secs(6) {
                        if let Some(lo) = nb.loss.loss(Duration::from_secs(4), 8) {
                            if lo >= 0.30 {
                                ctx.sh.note(format!("{}: потери UDP {:.0}% по пингам, переключаю носитель на TCP", nb.name, lo * 100.0));
                                nb.ctl.prefer_tcp.store(true, Relaxed);
                                nb.ctl.switches.fetch_add(1, Relaxed);
                                nb.loss.clear();
                            }
                        }
                    }
                    nb.ping_seq
                };
                spawn_dgram(&ctx.node, l, dgram_ping(seq, now_us(), b'P'));
            }
        }

        // Таймаут локального authenticated Link, не свидетельство смерти узла.
        let announce_ttl = Duration::from_secs((ctx.announce_s * 5 / 2).max(ctx.dead.as_secs() + 3));
        let heard: HashMap<LinkId, Instant> = ctx.links.lock().unwrap().iter()
            .filter(|(_, l)| matches!(l.role, Role::Server { .. }))
            .map(|(id, l)| (*id, l.last_heard)).collect();
        let mut to_close = Vec::new();
        let mut forget = Vec::new();
        {
            let mut n = ctx.neigh.lock().unwrap();
            for nb in n.values_mut() {
                if let Some(l) = nb.link {
                    if path::link_timed_out(now, heard.get(&l).copied(), ctx.dead) {
                        to_close.push((l, nb.name.clone()));
                    }
                }
                if nb.link.is_none() && now.duration_since(nb.last_announce) > announce_ttl {
                    forget.push((nb.dest, nb.name.clone()));
                }
            }
            for (d, _) in &forget {
                if let Some(nb) = n.remove(d) {
                    if let Some(a) = nb.dialer {
                        a.store(false, Relaxed);
                    }
                }
            }
        }
        for (l, name) in to_close {
            ctx.sh.note(format!("локальный Link к {name}: нет аутентифицированного приёма дольше {} с, закрываю связь", ctx.dead.as_secs()));
            ctx.close_link(l, "таймаут локального Link");
        }
        for (_, name) in forget {
            ctx.sh.note(format!("сосед {name} не виден: забыт"));
        }

        // таблица клиентам и в файл
        if now.duration_since(last_table) >= Duration::from_secs(2) {
            last_table = now;
            let t = ctx.table(false);
            // диагностика, не состояние: из отдельного потока и редко (W48). Проверка свежести деплоя требует ts не старше 10 с
            crate::bgwrite::put(&ctx.state.join("neighbors.json"), t.to_string().into_bytes(), Duration::from_secs(5));
            let n_clients = ctx.links.lock().unwrap().values().filter(|l| matches!(l.role, Role::Client { .. })).count();
            if ctx.t13.is_none() {
                // legacy: сырая таблица клиенту (0013: клиент строит список выходов сам по записям)
                let clients: Vec<LinkId> = ctx.links.lock().unwrap().iter().filter(|(_, l)| matches!(l.role, Role::Client { .. })).map(|(k, _)| *k).collect();
                for c in clients {
                    ctx.send_table(c);
                }
            }
            let st = serde_json::json!({"uptime_s": ctx.started.elapsed().as_secs(), "links": ctx.links.lock().unwrap().len(),
                "clients": n_clients, "tun": ctx.tun.as_ref().map(|t| t.stats()), "registry": ctx.reg.lock().unwrap().recs.len(),
                "model": if ctx.t13.is_some() { "0013" } else { "legacy" }, "pol": pol_counters(),
                "policy": ctx.t13.as_ref().map(|t| t.trust.lock().unwrap().policy_view(now_ms() as u64).iter()
                    .map(|(r, g, o, e)| serde_json::json!({"tag": trust::root_tag(r), "grant": g, "offer": o, "eff": e})).collect::<Vec<_>>())});
            crate::bgwrite::put(&ctx.state.join("status.json"), st.to_string().into_bytes(), Duration::from_secs(20));
        }
    }
}

// ------------------------------------------------------------------------------------------------ хаб

pub async fn run_hub(a: HubArgs) -> Result<()> {
    let hub_id = load_or_create_identity(&a.state)?;
    let key = iroh_key_from_identity(&hub_id)?;
    let b = start_base("h", &a.state, true, Some(a.port), key, 500, &[], Some(a.tcp_port)).await?;
    tokio::spawn(accept_loop(b.ep.clone(), b.node.clone(), b.sh.clone()));
    let mut ev = b.events;
    tokio::spawn(async move { while ev.recv().await.is_some() {} });
    write_atomic(&a.state.join("hub.json"), serde_json::json!({"id": b.ep.id().to_string()}).to_string().as_bytes());
    b.sh.note(format!("hub ready, iroh {}", b.ep.id()));
    let fin = a.state.join("fin");
    while !fin.exists() {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    b.ep.close().await;
    Ok(())
}

// ------------------------------------------------------------------------------------------------ админ-команды

/// Identity уже работавшей ноды: админ-команды её не создают (иначе опечатка в --state тихо породила бы нового админа).
fn load_identity_strict(state: &Path) -> Result<Identity> {
    if !state.join("identity.key").exists() {
        bail!("в {} нет identity.key: каталог состояния не принадлежит работавшей ноде", state.display());
    }
    load_or_create_identity(state)
}

/// Подписанная запись отдаётся работающей ноде через inbox13: сам CLI trust.json не пишет (владелец состояния - нода).
fn put_inbox13(state: &Path, rec: &trust::Record) -> Result<()> {
    let dir = state.join("inbox13");
    std::fs::create_dir_all(&dir)?;
    let name = format!("{}-{}", now_ms(), &hex(&rec.hh)[..8]);
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, hex(&rec.wire()))?;
    std::fs::rename(&tmp, dir.join(format!("{name}.rec")))?;
    Ok(())
}

/// Проверки выдающего при подготовке делегированного приглашения выполняются до создания pin.
fn validate_invite_rights(tr: &trust::Trust, root: &trust::Hash, rights: u16) -> Result<trust::Pk> {
    if !tr.has_anchor(root) { bail!("корень отсутствует среди якорей доверия"); }
    let mine = tr.my_rights_in(root);
    if mine & trust::ADD == 0 { bail!("в корне нет права ADD"); }
    if rights == 0 || rights & !trust::ALL != 0 { bail!("права приглашения пусты или содержат неизвестные биты"); }
    if rights & !mine != 0 { bail!("приглашение шире действующих прав"); }
    let depth = tr.depth_in(root, &tr.me_hash).ok_or_else(|| anyhow::anyhow!("глубина цепочки не подтверждена"))?;
    if depth as usize + 1 > trust::MAX_DEPTH { bail!("выдача превысит максимальную глубину цепочки"); }
    tr.anchors().into_iter().find(|(h, _)| h == root).map(|(_, pk)| pk)
        .ok_or_else(|| anyhow::anyhow!("публичный ключ корня не найден среди якорей"))
}

fn admin_invite(a: InviteArgs) -> Result<()> {
    let id = load_identity_strict(&a.state)?;
    let rights = trust::parse_rights(&a.rights)?;
    if rights == 0 {
        bail!("права приглашения не могут быть пустыми");
    }
    let mut addrs = a.addrs.clone();
    if addrs.is_empty() {
        if let Ok(b) = std::fs::read(a.state.join("server.json")) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) {
                addrs = v["a"].as_array().map(|x| x.iter().filter_map(|y| y.as_str().map(String::from)).collect()).unwrap_or_default();
            }
        }
    }
    if addrs.is_empty() {
        eprintln!("ВНИМАНИЕ: в приглашении нет адреса админа (за NAT?): новая нода найдёт вас только по анонсам через публичную RNS, а вы должны сами набрать её адрес.");
    }
    let mut nodes: Vec<trust::Hash> = Vec::new();
    for n in a.nodes.iter().map(|n| n.trim().to_lowercase()).filter(|n| !n.is_empty()) {
        let h: trust::Hash = unhex(&n).try_into().map_err(|_| anyhow::anyhow!("--nodes: нужен identity-хеш (32 hex), получено {n:?}"))?;
        if !nodes.contains(&h) {
            nodes.push(h);
        }
    }
    if nodes.len() > trust::MAX_INVITE_NODES {
        bail!("--nodes: не более {}", trust::MAX_INVITE_NODES);
    }
    let me = *id.hash();
    let root = match a.root {
        Some(h) => <[u8; 16]>::try_from(unhex(&h.trim().to_lowercase()))
            .map_err(|_| anyhow::anyhow!("--root: нужен хеш корня (32 hex)"))?,
        None => me,
    };
    let tr = trust::Trust::load(id.clone(), &a.state).context("trust.json для проверки прав приглашения")?;
    let root_pk = validate_invite_rights(&tr, &root, rights)?;
    if addrs.len() > 4 || addrs.iter().any(|x| x.len() > 200) { bail!("--addrs: не более 4 адресов длиной до 200 байт каждый"); }
    let pin = trust::pin_create(&a.state, &root, rights, &a.label, now_ms() as u64 / 1000)?;
    let inv = trust::Invite { admin: id.public_key_bytes(), root_pk: (root != me).then_some(root_pk), pin, rights, created: now_ms() as u64 / 1000, addrs, nodes };
    eprintln!("приглашение действует {} ч, одноразовое; права: {}", trust::INVITE_TTL_S / 3600, trust::rights_text(rights));
    if let Some(o) = &a.out {
        write_atomic(o, inv.encode()?.as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(o, std::fs::Permissions::from_mode(0o600));
        }
    } else {
        println!("{}", inv.encode()?);
    }
    Ok(())
}

/// H14: держатель по префиксу хеша. Префикс не короче 8 hex; совпасть должен ровно один держатель, иначе ошибка.
fn holder_by_prefix(prefix: &str, known: &[(String, trust::Pk)]) -> Result<trust::Pk> {
    if prefix.len() < 8 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("--holder: нужен публичный ключ (128 hex) или префикс хеша не короче 8 hex");
    }
    let mut hits: Vec<trust::Pk> = known.iter().filter(|(hh, _)| hh.starts_with(prefix)).map(|(_, pk)| *pk).collect();
    hits.sort();
    hits.dedup();
    match hits.len() {
        0 => bail!("--holder: держатель с таким префиксом не найден"),
        1 => Ok(hits[0]),
        n => bail!("--holder: префикс неоднозначен ({n} держателей), укажите больше hex или публичный ключ"),
    }
}

fn admin_grant(a: GrantArgs) -> Result<()> {
    let id = load_identity_strict(&a.state)?;
    let rights = trust::parse_rights(&a.rights)?;
    let mut tr = trust::Trust::load(id, &a.state)?;
    let root: trust::Hash = match &a.root {
        Some(r) => unhex(r.trim()).try_into().map_err(|_| anyhow::anyhow!("--root: нужен хеш identity админа (32 hex)"))?,
        None => tr.me_hash,
    };
    let h = a.holder.trim().to_lowercase();
    let holder: trust::Pk = if h.len() == 128 {
        unhex(&h).try_into().map_err(|_| anyhow::anyhow!("--holder: не публичный ключ"))?
    } else {
        // префикс хеша уже известного держателя (H14: не короче 8 hex и однозначный)
        let known: Vec<(String, trust::Pk)> = tr.export_all().into_iter().filter(|r| r.root == root).map(|r| (hex(&r.hh), r.holder)).collect();
        holder_by_prefix(&h, &known)?
    };
    let rec = tr.issue(root, holder, rights)?;
    put_inbox13(&a.state, &rec)?;
    println!("запись для {} ({}) подписана; нода применит её за ~1 с", &hex(&rec.hh)[..8], trust::rights_text(rights));
    Ok(())
}

/// `rawgd policy`: записывает желаемую политику в `<state>/policy-want.json` (атомарно); работающая нода или клиент подписывает её и разносит.
fn admin_policy(a: PolicyArgs) -> Result<()> {
    let offer = trust::parse_rights(&a.rights)?;
    let id = load_identity_strict(&a.state)?;
    let tr = trust::Trust::load(id, &a.state)?;
    let root: trust::Hash = match &a.root {
        Some(r) => unhex(r.trim()).try_into().map_err(|_| anyhow::anyhow!("--root: нужен хеш identity админа (32 hex)"))?,
        None => tr.me_hash,
    };
    if !tr.has_anchor(&root) {
        bail!("--root: такой сети нет среди моих якорей");
    }
    if tr.my_rights_in(&root) == 0 {
        bail!("в этой сети у меня нет выданных прав");
    }
    let mut want = read_policy_want(&a.state);
    want.insert(root, offer);
    let m: serde_json::Map<String, serde_json::Value> = want.iter().map(|(r, o)| (hex(r), serde_json::json!(o))).collect();
    let tmp = a.state.join("policy-want.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(&serde_json::Value::Object(m))?)?;
    std::fs::rename(&tmp, a.state.join("policy-want.json"))?;
    println!("политика для сети {}: согласна на {} (выдано мне: {}); нода применит за несколько секунд", &hex(&root)[..8], trust::rights_text(offer), trust::rights_text(tr.my_rights_in(&root)));
    Ok(())
}

/// Желаемые политики из `policy-want.json` (корень -> биты). Битый файл и лишние биты игнорируются: это настройка владельца, не ввод пира.
fn read_policy_want(state: &Path) -> std::collections::BTreeMap<trust::Hash, u16> {
    let mut out = std::collections::BTreeMap::new();
    let Some(v) = std::fs::read(state.join("policy-want.json")).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()) else { return out };
    for (k, o) in v.as_object().into_iter().flatten() {
        if let (Ok(root), Some(o)) = (trust::Hash::try_from(unhex(k)), o.as_u64()) {
            if o <= trust::ALL as u64 {
                out.insert(root, o as u16);
            }
        }
    }
    out
}

/// Один шаг политик (раз в несколько секунд): применить `policy-want.json`, на клиенте выставить значение по умолчанию (0015: только USE)
/// в чужих сетях, где оно ещё не задано, и переподписать устаревающие. Вернуть новые политики (разослать) и строки для журнала.
fn policy_step(tr: &mut trust::Trust, state: &Path, defaults: bool, now: u64) -> (Vec<trust::Policy>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    for (root, offer) in read_policy_want(state) {
        if tr.my_policy_offer(&root) == Some(offer) {
            continue;
        }
        match tr.set_my_policy(root, offer, now) {
            Ok(p) => {
                notes.push(format!("политика сети {}: {}", &hex(&root)[..8], trust::rights_text(offer)));
                out.push(p);
            }
            Err(e) => notes.push(format!("политика сети {} не применена: {e:#}", &hex(&root)[..8])),
        }
    }
    if defaults {
        let roots: Vec<trust::Hash> = tr.anchors().into_iter().map(|(h, _)| h).filter(|h| *h != tr.me_hash).collect();
        for root in roots {
            if tr.my_policy_offer(&root).is_none() && tr.my_rights_in(&root) != 0 {
                if let Ok(p) = tr.set_my_policy(root, trust::USE, now) {
                    notes.push(format!("политика сети {} по умолчанию: только USE", &hex(&root)[..8]));
                    out.push(p);
                }
            }
        }
    }
    out.extend(tr.refresh_my_policies(now));
    (out, notes)
}

/// `rawgd bench`: кладёт запрос в `<state>/bench/req-<id>.json` (атомарно), ждёт `res-<id>.json` от работающей ноды и печатает итог.
fn bench_cli(a: BenchArgs) -> Result<()> {
    if a.mb == 0 || a.mb > BENCH_MAX_MB {
        bail!("--mb: от 1 до {BENCH_MAX_MB} МБ");
    }
    let to = a.to.trim().to_lowercase();
    if to.is_empty() {
        bail!("--to: имя соседа, dest (32 hex) или его префикс не короче 8 hex");
    }
    let dir = a.state.join("bench");
    std::fs::create_dir_all(&dir)?;
    let timeout = a.timeout.clamp(10, 900);
    let id = u32::from_le_bytes(rand16()[..4].try_into().unwrap());
    let req = dir.join(format!("req-{id}.json"));
    let tmp = dir.join(format!("req-{id}.tmp"));
    std::fs::write(&tmp, serde_json::json!({"id": id, "to": to, "mb": a.mb, "timeout": timeout}).to_string())?;
    std::fs::rename(&tmp, &req)?;
    let res = dir.join(format!("res-{id}.json"));
    let until = Instant::now() + Duration::from_secs(timeout + 60);
    while !res.exists() {
        if Instant::now() > until {
            bail!("нет результата за {} с: нода с этим --state запущена и работает?", timeout + 60);
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&res)?)?;
    for k in ["verdict", "to", "path", "mbps", "pps", "bytes_rx", "pkts_rx", "pkts_lost", "dup", "reordered", "secs", "ttfb_ms", "rtt_ms_idle", "rtt_ms_load", "stalls", "stall_s", "why"] {
        if !v[k].is_null() {
            let s = v[k].as_str().map(String::from).unwrap_or_else(|| v[k].to_string());
            println!("{k:<12} {s}");
        }
    }
    Ok(())
}

fn admin_list(state: &Path) -> Result<()> {
    if state.join("identity.key").exists() {
        let id = load_identity_strict(state)?;
        let tr = trust::Trust::load(id, state)?;
        println!("нода {}", hex(&tr.me_hash));
        for (h, _) in tr.anchors() {
            let me = if h == tr.me_hash { " (свой)" } else { "" };
            println!("якорь {}{me}; мои права {}", hex(&h), trust::rights_text(tr.my_rights_in(&h)));
        }
        let mut recs = tr.export_all();
        recs.sort_by_key(|r| (r.root, r.hh));
        println!("записи ({}):", recs.len());
        for r in recs {
            let eff = tr.rights_in(&r.root, &r.hh);
            println!("  корень {}  держатель {}  выдал {}  {}{}", &hex(&r.root)[..8], &hex(&r.hh)[..8], &hex(&r.issuer)[..8], trust::rights_text(r.rights),
                if eff != r.rights { format!(" (действует {})", trust::rights_text(eff)) } else { String::new() });
        }
        let pins = trust::pin_list(state);
        println!("приглашения ({}):", pins.len());
        for (p, st, l) in pins {
            println!("  {p}  {st}  {l}");
        }
    }
    let reg = Registry::load(&state.join("clients.json"));
    let mut v = reg.all();
    if !v.is_empty() {
        v.sort_by_key(|r| r.ts);
        println!("легаси-клиенты ({}):", v.len());
        for r in v {
            println!("  {}  {:8}  {}  выдал {}", r.id, r.status, r.name, &r.issuer.chars().take(8).collect::<String>());
        }
    }
    if let Ok(b) = std::fs::read(state.join("neighbors.json")) {
        println!("таблица соседей: {}", String::from_utf8_lossy(&b));
    }
    Ok(())
}

pub fn run_admin(cmd: VpnCmd) -> Result<()> {
    match cmd {
        VpnCmd::Keygen(k) => {
            let mut s = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut s);
            secure_write(&k.out, b64e(&s).as_bytes())?;
            println!("серверный секрет записан в {} (не публиковать, передавать файлом)", k.out.display());
            Ok(())
        }
        VpnCmd::Issue(a) => {
            let me: serde_json::Value = serde_json::from_slice(&std::fs::read(a.state.join("server.json")).context("server.json: узел не запускался с этим каталогом")?)?;
            let mut seed = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut seed);
            if let Some(cn) = me["cn"].as_str() {
                let _ = CLIENT_NET.set(parse_net(cn)?);
            }
            let id = client_identity(&seed)?;
            let idh = *id.hash();
            let rec = ClientRec { id: hex(&idh), pk: hex(&id.public_key_bytes()), name: a.client_name.chars().take(64).collect(), issuer: me["d"].as_str().unwrap_or("").into(),
                status: "active".into(), ts: now_ms() as u64 / 1000 };
            let inbox = a.state.join("inbox");
            std::fs::create_dir_all(&inbox)?;
            write_atomic(&inbox.join(format!("{}.json", rec.id)), &serde_json::to_vec(&vec![rec.clone()])?);
            let from_json = |x: &serde_json::Value| -> Option<ProfServer> {
                let addrs: Vec<String> = x["a"].as_array()?.iter().filter_map(|y| y.as_str().map(String::from)).collect();
                Some(ProfServer { n: x["n"].as_str()?.chars().take(32).collect(), d: dest32(x["d"].as_str()?)?, k: unhex(x["k"].as_str()?).try_into().ok()?, a: addrs })
            };
            let mut servers: Vec<ProfServer> = from_json(&me).into_iter().collect();
            if let Ok(b) = std::fs::read(a.state.join("neighbors.json")) {
                if let Ok(t) = serde_json::from_slice::<serde_json::Value>(&b) {
                    for x in t["exits"].as_array().cloned().unwrap_or_default() {
                        if servers.len() >= a.servers || x["self"] == true || x["s"] != "up" {
                            continue;
                        }
                        servers.extend(from_json(&x));
                    }
                }
            }
            servers.sort_by_key(|s| s.a.is_empty()); // достижимые напрямую вперёд: клиент входит в сеть через них
            if servers.iter().all(|s| s.a.is_empty()) {
                eprintln!("ВНИМАНИЕ: ни у одного сервера в профиле нет адреса (узел за NAT?): клиент не сможет войти. Выдавайте профиль на узле с публичным адресом.");
            }
            if let Some(max) = a.max_addrs {
                for s in servers.iter_mut() {
                    s.a.truncate(max);
                }
            }
            let prof = Profile { group: me["g"].as_str().unwrap_or("").into(), seed, ip: client_ip(&idh), s: servers };
            let text = encode_profile(&prof);
            eprintln!("клиент {} ({}) внесён в реестр; адрес в туннеле {}; серверов в профиле: {}; длина строки {} символов", rec.name, &rec.id[..8], ip_str(prof.ip), prof.s.len(), text.len());
            println!("{text}");
            Ok(())
        }
        VpnCmd::Revoke(a) => {
            let id = a.id.to_lowercase();
            // модель 0013: держатель по префиксу хеша -> запись с пустыми правами; иначе легаси-реестр
            if a.state.join("identity.key").exists() {
                if let Ok(me) = load_identity_strict(&a.state) {
                    let tr = trust::Trust::load(me, &a.state)?;
                    let root = tr.me_hash;
                    let hit = tr.export_all().into_iter().find(|r| r.root == root && hex(&r.hh).starts_with(&id)).map(|r| r.holder);
                    if let Some(holder) = hit {
                        return admin_grant(GrantArgs { state: a.state, root: None, holder: hex(&holder), rights: "none".into() });
                    }
                }
            }
            let inbox = a.state.join("inbox");
            std::fs::create_dir_all(&inbox)?;
            let reg = Registry::load(&a.state.join("clients.json"));
            let full = reg.recs.keys().find(|k| k.starts_with(&id)).cloned().ok_or_else(|| anyhow::anyhow!("такого держателя или клиента нет"))?;
            let mut rec = reg.recs[&full].clone();
            rec.status = "revoked".into();
            write_atomic(&inbox.join(format!("revoke-{full}.json")), &serde_json::to_vec(&vec![rec])?);
            println!("клиент {full} отозван (применится за ~1 с, откроется синхронизация с соседями)");
            Ok(())
        }
        VpnCmd::Whoami(a) => {
            std::fs::create_dir_all(&a.state)?;
            let id = load_or_create_identity(&a.state)?;
            let j = serde_json::json!({"hash": hex(id.hash()), "ip": ip_str(client_ip(id.hash())), "prefix": client_net().1});
            write_atomic(&a.state.join("whoami.json"), j.to_string().as_bytes());
            println!("{j}");
            Ok(())
        }
        VpnCmd::RulesList(a) => route::cmd_list(&a.state),
        VpnCmd::RulesCompile(a) => route::cmd_compile(&a.state),
        VpnCmd::Invite(a) => admin_invite(a),
        VpnCmd::Grant(a) => admin_grant(a),
        VpnCmd::Policy(a) => admin_policy(a),
        VpnCmd::Bench(a) => bench_cli(a),
        VpnCmd::List(a) => admin_list(&a.state),
        _ => bail!("не админ-команда"),
    }
}

// ------------------------------------------------------------------------------------------------ клиент

#[derive(Clone)]
struct CServer {
    dest: [u8; 16],
    key: [u8; 32],
    name: String,
    ep: String,
    addrs: Vec<String>,
    hops: Option<u8>,
    rtt_ms: Option<f64>,
    state: String,
    seen: Instant,
    pinned: bool,
    /// полный публичный ключ (0013): известен из записей о правах, нужен для проверки EXIT у выхода
    pk: Option<[u8; 64]>,
}

/// Состояние клиента модели 0013.
struct C13 {
    /// порядок блокировок: invite, затем trust
    trust: Mutex<trust::Trust>,
    /// приглашение, по которому клиент ещё не зачислен
    invite: Mutex<Option<trust::Invite>>,
    /// админ отказал в приглашении: повторять бесполезно
    rejected: Mutex<Option<String>>,
    /// публичный ключ собеседника на Link (клиент сам его выбирает при дозвоне)
    peers: Mutex<HashMap<LinkId, [u8; 64]>>,
    /// последние известные адреса выходов (dest -> `host:порт`), `hints.json` в state. После зачисления приглашение игнорируется,
    /// а публичная RNS адрес может и не объявлять: без этого кэша клиент после перезапуска не нашёл бы ни одного выхода. Это подсказки, не доверие.
    hints: Mutex<HashMap<String, Vec<String>>>,
    /// админ-режим: ноды, к которым мы звонили для зачисления (Link -> ожидаемый ключ), и Link, где зачисление завершено
    enrollees: Mutex<HashMap<LinkId, [u8; 64]>>,
    enrolled: Mutex<HashSet<LinkId>>,
    /// когда последний раз пробовали зачислить ноду (dest -> момент): не чаще раза в минуту
    enroll_try: Mutex<HashMap<[u8; 16], Instant>>,
    /// пользователь по приглашению (админ - телефон за NAT): ноды, чей анонс несёт тег корня админа; через любую из них идёт T_PAIRQ
    relays: Mutex<HashMap<[u8; 16], CServer>>,
    /// админ-режим: приглашённые пользователи, получившие запись через посредника (hex хеша -> когда); для показа в приложении
    users: Mutex<Vec<(String, u64)>>,
    /// записи сети, пришедшие раньше записи о нас (до появления якоря админа): применяются сразу после зачисления
    early: Mutex<Vec<(LinkId, trust::Record)>>,
}

/// Соседи выхода, которые он сообщил клиенту (T_NBRS): dest выхода -> (когда, [(dest соседа, rtt мс)]). Недоверенная подсказка для рёбер в приложении.
struct NbrReport {
    received: Instant,
    ttl: Duration,
    neighbors: Vec<([u8; 16], Option<f64>)>,
}
impl NbrReport {
    fn fresh(&self) -> bool { self.received.elapsed() < self.ttl }
}
type NbrsMap = HashMap<[u8; 16], NbrReport>;

struct ClientCtx {
    node: Arc<Node>,
    sh: Arc<Shared>,
    ep: Endpoint,
    identity: Identity,
    group: String,
    ip: String,
    servers: Mutex<Vec<CServer>>,
    tun: Arc<TunState>,
    auth_wait: Mutex<HashMap<LinkId, tokio::sync::oneshot::Sender<std::result::Result<serde_json::Value, String>>>>,
    cur: Mutex<Option<([u8; 16], LinkId, Instant)>>,
    last_pong: std::sync::atomic::AtomicU64,
    rtt_pong: std::sync::atomic::AtomicU64,
    rtt_ms: Mutex<Option<f64>>,
    failovers: Mutex<Vec<serde_json::Value>>,
    state: PathBuf,
    status: Mutex<String>,
    dialers: Mutex<HashMap<[u8; 16], Arc<AtomicBool>>>,
    carriers: Mutex<HashMap<[u8; 16], Arc<CarrierCtl>>>,
    /// интерфейсы подключения к публичным узлам RNS (перебор путей при зачислении)
    public_ids: Mutex<Vec<usize>>,
    /// имена узлов, которые они сами сообщили по допущенному Link (dest -> имя); хранятся в state/names.json
    names: Mutex<HashMap<[u8; 16], String>>,
    /// имена этой сессии от допущенных пиров: от самого узла (T_AUTH_OK) и от выхода про его соседей (T_NBRS); не сохраняются; свежее сохранённого в `names`
    hints: Mutex<HashMap<[u8; 16], String>>,
    /// тип узла из T_AUTH_OK («android», «ios», «server»); узлы, к которым ещё не подключались, - неизвестен
    platforms: Mutex<HashMap<[u8; 16], &'static str>>,
    /// адреса выходов для диалеров (dest -> общее хранилище): анонс обновляет, диалер читает на каждой попытке (0014 R4)
    books: Mutex<HashMap<[u8; 16], Arc<Addrs>>>,
    table_acc: Mutex<HashSet<[u8; 16]>>,
    loss: Mutex<LossWin>,
    fail_ms: u64,
    path_gate: path::PathGate,
    /// модель 0013; None - легаси (профиль rawg2-)
    c13: Option<C13>,
    /// соседи выходов по T_NBRS (0014 R3): недоверенная подсказка, список выходов не меняет
    nbrs: Mutex<NbrsMap>,
    /// Only exits whose AUTH_OK and rights were validated, not merely established Links.
    admitted_exits: Mutex<HashMap<LinkId, [u8; 16]>>,
    /// B: ведро управляющих сообщений на каждый Link (CtrlBucket, как у ноды); запись удаляется при LinkClosed
    ctrl: Mutex<HashMap<LinkId, CtrlBucket>>,
    /// последняя неудачная попытка Link к выходу (dest -> когда, причина до 80 символов), для `lk`/`why` в status.json (0014 R2)
    lk_fail: Mutex<HashMap<[u8; 16], (Instant, String)>>,
    /// R8: последний вид пути к выходу (vis, nh) и число его смен (pc), до 32 выходов
    vis: Mutex<HashMap<[u8; 16], (&'static str, Option<[u8; 16]>, u32)>>,
    /// R9: удачные/неудачные Link к выходу, для `q` в status.json (до 32 выходов)
    qstat: Mutex<HashMap<[u8; 16], QStat>>,
    /// R10: бенч текущего выхода с телефона (одна сессия) и последний итог (для status.json)
    bench_sess: Mutex<Option<BenchSess>>,
    bench_last: Mutex<Option<serde_json::Value>>,
    /// раздельное туннелирование: действующий конфиг (приоритеты нужны выбору выхода), отчёт о загрузке списков,
    /// выходы с идущей попыткой Link и пауза после неудачи
    rcfg: std::sync::RwLock<Arc<route::Cfg>>,
    rreport: Mutex<serde_json::Value>,
    rpending: Mutex<HashSet<[u8; 16]>>,
    rback: Mutex<HashMap<[u8; 16], Instant>>,
}

/// R9: счётчики Link к одному выходу
#[derive(Clone, Default)]
struct QStat {
    ok: u32,
    fail: u32,
    last_ok: Option<Instant>,
}

impl ClientCtx {
    /// R9: итог попытки Link к выходу
    fn note_link(&self, dest: &[u8; 16], ok: bool) {
        let mut m = self.qstat.lock().unwrap();
        if !m.contains_key(dest) && m.len() >= 32 {
            return;
        }
        let q = m.entry(*dest).or_default();
        if ok {
            q.ok += 1;
            q.last_ok = Some(Instant::now());
        } else {
            q.fail += 1;
        }
    }

    /// Общее хранилище адресов выхода для диалера (создаётся по требованию).
    fn book_for(&self, dest: &[u8; 16]) -> Arc<Addrs> {
        self.books.lock().unwrap().entry(*dest).or_insert_with(|| Addrs::new(vec![])).clone()
    }

    /// Запомнить адреса выхода (0013) и сохранить на диск, если они изменились.
    fn remember_addrs(&self, dest: &[u8; 16], addrs: &[String]) {
        let Some(c) = &self.c13 else { return };
        if addrs.is_empty() {
            return;
        }
        let mut h = c.hints.lock().unwrap();
        let k = hex(dest);
        if h.get(&k).map(|v| v.as_slice()) == Some(addrs) {
            return;
        }
        h.insert(k, addrs.to_vec());
        if h.len() > 64 {
            let drop_key = h.keys().next().cloned();
            if let Some(d) = drop_key {
                h.remove(&d);
            }
        }
        if let Ok(b) = serde_json::to_vec(&*h) {
            write_atomic(&self.state.join("hints.json"), &b);
        }
    }

    /// Выходы 0013 строятся из записей, а не из профиля: держатели с EXIT, у которых общий с нами корень, и админ ожидающего приглашения.
    /// Адреса приходят только подсказками (приглашение, анонс).
    /// Имя соседа из T_NBRS: в список выходов, на диск не пишем (сохраняет только имя от самого узла, learn_name).
    fn hint_name(&self, dest: [u8; 16], name: &str) {
        let Some(n) = norm_peer_name(name, "") else { return };
        {
            let mut h = self.hints.lock().unwrap();
            if h.len() >= 64 && !h.contains_key(&dest) {
                return;
            }
            h.insert(dest, n.clone());
        }
        if let Some(e) = self.servers.lock().unwrap().iter_mut().find(|e| e.dest == dest) {
            e.name = n;
        }
    }

    /// Имя для интерфейса: сохранённое с прошлого допуска, если в записи только короткий dest.
    fn shown_name(&self, e: &CServer) -> String {
        if e.name == "?" || e.name == hex(&e.dest)[..8] {
            if let Some(n) = self.hints.lock().unwrap().get(&e.dest).cloned().or_else(|| self.names.lock().unwrap().get(&e.dest).cloned()) {
                return n;
            }
        }
        e.name.clone()
    }

    /// Имя, которое узел сообщил по допущенному Link (T_AUTH_OK): в списке выходов и в хранилище. Вызывать только после проверки прав узла.
    fn learn_name(&self, dest: [u8; 16], name: &str, cc: &str) {
        let Some(n) = norm_peer_name(name, cc) else { return };
        self.hints.lock().unwrap().insert(dest, n.clone());
        {
            let mut m = self.names.lock().unwrap();
            if m.get(&dest) != Some(&n) && (m.len() < 64 || m.contains_key(&dest)) {
                m.insert(dest, n.clone());
                let j: HashMap<String, &String> = m.iter().map(|(d, v)| (hex(d), v)).collect();
                if let Ok(t) = serde_json::to_vec(&j) {
                    write_atomic(&self.state.join("names.json"), &t);
                }
            }
        }
        if let Some(e) = self.servers.lock().unwrap().iter_mut().find(|e| e.dest == dest) {
            e.name = n;
        }
    }

    fn refresh_servers13(&self) {
        let Some(c) = &self.c13 else { return };
        let mut want: Vec<([u8; 64], Vec<String>)> = Vec::new();
        {
            let inv = c.invite.lock().unwrap();
            let tr = c.trust.lock().unwrap();
            if let Some(i) = inv.as_ref() {
                want.push((i.admin, i.addrs.clone()));
            }
            let mut pks = tr.holders_with(trust::EXIT);
            pks.extend(tr.anchors().into_iter().map(|(_, pk)| pk).filter(|pk| *pk != tr.me_pk));
            for pk in pks {
                if pk != tr.me_pk && !want.iter().any(|w| w.0 == pk) && tr.common_with(&pk, trust::USE, trust::EXIT, false, true, now_ms() as u64) {
                    want.push((pk, vec![]));
                }
            }
        }
        let mut s = self.servers.lock().unwrap();
        let keep: HashSet<[u8; 64]> = want.iter().map(|w| w.0).collect();
        s.retain(|e| e.pk.map(|p| keep.contains(&p)).unwrap_or(true));
        for (pk, addrs) in want {
            let dest = dest_from_pub_tag(&pk, T13_TAG);
            if dest == [0u8; 16] {
                continue;
            }
            let key: [u8; 32] = pk[32..64].try_into().unwrap();
            let addrs = if addrs.is_empty() {
                c.hints.lock().unwrap().get(&hex(&dest)).cloned().unwrap_or_default()
            } else {
                self.remember_addrs(&dest, &addrs);
                addrs
            };
            if let Some(e) = s.iter_mut().find(|e| e.dest == dest) {
                e.pk = Some(pk);
                // имя, сохранённое с прошлого допуска: пока узел не отвечал в этой сессии, в записи только короткий dest
                if e.name == "?" || e.name == hex(&dest)[..8] {
                    let known = self.hints.lock().unwrap().get(&dest).cloned().or_else(|| self.names.lock().unwrap().get(&dest).cloned());
                    if let Some(n) = known {
                        e.name = n;
                    }
                }
                if e.addrs.is_empty() {
                    e.addrs = addrs;
                }
            } else if s.len() < 32 {
                let name = self.hints.lock().unwrap().get(&dest).cloned().or_else(|| self.names.lock().unwrap().get(&dest).cloned()).unwrap_or_else(|| hex(&dest)[..8].to_string());
                s.push(CServer { dest, key, name, ep: hex(&key), addrs, hops: None, rtt_ms: None,
                    state: "seen".into(), seen: Instant::now(), pinned: true, pk: Some(pk) });
            }
        }
    }

    fn merge_table(&self, t: &serde_json::Value) {
        let Some(arr) = t["exits"].as_array() else { return };
        let mut s = self.servers.lock().unwrap();
        for x in arr {
            let (Some(d), Some(k)) = (x["d"].as_str().and_then(dest32), x["k"].as_str().and_then(|k| unhex(k).try_into().ok())) else { continue };
            let name = x["n"].as_str().unwrap_or("?").chars().take(32).collect::<String>();
            let ep = x["e"].as_str().unwrap_or("").to_string();
            let addrs: Vec<String> = x["a"].as_array().map(|a| a.iter().filter_map(|y| y.as_str().map(String::from)).take(3).collect()).unwrap_or_default();
            let rtt = x["r"].as_f64();
            if let Some(e) = s.iter_mut().find(|e| e.dest == d) {
                e.name = name;
                e.seen = Instant::now();
                e.rtt_ms = rtt;
                e.state = x["s"].as_str().unwrap_or("up").into();
                if e.ep.is_empty() {
                    e.ep = ep;
                }
                if e.addrs.is_empty() {
                    e.addrs = addrs;
                }
            } else if s.len() < 32 {
                // сервер, внесённый закреплённым сервером по аутентифицированному Link: доверяем транзитивно (план 4.2)
                s.push(CServer { dest: d, key: k, name, ep, addrs, hops: None, rtt_ms: rtt, state: x["s"].as_str().unwrap_or("up").into(), seen: Instant::now(), pinned: false, pk: None });
            }
        }
        // записи из таблицы, которых нет в свежей таблице, считаются потерянными; закреплённые остаются в списке.
        // Таблица приходит кусками (i из n): собираем присутствующих и «забываем» отсутствующих только после последнего куска.
        let (i, n) = (t["i"].as_u64(), t["n"].as_u64());
        let mut acc = self.table_acc.lock().unwrap();
        if i.unwrap_or(0) == 0 {
            acc.clear();
        }
        acc.extend(arr.iter().filter_map(|x| x["d"].as_str().and_then(dest32)));
        if let (Some(i), Some(n)) = (i, n) {
            if i + 1 < n {
                return;
            }
        }
        let present: HashSet<[u8; 16]> = std::mem::take(&mut *acc);
        s.retain(|e| e.pinned || present.contains(&e.dest) || e.seen.elapsed() < Duration::from_secs(15));
        for e in s.iter_mut() {
            if !present.contains(&e.dest) {
                e.state = "lost".into();
            }
        }
    }

    fn publish_service(&self) {
        let cur = *self.cur.lock().unwrap();
        let current = cur.map(|c| {
            let name = self.servers.lock().unwrap().iter().find(|e| e.dest == c.0).map(|e| self.shown_name(e));
            serde_json::json!({"d":hex(&c.0), "n":name})
        });
        let j = serde_json::json!({"state":if cur.is_some() {"up"} else {"connecting"}, "current":current});
        crate::bgwrite::put(&self.state.join("service.json"), j.to_string().into_bytes(), Duration::ZERO);
    }

    fn write_status(&self, state: &str, up_since: Instant) {
        let cur = *self.cur.lock().unwrap();
        let mut servers = self.servers.lock().unwrap().clone();
        servers.sort_by(|a, b| b.pinned.cmp(&a.pinned).then(a.name.cmp(&b.name)));
        // R8: таблица путей RNS; интерфейс пути -> носитель: `iroh-dg-out-<label>-N` / `tcp-out-<label>-N`, label -> dest узла
        let paths = self.node.path_table();
        let ifaces = self.node.engine().interface_stats();
        let carrier_of = |ifc: usize| -> Option<[u8; 16]> {
            let name = ifaces.iter().find(|i| i.interface_id.0 == ifc)?.name.clone();
            let label = name.strip_prefix("iroh-dg-out-").or_else(|| name.strip_prefix("tcp-out-"))?.rsplit_once('-')?.0.to_string();
            self.carriers.lock().unwrap().iter().find(|(_, x)| *x.label.lock().unwrap() == label).map(|(d, _)| *d)
        };
        // в интерфейсе видны только ноды, которым по записям можно выход или транзит (клиенты с одним USE друг другу не показываются);
        // якорь (админ сети) виден всегда. Легаси (без 0013) не фильтруется
        if let Some(c) = &self.c13 {
            let tr = c.trust.lock().unwrap();
            let anchors: Vec<trust::Pk> = tr.anchors().into_iter().map(|(_, pk)| pk).collect();
            servers.retain(|e| match e.pk {
                Some(pk) => anchors.contains(&pk) || tr.rights(&pk) & (trust::EXIT | trust::TRANSIT) != 0,
                None => false,
            });
        }
        let shown: HashSet<[u8; 16]> = servers.iter().map(|e| e.dest).collect();
        // свежие отчёты других выходов (T_NBRS): какие ноды они видят живым соседом
        let nbr_reports = self.nbrs.lock().unwrap().iter().filter(|(_, report)| report.fresh())
            .map(|(x, report)| (*x, report.neighbors.iter().map(|(d, _)| *d).collect::<Vec<_>>())).collect::<Vec<_>>();
        let exits: Vec<serde_json::Value> = servers.iter().map(|e| {
            let is_cur = cur.map(|c| c.0 == e.dest).unwrap_or(false);
            // ra: сколько других нод сейчас сообщают, что видят эту ноду живым соседом
            let ra = nbr_reports.iter().filter(|(x, v)| *x != e.dest && v.contains(&e.dest)).count();
            // lk (0014 R2): up - текущий выход с живым Link; fail - последняя попытка не удалась (отказ старше 5 мин - none).
            // Недоступной (fail) нода считается, только если её не видит ни одна другая нода; иначе неудача - свойство моего пути, а не ноды
            let (lk, why) = if is_cur {
                ("up", None)
            } else {
                match self.lk_fail.lock().unwrap().get(&e.dest).filter(|(t, _)| t.elapsed() < Duration::from_secs(300)).cloned() {
                    Some((_, w)) if ra == 0 => ("fail", Some(w)),
                    _ => ("none", None),
                }
            };
            let hops = self.node.hops_to(&DestinationHash::new(e.dest));
            // v: у телефона есть своя прямая связь с узлом (QUIC или TCP): так он его «видит»; c: каким носителем
            let carrier = self.carriers.lock().unwrap().get(&e.dest).map(|x| *x.mode.lock().unwrap()).unwrap_or("none");
            let pr_us = self.carriers.lock().unwrap().get(&e.dest).map(|x| x.rtt_us.load(Relaxed)).unwrap_or(0);
            let pr: Option<f64> = if pr_us > 0 { Some(pr_us as f64 / 1000.0) } else { None };
            // id - identity-хеш ноды; adm - в моём собственном корне у неё есть ADD (я могу выбрать её входной нодой приглашения)
            let (id, adm) = match (&self.c13, e.pk.as_ref().and_then(trust::hash_of)) {
                (Some(c), Some(h)) => {
                    let tr = c.trust.lock().unwrap();
                    (Some(hex(&h)), tr.rights_in(&tr.me_hash, &h) & trust::ADD != 0)
                }
                _ => (None, false),
            };
            // vis (R8): direct - путь 1 хоп через мой носитель к этой ноде; via - путь через носитель другой ноды (nh); none - пути нет.
            // Для текущего выхода интерфейс берётся у его Link, иначе - из таблицы путей
            let ifc = cur.filter(|c| c.0 == e.dest).and_then(|c| self.node.engine().link_stats(&c.1)).and_then(|s| s.attached_interface())
                .or_else(|| paths.iter().find(|p| p.hash == e.dest).map(|p| p.interface_index));
            let (vis, nh): (&'static str, Option<[u8; 16]>) = match ifc {
                None => ("none", None),
                Some(i) => match carrier_of(i) {
                    Some(d) if d == e.dest && hops.unwrap_or(1) == 1 => ("direct", None),
                    d => ("via", d.filter(|x| *x != e.dest)),
                },
            };
            // pc (R9): сколько раз менялись vis/nh; первое наблюдение не считается
            let pc = {
                let mut m = self.vis.lock().unwrap();
                if m.contains_key(&e.dest) || m.len() < 32 {
                    let ent = m.entry(e.dest).or_insert((vis, nh, 0));
                    if ent.0 != vis || ent.1 != nh {
                        *ent = (vis, nh, ent.2 + 1);
                    }
                    ent.2
                } else {
                    0
                }
            };
            // q (R9): попытки Link, RTT, давность контакта (для текущего выхода - последний ответ)
            let q = self.qstat.lock().unwrap().get(&e.dest).cloned().unwrap_or_default();
            let rtt = if is_cur { *self.rtt_ms.lock().unwrap() } else { e.rtt_ms };
            let age: Option<u64> = if is_cur {
                let lp = self.last_pong.load(Relaxed);
                if lp == 0 { None } else { Some((now_ms() as u64).saturating_sub(lp) / 1000) }
            } else {
                q.last_ok.map(|t| t.elapsed().as_secs())
            };
            // RNS path/carrier caches are not proof of a live node. Missing observations
            // cannot establish global death: another (unobserved) neighbour may see it.
            let contact = is_cur && (now_ms() as u64).saturating_sub(self.last_pong.load(Relaxed)) <= self.fail_ms;
            let presence = crate::observations::presence(contact, ra);
            serde_json::json!({"n": self.shown_name(e), "d": hex(&e.dest), "h": hops.or(e.hops), "r": e.rtt_ms, "s": if is_cur { "current" } else { e.state.as_str() }, "pinned": e.pinned, "pl": self.platforms.lock().unwrap().get(&e.dest).copied(), "presence": presence,
                "v": carrier != "none", "c": carrier, "lk": lk, "why": why,
                "pr": pr, "id": id, "adm": adm, "ra": ra,
                "vis": vis, "nh": nh.map(|n| hex(&n)), "q": {"ok": q.ok, "fail": q.fail, "rtt": rtt, "pc": pc, "age": age}})
        }).collect();
        // рёбра нода-нода от выходов, которые прислали T_NBRS не старше 60 с (0014 R3)
        let edges: Vec<serde_json::Value> = self.nbrs.lock().unwrap().iter()
            .filter(|(x, report)| report.fresh() && shown.contains(*x))
            .flat_map(|(x, report)| report.neighbors.iter().filter(|(nb, _)| shown.contains(nb)).map(move |(nb, r)| serde_json::json!([hex(x), hex(nb), r])))
            .collect();
        // Маршрут до текущего выхода: Link идёт через интерфейс, на который телефон набрал узел (его имя в названии интерфейса). Если это не сам выход -
        // выход достигается через транзитный узел (первая пересылка); дальше цепочка клиенту неизвестна.
        let via: Option<String> = cur.and_then(|c| {
            let ifc = self.node.engine().link_stats(&c.1)?.attached_interface()?;
            let name = self.node.engine().interface_stats().iter().find(|i| i.interface_id.0 == ifc)?.name.clone();
            let label = name.strip_prefix("iroh-dg-out-").or_else(|| name.strip_prefix("tcp-out-"))?.rsplit_once('-')?.0.to_string();
            let dest_of = self.carriers.lock().unwrap().iter().find(|(_, x)| *x.label.lock().unwrap() == label).map(|(d, _)| *d)?;
            if dest_of == c.0 { None } else { Some(hex(&dest_of)) }
        });
        let j = serde_json::json!({"state": state, "group": self.group, "ip": self.ip, "up_s": up_since.elapsed().as_secs(),
            "current": cur.map(|c| serde_json::json!({"d": hex(&c.0), "n": servers.iter().find(|e| e.dest == c.0).map(|e| e.name.clone()), "since_s": c.2.elapsed().as_secs(),
                "rtt_ms": *self.rtt_ms.lock().unwrap(), "hops": self.node.hops_to(&DestinationHash::new(c.0)),
                "carrier": self.carriers.lock().unwrap().get(&c.0).map(|x| *x.mode.lock().unwrap()), "via": via})),
            "log_tail": self.sh.log.lock().unwrap().iter().rev().take(25).map(|(t, m)| format!("{} {}", *t as u64, m)).collect::<Vec<_>>(),
            "selected": std::fs::read_to_string(self.state.join("select")).unwrap_or_default().trim().to_string(),
            "bench": self.bench_last.lock().unwrap().clone(),
            "routing": self.routing_json(&servers),
            "exits": exits, "edges": edges, "tun": self.tun.stats(), "udp": udp_stats(), "failovers": self.failovers.lock().unwrap().clone(), "status": self.status.lock().unwrap().clone(),
            "users": self.c13.as_ref().map(|c| c.users.lock().unwrap().iter().map(|(h, t)| serde_json::json!({"h": &h[..8], "t": t})).collect::<Vec<_>>()).unwrap_or_default(),
            "pol": pol_counters(),
            "policy": self.c13.as_ref().map(|c| c.trust.lock().unwrap().policy_view(now_ms() as u64).iter()
                .map(|(r, g, o, e)| serde_json::json!({"root": hex(r), "tag": trust::root_tag(r), "grant": g, "offer": o, "eff": e})).collect::<Vec<_>>()).unwrap_or_default(),
            "ts_ms": now_ms() as u64});
        // раз в секунду читает интерфейс приложения: частота прежняя, но запись не в async-задаче
        crate::bgwrite::put(&self.state.join("status.json"), j.to_string().into_bytes(), Duration::ZERO);
    }
}

pub async fn run_client(a: ClientArgs) -> Result<()> {
    // легаси: профиль rawg2- (seed клиента внутри); 0013: своя identity в --state, права и выходы - записями
    let (prof, identity, c13) = match &a.profile_file {
        Some(f) => {
            let prof = decode_profile(&std::fs::read_to_string(f).context("profile file")?)?;
            let id = client_identity(&prof.seed)?;
            (prof, id, None)
        }
        None => {
            let id = load_or_create_identity(&a.state)?;
            let my_pk = id.public_key_bytes();
            let raw = match &a.invite_file {
                Some(f) => std::fs::read_to_string(f).with_context(|| format!("invite-file {}", f.display()))?,
                None => a.invite.clone(),
            };
            let tr = trust::Trust::load(id.clone(), &a.state).context("trust.json")?;
            let mut inv = None;
            if !raw.trim().is_empty() {
                match trust::Invite::parse(&raw) {
                    Ok(i) => {
                        // запись по этому приглашению уже есть (выдана админом после его создания): приглашение использовано.
                        // Android передаёт сохранённое приглашение при каждом подключении, повторно зачисляться не надо.
                        let used = invite_used(&i, &my_pk, &tr.chain_for(&my_pk));   // и отзыв по нему: приглашение тоже использовано
                        if i.root().ok() == Some(*id.hash()) || i.admin == my_pk {
                            bail!("приглашение не может зачислить эту identity или выдано ею самой");
                        } else if i.root().map(|root| tr.has_anchor(&root)).unwrap_or(false) {
                            eprintln!("приглашение игнорируется: этот корень уже в якорях");
                        } else if used {
                            eprintln!("приглашение уже использовано: запись админа по нему есть");
                        } else if !i.fresh(now_ms() as u64 / 1000) {
                            bail!("приглашение просрочено или датировано будущим: попросите новое у админа");
                        } else {
                            inv = Some(i);
                        }
                    }
                    Err(e) if tr.anchors().len() > 1 || tr.record_count() > 0 => {
                        // клиент уже зачислен: мусорное или устаревшее приглашение не должно мешать работе
                        eprintln!("приглашение не разобрано ({e:#}), но записи есть - продолжаю без него");
                    }
                    Err(e) => {
                        return Err(e).context("приглашение");
                    }
                }
            }
            let prof = Profile { group: String::new(), seed: [0u8; 32], ip: client_ip(id.hash()), s: vec![] };
            let mut hints: HashMap<String, Vec<String>> = std::fs::read(a.state.join("hints.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            migrate_hints(&mut hints, tr.holders_with(trust::USE | trust::TRANSIT | trust::EXIT).into_iter().chain(tr.anchors().into_iter().map(|(_, pk)| pk)));
            (prof, id, Some(C13 { trust: Mutex::new(tr), invite: Mutex::new(inv), rejected: Mutex::new(None), peers: Mutex::new(HashMap::new()), hints: Mutex::new(hints),
                enrollees: Mutex::new(HashMap::new()), enrolled: Mutex::new(HashSet::new()), enroll_try: Mutex::new(HashMap::new()),
                relays: Mutex::new(HashMap::new()), users: Mutex::new(Vec::new()), early: Mutex::new(Vec::new()) }))
        }
    };
    let tun_arg = a.tun_fd.to_string();
    // без дескриптора от VpnService (лаборатория, Linux) TUN создаётся самим процессом и получает адрес, выведенный из identity
    let tun_ip = format!("{}/{}", ip_str(prof.ip), client_net().1);
    let mut extra: Vec<&str> = vec!["--tun-fd", &tun_arg, "--tun-mtu", "1327", "--path-keepalive-ms", "4000", "--conn-idle-ms", "12000"];
    if a.tun_fd < 0 && c13.is_some() {
        extra.extend(["--tun-ip", &tun_ip]);
    }
    let b = start_base("c", &a.state, false, None, SecretKey::generate(), a.quic_cc_mbit, &extra, None).await?;
    let (node, sh, ep, cli, events) = (b.node.clone(), b.sh.clone(), b.ep.clone(), b.cli.clone(), b.events);
    let tun = TunState::open(&cli, false)?;
    let _ = sh.tun.set(tun.clone());
    tokio::spawn(tun_reader(tun.clone(), node.clone(), sh.clone()));

    let servers: Vec<CServer> = prof.s.iter().map(|s| CServer { dest: s.d, key: s.k, name: s.n.clone(), ep: hex(&s.k), addrs: s.a.clone(),
        hops: None, rtt_ms: None, state: "seen".into(), seen: Instant::now(), pinned: true, pk: None }).collect();
    if servers.is_empty() && c13.is_none() {
        bail!("в профиле нет серверов");
    }
    let ctx = Arc::new(ClientCtx { node: node.clone(), sh: sh.clone(), ep: ep.clone(), identity, group: prof.group.clone(), ip: ip_str(prof.ip), servers: Mutex::new(servers.clone()), tun,
        auth_wait: Mutex::new(HashMap::new()), cur: Mutex::new(None), last_pong: Default::default(), rtt_pong: Default::default(), rtt_ms: Mutex::new(None), failovers: Mutex::new(Vec::new()),
        state: a.state.clone(), status: Mutex::new("подключаюсь".into()), dialers: Mutex::new(HashMap::new()),
        carriers: Mutex::new(HashMap::new()), public_ids: Mutex::new(Vec::new()), names: Mutex::new(load_names(&a.state)), hints: Mutex::new(HashMap::new()), platforms: Mutex::new(HashMap::new()), books: Mutex::new(HashMap::new()), table_acc: Mutex::new(HashSet::new()), loss: Mutex::new(LossWin::default()), fail_ms: a.fail_ms,
        c13, path_gate: path::PathGate::default(), nbrs: Mutex::new(HashMap::new()), admitted_exits: Mutex::new(HashMap::new()), ctrl: Mutex::new(HashMap::new()), lk_fail: Mutex::new(HashMap::new()), vis: Mutex::new(HashMap::new()), qstat: Mutex::new(HashMap::new()),
        bench_sess: Mutex::new(None), bench_last: Mutex::new(None),
        rcfg: std::sync::RwLock::new(Arc::new(route::Cfg::default())), rreport: Mutex::new(serde_json::Value::Null), rpending: Mutex::new(HashSet::new()), rback: Mutex::new(HashMap::new()) });
    if ctx.c13.is_some() {
        // (а) админ без приглашения объявляет свой корень: destination только для анонса, Link к нему не принимаем
        let mut dest = new_dest(ctx.identity.clone(), Direction::In, T13_TAG)
            .map_err(|e| anyhow::anyhow!("destination: {e:?}"))?;
        dest.set_accepts_links(false);
        let dh = *dest.hash().as_bytes();
        node.register_destination(dest);
        tokio::spawn(client_announce(ctx.clone(), dh));
        ctx.refresh_servers13();
        tokio::spawn(client_policy_loop(ctx.clone()));
        let note = {
            let c = ctx.c13.as_ref().unwrap();
            let tr = c.trust.lock().unwrap();
            format!("модель 0013: якорей {}, записей {}{}", tr.anchors().len(), tr.record_count(), if c.invite.lock().unwrap().is_some() { ", жду зачисления по приглашению" } else { "" })
        };
        sh.note(note);
    }
    // Публичная сеть RNS: только анонсы и первый Link (данные не идут: link_is_public закрывает Link через неё)
    let public = load_public_list(&a.public_rns_file, &[]);
    let mut public_handles = Vec::new();
    for e in &public {
        let Some((host, port)) = e.rsplit_once(':').and_then(|(h, p)| Some((h.trim_matches(|c| c == '[' || c == ']'), p.parse::<u16>().ok()?))) else {
            sh.note(format!("публичный узел {e:?}: нужен host:порт"));
            continue;
        };
        let conf: leviculum_std::api::InterfaceConfig = serde_json::from_value(serde_json::json!({
            "name": format!("pub-{host}"), "type": "TCPClientInterface", "target_host": host, "target_port": port, "mode": "roaming"}))
            .map_err(|e| anyhow::anyhow!("интерфейс {host}: {e}"))?;
        match node.spawn_interface(conf) {
            Ok(ids) => {
                ctx.public_ids.lock().unwrap().extend(ids.iter().map(|i| i.0));
                public_handles.push(ids)
            }
            Err(e) => sh.note(format!("публичный узел {host}:{port}: {e}")),
        }
    }
    if !public.is_empty() {
        sh.note(format!("публичных узлов RNS подключено: {} из {}", public_handles.len(), public.len()));
    }
    let servers = ctx.servers.lock().unwrap().clone();
    for s in &servers {
        start_dialer(&ctx, s);
    }
    {
        // имена узлов с прошлых допусков (state/names.json) - сразу в список, не дожидаясь подключения к каждому
        let nm = ctx.names.lock().unwrap().clone();
        for e in ctx.servers.lock().unwrap().iter_mut() {
            if let Some(n) = nm.get(&e.dest) {
                e.name = n.clone();
            }
        }
    }
    tokio::spawn(client_events(ctx.clone(), events));
    tokio::spawn(client_bench(ctx.clone()));
    // Прямая связь телефона с узлом (наш носитель QUIC/TCP) должна быть и путём RNS. Путь уходит на транзит, когда копия свежего анонса
    // пришла через соседа раньше прямой или носитель переподключился; сам RNS его не вернёт до следующего анонса (600 с).
    // Раз в 60 с на узел спрашиваем путь только по носителю к нему: ответ самого узла (1 хоп, свежий) RNS примет штатно.
    // Путь не удаляем; запрос - через общий ограничитель (один владелец, не чаще 20 с на destination).
    {
        let c2 = ctx.clone();
        tokio::spawn(async move {
            let mut asked: HashMap<[u8; 16], Instant> = HashMap::new();
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let servers = c2.servers.lock().unwrap().clone();
                let ifs = c2.node.engine().interface_stats();
                asked.retain(|_, t| t.elapsed() < Duration::from_secs(60));
                for sv in servers {
                    if asked.contains_key(&sv.dest) {
                        continue;
                    }
                    let label = {
                        let cs = c2.carriers.lock().unwrap();
                        match cs.get(&sv.dest) {
                            Some(x) if *x.mode.lock().unwrap() != "none" => x.label.lock().unwrap().clone(),
                            _ => continue,
                        }
                    };
                    if label.is_empty() {
                        continue;
                    }
                    let dh = DestinationHash::new(sv.dest);
                    let (pq, pt) = (format!("iroh-dg-out-{label}-"), format!("tcp-out-{label}-"));
                    let Some(own) = ifs.iter().filter(|i| i.online && (i.name.starts_with(&pq) || i.name.starts_with(&pt))).map(|i| i.interface_id.0).max() else { continue };
                    let path = c2.node.engine().get_path_clone(&dh);
                    if path.as_ref().map(|p| p.interface_index == own && p.hops <= 1).unwrap_or(false) {
                        continue;   // путь уже прямой
                    }
                    let Some(lease) = c2.path_gate.begin(sv.dest, Instant::now()) else { continue };
                    if lease.request_due(Instant::now()) {
                        let _ = c2.node.engine().request_path_on(&dh, &[own]).await;
                        asked.insert(sv.dest, Instant::now());
                    }
                }
            }
        });
    }
    // Android sends the existing ConnectivityManager event through JNI. CLI retains its file hook.
    {
        let (ep2, f) = (ep.clone(), a.state.join("netchange"));
        tokio::spawn(async move {
            let mut changes = crate::mobile::network_changes();
            loop {
                let event = if cfg!(target_os = "android") {
                    changes.changed().await.is_ok()
                } else {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    f.exists()
                };
                if event {
                    changes.borrow_and_update();
                    if !cfg!(target_os = "android") {
                    let _ = std::fs::remove_file(&f);
                    }
                    ep2.network_change().await;
                }
            }
        });
    }
    tokio::spawn(route_manager(ctx.clone()));
    let up_since = Instant::now();
    let c2 = ctx.clone();
    tokio::spawn(async move {
        let mut visibility = crate::mobile::ui_changes();
        loop {
            let st = if c2.cur.lock().unwrap().is_some() { "up" } else { "connecting" };
            c2.publish_service();
            c2.write_status(st, up_since);
            crate::mobile::next_status(&mut visibility).await;
        }
    });
    let c2 = ctx.clone();
    tokio::spawn(async move {
        let mut visibility = crate::mobile::ui_changes();
        while visibility.changed().await.is_ok() {
            let visible = *visibility.borrow_and_update();
            let links: Vec<_> = c2.admitted_exits.lock().unwrap().keys().copied().collect();
            for link in links { spawn_ctl(&c2.node, link, T_OBSERVE, vec![u8::from(visible)]); }
        }
    });
    client_supervisor(ctx.clone()).await;
    drop(public_handles);
    ep.close().await;
    let rejected = ctx.c13.as_ref().and_then(|c| c.rejected.lock().unwrap().clone());
    if let Some(why) = rejected {
        bail!("зачисление отклонено админом: {why}");
    }
    Ok(())
}

/// Зачисление по приглашению. Админ - нода с адресом: идём к нему напрямую (T_PAIR1). Админ - телефон за NAT (адресов в приглашении нет):
/// просимся через ноду его сети (T_PAIRQ), а он подтверждает, пока приложение у него включено.
async fn pair_client(ctx: &Arc<ClientCtx>) -> Result<()> {
    let Some(c) = &ctx.c13 else { return Ok(()) };
    let Some(inv) = c.invite.lock().unwrap().clone() else { return Ok(()) };
    let dest = dest_from_pub_tag(&inv.admin, T13_TAG);
    let direct = ctx.servers.lock().unwrap().iter().any(|s| s.dest == dest && !s.addrs.is_empty());
    if direct {
        pair_direct(ctx).await
    } else {
        pair_via_relay(ctx).await
    }
}

/// A (клиент): таблица попыток зачисления. Записи старше ENROLL_TRY_TTL выкидываем; новый ключ сверх ENROLL_TRY_MAX не вставляем (`false`).
/// Вытеснять самую старую не стали: чужие анонсы тогда сбивали бы таблицу и тратили попытки; отказ лишь не даёт запомнить попытку.
fn enroll_try_put(t: &mut HashMap<[u8; 16], Instant>, dest: [u8; 16], now: Instant) -> bool {
    t.retain(|_, x| now.saturating_duration_since(*x) < ENROLL_TRY_TTL);
    if !t.contains_key(&dest) && t.len() >= ENROLL_TRY_MAX {
        return false;
    }
    t.insert(dest, now);
    true
}

/// Через посредника: Link к ноде сети админа, identify, T_PAIRQ раз в 6 с; ответ - T_REC с записью о нас (on_rec_client).
async fn pair_via_relay(ctx: &Arc<ClientCtx>) -> Result<()> {
    let Some(c) = &ctx.c13 else { return Ok(()) };
    let Some(inv) = c.invite.lock().unwrap().clone() else { return Ok(()) };
    *ctx.status.lock().unwrap() = "ищу ноды сети админа".into();
    let t0 = Instant::now();
    let cand = loop {
        let pick = {
            let tried = c.enroll_try.lock().unwrap();
            let mut relays: Vec<CServer> = c.relays.lock().unwrap().values().cloned().collect();
            // Повторное приглашение того же админа (смена прав): узлы его сети уже известны по записям, ждать их анонса (600 с) незачем.
            // Посредник - узел с действующим TRANSIT или EXIT в корне админа (по подписанным записям, не по анонсу).
            {
                let tr = c.trust.lock().unwrap();
                let Ok(root) = inv.root() else { return Ok(()) };
                for s in ctx.servers.lock().unwrap().iter() {
                    let member = s.pk.and_then(|pk| trust::hash_of(&pk)).map(|h| tr.rights_in(&root, &h) & (trust::TRANSIT | trust::EXIT) != 0).unwrap_or(false);
                    if member && relays.len() < 32 && !relays.iter().any(|r| r.dest == s.dest) {
                        relays.push(s.clone());
                    }
                }
            }
            let best = relays.iter()
                .filter(|s| tried.get(&s.dest).map(|t| t.elapsed() > Duration::from_secs(20)).unwrap_or(true))
                .min_by_key(|s| tried.get(&s.dest).map(|t| std::cmp::Reverse(t.elapsed())))
                .cloned();
            best
        };
        if let Some(s) = pick {
            break s;
        }
        if t0.elapsed() > Duration::from_secs(60) {
            bail!("нет нод сети админа в анонсах (публичная RNS пуста или анонсы не доходят)");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    // предел таблицы: без места попытка всё равно идёт (это действие владельца приглашения), только не запоминается
    let _ = enroll_try_put(&mut c.enroll_try.lock().unwrap(), cand.dest, Instant::now());
    *ctx.status.lock().unwrap() = format!("прошусь к админу через {}", cand.name);
    // ADR 0016: анонс адреса не несёт; без адреса идём к посреднику по пути RNS (Link сквозь зашифрован, ключ посредника проверен анонсом)
    let id = if cand.addrs.is_empty() {
        rns_link(ctx, &cand).await?
    } else {
        start_dialer(ctx, &cand);
        direct_link(ctx, &cand).await?
    };
    c.peers.lock().unwrap().insert(id, cand.pk.unwrap_or([0u8; 64]));
    ctx.node.identify_link(&id, &ctx.identity).await.map_err(|e| anyhow::anyhow!("identify: {e:?}"))?;
    let my_pk = ctx.identity.public_key_bytes();
    let (Ok(root), Ok(admin), Ok(mac)) = (inv.root(), inv.admin_hash(), inv.mac(&my_pk)) else { return Ok(()) };
    let body = pairq_body(root, admin, &my_pk, &mac);
    ctx.sh.note(format!("зачисление: прошусь к админу через {}", cand.name));
    *ctx.status.lock().unwrap() = format!("жду подтверждения админа (через {})", cand.name);
    let t = Instant::now();
    let mut last = Instant::now() - Duration::from_secs(60);
    while t.elapsed() < Duration::from_secs(24) {
        if c.invite.lock().unwrap().is_none() {
            break;
        }
        if last.elapsed() >= Duration::from_secs(6) {
            last = Instant::now();
            send_ctl(&ctx.node, id, T_PAIRQ, &body).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if c.invite.lock().unwrap().is_none() {
        // Посредник допускает нас соседом и шлёт выгрузку сети следом за записью о нас: ждём, пока она дойдёт (иначе нода-новичок знает
        // лишь свою запись и не поднимает Link с соседями).
        tokio::time::sleep(Duration::from_millis(4500)).await;
    }
    let _ = ctx.node.engine().close_link(&id).await;
    c.peers.lock().unwrap().remove(&id);
    if c.invite.lock().unwrap().is_some() {
        bail!("админ не подтвердил (телефон админа выключен или не подключён к сети?)");
    }
    Ok(())
}

/// Зачисление клиента по приглашению: Link к админу, identify, T_PAIR1; ответ - обычная T_REC с записью о нас (on_rec_client).
async fn pair_direct(ctx: &Arc<ClientCtx>) -> Result<()> {
    let Some(c) = &ctx.c13 else { return Ok(()) };
    let Some(inv) = c.invite.lock().unwrap().clone() else { return Ok(()) };
    let dest = dest_from_pub_tag(&inv.admin, T13_TAG);
    let cand = ctx.servers.lock().unwrap().iter().find(|s| s.dest == dest).cloned().ok_or_else(|| anyhow::anyhow!("админ приглашения не в списке выходов"))?;
    *ctx.status.lock().unwrap() = "зачисляюсь по приглашению".into();
    let (id, _h) = open_link(ctx, &cand, None).await?;
    c.peers.lock().unwrap().insert(id, inv.admin);
    ctx.node.identify_link(&id, &ctx.identity).await.map_err(|e| anyhow::anyhow!("identify: {e:?}"))?;
    let my_pk = ctx.identity.public_key_bytes();
    let mut body = my_pk.to_vec();
    let Ok(mac) = inv.mac(&my_pk) else { return Ok(()) };
    body.extend_from_slice(&mac);
    send_ctl(&ctx.node, id, T_PAIR1, &body).await;
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(10) {
        if c.invite.lock().unwrap().is_none() || c.rejected.lock().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = ctx.node.engine().close_link(&id).await;
    c.peers.lock().unwrap().remove(&id);
    if c.invite.lock().unwrap().is_some() && c.rejected.lock().unwrap().is_none() {
        bail!("админ не ответил на зачисление");
    }
    Ok(())
}

/// Запись от узла по Link клиента: завершение зачисления (запись о нас от админа приглашения) и пополнение списка выходов.
/// Соседи выхода (0014 R3): принимаем только от текущего выхода по его Link. Это подсказка для рёбер, список выходов не меняем.
fn on_nbrs_client(ctx: &ClientCtx, link: LinkId, body: &[u8]) {
    if body.len() > 4096 { return; }
    let Some(source) = ctx.admitted_exits.lock().unwrap().get(&link).copied() else { return };
    let source_server = ctx.servers.lock().unwrap().iter().find(|s| s.dest == source).cloned();
    if !source_server.as_ref().map(|s| exit_eligible(ctx, s)).unwrap_or(false) { return; }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else { return };
    let known: HashSet<_> = ctx.servers.lock().unwrap().iter().map(|s| s.dest).collect();
    let list: Vec<([u8; 16], Option<f64>)> = v["n"].as_array().map(|a| {
        a.iter().take(NBRS_MAX).filter_map(|x| {
            let d = x["d"].as_str().filter(|d| d.len() == 32 && d.bytes().all(|b| b.is_ascii_hexdigit()))?;
            let dest = dest32(d)?;
            if !known.contains(&dest) { return None; }
            if let Some(n) = x["n"].as_str() {
                ctx.hint_name(dest, n);
            }
            if let Some(pl) = x["pl"].as_str().and_then(|p| parse_platform(p.as_bytes())) {
                let mut m = ctx.platforms.lock().unwrap();
                if m.len() < 64 || m.contains_key(&dest) {
                    m.insert(dest, pl);
                }
            }
            // клиент выхода с правами узла (телефон-админ): только имя и тип, не ребро соседства
            if x["c"].as_u64() == Some(1) { return None; }
            Some((dest, x["r"].as_f64().filter(|r| *r >= 0.0)))
        }).collect()
    }).unwrap_or_default();
    let mut reports = ctx.nbrs.lock().unwrap();
    reports.retain(|_, r| r.fresh());
    if reports.len() < 32 || reports.contains_key(&source) {
        reports.insert(source, NbrReport { received: Instant::now(), ttl: crate::observations::report_ttl(&v), neighbors: list });
    }
}

/// T_POL у клиента: политика выхода (выключил EXIT - в кандидаты не берём). Принимается только на Link, где мы знаем собеседника.
fn on_pol_client(ctx: &Arc<ClientCtx>, link: LinkId, body: &[u8]) {
    POL_RX.fetch_add(1 + body.len() as u64, Relaxed);
    POL_RX_N.fetch_add(1, Relaxed);
    let Some(c) = &ctx.c13 else { return };
    if body.len() != trust::POL_LEN || !c.peers.lock().unwrap().contains_key(&link) {
        return;
    }
    let Some(pol) = trust::Policy::parse(body) else { return };
    let off = c.trust.lock().unwrap().offer_policy(pol, now_ms() as u64);
    if off == trust::Offer::Added {
        if let Err(e) = c.trust.lock().unwrap().save() {
            ctx.sh.note(format!("trust.json не записан: {e:#}"));
        }
        ctx.refresh_servers13();
    }
}

fn on_rec_client(ctx: &Arc<ClientCtx>, link: LinkId, body: &[u8]) {
    let Some(c) = &ctx.c13 else { return };
    if body.len() != trust::REC_LEN {
        return;
    }
    if !c.peers.lock().unwrap().contains_key(&link) {
        return;
    }
    let Some(rec) = trust::Record::parse(body) else { return };
    let pending_inv = c.invite.lock().unwrap().clone();
    let mut done = false;
    if let Some(inv) = pending_inv.as_ref() {
        if inv.root().ok() == Some(rec.root) {
            let mut early = c.early.lock().unwrap();
            let _ = early_push(&mut early, link, rec.clone(), &rec.root);
            let records: Vec<trust::Record> = early.iter().map(|(_, r)| r.clone()).collect();
            if let Some(proof) = enrollment_proof(&ctx.identity, inv, &records) {
                let mut tr = c.trust.lock().unwrap();
                if inv.root_pk().and_then(|pk| tr.add_anchor(&pk).map(|_| ())).is_ok() {
                    for r in proof { let _ = tr.offer(r); }
                    *c.invite.lock().unwrap() = None;
                    done = true;
                }
            }
        }
    }
    let mut off = if pending_inv.as_ref().and_then(|i| i.root().ok()) == Some(rec.root) && !done {
        trust::Offer::Rejected("чужой корень")
    } else {
        c.trust.lock().unwrap().offer(rec.clone())
    };
    if done {
        let early: Vec<(LinkId, trust::Record)> = std::mem::take(&mut *c.early.lock().unwrap());
        let mut tr = c.trust.lock().unwrap();
        for (_, r) in early {
            if tr.offer(r) == trust::Offer::Added {
                off = trust::Offer::Added;
            }
        }
    }
    if done || off == trust::Offer::Added {
        if let Err(e) = c.trust.lock().unwrap().save() {
            ctx.sh.note(format!("trust.json не записан: {e:#}"));
        }
        ctx.refresh_servers13();
        start_dialers(ctx);
    }
    if done {
        ctx.sh.note("зачисление подтверждено цепочкой до корня приглашения; приглашение больше не используется".to_string());
    }
}

/// Анонс неизвестной ноды с тегом корня, который мы признаём (якорь или админ ожидающего приглашения): запоминаем адрес, чтобы после зачисления
/// выход нашёлся без нового анонса; если приглашение ещё не принято - нода кандидат в посредники зачисления (T_PAIRQ). Адрес - подсказка, не доверие.
fn maybe_relay(ctx: &Arc<ClientCtx>, pk: &[u8; 64], v: &serde_json::Value, dest: [u8; 16], name: &str, addrs: &[String]) {
    let Some(c) = &ctx.c13 else { return };
    let (mut tags, pending, only) = {
        let tr = c.trust.lock().unwrap();
        let inv = c.invite.lock().unwrap();
        (tr.tags(), inv.as_ref().and_then(|i| i.root().ok()).map(|r| trust::root_tag(&r)), inv.as_ref().map(|i| i.nodes.clone()).unwrap_or_default())
    };
    if let Some(p) = &pending {
        tags.push(p.clone());
    }
    let theirs: Vec<&str> = v["r"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
    if !tags.iter().any(|t| theirs.contains(&t.as_str())) {
        return;
    }
    ctx.remember_addrs(&dest, addrs);
    let Some(p) = pending else { return };
    if !theirs.contains(&p.as_str()) {
        return;
    }
    // админ выбрал входные ноды: посредником зачисления может быть только одна из них (identity нода доказывает на Link, анонс - лишь подсказка)
    if !only.is_empty() && !trust::hash_of(pk).map(|h| only.contains(&h)).unwrap_or(false) {
        return;
    }
    let mut r = c.relays.lock().unwrap();
    if r.len() >= 16 && !r.contains_key(&dest) {
        return;
    }
    r.insert(dest, CServer { dest, key: pk[32..64].try_into().unwrap(), name: name.to_string(), ep: v["e"].as_str().unwrap_or("").to_string(), addrs: addrs.to_vec(),
        hops: None, rtt_ms: None, state: "relay".into(), seen: Instant::now(), pinned: false, pk: Some(*pk) });
}

/// Админ-режим клиента (телефон): анонс ноды, ждущей НАШЕГО приглашения (в `r` тег моего корня, ключ мне не знаком, есть свежий pin).
/// Нода за NAT или без адреса недостижима для админа, поэтому набираем мы: адрес берём из анонса (подсказка, не доверие).
fn maybe_enroll(ctx: &Arc<ClientCtx>, pk: &[u8; 64], v: &serde_json::Value, dest: [u8; 16], name: String, addrs: Vec<String>) {
    let Some(c) = &ctx.c13 else { return };
    let roots = trust::pin_roots_fresh(&ctx.state);
    let announced: Vec<&str> = v["r"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
    let waiting = roots.iter().any(|r| announced.contains(&trust::root_tag(r).as_str()));
    if !waiting || c.trust.lock().unwrap().rights(pk) != 0 {
        return;
    }
    {
        let mut t = c.enroll_try.lock().unwrap();
        if t.get(&dest).map(|x| x.elapsed() < Duration::from_secs(60)).unwrap_or(false) || !enroll_try_put(&mut t, dest, Instant::now()) {
            return;
        }
    }
    let ep = v["e"].as_str().unwrap_or("").to_string();
    if !addrs.is_empty() {
        ctx.remember_addrs(&dest, &addrs); // легаси-анонс с адресом; в 0013 адрес придёт по T_DIR на Link зачисления
    }
    let (ctx2, pk2) = (ctx.clone(), *pk);
    ctx.sh.note(format!("нода {name} ({}) ждёт приглашения: открываю Link по пути RNS", &hex(&dest)[..8]));
    tokio::spawn(async move {
        if let Err(e) = enroll_node(&ctx2, dest, pk2, ep, name.clone(), addrs).await {
            ctx2.sh.note(format!("зачисление ноды {name}: {e:#}"));
        }
    });
}

/// Дозвониться до ожидающей ноды своим носителем (QUIC), открыть Link по нему (не через публичную RNS), identify; дальше нода шлёт T_PAIR1.
async fn enroll_node(ctx: &Arc<ClientCtx>, dest: [u8; 16], pk: [u8; 64], ep: String, name: String, addrs: Vec<String>) -> Result<()> {
    let Some(c) = &ctx.c13 else { return Ok(()) };
    let cand = CServer { dest, key: pk[32..64].try_into().unwrap(), name: name.clone(), ep, addrs, hops: None, rtt_ms: None,
        state: "enroll".into(), seen: Instant::now(), pinned: false, pk: Some(pk) };
    if !cand.addrs.is_empty() {
        start_dialer(ctx, &cand);
    }
    let res = enroll_link(ctx, c, &cand).await;
    if res.is_err() {
        // неудавшуюся попытку не держим: носитель и дозвон нужны только тем нодам, что стали выходами
        if let Some(a) = ctx.dialers.lock().unwrap().remove(&dest) {
            a.store(false, Relaxed);
        }
        ctx.carriers.lock().unwrap().remove(&dest);
    }
    res
}

/// Link к ожидающей ноде по любому пути RNS (ADR 0016): адреса нет, путь строит RNS. Link сквозь зашифрован, ключ ноды сверяется
/// с анонсом (`connect_with_key`) и ещё раз при T_PAIR1; допуск даёт только pin приглашения.
async fn rns_link(ctx: &Arc<ClientCtx>, cand: &CServer) -> Result<LinkId> {
    let dh = DestinationHash::new(cand.dest);
    // Публичная RNS нужна для координации (анонсы, поиск узла). Когда таблица путей уже есть и у нас живут носители к своим нодам,
    // сначала идём через них (транзит нашей ноды, Link в GCM как на любом нашем пути), и лишь потом через публичные хабы (CBC).
    if let Some(r) = link_via_ours(ctx, cand).await {
        return Ok(r);
    }
    let until = Instant::now() + Duration::from_secs(20);
    let mut pending = ctx.path_gate.begin(cand.dest, Instant::now());
    while !ctx.node.has_path(&dh) && Instant::now() < until {
        if pending.is_none() { pending = ctx.path_gate.begin(cand.dest, Instant::now()); }
        if pending.as_ref().map(|p| p.request_due(Instant::now())).unwrap_or(false) {
            let _ = ctx.node.engine().request_path(&dh).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    drop(pending);
    // Публичные хабы ведут себя по-разному: часть из них не пропускает Link-запрос или подтверждение (стандартный Python RNS на таком пути виснет так же).
    // Путь выбирает RNS, но если Link по нему не встал, забываем путь и спрашиваем остальные публичные интерфейсы по очереди.
    let ids = ctx.public_ids.lock().unwrap().clone();
    let public: Vec<usize> = ctx.node.engine().interface_stats().iter().filter(|i| i.online && ids.contains(&i.interface_id.0)).map(|i| i.interface_id.0).collect();
    let (mut tried, mut asked): (Vec<usize>, Vec<usize>) = (Vec::new(), Vec::new());
    let mut err = anyhow::anyhow!("нет пути до {}", cand.name);
    for round in 0..=public.len().min(4) {
        if round > 0 {
            let Some(next) = public.iter().copied().find(|i| !asked.contains(i) && !tried.contains(i)) else { break };
            asked.push(next);
            wait_scoped_path(&ctx.node, &ctx.path_gate, &dh, || vec![next], None, 20).await;
            if !scoped_path(&ctx.node, &dh, &[next], None) { continue; }
        }
        if !ctx.node.has_path(&dh) {
            continue;
        }
        // через этот интерфейс Link уже пробовали: другой путь не нашёлся
        if let Some(v) = ctx.node.engine().path_table_entries().iter().find(|p| p.hash == cand.dest).map(|p| p.interface_index) {
            if tried.contains(&v) {
                continue;
            }
            tried.push(v);
        }
        let via = ctx.node.engine().path_table_entries().iter().find(|p| p.hash == cand.dest).map(|p| {
            let name = ctx.node.engine().interface_stats().iter().find(|i| i.interface_id.0 == p.interface_index).map(|i| i.name.clone()).unwrap_or_default();
            format!("{name}, транспорт {}", p.next_hop.map(|h| hex(&h)[..8].to_string()).unwrap_or_else(|| "-".into()))
        });
        ctx.sh.note(format!("link по пути RNS до {}: хопов {:?}, попытка {} из {} публичных интерфейсов, путь через {}", &hex(&cand.dest)[..8], ctx.node.hops_to(&dh), round + 1, public.len(), via.unwrap_or_default()));
        // чужие транспорты принимают только стандартный CBC, поэтому Link зачисления в CBC (на ноде такой Link допускается лишь на зачисление),
        // а VPN-данные идут по нашим носителям в GCM; по публичной RNS это несколько хабов: окно установления шире, чем на прямом хопе
        match open_link_wait(ctx, cand, None, 12, leviculum_std::api::LinkCipher::Cbc).await {
            Ok((id, _h)) => return Ok(id),
            Err(e) => err = e,
        }
    }
    Err(err)
}

/// Link до ноды по пути через наши носители (транзит наших нод): None, если носителей нет, путь не нашёлся или Link не встал.
async fn link_via_ours(ctx: &Arc<ClientCtx>, cand: &CServer) -> Option<LinkId> {
    let dh = DestinationHash::new(cand.dest);
    let ours = carrier_ifaces(ctx, None);
    if ours.is_empty() {
        return None;
    }
    let on_ours = |ctx: &ClientCtx| -> bool {
        ctx.node.engine().path_table_entries().iter().find(|p| p.hash == cand.dest).map(|p| ours.contains(&p.interface_index)).unwrap_or(false)
    };
    wait_scoped_path(&ctx.node, &ctx.path_gate, &dh, || carrier_ifaces(ctx, None), None, 8).await;
    if !(ctx.node.has_path(&dh) && on_ours(ctx)) {
        ctx.sh.note(format!("зачисление {}: через наши ноды пути нет, пробую публичные хабы", &hex(&cand.dest)[..8]));
        return None;
    }
    ctx.sh.note(format!("link до {} через наши ноды: хопов {:?}", &hex(&cand.dest)[..8], ctx.node.hops_to(&dh)));
    match open_link_wait(ctx, cand, None, 10, leviculum_std::api::LinkCipher::Gcm).await {
        Ok((id, _h)) => Some(id),
        Err(e) => {
            ctx.sh.note(format!("link до {} через наши ноды не встал ({e:#}), пробую публичные хабы", &hex(&cand.dest)[..8]));
            // путь через наши ноды нам не помог: забываем его, публичный перебор спросит заново
            ctx.node.engine().remove_path(&dh);
            None
        }
    }
}

/// Link к ноде строго по нашему носителю (QUIC/TCP, хоп 1), а не через публичную RNS.
async fn direct_link(ctx: &Arc<ClientCtx>, cand: &CServer) -> Result<LinkId> {
    let dh = DestinationHash::new(cand.dest);
    // метка носителя задаётся при создании дозвона; имя узла после допуска может смениться, поэтому берём метку, а не имя
    let label = ctx.carriers.lock().unwrap().get(&cand.dest).map(|x| x.label.lock().unwrap().clone()).filter(|l| !l.is_empty()).unwrap_or_else(|| cand.name.clone());
    let prefixes = [format!("iroh-dg-out-{label}-"), format!("tcp-out-{label}-")];
    let mut until = Instant::now() + Duration::from_secs(30);
    let mut first = true;
    let mut pending = ctx.path_gate.begin(cand.dest, Instant::now());
    loop {
        if Instant::now() > until {
            bail!("нет прямого пути до ноды (QUIC не поднялся)");
        }
        let ours: Vec<usize> = ctx.node.engine().interface_stats().iter().filter(|i| i.online && prefixes.iter().any(|p| i.name.starts_with(p))).map(|i| i.interface_id.0).collect();
        if ours.is_empty() {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }
        if scoped_path(&ctx.node, &dh, &ours, None) && ctx.node.hops_to(&dh) == Some(1) { break; }
        if pending.is_none() { pending = ctx.path_gate.begin(cand.dest, Instant::now()); }
        if first {
            first = false;
            // QUIC мог съесть почти всё окно (две неудачи, переход на TCP): отсчёт идёт от появления рабочего интерфейса
            until = Instant::now() + Duration::from_secs(25);
        }
        if pending.is_some() && !scoped_path(&ctx.node, &dh, &ours, None) {
            ctx.node.engine().remove_path(&dh);
        }
        if pending.as_ref().map(|p| p.request_due(Instant::now())).unwrap_or(false) {
            let _ = ctx.node.engine().request_path_on(&dh, &ours).await;
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
        if scoped_path(&ctx.node, &dh, &ours, None) && ctx.node.hops_to(&dh) == Some(1) {
            break;
        }
    }
    drop(pending);
    let (id, _h) = open_link(ctx, cand, None).await?;
    Ok(id)
}

async fn enroll_link(ctx: &Arc<ClientCtx>, c: &C13, cand: &CServer) -> Result<()> {
    let id = if cand.addrs.is_empty() { rns_link(ctx, cand).await? } else { direct_link(ctx, cand).await? };
    c.enrollees.lock().unwrap().insert(id, cand.pk.unwrap());
    ctx.node.identify_link(&id, &ctx.identity).await.map_err(|e| anyhow::anyhow!("identify: {e:?}"))?;
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(12) && !c.enrolled.lock().unwrap().contains(&id) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let done = c.enrolled.lock().unwrap().contains(&id);
    if done {
        tokio::time::sleep(Duration::from_millis(1500)).await; // дать записям уйти
    }
    let _ = ctx.node.engine().close_link(&id).await;
    c.enrollees.lock().unwrap().remove(&id);
    c.enrolled.lock().unwrap().remove(&id);
    if !done {
        bail!("нода не запросила зачисление (приглашение другого админа или уже погашено)");
    }
    Ok(())
}

/// Админ-режим: ожидающая нода просится по нашему приглашению. Зеркало `on_pair1` ноды, но Link открыли мы.
async fn on_pair1_client(ctx: Arc<ClientCtx>, link: LinkId, body: Vec<u8>) {
    let Some(c) = &ctx.c13 else { return };
    if body.len() != 64 + 32 {
        return;
    }
    let Some(expect) = c.enrollees.lock().unwrap().get(&link).copied() else { return };
    let holder: [u8; 64] = body[..64].try_into().unwrap();
    if holder != expect {
        ctx.sh.note("зачисление: ключ ноды не совпал с анонсом, закрываю".to_string());
        let _ = ctx.node.engine().close_link(&link).await;
        return;
    }
    let my_pk = ctx.identity.public_key_bytes();
    let my_hash = c.trust.lock().unwrap().me_hash;
    let rec = match trust::pin_claim(&ctx.state, &my_pk, &holder, &body[64..], now_ms() as u64 / 1000) {
        trust::Claim::New { rights, root } => {
            let r = c.trust.lock().unwrap().issue(root, holder, rights);
            match r {
                Ok(r) => {
                    if let Err(e) = c.trust.lock().unwrap().save() {
                        trust::pin_unclaim(&ctx.state, &my_pk, &holder, &body[64..]);
                        ctx.sh.note(format!("trust.json не записан: {e:#}"));
                        return;
                    }
                    ctx.sh.note(format!("зачисление: нода {} получила права {}", &hex(&r.hh)[..8], trust::rights_text(r.rights)));
                    Some(r)
                }
                Err(e) => {
                    // H8: выдача не удалась - возвращаем pin, приглашение не сгорает
                    trust::pin_unclaim(&ctx.state, &my_pk, &holder, &body[64..]);
                    ctx.sh.note(format!("зачисление: запись не выдана: {e:#}"));
                    None
                }
            }
        }
        trust::Claim::Repeat { root } => {
            let tr = c.trust.lock().unwrap();
            let found = repeat_record(&tr, &root, &holder, &my_hash);
            if found.is_none() {
                drop(tr);
                trust::pin_unclaim(&ctx.state, &my_pk, &holder, &body[64..]);
                ctx.sh.note("зачисление: незавершённое погашение возвращено; повторите запрос".to_string());
                return;
            }
            found
        }
        other => {
            let why = match other {
                trust::Claim::Spent => "приглашение уже использовано",
                trust::Claim::Expired => "приглашение просрочено",
                _ => "приглашение неизвестно этому админу",
            };
            ctx.sh.note(format!("зачисление отклонено: {why}"));
            send_ctl(&ctx.node, link, T_PAIR_NO, why.as_bytes()).await;
            return;
        }
    };
    let Some(rec) = rec else {
        send_ctl(&ctx.node, link, T_PAIR_NO, "запись не выдана".as_bytes()).await;
        return;
    };
    let (chain, rest) = {
        let tr = c.trust.lock().unwrap();
        let chain = tr.chain_for(&holder);
        let rest: Vec<trust::Record> = tr.export_for(rec.rights, &holder).into_iter().filter(|r| !chain.contains(r)).collect();
        (chain, rest)
    };
    for r in chain { send_ctl(&ctx.node, link, T_REC, &r.wire()).await; }
    for r in rest {
        send_ctl(&ctx.node, link, T_REC, &r.wire()).await;
    }
    // текущий выход узнаёт о новой ноде сразу (иначе - при следующем подключении к нему), дальше он разнесёт запись соседям
    let cur = ctx.cur.lock().unwrap().map(|x| x.1);
    if let Some(cur) = cur {
        send_ctl(&ctx.node, cur, T_REC, &rec.wire()).await;
    }
    // новая нода не знает адресов остальных (анонс их не несёт): отдаём ей известные нам выходы; это подсказки, допуск по записям
    send_catalog(&ctx, link, &holder).await;
    c.enrolled.lock().unwrap().insert(link);
    ctx.refresh_servers13();
    start_dialers(&ctx);
}

/// Админ -> только что зачисленная нода: адреса известных нам нод (до DIR_MAX, кусками по DIR_CHUNK Б).
async fn send_catalog(ctx: &Arc<ClientCtx>, link: LinkId, except: &[u8; 64]) {
    let list: Vec<serde_json::Value> = ctx.servers.lock().unwrap().iter()
        .filter(|x| x.pk.is_some() && x.pk.as_ref() != Some(except) && !x.addrs.is_empty())
        .take(DIR_MAX)
        .map(|x| serde_json::json!({"d": hex(&x.dest), "k": hex(&x.pk.unwrap()), "e": x.ep, "a": x.addrs.iter().take(3).collect::<Vec<_>>(), "n": x.name, "pl": platform()}))
        .collect();
    let mut cur: Vec<serde_json::Value> = Vec::new();
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    for e in list {
        cur.push(e);
        if cur.len() > 1 && serde_json::json!({"n": cur}).to_string().len() > DIR_CHUNK {
            let last = cur.pop().unwrap();
            chunks.push(serde_json::json!({"n": cur}).to_string().into_bytes());
            cur = vec![last];
        }
    }
    if !cur.is_empty() {
        chunks.push(serde_json::json!({"n": cur}).to_string().into_bytes());
    }
    for c in chunks {
        send_ctl(&ctx.node, link, T_DIR, &c).await;
    }
}

/// Админ-режим: пользователь просится по нашему приглашению через ноду-посредника (Link к ноде - наш, пришёл T_PAIRQ). pin гасится за ключом
/// новичка, запись о нём подписываем сами и отдаём ноде: она разнесёт её соседям (так нового пользователя узнают все ноды) и ответит новичку.
async fn on_pairq_client(ctx: Arc<ClientCtx>, link: LinkId, body: Vec<u8>) {
    let Some(c) = &ctx.c13 else { return };
    let Some((requested_root, inviter_h, holder, mac)) = parse_pairq(&body) else { return };
    let (me_hash, my_pk) = (c.trust.lock().unwrap().me_hash, ctx.identity.public_key_bytes());
    if inviter_h != me_hash {
        return;
    }
    let Some(hh) = id_of_pub(&holder) else { return };
    let claim = trust::pin_claim(&ctx.state, &my_pk, &holder, &mac, now_ms() as u64 / 1000);
    if let trust::Claim::New { root, .. } | trust::Claim::Repeat { root } = &claim {
        if !pairq_client_matches(&inviter_h, &me_hash, &requested_root, root) {
            if matches!(&claim, trust::Claim::New { .. }) { trust::pin_unclaim(&ctx.state, &my_pk, &holder, &mac); }
            return;
        }
    }
    let rec = match claim {
        trust::Claim::New { rights, root } => {
            let r = c.trust.lock().unwrap().issue(root, holder, rights);
            match r {
                Ok(r) => {
                    if let Err(e) = c.trust.lock().unwrap().save() {
                        trust::pin_unclaim(&ctx.state, &my_pk, &holder, &mac);
                        ctx.sh.note(format!("trust.json не записан: {e:#}"));
                        return;
                    }
                    ctx.sh.note(format!("зачисление: пользователь {} получил права {}", &hex(&hh)[..8], trust::rights_text(r.rights)));
                    if root == me_hash { c.users.lock().unwrap().push((hex(&hh), now_ms() as u64 / 1000)); }
                    Some(r)
                }
                Err(e) => {
                    // H8: выдача не удалась - возвращаем pin, приглашение не сгорает
                    trust::pin_unclaim(&ctx.state, &my_pk, &holder, &mac);
                    ctx.sh.note(format!("зачисление: запись не выдана: {e:#}"));
                    None
                }
            }
        }
        trust::Claim::Repeat { root } => {
            let tr = c.trust.lock().unwrap();
            let found = repeat_record(&tr, &root, &holder, &me_hash);
            if found.is_none() {
                drop(tr);
                trust::pin_unclaim(&ctx.state, &my_pk, &holder, &mac);
                ctx.sh.note("зачисление: незавершённое погашение возвращено; повторите запрос".to_string());
                return;
            }
            found
        }
        other => {
            ctx.sh.note(format!("зачисление пользователя {}: {other:?}", &hex(&hh)[..8]));
            None
        }
    };
    let Some(rec) = rec else { return };
    let (chain, rest) = {
        let tr = c.trust.lock().unwrap();
        let chain = tr.chain_for(&holder);
        let rest: Vec<trust::Record> = tr.export_for(rec.rights, &holder).into_iter().filter(|r| !chain.contains(r)).collect();
        (chain, rest)
    };
    for r in chain { send_ctl(&ctx.node, link, T_REC, &r.wire()).await; }
    for r in rest { send_ctl(&ctx.node, link, T_REC, &r.wire()).await; }
    let cur = ctx.cur.lock().unwrap().map(|x| x.1);
    if let Some(cur) = cur.filter(|x| *x != link) {
        let chain = c.trust.lock().unwrap().chain_for(&holder);
        for r in chain { send_ctl(&ctx.node, cur, T_REC, &r.wire()).await; }
    }
}

/// (а, 0014 R6) Админ без приглашения (телефон или зачисленный клиент) анонсирует тег своего корня без адресов: нода, ждущая зачисления,
/// видит, что админ на связи, и просится через посредника. При старте, через 20 с, затем раз в 600 с (инвариант 8).
/// Входящие Link на этот destination не принимаются (set_accepts_links(false)): он нужен только для анонса.
async fn client_announce(ctx: Arc<ClientCtx>, dest: [u8; 16]) {
    let Some(c) = &ctx.c13 else { return };
    let mut wait = [Duration::ZERO, Duration::from_secs(20)].into_iter().chain(std::iter::repeat(Duration::from_secs(600)));
    while let Some(d) = wait.next() {
        tokio::time::sleep(d).await;
        if c.invite.lock().unwrap().is_some() {
            continue; // пока ждём зачисления, своих нод у нас нет
        }
        // анонсируется только админ: есть выданные им записи или ждущий pin; рядовой пользователь в публичную RNS не анонсируется
        let (me, admin) = {
            let tr = c.trust.lock().unwrap();
            (tr.me_hash, tr.export_all().iter().any(|r| r.issuer == tr.me_hash && r.hh != tr.me_hash))
        };
        if !admin && !trust::pin_list(&ctx.state).iter().any(|p| p.1 == "свежий") {
            continue;
        }
        // This destination exists only to publish the admin anchor for discovery; it rejects incoming Links.
        let data = serde_json::json!({"r": [trust::root_tag(&me)], "lc": false});
        let _ = ctx.node.announce(&DestinationHash::new(dest), Some(data.to_string().as_bytes())).await;
    }
}

/// T_DIR от посредника зачисления (R6): адреса выходов - подсказки (hints и диалер). Допуск - по записям о правах.
fn on_dir_client(ctx: &Arc<ClientCtx>, link: LinkId, body: &[u8]) {
    let Some(c) = &ctx.c13 else { return };
    // Link зачисления: от ожидавшей ноды принимаем только запись о ней самой
    let enrollee = c.enrollees.lock().unwrap().get(&link).copied();
    if body.len() > 1024 || !(enrollee.is_some() || c.peers.lock().unwrap().contains_key(&link)) {
        return;
    }
    for e in parse_dir(body, T13_TAG) {
        if enrollee.map(|pk| pk != e.pk).unwrap_or(false) {
            continue;
        }
        ctx.remember_addrs(&e.dest, &e.addrs);
        ctx.hint_name(e.dest, &e.name);
        if let Some(pl) = e.pl.as_deref() {
            if let Some(pl) = parse_platform(pl.as_bytes()) {
                let mut m = ctx.platforms.lock().unwrap();
                if m.len() < 64 || m.contains_key(&e.dest) {
                    m.insert(e.dest, pl);
                }
            }
        }
        // F-05: известный выход не перенацеливаем - endpoint уже задан и идентифицирует носитель; адреса каталога - подсказка, только если их нет
        let set_book = {
            let mut servers = ctx.servers.lock().unwrap();
            let Some(sv) = servers.iter_mut().find(|x| x.dest == e.dest) else { continue };
            if sv.ep.is_empty() && !e.ep.is_empty() {
                sv.ep = e.ep.clone();
            }
            if sv.addrs.is_empty() && !e.addrs.is_empty() {
                sv.addrs = e.addrs.clone();
                true
            } else {
                false
            }
        };
        if set_book {
            ctx.book_for(&e.dest).set(e.addrs.clone());
        }
    }
    ctx.refresh_servers13();
    start_dialers(ctx);
}

fn start_dialer(ctx: &Arc<ClientCtx>, s: &CServer) {
    if ctx.dialers.lock().unwrap().contains_key(&s.dest) {
        return;
    }
    let book = ctx.book_for(&s.dest);
    if !s.addrs.is_empty() {
        book.set(s.addrs.clone());
    }
    let (Ok(id), false) = (s.ep.parse::<EndpointId>(), book.is_empty()) else { return };
    let alive = Arc::new(AtomicBool::new(true));
    ctx.dialers.lock().unwrap().insert(s.dest, alive.clone());
    let cc = CarrierCtl::new();
    *cc.label.lock().unwrap() = s.name.clone();
    ctx.carriers.lock().unwrap().insert(s.dest, cc.clone());
    tokio::spawn(dial_direct(ctx.ep.clone(), ctx.node.clone(), ctx.sh.clone(), s.name.clone(), id, book, alive, cc));
}

/// Запустить диалеры выходов, у которых появился адрес: после пересборки списка по записям (новая запись работает без перезапуска клиента).
fn start_dialers(ctx: &Arc<ClientCtx>) {
    if ctx.c13.is_none() {
        return;
    }
    let list = ctx.servers.lock().unwrap().clone();
    for s in &list {
        start_dialer(ctx, s);
    }
}

async fn client_events(ctx: Arc<ClientCtx>, mut events: leviculum_std::driver::EventReceiver) {
    while let Some(ev) = events.recv().await {
        match ev {
            NodeEvent::AnnounceReceived { announce, .. } if ctx.c13.is_some() => {
                // анонс лишь подсказка адреса и имени для выхода, которого мы и так знаем по записям о правах
                let Ok(v) = serde_json::from_slice::<serde_json::Value>(announce.app_data()) else { continue };
                if !v["r"].is_array() {
                    continue;
                }
                let dest = *announce.destination_hash().as_bytes();
                let addrs: Vec<String> = v["a"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).take(3).collect()).unwrap_or_default();
                let name: Option<String> = v["n"].as_str().and_then(|n| norm_peer_name(n, ""));
                let known = {
                    let mut s = ctx.servers.lock().unwrap();
                    match s.iter_mut().find(|e| e.dest == dest) {
                        Some(e) => {
                            if let Some(n) = &name {
                                e.name = n.clone();
                            }
                            e.seen = Instant::now();
                            if !addrs.is_empty() {
                                e.addrs = addrs.clone();
                            }
                            Some(e.clone())
                        }
                        None => None,
                    }
                };
                match known {
                    Some(e) => {
                        ctx.remember_addrs(&dest, &addrs);
                        // анонс обновляет адреса работающего диалера (он читает их на каждой попытке)
                        if !addrs.is_empty() {
                            ctx.book_for(&dest).set(addrs.clone());
                        }
                        start_dialer(&ctx, &e);
                    }
                    None => {
                        let name = name.unwrap_or_else(|| "?".into());
                        maybe_relay(&ctx, announce.public_key(), &v, dest, &name, &addrs);
                        maybe_enroll(&ctx, announce.public_key(), &v, dest, name, addrs)
                    }
                }
            }
            NodeEvent::LinkEstablished { link_id, .. } => {
                ctx.sh.established.lock().unwrap().insert(hex(link_id.as_bytes()));
            }
            NodeEvent::LinkClosed { link_id, reason, .. } => {
                ctx.admitted_exits.lock().unwrap().remove(&link_id);
                ctx.ctrl.lock().unwrap().remove(&link_id);
                ctx.sh.closed.lock().unwrap().insert(hex(link_id.as_bytes()), format!("{reason:?}"));
            }
            NodeEvent::MessageReceived { link_id, data, .. } if !data.is_empty() => {
                // B: управляющий канал ограничен ведром на Link; VPN-датаграммы (LinkDataReceived) этим не учитываются
                let verdict = {
                    let mut buckets = ctx.ctrl.lock().unwrap();
                    client_ctrl_pass(&mut buckets, link_id, Instant::now())
                };
                match verdict {
                    Some(CtrlVerdict::Pass) => {}
                    Some(CtrlVerdict::Drop { first: true }) => {
                        ctx.sh.note(format!("link {}: управляющие сообщения сверх частоты, отбрасываю", &hex(link_id.as_bytes())[..8]));
                        continue;
                    }
                    _ => continue,
                }
                let body = &data[1..];
                match data[0] {
                    T_AUTH_OK => {
                        let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
                        if let Some(tx) = ctx.auth_wait.lock().unwrap().remove(&link_id) {
                            let _ = tx.send(Ok(v));
                        }
                    }
                    T_AUTH_FAIL => {
                        if let Some(tx) = ctx.auth_wait.lock().unwrap().remove(&link_id) {
                            let _ = tx.send(Err(String::from_utf8_lossy(body).into()));
                        }
                    }
                    T_TABLE => {
                        // в модели 0013 таблицу выходов клиент строит сам по записям о правах
                        if ctx.c13.is_none() {
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
                                ctx.merge_table(&v);
                            }
                        }
                    }
                    T_REC => on_rec_client(&ctx, link_id, body),
                    T_POL => on_pol_client(&ctx, link_id, body),
                    T_DIR => {
                        if ctx.c13.is_some() {
                            on_dir_client(&ctx, link_id, body);
                        }
                    }
                    T_BENCH => {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
                            bench_msg(&ctx.bench_sess, link_id, &v);
                        }
                    }
                    T_NBRS => {
                        if ctx.c13.is_some() {
                            on_nbrs_client(&ctx, link_id, body);
                        }
                    }
                    T_PAIR1 => {
                        let (c2, b) = (ctx.clone(), body.to_vec());
                        tokio::spawn(async move { on_pair1_client(c2, link_id, b).await });
                    }
                    T_PAIRQ => {
                        let (c2, b) = (ctx.clone(), body.to_vec());
                        tokio::spawn(async move { on_pairq_client(c2, link_id, b).await });
                    }
                    T_PAIR_NO => {
                        if let Some(c) = &ctx.c13 {
                            // H7: отказ принимаем только от админа ожидающего приглашения; посредник зачисления срывать его не может
                            let admin = c.invite.lock().unwrap().as_ref().map(|i| i.admin);
                            let from_admin = admin.is_some() && c.peers.lock().unwrap().get(&link_id).copied() == admin;
                            if from_admin {
                                let why: String = String::from_utf8_lossy(body).chars().take(80).collect();
                                ctx.sh.note(format!("зачисление отклонено админом: {why}"));
                                *c.rejected.lock().unwrap() = Some(why);
                            } else if c.peers.lock().unwrap().contains_key(&link_id) {
                                ctx.sh.note("T_PAIR_NO не от админа приглашения: проигнорирован".to_string());
                            }
                        }
                    }
                    T_PONG if body.len() >= 12 => {
                        let cur = ctx.cur.lock().unwrap().map(|c| c.1);
                        if cur == Some(link_id) {
                            ctx.last_pong.store(now_ms() as u64, Relaxed);
                            ctx.loss.lock().unwrap().ack(u32::from_le_bytes(body[..4].try_into().unwrap()));
                            let ts = u64::from_le_bytes(body[4..12].try_into().unwrap());
                            *ctx.rtt_ms.lock().unwrap() = Some(now_us().saturating_sub(ts) as f64 / 1000.0);
                            ctx.rtt_pong.store(now_ms() as u64, Relaxed);
                        }
                    }
                    _ => {}
                }
            }
            NodeEvent::LinkDataReceived { link_id, data, .. } if data.first() == Some(&T_BENCH_DATA) => bench_rx(&ctx.bench_sess, link_id, &data),
            NodeEvent::LinkDataReceived { link_id, data, .. } => {
                let cur = ctx.cur.lock().unwrap().map(|c| c.1);
                if cur == Some(link_id) {
                    ctx.last_pong.store(now_ms() as u64, Relaxed); // любой пакет от выхода - признак жизни
                    if is_rgp(&data) {
                        if data[3] == b'R' {
                            ctx.loss.lock().unwrap().ack(u32::from_le_bytes(data[4..8].try_into().unwrap()));
                            *ctx.rtt_ms.lock().unwrap() = Some(now_us().saturating_sub(u64::from_le_bytes(data[8..16].try_into().unwrap())) as f64 / 1000.0);
                            ctx.rtt_pong.store(now_ms() as u64, Relaxed);
                        }
                    } else {
                        ctx.tun.on_link_packet(&ctx.node, link_id, &data);
                    }
                } else if ctx.tun.routing.load(Relaxed) {
                    let x = ctx.tun.extra.read().unwrap().values().find(|x| x.id == link_id).cloned();
                    if let Some(x) = x {
                        x.last_rx_ms.store(now_ms() as u64, Relaxed);
                        if !is_rgp(&data) {
                            ctx.tun.on_extra_packet(&data);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Наши интерфейсы носителя (QUIC/TCP, входящие и исходящие), online, кроме `skip`. Публичная RNS сюда не входит:
/// клиент по ней Link не открывает. Публичные интерфейсы клиент не помнит по id (spawn_interface выдаёт tcp_client_N), поэтому отбор по префиксу.
fn carrier_ifaces(ctx: &ClientCtx, skip: Option<usize>) -> Vec<usize> {
    own_carrier_ifaces(&ctx.node).into_iter().filter(|i| Some(*i) != skip).collect()
}

fn own_carrier_ifaces(node: &Arc<Node>) -> Vec<usize> {
    const PREFIXES: [&str; 4] = ["iroh-dg-out-", "iroh-dg-in-", "tcp-out-", "tcp-in-"];
    node.engine().interface_stats().iter()
        .filter(|i| i.online && PREFIXES.iter().any(|p| i.name.starts_with(p)))
        .map(|i| i.interface_id.0).collect()
}

fn scoped_path(node: &Arc<Node>, dest: &DestinationHash, allowed: &[usize], avoid: Option<usize>) -> bool {
    path::acceptable(node.engine().get_path_clone(dest).map(|p| p.interface_index), allowed, avoid)
}

/// Прямой путь (1 хоп) по нашему носителю: сосед, с которым у нас QUIC/TCP сам, без транзита.
fn direct_our_path(node: &Arc<Node>, dest: &DestinationHash, ours: &[usize], avoid: Option<usize>) -> Option<usize> {
    let p = node.engine().get_path_clone(dest)?;
    (p.hops == 1 && ours.contains(&p.interface_index) && Some(p.interface_index) != avoid).then_some(p.interface_index)
}

/// Любой путь по нашим носителям, включая транзит через наши ноды (2+ хопа).
fn any_our_path(node: &Arc<Node>, dest: &DestinationHash, ours: &[usize], avoid: Option<usize>) -> Option<usize> {
    let p = node.engine().get_path_clone(dest)?;
    (ours.contains(&p.interface_index) && Some(p.interface_index) != avoid).then_some(p.interface_index)
}

/// Наш исходящий носитель (QUIC/TCP) к пиру по его метке: интерфейс, через который мы сами набираем пира.
fn out_carrier_iface(node: &Arc<Node>, label: &str) -> Option<usize> {
    if label.is_empty() {
        return None;
    }
    let pats = [format!("iroh-dg-out-{label}-"), format!("tcp-out-{label}-")];
    node.engine().interface_stats().iter()
        .filter(|i| i.online && pats.iter().any(|p| i.name.starts_with(p)))
        .map(|i| i.interface_id.0).max()
}

/// Единый порядок выбора пути - одинаковый для ноды (сосед) и для клиента (выход):
/// 1) прямой путь (1 хоп) по нашему носителю - приоритет;
/// 2) если к пиру есть наш носитель, но прямой путь ещё не найден - ждём его, спрашивая путь только по этому носителю;
/// 3) иначе - транзит через наши ноды (любой путь по нашим носителям).
/// Публичный RNS - только координация (поиск), носителем VPN-данных он не бывает.
/// Носители и интерфейс носителя к пиру пересчитываются на каждой итерации: носитель, поднявшийся во время ожидания,
/// сразу участвует в выборе, а его путь не удаляется как «чужой». Возвращает интерфейс найденного пути.
async fn wait_our_path(node: &Arc<Node>, gate: &path::PathGate, dest: &DestinationHash,
    ours_now: impl Fn() -> Vec<usize>, carrier_now: impl Fn() -> Option<usize>, avoid: Option<usize>, secs: u64) -> Option<usize> {
    let until = Instant::now() + Duration::from_secs(secs);
    // сколько ждём прямой путь, когда носитель к пиру есть (ответ пира на запрос пути приходит за десятки мс)
    let direct_until = Instant::now() + Duration::from_secs(3);
    let mut pending = gate.begin(*dest.as_bytes(), Instant::now());
    loop {
        let now = Instant::now();
        if now >= until {
            break;
        }
        let ours = ours_now();
        let carrier = carrier_now().filter(|c| ours.contains(c) && Some(*c) != avoid);
        if let Some(i) = direct_our_path(node, dest, &ours, avoid) {
            return Some(i);
        }
        // транзит принимаем, только если своего носителя к пиру нет или прямой путь уже не ждём
        if carrier.is_none() || now >= direct_until {
            if let Some(i) = any_our_path(node, dest, &ours, avoid) {
                return Some(i);
            }
        }
        if pending.is_none() {
            pending = gate.begin(*dest.as_bytes(), Instant::now());
        }
        if let Some(p) = &pending {
            // путь, который не подходит (например, с исключённого интерфейса), мешает - убираем
            if let Some(cur) = node.engine().get_path_clone(dest) {
                if !ours.contains(&cur.interface_index) || Some(cur.interface_index) == avoid {
                    node.engine().remove_path(dest);
                }
            }
            let ifs: Vec<usize> = match carrier {
                Some(c) => vec![c],
                None => ours.clone(),
            };
            if !ifs.is_empty() && p.request_due(now) {
                let _ = node.engine().request_path_on(dest, &ifs).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    any_our_path(node, dest, &ours_now(), avoid)
}

/// Один владелец discovery, не более одного scoped forced-запроса за 20 с.
/// Другие задачи только наблюдают таблицу. Нет предпочтений по хопам/RTT: путь выбирает RNS.
async fn wait_scoped_path(node: &Arc<Node>, gate: &path::PathGate, dest: &DestinationHash,
    allowed: impl Fn() -> Vec<usize>, avoid: Option<usize>, secs: u64) {
    let until = Instant::now() + Duration::from_secs(secs);
    let mut pending = gate.begin(*dest.as_bytes(), Instant::now());
    loop {
        let ifs = allowed();
        if scoped_path(node, dest, &ifs, avoid) { return; }
        if Instant::now() >= until { return; }
        // Только владелец удаляет неприемлемый путь, включая запоздалый ответ
        // с исключённого интерфейса. Пригодные пути никогда не удаляем.
        if pending.is_none() { pending = gate.begin(*dest.as_bytes(), Instant::now()); }
        if let Some(p) = &pending {
            if node.engine().get_path_clone(dest).is_some() {
                node.engine().remove_path(dest);
            }
            if !ifs.is_empty() && p.request_due(Instant::now()) {
                let _ = node.engine().request_path_on(dest, &ifs).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Путь до выхода ведёт через наш носитель к нему (прямой путь)? Тогда возвращаем его интерфейс.
fn direct_carrier_iface(ctx: &ClientCtx, dest: &[u8; 16]) -> Option<usize> {
    let label = ctx.carriers.lock().unwrap().get(dest).map(|x| x.label.lock().unwrap().clone())?;
    if label.is_empty() {
        return None;
    }
    let (pq, pt) = (format!("iroh-dg-out-{label}-"), format!("tcp-out-{label}-"));
    let idx = ctx.node.engine().path_table_entries().iter().find(|p| p.hash == *dest)?.interface_index;
    let name = ctx.node.engine().interface_stats().iter().find(|i| i.interface_id.0 == idx)?.name.clone();
    (name.starts_with(&pq) || name.starts_with(&pt)).then_some(idx)
}

/// Путь до узла и установленный Link (без identify).
async fn open_link(ctx: &Arc<ClientCtx>, cand: &CServer, avoid_iface: Option<usize>) -> Result<(LinkId, Arc<leviculum_std::LinkHandle>)> {
    open_link_wait(ctx, cand, avoid_iface, 6, leviculum_std::api::LinkCipher::Gcm).await
}

async fn open_link_wait(ctx: &Arc<ClientCtx>, cand: &CServer, avoid_iface: Option<usize>, est_s: u64, cipher: leviculum_std::api::LinkCipher) -> Result<(LinkId, Arc<leviculum_std::LinkHandle>)> {
    let dest = DestinationHash::new(cand.dest);
    // CBC enrollment сохраняет публичный fallback. GCM открывается только по нашим носителям.
    let allowed = || if cipher == leviculum_std::api::LinkCipher::Cbc {
        ctx.node.engine().interface_stats().iter().filter(|i| i.online).map(|i| i.interface_id.0).collect()
    } else { carrier_ifaces(ctx, avoid_iface) };
    if cipher == leviculum_std::api::LinkCipher::Cbc {
        if !scoped_path(&ctx.node, &dest, &allowed(), avoid_iface) {
            wait_scoped_path(&ctx.node, &ctx.path_gate, &dest, allowed, avoid_iface, 8).await;
        }
    } else {
        // Тот же порядок, что у ноды к соседу: прямой путь по нашему носителю, иначе транзит через наши узлы.
        if !scoped_path(&ctx.node, &dest, &carrier_ifaces(ctx, avoid_iface), avoid_iface) {
            start_dialer(ctx, cand);
            let carrier_now = || {
                let label = ctx.carriers.lock().unwrap().get(&cand.dest).filter(|x| *x.mode.lock().unwrap() != "none").map(|x| x.label.lock().unwrap().clone()).unwrap_or_default();
                out_carrier_iface(&ctx.node, &label)
            };
            wait_our_path(&ctx.node, &ctx.path_gate, &dest, || carrier_ifaces(ctx, avoid_iface), carrier_now, avoid_iface, if avoid_iface.is_some() { 6 } else { 8 }).await;
        }
    }
    if !scoped_path(&ctx.node, &dest, &allowed(), avoid_iface) {
        bail!("нет пути до {}", cand.name);
    }
    let handle = ctx.node.connect_with_key_cipher(&dest, &cand.key, cipher).await?;
    let id = *handle.link_id();
    let k = hex(id.as_bytes());
    let t = Instant::now();
    while !ctx.sh.established.lock().unwrap().contains(&k) {
        if ctx.sh.closed.lock().unwrap().contains_key(&k) || t.elapsed() > Duration::from_secs(est_s) {
            let _ = ctx.node.engine().close_link(&id).await;
            bail!("link до {} не установился", cand.name);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Проверка attached interface закрывает гонку изменения таблицы во время connect. У инициатора интерфейс
    // известен только после proof (у ожидающего Link он None), поэтому проверяем установленный Link.
    if !path::acceptable(ctx.node.engine().link_stats(&id).and_then(|s| s.attached_interface()), &allowed(), avoid_iface) {
        let _ = ctx.node.engine().close_link(&id).await;
        bail!("Link до {} выбрал недопустимый интерфейс", cand.name);
    }
    Ok((id, Arc::new(handle)))
}

/// Подключиться к выходу: путь, Link, identify (доказательство владения ключом клиента), ответ AUTH_OK.
async fn connect_exit(ctx: &Arc<ClientCtx>, cand: &CServer, avoid_iface: Option<usize>) -> Result<(LinkId, Arc<leviculum_std::LinkHandle>)> {
    if ctx.c13.is_some() && !exit_eligible(ctx, cand) {
        bail!("{} не имеет действующего права/политики EXIT в общей сети", cand.name);
    }
    let dest = DestinationHash::new(cand.dest);
    let t0 = Instant::now();
    let (id, handle) = open_link(ctx, cand, avoid_iface).await?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    ctx.auth_wait.lock().unwrap().insert(id, tx);
    if let Some(c) = &ctx.c13 {
        c.peers.lock().unwrap().insert(id, cand.pk.unwrap_or([0u8; 64]));
    }
    // 0013: «пришёл за выходом» (T_USE) уходит ДО identify: у клиента с правами транзита (админ, телефон-админ) сервер иначе допустил бы его
    // соседом в момент identify. Цепочка идёт после identify (у ответчика identity появляется только после него).
    if ctx.c13.is_some() {
        send_ctl(&ctx.node, id, T_USE, &client_info_body(&ctx.identity)).await;
    }
    ctx.node.identify_link(&id, &ctx.identity).await.map_err(|e| anyhow::anyhow!("identify: {e:?}"))?;
    if let Some(c) = &ctx.c13 {
        let chain = c.trust.lock().unwrap().chain_for(&ctx.identity.public_key_bytes());
        for r in chain {
            send_ctl(&ctx.node, id, T_REC, &r.wire()).await;
        }
        // повтор T_USE после identify: если первый пакет отстал, узел уже увидит намерение стать клиентом
        send_ctl(&ctx.node, id, T_USE, &client_info_body(&ctx.identity)).await;
    }
    let reply = match tokio::time::timeout(Duration::from_secs(6), rx).await {
        Ok(Ok(Ok(v))) => v,
        Ok(Ok(Err(why))) => {
            let _ = ctx.node.engine().close_link(&id).await;
            bail!("{} отказал в доступе: {why}", cand.name);
        }
        _ => {
            ctx.auth_wait.lock().unwrap().remove(&id);
            let _ = ctx.node.engine().close_link(&id).await;
            bail!("{} не ответил на авторизацию", cand.name);
        }
    };
    if let Some(c) = &ctx.c13 {
        // цепочка сервера пришла раньше AUTH_OK (события клиента обрабатываются по порядку): сверяем его право EXIT в общем корне
        let ok = authorized_exit(&c.trust.lock().unwrap(), cand.pk.as_ref(), now_ms() as u64);
        if !ok {
            let _ = ctx.node.engine().close_link(&id).await;
            bail!("{} не имеет права EXIT в общей с нами сети", cand.name);
        }
        ctx.learn_name(cand.dest, reply["name"].as_str().unwrap_or(""), reply["cc"].as_str().unwrap_or(""));
        if let Some(pl) = reply["pl"].as_str().and_then(|p| parse_platform(p.as_bytes())) {
            let mut m = ctx.platforms.lock().unwrap();
            if m.len() < 64 || m.contains_key(&cand.dest) {
                m.insert(cand.dest, pl);
            }
        }
        {
            let mut admitted = ctx.admitted_exits.lock().unwrap();
            if admitted.len() < 32 { admitted.insert(id, cand.dest); }
        }
        // Explicit subscription after EXIT validation fixes the early AUTH_OK/T_NBRS race.
        spawn_ctl(&ctx.node, id, T_OBSERVE, vec![u8::from(crate::mobile::ui_visible())]);
        // Админ без постоянной ноды (телефон): остальные ноды узнают о новых записях, только когда мы к ним подключаемся. Отдаём выходу всё хранилище
        // (он применит записи, цепочка которых ведёт к его якорю, и сам разнесёт их соседям).
        // 0015: своя политика (например, «только USE») - выходу и дальше соседям, чтобы они не предлагали наш телефон как выход или транзит
        let pols = c.trust.lock().unwrap().my_policies(now_ms() as u64);
        if !pols.is_empty() {
            let node = ctx.node.clone();
            tokio::spawn(async move {
                for p in pols {
                    send_ctl(&node, id, T_POL, &p.wire()).await;
                }
            });
        }
        let recs = {
            let tr = c.trust.lock().unwrap();
            if tr.my_rights_in(&tr.me_hash) & trust::ADD != 0 { tr.export_all() } else { vec![] }
        };
        if !recs.is_empty() {
            let node = ctx.node.clone();
            tokio::spawn(async move {
                for r in recs {
                    send_ctl(&node, id, T_REC, &r.wire()).await;
                }
            });
        }
    }
    if let Some(t) = reply.get("table") {
        ctx.merge_table(t);
    }
    ctx.sh.note(format!("выход {} принял клиента за {} мс (хопов {:?})", cand.name, t0.elapsed().as_millis(), ctx.node.hops_to(&dest)));
    Ok((id, handle))
}

fn candidates(ctx: &Arc<ClientCtx>, banned: &HashMap<[u8; 16], Instant>, only: Option<[u8; 16]>) -> Vec<CServer> {
    // 0013: допущенный EXIT может требовать discovery, даже без адресов/кэша пути.
    // Legacy сохраняет прежнее требование достижимости; бан ограничивает повторные попытки.
    let mut v: Vec<CServer> = ctx.servers.lock().unwrap().iter().filter(|s| exit_eligible(ctx, s) && banned.get(&s.dest).map(|t| *t < Instant::now()).unwrap_or(true)).cloned().collect();
    if let Some(o) = only {
        v.retain(|s| s.dest == o);
        return v;
    }
    // «Авто»: сначала узлы, до которых у телефона есть своё измеренное QUIC-соединение, по его RTT; затем остальные по хопам и RTT из таблицы сервера
    // (это RTT между сервером и узлом, а не телефоном, поэтому как главный критерий не годится). Равные в пределах 15% и 3 мс считаются равными: тогда решает число хопов.
    let phone_rtt = |d: &[u8; 16]| -> Option<f64> {
        let us = ctx.carriers.lock().unwrap().get(d).map(|c| c.rtt_us.load(Relaxed)).unwrap_or(0);
        if us > 0 { Some(us as f64 / 1000.0) } else { None }
    };
    v.sort_by(|a, b| {
        let (ra, rb) = (phone_rtt(&a.dest), phone_rtt(&b.dest));
        let hops = |x: &CServer| ctx.node.hops_to(&DestinationHash::new(x.dest)).unwrap_or(9);
        match (ra, rb) {
            (Some(x), Some(y)) => {
                let close = (x - y).abs() < 3.0 || (x - y).abs() < 0.15 * x.max(y);
                if close { hops(a).cmp(&hops(b)).then(x.partial_cmp(&y).unwrap()) } else { x.partial_cmp(&y).unwrap() }
            }
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => hops(a).cmp(&hops(b)).then(b.pinned.cmp(&a.pinned)).then(a.rtt_ms.unwrap_or(1e9).partial_cmp(&b.rtt_ms.unwrap_or(1e9)).unwrap()),
        }
    });
    // приоритеты пользователя (вкладка «Маршрутизация»): названные выходы идут первыми по порядку списка, остальные - после, в обычном порядке
    let rc = ctx.rcfg.read().unwrap().clone();
    if rc.mode != "auto" && !rc.priority.is_empty() {
        v.sort_by_key(|s| rc.prio_of(&s.dest));
    }
    v
}

fn exit_eligible(ctx: &ClientCtx, s: &CServer) -> bool {
    let authorized = ctx.c13.as_ref().map(|c| authorized_exit(&c.trust.lock().unwrap(), s.pk.as_ref(), now_ms() as u64));
    path::eligible(authorized, !s.addrs.is_empty() || s.state == "up", s.state == "lost")
}

fn authorized_exit(tr: &trust::Trust, pk: Option<&trust::Pk>, now: u64) -> bool {
    pk.map(|pk| tr.common_with(pk, trust::USE, trust::EXIT, false, true, now)).unwrap_or(false)
}


impl ClientCtx {
    fn routing_json(&self, servers: &[CServer]) -> serde_json::Value {
        let rc = self.rcfg.read().unwrap().clone();
        let t = &self.tun;
        let extras: Vec<serde_json::Value> = t.extra.read().unwrap().iter().map(|(d, x)| serde_json::json!({
            "d": hex(d), "n": servers.iter().find(|e| e.dest == *d).map(|e| self.shown_name(e)),
            "age_s": (now_ms() as u64).saturating_sub(x.last_rx_ms.load(Relaxed)) / 1000})).collect();
        let pending: Vec<String> = self.rpending.lock().unwrap().iter().map(|d| hex(d)).collect();
        serde_json::json!({"mode": rc.mode, "on": t.routing.load(Relaxed), "extras": extras, "pending": pending, "report": self.rreport.lock().unwrap().clone(),
            "extra_pkts": t.rt.extra_pkts.load(Relaxed), "fallback_pkts": t.rt.fallback_pkts.load(Relaxed), "direct_fallback_pkts": t.rt.direct_fallback_pkts.load(Relaxed), "dot_dropped": t.rt.dot_dropped.load(Relaxed)})
    }
}

/// Раздельное туннелирование клиента: перечитывает `routing.json` и файлы списков, собирает правила и держит дополнительные Link к выходам,
/// на которые правила шлют трафик. Основной выход выбирает `client_supervisor`; здесь только то, что сверх него.
async fn route_manager(ctx: Arc<ClientCtx>) {
    let fin = ctx.state.join("fin");
    let cfg_path = ctx.state.join("routing.json");
    let rules = route::rules_dir(&ctx.state);
    let stamp_of = || -> Vec<Option<(std::time::SystemTime, u64)>> {
        [cfg_path.clone(), rules.join("geoip.dat"), rules.join("geosite.dat")].iter().map(|p| std::fs::metadata(p).ok().and_then(|m| Some((m.modified().ok()?, m.len())))).collect()
    };
    let mut stamp = Vec::new();
    let mut last_ping = Instant::now();
    let mut seq = 0u32;
    while !fin.exists() {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let st = stamp_of();
        if st != stamp {
            stamp = st;
            let (state, rules2) = (ctx.state.clone(), rules.clone());
            let built = tokio::task::spawn_blocking(move || {
                let cfg = route::Cfg::load(&state);
                let mut r = if cfg.mode == "rules" { route::Router::build(&cfg, &rules2) } else { route::Router::empty() };
                let note = r.cap_note();
                r.warnings.extend(note);
                (cfg, r)
            }).await;
            if let Ok((cfg, r)) = built {
                *ctx.rreport.lock().unwrap() = serde_json::json!({"warnings": r.warnings, "stats": r.stats});
                ctx.sh.note(format!("маршрутизация: режим {}, правил {}, ручных {}, приоритетов {}{}", cfg.mode, cfg.rules.len(), cfg.manual.len(), cfg.priority.len(),
                    if r.warnings.is_empty() { String::new() } else { format!(", предупреждений {}", r.warnings.len()) }));
                *ctx.tun.router.write().unwrap() = Arc::new(r);
                ctx.tun.routing.store(cfg.mode == "rules", Relaxed);
                *ctx.rcfg.write().unwrap() = Arc::new(cfg);
            }
        }
        let rc = ctx.rcfg.read().unwrap().clone();
        let main = ctx.cur.lock().unwrap().map(|c| c.0);
        let wanted: Vec<[u8; 16]> = if rc.mode == "rules" { rc.exits().into_iter().filter(|d| Some(*d) != main).collect() } else { Vec::new() };
        // лишние, закрытые и замолчавшие Link
        let have: Vec<([u8; 16], ExtraLink)> = ctx.tun.extra.read().unwrap().iter().map(|(d, x)| (*d, x.clone())).collect();
        for (d, x) in &have {
            let closed = ctx.sh.closed.lock().unwrap().contains_key(&hex(x.id.as_bytes()));
            let silent = (now_ms() as u64).saturating_sub(x.last_rx_ms.load(Relaxed));
            let why = if !wanted.contains(d) { Some("не нужен") } else if closed { Some("закрыт") } else if silent > ctx.fail_ms.max(3000) { Some("нет ответа") } else { None };
            if let Some(why) = why {
                ctx.tun.extra.write().unwrap().remove(d);
                let _ = ctx.node.engine().close_link(&x.id).await;
                if why != "не нужен" {
                    ctx.sh.note(format!("доп. выход {}: {why}", hex(&d[..4])));
                    ctx.rback.lock().unwrap().insert(*d, Instant::now() + Duration::from_secs(10));
                }
            }
        }
        if last_ping.elapsed() >= Duration::from_secs(1) {
            last_ping = Instant::now();
            seq = seq.wrapping_add(1);
            for (_, x) in ctx.tun.extra.read().unwrap().iter() {
                spawn_dgram(&ctx.node, x.id, dgram_ping(seq, now_us(), b'P'));
            }
        }
        // недостающие Link
        for d in wanted {
            if ctx.tun.extra.read().unwrap().contains_key(&d) || ctx.rpending.lock().unwrap().contains(&d) {
                continue;
            }
            if ctx.rback.lock().unwrap().get(&d).map(|t| *t > Instant::now()).unwrap_or(false) {
                continue;
            }
            let Some(cand) = ctx.servers.lock().unwrap().iter().find(|s| s.dest == d && s.state != "lost" && (ctx.c13.is_none() || exit_eligible(&ctx, s))).cloned() else { continue };
            ctx.rpending.lock().unwrap().insert(d);
            let c2 = ctx.clone();
            tokio::spawn(async move {
                let r = tokio::time::timeout(Duration::from_secs(25), connect_exit(&c2, &cand, None)).await;
                c2.rpending.lock().unwrap().remove(&d);
                match r {
                    Ok(Ok((id, handle))) => {
                        c2.tun.extra.write().unwrap().insert(d, ExtraLink { id, handle, last_rx_ms: Arc::new(std::sync::atomic::AtomicU64::new(now_ms() as u64)) });
                        c2.sh.note(format!("доп. выход: {}", cand.name));
                    }
                    other => {
                        let why = match other { Ok(Err(e)) => format!("{e:#}"), _ => "таймаут".into() };
                        c2.sh.note(format!("доп. выход {}: {why}", cand.name));
                        c2.rback.lock().unwrap().insert(d, Instant::now() + Duration::from_secs(10));
                    }
                }
            });
        }
    }
}

/// 0015: раз в 4 с - настройка из `policy-want.json`, значение по умолчанию (только USE) в чужих сетях, переподпись по возрасту;
/// новые политики уходят на текущий выход, а тот разносит их дальше.
async fn client_policy_loop(ctx: Arc<ClientCtx>) {
    let fin = ctx.state.join("fin");
    let Some(c) = &ctx.c13 else { return };
    while !fin.exists() {
        tokio::time::sleep(Duration::from_secs(4)).await;
        if c.invite.lock().unwrap().is_some() {
            continue;
        }
        let (pols, notes) = policy_step(&mut c.trust.lock().unwrap(), &ctx.state, true, now_ms() as u64);
        for n in notes {
            ctx.sh.note(n);
        }
        if pols.is_empty() {
            continue;
        }
        if let Err(e) = c.trust.lock().unwrap().save() {
            ctx.sh.note(format!("trust.json не записан: {e:#}"));
        }
        let cur = ctx.cur.lock().unwrap().as_ref().map(|x| x.1);
        if let Some(id) = cur {
            for p in pols {
                send_ctl(&ctx.node, id, T_POL, &p.wire()).await;
            }
        }
        ctx.refresh_servers13();
    }
}

async fn client_supervisor(ctx: Arc<ClientCtx>) {
    let fin = ctx.state.join("fin");
    let sel_file = ctx.state.join("select");
    let mut banned: HashMap<[u8; 16], Instant> = HashMap::new();
    let mut avoid: Option<([u8; 16], usize)> = None;
    let mut keep_trying: HashMap<[u8; 16], Instant> = HashMap::new();
    // переходы текущего выхода с транзита на прямой путь: не чаще раза в 5 мин на выход (если прямой путь не держится - не зацикливаемся)
    let mut direct_retry: HashMap<[u8; 16], Instant> = HashMap::new();
    while !fin.exists() {
        // 0013: сначала зачисление по приглашению (до него права есть только в собственном дереве, выходов нет)
        if ctx.c13.as_ref().map(|c| c.invite.lock().unwrap().is_some()).unwrap_or(false) {
            if let Err(e) = pair_client(&ctx).await {
                ctx.sh.note(format!("зачисление: {e:#}"));
                if ctx.c13.as_ref().map(|c| c.rejected.lock().unwrap().is_some()).unwrap_or(false) {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            continue;
        }
        // выбор пользователя: "auto" или хеш выхода
        let want: Option<[u8; 16]> = std::fs::read_to_string(&sel_file).ok().and_then(|t| dest32(t.trim()));
        // выход, на котором только что сменили носитель, идёт первым
        let keep_first: Option<[u8; 16]> = keep_trying.iter().find(|(_, t)| **t > Instant::now()).map(|(d, _)| *d);
        let mut cands = candidates(&ctx, &banned, want.or(keep_first));
        if cands.is_empty() && want.is_some() {
            // выбранный вручную выход недоступен: пока он не вернётся, работаем через лучший из остальных
            ctx.sh.note(format!("выбранный выход {} недоступен, работаю через лучший из остальных", want.map(|w| hex(&w[..4])).unwrap_or_default()));
            cands = candidates(&ctx, &banned, None);
        }
        let mut connected = None;
        for c in cands {
            *ctx.status.lock().unwrap() = format!("подключаюсь к {}", c.name);
            let av = avoid.and_then(|(d, i)| if d == c.dest { Some(i) } else { None });
            match connect_exit(&ctx, &c, av).await {
                Ok((id, h)) => {
                    ctx.lk_fail.lock().unwrap().remove(&c.dest);
                    ctx.note_link(&c.dest, true);
                    if let Some(cc) = ctx.carriers.lock().unwrap().get(&c.dest) {
                        cc.fails.store(0, Relaxed);
                    }
                    connected = Some((c, id, h));
                    break;
                }
                Err(e) => {
                    ctx.sh.note(format!("выход {}: {e:#}", c.name));
                    ctx.lk_fail.lock().unwrap().insert(c.dest, (Instant::now(), format!("{e:#}").chars().take(80).collect()));
                    ctx.note_link(&c.dest, false);
                    // FI: прямой путь через наш носитель не дал Link - забываем его, следующая попытка обходит этот интерфейс
                    if let Some(i) = direct_carrier_iface(&ctx, &c.dest) {
                        ctx.node.engine().remove_path(&DestinationHash::new(c.dest));
                        avoid = Some((c.dest, i));
                    }
                    // после смены носителя этот выход пробуем снова сразу, без бана (пока не истёк срок keep_trying)
                    let keep = keep_trying.get(&c.dest).map(|t| *t > Instant::now()).unwrap_or(false);
                    if !keep {
                        banned.insert(c.dest, Instant::now() + Duration::from_secs(10));
                    }
                    let cc = ctx.carriers.lock().unwrap().get(&c.dest).cloned();
                    if let Some(cc) = cc {
                        if cc.fails.fetch_add(1, Relaxed) + 1 >= 2 && !cc.prefer_tcp.load(Relaxed) {
                            ctx.sh.note(format!("{}: две неудачи подряд, пробую TCP", c.name));
                            cc.prefer_tcp.store(true, Relaxed);
                            cc.switches.fetch_add(1, Relaxed);
                            cc.fails.store(0, Relaxed);
                        }
                    }
                }
            }
        }
        let Some((cand, id, handle)) = connected else {
            *ctx.status.lock().unwrap() = "нет доступных выходов, повторяю".into();
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        };
        avoid = None;
        keep_trying.remove(&cand.dest);
        let gen_at_connect = ctx.carriers.lock().unwrap().get(&cand.dest).map(|c| c.generation.load(Relaxed)).unwrap_or(0);
        *ctx.tun.client_link.write().unwrap() = Some(handle);
        *ctx.tun.main_dest.write().unwrap() = cand.dest;
        let prev = ctx.cur.lock().unwrap().replace((cand.dest, id, Instant::now()));
        ctx.last_pong.store(now_ms() as u64, Relaxed);
        ctx.loss.lock().unwrap().clear();
        *ctx.rtt_ms.lock().unwrap() = None;
        *ctx.status.lock().unwrap() = format!("выход: {}", cand.name);
        ctx.publish_service();
        if let Some((_, old, _)) = prev {
            let _ = ctx.node.engine().close_link(&old).await;
        }
        ctx.sh.note(format!("текущий выход: {} ({})", cand.name, &hex(&cand.dest)[..8]));

        // обслуживание: пинг раз в секунду, смена по просьбе пользователя, отказ -> следующий выход
        let mut seq = 0u32;
        let mut last_ping = Instant::now() - Duration::from_secs(5);
        let mut better_since: Option<Instant> = None;
        let mut last_eval = Instant::now();
        let mut direct_since: Option<Instant> = None;
        let mut last_direct_check = Instant::now();
        let reason = loop {
            if fin.exists() {
                break "fin".to_string();
            }
            // «Авто» пересматривается: если другой выход заметно быстрее по RTT телефона (в 1,4 раза и на 15 мс) 15 с подряд - переходим на него.
            let rc = ctx.rcfg.read().unwrap().clone();
            if want.is_none() && rc.mode != "auto" && !rc.priority.is_empty() {
                // приоритеты: если выход выше по списку доступен 15 с подряд - переходим на него; RTT при этом не сравниваем
                if last_eval.elapsed() >= Duration::from_secs(3) {
                    last_eval = Instant::now();
                    let top = candidates(&ctx, &banned, None).into_iter().next();
                    match top {
                        Some(t) if t.dest != cand.dest && rc.prio_of(&t.dest) < rc.prio_of(&cand.dest) => {
                            let t0 = *better_since.get_or_insert(Instant::now());
                            if t0.elapsed() >= Duration::from_secs(15) {
                                break format!("авто: {} выше по приоритету", t.name);
                            }
                        }
                        _ => better_since = None,
                    }
                }
            } else if want.is_none() && last_eval.elapsed() >= Duration::from_secs(3) {
                last_eval = Instant::now();
                let rtt_of = |d: &[u8; 16]| -> Option<f64> {
                    let us = ctx.carriers.lock().unwrap().get(d).map(|c| c.rtt_us.load(Relaxed)).unwrap_or(0);
                    if us > 0 { Some(us as f64 / 1000.0) } else { None }
                };
                let cur_rtt = rtt_of(&cand.dest);
                let best = candidates(&ctx, &banned, None).into_iter().find(|c| c.dest != cand.dest && rtt_of(&c.dest).is_some());
                let better = match (cur_rtt, best.as_ref().and_then(|b| rtt_of(&b.dest))) {
                    (Some(cr), Some(br)) => cr > br * 1.4 && cr - br > 15.0,
                    _ => false,
                };
                if better {
                    let t0 = *better_since.get_or_insert(Instant::now());
                    if t0.elapsed() >= Duration::from_secs(15) {
                        break format!("авто: {} быстрее ({:.0} мс против {:.0} мс)", best.as_ref().map(|b| b.name.clone()).unwrap_or_default(), best.as_ref().and_then(|b| rtt_of(&b.dest)).unwrap_or(0.0), cur_rtt.unwrap_or(0.0));
                    }
                } else {
                    better_since = None;
                }
            }
            // Link к выходу открылся, пока путь шёл через транзит, и так на нём и остаётся (Link не переезжает при смене пути):
            // пинг складывается из двух плеч. Если прямой путь через наш носитель к этому выходу держится 10 с - переподключаемся к нему же.
            if last_direct_check.elapsed() >= Duration::from_secs(3) {
                last_direct_check = Instant::now();
                let attached = ctx.node.engine().link_stats(&id).and_then(|s| s.attached_interface());
                let direct = direct_carrier_iface(&ctx, &cand.dest).filter(|_| ctx.node.hops_to(&DestinationHash::new(cand.dest)) == Some(1));
                let may = direct_retry.get(&cand.dest).map(|t| t.elapsed() > Duration::from_secs(300)).unwrap_or(true);
                match (attached, direct) {
                    (Some(a), Some(dv)) if a != dv && may => {
                        if direct_since.get_or_insert(Instant::now()).elapsed() >= Duration::from_secs(10) {
                            break format!("прямой путь к {}: Link шёл через транзит", cand.name);
                        }
                    }
                    _ => direct_since = None,
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            let k = hex(id.as_bytes());
            if let Some(r) = ctx.sh.closed.lock().unwrap().get(&k) {
                break format!("link закрыт: {r}");
            }
            let silent = (now_ms() as u64).saturating_sub(ctx.last_pong.load(Relaxed));
            if silent > ctx.fail_ms {
                break format!("нет ответа {silent} мс");
            }
            let want: Option<[u8; 16]> = std::fs::read_to_string(&sel_file).ok().and_then(|t| dest32(t.trim()));
            if let Some(w) = want {
                // вернуться к выбранному выходу можно, только если он снова доступен (не забанен и не потерян)
                let usable = banned.get(&w).map(|t| *t < Instant::now()).unwrap_or(true)
                    && ctx.servers.lock().unwrap().iter().any(|e| e.dest == w && e.state != "lost" && (ctx.c13.is_none() || exit_eligible(&ctx, e)));
                if w != cand.dest && usable {
                    break "выбор пользователя".to_string();
                }
            }
            if last_ping.elapsed() >= Duration::from_secs(1) {
                last_ping = Instant::now();
                seq += 1;
                spawn_dgram(&ctx.node, id, dgram_ping(seq, now_us(), b'P'));
                ctx.loss.lock().unwrap().sent(seq);
                // монитор качества: на QUIC потери пингов >= 30% при >= 8 созревших -> запасной TCP для этого выхода
                let cc = ctx.carriers.lock().unwrap().get(&cand.dest).cloned();
                if let Some(cc) = cc {
                    if cc.is_quic() && !cc.prefer_tcp.load(Relaxed) {
                        if let Some(l) = ctx.loss.lock().unwrap().loss(Duration::from_secs(3), 8) {
                            if l >= 0.30 {
                                ctx.sh.note(format!("{}: потери UDP {:.0}% по пингам, переключаю носитель на TCP", cand.name, l * 100.0));
                                cc.prefer_tcp.store(true, Relaxed);
                                cc.switches.fetch_add(1, Relaxed);
                            }
                        }
                    }
                }
            }
        };
        if reason == "fin" {
            break;
        }
        // прямой путь к тому же выходу - как смена по выбору: старый Link держим до нового, без бана
        let direct_move = reason.starts_with("прямой путь");
        if direct_move {
            direct_retry.retain(|_, t| t.elapsed() < Duration::from_secs(300));
            direct_retry.insert(cand.dest, Instant::now());
            keep_trying.insert(cand.dest, Instant::now() + Duration::from_secs(25));
        }
        let user = reason == "выбор пользователя" || reason.starts_with("авто:") || direct_move;
        ctx.sh.note(format!("смена выхода: {reason}"));
        ctx.failovers.lock().unwrap().push(serde_json::json!({"at_ms": now_ms() as u64, "from": cand.name, "reason": reason}));
        if reason.starts_with("нет ответа") {
            // тишина по QUIC: вероятно, UDP режется; у этого пира пробуем запасной TCP (если и он не пойдёт, дозвон сам вернётся на QUIC)
            let cc = ctx.carriers.lock().unwrap().get(&cand.dest).cloned();
            if let Some(cc) = cc {
                if cc.is_quic() && !cc.prefer_tcp.load(Relaxed) {
                    ctx.sh.note(format!("{}: тишина по QUIC, пробую TCP", cand.name));
                    cc.prefer_tcp.store(true, Relaxed);
                    cc.switches.fetch_add(1, Relaxed);
                }
            }
        }
        // Выбранный пользователем выход при смене носителя не бросаем: Link закрыт ради TCP, тот же выход поднимется заново за секунды.
        // Если за это время не поднялся - обычные правила (бан 10 с и переход на лучший из остальных).
        let carrier_flip = ctx.carriers.lock().unwrap().get(&cand.dest).map(|c| c.generation.load(Relaxed) != gen_at_connect).unwrap_or(false);
        if carrier_flip && !user {
            keep_trying.insert(cand.dest, Instant::now() + Duration::from_secs(25));
            ctx.sh.note(format!("{}: смена носителя, остаюсь на этом выходе", cand.name));
        }
        if !user {
            // отказавший выход не пробуем 10 с; путь к нему ведёт через интерфейс, который и подвёл
            banned.insert(cand.dest, Instant::now() + Duration::from_secs(10));
            if let Some(i) = ctx.node.engine().link_stats(&id).and_then(|s| s.attached_interface()) {
                avoid = Some((cand.dest, i));
            }
            *ctx.tun.client_link.write().unwrap() = None;
            *ctx.cur.lock().unwrap() = None;
            ctx.publish_service();
            let _ = ctx.node.engine().close_link(&id).await;
        }
    }
}
