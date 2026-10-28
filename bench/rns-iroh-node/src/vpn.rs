//! knothopd: узел и клиент VPN с индивидуальными правами 0013/0014.
//!
//! Роли:
//!   hub     - лабораторный ретранслятор RNS;
//!   node    - постоянная identity, права/политики Trust, TUN + NAT;
//!   client  - локальные identity и Trust, обнаружение RNS, выбор выхода и failover.
//!
//! Записи прав и политики идут по LXMF; оставшееся Link-управление — Channel [тип u8][тело]. Пакеты туннеля — datagrams Link.
//! Секреты не попадают в журнал; приглашение читается из приватного файла.

use super::*;
use clap::{Args, Subcommand};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

#[path = "vpn_path.rs"]
mod path;
#[path = "lxmf_admin.rs"]
mod lxmf_admin;
#[path = "lxmf_sync.rs"]
mod lxmf_sync;
#[path = "enroll_net.rs"]
mod enroll_net;

#[cfg(test)]
#[path = "../../tests/client_inbox13_tests.rs"]
mod client_inbox13_tests;


// ------------------------------------------------------------------------------------------------ команды

#[derive(Parser, Clone)]
#[command(name = "knothopd", about = "KnotHop: серверный узел, хаб и клиент VPN")]
pub struct VpnCli {
    #[command(subcommand)]
    pub cmd: VpnCmd,
}

#[derive(Subcommand, Clone)]
pub enum VpnCmd {
    /// узел сети (выход, сосед, транзит; права по подписанным записям)
    Node(NodeArgs),
    /// ретранслятор RNS (лабораторная «публичная сеть»)
    Hub(HubArgs),
    /// клиент VPN (identity и права из state, опциональное приглашение)
    Client(ClientArgs),
    /// отозвать держателя (запись с пустыми правами)
    Revoke(RevokeArgs),
    /// показать права, приглашения и таблицу соседей
    List(StateArg),
    /// выпустить приглашение `kh-…` для новой ноды (локальная команда админа)
    Invite(InviteArgs),
    /// выдать или изменить права ноды (запись подписывается identity из --state)
    Grant(GrantArgs),
    /// что эта нода согласна делать в сети (0015): политика подписывается ею самой и сужает выданные права; нода применит за несколько секунд
    Policy(PolicyArgs),
    /// создать identity, если её ещё нет, и записать `whoami.json` (хеш и адрес в туннеле): приложению адрес нужен до создания TUN
    Whoami(StateArg),
    /// привязать якорь корня на НОВОЙ ноде (оператор на самой ноде, узел остановлен): публичный ключ корня из файла или `-`, сверка с отпечатком
    TrustAnchor(TrustAnchorArgs),
    /// «Забыть сеть» на устройстве: оставить только собственный корень, удалить чужие якоря и записи зачисления (узел остановлен)
    ForgetNetwork(StateArg),
    /// безопасный native bridge: пока LXMF executor не активен, submit отклоняется как unavailable
    AdminSubmit(AdminSubmitArgs),
    /// прочитать состояние команды из bounded durable journal
    AdminStatus(AdminStatusArgs),
    /// безопасный capability/authority snapshot без сетевых hints и секретов
    AdminView(AdminViewArgs),
    /// список категорий скачанных geoip.dat/geosite.dat в `rules-cats.json` (раздельное туннелирование)
    RulesList(StateArg),
    /// подсети правил «мимо туннеля» в `direct.cidr` и отчёт `rules-report.json`
    RulesCompile(StateArg),
}

#[derive(Args, Clone)]
pub struct TrustAnchorArgs {
    #[arg(long)] pub state: PathBuf,
    /// файл с публичным ключом корня (128 hex, поле `pk` из `knothopd whoami` админа) или `-` для stdin
    #[arg(long)] pub root_key_file: PathBuf,
    /// отпечаток корня (32 hex, `hash` из `whoami`), полученный другим каналом: ключ с иным хешем отклоняется
    #[arg(long)] pub fingerprint: String,
}

#[derive(Args, Clone)]
pub struct AdminSubmitArgs {
    #[arg(long)] pub state: PathBuf,
    #[arg(long)] pub target: String,
    #[arg(long)] pub root: String,
    #[arg(long)] pub op: String,
    #[arg(long)] pub holder: Option<String>,
    #[arg(long)] pub rights: Option<u16>,
    #[arg(long)] pub scope: String,
    #[arg(long)] pub request_id: String,
}

#[derive(Args, Clone)]
pub struct AdminStatusArgs { #[arg(long)] pub state: PathBuf, #[arg(long)] pub request_id: String }

#[derive(Args, Clone)]
pub struct AdminViewArgs { #[arg(long)] pub state: PathBuf, #[arg(long)] pub target: String }

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

#[derive(Args, Clone, Default)]
pub struct NodeArgs {
    /// JSON-файл настроек узла (поля как в флагах ниже, кроме --state); при его наличии флаги name/advertise/seed игнорируются
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long, default_value = "-")]
    pub state: PathBuf,
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
    /// лаборатория без таблицы `inet knothop`: не управлять nft-наборами HOST_ACCESS (TCP к хосту остаётся закрытым); только CLI, не node.json
    #[arg(long)]
    pub no_host_nft: bool,
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
    /// приглашение `kh-…`: нода по нему только допускает анонсы нод приглашения (сама не зачисляется; якорь корня на новой ноде ставит `knothopd trust-anchor`). Без якорей чужих корней нода сама себе админ
    #[arg(long, default_value = "")]
    pub invite: String,
    /// то же приглашение из файла
    #[arg(long)]
    pub invite_file: Option<PathBuf>,
    /// iroh-relay для hole punching: TLS-relay делит TCP-порт `--port` с носителем, QAD слушает отдельный UDP-порт (по умолчанию выключено)
    #[arg(long)]
    pub iroh_relay: bool,
    /// UDP-порт QAD (определение собственного публичного адреса); нужен файрвол-разрешение владельца узла
    #[arg(long, default_value_t = 47002)]
    pub relay_quic_port: u16,
    /// iroh-relay для hole punching, `host:порт` (TLS на TCP-порту ноды с `--iroh-relay`), через запятую: ключ relay должен быть ключом доверенной ноды
    #[arg(long, default_value = "")]
    pub relay_url: String,
}

/// Файл настроек узла: всё по умолчанию.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct NodeConf {
    name: String,
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
    /// модель 0013: приглашение kh- (одноразовое; после зачисления игнорируется)
    invite: Option<String>,
    invite_file: Option<PathBuf>,
    iroh_relay: bool,
    relay_quic_port: Option<u16>,
    relay_urls: Vec<String>,
}

/// Минимальный HTTP GET по 80 порту без зависимостей: тело ответа или None.
async fn http_get(host: &str, path: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::time::timeout(Duration::from_secs(4), tokio::net::TcpStream::connect((host, 80))).await.ok()?.ok()?;
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: knothopd\r\nConnection: close\r\n\r\n").as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), s.take(8192).read_to_end(&mut buf)).await.ok()?.ok()?;
    let t = String::from_utf8_lossy(&buf).to_string();
    if !t.starts_with("HTTP/1.") || !t.contains(" 200") {
        return None;
    }
    t.split_once("\r\n\r\n").map(|x| x.1.trim().to_string())
}

/// Двухбуквенный код страны узла по его внешнему IP: несколько сервисов по очереди, результат кэшируется в каталоге состояния.
/// Порядок: KNOTHOP_REGION (задаёт оператор/стенд) -> сервисы -> кэш -> "XX".
async fn detect_region(state: &Path) -> String {
    let ok = |c: &str| c.len() == 2 && c.chars().all(|x| x.is_ascii_alphabetic());
    if let Ok(r) = std::env::var("KNOTHOP_REGION") {
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

/// Тип узла, три значения: «android», «ios», «server» (knothopd node или приложение на Windows/Linux/macOS).
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
fn client_display_name(identity: &Identity, state: &Path) -> String {
    // имя, которое пользователь задал сам (оболочка кладёт state/node-name.txt), важнее автоимени
    if let Ok(t) = std::fs::read_to_string(state.join("node-name.txt")) {
        let n: String = t.chars().filter(|c| name_char_ok(*c)).take(32).collect();
        if !n.trim().is_empty() {
            return n.trim().to_string();
        }
    }
    match trust::hash_of(&identity.public_key_bytes()) {
        Some(h) => format!("телефон-{}", &hex(&h)[..6]),
        None => "телефон".into(),
    }
}

/// Тело T_USE от клиента: тип и имя узла, чтобы выход раздал их другим клиентам.
fn client_info_body(identity: &Identity, state: &Path) -> Vec<u8> {
    let name = client_display_name(identity, state);
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
    /// модель 0013: приглашение `kh-…` (одноразовое; после зачисления игнорируется)
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
    /// iroh-relay доверенных нод для hole punching, `host:порт` через запятую (по умолчанию выключено)
    #[arg(long, default_value = "")]
    pub relay_url: String,
}

#[derive(Args, Clone)]
pub struct RevokeArgs {
    #[arg(long)]
    pub state: PathBuf,
    /// префикс хеша держателя (из `list`)
    #[arg(long)]
    pub id: String,
}

#[derive(Args, Clone)]
pub struct InviteArgs {
    /// каталог состояния ноды-админа (identity и trust.json там же)
    #[arg(long)]
    pub state: PathBuf,
    /// права приглашаемого: подмножество USE|TRANSIT|EXIT, число или список (USE+EXIT), user = USE
    #[arg(long, default_value = "user")]
    pub rights: String,
    /// корень сети (хеш identity, 32 hex); по умолчанию свой
    #[arg(long)]
    pub root: Option<String>,
    /// записать приглашение в файл (для оболочки Android, у которой нет stdout), права 0600
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// ноды, которые выдадут права: identity-хеши (32 hex), через запятую, от 1 до 8
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

// ------------------------------------------------------------------------------------------------ вспомогательное

const T_AUTH_OK: u8 = 9;
const T_AUTH_FAIL: u8 = 10;
// модель прав (решение 0013): записи о правах, зачисление по приглашению
const T_USE: u8 = 14;      // клиент -> сервер: «я пришёл за выходом» (иначе Link - сосед-транзит)
const T_NBRS: u8 = 16;     // выход -> клиент: соседи с живым Link {"n":[{"d","r"}]} (0014 R3); список выходов не меняет
// 17 свободен: каталог нод (бывший T_DIR) идёт по LXMF, см. lxmf_sync::send_dir
/// Advisory observations are bounded by both count and negotiated Channel MDU.
const NBRS_MAX: usize = crate::observations::MAX_NEIGHBORS;
const T_OBSERVE: u8 = 21; // admitted client -> exit: UI visible (one byte 0/1), request fresh T_NBRS
/// сосед-сервер -> сосед-сервер: клиенты-узлы (якорь/TRANSIT/EXIT) с их именем и типом {"c":[{"k","n","pl"}]};
/// получатель проверяет права ключа по своим записям, держит не дольше CINFO_TTL; только для отображения
const T_CINFO: u8 = 22;
const CINFO_TTL: Duration = Duration::from_secs(60);
const CINFO_MAX: usize = 64;
/// Каталог нод: не более DIR_MAX записей в одном LXMF-сообщении
const DIR_MAX: usize = lxmf_sync::DIR_LIMIT;
/// книга адресов нод с правами (addr-book.json): не больше стольких записей
const BOOK_MAX: usize = 32;
static BOOK_LAST: Mutex<String> = Mutex::new(String::new());
/// 0015: подписанная политика ноды (`trust::Policy`, 163 Б). Принимается только на допущенном Link (сосед или клиент); верна по подписи самой ноды,
/// поэтому путь доставки не важен. Ничего не расширяет: действующие права = выдача ∩ политика.
const UNAUTH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_UNAUTH_LINKS: usize = 64;
/// H10: неаутентифицированных Link через один интерфейс носителя (глобально - MAX_UNAUTH_LINKS).
const MAX_UNAUTH_PER_IFACE: usize = 8;
/// H10: управляющие сообщения на Link (MessageReceived): ведро CTRL_RATE/с, запас CTRL_BURST. Сверх - отбрасываются.
/// Непрерывное нарушение CTRL_VIOLATION_CLOSE подряд - Link закрывается. VPN LinkDataReceived сюда не относится.
const CTRL_RATE: f64 = 50.0;
const CTRL_BURST: f64 = 100.0;
const CTRL_VIOLATION_CLOSE: Duration = Duration::from_secs(10);
/// B (клиент): ведро управляющих сообщений заводим не более чем на столько Link; сообщения с новых Link сверх лимита отбрасываются.
const CLIENT_CTRL_LINKS: usize = 64;
const MAX_NEIGHBORS: usize = 64;
/// S2/S3: записи соседей без TRANSIT по записям и без живого Link. Отдельный лимит, чтобы публичные анонсы не заняли таблицу.
const MAX_UNTRUSTED_NEIGHBORS: usize = 32;

fn rand16() -> [u8; 16] {
    let mut b = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

/// Подсеть адресов клиентов (одна на всю группу: клиент сохраняет адрес при смене выхода). Задаётся в конфиге узла (`client_net`),
/// выбирается так, чтобы не пересекаться с сетями узлов (на ru1 10.130.0.0/24 попадает в 10.128.0.0/10 - для пилота 198.18.0.0/15).
static CLIENT_NET: std::sync::OnceLock<(u32, u8)> = std::sync::OnceLock::new();
/// Двухбуквенный код страны этого узла (по внешнему IP или KNOTHOP_REGION); уходит только допущенным по Link (в анонсе его нет, ADR 0016).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_cli_protocols_are_not_accepted() {
        for args in [
            vec!["knothopd", "bench", "--state", "/unused", "--to", "x", "--mb", "1"],
            vec!["knothopd", "keygen", "--out", "/unused"],
            vec!["knothopd", "issue", "--state", "/unused"],
            vec!["knothopd", "client", "--state", "/unused", "--profile-file", "/unused"],
        ] { assert!(VpnCli::try_parse_from(args).is_err()); }
    }

    #[test]
    fn admin_cli_is_non_shell_and_never_claims_queue_or_apply() {
        let view: serde_json::Value = serde_json::from_str(&run_cli_json(
            "admin-view --state /ignored --target 00112233445566778899aabbccddeeff", "/safe/state"
        )).unwrap();
        assert_eq!(view["capabilities"]["admin_commands"], false);
        assert_eq!(view["effective_authority"]["authorities"].as_array().unwrap().len(), 0);
        let rejected: serde_json::Value = serde_json::from_str(&run_cli_json(
            "admin-submit --state /ignored --target 00112233445566778899aabbccddeeff --root 00112233445566778899aabbccddeeff --op rights.grant --holder 00 --rights 64 --scope 00112233445566778899aabbccddeeff --request-id 00112233445566778899aabbccddeeff",
            "/safe/state"
        )).unwrap();
        assert_eq!(rejected["accepted"], false);
        assert_eq!(rejected["queued"], false);
        // без живого клиентского LXMF runtime на этом state команда не принимается (нет фальшивой очереди)
        assert_eq!(rejected["rejected"], "unsupported_offline");
        let shell: serde_json::Value = serde_json::from_str(&run_cli_json("admin-view; reboot", "/safe/state")).unwrap();
        assert_eq!(shell["rejected"], "invalid_cli_input");
    }

    #[test]
    fn my_node_view_and_rights_set_use_inbox_and_signed_issue_rules() {
        let base = std::env::temp_dir().join(format!("knothop-mynode-{}-{}", std::process::id(), now_ms()));
        let (a, b) = (base.join("a"), base.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let ida = load_or_create_identity(&a).unwrap();
        let idb = load_or_create_identity(&b).unwrap();
        let holder_pk: trust::Pk = idb.public_key_bytes().try_into().unwrap();
        let holder = hex(idb.hash());
        let state = a.to_str().unwrap();
        // чужой для сети держатель пока неизвестен: запись не создаётся
        let r: serde_json::Value = serde_json::from_str(&run_cli_json(&format!("rights-set --state {state} --holder {holder} --rights 1"), state)).unwrap();
        assert_eq!(r["accepted"], false);
        let mut tr = trust::Trust::load(ida, &a).unwrap();
        tr.issue(tr.me_hash, holder_pk, trust::USE).unwrap();
        tr.save().unwrap();
        let v: serde_json::Value = serde_json::from_str(&run_cli_json(&format!("trust-view --state {state}"), state)).unwrap();
        assert_eq!(v["my_rights"], trust::ALL);
        assert_eq!(v["can_add"], true);
        assert_eq!(v["participants"].as_array().unwrap().len(), 1);
        assert_eq!(v["participants"][0]["holder"], holder);
        assert_eq!(v["participants"][0]["rights"], trust::USE);
        assert_eq!(v["queued"], 0);
        // HOST_ACCESS и мусор отвергаются до подписи
        for bad in ["rights-set --holder X --rights 1", &format!("rights-set --holder {holder} --rights 64"), &format!("rights-set --holder {holder} --rights 1 --root {holder}")] {
            let r: serde_json::Value = serde_json::from_str(&run_cli_json(bad, state)).unwrap();
            assert_eq!(r["accepted"], false, "{bad}");
        }
        let r: serde_json::Value = serde_json::from_str(&run_cli_json(&format!("rights-set --state {state} --holder {holder} --rights 7"), state)).unwrap();
        assert_eq!(r["accepted"], true, "{r}");
        let v: serde_json::Value = serde_json::from_str(&run_cli_json(&format!("trust-view --state {state}"), state)).unwrap();
        assert_eq!(v["queued"], 1);
        assert_eq!(v["participants"][0]["queued"], 7);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn exit_datagram_probe_requires_exact_echo_not_control_or_foreign_nonce() {
        let reply = dgram_ping(42, 1234, b'R');
        assert!(data_probe_matches(42, 1234, &reply));
        assert!(!data_probe_matches(41, 1234, &reply));
        assert!(!data_probe_matches(42, 1235, &reply));
        assert!(!data_probe_matches(42, 1234, &dgram_ping(42, 1234, b'P')));
        assert!(!data_probe_matches(42, 1234, &reply[..15]));
        assert!(!data_probe_matches(42, 1234, &[T_AUTH_OK]));
    }

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
        let (name, pl) = parse_client_info(&client_info_body(&id, std::path::Path::new("/nonexistent"))).unwrap();
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
    fn dial_filter_rejects_internal_ranges() {
        for bad in ["127.0.0.1", "10.1.2.3", "172.17.0.1", "172.31.255.1", "192.168.0.1", "100.64.0.1", "169.254.1.1", "198.18.0.5", "198.19.255.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fd00::1", "::"] {
            assert!(!is_global_ip(&bad.parse().unwrap()), "{bad} должен быть отклонён");
        }
        for good in ["1.1.1.1", "1.1.1.1", "8.8.8.8", "2a0d:6c2:26:4f0::"] {
            assert!(is_global_ip(&good.parse().unwrap()), "{good} должен проходить");
        }
    }

    #[test]
    fn auth_ok_only_after_successful_tun_admission() {
        assert_eq!(admission_outcome(Ok(Admission::Admitted)), AdmitOutcome::SendAuthOk);
        assert_eq!(admission_outcome(Ok(Admission::AlreadyAdmitted)), AdmitOutcome::SendAuthOk);
        for e in [AdmissionError::AclNotReady, AdmissionError::Capacity, AdmissionError::AddressInUse, AdmissionError::LinkAddressChanged] {
            match admission_outcome(Err(e)) {
                AdmitOutcome::Refuse { reason, note } => assert!(!reason.is_empty() && !note.is_empty(), "{e}"),
                AdmitOutcome::SendAuthOk => panic!("{e} must not lead to AUTH_OK"),
            }
        }
        assert_eq!(admission_outcome(Err(AdmissionError::Capacity)), AdmitOutcome::Refuse { reason: b"exit client capacity", note: "exit client capacity" });
        assert_eq!(admission_outcome(Err(AdmissionError::AddressInUse)), AdmitOutcome::Refuse { reason: b"address clash", note: "конфликт адреса клиента" });
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
    fn client_identity_and_enrollment_survive_restart_without_profile() {
        let dir = std::env::temp_dir().join(format!("kh-client13-{}", hex(&rand16())));
        std::fs::create_dir_all(&dir).unwrap();
        let first = load_or_create_identity(&dir).unwrap();
        let root = leviculum_std::api::generate_identity();
        let mut issuer = trust::Trust::new(root.clone(), None);
        let grant = issuer.issue(*root.hash(), first.public_key_bytes(), trust::USE).unwrap();
        let mut tr = trust::Trust::new(first.clone(), Some(dir.join("trust.json")));
        tr.add_anchor(&root.public_key_bytes()).unwrap();
        assert_eq!(tr.offer(grant), trust::Offer::Added);
        tr.save().unwrap();
        let second = load_or_create_identity(&dir).unwrap();
        assert_eq!(first.public_key_bytes(), second.public_key_bytes());
        let loaded = trust::Trust::load(second.clone(), &dir).unwrap();
        assert_eq!(loaded.effective(&second.public_key_bytes(), now_ms() as u64) & trust::USE, trust::USE);
        std::fs::remove_dir_all(dir).unwrap();
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
    fn relay_gate_admits_only_keys_with_rights() {
        let (root_id, node_id, holder, stranger) = (leviculum_std::api::generate_identity(), leviculum_std::api::generate_identity(), leviculum_std::api::generate_identity(), leviculum_std::api::generate_identity());
        let root = *root_id.hash();
        let mut issuer = trust::Trust::new(root_id.clone(), None);
        let rec = issuer.issue(root, holder.public_key_bytes(), trust::USE).unwrap();
        let mut node = trust::Trust::new(node_id, None);
        let key = |i: &Identity| i.ed25519_verifying().to_bytes();
        // без якоря и записи ключ не допущен
        assert!(!key_has_rights(&node, &key(&holder)));
        node.add_anchor(&root_id.public_key_bytes()).unwrap();
        assert!(!key_has_rights(&node, &key(&holder)), "якорь без записи держателя прав не даёт");
        assert_eq!(node.offer(rec), trust::Offer::Added);
        assert!(key_has_rights(&node, &key(&holder)));
        assert!(!key_has_rights(&node, &key(&stranger)));
        assert!(!key_has_rights(&node, &[0u8; 32]));
    }

    #[test]
    fn relay_urls_are_filtered_like_hints() {
        // частные и служебные адреса, мусор и схемы отбрасываются; больше трёх не берём
        let list = "127.0.0.1:47001, 10.0.0.5:47001, https://evil.example:1, 8.8.8.8:47001, relay.example.org:47001, bad host:1, 1.1.1.1:0, 9.9.9.9:47001, 4.4.4.4:47001";
        let urls = parse_relay_urls(list);
        assert!(urls.iter().all(|u| { let s = u.to_string(); !s.contains("127.0.0.1") && !s.contains("10.0.0.5") && !s.contains("evil") }), "{urls:?}");
        assert!(urls.iter().any(|u| u.to_string().contains("8.8.8.8")), "{urls:?}");
        assert!(urls.len() <= 3);
        assert!(parse_relay_urls("").is_empty());
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
        let old_name = Destination::new(Some(Identity::from_public_key_bytes(&pk).unwrap()), Direction::Out, DestinationType::Single, "knothopvpn", &["node", T13_TAG]).unwrap();
        assert_ne!(t13, *old_name.hash().as_bytes(), "0013 больше не использует имя knothopvpn");
        let legacy = Destination::new(Some(Identity::from_public_key_bytes(&pk).unwrap()), Direction::Out, DestinationType::Single, "knothopvpn", &["node", "grp"]).unwrap();
        assert_eq!(dest_from_pub_tag(&pk, "grp"), *legacy.hash().as_bytes());
    }

    #[test]
    fn trust_anchor_cli_binds_root_only_with_matching_fingerprint_and_stopped_node() {
        let dir = std::env::temp_dir().join(format!("kh-anchor-{}", hex(&rand16())));
        let (state, keyf) = (dir.join("state"), dir.join("root.pk"));
        std::fs::create_dir_all(&state).unwrap();
        let node = load_or_create_identity(&state).unwrap();
        let root = leviculum_std::api::generate_identity();
        std::fs::write(&keyf, format!("{}\n", hex(&root.public_key_bytes()))).unwrap();
        let args = |fp: String| TrustAnchorArgs { state: state.clone(), root_key_file: keyf.clone(), fingerprint: fp };
        assert!(trust_anchor_cmd(args(hex(&[7u8; 16]))).is_err(), "чужой отпечаток");
        assert!(!trust::Trust::load(node.clone(), &state).unwrap().has_anchor(root.hash()));
        write_atomic(&state.join("status.json"), b"{}");
        assert!(trust_anchor_cmd(args(hex(root.hash()))).is_err(), "узел работает");
        std::fs::remove_file(state.join("status.json")).unwrap();
        trust_anchor_cmd(args(hex(root.hash()))).unwrap();
        trust_anchor_cmd(args(hex(root.hash()).to_uppercase())).unwrap();
        let tr = trust::Trust::load(node, &state).unwrap();
        assert!(tr.has_anchor(root.hash()) && tr.anchors().len() == 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn hint_addresses_are_syntax_and_scope_checked_before_storing() {
        for ok in ["example.com:443", "node-1.example.org:47001", "8.8.8.8:47001", "[2001:4860:4860::8888]:443"] {
            assert!(sane_hint_addr(ok), "{ok}");
        }
        let long = format!("{}:1", "a".repeat(64));
        for bad in ["127.0.0.1:1", "10.0.0.1:80", "192.168.1.1:80", "169.254.1.1:1", "[::1]:1", "host", "a.b:0", "a.b:99999", "bad host:1", "evil..com:1", "-x.com:1", ":1", long.as_str()] {
            assert!(!sane_hint_addr(bad), "{bad}");
        }
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


// ------------------------------------------------------------------------------------------------ общий запуск

struct Base {
    node: Arc<Node>,
    events: leviculum_std::driver::EventReceiver,
    ep: Endpoint,
    sh: Arc<Shared>,
    cli: Cli,
    admin_lxmf: Option<lxmf_admin::AdminRuntime>,
}

/// Узел RNS + конечная точка QUIC. Общие настройки носителя те же, что у стенда (датаграммы QUIC, GCM на Link).
async fn start_base(role: &str, state: &Path, transport: bool, port: Option<u16>, key: SecretKey, admin_identity: Option<Identity>, mbit: u64, extra: &[&str], tcp: Option<u16>, relays: &[RelayUrl]) -> Result<Base> {
    std::fs::create_dir_all(state).context("create state dir")?;
    let mut args: Vec<String> = ["knothopd", "--role", role, "--ip", "0.0.0.0", "--relay", "none", "--mode", "tun", "--carrier", "datagram", "--dgram-mtu",
        "1400", "--cipher", "gcm", "--data-cap", "4096", "--chan-buf", "4096", "--quic-initial-mtu", "1452", "--quic-cc", "tunnel", "--quic-cc-mbit"]
        .iter().map(|s| s.to_string()).collect();
    args.push(mbit.to_string());
    // стенд: глубина очередей (по умолчанию 4096 пакетов; очередь интерфейса - на каждый Link-носитель) - для замеров W43
    for (env, flag) in [("KNOTHOP_CHAN_BUF", "--chan-buf"), ("KNOTHOP_DATA_CAP", "--data-cap")] {
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
        // Единый интервал также для отдельных LXMF Links: иначе server-initiated
        // LXMF будил бы телефон штатными RTT-derived keepalive каждые 5 с.
        .link_keepalive(CLIENT_KEEPALIVE_S)
        .proof_binding_policy(leviculum_std::api::ProofBindingPolicy::ByCipher)
        .data_channel_capacity(cli.data_cap)
        .link_cipher(leviculum_std::api::LinkCipher::Gcm)
        // ADR 0016: Link зачисления идёт через чужие транспорты RNS и может быть только стандартным CBC; такой Link допускается лишь на зачисление
        .accept_cbc_links(true);
    if let Some(tp) = tcp {
        nb = nb.add_tcp_server(SocketAddr::from(([0, 0, 0, 0], tp)));
    }
    let pn_identity = transport.then(|| admin_identity.clone()).flatten();
    let admin_lxmf = admin_identity.map(|i| {
        let (p, r) = lxmf_admin::AdminProcessor::new(i);
        (if transport { p.with_fetch_ms(lxmf_admin::PN_FETCH_SERVER_MS) } else { p }, r)
    });
    let (admin_lxmf, nb) = match admin_lxmf {
        Some((processor, runtime)) => {
            let nb = if let Some(identity) = pn_identity {
                nb.core_processor(lxmf_sync::Processors(processor, lxmf_sync::propagation_processor(state, identity)?))
            } else { nb.core_processor(processor) };
            (Some(runtime), nb)
        }
        None => (None, nb),
    };
    let mut node = nb.build().context("build node")?;
    node.start().await.context("start node")?;
    let events = node.take_event_receiver().context("event receiver")?;
    let node = Arc::new(node);

    let mut eb = Endpoint::builder(presets::Minimal).secret_key(key).alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled);
    if !relays.is_empty() {
        // relay нужен для сигнализации hole punching и QAD; сертификат принимается только от ключа доверенной ноды (relay.rs)
        let _ = RELAY_URLS.set(relays.to_vec());
        eb = eb.relay_mode(RelayMode::custom(relays.iter().cloned())).ca_tls_config(relay::pinned_ca(relay_trusted()));
    }
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
    Ok(Base { node, events, ep, sh, cli, admin_lxmf })
}

/// Relay-серверы, заданные для этого процесса: к адресу пира добавляются как подсказка пути (hole punching), когда прямой IP неизвестен или закрыт.
static RELAY_URLS: std::sync::OnceLock<Vec<RelayUrl>> = std::sync::OnceLock::new();
/// Права доверенных ключей читаются из Trust процесса; пока он не задан, relay никому не доверяет.
static RELAY_TRUST: std::sync::OnceLock<Arc<Mutex<trust::Trust>>> = std::sync::OnceLock::new();

/// Есть ли у ключа Ed25519 (он же EndpointId iroh и подпись identity RNS) хоть какое-то право в нашем Trust.
fn key_has_rights(tr: &trust::Trust, k: &[u8; 32]) -> bool {
    tr.holders_with(trust::USE | trust::TRANSIT | trust::EXIT | trust::ADD | trust::REMOVE | trust::CONFIG).iter().any(|pk| &pk[32..64] == k)
}

fn relay_trusted() -> relay::Trusted {
    Arc::new(|k: &[u8; 32]| RELAY_TRUST.get().is_some_and(|t| key_has_rights(&t.lock().unwrap(), k)))
}

/// `host:порт` -> `https://host:порт`; адрес проходит тот же фильтр, что и подсказки (публичный IP или нормальное имя).
fn parse_relay_urls(list: &str) -> Vec<RelayUrl> {
    list.split(',').map(str::trim).filter(|s| !s.is_empty()).filter_map(|s| {
        if !sane_hint_addr(s) { return None; }
        format!("https://{s}").parse::<RelayUrl>().ok()
    }).take(3).collect()
}

/// Добавить к адресу пира relay-подсказки (если заданы).
fn with_relays(mut addr: EndpointAddr) -> EndpointAddr {
    for u in RELAY_URLS.get().into_iter().flatten() {
        addr = addr.with_relay_url(u.clone());
    }
    addr
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
    /// EndpointId пира (ключ памяти носителей health.rs); задаёт дозвон, пусто - пока дозвон не запущен
    pub peer: Mutex<String>,
    /// когда Link замолчал на QUIC: подозрение, а не запись в health.rs; подтверждает его только работающий сразу после этого TCP (`confirm_quic_silence`)
    pub silence: Mutex<Option<Instant>>,
    /// когда в последний раз тишина по QUIC совпала со сбоем TCP-дозвона (общий сбой пути, а не блокировка носителя)
    pub joint_fail: Mutex<Option<Instant>>,
}

impl CarrierCtl {
    fn new() -> Arc<Self> {
        Arc::new(Self { prefer_tcp: AtomicBool::new(false), mode: Mutex::new("none"), switches: Default::default(), generation: Default::default(), fails: Default::default(), rtt_us: Default::default(), label: Mutex::new(String::new()), peer: Mutex::new(String::new()), silence: Mutex::new(None), joint_fail: Mutex::new(None) })
    }
    fn set_mode(&self, m: &'static str) {
        // `generation` тут не растёт: смена носителя интерфейс пира (`mux.rs`) не пересоздаёт и Link не рвёт; растёт `Dialer::mux_for`
        *self.mode.lock().unwrap() = m;
    }
    fn is_quic(&self) -> bool {
        *self.mode.lock().unwrap() == "quic"
    }
}

/// Пауза до первой попытки вернуться на QUIC по умолчанию, с; потолок роста (KNOTHOP_TCP_BACKOFF_S меняет только первую).
const TCP_BACK_OFF_FIRST_S: u64 = 120;
const TCP_BACK_OFF_MAX_S: u64 = 1800;
/// QUIC-сессия прожила столько - соединение доказано не одним рукопожатием, и запись «QUIC не работает» (health.rs) стирается. Больше окон
/// детекторов тишины (fail_ms 3 с) и потерь пингов (3-4 с при >= 8 пингах) вместе с запасом.
const QUIC_PROVEN: Duration = Duration::from_secs(20);
/// QUIC-сессия прожила столько - возврат удался и UDP пригоден: пауза `back_off` начинается заново. Вдвое больше первой памяти health.rs (5 мин) и
/// впятеро больше первой паузы (120 с): путь, державший сессию дольше, не похож на тот, что режут после рукопожатия. При дрожащем UDP цена -
/// одна неудачная попытка (~25 с, O52) не чаще раза в ~12 мин против раза в 30 мин у потолка.
const QUIC_STABLE: Duration = Duration::from_secs(600);

/// Пора снять рабочий TCP ради попытки вернуться на QUIC? Пока QUIC помечен неработающим (health.rs), TCP не рвём: возврат всё равно запрещён,
/// а просроченный срок убивал бы каждую новую сессию за 0,5 с (churn TCP, Link пересобирается впустую).
fn tcp_release_due(elapsed: Duration, back_off_s: u64, quic_bad: bool) -> bool {
    !quic_bad && elapsed >= Duration::from_secs(back_off_s)
}

/// Следующая пауза перед возвратом на QUIC после попытки.
fn grown_back_off(back_off_s: u64) -> u64 {
    back_off_s.saturating_mul(2).min(TCP_BACK_OFF_MAX_S)
}

/// Пауза возврата после завершённой QUIC-сессии длиной `up`: стабильная сессия сбрасывает рост паузы к первой.
fn back_off_after_quic(back_off_s: u64, first_s: u64, up: Duration) -> u64 {
    if up >= QUIC_STABLE { first_s.min(TCP_BACK_OFF_MAX_S) } else { back_off_s }
}

/// QUIC-сессия длиной `up` доказана: стереть запись о неработающем QUIC. Рукопожатие без живой сессии её не стирает - иначе счётчик
/// неудач (рост срока памяти 5 мин -> 6 ч) обнулялся бы при каждой попытке, прошедшей рукопожатие и сорвавшейся на данных.
fn settle_quic_health(health: &health::Health, peer: &str, up: Duration) -> bool {
    let proven = up >= QUIC_PROVEN;
    if proven && !peer.is_empty() {
        health.ok(peer, health::Kind::Quic);
    }
    proven
}

/// Смена носителя этого пира после создания Link (в том числе нами: дозвон сам снял TCP по `back_off`, или QUIC пересоединён после рестарта пира).
/// Link привязан к интерфейсу прежнего носителя и молчит из-за смены, а не из-за качества нового.
fn carrier_flipped(ctl: &CarrierCtl, gen_at_connect: u32) -> bool {
    ctl.generation.load(Relaxed) != gen_at_connect
}

/// Чем объяснять тишину Link (`нет ответа`).
#[derive(Debug, PartialEq, Eq)]
enum SilenceCause {
    /// Link жил на текущем QUIC и замолчал: вероятно, UDP режется
    Quic,
    /// носитель сменился после создания Link: тишина объяснена сменой, QUIC не виноват
    CarrierSwap,
    /// носитель не QUIC, или TCP уже выбран
    Other,
}

fn silence_cause(is_quic: bool, prefer_tcp: bool, flipped: bool) -> SilenceCause {
    if !is_quic || prefer_tcp {
        SilenceCause::Other
    } else if flipped {
        SilenceCause::CarrierSwap
    } else {
        SilenceCause::Quic
    }
}

/// Окно восстановления живого клиентского Link: не закрываем его через 3 с только из-за задержки/смены носителя.
/// Фактический LinkClosed/отзыв прав остаётся немедленным; это не изменение ACK/retransmit/rekey.
const SILENCE_GRACE: Duration = Duration::from_secs(30);
/// Сколько после тишины по QUIC TCP-дозвон может подтвердить подозрение: TCP, поднявшийся позже, говорит уже не об этой тишине.
const SILENCE_CONFIRM: Duration = Duration::from_secs(30);
/// Второе совпадение тишины по QUIC со сбоем TCP-дозвона за это время считается настоящей блокировкой обоих носителей, а не разовым сбоем сети.
const JOINT_FAIL_REPEAT: Duration = Duration::from_secs(600);

/// Разбор тишины Link у пира: при тишине по QUIC пробуем TCP. В память носителей (health.rs) QUIC при этом НЕ пишется: тишина может быть сбоем
/// самой сети (handover), а не блокировкой UDP. Запись делает `confirm_quic_silence`, когда рабочий TCP подтвердился сразу после тишины.
fn judge_silence(cc: &CarrierCtl, flipped: bool, now: Instant) -> SilenceCause {
    let cause = silence_cause(cc.is_quic(), cc.prefer_tcp.load(Relaxed), flipped);
    if cause == SilenceCause::Quic {
        cc.prefer_tcp.store(true, Relaxed);
        cc.switches.fetch_add(1, Relaxed);
        *cc.silence.lock().unwrap() = Some(now);
    }
    cause
}

/// Подозрение на тишину ещё в силе (`SILENCE_CONFIRM`)? Забирает его в любом случае.
fn take_silence(cc: &CarrierCtl, now: Instant) -> bool {
    cc.silence.lock().unwrap().take().is_some_and(|at| now.saturating_duration_since(at) <= SILENCE_CONFIRM)
}

/// TCP поднялся и подтвердил доставку (`tcpc::Dial::Up`) вскоре после тишины по QUIC: сеть жива, молчит именно UDP - QUIC запоминается
/// неработающим (у узла запись уходит в carrier_health.json, у клиента остаётся в памяти процесса: `health.init` вызывает только команда node,
/// файлов и пробуждений на телефоне не добавляется). Возвращает срок памяти.
fn confirm_quic_silence(health: &health::Health, cc: &CarrierCtl, peer: &str, now: Instant) -> Option<Duration> {
    (take_silence(cc, now) && !peer.is_empty()).then(|| health.fail(peer, health::Kind::Quic))
}

/// Что делать с `Dial::Blackhole`, пришедшим при подозрении на тишину по QUIC.
#[derive(Debug, PartialEq, Eq)]
enum JointFail {
    /// подозрения не было (или оно устарело): обычная обработка Blackhole
    NoSuspicion,
    /// оба носителя молчат в одном окне - общий сбой пути: ни TCP, ни QUIC не запоминаются
    PathFailure,
    /// то же совпадение повторилось за `JOINT_FAIL_REPEAT`: обе блокировки настоящие, запоминаются оба
    BothBlocked,
}

/// TCP-дозвон не прошёл при подозрении на тишину по QUIC. `Unreachable` (хост не отвечает) ничего не запоминает ни у кого; `Blackhole` в одном окне
/// с тишиной QUIC - общий сбой (handover, потеря сети), а не блокировка носителя: пара на ≥5 мин не блокируется. Повтор совпадения за 10 мин
/// остаётся сигналом настоящей блокировки обоих носителей (DPI на UDP и на TCP).
fn tcp_failed_with_silence(cc: &CarrierCtl, blackhole: bool, now: Instant) -> JointFail {
    if !take_silence(cc, now) {
        return JointFail::NoSuspicion;
    }
    if !blackhole {
        return JointFail::PathFailure;
    }
    let prev = cc.joint_fail.lock().unwrap().replace(now);
    if prev.is_some_and(|p| now.saturating_duration_since(p) <= JOINT_FAIL_REPEAT) { JointFail::BothBlocked } else { JointFail::PathFailure }
}

/// `Dial::Blackhole`: хост отвечает, данные не доходят. Запоминает TCP; QUIC, не прошедший перед этим (`quic_suspect`) или молчавший в паре с TCP
/// повторно (`BothBlocked`), запоминается вместе с ним. Совпадение с тишиной по QUIC впервые - общий сбой пути: не запоминается ничего (None).
/// Возвращает срок памяти TCP.
fn record_tcp_blackhole(health: &health::Health, cc: &CarrierCtl, peer: &str, quic_suspect: &mut bool, now: Instant) -> Option<Duration> {
    let joint = tcp_failed_with_silence(cc, true, now);
    let suspect = std::mem::take(quic_suspect);
    if joint == JointFail::PathFailure && !suspect {
        return None;
    }
    let d = health.fail(peer, health::Kind::Tcp);
    if suspect || joint == JointFail::BothBlocked {
        health.fail(peer, health::Kind::Quic);
    }
    Some(d)
}

/// Этап 0 make-before-break (docs/reviews/quic-return-make-before-break-2026-10-25.md): детерминированные регрессии без сети и часов.
#[cfg(test)]
mod carrier_return_tests {
    use super::*;

    fn quic_ctl(peer: &str) -> Arc<CarrierCtl> {
        let cc = CarrierCtl::new();
        *cc.peer.lock().unwrap() = peer.to_string();
        cc.set_mode("quic");
        cc
    }

    // 1. Тишина после снятия TCP нашим дозвоном не вменяется QUIC.
    #[test]
    fn silence_after_our_own_tcp_release_does_not_blame_quic() {
        let h = health::Health::default();
        let cc = CarrierCtl::new();
        let now = Instant::now();
        *cc.peer.lock().unwrap() = "p".into();
        cc.set_mode("tcp");
        let gen_at_connect = cc.generation.load(Relaxed); // Link поднят на TCP
        cc.set_mode("none"); // носитель закончился
        cc.generation.fetch_add(1, Relaxed); // интерфейс пира пересоздан (`Dialer::mux_for`): Link на снятом интерфейсе негоден
        cc.set_mode("quic"); // QUIC соединился за миллисекунды
        let flipped = carrier_flipped(&cc, gen_at_connect);
        assert!(flipped);
        // смена носителя внутри живого интерфейса Link не рвёт и «сменой» не считается
        let g = cc.generation.load(Relaxed);
        cc.set_mode("tcp");
        assert!(!carrier_flipped(&cc, g));
        cc.set_mode("quic");
        assert_eq!(judge_silence(&cc, flipped, now), SilenceCause::CarrierSwap);
        assert!(confirm_quic_silence(&h, &cc, "p", now).is_none() && !h.is_bad("p", health::Kind::Quic), "QUIC не запоминается");
        assert!(!cc.prefer_tcp.load(Relaxed) && cc.switches.load(Relaxed) == 0, "клиент остаётся на QUIC");
        // Link, поднятый уже на этом QUIC, замолчал: теперь это тишина по QUIC
        let gen_new = cc.generation.load(Relaxed);
        assert_eq!(judge_silence(&cc, carrier_flipped(&cc, gen_new), now), SilenceCause::Quic);
        assert!(cc.prefer_tcp.load(Relaxed) && cc.silence.lock().unwrap().is_some());
    }

    #[test]
    fn silence_cause_table() {
        use SilenceCause::*;
        assert_eq!(silence_cause(true, false, false), Quic);
        assert_eq!(silence_cause(true, false, true), CarrierSwap);
        assert_eq!(silence_cause(true, true, false), Other, "TCP уже выбран");
        assert_eq!(silence_cause(false, false, false), Other, "носитель не QUIC");
        assert_eq!(silence_cause(false, false, true), Other);
    }

    // 2. Гипотеза отчёта: при помеченном QUIC просроченный срок рвёт каждую новую TCP-сессию (churn). Модель: сторож проверяет раз в 0,5 с.
    #[test]
    fn tcp_is_not_churned_while_quic_is_bad() {
        let back_off = 120u64;
        let quic_bad_until = 314.0f64; // 14 с на два провала handshake + 5 мин памяти (health.rs FIRST)
        // Модель цикла dial_direct: сторож раз в 0,5 с; убитая сессия возвращает цикл наверх, где возврат на QUIC разрешён только при
        // !quic_bad и сроке; иначе TCP поднимается снова с паузой short_tcp (1,5 -> 3 -> ... -> 60 с, если сессия жила < 15 с).
        // tcp_since не обнуляется, пока стоит prefer_tcp, поэтому срок отсчитывается от первого перехода на TCP (t = 0).
        let bad_at = |t: f64| t < quic_bad_until;
        let run = |watch_due: &dyn Fn(Duration, bool) -> bool| {
            let (mut kills, mut t, mut short) = (0u32, 0.0f64, 0u32);
            loop {
                let started = t;
                loop {
                    t += 0.5;
                    if t >= 330.0 {
                        return kills;
                    }
                    if watch_due(Duration::from_secs_f64(t), bad_at(t)) {
                        break;
                    }
                }
                kills += 1;
                if tcp_release_due(Duration::from_secs_f64(t), back_off, bad_at(t)) {
                    return kills; // цикл вернулся на QUIC
                }
                if t - started < 15.0 {
                    short = (short + 1).min(6);
                    t += ((1500u64 << (short - 1)).min(60_000)) as f64 / 1000.0;
                } else {
                    short = 0;
                }
                t += 0.5;
            }
        };
        let old = run(&|el, _bad| el >= Duration::from_secs(back_off)); // условие до правки: дедлайн без учёта quic_bad
        let new = run(&|el, bad| tcp_release_due(el, back_off, bad));
        eprintln!("churn model: killed TCP sessions old={old} new={new}");
        assert!(old >= 6, "гипотеза подтверждена моделью: прежнее условие рвёт TCP-сессию снова и снова, пока QUIC помечен: {old}");
        assert_eq!(new, 1, "новое: единственное срабатывание после истечения памяти QUIC, затем возврат на QUIC");
        // а пока QUIC помечен, срок не наступает вообще
        assert!(!tcp_release_due(Duration::from_secs(3600), back_off, true));
        assert!(tcp_release_due(Duration::from_secs(back_off), back_off, false));
        assert!(!tcp_release_due(Duration::from_secs(back_off - 1), back_off, false));
    }

    // 3. Пауза возврата: рост до потолка 1800, сброс после стабильной QUIC-сессии.
    #[test]
    fn back_off_grows_to_cap_and_resets_after_stable_quic() {
        let mut b = TCP_BACK_OFF_FIRST_S;
        let mut seen = vec![b];
        for _ in 0..6 {
            b = grown_back_off(b);
            seen.push(b);
        }
        assert_eq!(seen, [120, 240, 480, 960, 1800, 1800, 1800], "потолок 30 мин сохранён");
        assert_eq!(grown_back_off(u64::MAX), TCP_BACK_OFF_MAX_S);
        // короткие QUIC-сессии (срыв до порога) паузу не сбрасывают
        assert_eq!(back_off_after_quic(1800, 120, Duration::from_secs(30)), 1800);
        assert_eq!(back_off_after_quic(480, 120, QUIC_STABLE - Duration::from_secs(1)), 480);
        // стабильная сессия сбрасывает к первой паузе (в том числе лабораторной)
        assert_eq!(back_off_after_quic(1800, 120, QUIC_STABLE), 120);
        assert_eq!(back_off_after_quic(960, 30, Duration::from_secs(3600)), 30);
        // первая пауза из окружения не может превысить потолок
        assert_eq!(back_off_after_quic(60, 99_999, QUIC_STABLE), TCP_BACK_OFF_MAX_S);
    }

    // 4. UDP заблокирован, TCP жив: тишина пишется в память носителей, как раньше, но только после подтверждения TCP. Рукопожатие без живой
    // сессии запись не стирает, сессия QUIC_PROVEN - стирает.
    #[test]
    fn quic_silence_with_live_tcp_is_remembered_and_escalates_until_session_is_proven() {
        let h = health::Health::default();
        let cc = quic_ctl("peer");
        let t0 = Instant::now();
        assert_eq!(judge_silence(&cc, false, t0), SilenceCause::Quic);
        assert!(!h.is_bad("peer", health::Kind::Quic), "до подтверждения TCP ничего не записано");
        assert!(cc.prefer_tcp.load(Relaxed) && cc.switches.load(Relaxed) == 1);
        // TCP поднялся и подтвердил доставку через 3 с
        let d1 = confirm_quic_silence(&h, &cc, "peer", t0 + Duration::from_secs(3)).unwrap();
        assert_eq!(d1, Duration::from_secs(300));
        assert!(h.is_bad("peer", health::Kind::Quic) && !h.is_bad("peer", health::Kind::Tcp) && h.blocked_for("peer").is_none());
        // подозрение израсходовано: повторное подтверждение ничего не добавляет
        assert!(confirm_quic_silence(&h, &cc, "peer", t0 + Duration::from_secs(4)).is_none());
        // повторная попытка: рукопожатие прошло, сессия сорвалась за 5 с (тишина) - запись остаётся, срок растёт
        assert!(!settle_quic_health(&h, "peer", Duration::from_secs(5)));
        cc.prefer_tcp.store(false, Relaxed);
        let t1 = t0 + Duration::from_secs(400);
        judge_silence(&cc, false, t1);
        let d2 = confirm_quic_silence(&h, &cc, "peer", t1 + Duration::from_secs(3)).unwrap();
        assert!(d2 > d1, "срок памяти растёт: {d2:?} > {d1:?}");
        // сессия дожила до QUIC_PROVEN: записи нет, счёт неудач обнулён
        assert!(settle_quic_health(&h, "peer", QUIC_PROVEN));
        assert!(!h.is_bad("peer", health::Kind::Quic));
        cc.prefer_tcp.store(false, Relaxed);
        let t2 = t1 + Duration::from_secs(900);
        judge_silence(&cc, false, t2);
        assert_eq!(confirm_quic_silence(&h, &cc, "peer", t2 + Duration::from_secs(3)).unwrap(), d1, "после доказанной сессии отсчёт неудач начинается заново");
    }

    // M-1: handover - молчат оба носителя в одном окне.
    #[test]
    fn handover_with_both_carriers_silent_blocks_neither_for_long() {
        let h = health::Health::default();
        let cc = quic_ctl("peer");
        let t0 = Instant::now();
        assert_eq!(judge_silence(&cc, false, t0), SilenceCause::Quic);
        // TCP-дозвон в том же окне: хост отвечает, данные не доходят (Blackhole)
        let mut quic_suspect = false;
        assert!(record_tcp_blackhole(&h, &cc, "peer", &mut quic_suspect, t0 + Duration::from_secs(4)).is_none());
        // ничего не записано: ни QUIC, ни TCP; пара не заблокирована
        assert!(!h.is_bad("peer", health::Kind::Quic) && !h.is_bad("peer", health::Kind::Tcp) && h.blocked_for("peer").is_none());
        // сеть вернулась, TCP поднялся позже: подозрение уже снято, QUIC не запоминается
        assert!(confirm_quic_silence(&h, &cc, "peer", t0 + Duration::from_secs(9)).is_none());
        assert!(!h.is_bad("peer", health::Kind::Quic));
    }

    #[test]
    fn handover_with_unreachable_tcp_drops_the_suspicion() {
        let h = health::Health::default();
        let cc = quic_ctl("peer");
        let t0 = Instant::now();
        judge_silence(&cc, false, t0);
        assert_eq!(tcp_failed_with_silence(&cc, false, t0 + Duration::from_secs(2)), JointFail::PathFailure);
        assert!(confirm_quic_silence(&h, &cc, "peer", t0 + Duration::from_secs(8)).is_none(), "TCP, поднявшийся после провала дозвона, тишину не подтверждает");
        assert!(!h.is_bad("peer", health::Kind::Quic));
    }

    #[test]
    fn stale_silence_suspicion_is_not_confirmed_or_joint() {
        let h = health::Health::default();
        let cc = quic_ctl("peer");
        let t0 = Instant::now();
        judge_silence(&cc, false, t0);
        assert!(confirm_quic_silence(&h, &cc, "peer", t0 + SILENCE_CONFIRM + Duration::from_secs(1)).is_none(), "TCP позже окна не подтверждает");
        cc.prefer_tcp.store(false, Relaxed);
        judge_silence(&cc, false, t0);
        assert_eq!(tcp_failed_with_silence(&cc, true, t0 + SILENCE_CONFIRM + Duration::from_secs(1)), JointFail::NoSuspicion, "устаревшее подозрение: обычный Blackhole");
        assert_eq!(tcp_failed_with_silence(&cc, true, t0), JointFail::NoSuspicion, "без подозрения - обычная обработка");
    }

    // Настоящая блокировка обоих носителей не маскируется: то же совпадение второй раз за 10 мин даёт запись обоих.
    #[test]
    fn repeated_joint_failure_is_a_real_block_of_both_carriers() {
        let h = health::Health::default();
        let cc = quic_ctl("peer");
        let t0 = Instant::now();
        let mut qs = false;
        judge_silence(&cc, false, t0);
        assert!(record_tcp_blackhole(&h, &cc, "peer", &mut qs, t0 + Duration::from_secs(4)).is_none(), "первое совпадение - общий сбой");
        assert!(h.blocked_for("peer").is_none());
        // дозвон вернулся на QUIC, Link снова замолчал, TCP снова Blackhole
        cc.set_mode("quic");
        cc.prefer_tcp.store(false, Relaxed);
        let t1 = t0 + Duration::from_secs(60);
        judge_silence(&cc, false, t1);
        assert!(record_tcp_blackhole(&h, &cc, "peer", &mut qs, t1 + Duration::from_secs(4)).is_some());
        assert!(h.blocked_for("peer").is_some(), "повтор: настоящая блокировка обоих запоминается как раньше");
        // совпадение через 10+ мин после предыдущего снова считается разовым
        let h2 = health::Health::default();
        cc.set_mode("quic");
        cc.prefer_tcp.store(false, Relaxed);
        let t2 = t1 + JOINT_FAIL_REPEAT + Duration::from_secs(30);
        judge_silence(&cc, false, t2);
        assert!(record_tcp_blackhole(&h2, &cc, "peer", &mut qs, t2 + Duration::from_secs(4)).is_none());
        assert!(h2.blocked_for("peer").is_none());
    }

    // Blackhole без тишины по QUIC (и с handshake-подозрением, как до правки) - прежнее поведение.
    #[test]
    fn plain_blackhole_keeps_legacy_marking() {
        let h = health::Health::default();
        let cc = quic_ctl("peer");
        let mut qs = false;
        assert!(record_tcp_blackhole(&h, &cc, "peer", &mut qs, Instant::now()).is_some());
        assert!(h.is_bad("peer", health::Kind::Tcp) && !h.is_bad("peer", health::Kind::Quic));
        let mut qs = true; // QUIC не соединился дважды, потом Blackhole: пара заблокирована
        assert!(record_tcp_blackhole(&h, &cc, "peer", &mut qs, Instant::now()).is_some());
        assert!(!qs && h.blocked_for("peer").is_some());
    }

    #[test]
    fn silence_without_known_peer_still_switches_but_remembers_nothing() {
        let h = health::Health::default();
        let cc = quic_ctl("");
        let t0 = Instant::now();
        assert_eq!(judge_silence(&cc, false, t0), SilenceCause::Quic);
        assert!(cc.prefer_tcp.load(Relaxed));
        assert!(confirm_quic_silence(&h, &cc, "", t0).is_none());
        assert!(settle_quic_health(&h, "", QUIC_PROVEN), "пустой ключ ничего не стирает, но сессия считается доказанной");
    }

    // Связка: QUIC помечен -> тишина не даёт возврата, TCP живёт, цикл не крутится.
    #[test]
    fn marked_quic_blocks_return_and_keeps_tcp() {
        let h = health::Health::default();
        let cc = quic_ctl("peer");
        let t0 = Instant::now();
        judge_silence(&cc, false, t0);
        confirm_quic_silence(&h, &cc, "peer", t0 + Duration::from_secs(2));
        let quic_bad = h.is_bad("peer", health::Kind::Quic);
        assert!(quic_bad);
        assert!(!tcp_release_due(Duration::from_secs(TCP_BACK_OFF_MAX_S), 120, quic_bad));
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

/// R-5: подсказка адреса должна быть `IP:порт` (публичный IP; лаборатория `KNOTHOP_ALLOW_PRIVATE_DIAL` снимает это) или `имя:порт`
/// с нормальным DNS-именем; не длиннее 64 байт. Подсказки приходят от пира, поэтому мусор не пишется в `hints.json`;
/// имена всё равно перепроверяются после разрешения в `resolve_addrs`.
fn sane_hint_addr(a: &str) -> bool {
    if a.len() > 64 {
        return false;
    }
    if let Ok(sa) = a.parse::<SocketAddr>() {
        return sa.port() != 0 && (std::env::var("KNOTHOP_ALLOW_PRIVATE_DIAL").is_ok() || is_global_ip(&sa.ip()));
    }
    let Some((host, port)) = a.rsplit_once(':') else { return false };
    port.parse::<u16>().is_ok_and(|p| p != 0)
        && !host.is_empty()
        && host.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
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
    // иначе чужой анонс превращает узел в сканер внутренней сети хоста (SSRF). Лаборатория включает KNOTHOP_ALLOW_PRIVATE_DIAL=1.
    if std::env::var("KNOTHOP_ALLOW_PRIVATE_DIAL").is_err() {
        out.retain(|a| is_global_ip(&a.ip()));
    }
    out.sort_by_key(|a| a.is_ipv6());
    out.dedup();
    out
}

/// Держит исходящую связь с узлом: один пакетный интерфейс RNS на пира (`mux.rs`), к которому подключаются и от которого отключаются носители.
/// Адреса - IP или имена из общего хранилища `book` (анонс его обновляет): разрешаются заново при каждой попытке (0014 R4).
/// Носитель: QUIC (датаграммы), а если он не соединяется или монитор качества нашёл потери UDP - TCP. Link привязан к интерфейсу, а не к носителю,
/// поэтому смена носителя в обе стороны идёт «сначала подключить новый, потом закрыть старый» и Link не рвёт. Из TCP пытаемся вернуться на QUIC, когда
/// прошла пауза `back_off` (120 с, удваивается до 30 мин) от перехода на TCP: кандидатный QUIC проходит зонд (`qprobe`) и только потом берёт данные.
#[allow(clippy::too_many_arguments)]
async fn dial_direct(ep: Endpoint, node: Arc<Node>, sh: Arc<Shared>, label: String, id: EndpointId, book: Arc<Addrs>, alive: Arc<AtomicBool>, ctl: Arc<CarrierCtl>) {
    // память о неработающих носителях к этому пиру (health.rs): ключ - EndpointId, не имя и не адрес
    let peer = id.to_string();
    *ctl.peer.lock().unwrap() = peer.clone();
    let d = Dialer { ep, node, sh, label, id, book, alive, ctl, peer };
    let first_back: u64 = std::env::var("KNOTHOP_TCP_BACKOFF_S").ok().and_then(|v| v.parse().ok()).unwrap_or(TCP_BACK_OFF_FIRST_S);
    let mut st = DialState { back_off: first_back, first_back, ..Default::default() };
    let (sh, ctl, label, peer) = (&d.sh, &d.ctl, d.label.as_str(), d.peer.as_str());
    let mut quic_fail = 0u32;
    let mut tcp_fail = 0u32;
    let mut announced_block = false;
    while d.alive.load(Relaxed) {
        if st.mux.as_ref().is_some_and(|m| m.is_closed()) {
            st.mux = None;
        }
        let quic_bad = sh.health.is_bad(peer, health::Kind::Quic);
        let tcp_bad = sh.health.is_bad(peer, health::Kind::Tcp);
        if let Some(rem) = sh.health.blocked_for(peer) {
            // оба носителя проверены и не работают: прямой интерфейс не поднимаем, путь к пиру найдёт RNS через другие узлы; позже проверим снова
            if !announced_block {
                announced_block = true;
                sh.note(format!("{label}: прямой путь заблокирован (QUIC и TCP не проходят), не подключаюсь, повторная проверка через {} мин", rem.as_secs() / 60 + 1));
            }
            d.book.pause(rem.min(Duration::from_secs(60))).await;
            continue;
        }
        announced_block = false;
        if tcp_bad {
            ctl.prefer_tcp.store(false, Relaxed);
        }
        if ctl.prefer_tcp.load(Relaxed) {
            let since = *st.tcp_since.get_or_insert_with(Instant::now);
            if tcp_release_due(since.elapsed(), st.back_off, quic_bad) {
                // пауза вышла: пробуем QUIC снова; если UDP всё ещё плох, монитор переключит обратно, а пауза вырастет
                ctl.prefer_tcp.store(false, Relaxed);
                st.tcp_since = None;
                st.back_off = grown_back_off(st.back_off);
                sh.note(format!("{label}: пробую вернуться на QUIC"));
            }
        } else {
            st.tcp_since = None;
        }
        let cur = d.book.get();
        let resolved = resolve_addrs(&cur).await;
        // без адресов можно дозвониться только через relay (hole punching по EndpointId); TCP-носителю нужен адрес
        let relay_only = resolved.is_empty() && RELAY_URLS.get().is_some();
        if resolved.is_empty() && !relay_only {
            sh.note(format!("{label}: адрес {cur:?} не разрешился"));
            d.book.pause(Duration::from_secs(5)).await;
            continue;
        }
        if relay_only || !(ctl.prefer_tcp.load(Relaxed) || quic_bad) {
            let mut addr = EndpointAddr::new(d.id);
            for a in &resolved {
                addr = addr.with_ip_addr(*a);
            }
            let addr = with_relays(addr);
            match tokio::time::timeout(Duration::from_secs(if resolved.is_empty() { 15 } else { 6 }), d.ep.connect(addr, ALPN)).await {
                Ok(Ok(conn)) => {
                    quic_fail = 0;
                    st.quic_suspect = false;
                    sh.note(format!("quic connected to {label}"));
                    let Some(m) = d.mux_for(&mut st) else {
                        conn.close(0u32.into(), b"no interface");
                        d.book.pause(Duration::from_secs(2)).await;
                        continue;
                    };
                    if m.add_quic(conn.clone(), true, *conn.remote_id().as_bytes()).is_none() {
                        conn.close(0u32.into(), b"too many carriers");
                        d.book.pause(Duration::from_secs(2)).await;
                        continue;
                    }
                    ctl.set_mode("quic");
                    d.session(&mut st, Cur::Quic(conn), m).await;
                }
                _ if relay_only => {
                    sh.note(format!("{label}: через relay не соединилось, повторю"));
                    d.book.pause(Duration::from_secs(10)).await;
                }
                _ => {
                    quic_fail += 1;
                    if quic_fail >= 2 {
                        quic_fail = 0;
                        if tcp_bad {
                            // TCP уже признан неработающим при живом хосте: если хост отвечает и сейчас, QUIC не проходит тоже
                            if tcpc::reachable(&resolved).await {
                                let dur = sh.health.fail(peer, health::Kind::Quic);
                                sh.note(format!("{label}: QUIC не соединяется при живом хосте, запоминаю на {} мин", dur.as_secs() / 60));
                            }
                        } else {
                            sh.note(format!("{label}: QUIC не соединяется 2 раза подряд, переключаюсь на TCP"));
                            ctl.prefer_tcp.store(true, Relaxed);
                            ctl.switches.fetch_add(1, Relaxed);
                            st.quic_suspect = true;
                        }
                    }
                    d.book.pause(Duration::from_secs(2)).await;
                }
            }
        } else {
            match tcpc::connect(&resolved, d.ep.secret_key(), &d.id).await {
                tcpc::Dial::Up(stream) => {
                    tcp_fail = 0;
                    d.tcp_confirmed(&mut st);
                    let Some(m) = d.mux_for(&mut st) else {
                        d.book.pause(Duration::from_secs(2)).await;
                        continue;
                    };
                    let Some(cur) = d.start_tcp(&m, stream).await else {
                        d.book.pause(Duration::from_secs(2)).await;
                        continue;
                    };
                    ctl.set_mode("tcp");
                    st.tcp_since.get_or_insert_with(Instant::now);
                    sh.note(format!("tcp connected to {label} (носитель TCP, возврат на QUIC через {} с от перехода)", st.back_off));
                    d.session(&mut st, cur, m).await;
                }
                tcpc::Dial::Blackhole => {
                    d.tcp_blackholed(&mut st);
                    ctl.prefer_tcp.store(false, Relaxed);
                    st.tcp_since = None;
                }
                tcpc::Dial::Unreachable => {
                    // хост не отвечает: это не признак блокировки, ничего не запоминаем (в том числе подозрение на тишину по QUIC: сети нет)
                    let _ = tcp_failed_with_silence(ctl, false, Instant::now());
                    st.quic_suspect = false;
                    tcp_fail += 1;
                    if tcp_fail >= 3 {
                        // TCP тоже не идёт: не застреваем, пробуем QUIC
                        ctl.prefer_tcp.store(false, Relaxed);
                        tcp_fail = 0;
                    }
                    d.book.pause(Duration::from_secs(2)).await;
                }
            }
        }
    }
    if let Some(m) = st.mux.take() {
        m.close();
    }
}

/// Носитель, который сейчас несёт данные пира.
enum Cur {
    Quic(Connection),
    Tcp { stop: tokio::sync::watch::Sender<bool>, done: tokio::task::JoinHandle<()> },
}

impl Cur {
    /// Ждать, пока носитель не закончится сам.
    async fn ended(&mut self) {
        match self {
            Cur::Quic(c) => {
                let _ = c.closed().await;
            }
            Cur::Tcp { done, .. } => {
                let _ = done.await;
            }
        }
    }

    fn close(&self) {
        match self {
            Cur::Quic(c) => c.close(0u32.into(), b"switch carrier"),
            Cur::Tcp { stop, .. } => {
                let _ = stop.send(true);
            }
        }
    }
}

/// Что дозвон пира помнит между сессиями носителей.
#[derive(Default)]
struct DialState {
    mux: Option<Arc<mux::Mux>>,
    /// пауза до попытки вернуться на QUIC; растёт вдвое до 30 минут
    back_off: u64,
    first_back: u64,
    /// с какого момента носитель TCP (замечаем и по флагу, выставленному монитором извне)
    tcp_since: Option<Instant>,
    /// QUIC дважды не соединился: если TCP при этом работает (или тоже режется при живом хосте), QUIC запоминается как неработающий
    quic_suspect: bool,
    /// подряд TCP-сессий, закрытых за секунды после подключения
    short_tcp: u32,
}

struct Dialer {
    ep: Endpoint,
    node: Arc<Node>,
    sh: Arc<Shared>,
    label: String,
    id: EndpointId,
    book: Arc<Addrs>,
    alive: Arc<AtomicBool>,
    ctl: Arc<CarrierCtl>,
    peer: String,
}

impl Dialer {
    /// Интерфейс этого пира: живой или новый. Новый интерфейс - новая «поколение»: Link на прежнем (снятом) интерфейсе больше не годится.
    fn mux_for(&self, st: &mut DialState) -> Option<Arc<mux::Mux>> {
        if let Some(m) = st.mux.as_ref().filter(|m| !m.is_closed()) {
            return Some(m.clone());
        }
        match mux::Mux::new(&self.node, &self.sh, mux::next_name("iroh-dg-out", &self.label), false) {
            Ok(m) => {
                self.ctl.generation.fetch_add(1, Relaxed);
                st.mux = Some(m.clone());
                Some(m)
            }
            Err(e) => {
                self.sh.note(format!("{}: интерфейс не создан: {e:#}", self.label));
                None
            }
        }
    }

    /// TCP подтвердил доставку (`Dial::Up`): запись о работающем TCP, а QUIC, не прошедший перед этим или молчавший перед этим, запоминается неработающим.
    fn tcp_confirmed(&self, st: &mut DialState) {
        let (sh, label, peer) = (&self.sh, &self.label, &self.peer);
        sh.health.ok(peer, health::Kind::Tcp);
        if std::mem::take(&mut st.quic_suspect) {
            let d = sh.health.fail(peer, health::Kind::Quic);
            sh.note(format!("{label}: QUIC не проходит, а TCP работает: запоминаю QUIC как неработающий на {} мин", d.as_secs() / 60));
        }
        // Link молчал на QUIC, и сразу после этого TCP подтвердил доставку: сеть жива, молчит UDP
        if let Some(d) = confirm_quic_silence(&sh.health, &self.ctl, peer, Instant::now()) {
            sh.note(format!("{label}: Link молчал на QUIC, а TCP работает: запоминаю QUIC как неработающий на {} мин", d.as_secs() / 60));
        }
    }

    /// `Dial::Blackhole`: хост отвечает, но данные не доходят: запоминаем; QUIC, не прошедший перед этим, запоминается вместе с ним (пара заблокирована).
    /// Исключение: Link только что молчал на QUIC и TCP не прошёл в том же окне - общий сбой пути (handover), не блокировка носителей;
    /// повтор такого совпадения за 10 мин считается настоящей блокировкой обоих.
    fn tcp_blackholed(&self, st: &mut DialState) {
        match record_tcp_blackhole(&self.sh.health, &self.ctl, &self.peer, &mut st.quic_suspect, Instant::now()) {
            Some(d) => self.sh.note(format!("{}: TCP соединяется, но данные не доходят (DPI или чёрная дыра), запоминаю на {} мин", self.label, d.as_secs() / 60)),
            None => self.sh.note(format!("{}: QUIC и TCP молчат в одном окне - общий сбой пути, носители не запоминаю", self.label)),
        }
    }

    /// Подключить TCP-поток носителем и дождаться, пока интерфейс его примет (только после этого прежний носитель можно закрывать).
    async fn start_tcp(&self, m: &Arc<mux::Mux>, stream: tokio::net::TcpStream) -> Option<Cur> {
        let _ = stream.set_nodelay(true);
        let (rd, wr) = stream.into_split();
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let done = tokio::spawn(tcpc::run(m.clone(), rd, wr, true, true, Some(ready_tx), stop_rx));
        match tokio::time::timeout(Duration::from_secs(2), ready_rx).await {
            Ok(Ok(true)) => Some(Cur::Tcp { stop, done }),
            _ => {
                let _ = stop.send(true);
                None
            }
        }
    }

    /// Сессия одного или нескольких носителей: сторож RTT и здоровья, переходы QUIC <-> TCP без разрыва интерфейса, учёт паузы возврата.
    /// Возвращается, когда носитель закончился (интерфейс остаётся ещё на `mux::GRACE`: следующий носитель подхватит Link).
    async fn session(&self, st: &mut DialState, mut cur: Cur, m: Arc<mux::Mux>) {
        let (sh, ctl, label, peer) = (&self.sh, &self.ctl, self.label.as_str(), self.peer.as_str());
        // с какого момента держится текущий носитель; «доказанный» QUIC стирает запись о неработающем (settle_quic_health)
        let mut since = Instant::now();
        let mut proven = false;
        loop {
            tokio::select! {
                _ = cur.ended() => break,
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
            if !self.alive.load(Relaxed) || m.is_closed() {
                cur.close();
                break;
            }
            match &cur {
                Cur::Quic(conn) => {
                    if let Some(p) = conn.paths().iter().find(|p| p.is_selected()) {
                        ctl.rtt_us.store(p.rtt().as_micros().min(u32::MAX as u128) as u32, Relaxed);
                    }
                    // запись «QUIC не работает» стирает не рукопожатие, а сессия, прожившая QUIC_PROVEN
                    if !proven {
                        proven = settle_quic_health(&sh.health, peer, since.elapsed());
                    }
                    if !ctl.prefer_tcp.load(Relaxed) {
                        continue;
                    }
                    if sh.health.is_bad(peer, health::Kind::Tcp) {
                        // TCP уже признан неработающим при живом хосте: остаёмся на QUIC
                        ctl.prefer_tcp.store(false, Relaxed);
                        continue;
                    }
                    // потери UDP или тишина Link: подключаем TCP рядом, переключаем данные и только потом закрываем QUIC
                    let resolved = resolve_addrs(&self.book.get()).await;
                    match tcpc::connect(&resolved, self.ep.secret_key(), &self.id).await {
                        tcpc::Dial::Up(stream) => {
                            self.tcp_confirmed(st);
                            match self.start_tcp(&m, stream).await {
                                Some(next) => {
                                    self.finish_quic(st, since);
                                    let old = std::mem::replace(&mut cur, next);
                                    ctl.set_mode("tcp");
                                    old.close();
                                    since = Instant::now();
                                    proven = false;
                                    st.tcp_since = Some(since);
                                    sh.note(format!("{label}: носитель сменён на TCP без разрыва Link (возврат на QUIC через {} с)", st.back_off));
                                }
                                None => ctl.prefer_tcp.store(false, Relaxed),
                            }
                        }
                        tcpc::Dial::Blackhole => {
                            self.tcp_blackholed(st);
                            ctl.prefer_tcp.store(false, Relaxed);
                        }
                        tcpc::Dial::Unreachable => {
                            let _ = tcp_failed_with_silence(ctl, false, Instant::now());
                            ctl.prefer_tcp.store(false, Relaxed);
                        }
                    }
                }
                Cur::Tcp { .. } => {
                    let quic_bad = sh.health.is_bad(peer, health::Kind::Quic);
                    let from = *st.tcp_since.get_or_insert(since);
                    // срок проверяется вместе с памятью о QUIC: помеченный неработающим QUIC не повод пробовать
                    if !tcp_release_due(from.elapsed(), st.back_off, quic_bad) {
                        continue;
                    }
                    match self.try_return(&m).await {
                        Ok(conn) => {
                            let old = std::mem::replace(&mut cur, Cur::Quic(conn));
                            ctl.set_mode("quic");
                            ctl.prefer_tcp.store(false, Relaxed);
                            old.close();
                            st.tcp_since = None;
                            since = Instant::now();
                            proven = false;
                            sh.note(format!("{label}: возврат на QUIC без разрыва Link"));
                        }
                        Err(grow) => {
                            // отказ из-за занятости узла (общие лимиты разрешений) - не вина пути: пауза не растёт, иначе чужой поток запросов
                            // удерживает клиентов на TCP до 30 минут
                            if grow {
                                st.back_off = grown_back_off(st.back_off);
                            }
                            st.tcp_since = Some(Instant::now());
                        }
                    }
                }
            }
        }
        match &cur {
            Cur::Quic(_) => {
                ctl.set_mode("none");
                ctl.rtt_us.store(0, Relaxed);
                sh.note(format!("quic to {label} ended"));
                self.finish_quic(st, since);
            }
            Cur::Tcp { .. } => {
                ctl.set_mode("none");
                st.tcp_since = None;
                // Сессия умерла сразу после рукопожатия (данные пира не доходят: чёрная дыра на пути): повтор каждые 0,5 с лишь тормозит восстановление,
                // каждая смена носителя - потери. Паузу растим 1,5 -> 3 -> ... -> 60 с, живая сессия её сбрасывает.
                if since.elapsed() < Duration::from_secs(15) && self.alive.load(Relaxed) {
                    st.short_tcp = (st.short_tcp + 1).min(6);
                    let pause = Duration::from_millis((1500u64 << (st.short_tcp - 1)).min(60_000));
                    if st.short_tcp == 3 {
                        sh.note(format!("{label}: TCP-сессии рвутся сразу после подключения, пауза между попытками растёт до 60 с"));
                    }
                    self.book.pause(pause).await;
                } else {
                    st.short_tcp = 0;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    /// QUIC-сессия длиной `since.elapsed()` закончилась: стабильная сессия сбрасывает паузу возврата с TCP к первой (потолок 30 мин сохранён).
    fn finish_quic(&self, st: &mut DialState, since: Instant) {
        let reset = back_off_after_quic(st.back_off, st.first_back, since.elapsed());
        if reset != st.back_off {
            self.sh.note(format!("{}: QUIC держался {} мин, пауза возврата с TCP {} -> {reset} с", self.label, since.elapsed().as_secs() / 60, st.back_off));
            st.back_off = reset;
        }
    }

    /// Возврат TCP -> QUIC: кандидатное соединение, не привязанное к интерфейсу, получает от узла разрешение, проходит зонд (эхо датаграмм в обе
    /// стороны) и только после этого принимается интерфейсом носителем данных. Неудача ничего не ломает: TCP и Link не тронуты.
    async fn try_return(&self, m: &Arc<mux::Mux>) -> Result<Connection, bool> {
        let (sh, label) = (&self.sh, self.label.as_str());
        let resolved = resolve_addrs(&self.book.get()).await;
        if resolved.is_empty() {
            return Err(true);
        }
        let mut addr = EndpointAddr::new(self.id);
        for a in &resolved {
            addr = addr.with_ip_addr(*a);
        }
        let conn = match tokio::time::timeout(Duration::from_secs(6), self.ep.connect(addr, ALPN)).await {
            Ok(Ok(c)) => c,
            _ => {
                let d = sh.health.fail(&self.peer, health::Kind::Quic);
                sh.note(format!("{label}: возврат на QUIC: соединение не открылось, остаюсь на TCP, QUIC запомнен на {} мин", d.as_secs() / 60));
                return Err(true);
            }
        };
        let nonce = rand_core::OsRng.next_u64();
        match qprobe::request_grant(&conn, nonce).await {
            Ok(()) => {}
            Err(why) => {
                // отказ узла или потеря запроса/ответа не доказывают, что QUIC плох: QUIC не виним, пауза растёт
                sh.note(format!("{label}: возврат на QUIC отложен: {}", match why {
                    Some(1) => "узел недавно выдавал разрешение".to_string(),
                    Some(2) => "узел занят".to_string(),
                    Some(c) => format!("отказ узла ({c})"),
                    None => "нет ответа на запрос разрешения".to_string(),
                }));
                conn.close(0u32.into(), b"probe deferred");
                return Err(why != Some(2));
            }
        }
        let st = qprobe::run(&conn, nonce).await;
        if !qprobe::probe_passed(&st) {
            let d = sh.health.fail(&self.peer, health::Kind::Quic);
            sh.note(format!("{label}: зонд QUIC не прошёл ({}/{} эхо за {} мс), остаюсь на TCP, QUIC запомнен на {} мин", st.echoed, st.sent, st.took_ms, d.as_secs() / 60));
            conn.close(0u32.into(), b"probe failed");
            return Err(true);
        }
        sh.note(format!("{label}: зонд QUIC прошёл ({}/{} эхо за {} мс, вверх {} Б, вниз {} Б)", st.echoed, st.sent, st.took_ms, st.bytes_up, st.bytes_down));
        if m.add_quic(conn.clone(), true, *conn.remote_id().as_bytes()).is_none() {
            conn.close(0u32.into(), b"no slot");
            return Err(true);
        }
        Ok(conn)
    }
}

impl ClientCtx {
    fn sync_to(&self, link: LinkId, recs: Vec<trust::Record>, pols: Vec<trust::Policy>) -> bool {
        let Some(c) = &self.c13 else { return false };
        let pk = c.peers.lock().unwrap().get(&link).copied()
            .or_else(|| c.enrollees.lock().unwrap().get(&link).copied());
        let Some(pk) = pk else { return false };
        // inbox13 уже держит Trust, но передаёт только одну проверенную запись.
        let pols = if pols.is_empty() { pols } else {
            let tr = c.trust.lock().unwrap();
            pols.into_iter().filter(|p| lxmf_sync::policy_visible(&tr, p, &pk)).collect()
        };
        lxmf_sync::queue(&self.state, c.trust.clone(), pk, recs, pols)
    }

}

/// Байты подписанных Policy с запуска (без обёртки); sync_* отдельно считает LXMF-конверты, включая ACK/повторы, но не RNS/носитель.
static POL_TX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static POL_RX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static POL_TX_N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static POL_RX_N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn pol_counters() -> serde_json::Value {
    let mut v = serde_json::json!({"tx_b": POL_TX.load(Relaxed), "tx_n": POL_TX_N.load(Relaxed), "rx_b": POL_RX.load(Relaxed), "rx_n": POL_RX_N.load(Relaxed),
        "sync_tx_lxmf_b":lxmf_sync::TX_BYTES.load(Relaxed), "sync_rx_lxmf_b":lxmf_sync::RX_BYTES.load(Relaxed),
        "sync_tx_n":lxmf_sync::TX_MESSAGES.load(Relaxed), "sync_rx_n":lxmf_sync::RX_MESSAGES.load(Relaxed)});
    // PN грузится в фоне (W110): pn_ready/pn_load_ms показывают, когда встроенный PN начал обслуживать пиров
    if let (Some(o), serde_json::Value::Object(pn)) = (v.as_object_mut(), lxmf_sync::pn_status()) { o.extend(pn); }
    v
}

async fn send_ctl(node: &Arc<Node>, link: LinkId, ty: u8, body: &[u8]) {
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

/// Keepalive RNS клиентских Link в секундах (ADR 0019 §11): ставят оба конца, клиент при подключении, сервер при допуске.
/// Одинаковое значение обязательно: ответчик с коротким окном stale закрыл бы Link клиента, молчащего между keepalive.
const CLIENT_KEEPALIVE_S: u64 = 25;
/// Запас сверх keepalive на задержку ответа, прежде чем пропуск считается потерей контакта.
const KEEPALIVE_SLACK_MS: u64 = 3_000;
/// Сколько после последнего IP-пакета выход считается занятым: пока занят, пингуем RGP раз в секунду.
const PING_ACTIVE_HOLD_MS: u64 = 10_000;

/// Решение клиента о живости выхода (ADR 0019 §11): без трафика телефон не будится пингами и полагается на keepalive RNS
/// (каждые `CLIENT_KEEPALIVE_S`). При трафике, а также после пропущенного keepalive, идут RGP-пинги раз в секунду;
/// `fail_ms` без любого ответа - выход мёртв. Для пропуска keepalive это три проверки по секунде.
/// Чистое состояние: время и счётчики приходят аргументами.
#[derive(Default)]
struct Pacer {
    last_pkts: u64,
    active_until: u64,
    active_since: Option<u64>,
    probing_since: Option<u64>,
    last_ping: u64,
    last_acked: u64,
}

struct PaceStep {
    /// отправить RGP-пинг сейчас
    ping: bool,
    /// молчание выхода в мс; 0, пока ответа никто не ждёт
    silent_ms: u64,
    /// ответ keepalive RNS пришёл с прошлого шага: это контакт
    keepalive_ack: bool,
    /// окно, в пределах которого последний контакт ещё считается свежим (для индикации)
    contact_window_ms: u64,
}

impl Pacer {
    /// `pkts` - счётчик IP-пакетов TUN в обе стороны, `last_contact` - время (мс) последнего пакета от выхода,
    /// `acked` - число ответов keepalive RNS по Link.
    fn step(&mut self, now: u64, pkts: u64, last_contact: u64, acked: u64, keepalive_ms: u64, fail_ms: u64) -> PaceStep {
        let keepalive_ack = acked > self.last_acked;
        self.last_acked = acked;
        let contact = if keepalive_ack { now } else { last_contact };
        if pkts != self.last_pkts {
            self.last_pkts = pkts;
            self.active_until = now + PING_ACTIVE_HOLD_MS;
        }
        if self.probing_since.is_some_and(|since| contact >= since) {
            self.probing_since = None; // ответ пришёл
        }
        let lapse = keepalive_ms + KEEPALIVE_SLACK_MS;
        if self.probing_since.is_none() && now.saturating_sub(contact) > lapse {
            self.probing_since = Some(now); // keepalive пропущен: три быстрые проверки
        }
        let active = now < self.active_until || self.probing_since.is_some();
        if !active {
            self.active_since = None;
            return PaceStep { ping: false, silent_ms: 0, keepalive_ack, contact_window_ms: lapse };
        }
        let since = *self.active_since.get_or_insert(now);
        let ping = now.saturating_sub(self.last_ping) >= 1_000;
        if ping {
            self.last_ping = now;
        }
        PaceStep { ping, silent_ms: now.saturating_sub(contact.max(since)), keepalive_ack, contact_window_ms: fail_ms }
    }
}

#[cfg(test)]
mod keepalive_pacer_tests {
    use super::*;

    #[test]
    fn idle_uses_rns_and_missing_keepalive_gets_three_fast_probes() {
        let mut p = Pacer::default();
        for now in (1_000..=28_000).step_by(250) {
            let s = p.step(now, 0, 1_000, 0, 25_000, 3_000);
            assert!(!s.ping && s.silent_ms == 0, "no RGP wakeup while idle");
        }
        for now in [29_250, 30_250, 31_250] {
            let s = p.step(now, 0, 1_000, 0, 25_000, 3_000);
            assert!(s.ping && s.silent_ms < 3_000);
        }
        assert_eq!(p.step(32_250, 0, 1_000, 0, 25_000, 3_000).silent_ms, 3_000);
    }

    #[test]
    fn rns_ack_and_payload_recover_contact_but_ack_is_not_a_grant() {
        let mut p = Pacer::default();
        assert!(p.step(29_250, 0, 1_000, 0, 25_000, 3_000).ping);
        let s = p.step(29_500, 0, 1_000, 1, 25_000, 3_000);
        assert!(s.keepalive_ack && !s.ping && s.silent_ms == 0);
        assert!(!p.step(30_000, 0, 29_500, 1, 25_000, 3_000).ping);
        assert!(p.step(30_500, 1, 29_500, 1, 25_000, 3_000).ping, "active traffic");
        assert_eq!(p.step(31_000, 1, 30_900, 1, 25_000, 3_000).silent_ms, 100);
        assert!(!p.step(41_000, 1, 40_500, 1, 25_000, 3_000).ping, "return to idle");
    }
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

// ------------------------------------------------------------------------------------------------ сервер

enum Role {
    /// только что пришёл, ещё не доказал себя
    Unknown,
    /// взаимно проверенный сервер
    Server { dest: [u8; 16] },
    /// клиент с допущенными правами USE
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
    /// Биты `AdmitDiag`, уже записанные в журнал для этого Link: одна строка на Link и причину.
    diag: u8,
}

/// Причины, по которым нода раньше молча не допускала клиента (ни записи в журнал, ни T_AUTH_FAIL).
/// Это только диагностика: решение о допуске принимают права, а не эти значения.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AdmitDiag {
    /// Link только для зачисления (шифр CBC или не определён - fail-closed, либо прямое зачисление по приглашению).
    EnrollOnly,
    /// Клиент прислал T_USE, общей цепочки EXIT/USE пока нет: цепочка может дойти позже, поэтому только запись в журнал.
    NoChainWait,
    /// То же после `NO_CHAIN_FAIL_AFTER`: цепочки по-прежнему нет, клиент получает T_AUTH_FAIL.
    NoChain,
    /// Допуск не состоялся, хотя Link ещё жив и не допущен (права или Link изменились между оценкой и публикацией).
    NotAuthorized,
}

impl AdmitDiag {
    const fn bit(self) -> u8 {
        match self {
            AdmitDiag::EnrollOnly => 1,
            AdmitDiag::NoChainWait => 2,
            AdmitDiag::NoChain => 4,
            AdmitDiag::NotAuthorized => 8,
        }
    }

    /// Причина для журнала: без адресов, ключей и полных хешей.
    const fn note(self) -> &'static str {
        match self {
            AdmitDiag::EnrollOnly => "клиент не допущен: Link только для зачисления (шифр CBC/не определён либо приглашение)",
            AdmitDiag::NoChainWait => "клиент пока не допущен: общей цепочки EXIT/USE нет, жду записи",
            AdmitDiag::NoChain => "клиент не допущен: общей цепочки EXIT/USE нет",
            AdmitDiag::NotAuthorized => "клиент не допущен: права или Link изменились до допуска",
        }
    }

    /// Фиксированный ответ клиенту; `None` - клиенту не отвечаем.
    const fn fail(self) -> Option<&'static [u8]> {
        match self {
            AdmitDiag::EnrollOnly => Some(b"link not eligible"),
            AdmitDiag::NoChainWait => None,
            AdmitDiag::NoChain => Some(b"no common exit chain"),
            AdmitDiag::NotAuthorized => Some(b"not authorized"),
        }
    }
}

/// Сколько ждать цепочку, прежде чем сообщить клиенту об отказе. Меньше 6 с ожидания клиента (`connect_exit`);
/// цепочка клиента уходит сразу после identify, поэтому окно допуска почти не сокращается.
const NO_CHAIN_FAIL_AFTER: Duration = Duration::from_secs(5);
/// Общий предел строк диагностики допуска: Link с чужими identity создаёт кто угодно, журнал не должен расти от этого.
const DIAG_MAX_PER_WINDOW: u32 = 16;
const DIAG_WINDOW_MS: u64 = 10_000;

/// Окно с ограничением числа строк; подавленные строки считаются и сообщаются одной строкой в начале следующего окна.
struct DiagBudget {
    window_start_ms: u64,
    used: u32,
    dropped: u32,
}

impl DiagBudget {
    const fn new() -> Self {
        DiagBudget { window_start_ms: 0, used: 0, dropped: 0 }
    }

    /// `(писать ли строку, сколько строк подавлено в прошлом окне - сообщить)`.
    fn allow(&mut self, now_ms: u64) -> (bool, u32) {
        let mut report = 0;
        if now_ms.saturating_sub(self.window_start_ms) >= DIAG_WINDOW_MS {
            report = std::mem::take(&mut self.dropped);
            self.window_start_ms = now_ms;
            self.used = 0;
        }
        if self.used < DIAG_MAX_PER_WINDOW {
            self.used += 1;
            (true, report)
        } else {
            self.dropped += 1;
            (false, report)
        }
    }
}

static DIAG_BUDGET: Mutex<DiagBudget> = Mutex::new(DiagBudget::new());

/// Помечает причину для Link; `true` - первый раз (запись и ответ положены). Нет Link - `false`.
fn diag_first(links: &Mutex<HashMap<LinkId, LinkInfo>>, link: LinkId, d: AdmitDiag) -> bool {
    let mut l = links.lock().unwrap();
    let Some(i) = l.get_mut(&link) else { return false };
    let first = i.diag & d.bit() == 0;
    i.diag |= d.bit();
    first
}

/// Клиент (прислал T_USE) с этим ключом по-прежнему ждёт допуска на этом Link.
fn client_awaiting_admission(links: &Mutex<HashMap<LinkId, LinkInfo>>, link: LinkId, pk: &[u8; 64]) -> bool {
    links.lock().unwrap().get(&link).is_some_and(|i| i.peer_pk.as_ref() == Some(pk) && i.want_use && matches!(i.role, Role::Unknown))
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
    tag: String,
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
    neigh: Mutex<HashMap<[u8; 16], Neighbor>>,
    tun: Option<Arc<TunState>>,
    started: Instant,
    /// когда (мс unix) выдать внеочередной анонс; 0 - не нужно. Внеочередной анонс не чаще раза в минуту.
    ours_online: std::sync::atomic::AtomicUsize,
    listen_port: u16,
    /// идентификаторы интерфейсов публичной сети RNS (их выдаёт spawn_interface; по имени узнавать нельзя: интерфейс называется `tcp_client_N`)
    public_ids: Mutex<HashSet<usize>>,
    /// модель 0013 (права и якоря доверия)
    t13: Option<T13>,
}

/// Состояние модели 0013 на узле.
struct T13 {
    /// записи о правах и якоря; порядок блокировок: invite, затем trust
    trust: Arc<Mutex<trust::Trust>>,
    /// приглашение, по которому нода ещё не зачислена; после зачисления None
    invite: Mutex<Option<trust::Invite>>,
    /// H1: записи от пиров есть в памяти, но не на диске; пишет `flush_trust` не чаще раза в 2 с
    trust_dirty: AtomicBool,
    /// когда в последний раз виден анонс админа приглашения (0014 R6а): по нему решаем, просимся ли через посредника
    /// попытки зачисления через посредника (dest посредника -> когда): каждому не чаще раза в 60 с
    /// T_DIR: когда последний раз слали каталог на Link (не чаще раза в 60 с)
    dir_sent: Mutex<HashMap<LinkId, Instant>>,
    /// Каталог для обычных клиентов и LXMF-запросов: один снимок в минуту на identity, не на новый Link.
    dir_requested: Mutex<HashMap<trust::Pk, Instant>>,
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


    /// Текущие объявляемые адреса (копия).
    fn adv(&self) -> Vec<String> {
        self.advertise.lock().unwrap().clone()
    }

    fn announce_data(&self) -> Vec<u8> {
        // ADR 0016: как у обычного узла RNS - только теги корней ("r": по пересечению с моими якорями сосед узнаёт знакомую сеть).
        // Адресов, имени и endpoint id нет: они приходят приватным каталогом по LXMF и из приглашения.
        Vec::new()
    }

    fn self_json(&self) -> serde_json::Value {
        serde_json::json!({"n": self.name, "d": hex(&self.my_dest), "k": hex(&self.my_key), "e": self.ep_id, "a": self.adv(), "t": self.tag, "cn": net_str()})
    }

    /// Диагностика для файла neighbors.json: мы сами и соседи (живые и просто виденные).
    fn table(&self) -> serde_json::Value {
        let now = Instant::now();
        let mut ex = vec![serde_json::json!({"n": self.name, "d": hex(&self.my_dest), "k": hex(&self.my_key), "e": self.ep_id, "a": self.adv(),
            "h": 0, "r": 0.0, "s": "up", "self": true})];
        let n = self.neigh.lock().unwrap();
        for nb in n.values() {
            let up = nb.link.is_some() && now.duration_since(nb.last_heard) < self.dead;
            let hops = self.node.hops_to(&DestinationHash::new(nb.dest));
            ex.push(serde_json::json!({"n": nb.name, "d": hex(&nb.dest), "k": hex(&nb.key), "e": nb.ep, "a": nb.addrs.get(), "h": hops, "r": nb.rtt_ms,
                "c": *nb.ctl.mode.lock().unwrap(), "sw": nb.ctl.switches.load(Relaxed), "s": if up { "up" } else { "seen" }, "age_s": now.duration_since(nb.last_announce).as_secs(), "heard_s": now.duration_since(nb.last_heard).as_secs()}));
        }
        serde_json::json!({"exits": ex, "ts": now_ms() as u64})
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

    fn close_link(self: &Arc<Self>, link: LinkId, why: &str) {
        self.sh.note(format!("close link {} ({why})", &hex(link.as_bytes())[..8]));
        self.drop_link_state(&link);
        let node = self.node.clone();
        tokio::spawn(async move {
            let _ = node.engine().close_link(&link).await;
        });
    }

    /// Одна строка журнала на Link и причину плюс T_AUTH_FAIL с фиксированным текстом (если он положен причине).
    /// Только сообщает об уже принятом решении: Link не закрывается, права и допуск не меняются.
    fn admit_diag(self: &Arc<Self>, link: LinkId, pk: &[u8; 64], d: AdmitDiag) {
        if !diag_first(&self.links, link, d) {
            return;
        }
        self.diag_note(link, pk, d);
        if let Some(reason) = d.fail() {
            spawn_ctl(&self.node, link, T_AUTH_FAIL, reason.to_vec());
        }
    }

    /// Строка журнала в рамках общего бюджета `DIAG_BUDGET`.
    fn diag_note(&self, link: LinkId, pk: &[u8; 64], d: AdmitDiag) {
        let (write, dropped) = DIAG_BUDGET.lock().unwrap().allow(now_ms() as u64);
        if dropped > 0 {
            self.sh.note(format!("диагностика допуска: подавлено строк {dropped}"));
        }
        if write {
            let who = trust::hash_of(pk).map(|h| hex(&h)[..8].to_string()).unwrap_or_else(|| "?".into());
            self.sh.note(format!("link {} (id {who}): {}", &hex(link.as_bytes())[..8], d.note()));
        }
    }

    /// Клиент без общей цепочки: сразу запись в журнал, отказ клиенту - только если спустя `NO_CHAIN_FAIL_AFTER` Link всё ещё
    /// ждёт допуска и права по-прежнему нет (запоздавшая цепочка допускает клиента обычным путём через `evaluate`).
    fn no_chain_watch(self: &Arc<Self>, link: LinkId, pk: [u8; 64]) {
        if !diag_first(&self.links, link, AdmitDiag::NoChainWait) {
            return;
        }
        // Бит выставлен: повторный вызов `evaluate` не создаст второй таймер.
        self.diag_note(link, &pk, AdmitDiag::NoChainWait);
        let c = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(NO_CHAIN_FAIL_AFTER).await;
            let Some(t) = &c.t13 else { return };
            let now = now_ms() as u64;
            let rights = {
                let tr = t.trust.lock().unwrap();
                tr.common_with(&pk, trust::EXIT, trust::USE, true, false, now) || tr.common(&pk, trust::EXIT, trust::USE)
            };
            if !rights && client_awaiting_admission(&c.links, link, &pk) {
                c.admit_diag(link, &pk, AdmitDiag::NoChain);
            }
        });
    }

    fn drop_link_state(&self, link: &LinkId) {
        let removed = remove_link_admission(&self.links, link, || {
            if let Some(t) = &self.tun { t.disallow(link); }
        });
        if removed.as_ref().is_some_and(|l| matches!(l.role, Role::Client { .. })) {
            crate::host_acl::notify_nft();
        }
        if let Some(t) = &self.t13 {
            t.dir_sent.lock().unwrap().remove(link);
        }
        if let Some(l) = removed {
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

fn id_of_pub(pk: &[u8; 64]) -> Option<[u8; 16]> {
    Identity::from_public_key_bytes(pk).ok().map(|i| *i.hash())
}

/// Запуск узла (модель допуска 0013: права и якоря доверия).
pub async fn run_node(a: NodeArgs) -> Result<()> {
    node_main(a).await
}

async fn node_main(mut a: NodeArgs) -> Result<()> {
    let mut public_inline: Vec<String> = Vec::new();
    if let Some(cf) = a.config.clone() {
        let c: NodeConf = serde_json::from_slice(&std::fs::read(&cf).with_context(|| format!("config {}", cf.display()))?).context("разбор конфига узла")?;
        a.name = c.name;
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
        a.iroh_relay = c.iroh_relay;
        a.relay_quic_port = c.relay_quic_port.unwrap_or(a.relay_quic_port);
        if !c.relay_urls.is_empty() { a.relay_url = c.relay_urls.join(","); }
    }
    let _ = CLIENT_NET.set(parse_net(&a.client_net)?);
    let region = detect_region(&a.state).await;
    let _ = REGION.set(region.clone());
    if a.name.is_empty() {
        // то же имя, что телефон задаёт в настройках своей ноды: state/node-name.txt (--name и config имеют приоритет)
        if let Ok(t) = std::fs::read_to_string(a.state.join("node-name.txt")) {
            a.name = t.chars().filter(|c| name_char_ok(*c)).take(32).collect::<String>().trim().to_string();
        }
    }
    if a.name.is_empty() {
        // имя вида knothop-<РЕГИОН>-<что угодно>: регион по внешнему IP, хвост - имя хоста (или KNOTHOP_NAME_SUFFIX)
        let suffix = std::env::var("KNOTHOP_NAME_SUFFIX").ok().filter(|v| !v.is_empty()).unwrap_or_else(hostname);
        a.name = format!("knothop-{region}-{suffix}").chars().take(48).collect();
    }
    if a.state == Path::new("-") {
        bail!("нужен --state (флагом или в --config)");
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
    let identity = load_or_create_identity(&a.state)?;
    let key = iroh_key_from_identity(&identity)?;
    // сертификат relay делается из ключа ноды; копию держим только если relay включён
    let relay_seed = a.iroh_relay.then(|| key.to_bytes());
    let exit_args = ["--tun-mtu", "1327", "--tun-ip", "10.99.0.1/24", "--tun-txqlen", "10240", "--tun-qdisc", "fq_codel", "--tun-name", a.tun_name.as_str()];
    let b = start_base("n", &a.state, true, Some(a.port), key, Some(identity.clone()), a.quic_cc_mbit, if a.no_exit { &[] } else { &exit_args[..] }, None, &parse_relay_urls(&a.relay_url)).await?;
    let (node, sh, ep, cli, events, admin_lxmf) = (b.node.clone(), b.sh.clone(), b.ep.clone(), b.cli.clone(), b.events, b.admin_lxmf);

    // тег назначения един для всей сети: нода находит соседей по тегам корней в анонсе
    let tag = T13_TAG.to_string();
    let my_pk = identity.public_key_bytes();
    let my_key = identity.ed25519_verifying().to_bytes();
    let my_id = *identity.hash();
    let node_identity = identity.clone();
    let dest = new_dest(identity, Direction::In, &tag).map_err(|e| anyhow::anyhow!("destination: {e:?}"))?;
    let my_dest = *dest.hash().as_bytes();
    node.register_destination(dest);

    // модель 0013: права, якоря доверия и (до зачисления) приглашение
    let t13 = {
        let tr = trust::Trust::load(node_identity.clone(), &a.state).context("trust.json")?;
        let mut inv = None;
        if !invite_raw.trim().is_empty() {
            match trust::Invite::parse(&invite_raw) {
                Ok(candidate) => {
                    let used = tr.enrollment_proofs(&my_pk).iter().any(|p| p.grant.id == crate::enroll::invite_id(&candidate.pin));
                    if !used { inv = Some(candidate); }
                }
                // старый invite_file из node.json (v3): нода уже зачислена, якорь ставится `knothopd trust-anchor`
                Err(e) if tr.anchors().len() > 1 || tr.record_count() > 0 => { eprintln!("Сохранённое зачисление используется без старого приглашения: {e:#}"); }
                Err(e) => return Err(e),
            }
        }
        Some(T13 { trust: Arc::new(Mutex::new(tr)), invite: Mutex::new(inv), 
            trust_dirty: AtomicBool::new(false),  dir_sent: Mutex::new(HashMap::new()), dir_requested: Mutex::new(HashMap::new()) })
    };
    if let Some(t) = &t13 { let _ = RELAY_TRUST.set(t.trust.clone()); }

    // Clear stale host-access kernel leases before any ordinary admission.
    // Без TUN (--no-exit) клиентов нет; --no-host-nft - лаборатория без таблицы: наборы пусты, TCP к хосту закрыт.
    let host_nft = if a.no_exit || a.no_host_nft { None } else {
        Some(crate::host_acl::NftHostAccess::new(client_net()).context("HOST_ACCESS nft startup")?)
    };
    let tun = if a.no_exit {
        None
    } else {
        let t = TunState::open(&cli, true)?;
        let acl_path = a.state.join("host-acl.json");
        if let Err(error) = t.configure_host_acl(&acl_path) {
            let status = serde_json::json!({"state":"error","status":"host ACL configuration failed","host_acl":{"ready":false,"error":format!("{error:#}")},"ts_ms":now_ms() as u64});
            write_atomic(&a.state.join("status.json"), status.to_string().as_bytes());
            bail!("host ACL configuration failed; refusing to admit clients: {error:#}");
        }
        if !t.host_acl_ready() { bail!("host ACL did not become ready; refusing to admit clients"); }
        t.enforce.store(true, Relaxed);
        // обратный маршрут для адресов клиентов; NAT выхода настраивает окружение (контейнер/хост)
        let _ = std::process::Command::new("ip").args(["route", "replace", &net_str(), "dev", &cli.tun_name]).status();
        let _ = sh.tun.set(t.clone());
        tokio::spawn(tun_reader(t.clone(), node.clone(), sh.clone()));
        Some(t)
    };

    // Адрес узла: флаг/конфиг, затем переменная KNOTHOP_ADVERTISE (единственное, что может отличаться на узле при одинаковом конфиге;
    // для динамического IP - доменное имя `host:порт`), иначе автоопределение глобальных адресов интерфейсов.
    let env_adv = std::env::var("KNOTHOP_ADVERTISE").unwrap_or_default();
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
        node: node.clone(), sh: sh.clone(), ep: ep.clone(), state: a.state.clone(), name: a.name.clone(), tag: tag.clone(),
        identity: node_identity, my_pk, my_id, my_dest, my_key, ep_id: ep.id().to_string(), advertise: Mutex::new(advertise), adv_auto,
        announce_s: a.announce_s, dead: Duration::from_secs(a.dead_s), path_gate: path::PathGate::default(), client_info: Mutex::new(HashMap::new()), peer_clients: Mutex::new(HashMap::new()),
        links: Mutex::new(HashMap::new()), neigh: Mutex::new(HashMap::new()),
        tun, started: Instant::now(),
        ours_online: Default::default(), listen_port: a.port, public_ids: Mutex::new(HashSet::new()),
        t13,
    });
    if let (Some(tun), Some(t), Some(host_nft)) = (&ctx.tun, &ctx.t13, host_nft) {
        let weak = Arc::downgrade(&ctx);
        host_nft.start(tun, t.trust.clone(), move || {
            let ctx = weak.upgrade()?;
            let links = ctx.links.lock().unwrap();
            Some(links.iter().filter(|(_, l)| !l.enroll_only && matches!(l.role, Role::Client { .. }))
                .filter_map(|(link, l)| l.peer_pk.map(|pk| (*link, pk))).collect())
        })?;
    }
    let _enrollment_service = ctx.t13.as_ref().map(|t| enroll_net::register(node.clone(), ctx.identity.clone(), t.trust.clone(), &a.state, None));
    let _sync_guard = admin_lxmf.as_ref().map(|r| lxmf_sync::register(&a.state, r.sync.clone()));
    if let Some(runtime) = admin_lxmf {
        if let Some(t) = &ctx.t13 { runtime.pn.set_source(t.trust.clone()); }
        lxmf_admin::spawn_node_worker(runtime, ctx.clone());
    }
    if let Some(t) = &ctx.t13 {
        let tr = t.trust.lock().unwrap();
        let inv = t.invite.lock().unwrap();
        sh.note(format!("модель 0013: якорей {}, записей {}{}", tr.anchors().len(), tr.record_count(),
            if inv.is_some() { ", жду зачисления по приглашению" } else { "" }));

    }
    ctx.book_load();
    write_atomic(&a.state.join("server.json"), ctx.self_json().to_string().as_bytes());
    sh.note(format!("node {} tag {} dest {} iroh {}", ctx.name, tag, hex(&my_dest), ctx.ep_id));

    tokio::spawn(accept_loop(ep.clone(), node.clone(), sh.clone()));
    let relay_host = match (relay_seed, &ctx.t13) {
        (Some(seed), Some(t)) => {
            // relay не даёт прав: к нему допускаются только ключи, у которых в нашей сети есть хоть какое-то право (цепочка до якоря проверена в Trust)
            let trust = t.trust.clone();
            let trusted: relay::Trusted = Arc::new(move |k: &[u8; 32]| key_has_rights(&trust.lock().unwrap(), k));
            match relay::Host::start(&seed, SocketAddr::from(([0, 0, 0, 0], a.relay_quic_port)), trusted).await {
                Ok(h) => { sh.note(format!("iroh-relay: TLS на {}/tcp (общий с носителем), QAD на {}/udp", a.port, a.relay_quic_port)); Some(Arc::new(h)) }
                Err(e) => { sh.note(format!("iroh-relay не запущен: {e:#}")); None }
            }
        }
        _ => None,
    };
    tokio::spawn(tcpc::listen(node.clone(), sh.clone(), a.port, ep.secret_key().clone(), relay_host));
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
        if last.elapsed() >= Duration::from_secs(every) {
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

fn vpn_incoming_destination(ours: &[u8;16], target: &DestinationHash) -> bool { target.as_bytes() == ours }

async fn node_events(ctx: Arc<NodeCtx>, mut events: leviculum_std::driver::EventReceiver) {
    while let Some(ev) = events.recv().await {
        match ev {
            NodeEvent::AnnounceReceived { announce, .. } => on_announce(&ctx, &announce),
            NodeEvent::RequestReceived { link_id, request_id, path, data, .. } if path == enroll_net::PATH => { enroll_net::dispatch(&ctx.state, link_id, request_id, data); }
            NodeEvent::LinkEstablished { link_id, is_initiator, destination_hash } => {
                // LXMF delivery/PN — отдельные назначения. Их identify не
                // должен продвигать Link в VPN-соседа или вытеснять mesh Link.
                if !is_initiator && !vpn_incoming_destination(&ctx.my_dest, &destination_hash) { continue; }
                ctx.sh.established.lock().unwrap().insert(hex(link_id.as_bytes()));
                if !is_initiator {
                    if std::env::var("KNOTHOP_DEBUG").is_ok() {
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
                    l.insert(link_id, LinkInfo { role: Role::Unknown, since: Instant::now(), last_heard: Instant::now(), peer_pk: None, want_use: false, enroll_only: cbc, iface, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default(), diag: 0 });
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
    if std::env::var("KNOTHOP_DEBUG").is_ok() {
        ctx.sh.note(format!("announce from {} path_response={} data={}", hex(&ann.destination_hash().as_bytes()[..4]), ann.is_path_response(), String::from_utf8_lossy(ann.app_data()).chars().take(60).collect::<String>()));
    }
    let dest = *ann.destination_hash().as_bytes();
    let pk = *ann.public_key();
    if dest == ctx.my_dest || dest != dest_from_pub_tag(&pk, T13_TAG) { return; }
    let Some(t) = &ctx.t13 else { return };
    let member = t.trust.lock().unwrap().effective(&pk, now_ms() as u64) & trust::TRANSIT != 0;
    let invited = t.invite.lock().unwrap().as_ref().is_some_and(|i| trust::hash_of(&pk).is_some_and(|h| i.nodes.contains(&h)));
    if !member && !invited { return; }
    let v: serde_json::Value = serde_json::from_slice(ann.app_data()).unwrap_or_default();
    let key: [u8; 32] = pk[32..64].try_into().unwrap();
    let name: Option<String> = None;
    let ep = EndpointId::from_bytes(&key).map(|e| e.to_string()).unwrap_or_default();
    let addrs = Vec::new();
    let tags = Vec::new();
    let accepts_links = v["lc"].as_bool().unwrap_or(true);
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
    }
}

fn name_of(ctx: &Arc<NodeCtx>, dest: &[u8; 16]) -> String {
    ctx.neigh.lock().unwrap().get(dest).map(|n| n.name.clone()).unwrap_or_default()
}

/// Прямое QUIC-соединение к соседу, если у него есть адрес. Набирает один из двух: тот, у кого хеш меньше, либо тот, у кого нет своих адресов
/// (его иначе не достать); если за 15 с никто не набрал - набираем в любом случае. Так для пары не создаётся два соединения, а за NAT всё равно работает.
fn maybe_dial(ctx: &Arc<NodeCtx>, dest: [u8; 16]) {
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
        let may = ctx.my_dest < dest || ctx.adv().is_empty() || nb.first_seen.elapsed() > Duration::from_secs(15);
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
            // 0013: роль не зависит от инициативы. Сначала identify (ответчик узнаёт нас), затем обе стороны обмениваются цепочками прав
            ctx.links.lock().unwrap().insert(id, LinkInfo { role: Role::Unknown, since: Instant::now(), last_heard: Instant::now(), peer_pk: Some(pk), want_use: false, enroll_only: false, iface: None, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default(), diag: 0 });
            let c = ctx.clone();
            tokio::spawn(async move {
                let my_id = c.identity.clone();
                if c.node.identify_link(&id, &my_id).await.is_err() {
                    c.close_link(id, "identify не завершён");
                    return;
                }
                on_peer_ready(&c, id, pk);
            });
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

/// Решение вызывающего по результату авторитетного допуска в TUN (`TunState::allow`).
#[derive(Debug, PartialEq, Eq)]
enum AdmitOutcome {
    /// Link и маршрут занесены: можно слать AUTH_OK.
    SendAuthOk,
    /// Отказ: слать только AUTH_FAIL с этой причиной и закрыть Link; AUTH_OK недопустим.
    Refuse { reason: &'static [u8], note: &'static str },
}

fn admission_outcome(result: Result<Admission, AdmissionError>) -> AdmitOutcome {
    match result {
        Ok(_) => AdmitOutcome::SendAuthOk,
        Err(AdmissionError::AclNotReady) => AdmitOutcome::Refuse { reason: b"exit not ready", note: "host ACL не готов" },
        Err(AdmissionError::Capacity) => AdmitOutcome::Refuse { reason: b"exit client capacity", note: "exit client capacity" },
        Err(AdmissionError::AddressInUse) => AdmitOutcome::Refuse { reason: b"address clash", note: "конфликт адреса клиента" },
        Err(AdmissionError::LinkAddressChanged) => AdmitOutcome::Refuse { reason: b"address changed", note: "адрес Link изменился" },
    }
}

fn on_identified(ctx: &Arc<NodeCtx>, link: LinkId, idh: [u8; 16]) {
    let ok = matches!(ctx.links.lock().unwrap().get(&link).map(|l| &l.role), Some(Role::Unknown));
    if !ok {
        return;
    }
    // допуск решают записи о правах (on_peer_ready -> evaluate)
    if let Some(i) = ctx.node.get_remote_identity(&link) {
        if *i.hash() == idh {
            on_peer_ready(ctx, link, i.public_key_bytes());
        }
    }
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
    if ctx.link_is_cbc(&link) && true {
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

/// Имя назначения RNS. Модель 0013 (ADR 0016): нейтральное, без `KnotHop`/`vpn` - хеш имени виден в каждом анонсе, и по строке
/// наблюдатель узнал бы наши узлы. Легаси оставляет прежнее имя `knothopvpn.node.<тег группы>`.
fn new_dest(id: Identity, dir: Direction, tag: &str) -> Result<Destination, String> {
    let r = if tag == T13_TAG {
        Destination::new(Some(id), dir, DestinationType::Single, "node", &["mesh"])
    } else {
        Destination::new(Some(id), dir, DestinationType::Single, "knothopvpn", &["node", tag])
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

/// Прежнее (до ADR 0016) имя назначения модели 0013: `knothopvpn.node.t13`. Нужно только для переноса сохранённых адресов.
fn old_dest13(pk: &[u8; 64]) -> [u8; 16] {
    let mut d = [0u8; 16];
    if let Ok(idn) = Identity::from_public_key_bytes(pk) {
        if let Ok(dd) = Destination::new(Some(idn), Direction::Out, DestinationType::Single, "knothopvpn", &["node", T13_TAG]) {
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum OrdinaryAdmission { Client, Server }

/// The authority and live Link state remain locked through publication, not just a snapshot.
/// Order: Trust -> links -> (neigh OR TUN host_access -> allowed -> routes).
/// No I/O, await, close_link or reentrant NodeCtx calls in `publish`.
fn with_authorized_link<R>(
    authority: &Mutex<trust::Trust>, links: &Mutex<HashMap<LinkId, LinkInfo>>,
    link: LinkId, pk: &trust::Pk, kind: OrdinaryAdmission, promote: bool,
    publish: impl FnOnce(&trust::Trust, &mut HashMap<LinkId, LinkInfo>) -> R,
) -> Option<R> {
    let tr = authority.lock().unwrap();
    let mut live = links.lock().unwrap();
    let i = live.get(&link)?;
    if i.peer_pk.as_ref() != Some(pk) || i.enroll_only { return None; }
    let role_ok = if promote {
        matches!(i.role, Role::Unknown) && match kind {
            OrdinaryAdmission::Client => i.want_use,
            OrdinaryAdmission::Server => !i.want_use,
        }
    } else {
        match kind {
            OrdinaryAdmission::Client => matches!(i.role, Role::Client { .. }),
            OrdinaryAdmission::Server => matches!(i.role, Role::Server { .. }) && !i.want_use,
        }
    };
    if !role_ok { return None; }
    let (mine, theirs) = match kind {
        OrdinaryAdmission::Client => (trust::EXIT, trust::USE),
        OrdinaryAdmission::Server => (trust::TRANSIT, trust::TRANSIT),
    };
    let rights = tr.common_with(pk, mine, theirs, true, false, now_ms() as u64);
    let authorized = match kind {
        OrdinaryAdmission::Client => rights,
        OrdinaryAdmission::Server => server_promotion_allowed(i.enroll_only, None, rights),
    };
    if !authorized { return None; }
    let result = publish(&tr, &mut live);
    drop(live);
    drop(tr);
    Some(result)
}

/// Poll only while currently authorized. Pending drops both guards; every wake rechecks them.
/// LinkHandle::send reserves its dispatch slot BEFORE core mutation and has no post-commit await.
fn poll_authorized_link<R>(
    authority: &Mutex<trust::Trust>, links: &Mutex<HashMap<LinkId, LinkInfo>>,
    link: LinkId, pk: &trust::Pk, kind: OrdinaryAdmission, poll: impl FnOnce(&trust::Trust) -> Poll<R>,
) -> Poll<Option<R>> {
    match with_authorized_link(authority, links, link, pk, kind, false, |tr, _| poll(tr)) {
        Some(Poll::Pending) => Poll::Pending,
        Some(Poll::Ready(r)) => Poll::Ready(Some(r)),
        None => Poll::Ready(None),
    }
}

/// Live T_REC/T_POL push guard. Order Trust -> links, nothing held across an await. It checks only
/// the live Link (same LinkId, exact peer key, current role): a known peer that dropped to rights=0
/// must still receive its OWN revoke, so USE/TRANSIT is not demanded here but by the payload
/// predicate (`live_rec_allowed`/`live_pol_allowed`) evaluated against the same Trust guard.
fn with_live_forward_link<R>(
    authority: &Mutex<trust::Trust>, links: &Mutex<HashMap<LinkId, LinkInfo>>,
    link: LinkId, pk: &trust::Pk, kind: OrdinaryAdmission, check: impl FnOnce(&trust::Trust) -> R,
) -> Option<R> {
    let tr = authority.lock().unwrap();
    let live = links.lock().unwrap();
    let i = live.get(&link)?;
    if i.peer_pk.as_ref() != Some(pk) || i.enroll_only { return None; }
    let role_ok = match kind {
        OrdinaryAdmission::Client => matches!(i.role, Role::Client { .. }),
        OrdinaryAdmission::Server => matches!(i.role, Role::Server { .. }) && !i.want_use,
    };
    if !role_ok { return None; }
    Some(check(&tr))
}

/// Per-poll gate of a queued live push: Ready(false) (nothing polled, future dropped) when the
/// Link or the payload permission is gone; otherwise the transport poll runs under the guards.
fn poll_live_forward(
    authority: &Mutex<trust::Trust>, links: &Mutex<HashMap<LinkId, LinkInfo>>,
    link: LinkId, pk: &trust::Pk, kind: OrdinaryAdmission,
    allowed: impl FnOnce(&trust::Trust) -> bool, poll: impl FnOnce() -> Poll<bool>,
) -> Poll<bool> {
    with_live_forward_link(authority, links, link, pk, kind, |tr| if allowed(tr) { poll() } else { Poll::Ready(false) })
        .unwrap_or(Poll::Ready(false))
}

/// Live T_REC is root-scoped for Clients and Servers alike: a record is pushed only if
/// `record_visible_to` allows it in ITS root. A Server with TRANSIT in root R therefore receives all
/// of R (mesh propagation inside one root), a Server with TRANSIT in R and S receives both, and a
/// Server with TRANSIT only in R never sees S. A peer that lost its rights still gets its own chain
/// and its own revoke.
fn live_rec_allowed(tr: &trust::Trust, rec: &trust::Record, pk: &trust::Pk) -> bool {
    tr.record_visible_to(rec, pk)
}

/// Current permitted policy projection for the peer (Server rights only while mutual TRANSIT holds).
fn live_pol_allowed(tr: &trust::Trust, kind: OrdinaryAdmission, pol: &trust::Policy, pk: &trust::Pk, now: u64) -> bool {
    let rights = if kind == OrdinaryAdmission::Server && tr.common_with(pk, trust::TRANSIT, trust::TRANSIT, true, false, now) {
        trust::TRANSIT
    } else {
        trust::USE
    };
    tr.export_policies_for(rights, pk, now).contains(pol)
}

/// Candidates for live push: admitted Client/Server Links with a known peer key. Only a queueing
/// hint; the actual permission is `poll_live_forward` at every send poll.
fn live_forward_targets(links: &Mutex<HashMap<LinkId, LinkInfo>>, except: Option<LinkId>) -> Vec<(LinkId, trust::Pk, OrdinaryAdmission)> {
    links.lock().unwrap().iter()
        .filter(|(k, _)| Some(**k) != except)
        .filter_map(|(k, i)| match (&i.role, i.peer_pk) {
            (Role::Server { .. }, Some(p)) => Some((*k, p, OrdinaryAdmission::Server)),
            (Role::Client { .. }, Some(p)) => Some((*k, p, OrdinaryAdmission::Client)),
            _ => None,
        }).collect()
}

/// Единственный путь снятия допущенного Link (закрытие, отзыв прав через `evaluate`, замена, `LinkClosed` - всё идёт через `drop_link_state`).
fn remove_link_admission(
    links: &Mutex<HashMap<LinkId, LinkInfo>>, link: &LinkId, disallow: impl FnOnce(),
) -> Option<LinkInfo> {
    let mut live = links.lock().unwrap();
    let removed = live.remove(link);
    disallow(); // no promotion/late allow may slip between removal and TUN cleanup
    removed
}

struct ClientAdmission {
    id: [u8; 16],
    ip: u32,
    replaced: Vec<LinkId>,
}

/// Actual client promotion transaction; the injected publisher is the authoritative TUN allow.
fn promote_client_link(
    authority: &Mutex<trust::Trust>, links: &Mutex<HashMap<LinkId, LinkInfo>>, link: LinkId, pk: &trust::Pk,
    publish_tun: impl FnOnce(u32, bool, &[LinkId]) -> std::result::Result<(), AdmitOutcome>,
) -> Option<std::result::Result<ClientAdmission, AdmitOutcome>> {
    with_authorized_link(authority, links, link, pk, OrdinaryAdmission::Client, true, |tr, live| {
        let id = id_of_pub(pk).expect("authorized public key");
        let ip = client_ip(&id);
        if live.iter().any(|(k, i)| *k != link && matches!(i.role, Role::Client { ip: p, id: h } if p == ip && h != id)) {
            return Err(AdmitOutcome::Refuse { reason: b"address clash", note: "конфликт адреса клиента" });
        }
        if live.values().filter(|i| matches!(i.role, Role::Client { .. })).count() >= 256 {
            return Err(AdmitOutcome::Refuse { reason: b"exit client capacity", note: "exit client capacity" });
        }
        // Прежние живые Link ТОЙ ЖЕ аутентифицированной identity с тем же адресом (зомби после смены носителя): их владение
        // адресом TUN вытесняет новый Link атомарно в `publish_tun`. Считаем под теми же guard Trust+links, что и публикацию.
        let evictable: Vec<LinkId> = live.iter()
            .filter(|(k, i)| **k != link && i.peer_pk.as_ref() == Some(pk) && matches!(i.role, Role::Client { id: h, ip: p } if h == id && p == ip))
            .map(|(k, _)| *k).collect();
        live.get_mut(&link).unwrap().role = Role::Client { id, ip };
        // Trust AND links are still held across role assignment, allow and host permission.
        if let Err(refusal) = publish_tun(ip, !tr.host_access_roots(pk, &tr.me_hash).is_empty(), &evictable) {
            live.get_mut(&link).unwrap().role = Role::Unknown;
            return Err(refusal);
        }
        // Вытесненные Link уже убраны из таблиц TUN; из `links` и закрытие - после, вне guard (`admit_client13`).
        let replaced = live.iter().filter(|(k, i)| **k != link && matches!(i.role, Role::Client { id: h, .. } if h == id)).map(|(k, _)| *k).collect();
        Ok(ClientAdmission { id, ip, replaced })
    })
}

/// Shared neighbor-table publication, including deterministic duplicate-Link selection.
fn admit_neighbor_state(n: &mut HashMap<[u8; 16], Neighbor>, link: LinkId, dest: [u8; 16], pk: &trust::Pk) -> Option<LinkId> {
    let mut key = [0u8; 32];
    key.copy_from_slice(&pk[32..64]);
    let e = n.entry(dest).or_insert_with(|| Neighbor { dest, key, pk: *pk, name: "?".into(), ep: String::new(), addrs: Addrs::new(vec![]), tags: vec![], accepts_links: true, last_announce: Instant::now(),
        link: None, last_heard: Instant::now(), rtt_ms: None, connecting: false, dialer: None, first_seen: Instant::now(), last_try: Instant::now() - Duration::from_secs(3600), ctl: CarrierCtl::new(), loss: LossWin::default(), ping_seq: 0, admitted_at: Instant::now(), seen_gen: 0 });
    if let Some(old) = e.link {
        if old != link {
            let keep_new = link.as_bytes() < old.as_bytes();
            if keep_new { e.link = Some(link); }
            e.connecting = false;
            e.last_heard = Instant::now();
            return Some(if keep_new { old } else { link });
        }
    }
    e.link = Some(link);
    e.connecting = false;
    e.last_heard = Instant::now();
    e.admitted_at = Instant::now();
    e.loss.clear();
    None
}

fn promote_server_link(
    authority: &Mutex<trust::Trust>, links: &Mutex<HashMap<LinkId, LinkInfo>>, neigh: &Mutex<HashMap<[u8; 16], Neighbor>>,
    link: LinkId, pk: &trust::Pk, dest: [u8; 16],
) -> Option<Option<LinkId>> {
    with_authorized_link(authority, links, link, pk, OrdinaryAdmission::Server, true, |_, live| {
        let mut n = neigh.lock().unwrap();
        let accepts = n.values().find(|n| &n.pk == pk).map(|n| n.accepts_links);
        // Ordinary mutual TRANSIT is already checked under the SAME guard, not a caller bool.
        if accepts == Some(false) { return Some(link); }
        live.get_mut(&link).unwrap().role = Role::Server { dest };
        admit_neighbor_state(&mut n, link, dest, pk)
    })
}

fn peer_of(ctx: &NodeCtx, link: &LinkId) -> Option<[u8; 64]> {
    ctx.links.lock().unwrap().get(link).and_then(|l| l.peer_pk)
}

#[cfg(test)]
mod ordinary_admission_tests {
    use super::*;
    use std::sync::{TryLockError, mpsc::channel};

    struct Fixture {
        issuer: trust::Trust,
        root: trust::Hash,
        node_pk: trust::Pk,
        pk: trust::Pk,
        authority: Arc<Mutex<trust::Trust>>,
        links: Arc<Mutex<HashMap<LinkId, LinkInfo>>>,
        neigh: Mutex<HashMap<[u8; 16], Neighbor>>,
    }

    fn link() -> LinkId { LinkId::new([71; 16]) }
    fn fixture(client: bool) -> Fixture {
        let root_id = leviculum_std::api::generate_identity();
        let node = leviculum_std::api::generate_identity();
        let peer = leviculum_std::api::generate_identity();
        let root = *root_id.hash();
        let (node_pk, pk) = (node.public_key_bytes(), peer.public_key_bytes());
        let mut issuer = trust::Trust::new(root_id.clone(), None);
        let node_rec = issuer.issue(root, node_pk, trust::EXIT | trust::TRANSIT).unwrap();
        let peer_rec = issuer.issue(root, pk, trust::USE | trust::TRANSIT).unwrap();
        let mut target = trust::Trust::new(node, None);
        target.add_anchor(&root_id.public_key_bytes()).unwrap();
        assert_eq!(target.offer(node_rec), trust::Offer::Added);
        assert_eq!(target.offer(peer_rec), trust::Offer::Added);
        let links = HashMap::from([(link(), LinkInfo { role: Role::Unknown, since: Instant::now(), last_heard: Instant::now(),
            peer_pk: Some(pk), want_use: client, enroll_only: false, iface: None, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default(), diag: 0 })]);
        Fixture { issuer, root, node_pk, pk, authority: Arc::new(Mutex::new(target)), links: Arc::new(Mutex::new(links)), neigh: Mutex::new(HashMap::new()) }
    }

    #[derive(Default)]
    struct TunCore {
        host: HostAccessSet,
        allowed: AllowedMap,
        routes: RouteMap<()>,
    }
    impl TunCore {
        fn publish(&self, ip: u32, host: bool, replaces: &[LinkId]) -> std::result::Result<(), AdmitOutcome> {
            self.publish_as(link(), ip, host, replaces)
        }
        fn publish_as(&self, new: LinkId, ip: u32, host: bool, replaces: &[LinkId]) -> std::result::Result<(), AdmitOutcome> {
            match admission_outcome(admit_link_replacing(&self.host, &self.allowed, &self.routes, new, ip, (), replaces)) {
                AdmitOutcome::Refuse { reason, note } => Err(AdmitOutcome::Refuse { reason, note }),
                AdmitOutcome::SendAuthOk => {
                    assert!(set_link_host_access(&self.host, &self.allowed, &new, host));
                    Ok(())
                }
            }
        }
        fn close(&self) { disallow_link(&self.host, &self.allowed, &self.routes, &link()); }
        fn sizes(&self) -> (usize, usize, usize) {
            (self.host.read().unwrap().len(), self.allowed.read().unwrap().len(), self.routes.read().unwrap().len())
        }
    }

    fn link_info(role: Role, enroll_only: bool, pk: Option<[u8; 64]>) -> LinkInfo {
        LinkInfo { role, since: Instant::now(), last_heard: Instant::now(), peer_pk: pk, want_use: false, enroll_only, iface: None, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default(), diag: 0 }
    }

    // каталог по LXMF: подпись опознаёт ключ, но принять его можно только по роли Link, записи о зачислении, приглашению или эффективному TRANSIT
    #[test]
    fn dir_sender_and_recipient_need_role_or_transit_not_just_a_valid_key() {
        let mut f = fixture(false);
        let now = now_ms() as u64;
        let use_only = leviculum_std::api::generate_identity().public_key_bytes();
        let rec = f.issuer.issue(f.root, use_only, trust::USE).unwrap();
        assert_eq!(f.authority.lock().unwrap().offer(rec), trust::Offer::Added);
        let stranger = leviculum_std::api::generate_identity().public_key_bytes();
        let tr = f.authority.lock().unwrap();
        let (none, mut links) = (HashSet::new(), HashMap::new());
        // TRANSIT в записях достаточно и без живого Link
        assert!(dir_sender_ok(&links, &none, None, &tr, &f.pk, now) && dir_recipient_ok(&links, None, &tr, &f.pk, now));
        // чужой ключ и держатель только с USE: ни отправитель, ни адресат
        for pk in [&stranger, &use_only] {
            assert!(!dir_sender_ok(&links, &none, None, &tr, pk, now), "ключ без роли и TRANSIT каталог не присылает");
            assert!(!dir_recipient_ok(&links, None, &tr, pk, now));
        }
        // админ ожидающего приглашения
        assert!(dir_sender_ok(&links, &none, Some(stranger), &tr, &stranger, now) && dir_recipient_ok(&links, Some(stranger), &tr, &stranger, now));
        // Link без роли: адресат (новичок) - да, отправитель - только если мы сами просились через него
        let l = LinkId::new([9; 16]);
        links.insert(l, link_info(Role::Unknown, false, Some(stranger)));
        assert!(dir_recipient_ok(&links, None, &tr, &stranger, now));
        assert!(!dir_sender_ok(&links, &none, None, &tr, &stranger, now));
        assert!(dir_sender_ok(&links, &HashSet::from([l]), None, &tr, &stranger, now));
        // Link клиента не делает его ни отправителем, ни адресатом каталога
        links.insert(l, link_info(Role::Client { id: [1; 16], ip: 1 }, false, Some(stranger)));
        assert!(!dir_sender_ok(&links, &none, None, &tr, &stranger, now) && !dir_recipient_ok(&links, None, &tr, &stranger, now));
        // сосед-сервер: обе стороны
        links.insert(l, link_info(Role::Server { dest: [2; 16] }, false, Some(stranger)));
        assert!(dir_sender_ok(&links, &none, None, &tr, &stranger, now) && dir_recipient_ok(&links, None, &tr, &stranger, now));
    }

    #[test]
    fn member_directory_is_root_scoped_and_revocation_closes_it() {
        let mut f = fixture(true);
        let foreign = leviculum_std::api::generate_identity();
        let other = leviculum_std::api::generate_identity();
        let stranger = leviculum_std::api::generate_identity();
        let mut ft = trust::Trust::new(foreign.clone(), None);
        let mine = ft.issue(*foreign.hash(), f.node_pk, trust::EXIT | trust::TRANSIT).unwrap();
        let sibling = ft.issue(*foreign.hash(), other.public_key_bytes(), trust::EXIT).unwrap();
        let mut tr = f.authority.lock().unwrap();
        tr.add_anchor(&foreign.public_key_bytes()).unwrap();
        tr.offer(mine); tr.offer(sibling);
        let roots = directory_roots(&tr, &f.pk, now_ms() as u64);
        assert_eq!(roots, vec![f.root]);
        assert!(directory_node_visible(&tr, &roots, &f.node_pk));
        assert!(!directory_node_visible(&tr, &roots, &other.public_key_bytes()), "каталог не раскрывает чужую сеть");
        assert!(directory_roots(&tr, &stranger.public_key_bytes(), now_ms() as u64).is_empty(), "собственный корень не даёт членства");
        let revoke = f.issuer.issue(f.root, f.pk, 0).unwrap();
        assert_eq!(tr.offer(revoke), trust::Offer::Added);
        assert!(directory_roots(&tr, &f.pk, now_ms() as u64).is_empty());
    }

    #[test]
    fn scoped_enrollment_gets_sibling_routes_but_not_sibling_use() {
        let root = leviculum_std::api::generate_identity();
        let node = leviculum_std::api::generate_identity();
        let sibling = leviculum_std::api::generate_identity();
        let user = leviculum_std::api::generate_identity();
        let rh = *root.hash();
        let mut issuer = trust::Trust::new(root.clone(), None);
        issuer.issue(rh, node.public_key_bytes(), trust::TRANSIT | trust::EXIT).unwrap();
        issuer.issue(rh, sibling.public_key_bytes(), trust::TRANSIT | trust::EXIT).unwrap();
        let inv = crate::enroll::Invite::new(vec![*node.hash()]).unwrap();
        let g = crate::enroll::Grant::create(&root, rh, &inv, trust::USE, now_ms() as u64 / 1000).unwrap();
        let consent = crate::enroll::EnRec::consent(&user, &g, trust::USE).unwrap();
        let proof = crate::enroll::Proof { root:root.public_key_bytes(), admin:root.public_key_bytes(), chain:issuer.chain_for(&node.public_key_bytes()),
            rec:crate::enroll::EnRec::create(&node, &g, user.public_key_bytes(), trust::USE, consent, now_ms() as u64).unwrap(), grant:g };
        let mut tr = trust::Trust::new(node.clone(), None);
        tr.add_anchor(&root.public_key_bytes()).unwrap();
        for rec in issuer.export_all() { tr.offer(rec); }
        tr.offer_enrollment(proof).unwrap();
        let roots = directory_roots(&tr, &user.public_key_bytes(), now_ms() as u64);
        assert_eq!(roots, vec![rh]);
        assert!(directory_node_visible(&tr, &roots, &sibling.public_key_bytes()), "путь к соседу виден независимо от его расписки");
        assert_eq!(tr.rights_at(&rh, user.hash(), sibling.hash()), 0, "каталог не выдаёт USE на другой scope");
        assert!(tr.records_visible_to(&user.public_key_bytes()).iter().any(|r| r.holder == sibling.public_key_bytes()), "цепочка EXIT отправляется вместе с каталогом");
    }

    #[test]
    fn ordinary_admission_delayed_client_rechecks_use_exit_and_policy() {
        for change in 0..3 {
            let mut f = fixture(true);
            let tun = Arc::new(TunCore::default());
            let (paused, ready) = channel();
            let (resume, resumed) = channel();
            let (authority, links, pk, old_tun) = (f.authority.clone(), f.links.clone(), f.pk, tun.clone());
            let old = std::thread::spawn(move || {
                let cli_ok = authority.lock().unwrap().common_with(&pk, trust::EXIT, trust::USE, true, false, now_ms() as u64);
                paused.send(cli_ok).unwrap();
                resumed.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(promote_client_link(&authority, &links, link(), &pk, |ip, host, r| old_tun.publish(ip, host, r)).is_none());
            });
            assert!(ready.recv_timeout(Duration::from_secs(5)).unwrap());
            match change {
                0 => {
                    let rec = f.issuer.issue(f.root, f.pk, trust::TRANSIT).unwrap();
                    assert_eq!(f.authority.lock().unwrap().offer(rec), trust::Offer::Added);
                }
                1 => {
                    let rec = f.issuer.issue(f.root, f.node_pk, trust::TRANSIT).unwrap();
                    assert_eq!(f.authority.lock().unwrap().offer(rec), trust::Offer::Added);
                }
                _ => { f.authority.lock().unwrap().set_my_policy(f.root, trust::TRANSIT, now_ms() as u64).unwrap(); }
            }
            resume.send(()).unwrap();
            old.join().unwrap();
            assert_eq!(tun.sizes(), (0, 0, 0));
            assert!(matches!(f.links.lock().unwrap()[&link()].role, Role::Unknown));
        }
    }

    #[test]
    fn ordinary_admission_delayed_server_rechecks_mutual_transit_and_policy() {
        for change in 0..3 {
            let mut f = fixture(false);
            assert!(f.authority.lock().unwrap().common_with(&f.pk, trust::TRANSIT, trust::TRANSIT, true, false, now_ms() as u64));
            // This is the real callback entry after the 500ms wait, not a timer/sleep model.
            match change {
                0 => {
                    let rec = f.issuer.issue(f.root, f.pk, trust::USE).unwrap();
                    assert_eq!(f.authority.lock().unwrap().offer(rec), trust::Offer::Added);
                }
                1 => {
                    let rec = f.issuer.issue(f.root, f.node_pk, trust::EXIT).unwrap();
                    assert_eq!(f.authority.lock().unwrap().offer(rec), trust::Offer::Added);
                }
                _ => { f.authority.lock().unwrap().set_my_policy(f.root, trust::EXIT, now_ms() as u64).unwrap(); }
            }
            assert!(promote_server_link(&f.authority, &f.links, &f.neigh, link(), &f.pk, dest_from_pub_tag(&f.pk, T13_TAG)).is_none());
            assert!(f.neigh.lock().unwrap().is_empty());
            assert!(with_authorized_link(&f.authority, &f.links, link(), &f.pk, OrdinaryAdmission::Server, false,
                |_, _| panic!("former peer must not reach export_all/T_DIR snapshot")).is_none());
        }
    }

    #[test]
    fn ordinary_admission_rejects_missing_identity_enrollment_role_and_use_changes() {
        for client in [true, false] {
            for change in 0..5 {
                let f = fixture(client);
                let tun = TunCore::default();
                if change == 0 {
                    remove_link_admission(&f.links, &link(), || tun.close());
                } else {
                    let mut live = f.links.lock().unwrap();
                    let i = live.get_mut(&link()).unwrap();
                    match change {
                        1 => i.peer_pk = Some(leviculum_std::api::generate_identity().public_key_bytes()),
                        2 => i.enroll_only = true,
                        3 => i.role = Role::Client { id: [0; 16], ip: 1 },
                        _ => i.want_use = !client,
                    }
                }
                if client {
                    assert!(promote_client_link(&f.authority, &f.links, link(), &f.pk, |_, _, _| panic!("ineligible Link must not reach allow")).is_none());
                } else {
                    assert!(promote_server_link(&f.authority, &f.links, &f.neigh, link(), &f.pk, dest_from_pub_tag(&f.pk, T13_TAG)).is_none());
                    assert!(f.neigh.lock().unwrap().is_empty());
                }
                assert_eq!(tun.sizes(), (0, 0, 0));
            }
        }
        let f = fixture(false);
        let dest = dest_from_pub_tag(&f.pk, T13_TAG);
        {
            let mut n = f.neigh.lock().unwrap();
            admit_neighbor_state(&mut n, LinkId::new([72; 16]), dest, &f.pk);
            let nb = n.get_mut(&dest).unwrap();
            nb.link = None;
            nb.accepts_links = false;
        }
        assert_eq!(promote_server_link(&f.authority, &f.links, &f.neigh, link(), &f.pk, dest), Some(Some(link())));
        assert!(matches!(f.links.lock().unwrap()[&link()].role, Role::Unknown));
        assert!(f.neigh.lock().unwrap()[&dest].link.is_none());
    }

    #[test]
    fn ordinary_admission_role_allow_serializes_revoke_and_close() {
        let mut f = fixture(true);
        let tun = Arc::new(TunCore::default());
        let revoke = f.issuer.issue(f.root, f.pk, trust::TRANSIT).unwrap();
        let (paused, ready) = channel();
        let (resume, resumed) = channel();
        let (authority, links, pk, old_tun) = (f.authority.clone(), f.links.clone(), f.pk, tun.clone());
        let old = std::thread::spawn(move || {
            assert!(matches!(promote_client_link(&authority, &links, link(), &pk, |ip, host, r| {
                paused.send(()).unwrap(); // role assigned; actual allow has not run yet
                resumed.recv_timeout(Duration::from_secs(5)).unwrap();
                old_tun.publish(ip, host, r)
            }), Some(Ok(_))));
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        let authority_held = matches!(f.authority.try_lock(), Err(TryLockError::WouldBlock));
        let link_held = matches!(f.links.try_lock(), Err(TryLockError::WouldBlock));
        let (attempted, attempt) = channel();
        let (authority, links, new_tun) = (f.authority.clone(), f.links.clone(), tun.clone());
        let revoker = std::thread::spawn(move || {
            attempted.send(()).unwrap();
            assert_eq!(authority.lock().unwrap().offer(revoke), trust::Offer::Added);
            remove_link_admission(&links, &link(), || new_tun.close());
        });
        let (closing, close_attempt) = channel();
        let (links, closed_tun) = (f.links.clone(), tun.clone());
        let closer = std::thread::spawn(move || {
            closing.send(()).unwrap();
            remove_link_admission(&links, &link(), || closed_tun.close());
        });
        attempt.recv_timeout(Duration::from_secs(5)).unwrap();
        close_attempt.recv_timeout(Duration::from_secs(5)).unwrap();
        resume.send(()).unwrap();
        old.join().unwrap();
        revoker.join().unwrap();
        closer.join().unwrap();
        assert!(authority_held && link_held, "ordinary authority/close must not slip between role and allow");
        assert_eq!(tun.sizes(), (0, 0, 0));
        assert!(!f.links.lock().unwrap().contains_key(&link()));
        // Even a later legitimate regrant cannot resurrect the SAME closed LinkId.
        let regrant = f.issuer.issue(f.root, f.pk, trust::USE | trust::TRANSIT).unwrap();
        assert_eq!(f.authority.lock().unwrap().offer(regrant), trust::Offer::Added);
        assert!(promote_client_link(&f.authority, &f.links, link(), &f.pk, |ip, host, r| tun.publish(ip, host, r)).is_none());
        assert_eq!(tun.sizes(), (0, 0, 0));
    }

    fn promoted(f: &Fixture, tun: &TunCore) {
        assert!(matches!(promote_client_link(&f.authority, &f.links, link(), &f.pk, |ip, host, r| tun.publish(ip, host, r)), Some(Ok(_))));
    }

    // Диагностика допуска: одна запись на Link и причину, независимо друг от друга; нет Link - нет записи.
    #[test]
    fn admit_diag_is_marked_once_per_link_and_reason() {
        let f = fixture(true);
        let all = [AdmitDiag::EnrollOnly, AdmitDiag::NoChainWait, AdmitDiag::NoChain, AdmitDiag::NotAuthorized];
        let mut bits = 0u8;
        for d in all {
            assert_eq!(bits & d.bit(), 0, "биты причин не пересекаются");
            bits |= d.bit();
        }
        for d in all {
            assert!(diag_first(&f.links, link(), d), "{d:?}: первый раз");
            assert!(!diag_first(&f.links, link(), d), "{d:?}: повтор молчит");
        }
        assert!(!diag_first(&f.links, LinkId::new([72; 16]), AdmitDiag::NoChain), "нет Link - нет записи");
    }

    // Причины фиксированы и безопасны: ответ клиенту - короткий ASCII без данных, журнал - без форматных подстановок и секретов.
    #[test]
    fn admit_diag_reasons_are_fixed_and_leak_nothing() {
        let all = [AdmitDiag::EnrollOnly, AdmitDiag::NoChainWait, AdmitDiag::NoChain, AdmitDiag::NotAuthorized];
        let mut fails = HashSet::new();
        for d in all {
            assert!(!d.note().contains('{') && !d.note().contains("KNOTHOP"), "{d:?}");
            if let Some(f) = d.fail() {
                assert!(f.len() <= 32 && f.iter().all(|b| b.is_ascii_lowercase() || *b == b' '), "{d:?}: фиксированный ASCII-текст");
                assert!(fails.insert(f), "{d:?}: причины клиенту различимы");
            }
        }
        assert_eq!(AdmitDiag::NoChainWait.fail(), None, "ожидание цепочки клиенту не отказ");
        assert!(AdmitDiag::NoChain.fail().is_some() && AdmitDiag::NotAuthorized.fail().is_some() && AdmitDiag::EnrollOnly.fail().is_some());
        assert!(NO_CHAIN_FAIL_AFTER < Duration::from_secs(6), "отказ раньше, чем клиент (connect_exit, 6 с) сам уйдёт по таймауту");
    }

    // Отказ клиенту и запись - только пока Link жив, тот же ключ, прислал T_USE и остаётся Unknown; допущенный/чужой/закрытый молчит.
    #[test]
    fn client_awaiting_admission_requires_live_unadmitted_use_link_of_same_key() {
        let f = fixture(true);
        let other = [9u8; 64];
        assert!(client_awaiting_admission(&f.links, link(), &f.pk));
        assert!(!client_awaiting_admission(&f.links, link(), &other), "ключ Link сменился");
        assert!(!client_awaiting_admission(&f.links, LinkId::new([72; 16]), &f.pk), "Link закрыт");
        f.links.lock().unwrap().get_mut(&link()).unwrap().want_use = false;
        assert!(!client_awaiting_admission(&f.links, link(), &f.pk), "не клиент");
        f.links.lock().unwrap().get_mut(&link()).unwrap().want_use = true;
        f.links.lock().unwrap().get_mut(&link()).unwrap().role = Role::Client { id: [1; 16], ip: 1 };
        assert!(!client_awaiting_admission(&f.links, link(), &f.pk), "проигравший гонку с допуском не получает отказ");
    }

    // Диагностика не меняет решение: пометки причин на Link не мешают допуску, а Link для зачисления по-прежнему не допускается.
    #[test]
    fn admit_diag_marks_do_not_change_the_admission_decision() {
        let f = fixture(true);
        let tun = TunCore::default();
        f.links.lock().unwrap().get_mut(&link()).unwrap().enroll_only = true;
        assert!(client_awaiting_admission(&f.links, link(), &f.pk), "enroll-only Link ждёт допуска и получит NotAuthorized/EnrollOnly");
        assert!(promote_client_link(&f.authority, &f.links, link(), &f.pk, |_, _, _| panic!("enroll-only не доходит до allow")).is_none());
        f.links.lock().unwrap().get_mut(&link()).unwrap().enroll_only = false;
        f.links.lock().unwrap().get_mut(&link()).unwrap().diag = 0xff;
        promoted(&f, &tun);
        assert_eq!(tun.sizes().1, 1, "клиент допущен несмотря на пометки диагностики");
    }

    #[test]
    fn diag_budget_caps_lines_per_window_and_reports_suppressed() {
        let mut b = DiagBudget::new();
        let t0 = 1_000_000;
        for i in 0..DIAG_MAX_PER_WINDOW {
            assert_eq!(b.allow(t0 + i as u64), (true, 0), "строка {i}");
        }
        for _ in 0..5 {
            assert_eq!(b.allow(t0 + 100), (false, 0), "сверх предела окна");
        }
        assert_eq!(b.allow(t0 + DIAG_WINDOW_MS - 1), (false, 0), "окно ещё идёт");
        assert_eq!(b.allow(t0 + DIAG_WINDOW_MS), (true, 6), "новое окно: строка пишется, подавленные сообщены");
        assert_eq!(b.allow(t0 + DIAG_WINDOW_MS + 1), (true, 0));
    }

    #[test]
    fn ordinary_admission_pending_control_cancels_before_commit_after_revoke_or_close() {
        for client in [true, false] {
            for close in [true, false] {
                let mut f = fixture(client);
                let tun = TunCore::default();
                let kind = if client { OrdinaryAdmission::Client } else { OrdinaryAdmission::Server };
                if client {
                    assert!(matches!(promote_client_link(&f.authority, &f.links, link(), &f.pk, |ip, host, r| tun.publish(ip, host, r)), Some(Ok(_))));
                } else {
                    assert_eq!(promote_server_link(&f.authority, &f.links, &f.neigh, link(), &f.pk, dest_from_pub_tag(&f.pk, T13_TAG)), Some(None));
                }
                let mut polls = 0;
                // Injectable transport seam only. The actual production poll guard must NOT
                // poll the send again after revoke/close, hence no stale queued output.
                assert!(poll_authorized_link(&f.authority, &f.links, link(), &f.pk, kind, |_| {
                    polls += 1;
                    Poll::<bool>::Pending
                }).is_pending());
                if close {
                    remove_link_admission(&f.links, &link(), || tun.close());
                } else {
                    let rights = if client { trust::TRANSIT } else { trust::USE };
                    let revoke = f.issuer.issue(f.root, f.pk, rights).unwrap();
                    assert_eq!(f.authority.lock().unwrap().offer(revoke), trust::Offer::Added);
                }
                assert_eq!(poll_authorized_link(&f.authority, &f.links, link(), &f.pk, kind, |_| {
                    polls += 1;
                    Poll::Ready(true) // would commit AUTH_OK / privileged export if polled
                }), Poll::Ready(None));
                assert_eq!(polls, 1);
            }
        }
    }

    #[test]
    fn ordinary_admission_host_only_revoke_keeps_use_and_allow_refusal_never_authorizes() {
        let f = fixture(true);
        let tun = TunCore::default();
        let scope = f.authority.lock().unwrap().me_hash;
        let grant = f.issuer.sign_host_access(f.root, scope, f.pk, true).unwrap();
        let revoke = f.issuer.sign_host_access(f.root, scope, f.pk, false).unwrap();
        f.authority.lock().unwrap().allow_host_root(f.root, 16);
        let commit = f.authority.lock().unwrap().prepare_host_access(&grant).unwrap();
        commit.commit(&f.authority).unwrap();
        assert!(matches!(promote_client_link(&f.authority, &f.links, link(), &f.pk, |ip, host, r| tun.publish(ip, host, r)), Some(Ok(_))));
        assert_eq!(tun.sizes(), (1, 1, 1));
        let commit = f.authority.lock().unwrap().prepare_host_access(&revoke).unwrap();
        commit.commit(&f.authority).unwrap();
        assert!(publish_host_access_decision(&f.authority, &f.pk, |_| (), |host| set_link_host_access(&tun.host, &tun.allowed, &link(), host)).1);
        assert_eq!(tun.sizes(), (0, 1, 1));
        assert_eq!(poll_authorized_link(&f.authority, &f.links, link(), &f.pk, OrdinaryAdmission::Client, |_| Poll::Ready(true)), Poll::Ready(Some(true)));

        let f = fixture(true);
        let tun = TunCore::default();
        let ip = client_ip(&id_of_pub(&f.pk).unwrap());
        admit_link(&tun.host, &tun.allowed, &tun.routes, LinkId::new([72; 16]), ip, ()).unwrap();
        assert!(matches!(promote_client_link(&f.authority, &f.links, link(), &f.pk, |ip, host, r| tun.publish(ip, host, r)),
            Some(Err(AdmitOutcome::Refuse { reason: b"address clash", .. }))));
        assert!(matches!(f.links.lock().unwrap()[&link()].role, Role::Unknown));
        assert_eq!(poll_authorized_link(&f.authority, &f.links, link(), &f.pk, OrdinaryAdmission::Client, |_| Poll::Ready(true)), Poll::Ready(None));
        assert_eq!(tun.sizes(), (0, 1, 1));
    }

    fn old_link() -> LinkId { LinkId::new([73; 16]) }

    /// Прежний Link (зомби после смены носителя): запись в `links` с заданными peer_pk/ролью и, при `publish`, владение адресом в TUN.
    fn add_old_client(f: &Fixture, tun: &TunCore, id: LinkId, peer_pk: trust::Pk, role_id: [u8; 16], ip: u32, host: bool) {
        f.links.lock().unwrap().insert(id, LinkInfo { role: Role::Client { id: role_id, ip }, since: Instant::now(), last_heard: Instant::now(),
            peer_pk: Some(peer_pk), want_use: true, enroll_only: false, iface: None, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default(), diag: 0 });
        assert!(tun.publish_as(id, ip, host, &[]).is_ok());
    }

    #[test]
    fn ordinary_admission_same_identity_replaces_stale_link_atomically_without_host_inheritance() {
        let f = fixture(true);
        let tun = TunCore::default();
        let cid = id_of_pub(&f.pk).unwrap();
        let ip = client_ip(&cid);
        // у прежнего Link был HOST_ACCESS, у identity в Trust его сейчас нет: новый Link не наследует
        add_old_client(&f, &tun, old_link(), f.pk, cid, ip, true);
        assert_eq!(tun.sizes(), (1, 1, 1));
        let adm = match promote_client_link(&f.authority, &f.links, link(), &f.pk, |ip, host, r| tun.publish(ip, host, r)) {
            Some(Ok(a)) => a,
            _ => panic!("same identity must replace its stale Link"),
        };
        assert_eq!(adm.replaced, vec![old_link()]);
        assert_eq!(tun.sizes(), (0, 1, 1), "stale Link removed from allowed/routes/host; new Link has no HOST_ACCESS");
        assert_eq!(tun.routes.read().unwrap().get(&ip).map(|(l, _)| *l), Some(link()));
        assert!(!tun.allowed.read().unwrap().contains_key(&old_link()));
        // закрытие вытесненного Link вне guard (как в admit_client13) не трогает маршрут нового
        let removed = remove_link_admission(&f.links, &old_link(), || disallow_link(&tun.host, &tun.allowed, &tun.routes, &old_link()));
        assert!(removed.is_some());
        assert_eq!(tun.routes.read().unwrap().get(&ip).map(|(l, _)| *l), Some(link()));
        assert_eq!(tun.sizes(), (0, 1, 1));
        assert!(matches!(f.links.lock().unwrap()[&link()].role, Role::Client { .. }));
    }

    #[test]
    fn ordinary_admission_recomputes_host_access_for_replacing_link() {
        let f = fixture(true);
        let tun = TunCore::default();
        let cid = id_of_pub(&f.pk).unwrap();
        let ip = client_ip(&cid);
        let scope = f.authority.lock().unwrap().me_hash;
        let grant = f.issuer.sign_host_access(f.root, scope, f.pk, true).unwrap();
        f.authority.lock().unwrap().allow_host_root(f.root, 16);
        let commit = f.authority.lock().unwrap().prepare_host_access(&grant).unwrap();
        commit.commit(&f.authority).unwrap();
        // прежний Link без HOST_ACCESS, у identity он выдан: новый получает его по свежему расчёту
        add_old_client(&f, &tun, old_link(), f.pk, cid, ip, false);
        assert!(matches!(promote_client_link(&f.authority, &f.links, link(), &f.pk, |ip, host, r| tun.publish(ip, host, r)), Some(Ok(_))));
        assert_eq!(tun.sizes(), (1, 1, 1));
        assert!(tun.host.read().unwrap().contains(&link()) && !tun.host.read().unwrap().contains(&old_link()));
    }

    #[test]
    fn ordinary_admission_other_identity_or_unauthenticated_owner_is_never_evicted() {
        // чужая identity с тем же адресом: address clash до публикации, без мутаций
        let f = fixture(true);
        let tun = TunCore::default();
        let cid = id_of_pub(&f.pk).unwrap();
        let ip = client_ip(&cid);
        let other_pk = leviculum_std::api::generate_identity().public_key_bytes();
        add_old_client(&f, &tun, old_link(), other_pk, [0xaa; 16], ip, true);
        assert!(matches!(promote_client_link(&f.authority, &f.links, link(), &f.pk, |ip, host, r| tun.publish(ip, host, r)),
            Some(Err(AdmitOutcome::Refuse { reason: b"address clash", .. }))));
        assert_eq!(tun.sizes(), (1, 1, 1));
        assert_eq!(tun.routes.read().unwrap().get(&ip).map(|(l, _)| *l), Some(old_link()));
        assert!(matches!(f.links.lock().unwrap()[&link()].role, Role::Unknown));

        // та же роль-id, но другой аутентифицированный ключ: не в `replaces`, отказ из таблиц TUN без мутаций
        let f = fixture(true);
        let tun = TunCore::default();
        let ip = client_ip(&id_of_pub(&f.pk).unwrap());
        let other_pk = leviculum_std::api::generate_identity().public_key_bytes();
        add_old_client(&f, &tun, old_link(), other_pk, id_of_pub(&f.pk).unwrap(), ip, true);
        assert!(matches!(promote_client_link(&f.authority, &f.links, link(), &f.pk, |ip, host, r| tun.publish(ip, host, r)),
            Some(Err(AdmitOutcome::Refuse { reason: b"address clash", .. }))));
        assert_eq!(tun.sizes(), (1, 1, 1));
        assert_eq!(tun.routes.read().unwrap().get(&ip).map(|(l, _)| *l), Some(old_link()));
        assert!(matches!(f.links.lock().unwrap()[&link()].role, Role::Unknown));
    }

    #[test]
    fn ordinary_admission_replacement_serializes_with_revoke_and_close() {
        let mut f = fixture(true);
        let tun = Arc::new(TunCore::default());
        let cid = id_of_pub(&f.pk).unwrap();
        let ip = client_ip(&cid);
        add_old_client(&f, &tun, old_link(), f.pk, cid, ip, false);
        let revoke = f.issuer.issue(f.root, f.pk, trust::TRANSIT).unwrap();
        let (paused, ready) = channel();
        let (resume, resumed) = channel();
        let (authority, links, pk, new_tun) = (f.authority.clone(), f.links.clone(), f.pk, tun.clone());
        let promoter = std::thread::spawn(move || {
            assert!(matches!(promote_client_link(&authority, &links, link(), &pk, |ip, host, r| {
                paused.send(()).unwrap(); // role assigned, eviction not yet done
                resumed.recv_timeout(Duration::from_secs(5)).unwrap();
                new_tun.publish(ip, host, r)
            }), Some(Ok(_))));
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        let authority_held = matches!(f.authority.try_lock(), Err(TryLockError::WouldBlock));
        let link_held = matches!(f.links.try_lock(), Err(TryLockError::WouldBlock));
        let (attempted, attempt) = channel();
        let (authority, links, closed_tun) = (f.authority.clone(), f.links.clone(), tun.clone());
        let revoker = std::thread::spawn(move || {
            attempted.send(()).unwrap();
            assert_eq!(authority.lock().unwrap().offer(revoke), trust::Offer::Added);
            remove_link_admission(&links, &link(), || closed_tun.close());
        });
        attempt.recv_timeout(Duration::from_secs(5)).unwrap();
        resume.send(()).unwrap();
        promoter.join().unwrap();
        revoker.join().unwrap();
        assert!(authority_held && link_held, "revoke/close must not slip between role assignment and replacement");
        // после отзыва у нового Link нет прав, прежний уже вытеснен: в TUN никого
        assert_eq!(tun.sizes(), (0, 0, 0));
        assert!(!f.links.lock().unwrap().contains_key(&link()));
        // последующая замена по отозванным правам невозможна
        assert!(promote_client_link(&f.authority, &f.links, LinkId::new([74; 16]), &f.pk, |ip, host, r| tun.publish(ip, host, r)).is_none());
        assert_eq!(tun.sizes(), (0, 0, 0));
    }

    fn set_role(f: &Fixture, client: bool) {
        let role = if client {
            let id = id_of_pub(&f.pk).unwrap();
            Role::Client { id, ip: client_ip(&id) }
        } else {
            Role::Server { dest: dest_from_pub_tag(&f.pk, T13_TAG) }
        };
        f.links.lock().unwrap().get_mut(&link()).unwrap().role = role;
    }

    fn kind(client: bool) -> OrdinaryAdmission {
        if client { OrdinaryAdmission::Client } else { OrdinaryAdmission::Server }
    }

    fn offer(f: &Fixture, rec: &trust::Record) {
        assert_eq!(f.authority.lock().unwrap().offer(rec.clone()), trust::Offer::Added);
    }

    /// The exact production gate used by `send_live_ctl` for T_REC; `polls` counts transport polls.
    fn poll_rec(f: &Fixture, client: bool, rec: &trust::Record, polls: &mut u32, result: Poll<bool>) -> Poll<bool> {
        poll_live_forward(&f.authority, &f.links, link(), &f.pk, kind(client),
            |tr| live_rec_allowed(tr, rec, &f.pk),
            || { *polls += 1; result })
    }

    #[test]
    fn live_forward_targets_are_admitted_links_with_known_peer_key() {
        let f = fixture(true);
        assert!(live_forward_targets(&f.links, None).is_empty(), "unknown-role Link is not a target");
        set_role(&f, true);
        assert!(live_forward_targets(&f.links, None) == vec![(link(), f.pk, OrdinaryAdmission::Client)]);
        assert!(live_forward_targets(&f.links, Some(link())).is_empty(), "except is honoured");
        set_role(&f, false);
        assert!(live_forward_targets(&f.links, None) == vec![(link(), f.pk, OrdinaryAdmission::Server)]);
        f.links.lock().unwrap().get_mut(&link()).unwrap().peer_pk = None;
        assert!(live_forward_targets(&f.links, None).is_empty());
    }

    #[test]
    fn live_forward_queued_sibling_record_is_not_committed_after_add_downgrade() {
        let mut f = fixture(true);
        set_role(&f, true);
        let delegate = f.issuer.issue(f.root, f.pk, trust::USE | trust::ADD).unwrap();
        offer(&f, &delegate);
        let sibling = f.issuer.issue(f.root, leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
        offer(&f, &sibling);

        // Queued while the peer still has ADD (the forward_rec planning predicate), then backpressure.
        let tr = f.authority.lock().unwrap();
        assert!(live_rec_allowed(&tr, &sibling, &f.pk));
        drop(tr);
        let mut polls = 0;
        assert!(poll_rec(&f, true, &sibling, &mut polls, Poll::Pending).is_pending());
        assert_eq!(polls, 1);

        // Signed downgrade ADD -> USE: Link and ordinary admission survive, sibling visibility does not.
        let downgrade = f.issuer.issue(f.root, f.pk, trust::USE).unwrap();
        offer(&f, &downgrade);
        assert!(f.authority.lock().unwrap().common_with(&f.pk, trust::EXIT, trust::USE, true, false, now_ms() as u64));
        assert!(poll_rec(&f, true, &sibling, &mut polls, Poll::Ready(true)) == Poll::Ready(false));
        assert_eq!(polls, 1, "the send future must not be polled (committed) after the downgrade");
    }

    #[test]
    fn live_forward_delivers_own_chain_and_revoke_after_downgrade_and_rights_zero() {
        let mut f = fixture(true);
        set_role(&f, true);
        let delegate = f.issuer.issue(f.root, f.pk, trust::USE | trust::ADD).unwrap();
        offer(&f, &delegate);
        let sibling = f.issuer.issue(f.root, leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
        offer(&f, &sibling);

        let downgrade = f.issuer.issue(f.root, f.pk, trust::USE).unwrap();
        offer(&f, &downgrade);
        let mut polls = 0;
        assert!(poll_rec(&f, true, &downgrade, &mut polls, Poll::Ready(true)) == Poll::Ready(true), "own record reaches a USE peer");
        assert!(poll_rec(&f, true, &sibling, &mut polls, Poll::Ready(true)) == Poll::Ready(false));
        assert_eq!(polls, 1);

        // Pending first, then the peer is revoked to rights=0 and its Link has not been closed yet.
        let revoke = f.issuer.issue(f.root, f.pk, 0).unwrap();
        offer(&f, &revoke);
        assert!(live_forward_targets(&f.links, None).iter().any(|(l, p, k)| *l == link() && *p == f.pk && *k == OrdinaryAdmission::Client));
        assert!(poll_rec(&f, true, &revoke, &mut polls, Poll::Pending).is_pending());
        assert!(poll_rec(&f, true, &revoke, &mut polls, Poll::Ready(true)) == Poll::Ready(true), "own revoke still delivered at rights=0");
        assert_eq!(polls, 3);
        assert!(poll_rec(&f, true, &sibling, &mut polls, Poll::Ready(true)) == Poll::Ready(false), "former role must not reveal siblings");
        assert_eq!(polls, 3);
    }

    #[test]
    fn live_forward_server_root_export_requires_current_transit_but_keeps_own_revoke() {
        let mut f = fixture(false);
        set_role(&f, false);
        let sibling = f.issuer.issue(f.root, leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
        offer(&f, &sibling);
        let mut polls = 0;
        assert!(poll_rec(&f, false, &sibling, &mut polls, Poll::Pending).is_pending());
        assert!(poll_rec(&f, false, &sibling, &mut polls, Poll::Ready(true)) == Poll::Ready(true), "TRANSIT neighbour gets the whole root");
        assert_eq!(polls, 2);

        let queued = f.issuer.issue(f.root, leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
        offer(&f, &queued);
        assert!(poll_rec(&f, false, &queued, &mut polls, Poll::Pending).is_pending());
        let downgrade = f.issuer.issue(f.root, f.pk, trust::USE).unwrap();
        offer(&f, &downgrade);
        assert!(poll_rec(&f, false, &queued, &mut polls, Poll::Ready(true)) == Poll::Ready(false));
        assert_eq!(polls, 3, "queued full-store export is cancelled once TRANSIT is gone");
        assert!(poll_rec(&f, false, &downgrade, &mut polls, Poll::Ready(true)) == Poll::Ready(true));
        let revoke = f.issuer.issue(f.root, f.pk, 0).unwrap();
        offer(&f, &revoke);
        assert!(poll_rec(&f, false, &revoke, &mut polls, Poll::Ready(true)) == Poll::Ready(true), "ex-neighbour still learns its own revoke");
        assert_eq!(polls, 5);
    }

    /// A second accepted root S on the same server (the target is its EXIT/TRANSIT member). Returns (S issuer, S record of a bystander).
    fn add_second_root(f: &Fixture) -> (trust::Trust, trust::Record) {
        let root2 = leviculum_std::api::generate_identity();
        let mut issuer2 = trust::Trust::new(root2.clone(), None);
        let mut tr = f.authority.lock().unwrap();
        tr.add_anchor(&root2.public_key_bytes()).unwrap();
        let node_rec2 = issuer2.issue(*root2.hash(), f.node_pk, trust::EXIT | trust::TRANSIT).unwrap();
        assert_eq!(tr.offer(node_rec2), trust::Offer::Added);
        let bystander = issuer2.issue(*root2.hash(), leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
        assert_eq!(tr.offer(bystander.clone()), trust::Offer::Added);
        (issuer2, bystander)
    }

    #[test]
    fn live_forward_server_with_transit_only_in_r_does_not_get_records_of_s() {
        let mut f = fixture(false);
        set_role(&f, false);
        let (_issuer2, s_rec) = add_second_root(&f);
        let r_rec = f.issuer.issue(f.root, leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
        offer(&f, &r_rec);
        let mut polls = 0;
        assert!(poll_rec(&f, false, &r_rec, &mut polls, Poll::Ready(true)) == Poll::Ready(true), "own root R stays visible");
        assert!(poll_rec(&f, false, &s_rec, &mut polls, Poll::Ready(true)) == Poll::Ready(false), "foreign root S is not pushed");
        assert_eq!(polls, 1, "the transport is never polled for the foreign record");
        // admission / server export uses the same projection
        let tr = f.authority.lock().unwrap();
        let admitted = tr.records_visible_to(&f.pk);
        assert!(admitted.contains(&r_rec) && !admitted.iter().any(|r| r.root == s_rec.root), "admission export carries no root S");
    }

    #[test]
    fn live_forward_server_with_transit_in_r_and_s_gets_both_roots() {
        let mut f = fixture(false);
        set_role(&f, false);
        let (mut issuer2, bystander) = add_second_root(&f);
        let root2 = bystander.root;
        // the peer is a TRANSIT member of S too
        let peer_rec2 = issuer2.issue(root2, f.pk, trust::USE | trust::TRANSIT).unwrap();
        offer(&f, &peer_rec2);
        let s_rec = issuer2.issue(root2, leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
        offer(&f, &s_rec);
        let r_rec = f.issuer.issue(f.root, leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
        offer(&f, &r_rec);
        let mut polls = 0;
        assert!(poll_rec(&f, false, &r_rec, &mut polls, Poll::Ready(true)) == Poll::Ready(true));
        assert!(poll_rec(&f, false, &s_rec, &mut polls, Poll::Ready(true)) == Poll::Ready(true), "mesh propagation in S is not broken");
        assert_eq!(polls, 2);
        let admitted = f.authority.lock().unwrap().records_visible_to(&f.pk);
        assert!(admitted.contains(&r_rec) && admitted.contains(&s_rec), "admission export carries both roots");
        // losing TRANSIT in S (signed downgrade) removes S, keeps R
        let down = issuer2.issue(root2, f.pk, trust::USE).unwrap();
        offer(&f, &down);
        let late = issuer2.issue(root2, leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
        offer(&f, &late);
        assert!(poll_rec(&f, false, &late, &mut polls, Poll::Ready(true)) == Poll::Ready(false));
        let r_late = f.issuer.issue(f.root, leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
        offer(&f, &r_late);
        assert!(poll_rec(&f, false, &r_late, &mut polls, Poll::Ready(true)) == Poll::Ready(true), "R is still served");
    }

    #[test]
    fn live_forward_requires_same_link_peer_and_role_at_every_poll() {
        for client in [true, false] {
            let mut f = fixture(client);
            set_role(&f, client);
            let sibling = f.issuer.issue(f.root, leviculum_std::api::generate_identity().public_key_bytes(), trust::USE).unwrap();
            offer(&f, &sibling);
            // A genuinely permitted record: Client needs ADD to see siblings.
            if client { let d = f.issuer.issue(f.root, f.pk, trust::USE | trust::ADD).unwrap(); offer(&f, &d); }
            let mut polls = 0;
            assert!(poll_rec(&f, client, &sibling, &mut polls, Poll::Pending).is_pending());
            assert_eq!(polls, 1);
            for change in 0..4 {
                let saved = f.links.lock().unwrap().get(&link()).map(|i| (i.peer_pk, i.enroll_only, i.want_use, match i.role {
                    Role::Client { id, ip } => Role::Client { id, ip }, Role::Server { dest } => Role::Server { dest }, _ => Role::Unknown }));
                {
                    let mut live = f.links.lock().unwrap();
                    let i = live.get_mut(&link()).unwrap();
                    match change {
                        0 => i.peer_pk = Some(leviculum_std::api::generate_identity().public_key_bytes()),
                        1 => i.role = Role::Unknown,
                        2 => i.enroll_only = true,
                        _ => { live.remove(&link()); }
                    }
                }
                assert!(poll_rec(&f, client, &sibling, &mut polls, Poll::Ready(true)) == Poll::Ready(false), "change {change}");
                assert_eq!(polls, 1, "change {change}: no commit after Link/peer/role change");
                let mut live = f.links.lock().unwrap();
                if change == 3 { live.insert(link(), LinkInfo { role: Role::Unknown, since: Instant::now(), last_heard: Instant::now(),
                    peer_pk: None, want_use: false, enroll_only: false, iface: None, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default(), diag: 0 }); }
                let i = live.get_mut(&link()).unwrap();
                let (pk, enroll, want, role) = saved.unwrap();
                i.peer_pk = pk; i.enroll_only = enroll; i.want_use = want; i.role = role;
            }
            assert!(poll_rec(&f, client, &sibling, &mut polls, Poll::Ready(true)) == Poll::Ready(true), "restored Link is eligible again");
        }
    }

    #[test]
    fn live_forward_policy_uses_current_projection() {
        // Server: a USE-only sibling policy is part of the full TRANSIT export only while TRANSIT holds.
        let mut f = fixture(false);
        set_role(&f, false);
        let holder = leviculum_std::api::generate_identity();
        let sibling = f.issuer.issue(f.root, holder.public_key_bytes(), trust::USE).unwrap();
        offer(&f, &sibling);
        let now = now_ms() as u64;
        let pol = trust::Policy::sign(&holder, f.root, trust::USE, now, now + 60_000).unwrap();
        assert_eq!(f.authority.lock().unwrap().offer_policy(pol.clone(), now), trust::Offer::Added);
        let gate = |f: &Fixture, client: bool, polls: &mut u32, result: Poll<bool>| poll_live_forward(&f.authority, &f.links, link(), &f.pk, kind(client),
            |tr| live_pol_allowed(tr, kind(client), &pol, &f.pk, now_ms() as u64), || { *polls += 1; result });
        let mut polls = 0;
        assert!(gate(&f, false, &mut polls, Poll::Pending).is_pending());
        let downgrade = f.issuer.issue(f.root, f.pk, trust::USE).unwrap();
        offer(&f, &downgrade);
        assert!(gate(&f, false, &mut polls, Poll::Ready(true)) == Poll::Ready(false));
        assert_eq!(polls, 1);

        // Client: an EXIT holder's policy is visible to USE peers until that holder stops being EXIT.
        let mut f = fixture(true);
        set_role(&f, true);
        let exit = leviculum_std::api::generate_identity();
        let exit_rec = f.issuer.issue(f.root, exit.public_key_bytes(), trust::EXIT).unwrap();
        offer(&f, &exit_rec);
        let pol = trust::Policy::sign(&exit, f.root, trust::EXIT, now, now + 60_000).unwrap();
        assert_eq!(f.authority.lock().unwrap().offer_policy(pol.clone(), now), trust::Offer::Added);
        let gate = |f: &Fixture, polls: &mut u32, result: Poll<bool>| poll_live_forward(&f.authority, &f.links, link(), &f.pk, OrdinaryAdmission::Client,
            |tr| live_pol_allowed(tr, OrdinaryAdmission::Client, &pol, &f.pk, now_ms() as u64), || { *polls += 1; result });
        let mut polls = 0;
        assert!(gate(&f, &mut polls, Poll::Pending).is_pending());
        let no_exit = f.issuer.issue(f.root, exit.public_key_bytes(), trust::USE).unwrap();
        offer(&f, &no_exit);
        assert!(gate(&f, &mut polls, Poll::Ready(true)) == Poll::Ready(false));
        assert_eq!(polls, 1);
    }

    /// Two accepted roots on one node. R: ADD-capable newcomer candidates, an EXIT holder, a USE sibling.
    /// S: its own exit and user. Returns (node trust, [rec_r_exit, rec_r_sibling, rec_s_exit, rec_s_user]).
    fn two_root_store(issuer_r: &mut trust::Trust, (root_r, pk_r): (trust::Hash, trust::Pk), issuer_s: &mut trust::Trust, (root_s, pk_s): (trust::Hash, trust::Pk))
        -> (trust::Trust, [trust::Record; 4]) {
        let ident = || leviculum_std::api::generate_identity();
        let r_exit = issuer_r.issue(root_r, ident().public_key_bytes(), trust::EXIT).unwrap();
        let r_sib = issuer_r.issue(root_r, ident().public_key_bytes(), trust::USE).unwrap();
        let s_exit = issuer_s.issue(root_s, ident().public_key_bytes(), trust::EXIT).unwrap();
        let s_user = issuer_s.issue(root_s, ident().public_key_bytes(), trust::USE | trust::ADD).unwrap();
        let mut node = trust::Trust::new(ident(), None);
        node.add_anchor(&pk_r).unwrap();
        node.add_anchor(&pk_s).unwrap();
        for r in [&r_exit, &r_sib, &s_exit, &s_user] { assert_eq!(node.offer((*r).clone()), trust::Offer::Added); }
        (node, [r_exit, r_sib, s_exit, s_user])
    }

    /// Enrollment export for a just-enrolled (or repeat-claimed) holder: its own chain first, then the
    /// rest of the root-scoped `records_visible_to` snapshot. Rights are derived per root from the
    /// CURRENT store, so ADD in root R never exports root S, and a USE-only holder gets only its own
    /// chain plus the EXIT chains of the roots in which it is a member. The record must already have
    /// been offered/issued into `tr`. The enrollment Link has no Client/Server role, so these sends stay
    /// on the plain control sender; the snapshot, not a rights scalar, is what bounds the disclosure.
    fn enrollment_export(tr: &trust::Trust, holder: &trust::Pk) -> (Vec<trust::Record>, Vec<trust::Record>) {
        let visible = tr.records_visible_to(holder);
        let chain: Vec<trust::Record> = tr.chain_for(holder).into_iter().filter(|r| visible.contains(r)).collect();
        let rest = visible.into_iter().filter(|r| !chain.contains(r)).collect();
        (chain, rest)
    }

    #[test]
    fn enrollment_export_is_root_scoped_for_add_and_use_newcomers() {
        let (root_r, root_s) = (leviculum_std::api::generate_identity(), leviculum_std::api::generate_identity());
        let (hr, hs) = (*root_r.hash(), *root_s.hash());
        let (pk_r, pk_s) = (root_r.public_key_bytes(), root_s.public_key_bytes());
        let mut issuer_r = trust::Trust::new(root_r, None);
        let mut issuer_s = trust::Trust::new(root_s, None);
        let (mut node, [r_exit, r_sib, s_exit, s_user]) = two_root_store(&mut issuer_r, (hr, pk_r), &mut issuer_s, (hs, pk_s));

        // ADD newcomer in R: everything in R, nothing from S (the legacy scalar export_for(ADD) leaked S).
        let adder = leviculum_std::api::generate_identity().public_key_bytes();
        let adder_rec = issuer_r.issue(hr, adder, trust::USE | trust::ADD).unwrap();
        assert_eq!(node.offer(adder_rec.clone()), trust::Offer::Added, "offered before the export is built");
        assert!(node.export_for(trust::ADD, &adder).contains(&s_exit), "documents the legacy cross-root leak");
        let (chain, rest) = enrollment_export(&node, &adder);
        assert!(chain == vec![adder_rec.clone()], "own chain first");
        assert!(rest.contains(&r_exit) && rest.contains(&r_sib), "ADD in R sees R");
        assert!(!rest.contains(&s_exit) && !rest.contains(&s_user) && !chain.contains(&s_exit), "ADD in R must not export root S");
        assert!(chain.iter().chain(rest.iter()).all(|r| r.root == hr));
        assert!(!rest.contains(&adder_rec), "no duplicate of the chain");

        // USE newcomer in R: own chain + EXIT chain of R only.
        let user = leviculum_std::api::generate_identity().public_key_bytes();
        let user_rec = issuer_r.issue(hr, user, trust::USE).unwrap();
        assert_eq!(node.offer(user_rec.clone()), trust::Offer::Added);
        let (chain, rest) = enrollment_export(&node, &user);
        assert!(chain == vec![user_rec.clone()]);
        assert!(rest == vec![r_exit.clone()], "USE newcomer: EXIT chain of its own root and nothing else");
        assert!(!rest.contains(&r_sib) && !rest.contains(&adder_rec) && !rest.contains(&s_exit) && !rest.contains(&s_user));

        // The rights=0 holder keeps only its own revoke (nothing from siblings or other roots).
        let revoke = issuer_r.issue(hr, user, 0).unwrap();
        assert_eq!(node.offer(revoke.clone()), trust::Offer::Added);
        let (chain, rest) = enrollment_export(&node, &user);
        assert!(chain == vec![revoke] && rest.is_empty());
    }
}

impl NodeCtx {
    /// Revalidate on EACH poll, including after channel-window/backpressure waits. There is no
    /// Trust/links guard across an await: send's synchronous commit+enqueue occurs inside poll.
    /// The driver core emits events through queues; it does not call back into NodeCtx/Trust.
    async fn send_admitted_ctl(self: &Arc<Self>, link: LinkId, pk: &trust::Pk, kind: OrdinaryAdmission, ty: u8, body: &[u8]) -> bool {
        let Some(t) = &self.t13 else { return false };
        let mut message = Vec::with_capacity(1 + body.len());
        message.push(ty);
        message.extend_from_slice(body);
        let handle = self.node.engine().link_handle(&link);
        let sending = handle.send(&message);
        tokio::pin!(sending);
        let result = std::future::poll_fn(|cx| {
            poll_authorized_link(&t.trust, &self.links, link, pk, kind, |_tr| {
                sending.as_mut().poll(cx).map(|r| r.is_ok())
            })
        }).await;
        result == Some(true)
    }

    /// Первичная постановка live push требует прежнего Link/ключа/роли. Затем
    /// LXMF адресует identity независимо от этого Link; процессор повторно
    /// проверяет видимость перед enqueue/retry и отменяет запрещённую очередь.
    async fn send_live_sync(self: &Arc<Self>, link: LinkId, pk: &trust::Pk, kind: OrdinaryAdmission, recs: Vec<trust::Record>, pols: Vec<trust::Policy>,
        allowed: impl Fn(&trust::Trust, u64) -> bool) -> bool {
        let Some(t) = &self.t13 else { return false };
        let sent = std::future::poll_fn(|cx| {
            let _ = cx;
            poll_live_forward(&t.trust, &self.links, link, pk, kind, |tr| allowed(tr, now_ms() as u64),
                || Poll::Ready(lxmf_sync::queue(&self.state, t.trust.clone(), *pk, recs.clone(), pols.clone())))
        }).await;
        sent
    }

    fn send_admitted_records(self: &Arc<Self>, link: LinkId, pk: trust::Pk, kind: OrdinaryAdmission) {
        let Some(t) = &self.t13 else { return };
        let Some((recs, pols)) = with_authorized_link(&t.trust, &self.links, link, &pk, kind, false, |tr, _| {
            match kind {
                // root-scoped as well: TRANSIT in root R gives all of R (and of every other root where the peer holds rights), never a foreign root
                OrdinaryAdmission::Server => (tr.records_visible_to(&pk), tr.export_policies_for(trust::TRANSIT, &pk, now_ms() as u64).into_iter().filter(|p| lxmf_sync::policy_visible(tr, p, &pk)).collect()),
                OrdinaryAdmission::Client => (tr.records_visible_to(&pk), tr.export_policies_for(trust::USE, &pk, now_ms() as u64).into_iter().filter(|p| lxmf_sync::policy_visible(tr, p, &pk)).collect()),
            }
        }) else { return };
        lxmf_sync::queue(&self.state, t.trust.clone(), pk, recs, pols);
    }

    /// (нужен ли сосед, наша ли очередь открывать Link). Нужны: админ приглашения (открываем мы), соседи-транзиты по записям
    /// (открывает меньший dest) и кандидаты на зачисление (только несём носитель QUIC: Link откроет сам приглашённый).
    fn neighbor_policy(&self, d: &[u8; 16]) -> (bool, bool) {
        let Some((pk, accepts)) = self.neigh.lock().unwrap().get(d).map(|n| (n.pk, n.accepts_links)) else { return (false, false) };
        let Some(t) = &self.t13 else { return (false, false) };
        let tr = t.trust.lock().unwrap();
        let transit = tr.common_with(&pk, trust::TRANSIT, trust::TRANSIT, true, true, now_ms() as u64);
        let wanted = plan_transit_neighbor(accepts, transit);
        (wanted, wanted && (self.my_dest < *d || self.adv().is_empty()))
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
        let Some(t) = &self.t13 else { return };
        let Some(pk) = peer_of(self, &link) else { return };
        lxmf_sync::queue(&self.state, t.trust.clone(), pk, recs, pols);
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

    /// Посредник (R6): каталог нод новичку или соседу - соседи с правом TRANSIT и адресом, не более DIR_MAX записей, одним LXMF-сообщением.
    /// Не чаще раза в 60 с на Link (инвариант 6). Адреса - подсказки: допуск по-прежнему по записям.
    fn send_dir(self: &Arc<Self>, link: LinkId) {
        let server = self.links.lock().unwrap().get(&link)
            .filter(|i| matches!(i.role, Role::Server { .. })).and_then(|i| i.peer_pk);
        self.send_dir_checked(link, server);
    }

    /// Полный каталог доступной сети и проверяемые цепочки её выходов. Работает и без enrollment/живого Link: LXMF доставит ответ.
    /// Подсказки не дают USE на другие scope. Корни, в которых адресат не участник, в ответ не попадают.
    fn send_member_directory(self: &Arc<Self>, pk: trust::Pk) -> bool {
        let Some(t) = &self.t13 else { return false };
        let (list, records, snapshot_roots) = {
            let tr = t.trust.lock().unwrap();
            let roots = directory_roots(&tr, &pk, now_ms() as u64);
            if roots.is_empty() { return false; }
            {
                let mut sent = t.dir_requested.lock().unwrap();
                sent.retain(|_, at| at.elapsed() < Duration::from_secs(60));
                // Не подтверждаем запрос без ответа: LXMF повторит его после окна лимита, иначе ручное обновление сразу после admission теряется.
                if sent.contains_key(&pk) { return false; }
                if sent.len() >= 256 { return false; }
                sent.insert(pk, Instant::now());
            }
            let mut list = vec![];
            let mine = self.adv();
            if !mine.is_empty() {
                list.push(serde_json::json!({"d":hex(&self.my_dest),"k":hex(&self.my_pk),"e":self.ep_id,"a":mine,"n":self.name,"pl":platform()}));
            }
            let n = self.neigh.lock().unwrap();
            list.extend(n.values().filter(|nb| !nb.addrs.is_empty() && directory_node_visible(&tr, &roots, &nb.pk))
                .take(DIR_MAX - list.len()).map(|nb| serde_json::json!({"d":hex(&nb.dest),"k":hex(&nb.pk),"e":nb.ep,
                    "a":nb.addrs.get().into_iter().take(3).collect::<Vec<_>>(),"n":nb.name})));
            (list, tr.records_visible_to(&pk), roots)
        };
        let me = Arc::downgrade(self);
        let gate: lxmf_sync::Gate = Arc::new(move || {
            let ctx = me.upgrade()?;
            let t = ctx.t13.as_ref()?;
            let tr = match t.trust.try_lock() {
                Ok(tr) => tr,
                Err(std::sync::TryLockError::WouldBlock) => return None,
                Err(_) => return Some(false),
            };
            let roots = directory_roots(&tr, &pk, now_ms() as u64);
            // Не отправляем старый снимок утраченного root, даже если адресат остался участником другого root.
            Some(snapshot_roots.iter().all(|r| roots.contains(r)))
        });
        let sent = !list.is_empty() && lxmf_sync::send_dir(&self.state, pk, list, gate);
        let recs_sent = records.is_empty() || lxmf_sync::queue(&self.state, t.trust.clone(), pk, records, vec![]);
        if !sent || !recs_sent { t.dir_requested.lock().unwrap().remove(&pk); }
        sent && recs_sent
    }

    /// Адресат каталога допустим, пока он: живой Link (новичок или сосед-сервер), админ ожидающего приглашения или ключ с эффективным TRANSIT.
    /// Без ожидания mutex (None - повторить позже); слабая ссылка не удерживает узел.
    fn dir_gate(self: &Arc<Self>, pk: trust::Pk) -> lxmf_sync::Gate {
        let me = Arc::downgrade(self);
        Arc::new(move || {
            use std::sync::TryLockError::WouldBlock;
            let ctx = me.upgrade()?;
            let Some(t) = &ctx.t13 else { return Some(false) };
            let tr = match t.trust.try_lock() { Ok(g) => g, Err(WouldBlock) => return None, Err(_) => return Some(false) };
            let links = match ctx.links.try_lock() { Ok(g) => g, Err(WouldBlock) => return None, Err(_) => return Some(false) };
            Some(dir_recipient_ok(&links, None, &tr, &pk, now_ms() as u64))
        })
    }

    /// Server callers retain the expected identity even after close: never fall back to the
    /// enrollment directory path merely because the Server Link disappeared while queued.
    fn send_dir_checked(self: &Arc<Self>, link: LinkId, expected_server: Option<trust::Pk>) {
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
        let build = |tr: &trust::Trust| {
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
        let (pk, list) = if let Some(pk) = expected_server {
            let Some(list) = with_authorized_link(&t.trust, &self.links, link, &pk, OrdinaryAdmission::Server, false, |tr, _| build(tr)) else { return };
            (pk, list)
        } else {
            let Some(pk) = peer_of(self, &link) else { return };
            (pk, build(&t.trust.lock().unwrap()))
        };
        if !list.is_empty() {
            lxmf_sync::send_dir(&self.state, pk, list, self.dir_gate(pk));
        }
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

    /// Соседям-серверам и клиентам - root-scoped выгрузка по их действующим правам в корне записи: TRANSIT в корне R даёт весь R,
    /// но не записи корня, где у соседа прав нет. Клиентская роль сама по себе не делает администратора USE-only и не объединяет права
    /// разных корней. Видимость проверяется при постановке и перед LXMF enqueue/retry.
    fn forward_rec(self: &Arc<Self>, rec: &trust::Record, except: Option<LinkId>) {
        let Some(t) = &self.t13 else { return };
        let targets = live_forward_targets(&self.links, except);
        if targets.is_empty() {
            return;
        }
        let send: Vec<_> = {
            let tr = t.trust.lock().unwrap();
            targets.into_iter().filter(|(_, pk, _)| live_rec_allowed(&tr, rec, pk)).collect()
        };
        for (l, pk, kind) in send {
            let (ctx, rec) = (self.clone(), rec.clone());
            tokio::spawn(async move {
                ctx.send_live_sync(l, &pk, kind, vec![rec.clone()], vec![], |tr, _now| live_rec_allowed(tr, &rec, &pk)).await;
            });
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
        let targets = live_forward_targets(&self.links, except);
        if targets.is_empty() {
            return;
        }
        let now = now_ms() as u64;
        let send: Vec<_> = {
            let tr = t.trust.lock().unwrap();
            targets.into_iter().filter(|(_, pk, kind)| live_pol_allowed(&tr, *kind, pol, pk, now)).collect()
        };
        for (l, pk, kind) in send {
            let (ctx, pol) = (self.clone(), pol.clone());
            tokio::spawn(async move {
                ctx.send_live_sync(l, &pk, kind, vec![], vec![pol.clone()], |tr, now| live_pol_allowed(tr, kind, &pol, &pk, now)).await;
            });
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
        crate::host_acl::notify_nft();
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
            };
            (pk, kind, i.want_use, i.enroll_only)
        };
        if enroll_only {
            // Link никогда не станет клиентом: сообщаем об этом пришедшему за выходом, а не оставляем его ждать таймаут
            if kind == 0 && want_use {
                self.admit_diag(link, &pk, AdmitDiag::EnrollOnly);
            }
            return;
        }
        // 0015: своё согласие (политика) учитывается, чужие права - по выдаче (чужой отказ исполняет он сам)
        let now = now_ms() as u64;
        let ((srv_ok, cli_ok, cli_granted), _) = publish_host_access_decision(&t.trust, &pk, |tr| {
            (tr.common_with(&pk, trust::TRANSIT, trust::TRANSIT, true, false, now), tr.common_with(&pk, trust::EXIT, trust::USE, true, false, now),
             tr.common(&pk, trust::EXIT, trust::USE))
        }, |host_ok| {
            // The Trust guard still covers the setter; close/admission below run after it drops.
            if kind == 2 {
                if let Some(tun) = &self.tun { return tun.set_host_access(&link, host_ok); }
            }
            true
        });
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
                            c.send_recs_pols(link, vec![], pols);
                            send_ctl(&c.node, link, T_AUTH_FAIL, b"exit disabled by node policy").await;
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            c.close_link(link, "политика ноды: выход выключен");
                        });
                    } else {
                        // ни права USE у пира с EXIT у нас в общем корне, ни выданного права: возможно, цепочка ещё в пути
                        self.no_chain_watch(link, pk);
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
        // Core/public-interface lookup happens before taking Trust/links.
        if self.link_is_public(&link) {
            self.close_link(link, "link через публичную сеть");
            return;
        }
        let dest = dest_of_pub(self, &pk);
        let Some(duplicate) = promote_server_link(&t.trust, &self.links, &self.neigh, link, &pk, dest) else { return };
        if let Some(drop_id) = duplicate {
            self.close_link(drop_id, "дубликат либо отказ от серверного Link");
            if drop_id == link { return; }
        }
        self.sh.note(format!("сосед {} допущен (права транзита подтверждены записями)", name_of(self, &dest)));
        self.send_admitted_records(link, pk, OrdinaryAdmission::Server);
        self.send_dir_checked(link, Some(pk));
        // Пир мог принять каталог раньше, чем присвоил Link роль Server (записи ещё обрабатываются): повтор через 5 с, помимо лимита 60 с
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Some(t) = &me.t13 {
                t.dir_sent.lock().unwrap().remove(&link);
            }
            me.send_dir_checked(link, Some(pk));
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
        let ids: Vec<(LinkId, trust::Pk)> = self.links.lock().unwrap().iter().filter(|(_, l)| matches!(l.role, Role::Server { .. })).filter_map(|(k, l)| l.peer_pk.map(|pk| (*k, pk))).collect();
        for (l, pk) in ids {
            self.send_dir_checked(l, Some(pk));
        }
        let clients: Vec<_> = self.links.lock().unwrap().values()
            .filter(|l| matches!(l.role, Role::Client { .. })).filter_map(|l| l.peer_pk).collect();
        for pk in clients { self.send_member_directory(pk); }
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
        // Constructing a handle touches the driver's completion registry; keep that outside
        // the authority transaction. The allow half below only touches the TUN tables.
        let handle = Arc::new(self.node.engine().link_handle(&link));
        let result = promote_client_link(&t.trust, &self.links, link, &pk, |ip, host_ok, replaces| {
            match admission_outcome(tun.allow_replacing_with_handle(link, ip, handle, replaces)) {
                AdmitOutcome::Refuse { reason, note } => Err(AdmitOutcome::Refuse { reason, note }),
                AdmitOutcome::SendAuthOk if tun.set_host_access(&link, host_ok) => Ok(()),
                _ => Err(AdmitOutcome::Refuse { reason: b"admission failed", note: "допуск в TUN не завершён" }),
            }
        });
        let admission = match result {
            Some(Ok(a)) => a,
            Some(Err(AdmitOutcome::Refuse { reason, note })) => {
                spawn_ctl(&self.node, link, T_AUTH_FAIL, reason.to_vec());
                self.close_link(link, note);
                return;
            }
            _ => {
                // no current ordinary permission/live eligible Link: no allow, no AUTH_OK.
                // Ответ и запись - только если Link жив и так и не допущен; проигравший гонку с параллельным допуском молчит.
                if client_awaiting_admission(&self.links, link, &pk) {
                    self.admit_diag(link, &pk, AdmitDiag::NotAuthorized);
                }
                return;
            }
        };
        for o in admission.replaced {
            self.close_link(o, "новый Link той же identity");
        }
        crate::host_acl::notify_nft();
        let (idh, ip) = (admission.id, admission.ip);
        let pl = self.client_info.lock().unwrap().get(&link).map(|(_, p)| *p).unwrap_or("?");
        self.sh.note(format!("client {} ({pl}) admitted on {}", &hex(&idh)[..8], &hex(link.as_bytes())[..8]));
        self.node.engine().set_link_keepalive(&link, Some(CLIENT_KEEPALIVE_S));
        let ok = serde_json::json!({"name": self.name, "ip": ip_str(ip), "cc": REGION.get().cloned().unwrap_or_default(), "pl": platform()}).to_string().into_bytes();
        let c = self.clone();
        tokio::spawn(async move {
            if !c.send_admitted_ctl(link, &pk, OrdinaryAdmission::Client, T_AUTH_OK, &ok).await { return; }
            // новому клиенту соседей шлём всегда (0014 R3)
            c.send_nbrs(link);
            c.send_admitted_records(link, pk, OrdinaryAdmission::Client);
            c.send_member_directory(pk);
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
                    if !self.save_trust() { continue; }
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

/// Запись каталога: подсказка адреса (недоверенная). Допуск - только по записям о правах.
struct DirEnt {
    dest: [u8; 16],
    pk: [u8; 64],
    ep: String,
    addrs: Vec<String>,
    name: String,
    /// тип платформы узла («android»/«ios»/«server») - для значка в интерфейсе
    pl: Option<String>,
}

/// Разбор каталога: не более DIR_MAX записей; dest обязан совпасть с ключом (тег `tag`); без адресов запись бесполезна.
#[cfg(test)]
fn parse_dir(body: &[u8], tag: &str) -> Vec<DirEnt> {
    parse_dir_max(body, tag, DIR_MAX)
}

fn parse_dir_max(body: &[u8], tag: &str, max: usize) -> Vec<DirEnt> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else { return vec![] };
    parse_dir_values(v["n"].as_array().map(Vec::as_slice).unwrap_or_default(), tag, max)
}

fn parse_dir_values(arr: &[serde_json::Value], tag: &str, max: usize) -> Vec<DirEnt> {
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

/// Узел принимает каталог от `sender`, если тот: допущенный сосед-сервер, ответчик нашей просьбы о зачислении, админ ожидающего приглашения
/// или ключ с эффективным TRANSIT. Подпись LXMF лишь опознаёт ключ; права и роли берутся из Trust и таблицы Link.
fn dir_sender_ok(links: &HashMap<LinkId, LinkInfo>, pair_sent: &HashSet<LinkId>, admin: Option<trust::Pk>, tr: &trust::Trust, sender: &trust::Pk, now: u64) -> bool {
    links.iter().any(|(k, l)| l.peer_pk == Some(*sender) && (matches!(l.role, Role::Server { .. }) || pair_sent.contains(k)))
        || admin == Some(*sender)
        || tr.effective(sender, now) & trust::TRANSIT != 0
}

/// Каталог ещё нужен адресату `pk`: у него живой Link (новичок или сосед-сервер), он админ ожидающего приглашения или имеет эффективный TRANSIT.
fn dir_recipient_ok(links: &HashMap<LinkId, LinkInfo>, admin: Option<trust::Pk>, tr: &trust::Trust, pk: &trust::Pk, now: u64) -> bool {
    links.values().any(|l| l.peer_pk == Some(*pk) && matches!(l.role, Role::Unknown | Role::Server { .. }))
        || admin == Some(*pk)
        || tr.effective(pk, now) & trust::TRANSIT != 0
}

/// Root-local membership, including an EnRec valid on THIS node. Identity ownership, foreign-root rights and an address hint are not membership.
fn directory_roots(tr: &trust::Trust, peer: &trust::Pk, now: u64) -> Vec<trust::Hash> {
    let Some(h) = trust::hash_of(peer) else { return vec![] };
    tr.anchors().into_iter().filter_map(|(root, _)| {
        let mine = tr.effective_in(&root, &tr.me_hash, now);
        (mine & (trust::EXIT | trust::TRANSIT) != 0 && tr.rights_at(&root, &h, &tr.me_hash) != 0).then_some(root)
    }).collect()
}

fn directory_node_visible(tr: &trust::Trust, roots: &[trust::Hash], pk: &trust::Pk) -> bool {
    trust::hash_of(pk).is_some_and(|h| roots.iter().any(|root| tr.rights_in(root, &h) & (trust::EXIT | trust::TRANSIT) != 0))
}

/// Каталог от посредника зачисления (R6), админа приглашения или соседа: адреса нод - подсказки для диалера.
/// Отправитель опознан по ключу LXMF-подписи (`source_key`); подпись не право, поэтому нужно ещё одно из: роль Server (взаимный TRANSIT),
/// Link, через который сами просимся, админ ожидающего приглашения или эффективный TRANSIT в записях. Истина - `true`, если адресата можно подтвердить.
fn on_dir_node(ctx: &Arc<NodeCtx>, sender: trust::Pk, dir: &[serde_json::Value]) -> bool {
    let Some(t) = &ctx.t13 else { return false };
    let allowed = {
        // порядок блокировок: Trust -> links; pair_sent и invite - листовые
        let tr = t.trust.lock().unwrap();
        let links = ctx.links.lock().unwrap();
        let sent = HashSet::new();
        let admin = None;
        dir_sender_ok(&links, &sent, admin, &tr, &sender, now_ms() as u64)
    };
    if !allowed {
        return false;
    }
    for e in parse_dir_values(dir, &ctx.tag, DIR_MAX) {
        if e.pk == ctx.my_pk {
            continue;
        }
        // S2/S3: каталог не занимает место защищённых соседей (см. neighbor_room)
        {
            let mut n = ctx.neigh.lock().unwrap();
            if let Some(nb) = n.get_mut(&e.dest) {
                // адрес ноды, пришедший от неё самой, актуальнее прежнего; о третьих лицах - только если своего нет
                let own = sender == e.pk;
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
    true
}

/// Пир доказал свой ключ (identify): предъявляем свою цепочку прав, при ожидающем приглашении просимся к его админу, оцениваем роль.
fn on_peer_ready(ctx: &Arc<NodeCtx>, link: LinkId, pk: [u8; 64]) {
    let Some(t) = &ctx.t13 else { return };
    if let Some(i) = ctx.links.lock().unwrap().get_mut(&link) { i.peer_pk = Some(pk); }
    lxmf_sync::queue_proof(&ctx.state, t.trust.clone(), ctx.my_pk, pk);
    if let Some(s) = enroll_net::find(&ctx.state) { s.send_proofs(pk); }
    ctx.evaluate(link);
}

/// LXMF sync принимается только после независимой проверки source-подписи.
/// Владение ключом не даёт прав: записи и политики по-прежнему проверяет Trust.
fn on_sync_node(ctx: &Arc<NodeCtx>, message: &leviculum_lxmf::Message) {
    let Some(wire) = lxmf_sync::Wire::decode(message) else { return };
    let Some(t) = &ctx.t13 else { return };
    let peers: Vec<_> = ctx.links.lock().unwrap().values().filter_map(|l| l.peer_pk).collect();
    let invited = None;
    let pk = lxmf_sync::source_key(message, &t.trust.lock().unwrap(), peers, invited);
    let Some(pk) = pk.filter(|pk| lxmf_sync::authenticated(message, &ctx.my_id, pk)) else { return };
    lxmf_sync::RX_BYTES.fetch_add(message.pack().len() as u64, Relaxed);
    lxmf_sync::RX_MESSAGES.fetch_add(1, Relaxed);
    if let Some(digest) = wire.ack { lxmf_sync::received_ack(&ctx.state, message.source_hash, digest); return; }
    if wire.get_dir {
        if ctx.send_member_directory(pk) { lxmf_sync::acknowledge(&ctx.state, message, pk); }
        return;
    }
    if !wire.dir.is_empty() {
        if message.content.len() <= lxmf_admin::MAX_ADMIN_CONTENT && on_dir_node(ctx, pk, &wire.dir) { lxmf_sync::acknowledge(&ctx.state, message, pk); }
        return;
    }
    let Some((recs, pols)) = lxmf_sync::parsed(&wire) else { return };
    let link = ctx.links.lock().unwrap().iter().find(|(_, l)| l.peer_pk == Some(pk)).map(|(l, _)| *l)
        .unwrap_or_else(|| LinkId::new(*lxmf_sync::public_identity(&pk).unwrap().hash()));
    // LXMF может переставить разные Resources: повтор до фиксированной точки,
    // максимум 16 записей в одной пачке; неизвестный issuer не получает ACK.
    for _ in 0..recs.len().max(1) { for rec in &recs { on_rec(ctx, link, &rec.wire()); } }
    for pol in &pols { on_pol(ctx, link, &pol.wire()); }
    let durable = {
        let mut tr = t.trust.lock().unwrap();
        recs.iter().all(|r| !matches!(tr.offer(r.clone()), trust::Offer::Rejected(_)))
            && pols.iter().all(|p| !matches!(tr.offer_policy(p.clone(), now_ms() as u64), trust::Offer::Rejected(_)))
            && tr.save().is_ok()
    };
    if durable { lxmf_sync::acknowledge(&ctx.state, message, pk); }
}

fn on_sync_client(ctx: &Arc<ClientCtx>, message: &leviculum_lxmf::Message) {
    let Some(wire) = lxmf_sync::Wire::decode(message) else { return };
    let Some(c) = &ctx.c13 else { return };
    // зачисляемая нода тоже присылает админу каталог (с собственным адресом), поэтому её ключ - допустимый отправитель подписи
    let mut peers: Vec<_> = c.peers.lock().unwrap().values().copied().collect();
    peers.extend(c.enrollees.lock().unwrap().values().copied());
    let invited = None;
    let pk = lxmf_sync::source_key(message, &c.trust.lock().unwrap(), peers, invited);
    let Some(pk) = pk.filter(|pk| lxmf_sync::authenticated(message, ctx.identity.hash(), pk)) else { return };
    lxmf_sync::RX_BYTES.fetch_add(message.pack().len() as u64, Relaxed);
    lxmf_sync::RX_MESSAGES.fetch_add(1, Relaxed);
    if let Some(digest) = wire.ack { lxmf_sync::received_ack(&ctx.state, message.source_hash, digest); return; }
    if wire.get_dir { return; } // телефон не выдаёт сетевой каталог и не является транзитным сервером
    if !wire.dir.is_empty() {
        if message.content.len() <= lxmf_admin::MAX_ADMIN_CONTENT && on_dir_client(ctx, pk, &wire.dir) { lxmf_sync::acknowledge(&ctx.state, message, pk); }
        return;
    }
    let Some((recs, pols)) = lxmf_sync::parsed(&wire) else { return };
    let link = c.peers.lock().unwrap().iter().find(|(_, p)| **p == pk).map(|(l, _)| *l)
        .unwrap_or_else(|| LinkId::new(*lxmf_sync::public_identity(&pk).unwrap().hash()));
    for _ in 0..recs.len().max(1) { for rec in &recs { on_rec_client(ctx, link, &rec.wire()); } }
    for pol in &pols { on_pol_client(ctx, link, &pol.wire()); }
    let durable = {
        let mut tr = c.trust.lock().unwrap();
        recs.iter().all(|r| !matches!(tr.offer(r.clone()), trust::Offer::Rejected(_)))
            && pols.iter().all(|p| !matches!(tr.offer_policy(p.clone(), now_ms() as u64), trust::Offer::Rejected(_)))
            && tr.save().is_ok()
    };
    if durable { lxmf_sync::acknowledge(&ctx.state, message, pk); }
}

/// Политику принимает LXMF worker. Проверки - в `Trust::offer_policy`; число политик ограничено числом
/// держателей с выдачей, частота - ведром `CtrlBucket`.
fn on_pol(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    POL_RX.fetch_add(body.len() as u64, Relaxed);
    POL_RX_N.fetch_add(1, Relaxed);
    if ctx.t13.is_none() || body.len() != trust::POL_LEN {
        return;
    }
    let Some(pol) = trust::Policy::parse(body) else { return };
    if let trust::Offer::Rejected(why) = ctx.accept_pol(pol, Some(link)) {
        ctx.sh.note(format!("политика отклонена: {why}"));
    }
}

fn on_rec(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    let Some(rec) = trust::Record::parse(body) else { return };
    if ctx.accept_rec(rec.clone(), Some(link)) == trust::Offer::Added { ctx.to_newcomer(&rec); }
    ctx.evaluate(link);
}


async fn node_housekeeping(ctx: Arc<NodeCtx>) {
    let mut tick = 0u64;
    let mut lost_listener = 0u32;
    let mut last_ping = Instant::now();
    let mut last_table = Instant::now();
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
                }
            }
        }

        // неавторизованные Link не живут дольше срока (в модели 0013 обмен цепочками и зачисление дольше - окно шире)
        let deadline = if ctx.t13.is_some() { Duration::from_secs(30) } else { UNAUTH_TIMEOUT };
        let stale: Vec<LinkId> = ctx.links.lock().unwrap().iter()
            .filter(|(id, l)| !matches!(l.role, Role::Server { .. } | Role::Client { .. }) && now.duration_since(l.since) > deadline && !enroll_net::session_live(&ctx.state, id)).map(|(k, _)| *k).collect();
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

        // соседи в файл (диагностика)
        if now.duration_since(last_table) >= Duration::from_secs(2) {
            last_table = now;
            let t = ctx.table();
            // диагностика, не состояние: из отдельного потока и редко (W48). Проверка свежести деплоя требует ts не старше 10 с
            crate::bgwrite::put(&ctx.state.join("neighbors.json"), t.to_string().into_bytes(), Duration::from_secs(5));
            let n_clients = ctx.links.lock().unwrap().values().filter(|l| matches!(l.role, Role::Client { .. })).count();
            // Только допущенные соседи, без адресов: Link может работать по старому
            // интерфейсу, пока таблица RNS уже выбрала для новых Link другой путь.
            let private_ifaces = own_carrier_ifaces(&ctx.node);
            let ifaces = ctx.node.engine().interface_stats();
            let vpn_paths: Vec<serde_json::Value> = ctx.neigh.lock().unwrap().values().filter(|n| n.link.is_some()).take(64).map(|n| {
                let p = ctx.node.engine().get_path_clone(&DestinationHash::new(n.dest));
                serde_json::json!({"d": hex(&n.dest), "n": n.name, "h": p.as_ref().map(|p| p.hops),
                    "iface": p.as_ref().and_then(|p| ifaces.iter().find(|i| i.interface_id.0 == p.interface_index).map(|i| i.name.clone())),
                    "private": p.as_ref().map(|p| private_ifaces.contains(&p.interface_index)),
                    "nh": p.and_then(|p| p.next_hop).map(|h| hex(&h))})
            }).collect();
            let st = serde_json::json!({"uptime_s": ctx.started.elapsed().as_secs(), "links": ctx.links.lock().unwrap().len(), "vpn_paths": vpn_paths,
                "clients": n_clients, "tun": ctx.tun.as_ref().map(|t| t.stats()),
                "pol": pol_counters(),
                "policy": ctx.t13.as_ref().map(|t| policy_status(&t.trust.lock().unwrap(), now_ms() as u64))});
            crate::bgwrite::put(&ctx.state.join("status.json"), st.to_string().into_bytes(), Duration::from_secs(20));
        }
    }
}

// ------------------------------------------------------------------------------------------------ хаб

pub async fn run_hub(a: HubArgs) -> Result<()> {
    let hub_id = load_or_create_identity(&a.state)?;
    let key = iroh_key_from_identity(&hub_id)?;
    let b = start_base("h", &a.state, true, Some(a.port), key, None, 500, &[], Some(a.tcp_port), &[]).await?;
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
const LOCAL_INBOX_LIMIT: usize = 256;
const CLIENT_INBOX_BATCH: usize = 16;

/// The directory is local control state, not an alternate network trust input.
/// Serialize CLI writers and maintenance without a lockfile containing identity data.
fn open_local_inbox(state: &Path, create: bool) -> Result<std::fs::File> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    let dir = state.join("inbox13");
    if create {
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => return Err(e.into()),
        }
    }
    let f = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC).open(&dir)?;
    let meta = f.metadata()?;
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() || (meta.uid() != euid && meta.uid() != 0) {
        bail!("inbox13: invalid directory owner/type");
    }
    // Upgrade an existing CLI-owned legacy directory; the consumer never relaxes permissions.
    if create { f.set_permissions(std::fs::Permissions::from_mode(0o700))?; }
    if f.metadata()?.mode() & 0o077 != 0 { bail!("inbox13: directory is not private"); }
    Ok(f)
}

fn lock_local_inbox(dir: &std::fs::File, nonblocking: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(dir.as_raw_fd(), flags) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(()) // File close releases flock, including error/unwind paths.
}

fn local_inbox_paths(state: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for e in std::fs::read_dir(state.join("inbox13"))?.take(LOCAL_INBOX_LIMIT + 1) {
        paths.push(e?.path());
    }
    if paths.len() > LOCAL_INBOX_LIMIT { bail!("inbox13: directory limit exceeded; records retained"); }
    Ok(paths)
}

fn put_inbox13(state: &Path, rec: &trust::Record) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let locked = open_local_inbox(state, true)?;
    lock_local_inbox(&locked, false)?;
    if local_inbox_paths(state)?.len() >= LOCAL_INBOX_LIMIT {
        bail!("inbox13: queue full; existing records retained");
    }
    let dir = state.join("inbox13");
    let name = format!("{}-{:016x}", now_ms(), rand_core::OsRng.next_u64());
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp)?;
    f.write_all(hex(&rec.wire()).as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, dir.join(format!("{name}.rec")))?;
    locked.sync_all()?;
    Ok(())
}

fn read_local_inbox_record(path: &Path) -> Result<trust::Record> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    let m = f.metadata()?;
    let euid = unsafe { libc::geteuid() };
    let max = (trust::REC_LEN * 2 + 2) as u64;
    if !m.is_file() || m.len() > max || m.mode() & 0o077 != 0 || (m.uid() != euid && m.uid() != 0) {
        bail!("inbox13: invalid record file");
    }
    let mut text = String::new();
    f.take(max + 1).read_to_string(&mut text)?;
    if text.len() as u64 > max { bail!("inbox13: oversized record"); }
    let text = text.trim();
    if text.len() != trust::REC_LEN * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("inbox13: malformed record");
    }
    trust::Record::parse(&unhex(text)).ok_or_else(|| anyhow::anyhow!("inbox13: malformed record"))
}

fn reject_local_inbox_record(path: &Path) -> Result<()> {
    // Unlike rename-over-existing, this never destroys earlier rejection evidence.
    std::fs::hard_link(path, path.with_extension("rejected"))?;
    std::fs::remove_file(path)?;
    Ok(())
}

#[derive(Default)]
struct ClientInboxStats { changed: bool, committed: usize, sent: usize, rejected: usize, retained: usize, save_failed: bool }

#[derive(Default)]
struct ClientInboxProgress { durable: HashSet<Vec<u8>>, cursor: usize }

fn local_record_authorized(tr: &trust::Trust, rec: &trust::Record) -> bool {
    // Only this state's CLI issues local work. Peer-signed records use on_rec_client.
    let mine = tr.my_rights_in(&rec.root);
    let need = if rec.rights == 0 { trust::REMOVE } else { trust::ADD };
    rec.issuer == tr.me_hash && tr.has_anchor(&rec.root) && mine & need != 0
        && rec.rights & !mine == 0
        && tr.depth_in(&rec.root, &rec.issuer).is_some_and(|d| (d as usize) < trust::MAX_DEPTH)
}

fn local_record_exit_authorized(tr: &trust::Trust, rec: &trust::Record, peer: Option<&trust::Pk>) -> bool {
    peer.and_then(trust::hash_of).is_some_and(|h|
        tr.my_rights_in(&rec.root) & trust::USE != 0
        && tr.effective_in(&rec.root, &h, now_ms() as u64) & trust::EXIT != 0)
}

/// Actual client consumer, also exercised with injected I/O/transport in narrow tests.
/// Caller holds live Trust, not a CLI-loaded copy. A successful save precedes every
/// send/dequeue. No remote ACK is implied; reconnect exports the current signed store.
fn client_inbox_step(
    state: &Path, tr: &mut trust::Trust, progress: &mut ClientInboxProgress, peer: Option<&trust::Pk>,
    save: impl FnOnce(&trust::Trust) -> Result<()>, mut publish: impl FnMut(&trust::Record) -> bool,
) -> Result<ClientInboxStats> {
    let mut stats = ClientInboxStats::default();
    let locked = match open_local_inbox(state, false) {
        Ok(f) => f,
        Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => return Ok(stats),
        Err(e) => return Err(e),
    };
    // Do not block the phone's existing maintenance task behind a CLI fsync.
    if lock_local_inbox(&locked, true).is_err() { return Ok(stats); }
    let mut paths = local_inbox_paths(state)?;
    paths.retain(|p| p.extension().is_some_and(|e| e == "rec"));
    paths.sort();
    if paths.is_empty() { progress.durable.clear(); progress.cursor = 0; return Ok(stats); }
    let start = progress.cursor % paths.len();
    paths.rotate_left(start);
    progress.cursor = (start + CLIENT_INBOX_BATCH.min(paths.len())) % paths.len();
    let mut pending = Vec::new();
    for p in paths.iter().take(CLIENT_INBOX_BATCH) {
        let rec = read_local_inbox_record(p);
        let off = match rec.as_ref() {
            Ok(rec) if local_record_authorized(tr, rec) => tr.offer(rec.clone()),
            _ => trust::Offer::Rejected("invalid local record or current authority"),
        };
        match off {
            trust::Offer::Rejected(_) => {
                if reject_local_inbox_record(p).is_ok() { stats.rejected += 1; }
                else { stats.retained += 1; }
            },
            off => {
                stats.changed |= off == trust::Offer::Added;
                pending.push((p, rec.expect("accepted parsed record")));
            },
        }
    }
    if pending.is_empty() { return Ok(stats); }
    // A stale queued grant must never supersede the current revoke on the wire.
    let all = tr.export_all();
    let current: Vec<_> = pending.into_iter().filter_map(|(p, r)| all.iter()
        .find(|x| x.root == r.root && x.hh == r.hh && x.issuer == r.issuer)
        .map(|r| (p, r))).collect();
    if current.is_empty() {
        return Ok(stats);
    }
    if stats.changed || current.iter().any(|(_, r)| !progress.durable.contains(&r.wire())) {
        if save(tr).is_err() { stats.save_failed = true; stats.retained += current.len(); return Ok(stats); }
        stats.committed = current.len();
    }
    // Cache only local-save facts, bounded independently of the network. It avoids
    // repeated fsync every 4 s while offline; no custody/retransmit protocol is added.
    for (_, r) in &current {
        let wire = r.wire();
        if progress.durable.len() == LOCAL_INBOX_LIMIT && !progress.durable.contains(&wire) {
            progress.durable.clear();
        }
        progress.durable.insert(wire);
    }
    let mut sent = HashSet::new();
    for (p, rec) in current {
        let wire = rec.wire();
        if local_record_authorized(tr, rec) && local_record_exit_authorized(tr, rec, peer)
            && (sent.contains(&wire) || publish(rec)) {
            sent.insert(wire);
            stats.sent += 1;
            if std::fs::remove_file(p).is_err() { stats.retained += 1; }
        } else {
            stats.retained += 1; // Keep queued work when no authenticated current exit exists.
        }
    }
    Ok(stats)
}

/// Presentation only; node-scoped rights stay scoped in all admission/delegation checks.
fn policy_status(tr: &trust::Trust, now: u64) -> Vec<serde_json::Value> {
    tr.policy_view(now).iter().map(|(r, g, o, e)| {
        let scopes = tr.policy_scope_view(r, now).iter().map(|(scope, grant, eff)|
            serde_json::json!({"node": hex(scope), "grant": grant, "eff": eff})).collect::<Vec<_>>();
        serde_json::json!({"root": hex(r), "tag": trust::root_tag(r), "grant": g, "offer": o, "eff": e, "scopes": scopes})
    }).collect()
}

/// Проверки выдающего при подготовке делегированного приглашения выполняются до создания pin.
fn admin_invite(a: InviteArgs) -> Result<()> {
    let nodes = a.nodes.iter().map(|h| unhex(h).try_into().map_err(|_|anyhow::anyhow!("node identity hash"))).collect::<Result<Vec<trust::Hash>>>()?;
    let rights = trust::parse_rights(&a.rights)?;
    // Сеть держит процесс узла/VPN: в нём (Android, JNI) выпускаем сразу, из отдельного CLI - файловым запросом к демону.
    let value = if let Some(s) = enroll_net::find(&a.state) {
        let root = match &a.root { Some(r) => unhex(r).try_into().map_err(|_|anyhow::anyhow!("root hash"))?, None => *s.identity.hash() };
        // Отдельный поток со своим runtime: вызов идёт из синхронного CLI внутри runtime процесса, блокировать его нельзя.
        std::thread::spawn(move || -> Result<String> {
            tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(s.issue_invite(root, nodes, rights))
        }).join().map_err(|_| anyhow::anyhow!("выпуск приглашения прерван"))??
    } else {
        let root = match &a.root {
            Some(r) => unhex(r).try_into().map_err(|_|anyhow::anyhow!("root hash"))?,
            None => *load_identity_strict(&a.state)?.hash(),
        };
        enroll_net::issue_via_daemon(&a.state, root, &nodes, rights, Duration::from_secs(120))?
    };
    match a.out {
        Some(out) => crate::enroll::write(&out, value.as_bytes())?,
        None => println!("{value}"), // явная команда владельца; предпочтителен --out (0600)
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

/// Подписать запись о правах и поставить в локальную очередь inbox13 (общий путь `grant` и экрана «Моя нода»).
fn grant_to_inbox(state: &Path, root: Option<&str>, holder: &str, rights: u16) -> Result<()> {
    let id = load_identity_strict(state)?;
    let mut tr = trust::Trust::load(id, state)?;
    let root: trust::Hash = match root {
        Some(r) => unhex(r.trim()).try_into().map_err(|_| anyhow::anyhow!("--root: нужен хеш identity админа (32 hex)"))?,
        None => tr.me_hash,
    };
    let h = holder.trim().to_lowercase();
    let holder: trust::Pk = if h.len() == 128 {
        unhex(&h).try_into().map_err(|_| anyhow::anyhow!("--holder: не публичный ключ"))?
    } else {
        // префикс хеша уже известного держателя (H14: не короче 8 hex и однозначный)
        let known: Vec<(String, trust::Pk)> = tr.export_all().into_iter().filter(|r| r.root == root).map(|r| (hex(&r.hh), r.holder)).collect();
        holder_by_prefix(&h, &known)?
    };
    let rec = tr.issue(root, holder, rights)?;
    put_inbox13(state, &rec)
}

fn admin_grant(a: GrantArgs) -> Result<()> {
    let rights = trust::parse_rights(&a.rights)?;
    grant_to_inbox(&a.state, a.root.as_deref(), &a.holder, rights)?;
    println!("запись ({}) подписана и поставлена в локальную очередь; удалённое применение не подтверждено", trust::rights_text(rights));
    Ok(())
}

/// Записи в очереди inbox13 (hex хеша держателя -> права), не больше 64 файлов; нечитаемые и чужие по правам пропускаются.
fn pending_inbox13(state: &Path, root: &trust::Hash) -> (usize, HashMap<String, u16>) {
    let mut n = 0;
    let mut by_holder = HashMap::new();
    let Ok(rd) = std::fs::read_dir(state.join("inbox13")) else { return (0, by_holder) };
    for p in rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "rec")).take(64) {
        n += 1;
        if let Ok(rec) = read_local_inbox_record(&p) {
            if rec.root == *root { by_holder.insert(hex(&rec.hh), rec.rights); }
        }
    }
    (n, by_holder)
}

/// Экран «Моя нода»: мои права, участники моей сети (по локальному Trust) и очередь неприменённых записей.
/// Права «действует» = цепочка до корня (`rights_in`); подписи уже проверены при приёме записей в Trust.
fn my_node_view(state: &Path) -> Result<String> {
    let id = load_identity_strict(state)?;
    let tr = trust::Trust::load(id, state)?;
    let me = tr.me_hash;
    // HOST_ACCESS живёт отдельными записями с областью NODE (экран ноды), в корневых правах не показывается и не меняется
    let mine = tr.my_rights_in(&me) & trust::ALL;
    let (queued, queue) = pending_inbox13(state, &me);
    let mut holders: Vec<trust::Hash> = tr.export_all().into_iter().filter(|r| r.root == me && r.hh != me).map(|r| r.hh).collect();
    holders.sort();
    holders.dedup();
    holders.truncate(200);
    let participants: Vec<_> = holders.iter().map(|h| {
        let hx = hex(h);
        let mut p = serde_json::json!({"holder": hx, "rights": tr.rights_in(&me, h) & trust::ALL, "eff": tr.effective_in(&me, h, now_ms() as u64) & trust::ALL});
        if let Some(q) = queue.get(&hx) { p["queued"] = serde_json::json!(q); }
        p
    }).collect();
    let networks: Vec<_> = tr.policy_view(now_ms() as u64).into_iter().filter(|(r, _, _, _)| *r != me)
        .map(|(r, g, _, _)| serde_json::json!({"root": hex(&r), "tag": trust::root_tag(&r), "rights": g & trust::ALL})).collect();
    Ok(serde_json::json!({"version": 1, "me": hex(&me), "root": hex(&me), "my_rights": mine,
        "can_add": mine & trust::ADD != 0, "can_remove": mine & trust::REMOVE != 0, "grantable": mine,
        "queued": queued, "participants": participants, "networks": networks, "policy": policy_status(&tr, now_ms() as u64)}).to_string())
}

/// Задать права держателя в СВОЕЙ сети (маска без HOST_ACCESS). Полномочия и подмножество своих прав проверяет `Trust::issue`;
/// запись подписывается и кладётся в inbox13, дальше её подхватит клиент (локальный приём и T_REC на текущий выход).
fn my_node_rights_set(state: &Path, holder: &str, rights: u16) -> String {
    let fail = |code: &str, detail: String| serde_json::json!({"version": 1, "accepted": false, "queued": false, "rejected": code, "detail": detail}).to_string();
    if rights & !trust::ALL != 0 { return fail("invalid_rights", "маска содержит биты вне USE..CONFIG".into()); }
    if holder.len() != 32 || !holder.bytes().all(|b| b.is_ascii_hexdigit()) { return fail("invalid_holder", "нужен хеш держателя (32 hex)".into()); }
    match grant_to_inbox(state, None, holder, rights) {
        Ok(()) => serde_json::json!({"version": 1, "accepted": true, "queued": true, "rights": rights, "holder": holder.to_lowercase(),
            "detail": "запись подписана и поставлена в локальную очередь; удалённое применение не подтверждено"}).to_string(),
        Err(e) => fail("backend_refused", format!("{e:#}").chars().take(200).collect()),
    }
}

/// `trust-view` и `rights-set` для JNI: фиксированные флаги, state всегда из аргумента `state_dir`.
fn my_node_cli(words: &[&str], state_dir: &str) -> String {
    let bad = |why: &str| serde_json::json!({"version": 1, "accepted": false, "queued": false, "error": why, "rejected": why}).to_string();
    let (mut holder, mut rights) = (None, None);
    let mut i = 1;
    while i < words.len() {
        if i + 1 >= words.len() { return bad("invalid_cli_arguments"); }
        match words[i] {
            "--state" => {}
            "--holder" if words[0] == "rights-set" => holder = Some(words[i + 1]),
            "--rights" if words[0] == "rights-set" => rights = words[i + 1].parse::<u16>().ok(),
            _ => return bad("invalid_cli_arguments"),
        }
        i += 2;
    }
    let state = Path::new(state_dir);
    if words[0] == "trust-view" {
        return my_node_view(state).unwrap_or_else(|_| bad("trust_state_unavailable"));
    }
    match (holder, rights) {
        (Some(h), Some(r)) => my_node_rights_set(state, h, r),
        _ => bad("invalid_cli_arguments"),
    }
}

/// `knothopd policy`: записывает желаемую политику в `<state>/policy-want.json` (атомарно); работающая нода или клиент подписывает её и разносит.
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

    }
    if let Ok(b) = std::fs::read(state.join("neighbors.json")) {
        println!("таблица соседей: {}", String::from_utf8_lossy(&b));
    }
    Ok(())
}

/// R-9: первичный якорь корня на новой ноде. Зачисление по приглашению ставит якорь только клиенту; серверная нода сама не вступает
/// (`knothopd node --invite-file` лишь допускает анонсы нод приглашения), поэтому оператор привязывает корень вручную:
/// ключ из файла/stdin, обязательная сверка с отпечатком из другого канала, Trust::load (fail-closed) + атомарная запись.
/// Узел не должен работать: он владеет trust.json и перезапишет файл из памяти.
fn trust_anchor_cmd(a: TrustAnchorArgs) -> Result<()> {
    use std::io::Read;
    if a.fingerprint.len() != 32 || !a.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) { bail!("отпечаток: нужно 32 hex"); }
    let mut raw = String::new();
    if a.root_key_file == Path::new("-") { std::io::stdin().take(1024).read_to_string(&mut raw)?; }
    else {
        let f = std::fs::File::open(&a.root_key_file).with_context(|| format!("файл ключа {}", a.root_key_file.display()))?;
        f.take(1024).read_to_string(&mut raw)?;
    }
    let raw = raw.trim();
    if raw.len() != 128 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) { bail!("ключ корня: нужно 128 hex (64 байта)"); }
    let pk: trust::Pk = unhex(raw).try_into().map_err(|_| anyhow::anyhow!("ключ корня"))?;
    let h = trust::hash_of(&pk).context("ключ корня не разобран")?;
    if hex(&h) != a.fingerprint.to_lowercase() { bail!("отпечаток не совпал с хешем ключа: якорь не добавлен"); }
    let me = load_identity_strict(&a.state)?;
    if std::fs::metadata(a.state.join("status.json")).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|d| d < Duration::from_secs(60)) {
        bail!("узел, похоже, работает (status.json свежий): остановите knothopd и повторите");
    }
    let mut tr = trust::Trust::load(me, &a.state)?;
    if tr.add_anchor(&pk)? { tr.save()?; println!("якорь корня {} добавлен", hex(&h)); } else { println!("якорь корня {} уже был", hex(&h)); }
    Ok(())
}

/// R-2: забыть чужие корни и зачисления. Identity и записи собственного корня остаются; временные файлы зачисления удаляются.
/// Отказывает, если узел работает (status.json свежее 60 с): иначе процесс перезапишет trust.json из памяти.
fn forget_network_cmd(state: &Path) -> Result<()> {
    if std::fs::metadata(state.join("status.json")).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|d| d < Duration::from_secs(60)) {
        bail!("узел, похоже, работает (status.json свежий): остановите VPN и повторите");
    }
    for f in ["enrollment.json", "enroll-consent.json", "enroll-consented.json", "enroll-join.json"] { let _ = std::fs::remove_file(state.join(f)); }
    if state.join("identity.key").exists() {
        let n = trust::Trust::load(load_identity_strict(state)?, state)?.forget_foreign_roots()?;
        println!("забыто якорей: {n}");
    }
    Ok(())
}

pub fn run_admin(cmd: VpnCmd) -> Result<()> {
    match cmd {
        VpnCmd::AdminSubmit(a) => { println!("{}", admin_submit(a)?); Ok(()) },
        VpnCmd::AdminStatus(a) => { println!("{}", admin_status(a)?); Ok(()) },
        VpnCmd::AdminView(a) => { println!("{}", admin_view(a)?); Ok(()) },
        VpnCmd::Revoke(a) => {
            let id = a.id.to_lowercase();
            // держатель по префиксу хеша -> запись с пустыми правами
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
            bail!("такого держателя нет")
        }
        VpnCmd::Whoami(a) => {
            std::fs::create_dir_all(&a.state)?;
            let id = load_or_create_identity(&a.state)?;
            let j = serde_json::json!({"hash": hex(id.hash()), "pk": hex(&id.public_key_bytes()), "ip": ip_str(client_ip(id.hash())), "prefix": client_net().1});
            write_atomic(&a.state.join("whoami.json"), j.to_string().as_bytes());
            println!("{j}");
            Ok(())
        }
        VpnCmd::TrustAnchor(a) => trust_anchor_cmd(a),
        VpnCmd::ForgetNetwork(a) => forget_network_cmd(&a.state),
        VpnCmd::RulesList(a) => route::cmd_list(&a.state),
        VpnCmd::RulesCompile(a) => route::cmd_compile(&a.state),
        VpnCmd::Invite(a) => admin_invite(a),
        VpnCmd::Grant(a) => admin_grant(a),
        VpnCmd::Policy(a) => admin_policy(a),
        VpnCmd::List(a) => admin_list(&a.state),
        _ => bail!("не админ-команда"),
    }
}

fn admin_json_error(error: &str, requestid: Option<&str>) -> String {
    serde_json::json!({"version":1,"accepted":false,"requestid":requestid.unwrap_or(""),"queued":false,"rejected":error}).to_string()
}

fn admin_submit(a: AdminSubmitArgs) -> Result<String> {
    match lxmf_admin::submit_from_cli(&a) {
        Ok(value) => Ok(value.to_string()),
        Err(error) => {
            let raw = error.to_string();
            let code = match raw.as_str() {
                "unsupported_offline" => "unsupported_offline",
                "lxmf_runtime_not_ready" => "lxmf_runtime_not_ready",
                "invalid_target" => "invalid_target",
                "invalid_root" => "invalid_root",
                "invalid_request_id" => "invalid_request_id",
                "scope_must_be_NODE" => "scope_must_be_NODE",
                "unsupported_operation" => "unsupported_operation",
                "target_not_in_authenticated_snapshot" => "target_not_in_authenticated_snapshot",
                "target_identity_unknown" => "target_identity_unknown",
                "target_not_in_selected_root" => "target_not_in_selected_root",
                "target_identity_destination_mismatch" => "target_identity_destination_mismatch",
                "target_capability_unknown" => "target_capability_unknown",
                "target_capability_stale" => "target_capability_stale",
                "target_host_access_unavailable" => "target_host_access_unavailable",
                "target_authority_changed" => "target_authority_changed",
                "request_id_conflict" => "request_id_conflict",
                "expired" => "expired",
                "no_status_authority" => "no_status_authority",
                "host_access_mask_must_be_exactly_64" => "host_access_mask_must_be_exactly_64",
                "host_access_mask_must_include_64_and_known_bits_only" => "host_access_mask_must_include_64_and_known_bits_only",
                "host_access_revoke_mask_must_be_exactly_64" => "host_access_revoke_mask_must_be_exactly_64",
                "stale_rights_snapshot" => "stale_rights_snapshot",
                "holder_not_known_in_selected_root" => "holder_not_known_in_selected_root",
                "insufficient_scoped_authority" => "insufficient_scoped_authority",
                "client_admin_queue_full" => "client_admin_queue_full",
                "lxmf_send_queue_full" => "lxmf_send_queue_full",
                _ => "backend_error",
            };
            Ok(admin_json_error(code, Some(&a.request_id)))
        }
    }
}

fn admin_status(a: AdminStatusArgs) -> Result<String> {
    let id = unhex(&a.request_id);
    if id.len()!=16 {
        return Ok(serde_json::json!({"version":1,"requestid":a.request_id,"state":"rejected","rejected":"invalid_request_id","durable_ack":false}).to_string());
    }
    Ok(lxmf_admin::status_json(&a.state, &hex(&id))?.to_string())
}

fn admin_view(a: AdminViewArgs) -> Result<String> {
    let target = unhex(&a.target);
    if target.len() != 16 {
        return Ok(serde_json::json!({"version":1,"error":"invalid_target"}).to_string());
    }
    let id = match load_identity_strict(&a.state) {
        Ok(id) => id,
        Err(_) => {
            return Ok(admin_view_json(&a.target, "local_identity_unavailable"));
        }
    };
    let target: [u8;16] = target.try_into().unwrap();
    let trust = match trust::Trust::load(id, &a.state) {
        Ok(t) => t,
        Err(_) => return Ok(admin_view_json(&hex(&target), "trust_state_unavailable")),
    };
    if let Ok(Some(cached)) = lxmf_admin::authenticated_target_view(&a.state, &a.target, &trust) {
        let reply = &cached["reply"];
        let seen = cached["seen"].as_u64().unwrap_or(0);
        let stale = (now_ms() as u64 / 1000).saturating_sub(seen) > 600;
        let status: serde_json::Value = std::fs::read(a.state.join("status.json")).ok()
            .and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let target_identity: Option<[u8;16]> = status["exits"].as_array().and_then(|items| items.iter()
            .find(|e| e["d"].as_str() == Some(&a.target)).and_then(|e| e["id"].as_str()).and_then(|x| unhex(x).try_into().ok()));
        let remote_root = reply["root"].as_str().unwrap_or("");
        let mut authorities=Vec::new();
        if let Some(target_identity)=target_identity {
            for (root,_) in trust.anchors() {
                let Some(pk)=trust.public_key_in(&root,&target_identity) else {continue};
                if dest_from_pub_tag(&pk,T13_TAG)!=target {continue}
                if hex(&root)==remote_root { authorities.push(reply["authority"].clone()); }
                else {
                    let rights=trust.my_rights_in(&root);
                    let can_status=rights&(trust::ADD|trust::REMOVE|trust::CONFIG)!=0;
                    authorities.push(serde_json::json!({"root":hex(&root),"trusted":true,"scope":"NODE","rights":rights,
                        "can_status":can_status,"can_read":can_status,"can_grant":false,"can_issue":false,"can_revoke":false,
                        "grantable_rights":0,"revocable_rights":0,"reason":"target_root_status_not_authenticated"}));
                }
            }
        }
        let mut capabilities=reply["capabilities"].clone();
        if !lxmf_admin::client_runtime_ready(&a.state) { capabilities["status_get"]=serde_json::json!(false); }
        if stale {
            capabilities["admin_commands"]=serde_json::json!(false);
            capabilities["rights_grant"]=serde_json::json!(false);
            capabilities["rights_revoke"]=serde_json::json!(false);
            capabilities["participants_export"]=serde_json::json!(false);
            capabilities["host_access"]=serde_json::json!(false);
        }
        let participants=if capabilities["participants_export"]==true {reply["participants"].clone()} else {serde_json::json!([])};
        return Ok(serde_json::json!({
            "version":1,"target":a.target.to_lowercase(),"node":{"status":"authenticated","stale":stale},
            "capabilities":capabilities,
            "effective_authority":{"reason":if stale {"last_authenticated_target_status_stale"} else {"authenticated_target_status"},"authorities":authorities},
            "participants":participants,"commands":lxmf_admin::commands_for_target(&a.state,&a.target)
        }).to_string());
    }
    let status: serde_json::Value = std::fs::read(a.state.join("status.json")).ok()
        .and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let target_identity: Option<[u8;16]> = status["exits"].as_array().and_then(|items| items.iter()
        .find(|e| e["d"].as_str() == Some(&a.target)).and_then(|e| e["id"].as_str())
        .and_then(|x| unhex(x).try_into().ok()));
    let mut authorities = Vec::new();
    if let Some(target_identity) = target_identity {
        for (root, _) in trust.anchors() {
            let Some(pk) = trust.public_key_in(&root, &target_identity) else { continue };
            if dest_from_pub_tag(&pk, T13_TAG) != target { continue; }
            let rights = trust.my_rights_in(&root);
            let can_status = rights & (trust::ADD | trust::REMOVE | trust::CONFIG) != 0;
            authorities.push(serde_json::json!({"root":hex(&root),"trusted":true,"scope":"NODE","rights":rights,
                "can_status":can_status,"can_read":can_status,"can_grant":false,"can_issue":false,"can_revoke":false,
                "grantable_rights":0,"revocable_rights":0,"reason":"target_status_not_authenticated"}));
        }
    }
    let status_bootstrap = lxmf_admin::client_runtime_ready(&a.state) && authorities.iter().any(|v| v["can_status"] == true);
    Ok(serde_json::json!({"version":1,"target":hex(&target),"node":{"status":"unknown","stale":true},
        "capabilities":{"host_access":false,"admin_commands":false,"status_get":status_bootstrap,"participants_export":false,"rights_grant":false,"rights_revoke":false},
        "effective_authority":{"reason":if authorities.is_empty(){"no_accepted_root_chain_for_target"}else{"target_status_not_authenticated"},"authorities":authorities},
        "participants":[],"commands":lxmf_admin::commands_for_target(&a.state,&a.target)}).to_string())
}

fn admin_view_json(target: &str, reason: &str) -> String {
    serde_json::json!({
        "version":1,"target":target.to_lowercase(),
        "node":{"status":"unknown","stale":true},
        "capabilities":{"host_access":false,"admin_commands":false,"status_get":false,"participants_export":false,"rights_grant":false,"rights_revoke":false},
        "effective_authority":{"reason":reason,"authorities":[]},
        "participants":[],"commands":[]
    }).to_string()
}

/// Narrow JNI bridge for the two admin projection commands. This accepts a fixed argv grammar,
/// never invokes a shell, and always overrides the caller-supplied state path with `state_dir`.
pub fn run_cli_json(command: &str, state_dir: &str) -> String {
    let fail = |why: &str| serde_json::json!({"version":1,"accepted":false,"requestid":"","queued":false,"rejected":why}).to_string();
    if command.len() > 4096 || state_dir.len() > 4096 || !command.is_ascii() || !state_dir.is_ascii()
        || command.bytes().any(|b| !(b.is_ascii_alphanumeric() || b.is_ascii_whitespace() || b"/._-".contains(&b)))
        || state_dir.bytes().any(|b| !(b.is_ascii_alphanumeric() || b"/._-".contains(&b))) {
        return fail("invalid_cli_input");
    }
    let words: Vec<&str> = command.split_whitespace().collect();
    if words.first().is_some_and(|w| matches!(*w, "trust-view" | "rights-set")) { return my_node_cli(&words, state_dir); }
    if words.is_empty() || !matches!(words[0], "admin-view" | "admin-submit" | "admin-status") { return fail("unsupported_command"); }
    let mut argv = vec!["knothopd".to_string(), words[0].to_string()];
    let mut i = 1;
    while i < words.len() {
        let flag = words[i];
        if flag == "--state" {
            i += 1;
            while i < words.len() && !words[i].starts_with("--") { i += 1; }
            argv.push("--state".into());
            argv.push(state_dir.to_string());
            continue;
        }
        if !matches!(flag, "--target" | "--root" | "--op" | "--holder" | "--rights" | "--scope" | "--request-id")
            || i + 1 >= words.len() || words[i + 1].starts_with("--") { return fail("invalid_cli_arguments"); }
        argv.push(flag.to_string());
        argv.push(words[i + 1].to_string());
        i += 2;
    }
    if !argv.iter().any(|x| x == "--state") {
        argv.extend(["--state".into(), state_dir.into()]);
    }
    let cli: VpnCli = match clap::Parser::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(_) => return fail("invalid_cli_arguments"),
    };
    match cli.cmd {
        VpnCmd::AdminSubmit(a) => admin_submit(a).unwrap_or_else(|_| fail("backend_error")),
        VpnCmd::AdminStatus(a) => admin_status(a).unwrap_or_else(|_| fail("backend_error")),
        VpnCmd::AdminView(a) => admin_view(a).unwrap_or_else(|_| fail("backend_error")),
        _ => fail("unsupported_command"),
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
    trust: Arc<Mutex<trust::Trust>>,
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
    /// админ-режим: приглашённые пользователи, получившие запись через посредника (hex хеша -> когда); для показа в приложении
    users: Mutex<Vec<(String, u64)>>,
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
    ip: String,
    servers: Mutex<Vec<CServer>>,
    tun: Arc<TunState>,
    auth_wait: Mutex<HashMap<LinkId, tokio::sync::oneshot::Sender<std::result::Result<serde_json::Value, String>>>>,
    /// Пробы датаграмм только после AUTH_OK и проверки EXIT: Link -> случайный seq, метка времени, ответ.
    data_wait: Mutex<HashMap<LinkId, (u32, u64, tokio::sync::oneshot::Sender<()>)>>,
    cur: Mutex<Option<([u8; 16], LinkId, Instant)>>,
    last_pong: std::sync::atomic::AtomicU64,
    /// Окно свежести контакта для индикации: `fail_ms` при трафике, keepalive с запасом в простое (выставляет `Pacer`).
    contact_window_ms: std::sync::atomic::AtomicU64,
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
    loss: Mutex<LossWin>,
    fail_ms: u64,
    path_gate: path::PathGate,
    /// состояние прав 0013 (создаётся при каждом запуске клиента)
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
    /// раздельное туннелирование: активные правила и отчёт о загрузке списков,
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
    rns_rtt: Option<(Instant, f64)>,
}

impl ClientCtx {
    fn native_rtt(&self, id: &LinkId) -> Option<f64> {
        let s = self.node.engine().link_stats(id)?;
        s.keepalive_rtt_ms().map(|r| r as f64).or(s.srtt_ms()).or_else(|| s.rtt_ms().map(|r| r as f64))
            .filter(|r| r.is_finite() && *r > 0.0)
    }

    fn remember_rns_rtt(&self, dest: [u8;16], id: &LinkId) {
        if let Some(rtt) = self.native_rtt(id) {
            let mut q = self.qstat.lock().unwrap();
            if q.contains_key(&dest) || q.len() < 32 { q.entry(dest).or_default().rns_rtt = Some((Instant::now(), rtt)); }
        }
    }

    /// RTT полного RNS Link, не RTT соседнего QUIC-сокета. Закрытые Links
    /// оставляют короткий кэш для сравнения выходов без новых фоновых проб.
    fn rns_rtt(&self, dest: &[u8;16]) -> Option<f64> {
        let current = self.cur.lock().unwrap().filter(|c| &c.0 == dest).map(|c| c.1);
        let id = current.or_else(|| self.tun.extra.read().unwrap().get(dest).map(|x| x.id));
        id.and_then(|id| self.native_rtt(&id)).or_else(|| self.qstat.lock().unwrap().get(dest)
            .and_then(|q| q.rns_rtt).filter(|(at, _)| at.elapsed() < Duration::from_secs(600)).map(|(_, r)| r))
    }

    /// Runs only from the existing 4 s policy maintenance; no new phone wakeup.
    fn take_local_inbox13(&self, progress: &mut ClientInboxProgress) {
        let Some(c) = &self.c13 else { return };
        let cur = *self.cur.lock().unwrap();
        let peer = cur.and_then(|(_, id, _)| c.peers.lock().unwrap().get(&id).copied());
        let result = {
            let mut tr = c.trust.lock().unwrap();
            client_inbox_step(&self.state, &mut tr, progress, peer.as_ref(), trust::Trust::save, |rec| {
                let Some((dest, id, _)) = cur else { return false };
                if self.cur.lock().unwrap().as_ref().map(|c| (c.0, c.1)) != Some((dest, id))
                    || self.admitted_exits.lock().unwrap().get(&id) != Some(&dest)
                    || c.peers.lock().unwrap().get(&id) != peer.as_ref() {
                    return false;
                }
                self.sync_to(id, vec![rec.clone()], vec![]) // очередь LXMF; не удалённый ACK.
            })
        };
        match result {
            Ok(s) => {
                if s.changed { self.refresh_servers13(); }
                if s.committed != 0 || s.rejected != 0 || s.sent != 0 || s.save_failed {
                    self.sh.note(format!("inbox13 client: local_saved={}, link_queued={}, rejected={}, retained={}, save_failed={}; remote apply unconfirmed",
                        s.committed, s.sent, s.rejected, s.retained, s.save_failed));
                }
            },
            Err(_) => self.sh.note("inbox13 client: очередь недоступна; записи сохранены".to_string()),
        }
    }

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
        let addrs: Vec<String> = addrs.iter().filter(|a| sane_hint_addr(a)).take(8).cloned().collect();
        let addrs = addrs.as_slice();
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
            let tr = c.trust.lock().unwrap();
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
            let contact = is_cur && (now_ms() as u64).saturating_sub(self.last_pong.load(Relaxed)) <= self.contact_window_ms.load(Relaxed).max(self.fail_ms);
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
        let j = serde_json::json!({"state": state, "ip": self.ip, "up_s": up_since.elapsed().as_secs(),
            "current": cur.map(|c| serde_json::json!({"d": hex(&c.0), "n": servers.iter().find(|e| e.dest == c.0).map(|e| e.name.clone()), "since_s": c.2.elapsed().as_secs(),
                "rtt_ms": *self.rtt_ms.lock().unwrap(), "hops": self.node.hops_to(&DestinationHash::new(c.0)),
                "carrier": self.carriers.lock().unwrap().get(&c.0).map(|x| *x.mode.lock().unwrap()), "via": via})),
            "log_tail": self.sh.log.lock().unwrap().iter().rev().take(25).map(|(t, m)| format!("{} {}", *t as u64, m)).collect::<Vec<_>>(),
            "selected": std::fs::read_to_string(self.state.join("select")).unwrap_or_default().trim().to_string(),
            "routing": self.routing_json(&servers),
            "exits": exits, "edges": edges, "tun": self.tun.stats(), "udp": udp_stats(), "failovers": self.failovers.lock().unwrap().clone(), "status": self.status.lock().unwrap().clone(),
            "users": self.c13.as_ref().map(|c| c.users.lock().unwrap().iter().map(|(h, t)| serde_json::json!({"h": &h[..8], "t": t})).collect::<Vec<_>>()).unwrap_or_default(),
            "pol": pol_counters(),
            "policy": self.c13.as_ref().map(|c| policy_status(&c.trust.lock().unwrap(), now_ms() as u64)).unwrap_or_default(),
            "ts_ms": now_ms() as u64});
        // раз в секунду читает интерфейс приложения: частота прежняя, но запись не в async-задаче
        crate::bgwrite::put(&self.state.join("status.json"), j.to_string().into_bytes(), Duration::ZERO);
    }
}

pub async fn run_client13(a: ClientArgs) -> Result<()> {
    std::fs::create_dir_all(&a.state)?;
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
            Ok(i) => { if !tr.enrollment_proofs(&my_pk).iter().any(|p| p.grant.id == crate::enroll::invite_id(&i.pin)) { inv = Some(i); } }
            Err(e) if tr.anchors().len() > 1 || tr.record_count() > 0 => { eprintln!("Сохранённое зачисление используется без старого приглашения: {e:#}"); }
            Err(e) => return Err(e),
        }
    }
    let mut hints: HashMap<String, Vec<String>> = std::fs::read(a.state.join("hints.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    migrate_hints(&mut hints, tr.holders_with(trust::USE | trust::TRANSIT | trust::EXIT).into_iter().chain(tr.anchors().into_iter().map(|(_, pk)| pk)));
    let c13 = Some(C13 { trust: Arc::new(Mutex::new(tr)), invite: Mutex::new(inv), rejected: Mutex::new(None), peers: Mutex::new(HashMap::new()), hints: Mutex::new(hints),
        enrollees: Mutex::new(HashMap::new()),
        users: Mutex::new(Vec::new()) });
    if let Some(c) = &c13 { let _ = RELAY_TRUST.set(c.trust.clone()); }
    let identity = id;
    let tun_arg = a.tun_fd.to_string();
    // без дескриптора от VpnService (лаборатория, Linux) TUN создаётся самим процессом и получает адрес, выведенный из identity
    let tun_ip = format!("{}/{}", ip_str(client_ip(identity.hash())), client_net().1);
    let mut extra: Vec<&str> = vec!["--tun-fd", &tun_arg, "--tun-mtu", "1327", "--path-keepalive-ms", "4000", "--conn-idle-ms", "12000"];
    if a.tun_fd < 0 {
        extra.extend(["--tun-ip", &tun_ip]);
    }
    // с relay EndpointId клиента должен быть связан с identity, иначе relay не отличит допущенного от чужого
    let relays = parse_relay_urls(&a.relay_url);
    let ep_key = if relays.is_empty() { SecretKey::generate() } else { iroh_key_from_identity(&identity)? };
    let b = start_base("c", &a.state, false, None, ep_key, Some(identity.clone()), a.quic_cc_mbit, &extra, None, &relays).await?;
    let (node, sh, ep, cli, events, admin_lxmf) = (b.node.clone(), b.sh.clone(), b.ep.clone(), b.cli.clone(), b.events, b.admin_lxmf);
    let tun = TunState::open(&cli, false)?;
    let _ = sh.tun.set(tun.clone());
    tokio::spawn(tun_reader(tun.clone(), node.clone(), sh.clone()));
    if a.tun_fd == crate::TUN_DETACHED {
        // Режим «в сети без VPN»: оболочка подключает и снимает TUN на лету, узел и его Link при этом живут (mobile::set_tun_fd).
        let (tun2, sh2) = (tun.clone(), sh.clone());
        tokio::spawn(async move {
            let mut commands = crate::mobile::tun_commands();
            commands.borrow_and_update();
            if let Some(fd) = crate::mobile::take_tun() {
                if let Err(e) = tun2.set_device(Some(fd)) { sh2.note(format!("TUN не подключён: {e:#}")); }
            }
            while commands.changed().await.is_ok() {
                let fd = crate::mobile::take_tun();
                let attach = fd.is_some();
                match tun2.set_device(fd) {
                    Ok(()) => sh2.note(if attach { "TUN подключён: режим VPN" } else { "TUN снят: узел остаётся в сети без VPN" }),
                    Err(e) => sh2.note(format!("TUN не переключён: {e:#}")),
                }
            }
        });
    }

    let servers: Vec<CServer> = Vec::new();
    let client_addr = ip_str(client_ip(identity.hash()));
    let ctx = Arc::new(ClientCtx { node: node.clone(), sh: sh.clone(), ep: ep.clone(), identity, ip: client_addr, servers: Mutex::new(servers.clone()), tun,
        auth_wait: Mutex::new(HashMap::new()), data_wait: Mutex::new(HashMap::new()), cur: Mutex::new(None), last_pong: Default::default(), contact_window_ms: Default::default(), rtt_pong: Default::default(), rtt_ms: Mutex::new(None), failovers: Mutex::new(Vec::new()),
        state: a.state.clone(), status: Mutex::new("подключаюсь".into()), dialers: Mutex::new(HashMap::new()),
        carriers: Mutex::new(HashMap::new()), public_ids: Mutex::new(Vec::new()), names: Mutex::new(load_names(&a.state)), hints: Mutex::new(HashMap::new()), platforms: Mutex::new(HashMap::new()), books: Mutex::new(HashMap::new()), loss: Mutex::new(LossWin::default()), fail_ms: a.fail_ms,
        c13, path_gate: path::PathGate::default(), nbrs: Mutex::new(HashMap::new()), admitted_exits: Mutex::new(HashMap::new()), ctrl: Mutex::new(HashMap::new()), lk_fail: Mutex::new(HashMap::new()), vis: Mutex::new(HashMap::new()), qstat: Mutex::new(HashMap::new()),
         rcfg: std::sync::RwLock::new(Arc::new(route::Cfg::default())), rreport: Mutex::new(serde_json::Value::Null), rpending: Mutex::new(HashSet::new()), rback: Mutex::new(HashMap::new()) });
    let _enrollment_service = ctx.c13.as_ref().map(|c| enroll_net::register(node.clone(), ctx.identity.clone(), c.trust.clone(), &a.state, Some(Arc::downgrade(&ctx))));
    let _admin_client_guard = if let (Some(runtime), Some(c13)) = (admin_lxmf, ctx.c13.as_ref()) {
        let guard = lxmf_admin::register_client_runtime(&a.state, &runtime);
        let trust = c13.trust.clone();
        runtime.pn.set_source(trust.clone());
        let sync_guard = lxmf_sync::register(&a.state, runtime.sync.clone());
        lxmf_admin::spawn_client_worker(runtime, ctx.clone(), trust);
        Some((guard, sync_guard))
    } else { None };
    if ctx.c13.is_some() {
        // (а) админ без приглашения объявляет свой корень: destination только для анонса, Link к нему не принимаем
        let mut dest = new_dest(ctx.identity.clone(), Direction::In, T13_TAG)
            .map_err(|e| anyhow::anyhow!("destination: {e:?}"))?;
        dest.set_accepts_links(true);
        let dh = *dest.hash().as_bytes();
        node.register_destination(dest);
        tokio::spawn(client_announce(ctx.clone(), dh));
        {
            // Проверка связи со всеми нодами по просьбе: поднять носители (QUIC/TCP) к нодам, у которых их нет; RTT носителя виден в списке нод.
            let ctx2 = ctx.clone();
            tokio::spawn(async move {
                let mut kicks = crate::mobile::kick_rx(crate::mobile::KICK_PING);
                kicks.borrow_and_update();
                while kicks.changed().await.is_ok() {
                    ctx2.refresh_servers13();
                    start_dialers(&ctx2);
                    ctx2.sh.note("проверка связи: носители ко всем нодам запрошены".to_string());
                }
            });
        }
        ctx.refresh_servers13();
        tokio::spawn(client_policy_loop(ctx.clone()));
        tokio::spawn(client_enroll_refresh(ctx.clone()));
        tokio::spawn(client_directory_refresh(ctx.clone()));
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
    crate::mobile::clear_tun();
    let rejected = ctx.c13.as_ref().and_then(|c| c.rejected.lock().unwrap().clone());
    if let Some(why) = rejected {
        bail!("зачисление прекращено: {why}");
    }
    Ok(())
}

/// Зачисление по приглашению v4 (ADR 0019): Link к нодам приглашения по RNS, проверка предложения, согласие пользователя, погашение pin.
async fn pair_client(ctx: &Arc<ClientCtx>) -> Result<()> {
    let Some(c) = &ctx.c13 else { return Ok(()) };
    let Some(inv) = c.invite.lock().unwrap().clone() else { return Ok(()) };
    let service = enroll_net::find(&ctx.state).context("enrollment runtime")?;
    *ctx.status.lock().unwrap() = "Связываюсь с нодами приглашения".into();
    let hints = enroll_net::join(&service, &inv).await?;
    for e in parse_dir_values(&hints, T13_TAG, DIR_MAX) { ctx.remember_addrs(&e.dest, &e.addrs); ctx.hint_name(e.dest, &e.name); }
    *c.invite.lock().unwrap() = None;
    ctx.refresh_servers13(); start_dialers(ctx); Ok(())
}

/// Отдельный быстрый путь каталога: не ждёт долгих запросов отсутствующих нод приглашения.
/// По жесту и раз в 2 минуты спрашиваем максимум два известных выхода через штатный LXMF.
async fn client_directory_refresh(ctx: Arc<ClientCtx>) {
    let Some(c) = &ctx.c13 else { return };
    let (fin, trigger) = (ctx.state.join("fin"), ctx.state.join("refresh-nodes"));
    let mut last = Instant::now() - Duration::from_secs(120);
    while !fin.exists() {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let manual = trigger.exists();
        if !manual && last.elapsed() < Duration::from_secs(120) { continue; }
        if c.invite.lock().unwrap().is_some() { continue; }
        if manual {
            let _ = std::fs::remove_file(&trigger);
            let _ = crate::enroll::write(&ctx.state.join("refresh-enrollment"), b"");
        }
        last = Instant::now();
        let current = ctx.cur.lock().unwrap().map(|v| v.0);
        let mut servers = ctx.servers.lock().unwrap().clone();
        servers.sort_by_key(|s| (Some(s.dest) != current, s.dest));
        let targets: Vec<_> = servers.into_iter().filter(|s| exit_eligible(&ctx, s)).filter_map(|s| s.pk).take(2).collect();
        let mut queued = 0;
        for pk in targets {
            let weak = Arc::downgrade(&ctx);
            let gate: lxmf_sync::Gate = Arc::new(move || {
                let ctx = weak.upgrade()?;
                let c = ctx.c13.as_ref()?;
                let tr = match c.trust.try_lock() {
                    Ok(tr) => tr,
                    Err(std::sync::TryLockError::WouldBlock) => return None,
                    Err(_) => return Some(false),
                };
                Some(authorized_exit(&tr, Some(&pk), now_ms() as u64))
            });
            if lxmf_sync::request_dir(&ctx.state, pk, gate) { queued += 1; }
        }
        if manual {
            let text = if queued == 0 { "Не удалось запросить каталог: нет доступного авторизованного выхода".into() }
                else { format!("Запрос каталога отправлен нодам: {queued}. Ожидаю ответ; подтверждения приглашения обновляются отдельно") };
            let _ = crate::enroll::write(&ctx.state.join("refresh-result.txt"), text.as_bytes());
        }
    }
}

/// Дожим расписок зачисления (см. `enroll_net::refresh`): раз в 2 мин и по файлу `refresh-enrollment`.
/// Найденные адреса - подсказки; права ноды получают только из подписанных записей.
async fn client_enroll_refresh(ctx: Arc<ClientCtx>) {
    let Some(c) = &ctx.c13 else { return };
    let (fin, trigger) = (ctx.state.join("fin"), ctx.state.join("refresh-enrollment"));
    // Грант может включать ноду, которая так и не зачислена (расписок всегда меньше): пауза растёт 2 -> 30 мин, пока новых записей нет.
    let (mut last, mut wait) = (Instant::now(), 120u64);
    let count = || c.trust.lock().unwrap().enrollment_proofs(&ctx.identity.public_key_bytes()).len();
    // Итог опроса по кнопке: приложение читает файл и показывает его (иначе «ничего не изменилось» неотличимо от «ещё идёт»).
    let result = ctx.state.join("refresh-result.txt");
    let report = |text: String| { let _ = crate::enroll::write(&result, text.as_bytes()); };
    while !fin.exists() {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let manual = trigger.exists();
        if (!manual && last.elapsed() < Duration::from_secs(wait)) || c.invite.lock().unwrap().is_some() {
            if manual && c.invite.lock().unwrap().is_some() {
                let _ = std::fs::remove_file(&trigger);
                report("Сначала завершите зачисление по приглашению".into());
            }
            continue;
        }
        let _ = std::fs::remove_file(&trigger);
        last = Instant::now();
        let Some(service) = enroll_net::find(&ctx.state) else {
            if manual { report("Служба зачисления недоступна".into()); }
            continue;
        };
        let before = count();
        // Один недоступный scope не блокирует жест/диагностику навсегда; сохранённый курсор продолжит следующий проход.
        let res = match tokio::time::timeout(Duration::from_secs(120), enroll_net::refresh(&service)).await {
            Ok(r) => r,
            Err(_) => Err(anyhow::anyhow!("Не все ноды ответили за 2 минуты; опрос продолжится в фоне")),
        };
        wait = if manual || count() > before { 120 } else { (wait * 2).min(1800) };
        let after = count();
        let (received, expected, refreshable) = enroll_net::receipt_progress(&service);
        let summary = format!("Расписок нод: {received} из {expected}");
        match res {
            Ok(Some(hints)) => {
                for e in parse_dir_values(&hints, T13_TAG, DIR_MAX) { ctx.remember_addrs(&e.dest, &e.addrs); ctx.hint_name(e.dest, &e.name); }
                if after > before { ctx.sh.note(format!("зачисление: дополучены расписки, {received} из {expected}")); }
                ctx.refresh_servers13(); start_dialers(&ctx);
                if manual { report(format!("{summary} (новых {}). {}", after.saturating_sub(before), if received < expected { "Остальные подтверждения ещё не доставлены" } else { "Все подтверждения получены" })); }
            }
            Ok(None) => { if manual { report(if expected == 0 { "Нет сохранённых подтверждений зачисления".into() }
                else if received == expected { format!("{summary}. Все подтверждения получены") }
                else if !refreshable { format!("{summary}. Не все подтверждения получены; срок опроса приглашения истёк") }
                else { format!("{summary}. Подтверждения ещё ожидаются") }); } }
            Err(e) => {
                ctx.sh.note(format!("зачисление: дожим расписок не удался: {e:#}"));
                if manual { report(format!("Не удалось: {}", format!("{e:#}").chars().take(160).collect::<String>())); }
            }
        }
    }
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

/// LXMF Policy у клиента: source проверен worker-ом; полномочия и срок проверяет Trust.
fn on_pol_client(ctx: &Arc<ClientCtx>, _link: LinkId, body: &[u8]) {
    POL_RX.fetch_add(body.len() as u64, Relaxed);
    POL_RX_N.fetch_add(1, Relaxed);
    let Some(c) = &ctx.c13 else { return };
    if body.len() != trust::POL_LEN {
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

fn on_rec_client(ctx: &Arc<ClientCtx>, _link: LinkId, body: &[u8]) {
    let Some(c) = &ctx.c13 else { return };
    let Some(rec) = trust::Record::parse(body) else { return };
    let mut tr = c.trust.lock().unwrap();
    if tr.offer(rec) == trust::Offer::Added { let _ = tr.save(); }
    drop(tr); ctx.refresh_servers13(); start_dialers(ctx);
}


/// Link к ожидающей ноде по любому пути RNS (ADR 0016): адреса нет, путь строит RNS. Link сквозь зашифрован, ключ ноды сверяется
/// с анонсом (`connect_with_key`); допуск даёт только pin приглашения.
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


/// (а, 0014 R6) Админ без приглашения (телефон или зачисленный клиент) анонсирует тег своего корня без адресов: нода, ждущая зачисления,
/// видит, что админ на связи, и просится через посредника. При старте, через 20 с, затем раз в 600 с (инвариант 8).
/// Входящие Link на этот destination не принимаются (set_accepts_links(false)): он нужен только для анонса.
async fn client_announce(ctx: Arc<ClientCtx>, dest: [u8; 16]) {
    let Some(c) = &ctx.c13 else { return };
    let mut wait = [Duration::ZERO, Duration::from_secs(20)].into_iter().chain(std::iter::repeat(Duration::from_secs(600)));
    let mut kicks = crate::mobile::kick_rx(crate::mobile::KICK_ANNOUNCE);
    kicks.borrow_and_update();
    let mut last: Option<Instant> = None;
    while let Some(d) = wait.next() {
        // Просьба пользователя будит раньше срока, но не чаще раза в 30 с: штатный период анонса (600 с) остаётся прежним.
        let manual = tokio::select! { _ = tokio::time::sleep(d) => false, r = kicks.changed() => r.is_ok() };
        if manual && last.is_some_and(|t| t.elapsed() < Duration::from_secs(30)) { continue; }
        if c.invite.lock().unwrap().is_some() {
            continue; // пока ждём зачисления, своих нод у нас нет
        }
        last = Some(Instant::now());
        // This destination exists only to publish the admin anchor for discovery; it rejects incoming Links.
        let data = serde_json::json!({"lc": false});
        let _ = ctx.node.announce(&DestinationHash::new(dest), Some(data.to_string().as_bytes())).await;
    }
}

/// Каталог по LXMF (R6): адреса выходов - подсказки (hints и диалер). Допуск - по записям о правах.
/// Отправитель опознан по ключу подписи; принимаем от допущенных серверов, от зачисляемой ноды (только запись о ней самой)
/// и от ключа с эффективным TRANSIT/EXIT. `true` - адресата можно подтвердить.
fn on_dir_client(ctx: &Arc<ClientCtx>, sender: trust::Pk, dir: &[serde_json::Value]) -> bool {
    let Some(c) = &ctx.c13 else { return false };
    let enrollee = c.enrollees.lock().unwrap().values().any(|p| *p == sender);
    let peer = c.peers.lock().unwrap().values().any(|p| *p == sender);
    let rights = c.trust.lock().unwrap().effective(&sender, now_ms() as u64) & (trust::TRANSIT | trust::EXIT) != 0;
    if !(enrollee || peer || rights) {
        return false;
    }
    let own_only = !(peer || rights);
    let mut accepted = 0;
    for e in parse_dir_values(dir, T13_TAG, DIR_MAX) {
        if own_only && sender != e.pk {
            continue;
        }
        accepted += 1;
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
    let known = ctx.servers.lock().unwrap().len();
    let summary = serde_json::json!({"at_ms":now_ms(),"entries":accepted,"known":known});
    let _ = crate::enroll::write(&ctx.state.join("directory-result.json"), &serde_json::to_vec(&summary).unwrap());
    true
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
                let v: serde_json::Value = serde_json::from_slice(announce.app_data()).unwrap_or_default();
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
                        let _ = name;
                    }
                }
            }
            NodeEvent::RequestReceived { link_id, request_id, path, data, .. } if path == enroll_net::PATH => { enroll_net::dispatch(&ctx.state, link_id, request_id, data); }
            NodeEvent::LinkEstablished { link_id, .. } => {
                ctx.sh.established.lock().unwrap().insert(hex(link_id.as_bytes()));
            }
            NodeEvent::LinkClosed { link_id, reason, .. } => {
                ctx.admitted_exits.lock().unwrap().remove(&link_id);
                ctx.ctrl.lock().unwrap().remove(&link_id);
                ctx.data_wait.lock().unwrap().remove(&link_id);
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
                    T_NBRS => {
                        if ctx.c13.is_some() {
                            on_nbrs_client(&ctx, link_id, body);
                        }
                    }
                    _ => {}
                }
            }
            NodeEvent::LinkDataReceived { link_id, data, .. } => {
                // IP-пакеты не берут дополнительный мьютекс таблицы проб.
                if is_rgp(&data) && data[3] == b'R' {
                    let probe = {
                        let mut pending = ctx.data_wait.lock().unwrap();
                        if pending.get(&link_id).map(|(seq, ts, _)| data_probe_matches(*seq, *ts, &data)).unwrap_or(false) {
                            pending.remove(&link_id)
                        } else { None }
                    };
                    if let Some((_, _, tx)) = probe { let _ = tx.send(()); }
                }
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
/// 1) прямой путь (1 хоп) по нашему носителю - предпочтение RNS path discovery (не пользовательский рейтинг выходов);
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
        {
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
    let used_iface = ctx.node.engine().get_path_clone(&dest).map(|p| p.interface_index);
    if let Some(p) = ctx.node.engine().get_path_clone(&dest) {
        let iface = ctx.node.engine().interface_stats().iter().find(|i| i.interface_id.0 == p.interface_index).map(|i| i.name.clone()).unwrap_or_default();
        ctx.sh.note(format!("путь к {}: {} хоп, интерфейс {}, транспорт {}", cand.name, p.hops, iface,
            p.next_hop.map(|h| hex(&h)[..8].to_string()).unwrap_or_else(|| "—".into())));
    }
    let handle = ctx.node.connect_with_key_cipher(&dest, &cand.key, cipher).await?;
    let id = *handle.link_id();
    let k = hex(id.as_bytes());
    let t = Instant::now();
    while !ctx.sh.established.lock().unwrap().contains(&k) {
        if ctx.sh.closed.lock().unwrap().contains_key(&k) || t.elapsed() > Duration::from_secs(est_s) {
            let _ = ctx.node.engine().close_link(&id).await;
            let why = format!("link до {} не установился", cand.name);
            return Err(match used_iface {
                Some(iface) => anyhow::Error::new(path::FailedPath { iface, why }),
                None => anyhow::anyhow!(why),
            });
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

fn data_probe_matches(seq: u32, ts: u64, data: &[u8]) -> bool {
    is_rgp(data) && data[3] == b'R'
        && data[4..8] == seq.to_le_bytes() && data[8..16] == ts.to_le_bytes()
}

struct ExitProbeGuard<'a> {
    ctx: &'a ClientCtx,
    id: LinkId,
    ready: bool,
}

impl Drop for ExitProbeGuard<'_> {
    fn drop(&mut self) {
        self.ctx.data_wait.lock().unwrap().remove(&self.id);
        if !self.ready {
            // Отмена внешнего timeout тоже освобождает только новый пробный Link.
            let (node, id) = (self.ctx.node.clone(), self.id);
            tokio::spawn(async move { let _ = node.engine().close_link(&id).await; });
        }
    }
}

/// Подключиться к выходу: путь, Link, identify, AUTH_OK и проверенная датаграмма.
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
        send_ctl(&ctx.node, id, T_USE, &client_info_body(&ctx.identity, &ctx.state)).await;
    }
    ctx.node.identify_link(&id, &ctx.identity).await.map_err(|e| anyhow::anyhow!("identify: {e:?}"))?;
    if let Some(c) = &ctx.c13 {
        if let Some(pk) = cand.pk {
            lxmf_sync::queue_proof(&ctx.state, c.trust.clone(), ctx.identity.public_key_bytes(), pk);
            if let Some(s) = enroll_net::find(&ctx.state) { s.send_proofs(pk); }
        }
        // повтор T_USE после identify: если первый пакет отстал, узел уже увидит намерение стать клиентом
        send_ctl(&ctx.node, id, T_USE, &client_info_body(&ctx.identity, &ctx.state)).await;
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
            ctx.sync_to(id, vec![], pols);
        }
        let recs = {
            let tr = c.trust.lock().unwrap();
            cand.pk.map(|pk| tr.records_visible_to(&pk)).unwrap_or_default()
        };
        if !recs.is_empty() {
            ctx.sync_to(id, recs, vec![]);
        }
    }
    // Управляющий Channel может отвечать, пока ненадёжные датаграммы по тому же
    // пути не проходят. Такой Link не должен вытеснять рабочий запасной выход.
    let (seq, ts) = (rand_core::OsRng.next_u32(), now_us());
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let room = {
        let mut pending = ctx.data_wait.lock().unwrap();
        if pending.len() >= 32 { false } else { pending.insert(id, (seq, ts, tx)); true }
    };
    if !room {
        let _ = ctx.node.engine().close_link(&id).await;
        bail!("слишком много проверок датаграмм выхода");
    }
    let mut probe = ExitProbeGuard { ctx, id, ready: false };
    for _ in 0..3 {
        spawn_dgram(&ctx.node, id, dgram_ping(seq, ts, b'P'));
        match tokio::time::timeout(Duration::from_secs(1), &mut rx).await {
            Ok(Ok(())) => { probe.ready = true; break; }
            Ok(Err(_)) => break,
            Err(_) => {}
        }
    }
    ctx.data_wait.lock().unwrap().remove(&id);
    if !probe.ready {
        let iface = ctx.node.engine().link_stats(&id).and_then(|s| s.attached_interface());
        let _ = ctx.node.engine().close_link(&id).await;
        let why = format!("{}: нет ответа на датаграммы выхода", cand.name);
        return Err(match iface {
            Some(iface) => anyhow::Error::new(path::FailedPath { iface, why }),
            None => anyhow::anyhow!(why),
        });
    }
    ctx.sh.note(format!("выход {} принял клиента за {} мс (хопов {:?})", cand.name, t0.elapsed().as_millis(), ctx.node.hops_to(&dest)));
    ctx.node.engine().set_link_keepalive(&id, Some(CLIENT_KEEPALIVE_S));
    ctx.remember_rns_rtt(cand.dest, &id);
    Ok((id, handle))
}

fn candidates(ctx: &Arc<ClientCtx>, banned: &path::ExitBackoff, only: Option<[u8; 16]>) -> Vec<CServer> {
    // 0013: допущенный EXIT может требовать discovery, даже без адресов/кэша пути.
    // Legacy сохраняет прежнее требование достижимости; бан ограничивает повторные попытки.
    let mut v: Vec<CServer> = ctx.servers.lock().unwrap().iter().filter(|s| exit_eligible(ctx, s) && banned.ready(&s.dest, Instant::now())).cloned().collect();
    if let Some(o) = only {
        v.retain(|s| s.dest == o);
        return v;
    }
    // «Авто»: сначала узлы с измеренным RTT полного RNS Link; затем остальные по хопам и RTT из таблицы сервера
    // (это RTT между сервером и узлом, а не телефоном, поэтому как главный критерий не годится). Равные в пределах 15% и 3 мс считаются равными: тогда решает число хопов.
    let phone_rtt = |d: &[u8; 16]| -> Option<f64> {
        ctx.rns_rtt(d)
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
        let have: Vec<_> = t.extra.read().unwrap().iter().map(|(d,x)|(*d,x.clone())).collect();
        let interfaces = self.node.engine().interface_stats();
        let extras: Vec<serde_json::Value> = have.iter().map(|(d, x)| {
            let attached = self.node.engine().link_stats(&x.id).and_then(|s|s.attached_interface());
            let label = attached.and_then(|i|interfaces.iter().find(|v|v.interface_id.0==i))
                .and_then(|i|i.name.strip_prefix("iroh-dg-out-").or_else(||i.name.strip_prefix("tcp-out-")))
                .and_then(|n|n.rsplit_once('-').map(|v|v.0));
            let hop = label.and_then(|label|self.carriers.lock().unwrap().iter().find(|(_,c)|*c.label.lock().unwrap()==label).map(|(d,_)|*d));
            serde_json::json!({"d":hex(d),"n":servers.iter().find(|e|e.dest==*d).map(|e|self.shown_name(e)),
                "age_s":(now_ms() as u64).saturating_sub(x.last_rx_ms.load(Relaxed))/1000,
                "sent_pkts":x.sent_pkts.load(Relaxed),"path_known":hop.is_some(),"via":hop.filter(|hop|hop!=d).map(|hop|hex(&hop))})
        }).collect();
        let assignments: Vec<_> = rc.exits().into_iter().map(|d| {
            let lists: Vec<_> = rc.rules.iter().filter(|r| r.action == route::Action::Exit(d)).map(|r| format!("{}:{}",r.kind,r.name)).collect();
            let manual = rc.manual.iter().filter(|r| r.action == route::Action::Exit(d)).count();
            serde_json::json!({"d":hex(&d),"lists":lists,"manual":manual})
        }).collect();
        let pending: Vec<String> = self.rpending.lock().unwrap().iter().map(|d| hex(d)).collect();
        serde_json::json!({"mode": rc.mode, "on": t.routing.load(Relaxed), "extras": extras, "pending": pending, "report": self.rreport.lock().unwrap().clone(),
            "assignments":assignments,"extra_pkts": t.rt.extra_pkts.load(Relaxed), "waiting_pkts": t.rt.waiting_pkts.load(Relaxed), "direct_fallback_pkts": t.rt.direct_fallback_pkts.load(Relaxed), "dot_dropped": t.rt.dot_dropped.load(Relaxed)})
    }
}

/// Раздельное туннелирование клиента: перечитывает `routing.json` и файлы списков, собирает правила и держит дополнительные Link к выходам,
/// на которые правила шлют трафик. Основной выход выбирает `client_supervisor`; здесь только то, что сверх него.
fn discover_recovery_path(ctx: &Arc<ClientCtx>, dest: [u8;16], link: LinkId) {
    let avoid = ctx.node.engine().link_stats(&link).and_then(|s|s.attached_interface());
    let c = ctx.clone();
    tokio::spawn(async move {
        // Только наши носители, общий PathGate (20 с); RNS выбирает обход, а не KnotHop.
        wait_scoped_path(&c.node, &c.path_gate, &DestinationHash::new(dest), || carrier_ifaces(&c, None), avoid, 8).await;
    });
}

async fn route_manager(ctx: Arc<ClientCtx>) {
    let fin = ctx.state.join("fin");
    let cfg_path = ctx.state.join("routing.json");
    let rules = route::rules_dir(&ctx.state);
    let stamp_of = || -> Vec<Option<(std::time::SystemTime, u64)>> {
        [cfg_path.clone(), rules.join("geoip.dat"), rules.join("geosite.dat")].iter().map(|p| std::fs::metadata(p).ok().and_then(|m| Some((m.modified().ok()?, m.len())))).collect()
    };
    let mut stamp = Vec::new();
    let mut pacers: HashMap<LinkId, Pacer> = HashMap::new();
    let mut recovering = HashSet::new();
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
                ctx.sh.note(format!("маршрутизация: режим {}, правил {}, ручных {}{}", cfg.mode, cfg.rules.len(), cfg.manual.len(),
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
            let now = now_ms() as u64;
            let acked = ctx.node.engine().link_stats(&x.id).map(|s| s.keepalives_acked()).unwrap_or(0);
            let pkts = ctx.tun.traffic_pkts();
            let step = pacers.entry(x.id).or_insert_with(|| Pacer { last_pkts: pkts, ..Default::default() })
                .step(now, pkts, x.last_rx_ms.load(Relaxed), acked, CLIENT_KEEPALIVE_S * 1000, ctx.fail_ms.max(3000));
            if step.keepalive_ack { x.last_rx_ms.store(now, Relaxed); }
            if step.silent_ms >= ctx.fail_ms.max(3000) {
                if recovering.insert(x.id) { discover_recovery_path(&ctx, *d, x.id); }
                if let Some(cc) = ctx.carriers.lock().unwrap().get(d) {
                    if cc.is_quic() { cc.prefer_tcp.store(true, Relaxed); }
                }
            } else { recovering.remove(&x.id); }
            let why = if !wanted.contains(d) { Some("не нужен") } else if closed { Some("закрыт") } else if step.silent_ms >= ctx.fail_ms.max(3000) + SILENCE_GRACE.as_millis() as u64 { Some("нет ответа") } else { None };
            if let Some(why) = why {
                ctx.tun.extra.write().unwrap().remove(d);
                pacers.remove(&x.id);
                recovering.remove(&x.id);
                let _ = ctx.node.engine().close_link(&x.id).await;
                if why != "не нужен" {
                    ctx.sh.note(format!("доп. выход {}: {why}", hex(&d[..4])));
                    ctx.rback.lock().unwrap().insert(*d, Instant::now() + Duration::from_secs(10));
                }
            } else if step.ping {
                seq = seq.wrapping_add(1);
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
                        c2.tun.extra.write().unwrap().insert(d, ExtraLink { id, handle, last_rx_ms: Arc::new(std::sync::atomic::AtomicU64::new(now_ms() as u64)), sent_pkts: Default::default() });
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
    let mut inbox_durable = ClientInboxProgress::default();
    while !fin.exists() {
        tokio::time::sleep(Duration::from_secs(4)).await;
        if c.invite.lock().unwrap().is_some() {
            continue;
        }
        ctx.take_local_inbox13(&mut inbox_durable);
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
            ctx.sync_to(id, vec![], pols);
        }
        ctx.refresh_servers13();
    }
}

async fn client_supervisor(ctx: Arc<ClientCtx>) {
    let fin = ctx.state.join("fin");
    let sel_file = ctx.state.join("select");
    let mut banned = path::ExitBackoff::default();
    let mut avoid: HashMap<[u8; 16], usize> = HashMap::new();
    // Рабочий запасной Link живёт и во время проверки выбранного выхода.
    // Неудачная проба не создаёт новый Link к прежнему выходу и не считается сменой.
    let mut active: Option<(CServer, LinkId, Arc<leviculum_std::LinkHandle>)> = None;
    let mut primary: Option<[u8;16]> = None;
    let mut pending_reason: Option<String> = None;
    let mut seq = 0u32;
    let mut keep_trying: HashMap<[u8; 16], Instant> = HashMap::new();
    // QAB-M2: перенос на QUIC не удался, а прежний Link мог быть вытеснен сервером; когда начался перенос; восстановленный выход и время
    let mut pair_delay = 2u64;
    while !fin.exists() {
        // 0013: сначала зачисление по приглашению (до него права есть только в собственном дереве, выходов нет)
        if ctx.c13.as_ref().map(|c| c.invite.lock().unwrap().is_some()).unwrap_or(false) {
            if let Err(e) = pair_client(&ctx).await {
                ctx.sh.note(format!("зачисление: {e:#}"));
                if e.downcast_ref::<enroll_net::Declined>().is_some() || e.downcast_ref::<enroll_net::Refused>().is_some() {
                    if let Some(c) = &ctx.c13 { *c.rejected.lock().unwrap() = Some(e.to_string()); }
                }
                if ctx.c13.as_ref().map(|c| c.rejected.lock().unwrap().is_some()).unwrap_or(false) {
                    return;
                }
                // неверный pin и недоступные ноды не повторяем часто: fail2ban нод растёт с числом неудач
                tokio::time::sleep(Duration::from_secs(pair_delay)).await;
                pair_delay = (pair_delay * 2).min(60);
            }
            continue;
        }
        // выбор пользователя: "auto" или хеш выхода
        let want: Option<[u8; 16]> = std::fs::read_to_string(&sel_file).ok().and_then(|t| dest32(t.trim()));
        // выход, на котором только что сменили носитель, идёт первым
        let keep_first: Option<[u8; 16]> = keep_trying.iter().find(|(_, t)| **t > Instant::now()).map(|(d, _)| *d);
        let mut cands = candidates(&ctx, &banned, want.or(keep_first));
        // Закрепление только явного выбора. В авто-режиме действующий выход лишь идёт первым среди живых,
        // отказавший выход отступает и подключается следующий (старый Link закрывается после нового).
        if want.is_none() {
            if let Some(i) = primary.and_then(|p| cands.iter().position(|c| c.dest == p)) {
                let c = cands.remove(i);
                cands.insert(0, c);
            }
        }
        let mut connected = None;
        for c in cands {
            if let Some(old) = active.as_ref().filter(|a| a.0.dest == c.dest && !keep_trying.get(&c.dest).map(|t| *t > Instant::now()).unwrap_or(false)) {
                connected = Some(old.clone());
                break;
            }
            *ctx.status.lock().unwrap() = format!("подключаюсь к {}", c.name);
            let av = avoid.get(&c.dest).copied();
            // Старый Link обслуживает штатный keepalive RNS и во время подключения нового.
            let result = connect_exit(&ctx, &c, av).await;
            match result {
                Ok((id, h)) => {
                    avoid.remove(&c.dest);
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
                    // Неудачный путь забываем и через транзит: следующий scoped discovery
                    // спрашивает другие наши интерфейсы; сам маршрут по-прежнему выбирает RNS.
                    if let Some(i) = e.downcast_ref::<path::FailedPath>().map(|p| p.iface) {
                        let dest = DestinationHash::new(c.dest);
                        if path::forget_failed_path(i, ctx.node.engine().get_path_clone(&dest).map(|p| p.interface_index)) {
                            ctx.node.engine().remove_path(&dest);
                        }
                        avoid.insert(c.dest, i);
                    }
                    // после смены носителя этот выход пробуем снова сразу, без бана (пока не истёк срок keep_trying)
                    let keep = keep_trying.get(&c.dest).map(|t| *t > Instant::now()).unwrap_or(false);
                    if !keep {
                        let delay = banned.failed(c.dest, Instant::now());
                        ctx.sh.note(format!("{}: повторная проверка через {} с", c.name, delay.as_secs()));
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
        if connected.is_none() {
            connected = active.as_ref().filter(|old| want.map_or(true, |d| old.0.dest == d)).cloned();
        }
        let Some((cand, id, handle)) = connected else {
            *ctx.tun.client_link.write().unwrap() = None;
            *ctx.cur.lock().unwrap() = None;
            ctx.publish_service();
            *ctx.status.lock().unwrap() = "восстанавливаю путь к выбранной ноде; другой выход не подставляется".into();
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        };
        keep_trying.remove(&cand.dest);
        let gen_at_connect = ctx.carriers.lock().unwrap().get(&cand.dest).map(|c| c.generation.load(Relaxed)).unwrap_or(0);
        let old_link = active.as_ref().map(|a| a.1);
        let reused = old_link == Some(id) && ctx.cur.lock().unwrap().map(|c| c.1) == Some(id);
        let previous_name = active.as_ref().map(|a| a.0.name.clone()).unwrap_or_default();
        active = Some((cand.clone(), id, handle.clone()));
        primary = Some(cand.dest);
        if !reused {
            *ctx.tun.client_link.write().unwrap() = Some(handle);
            *ctx.tun.main_dest.write().unwrap() = cand.dest;
            let prev = ctx.cur.lock().unwrap().replace((cand.dest, id, Instant::now()));
            ctx.last_pong.store(now_ms() as u64, Relaxed);
            ctx.loss.lock().unwrap().clear();
            *ctx.rtt_ms.lock().unwrap() = None;
            *ctx.status.lock().unwrap() = format!("выход: {}", cand.name);
            ctx.publish_service();
            if let Some((_, old, _)) = prev {
                if let Some(reason) = pending_reason.take() {
                    ctx.failovers.lock().unwrap().push(serde_json::json!({"at_ms": now_ms() as u64, "from": previous_name, "reason": reason}));
                }
                let _ = ctx.node.engine().close_link(&old).await;
            } else if let Some(old) = old_link.filter(|old| *old != id) {
                let _ = ctx.node.engine().close_link(&old).await;
            }
            ctx.sh.note(format!("текущий выход: {} ({})", cand.name, &hex(&cand.dest)[..8]));
        }

        // обслуживание: пинг раз в секунду, смена по просьбе пользователя, отказ -> следующий выход
        let mut pacer = Pacer { last_pkts: ctx.tun.traffic_pkts(), ..Default::default() };
        let mut sil_grace: Option<Instant> = None;
        let mut better_since: Option<Instant> = None;
        let mut last_eval = Instant::now();
        let connected_at = ctx.cur.lock().unwrap().map(|c| c.2).unwrap_or_else(Instant::now);
        let reason = loop {
            if fin.exists() {
                break "fin".to_string();
            }
            banned.healthy(&cand.dest, connected_at, Instant::now());
            let want: Option<[u8; 16]> = std::fs::read_to_string(&sel_file).ok().and_then(|t| dest32(t.trim()));
            let unavailable = want.filter(|w| *w != cand.dest).and_then(|w| {
                let why = ctx.lk_fail.lock().unwrap().get(&w).map(|(_, why)| why.clone())?;
                let name = ctx.servers.lock().unwrap().iter().find(|s| s.dest == w).map(|s| ctx.shown_name(s)).unwrap_or_else(|| hex(&w[..4]));
                let retry = banned.remaining(&w, Instant::now()).as_secs();
                Some(format!("выбранный выход {name} недоступен: {why}; повтор через {retry} с; работаю через {}", ctx.shown_name(&cand)))
            });
            *ctx.status.lock().unwrap() = unavailable.unwrap_or_else(|| format!("выход: {}", ctx.shown_name(&cand)));
            // Авто-режим: уходим с выхода только при кратно худшем RTT (в 2 раза и на 100 мс) дольше 20 с; новый Link поднимается до закрытия старого.
            // Явно выбранный выход и работающий Link при этом не трогаются.
            if want.is_none() && last_eval.elapsed() >= Duration::from_secs(3) {
                last_eval = Instant::now();
                let cur_rtt = ctx.rns_rtt(&cand.dest);
                let best = candidates(&ctx, &banned, None).into_iter().find(|c| c.dest != cand.dest && ctx.rns_rtt(&c.dest).is_some());
                let better = match (cur_rtt, best.as_ref().and_then(|b| ctx.rns_rtt(&b.dest))) {
                    (Some(cr), Some(br)) => cr > br * 2.0 && cr - br > 100.0,
                    _ => false,
                };
                if better {
                    if better_since.get_or_insert(Instant::now()).elapsed() >= Duration::from_secs(20) {
                        break format!("авто: {} быстрее", best.as_ref().map(|b| b.name.clone()).unwrap_or_default());
                    }
                } else {
                    better_since = None;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            let k = hex(id.as_bytes());
            if let Some(r) = ctx.sh.closed.lock().unwrap().get(&k) {
                break format!("link закрыт: {r}");
            }
            let (acked, ka_rtt) = ctx.node.engine().link_stats(&id).map(|s| (s.keepalives_acked(), s.keepalive_rtt_ms())).unwrap_or((0, None));
            let now = now_ms() as u64;
            let step = pacer.step(now, ctx.tun.traffic_pkts(), ctx.last_pong.load(Relaxed), acked, CLIENT_KEEPALIVE_S * 1000, ctx.fail_ms);
            if step.keepalive_ack {
                ctx.remember_rns_rtt(cand.dest, &id);
                // ответ keepalive RNS - контакт; его RTT нужен индикации, если свежих RGP нет
                ctx.last_pong.store(now, Relaxed);
                if now.saturating_sub(ctx.rtt_pong.load(Relaxed)) >= 5_000 {
                    if let Some(r) = ka_rtt {
                        *ctx.rtt_ms.lock().unwrap() = Some(r as f64);
                        ctx.rtt_pong.store(now, Relaxed);
                    }
                }
            }
            ctx.contact_window_ms.store(step.contact_window_ms, Relaxed);
            if step.silent_ms >= ctx.fail_ms.max(3000) {
                // Тишина на QUIC: носитель меняется внутри интерфейса пира (`mux.rs`), Link при этом не рвётся. Link держим, пока TCP не подтвердится
                // или не кончится `SILENCE_GRACE`; тишина без шансов (TCP уже выбран, либо время вышло) - прежний отказ выхода.
                if sil_grace.is_none() {
                    let cc = ctx.carriers.lock().unwrap().get(&cand.dest).cloned();
                    if let Some(cc) = cc {
                        let _ = judge_silence(&cc, false, Instant::now());
                    }
                    ctx.sh.note(format!("{}: восстанавливаю связь, сохраняю Link до {} с", cand.name, SILENCE_GRACE.as_secs()));
                    discover_recovery_path(&ctx, cand.dest, id);
                    sil_grace = Some(Instant::now() + SILENCE_GRACE);
                }
                if !sil_grace.is_some_and(|u| Instant::now() < u) {
                    break format!("нет ответа {} мс", step.silent_ms);
                }
            } else {
                sil_grace = None;
            }
            if let Some(w) = want {
                // Явный выбор не разрешает продолжать отправку через старый выход, даже если новый пока недоступен.
                if w != cand.dest {
                    break "выбор пользователя".to_string();
                }
            }
            if step.ping {
                seq = seq.wrapping_add(1);
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
        let user = reason == "выбор пользователя" || reason.starts_with("авто:");
        if reason.starts_with("авто:") { primary = None; }
        if user {
            ctx.sh.note(format!("проверка выхода: {reason}"));
            pending_reason = Some(reason.clone());
        } else {
            ctx.sh.note(format!("смена выхода: {reason}"));
            ctx.failovers.lock().unwrap().push(serde_json::json!({"at_ms": now_ms() as u64, "from": cand.name, "reason": reason}));
            pending_reason = None;
        }
        let carrier_flip = ctx.carriers.lock().unwrap().get(&cand.dest).map(|c| carrier_flipped(c, gen_at_connect)).unwrap_or(false);
        if reason.starts_with("нет ответа") {
            // Тишина после смены носителя (в том числе нашей: дозвон снял TCP по паузе возврата) объяснена сменой: Link привязан к прежнему
            // интерфейсу. QUIC в ней не виноват; если Link, поднятый уже на этом QUIC, замолчит снова, пойдёт обычная ветка.
            // Тишина Link, жившего на текущем QUIC: вероятно, UDP режется; у этого пира пробуем запасной TCP и запоминаем QUIC (health.rs).
            let cc = ctx.carriers.lock().unwrap().get(&cand.dest).cloned();
            if let Some(cc) = cc {
                match judge_silence(&cc, carrier_flip, Instant::now()) {
                    SilenceCause::Quic => ctx.sh.note(format!("{}: тишина по QUIC, пробую TCP (QUIC запомню, только если TCP сразу подтвердится)", cand.name)),
                    SilenceCause::CarrierSwap => ctx.sh.note(format!("{}: тишина после смены носителя, QUIC не виню", cand.name)),
                    SilenceCause::Other => {}
                }
            }
        }
        // Выбранный пользователем выход при смене носителя не бросаем: Link закрыт ради TCP, тот же выход поднимется заново за секунды.
        // Если за это время не поднялся — обычный отступ и переход на лучший из остальных.
        if carrier_flip && !user {
            keep_trying.insert(cand.dest, Instant::now() + Duration::from_secs(25));
            ctx.sh.note(format!("{}: смена носителя, остаюсь на этом выходе", cand.name));
        }
        if !user {
            // Отказавший выход отступает независимо от работающего запасного.
            ctx.lk_fail.lock().unwrap().insert(cand.dest, (Instant::now(), reason.chars().take(80).collect()));
            banned.failed(cand.dest, Instant::now());
            if let Some(i) = ctx.node.engine().link_stats(&id).and_then(|s| s.attached_interface()) {
                avoid.insert(cand.dest, i);
                let dest = DestinationHash::new(cand.dest);
                if ctx.node.engine().get_path_clone(&dest).map(|p| p.interface_index) == Some(i) {
                    ctx.node.engine().remove_path(&dest);
                }
            }
            if want.is_some() {
                active = None;
                *ctx.tun.client_link.write().unwrap() = None;
                *ctx.cur.lock().unwrap() = None;
                ctx.publish_service();
                let _ = ctx.node.engine().close_link(&id).await;
            } else {
                // Авто: прежний Link остаётся до подключения следующего выхода (или до возврата этого после бана).
                pending_reason = Some(reason.clone());
            }
        }
    }
}

/// Этапы A/B make-before-break (раздел 13 отчёта): состояние возврата, допуск эха, откат на этап 0. Без сети.
#[cfg(test)]
mod carrier_tests {
    use super::*;

    #[test]
    fn silence_grace_covers_carrier_switch_and_path_discovery() {
        assert!(SILENCE_GRACE >= Duration::from_secs(25), "TCP handshake and discovery must get time to recover");
    }

    #[test]
    fn lxmf_and_pn_destinations_never_enter_incoming_vpn_admission() {
        let identity = leviculum_std::api::generate_identity();
        let vpn = dest_from_pub_tag(&identity.public_key_bytes(), T13_TAG);
        let delivery = DestinationHash::new(lxmf_admin::lxmf_destination(identity.hash()));
        let pn = leviculum_lxmf::PropagationTransport::destination(identity).unwrap();
        assert!(vpn_incoming_destination(&vpn, &DestinationHash::new(vpn)));
        assert!(!vpn_incoming_destination(&vpn, &delivery));
        assert!(!vpn_incoming_destination(&vpn, pn.hash()));
    }

    // расписание возврата с TCP на QUIC не зависит от зонда: пауза удваивается до потолка, разрешение узла реже расписания
    #[test]
    fn return_schedule_stays_slower_than_grant_interval() {
        assert_eq!(grown_back_off(120), 240);
        assert_eq!(grown_back_off(TCP_BACK_OFF_MAX_S), TCP_BACK_OFF_MAX_S);
        assert!(qprobe::GRANT_INTERVAL < Duration::from_secs(TCP_BACK_OFF_FIRST_S), "разрешение не ограничивает штатное расписание");
    }
}
