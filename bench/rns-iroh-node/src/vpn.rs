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
use crate::{invite, lxmf_admin, lxmf_sync, ncmd, peers};
use clap::{Args, Subcommand};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

#[path = "vpn_path.rs"]
mod path;
#[path = "rrc.rs"]
mod rrc;



// ------------------------------------------------------------------------------------------------ команды

#[derive(Parser, Clone)]
#[command(name = "knothopd", about = "KnotHop: серверный узел, хаб и клиент VPN")]
pub struct VpnCli {
    #[command(subcommand)]
    pub cmd: VpnCmd,
}

#[derive(Subcommand, Clone)]
pub enum VpnCmd {
    /// узел сети (выход, сосед, транзит; права — таблица на ноде, ADR 0028)
    Node(NodeArgs),
    /// ретранслятор RNS (лабораторная «публичная сеть»)
    Hub(HubArgs),
    /// клиент VPN (identity и таблица из state; приглашение — через «Вступить»)
    Client(ClientArgs),
    /// таблица этой ноды: права соседей, контакты, приглашения, ожидающие пары, очередь команд (работающая нода)
    List(StateArg),
    /// выпустить приглашение (строку для получателя); без --nodes — на этой ноде, с --nodes — на перечисленных (админ)
    Invite(InviteArgs),
    /// вступить по строке приглашения из файла 0600 (`-` — stdin): работающая нода гасит пары сама (клиент, ПК, сервер без --invite-file)
    Join(JoinArgs),
    /// знакомство нод: автоматические приглашения на каждую пару, ноды гасят их сами (в т.ч. через PN)
    Introduce(IntroduceArgs),
    /// правка таблицы: set | remove | revoke-by | config | list; на работающей ноде через её сокет, `--offline` — прямо в peers.json (узел остановлен)
    Peers(PeersArgs),
    /// создать identity, если её ещё нет, и записать `whoami.json` (хеш и адрес в туннеле): приложению адрес нужен до создания TUN
    Whoami(StateArg),
    /// список категорий скачанных geoip.dat/geosite.dat в `rules-cats.json` (раздельное туннелирование)
    RulesList(StateArg),
    /// подсети правил «мимо туннеля» в `direct.cidr` и отчёт `rules-report.json`
    RulesCompile(StateArg),
}

#[derive(Args, Clone)]
pub struct InviteArgs {
    #[arg(long)]
    pub state: PathBuf,
    /// что получит принявший на выпустившей ноде: user (USE), server, admin, число или список (USE+EXIT)
    #[arg(long, default_value = "user")]
    pub rights: String,
    /// ноды, где приглашение должно быть погашено: identity-хеши (32 hex) через запятую, от 1 до 8; без списка — только эта нода
    #[arg(long, value_delimiter = ',')]
    pub nodes: Vec<String>,
    /// срок приглашения, часов (по умолчанию 48, максимум 168)
    #[arg(long, default_value_t = 48)]
    pub ttl_h: u64,
    /// записать строку в файл (0600) вместо stdout
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args, Clone)]
pub struct JoinArgs {
    #[arg(long)]
    pub state: PathBuf,
    #[arg(long)]
    pub invite_file: PathBuf,
}

#[derive(Args, Clone)]
pub struct IntroduceArgs {
    #[arg(long)]
    pub state: PathBuf,
    /// identity-хеши нод (32 hex) через запятую, от 2 до 12
    #[arg(long, value_delimiter = ',')]
    pub nodes: Vec<String>,
    /// что каждая нода разрешает остальным
    #[arg(long, default_value = "server")]
    pub rights: String,
}

#[derive(Args, Clone)]
pub struct PeersArgs {
    /// set | remove | revoke-by | config | list
    pub action: String,
    #[arg(long)]
    pub state: PathBuf,
    /// нода, которой адресована правка (32 hex); по умолчанию эта
    #[arg(long)]
    pub target: Option<String>,
    /// публичный ключ соседа (128 hex) для set
    #[arg(long)]
    pub pk: Option<String>,
    /// хеш соседа (32 hex) для remove
    #[arg(long)]
    pub hash: Option<String>,
    #[arg(long)]
    pub rights: Option<String>,
    #[arg(long)]
    pub name: Option<String>,
    /// issuer для revoke-by: local, hex хеша или invite:ID
    #[arg(long)]
    pub issuer: Option<String>,
    /// config: transit_enabled / exit_enabled
    #[arg(long)]
    pub transit: Option<bool>,
    #[arg(long)]
    pub exit: Option<bool>,
    /// править peers.json напрямую (узел остановлен): восстановление управления на сервере
    #[arg(long)]
    pub offline: bool,
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
    /// строка приглашения из приложения админа (ADR 0028 §2.5) из файла 0600 или `-` (stdin); в argv секрет виден через /proc
    #[arg(long)]
    pub invite_file: Option<PathBuf>,
    /// принять права управления, даже если у ноды уже есть управляющие (иначе повторный инвайт отклоняется)
    #[arg(long)]
    pub accept_manage: bool,
    /// iroh-relay для hole punching: TLS-relay делит TCP-порт `--port` с носителем, QAD слушает отдельный UDP-порт (по умолчанию выключено)
    #[arg(long)]
    pub iroh_relay: bool,
    /// UDP-порт QAD (определение собственного публичного адреса); нужен файрвол-разрешение владельца узла
    #[arg(long, default_value_t = 47002)]
    pub relay_quic_port: u16,
    /// iroh-relay для hole punching, `host:порт` (TLS на TCP-порту ноды с `--iroh-relay`), через запятую: ключ relay должен быть ключом доверенной ноды
    #[arg(long, default_value = "")]
    pub relay_url: String,
    /// REALITY (последний уровень запасного пути): TCP-слушатель `ip:порт`, обычно 127.0.0.1:порт за Traefik (HostSNI passthrough + PROXY v2). По умолчанию выключено
    #[arg(long)]
    pub reality_listen: Option<String>,
    /// сайт-прикрытие `host:порт`: чужой настоящий сайт с TLS 1.3 и h2, не на этом узле (обязателен с --reality-listen)
    #[arg(long)]
    pub reality_dest: Option<String>,
    /// допустимые SNI через запятую (по умолчанию имя из --reality-dest)
    #[arg(long, default_value = "")]
    pub reality_sni: String,
    /// сети, от которых принимается PROXY v2 (адреса Traefik), через запятую; пусто - PROXY не ждём
    #[arg(long, default_value = "")]
    pub reality_proxy_trusted: String,
    /// внешний порт REALITY для клиентов (Traefik :443), по умолчанию 443
    #[arg(long)]
    pub reality_public_port: Option<u16>,
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
    /// расширенный журнал (снимки состояния, причины закрытия Link, задержки цикла)
    debug: Option<bool>,
    quic_cc_mbit: Option<u64>,
    workers: Option<usize>,
    /// потолок хранилища PN, МиБ; нет — 1% свободного места в пределах 2…100
    pn_cap_mb: Option<u64>,
    /// хаб RRC на серверной ноде: включён по умолчанию, `false` отключает; `rrc_name` - имя в WELCOME (по умолчанию «hub»)
    rrc: Option<bool>,
    rrc_name: Option<String>,
    tun_name: Option<String>,
    client_net: Option<String>,
    invite_file: Option<PathBuf>,
    iroh_relay: bool,
    relay_quic_port: Option<u16>,
    relay_urls: Vec<String>,
    /// REALITY: см. одноимённые флаги `--reality-*`
    reality_listen: Option<String>,
    reality_dest: Option<String>,
    reality_sni: Vec<String>,
    reality_proxy_trusted: Vec<String>,
    reality_public_port: Option<u16>,
}

/// Символ допустим в отображаемом имени от пира: без управляющих и без невидимых/меняющих направление текста (подмена имени в UI).
fn name_char_ok(c: char) -> bool {
    !c.is_control() && !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// Единственная нормализация имени узла (своего, из настроек и от пира): до 32 знаков, без управляющих и невидимых, без пробелов по краям.
/// Больше в имени ничего не разбирается: иконку интерфейс берёт из самого имени (ведущий эмодзи или первые два знака).
fn norm_name(name: &str) -> Option<String> {
    let name: String = name.chars().filter(|c| name_char_ok(*c)).take(32).collect();
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Имя контакта — только подсказка для отображения, не свидетельство роли или права.
fn contact_name_or_dest(name: &str, dest: &[u8; 16]) -> String {
    norm_name(name).unwrap_or_else(|| hex(dest)[..8].to_string())
}

/// Имя клиента для сети: заданное пользователем (оболочка кладёт state/node-name.txt), иначе «телефон-XXXXXX» по хешу identity.
/// Имя раздаёт сам узел (клиент сообщает его выходу в T_USE, выход передаёт дальше в T_NBRS); приглашение его не переносит.
fn client_display_name(identity: &Identity, state: &Path) -> String {
    if let Some(n) = std::fs::read_to_string(state.join("node-name.txt")).ok().and_then(|t| norm_name(&t)) {
        return n;
    }
    match peers::hash_of(&identity.public_key_bytes()) {
        Some(h) => format!("телефон-{}", &hex(&h)[..6]),
        None => "телефон".into(),
    }
}

/// Тело T_USE от клиента: длина и имя узла, чтобы выход раздал его другим клиентам.
fn client_info_body(identity: &Identity, state: &Path) -> Vec<u8> {
    let name = client_display_name(identity, state);
    let mut b = Vec::with_capacity(1 + name.len());
    b.push(name.len() as u8);
    b.extend_from_slice(name.as_bytes());
    b
}

/// Ключ - узел сети (по его собственным сведениям роль TRANSIT/EXIT), а не рядовой пользователь: только таких раскрываем другим клиентам.
fn node_like(tr: &peers::Peers, pk: &[u8; 64]) -> bool {
    tr.roles_of_key(&peers::key_of(pk)) & (peers::TRANSIT | peers::EXIT) != 0
}

/// T_CINFO от соседа-сервера: клиенты-узлы с именем. Права каждого ключа проверяем сами; заявке соседа не верим.
fn on_cinfo(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    let Some(t) = &ctx.t13 else { return };
    if body.len() > 4096 || !ctx.links.lock().unwrap().get(&link).map(|l| matches!(l.role, Role::Server { .. })).unwrap_or(false) {
        return;
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else { return };
    let Some(arr) = v["c"].as_array() else { return };
    let mut got: Vec<([u8; 16], String)> = Vec::new();
    {
        let tr = t.peers.lock().unwrap();
        for x in arr.iter().take(16) {
            let Some(pk) = x["k"].as_str().filter(|k| k.len() == 128 && k.bytes().all(|b| b.is_ascii_hexdigit())).and_then(|k| <[u8; 64]>::try_from(unhex(k)).ok()) else { continue };
            let Some(name) = x["n"].as_str().and_then(norm_name) else { continue };
            if !node_like(&tr, &pk) {
                continue;
            }
            got.push((dest_from_pub_tag(&pk, T13_TAG), name));
        }
    }
    let mut pc = ctx.peer_clients.lock().unwrap();
    pc.retain(|_, v| v.1.elapsed() < CINFO_TTL);
    for (d, n) in got {
        if pc.len() < CINFO_MAX || pc.contains_key(&d) {
            pc.insert(d, (n, Instant::now()));
        }
    }
}

/// Разбор тела T_USE клиента: имя. None - клиент ничего не сообщил или прислал мусор.
fn parse_client_info(body: &[u8]) -> Option<String> {
    let name_len = *body.first()? as usize;
    if body.len() != 1 + name_len {
        return None;
    }
    norm_name(std::str::from_utf8(&body[1..]).ok()?)
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
pub(crate) fn is_global_ip(ip: &std::net::IpAddr) -> bool {
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
    local_addrs_ports(port, port, allow_private, skip_iface, false)
}

/// Как `local_addrs`, но у IPv4- и IPv6-сокета iroh могут быть разные порты (телефон биндится на случайные). Из трёх мест гарантированно
/// есть минимум по одному адресу каждого семейства, если оба нашлись (IPv6 часто единственный прямой путь без NAT).
fn local_addrs_ports(port4: u16, port6: u16, allow_private: bool, skip_iface: &str, lan: bool) -> Vec<String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    // локальная сеть (только клиент, подсказки известным контактам): частный IPv4 и ULA IPv6 идут после глобальных
    let mut l4 = Vec::new();
    let mut l6 = Vec::new();
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
                            v4.push(SocketAddr::new(ip.into(), port4).to_string());
                        } else if lan && !vpn_like_iface(&iname) && is_lan_ip(&ip.into()) {
                            l4.push(SocketAddr::new(ip.into(), port4).to_string());
                        }
                    }
                    libc::AF_INET6 => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
                        if is_global_ip(&std::net::IpAddr::V6(ip)) {
                            v6.push(SocketAddr::new(ip.into(), port6).to_string());
                        } else if lan && !vpn_like_iface(&iname) && is_lan_ip(&ip.into()) {
                            l6.push(SocketAddr::new(ip.into(), port6).to_string());
                        }
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    v4.dedup();
    v6.dedup();
    l4.dedup();
    l6.dedup();
    v4.extend(v6);
    if lan {
        v4.extend(l4);
        v4.extend(l6);
        return peers::balance_hints(v4, peers::MAX_CONTACT_HINTS);
    }
    peers::balance_hints(v4, peers::MAX_HINTS)
}

// ------------------------------------------------------------------------------------------------ локальная сеть для P2P-контактов
// Точечное исключение из фильтра п.5 AGENTS (ADR 0028 §2.4a): частный IPv4 и ULA IPv6 из подсказки ИЗВЕСТНОГО КОНТАКТА без ролей набираются,
// только если (а) адрес пришёл в подписанном шифрованном LXMF (`accept`/`ack`/`addr`, `invite::clean_hints`), (б) он лежит в подсети одного
// из моих текущих интерфейсов (не VPN, не loopback) - проверка на момент каждого набора, (в) ключ проверяется TLS iroh как всегда.
// Общий фильтр (`resolve_addrs`, анонсы, DNS) и `KNOTHOP_ALLOW_PRIVATE_DIAL` не меняются; серверы-соседи это не используют.
// Link-local IPv6 не поддержан: iroh при отправке теряет scope id (`canonical_addr`), адрес fe80:: был бы недостижим.

/// Адрес локальной сети: частный IPv4 (RFC 1918) или ULA IPv6 (fc00::/7). CGNAT, link-local, loopback, служебные - нет.
pub(crate) fn is_lan_ip(ip: &std::net::IpAddr) -> bool {
    match ip.to_canonical() {
        std::net::IpAddr::V4(v) => v.is_private(),
        std::net::IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Подсказка для клиента: обычная (`sane_hint_addr`) либо литеральный `IP:порт` локальной сети. Только синтаксис; имена сюда не входят.
pub(crate) fn sane_hint_addr_lan(a: &str) -> bool {
    sane_hint_addr(a) || (a.len() <= 64 && a.parse::<SocketAddr>().is_ok_and(|sa| sa.port() != 0 && is_lan_ip(&sa.ip())))
}

/// Интерфейс, который никогда не считается локальной сетью: туннели и VPN (`tun*`, `wg*`, `ppp*`, `tap*`, `ipsec*`, `utun*`, `tailscale*`), loopback.
fn vpn_like_iface(name: &str) -> bool {
    name == "lo" || ["tun", "wg", "ppp", "tap", "ipsec", "utun", "tailscale", "dummy"].iter().any(|p| name.starts_with(p))
}

/// Адрес интерфейса: имя, IP, длина префикса, поднят ли.
#[derive(Clone, Debug)]
pub(crate) struct IfAddr {
    pub name: String,
    pub ip: std::net::IpAddr,
    pub prefix: u8,
    pub up: bool,
}

/// Подсети подключённых интерфейсов, пригодные как «локальная сеть»: поднятые, не loopback, не VPN, не `skip` (свой TUN), адрес сам локальный.
pub(crate) fn lan_subnets(ifs: &[IfAddr], skip: &str) -> Vec<(std::net::IpAddr, u8)> {
    ifs.iter().filter(|i| i.up && i.name != skip && !vpn_like_iface(&i.name) && is_lan_ip(&i.ip)).map(|i| (i.ip.to_canonical(), i.prefix)).collect()
}

fn ip_in_subnet(ip: &std::net::IpAddr, net: &std::net::IpAddr, prefix: u8) -> bool {
    match (ip.to_canonical(), net.to_canonical()) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => prefix <= 32 && v4_in(u32::from(a), u32::from(b), prefix as u32),
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => prefix <= 128 && v6_in(u128::from(a), u128::from(b), prefix as u32),
        _ => false,
    }
}

/// Можно ли набрать `ip` как локальный адрес: он локальный (частный/ULA) и лежит в одной из подсетей `nets`.
pub(crate) fn lan_reachable(ip: &std::net::IpAddr, nets: &[(std::net::IpAddr, u8)]) -> bool {
    is_lan_ip(ip) && nets.iter().any(|(n, p)| ip_in_subnet(ip, n, *p))
}

/// Текущие адреса интерфейсов (getifaddrs) с длиной префикса.
fn iface_addrs() -> Vec<IfAddr> {
    let mut out = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() && !ifa.ifa_netmask.is_null() {
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy().to_string();
                let up = ifa.ifa_flags & (libc::IFF_UP as u32) != 0;
                match (*ifa.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let a = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                        out.push(IfAddr { name, ip: std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)).into(), prefix: u32::from_be(m.sin_addr.s_addr).count_ones() as u8, up });
                    }
                    libc::AF_INET6 => {
                        let a = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in6);
                        out.push(IfAddr { name, ip: std::net::Ipv6Addr::from(a.sin6_addr.s6_addr).into(), prefix: u128::from(std::net::Ipv6Addr::from(m.sin6_addr.s6_addr)).count_ones() as u8, up });
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// Адреса для набора контакта: обычный `resolve_addrs` плюс, если `lan` (контакт без ролей, мы клиент), литеральные адреса локальной сети
/// из подсетей текущих интерфейсов. Выбранные LAN-адреса точечно разрешаются в фильтре исходящих iroh (`set_egress_allow`).
async fn resolve_addrs_lan(addrs: &[String], lan: bool, peer: &[u8; 32]) -> Vec<SocketAddr> {
    let mut out = resolve_addrs(addrs).await;
    if !lan {
        return out;
    }
    let nets = lan_subnets(&iface_addrs(), "");
    let mut lan_ips = Vec::new();
    for a in addrs {
        if let Ok(sa) = a.parse::<SocketAddr>() {
            if sa.port() != 0 && !is_global_ip(&sa.ip()) && lan_reachable(&sa.ip(), &nets) && !out.contains(&sa) {
                lan_ips.push(sa.ip());
                out.push(sa);
            }
        }
    }
    iroh::knothop::set_egress_allow(*peer, lan_ips);
    out.sort_by_key(|a| (!is_global_ip(&a.ip()), a.is_ipv6()));
    out
}

/// UDP-порты сокетов iroh (IPv4, IPv6) - для подсказок адресов клиента, который биндится на случайные порты. Нет сокета семейства - порт другого.
fn endpoint_ports(ep: &Endpoint) -> (u16, u16) {
    let s = ep.bound_sockets();
    let p4 = s.iter().find(|a| a.is_ipv4()).map(|a| a.port());
    let p6 = s.iter().find(|a| a.is_ipv6()).map(|a| a.port());
    (p4.or(p6).unwrap_or(0), p6.or(p4).unwrap_or(0))
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
    /// файл с строкой приглашения (0600; приложение пишет сюда «Вступить»): нода берёт пары, файл стирается; пустой файл — ничего не делать
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

// ------------------------------------------------------------------------------------------------ вспомогательное

const T_AUTH_OK: u8 = 9;
const T_AUTH_FAIL: u8 = 10;
// модель прав (решение 0013): записи о правах, зачисление по приглашению
const T_USE: u8 = 14;      // клиент -> сервер: «я пришёл за выходом» (иначе Link - сосед-транзит)
const T_NBRS: u8 = 16;     // выход -> клиент: соседи с живым Link {"n":[{"d","r"}]} (0014 R3); список выходов не меняет
// 17 свободен: бывший T_DIR; адреса соседей приходят в `accept` (контакты), каталога нет (ADR 0028)
/// Advisory observations are bounded by both count and negotiated Channel MDU.
const NBRS_MAX: usize = crate::observations::MAX_NEIGHBORS;
const T_OBSERVE: u8 = 21; // admitted client -> exit: UI visible (one byte 0/1), request fresh T_NBRS
/// сосед-сервер -> сосед-сервер: клиенты-узлы (якорь/TRANSIT/EXIT) с их именем {"c":[{"k","n"}]};
/// получатель проверяет права ключа по своим записям, держит не дольше CINFO_TTL; только для отображения
const T_CINFO: u8 = 22;
/// Живость и RTT по Channel (0024; заменили RGP-датаграммы Link): T_PING [nonce u64 LE] -> T_PONG [тот же nonce].
/// Отвечает только допущенный Link (Server/Client, не `cbc_only`); ответ принимает лишь тот, кто послал именно этот nonce именно на этом Link.
const T_PING: u8 = 23;
const T_PONG: u8 = 24;
const PING_BODY_LEN: usize = 8;
const CINFO_TTL: Duration = Duration::from_secs(60);
const CINFO_MAX: usize = 64;
/// 0015: подписанная политика ноды (`peers::Policy`, 163 Б). Принимается только на допущенном Link (сосед или клиент); верна по подписи самой ноды,
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

/// Подсеть адресов клиентов (одна на всю группу: клиент сохраняет адрес при смене выхода). Задаётся в конфиге узла (`client_net`),
/// выбирается так, чтобы не пересекаться с сетями узлов (на ru1 10.130.0.0/24 попадает в 10.128.0.0/10 - для пилота 198.18.0.0/15).
static CLIENT_NET: std::sync::OnceLock<(u32, u8)> = std::sync::OnceLock::new();

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
    m.into_iter().take(64).filter_map(|(d, n)| Some((dest32(&d)?, norm_name(&n)?))).collect()
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
    fn quic_close_diagnostic_uses_fixed_categories() {
        use iroh::endpoint::ConnectionError as E;
        assert_eq!(quic_close_kind(None), "not-closed");
        assert_eq!(quic_close_kind(Some(&E::TimedOut)), "timeout");
        assert_eq!(quic_close_kind(Some(&E::LocallyClosed)), "local-close");
        assert_eq!(quic_close_kind(Some(&E::Reset)), "reset");
    }

    #[test]
    fn p2p_state_describes_selected_path_not_just_open_connection() {
        for kind in ["direct", "mesh", "relay", "reality"] {
            let info = serde_json::json!({"kind": kind});
            assert_eq!(p2p_state(Some(&info), true, false, 0), kind);
        }
        let no_path = serde_json::json!({"kind": "none"});
        assert_eq!(p2p_state(Some(&no_path), true, false, 0), "trying");
        assert_eq!(p2p_state(None, false, false, 0), "no_addr");
        assert_eq!(p2p_state(None, true, false, 0), "trying");
        assert_eq!(p2p_state(None, true, false, 2), "unreachable");
        assert_eq!(p2p_state(None, true, true, 0), "unreachable");
    }

    fn ifa(name: &str, ip: &str, prefix: u8, up: bool) -> IfAddr {
        IfAddr { name: name.into(), ip: ip.parse().unwrap(), prefix, up }
    }

    #[test]
    fn lan_filter_accepts_own_subnet_only_and_never_vpn_loopback_or_foreign_private() {
        let ifs = vec![
            ifa("wlan0", "192.168.1.20", 24, true),
            ifa("wlan0", "fd9a:1::20", 64, true),
            ifa("wlan0", "fe80::1", 64, true),       // link-local: не локальная сеть для набора
            ifa("lo", "127.0.0.1", 8, true),
            ifa("tun0", "10.8.0.2", 24, true),       // VPN: его подсеть не считается
            ifa("wg0", "10.66.0.2", 24, true),
            ifa("rmnet0", "10.77.0.5", 24, false),   // интерфейс не поднят
            ifa("kh0", "198.18.0.9", 15, true),      // адрес нашего туннеля вне частных диапазонов
        ];
        let nets = lan_subnets(&ifs, "kh0");
        let ok = |s: &str| lan_reachable(&s.parse().unwrap(), &nets);
        assert!(ok("192.168.1.77"), "своя подсеть");
        assert!(ok("fd9a:1::99"), "ULA своей подсети");
        assert!(!ok("192.168.2.77"), "чужая частная подсеть");
        assert!(!ok("10.0.0.5"), "чужая частная");
        assert!(!ok("127.0.0.1") && !ok("::1"), "loopback");
        assert!(!ok("10.8.0.9") && !ok("10.66.0.9"), "подсеть VPN-интерфейса");
        assert!(!ok("10.77.0.9"), "интерфейс не поднят");
        assert!(!ok("fe80::5"), "link-local не набирается");
        assert!(!ok("169.254.1.1"), "link-local IPv4");
        assert!(!ok("8.8.8.8"), "глобальный адрес идёт обычным путём, не через LAN-исключение");
        assert!(!ok("100.64.0.9"), "CGNAT не локальная сеть");
        assert_eq!(nets.len(), 2);
        // свой TUN, названный нестандартно, исключается по имени
        let nets = lan_subnets(&[ifa("vpn7", "192.168.50.2", 24, true), ifa("wlan0", "192.168.1.20", 24, true)], "vpn7");
        assert!(!lan_reachable(&"192.168.50.9".parse().unwrap(), &nets) && lan_reachable(&"192.168.1.9".parse().unwrap(), &nets));
    }

    #[test]
    fn lan_hint_syntax_is_client_only_and_literal_only() {
        for good in ["192.168.1.5:47001", "10.1.2.3:9", "[fd00::5]:47001"] {
            assert!(sane_hint_addr_lan(good), "{good}");
            assert!(!sane_hint_addr(good), "общий фильтр не ослаблен: {good}");
        }
        for bad in ["127.0.0.1:1", "[::1]:1", "169.254.1.1:1", "[fe80::1]:1", "100.64.1.1:1", "192.168.1.5:0", "0.0.0.0:5"] {
            assert!(!sane_hint_addr_lan(bad), "{bad}");
        }
        assert!(sane_hint_addr_lan("8.8.8.8:1"));
        // клиент принимает LAN-подсказку из accept, сервер - нет
        let j = serde_json::json!(["203.0.113.5:1", "8.8.8.8:1", "192.168.1.5:47001"]);
        assert!(crate::invite::clean_hints(&j, true).contains(&"192.168.1.5:47001".to_string()));
        assert!(!crate::invite::clean_hints(&j, false).contains(&"192.168.1.5:47001".to_string()));
    }

    #[test]
    fn hints_keep_one_of_each_kind_global_first() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let all = s(&["1.1.1.1:1", "2.2.2.2:1", "3.3.3.3:1", "4.4.4.4:1", "[2606::1]:1", "192.168.1.5:1", "[fd00::5]:1"]);
        let out = peers::balance_hints(all, peers::MAX_CONTACT_HINTS);
        assert_eq!(out.len(), 6);
        for must in ["1.1.1.1:1", "[2606::1]:1", "192.168.1.5:1", "[fd00::5]:1"] {
            assert!(out.contains(&must.to_string()), "{must} в {out:?}");
        }
    }

    #[test]
    fn ping_nonce_wire_is_exactly_eight_bytes() {
        let n = 0x0102_0304_0506_0708u64;
        assert_eq!(parse_ping_nonce(&n.to_le_bytes()), Some(n));
        assert_eq!(parse_ping_nonce(&n.to_le_bytes()[..7]), None);
        assert_eq!(parse_ping_nonce(&[n.to_le_bytes().as_slice(), &[0]].concat()), None);
        assert_eq!(parse_ping_nonce(&[]), None);
        assert_ne!(new_ping_nonce(), new_ping_nonce(), "nonce случайный");
        assert!(T_PING != T_PONG && ![T_AUTH_OK, T_AUTH_FAIL, T_USE, T_NBRS, T_OBSERVE, T_CINFO].contains(&T_PING)
            && ![T_AUTH_OK, T_AUTH_FAIL, T_USE, T_NBRS, T_OBSERVE, T_CINFO].contains(&T_PONG));
    }

    #[test]
    fn pong_is_accepted_once_for_the_sent_nonce_on_the_sent_link() {
        let (a, b) = (LinkId::new([1; 16]), LinkId::new([2; 16]));
        let mut book = PingBook::default();
        book.sent(a, 111);
        book.sent(a, 222);
        assert_eq!(book.ack(b, 111), None, "тот же nonce на чужом Link");
        assert_eq!(book.ack(a, 333), None, "nonce, которого не отправляли");
        assert!(book.ack(a, 111).is_some(), "ответ на отправленный nonce");
        assert_eq!(book.ack(a, 111), None, "повтор старого pong отвергается");
        assert!(book.ack(a, 222).is_some(), "второй nonce жив независимо");
    }

    #[test]
    fn neighbor_pong_requires_current_link_of_that_neighbor() {
        let (cur, other) = (LinkId::new([1; 16]), LinkId::new([2; 16]));
        let mut book = PingBook::default();
        book.sent(cur, 7);
        book.sent(other, 8);
        assert_eq!(accept_pong(&mut book, Some(cur), other, 8), None, "Link не текущий для соседа");
        assert_eq!(accept_pong(&mut book, None, cur, 7), None, "у соседа нет Link");
        assert_eq!(accept_pong(&mut book, Some(cur), cur, 8), None, "nonce другого Link");
        assert!(accept_pong(&mut book, Some(cur), cur, 7).is_some());
        assert_eq!(accept_pong(&mut book, Some(cur), cur, 7), None, "повтор");
    }

    #[test]
    fn ping_book_is_bounded_and_counts_unanswered_as_loss() {
        let l = LinkId::new([3; 16]);
        let mut book = PingBook::default();
        for n in 0..40u64 {
            book.sent(l, n);
        }
        assert_eq!(book.v.len(), 16, "окно ограничено");
        assert_eq!(book.ack(l, 0), None, "вытесненный nonce не принимается");
        assert!(book.ack(l, 39).is_some());
        assert_eq!(book.loss(Some(l), Duration::ZERO, 8), Some(15.0 / 16.0));
        assert_eq!(book.loss(Some(LinkId::new([4; 16])), Duration::ZERO, 1), None);
        assert_eq!(book.loss(None, Duration::from_secs(3600), 1), None, "никто не созрел");
    }

    #[test]
    fn quic_monitor_flags_silence_and_counter_loss_but_not_a_healthy_link() {
        // здоровый носитель: прогресс растёт каждый тик, потерь нет
        let mut m = QuicMon::default();
        assert!(!m.tick(5, 100, 0, 1000), "первый тик соединения - не контакт");
        for i in 1..=QMON_TICKS as u64 {
            assert!(m.tick(5, 100 + i * 4, 0, 1000 + i * 10));
        }
        assert_eq!(m.loss(), Some(0.0));
        // окно набирается не раньше QMON_TICKS тиков
        let mut m = QuicMon::default();
        m.tick(5, 0, 0, 0);
        for _ in 0..QMON_TICKS - 1 {
            m.tick(5, 0, 0, 0);
        }
        assert_eq!(m.loss(), None);
        m.tick(5, 0, 0, 0);
        assert_eq!(m.loss(), Some(1.0), "полная тишина: каждая проба потеряна");
        // 3 тихих из 8 = 37 % >= порога; 2 из 8 = 25 % < порога
        let mut m = QuicMon::default();
        m.tick(5, 0, 0, 0);
        let mut p = 0;
        for i in 0..QMON_TICKS {
            if i >= 3 { p += 1; }
            m.tick(5, p, 0, 0);
        }
        assert!(m.loss().unwrap() >= QMON_LOSS_LIMIT, "{:?}", m.loss());
        let mut m = QuicMon::default();
        m.tick(5, 0, 0, 0);
        let mut p = 0;
        for i in 0..QMON_TICKS {
            if i >= 2 { p += 1; }
            m.tick(5, p, 0, 0);
        }
        assert!(m.loss().unwrap() < QMON_LOSS_LIMIT);
        // под трафиком прогресс идёт, но QUIC считает потерянные пакеты: 40 % от отправленных
        let mut m = QuicMon::default();
        m.tick(5, 0, 0, 0);
        for i in 1..=QMON_TICKS as u64 {
            m.tick(5, i * 10, i * 20, i * 50);
        }
        assert!((m.loss().unwrap() - 0.4).abs() < 1e-9);
        // мало отправленного (< QMON_MIN_TX): доля потерь не значима
        let mut m = QuicMon::default();
        m.tick(5, 0, 0, 0);
        for i in 1..=QMON_TICKS as u64 {
            m.tick(5, i, i, i * 4);
        }
        assert_eq!(m.loss(), Some(0.0));
    }

    /// Источник статистики настоящий: после `ping()` растёт `frame_rx.authenticated_progress`, у закрытого пиром соединения - нет.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_monitor_sees_real_ping_progress_on_loopback() {
        use iroh::endpoint::presets;
        let mk = || async {
            iroh::Endpoint::builder(presets::Minimal).secret_key(iroh::SecretKey::generate()).alpns(vec![b"rns/0".to_vec()])
                .relay_mode(iroh::RelayMode::Disabled).bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0))).unwrap().bind().await.unwrap()
        };
        let (server, client) = (mk().await, mk().await);
        let addr = iroh::EndpointAddr::new(server.id()).with_ip_addr(std::net::SocketAddr::from(([127, 0, 0, 1], server.bound_sockets()[0].port())));
        let incoming = async { server.accept().await.unwrap().await.unwrap() };
        let (c, s) = tokio::join!(client.connect(addr, b"rns/0"), incoming);
        let (c, s) = (c.unwrap(), s);
        let mut m = QuicMon::default();
        let sample = |m: &mut QuicMon| {
            let st = c.stats();
            m.tick(c.stable_id(), st.frame_rx.authenticated_progress(), st.lost_packets, st.udp_tx.datagrams)
        };
        sample(&mut m);
        for _ in 0..QMON_TICKS + 2 {
            assert!(c.ping(), "соединение живо");
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert!(sample(&mut m), "ACK на QUIC PING - аутентифицированный контакт");
        }
        assert_eq!(m.loss(), Some(0.0));
        assert!(c.paths().iter().any(|p| p.is_selected() && p.rtt() < Duration::from_secs(1)));
        // пир закрыл соединение: контакта нет
        s.close(0u32.into(), b"bye");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(c.close_reason().is_some(), "закрытое пиром соединение: carrier_conn его не отдаст");
    }

    #[test]
    fn quic_monitor_resets_on_new_connection() {
        let mut m = QuicMon::default();
        m.tick(5, 0, 0, 0);
        for _ in 0..QMON_TICKS {
            m.tick(5, 0, 0, 0);
        }
        assert_eq!(m.loss(), Some(1.0));
        assert!(!m.tick(6, 500, 0, 0), "новое соединение - окно с нуля, контакта нет");
        assert_eq!(m.loss(), None);
        m.reset();
        assert!(!m.tick(6, 501, 0, 0));
    }

    #[test]
    fn client_info_roundtrip_and_garbage() {
        let id = leviculum_std::api::generate_identity();
        let name = parse_client_info(&client_info_body(&id, std::path::Path::new("/nonexistent"))).unwrap();
        assert!(name.starts_with("телефон-"));
        assert_eq!(parse_client_info(b""), None);
        assert_eq!(parse_client_info(&[7, b'a', b'n', b'd']), None, "обрезано");
        assert_eq!(parse_client_info(&[1, b'x', b'y']), None, "лишний хвост");
        assert_eq!(parse_client_info(&[0]), None, "пустое имя");
        assert_eq!(parse_client_info(&[2, b'a', 0x07]), Some("a".into()), "управляющие символы вырезаны");
        let nm = "a\u{202E}b";
        let mut b = vec![nm.len() as u8];
        b.extend_from_slice(nm.as_bytes());
        assert_eq!(parse_client_info(&b), Some("ab".into()), "смена направления текста вырезана");
    }

    #[test]
    fn peer_name_normalized() {
        assert_eq!(norm_name("knothop-FI-ubuntu24").as_deref(), Some("knothop-FI-ubuntu24"), "имя не переписывается");
        assert_eq!(norm_name("Home").as_deref(), Some("Home"));
        assert_eq!(norm_name("  Home \n").as_deref(), Some("Home"));
        assert_eq!(norm_name("🇫🇮 Хельсинки").as_deref(), Some("🇫🇮 Хельсинки"));
        assert_eq!(norm_name("  \n\t "), None);
        assert_eq!(norm_name(&"я".repeat(80)).unwrap().chars().count(), 32);
        assert_eq!(contact_name_or_dest("🇫🇮 Финляндия", &[0x8a; 16]), "🇫🇮 Финляндия");
        assert_eq!(contact_name_or_dest(" \n\t", &[0x8a; 16]), "8a8a8a8a");
        assert_eq!(contact_name_or_dest("  A\u{202e}B  ", &[0x8a; 16]), "AB");
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
    fn offline_issue_works_for_own_node_without_running_core_and_refuses_foreign() {
        let dir = std::env::temp_dir().join(format!("kh-offissue-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let id = load_or_create_identity(&dir).unwrap();
        let me = peers::hash_of(&id.public_key_bytes()).unwrap();
        let st = dir.to_str().unwrap();
        let r: serde_json::Value = serde_json::from_str(&run_cli_json(&serde_json::json!({"cmd": "issue", "rights": 1}).to_string(), st)).unwrap();
        assert_eq!(r["ok"], true, "{r}");
        let pairs = invite::decode(r["invite"].as_str().unwrap()).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, me);
        let p = peers::Peers::load(id.public_key_bytes(), &dir).unwrap();
        assert_eq!(p.invite_list().iter().filter(|i| i.state == peers::InviteState::Open && i.rights == peers::USE).count(), 1, "пин записан в peers.json");
        // чужая нода в стопке без работающего ядра: понятный отказ, ничего не пишется
        let r: serde_json::Value = serde_json::from_str(&run_cli_json(&serde_json::json!({"cmd": "issue", "nodes": [
            {"hash": hex(&me), "rights": 1}, {"hash": hex(&[9u8; 16]), "rights": 1}]}).to_string(), st)).unwrap();
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("Сеть"), "{r}");
        assert_eq!(peers::Peers::load(id.public_key_bytes(), &dir).unwrap().invite_list().len(), 1);
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
        .data_channel_capacity(cli.data_cap)
        .link_cipher(leviculum_std::api::LinkCipher::Gcm)
        // ADR 0016: Link зачисления идёт через чужие транспорты RNS и может быть только стандартным CBC; такой Link допускается лишь на зачисление
        .accept_cbc_links(true);
    if let Some(tp) = tcp {
        nb = nb.add_tcp_server(SocketAddr::from(([0, 0, 0, 0], tp)));
    }
    let pn_identity = transport.then(|| admin_identity.clone()).flatten();
    // хаб RRC (rrc.rs) - только на серверных узлах, на телефоне его нет
    let hub_identity = pn_identity.clone().filter(|_| rrc::enabled());
    let admin_lxmf = admin_identity.map(|i| {
        let (p, r) = lxmf_admin::AdminProcessor::new(i);
        (if transport { p.with_fetch_ms(lxmf_admin::PN_FETCH_SERVER_MS) } else { p }, r)
    });
    let (admin_lxmf, nb) = match admin_lxmf {
        Some((processor, runtime)) => {
            let nb = if let Some(identity) = pn_identity {
                let both = lxmf_sync::Processors(processor, lxmf_sync::propagation_processor(state, identity)?);
                match hub_identity {
                    Some(hub) => nb.core_processor(lxmf_sync::Processors(both, rrc::HubProcessor::new(hub))),
                    None => nb.core_processor(both),
                }
            } else { nb.core_processor(processor) };
            (Some(runtime), nb)
        }
        None => (None, nb),
    };
    let mut node = nb.build().context("build node")?;
    node.start().await.context("start node")?;
    let events = node.take_event_receiver().context("event receiver")?;
    let node = Arc::new(node);

    // фильтр исходящих адресов IP-транспорта (правка iroh): QNT-зонды выхода идут на адреса, которые называет пир; частные/loopback закрыты, лаборатория включает KNOTHOP_ALLOW_PRIVATE_DIAL=1
    iroh::knothop::set_block_private_egress(std::env::var("KNOTHOP_ALLOW_PRIVATE_DIAL").is_err());
    // mesh (ADR 0023): сквозное QUIC клиент↔выход через транзит. KNOTHOP_MESH=0 - транспорт на endpoint не ставится вовсе (поведение как до mesh)
    let mesh_inst = mesh::install(*key.public().as_bytes());
    // потолок UDP-пакета на путях mesh: соседский QUIC того же MTU; KNOTHOP_MESH_E2E_CAP=0 отключает (A/B в lab13)
    if cli.quic_initial_mtu > 0 && std::env::var("KNOTHOP_MESH_E2E_CAP").map(|v| v.trim() != "0").unwrap_or(true) {
        iroh::knothop::set_custom_path_max_udp(mesh::e2e_max_udp(cli.quic_initial_mtu));
    }
    if let Some(c) = transport_mtu(cli.path_idle_ms, cli.path_keepalive_ms, cli.conn_idle_ms, Some(1200)) {
        mesh::set_quic_cfg(c);
    }
    let mut eb = Endpoint::builder(presets::Minimal).secret_key(key).alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled);
    if mesh_inst.enabled() {
        eb = eb.add_custom_transport(mesh_inst.transport()).path_selector(mesh_inst.selector());
    }
    // REALITY - последний уровень запасного пути (reality_carrier.rs). KNOTHOP_REALITY=0: транспорт на endpoint не ставится, дозвона и сервера нет
    if std::env::var("KNOTHOP_REALITY").map(|v| v.trim() != "0").unwrap_or(true) {
        eb = eb.add_custom_transport(reality_carrier::install().transport());
    }
    if !relays.is_empty() {
        // relay нужен для сигнализации hole punching и QAD; сертификат принимается только от ключа доверенной ноды (relay.rs)
        let _ = RELAY_URLS.set(relays.to_vec());
        eb = eb.relay_mode(RelayMode::custom(relays.iter().cloned())).ca_tls_config(relay::pinned_ca(relay_trusted()));
    }
    if let Some(p) = port {
        // `bind_addr` заменяет только сокет своего семейства: без второго вызова IPv6-сокет остался бы на случайном порту, а в подсказках
        // стоял бы `[v6]:p`, где никто не слушает. IPv6 необязателен (нет стека - остаётся IPv4).
        eb = eb.bind_addr(SocketAddr::from(([0, 0, 0, 0], p)))?;
        eb = eb.bind_addr_with_opts(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, p)), iroh::endpoint::BindOpts::default().set_is_required(false))?;
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
/// Таблица прав процесса для relay; пока не задана, relay никому не доверяет.
static RELAY_PEERS: std::sync::OnceLock<Arc<Mutex<peers::Peers>>> = std::sync::OnceLock::new();

/// Политика mesh узла (ADR 0028 §3.1): транзит — чисто локальный предикат таблицы ноды (`transit_enabled` и все три ключа известны
/// и не отозваны); путь к назначению — из таблицы путей RNS.
struct MeshPolicy {
    node: Arc<Node>,
    peers: Arc<Mutex<peers::Peers>>,
    /// клиент (телефон) не транзит
    client: bool,
    /// поколение таблицы (читается без её замка): отзыв действует сразу после применения команды
    rights_gen: Arc<std::sync::atomic::AtomicU64>,
}

impl mesh::Policy for MeshPolicy {
    fn may_forward(&self, prev: &[u8; 32], src: &[u8; 32], dst: &[u8; 32]) -> bool {
        !self.client && self.peers.lock().unwrap().mesh_forward(prev, src, dst)
    }

    fn holds_rights(&self, key: &[u8; 32]) -> bool {
        self.peers.lock().unwrap().mesh_knows_key(key)
    }

    /// Сосед годится как следующий хоп, если он сам объявил роль транзита (контакт с `TRANSIT`) и нам известен.
    fn is_transit(&self, key: &[u8; 32]) -> bool {
        let p = self.peers.lock().unwrap();
        p.mesh_knows_key(key) && p.roles_of_key(key) & peers::TRANSIT != 0
    }

    fn generation(&self) -> u64 {
        self.rights_gen.load(Relaxed)
    }

    fn transit_candidates(&self) -> Vec<[u8; 32]> {
        let p = self.peers.lock().unwrap();
        p.contact_list().into_iter().filter(|c| c.roles & peers::TRANSIT != 0 && p.mesh_knows_key(&peers::key_of(&c.pk))).map(|c| peers::key_of(&c.pk)).collect()
    }

    fn key_for_id(&self, id: &[u8; 8]) -> Option<[u8; 32]> {
        self.peers.lock().unwrap().key_for_id8(id)
    }

    fn local_key_for_id(&self, id: &[u8; 8]) -> Option<[u8; 32]> {
        self.peers.lock().unwrap().local_key_for_id8(id)
    }

    fn local_source_key_for_id(&self, id: &[u8; 8]) -> Option<[u8; 32]> {
        let p = self.peers.lock().unwrap();
        if self.client { p.client_mesh_source_for_id8(id) } else { p.key_for_id8(id) }
    }

    /// Сосед по таблице путей RNS: назначение узла (из его публичного ключа) -> интерфейс пути -> мультиплексор -> ключ рабочего QUIC-носителя.
    fn route(&self, dst: &[u8; 32]) -> Option<[u8; 32]> {
        let pk = self.peers.lock().unwrap().pk_for_key(dst)?;
        let dh = DestinationHash::new(dest_from_pub_tag(&pk, T13_TAG));
        let path = self.node.engine().get_path_clone(&dh)?;
        let name = self.node.engine().interface_stats().iter().find(|i| i.interface_id.0 == path.interface_index)?.name.clone();
        mux::by_name(&name)?.quic_peer()
    }
}

fn install_mesh_policy(node: &Arc<Node>, table: &Arc<Mutex<peers::Peers>>, client: bool) {
    if let Some(m) = mesh::global() {
        let rights_gen = table.lock().unwrap().generation();
        m.set_policy(Arc::new(MeshPolicy { node: node.clone(), peers: table.clone(), client, rights_gen }));
    }
}

/// Relay iroh (ADR 0028 §3.4): нода сама вправе быть relay (`transit_enabled`) и ключ известен её таблице с ненулевыми правами.
fn relay_trusted() -> relay::Trusted {
    Arc::new(|k: &[u8; 32]| RELAY_PEERS.get().is_some_and(|t| t.lock().unwrap().relay_allows(k)))
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
    /// сосед не отвечает `DEAD_AFTER` наборов подряд и не анонсировался: не набираем (dial_direct, Liveness)
    pub dead: AtomicBool,
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
    /// растёт, когда у пира появляется носитель после перерыва без носителя ("none" -> quic/tcp/reality): отступ выхода после неудачных попыток Link на это время
    /// не нужен (клиент сбрасывает его в `client_supervisor`)
    pub up_epoch: std::sync::atomic::AtomicU32,
    /// подряд неудачных наборов (QUIC и TCP) на данный момент: по нему статус P2P-контакта говорит «не отвечает», а не «подключаюсь»
    pub misses: std::sync::atomic::AtomicU32,
}

impl CarrierCtl {
    fn new() -> Arc<Self> {
        Arc::new(Self { prefer_tcp: AtomicBool::new(false), mode: Mutex::new("none"), dead: AtomicBool::new(false), switches: Default::default(), generation: Default::default(), fails: Default::default(), rtt_us: Default::default(), label: Mutex::new(String::new()), peer: Mutex::new(String::new()), silence: Mutex::new(None), joint_fail: Mutex::new(None), up_epoch: Default::default(), misses: Default::default() })
    }
    fn set_mode(&self, m: &'static str) {
        // `generation` тут не растёт: смена носителя интерфейс пира (`mux.rs`) не пересоздаёт и Link не рвёт; растёт `Dialer::mux_for`
        let prev = std::mem::replace(&mut *self.mode.lock().unwrap(), m);
        if prev == "none" && m != "none" {
            self.up_epoch.fetch_add(1, Relaxed);
        }
    }
    fn is_quic(&self) -> bool {
        *self.mode.lock().unwrap() == "quic"
    }
    /// Название носителя для журнала и статуса.
    fn mode_label(&self) -> &'static str {
        match *self.mode.lock().unwrap() {
            "quic" => "QUIC",
            "reality" => "REALITY",
            _ => "TCP",
        }
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

/// Долго жившего Link закрыл сам RNS (Stale и др.): новый Link поднимается сразу, без отступа выхода (см. `client_supervisor`). Короткоживущий - нет.
const SOFT_CLOSE_MIN_LIFE: Duration = Duration::from_secs(30);

fn is_soft_link_close(reason: &str, lived: Duration) -> bool {
    reason.starts_with("link закрыт") && lived >= SOFT_CLOSE_MIN_LIFE
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
mod liveness_tests {
    use super::*;

    #[test]
    fn miss_pause_is_quadratic_and_bounded() {
        let s: Vec<u64> = (1..=DEAD_AFTER).map(|k| miss_pause(k).as_secs()).collect();
        assert_eq!(s, vec![2, 8, 18, 32, 50, 72, 98, 128]);
        assert_eq!(miss_pause(0), miss_pause(1));
        assert_eq!(miss_pause(1000), miss_pause(DEAD_AFTER));
    }

    #[test]
    fn neighbor_dies_after_n_misses_and_announce_revives() {
        let sh = Shared::new();
        let cc = CarrierCtl::new();
        let book = Addrs::new(vec!["a".into()]);
        let mut l = Liveness { may_die: true, miss: 0, dead: false, seen_gen: book.epoch() };
        for k in 1..DEAD_AFTER {
            assert_eq!(l.missed(&sh, &cc, "n"), miss_pause(k));
            assert!(!cc.dead.load(Relaxed));
        }
        assert_eq!(l.missed(&sh, &cc, "n"), DEAD_RECHECK);
        assert!(l.dead && cc.dead.load(Relaxed));
        // повторный промах у мёртвого: снова ждём анонса
        assert_eq!(l.missed(&sh, &cc, "n"), DEAD_RECHECK);
        assert!(!l.woken(&cc, book.epoch()), "без анонса не оживает");
        book.wake();
        assert!(l.woken(&cc, book.epoch()) && !l.dead && !cc.dead.load(Relaxed) && l.miss == 0);
        assert_eq!(l.missed(&sh, &cc, "n"), miss_pause(1), "после анонса счёт заново");
        // новые адреса тоже будят; одинаковые - нет
        let g = book.epoch();
        assert!(!book.set(vec!["a".into()]) && book.epoch() == g);
        assert!(book.set(vec!["b".into()]) && book.epoch() > g);
    }

    #[test]
    fn reached_clears_and_client_never_dies() {
        let sh = Shared::new();
        let cc = CarrierCtl::new();
        let mut l = Liveness { may_die: true, miss: 0, dead: false, seen_gen: 0 };
        for _ in 0..DEAD_AFTER {
            l.missed(&sh, &cc, "n");
        }
        l.reached(&sh, &cc, "n");
        assert!(!l.dead && !cc.dead.load(Relaxed) && l.miss == 0);
        let mut c = Liveness { may_die: false, miss: 0, dead: false, seen_gen: 0 };
        for _ in 0..DEAD_AFTER * 3 {
            assert_eq!(c.missed(&sh, &cc, "x"), Duration::from_secs(2));
        }
        assert!(!c.dead && !cc.dead.load(Relaxed));
    }
}

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

/// Окно отправленных Channel-пингов (T_PING/T_PONG): Link, случайный nonce, время отправки. Ответ засчитывается один раз и только
/// с тем nonce и на том Link, на котором пинг ушёл; повтор, чужой nonce и ответ на другом Link отвергаются. RTT считается по локальным часам.
struct PingBook {
    v: std::collections::VecDeque<(LinkId, u64, Instant, bool)>,
    cap: usize,
}

impl Default for PingBook {
    fn default() -> Self {
        Self::with_cap(16)
    }
}

impl PingBook {
    fn with_cap(cap: usize) -> Self {
        Self { v: Default::default(), cap }
    }
    fn sent(&mut self, link: LinkId, nonce: u64) {
        self.v.push_back((link, nonce, Instant::now(), false));
        while self.v.len() > self.cap {
            self.v.pop_front();
        }
    }
    /// Засчитать ответ: `Some(RTT)` только при первом ответе на отправленный на этом Link nonce.
    fn ack(&mut self, link: LinkId, nonce: u64) -> Option<Duration> {
        let e = self.v.iter_mut().find(|e| e.0 == link && e.1 == nonce && !e.3)?;
        e.3 = true;
        Some(e.2.elapsed())
    }
    fn clear(&mut self) {
        self.v.clear();
    }
    /// Доля не вернувшихся среди «созревших» (старше `age`) пингов, если их не меньше `min_n`; `link` - только этого Link.
    /// Channel надёжен: потеря здесь означает, что даже повторы Channel не дошли, а не потерю отдельной датаграммы.
    fn loss(&self, link: Option<LinkId>, age: Duration, min_n: usize) -> Option<f64> {
        let m: Vec<_> = self.v.iter().filter(|e| link.map_or(true, |l| l == e.0) && e.2.elapsed() >= age).collect();
        if m.len() < min_n {
            return None;
        }
        Some(m.iter().filter(|e| !e.3).count() as f64 / m.len() as f64)
    }
}

fn new_ping_nonce() -> u64 {
    rand_core::OsRng.next_u64()
}

/// Тело T_PING/T_PONG: ровно 8 байт nonce.
fn parse_ping_nonce(body: &[u8]) -> Option<u64> {
    <[u8; PING_BODY_LEN]>::try_from(body).ok().map(u64::from_le_bytes)
}

/// Окно монитора QUIC-носителя соседа и порог потерь (как у прежнего монитора пингов-датаграмм: >= 8 проб, >= 30 %).
const QMON_TICKS: usize = 8;
/// Минимум датаграмм за окно, при котором доля потерянных пакетов по счётчикам QUIC считается значимой.
const QMON_MIN_TX: u64 = 40;
const QMON_LOSS_LIMIT: f64 = 0.30;

/// Монитор качества QUIC-носителя по его статистике: замена потерь пингов-датаграмм выхода. Один шаг на тик (2 с), перед ним выход шлёт
/// QUIC PING. «Тихий» тик - ни одного аутентифицированного кадра от пира (`frame_rx.authenticated_progress`): проба потеряна. При трафике
/// потери видны и по счётчикам QUIC (`lost_packets` / отправленные датаграммы). Потеря окна = max из двух долей.
#[derive(Default)]
struct QuicMon {
    cid: usize,
    last: Option<(u64, u64, u64)>,
    ticks: std::collections::VecDeque<(bool, u64, u64)>,
}

impl QuicMon {
    fn reset(&mut self) {
        self.cid = 0;
        self.last = None;
        self.ticks.clear();
    }
    /// Учесть счётчики; true - от пира пришёл аутентифицированный кадр с прошлого тика (контакт). Первый тик нового соединения контактом не считается.
    fn tick(&mut self, cid: usize, progress: u64, lost: u64, tx: u64) -> bool {
        let prev = if self.cid == cid { self.last } else { None };
        if prev.is_none() {
            self.ticks.clear();
        }
        self.cid = cid;
        self.last = Some((progress, lost, tx));
        let Some((p, l, t)) = prev else { return false };
        let moved = progress > p;
        self.ticks.push_back((!moved, lost.saturating_sub(l), tx.saturating_sub(t)));
        while self.ticks.len() > QMON_TICKS {
            self.ticks.pop_front();
        }
        moved
    }
    fn loss(&self) -> Option<f64> {
        if self.ticks.len() < QMON_TICKS {
            return None;
        }
        let quiet = self.ticks.iter().filter(|t| t.0).count() as f64 / self.ticks.len() as f64;
        let tx: u64 = self.ticks.iter().map(|t| t.2).sum();
        let stat = if tx >= QMON_MIN_TX { self.ticks.iter().map(|t| t.1).sum::<u64>() as f64 / tx as f64 } else { 0.0 };
        Some(quiet.max(stat))
    }
}

/// Адреса одного пира, общие для диалера и приёма анонсов: диалер берёт их на каждой попытке, анонс обновляет (0014 R4).
struct Addrs {
    v: Mutex<Vec<String>>,
    /// будит паузу диалера, если адреса сменились или пир объявился
    changed: tokio::sync::Notify,
    /// растёт при смене адресов и свежем анонсе: диалер по нему снимает статус «мёртв»
    epoch: std::sync::atomic::AtomicU64,
    /// подсказка REALITY (`rl`): последний уровень запасного пути; хоста не несёт - берутся адреса из `v`
    rl: Mutex<Option<reality_carrier::RealityHint>>,
}

impl Addrs {
    fn new(v: Vec<String>) -> Arc<Self> {
        Arc::new(Self { v: Mutex::new(v), changed: Default::default(), epoch: Default::default(), rl: Mutex::new(None) })
    }
    fn rl(&self) -> Option<reality_carrier::RealityHint> {
        self.rl.lock().unwrap().clone()
    }
    /// Заменить подсказку REALITY; true - изменилась (диалер просыпается: возможно, она открывает единственный путь).
    fn set_rl(&self, h: Option<reality_carrier::RealityHint>) -> bool {
        let mut cur = self.rl.lock().unwrap();
        if *cur == h {
            return false;
        }
        *cur = h;
        drop(cur);
        self.wake();
        true
    }
    /// Подсказка из третьих рук: только если своей ещё нет.
    fn rl_fill(&self, h: &Option<reality_carrier::RealityHint>) {
        if h.is_some() && self.rl.lock().unwrap().is_none() {
            self.set_rl(h.clone());
        }
    }
    /// Пир объявился сам (свежий анонс): разбудить диалер, даже если адреса прежние.
    fn wake(&self) {
        self.epoch.fetch_add(1, Relaxed);
        self.changed.notify_one();
    }
    fn epoch(&self) -> u64 {
        self.epoch.load(Relaxed)
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
        drop(cur);
        self.wake();
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
pub(crate) fn sane_hint_addr(a: &str) -> bool {
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
/// Подряд неудачных наборов (хост не ответил ни по QUIC, ни по TCP/relay), после которых сосед считается мёртвым и не набирается до
/// свежего анонса или новых адресов. Пауза после k-го промаха - `MISS_BASE_MS`·k² (2, 8, 18 … 98 с): до признания ≈5 мин пауз плюс время попыток.
const DEAD_AFTER: u32 = 8;
const MISS_BASE_MS: u64 = 2_000;
/// Страховка от потерянного анонса: мёртвого соседа раз в час проверяем одной попыткой.
const DEAD_RECHECK: Duration = Duration::from_secs(3600);

fn miss_pause(miss: u32) -> Duration {
    let k = u64::from(miss.clamp(1, DEAD_AFTER));
    Duration::from_millis(MISS_BASE_MS * k * k)
}

/// Учёт недозвона до соседа: квадратичная пауза и статус «мёртв» (`may_die`, только соседи-узлы; у клиента своя логика смены сети).
struct Liveness {
    may_die: bool,
    miss: u32,
    dead: bool,
    seen_gen: u64,
}

impl Liveness {
    /// Хост ответил (носитель поднялся или TCP соединился): промахи забыть.
    fn reached(&mut self, sh: &Shared, ctl: &CarrierCtl, label: &str) {
        self.miss = 0;
        ctl.misses.store(0, Relaxed);
        if self.dead {
            self.dead = false;
            ctl.dead.store(false, Relaxed);
            sh.note(format!("{label}: снова на связи"));
        }
    }
    /// Свежий анонс или новые адреса: сразу набирать, счёт заново. true - статус «мёртв» снят.
    fn woken(&mut self, ctl: &CarrierCtl, epoch: u64) -> bool {
        if epoch == self.seen_gen {
            return false;
        }
        self.seen_gen = epoch;
        self.miss = 0;
        ctl.misses.store(0, Relaxed);
        ctl.dead.store(false, Relaxed);
        std::mem::take(&mut self.dead)
    }
    /// Промах; пауза до следующей попытки (у мёртвого - до анонса или часовой перепроверки).
    fn missed(&mut self, sh: &Shared, ctl: &CarrierCtl, label: &str) -> Duration {
        self.miss = self.miss.saturating_add(1);
        ctl.misses.store(self.miss, Relaxed);
        if !self.may_die {
            // клиент и seed: прежний ровный темп, телефон после смены сети не должен ждать минутами
            return Duration::from_secs(2);
        }
        if self.miss >= DEAD_AFTER {
            if !self.dead {
                self.dead = true;
                ctl.dead.store(true, Relaxed);
                sh.note(format!("{label}: не отвечает {} попыток подряд, считаю мёртвым до анонса (перепроверка раз в {} мин)", self.miss, DEAD_RECHECK.as_secs() / 60));
            }
            return DEAD_RECHECK;
        }
        miss_pause(self.miss)
    }
}

#[allow(clippy::too_many_arguments)]
async fn dial_direct(ep: Endpoint, node: Arc<Node>, sh: Arc<Shared>, label: String, id: EndpointId, book: Arc<Addrs>, alive: Arc<AtomicBool>, ctl: Arc<CarrierCtl>, may_die: bool) {
    // память о неработающих носителях к этому пиру (health.rs): ключ - EndpointId, не имя и не адрес
    let peer = id.to_string();
    *ctl.peer.lock().unwrap() = peer.clone();
    let d = Dialer { ep, node, sh, label, id, book, alive, ctl, peer, lan: may_die };
    let first_back: u64 = std::env::var("KNOTHOP_TCP_BACKOFF_S").ok().and_then(|v| v.parse().ok()).unwrap_or(TCP_BACK_OFF_FIRST_S);
    let mut st = DialState { back_off: first_back, first_back, ..Default::default() };
    let (sh, ctl, label, peer) = (&d.sh, &d.ctl, d.label.as_str(), d.peer.as_str());
    let mut quic_fail = 0u32;
    let mut tcp_fail = 0u32;
    let mut announced_block = false;
    let mut live = Liveness { may_die, miss: 0, dead: false, seen_gen: d.book.epoch() };
    while d.alive.load(Relaxed) {
        if live.woken(ctl, d.book.epoch()) {
            sh.note(format!("{label}: объявился, набираю снова"));
        }
        if st.mux.as_ref().is_some_and(|m| m.is_closed()) {
            st.mux = None;
        }
        let quic_bad = sh.health.is_bad(peer, health::Kind::Quic);
        let tcp_bad = sh.health.is_bad(peer, health::Kind::Tcp);
        if let Some(rem) = sh.health.blocked_for(peer) {
            // последний уровень: REALITY (TCP на 443, снаружи обычный TLS к сайту). Удачный набор = сессия, по её окончании снова с начала
            if d.try_reality(&mut st, &mut live).await {
                continue;
            }
            // оба носителя проверены и не работают: прямой интерфейс не поднимаем, путь к пиру найдёт RNS через другие узлы; позже проверим снова
            if !announced_block {
                announced_block = true;
                sh.note(format!("{label}: прямой путь заблокирован (QUIC и TCP не проходят), не подключаюсь, повторная проверка через {} мин; REALITY: {}", rem.as_secs() / 60 + 1,
                    if reality_carrier::global().is_none() { "выключен" } else if d.book.rl().is_none() { "нет подсказки rl у этого выхода" } else { "подсказка есть" }));
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
        let resolved = d.resolve().await;
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
            let mut addr = with_relays(addr);
            // тёплый запасной путь: mesh-адрес пира (правка iroh открывает его запасным рядом с IP); мимо прямого носителя кадры идут через альтернативный транзит
            if let Some(m) = mesh::global().filter(|m| m.enabled()) {
                let key = *d.id.as_bytes();
                addr = addr.with_addrs([iroh::TransportAddr::Custom(mesh::addr_of(&key))]);
                m.prepare(&key);
            }
            match tokio::time::timeout(Duration::from_secs(if resolved.is_empty() { 15 } else { 6 }), d.ep.connect(addr, ALPN)).await {
                Ok(Ok(conn)) => {
                    quic_fail = 0;
                    live.reached(sh, ctl, label);
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
                    if let Some(mm) = mesh::global().filter(|mm| mm.enabled()) {
                        mm.register_migratable(&conn);
                        tokio::spawn(mm.clone().watch_mesh_stall(conn.clone()));
                        tokio::spawn(mm.clone().watch_direct_upgrade(conn.clone()));
                    }
                    ctl.set_mode("quic");
                    d.session(&mut st, Cur::Quic(conn), m).await;
                    if std::mem::take(&mut st.quic_timed_out) && !relay_only && !tcp_bad && !ctl.prefer_tcp.load(Relaxed) {
                        // QUIC молчал до таймаута простоя: Link ещё держится на интерфейсе пира, а повторы QUIC (до 12 с) съедают окно stale. «Лучше в обход, чем
                        // разрыв»: TCP сразу; QUIC не объявляется неработающим (это мог быть и handover) - вернёмся зондом через `back_off`.
                        sh.note(format!("{label}: QUIC закрылся по таймауту простоя, подключаю TCP сразу"));
                        ctl.prefer_tcp.store(true, Relaxed);
                        ctl.switches.fetch_add(1, Relaxed);
                    }
                }
                _ if relay_only => {
                    sh.note(format!("{label}: через relay не соединилось, повторю"));
                    let p = live.missed(sh, ctl, label);
                    d.book.pause(p.max(Duration::from_secs(10))).await;
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
                    let p = live.missed(sh, ctl, label);
                    // переход на TCP не откладываем: «лучше в обход, чем разрыв»; у мёртвого соседа - ждём анонса
                    let p = if ctl.prefer_tcp.load(Relaxed) && p < DEAD_RECHECK { Duration::from_secs(2) } else { p };
                    d.book.pause(p).await;
                }
            }
        } else {
            match tcpc::connect(&resolved, d.ep.secret_key(), &d.id).await {
                tcpc::Dial::Up(stream) => {
                    tcp_fail = 0;
                    live.reached(sh, ctl, label);
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
                    // хост ответил (TCP соединился): это блокировка, не смерть
                    live.reached(sh, ctl, label);
                    d.tcp_blackholed(&mut st);
                    ctl.prefer_tcp.store(false, Relaxed);
                    st.tcp_since = None;
                    if d.try_reality(&mut st, &mut live).await {
                        continue;
                    }
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
                    if d.try_reality(&mut st, &mut live).await {
                        continue;
                    }
                    let p = live.missed(sh, ctl, label);
                    d.book.pause(p).await;
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

/// Только фиксированные категории: текст и коды закрытия от пира недоверенны и в журнал не попадают.
fn quic_close_kind(reason: Option<&iroh::endpoint::ConnectionError>) -> &'static str {
    use iroh::endpoint::ConnectionError as E;
    match reason {
        None => "not-closed",
        Some(E::TimedOut) => "timeout",
        Some(E::LocallyClosed) => "local-close",
        Some(E::Reset) => "reset",
        Some(E::ApplicationClosed(_)) => "peer-application-close",
        Some(E::ConnectionClosed(_)) => "peer-transport-close",
        Some(E::TransportError(_)) => "transport-error",
        Some(E::VersionMismatch) => "version-mismatch",
        Some(E::CidsExhausted) => "cids-exhausted",
    }
}

impl Cur {
    /// Ждать, пока носитель не закончится сам. true - QUIC закрылся по таймауту простоя (пир молчит: UDP режется или сети нет), а не по воле одной из сторон.
    async fn ended(&mut self) -> bool {
        match self {
            Cur::Quic(c) => matches!(c.closed().await, iroh::endpoint::ConnectionError::TimedOut),
            Cur::Tcp { done, .. } => {
                let _ = done.await;
                false
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
    /// последний QUIC закрылся по таймауту простоя: следующий набор идёт сразу на TCP, не тратя 2 x 6 с на повторы QUIC (интерфейс пира живёт `mux::GRACE`)
    quic_timed_out: bool,
    /// REALITY: подряд неудач набора и не раньше какого момента пробовать снова (в памяти, как и всё о носителях клиента)
    rl_fail: u32,
    rl_next: Option<Instant>,
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
    /// контакт без ролей и мы клиент: к глобальным подсказкам добавляются адреса своей локальной сети
    lan: bool,
}

impl Dialer {
    async fn resolve(&self) -> Vec<SocketAddr> {
        resolve_addrs_lan(&self.book.get(), self.lan, self.id.as_bytes()).await
    }

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

    /// Последний уровень запасного пути: туннель REALITY до порта подсказки `rl` (тот же хост, что у QUIC/TCP) и обычный QUIC iroh поверх него.
    /// Доверия не выводится: ключ пира берёт TLS этого QUIC (`ep.connect(self.id)`), допуск - как у любого QUIC-носителя. true - носитель держался и закончился.
    async fn try_reality(&self, st: &mut DialState, live: &mut Liveness) -> bool {
        let (sh, ctl, label) = (&self.sh, &self.ctl, self.label.as_str());
        let Some(rc) = reality_carrier::global() else { return false };
        let Some(hint) = self.book.rl() else { return false };
        if st.rl_next.is_some_and(|t| Instant::now() < t) {
            return false;
        }
        // адреса те же, что для QUIC/TCP, и прошли тот же фильтр (глобальные, кроме KNOTHOP_ALLOW_PRIVATE_DIAL); подсказка хоста не несёт
        let resolved = self.resolve().await;
        if resolved.is_empty() {
            return false;
        }
        let fail = |st: &mut DialState| {
            st.rl_fail = st.rl_fail.saturating_add(1);
            st.rl_next = Some(Instant::now() + Duration::from_secs((15u64 << (st.rl_fail - 1).min(5)).min(300)));
        };
        let mut tun = match rc.dial(&resolved, &hint).await {
            reality_carrier::Dial::Up(t) => {
                live.reached(sh, ctl, label);
                t
            }
            reality_carrier::Dial::Unreachable => {
                fail(st);
                return false;
            }
            reality_carrier::Dial::Rejected(why) => {
                // TCP соединился: хост жив, туннель не принят (подмена, нет доверия к ключу, перегрузка)
                live.reached(sh, ctl, label);
                sh.note(format!("{label}: REALITY: туннель не поднят ({why})"));
                fail(st);
                return false;
            }
        };
        let addr = EndpointAddr::from_parts(self.id, [iroh::TransportAddr::Custom(tun.addr())]);
        let conn = match tokio::time::timeout(Duration::from_secs(12), self.ep.connect(addr, ALPN)).await {
            Ok(Ok(c)) => c,
            _ => {
                tun.close();
                sh.note(format!("{label}: REALITY: туннель есть, QUIC поверх него не соединился"));
                fail(st);
                return false;
            }
        };
        let Some(m) = self.mux_for(st) else {
            conn.close(0u32.into(), b"no interface");
            tun.close();
            return false;
        };
        if m.add_quic(conn.clone(), true, *conn.remote_id().as_bytes()).is_none() {
            conn.close(0u32.into(), b"too many carriers");
            tun.close();
            return false;
        }
        st.rl_fail = 0;
        st.rl_next = None;
        ctl.set_mode("reality");
        sh.note(format!("reality connected to {label} (носитель REALITY, возврат на QUIC через {} с)", st.back_off));
        let t0 = Instant::now();
        self.reality_session(st, conn, &mut tun, m).await;
        tun.close();
        if t0.elapsed() < Duration::from_secs(15) {
            // туннель рвётся сразу после подключения: пауза растёт, как у коротких TCP-сессий
            fail(st);
        }
        true
    }

    /// Сессия на туннеле REALITY: ждём конца носителя; по `back_off` пробуем вернуться на прямой QUIC (зонд `qprobe` в `try_return`), как с TCP.
    async fn reality_session(&self, st: &mut DialState, conn: Connection, tun: &mut reality_carrier::TunnelHandle, m: Arc<mux::Mux>) {
        let (sh, ctl, label) = (&self.sh, &self.ctl, self.label.as_str());
        let mut next_return = Instant::now() + Duration::from_secs(st.back_off);
        loop {
            tokio::select! {
                _ = conn.closed() => break,
                _ = tun.closed() => {
                    // туннель умер раньше, чем QUIC заметил: не ждём таймаута
                    conn.close(0u32.into(), b"reality tunnel closed");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
            if !self.alive.load(Relaxed) || m.is_closed() {
                conn.close(0u32.into(), b"switch carrier");
                break;
            }
            if let Some(p) = conn.paths().iter().find(|p| p.is_selected()) {
                ctl.rtt_us.store(p.rtt().as_micros().min(u32::MAX as u128) as u32, Relaxed);
            }
            if Instant::now() < next_return || sh.health.is_bad(&self.peer, health::Kind::Quic) {
                continue;
            }
            match self.try_return(&m).await {
                Ok(c2) => {
                    ctl.set_mode("quic");
                    ctl.prefer_tcp.store(false, Relaxed);
                    conn.close(0u32.into(), b"switch carrier");
                    tun.close();
                    st.back_off = st.first_back;
                    sh.note(format!("{label}: возврат с REALITY на QUIC без разрыва Link"));
                    self.session(st, Cur::Quic(c2), m).await;
                    return;
                }
                Err(grow) => {
                    if grow {
                        st.back_off = grown_back_off(st.back_off);
                    }
                    next_return = Instant::now() + Duration::from_secs(st.back_off);
                }
            }
        }
        ctl.set_mode("none");
        ctl.rtt_us.store(0, Relaxed);
        sh.note(format!("reality to {label} ended"));
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
                timed_out = cur.ended() => {
                    st.quic_timed_out = timed_out;
                    break;
                }
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
                    let resolved = self.resolve().await;
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
                    let force_try = !ctl.prefer_tcp.load(Relaxed);
                    // срок проверяется вместе с памятью о QUIC: помеченный неработающим QUIC не повод пробовать
                    if !force_try && !tcp_release_due(from.elapsed(), st.back_off, quic_bad) {
                        continue;
                    }
                    match self.try_return(&m).await {
                        Ok(conn) => {
                            let old = std::mem::replace(&mut cur, Cur::Quic(conn));
                            ctl.set_mode("quic");
                            ctl.prefer_tcp.store(false, Relaxed);
                            old.close();
                            st.tcp_since = None;
                            st.back_off = st.first_back;
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
            Cur::Quic(conn) => {
                ctl.set_mode("none");
                ctl.rtt_us.store(0, Relaxed);
                sh.note(format!("quic to {label} ended: {}", quic_close_kind(conn.close_reason().as_ref())));
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
        let resolved = self.resolve().await;
        if resolved.is_empty() {
            return Err(true);
        }
        let mut addr = EndpointAddr::new(self.id);
        for a in &resolved {
            addr = addr.with_ip_addr(*a);
        }
        if let Some(m) = mesh::global().filter(|m| m.enabled()) {
            let key = *self.id.as_bytes();
            addr = addr.with_addrs([iroh::TransportAddr::Custom(mesh::addr_of(&key))]);
            m.prepare(&key);
        }
        let conn = match tokio::time::timeout(Duration::from_secs(6), self.ep.connect(addr, ALPN)).await {
            Ok(Ok(c)) => c,
            _ => {
                let d = sh.health.fail(&self.peer, health::Kind::Quic);
                sh.note(format!("{label}: возврат на QUIC: соединение не открылось, остаюсь на TCP, QUIC запомнен на {} мин", d.as_secs() / 60));
                return Err(true);
            }
        };
        // iroh помнит custom-адрес пира: пока у пира открыт туннель REALITY, новое соединение может открыться ПО НЕМУ - это не возврат на UDP, и закрыть
        // потом «старый» носитель значит убить собственный путь. IP-пути даём до 2 с, чтобы стать выбранным.
        if reality_carrier::global().is_some() && reality_carrier::selected_is_reality(&conn) {
            for _ in 0..8 {
                if !reality_carrier::selected_is_reality(&conn) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            if reality_carrier::selected_is_reality(&conn) {
                conn.close(0u32.into(), b"still on reality");
                return Err(true);
            }
        }
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

}

async fn send_ctl(node: &Arc<Node>, link: LinkId, ty: u8, body: &[u8]) {
    let mut m = Vec::with_capacity(1 + body.len());
    m.push(ty);
    m.extend_from_slice(body);
    let h = node.engine().link_handle(&link);
    let _ = h.send(&m).await;
}

/// Keepalive RNS клиентских Link в секундах (ADR 0019 §11): ставят оба конца, клиент при подключении, сервер при допуске.
/// Одинаковое значение обязательно: ответчик с коротким окном stale закрыл бы Link клиента, молчащего между keepalive.
const CLIENT_KEEPALIVE_S: u64 = 25;
/// Запас сверх keepalive на задержку ответа, прежде чем пропуск считается потерей контакта.
const KEEPALIVE_SLACK_MS: u64 = 3_000;
/// Сколько после последнего IP-пакета выход считается занятым: пока занят, пингуем (QUIC PING или Channel T_PING) раз в секунду.
const PING_ACTIVE_HOLD_MS: u64 = 10_000;

/// Решение клиента о живости выхода (ADR 0019 §11): без трафика телефон не будится пингами и полагается на keepalive RNS
/// (каждые `CLIENT_KEEPALIVE_S`). При трафике, а также после пропущенного keepalive, идут пинги раз в секунду;
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
    /// отправить пинг сейчас
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
            assert!(!s.ping && s.silent_ms == 0, "no ping wakeup while idle");
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

fn spawn_ctl(node: &Arc<Node>, link: LinkId, ty: u8, body: Vec<u8>) {
    let node = node.clone();
    // Отправка по Link синхронно берёт замок ядра RNS. Под нагрузкой поток ядра держит его секундами, и рабочий поток tokio,
    // ждущий на нём, останавливал рантайм (fin1 10.11: оба рабочих потока по 10–11 с на замке — QUIC туннеля не обслуживался).
    // Ждать замок — в пуле блокирующих потоков, не на рабочем.
    let rt = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || rt.block_on(send_ctl(&node, link, ty, &body)));
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
    cbc_only: bool,
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
    CbcOnly,
    /// Допуск не состоялся, хотя Link ещё жив и не допущен (права или Link изменились между оценкой и публикацией).
    NotAuthorized,
}

impl AdmitDiag {
    const fn bit(self) -> u8 {
        match self {
            AdmitDiag::CbcOnly => 1,
            AdmitDiag::NotAuthorized => 8,
        }
    }

    /// Причина для журнала: без адресов, ключей и полных хешей.
    const fn note(self) -> &'static str {
        match self {
            AdmitDiag::CbcOnly => "клиент не допущен: Link на стоковом шифре CBC (только служебный LXMF)",
            AdmitDiag::NotAuthorized => "клиент не допущен: нет USE в таблице этой ноды или Link изменился до допуска",
        }
    }

    /// Фиксированный ответ клиенту; `None` - клиенту не отвечаем.
    const fn fail(self) -> Option<&'static [u8]> {
        match self {
            AdmitDiag::CbcOnly => Some(b"link not eligible"),
            AdmitDiag::NotAuthorized => Some(b"not authorized"),
        }
    }
}

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

/// Недавно закрытые Link: `close_link` для того же Link в течение 10 с ничего не делает. Окно ограничено по размеру.
static RECENT_CLOSED: Mutex<Vec<(LinkId, Instant)>> = Mutex::new(Vec::new());

fn close_first(link: LinkId) -> bool {
    let now = Instant::now();
    let mut v = RECENT_CLOSED.lock().unwrap();
    v.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(10));
    if v.iter().any(|(l, _)| *l == link) {
        return false;
    }
    if v.len() >= 256 {
        v.remove(0);
    }
    v.push((link, now));
    true
}

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
    /// Channel-пинги (носитель не QUIC или нет прямого соединения)
    loss: PingBook,
    /// монитор QUIC-носителя по статистике соединения (вместо пингов по датаграммам)
    qmon: QuicMon,
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
    my_dest: [u8; 16],
    my_key: [u8; 32],
    ep_id: String,
    /// подсказка REALITY этого узла (`--reality-listen`): публикуется рядом с адресами в приватном каталоге
    /// объявляемые адреса (без явного advertise меняются вслед за интерфейсами: см. adv_auto)
    advertise: Mutex<Vec<String>>,
    /// адреса взяты с интерфейсов (нет явного advertise): (частные разрешены, свой туннель) для перепроверки раз в 60 с; None - адрес задан явно
    adv_auto: Option<(bool, String)>,
    announce_s: u64,
    dead: Duration,
    path_gate: path::PathGate,
    /// имя клиента из T_USE (Link -> имя); раздаётся дальше в T_NBRS; не больше 256 записей
    client_info: Mutex<HashMap<LinkId, String>>,
    /// клиенты-узлы соседей по T_CINFO: dest -> (имя, когда); не больше CINFO_MAX, живут CINFO_TTL
    peer_clients: Mutex<HashMap<[u8; 16], (String, Instant)>>,
    links: Mutex<HashMap<LinkId, LinkInfo>>,
    neigh: Mutex<HashMap<[u8; 16], Neighbor>>,
    tun: Option<Arc<TunState>>,
    started: Instant,
    listen_port: u16,
    /// идентификаторы интерфейсов публичной сети RNS (их выдаёт spawn_interface; по имени узнавать нельзя: интерфейс называется `tcp_client_N`)
    public_ids: Mutex<HashSet<usize>>,
    /// модель 0013 (права и якоря доверия)
    t13: Option<T13>,
}

/// Состояние модели 0028 на узле: таблица прав и единое ядро приглашений/команд.
struct T13 {
    peers: Arc<Mutex<peers::Peers>>,
    core: Arc<invite::Core>,
}

impl NodeCtx {
    /// Индексы интерфейсов, не относящихся к публичной сети RNS (QUIC-связи с нашими узлами и клиентами).
    fn iface_is_public(&self, idx: usize) -> bool {
        self.public_ids.lock().unwrap().contains(&idx)
    }

    /// Link пришёл (или ушёл) через публичную сеть RNS? Наши узлы и клиенты общаются только по нашим интерфейсам.
    /// S12: носитель неизвестен (Link не найден или не привязан) - считаем публичным, fail-closed.
    fn link_is_public(&self, link: &LinkId) -> bool {
        self.node.engine().with_link(link, |s| s.attached_interface()).flatten().map(|i| self.iface_is_public(i)).unwrap_or(true)
    }

    /// Link установлен стандартным CBC (не нашим GCM)? Шифр неизвестен - да (fail-closed).
    fn link_is_cbc(&self, link: &LinkId) -> bool {
        self.node.engine().with_link(link, |l| l.cipher() != leviculum_std::api::LinkCipher::Gcm).unwrap_or(true)
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
        link || t.peers.lock().unwrap().admits_server(pk)
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

    /// Расширенный журнал (debug): раз в 10 с одна строка с состоянием соседей, клиентов и нагрузкой хоста. Адресов и ключей нет.
    fn debug_snapshot(&self) {
        let now = Instant::now();
        let nb: Vec<String> = self.neigh.lock().unwrap().values().map(|n| {
            let st = if n.link.is_some() {
                format!("up {} rtt {} смен {}", n.ctl.mode_label(),
                    n.rtt_ms.map(|r| format!("{r:.0}")).unwrap_or_else(|| "?".into()), n.ctl.switches.load(Relaxed))
            } else {
                format!("seen {} с назад", now.duration_since(n.last_announce).as_secs())
            };
            format!("{}: {st}", n.name)
        }).collect();
        let (links, clients) = {
            let l = self.links.lock().unwrap();
            (l.len(), l.values().filter(|x| matches!(x.role, Role::Client { .. })).count())
        };
        self.sh.note(format!("снимок: аптайм {} с, Link {links}, клиентов {clients}; соседи [{}]; {}", self.started.elapsed().as_secs(), nb.join("; "), crate::host_pressure()));
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
                "c": *nb.ctl.mode.lock().unwrap(), "dead": nb.ctl.dead.load(Relaxed), "sw": nb.ctl.switches.load(Relaxed), "s": if up { "up" } else { "seen" }, "age_s": now.duration_since(nb.last_announce).as_secs(), "heard_s": now.duration_since(nb.last_heard).as_secs()}));
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
            .map(|(d, r, nm)| serde_json::json!({"d": hex(d), "r": r.map(|x| x.round() as i64), "n": nm.chars().take(32).collect::<String>()})).collect();
        // Клиенты с правами узла сети (якорь, TRANSIT или EXIT), например телефон-админ - свои и сообщённые соседями (T_CINFO):
        // только имя ("c":1), ребром соседа они не становятся. Рядовых пользователей (только USE) другим клиентам не раскрываем.
        let mut cl: Vec<([u8; 16], String)> = self.node_clients().into_iter().map(|(pk, n)| (dest_from_pub_tag(&pk, T13_TAG), n)).collect();
        {
            let mut pc = self.peer_clients.lock().unwrap();
            pc.retain(|_, v| v.1.elapsed() < CINFO_TTL);
            for (d, (n, _)) in pc.iter() {
                if !cl.iter().any(|c| c.0 == *d) {
                    cl.push((*d, n.clone()));
                }
            }
        }
        cl.sort_by(|a, b| a.0.cmp(&b.0));
        out.extend(cl.into_iter().take(NBRS_MAX.saturating_sub(out.len())).map(|(d, n)| serde_json::json!({"d": hex(&d), "c": 1, "n": n})));
        out
    }

    /// Допущенные напрямую клиенты с правами узла сети (якорь, TRANSIT или EXIT): (ключ, имя) из их T_USE.
    fn node_clients(&self) -> Vec<([u8; 64], String)> {
        let Some(t) = &self.t13 else { return vec![] };
        let info = self.client_info.lock().unwrap().clone();
        let peers: Vec<(LinkId, [u8; 64])> = self.links.lock().unwrap().iter()
            .filter(|(_, l)| matches!(l.role, Role::Client { .. }) && !l.cbc_only)
            .filter_map(|(k, l)| l.peer_pk.map(|pk| (*k, pk))).collect();
        let tr = t.peers.lock().unwrap();
        let mut v: Vec<([u8; 64], String)> = peers.iter().filter_map(|(link, pk)| {
            let name = info.get(link)?;
            node_like(&tr, pk).then(|| (*pk, name.clone()))
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
            for (pk, n) in &mine {
                c.push(serde_json::json!({"k": hex(pk), "n": n}));
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
            if !matches!(l.role, Role::Client { .. }) || l.cbc_only || !l.observation.due(Instant::now(), &entries) { return; }
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
        // Повторное закрытие того же Link (запись от пира приходит пачкой) не пишем и не повторяем: 922 строки за 3 ч засоряли журнал и диск.
        if !close_first(link) {
            return;
        }
        // Роль, возраст и тишина Link в момент закрытия: по ним видно, рвётся сосед, клиент или неизвестный Link.
        let who = self.links.lock().unwrap().get(&link).map(|l| {
            let role = match l.role { Role::Unknown => "новый", Role::Server { .. } => "сосед", Role::Client { .. } => "клиент" };
            format!("{role}, живёт {} с, тишина {} мс", l.since.elapsed().as_secs(), l.last_heard.elapsed().as_millis())
        });
        match who {
            Some(w) => self.sh.note(format!("close link {} ({why}; {w})", &hex(link.as_bytes())[..8])),
            None => self.sh.note(format!("close link {} ({why})", &hex(link.as_bytes())[..8])),
        }
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
            let who = peers::hash_of(pk).map(|h| hex(&h)[..8].to_string()).unwrap_or_else(|| "?".into());
            self.sh.note(format!("link {} (id {who}): {}", &hex(link.as_bytes())[..8], d.note()));
        }
    }

    fn drop_link_state(&self, link: &LinkId) {
        let removed = remove_link_admission(&self.links, link, || {
            if let Some(t) = &self.tun { t.disallow(link); }
        });
        if removed.as_ref().is_some_and(|l| matches!(l.role, Role::Client { .. })) {
            crate::host_acl::notify_nft();
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

fn key_of32(pk: &[u8; 64]) -> [u8; 32] { pk[32..64].try_into().unwrap() }

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
        if c.debug.unwrap_or(false) || std::env::var("KNOTHOP_DEBUG").is_ok() { crate::set_debug(true); }
        a.quic_cc_mbit = c.quic_cc_mbit.unwrap_or(a.quic_cc_mbit);
        a.workers = c.workers.unwrap_or(a.workers);
        lxmf_sync::set_pn_cap_mb(c.pn_cap_mb);
        rrc::configure(c.rrc, c.rrc_name);
        a.tun_name = c.tun_name.unwrap_or(a.tun_name);
        a.client_net = c.client_net.unwrap_or(a.client_net);
        a.invite_file = c.invite_file.or(a.invite_file.clone());
        a.iroh_relay = c.iroh_relay;
        a.relay_quic_port = c.relay_quic_port.unwrap_or(a.relay_quic_port);
        if !c.relay_urls.is_empty() { a.relay_url = c.relay_urls.join(","); }
        a.reality_listen = c.reality_listen.or(a.reality_listen.clone());
        a.reality_dest = c.reality_dest.or(a.reality_dest.clone());
        if !c.reality_sni.is_empty() { a.reality_sni = c.reality_sni.join(","); }
        if !c.reality_proxy_trusted.is_empty() { a.reality_proxy_trusted = c.reality_proxy_trusted.join(","); }
        a.reality_public_port = c.reality_public_port.or(a.reality_public_port);
    }
    let _ = CLIENT_NET.set(parse_net(&a.client_net)?);
    // Имя узла: --name / config, иначе state/node-name.txt (его же задаёт телефон в настройках), иначе имя хоста. Одна нормализация на все пути.
    a.name = norm_name(&a.name)
        .or_else(|| std::fs::read_to_string(a.state.join("node-name.txt")).ok().and_then(|t| norm_name(&t)))
        .or_else(|| norm_name(&hostname()))
        .unwrap_or_else(|| "узел".into());
    if a.state == Path::new("-") {
        bail!("нужен --state (флагом или в --config)");
    }
    // ADR 0028 §2.5: строка приглашения первого старта (выпускает приложение админа). Только файл 0600 или stdin (`-`):
    // в argv секрет виден через /proc. Отсутствующий файл — не ошибка: приглашение уже погашено и стёрто.
    let invite_raw = match &a.invite_file {
        Some(f) if f == Path::new("-") => { use std::io::Read; let mut s = String::new(); std::io::stdin().take(8192).read_to_string(&mut s)?; s }
        Some(f) => match peers::read_private(f, 8192) {
            Ok(Some(b)) => String::from_utf8(b).context("invite-file не UTF-8")?,
            Ok(None) => String::new(),
            Err(e) => return Err(e).with_context(|| format!("invite-file {}: нужен обычный файл с правами 0600", f.display())),
        },
        None => String::new(),
    };
    let identity = load_or_create_identity(&a.state)?;
    let key = iroh_key_from_identity(&identity)?;
    // сертификат relay делается из ключа ноды; копию держим только если relay включён
    let relay_seed = a.iroh_relay.then(|| key.to_bytes());
    let exit_args = ["--tun-mtu", "1327", "--tun-ip", "10.99.0.1/24", "--tun-txqlen", "10240", "--tun-qdisc", "fq_codel", "--tun-name", a.tun_name.as_str()];
    let b = start_base("n", &a.state, true, Some(a.port), key, Some(identity.clone()), a.quic_cc_mbit, if a.no_exit { &[] } else { &exit_args[..] }, None, &parse_relay_urls(&a.relay_url)).await?;
    let (node, sh, ep, cli, events, admin_lxmf) = (b.node.clone(), b.sh.clone(), b.ep.clone(), b.cli.clone(), b.events, b.admin_lxmf);
    // REALITY-сервер (по умолчанию выключен). Неверный конфиг - ошибка запуска, а не молчаливое отключение. Доверие из REALITY не выводится: туннель несёт обычный QUIC
    let _reality_hint = match (&a.reality_listen, reality_carrier::global()) {
        (Some(listen), Some(rc)) => {
            let Some(dest) = a.reality_dest.as_deref() else { bail!("--reality-listen требует --reality-dest") };
            let split = |s: &str| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect::<Vec<_>>();
            let conf = reality_carrier::ServerConf::parse(listen, dest, &split(&a.reality_sni), &split(&a.reality_proxy_trusted), a.reality_public_port)?;
            let shn = sh.clone();
            let (hint, _) = rc.start_server(&conf, &a.state, Arc::new(move |m| shn.note(m))).await?;
            Some(hint)
        }
        (Some(_), None) => bail!("--reality-listen при KNOTHOP_REALITY=0"),
        _ => None,
    };

    // тег назначения един для всей сети: нода находит соседей по тегам корней в анонсе
    let tag = T13_TAG.to_string();
    let my_pk = identity.public_key_bytes();
    let my_key = identity.ed25519_verifying().to_bytes();
    let node_identity = identity.clone();
    let dest = new_dest(identity, Direction::In, &tag).map_err(|e| anyhow::anyhow!("destination: {e:?}"))?;
    let my_dest = *dest.hash().as_bytes();
    node.register_destination(dest);

    // ADR 0028: таблица прав на ноде и ядро приглашений/команд. Нечитаемый peers.json — ошибка запуска (fail-closed).
    let ctx_cell: Arc<std::sync::OnceLock<std::sync::Weak<NodeCtx>>> = Arc::new(std::sync::OnceLock::new());
    let t13 = {
        let table = Arc::new(Mutex::new(peers::Peers::load(my_pk, &a.state).context("peers.json")?));
        let (c1, c2, c3) = (ctx_cell.clone(), ctx_cell.clone(), sh.clone());
        let core = invite::Core::new(&a.state, node_identity.clone(), table.clone(), false,
            Box::new(move || c1.get().and_then(|w| w.upgrade()).map(|c| c.adv()).unwrap_or_default()),
            Box::new(move || { if let Some(c) = c2.get().and_then(|w| w.upgrade()) { c.enforce_rights(); } }),
            Box::new(move |m| c3.note(m)))?;
        core.set_name(&a.name);
        core.set_rl(_reality_hint.as_ref().map_or(serde_json::Value::Null, |h| h.to_json()));
        if !invite_raw.trim().is_empty() {
            // Управление нодой - свойство запуска (ADR 0028 §2.5): выдавший станет управляющим после проверенного `accept`, если у ноды ещё
            // нет управляющих. Повторный инвайт не должен тихо делать второго админа: у уже управляемой ноды - только с --accept-manage;
            // без флага строка принимается как обычное вступление (контакт, без управления).
            let managed = table.lock().unwrap().has_controllers();
            let adopt = if a.accept_manage { invite::ADOPT_FORCE } else if managed { 0 } else { invite::ADOPT_IF_EMPTY };
            let (hs, _) = core.join_adopt(&invite_raw, adopt).context("приглашение")?;
            eprintln!("Приглашение принято к исполнению: нод {} (первая {}); {}", hs.len(), hex(&hs[0]),
                match adopt { invite::ADOPT_FORCE => "выдавший станет управляющим (--accept-manage)", invite::ADOPT_IF_EMPTY => "выдавший станет управляющим нодой после погашения", _ => "нода уже управляется: управление не выдаётся без --accept-manage" });
        }
        Some(T13 { peers: table, core })
    };
    if let Some(t) = &t13 { let _ = RELAY_PEERS.set(t.peers.clone()); install_mesh_policy(&b.node, &t.peers, false); }

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
    let mut advertise: Vec<String> = [a.advertise.as_str(), env_adv.as_str()].iter().flat_map(|t| t.split(',')).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
    advertise = peers::balance_hints(advertise, peers::MAX_HINTS);
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
        identity: node_identity, my_pk, my_dest, my_key, ep_id: ep.id().to_string(), advertise: Mutex::new(advertise), adv_auto,
        announce_s: a.announce_s, dead: Duration::from_secs(a.dead_s), path_gate: path::PathGate::default(), client_info: Mutex::new(HashMap::new()), peer_clients: Mutex::new(HashMap::new()),
        links: Mutex::new(HashMap::new()), neigh: Mutex::new(HashMap::new()),
        tun, started: Instant::now(),
        listen_port: a.port, public_ids: Mutex::new(HashSet::new()),
        t13,
    });
    if ctx.tun.is_some() {
        // Пакеты прямого канала VPN идут тем же обработчиком, что и пакеты Link допущенного клиента (allowed, source-IP, ACL, HOST_ACCESS).
        let weak = Arc::downgrade(&ctx);
        dataplane::plane().set_sink(Arc::new(move |link, pkt| {
            if let Some(ctx) = weak.upgrade() {
                if let Some(t) = &ctx.tun { t.on_link_packet(&ctx.node, link, pkt); }
            }
        }));
    }
    if let (Some(tun), Some(t), Some(host_nft)) = (&ctx.tun, &ctx.t13, host_nft) {
        let weak = Arc::downgrade(&ctx);
        host_nft.start(tun, t.peers.clone(), move || {
            let ctx = weak.upgrade()?;
            let links = ctx.links.lock().unwrap();
            Some(links.iter().filter(|(_, l)| !l.cbc_only && matches!(l.role, Role::Client { .. }))
                .filter_map(|(link, l)| l.peer_pk.map(|pk| (*link, pk))).collect())
        })?;
    }
    if let Some(t) = &ctx.t13 {
        let _ = ctx_cell.set(Arc::downgrade(&ctx));
        invite::register(&t.core);
    }
    let _sync_guard = admin_lxmf.as_ref().map(|r| lxmf_sync::register(&a.state, r.sync.clone()));
    if let (Some(runtime), Some(t)) = (admin_lxmf, &ctx.t13) {
        runtime.pn.set_source(t.peers.clone());
        if let Err(e) = lxmf_admin::spawn_worker(runtime, t.core.clone()) { sh.note(format!("не удалось запустить LXMF-воркер: {e}")); }
    }
    if let Some(t) = &ctx.t13 {
        let p = t.peers.lock().unwrap();
        sh.note(format!("модель 0028: записей {}, управляющих {}, контактов {}{}", p.peer_list().len(), p.controllers().len(), p.contact_list().len(),
            if t.core.has_pending() { ", вступаю по приглашению" } else { "" }));
    }
    ctx.seed_neighbors();
    write_atomic(&a.state.join("server.json"), ctx.self_json().to_string().as_bytes());
    sh.note(format!("node {} tag {} dest {} iroh {}", ctx.name, tag, hex(&my_dest), ctx.ep_id));

    tokio::spawn(accept_loop(ep.clone(), node.clone(), sh.clone()));
    let relay_host = match (relay_seed, &ctx.t13) {
        (Some(seed), Some(t)) => {
            // relay не даёт прав: к нему допускаются только ключи, у которых в нашей сети есть хоть какое-то право (цепочка до якоря проверена в Trust)
            let trust = t.peers.clone();
            let trusted: relay::Trusted = Arc::new(move |k: &[u8; 32]| trust.lock().unwrap().relay_allows(k));
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
            tokio::spawn(dial_direct(ep.clone(), node.clone(), sh.clone(), format!("seed-{}", id.fmt_short()), id, Addrs::new(addrs), Arc::new(AtomicBool::new(true)), CarrierCtl::new(), false));
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

// Bounded diagnostics for inbound VPN Link events. A remote peer can trigger
// these, so logging must stay rate-limited even during an unauthenticated flood.
static LAST_INBOUND_LINK_DIAG_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn node_events(ctx: Arc<NodeCtx>, mut events: leviculum_std::driver::EventReceiver) {
    while let Some(ev) = events.recv().await {
        match ev {
            NodeEvent::AnnounceReceived { announce, .. } => on_announce(&ctx, &announce),
            NodeEvent::LinkEstablished { link_id, is_initiator, destination_hash } => {
                // LXMF delivery/PN — отдельные назначения. Их identify не
                // должен продвигать Link в VPN-соседа или вытеснять mesh Link.
                if !is_initiator && !vpn_incoming_destination(&ctx.my_dest, &destination_hash) { continue; }
                ctx.sh.established.lock().unwrap().insert(hex(link_id.as_bytes()));
                if !is_initiator {
                    let now = now_ms() as u64;
                    let last = LAST_INBOUND_LINK_DIAG_MS.load(Relaxed);
                    if now.saturating_sub(last) >= 1000 && LAST_INBOUND_LINK_DIAG_MS.compare_exchange(last, now, Relaxed, Relaxed).is_ok() {
                        ctx.sh.note(format!("входящий Link {}: событие RNS установлено", &hex(link_id.as_bytes())[..8]));
                    }
                    if crate::debug() {
                        ctx.sh.note(format!("входящий Link {}", &hex(link_id.as_bytes())[..8]));
                    }
                    // H10: интерфейс носителя известен из состояния Link (если его ещё нет - лимит на интерфейс не применяем, общий работает)
                    let (iface, cipher) = ctx.node.engine().with_link(&link_id, |l| (l.attached_interface(), l.cipher())).unzip();
                    let iface = iface.flatten();
                    // fail-closed: шифр неизвестен - считаем стандартным CBC
                    let cbc = cipher.map(|c| c != leviculum_std::api::LinkCipher::Gcm).unwrap_or(true);
                    let mut l = ctx.links.lock().unwrap();
                    let unauth = l.values().filter(|x| matches!(x.role, Role::Unknown)).count();
                    let unauth_iface = l.values().filter(|x| matches!(x.role, Role::Unknown) && iface.is_some() && x.iface == iface).count();
                    if unauth >= MAX_UNAUTH_LINKS || unauth_iface >= MAX_UNAUTH_PER_IFACE {
                        drop(l);
                        ctx.close_link(link_id, "слишком много неавторизованных link");
                        continue;
                    }
                    l.insert(link_id, LinkInfo { role: Role::Unknown, since: Instant::now(), last_heard: Instant::now(), peer_pk: None, want_use: false, cbc_only: cbc, iface, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default(), diag: 0 });
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
            // Link хаба RRC обслуживает rrc.rs; в разбор VPN-пакетов они не попадают
            NodeEvent::LinkDataReceived { link_id, .. } if rrc::is_hub_link(&link_id) => {}
            NodeEvent::LinkDataReceived { link_id, .. } if ctx.link_is_cbc(&link_id) => {}
            NodeEvent::LinkDataReceived { link_id, data, .. } => {
                if let Some(t) = &ctx.tun {
                    t.on_link_packet(&ctx.node, link_id, &data);
                }
            }
            _ => {}
        }
    }
}

fn on_announce(ctx: &Arc<NodeCtx>, ann: &leviculum_std::ReceivedAnnounce) {
    if crate::debug() {
        ctx.sh.note(format!("announce from {} path_response={} data={}", hex(&ann.destination_hash().as_bytes()[..4]), ann.is_path_response(), String::from_utf8_lossy(ann.app_data()).chars().take(60).collect::<String>()));
    }
    let dest = *ann.destination_hash().as_bytes();
    let pk = *ann.public_key();
    if dest == ctx.my_dest || dest != dest_from_pub_tag(&pk, T13_TAG) { return; }
    let Some(t) = &ctx.t13 else { return };
    // анонс принимается только от ноды, которую знает таблица (запись или контакт); чужие анонсы соседей не создают
    if !t.peers.lock().unwrap().knows_key(&key_of32(&pk)) { return; }
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
            last_try: Instant::now() - Duration::from_secs(3600), ctl: CarrierCtl::new(), loss: PingBook::default(), qmon: QuicMon::default(), admitted_at: Instant::now(), seen_gen: 0 });
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
        // свежий анонс (не ответ на запрос пути из чужого кэша) - узел жив: снять «мёртв» и набрать сразу
        if !ann.is_path_response() {
            e.addrs.wake();
        }
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
            async move { dial_direct(ep, node, sh, label, id, book, alive, cc, true).await }
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
        if !path::acceptable(ctx.node.engine().with_link(&id, |s| s.attached_interface()).flatten(), &own_carrier_ifaces(&ctx.node), None) {
            let _ = ctx.node.engine().close_link(&id).await;
            bail!("Link выбрал интерфейс вне наших носителей");
        }
        Ok(id)
    }
    .await;
    match res {
        Ok(id) => {
            // 0013: роль не зависит от инициативы. Сначала identify (ответчик узнаёт нас), затем обе стороны обмениваются цепочками прав
            ctx.links.lock().unwrap().insert(id, LinkInfo { role: Role::Unknown, since: Instant::now(), last_heard: Instant::now(), peer_pk: Some(pk), want_use: false, cbc_only: false, iface: None, ctrl: CtrlBucket::new(Instant::now()), observation: Default::default(), diag: 0 });
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

/// Допущенный (Server/Client) Link не для зачисления? Только такой отвечает на T_PING и принимает T_PONG.
/// `Some(Some(dest))` - сосед, `Some(None)` - клиент.
fn admitted_ping_role(ctx: &Arc<NodeCtx>, link: LinkId) -> Option<Option<[u8; 16]>> {
    let l = ctx.links.lock().unwrap();
    let info = l.get(&link)?;
    if info.cbc_only {
        return None;
    }
    match info.role {
        Role::Server { dest } => Some(Some(dest)),
        Role::Client { .. } => Some(None),
        Role::Unknown => None,
    }
}

/// T_PING от допущенного Link: эхо nonce тем же Link. Размер ответа равен запросу (усиления нет); частоту ограничивает `ctrl_pass`.
fn on_ping(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    if parse_ping_nonce(body).is_none() || admitted_ping_role(ctx, link).is_none() {
        return;
    }
    spawn_ctl(&ctx.node, link, T_PONG, body.to_vec());
}

/// T_PONG на выходе: только от соседа (Server) и только на nonce, отправленный на этот же Link. RTT и «слышали» берутся отсюда.
fn on_pong(ctx: &Arc<NodeCtx>, link: LinkId, body: &[u8]) {
    let Some(nonce) = parse_ping_nonce(body) else { return };
    let Some(Some(dest)) = admitted_ping_role(ctx, link) else { return };
    let mut n = ctx.neigh.lock().unwrap();
    let Some(nb) = n.get_mut(&dest) else { return };
    if let Some(rtt) = accept_pong(&mut nb.loss, nb.link, link, nonce) {
        nb.rtt_ms = Some(rtt.as_secs_f64() * 1000.0);
        nb.last_heard = Instant::now();
    }
}

/// Засчитывать ли T_PONG соседа: Link должен быть текущим Link соседа, а nonce - отправленным на него и ещё не отвеченным.
fn accept_pong(book: &mut PingBook, current: Option<LinkId>, link: LinkId, nonce: u64) -> Option<Duration> {
    if current != Some(link) {
        return None;
    }
    book.ack(link, nonce)
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
        T_PING => on_ping(ctx, link, body),
        T_PONG => on_pong(ctx, link, body),
        T_OBSERVE if matches!(body, [0] | [1]) => {
            {
                let mut links = ctx.links.lock().unwrap();
                let Some(l) = links.get_mut(&link) else { return };
                if !matches!(l.role, Role::Client { .. }) || l.cbc_only { return; }
                l.observation.set_visible(body[0] == 1);
            }
            ctx.send_nbrs(link);
        }
        T_USE => {
            if let Some(l) = ctx.links.lock().unwrap().get_mut(&link) {
                l.want_use = true;
            }
            if let Some(name) = parse_client_info(body) {
                let live: HashSet<LinkId> = ctx.links.lock().unwrap().keys().copied().collect();
                let mut m = ctx.client_info.lock().unwrap();
                m.retain(|l, _| live.contains(l));
                if m.len() < 256 || m.contains_key(&link) {
                    m.insert(link, name);
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

/// Адреса выходов хранятся по хешу назначения; после смены имени (ADR 0016) старые ключи перекладываем на новые по известным ключам нод.
/// `hints-rl.json`: подсказки REALITY, прошедшие тот же разбор, что и из каталога (файл недоверенный, не больше 64 КБ и 64 записей).
fn load_rl_hints(state: &Path) -> HashMap<String, reality_carrier::RealityHint> {
    let Ok(b) = std::fs::read(state.join("hints-rl.json")) else { return HashMap::new() };
    if b.len() > 64 * 1024 {
        return HashMap::new();
    }
    let Ok(m) = serde_json::from_slice::<HashMap<String, serde_json::Value>>(&b) else { return HashMap::new() };
    m.into_iter().filter(|(k, _)| k.len() == 32).filter_map(|(k, v)| reality_carrier::RealityHint::from_json(&v).map(|h| (k, h))).take(64).collect()
}

/// Announced link capability is only a scheduler hint; it never participates in authorization.
fn plan_transit_neighbor(accepts_links: bool, has_transit_rights: bool) -> bool {
    accepts_links && has_transit_rights
}

/// Guard for actual Server promotion (including delayed callbacks). An announce can only opt
/// its own known identity out; authorization still comes exclusively from the trust records.
fn server_promotion_allowed(cbc_only: bool, accepts_links: Option<bool>, has_transit_rights: bool) -> bool {
    !cbc_only && accepts_links != Some(false) && has_transit_rights
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OrdinaryAdmission { Client, Server }

/// The authority and live Link state remain locked through publication, not just a snapshot.
/// Order: Trust -> links -> (neigh OR TUN host_access -> allowed -> routes).
/// No I/O, await, close_link or reentrant NodeCtx calls in `publish`.
fn with_authorized_link<R>(
    authority: &Mutex<peers::Peers>, links: &Mutex<HashMap<LinkId, LinkInfo>>,
    link: LinkId, pk: &peers::Pk, kind: OrdinaryAdmission, promote: bool,
    publish: impl FnOnce(&peers::Peers, &mut HashMap<LinkId, LinkInfo>) -> R,
) -> Option<R> {
    let tr = authority.lock().unwrap();
    let mut live = links.lock().unwrap();
    let i = live.get(&link)?;
    if i.peer_pk.as_ref() != Some(pk) || i.cbc_only { return None; }
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
    let authorized = match kind {
        OrdinaryAdmission::Client => tr.admits_client(pk),
        OrdinaryAdmission::Server => server_promotion_allowed(i.cbc_only, None, tr.admits_server(pk)),
    };
    if !authorized { return None; }
    let result = publish(&tr, &mut live);
    drop(live);
    drop(tr);
    Some(result)
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
    authority: &Mutex<peers::Peers>, links: &Mutex<HashMap<LinkId, LinkInfo>>, link: LinkId, pk: &peers::Pk,
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
        if let Err(refusal) = publish_tun(ip, tr.rights_pk(pk) & peers::HOST_ACCESS != 0, &evictable) {
            live.get_mut(&link).unwrap().role = Role::Unknown;
            return Err(refusal);
        }
        // Вытесненные Link уже убраны из таблиц TUN; из `links` и закрытие - после, вне guard (`admit_client13`).
        let replaced = live.iter().filter(|(k, i)| **k != link && matches!(i.role, Role::Client { id: h, .. } if h == id)).map(|(k, _)| *k).collect();
        Ok(ClientAdmission { id, ip, replaced })
    })
}

/// Shared neighbor-table publication, including deterministic duplicate-Link selection.
fn admit_neighbor_state(n: &mut HashMap<[u8; 16], Neighbor>, link: LinkId, dest: [u8; 16], pk: &peers::Pk) -> Option<LinkId> {
    let mut key = [0u8; 32];
    key.copy_from_slice(&pk[32..64]);
    let e = n.entry(dest).or_insert_with(|| Neighbor { dest, key, pk: *pk, name: "?".into(), ep: String::new(), addrs: Addrs::new(vec![]), tags: vec![], accepts_links: true, last_announce: Instant::now(),
        link: None, last_heard: Instant::now(), rtt_ms: None, connecting: false, dialer: None, first_seen: Instant::now(), last_try: Instant::now() - Duration::from_secs(3600), ctl: CarrierCtl::new(), loss: PingBook::default(), qmon: QuicMon::default(), admitted_at: Instant::now(), seen_gen: 0 });
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
    e.qmon.reset();
    None
}

fn promote_server_link(
    authority: &Mutex<peers::Peers>, links: &Mutex<HashMap<LinkId, LinkInfo>>, neigh: &Mutex<HashMap<[u8; 16], Neighbor>>,
    link: LinkId, pk: &peers::Pk, dest: [u8; 16],
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

impl NodeCtx {


    /// (нужен ли сосед, наша ли очередь открывать Link). Нужны соседи, которых таблица знает и из которых хотя бы один транзит
    /// (открывает меньший dest).
    fn neighbor_policy(&self, d: &[u8; 16]) -> (bool, bool) {
        let Some((pk, accepts)) = self.neigh.lock().unwrap().get(d).map(|n| (n.pk, n.accepts_links)) else { return (false, false) };
        let Some(t) = &self.t13 else { return (false, false) };
        let wanted = plan_transit_neighbor(accepts, t.peers.lock().unwrap().admits_server(&pk));
        (wanted, wanted && (self.my_dest < *d || self.adv().is_empty()))
    }

    /// Соседи по контактам: адреса-подсказки из `accept` (ADR 0028 §2.4) становятся записями таблицы соседей. Анонсы адресов не несут (0016).
    fn seed_neighbors(&self) {
        let Some(t) = &self.t13 else { return };
        let contacts = t.peers.lock().unwrap().contact_list();
        let mut n = self.neigh.lock().unwrap();
        for c in contacts {
            let dest = dest_from_pub_tag(&c.pk, &self.tag);
            let hints: Vec<String> = c.hints.iter().filter(|a| sane_hint_addr(a)).cloned().collect();
            // клиент (телефон), объявивший себя в accept/ack, не сосед-транзит: сервер его не набирает (P2P набирают сами клиенты)
            if c.pk == self.my_pk || hints.is_empty() || c.client { continue; }
            let rl = reality_carrier::RealityHint::from_json(&c.rl);
            if let Some(nb) = n.get_mut(&dest) { if nb.addrs.is_empty() { nb.addrs.set(hints); } nb.addrs.rl_fill(&rl); continue; }
            let key: [u8; 32] = c.pk[32..64].try_into().unwrap();
            let Some(ep) = endpoint_peer_id(&key) else { continue };
            let book = Addrs::new(hints);
            book.rl_fill(&rl);
            n.insert(dest, Neighbor { dest, key, pk: c.pk, name: c.name, ep, addrs: book, tags: vec![], accepts_links: true, last_announce: Instant::now(),
                link: None, last_heard: Instant::now() - Duration::from_secs(3600), rtt_ms: None, connecting: false, dialer: None, first_seen: Instant::now(),
                last_try: Instant::now() - Duration::from_secs(3600), ctl: CarrierCtl::new(), loss: PingBook::default(), qmon: QuicMon::default(), admitted_at: Instant::now(), seen_gen: 0 });
        }
    }

    /// Переоценить все Link по текущей таблице: права сняты - закрыть, права появились - допустить.
    fn enforce_rights(self: &Arc<Self>) {
        self.seed_neighbors();
        let ids: Vec<LinkId> = self.links.lock().unwrap().keys().copied().collect();
        for l in ids {
            self.evaluate(l);
        }
        crate::host_acl::notify_nft();
    }

    /// Роль Link определяют записи таблицы, а не заявленная роль: сосед-сервер - известен и один из двух транзит;
    /// клиент (прислал T_USE) - `exit_enabled` у нас и USE в его записи.
    fn evaluate(self: &Arc<Self>, link: LinkId) {
        let Some(t) = &self.t13 else { return };
        let (pk, kind, want_use, cbc_only) = {
            let l = self.links.lock().unwrap();
            let Some(i) = l.get(&link) else { return };
            let Some(pk) = i.peer_pk else { return };
            let kind = match i.role {
                Role::Unknown => 0,
                Role::Server { .. } => 1,
                Role::Client { .. } => 2,
            };
            (pk, kind, i.want_use, i.cbc_only)
        };
        if cbc_only {
            // Link на стоковом (CBC) шифре никогда не станет клиентом/соседом: сообщаем пришедшему за выходом, а не оставляем ждать таймаут
            if kind == 0 && want_use {
                self.admit_diag(link, &pk, AdmitDiag::CbcOnly);
            }
            return;
        }
        let ((srv_ok, cli_ok, exit_on), _) = publish_host_access_decision(&t.peers, &pk, |p| (p.admits_server(&pk), p.admits_client(&pk), p.config().exit_enabled), |host_ok| {
            // Замок таблицы ещё держит установку; закрытие/допуск ниже - после его снятия.
            if kind == 2 {
                if let Some(tun) = &self.tun { return tun.set_host_access(&link, host_ok); }
            }
            true
        });
        match kind {
            1 => {
                if !srv_ok {
                    self.close_link(link, "сосед больше не знаком таблице или транзит выключен");
                }
            }
            2 => {
                if !cli_ok {
                    self.close_link(link, if exit_on { "право USE снято" } else { "выход выключен на ноде" });
                }
            }
            _ => {
                if want_use {
                    if cli_ok {
                        self.admit_client13(link, pk);
                    } else if !exit_on {
                        // нода не выход: клиент должен сразу перейти к другому, а не ждать таймаута
                        let c = self.clone();
                        tokio::spawn(async move {
                            send_ctl(&c.node, link, T_AUTH_FAIL, b"exit disabled by node policy").await;
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            c.close_link(link, "нода не выход (exit_enabled выключен)");
                        });
                    } else {
                        // запись клиента появляется до ответа `accept` (атомарное погашение), поэтому ждать нечего
                        self.admit_diag(link, &pk, AdmitDiag::NotAuthorized);
                    }
                } else if srv_ok && !cli_ok {
                    self.admit_server13(link, pk);
                } else if srv_ok {
                    // Пир с обоими допусками (например, телефон-админ): сосед он или клиент - решает T_USE, а он может прийти позже
                    // identify из-за порядка доставки. Даём доле секунды и только затем берём его соседом.
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
        if self.link_is_public(&link) {
            self.close_link(link, "link через публичную сеть");
            return;
        }
        let dest = dest_of_pub(self, &pk);
        let Some(duplicate) = promote_server_link(&t.peers, &self.links, &self.neigh, link, &pk, dest) else { return };
        if let Some(drop_id) = duplicate {
            self.close_link(drop_id, "дубликат либо отказ от серверного Link");
            if drop_id == link { return; }
        }
        self.sh.note(format!("сосед {} допущен по таблице прав", name_of(self, &dest)));
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
        let result = promote_client_link(&t.peers, &self.links, link, &pk, |ip, host_ok, replaces| {
            match admission_outcome(tun.allow_replacing_with_handle(link, ip, handle, replaces)) {
                AdmitOutcome::Refuse { reason, note } => Err(AdmitOutcome::Refuse { reason, note }),
                AdmitOutcome::SendAuthOk if tun.set_host_access(&link, host_ok) => {
                    // Прямой канал VPN-данных: ключ iroh клиента = ключ подписи его identity (pk[32..64]); привязка только после допуска,
                    // под теми же guard Trust+links, что и allow. Нет места - клиент просто остаётся на Link.
                    dataplane::plane().bind(pk[32..64].try_into().expect("32 bytes"), link);
                    Ok(())
                }
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
        self.sh.note(format!("client {} admitted on {}", &hex(&idh)[..8], &hex(link.as_bytes())[..8]));
        self.node.engine().with_link_mut(&link, |l| l.set_keepalive_override(Some(CLIENT_KEEPALIVE_S)));
        let ok = serde_json::json!({"name": self.name, "ip": ip_str(ip)}).to_string().into_bytes();
        let c = self.clone();
        tokio::spawn(async move {
            send_ctl(&c.node, link, T_AUTH_OK, &ok).await;
            // новому клиенту соседей шлём всегда (0014 R3)
            c.send_nbrs(link);
        });
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

/// Пир доказал свой ключ (identify): оцениваем роль по таблице прав.
fn on_peer_ready(ctx: &Arc<NodeCtx>, link: LinkId, pk: [u8; 64]) {
    if ctx.t13.is_none() { return; }
    if let Some(i) = ctx.links.lock().unwrap().get_mut(&link) { i.peer_pk = Some(pk); }
    ctx.evaluate(link);
}


async fn node_housekeeping(ctx: Arc<NodeCtx>) {
    let mut tick = 0u64;
    let mut lost_listener = 0u32;
    let mut last_ping = Instant::now();
    let mut last_table = Instant::now();
    let fin = ctx.state.join("fin");
    let mut last_wake = Instant::now();
    let mut last_snap = Instant::now();
    while !fin.exists() {
        // Тело цикла (замки, обход соседей) — отдельно от сна: прежняя единая «задержка» смешивала долгое тело (блокировка внутри
        // процесса) с поздним пробуждением (CPU/планировщик) и подписывала всё как «процесс стоял». Конец тела — здесь (у тела есть `continue`).
        let body_end = Instant::now();
        let body = body_end.duration_since(last_wake);
        tokio::time::sleep(Duration::from_millis(500)).await;
        tick += 1;
        let now = Instant::now();
        // Позднее пробуждение: таймер сна 500 мс сработал намного позже — процесс не получал CPU (или стоял на диске).
        let late = now.duration_since(body_end).saturating_sub(Duration::from_millis(500));
        let lag = now.duration_since(last_wake).saturating_sub(Duration::from_millis(500));
        last_wake = now;
        if lag >= Duration::from_secs(3) || (crate::debug() && lag >= Duration::from_secs(1)) {
            ctx.sh.note(format!("главный цикл опоздал на {} мс (пробуждение позже на {} мс, тело цикла {} мс); {}",
                lag.as_millis(), late.as_millis(), body.as_millis(), crate::host_pressure()));
        }
        if crate::debug() && now.duration_since(last_snap) >= Duration::from_secs(10) {
            last_snap = now;
            ctx.debug_snapshot();
        }

        // Тело — синхронные замки (соседи, Link, ядро RNS, перепись интерфейсов). На рабочем потоке tokio их ожидание под нагрузкой
        // останавливало остальные задачи, включая QUIC туннеля (fin1 10.11). `block_in_place` отдаёт эти задачи другому потоку.
        blocking_section(|| {
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
                    nb.qmon.reset();
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

        // неавторизованные Link не живут дольше срока
        let deadline = if ctx.t13.is_some() { Duration::from_secs(30) } else { UNAUTH_TIMEOUT };
        let stale: Vec<LinkId> = ctx.links.lock().unwrap().iter()
            .filter(|(_, l)| !matches!(l.role, Role::Server { .. } | Role::Client { .. }) && now.duration_since(l.since) > deadline).map(|(k, _)| *k).collect();
        for l in stale {
            ctx.close_link(l, "авторизация не завершена вовремя");
        }

        // контакты → адреса соседей (подсказки из `accept`), раз в 10 с
        if tick % 20 == 5 {
            ctx.seed_neighbors();
        }

        // пинги соседям и клиентам-проверка живости
        if now.duration_since(last_ping) >= Duration::from_secs(2) {
            last_ping = now;
            // 0024: на QUIC-носителе живость, RTT и потери берутся из статистики соединения (QUIC PING + аутентифицированный приём),
            // без сообщений Link; без QUIC (TCP-носитель, транзит RNS) - Channel-пинг T_PING/T_PONG раз в 2 с.
            let links: Vec<(LinkId, [u8; 16])> = ctx.links.lock().unwrap().iter().filter_map(|(k, l)| match l.role { Role::Server { dest } => Some((*k, dest)), _ => None }).collect();
            for (l, dest) in links {
                let Some(key) = ctx.neigh.lock().unwrap().get(&dest).filter(|nb| nb.link == Some(l)).map(|nb| nb.key) else { continue };
                // выбор носителя берёт замки мультиплексора: вне замка `neigh`
                let conn = dataplane::plane().carrier_conn(&key);
                let snap = conn.as_ref().map(|c| {
                    let st = c.stats();
                    let rtt = c.paths().iter().find(|p| p.is_selected()).map(|p| (p.rtt().as_secs_f64() * 1000.0 * 100.0).round() / 100.0);
                    (c.stable_id(), st.frame_rx.authenticated_progress(), st.lost_packets, st.udp_tx.datagrams, rtt)
                });
                let mut ping: Option<u64> = None;
                let mut contact = false;
                {
                    let mut n = ctx.neigh.lock().unwrap();
                    let Some(nb) = n.get_mut(&dest) else { continue };
                    match snap {
                        Some((cid, progress, lost, tx, rtt)) => {
                            nb.loss.clear();
                            contact = nb.qmon.tick(cid, progress, lost, tx);
                            if contact {
                                nb.last_heard = Instant::now();
                            }
                            if rtt.is_some() {
                                nb.rtt_ms = rtt;
                            }
                            // монитор качества: потери >= 30% (тихие тики или доля потерянных пакетов QUIC) по окну из 8 тиков (16 с) на QUIC
                            // -> TCP (набирает дозвон этого пира; принимающая сторона следует за ним)
                            if nb.ctl.is_quic() && !nb.ctl.prefer_tcp.load(Relaxed) && nb.admitted_at.elapsed() > Duration::from_secs(6) {
                                if let Some(lo) = nb.qmon.loss() {
                                    if lo >= QMON_LOSS_LIMIT {
                                        ctx.sh.note(format!("{}: потери UDP {:.0}% по статистике QUIC, переключаю носитель на TCP", nb.name, lo * 100.0));
                                        nb.ctl.prefer_tcp.store(true, Relaxed);
                                        nb.ctl.switches.fetch_add(1, Relaxed);
                                        nb.qmon.reset();
                                    }
                                }
                            }
                        }
                        None => {
                            nb.qmon.reset();
                            let nonce = new_ping_nonce();
                            nb.loss.sent(l, nonce);
                            ping = Some(nonce);
                        }
                    }
                }
                if contact {
                    if let Some(info) = ctx.links.lock().unwrap().get_mut(&l) {
                        info.last_heard = Instant::now();
                    }
                }
                match (&conn, ping) {
                    (Some(c), _) => { c.ping(); } // проба запрашивает ACK; контакт засчитывает только приём
                    (None, Some(nonce)) => spawn_ctl(&ctx.node, l, T_PING, nonce.to_le_bytes().to_vec()),
                    _ => {}
                }
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
                        let silent = heard.get(&l).map(|t| now.duration_since(*t).as_millis()).unwrap_or(0);
                        let detail = format!("тишина {silent} мс, носитель {}, смен носителя {}, потери пингов {}, rtt {}, допущен {} с назад",
                            nb.ctl.mode_label(), nb.ctl.switches.load(Relaxed),
                            nb.qmon.loss().or_else(|| nb.loss.loss(None, Duration::from_secs(10), 1)).map(|x| format!("{:.0}%", x * 100.0)).unwrap_or_else(|| "?".into()),
                            nb.rtt_ms.map(|r| format!("{r:.0} мс")).unwrap_or_else(|| "?".into()), nb.admitted_at.elapsed().as_secs());
                        to_close.push((l, nb.name.clone(), detail));
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
        for (l, name, detail) in to_close {
            ctx.sh.note(format!("локальный Link к {name}: нет аутентифицированного приёма дольше {} с, закрываю связь ({detail}); {}", ctx.dead.as_secs(), crate::host_pressure()));
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
                "pn": lxmf_sync::pn_status(), "table": ctx.t13.as_ref().map(|t| { let p = t.peers.lock().unwrap(); serde_json::json!({"peers": p.live().count(), "contacts": p.contact_list().len(), "controllers": p.controllers().len(), "transit": p.config().transit_enabled, "exit": p.config().exit_enabled}) })});
            crate::bgwrite::put(&ctx.state.join("status.json"), st.to_string().into_bytes(), Duration::from_secs(20));
        }
        });
    }
}

/// Синхронный участок с замками внутри async-задачи: на многопоточном рантайме — `block_in_place` (задачи этого рабочего
/// потока переходят к другому), иначе (однопоточный рантайм тестов) — как есть.
fn blocking_section<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
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

fn parse_hash(s: &str) -> Result<[u8; 16]> {
    unhex(s.trim()).try_into().map_err(|_| anyhow::anyhow!("ожидается хеш identity: 32 hex-знака"))
}

/// Нода запущена с этим state, если status.json свежее 60 с: тогда peers.json принадлежит ей и CLI напрямую его не пишет.
fn node_running(state: &Path) -> bool {
    std::fs::metadata(state.join("status.json")).and_then(|m| m.modified()).ok()
        .and_then(|t| t.elapsed().ok()).is_some_and(|e| e < Duration::from_secs(60))
}

/// Команда локального владельца: живое ядро этого процесса, иначе запрос через `state/ctl` работающей ноды.
fn ctl(state: &Path, req: &serde_json::Value) -> Result<serde_json::Value> {
    let v = match invite::lookup(state) {
        Some(core) => core.ctl(req),
        None => ncmd::ctl_call(state, req)?,
    };
    if v["ok"].as_bool() != Some(true) {
        bail!("{}", v["error"].as_str().unwrap_or("отказ"));
    }
    Ok(v)
}

fn write_secret_out(out: &Option<PathBuf>, text: &str) -> Result<()> {
    match out {
        Some(f) => { lxmf_admin::write_private_atomic(f, text.as_bytes())?; eprintln!("записано в {} (0600)", f.display()); }
        None => println!("{text}"),
    }
    Ok(())
}

fn peers_cmd(a: PeersArgs) -> Result<()> {
    let seq = now_ms() as u64;
    let rights = |a: &PeersArgs| -> Result<u16> { peers::parse_rights(a.rights.as_deref().ok_or_else(|| anyhow::anyhow!("нужен --rights"))?) };
    let op = match a.action.as_str() {
        "list" => {
            let v = if a.offline || (!node_running(&a.state) && invite::lookup(&a.state).is_none()) {
                let id = load_identity_strict(&a.state)?;
                peers::Peers::load(id.public_key_bytes(), &a.state)?.status(now_ms() as u64)
            } else { ctl(&a.state, &serde_json::json!({"cmd": "view"}))? };
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(());
        }
        "set" => serde_json::json!({"op": "peer.set", "pk": a.pk.clone().ok_or_else(|| anyhow::anyhow!("нужен --pk"))?, "rights": rights(&a)?, "name": a.name.clone().unwrap_or_default()}),
        "remove" => serde_json::json!({"op": "peer.remove", "hash": a.hash.clone().ok_or_else(|| anyhow::anyhow!("нужен --hash"))?}),
        "revoke-by" => serde_json::json!({"op": "peers.revoke_by", "issuer": a.issuer.clone().ok_or_else(|| anyhow::anyhow!("нужен --issuer"))?}),
        "config" => serde_json::json!({"op": "config.set", "transit_enabled": a.transit, "exit_enabled": a.exit}),
        x => bail!("неизвестное действие {x:?} (set, remove, revoke-by, config, list)"),
    };
    if a.offline {
        // восстановление управления на сервере (ADR §4.4): прямо в peers.json, узел остановлен
        if node_running(&a.state) { bail!("узел работает (status.json свежий): без --offline, через сокет ноды"); }
        let id = load_identity_strict(&a.state)?;
        let mut p = peers::Peers::load(id.public_key_bytes(), &a.state)?;
        let now = now_ms() as u64;
        let r: std::result::Result<String, &'static str> = match op["op"].as_str().unwrap() {
            "peer.set" => { let pk: peers::Pk = unhex(op["pk"].as_str().unwrap()).try_into().map_err(|_| anyhow::anyhow!("--pk: 128 hex"))?;
                p.peer_set(&peers::Actor::Local, pk, rights(&a)?, a.name.as_deref().unwrap_or(""), seq, now).map(|x| format!("{x:?}")) }
            "peer.remove" => p.peer_remove(&peers::Actor::Local, &parse_hash(op["hash"].as_str().unwrap())?, seq, now).map(|x| format!("{x:?}")),
            "peers.revoke_by" => p.revoke_by(&peers::Actor::Local, op["issuer"].as_str().unwrap(), seq, now).map(|n| format!("отозвано {n}")),
            _ => p.set_config(&peers::Actor::Local, a.transit, a.exit).map(|x| format!("{x:?}")),
        };
        match r { Ok(m) => { p.save()?; println!("{m}"); } Err(e) => bail!("отказ: {e}") }
        return Ok(());
    }
    let mut req = serde_json::json!({"cmd": "ops", "ops": [op]});
    if let Some(t) = &a.target { req["target"] = parse_hash(t).map(|h| hex(&h)).map(serde_json::Value::from)?; }
    println!("{}", ctl(&a.state, &req)?);
    Ok(())
}

pub fn run_admin(cmd: VpnCmd) -> Result<()> {
    match cmd {
        VpnCmd::Whoami(a) => {
            std::fs::create_dir_all(&a.state)?;
            let id = load_or_create_identity(&a.state)?;
            let j = serde_json::json!({"hash": hex(id.hash()), "pk": hex(&id.public_key_bytes()), "ip": ip_str(client_ip(id.hash())), "prefix": client_net().1});
            write_atomic(&a.state.join("whoami.json"), j.to_string().as_bytes());
            println!("{j}");
            Ok(())
        }
        VpnCmd::RulesList(a) => route::cmd_list(&a.state),
        VpnCmd::RulesCompile(a) => route::cmd_compile(&a.state),
        VpnCmd::List(a) => { println!("{}", serde_json::to_string_pretty(&ctl(&a.state, &serde_json::json!({"cmd": "view"}))?)?); Ok(()) }
        VpnCmd::Invite(a) => {
            let nodes: Vec<serde_json::Value> = a.nodes.iter().map(|h| Ok(serde_json::json!({"hash": hex(&parse_hash(h)?), "rights": peers::parse_rights(&a.rights)?}))).collect::<Result<_>>()?;
            let v = ctl(&a.state, &serde_json::json!({"cmd": "issue", "nodes": nodes, "rights": peers::parse_rights(&a.rights)?, "ttl_ms": a.ttl_h.clamp(1, 168) * 3600 * 1000}))?;
            write_secret_out(&a.out, v["invite"].as_str().unwrap_or(""))
        }
        VpnCmd::Join(a) => {
            let raw = if a.invite_file == Path::new("-") { use std::io::Read; let mut s = String::new(); std::io::stdin().take(8192).read_to_string(&mut s)?; s }
                else { String::from_utf8(peers::read_private(&a.invite_file, 8192)?.ok_or_else(|| anyhow::anyhow!("нет файла приглашения"))?)? };
            let v = ctl(&a.state, &serde_json::json!({"cmd": "join", "invite": raw.trim()}))?;
            println!("{}", v);
            Ok(())
        }
        VpnCmd::Introduce(a) => {
            let nodes: Vec<String> = a.nodes.iter().map(|h| parse_hash(h).map(|h| hex(&h))).collect::<Result<_>>()?;
            println!("{}", ctl(&a.state, &serde_json::json!({"cmd": "introduce", "nodes": nodes, "rights": peers::parse_rights(&a.rights)?}))?);
            Ok(())
        }
        VpnCmd::Peers(a) => peers_cmd(a),
        _ => bail!("не админ-команда"),
    }
}

/// JNI-мост приложения: `command` — JSON-запрос локального владельца (`Core::ctl`), без оболочки и без argv. Живое ядро процесса;
/// без него доступен только просмотр таблицы с диска. Секреты (строка приглашения) проходят только через память.
pub fn run_cli_json(command: &str, state_dir: &str) -> String {
    let fail = |why: &str| serde_json::json!({"ok": false, "error": why}).to_string();
    if command.len() > 64 * 1024 || state_dir.len() > 4096 || state_dir.bytes().any(|b| !(b.is_ascii_alphanumeric() || b"/._-".contains(&b))) {
        return fail("invalid_input");
    }
    let Ok(req) = serde_json::from_str::<serde_json::Value>(command) else { return fail("invalid_json") };
    let state = Path::new(state_dir);
    if req["cmd"].as_str() == Some("init") {
        // ключ создаётся при первом запуске приложения, а не при включении «Сети»; идемпотентно, работает и при живой ноде
        return init_identity(state).unwrap_or_else(|e| fail(&format!("{e:#}")));
    }
    if let Some(core) = invite::lookup(state) {
        return core.ctl(&req).to_string();
    }
    if req["cmd"].as_str() == Some("join") {
        // «Сеть» выключена: пары дописываются в pending-invite.json, нода погасит их при запуске (на живую ноду пишет Core::join)
        return offline_join(state, &req).unwrap_or_else(|e| fail(&format!("{e:#}")));
    }
    if req["cmd"].as_str() == Some("issue") {
        // «Сеть» выключена: выпустить можно всегда, но только на себе (чужим нодам «ожидай» уходит по LXMF, для этого нужна работающая нода)
        return offline_issue(state, &req).unwrap_or_else(|e| fail(&format!("{e:#}")));
    }
    if req["cmd"].as_str() == Some("view") {
        return match load_identity_strict(state).and_then(|id| peers::Peers::load(id.public_key_bytes(), state)) {
            Ok(p) => { let mut v = p.status(now_ms() as u64); v["pending"] = invite::pending_view_offline(state); v["ok"] = true.into(); v["offline"] = true.into(); v.to_string() }
            Err(e) => fail(&format!("{e:#}")),
        };
    }
    fail("нода не запущена")
}

/// Создать ключ ноды (если его ещё нет) и записать `whoami.json`; вызывается приложением при каждом запуске.
fn init_identity(state: &Path) -> Result<String> {
    std::fs::create_dir_all(state)?;
    let id = load_or_create_identity(state)?;
    let j = serde_json::json!({"hash": hex(id.hash()), "pk": hex(&id.public_key_bytes()), "ip": ip_str(client_ip(id.hash())), "prefix": client_net().1});
    write_atomic(&state.join("whoami.json"), j.to_string().as_bytes());
    Ok(serde_json::json!({"ok": true, "hash": hex(id.hash())}).to_string())
}

/// Вступление без запущенной ноды: дописать пары в `pending-invite.json` (0600). Ключ ноды должен уже существовать (`init`).
fn offline_join(state: &Path, req: &serde_json::Value) -> Result<String> {
    let id = load_identity_strict(state)?;
    let me = peers::hash_of(&id.public_key_bytes()).context("identity")?;
    let (hs, added) = invite::join_offline(state, &me, req["invite"].as_str().unwrap_or(""))?;
    Ok(serde_json::json!({"ok": true, "offline": true, "added": added, "nodes": hs.iter().map(|h| hex(h)).collect::<Vec<_>>()}).to_string())
}

/// Выпуск приглашения на себе без запущенной ноды (приложение при выключенной «Сети»): пин пишется в `peers.json` этой ноды, строка
/// возвращается вызывающему. Получатель сможет погасить его, когда нода будет запущена. Другие ноды в стопке - отказ.
fn offline_issue(state: &Path, req: &serde_json::Value) -> Result<String> {
    let id = load_identity_strict(state)?;
    let me = peers::hash_of(&id.public_key_bytes()).context("identity")?;
    let grants: Vec<(peers::Hash, u16)> = match req["nodes"].as_array() {
        Some(a) if !a.is_empty() => a.iter().map(|g| Ok((unhex(g["hash"].as_str().unwrap_or("")).try_into().map_err(|_| anyhow::anyhow!("nodes[]: hash"))?,
            g["rights"].as_u64().context("nodes[]: rights")? as u16))).collect::<Result<_>>()?,
        _ => vec![(me, req["rights"].as_u64().unwrap_or(peers::USE as u64) as u16)],
    };
    if grants.len() != 1 || grants[0].0 != me {
        bail!("нода не запущена: включите «Сеть», чтобы выпустить приглашение на другие ноды");
    }
    let ttl = req["ttl_ms"].as_u64().unwrap_or(peers::INVITE_DEFAULT_MS);
    let mut pin = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut pin);
    let mut p = peers::Peers::load(id.public_key_bytes(), state)?;
    p.invite_add(&peers::Actor::Local, peers::pin_id(&pin), peers::pin_key(&pin), grants[0].1, ttl, now_ms() as u64).map_err(|e| anyhow::anyhow!("приглашение не выпущено: {e}"))?;
    p.save()?;
    let s = invite::encode(&[(me, pin)])?;
    Ok(serde_json::json!({"ok": true, "invite": s, "requests": [], "offline": true}).to_string())
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
    /// таблица прав клиента (ADR 0028): управляющие, контакты с подсказками адресов и ролями нод
    peers: Arc<Mutex<peers::Peers>>,
    /// единое ядро приглашений и команд (то же, что у сервера)
    core: Arc<invite::Core>,
    /// публичный ключ собеседника на Link (клиент сам его выбирает при дозвоне)
    link_pk: Mutex<HashMap<LinkId, [u8; 64]>>,
    /// подсказки REALITY выходов (dest -> `rl`), `hints-rl.json` в state: нужны, когда UDP и TCP к выходу уже закрыты
    rl_hints: Mutex<HashMap<String, reality_carrier::RealityHint>>,
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
    /// Проба выхода (гейт допуска) только после AUTH_OK и проверки EXIT: Link -> случайный nonce T_PING и ответ.
    data_wait: Mutex<HashMap<LinkId, (u64, tokio::sync::oneshot::Sender<()>)>>,
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
    /// имена узлов (dest -> имя) от них самих по допущенному Link, от выхода про его соседей и из каталога; хранятся в state/names.json
    names: Mutex<HashMap<[u8; 16], String>>,
    /// адреса выходов для диалеров (dest -> общее хранилище): анонс обновляет, диалер читает на каждой попытке (0014 R4)
    books: Mutex<HashMap<[u8; 16], Arc<Addrs>>>,
    /// отправленные Channel-пинги текущего и дополнительных выходов (Link в записи)
    loss: Mutex<PingBook>,
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

/// Статус P2P описывает выбранный путь QUIC, а не просто наличие соединения:
/// открытый QUIC может идти через mesh, relay или REALITY.
fn p2p_state(info: Option<&serde_json::Value>, has_addr: bool, dead: bool, misses: u32) -> &'static str {
    if let Some(info) = info {
        match info["kind"].as_str() {
            Some("direct") => "direct",
            Some("mesh") => "mesh",
            Some("relay") => "relay",
            Some("reality") => "reality",
            _ => "trying", // соединение есть, но путь ещё не выбран
        }
    } else if !has_addr {
        "no_addr"
    } else if dead || misses >= 2 {
        "unreachable"
    } else {
        "trying"
    }
}

impl ClientCtx {
    fn native_rtt(&self, id: &LinkId) -> Option<f64> {
        let ka = self.node.engine().with_link(id, |l| l.keepalive_rtt_ms()).flatten();
        let s = self.node.engine().link_stats(id)?;
        ka.map(|r| r as f64).or(s.srtt_ms()).or_else(|| s.rtt_ms().map(|r| r as f64))
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

    /// Состояние связи с контактами без ролей. `state`: `direct`, `mesh`, `relay`, `reality` (выбранный путь QUIC), `no_addr` (адреса нет ни у нас,
    /// ни от контакта), `unreachable` (набор не удался ≥2 раз подряд или нода признана мёртвой),
    /// `trying` (первые попытки). `exit` - у контакта есть EXIT (тогда он годится выходом и виден в `exits`).
    fn p2p_json(&self, servers: &[CServer]) -> serde_json::Value {
        let Some(c) = &self.c13 else { return serde_json::Value::Array(vec![]) };
        let tr = c.peers.lock().unwrap();
        let books = self.books.lock().unwrap();
        let carriers = self.carriers.lock().unwrap();
        let out: Vec<serde_json::Value> = servers.iter().filter_map(|e| {
            let pk = e.pk?;
            let key = peers::key_of(&pk);
            if tr.roles_of_key(&key) & (peers::EXIT | peers::TRANSIT) != 0 {
                return None;
            }
            let h = peers::hash_of(&pk)?;
            let info = dataplane::plane().carrier_conn(&e.key).map(|conn| mesh::path_json(&conn, None));
            let has_addr = !e.addrs.is_empty() || books.get(&e.dest).is_some_and(|b| !b.is_empty());
            let ctl = carriers.get(&e.dest);
            let (misses, dead) = ctl.map_or((0, false), |x| (x.misses.load(Relaxed), x.dead.load(Relaxed)));
            let state = p2p_state(info.as_ref(), has_addr, dead, misses);
            let rtt = info.as_ref().and_then(|i| i["rtt_ms"].as_f64());
            let name = tr.contact(&h).map(|x| x.name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| self.shown_name(e));
            Some(serde_json::json!({"d": hex(&e.dest), "id": hex(&h), "n": name, "state": state, "rtt_ms": rtt, "path": info.as_ref().and_then(|i| i["path_desc"].as_str().map(String::from)), "lan": info.as_ref().is_some_and(|i| i["lan"].as_bool() == Some(true)),
                "misses": misses, "they_grant": tr.contact(&h).map_or(0, |x| x.they_grant), "exit": false}))
        }).collect();
        serde_json::Value::Array(out)
    }

    /// Общее хранилище адресов выхода для диалера (создаётся по требованию).
    fn book_for(&self, dest: &[u8; 16]) -> Arc<Addrs> {
        self.books.lock().unwrap().entry(*dest).or_insert_with(|| Addrs::new(vec![])).clone()
    }

    /// Выходы 0013 строятся из записей, а не из профиля: держатели с EXIT, у которых общий с нами корень, и админ ожидающего приглашения.
    /// Адреса приходят только подсказками (приглашение, анонс).
    /// Единственное место, где узел получает имя: от самого узла (T_AUTH_OK), от выхода про его соседей (T_NBRS) или из каталога.
    /// Побеждает последнее; имя нормализуется `norm_name` и хранится в state/names.json (не больше 64). Вызывать только для узла, чьи права проверены.
    fn set_name(&self, dest: [u8; 16], name: &str) {
        let Some(n) = norm_name(name) else { return };
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

    /// Имя для интерфейса: известное имя узла, иначе то, что в записи (в ней может быть только короткий dest).
    fn shown_name(&self, e: &CServer) -> String {
        self.names.lock().unwrap().get(&e.dest).cloned().unwrap_or_else(|| e.name.clone())
    }

    fn refresh_servers13(&self) {
        let Some(c) = &self.c13 else { return };
        let mut want: Vec<([u8; 64], Vec<String>, String)> = Vec::new();
        {
            let tr = c.peers.lock().unwrap();
            // подсказки REALITY из accept: нужны, когда UDP и TCP к выходу уже закрыты
            {
                let mut rl = c.rl_hints.lock().unwrap();
                for x in tr.contact_list() {
                    if let Some(h) = reality_carrier::RealityHint::from_json(&x.rl) {
                        if rl.len() < 64 || rl.contains_key(&hex(&dest_from_pub_tag(&x.pk, T13_TAG))) { rl.insert(hex(&dest_from_pub_tag(&x.pk, T13_TAG)), h); }
                    }
                }
            }
            // в списке нод: контакты с ролью EXIT (выходы) или TRANSIT (носители/транзит для mesh), разрешающие мне USE, из доверенного источника
            // (приглашение, локальный владелец или контроллер). Выходом годятся только EXIT (`exit_eligible`); допуск решает сам выход (ADR 0028 §3.2)
            // P2P (без серверов): контакт, разрешающий мне USE, либо мой знакомый, которому разрешено USE на мне (выдавший приглашение
            // и получатель), набирается как обычный пир и без ролей. Выходом он от этого не становится: `exit_eligible` требует роль EXIT.
            for c in tr.contact_list() {
                if c.pk != tr.me_pk && !want.iter().any(|w| w.0 == c.pk) && trusted_intro(&c) && (c.they_grant & peers::USE != 0 || tr.rights_pk(&c.pk) != 0) {
                    want.push((c.pk, c.hints.clone(), c.name.clone()));
                }
            }
        }
        let mut s = self.servers.lock().unwrap();
        let keep: HashSet<[u8; 64]> = want.iter().map(|w| w.0).collect();
        s.retain(|e| e.pk.map(|p| keep.contains(&p)).unwrap_or(true));
        for (pk, addrs, contact_name) in want {
            let dest = dest_from_pub_tag(&pk, T13_TAG);
            if dest == [0u8; 16] {
                continue;
            }
            let key: [u8; 32] = pk[32..64].try_into().unwrap();
            let addrs: Vec<String> = peers::balance_hints(addrs.into_iter().filter(|a| sane_hint_addr_lan(a)).collect(), peers::MAX_CONTACT_HINTS);
            if let Some(e) = s.iter_mut().find(|e| e.dest == dest) {
                e.pk = Some(pk);
                // имя, сохранённое с прошлого допуска: пока узел не отвечал в этой сессии, в записи только короткий dest
                if e.name == "?" || e.name == hex(&dest)[..8] {
                    let known = self.names.lock().unwrap().get(&dest).cloned();
                    e.name = known.unwrap_or_else(|| contact_name_or_dest(&contact_name, &dest));
                }
                if !addrs.is_empty() && e.addrs != addrs {
                    // новые подсказки (сообщение `addr` или повторный accept): диалер читает их на каждой попытке, смена его будит
                    e.addrs = addrs.clone();
                    self.book_for(&dest).set(addrs);
                }
            } else if s.len() < 32 {
                let name = self.names.lock().unwrap().get(&dest).cloned().unwrap_or_else(|| contact_name_or_dest(&contact_name, &dest));
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
        // P2P-контакты (без ролей EXIT/TRANSIT): честное состояние прямого соединения, а не вечное «подключаюсь»
        let p2p = self.p2p_json(&servers);
        // в интерфейсе видны только ноды, которых я знаю как контакт (приглашение, знакомство) и которые сами объявили роль выхода/транзита
        if let Some(c) = &self.c13 {
            let tr = c.peers.lock().unwrap();
            servers.retain(|e| e.pk.is_some_and(|pk| tr.roles_of_key(&peers::key_of(&pk)) & (peers::EXIT | peers::TRANSIT) != 0));
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
            // id - identity-хеш ноды; adm - я управляю этой нодой (от неё есть status.push: она держит меня в CONFIG)
            let (id, adm) = match (&self.c13, e.pk.as_ref().and_then(peers::hash_of)) {
                (Some(c), Some(h)) => (Some(hex(&h)), c.core.manages(&h)),
                _ => (None, false),
            };
            // vis (R8): direct - путь 1 хоп через мой носитель к этой ноде; via - путь через носитель другой ноды (nh); none - пути нет.
            // Для текущего выхода интерфейс берётся у его Link, иначе - из таблицы путей
            let ifc = cur.filter(|c| c.0 == e.dest).and_then(|c| self.node.engine().with_link(&c.1, |l| l.attached_interface()).flatten())
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
            serde_json::json!({"n": self.shown_name(e), "d": hex(&e.dest), "h": hops.or(e.hops), "r": e.rtt_ms, "s": if is_cur { "current" } else { e.state.as_str() }, "pinned": e.pinned, "presence": presence,
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
        let mut quic_via_dest = None;
        let quic_info = cur.and_then(|c| {
            servers.iter().find(|e| e.dest == c.0).and_then(|e| {
                dataplane::plane().carrier_conn(&e.key).map(|conn| {
                    let hop = mesh::global().and_then(|m| m.hop_peer(&e.key));
                    let info = mesh::path_json(&conn, hop);
                    if info["kind"] == "mesh" {
                        // UI indexes nodes by full RNS destination, not a prefix of the QUIC key.
                        quic_via_dest = hop.and_then(|key| servers.iter().find(|s| s.key == key).map(|s| hex(&s.dest)));
                    }
                    info
                })
            })
        });
        let via: Option<String> = if quic_info.is_some() {
            quic_via_dest
        } else {
            cur.and_then(|c| {
                let ifc = self.node.engine().with_link(&c.1, |l| l.attached_interface())??;
                let name = self.node.engine().interface_stats().iter().find(|i| i.interface_id.0 == ifc)?.name.clone();
                let label = name.strip_prefix("iroh-dg-out-").or_else(|| name.strip_prefix("tcp-out-"))?.rsplit_once('-')?.0.to_string();
                let dest_of = self.carriers.lock().unwrap().iter().find(|(_, x)| *x.label.lock().unwrap() == label).map(|(d, _)| *d)?;
                if dest_of == c.0 { None } else { Some(hex(&dest_of)) }
            })
        };
        let rtt = if let Some(ref q) = quic_info {
            q["rtt_ms"].as_f64().or(*self.rtt_ms.lock().unwrap())
        } else {
            *self.rtt_ms.lock().unwrap()
        };
        let path_desc = quic_info.as_ref().and_then(|q| q["path_desc"].as_str().map(String::from));
        let j = serde_json::json!({"state": state, "ip": self.ip, "up_s": up_since.elapsed().as_secs(),
            "current": cur.map(|c| serde_json::json!({"d": hex(&c.0), "n": servers.iter().find(|e| e.dest == c.0).map(|e| e.name.clone()), "since_s": c.2.elapsed().as_secs(),
                "rtt_ms": rtt, "hops": self.node.hops_to(&DestinationHash::new(c.0)),
                "carrier": self.carriers.lock().unwrap().get(&c.0).map(|x| *x.mode.lock().unwrap()), "via": via,
                "path_desc": path_desc,
                "quic": quic_info})),
            "log_tail": self.sh.log.lock().unwrap().iter().rev().take(25).map(|(t, m)| format!("{} {}", *t as u64, m)).collect::<Vec<_>>(),
            "selected": std::fs::read_to_string(self.state.join("select")).unwrap_or_default().trim().to_string(),
            "routing": self.routing_json(&servers),
            "exits": exits, "p2p": p2p, "edges": edges, "tun": self.tun.stats(), "udp": udp_stats(), "failovers": self.failovers.lock().unwrap().clone(), "status": self.status.lock().unwrap().clone(),
            "ts_ms": now_ms() as u64});
        // раз в секунду читает интерфейс приложения: частота прежняя, но запись не в async-задаче
        crate::bgwrite::put(&self.state.join("status.json"), j.to_string().into_bytes(), Duration::ZERO);
    }
}

pub async fn run_client13(a: ClientArgs) -> Result<()> {
    if std::env::var("KNOTHOP_DEBUG").is_ok() { crate::set_debug(true); }
    std::fs::create_dir_all(&a.state)?;
    let id = load_or_create_identity(&a.state)?;
    let my_pk = id.public_key_bytes();
    let table = Arc::new(Mutex::new(peers::Peers::load(my_pk, &a.state).context("peers.json")?));
    let ctx_cell: Arc<std::sync::OnceLock<std::sync::Weak<ClientCtx>>> = Arc::new(std::sync::OnceLock::new());
    // Адреса клиента для `accept`/`ack`/`addr` (P2P): глобальные IPv4 и IPv6 интерфейсов с портами сокетов iroh (у v4 и v6 они разные).
    // Порты известны после старта endpoint; до тех пор подсказок нет. Частные адреса - только в явно включённой лаборатории.
    // Только шифрованный LXMF к контакту, в анонс RNS они не попадают.
    let own_ports: Arc<std::sync::OnceLock<(u16, u16, String)>> = Arc::new(std::sync::OnceLock::new());
    let core = {
        let (c1, c2) = (ctx_cell.clone(), ctx_cell.clone());
        let ports = own_ports.clone();
        let hints_fn: Box<dyn Fn() -> Vec<String> + Send + Sync> = Box::new(move || match ports.get() {
            Some((p4, p6, tun)) => local_addrs_ports(*p4, *p6, std::env::var("KNOTHOP_ALLOW_PRIVATE_DIAL").is_ok(), tun, true),
            None => vec![],
        });
        // телефон: права управления выдавшему принимаются только после явного согласия пользователя (ADR 0028 §2.4)
        invite::Core::new(&a.state, id.clone(), table.clone(), true, hints_fn,
            Box::new(move || { if let Some(c) = c1.get().and_then(|w| w.upgrade()) { c.refresh_servers13(); start_dialers(&c); } }),
            Box::new(move |m| { if let Some(c) = c2.get().and_then(|w| w.upgrade()) { c.sh.note(m); } }))?
    };
    if let Some(f) = &a.invite_file {
        // «Вступить» в приложении: пары переходят в приватный pending-invite.json, исходный файл со строкой стирается сразу
        match peers::read_private(f, 8192) {
            Ok(Some(b)) if !String::from_utf8_lossy(&b).trim().is_empty() => {
                match core.join(&String::from_utf8_lossy(&b)) {
                    Ok(hs) => eprintln!("Приглашение принято к исполнению: нод {}", hs.len()),
                    Err(e) => eprintln!("Приглашение отклонено: {e:#}"),
                }
                let _ = std::fs::remove_file(f);
            }
            Ok(_) => {}
            Err(e) => eprintln!("invite-file {}: {e:#}", f.display()),
        }
    }
    let c13 = Some(C13 { peers: table, core, link_pk: Mutex::new(HashMap::new()), rl_hints: Mutex::new(load_rl_hints(&a.state)) });
    let identity = id;
    let tun_arg = a.tun_fd.to_string();
    // без дескриптора от VpnService (лаборатория, Linux) TUN создаётся самим процессом и получает адрес, выведенный из identity
    let tun_ip = format!("{}/{}", ip_str(client_ip(identity.hash())), client_net().1);
    let mut extra: Vec<&str> = vec!["--tun-fd", &tun_arg, "--tun-mtu", "1327", "--path-keepalive-ms", "4000", "--conn-idle-ms", "12000"];
    if a.tun_fd < 0 {
        extra.extend(["--tun-ip", &tun_ip]);
    }
    // EndpointId клиента всегда = ключ подписи identity: по нему выход сопоставляет QUIC-носитель с допущенным Link (dataplane, 0023), и relay
    // отличает допущенного от чужого. Случайный ключ здесь = датаграммы VPN клиента отбрасываются выходом как непривязанные (ошибка hop alpha 30.10).
    let relays = parse_relay_urls(&a.relay_url);
    let ep_key = iroh_key_from_identity(&identity)?;
    let b = start_base("c", &a.state, false, None, ep_key, Some(identity.clone()), a.quic_cc_mbit, &extra, None, &relays).await?;
    let (node, sh, ep, cli, events, admin_lxmf) = (b.node.clone(), b.sh.clone(), b.ep.clone(), b.cli.clone(), b.events, b.admin_lxmf);
    if let Some(c) = &c13 { install_mesh_policy(&node, &c.peers, true); }
    let (p4, p6) = endpoint_ports(&ep);
    let _ = own_ports.set((p4, p6, cli.tun_name.clone()));
    sh.note(format!("слушаю UDP (iroh): {:?}", ep.bound_sockets()));
    if let Some(c) = &c13 {
        // P2P: входящий QUIC принимают и клиенты, но только от ключей, известных таблице (контакт или запись `peers`); остальные закрываются сразу после TLS
        let t = c.peers.clone();
        tokio::spawn(accept_loop_with(ep.clone(), node.clone(), sh.clone(), Some(Arc::new(move |k: &[u8; 32]| t.lock().unwrap().knows_key(k)))));
    }
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
        carriers: Mutex::new(HashMap::new()), public_ids: Mutex::new(Vec::new()), names: Mutex::new(load_names(&a.state)), books: Mutex::new(HashMap::new()), loss: Mutex::new(PingBook::with_cap(64)), fail_ms: a.fail_ms,
        c13, path_gate: path::PathGate::default(), nbrs: Mutex::new(HashMap::new()), admitted_exits: Mutex::new(HashMap::new()), ctrl: Mutex::new(HashMap::new()), lk_fail: Mutex::new(HashMap::new()), vis: Mutex::new(HashMap::new()), qstat: Mutex::new(HashMap::new()),
         rcfg: std::sync::RwLock::new(Arc::new(route::Cfg::default())), rreport: Mutex::new(serde_json::Value::Null), rpending: Mutex::new(HashSet::new()), rback: Mutex::new(HashMap::new()) });
    {
        let weak = Arc::downgrade(&ctx);
        dataplane::plane().set_sink(Arc::new(move |link, pkt| {
            if let Some(ctx) = weak.upgrade() { client_direct_packet(&ctx, link, pkt); }
        }));
    }
    let _admin_client_guard = if let (Some(runtime), Some(c13)) = (admin_lxmf, ctx.c13.as_ref()) {
        let _ = ctx_cell.set(Arc::downgrade(&ctx));
        invite::register(&c13.core);
        runtime.pn.set_source(c13.peers.clone());
        let sync_guard = lxmf_sync::register(&a.state, runtime.sync.clone());
        if let Err(e) = lxmf_admin::spawn_worker(runtime, c13.core.clone()) { sh.note(format!("не удалось запустить LXMF-воркер: {e}")); }
        Some(sync_guard)
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
        let note = {
            let c = ctx.c13.as_ref().unwrap();
            let p = c.peers.lock().unwrap();
            format!("модель 0028: записей {}, контактов {}{}", p.peer_list().len(), p.contact_list().len(), if c.core.has_pending() { ", вступаю по приглашению" } else { "" })
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
                    let due = lease.due_ifaces(&[own], Instant::now());
                    if !due.is_empty() {
                        let _ = c2.node.engine().request_path_on(&dh, &due).await;
                        asked.insert(sv.dest, Instant::now());
                    }
                }
            }
        });
    }
    // Android sends the existing ConnectivityManager event through JNI. CLI retains its file hook.
    {
        let (ep2, f, c_net) = (ep.clone(), a.state.join("netchange"), ctx.clone());
        tokio::spawn(async move {
            let mut changes = crate::mobile::network_changes();
            loop {
                let event = if cfg!(target_os = "android") {
                    changes.changed().await.is_ok()
                } else {
                    tokio::select! {
                        _ = changes.changed() => true,
                        _ = tokio::time::sleep(Duration::from_millis(500)) => f.exists(),
                    }
                };
                if event {
                    changes.borrow_and_update();
                    if !cfg!(target_os = "android") {
                        let _ = std::fs::remove_file(&f);
                    }
                    sh.health.reset_all();
                    for ctl in c_net.carriers.lock().unwrap().values() {
                        ctl.prefer_tcp.store(false, Relaxed);
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
                ctx.set_name(dest, n);
            }
            // клиент выхода с правами узла (телефон-админ): только имя, не ребро соседства
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



/// (а, 0014 R6) Админ без приглашения (телефон или зачисленный клиент) анонсирует тег своего корня без адресов: нода, ждущая зачисления,
/// видит, что админ на связи, и просится через посредника. При старте, через 20 с, затем раз в 600 с (инвариант 8).
/// Входящие Link на этот destination не принимаются (set_accepts_links(false)): он нужен только для анонса.
async fn client_announce(ctx: Arc<ClientCtx>, dest: [u8; 16]) {
    if ctx.c13.is_none() { return; }
    let mut wait = [Duration::ZERO, Duration::from_secs(20)].into_iter().chain(std::iter::repeat(Duration::from_secs(600)));
    let mut kicks = crate::mobile::kick_rx(crate::mobile::KICK_ANNOUNCE);
    kicks.borrow_and_update();
    let mut last: Option<Instant> = None;
    while let Some(d) = wait.next() {
        // Просьба пользователя будит раньше срока, но не чаще раза в 30 с: штатный период анонса (600 с) остаётся прежним.
        let manual = tokio::select! { _ = tokio::time::sleep(d) => false, r = kicks.changed() => r.is_ok() };
        if manual && last.is_some_and(|t| t.elapsed() < Duration::from_secs(30)) { continue; }
        last = Some(Instant::now());
        // This destination exists only to publish the admin anchor for discovery; it rejects incoming Links.
        let data = serde_json::json!({"lc": false});
        let _ = ctx.node.announce(&DestinationHash::new(dest), Some(data.to_string().as_bytes())).await;
    }
}

fn start_dialer(ctx: &Arc<ClientCtx>, s: &CServer) {
    if ctx.dialers.lock().unwrap().contains_key(&s.dest) {
        return;
    }
    let book = ctx.book_for(&s.dest);
    if !s.addrs.is_empty() {
        book.set(s.addrs.clone());
    }
    if let Some(h) = ctx.c13.as_ref().and_then(|c| c.rl_hints.lock().unwrap().get(&hex(&s.dest)).cloned()) {
        book.rl_fill(&Some(h));
    }
    let (Ok(id), false) = (s.ep.parse::<EndpointId>(), book.is_empty()) else { return };
    let alive = Arc::new(AtomicBool::new(true));
    ctx.dialers.lock().unwrap().insert(s.dest, alive.clone());
    let cc = CarrierCtl::new();
    *cc.label.lock().unwrap() = s.name.clone();
    ctx.carriers.lock().unwrap().insert(s.dest, cc.clone());
    // контакт без ролей (P2P): после DEAD_AFTER промахов не долбим его каждые 2 с, а перепроверяем реже и при новых адресах (`Liveness`)
    let p2p = is_p2p_server(ctx, s);
    tokio::spawn(dial_direct(ctx.ep.clone(), ctx.node.clone(), ctx.sh.clone(), s.name.clone(), id, book, alive, cc, p2p));
}

/// Запись списка нод - обычный пир (P2P): у контакта нет объявленных ролей EXIT/TRANSIT.
fn is_p2p_server(ctx: &ClientCtx, s: &CServer) -> bool {
    match (&ctx.c13, &s.pk) {
        (Some(c), Some(pk)) => c.peers.lock().unwrap().roles_of_key(&peers::key_of(pk)) & (peers::EXIT | peers::TRANSIT) == 0,
        _ => false,
    }
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
                let addrs: Vec<String> = v["a"].as_array().map(|a| peers::balance_hints(a.iter().filter_map(|x| x.as_str().map(String::from)).collect(), peers::MAX_HINTS)).unwrap_or_default();
                let name: Option<String> = v["n"].as_str().and_then(norm_name);
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
            NodeEvent::LinkEstablished { link_id, .. } => {
                ctx.sh.established.lock().unwrap().insert(hex(link_id.as_bytes()));
            }
            NodeEvent::LinkClosed { link_id, reason, .. } => {
                dataplane::plane().unbind(&link_id);
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
                    T_PONG => on_pong_client(&ctx, link_id, body),
                    _ => {}
                }
            }
            NodeEvent::LinkDataReceived { link_id, data, .. } => {
                let cur = ctx.cur.lock().unwrap().map(|c| c.1);
                if cur == Some(link_id) {
                    ctx.last_pong.store(now_ms() as u64, Relaxed); // любой пакет от выхода - признак жизни
                    ctx.tun.on_link_packet(&ctx.node, link_id, &data);
                } else if ctx.tun.routing.load(Relaxed) {
                    let x = ctx.tun.extra.read().unwrap().values().find(|x| x.id == link_id).cloned();
                    if let Some(x) = x {
                        x.last_rx_ms.store(now_ms() as u64, Relaxed);
                        ctx.tun.on_extra_packet(&data);
                    }
                }
            }
            _ => {}
        }
    }
}

/// T_PONG выхода (клиент). Принимается только ответ с nonce, отправленным именно на этот Link: гейт допуска (`connect_exit`) либо Channel-пинг
/// пейсера (текущий или дополнительный выход). Повтор, чужой nonce и ответ другого Link отвергаются.
fn on_pong_client(ctx: &ClientCtx, link: LinkId, body: &[u8]) {
    let Some(nonce) = parse_ping_nonce(body) else { return };
    {
        let mut pending = ctx.data_wait.lock().unwrap();
        if pending.get(&link).is_some_and(|(n, _)| *n == nonce) {
            if let Some((_, tx)) = pending.remove(&link) {
                let _ = tx.send(());
            }
            return;
        }
    }
    let Some(rtt) = ctx.loss.lock().unwrap().ack(link, nonce) else { return };
    let cur = ctx.cur.lock().unwrap().map(|c| c.1);
    if cur == Some(link) {
        ctx.last_pong.store(now_ms() as u64, Relaxed);
        *ctx.rtt_ms.lock().unwrap() = Some(rtt.as_secs_f64() * 1000.0);
        ctx.rtt_pong.store(now_ms() as u64, Relaxed);
    } else if ctx.tun.routing.load(Relaxed) {
        let x = ctx.tun.extra.read().unwrap().values().find(|x| x.id == link).cloned();
        if let Some(x) = x {
            x.last_rx_ms.store(now_ms() as u64, Relaxed);
        }
    }
}

/// IP-пакет из прямого канала (`dataplane`) от выхода, к ключу которого привязан `link_id`: тот же разбор, что у пакета из этого Link
/// (`NodeEvent::LinkDataReceived` выше). Пакеты Link, не являющегося ни текущим, ни дополнительным выходом, отбрасываются.
fn client_direct_packet(ctx: &ClientCtx, link_id: LinkId, data: &[u8]) {
    let cur = ctx.cur.lock().unwrap().map(|c| c.1);
    if cur == Some(link_id) {
        ctx.last_pong.store(now_ms() as u64, Relaxed);
        ctx.tun.on_link_packet(&ctx.node, link_id, data);
    } else if ctx.tun.routing.load(Relaxed) {
        let x = ctx.tun.extra.read().unwrap().values().find(|x| x.id == link_id).cloned();
        if let Some(x) = x {
            x.last_rx_ms.store(now_ms() as u64, Relaxed);
            ctx.tun.on_extra_packet(data);
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
/// 2) если к пиру есть наш носитель, но прямой путь ещё не найден - кратко ждём его, запрашивая путь через все свои носители;
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
            // Один rate-limited запрос на каждый наш носитель: вновь подключившиеся
            // соседи опрашиваются сразу, не дожидаясь истечения 20 с от первого.
            let ifs = path::discovery_ifaces(&ours, avoid);
            let due = p.due_ifaces(&ifs, now);
            if !due.is_empty() {
                let _ = node.engine().request_path_on(dest, &due).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    any_our_path(node, dest, &ours_now(), avoid)
}

/// Один владелец discovery, не более одного scoped forced-запроса на интерфейс за 20 с.
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
            let due = p.due_ifaces(&ifs, Instant::now());
            if !due.is_empty() {
                let _ = node.engine().request_path_on(dest, &due).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Путь до узла и установленный Link (без identify).
async fn open_link(ctx: &Arc<ClientCtx>, cand: &CServer, avoid_iface: Option<usize>, establish_s: u64) -> Result<(LinkId, Arc<leviculum_std::LinkHandle>)> {
    open_link_wait(ctx, cand, avoid_iface, establish_s, leviculum_std::api::LinkCipher::Gcm).await
}

async fn open_link_wait(ctx: &Arc<ClientCtx>, cand: &CServer, avoid_iface: Option<usize>, est_s: u64, cipher: leviculum_std::api::LinkCipher) -> Result<(LinkId, Arc<leviculum_std::LinkHandle>)> {
    let dest = DestinationHash::new(cand.dest);
    // CBC-Link (стоковые транспорты) годится только для служебного LXMF. GCM открывается только по нашим носителям.
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
                // прямого носителя нет: сквозное mesh-QUIC к выходу (mesh_first) — тоже наш носитель, путь 1 хоп по нему
                out_carrier_iface(&ctx.node, &label).or_else(|| out_carrier_iface(&ctx.node, &mesh_label(&cand.key)))
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
        ctx.sh.note(format!("путь к {}: промежуточных нод RNS {}, интерфейс {}, транспорт {}", cand.name, p.hops.saturating_sub(1), iface,
            p.next_hop.map(|h| hex(&h)[..8].to_string()).unwrap_or_else(|| "—".into())));
    }
    let handle = ctx.node.connect_with_key_cipher(&dest, &cand.key, cipher).await?;
    let id = *handle.link_id();
    let k = hex(id.as_bytes());
    // Only an opaque, truncated Link identifier: no identity, address or packet
    // contents. Correlates this attempt with the responder's Link event without
    // treating an opened carrier as proof of an established Link.
    ctx.sh.note(format!("Link попытка {}: запрос передан RNS", &k[..8]));
    let t = Instant::now();
    while !ctx.sh.established.lock().unwrap().contains(&k) {
        if ctx.sh.closed.lock().unwrap().contains_key(&k) || t.elapsed() > Duration::from_secs(est_s) {
            let _ = ctx.node.engine().close_link(&id).await;
            let why = format!("link до {} не установился ({})", cand.name, &k[..8]);
            return Err(match used_iface {
                Some(iface) => anyhow::Error::new(path::FailedPath { iface, why }),
                None => anyhow::anyhow!(why),
            });
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    ctx.sh.note(format!("Link попытка {}: установлен за {} мс", &k[..8], t.elapsed().as_millis()));
    // Проверка attached interface закрывает гонку изменения таблицы во время connect. У инициатора интерфейс
    // известен только после proof (у ожидающего Link он None), поэтому проверяем установленный Link.
    if !path::acceptable(ctx.node.engine().with_link(&id, |s| s.attached_interface()).flatten(), &allowed(), avoid_iface) {
        let _ = ctx.node.engine().close_link(&id).await;
        bail!("Link до {} выбрал недопустимый интерфейс", cand.name);
    }
    Ok((id, Arc::new(handle)))
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
async fn connect_exit(ctx: &Arc<ClientCtx>, cand: &CServer, avoid_iface: Option<usize>, pinned: bool) -> Result<(LinkId, Arc<leviculum_std::LinkHandle>)> {
    let wait = path::link_wait(pinned);
    if ctx.c13.is_some() && !exit_eligible(ctx, cand) {
        bail!("{} не имеет действующего права/политики EXIT в общей сети", cand.name);
    }
    let dest = DestinationHash::new(cand.dest);
    let t0 = Instant::now();
    // ADR 0028: прямой путь к выходу заблокирован (QUIC и TCP не проходят) — сквозной mesh-носитель через соседа-транзит строим ДО Link,
    // иначе Link идёт по RNS-транзиту (3+ хопа), который может не пройти. Права и допуск после Link прежние.
    let blocked = mesh_first_eligible(ctx, cand) && endpoint_peer_id(&cand.key).is_some_and(|p| ctx.sh.health.blocked_for(&p).is_some());
    if blocked {
        let ok = mesh_first(ctx, cand).await;
        ctx.sh.note(format!("{}: прямой путь заблокирован, mesh-носитель до Link {}", cand.name, if ok { "готов" } else { "не поднялся" }));
    } else if mesh_first_eligible(ctx, cand) {
        mesh_carrier(ctx, cand);
    }
    let (id, handle) = match open_link(ctx, cand, avoid_iface, wait.establish_s).await {
        Ok(v) => v,
        // Link не поднялся (нет пути/не установился): если к выходу нет своего QUIC — один раз пробуем через mesh-носитель
        Err(e) if !blocked && mesh_first_eligible(ctx, cand) => {
            ctx.sh.note(format!("{}: Link не поднялся ({e:#}), строю mesh-носитель и повторяю", cand.name));
            if !mesh_first(ctx, cand).await { return Err(e); }
            open_link(ctx, cand, avoid_iface, wait.establish_s).await?
        }
        Err(e) => return Err(e),
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    ctx.auth_wait.lock().unwrap().insert(id, tx);
    if let Some(c) = &ctx.c13 {
        c.link_pk.lock().unwrap().insert(id, cand.pk.unwrap_or([0u8; 64]));
    }
    // 0013: «пришёл за выходом» (T_USE) уходит ДО identify: у клиента с правами транзита (админ, телефон-админ) сервер иначе допустил бы его
    // соседом в момент identify. Цепочка идёт после identify (у ответчика identity появляется только после него).
    if ctx.c13.is_some() {
        send_ctl(&ctx.node, id, T_USE, &client_info_body(&ctx.identity, &ctx.state)).await;
    }
    ctx.node.identify_link(&id, &ctx.identity).await.map_err(|e| anyhow::anyhow!("identify: {e:?}"))?;
    if ctx.c13.is_some() {
        // повтор T_USE после identify: если первый пакет отстал, узел уже увидит намерение стать клиентом
        send_ctl(&ctx.node, id, T_USE, &client_info_body(&ctx.identity, &ctx.state)).await;
    }
    let reply = match tokio::time::timeout(Duration::from_secs(wait.auth_s), rx).await {
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
    // Гейт допуска (0024): T_PING с новым случайным nonce на ЭТОТ Link, ответ принимается только с тем же nonce (`on_pong_client`).
    // Проба уходит до T_OBSERVE и отправки хранилища прав, чтобы Channel не ждал за ними; ответ ждём ниже.
    let nonce = new_ping_nonce();
    let (ptx, mut prx) = tokio::sync::oneshot::channel();
    let room = {
        let mut pending = ctx.data_wait.lock().unwrap();
        if pending.len() >= 32 { false } else { pending.insert(id, (nonce, ptx)); true }
    };
    if !room {
        let _ = ctx.node.engine().close_link(&id).await;
        bail!("слишком много проверок выхода");
    }
    let mut probe = ExitProbeGuard { ctx, id, ready: false };
    let probe_at = tokio::time::Instant::now();
    send_ctl(&ctx.node, id, T_PING, &nonce.to_le_bytes()).await;
    if let Some(c) = &ctx.c13 {
        // выход обязан быть контактом из доверенного источника с ролью EXIT; окончательно допуск решил сам выход (AUTH_OK)
        let ok = authorized_exit(&c.peers.lock().unwrap(), cand.pk.as_ref());
        if !ok {
            let _ = ctx.node.engine().close_link(&id).await;
            bail!("{} не объявил себя выходом или не разрешает нам USE (таблица контактов)", cand.name);
        }
        ctx.set_name(cand.dest, reply["name"].as_str().unwrap_or(""));
        {
            let mut admitted = ctx.admitted_exits.lock().unwrap();
            if admitted.len() < 32 { admitted.insert(id, cand.dest); }
        }
        // Explicit subscription after EXIT validation fixes the early AUTH_OK/T_NBRS race.
        spawn_ctl(&ctx.node, id, T_OBSERVE, vec![u8::from(crate::mobile::ui_visible())]);
    }
    // Выход обязан ответить эхом nonce по этому Link за 3 с с отправки пробы (как прежние 3 x 1 с). Ответ с чужим nonce, повтор старого
    // и ответ другого Link отвергает `on_pong_client`. Channel надёжен: датаграммы Link пробой больше не проверяются, качество QUIC-носителя
    // дальше смотрят статистика QUIC и пейсер.
    match tokio::time::timeout_at(probe_at + Duration::from_secs(wait.probe_s), &mut prx).await {
        Ok(Ok(())) => probe.ready = true,
        _ => {}
    }
    ctx.data_wait.lock().unwrap().remove(&id);
    if !probe.ready {
        let iface = ctx.node.engine().with_link(&id, |s| s.attached_interface()).flatten();
        let _ = ctx.node.engine().close_link(&id).await;
        let why = format!("{}: нет ответа на проверку выхода", cand.name);
        return Err(match iface {
            Some(iface) => anyhow::Error::new(path::FailedPath { iface, why }),
            None => anyhow::anyhow!(why),
        });
    }
    ctx.sh.note(format!("выход {} принял клиента за {} мс (промежуточных нод RNS {:?})", cand.name, t0.elapsed().as_millis(), ctx.node.hops_to(&dest).map(|h| h.saturating_sub(1))));
    ctx.node.engine().with_link_mut(&id, |l| l.set_keepalive_override(Some(CLIENT_KEEPALIVE_S)));
    ctx.remember_rns_rtt(cand.dest, &id);
    // Прямой канал VPN-данных к этому выходу: после AUTH_OK и проверки EXIT. Ключ - `cand.key`: именно им Link проверил подпись ответчика
    // (`connect_with_key_cipher`), то есть это ключ подписи пира Link и ключ iroh выхода; он обязан совпасть с ключом проверенного кандидата.
    // (`get_remote_identity` здесь не годится: у инициатора Link он пуст, пока пир не вызвал identify.) Нет совпадения или нет c13 - данные идут по Link.
    if ctx.c13.is_some() {
        if let Some(ck) = cand.pk {
            if ck[32..64] == cand.key {
                dataplane::plane().bind(cand.key, id);
                mesh_carrier(ctx, cand);
            }
        }
    }
    Ok((id, handle))
}

fn mesh_label(key: &[u8; 32]) -> String { format!("mesh-{}", &hex(key)[..8]) }

fn endpoint_peer_id(key: &[u8; 32]) -> Option<String> { EndpointId::from_bytes(key).ok().map(|i| i.to_string()) }

/// Mesh до Link возможен: модель 0013, проверенный ключ кандидата (ключ подписи Link = ключ iroh), mesh включён, прямого QUIC-носителя ещё нет.
fn mesh_first_eligible(ctx: &Arc<ClientCtx>, cand: &CServer) -> bool {
    let Some(m) = mesh::global() else { return false };
    ctx.c13.is_some() && m.enabled() && mesh::quic_cfg().is_some() && cand.pk.is_some_and(|pk| pk[32..64] == cand.key) && !dataplane::plane().has_carrier(&cand.key)
}

/// Поднять сквозное QUIC к выходу через соседа-транзит и дождаться интерфейса мультиплексора (до 15 с). Данные не принимаются:
/// bind в dataplane — только после AUTH_OK и проверки EXIT в `connect_exit`; ключ пира берётся из TLS (`mark_e2e`/`add_quic(owner)`).
async fn mesh_first(ctx: &Arc<ClientCtx>, cand: &CServer) -> bool {
    mesh_carrier(ctx, cand);
    let label = mesh_label(&cand.key);
    let until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < until {
        if out_carrier_iface(&ctx.node, &label).is_some() { return true; }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Выходы, к которым сейчас идёт попытка mesh-соединения (не больше `MESH_DIAL_MAX` одновременно).
static MESH_DIALING: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());
const MESH_DIAL_MAX: usize = 2;

/// У выхода нет прямого QUIC-носителя (клиент и выход не соседи): поднять сквозное QUIC-соединение по mesh и подключить его носителем мультиплексора выхода.
/// Адрес выхода - mesh плюс проверенные подсказки IP выхода (книга адресов, прошедшая фильтр `resolve_addrs`): IP достижим - соединение сразу идёт прямым
/// путём, mesh остаётся тёплым запасным (правка iroh 1); недостижим - рукопожатие идёт по mesh. Только mesh было нельзя: без relay/QAD iroh не знает публичного
/// адреса выхода за NAT (облачная ВМ с частным адресом на интерфейсе), NAT traversal поверх mesh нечем и апгрейд на IP не происходит (W138, `nat_exit_behind_1to1_*`).
/// Если соединение осталось на mesh, рукопожатие по IP не повод разрывать его: проверка объёма прямого пути ещё не реализована.
/// Дальше Link/dataplane к выходу идут по этому соединению. Повторы с задержкой 2..60 с, пока выход остаётся текущим.
fn mesh_carrier(ctx: &Arc<ClientCtx>, cand: &CServer) {
    let Some(m) = mesh::global() else { return };
    if !m.enabled() || mesh::quic_cfg().is_none() {
        return;
    }
    let key = cand.key;
    if dataplane::plane().has_carrier(&key) {
        return;
    }
    {
        let mut d = MESH_DIALING.lock().unwrap();
        if d.contains(&key) || d.len() >= MESH_DIAL_MAX {
            return;
        }
        d.push(key);
    }
    let (weak, dest, name, fallback) = (Arc::downgrade(ctx), cand.dest, cand.name.clone(), cand.addrs.clone());
    tokio::spawn(async move {
        let mut wait = 2u64;
        let mut first = true;
        let mut tried_in_round = 0usize;
        loop {
            let Some(ctx) = weak.upgrade() else { break };
            // при первой попытке `cur` ещё не записан (connect_exit не вернулся)
            let wanted = std::mem::take(&mut first) || ctx.cur.lock().unwrap().is_some_and(|c| c.0 == dest);
            if !wanted || dataplane::plane().has_carrier(&key) {
                break;
            }
            let hints = mesh_hints(&ctx, &dest, &fallback).await;
            let (Some(addr), Some(cfg)) = (mesh::endpoint_addr_with(&key, &hints), mesh::quic_cfg()) else { break };
            m.prepare(&key);
            let t0 = Instant::now();
            let attempt = async {
                let c = ctx.ep.connect_with_opts(addr, ALPN, iroh::endpoint::ConnectOptions::new().with_transport_config(cfg)).await.ok()?;
                c.await.ok()
            };
            match tokio::time::timeout(Duration::from_secs(4), attempt).await {
                Ok(Some(conn)) => {
                    // не удалось пометить сквозным - соединение закрываем: непомеченное могло бы стать «соседом» mesh
                    if !m.mark_e2e(&conn) {
                        conn.close(0u32.into(), b"mesh table full");
                        break;
                    }
                    tokio::spawn(m.clone().watch_mesh_stall(conn.clone()));
                    tokio::spawn(m.clone().watch_direct_upgrade(conn.clone()));
                    let Ok(mx) = mux::Mux::new(&ctx.node, &ctx.sh, mux::next_name("iroh-dg-out", &mesh_label(&key)), false) else { conn.close(0u32.into(), b"no interface"); break };
                    if mx.add_quic(conn.clone(), true, key).is_none() {
                        conn.close(0u32.into(), b"too many carriers");
                        break;
                    }
                    ctx.sh.note(format!("mesh: сквозное QUIC к {name} установлено за {} мс", t0.elapsed().as_millis()));
                    wait = 2;
                    tried_in_round = 0;
                    drop(ctx);
                    let reason = loop {
                        tokio::select! {
                            r = conn.closed() => break r,
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                                let Some(ctx) = weak.upgrade() else { continue };
                                for e in m.take_hop_events() {
                                    let label = |k: Option<[u8; 32]>| k.map_or("—".to_string(), |k| ctx.servers.lock().unwrap().iter()
                                        .find(|s| s.key == k).map_or_else(|| mesh_label(&k), |s| s.name.clone()));
                                    ctx.sh.note(format!("mesh: хоп к {}: {} → {} ({}) {}", label(Some(e.dst)), label(e.old), label(e.new), e.why, e.detail));
                                }
                            }
                        }
                    };
                    if let Some(ctx) = weak.upgrade() {
                        ctx.sh.note(format!("mesh: сквозное QUIC к {name} завершено: {}", quic_close_kind(Some(&reason))));
                    }
                    mx.close();
                }
                _ => {
                    // следующая попытка сразу идёт через другой живой транзит, не тратя 2..60 с до обхода всех кандидатов
                    m.rotate_alt(&key);
                    tried_in_round += 1;
                    let total_transits = m.live_transit_count(&key).max(1);
                    if tried_in_round < total_transits {
                        first = true;
                        drop(ctx);
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    } else {
                        tried_in_round = 0;
                        ctx.sh.note(format!("mesh: к {name} не соединилось, повтор через {wait} с"));
                        drop(ctx);
                        tokio::time::sleep(Duration::from_secs(wait)).await;
                        wait = (wait * 2).min(30);
                    }
                }
            }
        }
        MESH_DIALING.lock().unwrap().retain(|k| k != &key);
    });
}

/// Проверенные подсказки IP выхода для mesh-соединения: книга адресов (обновляется анонсом, `dial_direct` читает её же) либо адреса кандидата;
/// фильтр `resolve_addrs` (частные/служебные сети отбрасываются, кроме лаборатории). Не больше 3.
async fn mesh_hints(ctx: &Arc<ClientCtx>, dest: &[u8; 16], fallback: &[String]) -> Vec<SocketAddr> {
    let mut cur = ctx.book_for(dest).get();
    if cur.is_empty() {
        cur = fallback.to_vec();
    }
    let mut v = resolve_addrs(&cur).await;
    v.truncate(3);
    v
}

fn candidates(ctx: &Arc<ClientCtx>, banned: &path::ExitBackoff, only: Option<[u8; 16]>) -> Vec<CServer> {
    // 0013: допущенный EXIT может требовать discovery, даже без адресов/кэша пути.
    // Legacy сохраняет прежнее требование достижимости; бан ограничивает повторные попытки.
    let mut v: Vec<CServer> = ctx.servers.lock().unwrap().iter().filter(|s| exit_eligible(ctx, s) && banned.ready(&s.dest, Instant::now())).cloned().collect();
    if let Some(o) = only {
        v.retain(|s| s.dest == o);
        return v;
    }
    // Фильтр имён (настройка маршрутизации): только для автовыбора. Если он отсекает все выходы, лучше работать через остальные, чем без связи.
    let filter = ctx.rcfg.read().unwrap().exit_filter.clone();
    if !filter.words.is_empty() {
        let kept: Vec<CServer> = v.iter().filter(|s| filter.allows(&ctx.shown_name(s))).cloned().collect();
        if !kept.is_empty() { v = kept; }
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

/// Контакт годится как выход: сам объявил роль EXIT, разрешает мне USE, представлен доверенным источником.
fn authorized_exit(p: &peers::Peers, pk: Option<&peers::Pk>) -> bool {
    pk.and_then(peers::hash_of).and_then(|h| p.contact(&h).map(authorized_exit_contact)).unwrap_or(false)
}

fn authorized_exit_contact(c: &peers::Contact) -> bool {
    c.roles & peers::EXIT != 0 && c.they_grant & peers::USE != 0 && trusted_intro(c)
}

fn trusted_intro(c: &peers::Contact) -> bool {
    c.intro_by == "invite" || c.intro_by == "local" || c.intro_by.len() == 32
}

fn exit_eligible(ctx: &ClientCtx, s: &CServer) -> bool {
    let authorized = ctx.c13.as_ref().map(|c| authorized_exit(&c.peers.lock().unwrap(), s.pk.as_ref()));
    path::eligible(authorized, !s.addrs.is_empty() || s.state == "up", s.state == "lost")
}



impl ClientCtx {
    fn routing_json(&self, servers: &[CServer]) -> serde_json::Value {
        let rc = self.rcfg.read().unwrap().clone();
        let t = &self.tun;
        let have: Vec<_> = t.extra.read().unwrap().iter().map(|(d,x)|(*d,x.clone())).collect();
        let interfaces = self.node.engine().interface_stats();
        let extras: Vec<serde_json::Value> = have.iter().map(|(d, x)| {
            let attached = self.node.engine().with_link(&x.id, |s| s.attached_interface()).flatten();
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
    let avoid = ctx.node.engine().with_link(&link, |s| s.attached_interface()).flatten();
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
            let acked = ctx.node.engine().with_link(&x.id, |l| l.keepalives_acked()).unwrap_or(0);
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
                dataplane::plane().unbind(&x.id);
                pacers.remove(&x.id);
                recovering.remove(&x.id);
                let _ = ctx.node.engine().close_link(&x.id).await;
                if why != "не нужен" {
                    ctx.sh.note(format!("доп. выход {}: {why}", hex(&d[..4])));
                    ctx.rback.lock().unwrap().insert(*d, Instant::now() + Duration::from_secs(10));
                }
            } else if step.ping {
                // Channel-пинг доп. выхода (0024): ответ T_PONG с тем же nonce обновит `last_rx_ms` (`on_pong_client`)
                let nonce = new_ping_nonce();
                ctx.loss.lock().unwrap().sent(x.id, nonce);
                spawn_ctl(&ctx.node, x.id, T_PING, nonce.to_le_bytes().to_vec());
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
                let r = tokio::time::timeout(Duration::from_secs(25), connect_exit(&c2, &cand, None, false)).await;
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

async fn client_supervisor(ctx: Arc<ClientCtx>) {
    let fin = ctx.state.join("fin");
    let sel_file = ctx.state.join("select");
    let mut banned = path::ExitBackoff::default();
    let mut seen_up: HashMap<[u8; 16], u32> = HashMap::new();
    let mut avoid: HashMap<[u8; 16], usize> = HashMap::new();
    // Рабочий запасной Link живёт и во время проверки выбранного выхода.
    // Неудачная проба не создаёт новый Link к прежнему выходу и не считается сменой.
    let mut active: Option<(CServer, LinkId, Arc<leviculum_std::LinkHandle>)> = None;
    let mut primary: Option<[u8;16]> = None;
    let mut pending_reason: Option<String> = None;
    let mut keep_trying: HashMap<[u8; 16], Instant> = HashMap::new();
    // QAB-M2: перенос на QUIC не удался, а прежний Link мог быть вытеснен сервером; когда начался перенос; восстановленный выход и время
        while !fin.exists() {
        // У пира снова появился носитель (после перерыва без носителя): отступ выхода, набранный за время без связи (10 -> 20 -> ... с на неудачных попытках
        // Link), больше не отражает состояние пути - новый Link поднимаем сразу, не дожидаясь его конца.
        for (d, cc) in ctx.carriers.lock().unwrap().iter() {
            let e = cc.up_epoch.load(Relaxed);
            if seen_up.insert(*d, e).is_some_and(|old| old != e) {
                banned.succeeded(d);
                // «Не этот интерфейс» относилось к прежнему носителю: интерфейс пира (`mux.rs`) переживает смену носителя, и после неё он единственный путь к пиру
                avoid.remove(d);
            }
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
            // Закрытый Link (Stale и др.) не переиспользуем: иначе внутренний цикл тут же выходит с тем же «link закрыт» и новый Link никогда не поднимается
            // (шторм каждые 250 мс, найден lab13 realityfail --control). Закрытый - значит RNS признал пира мёртвым на этом Link: нужен новый.
            if let Some(old) = active.as_ref().filter(|a| a.0.dest == c.dest && !ctx.sh.closed.lock().unwrap().contains_key(&hex(a.1.as_bytes())) && !keep_trying.get(&c.dest).map(|t| *t > Instant::now()).unwrap_or(false)) {
                connected = Some(old.clone());
                break;
            }
            *ctx.status.lock().unwrap() = format!("подключаюсь к {}", c.name);
            let av = avoid.get(&c.dest).copied();
            // Старый Link обслуживает штатный keepalive RNS и во время подключения нового.
            let t_conn = Instant::now();
            let result = connect_exit(&ctx, &c, av, want == Some(c.dest)).await;
            if crate::debug() {
                ctx.sh.note(format!("подключение к {}: {} за {} мс", c.name, if result.is_ok() { "успех" } else { "неудача" }, t_conn.elapsed().as_millis()));
            }
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
                        let delay = banned.failed(c.dest, Instant::now(), path::backoff_cap_s(want == Some(c.dest)));
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
            connected = active.as_ref().filter(|old| want.map_or(true, |d| old.0.dest == d) && !ctx.sh.closed.lock().unwrap().contains_key(&hex(old.1.as_bytes()))).cloned();
        }
        let Some((cand, id, handle)) = connected else {
            *ctx.tun.client_link.write().unwrap() = None;
            *ctx.cur.lock().unwrap() = None;
            ctx.publish_service();
            // выбора нет, если выходов нет вовсе (клиент только с P2P-контактами): не «восстанавливаю путь к выбранной ноде»
            *ctx.status.lock().unwrap() = if ctx.servers.lock().unwrap().is_empty() { "Выходов пока нет".into() }
                else { "восстанавливаю путь к выбранной ноде; другой выход не подставляется".into() };
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
        let mut quic_tracker = (0usize, 0u64); // (conn_id, last_rx_count)
        let mut sil_grace: Option<Instant> = None;
        let mut better_since: Option<Instant> = None;
        let mut last_eval = Instant::now();
        let connected_at = ctx.cur.lock().unwrap().map(|c| c.2).unwrap_or_else(Instant::now);
        let mut last_wake = Instant::now();
        let mut last_snap = Instant::now();
        let mut last_silent = 0u64;
        let reason = loop {
            if fin.exists() {
                break "fin".to_string();
            }
            // Пауза цикла (250 мс сна): Doze/энергосбережение или нагрузка могли заморозить процесс; от неё зависят «нет ответа» и обрывы.
            let lag = last_wake.elapsed().saturating_sub(Duration::from_millis(250));
            last_wake = Instant::now();
            if lag >= Duration::from_secs(2) || (crate::debug() && lag >= Duration::from_millis(800)) {
                ctx.sh.note(format!("цикл клиента опоздал на {} мс (процесс стоял: сон или нагрузка)", lag.as_millis()));
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
            let (acked, ka_rtt) = ctx.node.engine().with_link(&id, |l| (l.keepalives_acked(), l.keepalive_rtt_ms())).unwrap_or((0, None));
            let now = now_ms() as u64;

            // Телеметрия и живость выхода через сквозной QUIC (Задача Б):
            let quic_carrier = dataplane::plane().carrier_conn(&cand.key);
            if let Some(ref quic_conn) = quic_carrier {
                let st = quic_conn.stats();
                // Only authenticated, non-replayed frames are contact. Raw UDP
                // includes garbage/replays addressed to the connection ID.
                let rx_count = st.frame_rx.authenticated_progress();
                let cid = quic_conn.stable_id();
                let mut fresh = false;
                if quic_tracker.0 != cid {
                    quic_tracker = (cid, rx_count);
                    *ctx.rtt_ms.lock().unwrap() = None;
                } else if rx_count > quic_tracker.1 {
                    quic_tracker.1 = rx_count;
                    ctx.last_pong.store(now, Relaxed);
                    fresh = true;
                }
                if let Some(sel) = quic_conn.paths().iter().find(|p| p.is_selected()).filter(|_| fresh) {
                    let rtt = (sel.rtt().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
                    *ctx.rtt_ms.lock().unwrap() = Some(rtt);
                    ctx.rtt_pong.store(now, Relaxed);
                }
            } else {
                // carrier_conn omits closed/unselected QUIC. Let the existing
                // Link/TCP recovery run; a closed carrier does not prove a dead exit.
                quic_tracker = (0, 0);
            }
            let step = pacer.step(now, ctx.tun.traffic_pkts(), ctx.last_pong.load(Relaxed), acked, CLIENT_KEEPALIVE_S * 1000, ctx.fail_ms);
            if step.keepalive_ack {
                ctx.remember_rns_rtt(cand.dest, &id);
                // ответ keepalive RNS - контакт; его RTT нужен индикации, если свежих замеров QUIC/T_PONG нет
                ctx.last_pong.store(now, Relaxed);
                if now.saturating_sub(ctx.rtt_pong.load(Relaxed)) >= 5_000 {
                    if let Some(r) = ka_rtt {
                        *ctx.rtt_ms.lock().unwrap() = Some(r as f64);
                        ctx.rtt_pong.store(now, Relaxed);
                    }
                }
            }
            ctx.contact_window_ms.store(step.contact_window_ms, Relaxed);
            last_silent = step.silent_ms;
            if crate::debug() && last_snap.elapsed() >= Duration::from_secs(5) {
                last_snap = Instant::now();
                let car = ctx.carriers.lock().unwrap().get(&cand.dest).cloned();
                let car = car.map(|c| format!("{} смен {}", c.mode_label(), c.switches.load(Relaxed))).unwrap_or_else(|| "?".into());
                let rtt = ctx.rtt_ms.lock().unwrap().map(|r| format!("{r:.0} мс")).unwrap_or_else(|| "?".into());
                let loss = if let Some(ref conn) = quic_carrier {
                    format!("QUIC lost_packets={} (за соединение)", conn.stats().lost_packets)
                } else {
                    ctx.loss.lock().unwrap().loss(Some(id), Duration::from_secs(10), 1).map(|x| format!("T_PING {:.0}%", x * 100.0)).unwrap_or_else(|| "?".into())
                };
                ctx.sh.note(format!("снимок: выход {}, живёт {} с, носитель {car}, rtt {rtt}, потери {loss}, тишина {} мс, keepalive ack {acked}, пакетов TUN {}",
                    cand.name, connected_at.elapsed().as_secs(), step.silent_ms, ctx.tun.traffic_pkts()));
            }
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
                if let Some(ref quic_conn) = quic_carrier {
                    // Проба запрашивает ACK; живость обновляет только приём, не сам вызов ping().
                    quic_conn.ping();
                } else {
                    // Нет выбранного QUIC-носителя (TCP или Link): Channel-пинг T_PING вместо датаграммы Link (0024)
                    let nonce = new_ping_nonce();
                    ctx.loss.lock().unwrap().sent(id, nonce);
                    spawn_ctl(&ctx.node, id, T_PING, nonce.to_le_bytes().to_vec());
                    // монитор качества: режим QUIC, но выбранного соединения нет, а Channel-пинги не возвращаются (>= 30% при >= 8 созревших)
                    // -> запасной TCP для этого выхода. Channel надёжен, поэтому срабатывает лишь при реальной потере связи
                    let cc = ctx.carriers.lock().unwrap().get(&cand.dest).cloned();
                    if let Some(cc) = cc {
                        if cc.is_quic() && !cc.prefer_tcp.load(Relaxed) {
                            if let Some(l) = ctx.loss.lock().unwrap().loss(Some(id), Duration::from_secs(3), 8) {
                                if l >= 0.30 {
                                    ctx.sh.note(format!("{}: потери UDP {:.0}% по пингам, переключаю носитель на TCP", cand.name, l * 100.0));
                                    cc.prefer_tcp.store(true, Relaxed);
                                    cc.switches.fetch_add(1, Relaxed);
                                }
                            }
                        }
                    }
                }
            }
        };
        if reason == "fin" {
            break;
        }
        if crate::debug() {
            ctx.sh.note(format!("уход с выхода {}: {reason}; Link жил {} с, последняя тишина {last_silent} мс", cand.name, connected_at.elapsed().as_secs()));
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
        // Долго жившего Link закрыл сам RNS (Stale): пир замолчал (смена носителя заняла дольше окна stale), а не выход «отказал». Новый Link поднимаем сразу,
        // без отступа и без отказа от интерфейса: смена носителя идёт внутри того же интерфейса пира (`mux.rs`). Короткоживущий закрытый Link - прежняя ветка
        // (отступ 10 с, растёт вдвое): так закрывающий сразу после допуска выход не даёт шторм.
        let soft_close = is_soft_link_close(&reason, connected_at.elapsed());
        if soft_close {
            ctx.lk_fail.lock().unwrap().insert(cand.dest, (Instant::now(), reason.chars().take(80).collect()));
            ctx.sh.note(format!("{}: Link закрыт ({reason}), поднимаю новый сразу", cand.name));
            pending_reason = Some(reason.clone());
        } else if !user {
            // Отказавший выход отступает независимо от работающего запасного.
            ctx.lk_fail.lock().unwrap().insert(cand.dest, (Instant::now(), reason.chars().take(80).collect()));
            banned.failed(cand.dest, Instant::now(), path::backoff_cap_s(want == Some(cand.dest)));
            if let Some(i) = ctx.node.engine().with_link(&id, |s| s.attached_interface()).flatten() {
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
    fn carrier_up_epoch_grows_only_when_a_carrier_appears_after_none() {
        let cc = CarrierCtl::new();
        assert_eq!(cc.up_epoch.load(Relaxed), 0);
        cc.set_mode("quic");
        assert_eq!(cc.up_epoch.load(Relaxed), 1, "none -> quic");
        cc.set_mode("tcp");
        cc.set_mode("reality");
        assert_eq!(cc.up_epoch.load(Relaxed), 1, "смена носителя без перерыва отступ не сбрасывает");
        cc.set_mode("none");
        cc.set_mode("tcp");
        assert_eq!(cc.up_epoch.load(Relaxed), 2, "носитель появился после перерыва");
    }

    #[test]
    fn closed_long_lived_link_is_reestablished_at_once_and_grace_outlives_stale() {
        assert!(is_soft_link_close("link закрыт: Stale", Duration::from_secs(180)), "долго жившего Link поднимаем заново сразу");
        assert!(!is_soft_link_close("link закрыт: Stale", Duration::from_secs(2)), "закрытый сразу после допуска Link - отступ, не шторм");
        assert!(!is_soft_link_close("нет ответа 12000 мс", Duration::from_secs(180)));
        assert!(mux::GRACE >= Duration::from_secs(55), "интерфейс пира должен пережить stale Link клиента (2 x 25 с)");
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
