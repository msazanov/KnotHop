//! Fail-closed IPv4 host-access policy for the TUN data plane.
//!
//! The state file is operator-provisioned local state, never peer input. It is
//! intentionally small and contains only literal IPv4 addresses.

use std::collections::HashSet;
use std::ffi::CStr;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) fn refresh_interval() -> std::time::Duration { REFRESH_INTERVAL }

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    #[serde(default)]
    aliases: Vec<String>,
    /// Exact locally-owned private/service addresses explicitly exposed to ACL.
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Inventory {
    /// All exact addresses assigned to non-loopback, non-container interfaces,
    /// including private addresses which are never treated as internet.
    pub(crate) owned: HashSet<u32>,
    /// Exact destinations the owner has chosen to expose to HOST_ACCESS.
    pub(crate) host_allow: HashSet<u32>,
    /// Own service-TUN addresses, for the narrow health echo exception.
    pub(crate) service_tun: HashSet<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DestinationDecision {
    Internet,
    HostNeedsPermission,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceDecision {
    Public,
    HostNeedsPermission,
    Deny,
}

pub(crate) fn build(state: &Path) -> Result<Inventory> {
    let config = read_config(state)?;
    let (owned, service_tun) = interface_ipv4()?;
    let aliases = config.aliases.iter().map(|s| parse_global(s, "alias")).collect::<Result<HashSet<_>>>()?;
    let explicit = config.allow.iter().map(|s| parse_literal(s, "allow")).collect::<Result<HashSet<_>>>()?;

    let mut all_owned = owned;
    all_owned.extend(aliases.iter().copied());
    for address in &explicit {
        if !all_owned.contains(address) {
            bail!("host ACL allow entry is not a locally-owned or configured alias address");
        }
    }

    let mut host_allow = aliases;
    // Public interface addresses are enabled by exact address by default.
    host_allow.extend(all_owned.iter().copied().filter(|ip| is_public(*ip)));
    host_allow.extend(explicit);
    Ok(Inventory { owned: all_owned, host_allow, service_tun })
}

fn read_config(path: &Path) -> Result<Config> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path).context("open host ACL state without following symlinks")?;
    let meta = file.metadata().context("host ACL state metadata")?;
    if !meta.file_type().is_file() { bail!("host ACL state must be a regular file"); }
    if meta.len() > MAX_CONFIG_BYTES || meta.mode() & 0o077 != 0 {
        bail!("host ACL state must be <=16KiB and inaccessible to group/other");
    }
    // Accept root-owned state or state owned by the effective service user.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        bail!("host ACL state has unexpected owner");
    }
    use std::io::Read;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes).context("read host ACL state")?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES { bail!("host ACL state exceeds 16KiB"); }
    let config: Config = serde_json::from_slice(&bytes).context("parse host ACL state")?;
    if config.version != 1 || config.aliases.len() > 64 || config.allow.len() > 64 {
        bail!("unsupported or oversized host ACL state");
    }
    Ok(config)
}

fn interface_ipv4() -> Result<(HashSet<u32>, HashSet<u32>)> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error()).context("getifaddrs for host ACL");
    }
    let mut owned = HashSet::new();
    let mut service_tun = HashSet::new();
    let mut current = head;
    while !current.is_null() {
        let ifa = unsafe { &*current };
        if !ifa.ifa_addr.is_null() && unsafe { (*ifa.ifa_addr).sa_family as i32 } == libc::AF_INET {
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
            if !is_excluded_interface(&name) {
                let sockaddr = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let octets = u32::from_be(sockaddr.sin_addr.s_addr);
                if octets != 0 && !is_martian(octets) {
                    owned.insert(octets);
                    if is_service_tun(&name) { service_tun.insert(octets); }
                }
            }
        }
        current = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    Ok((owned, service_tun))
}

fn is_excluded_interface(name: &str) -> bool {
    name == "lo" || name == "docker0" || name.starts_with("br") || name.starts_with("docker")
        || name.starts_with("veth") || name.starts_with("cni") || name.starts_with("flannel")
        || name.starts_with("virbr") || name.starts_with("lxcbr") || name.starts_with("podman") || name.starts_with("cali")
}

fn is_service_tun(name: &str) -> bool {
    // Current KnotHop node TUN interface; do not infer this from address ranges.
    name == "khd0"
}

fn parse_literal(raw: &str, field: &str) -> Result<u32> {
    let ip: Ipv4Addr = raw.parse().with_context(|| format!("{field} must be a literal IPv4 address"))?;
    let value = u32::from(ip);
    if is_martian(value) { bail!("{field} contains a forbidden special-use address"); }
    Ok(value)
}

fn parse_global(raw: &str, field: &str) -> Result<u32> {
    let value = parse_literal(raw, field)?;
    if !is_public(value) { bail!("{field} must be a globally-routable literal IPv4 address"); }
    Ok(value)
}

pub(crate) fn classify_destination(ip: u32, inventory: &Inventory) -> DestinationDecision {
    if is_martian(ip) { return DestinationDecision::Deny; }
    if inventory.owned.contains(&ip) { return DestinationDecision::HostNeedsPermission; }
    if is_private_or_special(ip) { return DestinationDecision::Deny; }
    DestinationDecision::Internet
}

pub(crate) fn classify_source(ip: u32, inventory: &Inventory) -> SourceDecision {
    if is_martian(ip) { return SourceDecision::Deny; }
    if inventory.owned.contains(&ip) { return SourceDecision::HostNeedsPermission; }
    if is_private_or_special(ip) { return SourceDecision::Deny; }
    SourceDecision::Public
}

pub(crate) fn is_martian(ip: u32) -> bool {
    let [a, b, c, d] = ip.to_be_bytes();
    a == 0 || a == 127 || a >= 224 || (a == 169 && b == 254) || (a == 255 && b == 255 && c == 255 && d == 255)
}

fn is_private_or_special(ip: u32) -> bool {
    let [a, b, c, _] = ip.to_be_bytes();
    is_martian(ip) || (a == 10) || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b)) || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0) || (a == 192 && b == 2) || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113) || (a == 192 && b == 88 && c == 99)
}

fn is_public(ip: u32) -> bool { !is_private_or_special(ip) }

// The nft worker never runs on the packet path and never logs addresses or nft's
// diagnostics (which contain the input script). Kernel leases are defense in
// depth; the per-Link TUN ACL remains authoritative, including for active flows.
const NFT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
const NFT_TICK: std::time::Duration = std::time::Duration::from_secs(1);
const NFT_MIN_UPDATE: std::time::Duration = std::time::Duration::from_millis(100);
// Холодный exec nft на загруженном 1-CPU хосте (Nice=10) дольше штатных 500 мс: стартовая очистка получает запас и повторы.
const NFT_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const NFT_STARTUP_TRIES: u32 = 3;
#[cfg(not(test))]
const NFT_STARTUP_PAUSE: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
const NFT_STARTUP_PAUSE: std::time::Duration = std::time::Duration::from_millis(10);
const NFT_CLEAR: &str = "flush set inet knothop host_access_v4\nflush set inet knothop host_access_dest_v4\n";
static NFT_WAKE: std::sync::OnceLock<std::sync::mpsc::SyncSender<()>> = std::sync::OnceLock::new();

// Счётчики worker для status.json (без адресов): отказ публикации закрывает доступ всем, это должно быть видно владельцу.
static NFT_PUBLISH_OK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static NFT_PUBLISH_FAIL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static NFT_FALLBACK_CLEARS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static NFT_LAST_OK_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn notify_nft() {
    if let Some(wake) = NFT_WAKE.get() { let _ = wake.try_send(()); }
}

/// Диагностика worker: `active` = контроллер запущен; `last_ok_ms` = unix-время последней успешной публикации (0 - не было).
pub(crate) fn nft_stats() -> serde_json::Value {
    use std::sync::atomic::Ordering::Relaxed;
    serde_json::json!({
        "active": NFT_WAKE.get().is_some(),
        "publish_ok": NFT_PUBLISH_OK.load(Relaxed), "publish_fail": NFT_PUBLISH_FAIL.load(Relaxed),
        "fallback_clears": NFT_FALLBACK_CLEARS.load(Relaxed), "last_ok_ms": NFT_LAST_OK_MS.load(Relaxed),
    })
}

/// One writer, fresh snapshots only, bounded CLI lifetime, no shell or PATH lookup.
pub(crate) struct NftHostAccess {
    program: &'static str,
    pool: (u32, u8),
}

impl NftHostAccess {
    /// Clear stale leases before admitting any clients. An absent/old firewall is
    /// a startup error, not an excuse to create a broader or partial ruleset.
    pub(crate) fn new(pool: (u32, u8)) -> Result<Self> {
        validate_pool(pool)?;
        let program = ["/usr/sbin/nft", "/usr/bin/nft"].into_iter()
            .find(|p| Path::new(p).is_file()).context("nft executable unavailable")?;
        let controller = Self { program, pool };
        controller.clear_startup()?;
        Ok(controller)
    }

    /// Первый вызов при старте: увеличенный таймаут и повторы. Постоянная ошибка (нет таблицы/наборов) по-прежнему ошибка старта.
    fn clear_startup(&self) -> Result<()> {
        let mut last = None;
        for attempt in 0..NFT_STARTUP_TRIES {
            if attempt > 0 { std::thread::sleep(NFT_STARTUP_PAUSE); }
            match run_nft(self.program, NFT_CLEAR, NFT_STARTUP_TIMEOUT) {
                Ok(()) => return Ok(()),
                Err(e) => last = Some(e),
            }
        }
        Err(last.expect("at least one attempt")).context("clear host-access nft sets at startup")
    }

    fn clear(&self) -> Result<()> { run_nft(self.program, NFT_CLEAR, NFT_TIMEOUT) }

    /// `peers` only returns authenticated, live, non-enrollment client Links.
    /// Called with Trust held (Trust -> links -> host_access -> allowed); no I/O
    /// under those locks. Only the single worker publishes snapshots to nft.
    pub(crate) fn start(
        self, tun: &std::sync::Arc<crate::TunState>,
        authority: std::sync::Arc<std::sync::Mutex<crate::trust::Trust>>,
        peers: impl Fn() -> Option<Vec<(leviculum_std::api::LinkId, crate::trust::Pk)>> + Send + 'static,
    ) -> Result<()> {
        let tun = std::sync::Arc::downgrade(tun);
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        // knothopd runs one node per process; do not silently install two writers.
        NFT_WAKE.set(send).map_err(|_| anyhow::anyhow!("nft worker already configured"))?;
        std::thread::Builder::new().name("host-nft-refresh".into()).spawn(move || {
            let mut failing = false;
            let mut next_update = std::time::Instant::now();
            loop {
                // Coalesce event storms: at most ten publications/s, including
                // authenticated reconnect churn; unauthenticated close is not a wakeup.
                std::thread::sleep(next_update.saturating_duration_since(std::time::Instant::now()));
                let _ = recv.try_recv(); // capacity is one; never spin on concurrent senders
                let Some(tun) = tun.upgrade() else { let _ = self.clear(); break };
                let snapshot = {
                    let tr = authority.lock().unwrap();
                    let Some(peers) = peers() else { break };
                    let permissions = tun.host_access.read().unwrap();
                    let allowed = tun.allowed.read().unwrap();
                    let clients = authorized_clients(&tr, &peers, &permissions, &allowed);
                    let inventory = tun.host_inventory.read().unwrap().clone();
                    if tun.host_acl_ready() { inventory.map(|inv| (clients, inv)) } else { None }
                };
                let script = match snapshot {
                    Some((clients, inventory)) => nft_batch(self.pool, &clients, &inventory),
                    None => Ok(NFT_CLEAR.to_owned()),
                };
                let success = script.and_then(|script| run_nft(self.program, &script, NFT_TIMEOUT)).is_ok();
                use std::sync::atomic::Ordering::Relaxed;
                if success {
                    NFT_PUBLISH_OK.fetch_add(1, Relaxed);
                    NFT_LAST_OK_MS.store(crate::now_ms() as u64, Relaxed);
                } else {
                    NFT_PUBLISH_FAIL.fetch_add(1, Relaxed);
                    NFT_FALLBACK_CLEARS.fetch_add(1, Relaxed);
                    // Atomic nft transactions leave the old state on failure.
                    // Clear it immediately; even if that fails leases expire.
                    let _ = self.clear();
                    if !failing { eprintln!("HOST_ACCESS nft update failed; host TCP remains fail-closed"); }
                }
                failing = !success;
                drop(tun);
                next_update = std::time::Instant::now() + NFT_MIN_UPDATE;
                let _ = recv.recv_timeout(NFT_TICK);
            }
            let _ = self.clear();
        }).context("start host-access nft worker")?;
        Ok(())
    }
}

fn authorized_clients(
    tr: &crate::trust::Trust,
    peers: &[(leviculum_std::api::LinkId, crate::trust::Pk)],
    permissions: &HashSet<leviculum_std::api::LinkId>,
    allowed: &std::collections::HashMap<leviculum_std::api::LinkId, u32>,
) -> HashSet<u32> {
    let now = crate::now_ms() as u64;
    peers.iter().filter(|(link, pk)| {
        permissions.contains(link) && !tr.host_access_roots(pk, &tr.me_hash).is_empty()
            && tr.common_with(pk, crate::trust::EXIT, crate::trust::USE, true, false, now)
    }).filter_map(|(link, _)| allowed.get(link).copied()).collect()
}

fn validate_pool((base, prefix): (u32, u8)) -> Result<()> {
    if !(8..=24).contains(&prefix) || base & (u32::MAX >> prefix) != 0 || is_martian(base) {
        bail!("invalid host-access client pool");
    }
    Ok(())
}

fn valid_client(ip: u32, (base, prefix): (u32, u8)) -> bool {
    let host_mask = u32::MAX >> prefix;
    !is_martian(ip) && ip & !host_mask == base && ip & host_mask != 0 && ip & host_mask != host_mask
}

fn nft_batch(pool: (u32, u8), clients: &HashSet<u32>, inventory: &Inventory) -> Result<String> {
    validate_pool(pool)?;
    if clients.len() > 256 || inventory.host_allow.len() > 256
        || clients.iter().any(|ip| !valid_client(*ip, pool))
        || inventory.host_allow.iter().any(|ip| is_martian(*ip) || !inventory.owned.contains(ip)) {
        bail!("invalid or oversized host-access nft snapshot");
    }
    let mut script = NFT_CLEAR.to_owned();
    for (name, entries) in [("host_access_v4", clients), ("host_access_dest_v4", &inventory.host_allow)] {
        if entries.is_empty() { continue; }
        let mut entries: Vec<_> = entries.iter().copied().collect();
        entries.sort_unstable();
        let elements = entries.into_iter().map(|ip| format!("{} timeout 3s", Ipv4Addr::from(ip))).collect::<Vec<_>>().join(", ");
        script.push_str(&format!("add element inet knothop {name} {{ {elements} }}\n"));
    }
    Ok(script)
}

fn run_nft(program: &str, script: &str, timeout: std::time::Duration) -> Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};
    if script.len() > 32 * 1024 { bail!("host-access nft batch too large"); }
    // Окружение юнита (EnvironmentFile: KNOTHOP_*, возможные LD_*) nft не нужно; программа - абсолютный путь.
    let mut child = Command::new(program).args(["-f", "-"]).env_clear()
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().context("start nft host-access update")?;
    let deadline = std::time::Instant::now() + timeout;
    let result = (|| -> Result<()> {
        let mut input = child.stdin.take().context("nft stdin unavailable")?;
        // Nonblocking writes include a stalled stdin reader in the same deadline.
        let fd = input.as_raw_fd();
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            bail!("cannot make nft input nonblocking");
        }
        let mut rest = script.as_bytes();
        while !rest.is_empty() {
            if std::time::Instant::now() >= deadline { bail!("nft host-access update timed out"); }
            match input.write(rest) {
                Ok(0) => bail!("nft input closed"),
                Ok(n) => rest = &rest[n..],
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(2)),
                Err(_) => bail!("cannot write nft host-access input"),
            }
        }
        drop(input);
        loop {
            if let Some(status) = child.try_wait().context("wait for nft host-access update")? {
                if !status.success() { bail!("nft host-access transaction rejected"); }
                return Ok(());
            }
            if std::time::Instant::now() >= deadline { bail!("nft host-access update timed out"); }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        // Ограниченное ожидание: процесс в состоянии D не должен подвесить единственный worker.
        for _ in 0..50 {
            if !matches!(child.try_wait(), Ok(None)) { break; }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> u32 { u32::from(s.parse::<Ipv4Addr>().unwrap()) }

    #[test]
    fn destination_classes_keep_remote_private_and_other_clients_denied() {
        let mut inv = Inventory::default();
        inv.owned.insert(ip("10.1.2.3"));
        assert_eq!(classify_destination(ip("10.1.2.3"), &inv), DestinationDecision::HostNeedsPermission);
        assert_eq!(classify_destination(ip("10.1.2.4"), &inv), DestinationDecision::Deny);
        assert_eq!(classify_destination(ip("172.17.0.1"), &inv), DestinationDecision::Deny);
        assert_eq!(classify_destination(ip("198.18.0.1"), &inv), DestinationDecision::Deny);
        assert_eq!(classify_destination(ip("8.8.8.8"), &inv), DestinationDecision::Internet);
    }

    #[test]
    fn aliases_are_literal_global_only_and_private_allow_is_exact() {
        assert!(parse_global("203.0.113.7", "alias").is_err());
        assert!(parse_global("10.0.0.1", "alias").is_err());
        assert!(parse_global("https://example.test", "alias").is_err());
        assert_eq!(parse_literal("10.0.0.1", "allow").unwrap(), ip("10.0.0.1"));
        assert!(parse_literal("127.0.0.1", "allow").is_err());
    }

    #[test]
    fn state_file_requires_private_regular_file_and_aliases_are_exact() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kh-host-acl-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("host-acl.json");
        fs::write(&path, br#"{"version":1,"aliases":["8.8.8.8"],"allow":[]}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let inventory = build(&path).unwrap();
        assert!(inventory.host_allow.contains(&u32::from(Ipv4Addr::new(8, 8, 8, 8))));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(build(&path).is_err());
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(build(&link).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn martians_and_private_sources_are_never_public() {
        for addr in ["127.0.0.1", "0.1.2.3", "169.254.1.1", "224.0.0.1", "240.0.0.1"] {
            assert_eq!(classify_destination(ip(addr), &Inventory::default()), DestinationDecision::Deny);
        }
        assert_eq!(classify_source(ip("192.168.1.2"), &Inventory::default()), SourceDecision::Deny);
    }

    #[test]
    fn nft_snapshot_is_exact_bounded_and_always_replaces_both_sets() {
        let pool = (ip("198.18.0.0"), 15);
        let client = ip("198.18.1.7");
        let host = ip("8.8.4.4");
        let private = ip("10.1.2.3");
        let inv = Inventory { owned: [host, private].into(), host_allow: [host, private].into(), ..Default::default() };
        let batch = nft_batch(pool, &[client].into(), &inv).unwrap();
        assert!(batch.starts_with(NFT_CLEAR));
        assert_eq!(batch.matches("add element").count(), 2);
        assert_eq!(batch.matches("timeout 3s").count(), 3);
        assert!(!batch.contains("table ip knothop_nat"));
        assert!(!batch.contains("chain"));
        // Revoke/disconnect clears clients without retaining any previous source.
        let revoke = nft_batch(pool, &HashSet::new(), &inv).unwrap();
        assert!(!revoke.contains("add element inet knothop host_access_v4"));
        assert_eq!(nft_batch(pool, &HashSet::new(), &Inventory::default()).unwrap(), NFT_CLEAR);
        let mut bad = inv.clone();
        bad.host_allow.insert(ip("10.1.2.4"));
        assert!(nft_batch(pool, &[client].into(), &bad).is_err(), "not owned");
        let too_many: HashSet<_> = (1..=257).map(|n| pool.0 + n).collect();
        assert!(nft_batch(pool, &too_many, &inv).is_err());
    }

    #[test]
    fn nft_clients_are_only_usable_literal_pool_addresses() {
        let pool = (ip("198.18.0.0"), 15);
        for value in ["198.18.0.0", "198.19.255.255", "198.20.0.1", "127.0.0.1", "10.1.1.1"] {
            assert!(nft_batch(pool, &[ip(value)].into(), &Inventory::default()).is_err());
        }
        for prefix in [0, 7, 25, 32, 255] {
            assert!(nft_batch((pool.0, prefix), &HashSet::new(), &Inventory::default()).is_err());
        }
        assert!(validate_pool((pool.0 + 1, 15)).is_err());
        assert!(valid_client(ip("198.18.0.1"), pool));
        assert!(valid_client(ip("198.19.255.254"), pool));
    }

    #[test]
    fn nft_authorization_rechecks_scoped_trust_not_just_cached_tun_bits() {
        use crate::trust::{Trust, USE};
        let node = leviculum_std::api::generate_identity();
        let holder = leviculum_std::api::generate_identity().public_key_bytes();
        let root = *node.hash();
        let mut tr = Trust::new(node, None);
        tr.issue(root, holder, USE).unwrap();
        let link = leviculum_std::api::LinkId::new([71; 16]);
        let peers = [(link, holder)];
        let permissions = [link].into();
        let allowed = [(link, ip("198.18.1.7"))].into();
        assert!(authorized_clients(&tr, &peers, &permissions, &allowed).is_empty());
        // A signed record for a different node is never a fallback grant.
        let other = tr.sign_host_access(root, [42; 16], holder, true).unwrap();
        assert!(tr.accept_host_access(other).is_err());
        assert!(authorized_clients(&tr, &peers, &permissions, &allowed).is_empty());
        let grant = tr.sign_host_access(root, root, holder, true).unwrap();
        tr.accept_host_access(grant).unwrap();
        assert_eq!(authorized_clients(&tr, &peers, &permissions, &allowed).len(), 1);
        assert!(authorized_clients(&tr, &[], &permissions, &allowed).is_empty(), "closed Link");
        assert!(authorized_clients(&tr, &peers, &permissions, &Default::default()).is_empty(), "disallowed Link");
        let revoke = tr.sign_host_access(root, root, holder, false).unwrap();
        tr.accept_host_access(revoke).unwrap();
        assert!(authorized_clients(&tr, &peers, &permissions, &allowed).is_empty(), "stale TUN bits cannot restore revoke");
    }

    #[test]
    fn nft_cli_failure_timeout_and_stalled_stdin_are_bounded_and_silent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kh-nft-cli-{}-{}", std::process::id(), crate::now_ms()));
        fs::create_dir(&dir).unwrap();
        let tool = dir.join("nft");
        fs::write(&tool, "#!/bin/sh\ncat >/dev/null\nexit 0\n").unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(run_nft(tool.to_str().unwrap(), NFT_CLEAR, NFT_TIMEOUT).is_ok());
        fs::write(&tool, "#!/bin/sh\nexit 1\n").unwrap();
        assert!(run_nft(tool.to_str().unwrap(), NFT_CLEAR, NFT_TIMEOUT).is_err());
        // A child which neither reads stdin nor exits must also be killed/reaped.
        fs::write(&tool, "#!/bin/sh\nwhile :; do :; done\n").unwrap();
        let start = std::time::Instant::now();
        let error = run_nft(tool.to_str().unwrap(), &"x".repeat(32 * 1024), std::time::Duration::from_millis(80)).unwrap_err();
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(error.to_string(), "nft host-access update timed out");
        assert!(run_nft("/does-not-exist", NFT_CLEAR, NFT_TIMEOUT).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nft_child_does_not_inherit_service_environment() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kh-nft-env-{}-{}", std::process::id(), crate::now_ms()));
        fs::create_dir(&dir).unwrap();
        let (tool, out) = (dir.join("nft"), dir.join("env.out"));
        fs::write(&tool, format!("#!/bin/sh\ncat >/dev/null\nenv > {}\nexit 0\n", out.display())).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: тестовая переменная с уникальным именем; другие тесты её не читают.
        unsafe { std::env::set_var("KNOTHOP_TEST_SECRET_ENV", "leak") };
        run_nft(tool.to_str().unwrap(), NFT_CLEAR, NFT_TIMEOUT).unwrap();
        let seen = fs::read_to_string(&out).unwrap();
        assert!(!seen.contains("KNOTHOP_TEST_SECRET_ENV") && !seen.contains("leak"), "{seen}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn startup_clear_retries_transient_failure_but_not_a_permanent_one() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kh-nft-start-{}-{}", std::process::id(), crate::now_ms()));
        fs::create_dir(&dir).unwrap();
        let (tool, count) = (dir.join("nft"), dir.join("count"));
        // Первые два запуска отказывают (холодный старт), третий проходит.
        fs::write(&tool, format!("#!/bin/sh\ncat >/dev/null\necho x >> {c}\n[ $(wc -l < {c}) -ge 3 ]\n", c = count.display())).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        let program: &'static str = Box::leak(tool.to_str().unwrap().to_owned().into_boxed_str());
        let ctl = NftHostAccess { program, pool: (ip("198.18.0.0"), 15) };
        ctl.clear_startup().unwrap();
        assert_eq!(fs::read_to_string(&count).unwrap().lines().count(), 3);
        // Постоянная ошибка (нет таблицы/набора) остаётся ошибкой старта после NFT_STARTUP_TRIES попыток.
        fs::write(&tool, "#!/bin/sh\ncat >/dev/null\nexit 1\n").unwrap();
        assert!(ctl.clear_startup().is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nft_stats_carry_only_counters() {
        let stats = nft_stats();
        for key in ["active", "publish_ok", "publish_fail", "fallback_clears", "last_ok_ms"] {
            assert!(stats.get(key).is_some(), "{key}");
        }
        assert_eq!(stats.as_object().unwrap().len(), 5);
    }
}
