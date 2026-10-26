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
}
