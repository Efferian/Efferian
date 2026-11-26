//! Pure IP and URL policy shared by all egress transports.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net};
use url::{Host, Url};

use crate::validate::valid_dns_name;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    allowed_egress_cidrs: Vec<IpNet>,
    pub allow_insecure_http_egress: bool,
}

impl EgressPolicy {
    pub fn from_cidrs(cidrs: &[&str], allow_insecure_http_egress: bool) -> Result<Self, SsrfError> {
        let allowed_egress_cidrs = cidrs
            .iter()
            .map(|cidr| normalize_cidr(cidr))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            allowed_egress_cidrs,
            allow_insecure_http_egress,
        })
    }

    pub fn allowed_egress_cidrs(&self) -> &[IpNet] {
        &self.allowed_egress_cidrs
    }
}

fn normalize_cidr(cidr: &str) -> Result<IpNet, SsrfError> {
    let network: IpNet = cidr.parse().map_err(|_| SsrfError::InvalidCidr)?;
    if let IpNet::V6(v6) = network
        && let Some(v4) = v6.addr().to_ipv4_mapped()
    {
        let prefix = v6
            .prefix_len()
            .checked_sub(96)
            .ok_or(SsrfError::InvalidCidr)?;
        let v4 = Ipv4Net::new(v4, prefix).map_err(|_| SsrfError::InvalidCidr)?;
        return Ok(IpNet::V4(v4.trunc()));
    }
    Ok(network.trunc())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SsrfError {
    #[error("invalid or ambiguous egress CIDR")]
    InvalidCidr,
    #[error("invalid egress URL syntax")]
    InvalidUrl,
    #[error("egress URL scheme must be HTTP or HTTPS")]
    InvalidScheme,
    #[error("egress URL must have a host")]
    MissingHost,
    #[error("egress URL userinfo is forbidden")]
    UserinfoForbidden,
    #[error("egress host percent escapes and IPv6 zone IDs are forbidden")]
    Ipv6ZoneIdForbidden,
    #[error("egress URL fragment is forbidden")]
    FragmentForbidden,
    #[error("egress is disallowed to {0}")]
    DisallowedIp(IpAddr),
    #[error("plaintext egress requires an allowed loopback IP literal or an explicit opt-in")]
    InsecureHttpForbidden,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressUrlMode {
    /// Managed HTTP without credentials.
    Plain,
    /// Upstreams and managed HTTP with credentials.
    RequireHttpsByDefault,
}

pub const fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => ip,
    }
}

// Kept explicit even where a broader entry covers a network. These are the v0
// policy ranges, rather than a claim about every IANA special-purpose network.
const BLOCKED_V4: [(u32, u8); 15] = [
    (v4(0, 0, 0, 0), 8),
    (v4(10, 0, 0, 0), 8),
    (v4(100, 64, 0, 0), 10),
    (v4(127, 0, 0, 0), 8),
    (v4(169, 254, 0, 0), 16),
    (v4(172, 16, 0, 0), 12),
    (v4(192, 0, 0, 0), 24),
    (v4(192, 0, 2, 0), 24),
    (v4(192, 168, 0, 0), 16),
    (v4(198, 18, 0, 0), 15),
    (v4(198, 51, 100, 0), 24),
    (v4(203, 0, 113, 0), 24),
    (v4(224, 0, 0, 0), 4),
    (v4(240, 0, 0, 0), 4),
    (v4(255, 255, 255, 255), 32),
];

const BLOCKED_V6: [(u128, u8); 15] = [
    (Ipv6Addr::UNSPECIFIED.to_bits(), 128),
    (Ipv6Addr::LOCALHOST.to_bits(), 128),
    (Ipv6Addr::UNSPECIFIED.to_bits(), 96), // Deprecated IPv4-compatible form.
    (Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0, 0).to_bits(), 96), // IPv4-translated.
    (v6(0x64, 0xff9b, 0), 96),             // NAT64 well-known prefix.
    (v6(0x64, 0xff9b, 1), 48),             // NAT64 local-use prefix.
    (v6(0x100, 0, 0), 64),
    (v6(0x2001, 0xdb8, 0), 32),
    (v6(0x2001, 0x10, 0), 28),
    (v6(0x2001, 0, 0), 32),
    (v6(0x2002, 0, 0), 16),
    (v6(0xfc00, 0, 0), 7),
    (v6(0xfe80, 0, 0), 10),
    (v6(0xfec0, 0, 0), 10),
    (v6(0xff00, 0, 0), 8),
];

const fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    Ipv4Addr::new(a, b, c, d).to_bits()
}

const fn v6(a: u16, b: u16, c: u16) -> u128 {
    Ipv6Addr::new(a, b, c, 0, 0, 0, 0, 0).to_bits()
}

pub const fn is_globally_routable_ip(ip: IpAddr) -> bool {
    match canonicalize_ip(ip) {
        IpAddr::V4(addr) => {
            let mut index = 0;
            while index < BLOCKED_V4.len() {
                let (net, prefix) = BLOCKED_V4[index];
                if (addr.to_bits() ^ net) >> (32 - prefix) == 0 {
                    return false;
                }
                index += 1;
            }
        }
        IpAddr::V6(addr) => {
            let mut index = 0;
            while index < BLOCKED_V6.len() {
                let (net, prefix) = BLOCKED_V6[index];
                if (addr.to_bits() ^ net) >> (128 - prefix) == 0 {
                    return false;
                }
                index += 1;
            }
        }
    }
    true
}

pub fn is_allowed_egress_ip(ip: IpAddr, policy: &EgressPolicy) -> bool {
    let ip = canonicalize_ip(ip);
    policy
        .allowed_egress_cidrs
        .iter()
        .any(|net| net.contains(&ip))
        || is_globally_routable_ip(ip)
}

/// Validate the URL before transport. Apply the same IP policy to all resolved
/// destinations at connection time.
pub fn validate_egress_url(
    raw: &str,
    policy: &EgressPolicy,
    mode: EgressUrlMode,
) -> Result<Url, SsrfError> {
    if raw.is_empty() || raw.trim() != raw || raw.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(SsrfError::InvalidUrl);
    }
    let (scheme, after_scheme) = raw.split_once("://").ok_or(SsrfError::InvalidUrl)?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(SsrfError::InvalidScheme);
    }

    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    if authority.is_empty() {
        return Err(SsrfError::MissingHost);
    }
    if authority.contains('\\') {
        return Err(SsrfError::InvalidUrl);
    }
    if authority.contains('@') {
        return Err(SsrfError::UserinfoForbidden);
    }
    if authority.contains('%') {
        return Err(SsrfError::Ipv6ZoneIdForbidden);
    }

    let url = Url::parse(raw).map_err(|_| SsrfError::InvalidUrl)?;
    if !scheme.eq_ignore_ascii_case(url.scheme()) {
        return Err(SsrfError::InvalidScheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SsrfError::UserinfoForbidden);
    }
    if url.fragment().is_some() {
        return Err(SsrfError::FragmentForbidden);
    }

    let literal = match url.host().ok_or(SsrfError::MissingHost)? {
        Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        Host::Ipv6(ip) => Some(canonicalize_ip(IpAddr::V6(ip))),
        Host::Domain(name) => {
            if !valid_dns_name(name.strip_suffix('.').unwrap_or(name)) {
                return Err(SsrfError::InvalidUrl);
            }
            None
        }
    };
    if let Some(ip) = literal
        && !is_allowed_egress_ip(ip, policy)
    {
        return Err(SsrfError::DisallowedIp(ip));
    }
    if mode == EgressUrlMode::RequireHttpsByDefault
        && url.scheme() == "http"
        && !policy.allow_insecure_http_egress
        && !literal.is_some_and(|ip| ip.is_loopback())
    {
        return Err(SsrfError::InsecureHttpForbidden);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_match_the_published_policy() {
        let v4 = BLOCKED_V4.map(|(addr, prefix)| format!("{}/{prefix}", Ipv4Addr::from_bits(addr)));
        assert_eq!(
            v4,
            [
                "0.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.0.0.0/24",
                "192.0.2.0/24",
                "192.168.0.0/16",
                "198.18.0.0/15",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "224.0.0.0/4",
                "240.0.0.0/4",
                "255.255.255.255/32",
            ]
        );
        let v6 = BLOCKED_V6.map(|(addr, prefix)| format!("{}/{prefix}", Ipv6Addr::from_bits(addr)));
        assert_eq!(
            v6,
            [
                "::/128",
                "::1/128",
                "::/96",
                "::ffff:0:0:0/96",
                "64:ff9b::/96",
                "64:ff9b:1::/48",
                "100::/64",
                "2001:db8::/32",
                "2001:10::/28",
                "2001::/32",
                "2002::/16",
                "fc00::/7",
                "fe80::/10",
                "fec0::/10",
                "ff00::/8",
            ]
        );
    }
}
