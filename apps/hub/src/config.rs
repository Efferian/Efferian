//! Operator settings for the Hub.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use efferian_protocol::ssrf::EgressPolicy;
use serde::{Deserialize, Deserializer};

use crate::storage::{SqliteSynchronous, StorageConfig};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    host: String,
    port: Option<u16>,
}

impl FromStr for Authority {
    type Err = InvalidAuthority;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (host, port) = if let Some(raw) = raw.strip_prefix('[') {
            let (literal, suffix) = raw.split_once(']').ok_or(InvalidAuthority)?;
            let ip: Ipv6Addr = literal.parse().map_err(|_| InvalidAuthority)?;
            let port = if suffix.is_empty() {
                None
            } else {
                Some(parse_port(
                    suffix.strip_prefix(':').ok_or(InvalidAuthority)?,
                )?)
            };
            (format!("[{ip}]"), port)
        } else {
            let (host, port) = match raw.split_once(':') {
                Some((host, port)) => (host, Some(parse_port(port)?)),
                None => (raw, None),
            };
            if let Ok(ip) = host.parse::<IpAddr>() {
                (ip.to_string(), port)
            } else if is_dns_name(host) {
                (host.to_ascii_lowercase(), port)
            } else {
                return Err(InvalidAuthority);
            }
        };
        Ok(Self { host, port })
    }
}

fn parse_port(raw: &str) -> Result<u16, InvalidAuthority> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(InvalidAuthority);
    }
    raw.parse().map_err(|_| InvalidAuthority)
}

fn is_dns_name(raw: &str) -> bool {
    raw.len() <= 253
        && raw.split('.').all(|label| {
            let bytes = label.as_bytes();
            bytes.len() <= 63
                && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("expected a DNS name, IPv4 address, or bracketed IPv6 address, with optional port")]
pub struct InvalidAuthority;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    https: bool,
    authority: Authority,
}

impl FromStr for Origin {
    type Err = InvalidOrigin;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (scheme, authority) = raw.split_once("://").ok_or(InvalidOrigin)?;
        let https = scheme.eq_ignore_ascii_case("https");
        if !https && !scheme.eq_ignore_ascii_case("http") {
            return Err(InvalidOrigin);
        }
        Ok(Self {
            https,
            authority: authority.parse().map_err(|_| InvalidOrigin)?,
        })
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("expected an HTTP or HTTPS origin with no path, query, or fragment")]
pub struct InvalidOrigin;

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Synchronous {
    #[default]
    Full,
    Normal,
}

impl FromStr for Synchronous {
    type Err = ();

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "full" => Ok(Self::Full),
            "normal" => Ok(Self::Normal),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    state_dir: Option<PathBuf>,
    pub listen: SocketAddr,
    #[serde(deserialize_with = "deserialize_list")]
    allowed_hosts: Vec<Authority>,
    #[serde(deserialize_with = "deserialize_list")]
    pub allowed_origins: Vec<Origin>,
    pub max_active_tokens_per_principal: usize,
    sqlite_synchronous: Synchronous,
    max_page_count: u32,
    allowed_egress_cidrs: Vec<String>,
    allow_insecure_http_egress: bool,
    pub max_tcp_connections: usize,
    pub max_pre_auth_in_flight: usize,
    pub max_app_requests: usize,
    pub max_requests_per_principal: usize,
    pub max_control_requests: usize,
    pub max_managed_agents_per_member: usize,
    pub max_managed_agents_per_orchestrator: usize,
    pub max_active_nodes_per_orchestrator: usize,
    pub max_pending_enrollments_per_issuer: usize,
    pub orchestrator_agent_token_ttl_ms: i64,
    pub orchestrator_enrollment_ttl_ms: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            state_dir: None,
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            max_active_tokens_per_principal: 64,
            sqlite_synchronous: Synchronous::Full,
            max_page_count: StorageConfig::default().max_page_count,
            allowed_egress_cidrs: Vec::new(),
            allow_insecure_http_egress: false,
            max_tcp_connections: 2048,
            max_pre_auth_in_flight: 128,
            max_app_requests: 1024,
            max_requests_per_principal: 64,
            max_control_requests: 64,
            max_managed_agents_per_member: 16,
            max_managed_agents_per_orchestrator: 256,
            max_active_nodes_per_orchestrator: 256,
            max_pending_enrollments_per_issuer: 64,
            orchestrator_agent_token_ttl_ms: 86_400_000,
            orchestrator_enrollment_ttl_ms: 900_000,
        }
    }
}

#[derive(Default)]
pub struct Overrides {
    pub state_dir: Option<PathBuf>,
    pub listen: Option<SocketAddr>,
    pub allowed_hosts: Option<Vec<Authority>>,
    pub allowed_origins: Option<Vec<Origin>>,
    pub max_active_tokens_per_principal: Option<usize>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read the selected Hub configuration: {0}")]
    Read(#[from] std::io::Error),
    #[error(
        "the selected Hub configuration has invalid TOML, an unknown field, or a malformed value"
    )]
    InvalidToml,
    #[error("invalid Hub setting: {0}")]
    InvalidSetting(&'static str),
    #[error("set the Hub state directory with --state-dir or EFFERIAN_HUB_STATE_DIR")]
    MissingStateDir,
    #[error("non-loopback listen requires a nonempty allowed_hosts list")]
    MissingAllowedHosts,
}

impl Config {
    pub fn load(path: Option<&Path>, overrides: Overrides) -> Result<Self, ConfigError> {
        Self::load_with(path, overrides, |key| env::var_os(key))
    }

    fn load_with(
        path: Option<&Path>,
        overrides: Overrides,
        env: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Self, ConfigError> {
        let mut config: Self = match path {
            Some(path) => {
                toml::from_str(&fs::read_to_string(path)?).map_err(|_| ConfigError::InvalidToml)?
            }
            None => Self::default(),
        };
        config.validate_values()?;
        if let Some(path) = env("EFFERIAN_HUB_STATE_DIR") {
            config.state_dir = Some(path.into());
        }
        macro_rules! overlay {
            ($field:ident, $key:literal) => {
                overlay!($field, $key, str::parse)
            };
            ($field:ident, $key:literal, $parse:expr) => {{
                const VARIABLE: &str = concat!("EFFERIAN_HUB_", $key);
                if let Some(raw) = env(VARIABLE) {
                    let value = raw.to_str().ok_or(ConfigError::InvalidSetting(VARIABLE))?;
                    config.$field =
                        ($parse)(value).map_err(|_| ConfigError::InvalidSetting(VARIABLE))?;
                }
            }};
        }
        overlay!(listen, "LISTEN");
        overlay!(allowed_hosts, "ALLOWED_HOSTS", parse_csv);
        overlay!(allowed_origins, "ALLOWED_ORIGINS", parse_csv);
        overlay!(
            max_active_tokens_per_principal,
            "MAX_ACTIVE_TOKENS_PER_PRINCIPAL"
        );
        overlay!(sqlite_synchronous, "SQLITE_SYNCHRONOUS");
        overlay!(max_page_count, "MAX_PAGE_COUNT");
        overlay!(allowed_egress_cidrs, "ALLOWED_EGRESS_CIDRS", parse_csv);
        overlay!(allow_insecure_http_egress, "ALLOW_INSECURE_HTTP_EGRESS");
        overlay!(max_tcp_connections, "MAX_TCP_CONNECTIONS");
        overlay!(max_pre_auth_in_flight, "MAX_PRE_AUTH_IN_FLIGHT");
        overlay!(max_app_requests, "MAX_APP_REQUESTS");
        overlay!(max_requests_per_principal, "MAX_REQUESTS_PER_PRINCIPAL");
        overlay!(max_control_requests, "MAX_CONTROL_REQUESTS");
        overlay!(
            max_managed_agents_per_member,
            "MAX_MANAGED_AGENTS_PER_MEMBER"
        );
        overlay!(
            max_managed_agents_per_orchestrator,
            "MAX_MANAGED_AGENTS_PER_ORCHESTRATOR"
        );
        overlay!(
            max_active_nodes_per_orchestrator,
            "MAX_ACTIVE_NODES_PER_ORCHESTRATOR"
        );
        overlay!(
            max_pending_enrollments_per_issuer,
            "MAX_PENDING_ENROLLMENTS_PER_ISSUER"
        );
        overlay!(
            orchestrator_agent_token_ttl_ms,
            "ORCHESTRATOR_AGENT_TOKEN_TTL_MS"
        );
        overlay!(
            orchestrator_enrollment_ttl_ms,
            "ORCHESTRATOR_ENROLLMENT_TTL_MS"
        );
        config.validate_values()?;

        if let Some(path) = overrides.state_dir {
            config.state_dir = Some(path);
        }
        if let Some(listen) = overrides.listen {
            config.listen = listen;
        }
        if let Some(hosts) = overrides.allowed_hosts {
            config.allowed_hosts = hosts;
        }
        if let Some(origins) = overrides.allowed_origins {
            config.allowed_origins = origins;
        }
        if let Some(limit) = overrides.max_active_tokens_per_principal {
            config.max_active_tokens_per_principal = limit;
        }
        config.validate_values()?;
        config.state_dir()?;
        Ok(config)
    }

    pub fn state_dir(&self) -> Result<&Path, ConfigError> {
        self.state_dir
            .as_deref()
            .ok_or(ConfigError::MissingStateDir)
    }

    pub fn validate_listen(&self) -> Result<(), ConfigError> {
        if self.listen.ip().is_loopback() || !self.allowed_hosts.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::MissingAllowedHosts)
        }
    }

    pub fn allowed_hosts_for_port(&self, bound_port: u16) -> Vec<Authority> {
        if self.allowed_hosts.is_empty() && self.listen.ip().is_loopback() {
            ["127.0.0.1", "localhost", "[::1]"]
                .into_iter()
                .map(|host| Authority {
                    host: host.to_owned(),
                    port: Some(bound_port),
                })
                .collect()
        } else {
            self.allowed_hosts.clone()
        }
    }

    pub fn storage_config(&self) -> StorageConfig {
        StorageConfig {
            synchronous: match self.sqlite_synchronous {
                Synchronous::Full => SqliteSynchronous::Full,
                Synchronous::Normal => SqliteSynchronous::Normal,
            },
            max_page_count: self.max_page_count,
            ..StorageConfig::default()
        }
    }

    pub fn egress_policy(&self) -> Result<EgressPolicy, ConfigError> {
        let cidrs: Vec<_> = self
            .allowed_egress_cidrs
            .iter()
            .map(String::as_str)
            .collect();
        EgressPolicy::from_cidrs(&cidrs, self.allow_insecure_http_egress)
            .map_err(|_| ConfigError::InvalidSetting("allowed_egress_cidrs"))
    }

    fn validate_values(&self) -> Result<(), ConfigError> {
        if self
            .state_dir
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::InvalidSetting("state_dir"));
        }
        self.storage_config()
            .validate()
            .map_err(|_| ConfigError::InvalidSetting("max_page_count"))?;
        self.egress_policy()?;
        for (key, limit) in [
            ("max_tcp_connections", self.max_tcp_connections),
            ("max_pre_auth_in_flight", self.max_pre_auth_in_flight),
            ("max_app_requests", self.max_app_requests),
            (
                "max_requests_per_principal",
                self.max_requests_per_principal,
            ),
            ("max_control_requests", self.max_control_requests),
        ] {
            if !(1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&limit) {
                return Err(ConfigError::InvalidSetting(key));
            }
        }
        for (key, limit) in [
            (
                "max_active_tokens_per_principal",
                self.max_active_tokens_per_principal,
            ),
            (
                "max_managed_agents_per_member",
                self.max_managed_agents_per_member,
            ),
            (
                "max_managed_agents_per_orchestrator",
                self.max_managed_agents_per_orchestrator,
            ),
            (
                "max_active_nodes_per_orchestrator",
                self.max_active_nodes_per_orchestrator,
            ),
            (
                "max_pending_enrollments_per_issuer",
                self.max_pending_enrollments_per_issuer,
            ),
        ] {
            if limit == 0 {
                return Err(ConfigError::InvalidSetting(key));
            }
        }
        if self.orchestrator_agent_token_ttl_ms <= 0 {
            return Err(ConfigError::InvalidSetting(
                "orchestrator_agent_token_ttl_ms",
            ));
        }
        if self.orchestrator_enrollment_ttl_ms <= 0 {
            return Err(ConfigError::InvalidSetting(
                "orchestrator_enrollment_ttl_ms",
            ));
        }
        Ok(())
    }
}

pub fn state_dir(flag: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
    let path = flag
        .or_else(|| env::var_os("EFFERIAN_HUB_STATE_DIR").map(PathBuf::from))
        .ok_or(ConfigError::MissingStateDir)?;
    if path.as_os_str().is_empty() {
        return Err(ConfigError::InvalidSetting("state_dir"));
    }
    Ok(path)
}

fn deserialize_list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: std::fmt::Display,
{
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|value| value.parse().map_err(serde::de::Error::custom))
        .collect()
}

pub fn parse_csv<T: FromStr>(raw: &str) -> Result<Vec<T>, ConfigError> {
    raw.split(',')
        .map(|element| {
            if element.is_empty() || element.trim() != element {
                return Err(ConfigError::InvalidSetting(
                    "expected nonempty comma-separated values",
                ));
            }
            element
                .parse()
                .map_err(|_| ConfigError::InvalidSetting("invalid comma-separated value"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorities_use_exact_normalized_hosts_and_ports() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(
            "EXAMPLE.test:0443".parse::<Authority>()?,
            "example.test:443".parse()?
        );
        assert_eq!("[0::1]:8080".parse::<Authority>()?, "[::1]:8080".parse()?);
        assert_ne!(
            "example.test".parse::<Authority>()?,
            "example.test:443".parse()?
        );
        for raw in [
            "", "a: ", "a:", "a:b", "a@b", "a.b.", "[::1%lo]", "[::1]foo", "::1",
        ] {
            assert!(raw.parse::<Authority>().is_err(), "{raw}");
        }
        assert_eq!(
            "HTTPS://EXAMPLE.test:8443".parse::<Origin>()?,
            "https://example.test:8443".parse()?
        );
        assert!("https://example.test/".parse::<Origin>().is_err());
        assert!(parse_csv::<Authority>("a, b").is_err());
        assert!(parse_csv::<Authority>("a,").is_err());
        Ok(())
    }

    #[test]
    fn cli_overrides_environment_and_invalid_lower_sources_fail() -> Result<(), ConfigError> {
        let env = |key: &str| match key {
            "EFFERIAN_HUB_STATE_DIR" => Some("env-state".into()),
            "EFFERIAN_HUB_MAX_ACTIVE_TOKENS_PER_PRINCIPAL" => Some("65".into()),
            "EFFERIAN_HUB_LISTEN" => Some("[::1]:0".into()),
            _ => None,
        };
        let config = Config::load_with(
            None,
            Overrides {
                state_dir: Some("flag-state".into()),
                max_active_tokens_per_principal: Some(66),
                ..Overrides::default()
            },
            env,
        )?;
        assert_eq!(config.state_dir()?, Path::new("flag-state"));
        assert_eq!(config.max_active_tokens_per_principal, 66);
        assert_eq!(config.listen, SocketAddr::from((Ipv6Addr::LOCALHOST, 0)));
        assert_eq!(
            config.allowed_hosts_for_port(38123),
            parse_csv::<Authority>("127.0.0.1:38123,localhost:38123,[::1]:38123")?
        );

        let invalid = |key: &str| match key {
            "EFFERIAN_HUB_MAX_ACTIVE_TOKENS_PER_PRINCIPAL" => Some("0".into()),
            _ => env(key),
        };
        assert!(
            Config::load_with(
                None,
                Overrides {
                    max_active_tokens_per_principal: Some(66),
                    ..Overrides::default()
                },
                invalid
            )
            .is_err()
        );
        Ok(())
    }
}
