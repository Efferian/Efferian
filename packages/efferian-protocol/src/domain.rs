use serde::{Deserialize, Serialize};

use crate::ProfileId;

macro_rules! wire_enum {
    ($($definition:tt)*) => {
        crate::wire::string_enum! {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
            #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
            $($definition)*
        }
    };
}

wire_enum! {
    pub enum PrincipalKind {
        Admin => "admin",
        Member => "member",
        Agent => "agent",
        Service => "service",
    }
}

wire_enum! {
    #[derive(PartialOrd, Ord)]
    pub enum Capability {
        Discover => "discover",
        Invoke => "invoke",
        Admin => "admin",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "scope_kind", content = "scope_id", rename_all = "snake_case")]
pub enum GrantScope {
    Global,
    Profile(ProfileId),
}

#[cfg(feature = "openapi")]
impl utoipa::PartialSchema for GrantScope {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        use crate::wire::schema::{closed_object, string_tag};
        use utoipa::openapi::schema::OneOfBuilder;

        OneOfBuilder::new()
            .item(
                closed_object()
                    .property("scope_kind", string_tag("global"))
                    .required("scope_kind"),
            )
            .item(
                closed_object()
                    .property("scope_kind", string_tag("profile"))
                    .required("scope_kind")
                    .property("scope_id", ProfileId::schema())
                    .required("scope_id"),
            )
            .into()
    }
}

#[cfg(feature = "openapi")]
impl utoipa::ToSchema for GrantScope {}

impl GrantScope {
    pub const fn scope_kind_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Profile(_) => "profile",
        }
    }

    pub fn scope_id_string(self) -> String {
        match self {
            Self::Global => String::new(),
            Self::Profile(id) => id.to_string(),
        }
    }
}

impl<'de> Deserialize<'de> for GrantScope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "scope_kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Scope {
            Global {},
            Profile { scope_id: ProfileId },
        }

        Ok(
            match crate::wire::deserialize_tagged_object(deserializer, "scope_kind")? {
                Scope::Global {} => Self::Global,
                Scope::Profile { scope_id } => Self::Profile(scope_id),
            },
        )
    }
}

wire_enum! {
    pub enum DiscoveryMode {
        Full => "full",
        Curated => "curated",
        Search => "search",
    }
}

wire_enum! {
    #[derive(Default)]
    pub enum ExecutionMode {
        #[default] Auto => "auto",
        Async => "async",
    }
}

wire_enum! {
    pub enum InvokeKind {
        Profile => "profile",
        ToolTest => "tool_test",
    }
}

wire_enum! {
    pub enum ExecutorKind {
        Node => "node",
        Upstream => "upstream",
    }
}

wire_enum! {
    pub enum PlatformOs {
        Linux => "linux",
        Macos => "macos",
    }
}

wire_enum! {
    pub enum AccountVisibility {
        Private => "private",
        Shared => "shared",
    }
}

wire_enum! {
    pub enum AccountKind {
        HttpAuth => "http_auth",
        SshKey => "ssh_key",
        SecretKv => "secret_kv",
    }
}

wire_enum! {
    pub enum UpstreamAccountMode {
        None => "none",
        SharedAccount => "shared_account",
        CallerBound => "caller_bound",
    }
}

wire_enum! {
    pub enum AccountNotBoundReason {
        MissingBinding => "missing_binding",
        OwnerDisabled => "owner_disabled",
        InheritDisabled => "inherit_disabled",
    }
}

wire_enum! {
    pub enum ToolKind {
        Command => "command",
        Script => "script",
        Http => "http",
        Ssh => "ssh",
        UpstreamRef => "upstream_ref",
    }
}

wire_enum! {
    pub enum HttpMethod {
        Get => "GET",
        Post => "POST",
        Put => "PUT",
        Patch => "PATCH",
        Delete => "DELETE",
        Head => "HEAD",
    }
}

wire_enum! {
    pub enum ExecutionState {
        Accepted => "accepted",
        Running => "running",
        Succeeded => "succeeded",
        Failed => "failed",
        Cancelled => "cancelled",
        TimedOut => "timed_out",
        Unknown => "unknown",
    }
}

impl ExecutionState {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Accepted | Self::Running)
    }
}

wire_enum! {
    pub enum TerminalExecutionState {
        Succeeded => "succeeded",
        Failed => "failed",
        Cancelled => "cancelled",
        TimedOut => "timed_out",
        Unknown => "unknown",
    }
}

impl From<TerminalExecutionState> for ExecutionState {
    fn from(state: TerminalExecutionState) -> Self {
        match state {
            TerminalExecutionState::Succeeded => Self::Succeeded,
            TerminalExecutionState::Failed => Self::Failed,
            TerminalExecutionState::Cancelled => Self::Cancelled,
            TerminalExecutionState::TimedOut => Self::TimedOut,
            TerminalExecutionState::Unknown => Self::Unknown,
        }
    }
}

wire_enum! {
    pub enum OutputDiscardedReason {
        RamCap => "ram_cap",
    }
}

wire_enum! {
    pub enum AggregateType {
        Execution => "execution",
        Node => "node",
        Profile => "profile",
        Principal => "principal",
        Token => "token",
    }
}
