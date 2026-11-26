use serde::{Deserialize, Serialize};

use crate::ProfileId;

macro_rules! wire_enum {
    ($(#[$attr:meta])* pub enum $name:ident { $($variants:tt)* }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$attr])*
        pub enum $name { $($variants)* }
    };
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum PrincipalKind { Admin, Member, Agent, Service }
}

wire_enum! {
    #[derive(PartialOrd, Ord)]
    #[serde(rename_all = "snake_case")]
    pub enum Capability { Discover, Invoke, Admin }
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

        Ok(match Scope::deserialize(deserializer)? {
            Scope::Global {} => Self::Global,
            Scope::Profile { scope_id } => Self::Profile(scope_id),
        })
    }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum DiscoveryMode { Full, Curated, Search }
}

wire_enum! {
    #[derive(Default)]
    #[serde(rename_all = "snake_case")]
    pub enum ExecutionMode { #[default] Auto, Async }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum InvokeKind { Profile, ToolTest }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum ExecutorKind { Node, Upstream }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum PlatformOs { Linux, Macos }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum AccountVisibility { Private, Shared }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum AccountKind { HttpAuth, SshKey, SecretKv }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum UpstreamAccountMode { None, SharedAccount, CallerBound }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum AccountNotBoundReason { MissingBinding, OwnerDisabled, InheritDisabled }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum ToolKind { Command, Script, Http, Ssh, UpstreamRef }
}

wire_enum! {
    #[serde(rename_all = "UPPERCASE")]
    pub enum HttpMethod { Get, Post, Put, Patch, Delete, Head }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum ExecutionState { Accepted, Running, Succeeded, Failed, Cancelled, TimedOut, Unknown }
}

impl ExecutionState {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Accepted | Self::Running)
    }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum TerminalExecutionState { Succeeded, Failed, Cancelled, TimedOut, Unknown }
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
    #[serde(rename_all = "snake_case")]
    pub enum OutputDiscardedReason { RamCap }
}

wire_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum AggregateType { Execution, Node, Profile, Principal, Token }
}
