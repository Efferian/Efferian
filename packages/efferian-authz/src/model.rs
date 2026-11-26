use std::collections::BTreeSet;

use efferian_protocol::{
    AccountId, AccountKind, AccountVisibility, Capability, GrantScope, NodeId, PrincipalId,
    PrincipalKind, ProfileId, TokenId, UpstreamId,
};

use crate::AuthzError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalView {
    pub principal_id: PrincipalId,
    pub kind: PrincipalKind,
    pub owner_principal_id: Option<PrincipalId>,
    pub managed_by_principal_id: Option<PrincipalId>,
    pub inherit_owner_bindings: bool,
    pub is_orchestrator: bool,
    pub allowed_node_tags: BTreeSet<String>,
    pub observe_executions: bool,
    pub disabled_at_ms: Option<i64>,
}

impl PrincipalView {
    pub fn validate(&self) -> Result<(), AuthzError> {
        use PrincipalKind::{Agent, Service};

        if !self.principal_id.matches_kind(self.kind)
            || (self.owner_principal_id.is_some() && self.kind != Agent)
            || (self.inherit_owner_bindings && self.owner_principal_id.is_none())
            || (self.is_orchestrator && self.kind != Service)
            || (!self.allowed_node_tags.is_empty() && !self.is_orchestrator)
            || (self.observe_executions && self.kind != Service)
        {
            return Err(AuthzError::InvalidAuthContext);
        }
        Ok(())
    }

    pub(crate) fn orchestrator(&self) -> bool {
        self.kind == PrincipalKind::Service && self.is_orchestrator
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenScope {
    pub token_id: TokenId,
    pub principal_id: PrincipalId,
    pub max_capability: Option<Capability>,
    pub allowed_profiles: Option<BTreeSet<ProfileId>>,
    pub allowed_nodes: Option<BTreeSet<NodeId>>,
    pub withhold_sensitive: bool,
    pub expires_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}

impl TokenScope {
    pub const fn is_unrestricted(&self) -> bool {
        self.max_capability.is_none()
            && self.allowed_profiles.is_none()
            && self.allowed_nodes.is_none()
            && !self.withhold_sensitive
    }

    pub fn is_active(&self, now_ms: i64) -> bool {
        self.revoked_at_ms.is_none() && self.expires_at_ms.is_none_or(|expiry| expiry > now_ms)
    }

    pub(crate) fn permits_profile(&self, profile_id: Option<ProfileId>) -> bool {
        scope_allows(&self.allowed_profiles, profile_id)
    }

    pub(crate) fn permits_node(&self, node_id: Option<NodeId>) -> bool {
        scope_allows(&self.allowed_nodes, node_id)
    }

    pub(crate) fn permits_capability(&self, required: Capability) -> bool {
        self.max_capability
            .is_none_or(|capability| capability >= required)
    }
}

fn scope_allows<T: Ord>(scope: &Option<BTreeSet<T>>, value: Option<T>) -> bool {
    scope
        .as_ref()
        .is_none_or(|allowed| value.is_some_and(|value| allowed.contains(&value)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantView {
    pub scope: GrantScope,
    pub capability: Capability,
}

/// Trusted projections from the same authorization snapshot. Grants belong to
/// the corresponding principal and exclude grants that are no longer active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthContext {
    pub caller: PrincipalView,
    pub token: TokenScope,
    pub caller_grants: Vec<GrantView>,
    /// Required exactly when the caller has an owner.
    pub owner: Option<PrincipalView>,
    pub owner_grants: Vec<GrantView>,
    /// Required exactly when the caller has a manager.
    pub managed_by: Option<PrincipalView>,
    pub managed_by_grants: Vec<GrantView>,
    pub now_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeAuthTarget {
    pub node_id: NodeId,
    pub managed_by_principal_id: Option<PrincipalId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingView {
    pub principal_id: PrincipalId,
    pub upstream_id: UpstreamId,
    pub account_id: AccountId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountView {
    pub account_id: AccountId,
    pub owner_principal_id: PrincipalId,
    pub visibility: AccountVisibility,
    pub kind: AccountKind,
    pub upstream_id: Option<UpstreamId>,
}

/// An exact binding and its current account from the same authorization snapshot.
/// Keep the binding row even when its account is missing or no longer applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvokeBindingView {
    pub binding: BindingView,
    pub account: Option<AccountView>,
}

/// Existing upstream and the published profiles with a live caller-bound tool
/// from that upstream.
#[derive(Clone, Copy, Debug)]
pub struct BindingUpstream<'a> {
    pub upstream_id: UpstreamId,
    pub caller_bound_profiles: &'a [ProfileId],
}
