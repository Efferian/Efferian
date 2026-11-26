use std::collections::BTreeSet;

use efferian_protocol::{Capability, NodeId, PrincipalKind, ProfileId};

use crate::{
    AuthContext, AuthzError, PrincipalView,
    policy::{ActiveContext, guard},
};

pub const MAX_ORCHESTRATOR_AGENT_TOKEN_TTL_MS: i64 = 24 * 60 * 60 * 1000;
pub const MAX_ORCHESTRATOR_ENROLLMENT_TTL_MS: i64 = 15 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrchestratorLimits {
    pub agent_token_ttl_ms: i64,
    pub enrollment_ttl_ms: i64,
}

impl Default for OrchestratorLimits {
    fn default() -> Self {
        Self {
            agent_token_ttl_ms: MAX_ORCHESTRATOR_AGENT_TOKEN_TTL_MS,
            enrollment_ttl_ms: MAX_ORCHESTRATOR_ENROLLMENT_TTL_MS,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenMintRequest {
    pub max_capability: Option<Capability>,
    pub allowed_profiles: Option<BTreeSet<ProfileId>>,
    pub allowed_nodes: Option<BTreeSet<NodeId>>,
    pub withhold_sensitive: bool,
    pub expires_at_ms: Option<i64>,
}

pub fn authorize_token_mint(
    ctx: &AuthContext,
    target: &PrincipalView,
    request: &TokenMintRequest,
    policy: &OrchestratorLimits,
    managed_node_ids: &BTreeSet<NodeId>,
) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    target.validate()?;
    let orchestrator_mint = ctx.caller.orchestrator() && active.manages(target);
    if !orchestrator_mint {
        authorize_token_operator(active, target)?;
        active.require_unrestricted()?;
    }
    if request
        .expires_at_ms
        .is_some_and(|expires| expires <= ctx.now_ms)
    {
        return Err(AuthzError::InvalidTtl);
    }
    if request.max_capability == Some(Capability::Admin) && target.kind != PrincipalKind::Admin {
        return Err(AuthzError::AdminHumanRequired);
    }
    if orchestrator_mint {
        check_orchestrator_attenuation(ctx, request, policy, managed_node_ids)?;
    }
    Ok(())
}

pub fn authorize_token_revoke(ctx: &AuthContext, target: &PrincipalView) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    target.validate()?;
    authorize_token_operator(active, target)?;
    active.require_unrestricted()
}

fn authorize_token_operator(
    active: ActiveContext<'_>,
    target: &PrincipalView,
) -> Result<(), AuthzError> {
    let caller = &active.context().caller;
    let member = caller.kind == PrincipalKind::Member
        && (caller.principal_id == target.principal_id || active.owns(target));
    if active.global_admin() || member || (caller.orchestrator() && active.manages(target)) {
        return Ok(());
    }
    Err(AuthzError::Forbidden)
}

fn check_orchestrator_attenuation(
    ctx: &AuthContext,
    child: &TokenMintRequest,
    policy: &OrchestratorLimits,
    managed_node_ids: &BTreeSet<NodeId>,
) -> Result<(), AuthzError> {
    let parent = &ctx.token;
    let expiry = child
        .expires_at_ms
        .ok_or(AuthzError::TokenAmplification("expires_at_ms"))?;
    let ttl = i128::from(expiry) - i128::from(ctx.now_ms);
    let cap = policy
        .agent_token_ttl_ms
        .min(MAX_ORCHESTRATOR_AGENT_TOKEN_TTL_MS);
    if ttl > i128::from(cap) {
        return Err(AuthzError::InvalidTtl);
    }
    if parent
        .expires_at_ms
        .is_some_and(|parent_exp| expiry > parent_exp)
    {
        return Err(AuthzError::TokenAmplification("expires_at_ms"));
    }
    if parent
        .max_capability
        .is_some_and(|parent_cap| child.max_capability.is_none_or(|cap| cap > parent_cap))
    {
        return Err(AuthzError::TokenAmplification("max_capability"));
    }
    if !is_attenuated(&parent.allowed_profiles, &child.allowed_profiles) {
        return Err(AuthzError::TokenAmplification("allowed_profiles"));
    }
    if !is_attenuated(&parent.allowed_nodes, &child.allowed_nodes) {
        return Err(AuthzError::TokenAmplification("allowed_nodes"));
    }
    if parent.withhold_sensitive && !child.withhold_sensitive {
        return Err(AuthzError::TokenAmplification("withhold_sensitive"));
    }
    if child
        .allowed_nodes
        .as_ref()
        .is_some_and(|nodes| !nodes.is_subset(managed_node_ids))
    {
        return Err(AuthzError::TokenAmplification("unmanaged_node"));
    }
    Ok(())
}

fn is_attenuated<T: Ord>(parent: &Option<BTreeSet<T>>, child: &Option<BTreeSet<T>>) -> bool {
    parent
        .as_ref()
        .is_none_or(|parent| child.as_ref().is_some_and(|child| child.is_subset(parent)))
}
