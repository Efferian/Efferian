use std::collections::BTreeSet;

use efferian_protocol::PrincipalId;

use crate::{
    AuthContext, AuthzError, MAX_ORCHESTRATOR_ENROLLMENT_TTL_MS, NodeAuthTarget,
    OrchestratorLimits,
    policy::{ActiveContext, guard},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentRequest {
    pub is_reenroll: bool,
    pub requested_tags: BTreeSet<String>,
    pub managed_by_principal_id: Option<PrincipalId>,
    pub ttl_ms: i64,
}

pub fn authorize_node_enrollment(
    ctx: &AuthContext,
    request: &EnrollmentRequest,
    policy: &OrchestratorLimits,
) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    if request.ttl_ms <= 0 || ctx.now_ms.checked_add(request.ttl_ms).is_none() {
        return Err(AuthzError::InvalidTtl);
    }
    if request.is_reenroll {
        return active.require_admin();
    }
    if active.global_admin() {
        return active.require_unrestricted();
    }
    if !ctx.caller.orchestrator()
        || request.managed_by_principal_id != Some(ctx.caller.principal_id)
    {
        return Err(AuthzError::Forbidden);
    }
    active.require_unrestricted()?;
    if request.ttl_ms
        > policy
            .enrollment_ttl_ms
            .min(MAX_ORCHESTRATOR_ENROLLMENT_TTL_MS)
    {
        return Err(AuthzError::InvalidTtl);
    }
    if let Some(tag) = request
        .requested_tags
        .difference(&ctx.caller.allowed_node_tags)
        .next()
    {
        return Err(AuthzError::NodeTagNotAllowed { tag: tag.clone() });
    }
    Ok(())
}

pub fn authorize_node_read(ctx: &AuthContext, node: &NodeAuthTarget) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    if active.unrestricted_admin() {
        return Ok(());
    }
    check_orchestrator_node(active, node)?;
    if !ctx.token.permits_node(Some(node.node_id)) {
        return Err(AuthzError::ScopeNarrowedOut);
    }
    Ok(())
}

pub fn authorize_node_revoke_or_delete(
    ctx: &AuthContext,
    node: &NodeAuthTarget,
) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    if !active.global_admin() {
        check_orchestrator_node(active, node)?;
    }
    active.require_unrestricted()
}

fn check_orchestrator_node(
    active: ActiveContext<'_>,
    node: &NodeAuthTarget,
) -> Result<(), AuthzError> {
    let caller = &active.context().caller;
    if !caller.orchestrator() || node.managed_by_principal_id != Some(caller.principal_id) {
        return Err(AuthzError::Forbidden);
    }
    Ok(())
}
