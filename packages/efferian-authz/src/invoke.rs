use efferian_protocol::{
    AccountId, AccountNotBoundReason, Capability, NodeId, ProfileId, UpstreamAccountMode,
    UpstreamId,
};

use crate::{
    AuthContext, AuthzError, ExecutionAccess, ExecutionAuthTarget, InvokeBindingView,
    NodeAuthTarget,
    account::resolve_caller_bound_account,
    authorize_execution_access,
    policy::{ActiveContext, CheckedContext, Phase, guard, verify_context},
};

/// The executor selected by the catalog and the actual node row when applicable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionTarget<'a> {
    Managed {
        selected_id: NodeId,
        node: Option<&'a NodeAuthTarget>,
    },
    Upstream {
        upstream_id: UpstreamId,
        account: UpstreamAccountMode,
    },
}

/// The dependency missing from an exact retained binding. Target evidence from
/// a deleted tool can establish scope for an active caller. Only a surviving
/// tool can establish route visibility during an activity failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchivedDependency<'a> {
    Tool {
        target_evidence: Option<ExecutionTarget<'a>>,
    },
    Account {
        target: ExecutionTarget<'a>,
    },
}

pub fn authorize_profile_discover(
    ctx: &AuthContext,
    published_profile: Option<ProfileId>,
) -> Result<(), AuthzError> {
    discover(guard(ctx)?.checked(), published_profile).map(|_| ())
}

pub fn authorize_discovery_target(
    ctx: &AuthContext,
    profile_id: ProfileId,
    target: ExecutionTarget<'_>,
) -> Result<(), AuthzError> {
    let checked = guard(ctx)?.checked();
    discover(checked, Some(profile_id))?;
    check_target_scope(checked, target)
}

/// Check catalog visibility and scope before fetching any caller-bound rows.
/// A successful result permits only that lookup.
pub fn check_profile_invoke_metadata(
    ctx: &AuthContext,
    published_profile: Option<ProfileId>,
    target: Option<ExecutionTarget<'_>>,
) -> Result<(), AuthzError> {
    profile_invoke_gate(ctx, published_profile, target).map(|_| ())
}

/// Authorize the actual target. For caller-bound upstreams return the exact
/// account that the Hub may open. Other execution modes select credentials
/// from their validated tool revision.
pub fn authorize_profile_invoke(
    ctx: &AuthContext,
    published_profile: Option<ProfileId>,
    target: Option<ExecutionTarget<'_>>,
    bindings: &[InvokeBindingView],
) -> Result<Option<AccountId>, AuthzError> {
    let (active, target) = profile_invoke_gate(ctx, published_profile, target)?;
    resolve_target_account(active, target, bindings)
}

/// Authorize an existing invocation before comparing its recorded intent.
/// The execution target is read from history, independently of live catalog
/// dependencies and node inventory.
pub fn authorize_profile_invoke_replay(
    ctx: &AuthContext,
    published_profile: Option<ProfileId>,
    recorded: &ExecutionAuthTarget,
) -> Result<(), AuthzError> {
    let checked = verify_context(ctx)?;
    match checked.active(Phase::Invoke) {
        Ok(_) => {
            let capability = discover(checked, published_profile)?;
            authorize_execution_access(ctx, Some(recorded), ExecutionAccess::ReadMetadata)?;
            require_invoke(capability)
        }
        Err(AuthzError::OwnerDisabled) => {
            let capability = discover(checked, published_profile)?;
            if recorded.caller_principal_id != ctx.caller.principal_id
                || !ctx.token.permits_profile(recorded.profile_id)
                || !ctx.token.permits_node(recorded.node_id)
            {
                return Err(AuthzError::ResourceNotFound);
            }
            require_invoke(capability)?;
            Err(AuthzError::OwnerDisabled)
        }
        Err(error) => Err(error),
    }
}

/// Check a retained binding whose referenced tool or fixed account is gone.
/// The caller must supply the exact archived binding's profile and any target
/// evidence available in the snapshot.
pub fn check_archived_invoke_metadata(
    ctx: &AuthContext,
    published_profile: Option<ProfileId>,
    missing: ArchivedDependency<'_>,
) -> Result<(), AuthzError> {
    let checked = verify_context(ctx)?;
    if let Err(error) = checked.active(Phase::Invoke) {
        if error == AuthzError::OwnerDisabled {
            let live_target = match missing {
                ArchivedDependency::Tool { .. } => None,
                ArchivedDependency::Account { target } => Some(target),
            };
            return Err(disabled_owner_invoke_error(
                checked,
                published_profile,
                live_target,
            ));
        }
        return Err(error);
    }

    let capability = discover(checked, published_profile)?;
    let target = match missing {
        ArchivedDependency::Tool { target_evidence } => target_evidence,
        ArchivedDependency::Account { target } => Some(target),
    };
    match target {
        Some(target) => match check_target_scope(checked, target) {
            Ok(()) => {}
            Err(AuthzError::ScopeNarrowedOut) => return Err(AuthzError::ResourceNotFound),
            Err(error) => return Err(error),
        },
        None if checked.context().token.allowed_nodes.is_some()
            || checked.context().orchestrator_node_manager().is_some() =>
        {
            return Err(AuthzError::ResourceNotFound);
        }
        None => {}
    }
    require_invoke(capability)
}

pub fn authorize_tool_test(
    ctx: &AuthContext,
    target: ExecutionTarget<'_>,
    bindings: &[InvokeBindingView],
) -> Result<Option<AccountId>, AuthzError> {
    let active = guard(ctx)?;
    active.require_admin()?;
    check_target_scope(active.checked(), target)?;
    resolve_target_account(active, target, bindings)
}

fn discover(
    checked: CheckedContext<'_>,
    published_profile: Option<ProfileId>,
) -> Result<Capability, AuthzError> {
    published_profile
        .and_then(|profile| checked.effective_profile_capability(profile))
        .ok_or(AuthzError::ResourceNotFound)
}

fn require_invoke(capability: Capability) -> Result<(), AuthzError> {
    if capability < Capability::Invoke {
        return Err(AuthzError::InsufficientCapability);
    }
    Ok(())
}

fn check_target_scope(
    checked: CheckedContext<'_>,
    target: ExecutionTarget<'_>,
) -> Result<(), AuthzError> {
    let ctx = checked.context();
    let allowed = match target {
        ExecutionTarget::Managed { selected_id, node } => {
            let node = node
                .filter(|node| node.node_id == selected_id)
                .ok_or(AuthzError::InvalidAuthContext)?;
            ctx.token.permits_node(Some(node.node_id))
                && ctx
                    .orchestrator_node_manager()
                    .is_none_or(|manager| node.managed_by_principal_id == Some(manager))
        }
        ExecutionTarget::Upstream { .. } => ctx.token.permits_node(None),
    };
    if !allowed {
        return Err(AuthzError::ScopeNarrowedOut);
    }
    Ok(())
}

fn profile_invoke_gate<'ctx, 'target>(
    ctx: &'ctx AuthContext,
    published_profile: Option<ProfileId>,
    target: Option<ExecutionTarget<'target>>,
) -> Result<(ActiveContext<'ctx>, ExecutionTarget<'target>), AuthzError> {
    let checked = verify_context(ctx)?;
    let active = match checked.active(Phase::Invoke) {
        Ok(active) => active,
        Err(AuthzError::OwnerDisabled) => {
            return Err(disabled_owner_invoke_error(
                checked,
                published_profile,
                target,
            ));
        }
        Err(error) => return Err(error),
    };
    let capability = discover(checked, published_profile)?;
    let target = target.ok_or(AuthzError::ResourceNotFound)?;
    check_target_scope(checked, target)?;
    require_invoke(capability)?;
    Ok((active, target))
}

/// A disabled owner may affect the shape of a visible error. This path has
/// checked metadata and has no active caller context or access to bindings.
fn disabled_owner_invoke_error(
    checked: CheckedContext<'_>,
    published_profile: Option<ProfileId>,
    target: Option<ExecutionTarget<'_>>,
) -> AuthzError {
    let Some(target) = target else {
        return AuthzError::ResourceNotFound;
    };
    let Ok(capability) = discover(checked, published_profile) else {
        return AuthzError::ResourceNotFound;
    };
    match check_target_scope(checked, target) {
        Ok(()) => {}
        Err(AuthzError::ScopeNarrowedOut) => return AuthzError::ResourceNotFound,
        Err(error) => return error,
    }
    if let Err(error) = require_invoke(capability) {
        return error;
    }
    match target {
        ExecutionTarget::Upstream {
            account: UpstreamAccountMode::CallerBound,
            ..
        } => AuthzError::AccountNotBound {
            reason: AccountNotBoundReason::OwnerDisabled,
        },
        _ => AuthzError::OwnerDisabled,
    }
}

fn resolve_target_account(
    active: ActiveContext<'_>,
    target: ExecutionTarget<'_>,
    bindings: &[InvokeBindingView],
) -> Result<Option<AccountId>, AuthzError> {
    if let ExecutionTarget::Upstream {
        upstream_id,
        account: UpstreamAccountMode::CallerBound,
    } = target
    {
        return resolve_caller_bound_account(active, upstream_id, bindings).map(Some);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use efferian_protocol::{
        Capability, GrantScope, NodeId, PrincipalId, PrincipalKind, ProfileId, TokenId,
    };

    use super::*;
    use crate::{AuthContext, GrantView, NodeAuthTarget, PrincipalView, TokenScope};

    fn base_member_context(
        max_capability: Option<Capability>,
        allowed_nodes: Option<BTreeSet<NodeId>>,
    ) -> (AuthContext, ProfileId) {
        let caller_id = PrincipalId::new_for_kind(PrincipalKind::Member);
        let profile_id = ProfileId::new();
        let ctx = AuthContext {
            caller: PrincipalView {
                principal_id: caller_id,
                kind: PrincipalKind::Member,
                owner_principal_id: None,
                managed_by_principal_id: None,
                inherit_owner_bindings: false,
                is_orchestrator: false,
                allowed_node_tags: BTreeSet::new(),
                observe_executions: false,
                disabled_at_ms: None,
            },
            token: TokenScope {
                token_id: TokenId::new_for_kind(PrincipalKind::Member),
                principal_id: caller_id,
                max_capability,
                allowed_profiles: None,
                allowed_nodes,
                withhold_sensitive: false,
                expires_at_ms: None,
                revoked_at_ms: None,
            },
            caller_grants: vec![GrantView {
                scope: GrantScope::Profile(profile_id),
                capability: Capability::Invoke,
            }],
            owner: None,
            owner_grants: Vec::new(),
            managed_by: None,
            managed_by_grants: Vec::new(),
            now_ms: 1_000,
        };
        (ctx, profile_id)
    }

    #[test]
    fn profile_invoke_gate_checks_target_scope_before_invoke_capability() {
        let allowed_node = NodeId::new();
        let other_node = NodeId::new();
        let (ctx, profile_id) = base_member_context(
            Some(Capability::Discover),
            Some(BTreeSet::from([allowed_node])),
        );
        // Narrowed-out node yields ScopeNarrowedOut (mapped to 404 by discovery/selection),
        // NOT InsufficientCapability (403), even for a Discover-only token.
        let other_target = NodeAuthTarget {
            node_id: other_node,
            managed_by_principal_id: None,
        };
        let target = ExecutionTarget::Managed {
            selected_id: other_node,
            node: Some(&other_target),
        };
        assert_eq!(
            check_profile_invoke_metadata(&ctx, Some(profile_id), Some(target)),
            Err(AuthzError::ScopeNarrowedOut)
        );
        // In-scope node yields InsufficientCapability (403) because token is capped at Discover.
        let allowed_target = NodeAuthTarget {
            node_id: allowed_node,
            managed_by_principal_id: None,
        };
        let in_scope = ExecutionTarget::Managed {
            selected_id: allowed_node,
            node: Some(&allowed_target),
        };
        assert_eq!(
            check_profile_invoke_metadata(&ctx, Some(profile_id), Some(in_scope)),
            Err(AuthzError::InsufficientCapability)
        );
    }

    #[test]
    fn archived_invoke_propagates_invalid_auth_context_instead_of_masking_as_not_found() {
        let (ctx, profile_id) = base_member_context(None, None);
        let mismatched = NodeAuthTarget {
            node_id: NodeId::new(),
            managed_by_principal_id: None,
        };
        let target = ExecutionTarget::Managed {
            selected_id: NodeId::new(),
            node: Some(&mismatched),
        };
        assert_eq!(
            check_archived_invoke_metadata(
                &ctx,
                Some(profile_id),
                ArchivedDependency::Tool {
                    target_evidence: Some(target),
                },
            ),
            Err(AuthzError::InvalidAuthContext)
        );
    }
}
