use std::collections::BTreeSet;

use efferian_authz::*;
use efferian_protocol::*;

#[path = "authorization/access.rs"]
mod access;
#[path = "authorization/accounts.rs"]
mod accounts;
#[path = "authorization/delegation.rs"]
mod delegation;

fn principal(kind: PrincipalKind) -> PrincipalView {
    PrincipalView {
        principal_id: PrincipalId::new_for_kind(kind),
        kind,
        owner_principal_id: None,
        managed_by_principal_id: None,
        inherit_owner_bindings: false,
        is_orchestrator: false,
        allowed_node_tags: BTreeSet::new(),
        observe_executions: false,
        disabled_at_ms: None,
    }
}

fn context(caller: PrincipalView, grants: Vec<GrantView>) -> AuthContext {
    AuthContext {
        token: TokenScope {
            token_id: TokenId::new_for_kind(caller.kind),
            principal_id: caller.principal_id,
            max_capability: None,
            allowed_profiles: None,
            allowed_nodes: None,
            withhold_sensitive: false,
            expires_at_ms: None,
            revoked_at_ms: None,
        },
        caller,
        caller_grants: grants,
        owner: None,
        owner_grants: Vec::new(),
        managed_by: None,
        managed_by_grants: Vec::new(),
        now_ms: 1_000,
    }
}

fn admin() -> AuthContext {
    context(
        principal(PrincipalKind::Admin),
        vec![global(Capability::Admin)],
    )
}

fn orchestrator() -> PrincipalView {
    PrincipalView {
        is_orchestrator: true,
        allowed_node_tags: BTreeSet::from(["sandbox".to_owned()]),
        ..principal(PrincipalKind::Service)
    }
}

fn child(owner: Option<&PrincipalView>, manager: Option<&PrincipalView>) -> PrincipalView {
    PrincipalView {
        owner_principal_id: owner.map(|p| p.principal_id),
        managed_by_principal_id: manager.map(|p| p.principal_id),
        ..principal(PrincipalKind::Agent)
    }
}

fn child_context(
    owner: Option<&AuthContext>,
    manager: Option<&AuthContext>,
    child_grants: Vec<GrantView>,
) -> AuthContext {
    let child = child(owner.map(|ctx| &ctx.caller), manager.map(|ctx| &ctx.caller));
    AuthContext {
        owner: owner.map(|ctx| ctx.caller.clone()),
        owner_grants: owner
            .map(|ctx| ctx.caller_grants.clone())
            .unwrap_or_default(),
        managed_by: manager.map(|ctx| ctx.caller.clone()),
        managed_by_grants: manager
            .map(|ctx| ctx.caller_grants.clone())
            .unwrap_or_default(),
        ..context(child, child_grants)
    }
}

fn global(capability: Capability) -> GrantView {
    GrantView {
        scope: GrantScope::Global,
        capability,
    }
}

fn grant(profile: ProfileId, capability: Capability) -> GrantView {
    GrantView {
        scope: GrantScope::Profile(profile),
        capability,
    }
}

fn node(manager: Option<PrincipalId>) -> NodeAuthTarget {
    NodeAuthTarget {
        node_id: NodeId::new(),
        managed_by_principal_id: manager,
    }
}

fn managed(node: &NodeAuthTarget) -> ExecutionTarget<'_> {
    ExecutionTarget::Managed {
        selected_id: node.node_id,
        node: Some(node),
    }
}

fn upstream(upstream_id: UpstreamId, account: UpstreamAccountMode) -> ExecutionTarget<'static> {
    ExecutionTarget::Upstream {
        upstream_id,
        account,
    }
}

fn denied<T>(result: Result<T, AuthzError>, expected: AuthzError, status: u16, code: &str) {
    let err = result.err();
    assert_eq!(err.as_ref(), Some(&expected));
    assert_eq!(err.as_ref().map(AuthzError::code), Some(code));
    assert_eq!(err.as_ref().map(AuthzError::status_code), Some(status));
}

fn narrowed_tokens(current: &TokenScope) -> [TokenScope; 4] {
    [
        TokenScope {
            max_capability: Some(Capability::Admin),
            ..current.clone()
        },
        TokenScope {
            allowed_profiles: Some(BTreeSet::from([ProfileId::new()])),
            ..current.clone()
        },
        TokenScope {
            allowed_nodes: Some(BTreeSet::new()),
            ..current.clone()
        },
        TokenScope {
            withhold_sensitive: true,
            ..current.clone()
        },
    ]
}
