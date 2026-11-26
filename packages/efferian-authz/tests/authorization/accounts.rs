use std::cell::Cell;

use super::*;

fn binding(subject: &PrincipalView, upstream_id: UpstreamId) -> BindingView {
    BindingView {
        principal_id: subject.principal_id,
        upstream_id,
        account_id: AccountId::new(),
    }
}

#[test]
fn caller_bound_uses_both_keys_and_never_falls_back_to_other_accounts() {
    let profile = ProfileId::new();
    let grant = grant(profile, Capability::Invoke);
    let a = context(principal(PrincipalKind::Member), vec![grant]);
    let b = context(principal(PrincipalKind::Member), vec![grant]);
    let upstream_id = UpstreamId::new();
    let target = upstream(upstream_id, UpstreamAccountMode::CallerBound);
    let same = invoke_binding(&a.caller, upstream_id);
    let different_caller = invoke_binding(&b.caller, upstream_id);
    let different_upstream = invoke_binding(&a.caller, UpstreamId::new());
    let all = [different_caller, different_upstream, same];
    assert_eq!(
        check_profile_invoke_metadata(&a, Some(profile), Some(target)),
        Ok(())
    );
    assert_eq!(
        authorize_profile_invoke(&a, Some(profile), Some(target), &all),
        Ok(Some(same.binding.account_id))
    );
    assert_eq!(
        authorize_profile_invoke(&b, Some(profile), Some(target), &all),
        Ok(Some(different_caller.binding.account_id))
    );

    let missing = AuthzError::AccountNotBound {
        reason: AccountNotBoundReason::MissingBinding,
    };
    denied(
        authorize_profile_invoke(&a, Some(profile), Some(target), &all[..2]),
        missing.clone(),
        403,
        "account_not_bound",
    );
    denied(
        authorize_profile_invoke(&a, Some(profile), Some(target), &[same, same]),
        AuthzError::InvalidAuthContext,
        403,
        "forbidden",
    );
    let admin = admin();
    denied(
        authorize_tool_test(&admin, target, &all),
        missing.clone(),
        403,
        "account_not_bound",
    );
    let bound_to_admin = invoke_binding(&admin.caller, upstream_id);
    assert_eq!(
        authorize_tool_test(&admin, target, &[same, bound_to_admin]),
        Ok(Some(bound_to_admin.binding.account_id))
    );

    let manager = context(orchestrator(), vec![grant]);
    let ownerless = child_context(None, Some(&manager), vec![grant]);
    denied(
        authorize_profile_invoke(&ownerless, Some(profile), Some(target), &all),
        missing,
        403,
        "account_not_bound",
    );

    let mut agent = child_context(Some(&a), Some(&a), vec![grant]);
    let own = invoke_binding(&agent.caller, upstream_id);
    denied(
        authorize_profile_invoke(&agent, Some(profile), Some(target), &all),
        AuthzError::AccountNotBound {
            reason: AccountNotBoundReason::InheritDisabled,
        },
        403,
        "account_not_bound",
    );
    assert_eq!(
        authorize_profile_invoke(&agent, Some(profile), Some(target), &[same, own]),
        Ok(Some(own.binding.account_id))
    );
    agent.caller.inherit_owner_bindings = true;
    assert_eq!(
        authorize_profile_invoke(&agent, Some(profile), Some(target), &all),
        Ok(Some(same.binding.account_id))
    );
    assert_eq!(
        authorize_profile_invoke(&agent, Some(profile), Some(target), &[same, own]),
        Ok(Some(own.binding.account_id))
    );
    denied(
        authorize_tool_test(&agent, target, &all),
        AuthzError::AdminHumanRequired,
        403,
        "admin_human_required",
    );
}

#[test]
fn final_invoke_requires_the_current_account_for_the_exact_binding() {
    let profile = ProfileId::new();
    let grants = vec![grant(profile, Capability::Invoke)];
    let owner = context(principal(PrincipalKind::Member), grants.clone());
    let mut agent = child_context(Some(&owner), Some(&owner), grants);
    agent.caller.inherit_owner_bindings = true;
    let upstream_id = UpstreamId::new();
    let target = Some(upstream(upstream_id, UpstreamAccountMode::CallerBound));
    let inherited = invoke_binding(&owner.caller, upstream_id);
    let own = invoke_binding(&agent.caller, upstream_id);
    let account = own.account.expect("account fixture");
    let missing = AuthzError::AccountNotBound {
        reason: AccountNotBoundReason::MissingBinding,
    };
    for (current, expected) in [
        (
            Some(AccountView {
                upstream_id: Some(UpstreamId::new()),
                ..account
            }),
            missing.clone(),
        ),
        (
            Some(AccountView {
                kind: AccountKind::SecretKv,
                upstream_id: None,
                ..account
            }),
            missing,
        ),
        (None, AuthzError::InvalidAuthContext),
        (
            Some(AccountView {
                account_id: AccountId::new(),
                ..account
            }),
            AuthzError::InvalidAuthContext,
        ),
    ] {
        let stale = InvokeBindingView {
            account: current,
            ..own
        };
        assert_eq!(
            authorize_profile_invoke(&agent, Some(profile), target, &[stale, inherited]),
            Err(expected.clone())
        );
        let stale_owner = InvokeBindingView {
            binding: BindingView {
                principal_id: owner.caller.principal_id,
                ..own.binding
            },
            account: current,
        };
        assert_eq!(
            authorize_profile_invoke(&agent, Some(profile), target, &[stale_owner]),
            Err(expected)
        );
    }
}

#[test]
fn repeated_activity_check_only_discloses_owner_disabled_for_visible_authorized_routes() {
    let profile = ProfileId::new();
    let invoke = grant(profile, Capability::Invoke);
    let owner = context(principal(PrincipalKind::Member), vec![invoke]);
    let manager = context(orchestrator(), vec![invoke]);
    let mut agent = child_context(Some(&owner), Some(&manager), vec![invoke]);
    agent.caller.inherit_owner_bindings = true;
    let node = node(None);
    let upstream_id = UpstreamId::new();
    let bound = upstream(upstream_id, UpstreamAccountMode::CallerBound);
    let plain = upstream(upstream_id, UpstreamAccountMode::None);
    let own = invoke_binding(&agent.caller, upstream_id);
    let owner_binding = invoke_binding(&owner.caller, upstream_id);
    let lookups = Cell::new(0);
    let invoke_fake = |ctx: &AuthContext, profile, target, rows: &[InvokeBindingView]| {
        check_profile_invoke_metadata(ctx, profile, target)?;
        lookups.set(lookups.get() + 1);
        authorize_profile_invoke(ctx, profile, target, rows)
    };
    assert_eq!(check_active(&agent), Ok(()));
    assert_eq!(
        invoke_fake(&agent, Some(profile), Some(bound), &[own]),
        Ok(Some(own.binding.account_id))
    );
    assert_eq!(
        invoke_fake(&agent, Some(profile), Some(bound), &[owner_binding]),
        Ok(Some(owner_binding.binding.account_id))
    );
    assert_eq!(lookups.replace(0), 2);

    let mut disabled_owner = owner.caller.clone();
    disabled_owner.disabled_at_ms = Some(agent.now_ms);
    agent.owner = Some(disabled_owner);
    denied(
        check_active(&agent),
        AuthzError::OwnerDisabled,
        403,
        "owner_disabled",
    );
    for rows in [&[][..], &[own][..]] {
        let error = AuthzError::AccountNotBound {
            reason: AccountNotBoundReason::OwnerDisabled,
        };
        denied(
            invoke_fake(&agent, Some(profile), Some(bound), rows),
            error.clone(),
            403,
            "account_not_bound",
        );
        denied(
            authorize_profile_invoke(&agent, Some(profile), Some(bound), rows),
            error,
            403,
            "account_not_bound",
        );
    }
    for (profile, target) in [(None, Some(bound)), (Some(profile), None)] {
        denied(
            invoke_fake(&agent, profile, target, &[own]),
            AuthzError::ResourceNotFound,
            404,
            "not_found",
        );
    }
    for target in [Some(plain), Some(managed(&node))] {
        denied(
            invoke_fake(&agent, Some(profile), target, &[own]),
            AuthzError::OwnerDisabled,
            403,
            "owner_disabled",
        );
    }
    agent.token.allowed_profiles = Some(BTreeSet::from([ProfileId::new()]));
    denied(
        invoke_fake(&agent, Some(profile), Some(bound), &[own]),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
    agent.token.allowed_profiles = None;
    agent.token.allowed_nodes = Some(BTreeSet::from([node.node_id]));
    denied(
        invoke_fake(&agent, Some(profile), Some(bound), &[own]),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
    agent.token.allowed_nodes = None;
    agent.owner_grants.clear();
    for target in [bound, plain, managed(&node)] {
        denied(
            invoke_fake(&agent, Some(profile), Some(target), &[own]),
            AuthzError::ResourceNotFound,
            404,
            "not_found",
        );
    }
    agent.owner_grants = vec![grant(profile, Capability::Discover)];
    denied(
        invoke_fake(&agent, Some(profile), Some(bound), &[own]),
        AuthzError::InsufficientCapability,
        403,
        "forbidden",
    );
    agent.owner_grants = vec![invoke];

    for token in [
        TokenScope {
            expires_at_ms: Some(agent.now_ms),
            ..agent.token.clone()
        },
        TokenScope {
            revoked_at_ms: Some(agent.now_ms),
            ..agent.token.clone()
        },
    ] {
        let expired = AuthContext {
            token,
            ..agent.clone()
        };
        denied(
            check_active(&expired),
            AuthzError::Unauthenticated,
            401,
            "unauthenticated",
        );
        for (profile, target) in [
            (None, None),
            (Some(profile), Some(bound)),
            (Some(profile), Some(plain)),
        ] {
            denied(
                invoke_fake(&expired, profile, target, &[own]),
                AuthzError::Unauthenticated,
                401,
                "unauthenticated",
            );
        }
    }
    let mut disabled_manager = manager.caller;
    disabled_manager.disabled_at_ms = Some(agent.now_ms);
    agent.managed_by = Some(disabled_manager);
    denied(
        check_active(&agent),
        AuthzError::OwnerDisabled,
        403,
        "owner_disabled",
    );
    denied(
        invoke_fake(&agent, Some(profile), Some(bound), &[own]),
        AuthzError::ManagedByDisabled,
        403,
        "managed_by_disabled",
    );
    assert_eq!(lookups.get(), 0);
    agent.managed_by = None;
    denied(
        invoke_fake(&agent, Some(profile), Some(bound), &[own]),
        AuthzError::InvalidAuthContext,
        403,
        "forbidden",
    );
    assert_eq!(lookups.get(), 0);
}

#[test]
fn parent_integrity_and_disable_cascades_also_gate_streams() {
    let profile = ProfileId::new();
    let invoke = grant(profile, Capability::Invoke);
    let mut owner = context(principal(PrincipalKind::Member), vec![invoke]);
    owner.caller.disabled_at_ms = Some(owner.now_ms);
    let owner_child = child_context(Some(&owner), Some(&owner), vec![invoke]);
    let mut manager = context(orchestrator(), vec![invoke]);
    manager.caller.disabled_at_ms = Some(manager.now_ms);
    let manager_child = child_context(None, Some(&manager), vec![invoke]);
    let event = EventAuthTarget {
        kind: EventKind::ProfilePublished,
        owner_principal_id: None,
        agent_owner_principal_id: None,
        node_id: None,
        profile_id: Some(profile),
    };
    for (ctx, error, code) in [
        (&owner_child, AuthzError::OwnerDisabled, "owner_disabled"),
        (
            &manager_child,
            AuthzError::ManagedByDisabled,
            "managed_by_disabled",
        ),
    ] {
        denied(check_active(ctx), error.clone(), 403, code);
        denied(
            authorize_profile_discover(ctx, Some(profile)),
            error,
            403,
            code,
        );
        assert!(!can_observe_event(ctx, &event));
    }
    let wrong = AuthContext {
        owner: Some(principal(PrincipalKind::Member)),
        ..owner_child.clone()
    };
    let missing = AuthContext {
        managed_by: None,
        ..manager_child
    };
    for corrupt in [&wrong, &missing] {
        denied(
            check_active(corrupt),
            AuthzError::InvalidAuthContext,
            403,
            "forbidden",
        );
        assert!(!can_observe_event(corrupt, &event));
    }
    let wrong_token = AuthContext {
        token: TokenScope {
            token_id: TokenId::new_service(),
            ..owner_child.token.clone()
        },
        ..owner_child
    };
    denied(
        check_active(&wrong_token),
        AuthzError::Unauthenticated,
        401,
        "unauthenticated",
    );

    let mut disabled = context(principal(PrincipalKind::Member), vec![invoke]);
    disabled.caller.disabled_at_ms = Some(disabled.now_ms);
    denied(
        check_active(&disabled),
        AuthzError::PrincipalDisabled,
        403,
        "principal_disabled",
    );
}

#[test]
fn binding_management_checks_upstream_visibility_relationship_and_account_kind() {
    let profile = ProfileId::new();
    let mut member = context(
        principal(PrincipalKind::Member),
        vec![grant(profile, Capability::Discover)],
    );
    let other = principal(PrincipalKind::Member);
    let owned = child(Some(&member.caller), None);
    let upstream_id = UpstreamId::new();
    let visible = Some(BindingUpstream {
        upstream_id,
        caller_bound_profiles: &[profile],
    });
    let record = binding(&owned, upstream_id);
    let account = AccountView {
        account_id: record.account_id,
        owner_principal_id: member.caller.principal_id,
        visibility: AccountVisibility::Private,
        kind: AccountKind::HttpAuth,
        upstream_id: Some(upstream_id),
    };
    assert_eq!(
        authorize_account_access(&member, &account, AccountAccess::Read),
        Ok(())
    );
    assert_eq!(
        authorize_account_access(&member, &account, AccountAccess::Mutate),
        Ok(())
    );
    assert_eq!(
        authorize_binding_read(&member, visible, &owned, &record),
        Ok(())
    );
    assert_eq!(
        authorize_binding_mutation(&member, visible, &owned, &account, BindingMutation::Set),
        Ok(())
    );
    assert_eq!(
        authorize_binding_mutation(
            &member,
            visible,
            &owned,
            &account,
            BindingMutation::Remove { existing: record }
        ),
        Ok(())
    );
    let missing = Some(BindingUpstream {
        upstream_id,
        caller_bound_profiles: &[],
    });
    for upstream in [None, missing] {
        denied(
            authorize_binding_read(&member, upstream, &owned, &record),
            AuthzError::ResourceNotFound,
            404,
            "not_found",
        );
        denied(
            authorize_binding_mutation(&member, upstream, &owned, &account, BindingMutation::Set),
            AuthzError::ResourceNotFound,
            404,
            "not_found",
        );
    }
    let wrong_account = AccountView {
        account_id: AccountId::new(),
        ..account
    };
    denied(
        authorize_binding_mutation(
            &member,
            visible,
            &owned,
            &wrong_account,
            BindingMutation::Remove { existing: record },
        ),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    let foreign = AccountView {
        owner_principal_id: other.principal_id,
        ..account
    };
    denied(
        authorize_account_access(&member, &foreign, AccountAccess::Read),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    let shared = AccountView {
        visibility: AccountVisibility::Shared,
        ..account
    };
    denied(
        authorize_account_access(&member, &shared, AccountAccess::Read),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    for account in [
        foreign,
        shared,
        AccountView {
            kind: AccountKind::SshKey,
            ..account
        },
        AccountView {
            upstream_id: Some(UpstreamId::new()),
            ..account
        },
    ] {
        denied(
            authorize_binding_mutation(&member, visible, &owned, &account, BindingMutation::Set),
            AuthzError::Forbidden,
            403,
            "forbidden",
        );
    }
    assert_eq!(
        authorize_binding_mutation(&admin(), missing, &owned, &shared, BindingMutation::Set),
        Ok(())
    );
    // Historical binding cleanup still identifies the actual account by its ID.
    let reassigned = AccountView {
        upstream_id: Some(UpstreamId::new()),
        ..account
    };
    for caller in [&member, &admin()] {
        assert_eq!(
            authorize_binding_mutation(
                caller,
                visible,
                &owned,
                &reassigned,
                BindingMutation::Remove { existing: record }
            ),
            Ok(())
        );
        denied(
            authorize_binding_mutation(caller, visible, &owned, &reassigned, BindingMutation::Set),
            AuthzError::Forbidden,
            403,
            "forbidden",
        );
    }
    let other_binding = binding(&other, upstream_id);
    denied(
        authorize_binding_read(&member, visible, &other, &other_binding),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    let orchestrator = context(orchestrator(), member.caller_grants.clone());
    denied(
        authorize_binding_read(&orchestrator, visible, &owned, &record),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );

    member.token.withhold_sensitive = true;
    assert_eq!(
        authorize_binding_read(&member, visible, &owned, &record),
        Ok(())
    );
    denied(
        authorize_account_access(&member, &account, AccountAccess::Mutate),
        AuthzError::UnrestrictedTokenRequired,
        403,
        "token_narrowed",
    );
    denied(
        authorize_binding_mutation(&member, visible, &owned, &account, BindingMutation::Set),
        AuthzError::UnrestrictedTokenRequired,
        403,
        "token_narrowed",
    );
    member.token.allowed_profiles = Some(BTreeSet::new());
    denied(
        authorize_binding_read(&member, visible, &owned, &record),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
    member.token.allowed_profiles = None;
    member.token.allowed_nodes = Some(BTreeSet::new());
    denied(
        authorize_binding_read(&member, visible, &owned, &record),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
}
