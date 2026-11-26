use super::*;

#[test]
fn profiles_hide_missing_or_filtered_rows_and_require_invoke_for_visible_rows() {
    let profile = ProfileId::new();
    let mut member = context(
        principal(PrincipalKind::Member),
        vec![grant(profile, Capability::Discover)],
    );
    let other = ProfileId::new();
    let target = node(None);
    assert_eq!(authorize_profile_discover(&member, Some(profile)), Ok(()));
    for missing in [None, Some(other)] {
        denied(
            authorize_profile_discover(&member, missing),
            AuthzError::ResourceNotFound,
            404,
            "not_found",
        );
        denied(
            authorize_profile_invoke(&member, missing, Some(managed(&target)), &[]),
            AuthzError::ResourceNotFound,
            404,
            "not_found",
        );
    }
    denied(
        authorize_profile_invoke(&member, Some(profile), None, &[]),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
    denied(
        authorize_profile_invoke(&member, Some(profile), Some(managed(&target)), &[]),
        AuthzError::InsufficientCapability,
        403,
        "forbidden",
    );
    member.token.allowed_profiles = Some(BTreeSet::from([other]));
    denied(
        authorize_profile_discover(&member, Some(profile)),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );

    let mut narrowed = admin();
    narrowed.token.allowed_profiles = Some(BTreeSet::from([profile]));
    narrowed.token.allowed_nodes = Some(BTreeSet::from([target.node_id]));
    assert_eq!(
        authorize_profile_invoke(&narrowed, Some(profile), Some(managed(&target)), &[]),
        Ok(None)
    );
    denied(
        authorize_tool_test(&narrowed, managed(&target), &[]),
        AuthzError::UnrestrictedTokenRequired,
        403,
        "token_narrowed",
    );
}

#[test]
fn managed_agent_discovery_and_invoke_use_the_nodes_current_manager() {
    let profile = ProfileId::new();
    let invoke = grant(profile, Capability::Invoke);
    let manager = context(orchestrator(), vec![invoke]);
    let mut agent = child_context(None, Some(&manager), vec![invoke]);
    let node1 = node(Some(manager.caller.principal_id));
    let node2 = node(Some(manager.caller.principal_id));
    let foreign = node(Some(PrincipalId::new_service()));
    let unowned = node(None);

    let verify = |agent: &AuthContext, target: ExecutionTarget<'_>, result| {
        assert_eq!(authorize_discovery_target(agent, profile, target), result);
        assert_eq!(
            authorize_profile_invoke(agent, Some(profile), Some(target), &[]).map(|_| ()),
            result
        );
    };
    let allowed = |agent: &AuthContext, target| verify(agent, target, Ok(()));
    for owned in [&node1, &node2] {
        allowed(&agent, managed(owned));
    }
    for out in [&foreign, &unowned] {
        verify(&agent, managed(out), Err(AuthzError::ScopeNarrowedOut));
    }
    for row in [None, Some(&node2)] {
        verify(
            &agent,
            ExecutionTarget::Managed {
                selected_id: node1.node_id,
                node: row,
            },
            Err(AuthzError::InvalidAuthContext),
        );
    }
    agent.token.allowed_nodes = Some(BTreeSet::from([node1.node_id]));
    allowed(&agent, managed(&node1));
    verify(&agent, managed(&node2), Err(AuthzError::ScopeNarrowedOut));

    let issued_by_admin = TokenMintRequest {
        allowed_nodes: Some(BTreeSet::from([node1.node_id, foreign.node_id])),
        ..TokenMintRequest::default()
    };
    assert_eq!(
        authorize_token_mint(
            &admin(),
            &agent.caller,
            &issued_by_admin,
            &OrchestratorLimits::default(),
            &BTreeSet::new()
        ),
        Ok(())
    );
    agent.token.allowed_nodes = issued_by_admin.allowed_nodes;
    allowed(&agent, managed(&node1));
    verify(&agent, managed(&foreign), Err(AuthzError::ScopeNarrowedOut));
    let upstream_id = UpstreamId::new();
    let upstream = upstream(upstream_id, UpstreamAccountMode::CallerBound);
    let binding = BindingView {
        principal_id: agent.caller.principal_id,
        upstream_id,
        account_id: AccountId::new(),
    };
    denied(
        authorize_profile_invoke(&agent, Some(profile), Some(upstream), &[binding]),
        AuthzError::ScopeNarrowedOut,
        403,
        "forbidden",
    );
    agent.token.allowed_nodes = Some(BTreeSet::new());
    verify(&agent, managed(&node1), Err(AuthzError::ScopeNarrowedOut));
    verify(&agent, upstream, Err(AuthzError::ScopeNarrowedOut));
    agent.token.allowed_nodes = None;
    assert_eq!(
        authorize_discovery_target(&agent, profile, upstream),
        Ok(())
    );
    assert_eq!(
        authorize_profile_invoke(&agent, Some(profile), Some(upstream), &[binding]),
        Ok(Some(binding.account_id))
    );
    denied(
        authorize_profile_invoke(&agent, Some(profile), Some(upstream), &[]),
        AuthzError::AccountNotBound {
            reason: AccountNotBoundReason::MissingBinding,
        },
        403,
        "account_not_bound",
    );
    agent.caller_grants = vec![grant(profile, Capability::Discover)];
    denied(
        authorize_profile_invoke(&agent, Some(profile), Some(upstream), &[binding]),
        AuthzError::InsufficientCapability,
        403,
        "forbidden",
    );

    let mut manager = manager;
    manager.caller.is_orchestrator = false;
    manager.caller.allowed_node_tags.clear();
    agent.managed_by = Some(manager.caller);
    verify(&agent, managed(&node1), Err(AuthzError::InvalidAuthContext));
}

#[test]
fn archived_bindings_require_visibility_and_evidence_for_a_narrowed_target() {
    let profile = ProfileId::new();
    let mut member = context(
        principal(PrincipalKind::Member),
        vec![grant(profile, Capability::Invoke)],
    );
    let target = node(None);
    let removed = ArchivedDependency::Tool {
        target_evidence: None,
    };
    assert_eq!(
        check_archived_invoke_metadata(&member, Some(profile), removed),
        Ok(())
    );
    member.token.allowed_nodes = Some(BTreeSet::from([target.node_id]));
    denied(
        check_archived_invoke_metadata(&member, Some(profile), removed),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
    let account_removed = ArchivedDependency::Account {
        target: managed(&target),
    };
    let tool_removed_with_evidence = ArchivedDependency::Tool {
        target_evidence: Some(managed(&target)),
    };
    for archived in [account_removed, tool_removed_with_evidence] {
        assert_eq!(
            check_archived_invoke_metadata(&member, Some(profile), archived),
            Ok(())
        );
    }
    let other = node(None);
    denied(
        check_archived_invoke_metadata(
            &member,
            Some(profile),
            ArchivedDependency::Account {
                target: managed(&other),
            },
        ),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
    denied(
        check_archived_invoke_metadata(&member, None, account_removed),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
    member.caller_grants = vec![grant(profile, Capability::Discover)];
    denied(
        check_archived_invoke_metadata(&member, Some(profile), account_removed),
        AuthzError::InsufficientCapability,
        403,
        "forbidden",
    );
}

#[test]
fn disabled_owner_cannot_distinguish_missing_tool_from_unknown_alias() {
    let profile = ProfileId::new();
    let mut owner = context(
        principal(PrincipalKind::Member),
        vec![grant(profile, Capability::Invoke)],
    );
    let target = node(None);
    owner.caller.disabled_at_ms = Some(owner.now_ms);
    for capability in [Capability::Discover, Capability::Invoke] {
        let ctx = child_context(Some(&owner), None, vec![grant(profile, capability)]);
        let unknown = check_profile_invoke_metadata(&ctx, Some(profile), None);
        denied(
            unknown.clone(),
            AuthzError::ResourceNotFound,
            404,
            "not_found",
        );
        for target_evidence in [None, Some(managed(&target))] {
            let missing = ArchivedDependency::Tool { target_evidence };
            assert_eq!(
                check_archived_invoke_metadata(&ctx, Some(profile), missing),
                unknown
            );
        }
        // The same archived binding with a live tool retains its ordinary visibility rules.
        let deleted_account = ArchivedDependency::Account {
            target: managed(&target),
        };
        assert_eq!(
            check_archived_invoke_metadata(&ctx, Some(profile), deleted_account),
            check_profile_invoke_metadata(&ctx, Some(profile), Some(managed(&target)))
        );
    }
}

#[test]
fn an_agents_owner_sees_recorded_event_metadata_within_token_scope() {
    let mut owner = context(principal(PrincipalKind::Member), vec![]);
    let agent = child_context(Some(&owner), None, vec![]);
    let event = EventAuthTarget {
        kind: EventKind::ExecutionFinished,
        owner_principal_id: Some(agent.caller.principal_id),
        agent_owner_principal_id: Some(owner.caller.principal_id),
        node_id: Some(NodeId::new()),
        profile_id: Some(ProfileId::new()),
    };
    assert!(can_observe_event(&owner, &event));
    assert!(can_observe_event(&agent, &event));
    assert!(!can_observe_event(
        &context(principal(PrincipalKind::Member), vec![]),
        &event
    ));
    assert!(!can_observe_event(
        &agent,
        &EventAuthTarget {
            owner_principal_id: Some(owner.caller.principal_id),
            agent_owner_principal_id: None,
            ..event
        }
    ));
    owner.token.allowed_nodes = Some(BTreeSet::new());
    assert!(!can_observe_event(&owner, &event));
    owner.token.allowed_nodes = None;
    owner.token.allowed_profiles = Some(BTreeSet::new());
    assert!(!can_observe_event(&owner, &event));
}

#[test]
fn execution_access_uses_ownership_and_stored_scope_without_new_node_lookup() {
    let profile = ProfileId::new();
    let owner = context(principal(PrincipalKind::Member), vec![]);
    let mut agent = child_context(Some(&owner), None, vec![]);
    let managed_by = context(orchestrator(), vec![]);
    let mut managed_agent = child_context(None, Some(&managed_by), vec![]);
    let target_node = NodeId::new();
    let own = ExecutionAuthTarget {
        caller_principal_id: agent.caller.principal_id,
        caller_owner_principal_id: Some(owner.caller.principal_id),
        profile_id: Some(profile),
        node_id: Some(target_node),
    };
    assert_eq!(
        authorize_execution_access(&owner, Some(&own), ExecutionAccess::Cancel),
        Ok(())
    );
    assert_eq!(
        authorize_execution_access(&agent, Some(&own), ExecutionAccess::ReadMetadata),
        Ok(())
    );
    let parents_job = ExecutionAuthTarget {
        caller_principal_id: owner.caller.principal_id,
        caller_owner_principal_id: None,
        ..own
    };
    for missing in [None, Some(&parents_job)] {
        denied(
            authorize_execution_access(&agent, missing, ExecutionAccess::ReadMetadata),
            AuthzError::ResourceNotFound,
            404,
            "not_found",
        );
    }

    agent.token.withhold_sensitive = true;
    assert_eq!(
        authorize_execution_access(&agent, Some(&own), ExecutionAccess::ReadMetadata),
        Ok(())
    );
    assert!(!can_read_sensitive_result(&agent, &own));
    denied(
        authorize_execution_access(&agent, Some(&own), ExecutionAccess::ReadSensitive),
        AuthzError::SensitiveWithheld,
        403,
        "forbidden",
    );
    agent.token.withhold_sensitive = false;
    agent.token.max_capability = Some(Capability::Discover);
    assert_eq!(
        authorize_execution_access(&agent, Some(&own), ExecutionAccess::ReadMetadata),
        Ok(())
    );
    for access in [ExecutionAccess::Cancel, ExecutionAccess::ReadSensitive] {
        denied(
            authorize_execution_access(&agent, Some(&own), access),
            AuthzError::InsufficientCapability,
            403,
            "forbidden",
        );
    }

    agent.token.max_capability = None;
    agent.token.allowed_profiles = Some(BTreeSet::from([profile]));
    agent.token.allowed_nodes = Some(BTreeSet::from([target_node]));
    for access in [
        ExecutionAccess::ReadMetadata,
        ExecutionAccess::ReadSensitive,
        ExecutionAccess::Cancel,
    ] {
        for invisible in [
            ExecutionAuthTarget {
                profile_id: None,
                ..own
            },
            ExecutionAuthTarget {
                node_id: None,
                ..own
            },
        ] {
            denied(
                authorize_execution_access(&agent, Some(&invisible), access),
                AuthzError::ResourceNotFound,
                404,
                "not_found",
            );
        }
        assert_eq!(
            authorize_execution_access(&agent, Some(&own), access),
            Ok(())
        );
    }

    let historical = ExecutionAuthTarget {
        caller_principal_id: managed_agent.caller.principal_id,
        caller_owner_principal_id: None,
        ..own
    };
    let event = EventAuthTarget {
        kind: EventKind::ExecutionLateReceipt,
        owner_principal_id: Some(managed_agent.caller.principal_id),
        agent_owner_principal_id: None,
        node_id: historical.node_id,
        profile_id: historical.profile_id,
    };
    managed_agent.token.allowed_nodes = Some(BTreeSet::from([target_node]));
    assert_eq!(
        authorize_execution_access(&managed_agent, Some(&historical), ExecutionAccess::Cancel),
        Ok(())
    );
    assert!(can_observe_event(&managed_agent, &event));
    managed_agent.token.allowed_nodes = Some(BTreeSet::new());
    denied(
        authorize_execution_access(
            &managed_agent,
            Some(&historical),
            ExecutionAccess::ReadMetadata,
        ),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
    assert!(!can_observe_event(&managed_agent, &event));

    let mut narrow_admin = admin();
    let admin_job = ExecutionAuthTarget {
        caller_principal_id: narrow_admin.caller.principal_id,
        ..historical
    };
    narrow_admin.token.allowed_profiles = Some(BTreeSet::from([profile]));
    assert!(can_read_sensitive_result(&narrow_admin, &admin_job));
    denied(
        authorize_execution_access(&narrow_admin, Some(&own), ExecutionAccess::ReadMetadata),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
}

#[test]
fn event_observers_see_only_metadata_in_authorized_projections() {
    let p1 = ProfileId::new();
    let p2 = ProfileId::new();
    let foreign = principal(PrincipalKind::Member);
    let own_node = NodeId::new();
    let mut observer = context(
        PrincipalView {
            observe_executions: true,
            ..orchestrator()
        },
        vec![grant(p1, Capability::Discover)],
    );
    let job = EventAuthTarget {
        kind: EventKind::ExecutionFinished,
        owner_principal_id: Some(foreign.principal_id),
        agent_owner_principal_id: None,
        node_id: Some(own_node),
        profile_id: Some(p1),
    };
    assert!(can_observe_event(&observer, &job));
    let view = ExecutionAuthTarget {
        caller_principal_id: foreign.principal_id,
        caller_owner_principal_id: None,
        profile_id: Some(p1),
        node_id: Some(own_node),
    };
    denied(
        authorize_execution_access(&observer, Some(&view), ExecutionAccess::ReadMetadata),
        AuthzError::ResourceNotFound,
        404,
        "not_found",
    );
    assert!(!can_observe_event(
        &observer,
        &EventAuthTarget {
            profile_id: Some(p2),
            ..job
        }
    ));
    assert!(!can_observe_event(
        &observer,
        &EventAuthTarget {
            profile_id: None,
            ..job
        }
    ));

    observer.token.allowed_profiles = Some(BTreeSet::from([p1]));
    observer.token.allowed_nodes = Some(BTreeSet::from([own_node]));
    assert!(can_observe_event(&observer, &job));
    assert!(!can_observe_event(
        &observer,
        &EventAuthTarget {
            node_id: None,
            ..job
        }
    ));
    assert!(!can_observe_event(
        &observer,
        &EventAuthTarget {
            owner_principal_id: Some(observer.caller.principal_id),
            profile_id: None,
            ..job
        }
    ));

    let node_event = EventAuthTarget {
        kind: EventKind::NodeConnected,
        owner_principal_id: Some(observer.caller.principal_id),
        agent_owner_principal_id: None,
        profile_id: None,
        node_id: Some(own_node),
    };
    assert!(can_observe_event(&observer, &node_event));
    assert!(!can_observe_event(
        &observer,
        &EventAuthTarget {
            node_id: None,
            ..node_event
        }
    ));
    assert!(!can_observe_event(
        &observer,
        &EventAuthTarget {
            node_id: Some(NodeId::new()),
            ..node_event
        }
    ));
    assert!(!can_observe_event(
        &observer,
        &EventAuthTarget {
            owner_principal_id: None,
            ..node_event
        }
    ));

    let published = EventAuthTarget {
        kind: EventKind::ProfilePublished,
        profile_id: Some(p1),
        ..node_event
    };
    assert!(can_observe_event(&observer, &published));
    assert!(!can_observe_event(
        &observer,
        &EventAuthTarget {
            profile_id: Some(p2),
            ..published
        }
    ));
    let revoke = EventAuthTarget {
        kind: EventKind::AuthRevoked,
        owner_principal_id: Some(foreign.principal_id),
        ..node_event
    };
    assert!(!can_observe_event(&observer, &revoke));
    assert!(can_observe_event(&context(foreign, vec![]), &revoke));
    assert!(can_observe_event(&admin(), &revoke));
}
