use super::*;

#[test]
fn admin_requires_a_human_global_grant_and_an_unrestricted_token() {
    let administrator = admin();
    for kind in [
        PrincipalKind::Member,
        PrincipalKind::Agent,
        PrincipalKind::Service,
    ] {
        let caller = context(principal(kind), vec![global(Capability::Admin)]);
        denied(
            authorize_admin(&caller),
            AuthzError::AdminHumanRequired,
            403,
            "admin_human_required",
        );
        denied(
            authorize_grant_mutation(
                &caller,
                &administrator.caller,
                global(Capability::Admin),
                GrantMutation::Put,
            ),
            AuthzError::AdminHumanRequired,
            403,
            "admin_human_required",
        );
        denied(
            authorize_profile_discover(&caller, Some(ProfileId::new())),
            AuthzError::ResourceNotFound,
            404,
            "not_found",
        );
    }
    let mut caller = administrator.clone();
    caller.caller_grants.clear();
    denied(
        authorize_admin(&caller),
        AuthzError::InsufficientCapability,
        403,
        "forbidden",
    );
    assert_eq!(authorize_admin(&administrator), Ok(()));

    let newcomer = principal(PrincipalKind::Member);
    let req = TokenMintRequest::default();
    let limits = OrchestratorLimits::default();
    let enrollment = EnrollmentRequest {
        is_reenroll: false,
        requested_tags: BTreeSet::new(),
        managed_by_principal_id: None,
        ttl_ms: 1,
    };
    let nodes = BTreeSet::new();
    for token in narrowed_tokens(&administrator.token) {
        let caller = AuthContext {
            token,
            ..administrator.clone()
        };
        for decision in [
            authorize_admin(&caller),
            authorize_token_mint(&caller, &newcomer, &req, &limits, &nodes),
            authorize_token_revoke(&caller, &newcomer),
            authorize_grant_mutation(
                &caller,
                &newcomer,
                global(Capability::Discover),
                GrantMutation::Put,
            ),
            authorize_node_enrollment(&caller, &enrollment, &limits),
            authorize_node_enrollment(
                &caller,
                &EnrollmentRequest {
                    is_reenroll: true,
                    ..enrollment.clone()
                },
                &limits,
            ),
        ] {
            denied(
                decision,
                AuthzError::UnrestrictedTokenRequired,
                403,
                "token_narrowed",
            );
        }
    }
    denied(
        authorize_grant_mutation(
            &administrator,
            &newcomer,
            global(Capability::Admin),
            GrantMutation::Put,
        ),
        AuthzError::AdminHumanRequired,
        403,
        "admin_human_required",
    );
    denied(
        authorize_grant_mutation(
            &administrator,
            &administrator.caller,
            grant(ProfileId::new(), Capability::Admin),
            GrantMutation::Put,
        ),
        AuthzError::InvalidGrantScope,
        400,
        "invalid_input",
    );
    denied(
        authorize_token_mint(
            &administrator,
            &newcomer,
            &TokenMintRequest {
                max_capability: Some(Capability::Admin),
                ..req
            },
            &limits,
            &nodes,
        ),
        AuthzError::AdminHumanRequired,
        403,
        "admin_human_required",
    );
}

#[test]
fn owned_and_managed_relations_bound_grants_and_mutations() {
    let profile = ProfileId::new();
    let invoke = grant(profile, Capability::Invoke);
    let discover = grant(profile, Capability::Discover);
    for principal in [principal(PrincipalKind::Member), orchestrator()] {
        let mut parent = context(principal, vec![invoke]);
        let owner = (parent.caller.kind == PrincipalKind::Member).then_some(&parent);
        let child = child(owner.map(|ctx| &ctx.caller), Some(&parent.caller));
        let unrelated = super::child(None, None);
        assert_eq!(
            authorize_principal_upsert(
                &parent,
                &child,
                None,
                owner.map(|ctx| &ctx.caller),
                Some(&parent.caller)
            ),
            Ok(())
        );
        assert_eq!(
            authorize_grant_mutation(&parent, &child, invoke, GrantMutation::Put),
            Ok(())
        );
        denied(
            authorize_grant_mutation(
                &parent,
                &child,
                global(Capability::Discover),
                GrantMutation::Put,
            ),
            AuthzError::Forbidden,
            403,
            "forbidden",
        );
        denied(
            authorize_grant_mutation(&parent, &unrelated, invoke, GrantMutation::Put),
            AuthzError::Forbidden,
            403,
            "forbidden",
        );
        let mut narrow = parent.clone();
        narrow.token.max_capability = Some(Capability::Invoke);
        assert_eq!(
            authorize_principal_manage(&narrow, &child, PrincipalAccess::Read),
            Ok(())
        );
        denied(
            authorize_principal_manage(&narrow, &child, PrincipalAccess::Disable),
            AuthzError::UnrestrictedTokenRequired,
            403,
            "token_narrowed",
        );
        denied(
            authorize_principal_manage(&narrow, &unrelated, PrincipalAccess::Disable),
            AuthzError::Forbidden,
            403,
            "forbidden",
        );

        parent.caller_grants = vec![discover];
        denied(
            authorize_grant_mutation(&parent, &child, invoke, GrantMutation::Put),
            AuthzError::GrantEscalation,
            403,
            "forbidden",
        );
        assert_eq!(
            authorize_grant_mutation(&parent, &child, invoke, GrantMutation::Remove),
            Ok(())
        );
        let owner = (parent.caller.kind == PrincipalKind::Member).then_some(&parent);
        let mut child = child_context(owner, Some(&parent), vec![invoke]);
        let destination = node(Some(parent.caller.principal_id));
        assert_eq!(
            authorize_discovery_target(&child, profile, managed(&destination)),
            Ok(())
        );
        denied(
            authorize_profile_invoke(&child, Some(profile), Some(managed(&destination)), &[]),
            AuthzError::InsufficientCapability,
            403,
            "forbidden",
        );

        child.caller_grants.clear(); // Model the applied removal.
        child.managed_by_grants = vec![invoke];
        if owner.is_some() {
            child.owner_grants = vec![invoke];
        }
        denied(
            authorize_profile_discover(&child, Some(profile)),
            AuthzError::ResourceNotFound,
            404,
            "not_found",
        );
    }
}

#[test]
fn principal_relationships_are_immutable_and_metadata_roles_stay_distinct() {
    let member = context(principal(PrincipalKind::Member), vec![]);
    let manager = context(orchestrator(), vec![]);
    let owned = child(Some(&member.caller), None);
    let managed = child(None, Some(&manager.caller));
    for metadata in [
        SubjectMetadata::Grants,
        SubjectMetadata::Tokens,
        SubjectMetadata::AccountBindings,
    ] {
        assert_eq!(
            authorize_subject_metadata_read(&member, &member.caller, metadata),
            Ok(())
        );
        assert_eq!(
            authorize_subject_metadata_read(&member, &owned, metadata),
            Ok(())
        );
        denied(
            authorize_subject_metadata_read(&member, &managed, metadata),
            AuthzError::Forbidden,
            403,
            "forbidden",
        );
        denied(
            authorize_subject_metadata_read(&manager, &manager.caller, metadata),
            AuthzError::Forbidden,
            403,
            "forbidden",
        );
        if metadata == SubjectMetadata::AccountBindings {
            denied(
                authorize_subject_metadata_read(&manager, &managed, metadata),
                AuthzError::Forbidden,
                403,
                "forbidden",
            );
        } else {
            assert_eq!(
                authorize_subject_metadata_read(&manager, &managed, metadata),
                Ok(())
            );
        }
    }
    assert_eq!(
        authorize_principal_manage(&member, &owned, PrincipalAccess::Read),
        Ok(())
    );
    denied(
        authorize_principal_manage(&member, &owned, PrincipalAccess::Delete),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    let next = PrincipalView {
        managed_by_principal_id: None,
        ..managed.clone()
    };
    denied(
        authorize_principal_upsert(&admin(), &next, Some(&managed), None, None),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    let next = PrincipalView {
        owner_principal_id: None,
        ..owned.clone()
    };
    denied(
        authorize_principal_upsert(&admin(), &next, Some(&owned), None, None),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    let next = PrincipalView {
        managed_by_principal_id: Some(member.caller.principal_id),
        ..managed.clone()
    };
    denied(
        authorize_principal_upsert(&admin(), &next, Some(&managed), None, Some(&member.caller)),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    let non_orchestrator = PrincipalView {
        is_orchestrator: false,
        allowed_node_tags: BTreeSet::new(),
        ..manager.caller
    };
    denied(
        authorize_principal_upsert(&admin(), &managed, None, None, Some(&non_orchestrator)),
        AuthzError::InvalidAuthContext,
        403,
        "forbidden",
    );
}

#[test]
fn orchestrator_mint_is_monotonic_in_each_dimension() {
    let mut ctx = context(orchestrator(), vec![]);
    let target = child(None, Some(&ctx.caller));
    let node = NodeId::new();
    let foreign = NodeId::new();
    let managed = BTreeSet::from([node]);
    let p1 = ProfileId::new();
    let p2 = ProfileId::new();
    ctx.token.expires_at_ms = Some(ctx.now_ms + 50);
    ctx.token.allowed_profiles = Some(BTreeSet::from([p1]));
    ctx.token.allowed_nodes = Some(BTreeSet::from([node]));
    ctx.token.max_capability = Some(Capability::Invoke);
    ctx.token.withhold_sensitive = true;
    let valid = TokenMintRequest {
        allowed_nodes: ctx.token.allowed_nodes.clone(),
        allowed_profiles: ctx.token.allowed_profiles.clone(),
        max_capability: Some(Capability::Discover),
        expires_at_ms: ctx.token.expires_at_ms,
        withhold_sensitive: true,
    };
    let policy = OrchestratorLimits::default();
    let check = |request: &TokenMintRequest| {
        authorize_token_mint(&ctx, &target, request, &policy, &managed)
    };
    assert_eq!(check(&valid), Ok(()));
    for (request, field) in [
        (
            TokenMintRequest {
                max_capability: None,
                ..valid.clone()
            },
            "max_capability",
        ),
        (
            TokenMintRequest {
                allowed_profiles: None,
                ..valid.clone()
            },
            "allowed_profiles",
        ),
        (
            TokenMintRequest {
                allowed_profiles: Some(BTreeSet::from([p1, p2])),
                ..valid.clone()
            },
            "allowed_profiles",
        ),
        (
            TokenMintRequest {
                allowed_nodes: None,
                ..valid.clone()
            },
            "allowed_nodes",
        ),
        (
            TokenMintRequest {
                allowed_nodes: Some(BTreeSet::from([foreign])),
                ..valid.clone()
            },
            "allowed_nodes",
        ),
        (
            TokenMintRequest {
                expires_at_ms: None,
                ..valid.clone()
            },
            "expires_at_ms",
        ),
        (
            TokenMintRequest {
                expires_at_ms: Some(ctx.now_ms + 51),
                ..valid.clone()
            },
            "expires_at_ms",
        ),
        (
            TokenMintRequest {
                withhold_sensitive: false,
                ..valid.clone()
            },
            "withhold_sensitive",
        ),
    ] {
        denied(
            check(&request),
            AuthzError::TokenAmplification(field),
            403,
            "token_amplification",
        );
    }
    let mut empty_parent = ctx.clone();
    empty_parent.token.allowed_nodes = Some(BTreeSet::new());
    for allowed_nodes in [None, Some(BTreeSet::from([node]))] {
        let request = TokenMintRequest {
            allowed_nodes,
            ..valid.clone()
        };
        denied(
            authorize_token_mint(&empty_parent, &target, &request, &policy, &managed),
            AuthzError::TokenAmplification("allowed_nodes"),
            403,
            "token_amplification",
        );
    }
    let request = TokenMintRequest {
        allowed_nodes: Some(BTreeSet::new()),
        ..valid.clone()
    };
    assert_eq!(
        authorize_token_mint(&empty_parent, &target, &request, &policy, &managed),
        Ok(())
    );
    let mut open = ctx.clone();
    open.token.allowed_nodes = None;
    let foreign_request = TokenMintRequest {
        allowed_nodes: Some(BTreeSet::from([foreign])),
        ..valid.clone()
    };
    denied(
        authorize_token_mint(&open, &target, &foreign_request, &policy, &managed),
        AuthzError::TokenAmplification("unmanaged_node"),
        403,
        "token_amplification",
    );
    let none = TokenMintRequest {
        allowed_nodes: None,
        ..valid
    };
    assert_eq!(
        authorize_token_mint(&open, &target, &none, &policy, &managed),
        Ok(())
    );
    let own = &open.caller;
    denied(
        authorize_token_mint(&open, own, &none, &policy, &managed),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );

    let original = context(own.clone(), vec![]);
    assert_eq!(authorize_token_revoke(&original, &target), Ok(()));
    for token in narrowed_tokens(&original.token) {
        let ctx = AuthContext {
            token,
            ..original.clone()
        };
        denied(
            authorize_token_revoke(&ctx, &target),
            AuthzError::UnrestrictedTokenRequired,
            403,
            "token_narrowed",
        );
    }
}

#[test]
fn min_of_configured_and_hard_ttl_caps_is_inclusive_and_overflow_safe() {
    let ctx = context(orchestrator(), vec![]);
    let child = child(None, Some(&ctx.caller));
    let max = MAX_ORCHESTRATOR_AGENT_TOKEN_TTL_MS;
    let managed = BTreeSet::new();
    for (config, accepted) in [(max + 99, max), (99, 99)] {
        let policy = OrchestratorLimits {
            agent_token_ttl_ms: config,
            ..Default::default()
        };
        let mint = |ttl| {
            let req = TokenMintRequest {
                expires_at_ms: Some(ctx.now_ms + ttl),
                ..Default::default()
            };
            authorize_token_mint(&ctx, &child, &req, &policy, &managed)
        };
        assert_eq!(mint(accepted), Ok(()));
        for invalid in [accepted + 1, 0, -1] {
            denied(mint(invalid), AuthzError::InvalidTtl, 400, "invalid_input");
        }
    }
    for (now, expires, accepted) in [
        (i64::MIN, i64::MAX, false),
        (i64::MIN, i64::MIN + 10, true),
        (i64::MAX - 1, i64::MAX, true),
        (i64::MAX, i64::MIN, false),
    ] {
        let ctx = AuthContext {
            now_ms: now,
            ..ctx.clone()
        };
        let req = TokenMintRequest {
            expires_at_ms: Some(expires),
            ..Default::default()
        };
        let result =
            authorize_token_mint(&ctx, &child, &req, &OrchestratorLimits::default(), &managed);
        if accepted {
            assert_eq!(result, Ok(()));
        } else {
            denied(result, AuthzError::InvalidTtl, 400, "invalid_input");
        }
    }
}

#[test]
fn enrollment_checks_manager_tags_reenroll_and_ttl() {
    let mut ctx = context(orchestrator(), vec![]);
    let manager = Some(ctx.caller.principal_id);
    let mut request = EnrollmentRequest {
        is_reenroll: false,
        requested_tags: BTreeSet::from(["sandbox".into()]),
        managed_by_principal_id: manager,
        ttl_ms: MAX_ORCHESTRATOR_ENROLLMENT_TTL_MS,
    };
    let high = OrchestratorLimits {
        enrollment_ttl_ms: MAX_ORCHESTRATOR_ENROLLMENT_TTL_MS + 100,
        ..Default::default()
    };
    assert_eq!(authorize_node_enrollment(&ctx, &request, &high), Ok(()));
    request.ttl_ms += 1;
    denied(
        authorize_node_enrollment(&ctx, &request, &high),
        AuthzError::InvalidTtl,
        400,
        "invalid_input",
    );
    request.ttl_ms = 5;
    for mut tags in [
        BTreeSet::from(["prod".to_owned()]),
        BTreeSet::from(["sandbox".into(), "prod".into()]),
    ] {
        request.requested_tags = std::mem::take(&mut tags);
        denied(
            authorize_node_enrollment(&ctx, &request, &high),
            AuthzError::NodeTagNotAllowed { tag: "prod".into() },
            403,
            "node_tag_not_allowed",
        );
    }
    ctx.caller.allowed_node_tags.clear();
    request.requested_tags = BTreeSet::from(["sandbox".into()]);
    denied(
        authorize_node_enrollment(&ctx, &request, &high),
        AuthzError::NodeTagNotAllowed {
            tag: "sandbox".into(),
        },
        403,
        "node_tag_not_allowed",
    );
    request.requested_tags.clear();
    assert_eq!(authorize_node_enrollment(&ctx, &request, &high), Ok(()));
    request.managed_by_principal_id = None;
    denied(
        authorize_node_enrollment(&ctx, &request, &high),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    request.managed_by_principal_id = manager;
    let low = OrchestratorLimits {
        enrollment_ttl_ms: 4,
        ..Default::default()
    };
    denied(
        authorize_node_enrollment(&ctx, &request, &low),
        AuthzError::InvalidTtl,
        400,
        "invalid_input",
    );
    request.ttl_ms = 4;
    assert_eq!(authorize_node_enrollment(&ctx, &request, &low), Ok(()));

    request.is_reenroll = true;
    denied(
        authorize_node_enrollment(&ctx, &request, &high),
        AuthzError::AdminHumanRequired,
        403,
        "admin_human_required",
    );
    assert_eq!(authorize_node_enrollment(&admin(), &request, &high), Ok(()));
    for bad in [0, -1, i64::MAX] {
        request.ttl_ms = bad;
        denied(
            authorize_node_enrollment(&admin(), &request, &high),
            AuthzError::InvalidTtl,
            400,
            "invalid_input",
        );
        request.is_reenroll = false;
        denied(
            authorize_node_enrollment(&ctx, &request, &high),
            AuthzError::InvalidTtl,
            400,
            "invalid_input",
        );
        request.is_reenroll = true;
    }
}

#[test]
fn managed_nodes_have_distinct_read_and_mutation_scope() {
    let mut ctx = context(orchestrator(), vec![]);
    let first = node(Some(ctx.caller.principal_id));
    let other = node(Some(ctx.caller.principal_id));
    let foreign = node(Some(PrincipalId::new_service()));
    assert_eq!(authorize_node_read(&ctx, &first), Ok(()));
    assert_eq!(authorize_node_revoke_or_delete(&ctx, &first), Ok(()));
    ctx.token.allowed_nodes = Some(BTreeSet::from([first.node_id, foreign.node_id]));
    assert_eq!(authorize_node_read(&ctx, &first), Ok(()));
    denied(
        authorize_node_read(&ctx, &other),
        AuthzError::ScopeNarrowedOut,
        403,
        "forbidden",
    );
    denied(
        authorize_node_read(&ctx, &foreign),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    denied(
        authorize_node_revoke_or_delete(&ctx, &first),
        AuthzError::UnrestrictedTokenRequired,
        403,
        "token_narrowed",
    );
    denied(
        authorize_node_revoke_or_delete(&ctx, &foreign),
        AuthzError::Forbidden,
        403,
        "forbidden",
    );
    assert_eq!(authorize_node_revoke_or_delete(&admin(), &foreign), Ok(()));
}
