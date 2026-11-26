use efferian_protocol::{Capability, GrantScope, PrincipalKind};

use crate::{
    AuthContext, AuthzError, GrantView, PrincipalView,
    policy::{ActiveContext, guard, validate_parents},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalAccess {
    Read,
    Disable,
    Enable,
    Delete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectMetadata {
    Grants,
    Tokens,
    AccountBindings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantMutation {
    Put,
    Remove,
}

pub fn authorize_principal_upsert(
    ctx: &AuthContext,
    requested: &PrincipalView,
    existing: Option<&PrincipalView>,
    requested_owner: Option<&PrincipalView>,
    requested_manager: Option<&PrincipalView>,
) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    requested.validate()?;
    if let Some(existing) = existing {
        existing.validate()?;
        if existing.principal_id != requested.principal_id
            || existing.kind != requested.kind
            || (existing.kind == PrincipalKind::Agent
                && (existing.owner_principal_id != requested.owner_principal_id
                    || existing.managed_by_principal_id != requested.managed_by_principal_id))
        {
            return Err(AuthzError::Forbidden);
        }
    }
    validate_parents(requested, requested_owner, requested_manager)?;
    allow_subject_mutation(active, requested)
}

pub fn authorize_principal_manage(
    ctx: &AuthContext,
    target: &PrincipalView,
    access: PrincipalAccess,
) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    target.validate()?;
    if access == PrincipalAccess::Read {
        return if can_read_principal(active, target) {
            Ok(())
        } else {
            Err(AuthzError::Forbidden)
        };
    }
    allow_subject_mutation(active, target)
}

pub fn authorize_subject_metadata_read(
    ctx: &AuthContext,
    target: &PrincipalView,
    metadata: SubjectMetadata,
) -> Result<(), AuthzError> {
    check_subject_metadata(guard(ctx)?, target, metadata)
}

pub(crate) fn check_subject_metadata(
    active: ActiveContext<'_>,
    target: &PrincipalView,
    metadata: SubjectMetadata,
) -> Result<(), AuthzError> {
    target.validate()?;
    if !can_read_principal(active, target) {
        return Err(AuthzError::Forbidden);
    }
    let caller = &active.context().caller;
    let member = caller.kind == PrincipalKind::Member
        && (caller.principal_id == target.principal_id || active.owns(target));
    let orchestrator = metadata != SubjectMetadata::AccountBindings
        && caller.orchestrator()
        && active.manages(target);

    if active.unrestricted_admin() || member || orchestrator {
        Ok(())
    } else {
        Err(AuthzError::Forbidden)
    }
}

fn can_read_principal(active: ActiveContext<'_>, target: &PrincipalView) -> bool {
    active.unrestricted_admin()
        || active.context().caller.principal_id == target.principal_id
        || active.owns(target)
        || active.manages(target)
}

fn allow_subject_mutation(
    active: ActiveContext<'_>,
    target: &PrincipalView,
) -> Result<(), AuthzError> {
    if active.global_admin() || active.manages(target) {
        return active.require_unrestricted();
    }
    Err(AuthzError::Forbidden)
}

pub fn authorize_grant_mutation(
    ctx: &AuthContext,
    target: &PrincipalView,
    grant: GrantView,
    mutation: GrantMutation,
) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    target.validate()?;
    if grant.capability == Capability::Admin && mutation == GrantMutation::Put {
        if grant.scope != GrantScope::Global {
            return Err(AuthzError::InvalidGrantScope);
        }
        if ctx.caller.kind != PrincipalKind::Admin || target.kind != PrincipalKind::Admin {
            return Err(AuthzError::AdminHumanRequired);
        }
    }
    if active.global_admin() {
        return active.require_unrestricted();
    }
    let GrantScope::Profile(profile) = grant.scope else {
        return Err(AuthzError::Forbidden);
    };
    if !active.manages(target) || grant.capability == Capability::Admin {
        return Err(AuthzError::Forbidden);
    }
    active.require_unrestricted()?;
    if mutation == GrantMutation::Put
        && active.checked().effective_profile_capability(profile) < Some(grant.capability)
    {
        return Err(AuthzError::GrantEscalation);
    }
    Ok(())
}
