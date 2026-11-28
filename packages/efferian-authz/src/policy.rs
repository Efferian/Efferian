use efferian_protocol::{Capability, GrantScope, PrincipalKind, ProfileId};

use crate::{AuthContext, AuthzError, GrantView, PrincipalView};

#[derive(Clone, Copy)]
pub(crate) struct CheckedContext<'a>(&'a AuthContext);

#[derive(Clone, Copy)]
pub(crate) struct ActiveContext<'a>(CheckedContext<'a>);

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Admission,
    Invoke,
}

impl<'a> CheckedContext<'a> {
    pub(crate) fn context(self) -> &'a AuthContext {
        self.0
    }

    pub(crate) fn active(self, phase: Phase) -> Result<ActiveContext<'a>, AuthzError> {
        let ctx = self.context();
        let owner_disabled = ctx.owner.as_ref().is_some_and(is_disabled);
        let manager_disabled = ctx.managed_by.as_ref().is_some_and(is_disabled);
        let same_parent = ctx.caller.owner_principal_id == ctx.caller.managed_by_principal_id;
        if matches!(phase, Phase::Invoke) && manager_disabled && !same_parent {
            return Err(AuthzError::ManagedByDisabled);
        }
        if owner_disabled {
            return Err(AuthzError::OwnerDisabled);
        }
        if manager_disabled {
            return Err(AuthzError::ManagedByDisabled);
        }
        Ok(ActiveContext(self))
    }

    pub(crate) fn effective_profile_capability(self, profile_id: ProfileId) -> Option<Capability> {
        let ctx = self.context();
        if !ctx.token.permits_profile(Some(profile_id)) {
            return None;
        }
        let mut cap = raw_profile_capability(&ctx.caller, &ctx.caller_grants, profile_id)?;
        if let Some(owner) = &ctx.owner {
            cap = cap.min(raw_profile_capability(
                owner,
                &ctx.owner_grants,
                profile_id,
            )?);
        }
        if let Some(manager) = &ctx.managed_by {
            cap = cap.min(raw_profile_capability(
                manager,
                &ctx.managed_by_grants,
                profile_id,
            )?);
        }
        if let Some(max) = ctx.token.max_capability {
            cap = cap.min(max);
        }
        Some(cap)
    }
}

impl<'a> ActiveContext<'a> {
    pub(crate) fn checked(self) -> CheckedContext<'a> {
        self.0
    }

    pub(crate) fn context(self) -> &'a AuthContext {
        self.checked().context()
    }

    pub(crate) fn global_admin(self) -> bool {
        let ctx = self.context();
        has_global_admin(&ctx.caller, &ctx.caller_grants)
    }

    pub(crate) fn unrestricted_admin(self) -> bool {
        self.global_admin() && self.context().token.is_unrestricted()
    }

    pub(crate) fn require_unrestricted(self) -> Result<(), AuthzError> {
        if !self.context().token.is_unrestricted() {
            return Err(AuthzError::UnrestrictedTokenRequired);
        }
        Ok(())
    }

    pub(crate) fn require_admin(self) -> Result<(), AuthzError> {
        if self.context().caller.kind != PrincipalKind::Admin {
            return Err(AuthzError::AdminHumanRequired);
        }
        if !self.global_admin() {
            return Err(AuthzError::InsufficientCapability);
        }
        self.require_unrestricted()
    }

    pub(crate) fn owns(self, target: &PrincipalView) -> bool {
        self.context().caller.kind == PrincipalKind::Member
            && target.kind == PrincipalKind::Agent
            && target.owner_principal_id == Some(self.context().caller.principal_id)
    }

    pub(crate) fn manages(self, target: &PrincipalView) -> bool {
        let caller = &self.context().caller;
        target.kind == PrincipalKind::Agent
            && target.managed_by_principal_id == Some(caller.principal_id)
            && (self.owns(target) || (caller.orchestrator() && target.owner_principal_id.is_none()))
    }
}

pub(crate) fn has_global_admin(principal: &PrincipalView, grants: &[GrantView]) -> bool {
    principal.kind == PrincipalKind::Admin
        && grants
            .iter()
            .any(|grant| grant.scope == GrantScope::Global && grant.capability == Capability::Admin)
}

fn raw_profile_capability(
    principal: &PrincipalView,
    grants: &[GrantView],
    profile_id: ProfileId,
) -> Option<Capability> {
    if has_global_admin(principal, grants) {
        return Some(Capability::Invoke);
    }
    grants
        .iter()
        .filter(|grant| {
            grant.capability != Capability::Admin
                && (grant.scope == GrantScope::Global
                    || grant.scope == GrantScope::Profile(profile_id))
        })
        .map(|grant| grant.capability)
        .max()
}

pub(crate) fn verify_context(ctx: &AuthContext) -> Result<CheckedContext<'_>, AuthzError> {
    ctx.caller.validate()?;
    if ctx.token.principal_id != ctx.caller.principal_id
        || !ctx.token.token_id.matches_kind(ctx.caller.kind)
        || !ctx.token.is_active(ctx.now_ms)
    {
        return Err(AuthzError::Unauthenticated);
    }
    if is_disabled(&ctx.caller) {
        return Err(AuthzError::PrincipalDisabled);
    }

    validate_parents(&ctx.caller, ctx.owner.as_ref(), ctx.managed_by.as_ref())?;
    if (ctx.owner.is_none() && !ctx.owner_grants.is_empty())
        || (ctx.managed_by.is_none() && !ctx.managed_by_grants.is_empty())
    {
        return Err(AuthzError::InvalidAuthContext);
    }
    Ok(CheckedContext(ctx))
}

pub(crate) fn validate_parents(
    caller: &PrincipalView,
    owner: Option<&PrincipalView>,
    manager: Option<&PrincipalView>,
) -> Result<(), AuthzError> {
    use PrincipalKind::{Admin, Agent, Member, Service};

    if caller.owner_principal_id != owner.map(|p| p.principal_id)
        || caller.managed_by_principal_id != manager.map(|p| p.principal_id)
    {
        return Err(AuthzError::InvalidAuthContext);
    }
    if let Some(owner) = owner {
        owner.validate()?;
        if !matches!(owner.kind, Admin | Member) {
            return Err(AuthzError::InvalidAuthContext);
        }
    }
    if let Some(manager) = manager {
        manager.validate()?;
        if !matches!(manager.kind, Admin | Member | Service)
            || (caller.kind == Agent
                && owner.is_none()
                && manager.kind == Service
                && !manager.orchestrator())
            || owner
                .is_some_and(|owner| owner.principal_id == manager.principal_id && owner != manager)
        {
            return Err(AuthzError::InvalidAuthContext);
        }
    }
    Ok(())
}

fn is_disabled(principal: &PrincipalView) -> bool {
    principal.disabled_at_ms.is_some()
}

pub(crate) fn guard(ctx: &AuthContext) -> Result<ActiveContext<'_>, AuthzError> {
    verify_context(ctx)?.active(Phase::Admission)
}

/// Repeat the activity and snapshot checks without checking a particular resource.
pub fn check_active(ctx: &AuthContext) -> Result<(), AuthzError> {
    guard(ctx).map(|_| ())
}

pub fn authorize_admin(ctx: &AuthContext) -> Result<(), AuthzError> {
    guard(ctx)?.require_admin()
}
