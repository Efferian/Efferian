use efferian_protocol::{
    AccountId, AccountKind, AccountNotBoundReason, AccountVisibility, Capability, PrincipalKind,
    UpstreamId,
};

use crate::{
    AccountView, AuthContext, AuthzError, BindingUpstream, BindingView, InvokeBindingView,
    PrincipalView, SubjectMetadata,
    policy::{ActiveContext, guard},
    principal::check_subject_metadata,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountAccess {
    Read,
    Mutate,
}

pub fn authorize_account_access(
    ctx: &AuthContext,
    account: &AccountView,
    access: AccountAccess,
) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    if active.unrestricted_admin() {
        return Ok(());
    }
    let member = owns_private_account(active, account);
    match access {
        AccountAccess::Read if member => Ok(()),
        AccountAccess::Mutate if member || active.global_admin() => active.require_unrestricted(),
        _ => Err(AuthzError::Forbidden),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingMutation {
    Set,
    Remove { existing: BindingView },
}

pub fn authorize_binding_read(
    ctx: &AuthContext,
    upstream: Option<BindingUpstream<'_>>,
    subject: &PrincipalView,
    binding: &BindingView,
) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    let upstream = visible_binding_upstream(active, upstream)?;
    if binding.upstream_id != upstream || binding.principal_id != subject.principal_id {
        return Err(AuthzError::ResourceNotFound);
    }
    check_subject_metadata(active, subject, SubjectMetadata::AccountBindings)
}

pub fn authorize_binding_mutation(
    ctx: &AuthContext,
    upstream: Option<BindingUpstream<'_>>,
    subject: &PrincipalView,
    account: &AccountView,
    mutation: BindingMutation,
) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    let upstream = visible_binding_upstream(active, upstream)?;
    subject.validate()?;
    let matches_operation = match mutation {
        BindingMutation::Set => is_http_account_for(account, upstream),
        BindingMutation::Remove { existing } => {
            existing.upstream_id == upstream
                && existing.principal_id == subject.principal_id
                && existing.account_id == account.account_id
        }
    };
    if !matches_operation {
        return Err(AuthzError::Forbidden);
    }
    let member = owns_private_account(active, account)
        && (subject.principal_id == ctx.caller.principal_id || active.owns(subject));
    if !active.global_admin() && !member {
        return Err(AuthzError::Forbidden);
    }
    active.require_unrestricted()
}

fn is_http_account_for(account: &AccountView, upstream: UpstreamId) -> bool {
    account.kind == AccountKind::HttpAuth && account.upstream_id == Some(upstream)
}

fn owns_private_account(active: ActiveContext<'_>, account: &AccountView) -> bool {
    let caller = &active.context().caller;
    caller.kind == PrincipalKind::Member
        && account.visibility == AccountVisibility::Private
        && account.owner_principal_id == caller.principal_id
}

fn visible_binding_upstream(
    active: ActiveContext<'_>,
    upstream: Option<BindingUpstream<'_>>,
) -> Result<UpstreamId, AuthzError> {
    let upstream = upstream.ok_or(AuthzError::ResourceNotFound)?;
    if active.unrestricted_admin()
        || (active.context().token.permits_node(None)
            && upstream.caller_bound_profiles.iter().any(|&profile| {
                active.checked().effective_profile_capability(profile) >= Some(Capability::Discover)
            }))
    {
        return Ok(upstream.upstream_id);
    }
    Err(AuthzError::ResourceNotFound)
}

pub(crate) fn resolve_caller_bound_account(
    active: ActiveContext<'_>,
    upstream_id: UpstreamId,
    bindings: &[InvokeBindingView],
) -> Result<AccountId, AuthzError> {
    let ctx = active.context();
    let explicit = |principal_id| {
        let mut matches = bindings.iter().filter(|row| {
            row.binding.principal_id == principal_id && row.binding.upstream_id == upstream_id
        });
        let Some(row) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(AuthzError::InvalidAuthContext);
        }
        let account = row.account.ok_or(AuthzError::InvalidAuthContext)?;
        if account.account_id != row.binding.account_id {
            return Err(AuthzError::InvalidAuthContext);
        }
        if !is_http_account_for(&account, upstream_id) {
            return Err(AuthzError::AccountNotBound {
                reason: AccountNotBoundReason::MissingBinding,
            });
        }
        Ok(Some(account.account_id))
    };

    if let Some(account) = explicit(ctx.caller.principal_id)? {
        return Ok(account);
    }
    if let Some(owner) = &ctx.owner {
        if !ctx.caller.inherit_owner_bindings {
            return Err(AuthzError::AccountNotBound {
                reason: AccountNotBoundReason::InheritDisabled,
            });
        }
        if let Some(account) = explicit(owner.principal_id)? {
            return Ok(account);
        }
    }
    Err(AuthzError::AccountNotBound {
        reason: AccountNotBoundReason::MissingBinding,
    })
}
