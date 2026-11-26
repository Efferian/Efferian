use efferian_protocol::{Capability, NodeId, PrincipalId, ProfileId};

use crate::{AuthContext, AuthzError, policy::guard};

/// Stored authorization attributes of an execution, including its original node and owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionAuthTarget {
    pub caller_principal_id: PrincipalId,
    pub caller_owner_principal_id: Option<PrincipalId>,
    pub profile_id: Option<ProfileId>,
    pub node_id: Option<NodeId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionAccess {
    ReadMetadata,
    ReadSensitive,
    Cancel,
}

pub fn authorize_execution_access(
    ctx: &AuthContext,
    target: Option<&ExecutionAuthTarget>,
    access: ExecutionAccess,
) -> Result<(), AuthzError> {
    let active = guard(ctx)?;
    let target = target.ok_or(AuthzError::ResourceNotFound)?;
    if active.unrestricted_admin() {
        return Ok(());
    }
    let caller = ctx.caller.principal_id;
    let owns =
        target.caller_principal_id == caller || target.caller_owner_principal_id == Some(caller);
    if !owns
        || !ctx.token.permits_profile(target.profile_id)
        || !ctx.token.permits_node(target.node_id)
    {
        return Err(AuthzError::ResourceNotFound);
    }
    if access == ExecutionAccess::ReadSensitive && ctx.token.withhold_sensitive {
        return Err(AuthzError::SensitiveWithheld);
    }
    if access != ExecutionAccess::ReadMetadata && !ctx.token.permits_capability(Capability::Invoke)
    {
        return Err(AuthzError::InsufficientCapability);
    }
    Ok(())
}

pub fn can_read_sensitive_result(ctx: &AuthContext, target: &ExecutionAuthTarget) -> bool {
    authorize_execution_access(ctx, Some(target), ExecutionAccess::ReadSensitive).is_ok()
}
