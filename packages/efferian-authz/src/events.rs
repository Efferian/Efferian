use efferian_protocol::{Capability, EventKind, NodeId, PrincipalId, PrincipalKind, ProfileId};

use crate::{AuthContext, policy::guard};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventAuthTarget {
    pub kind: EventKind,
    /// Execution caller, node manager, or the affected principal in an auth revocation.
    pub owner_principal_id: Option<PrincipalId>,
    /// The execution caller's recorded owner.
    pub agent_owner_principal_id: Option<PrincipalId>,
    pub node_id: Option<NodeId>,
    pub profile_id: Option<ProfileId>,
}

pub fn can_observe_event(ctx: &AuthContext, event: &EventAuthTarget) -> bool {
    let Ok(active) = guard(ctx) else { return false };
    if active.unrestricted_admin() {
        return true;
    }

    let caller = ctx.caller.principal_id;
    let owner = event.owner_principal_id == Some(caller);
    let profile_visible = || {
        event.profile_id.is_some_and(|profile| {
            active.checked().effective_profile_capability(profile) >= Some(Capability::Discover)
        })
    };

    match event.kind {
        EventKind::ExecutionStarted
        | EventKind::ExecutionFinished
        | EventKind::ExecutionCancelled
        | EventKind::ExecutionLateReceipt => {
            ctx.token.permits_profile(event.profile_id)
                && ctx.token.permits_node(event.node_id)
                && (owner
                    || event.agent_owner_principal_id == Some(caller)
                    || (ctx.caller.kind == PrincipalKind::Service
                        && ctx.caller.observe_executions
                        && profile_visible()))
        }
        EventKind::NodeConnected | EventKind::NodeDisconnected | EventKind::NodeRevoked => {
            ctx.caller.orchestrator()
                && owner
                && event.node_id.is_some()
                && ctx.token.permits_node(event.node_id)
        }
        EventKind::ProfilePublished => profile_visible(),
        EventKind::AuthRevoked => owner,
    }
}
