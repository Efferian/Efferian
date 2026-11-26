use std::collections::BTreeSet;

use crate::{
    ExecutionMode, NodeId, ToolId, ValidationError, validate_public_tool_name, wire::strict_struct,
};

pub const MAX_WAIT_MS: u32 = 25_000;
pub const DEFAULT_INLINE_WAIT_MS: u32 = 15_000;
pub const DEFAULT_MCP_EXECUTION_GET_WAIT_MS: u32 = 20_000;
pub const MAX_PROFILE_BINDINGS: usize = 1024;
pub const RESERVED_CONTROL_TOOL_NAMES: [&str; 5] = [
    "efferian_search",
    "efferian_inspect",
    "efferian_invoke",
    "efferian_execution_get",
    "efferian_execution_cancel",
];

strict_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ProfileToolBinding {
        pub public_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description_override: Option<String>,
        pub tool_id: ToolId,
        pub tool_version: u64 => (minimum = 1),
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fixed_node_id: Option<NodeId>,
        #[serde(default)]
        pub curated_featured: bool,
        #[serde(default)]
        pub execution_mode: ExecutionMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inline_wait_ms: Option<u32> => (maximum = 25_000),
    }
}

pub fn validate_profile_bindings(bindings: &[ProfileToolBinding]) -> Result<(), ValidationError> {
    if bindings.len() > MAX_PROFILE_BINDINGS {
        return Err(ValidationError::InvalidField("profile bindings count"));
    }
    let mut names = BTreeSet::new();
    for binding in bindings {
        validate_public_tool_name(&binding.public_name)?;
        if !names.insert(&binding.public_name) {
            return Err(ValidationError::InvalidField("duplicate public tool name"));
        }
        if binding.tool_version == 0 {
            return Err(ValidationError::InvalidField("tool version"));
        }
        if let Some(wait) = binding.inline_wait_ms
            && (wait > MAX_WAIT_MS || binding.execution_mode == ExecutionMode::Async)
        {
            return Err(ValidationError::InvalidField("inline wait"));
        }
    }
    Ok(())
}
