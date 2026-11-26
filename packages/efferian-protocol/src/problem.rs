use std::collections::BTreeMap;

use serde_json::Value;

use crate::{TraceId, wire::wire_struct};

pub const PROBLEM_JSON_MEDIA_TYPE: &str = "application/problem+json";

wire_struct! {
    []
    /// RFC 9457 response emitted by Efferian. Readers ignore unknown top-level extensions.
    #[derive(Clone, Debug, PartialEq)]
    pub struct ProblemDetails {
        #[serde(rename = "type")]
        pub problem_type: String,
        pub title: String,
        pub status: u16,
        pub code: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub instance: Option<String>,
        pub retryable: bool,
        pub trace_id: TraceId,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub extensions: BTreeMap<String, Value>,
    }
}

impl ProblemDetails {
    pub fn new(
        status: u16,
        code: impl Into<String>,
        title: impl Into<String>,
        retryable: bool,
        trace_id: TraceId,
    ) -> Self {
        let code = code.into();
        Self {
            problem_type: format!("urn:efferian:problem:{code}"),
            title: title.into(),
            status,
            code,
            detail: None,
            instance: None,
            retryable,
            trace_id,
            extensions: BTreeMap::new(),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }

    pub fn with_extension(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extensions.insert(key.into(), value.into());
        self
    }
}

pub mod error_codes {
    pub const UNAUTHENTICATED: &str = "unauthenticated";
    pub const FORBIDDEN: &str = "forbidden";
    pub const ADMIN_HUMAN_REQUIRED: &str = "admin_human_required";
    pub const TOKEN_NARROWED: &str = "token_narrowed";
    pub const TOKEN_AMPLIFICATION: &str = "token_amplification";
    pub const NODE_TAG_NOT_ALLOWED: &str = "node_tag_not_allowed";
    pub const ACCOUNT_NOT_BOUND: &str = "account_not_bound";
    pub const PRINCIPAL_DISABLED: &str = "principal_disabled";
    pub const OWNER_DISABLED: &str = "owner_disabled";
    pub const MANAGED_BY_DISABLED: &str = "managed_by_disabled";

    pub const NOT_FOUND: &str = "not_found";
    pub const TOOL_NOT_FOUND: &str = "tool_not_found";
    pub const ACCOUNT_NOT_FOUND: &str = "account_not_found";
    pub const TOOL_DISABLED: &str = "tool_disabled";
    pub const RESOURCE_IN_USE: &str = "resource_in_use";
    pub const NODE_NAME_IN_USE: &str = "node_name_in_use";
    pub const HUB_IDENTITY_MISMATCH: &str = "hub_identity_mismatch";

    pub const INVALID_INPUT: &str = "invalid_input";
    pub const INVALID_ARGUMENTS: &str = "invalid_arguments";
    pub const AMBIGUOUS_TARGET: &str = "ambiguous_target";
    pub const TARGET_REQUIRED: &str = "target_required";
    pub const REQUEST_ID_CONFLICT: &str = "request_id_conflict";
    pub const REQUEST_ID_EXPIRED: &str = "request_id_expired";
    pub const NODE_OFFLINE: &str = "node_offline";
    pub const NODE_BUSY: &str = "node_busy";
    pub const UPSTREAM_BUSY: &str = "upstream_busy";
    pub const UPSTREAM_AUTH_FAILED: &str = "upstream_auth_failed";
    pub const OVERLOADED: &str = "overloaded";
    pub const STORAGE_PRESSURE: &str = "storage_pressure";
    pub const RESYNC_REQUIRED: &str = "resync_required";
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    pub const INTERNAL_ERROR: &str = "internal_error";
}
