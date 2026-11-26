use crate::wire::strict_enum;

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{
    AccountId, AccountKind, AccountSecretPayload, ArgBinding, EgressPolicy, EnvBinding,
    ExecuteReqPayload, ExecutionId, HttpBodyBinding, HttpMethod, MAX_RESOLVED_ACTION_BYTES, NodeId,
    ResolvedAction, SecretString, ToolKind, UpstreamAccountMode, UpstreamId, ValidationError,
    action::{validate_runtime_limits, validate_ssh_fields},
    binding::copy_text,
    compute_input_schema_sha256,
    validate::*,
    wire::{BoundedJsonError, bounded_json_len, strict_struct},
};

pub const MAX_TOOL_DEFINITION_BYTES: usize = 256 * 1024;
pub const MAX_FIXED_TARGET_NODES: usize = 64;
pub const DEFAULT_UPSTREAM_HARD_TIMEOUT_MS: u64 = 300_000;

strict_enum! {
    tag = "kind",
    #[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
    pub enum TargetSelector {
        Fixed { node_ids: Vec<NodeId> },
        Tag { tag: String },
    }
}

impl TargetSelector {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Fixed { node_ids } => {
                if !(1..=MAX_FIXED_TARGET_NODES).contains(&node_ids.len())
                    || node_ids.iter().collect::<BTreeSet<_>>().len() != node_ids.len()
                {
                    return Err(ValidationError::InvalidField("fixed target nodes"));
                }
                Ok(())
            }
            Self::Tag { tag } => validate_node_tag(tag),
        }
    }
}

strict_struct! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ToolAnnotations {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub read_only_hint: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub destructive_hint: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub idempotent_hint: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub open_world_hint: Option<bool>,
    }
}

strict_struct! {
    #[derive(Clone, Debug, PartialEq)]
    pub struct ToolDefinition {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub input_schema: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub annotations: Option<ToolAnnotations>,
        pub spec: ToolSpec,
    }
}

strict_enum! {
    tag = "kind",
    #[derive(Clone, Debug, PartialEq, Deserialize)]
    pub enum ToolSpec {
        Command {
            program: String,
            args: Vec<ArgBinding>,
            cwd: String,
            #[serde(deserialize_with = "crate::wire::deserialize_unique_map")]
            env: BTreeMap<String, EnvBinding>,
            #[serde(skip_serializing_if = "Option::is_none")]
            account_id: Option<AccountId>,
            target_selector: TargetSelector,
            runtime_ms: u64,
            max_output_bytes: u32,
        },
        Script {
            interpreter: String,
            code: String,
            args: Vec<ArgBinding>,
            cwd: String,
            #[serde(deserialize_with = "crate::wire::deserialize_unique_map")]
            env: BTreeMap<String, EnvBinding>,
            #[serde(skip_serializing_if = "Option::is_none")]
            account_id: Option<AccountId>,
            target_selector: TargetSelector,
            runtime_ms: u64,
            max_output_bytes: u32,
        },
        Http {
            method: HttpMethod,
            base_url: String,
            path_segments: Vec<ArgBinding>,
            #[serde(deserialize_with = "crate::wire::deserialize_unique_map")]
            query: BTreeMap<String, ArgBinding>,
            #[serde(deserialize_with = "crate::wire::deserialize_unique_map")]
            headers: BTreeMap<String, ArgBinding>,
            #[serde(skip_serializing_if = "Option::is_none")]
            body: Option<HttpBodyBinding>,
            #[serde(skip_serializing_if = "Option::is_none")]
            account_id: Option<AccountId>,
            target_selector: TargetSelector,
            runtime_ms: u64,
            max_output_bytes: u32,
        },
        Ssh {
            host: String,
            port: u16,
            user: String,
            command: String,
            args: Vec<ArgBinding>,
            known_hosts_file: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            account_id: Option<AccountId>,
            #[serde(skip_serializing_if = "Option::is_none")]
            identity_file: Option<String>,
            target_selector: TargetSelector,
            runtime_ms: u64,
            max_output_bytes: u32,
        },
        UpstreamRef {
            upstream_id: UpstreamId,
            upstream_tool_name: String,
            account_mode: UpstreamAccountMode,
            #[serde(skip_serializing_if = "Option::is_none")]
            shared_account_id: Option<AccountId>,
            runtime_ms: u64,
        },
    }
}

impl ToolSpec {
    pub const fn kind(&self) -> ToolKind {
        match self {
            Self::Command { .. } => ToolKind::Command,
            Self::Script { .. } => ToolKind::Script,
            Self::Http { .. } => ToolKind::Http,
            Self::Ssh { .. } => ToolKind::Ssh,
            Self::UpstreamRef { .. } => ToolKind::UpstreamRef,
        }
    }

    pub const fn target_selector(&self) -> Option<&TargetSelector> {
        match self {
            Self::Command {
                target_selector, ..
            }
            | Self::Script {
                target_selector, ..
            }
            | Self::Http {
                target_selector, ..
            }
            | Self::Ssh {
                target_selector, ..
            } => Some(target_selector),
            Self::UpstreamRef { .. } => None,
        }
    }

    pub const fn runtime_ms(&self) -> u64 {
        match self {
            Self::Command { runtime_ms, .. }
            | Self::Script { runtime_ms, .. }
            | Self::Http { runtime_ms, .. }
            | Self::Ssh { runtime_ms, .. }
            | Self::UpstreamRef { runtime_ms, .. } => *runtime_ms,
        }
    }

    pub const fn max_output_bytes(&self) -> Option<u32> {
        match self {
            Self::Command {
                max_output_bytes, ..
            }
            | Self::Script {
                max_output_bytes, ..
            }
            | Self::Http {
                max_output_bytes, ..
            }
            | Self::Ssh {
                max_output_bytes, ..
            } => Some(*max_output_bytes),
            Self::UpstreamRef { .. } => None,
        }
    }
}

/// The authoritative discovery metadata for one exact upstream tool.
#[derive(Clone, Debug, PartialEq)]
pub struct DiscoveredUpstreamTool {
    pub upstream_id: UpstreamId,
    pub tool_name: String,
    pub description: Option<String>,
    pub input_schema: Value,
    pub annotations: Option<ToolAnnotations>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolRevisionDefinition {
    pub definition: ToolDefinition,
    pub input_schema_sha256: String,
}

/// An account selected by the launcher after authorization and opened by its vault.
#[derive(Clone, Copy, Debug)]
pub struct ManagedAccount<'a> {
    pub account_id: AccountId,
    pub upstream_id: Option<UpstreamId>,
    pub payload: &'a AccountSecretPayload,
}

impl ToolDefinition {
    pub const fn kind(&self) -> ToolKind {
        self.spec.kind()
    }

    /// Validate an authored definition. Upstream schema snapshots are created by freeze_revision.
    pub fn validate(
        &self,
        max_runtime_ms: u64,
        upstream_hard_timeout_ms: u64,
        policy: &EgressPolicy,
    ) -> Result<(), ValidationError> {
        bounded_json_len(MAX_TOOL_DEFINITION_BYTES, |writer| {
            serde_json::to_writer(writer, self)
        })
        .map_err(|error| match error {
            BoundedJsonError::TooLarge => ValidationError::DefinitionLimit,
            BoundedJsonError::Serialization => ValidationError::InvalidJson,
        })?;

        if let ToolSpec::UpstreamRef {
            upstream_tool_name,
            account_mode,
            shared_account_id,
            runtime_ms,
            ..
        } = &self.spec
        {
            validate_runtime_limits(*runtime_ms, max_runtime_ms.min(upstream_hard_timeout_ms), 0)?;
            if self.input_schema.is_some() {
                return Err(ValidationError::InvalidField(
                    "authored upstream input schema",
                ));
            }
            if upstream_tool_name.trim().is_empty()
                || upstream_tool_name
                    .bytes()
                    .any(|byte| byte.is_ascii_control())
            {
                return Err(ValidationError::InvalidField("upstream tool name"));
            }
            if (*account_mode == UpstreamAccountMode::SharedAccount) != shared_account_id.is_some()
            {
                return Err(ValidationError::InvalidAccount);
            }
            return Ok(());
        }

        if self
            .description
            .as_deref()
            .is_none_or(|text| text.trim().is_empty())
        {
            return Err(ValidationError::InvalidField("tool description"));
        }
        validate_input_schema_structure(
            self.input_schema
                .as_ref()
                .ok_or(ValidationError::InvalidField("input schema"))?,
        )?;
        validate_runtime_limits(
            self.spec.runtime_ms(),
            max_runtime_ms,
            self.spec.max_output_bytes().unwrap_or_default(),
        )?;
        if let Some(selector) = self.spec.target_selector() {
            selector.validate()?;
        }

        match &self.spec {
            ToolSpec::Command {
                program,
                args,
                cwd,
                env,
                account_id,
                ..
            } => {
                validate_command_program(program)?;
                validate_process_definition(args, cwd, env, *account_id)
            }
            ToolSpec::Script {
                interpreter,
                code,
                args,
                cwd,
                env,
                account_id,
                ..
            } => {
                validate_script_interpreter(interpreter)?;
                validate_process_arg(code)?;
                validate_process_definition(args, cwd, env, *account_id)
            }
            ToolSpec::Http {
                base_url,
                path_segments,
                headers,
                account_id,
                ..
            } => {
                validate_http_base_url(base_url, policy, account_id.is_some())?;
                validate_http_headers_no_auth_collision(headers, None)?;
                for segment in path_segments {
                    segment.validate_literal(validate_http_path_segment)?;
                }
                for (name, header) in headers {
                    validate_http_tool_header_name(name)?;
                    header.validate_literal(validate_http_header_value)?;
                }
                Ok(())
            }
            ToolSpec::Ssh {
                host,
                port,
                user,
                command,
                args,
                known_hosts_file,
                account_id,
                identity_file,
                ..
            } => {
                if account_id.is_some() == identity_file.is_some() {
                    return Err(ValidationError::InvalidAccount);
                }
                validate_ssh_fields(
                    host,
                    *port,
                    user,
                    command,
                    known_hosts_file,
                    identity_file.as_deref(),
                )?;
                for arg in args {
                    arg.validate_literal(|text| validate_ssh_command_token(text, true))?;
                }
                Ok(())
            }
            ToolSpec::UpstreamRef { .. } => Ok(()),
        }
    }

    /// Snapshot the schema used by this revision and hash the exact stored value.
    pub fn freeze_revision(
        &self,
        discovered: Option<&DiscoveredUpstreamTool>,
        max_runtime_ms: u64,
        upstream_hard_timeout_ms: u64,
        policy: &EgressPolicy,
    ) -> Result<ToolRevisionDefinition, ValidationError> {
        self.validate(max_runtime_ms, upstream_hard_timeout_ms, policy)?;
        let mut definition = self.clone();
        if let ToolSpec::UpstreamRef {
            upstream_id,
            upstream_tool_name,
            ..
        } = &self.spec
        {
            let discovered = discovered
                .filter(|tool| {
                    tool.upstream_id == *upstream_id && tool.tool_name == *upstream_tool_name
                })
                .ok_or(ValidationError::MissingUpstreamTool)?;
            definition.input_schema = Some(discovered.input_schema.clone());
            definition.description = self
                .description
                .clone()
                .or_else(|| discovered.description.clone());
            definition.annotations = self
                .annotations
                .clone()
                .or_else(|| discovered.annotations.clone());
        }
        let schema = definition
            .input_schema
            .as_ref()
            .ok_or(ValidationError::InvalidField("input schema"))?;
        let input_schema_sha256 =
            compute_input_schema_sha256(schema).map_err(|_| ValidationError::InvalidJson)?;
        Ok(ToolRevisionDefinition {
            definition,
            input_schema_sha256,
        })
    }

    /// Resolve a managed definition against user arguments and the authorized account.
    pub fn resolve_managed(
        &self,
        execution_id: ExecutionId,
        arguments: &Map<String, Value>,
        account: Option<ManagedAccount<'_>>,
        max_runtime_ms: u64,
        policy: &EgressPolicy,
    ) -> Result<ExecuteReqPayload, ValidationError> {
        let max_output_bytes = self
            .spec
            .max_output_bytes()
            .ok_or(ValidationError::InvalidField("managed tool kind"))?;
        self.validate(max_runtime_ms, max_runtime_ms, policy)?;
        let mut remaining = MAX_RESOLVED_ACTION_BYTES;
        let mut env_secrets = BTreeMap::new();
        let mut http_auth_headers = Vec::new();
        let mut ssh_key_pem = None;

        let action = match &self.spec {
            ToolSpec::Command {
                program,
                args,
                cwd,
                env,
                account_id,
                ..
            } => ResolvedAction::Command {
                program: copy_text(program, &mut remaining)?,
                args: resolve_args(args, arguments, &mut remaining)?,
                cwd: copy_text(cwd, &mut remaining)?,
                env: resolve_env(env, *account_id, account, &mut env_secrets, &mut remaining)?,
            },
            ToolSpec::Script {
                interpreter,
                code,
                args,
                cwd,
                env,
                account_id,
                ..
            } => ResolvedAction::Script {
                interpreter: copy_text(interpreter, &mut remaining)?,
                code: copy_text(code, &mut remaining)?,
                args: resolve_args(args, arguments, &mut remaining)?,
                cwd: copy_text(cwd, &mut remaining)?,
                env: resolve_env(env, *account_id, account, &mut env_secrets, &mut remaining)?,
            },
            ToolSpec::Http {
                method,
                base_url,
                path_segments,
                query,
                headers,
                body,
                account_id,
                ..
            } => {
                let selected = validate_account(*account_id, account, AccountKind::HttpAuth)?;
                if let Some(AccountSecretPayload::HttpAuth { auth }) = selected {
                    validate_http_headers_no_auth_collision(headers, Some(auth.header_name()))?;
                    http_auth_headers.push(auth.resolve_header(&mut remaining)?);
                }
                let base = validate_http_base_url(base_url, policy, selected.is_some())?;
                spend_action_bytes(&mut remaining, base.as_str().len())?;
                let parts = resolve_args(path_segments, arguments, &mut remaining)?;
                let query = resolve_map(query, arguments, &mut remaining)?;
                let url = resolve_http_url(&base, &parts, &query)?;
                ResolvedAction::Http {
                    method: *method,
                    url: url.into(),
                    headers: resolve_map(headers, arguments, &mut remaining)?,
                    body: body
                        .as_ref()
                        .map(|body| body.resolve(arguments, &mut remaining))
                        .transpose()?,
                }
            }
            ToolSpec::Ssh {
                host,
                port,
                user,
                command,
                args,
                known_hosts_file,
                account_id,
                identity_file,
                ..
            } => {
                let selected = validate_account(*account_id, account, AccountKind::SshKey)?;
                if let Some(AccountSecretPayload::SshKey { private_key_pem }) = selected {
                    spend_action_bytes(&mut remaining, private_key_pem.len())?;
                    ssh_key_pem = Some(private_key_pem.clone());
                }
                ResolvedAction::Ssh {
                    host: copy_text(host, &mut remaining)?,
                    port: *port,
                    user: copy_text(user, &mut remaining)?,
                    command: copy_text(command, &mut remaining)?,
                    args: resolve_args(args, arguments, &mut remaining)?,
                    known_hosts_file: copy_text(known_hosts_file, &mut remaining)?,
                    identity_file: identity_file
                        .as_deref()
                        .map(|path| copy_text(path, &mut remaining))
                        .transpose()?,
                }
            }
            ToolSpec::UpstreamRef { .. } => {
                return Err(ValidationError::InvalidField("managed tool kind"));
            }
        };

        let request = ExecuteReqPayload {
            execution_id,
            action,
            env_secrets,
            http_auth_headers,
            ssh_key_pem,
            runtime_ms: self.spec.runtime_ms(),
            max_output_bytes,
        };
        request.validate_resolved(max_runtime_ms, policy)?;
        Ok(request)
    }
}

fn validate_process_definition(
    args: &[ArgBinding],
    cwd: &str,
    env: &BTreeMap<String, EnvBinding>,
    account_id: Option<AccountId>,
) -> Result<(), ValidationError> {
    validate_absolute_path_syntax(cwd)?;
    for arg in args {
        arg.validate_literal(validate_process_arg)?;
    }
    for (name, binding) in env {
        validate_env_var_name(name)?;
        match binding {
            EnvBinding::Literal { value } => validate_env_var_value(value)?,
            EnvBinding::Secret { key } => {
                if account_id.is_none() {
                    return Err(ValidationError::InvalidAccount);
                }
                validate_secret_key(key)?;
            }
        }
    }
    Ok(())
}

fn validate_account(
    expected: Option<AccountId>,
    supplied: Option<ManagedAccount<'_>>,
    kind: AccountKind,
) -> Result<Option<&AccountSecretPayload>, ValidationError> {
    match (expected, supplied) {
        (None, None) => Ok(None),
        (Some(expected), Some(account))
            if expected == account.account_id
                && account.upstream_id.is_none()
                && account.payload.kind() == kind =>
        {
            Ok(Some(account.payload))
        }
        _ => Err(ValidationError::InvalidAccount),
    }
}

fn resolve_args(
    bindings: &[ArgBinding],
    arguments: &Map<String, Value>,
    remaining: &mut usize,
) -> Result<Vec<String>, ValidationError> {
    bindings
        .iter()
        .map(|binding| binding.resolve_text(arguments, remaining))
        .collect()
}

fn resolve_map(
    bindings: &BTreeMap<String, ArgBinding>,
    arguments: &Map<String, Value>,
    remaining: &mut usize,
) -> Result<BTreeMap<String, String>, ValidationError> {
    bindings
        .iter()
        .map(|(name, binding)| {
            Ok((
                copy_text(name, remaining)?,
                binding.resolve_text(arguments, remaining)?,
            ))
        })
        .collect()
}

fn resolve_env(
    env: &BTreeMap<String, EnvBinding>,
    account_id: Option<AccountId>,
    account: Option<ManagedAccount<'_>>,
    env_secrets: &mut BTreeMap<String, SecretString>,
    remaining: &mut usize,
) -> Result<BTreeMap<String, String>, ValidationError> {
    let account = validate_account(account_id, account, AccountKind::SecretKv)?;
    let secrets = match account {
        Some(payload @ AccountSecretPayload::SecretKv { entries }) => {
            payload.validate()?;
            Some(entries)
        }
        _ => None,
    };
    let mut literals = BTreeMap::new();
    for (name, binding) in env {
        let name = copy_text(name, remaining)?;
        match binding {
            EnvBinding::Literal { value } => {
                literals.insert(name, copy_text(value, remaining)?);
            }
            EnvBinding::Secret { key } => {
                let value = secrets
                    .and_then(|entries| entries.get(key))
                    .ok_or(ValidationError::MissingSecret)?;
                spend_action_bytes(remaining, value.len())?;
                env_secrets.insert(name, value.clone());
            }
        }
    }
    Ok(literals)
}
