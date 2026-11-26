use crate::wire::strict_enum;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::{
    EgressPolicy, ExecuteReqPayload, HttpMethod, MAX_OUTPUT_BYTES, ToolKind, ValidationError,
    validate::*, validate_egress_url, validate_ssh_private_key_pem,
};

pub const MAX_RESOLVED_ACTION_BYTES: usize = 256 * 1024;

strict_enum! {
    tag = "kind",
    decode = object,
    #[derive(Clone, PartialEq, Eq)]
    pub enum ResolvedAction {
        Command {
            program: String,
            args: Vec<String>,
            cwd: String,
            #[serde(deserialize_with = "crate::wire::deserialize_unique_map")]
            env: BTreeMap<String, String>,
        },
        Script {
            interpreter: String,
            code: String,
            args: Vec<String>,
            cwd: String,
            #[serde(deserialize_with = "crate::wire::deserialize_unique_map")]
            env: BTreeMap<String, String>,
        },
        Http {
            method: HttpMethod,
            url: String,
            #[serde(deserialize_with = "crate::wire::deserialize_unique_map")]
            headers: BTreeMap<String, String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            body: Option<String>,
        },
        Ssh {
            host: String,
            port: u16,
            user: String,
            command: String,
            args: Vec<String>,
            known_hosts_file: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            identity_file: Option<String>,
        },
    }
}

impl ResolvedAction {
    pub const fn kind(&self) -> ToolKind {
        match self {
            Self::Command { .. } => ToolKind::Command,
            Self::Script { .. } => ToolKind::Script,
            Self::Http { .. } => ToolKind::Http,
            Self::Ssh { .. } => ToolKind::Ssh,
        }
    }
}

impl fmt::Debug for ResolvedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedAction")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl ExecuteReqPayload {
    /// Check the complete request with the receiving side's resolved-action limits.
    /// Network and filesystem checks use this validated request at the consumer.
    pub fn validate_resolved(
        &self,
        max_runtime_ms: u64,
        policy: &EgressPolicy,
    ) -> Result<(), ValidationError> {
        validate_runtime_limits(self.runtime_ms, max_runtime_ms, self.max_output_bytes)?;
        let mut remaining = MAX_RESOLVED_ACTION_BYTES;

        match &self.action {
            ResolvedAction::Command {
                program,
                args,
                cwd,
                env,
            } => {
                validate_command_program(program)?;
                spend_action_bytes(&mut remaining, program.len())?;
                self.validate_process_fields(args, cwd, env, &mut remaining)
            }
            ResolvedAction::Script {
                interpreter,
                code,
                args,
                cwd,
                env,
            } => {
                validate_script_interpreter(interpreter)?;
                validate_process_arg(code)?;
                spend_texts(&mut remaining, [interpreter.as_str(), code])?;
                self.validate_process_fields(args, cwd, env, &mut remaining)
            }
            ResolvedAction::Http {
                url, headers, body, ..
            } => {
                if !self.env_secrets.is_empty() || self.ssh_key_pem.is_some() {
                    return Err(ValidationError::InvalidAccount);
                }
                spend_texts(
                    &mut remaining,
                    [url.as_str()].into_iter().chain(body.as_deref()),
                )?;
                validate_egress_url(
                    url,
                    policy,
                    http_egress_mode(!self.http_auth_headers.is_empty()),
                )?;
                let mut names = BTreeSet::new();
                for (name, value) in headers {
                    spend_texts(&mut remaining, [name.as_str(), value])?;
                    validate_http_tool_header_name(name)?;
                    validate_http_header_value(value)?;
                    if !names.insert(name.to_ascii_lowercase()) {
                        return Err(ValidationError::HeaderCollision);
                    }
                }
                for (name, value) in &self.http_auth_headers {
                    spend_texts(&mut remaining, [name.as_str(), value.expose_secret()])?;
                    validate_secret_header_name(name)?;
                    validate_http_header_value(value.expose_secret())?;
                    if !names.insert(name.to_ascii_lowercase()) {
                        return Err(ValidationError::HeaderCollision);
                    }
                }
                Ok(())
            }
            ResolvedAction::Ssh {
                host,
                port,
                user,
                command,
                args,
                known_hosts_file,
                identity_file,
            } => {
                if !self.env_secrets.is_empty()
                    || !self.http_auth_headers.is_empty()
                    || identity_file.is_some() == self.ssh_key_pem.is_some()
                {
                    return Err(ValidationError::InvalidAccount);
                }
                spend_texts(
                    &mut remaining,
                    [host.as_str(), user, command, known_hosts_file]
                        .into_iter()
                        .chain(identity_file.as_deref())
                        .chain(args.iter().map(String::as_str)),
                )?;
                validate_ssh_fields(
                    host,
                    *port,
                    user,
                    command,
                    known_hosts_file,
                    identity_file.as_deref(),
                )?;
                for arg in args {
                    validate_ssh_command_token(arg, true)?;
                }
                if let Some(key) = &self.ssh_key_pem {
                    spend_action_bytes(&mut remaining, key.len())?;
                    validate_ssh_private_key_pem(key.expose_secret())?;
                }
                Ok(())
            }
        }
    }

    fn validate_process_fields(
        &self,
        args: &[String],
        cwd: &str,
        env: &BTreeMap<String, String>,
        remaining: &mut usize,
    ) -> Result<(), ValidationError> {
        if !self.http_auth_headers.is_empty() || self.ssh_key_pem.is_some() {
            return Err(ValidationError::InvalidAccount);
        }
        spend_texts(
            remaining,
            [cwd].into_iter().chain(args.iter().map(String::as_str)),
        )?;
        validate_absolute_path_syntax(cwd)?;
        for arg in args {
            validate_process_arg(arg)?;
        }
        for (name, value) in env {
            spend_texts(remaining, [name.as_str(), value])?;
            validate_env_var_name(name)?;
            validate_env_var_value(value)?;
        }
        for (name, value) in &self.env_secrets {
            spend_texts(remaining, [name.as_str(), value.expose_secret()])?;
            validate_env_var_name(name)?;
            validate_env_var_value(value.expose_secret())?;
            if env.contains_key(name) {
                return Err(ValidationError::InvalidAccount);
            }
        }
        Ok(())
    }
}

fn spend_texts<'a>(
    remaining: &mut usize,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), ValidationError> {
    for value in values {
        spend_action_bytes(remaining, value.len())?;
    }
    Ok(())
}

pub(crate) fn validate_runtime_limits(
    runtime_ms: u64,
    max_runtime_ms: u64,
    max_output_bytes: u32,
) -> Result<(), ValidationError> {
    if !(1..=max_runtime_ms).contains(&runtime_ms) {
        return Err(ValidationError::RuntimeLimit);
    }
    if max_output_bytes > MAX_OUTPUT_BYTES {
        return Err(ValidationError::OutputLimit);
    }
    Ok(())
}

pub(crate) fn validate_ssh_fields(
    host: &str,
    port: u16,
    user: &str,
    command: &str,
    known_hosts_file: &str,
    identity_file: Option<&str>,
) -> Result<(), ValidationError> {
    validate_ssh_host(host)?;
    validate_ssh_port(port)?;
    validate_ssh_user(user)?;
    validate_ssh_command_token(command, false)?;
    validate_ssh_path(known_hosts_file)?;
    if let Some(path) = identity_file {
        validate_ssh_path(path)?;
    }
    Ok(())
}
