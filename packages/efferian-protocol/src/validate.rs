//! Pure validators used on both sides of the Hub–Node bridge.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde_json::Value;
use url::Url;

use crate::{
    EgressPolicy, EgressUrlMode, ValidationError, profile::RESERVED_CONTROL_TOOL_NAMES,
    validate_egress_url,
};

pub fn validate_http_base_url(
    raw: &str,
    policy: &EgressPolicy,
    has_account: bool,
) -> Result<Url, ValidationError> {
    let url = validate_egress_url(raw, policy, http_egress_mode(has_account))?;
    if url.query().is_some() {
        return Err(ValidationError::InvalidField("HTTP base URL query"));
    }
    Ok(url)
}

pub(crate) const fn http_egress_mode(has_credentials: bool) -> EgressUrlMode {
    if has_credentials {
        EgressUrlMode::RequireHttpsByDefault
    } else {
        EgressUrlMode::Plain
    }
}

pub fn validate_http_path_segment(segment: &str) -> Result<(), ValidationError> {
    if matches!(segment, "" | "." | "..")
        || segment
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b'/' | b'\\' | b'?' | b'#' | b'%' | b';'))
    {
        return Err(ValidationError::InvalidField("HTTP path segment"));
    }
    Ok(())
}

/// Add only path segments and query pairs to a validated HTTP base URL.
pub fn resolve_http_url(
    base: &Url,
    dynamic_segments: &[String],
    query: &BTreeMap<String, String>,
) -> Result<Url, ValidationError> {
    let invalid = ValidationError::InvalidField("resolved HTTP URL");
    if base.query().is_some()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.fragment().is_some()
    {
        return Err(invalid);
    }
    dynamic_segments
        .iter()
        .try_for_each(|segment| validate_http_path_segment(segment))?;

    let mut url = base.clone();
    if !dynamic_segments.is_empty() {
        url.path_segments_mut()
            .map_err(|()| invalid)?
            .pop_if_empty()
            .extend(dynamic_segments);
    }
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }

    let parsed = Url::parse(url.as_str()).map_err(|_| invalid)?;
    if parsed.scheme() != base.scheme()
        || parsed.host() != base.host()
        || parsed.port_or_known_default() != base.port_or_known_default()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid);
    }

    if dynamic_segments.is_empty() {
        if parsed.path() != base.path() {
            return Err(invalid);
        }
    } else {
        let base_path = base.path().strip_suffix('/').unwrap_or(base.path());
        let suffix = parsed
            .path()
            .strip_prefix(base_path)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .ok_or(invalid)?;
        let mut actual = suffix.split('/');
        for expected in dynamic_segments {
            let segment = actual.next().ok_or(invalid)?;
            if !decoded_segment_eq(segment, expected) {
                return Err(invalid);
            }
        }
        if actual.next().is_some() {
            return Err(invalid);
        }
    }
    if parsed.query().is_some() == query.is_empty()
        || !parsed.query_pairs().eq(query
            .iter()
            .map(|(key, value)| (key.as_str().into(), value.as_str().into())))
    {
        return Err(invalid);
    }
    Ok(parsed)
}

fn decoded_segment_eq(encoded: &str, expected: &str) -> bool {
    let mut bytes = encoded.bytes();
    for expected in expected.bytes() {
        let decoded = match bytes.next() {
            Some(b'%') => match (
                bytes.next().and_then(hex_digit),
                bytes.next().and_then(hex_digit),
            ) {
                (Some(high), Some(low)) => high * 16 + low,
                _ => return false,
            },
            Some(byte) => byte,
            None => return false,
        };
        if decoded != expected {
            return false;
        }
    }
    bytes.next().is_none()
}

fn hex_digit(byte: u8) -> Option<u8> {
    char::from(byte).to_digit(16).map(|value| value as u8)
}

const TRANSPORT_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

pub fn validate_http_header_name(name: &str) -> Result<(), ValidationError> {
    if !(1..=128).contains(&name.len())
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_|~".contains(&b) || b == 0x60)
    {
        return Err(ValidationError::InvalidField("HTTP header name"));
    }
    Ok(())
}

pub(crate) fn validate_secret_header_name(name: &str) -> Result<(), ValidationError> {
    validate_http_header_name(name)?;
    if TRANSPORT_HEADERS
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
    {
        return Err(ValidationError::InvalidField("reserved HTTP header"));
    }
    Ok(())
}

pub fn validate_http_tool_header_name(name: &str) -> Result<(), ValidationError> {
    validate_secret_header_name(name)?;
    if ["authorization", "proxy-authorization", "cookie"]
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
    {
        return Err(ValidationError::InvalidField("reserved HTTP header"));
    }
    Ok(())
}

pub fn validate_http_header_value(value: &str) -> Result<(), ValidationError> {
    if value.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
        return Err(ValidationError::InvalidField("HTTP header value"));
    }
    Ok(())
}

pub fn validate_http_headers_no_auth_collision<V>(
    headers: &BTreeMap<String, V>,
    auth_header_name: Option<&str>,
) -> Result<(), ValidationError> {
    let mut seen = BTreeSet::new();
    if let Some(auth_header_name) = auth_header_name {
        seen.insert(auth_header_name.to_ascii_lowercase());
    }
    for name in headers.keys() {
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(ValidationError::HeaderCollision);
        }
    }
    Ok(())
}

pub fn validate_env_var_name(name: &str) -> Result<(), ValidationError> {
    const PREFIXES: &[&str] = &["LD_", "DYLD_", "BASH_FUNC_", "SSH_ASKPASS"];
    const NAMES: &[&str] = &[
        "PATH",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "SHELLOPTS",
        "BASHOPTS",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONSAFEPATH",
        "NODE_OPTIONS",
        "RUBYOPT",
        "PERL5OPT",
        "IFS",
        "GCONV_PATH",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
    ];
    let mut bytes = name.bytes();
    if name.len() > 128
        || !bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(ValidationError::InvalidField("environment variable name"));
    }
    let upper = name.to_ascii_uppercase();
    if NAMES.contains(&upper.as_str()) || PREFIXES.iter().any(|prefix| upper.starts_with(prefix)) {
        return Err(ValidationError::InvalidField(
            "reserved environment variable",
        ));
    }
    Ok(())
}

pub fn validate_env_var_value(value: &str) -> Result<(), ValidationError> {
    if value.contains('\0') {
        return Err(ValidationError::InvalidField("environment variable value"));
    }
    Ok(())
}

pub(crate) fn validate_secret_key(key: &str) -> Result<(), ValidationError> {
    if key.is_empty() || key.contains(['\0', '=']) {
        return Err(ValidationError::InvalidField("secret key name"));
    }
    Ok(())
}

pub fn validate_command_program(program: &str) -> Result<(), ValidationError> {
    if program.starts_with('/') {
        return validate_executable_path(program);
    }
    if matches!(program, "" | "." | "..") || program.contains(['/', '\0', '\r', '\n']) {
        return Err(ValidationError::InvalidField("command program"));
    }
    Ok(())
}

pub fn validate_script_interpreter(interpreter: &str) -> Result<(), ValidationError> {
    validate_executable_path(interpreter)
}

fn validate_executable_path(path: &str) -> Result<(), ValidationError> {
    validate_absolute_path_syntax(path)?;
    if path.ends_with('/') {
        return Err(ValidationError::InvalidField("executable path"));
    }
    Ok(())
}

pub fn validate_absolute_path_syntax(path: &str) -> Result<(), ValidationError> {
    if !path.starts_with('/')
        || path.contains(['\0', '\r', '\n'])
        || path.split('/').any(|segment| segment == "..")
    {
        return Err(ValidationError::InvalidField("absolute path"));
    }
    Ok(())
}

pub fn validate_process_arg(arg: &str) -> Result<(), ValidationError> {
    if arg.contains('\0') {
        return Err(ValidationError::InvalidField("process argument"));
    }
    Ok(())
}

pub(crate) fn valid_dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub fn validate_ssh_host(host: &str) -> Result<(), ValidationError> {
    if host.parse::<IpAddr>().is_ok() || valid_dns_name(host) {
        return Ok(());
    }
    Err(ValidationError::InvalidField("SSH host"))
}

pub fn validate_ssh_port(port: u16) -> Result<(), ValidationError> {
    if port == 0 {
        return Err(ValidationError::InvalidField("SSH port"));
    }
    Ok(())
}

pub fn validate_ssh_user(user: &str) -> Result<(), ValidationError> {
    let mut bytes = user.bytes();
    let first = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_');
    if user.len() > 64 || !bytes.next().is_some_and(first) || !bytes.all(|b| first(b) || b == b'-')
    {
        return Err(ValidationError::InvalidField("SSH user"));
    }
    Ok(())
}

pub fn validate_ssh_path(path: &str) -> Result<(), ValidationError> {
    validate_absolute_path_syntax(path)?;
    if path
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'%' | b'"'))
    {
        return Err(ValidationError::InvalidField("SSH path"));
    }
    Ok(())
}

pub fn validate_ssh_command_token(token: &str, allow_empty: bool) -> Result<(), ValidationError> {
    if (!allow_empty && token.is_empty()) || token.contains(['\0', '\r', '\n']) {
        return Err(ValidationError::InvalidField("SSH command token"));
    }
    Ok(())
}

/// Quote one argument for a POSIX shell.
pub fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

pub fn build_ssh_remote_command(command: &str, args: &[String]) -> Result<String, ValidationError> {
    validate_ssh_command_token(command, false)?;
    let mut quoted = shell_quote(command);
    for arg in args {
        validate_ssh_command_token(arg, true)?;
        quoted.push(' ');
        quoted.push_str(&shell_quote(arg));
    }
    Ok(quoted)
}

fn lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn validate_name(
    name: &str,
    start: impl Fn(u8) -> bool,
    rest: impl Fn(u8) -> bool,
    field: &'static str,
) -> Result<(), ValidationError> {
    let mut bytes = name.bytes();
    if name.len() > 64 || !bytes.next().is_some_and(start) || !bytes.all(rest) {
        return Err(ValidationError::InvalidField(field));
    }
    Ok(())
}

pub fn validate_slug(slug: &str) -> Result<(), ValidationError> {
    validate_name(
        slug,
        lower_alphanumeric,
        |b| lower_alphanumeric(b) || matches!(b, b'_' | b'-'),
        "slug",
    )
}

pub fn validate_resource_name(name: &str) -> Result<(), ValidationError> {
    validate_name(
        name,
        |b| b.is_ascii_alphanumeric(),
        |b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'),
        "resource name",
    )
}

pub fn validate_node_tag(tag: &str) -> Result<(), ValidationError> {
    validate_name(
        tag,
        lower_alphanumeric,
        |b| lower_alphanumeric(b) || matches!(b, b'.' | b'_' | b'-'),
        "node tag",
    )
}

pub fn validate_public_tool_name(name: &str) -> Result<(), ValidationError> {
    if !(1..=128).contains(&name.len())
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        || RESERVED_CONTROL_TOOL_NAMES.contains(&name)
    {
        return Err(ValidationError::InvalidField("public tool name"));
    }
    Ok(())
}

/// Gate references in positions occupied by Draft 2020-12 schemas. The
/// consumer compiles the schema separately with external resolution disabled.
pub fn validate_input_schema_structure(schema: &Value) -> Result<(), ValidationError> {
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(ValidationError::InvalidField("object input schema"));
    }
    let mut pending = vec![schema];
    while let Some(schema) = pending.pop() {
        let Value::Object(schema) = schema else {
            if schema.is_boolean() {
                continue;
            }
            return Err(ValidationError::InvalidField("input subschema"));
        };
        for keyword in ["$ref", "$dynamicRef"] {
            if let Some(reference) = schema.get(keyword)
                && !reference
                    .as_str()
                    .is_some_and(|reference| reference.starts_with('#'))
            {
                return Err(ValidationError::InvalidField(
                    "non-local input schema reference",
                ));
            }
        }
        for keyword in [
            "$defs",
            "properties",
            "patternProperties",
            "dependentSchemas",
        ] {
            if let Some(value) = schema.get(keyword) {
                pending.extend(
                    value
                        .as_object()
                        .ok_or(ValidationError::InvalidField("input subschema map"))?
                        .values(),
                );
            }
        }
        for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
            if let Some(value) = schema.get(keyword) {
                pending.extend(
                    value
                        .as_array()
                        .ok_or(ValidationError::InvalidField("input subschema array"))?,
                );
            }
        }
        for keyword in [
            "not",
            "if",
            "then",
            "else",
            "items",
            "contains",
            "additionalProperties",
            "propertyNames",
            "unevaluatedItems",
            "unevaluatedProperties",
            "contentSchema",
        ] {
            if let Some(value) = schema.get(keyword) {
                pending.push(value);
            }
        }
    }
    Ok(())
}

pub(crate) fn spend_action_bytes(
    remaining: &mut usize,
    count: usize,
) -> Result<(), ValidationError> {
    *remaining = remaining
        .checked_sub(count)
        .ok_or(ValidationError::ActionLimit)?;
    Ok(())
}
