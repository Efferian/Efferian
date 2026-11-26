use crate::wire::strict_enum;

use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    OutputDiscardedReason, ValidationError,
    wire::{deserialize_object, strict_struct},
};

pub const MAX_OUTPUT_BYTES: u32 = 1024 * 1024;
pub const DEFAULT_OUTPUT_BYTES: u32 = MAX_OUTPUT_BYTES;
pub const MAX_EXECUTION_ERROR_MESSAGE_BYTES: usize = 512;

strict_struct! {
    /// Summary persisted for an execution. Active executions can have an empty summary.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ExecutionSummary {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub exit_code: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub http_status: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub duration_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error_code: Option<String>,
        #[serde(default, deserialize_with = "deserialize_error_message", skip_serializing_if = "Option::is_none")]
        pub error_message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub effect_may_have_occurred: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub output_discarded_reason: Option<OutputDiscardedReason>,
    }
}

fn deserialize_error_message<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let message = Option::deserialize(d)?;
    validate_error_message(message.as_deref()).map_err(de::Error::custom)?;
    Ok(message)
}

pub(crate) fn validate_error_message(message: Option<&str>) -> Result<(), ValidationError> {
    if message.is_some_and(|message| message.len() > MAX_EXECUTION_ERROR_MESSAGE_BYTES) {
        return Err(ValidationError::InvalidField(
            "execution error message length",
        ));
    }
    Ok(())
}

strict_enum! {
    tag = "kind",
    #[derive(Clone, PartialEq, Deserialize)]
    pub enum StoredResult {
        Managed {
            stdout: String,
            stderr: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            exit_code: Option<i32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            http_status: Option<u16>,
        },
        UpstreamMcp {
            result: UpstreamMcpResult,
        },
    }
}

impl StoredResult {
    /// Enforce the raw byte limit before decoding the two streams independently.
    pub fn managed_from_bytes(
        stdout: &[u8],
        stderr: &[u8],
        exit_code: Option<i32>,
        http_status: Option<u16>,
        max_output_bytes: u32,
    ) -> Result<Self, ValidationError> {
        check_output_lengths(stdout.len(), stderr.len(), max_output_bytes)?;
        Ok(Self::Managed {
            stdout: String::from_utf8_lossy(stdout).into_owned(),
            stderr: String::from_utf8_lossy(stderr).into_owned(),
            exit_code,
            http_status,
        })
    }
}

impl fmt::Debug for StoredResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Managed { .. } => "StoredResult::Managed",
            Self::UpstreamMcp { .. } => "StoredResult::UpstreamMcp",
        };
        f.debug_struct(name).finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum UpstreamMcpResultType {
    Complete,
}

/// Compatibility contract for the CallToolResult value produced by the MCP SDK.
#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpstreamMcpResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_type: Option<UpstreamMcpResultType>,
    pub content: Vec<Value>,
    /// Some(Null) represents an explicit structuredContent null on the wire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<BTreeMap<String, Value>>,
}

impl fmt::Debug for UpstreamMcpResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamMcpResult").finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for UpstreamMcpResult {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Fields {
            result_type: Option<UpstreamMcpResultType>,
            content: Option<Vec<Value>>,
            #[serde(default, deserialize_with = "present_value")]
            structured_content: Option<Value>,
            is_error: Option<bool>,
            #[serde(rename = "_meta")]
            meta: Option<BTreeMap<String, Value>>,
        }

        fn present_value<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
            Value::deserialize(d).map(Some)
        }

        let fields: Fields = deserialize_object(deserializer)?;
        if fields.content.is_none()
            && fields.structured_content.is_none()
            && fields.is_error.is_none()
        {
            return Err(de::Error::custom(
                "expected content, structuredContent, or isError",
            ));
        }
        Ok(Self {
            result_type: fields.result_type,
            content: fields.content.unwrap_or_default(),
            structured_content: fields.structured_content,
            is_error: fields.is_error,
            meta: fields.meta,
        })
    }
}

/// Raw execution output after both streams have been checked against one byte budget.
pub struct DecodedOutput {
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for DecodedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedOutput")
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .finish()
    }
}

pub(crate) fn decode_output(
    stdout: Option<&str>,
    stderr: Option<&str>,
    max_output_bytes: u32,
) -> Result<DecodedOutput, ValidationError> {
    let stdout = stdout.unwrap_or_default();
    let stderr = stderr.unwrap_or_default();
    let stdout_len = decoded_base64_len(stdout)?;
    let stderr_len = decoded_base64_len(stderr)?;
    check_output_lengths(stdout_len, stderr_len, max_output_bytes)?;
    Ok(DecodedOutput {
        stdout: decode_base64(stdout, stdout_len)?,
        stderr: decode_base64(stderr, stderr_len)?,
    })
}

pub(crate) fn check_output_lengths(
    stdout_len: usize,
    stderr_len: usize,
    max_output_bytes: u32,
) -> Result<(), ValidationError> {
    if max_output_bytes > MAX_OUTPUT_BYTES
        || stdout_len.saturating_add(stderr_len) > max_output_bytes as usize
    {
        return Err(ValidationError::OutputLimit);
    }
    Ok(())
}

pub(crate) fn decoded_base64_len(encoded: &str) -> Result<usize, ValidationError> {
    if !encoded.len().is_multiple_of(4) {
        return Err(ValidationError::InvalidOutputEncoding);
    }
    let padding = if encoded.ends_with("==") {
        2
    } else {
        usize::from(encoded.ends_with('='))
    };
    Ok(encoded.len() / 4 * 3 - padding)
}

pub(crate) fn decode_base64(
    encoded: &str,
    decoded_len: usize,
) -> Result<Zeroizing<Vec<u8>>, ValidationError> {
    let mut bytes = Zeroizing::new(vec![0; decoded_len]);
    let actual = STANDARD
        .decode_slice(encoded, &mut bytes)
        .map_err(|_| ValidationError::InvalidOutputEncoding)?;
    if actual != decoded_len {
        return Err(ValidationError::InvalidOutputEncoding);
    }
    Ok(bytes)
}
