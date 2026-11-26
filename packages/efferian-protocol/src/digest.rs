use std::{collections::BTreeMap, num::NonZeroU64};

use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{InvokeKind, NodeId, ProfileId, ToolId};

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("inconsistent invocation digest fields")]
    InvalidInvocation,
    #[error("cannot serialize canonical JSON")]
    Serialization(#[from] serde_json::Error),
}

/// Serializes compact JSON with lexicographically sorted object keys at every depth.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, DigestError> {
    Ok(serde_json::to_vec(&SortedJson(value))?)
}

struct SortedJson<'a>(&'a Value);

impl Serialize for SortedJson<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(object) => {
                let sorted: BTreeMap<_, _> = object.iter().collect();
                let mut map = serializer.serialize_map(Some(sorted.len()))?;
                for (key, value) in sorted {
                    map.serialize_entry(key, &Self(value))?;
                }
                map.end()
            }
            Value::Array(array) => serializer.collect_seq(array.iter().map(Self)),
            primitive => primitive.serialize(serializer),
        }
    }
}

pub fn canonical_json_sha256(value: &Value) -> Result<String, DigestError> {
    let hash: [u8; 32] = Sha256::digest(canonical_json_bytes(value)?).into();
    Ok(encode_hex_lower(&hash))
}

fn encode_hex_lower(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for &byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0xf)]));
    }
    encoded
}

/// The client intent and the catalog identifiers from the original invocation on a replay.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RequestDigestInput<'a> {
    pub invoke_kind: InvokeKind,
    pub profile_id: Option<ProfileId>,
    /// Tool from the recorded binding on replay, even if the alias now points elsewhere.
    pub tool_id: ToolId,
    pub public_name: &'a str,
    /// The client's normalized target selector before resolution to an available node.
    pub requested_target: Option<&'a str>,
    /// Fixed node in the original profile binding, independent of the node chosen to run the call.
    pub fixed_node_id: Option<NodeId>,
    pub arguments: &'a Map<String, Value>,
    /// Explicit tool-test version pin. An unpinned retry stays unpinned after publication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_tool_version: Option<NonZeroU64>,
}

pub fn compute_request_digest(input: &RequestDigestInput<'_>) -> Result<String, DigestError> {
    let valid = match input.invoke_kind {
        InvokeKind::Profile => input.profile_id.is_some() && input.requested_tool_version.is_none(),
        InvokeKind::ToolTest => input.profile_id.is_none() && input.fixed_node_id.is_none(),
    };
    if !valid {
        return Err(DigestError::InvalidInvocation);
    }
    canonical_json_sha256(&serde_json::to_value(input)?)
}

pub fn compute_input_schema_sha256(schema: &Value) -> Result<String, DigestError> {
    canonical_json_sha256(schema)
}
