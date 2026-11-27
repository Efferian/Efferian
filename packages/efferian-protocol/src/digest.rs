use std::{collections::BTreeMap, io, num::NonZeroU64};

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
            Value::Object(object) => SortedObject(object).serialize(serializer),
            Value::Array(array) => serializer.collect_seq(array.iter().map(Self)),
            primitive => primitive.serialize(serializer),
        }
    }
}

struct SortedObject<'a>(&'a Map<String, Value>);

impl Serialize for SortedObject<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let sorted: BTreeMap<_, _> = self.0.iter().collect();
        let mut map = serializer.serialize_map(Some(sorted.len()))?;
        for (key, value) in sorted {
            map.serialize_entry(key, &SortedJson(value))?;
        }
        map.end()
    }
}

struct Sha256Writer<'a> {
    hasher: &'a mut Sha256,
    written: usize,
}

impl io::Write for Sha256Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.hasher.update(bytes);
        self.written = self.written.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn canonical_json_sha256(value: &Value) -> Result<String, DigestError> {
    let mut hasher = Sha256::new();
    let mut writer = Sha256Writer {
        hasher: &mut hasher,
        written: 0,
    };
    serde_json::to_writer(&mut writer, &SortedJson(value))?;
    let hash: [u8; 32] = hasher.finalize().into();
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

/// Resolved metadata combined with a [`PreparedArgumentsDigest`] to compute the
/// same canonical SHA-256 digest as [`compute_request_digest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestDigestMetadata<'a> {
    pub invoke_kind: InvokeKind,
    pub profile_id: Option<ProfileId>,
    pub tool_id: ToolId,
    pub public_name: &'a str,
    pub requested_target: Option<&'a str>,
    pub fixed_node_id: Option<NodeId>,
    pub requested_tool_version: Option<NonZeroU64>,
}

/// Pre-hashed prefix (`{"arguments":<canonical>`) of [`RequestDigestInput`].
/// Allows callers to canonicalize and hash large argument payloads outside a
/// serialized writer thread, then finish the digest once catalog metadata is resolved.
#[derive(Clone, Debug)]
pub struct PreparedArgumentsDigest {
    hasher: Sha256,
    canonical_bytes: usize,
}

impl PreparedArgumentsDigest {
    pub fn new(arguments: &Map<String, Value>) -> Result<Self, DigestError> {
        let mut hasher = Sha256::new();
        hasher.update(br#"{"arguments":"#);
        let mut writer = Sha256Writer {
            hasher: &mut hasher,
            written: 0,
        };
        serde_json::to_writer(&mut writer, &SortedObject(arguments))?;
        let canonical_bytes = writer.written;
        Ok(Self {
            hasher,
            canonical_bytes,
        })
    }

    pub const fn canonical_bytes(&self) -> usize {
        self.canonical_bytes
    }

    pub fn finish(&self, metadata: &RequestDigestMetadata<'_>) -> Result<String, DigestError> {
        let valid = match metadata.invoke_kind {
            InvokeKind::Profile => {
                metadata.profile_id.is_some() && metadata.requested_tool_version.is_none()
            }
            InvokeKind::ToolTest => {
                metadata.profile_id.is_none() && metadata.fixed_node_id.is_none()
            }
        };
        if !valid {
            return Err(DigestError::InvalidInvocation);
        }

        // Field names are emitted in strict lexicographical order after "arguments".
        #[derive(Serialize)]
        struct Tail<'a> {
            fixed_node_id: Option<NodeId>,
            invoke_kind: InvokeKind,
            profile_id: Option<ProfileId>,
            public_name: &'a str,
            requested_target: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            requested_tool_version: Option<NonZeroU64>,
            tool_id: ToolId,
        }

        let mut hasher = self.hasher.clone();
        let mut tail = serde_json::to_vec(&Tail {
            fixed_node_id: metadata.fixed_node_id,
            invoke_kind: metadata.invoke_kind,
            profile_id: metadata.profile_id,
            public_name: metadata.public_name,
            requested_target: metadata.requested_target,
            requested_tool_version: metadata.requested_tool_version,
            tool_id: metadata.tool_id,
        })?;
        // Replace leading '{' from the serialized tail object with ',' to continue the outer object.
        if let Some(first) = tail.first_mut() {
            *first = b',';
        }
        hasher.update(&tail);
        let hash: [u8; 32] = hasher.finalize().into();
        Ok(encode_hex_lower(&hash))
    }
}

pub fn compute_request_digest(input: &RequestDigestInput<'_>) -> Result<String, DigestError> {
    PreparedArgumentsDigest::new(input.arguments)?.finish(&RequestDigestMetadata {
        invoke_kind: input.invoke_kind,
        profile_id: input.profile_id,
        tool_id: input.tool_id,
        public_name: input.public_name,
        requested_target: input.requested_target,
        fixed_node_id: input.fixed_node_id,
        requested_tool_version: input.requested_tool_version,
    })
}

pub fn compute_input_schema_sha256(schema: &Value) -> Result<String, DigestError> {
    canonical_json_sha256(schema)
}
