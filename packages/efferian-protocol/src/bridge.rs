use std::{collections::BTreeMap, fmt, io};

use serde::{Deserialize, Serialize, de::IgnoredAny};
use zeroize::Zeroizing;

use crate::{
    ExecutionId, ExecutionSummary, HubId, MAX_OUTPUT_BYTES, NodeId, OutputDiscardedReason,
    PlatformOs, ResolvedAction, SecretString, TerminalExecutionState, ValidationError, error_codes,
    result::{DecodedOutput, decode_output, validate_error_message},
    wire::{deserialize_object, strict_struct},
};

pub const BRIDGE_PROTOCOL_VERSION: u32 = 1;
pub const MAX_BRIDGE_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ROSTER_CWD_ROOTS: usize = 64;
pub const MAX_ROSTER_CWD_ROOT_BYTES: usize = 8 * 1024;

pub const BRIDGE_CLOSE_SUPERSEDED: u16 = 4001;
pub const BRIDGE_CLOSE_EPOCH_MISMATCH: u16 = 4002;
pub const BRIDGE_CLOSE_NODE_REVOKED: u16 = 4003;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeReceiver {
    Hub,
    Node,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BridgeCodecError {
    #[error("bridge frame exceeds the byte limit")]
    FrameTooLarge,
    #[error("invalid bridge frame")]
    InvalidFrame,
    #[error("unsupported bridge version {0}")]
    UnsupportedVersion(u32),
    #[error("bridge frame {0:?} is invalid for receiver {1:?}")]
    WrongDirection(BridgeKind, BridgeReceiver),
    #[error("bridge hello epoch does not match the envelope")]
    EpochMismatch,
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

strict_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct HelloAckPayload {
        pub hub_id: HubId,
        pub node_id: NodeId,
        pub session_epoch: u64,
    }
}

strict_struct! {
    #[derive(Clone, PartialEq, Eq)]
    pub struct ExecuteReqPayload {
        pub execution_id: ExecutionId,
        pub action: ResolvedAction,
        #[serde(deserialize_with = "crate::wire::deserialize_unique_map")]
        pub env_secrets: BTreeMap<String, SecretString>,
        pub http_auth_headers: Vec<(String, SecretString)>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ssh_key_pem: Option<SecretString>,
        pub runtime_ms: u64,
        pub max_output_bytes: u32,
    }
}

impl ExecuteReqPayload {
    fn validate_wire(&self) -> Result<(), BridgeCodecError> {
        if self.runtime_ms == 0 {
            return Err(ValidationError::RuntimeLimit.into());
        }
        if self.max_output_bytes > MAX_OUTPUT_BYTES {
            return Err(ValidationError::OutputLimit.into());
        }
        Ok(())
    }
}

impl fmt::Debug for ExecuteReqPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecuteReqPayload")
            .field("execution_id", &self.execution_id)
            .field("runtime_ms", &self.runtime_ms)
            .field("max_output_bytes", &self.max_output_bytes)
            .finish_non_exhaustive()
    }
}

strict_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CancelReqPayload {
        pub execution_id: ExecutionId,
    }
}

strict_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ReceiptAckPayload {
        pub execution_ids: Vec<ExecutionId>,
    }
}

strict_struct! {
    #[derive(Clone, PartialEq, Eq)]
    pub struct RosterSyncPayload {
        pub platform_os: PlatformOs,
        pub platform_arch: String,
        pub allowed_cwd_roots: Vec<String>,
        pub max_concurrent_executions: u32,
        pub active_execution_ids: Vec<ExecutionId>,
        pub pending_receipt_count: u32,
    }
}

impl RosterSyncPayload {
    fn validate_wire(&self) -> Result<(), BridgeCodecError> {
        if self.allowed_cwd_roots.len() > MAX_ROSTER_CWD_ROOTS
            || self
                .allowed_cwd_roots
                .iter()
                .map(String::len)
                .sum::<usize>()
                > MAX_ROSTER_CWD_ROOT_BYTES
            || self.max_concurrent_executions == 0
            || self.active_execution_ids.len()
                > (self.max_concurrent_executions as usize).saturating_mul(2)
        {
            return Err(ValidationError::InvalidField("roster limits").into());
        }
        Ok(())
    }
}

impl fmt::Debug for RosterSyncPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RosterSyncPayload")
            .field("platform_os", &self.platform_os)
            .field("active_execution_ids", &self.active_execution_ids)
            .field("pending_receipt_count", &self.pending_receipt_count)
            .finish_non_exhaustive()
    }
}

strict_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ExecuteAckPayload {
        pub execution_id: ExecutionId,
        pub started_at_ms: i64,
    }
}

strict_struct! {
    #[derive(Clone, PartialEq, Eq)]
    pub struct ExecuteResPayload {
        pub execution_id: ExecutionId,
        pub state: TerminalExecutionState,
        pub effect_may_have_occurred: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub exit_code: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub http_status: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error_code: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error_message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub stdout_b64: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub stderr_b64: Option<String>,
        pub truncated: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub output_discarded_reason: Option<OutputDiscardedReason>,
        pub finished_at_ms: i64,
    }
}

impl ExecuteResPayload {
    fn validate_receipt(&self) -> Result<(), ValidationError> {
        use TerminalExecutionState::{Cancelled, TimedOut, Unknown};

        if (matches!(self.state, Unknown | Cancelled | TimedOut) && !self.effect_may_have_occurred)
            || (self.error_code.as_deref() == Some(error_codes::NODE_BUSY)
                && self.effect_may_have_occurred)
        {
            return Err(ValidationError::InvalidReceipt);
        }
        if self.output_discarded_reason.is_some()
            && (!self.truncated || self.stdout_b64.is_some() || self.stderr_b64.is_some())
        {
            return Err(ValidationError::InvalidReceipt);
        }
        validate_error_message(self.error_message.as_deref())
    }

    pub fn decode_and_validate_output(
        &self,
        max_output_bytes: u32,
    ) -> Result<DecodedOutput, ValidationError> {
        self.validate_receipt()?;
        decode_output(
            self.stdout_b64.as_deref(),
            self.stderr_b64.as_deref(),
            max_output_bytes,
        )
    }

    /// Convert the metadata of a validated receipt to a terminal summary.
    pub fn summary(&self, duration_ms: Option<u64>) -> Result<ExecutionSummary, ValidationError> {
        self.validate_receipt()?;
        Ok(ExecutionSummary {
            exit_code: self.exit_code,
            http_status: self.http_status,
            duration_ms,
            error_code: self.error_code.clone(),
            error_message: self.error_message.clone(),
            effect_may_have_occurred: Some(self.effect_may_have_occurred),
            output_discarded_reason: self.output_discarded_reason,
        })
    }
}

impl fmt::Debug for ExecuteResPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecuteResPayload")
            .field("execution_id", &self.execution_id)
            .field("state", &self.state)
            .field("effect_may_have_occurred", &self.effect_may_have_occurred)
            .field("output_discarded_reason", &self.output_discarded_reason)
            .finish_non_exhaustive()
    }
}

strict_struct! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct SyncCompletePayload {}
}

crate::wire::string_enum! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BridgeKind {
        HelloAck => "hello_ack",
        ExecuteReq => "execute_req",
        CancelReq => "cancel_req",
        ReceiptAck => "receipt_ack",
        RosterSync => "roster_sync",
        ExecuteAck => "execute_ack",
        ExecuteRes => "execute_res",
        SyncComplete => "sync_complete",
    }
}

impl BridgeKind {
    pub const fn receiver(self) -> BridgeReceiver {
        match self {
            Self::HelloAck | Self::ExecuteReq | Self::CancelReq | Self::ReceiptAck => {
                BridgeReceiver::Node
            }
            Self::RosterSync | Self::ExecuteAck | Self::ExecuteRes | Self::SyncComplete => {
                BridgeReceiver::Hub
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeMessage {
    HelloAck(HelloAckPayload),
    ExecuteReq(ExecuteReqPayload),
    CancelReq(CancelReqPayload),
    ReceiptAck(ReceiptAckPayload),
    RosterSync(RosterSyncPayload),
    ExecuteAck(ExecuteAckPayload),
    ExecuteRes(ExecuteResPayload),
    SyncComplete(SyncCompletePayload),
}

impl BridgeMessage {
    pub const fn kind(&self) -> BridgeKind {
        match self {
            Self::HelloAck(_) => BridgeKind::HelloAck,
            Self::ExecuteReq(_) => BridgeKind::ExecuteReq,
            Self::CancelReq(_) => BridgeKind::CancelReq,
            Self::ReceiptAck(_) => BridgeKind::ReceiptAck,
            Self::RosterSync(_) => BridgeKind::RosterSync,
            Self::ExecuteAck(_) => BridgeKind::ExecuteAck,
            Self::ExecuteRes(_) => BridgeKind::ExecuteRes,
            Self::SyncComplete(_) => BridgeKind::SyncComplete,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BridgeEnvelope {
    pub epoch: u64,
    pub message: BridgeMessage,
}

impl BridgeEnvelope {
    pub const fn kind(&self) -> BridgeKind {
        self.message.kind()
    }

    fn validate_wire(&self) -> Result<(), BridgeCodecError> {
        match &self.message {
            BridgeMessage::HelloAck(payload) if payload.session_epoch != self.epoch => {
                Err(BridgeCodecError::EpochMismatch)
            }
            BridgeMessage::ExecuteReq(payload) => payload.validate_wire(),
            BridgeMessage::RosterSync(payload) => payload.validate_wire(),
            BridgeMessage::ExecuteRes(payload) => {
                payload.decode_and_validate_output(MAX_OUTPUT_BYTES)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl fmt::Debug for BridgeEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeEnvelope")
            .field("epoch", &self.epoch)
            .field("kind", &self.kind())
            .finish()
    }
}

#[derive(Serialize)]
struct WireFrame<'a, T> {
    v: u32,
    epoch: u64,
    kind: BridgeKind,
    payload: &'a T,
}

fn write_frame<T: Serialize>(
    writer: &mut impl io::Write,
    envelope: &BridgeEnvelope,
    payload: &T,
) -> serde_json::Result<()> {
    serde_json::to_writer(
        writer,
        &WireFrame {
            v: BRIDGE_PROTOCOL_VERSION,
            epoch: envelope.epoch,
            kind: envelope.kind(),
            payload,
        },
    )
}

fn write_message(writer: &mut impl io::Write, envelope: &BridgeEnvelope) -> serde_json::Result<()> {
    match &envelope.message {
        BridgeMessage::HelloAck(payload) => write_frame(writer, envelope, payload),
        BridgeMessage::ExecuteReq(payload) => write_frame(writer, envelope, payload),
        BridgeMessage::CancelReq(payload) => write_frame(writer, envelope, payload),
        BridgeMessage::ReceiptAck(payload) => write_frame(writer, envelope, payload),
        BridgeMessage::RosterSync(payload) => write_frame(writer, envelope, payload),
        BridgeMessage::ExecuteAck(payload) => write_frame(writer, envelope, payload),
        BridgeMessage::ExecuteRes(payload) => write_frame(writer, envelope, payload),
        BridgeMessage::SyncComplete(payload) => write_frame(writer, envelope, payload),
    }
}

pub fn encode_bridge_frame(
    envelope: &BridgeEnvelope,
) -> Result<Zeroizing<Vec<u8>>, BridgeCodecError> {
    envelope.validate_wire()?;

    let size = crate::wire::bounded_json_len(MAX_BRIDGE_FRAME_BYTES, |writer| {
        write_message(writer, envelope)
    })
    .map_err(|error| match error {
        crate::wire::BoundedJsonError::TooLarge => BridgeCodecError::FrameTooLarge,
        crate::wire::BoundedJsonError::Serialization => BridgeCodecError::InvalidFrame,
    })?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    {
        let mut writer = crate::wire::BoundedBuffer::new(&mut bytes, size);
        write_message(&mut writer, envelope).map_err(|_| BridgeCodecError::InvalidFrame)?;
    }
    if bytes.len() != size {
        return Err(BridgeCodecError::InvalidFrame);
    }
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadFrame<T> {
    v: u32,
    epoch: u64,
    kind: BridgeKind,
    payload: T,
}

fn read_frame<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<ReadFrame<T>, BridgeCodecError> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let frame = deserialize_object(&mut decoder).map_err(|_| BridgeCodecError::InvalidFrame)?;
    decoder.end().map_err(|_| BridgeCodecError::InvalidFrame)?;
    Ok(frame)
}

/// Decode using the receiver role established by the connection.
pub fn decode_bridge_frame(
    bytes: &[u8],
    receiver: BridgeReceiver,
) -> Result<BridgeEnvelope, BridgeCodecError> {
    if bytes.len() > MAX_BRIDGE_FRAME_BYTES {
        return Err(BridgeCodecError::FrameTooLarge);
    }
    let header = read_frame::<IgnoredAny>(bytes)?;
    if header.v != BRIDGE_PROTOCOL_VERSION {
        return Err(BridgeCodecError::UnsupportedVersion(header.v));
    }
    if header.kind.receiver() != receiver {
        return Err(BridgeCodecError::WrongDirection(header.kind, receiver));
    }

    let message = match header.kind {
        BridgeKind::HelloAck => BridgeMessage::HelloAck(read_frame(bytes)?.payload),
        BridgeKind::ExecuteReq => BridgeMessage::ExecuteReq(read_frame(bytes)?.payload),
        BridgeKind::CancelReq => BridgeMessage::CancelReq(read_frame(bytes)?.payload),
        BridgeKind::ReceiptAck => BridgeMessage::ReceiptAck(read_frame(bytes)?.payload),
        BridgeKind::RosterSync => BridgeMessage::RosterSync(read_frame(bytes)?.payload),
        BridgeKind::ExecuteAck => BridgeMessage::ExecuteAck(read_frame(bytes)?.payload),
        BridgeKind::ExecuteRes => BridgeMessage::ExecuteRes(read_frame(bytes)?.payload),
        BridgeKind::SyncComplete => BridgeMessage::SyncComplete(read_frame(bytes)?.payload),
    };

    let envelope = BridgeEnvelope {
        epoch: header.epoch,
        message,
    };
    envelope.validate_wire()?;
    Ok(envelope)
}
