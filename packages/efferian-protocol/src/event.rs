use crate::wire::strict_enum;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    ActorId, AggregateId, AggregateType, EventId, ExecutionId, ExecutionState, HubId, NodeId,
    PrincipalId, ProfileId, TokenId, ToolId,
    wire::{deserialize_object, strict_struct},
};

macro_rules! event_kinds {
    ($($variant:ident => $wire:tt),+ $(,)?) => {
        crate::wire::string_enum! {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
            #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
            pub enum EventKind { $($variant => $wire),+ }
        }

        impl EventKind {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire),+
                }
            }
        }
    };
}

event_kinds! {
    ExecutionStarted => "execution.started",
    ExecutionFinished => "execution.finished",
    ExecutionCancelled => "execution.cancelled",
    ExecutionLateReceipt => "execution.late_receipt",
    NodeConnected => "node.connected",
    NodeDisconnected => "node.disconnected",
    NodeRevoked => "node.revoked",
    ProfilePublished => "profile.published",
    AuthRevoked => "auth.revoked",
}

strict_struct! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ExecutionEventPayload {
        pub execution_id: ExecutionId,
        pub state: ExecutionState,
        #[serde(deserialize_with = "Deserialize::deserialize")]
        pub profile_id: Option<ProfileId> => (required = true),
        pub tool_id: ToolId,
        pub public_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub node_id: Option<NodeId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub exit_code: Option<i32>,
        #[serde(default, deserialize_with = "crate::result::deserialize_error_code", skip_serializing_if = "Option::is_none")]
        pub error_code: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub duration_ms: Option<u64>,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    ExecutionStarted(ExecutionEventPayload),
    ExecutionFinished(ExecutionEventPayload),
    ExecutionCancelled(ExecutionEventPayload),
    ExecutionLateReceipt(ExecutionEventPayload),
    NodeConnected(NodeId),
    NodeDisconnected(NodeId),
    NodeRevoked(NodeId),
    ProfilePublished(ProfileId),
    PrincipalRevoked(PrincipalId),
    TokenRevoked(TokenId),
}

impl Event {
    pub const fn kind(&self) -> EventKind {
        match self {
            Self::ExecutionStarted(_) => EventKind::ExecutionStarted,
            Self::ExecutionFinished(_) => EventKind::ExecutionFinished,
            Self::ExecutionCancelled(_) => EventKind::ExecutionCancelled,
            Self::ExecutionLateReceipt(_) => EventKind::ExecutionLateReceipt,
            Self::NodeConnected(_) => EventKind::NodeConnected,
            Self::NodeDisconnected(_) => EventKind::NodeDisconnected,
            Self::NodeRevoked(_) => EventKind::NodeRevoked,
            Self::ProfilePublished(_) => EventKind::ProfilePublished,
            Self::PrincipalRevoked(_) | Self::TokenRevoked(_) => EventKind::AuthRevoked,
        }
    }

    pub const fn aggregate_id(&self) -> AggregateId {
        match self {
            Self::ExecutionStarted(payload)
            | Self::ExecutionFinished(payload)
            | Self::ExecutionCancelled(payload)
            | Self::ExecutionLateReceipt(payload) => AggregateId::Execution(payload.execution_id),
            Self::NodeConnected(id) | Self::NodeDisconnected(id) | Self::NodeRevoked(id) => {
                AggregateId::Node(*id)
            }
            Self::ProfilePublished(id) => AggregateId::Profile(*id),
            Self::PrincipalRevoked(id) => AggregateId::Principal(*id),
            Self::TokenRevoked(id) => AggregateId::Token(*id),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventEnvelope {
    pub seq: i64,
    pub event_id: EventId,
    pub source_id: HubId,
    pub actor_id: ActorId,
    pub created_at_ms: i64,
    pub event: Event,
}

crate::wire::string_enum! {
    #[derive(Clone, Copy)]
    enum SourceKind { Hub => "hub" }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEvent<T> {
    seq: i64,
    event_id: EventId,
    source_kind: SourceKind,
    source_id: HubId,
    kind: EventKind,
    aggregate_type: AggregateType,
    aggregate_id: AggregateId,
    actor_id: ActorId,
    created_at_ms: i64,
    payload: T,
}

strict_struct! {
    struct EmptyPayload {}
}

impl EventEnvelope {
    pub const fn kind(&self) -> EventKind {
        self.event.kind()
    }

    pub const fn aggregate_id(&self) -> AggregateId {
        self.event.aggregate_id()
    }

    fn wire<T>(&self, payload: T) -> WireEvent<T> {
        let aggregate_id = self.aggregate_id();
        WireEvent {
            seq: self.seq,
            event_id: self.event_id,
            source_kind: SourceKind::Hub,
            source_id: self.source_id,
            kind: self.kind(),
            aggregate_type: aggregate_id.aggregate_type(),
            aggregate_id,
            actor_id: self.actor_id,
            created_at_ms: self.created_at_ms,
            payload,
        }
    }
}

impl Serialize for EventEnvelope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.event {
            Event::ExecutionStarted(payload)
            | Event::ExecutionFinished(payload)
            | Event::ExecutionCancelled(payload)
            | Event::ExecutionLateReceipt(payload) => self.wire(payload).serialize(serializer),
            _ => self.wire(EmptyPayload {}).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for EventEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Payload {
            Execution(ExecutionEventPayload),
            Empty(EmptyPayload),
        }

        let wire: WireEvent<Payload> = deserialize_object(deserializer)?;
        if wire.aggregate_type != wire.aggregate_id.aggregate_type() {
            return Err(de::Error::custom(
                "event aggregate type does not match the ID",
            ));
        }

        use AggregateId::*;
        let event = match (wire.kind, wire.aggregate_id, wire.payload) {
            (kind, Execution(id), Payload::Execution(payload)) if payload.execution_id == id => {
                match kind {
                    EventKind::ExecutionStarted => Event::ExecutionStarted(payload),
                    EventKind::ExecutionFinished => Event::ExecutionFinished(payload),
                    EventKind::ExecutionCancelled => Event::ExecutionCancelled(payload),
                    EventKind::ExecutionLateReceipt => Event::ExecutionLateReceipt(payload),
                    _ => return Err(de::Error::custom("invalid execution event kind")),
                }
            }
            (EventKind::NodeConnected, Node(id), Payload::Empty(_)) => Event::NodeConnected(id),
            (EventKind::NodeDisconnected, Node(id), Payload::Empty(_)) => {
                Event::NodeDisconnected(id)
            }
            (EventKind::NodeRevoked, Node(id), Payload::Empty(_)) => Event::NodeRevoked(id),
            (EventKind::ProfilePublished, Profile(id), Payload::Empty(_)) => {
                Event::ProfilePublished(id)
            }
            (EventKind::AuthRevoked, Principal(id), Payload::Empty(_)) => {
                Event::PrincipalRevoked(id)
            }
            (EventKind::AuthRevoked, Token(id), Payload::Empty(_)) => Event::TokenRevoked(id),
            _ => {
                return Err(de::Error::custom(
                    "invalid event kind, aggregate, or payload",
                ));
            }
        };
        Ok(Self {
            seq: wire.seq,
            event_id: wire.event_id,
            source_id: wire.source_id,
            actor_id: wire.actor_id,
            created_at_ms: wire.created_at_ms,
            event,
        })
    }
}

strict_enum! {
    tag = "type",
    decode = object,
    // Inline storage avoids an extra allocation for each event in the stream.
    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum EventStreamFrame {
        Event {
            event: EventEnvelope,
        },
        Ping {},
        ResyncRequired {
            oldest_available_seq: i64,
            latest_seq: i64,
        },
    }
}

#[cfg(feature = "openapi")]
mod openapi {
    use utoipa::{
        PartialSchema, ToSchema,
        openapi::{
            Ref, RefOr,
            schema::{ObjectBuilder, OneOfBuilder, Schema},
        },
    };

    use super::*;
    use crate::wire::schema::{closed_object, string_tag};

    fn event_schema(
        kind: EventKind,
        aggregate_type: &str,
        aggregate_id: RefOr<Schema>,
        payload: RefOr<Schema>,
    ) -> ObjectBuilder {
        closed_object()
            .property("seq", i64::schema())
            .required("seq")
            .property("event_id", EventId::schema())
            .required("event_id")
            .property("source_kind", string_tag("hub"))
            .required("source_kind")
            .property("source_id", HubId::schema())
            .required("source_id")
            .property("kind", string_tag(kind.as_str()))
            .required("kind")
            .property("aggregate_type", string_tag(aggregate_type))
            .required("aggregate_type")
            .property("aggregate_id", aggregate_id)
            .required("aggregate_id")
            .property("actor_id", ActorId::schema())
            .required("actor_id")
            .property("created_at_ms", i64::schema())
            .required("created_at_ms")
            .property("payload", payload)
            .required("payload")
    }

    impl PartialSchema for EventEnvelope {
        fn schema() -> RefOr<Schema> {
            let mut schema = OneOfBuilder::new();
            for kind in [
                EventKind::ExecutionStarted,
                EventKind::ExecutionFinished,
                EventKind::ExecutionCancelled,
                EventKind::ExecutionLateReceipt,
            ] {
                schema = schema.item(
                    event_schema(
                        kind,
                        "execution",
                        ExecutionId::schema(),
                        Ref::from_schema_name(ExecutionEventPayload::name()).into(),
                    )
                    .description(Some("The payload's execution_id must equal aggregate_id.")),
                );
            }
            for kind in [
                EventKind::NodeConnected,
                EventKind::NodeDisconnected,
                EventKind::NodeRevoked,
            ] {
                schema = schema.item(event_schema(
                    kind,
                    "node",
                    NodeId::schema(),
                    closed_object().into(),
                ));
            }
            schema
                .item(event_schema(
                    EventKind::ProfilePublished,
                    "profile",
                    ProfileId::schema(),
                    closed_object().into(),
                ))
                .item(event_schema(
                    EventKind::AuthRevoked,
                    "principal",
                    PrincipalId::schema(),
                    closed_object().into(),
                ))
                .item(event_schema(
                    EventKind::AuthRevoked,
                    "token",
                    TokenId::schema(),
                    closed_object().into(),
                ))
                .into()
        }
    }

    impl ToSchema for EventEnvelope {
        fn schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
            schemas.push((
                ExecutionEventPayload::name().into(),
                ExecutionEventPayload::schema(),
            ));
            ExecutionEventPayload::schemas(schemas);
        }
    }
}
