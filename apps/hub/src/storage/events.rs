use std::error::Error;
use std::str::FromStr;

use efferian_authz::EventAuthTarget;
use efferian_protocol::{
    ActorId, AggregateId, AggregateType, Event, EventEnvelope, EventId, EventKind,
    ExecutionEventPayload, GrantId, HubId, NodeId, PrincipalId, ProfileId, TokenId,
};
use rusqlite::types::Type;
use rusqlite::{Row, params};
use serde::Deserialize;
use serde::de::{DeserializeOwned, IntoDeserializer, value::Error as DeError};
use tokio::sync::broadcast;

use super::actor::WriteTx;
use super::{StorageError, StorageHandle};

#[derive(Clone, Debug)]
pub struct StoredEvent {
    pub envelope: EventEnvelope,
    pub auth: EventAuthTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationSignal {
    pub reason: RevocationReason,
    pub affected_principals: Vec<PrincipalId>,
    pub affected_nodes: Vec<NodeId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationReason {
    TokenRevoked(TokenId),
    PrincipalDisabled(PrincipalId),
    GrantRevoked(GrantId),
    EditionDisabled { profile_id: ProfileId, version: u64 },
    PrincipalPermissionsReduced(PrincipalId),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}

impl WriteTx<'_> {
    /// Persist the event and capture its authorization target in the same savepoint.
    pub(crate) fn append_event(
        &mut self,
        actor_id: ActorId,
        event: Event,
    ) -> Result<(), StorageError> {
        let conn = self.conn();
        let kind = event.kind();
        let aggregate_id = event.aggregate_id();
        let mut auth = EventAuthTarget {
            kind,
            owner_principal_id: None,
            agent_owner_principal_id: None,
            node_id: None,
            profile_id: None,
        };
        let payload = match &event {
            Event::ExecutionStarted(payload)
            | Event::ExecutionFinished(payload)
            | Event::ExecutionCancelled(payload)
            | Event::ExecutionLateReceipt(payload) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT e.caller_principal_id, p.owner_principal_id, e.node_id, e.profile_id
                     FROM executions e JOIN principals p ON p.principal_id = e.caller_principal_id
                     WHERE e.execution_id = ?1",
                )?;
                stmt.query_row([payload.execution_id.to_string()], |row| {
                    auth.owner_principal_id = Some(id(row, 0)?);
                    auth.agent_owner_principal_id = opt_id(row, 1)?;
                    auth.node_id = opt_id(row, 2)?;
                    auth.profile_id = opt_id(row, 3)?;
                    Ok(())
                })?;
                if auth.node_id != payload.node_id || auth.profile_id != payload.profile_id {
                    return Err(StorageError::InvalidDatabase("event projection mismatch"));
                }
                serde_json::to_string(payload).map_err(json_write_error)?
            }
            Event::NodeConnected(node_id)
            | Event::NodeDisconnected(node_id)
            | Event::NodeRevoked(node_id) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT managed_by_principal_id FROM nodes WHERE node_id = ?1",
                )?;
                auth.owner_principal_id =
                    stmt.query_row([node_id.to_string()], |row| opt_id(row, 0))?;
                auth.node_id = Some(*node_id);
                "{}".to_owned()
            }
            Event::ProfilePublished(profile_id) => {
                auth.profile_id = Some(*profile_id);
                "{}".to_owned()
            }
            Event::PrincipalRevoked(principal_id) => {
                auth.owner_principal_id = Some(*principal_id);
                "{}".to_owned()
            }
            Event::TokenRevoked(token_id) => {
                let mut stmt = conn
                    .prepare_cached("SELECT principal_id FROM auth_tokens WHERE token_id = ?1")?;
                auth.owner_principal_id =
                    Some(stmt.query_row([token_id.to_string()], |row| id(row, 0))?);
                "{}".to_owned()
            }
        };

        let event_id = EventId::new();
        let now = self.now_ms();
        let aggregate_type = scalar_text(aggregate_id.aggregate_type())?;
        let seq = {
            let mut insert = conn.prepare_cached(
                "INSERT INTO events(event_id, kind, aggregate_type, aggregate_id, actor_id,
                     owner_principal_id, agent_owner_principal_id, node_id, profile_id, payload_json,
                     created_at_ms, expires_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) RETURNING seq",
            )?;
            let seq = insert.query_row(
                params![
                    event_id.to_string(),
                    kind.as_str(),
                    aggregate_type,
                    aggregate_id.to_string(),
                    actor_id.to_string(),
                    auth.owner_principal_id.map(|id| id.to_string()),
                    auth.agent_owner_principal_id.map(|id| id.to_string()),
                    auth.node_id.map(|id| id.to_string()),
                    auth.profile_id.map(|id| id.to_string()),
                    payload,
                    now,
                    now.saturating_add(self.config.event_ttl_ms),
                ],
                |row| row.get::<_, i64>(0),
            )?;
            let mut update_head = conn.prepare_cached(
                "UPDATE hub_meta SET events_head_seq = MAX(events_head_seq, ?1) WHERE id = 1",
            )?;
            update_head.execute([seq])?;
            seq
        };
        self.stage_event(StoredEvent {
            envelope: EventEnvelope {
                seq,
                event_id,
                source_id: self.hub_id,
                actor_id,
                created_at_ms: now,
                event,
            },
            auth,
        });
        Ok(())
    }
}

#[derive(Debug)]
pub struct EventsPageRaw {
    pub items: Vec<StoredEvent>,
    pub scanned_through: i64,
    pub oldest_available_seq: i64,
    pub latest_seq: i64,
    pub has_more: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum EventsReadError {
    #[error("invalid event cursor or page size")]
    InvalidCursor,
    #[error("event cursor requires resync (oldest {oldest_available_seq}, latest {latest_seq})")]
    ResyncRequired {
        oldest_available_seq: i64,
        latest_seq: i64,
    },
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl From<rusqlite::Error> for EventsReadError {
    fn from(error: rusqlite::Error) -> Self {
        StorageError::from(error).into()
    }
}

impl StorageHandle {
    /// Call after subscribing to the live feed. Filter each returned item
    /// using the stored authorization target, then advance the raw cursor.
    pub async fn read_events(
        &self,
        after: i64,
        upper_bound: Option<i64>,
        limit: u32,
    ) -> Result<EventsPageRaw, EventsReadError> {
        if after < 0
            || !(1..=500).contains(&limit)
            || upper_bound.is_some_and(|upper| upper < after)
        {
            return Err(EventsReadError::InvalidCursor);
        }

        let source = *self.hub_id();
        self.read_snapshot(move |conn| {
            let mut meta = conn.prepare_cached(
                "SELECT events_head_seq, events_pruned_through_seq FROM hub_meta WHERE id = 1",
            )?;
            let (head, pruned): (i64, i64) =
                meta.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let oldest_available_seq = pruned.saturating_add(1);
            let upper = upper_bound.unwrap_or(head);
            if upper > head || after > head || (after > 0 && after < pruned) {
                return Err(EventsReadError::ResyncRequired {
                    oldest_available_seq,
                    latest_seq: head,
                });
            }

            let mut stmt = conn.prepare_cached(
                "SELECT seq, event_id, kind, aggregate_type, aggregate_id, actor_id, created_at_ms,
                        payload_json, owner_principal_id, agent_owner_principal_id, node_id, profile_id
                 FROM events WHERE seq > ?1 AND seq <= ?2 ORDER BY seq LIMIT ?3",
            )?;
            let items = stmt
                .query_map(params![after, upper, limit], |row| read_event(row, source))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let last = items.last().map_or(upper, |item| item.envelope.seq);
            let has_more = items.len() == limit as usize && last < upper;
            Ok(EventsPageRaw {
                items,
                scanned_through: if has_more { last } else { upper },
                oldest_available_seq,
                latest_seq: head,
                has_more,
            })
        })
        .await
    }
}

/// A revocation receiver reports a terminal receive error on either a gap or
/// closure, so cached permissions cannot become usable again after a gap.
pub struct RevocationWatch {
    receiver: Option<broadcast::Receiver<std::sync::Arc<RevocationSignal>>>,
}

impl RevocationWatch {
    pub(super) fn new(receiver: broadcast::Receiver<std::sync::Arc<RevocationSignal>>) -> Self {
        Self {
            receiver: Some(receiver),
        }
    }

    pub async fn recv(
        &mut self,
    ) -> Result<std::sync::Arc<RevocationSignal>, broadcast::error::RecvError> {
        let receiver = self
            .receiver
            .as_mut()
            .ok_or(broadcast::error::RecvError::Closed)?;
        let result = receiver.recv().await;
        if result.is_err() {
            self.receiver = None;
        }
        result
    }

    pub fn try_recv(
        &mut self,
    ) -> Result<std::sync::Arc<RevocationSignal>, broadcast::error::TryRecvError> {
        use broadcast::error::TryRecvError;
        let receiver = self.receiver.as_mut().ok_or(TryRecvError::Closed)?;
        let result = receiver.try_recv();
        if matches!(result, Err(TryRecvError::Closed | TryRecvError::Lagged(_))) {
            self.receiver = None;
        }
        result
    }
}

fn read_event(row: &Row<'_>, source_id: HubId) -> rusqlite::Result<StoredEvent> {
    let seq: i64 = row.get(0)?;
    let event_id: EventId = id(row, 1)?;
    let kind: EventKind = scalar(row, 2)?;
    let aggregate_type: AggregateType = scalar(row, 3)?;
    let aggregate_id: AggregateId = id(row, 4)?;
    let actor_id: ActorId = id(row, 5)?;
    let created_at_ms: i64 = row.get(6)?;
    let payload_str = row.get_ref(7)?.as_str()?;

    if aggregate_type != aggregate_id.aggregate_type() {
        return Err(invalid_text_msg(
            3,
            "event aggregate type does not match the ID",
        ));
    }

    let event = match (kind, aggregate_id) {
        (
            EventKind::ExecutionStarted
            | EventKind::ExecutionFinished
            | EventKind::ExecutionCancelled
            | EventKind::ExecutionLateReceipt,
            AggregateId::Execution(exec_id),
        ) => {
            let payload: ExecutionEventPayload =
                serde_json::from_str(payload_str).map_err(|error| invalid_text(7, error))?;
            if payload.execution_id != exec_id {
                return Err(invalid_text_msg(
                    7,
                    "execution event payload ID does not match aggregate ID",
                ));
            }
            match kind {
                EventKind::ExecutionStarted => Event::ExecutionStarted(payload),
                EventKind::ExecutionFinished => Event::ExecutionFinished(payload),
                EventKind::ExecutionCancelled => Event::ExecutionCancelled(payload),
                EventKind::ExecutionLateReceipt => Event::ExecutionLateReceipt(payload),
                _ => return Err(invalid_text_msg(2, "invalid execution event kind")),
            }
        }
        (EventKind::NodeConnected, AggregateId::Node(node_id)) => {
            decode_empty_payload(payload_str)?;
            Event::NodeConnected(node_id)
        }
        (EventKind::NodeDisconnected, AggregateId::Node(node_id)) => {
            decode_empty_payload(payload_str)?;
            Event::NodeDisconnected(node_id)
        }
        (EventKind::NodeRevoked, AggregateId::Node(node_id)) => {
            decode_empty_payload(payload_str)?;
            Event::NodeRevoked(node_id)
        }
        (EventKind::ProfilePublished, AggregateId::Profile(profile_id)) => {
            decode_empty_payload(payload_str)?;
            Event::ProfilePublished(profile_id)
        }
        (EventKind::AuthRevoked, AggregateId::Principal(principal_id)) => {
            decode_empty_payload(payload_str)?;
            Event::PrincipalRevoked(principal_id)
        }
        (EventKind::AuthRevoked, AggregateId::Token(token_id)) => {
            decode_empty_payload(payload_str)?;
            Event::TokenRevoked(token_id)
        }
        _ => {
            return Err(invalid_text_msg(
                2,
                "invalid event kind, aggregate, or payload",
            ));
        }
    };

    let auth = EventAuthTarget {
        kind,
        owner_principal_id: opt_id(row, 8)?,
        agent_owner_principal_id: opt_id(row, 9)?,
        node_id: opt_id(row, 10)?,
        profile_id: opt_id(row, 11)?,
    };

    let auth_consistent = match &event {
        Event::ExecutionStarted(payload)
        | Event::ExecutionFinished(payload)
        | Event::ExecutionCancelled(payload)
        | Event::ExecutionLateReceipt(payload) => {
            auth.owner_principal_id.is_some()
                && auth.node_id == payload.node_id
                && auth.profile_id == payload.profile_id
        }
        Event::NodeConnected(node_id)
        | Event::NodeDisconnected(node_id)
        | Event::NodeRevoked(node_id) => {
            auth.node_id == Some(*node_id)
                && auth.agent_owner_principal_id.is_none()
                && auth.profile_id.is_none()
        }
        Event::ProfilePublished(profile_id) => {
            auth.profile_id == Some(*profile_id)
                && auth.owner_principal_id.is_none()
                && auth.agent_owner_principal_id.is_none()
                && auth.node_id.is_none()
        }
        Event::PrincipalRevoked(principal_id) => {
            auth.owner_principal_id == Some(*principal_id)
                && auth.agent_owner_principal_id.is_none()
                && auth.node_id.is_none()
                && auth.profile_id.is_none()
        }
        Event::TokenRevoked(_) => {
            auth.owner_principal_id.is_some()
                && auth.agent_owner_principal_id.is_none()
                && auth.node_id.is_none()
                && auth.profile_id.is_none()
        }
    };
    if !auth_consistent {
        return Err(invalid_text_msg(
            8,
            "persisted event authorization projection does not match envelope",
        ));
    }

    Ok(StoredEvent {
        envelope: EventEnvelope {
            seq,
            event_id,
            source_id,
            actor_id,
            created_at_ms,
            event,
        },
        auth,
    })
}

fn decode_empty_payload(raw: &str) -> rusqlite::Result<()> {
    let _: EmptyPayload = serde_json::from_str(raw).map_err(|error| invalid_text(7, error))?;
    Ok(())
}

pub(super) fn id<T: FromStr>(row: &Row<'_>, column: usize) -> rusqlite::Result<T>
where
    T::Err: Error + Send + Sync + 'static,
{
    row.get_ref(column)?
        .as_str()?
        .parse()
        .map_err(|error| invalid_text(column, error))
}

pub(super) fn opt_id<T: FromStr>(row: &Row<'_>, column: usize) -> rusqlite::Result<Option<T>>
where
    T::Err: Error + Send + Sync + 'static,
{
    if row.get_ref(column)? == rusqlite::types::ValueRef::Null {
        Ok(None)
    } else {
        id(row, column).map(Some)
    }
}

pub(super) fn json<T: DeserializeOwned>(row: &Row<'_>, column: usize) -> rusqlite::Result<T> {
    serde_json::from_str(row.get_ref(column)?.as_str()?)
        .map_err(|error| invalid_text(column, error))
}

pub(super) fn scalar<T: DeserializeOwned>(row: &Row<'_>, column: usize) -> rusqlite::Result<T> {
    let text = row.get_ref(column)?.as_str()?;
    T::deserialize(text.into_deserializer()).map_err(|error: DeError| invalid_text(column, error))
}

pub(super) fn scalar_text<T: serde::Serialize>(value: T) -> rusqlite::Result<String> {
    match serde_json::to_value(value).map_err(json_write_error)? {
        serde_json::Value::String(text) => Ok(text),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

pub(super) fn json_write_error(error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

fn invalid_text(index: usize, error: impl Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(index, Type::Text, Box::new(error))
}

fn invalid_text_msg(index: usize, message: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message,
        )),
    )
}
