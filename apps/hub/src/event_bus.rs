//! Durable catch-up and live NDJSON from the same committed outbox.

mod stream;

use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use efferian_authz::{AuthContext, can_observe_event};
use efferian_protocol::{
    EventEnvelope, EventKind, EventStreamFrame, ProblemDetails, TokenId, error_codes,
};
use http::StatusCode;
use serde::{Deserialize, Serialize, de::value::StrDeserializer};
use utoipa::{PartialSchema, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{ApiCaller, ApiError, ApiQuery, ApiResult, AppState, RouteGroups};
use crate::storage::{
    EventsPageRaw, EventsReadError, StorageClock, StorageError, StorageHandle, StoredEvent,
};
use crate::vault::auth::{CredentialError, VerifiedCredential, refresh_api};

const CATCH_UP_LIMIT: u32 = 500;
const NDJSON: &str = "application/x-ndjson";

pub(crate) fn routes() -> RouteGroups {
    let mut application = OpenApiRouter::new().routes(routes!(list));
    // Utoipa collects schemas from bodies, so register this query-only enum.
    application
        .get_openapi_mut()
        .components
        .get_or_insert_with(Default::default)
        .schemas
        .insert(EventKind::name().into_owned(), EventKind::schema());
    RouteGroups {
        application,
        event_stream: OpenApiRouter::new().routes(routes!(subscribe)),
        ..RouteGroups::default()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    after: Option<i64>,
    limit: Option<u32>,
    kinds: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamQuery {
    after: Option<i64>,
    kinds: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct EventsPage {
    items: Vec<EventEnvelope>,
    next_seq: i64,
    oldest_available_seq: i64,
    latest_seq: i64,
    has_more: bool,
}

#[utoipa::path(
    get,
    path = "/v1/events",
    tag = "Events",
    security(("api_bearer" = [])),
    params(
        ("after" = Option<i64>, Query, minimum = 0, description = "Last scanned sequence (0 starts at the retained prefix)"),
        ("limit" = Option<u32>, Query, minimum = 1, maximum = 500, description = "Maximum outbox rows to scan (default 50)"),
        ("kinds" = Option<Vec<EventKind>>, Query, style = Form, explode = false, description = "Comma-separated event kinds"),
    ),
    responses(
        (status = 200, body = EventsPage, description = "Authorized outbox page"),
        (status = 410, body = ProblemDetails, content_type = "application/problem+json",
            description = "resync_required if after is nonzero and older than the last pruned sequence or if it exceeds the outbox head. extensions.oldest_available_seq gives the first sequence after the pruned prefix. extensions.latest_seq gives the outbox head.")
    )
)]
async fn list(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<ListQuery>,
) -> ApiResult<Json<EventsPage>> {
    let kinds = EventKinds::parse(query.kinds.as_deref())?;
    let page = EventReader::new(&state, caller.credential, false)
        .read(
            query.after.unwrap_or(0),
            None,
            query.limit.unwrap_or(50),
            true,
            &kinds,
        )
        .await?
        .events;
    Ok(Json(EventsPage {
        items: page.items.into_iter().map(|event| event.envelope).collect(),
        next_seq: page.scanned_through,
        oldest_available_seq: page.oldest_available_seq,
        latest_seq: page.latest_seq,
        has_more: page.has_more,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/events/stream",
    tag = "Events",
    security(("api_bearer" = [])),
    params(
        ("after" = Option<i64>, Query, minimum = 0, description = "Last scanned sequence (0 starts at the retained prefix)"),
        ("kinds" = Option<Vec<EventKind>>, Query, style = Form, explode = false, description = "Comma-separated event kinds")
    ),
    responses(
        (status = 200, body = EventStreamFrame, content_type = "application/x-ndjson",
            description = "One event, ping or resync frame per line", headers(
                ("X-Accel-Buffering" = String, description = "no"),
                ("Cache-Control" = String, description = "no-store")
            )),
        (status = 410, body = ProblemDetails, content_type = "application/problem+json",
            description = "resync_required before streaming if after is nonzero and older than the last pruned sequence or if it exceeds the outbox head. extensions.oldest_available_seq gives the first sequence after the pruned prefix. extensions.latest_seq gives the outbox head."),
        (status = 429, body = ProblemDetails, content_type = "application/problem+json", description = "Event stream limit reached")
    )
)]
async fn subscribe(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<StreamQuery>,
) -> ApiResult<Response> {
    let kinds = EventKinds::parse(query.kinds.as_deref())?;
    let after = query.after.unwrap_or(0);
    // Subscribe to both channels before fixing the initial database snapshot.
    let revocations = state.storage.subscribe_revocations()?;
    let events = state.storage.subscribe_events()?;
    let reader = EventReader::new(&state, caller.credential, true);
    let page = reader
        .read(after, None, CATCH_UP_LIMIT, true, &kinds)
        .await?;
    let body = stream::body(
        reader,
        state.execution.shutdown_receiver(),
        kinds,
        revocations,
        events,
        after,
        page,
    );
    Ok((
        [
            ("content-type", NDJSON),
            ("x-accel-buffering", "no"),
            ("cache-control", "no-store"),
        ],
        body,
    )
        .into_response())
}

#[derive(Clone)]
struct EventReader {
    storage: StorageHandle,
    clock: Arc<dyn StorageClock>,
    credential: VerifiedCredential<TokenId>,
    stream_lane: bool,
}

struct AuthorizedPage {
    scope: AuthContext,
    events: EventsPageRaw,
}

impl EventReader {
    fn new(state: &AppState, credential: VerifiedCredential<TokenId>, stream_lane: bool) -> Self {
        Self {
            storage: state.storage.clone(),
            clock: state.clock.clone(),
            credential,
            stream_lane,
        }
    }

    async fn read(
        &self,
        after: i64,
        through: Option<i64>,
        limit: u32,
        allow_bootstrap_zero: bool,
        kinds: &EventKinds,
    ) -> Result<AuthorizedPage, PageError> {
        if after < 0 || !(1..=CATCH_UP_LIMIT).contains(&limit) {
            return Err(EventsReadError::InvalidCursor.into());
        }
        let clock = self.clock.clone();
        let credential = self.credential.clone();
        let hub = *self.storage.hub_id();
        let kinds = kinds.clone();
        let read_fn = move |conn: &rusqlite::Connection| {
            let scope = refresh_api(conn, &credential, clock.wall_now_ms())?;
            // A SQLite commit can precede its RevocationWatch notification.
            // Filter with the permissions from the very snapshot that supplied
            // the rows before decoding `payload_json`.
            let events = StorageHandle::read_events_page_filtered(
                conn,
                hub,
                after,
                through,
                limit,
                allow_bootstrap_zero,
                |kind, auth| kinds.includes(kind) && can_observe_event(&scope, auth),
            )?;
            Ok(AuthorizedPage { scope, events })
        };
        if self.stream_lane {
            self.storage.read_stream_snapshot(read_fn).await
        } else {
            self.storage.read_snapshot(read_fn).await
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum PageError {
    #[error(transparent)]
    Credential(#[from] CredentialError),
    #[error(transparent)]
    Events(#[from] EventsReadError),
}

impl From<StorageError> for PageError {
    fn from(error: StorageError) -> Self {
        EventsReadError::from(error).into()
    }
}

impl From<PageError> for ApiError {
    fn from(error: PageError) -> Self {
        match error {
            PageError::Credential(error) => error.into(),
            PageError::Events(EventsReadError::InvalidCursor) => Self::bad_input(),
            PageError::Events(EventsReadError::Storage(error)) => error.into(),
            PageError::Events(EventsReadError::ResyncRequired {
                oldest_available_seq,
                latest_seq,
            }) => Self::new(StatusCode::GONE, error_codes::RESYNC_REQUIRED)
                .with_extension("oldest_available_seq", oldest_available_seq.into())
                .with_extension("latest_seq", latest_seq.into()),
        }
    }
}

#[derive(Clone)]
struct EventKinds(Option<Arc<HashSet<EventKind>>>);

impl EventKinds {
    fn parse(raw: Option<&str>) -> ApiResult<Self> {
        let kinds = raw
            .map(|value| {
                value
                    .split(',')
                    .map(|kind| {
                        EventKind::deserialize(StrDeserializer::<serde::de::value::Error>::new(
                            kind,
                        ))
                    })
                    .collect::<Result<HashSet<_>, _>>()
                    .map(Arc::new)
            })
            .transpose()
            .map_err(|_| ApiError::bad_input())?;
        Ok(Self(kinds))
    }

    fn includes(&self, kind: EventKind) -> bool {
        self.0.as_ref().is_none_or(|kinds| kinds.contains(&kind))
    }

    fn permits(&self, ctx: &AuthContext, event: &StoredEvent) -> bool {
        self.includes(event.auth.kind) && can_observe_event(ctx, &event.auth)
    }
}

#[cfg(test)]
mod tests;
