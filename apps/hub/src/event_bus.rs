//! Durable catch-up and live NDJSON from the same committed outbox.

mod stream;

use std::collections::HashSet;

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use efferian_authz::{AuthContext, can_observe_event};
use efferian_protocol::{EventEnvelope, EventKind, EventStreamFrame, ProblemDetails, error_codes};
use http::StatusCode;
use serde::{Deserialize, Serialize, de::value::StrDeserializer};
use utoipa::{PartialSchema, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{ApiCaller, ApiError, ApiQuery, ApiResult, AppState, RouteGroups};
use crate::storage::{EventsPageRaw, EventsReadError, StorageHandle, StoredEvent};
use crate::vault::auth::refresh_api;

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
        (status = 410, body = ProblemDetails, content_type = "application/problem+json", description = "Cursor requires resync")
    )
)]
async fn list(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<ListQuery>,
) -> ApiResult<Json<EventsPage>> {
    let kinds = EventKinds::parse(query.kinds.as_deref())?;
    let (ctx, page) = authorized_page(
        &state,
        caller,
        query.after.unwrap_or(0),
        query.limit.unwrap_or(50),
    )
    .await?;
    Ok(Json(EventsPage {
        items: page
            .items
            .into_iter()
            .filter(|event| kinds.permits(&ctx, event))
            .map(|event| event.envelope)
            .collect(),
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
        (status = 410, body = ProblemDetails, content_type = "application/problem+json", description = "Cursor requires resync"),
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
    let (ctx, page) = authorized_page(&state, caller, after, CATCH_UP_LIMIT).await?;
    let body = stream::body(state, ctx, kinds, revocations, events, after, page);
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

async fn authorized_page(
    state: &AppState,
    caller: crate::vault::auth::AuthenticatedApi,
    after: i64,
    limit: u32,
) -> ApiResult<(AuthContext, EventsPageRaw)> {
    if after < 0 || !(1..=CATCH_UP_LIMIT).contains(&limit) {
        return Err(ApiError::bad_input());
    }
    let clock = state.clock.clone();
    let hub = *state.storage.hub_id();
    state
        .storage
        .read_snapshot(move |conn| {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            let page = StorageHandle::read_events_page(conn, hub, after, None, limit, true)
                .map_err(events_error)?;
            Ok((ctx, page))
        })
        .await
}

fn events_error(error: EventsReadError) -> ApiError {
    match error {
        EventsReadError::InvalidCursor => ApiError::bad_input(),
        EventsReadError::Storage(error) => error.into(),
        EventsReadError::ResyncRequired {
            oldest_available_seq,
            latest_seq,
        } => ApiError::new(StatusCode::GONE, error_codes::RESYNC_REQUIRED)
            .with_extension("oldest_available_seq", oldest_available_seq.into())
            .with_extension("latest_seq", latest_seq.into()),
    }
}

struct EventKinds(Option<HashSet<EventKind>>);

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
                    .collect::<Result<_, _>>()
            })
            .transpose()
            .map_err(|_| ApiError::bad_input())?;
        Ok(Self(kinds))
    }

    fn permits(&self, ctx: &AuthContext, event: &StoredEvent) -> bool {
        self.0
            .as_ref()
            .is_none_or(|kinds| kinds.contains(&event.auth.kind))
            && can_observe_event(ctx, &event.auth)
    }
}

#[cfg(test)]
mod tests;
