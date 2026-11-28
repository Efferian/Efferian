//! Upstream configuration and atomic refresh of its discovery cache.

mod discover;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{Json, extract::State};
use efferian_authz::authorize_admin;
use efferian_protocol::{
    EgressUrlMode, ProblemDetails, UpstreamId, egress_url_origin_eq, error_codes as code,
    validate_egress_url, validate_http_header_value, validate_http_headers_no_auth_collision,
    validate_http_tool_header_name, validate_slug,
};
use http::StatusCode;
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{
    ApiCaller, ApiError, ApiJson, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, Page,
    PageQuery, RouteGroups,
};
use crate::storage::{PriorityKind, WriteTx, WriteTxError, id, json};
use crate::upstream_dispatch::{UpstreamDispatcher, UpstreamInvalidation};
use crate::vault::auth::refresh_api;

pub(crate) use discover::DiscoveredToolSummary;

use super::{
    Outcome,
    references::{DELETE_REFERENCE_WORK_BYTES, upstream_in_use},
};

const MAX_HEADER_COUNT: usize = 32;
const MAX_HEADER_BYTES: usize = 16 * 1024;

const SUMMARY_COLUMNS: &str =
    "upstream_id, slug, url, headers_template_json, config_version, discovered_at_ms,
     json_array_length(discovered_tools_json), disabled_at_ms, created_at_ms, updated_at_ms";

type WriteResult<T> = Result<T, WriteTxError<ApiError>>;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UpstreamConfig {
    pub slug: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub config_version: u64,
    pub disabled_at_ms: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct UpstreamSummary {
    pub upstream_id: UpstreamId,
    pub slug: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    #[schema(minimum = 1)]
    pub config_version: u64,
    pub discovered_at_ms: Option<i64>,
    pub discovered_tool_count: usize,
    pub disabled_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct UpstreamDetail {
    #[serde(flatten)]
    pub summary: UpstreamSummary,
    pub discovered_tools: Vec<DiscoveredToolSummary>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct PutUpstream {
    url: String,
    #[serde(default, deserialize_with = "deserialize_headers")]
    headers: BTreeMap<String, String>,
}

#[derive(Serialize, ToSchema)]
struct PutUpstreamResponse {
    outcome: Outcome,
    upstream: UpstreamSummary,
}

fn deserialize_headers<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Headers;

    impl<'de> serde::de::Visitor<'de> for Headers {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique upstream headers")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut headers = BTreeMap::new();
            let mut bytes = 0;
            while let Some((name, value)) = map.next_entry::<String, String>()? {
                bytes += name.len() + value.len();
                if headers.len() == MAX_HEADER_COUNT || bytes > MAX_HEADER_BYTES {
                    return Err(serde::de::Error::custom(
                        "upstream headers exceed their limit",
                    ));
                }
                validate_http_tool_header_name(&name).map_err(serde::de::Error::custom)?;
                validate_http_header_value(&value).map_err(serde::de::Error::custom)?;
                if headers.insert(name.to_ascii_lowercase(), value).is_some() {
                    return Err(serde::de::Error::custom("duplicate upstream header"));
                }
            }
            validate_http_headers_no_auth_collision(&headers, None)
                .map_err(serde::de::Error::custom)?;
            Ok(headers)
        }
    }

    deserializer.deserialize_map(Headers)
}

pub(super) fn routes() -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::new()
            .routes(routes!(list))
            .routes(routes!(get, put, delete))
            .routes(routes!(enable))
            .merge(discover::route()),
        control: OpenApiRouter::new().routes(routes!(disable)),
        ..RouteGroups::default()
    }
}

#[utoipa::path(
    get,
    path = "/v1/upstreams",
    tag = "Upstreams",
    params(
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Page size (default 50)"),
        ("cursor" = Option<UpstreamId>, Query, description = "Return items after this upstream ID")
    ),
    responses((status = 200, description = "Upstream page", body = Page<UpstreamSummary>)),
    security(("api_bearer" = []))
)]
async fn list(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<PageQuery<UpstreamId>>,
) -> ApiResult<Json<Page<UpstreamSummary>>> {
    let limit = query.checked_limit()?;
    let cursor = query.cursor.map_or_else(String::new, |id| id.to_string());
    let clock = state.clock;
    let page = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            authorize_admin(&ctx)?;
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {SUMMARY_COLUMNS} FROM upstreams
                 WHERE upstream_id > ?1 COLLATE BINARY
                 ORDER BY upstream_id COLLATE BINARY LIMIT ?2"
            ))?;
            let items = stmt
                .query_map(params![cursor, limit + 1], read_summary_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Page::from_rows(items, limit, |summary| summary.upstream_id))
        })
        .await?;
    Ok(Json(page))
}

#[utoipa::path(
    get,
    path = "/v1/upstreams/{slug}",
    tag = "Upstreams",
    params(("slug" = String, Path, description = "Upstream slug")),
    responses(
        (status = 200, description = "Upstream and its discovered tools", body = UpstreamDetail),
        (status = 404, description = "Upstream does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn get(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
) -> ApiResult<Json<UpstreamDetail>> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    let clock = state.clock;
    let upstream = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            authorize_admin(&ctx)?;
            let upstream = upstream_id(conn, &slug)?.ok_or_else(ApiError::not_found)?;
            read_upstream_by_id(conn, upstream)?.ok_or_else(ApiError::not_found)
        })
        .await?;
    Ok(Json(upstream))
}

#[utoipa::path(
    put,
    path = "/v1/upstreams/{slug}",
    tag = "Upstreams",
    params(("slug" = String, Path, description = "Upstream slug")),
    request_body = PutUpstream,
    responses(
        (status = 200, description = "Upstream updated or unchanged", body = PutUpstreamResponse),
        (status = 201, description = "Upstream created", body = PutUpstreamResponse),
        (status = 409, description = "Accounts still use the current origin", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn put(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    ApiJson(request): ApiJson<PutUpstream>,
) -> ApiResult<(StatusCode, Json<PutUpstreamResponse>)> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    let url = validate_egress_url(
        &request.url,
        state.egress.policy(),
        EgressUrlMode::RequireHttpsByDefault,
    )
    .map_err(|_| ApiError::bad_input())?
    .to_string();
    let headers_json = serde_json::to_string(&request.headers).map_err(|_| ApiError::internal())?;
    let bytes = slug.len() + url.len() + headers_json.len();
    let response = state
        .storage
        .execute_work(bytes, move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            authorize_admin(&ctx)?;
            let (upstream_id, outcome) = upsert_upstream(tx, &slug, &url, &headers_json)?;
            if outcome != Outcome::Unchanged {
                invalidate(tx, state.upstream, upstream_id);
            }
            let upstream = read_summary(tx.conn(), upstream_id)?;
            Ok::<_, WriteTxError<ApiError>>(PutUpstreamResponse { outcome, upstream })
        })
        .await?;
    Ok((response.outcome.status(), Json(response)))
}

fn upsert_upstream(
    tx: &WriteTx<'_>,
    slug: &str,
    url: &str,
    headers_json: &str,
) -> WriteResult<(UpstreamId, Outcome)> {
    let existing: Option<(UpstreamId, String, String)> = tx
        .conn()
        .prepare_cached(
            "SELECT upstream_id, url, headers_template_json FROM upstreams WHERE slug = ?1",
        )?
        .query_row([slug], |row| Ok((id(row, 0)?, row.get(1)?, row.get(2)?)))
        .optional()?;
    if let Some((id, current_url, current_headers)) = existing {
        if current_url == url && current_headers == headers_json {
            return Ok((id, Outcome::Unchanged));
        }
        let same_origin = egress_url_origin_eq(&current_url, url)
            .map_err(|_| WriteTxError::InvalidDatabase("invalid stored upstream URL"))?;
        if !same_origin && has_http_accounts(tx.conn(), id)? {
            return Err(ApiError::conflict(code::RESOURCE_IN_USE).into());
        }
        tx.conn()
            .prepare_cached(
                "UPDATE upstreams SET url = ?2, headers_template_json = ?3, updated_at_ms = ?4,
                 config_version = config_version + 1,
                 discovered_tools_json = '[]', discovered_at_ms = NULL
             WHERE upstream_id = ?1",
            )?
            .execute(params![id.to_string(), url, headers_json, tx.now_ms()])?;
        Ok((id, Outcome::Updated))
    } else {
        let id = UpstreamId::new();
        tx.conn()
            .prepare_cached(
                "INSERT INTO upstreams (
                 upstream_id, slug, url, headers_template_json, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            )?
            .execute(params![
                id.to_string(),
                slug,
                url,
                headers_json,
                tx.now_ms()
            ])?;
        Ok((id, Outcome::Created))
    }
}

fn has_http_accounts(conn: &Connection, upstream: UpstreamId) -> rusqlite::Result<bool> {
    conn.prepare_cached(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE upstream_id = ?1 AND kind = 'http_auth')",
    )?
    .query_row([upstream.to_string()], |row| row.get(0))
}

#[utoipa::path(
    delete,
    path = "/v1/upstreams/{slug}",
    tag = "Upstreams",
    params(("slug" = String, Path, description = "Upstream slug")),
    responses(
        (status = 204, description = "Upstream deleted"),
        (status = 404, description = "Upstream does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A live resource still references the upstream", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn delete(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    {
        let slug = slug.clone();
        let clock = Arc::clone(&state.clock);
        let credential = caller.credential.clone();
        state
            .storage
            .read_snapshot(move |conn| -> ApiResult<()> {
                let ctx = refresh_api(conn, &credential, clock.wall_now_ms())?;
                authorize_admin(&ctx)?;
                let upstream = upstream_id(conn, &slug)?.ok_or_else(ApiError::not_found)?;
                if upstream_in_use(conn, upstream)? {
                    return Err(ApiError::conflict(code::RESOURCE_IN_USE));
                }
                Ok(())
            })
            .await?;
    }
    state
        .storage
        .execute_work(DELETE_REFERENCE_WORK_BYTES, move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            authorize_admin(&ctx)?;
            let upstream = upstream_id(tx.conn(), &slug)?.ok_or_else(ApiError::not_found)?;
            if upstream_in_use(tx.conn(), upstream)? {
                return Err(ApiError::conflict(code::RESOURCE_IN_USE).into());
            }
            tx.conn()
                .prepare_cached("DELETE FROM upstreams WHERE upstream_id = ?1")?
                .execute([upstream.to_string()])?;
            invalidate(tx, state.upstream, upstream);
            Ok::<_, WriteTxError<ApiError>>(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/upstreams/{slug}/disable",
    tag = "Upstreams",
    params(("slug" = String, Path, description = "Upstream slug")),
    responses(
        (status = 204, description = "Upstream disabled"),
        (status = 404, description = "Upstream does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn disable(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    state
        .storage
        .execute_priority(PriorityKind::DisableUpstream, move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            authorize_admin(&ctx)?;
            set_disabled(tx, &slug, true, state.upstream)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/upstreams/{slug}/enable",
    tag = "Upstreams",
    params(("slug" = String, Path, description = "Upstream slug")),
    responses(
        (status = 204, description = "Upstream enabled"),
        (status = 404, description = "Upstream does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn enable(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    state
        .storage
        .execute_work(slug.len(), move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            authorize_admin(&ctx)?;
            set_disabled(tx, &slug, false, state.upstream)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn set_disabled(
    tx: &mut WriteTx<'_>,
    slug: &str,
    disabled: bool,
    dispatcher: std::sync::Arc<dyn UpstreamDispatcher>,
) -> WriteResult<()> {
    let upstream = upstream_id(tx.conn(), slug)?.ok_or_else(ApiError::not_found)?;
    let now = tx.now_ms();
    let changed = tx
        .conn()
        .prepare_cached(
            "UPDATE upstreams SET disabled_at_ms = ?2, updated_at_ms = ?3,
             config_version = config_version + 1
         WHERE upstream_id = ?1 AND (disabled_at_ms IS NOT NULL) != ?4",
        )?
        .execute(params![
            upstream.to_string(),
            disabled.then_some(now),
            now,
            disabled
        ])?;
    if changed != 0 {
        invalidate(tx, dispatcher, upstream);
    }
    Ok(())
}

fn invalidate(
    tx: &mut WriteTx<'_>,
    dispatcher: std::sync::Arc<dyn UpstreamDispatcher>,
    id: UpstreamId,
) {
    tx.on_commit(move || dispatcher.invalidate(UpstreamInvalidation::Upstream(id)));
}

fn upstream_id(conn: &Connection, slug: &str) -> rusqlite::Result<Option<UpstreamId>> {
    conn.prepare_cached("SELECT upstream_id FROM upstreams WHERE slug = ?1")?
        .query_row([slug], |row| id(row, 0))
        .optional()
}

fn read_summary_row(row: &Row<'_>) -> rusqlite::Result<UpstreamSummary> {
    Ok(UpstreamSummary {
        upstream_id: id(row, 0)?,
        slug: row.get(1)?,
        url: row.get(2)?,
        headers: json(row, 3)?,
        config_version: row.get(4)?,
        discovered_at_ms: row.get(5)?,
        discovered_tool_count: row.get(6)?,
        disabled_at_ms: row.get(7)?,
        created_at_ms: row.get(8)?,
        updated_at_ms: row.get(9)?,
    })
}

fn read_summary(conn: &Connection, upstream: UpstreamId) -> rusqlite::Result<UpstreamSummary> {
    conn.prepare_cached(&format!(
        "SELECT {SUMMARY_COLUMNS} FROM upstreams WHERE upstream_id = ?1"
    ))?
    .query_row([upstream.to_string()], read_summary_row)
}

pub(crate) fn read_upstream_by_id(
    conn: &Connection,
    upstream: UpstreamId,
) -> rusqlite::Result<Option<UpstreamDetail>> {
    conn.prepare_cached(&format!(
        "SELECT {SUMMARY_COLUMNS}, discovered_tools_json FROM upstreams WHERE upstream_id = ?1"
    ))?
    .query_row([upstream.to_string()], |row| {
        Ok(UpstreamDetail {
            summary: read_summary_row(row)?,
            discovered_tools: json(row, 10)?,
        })
    })
    .optional()
}

pub(crate) fn read_upstream_config(
    conn: &Connection,
    upstream: UpstreamId,
) -> rusqlite::Result<Option<UpstreamConfig>> {
    conn.prepare_cached(
        "SELECT slug, url, headers_template_json, config_version, disabled_at_ms
         FROM upstreams WHERE upstream_id = ?1",
    )?
    .query_row([upstream.to_string()], |row| {
        Ok(UpstreamConfig {
            slug: row.get(0)?,
            url: row.get(1)?,
            headers: json(row, 2)?,
            config_version: row.get(3)?,
            disabled_at_ms: row.get(4)?,
        })
    })
    .optional()
}

pub(crate) fn upstream_discovery_matches(
    conn: &Connection,
    upstream: UpstreamId,
    config_version: u64,
    discovered_at_ms: Option<i64>,
) -> rusqlite::Result<bool> {
    conn.prepare_cached(
        "SELECT EXISTS(SELECT 1 FROM upstreams
         WHERE upstream_id = ?1 AND config_version = ?2 AND discovered_at_ms IS ?3)",
    )?
    .query_row(
        params![upstream.to_string(), config_version, discovered_at_ms],
        |row| row.get(0),
    )
}

#[cfg(test)]
mod tests;
