//! Profile drafts and immutable published editions.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use axum::{Json, extract::State};
use efferian_authz::authorize_admin;
use efferian_protocol::{
    ActorId, DiscoveryMode, Event, MAX_PROFILE_BINDINGS, PrincipalId, ProblemDetails, ProfileId,
    ProfileToolBinding, error_codes as code, validate_profile_bindings, validate_slug,
};
use http::StatusCode;
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{
    API_LIMIT, ApiCaller, ApiError, ApiJson, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody,
    Page, PageQuery, RouteGroups,
};
use crate::storage::{
    PriorityKind, WriteTx, WriteTxError, id, invalid_text_msg, json, scalar, scalar_text,
};
use crate::vault::auth::{AuthenticatedApi, refresh_api};

use super::Outcome;
use super::references::profile_in_use;
use super::tools::{read_tool_revision, validate_binding_node, validate_dependencies};

type WriteResult<T> = Result<T, WriteTxError<ApiError>>;

// The normalized JSON can add default fields to each binding. Account this
// worst case on publish, whose request does not carry the draft's bytes.
const MAX_PUBLISH_BYTES: usize = API_LIMIT + 64 * MAX_PROFILE_BINDINGS;

pub(super) fn routes() -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::new()
            .routes(routes!(list))
            .routes(routes!(get, put, delete))
            .routes(routes!(publish))
            .routes(routes!(enable)),
        control: OpenApiRouter::new()
            .routes(routes!(disable))
            .routes(routes!(disable_edition)),
        ..RouteGroups::default()
    }
}

#[derive(Clone, Serialize, ToSchema)]
pub(crate) struct ProfileSummary {
    pub(crate) profile_id: ProfileId,
    pub(crate) slug: String,
    pub(crate) discovery_mode: DiscoveryMode,
    pub(crate) published_version: u64,
    pub(crate) disabled_at_ms: Option<i64>,
    pub(crate) created_at_ms: i64,
    pub(crate) updated_at_ms: i64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ProfileDetail {
    #[serde(flatten)]
    pub(crate) summary: ProfileSummary,
    pub(crate) draft_bindings: Vec<ProfileToolBinding>,
    pub(crate) published_edition: Option<ProfileEditionSummary>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ProfileEditionSummary {
    pub(crate) profile_id: ProfileId,
    #[schema(minimum = 1)]
    pub(crate) version: u64,
    pub(crate) discovery_mode: DiscoveryMode,
    pub(crate) published_by: PrincipalId,
    pub(crate) published_at_ms: i64,
    pub(crate) disabled_at_ms: Option<i64>,
    pub(crate) bindings: Vec<ProfileToolBinding>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct ProfilePut {
    discovery_mode: DiscoveryMode,
    #[schema(max_items = 1024)]
    bindings: Vec<ProfileToolBinding>,
}

#[derive(Serialize, ToSchema)]
struct ProfilePutResponse {
    outcome: Outcome,
    profile: ProfileDetail,
}

#[derive(Serialize, ToSchema)]
struct PublishResponse {
    outcome: Outcome,
    edition: ProfileEditionSummary,
}

#[utoipa::path(
    get, path = "/v1/profiles", tag = "Profiles",
    params(
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Page size (default 50)"),
        ("cursor" = Option<ProfileId>, Query, description = "Return items after this profile ID")
    ),
    responses((status = 200, description = "Profiles page", body = Page<ProfileSummary>)),
    security(("api_bearer" = []))
)]
async fn list(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<PageQuery<ProfileId>>,
) -> ApiResult<Json<Page<ProfileSummary>>> {
    let limit = query.checked_limit()?;
    let cursor = query.cursor.map(|value| value.to_string());
    let clock = state.clock;
    let page = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            authorize_admin(&refresh_api(conn, &caller.credential, clock.wall_now_ms())?)?;
            let mut stmt = conn.prepare_cached(
                "SELECT profile_id, slug, discovery_mode, published_version, disabled_at_ms,
                    created_at_ms, updated_at_ms FROM profiles
             WHERE profile_id COLLATE BINARY > ?1 ORDER BY profile_id COLLATE BINARY LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(
                    params![cursor.as_deref().unwrap_or(""), limit + 1],
                    read_summary,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Page::from_rows(rows, limit, |profile| profile.profile_id))
        })
        .await?;
    Ok(Json(page))
}

#[utoipa::path(
    get, path = "/v1/profiles/{slug}", tag = "Profiles",
    params(("slug" = String, Path, description = "Profile slug")),
    responses(
        (status = 200, description = "Profile draft and current edition", body = ProfileDetail),
        (status = 404, description = "Profile does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn get(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
) -> ApiResult<Json<ProfileDetail>> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    let clock = state.clock;
    let profile = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            authorize_admin(&refresh_api(conn, &caller.credential, clock.wall_now_ms())?)?;
            read_profile(conn, &slug)?.ok_or_else(ApiError::not_found)
        })
        .await?;
    Ok(Json(profile))
}

#[utoipa::path(
    put, path = "/v1/profiles/{slug}", tag = "Profiles",
    params(("slug" = String, Path, description = "Profile slug")),
    request_body = ProfilePut,
    responses(
        (status = 200, description = "Draft updated or unchanged", body = ProfilePutResponse),
        (status = 201, description = "Profile created", body = ProfilePutResponse),
        (status = 400, description = "Invalid tool bindings", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Referenced dependency does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn put(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    ApiJson(request): ApiJson<ProfilePut>,
) -> ApiResult<(StatusCode, Json<ProfilePutResponse>)> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    validate_profile_bindings(&request.bindings).map_err(|_| ApiError::bad_input())?;
    let bindings_json = serialize_bindings(&request.bindings)?;
    let bytes = bindings_json.len() + slug.len();
    let new_id = ProfileId::new();
    let response = state
        .storage
        .execute_work(bytes, move |tx| {
            authorize_admin(&refresh_api(tx.conn(), &caller.credential, tx.now_ms())?)?;
            validate_dependencies_for_bindings(tx.conn(), &request.bindings)?;
            upsert_profile(tx, slug, new_id, request, bindings_json)
        })
        .await?;
    Ok((response.outcome.status(), Json(response)))
}

#[utoipa::path(
    post, path = "/v1/profiles/{slug}/publish", tag = "Profiles",
    params(("slug" = String, Path, description = "Profile slug")),
    responses(
        (status = 200, description = "Identical active edition already published", body = PublishResponse),
        (status = 201, description = "New edition published", body = PublishResponse),
        (status = 400, description = "Draft dependencies are invalid", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Profile or a draft dependency does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn publish(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    _: EmptyBody,
) -> ApiResult<(StatusCode, Json<PublishResponse>)> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    let response = state
        .storage
        .execute_work(MAX_PUBLISH_BYTES + slug.len(), move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            authorize_admin(&ctx)?;
            let profile = read_profile(tx.conn(), &slug)?.ok_or_else(ApiError::not_found)?;
            validate_dependencies_for_bindings(tx.conn(), &profile.draft_bindings)?;
            publish_edition(tx, profile, ctx.caller.principal_id)
        })
        .await?;
    Ok((response.outcome.status(), Json(response)))
}

#[utoipa::path(
    delete, path = "/v1/profiles/{slug}", tag = "Profiles",
    params(("slug" = String, Path, description = "Profile slug")),
    responses(
        (status = 204, description = "Profile, editions and grants deleted"),
        (status = 404, description = "Profile does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Profile has active executions", body = ProblemDetails, content_type = "application/problem+json")
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
    state
        .storage
        .execute_work(slug.len(), move |tx| {
            authorize_admin(&refresh_api(tx.conn(), &caller.credential, tx.now_ms())?)?;
            let (profile, _) = profile_status(tx.conn(), &slug)?;
            if profile_in_use(tx.conn(), profile)? {
                return Err(ApiError::conflict(code::RESOURCE_IN_USE).into());
            }
            tx.revoke_profile_grants(profile)?;
            let profile = profile.to_string();
            tx.conn()
                .prepare_cached("DELETE FROM profile_editions WHERE profile_id = ?1")?
                .execute([&profile])?;
            tx.conn()
                .prepare_cached("DELETE FROM profiles WHERE profile_id = ?1")?
                .execute([&profile])?;
            Ok::<_, WriteTxError<ApiError>>(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/profiles/{slug}/disable", tag = "Profiles",
    params(("slug" = String, Path, description = "Profile slug")),
    responses(
        (status = 204, description = "Profile disabled"),
        (status = 404, description = "Profile does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn disable(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    set_disabled(state, caller, slug, true).await
}

#[utoipa::path(
    post, path = "/v1/profiles/{slug}/enable", tag = "Profiles",
    params(("slug" = String, Path, description = "Profile slug")),
    responses(
        (status = 204, description = "Profile enabled"),
        (status = 404, description = "Profile does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn enable(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    set_disabled(state, caller, slug, false).await
}

#[utoipa::path(
    post, path = "/v1/profiles/{slug}/versions/{version}/disable", tag = "Profiles",
    params(
        ("slug" = String, Path, description = "Profile slug"),
        ("version" = u64, Path, minimum = 1, description = "Edition version")
    ),
    responses(
        (status = 204, description = "Edition irreversibly disabled"),
        (status = 404, description = "Profile or edition does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn disable_edition(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath((slug, version)): ApiPath<(String, u64)>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    let version = NonZeroU64::new(version)
        .ok_or_else(ApiError::bad_input)?
        .get();
    state.storage.execute_priority(PriorityKind::DisableEdition, move |tx| {
        authorize_admin(&refresh_api(tx.conn(), &caller.credential, tx.now_ms())?)?;
        let (profile, _) = profile_status(tx.conn(), &slug)?;
        if !tx.disable_edition(profile, version)? {
            let version = i64::try_from(version).map_err(|_| ApiError::not_found())?;
            let exists: bool = tx.conn().prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM profile_editions WHERE profile_id = ?1 AND version = ?2)",
            )?.query_row(params![profile.to_string(), version], |row| row.get(0))?;
            if !exists {
                return Err(ApiError::not_found().into());
            }
        }
        Ok::<_, WriteTxError<ApiError>>(())
    }).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_disabled(
    state: AppState,
    caller: AuthenticatedApi,
    slug: String,
    disabled: bool,
) -> ApiResult<StatusCode> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    let bytes = slug.len();
    let update = move |tx: &mut WriteTx<'_>| -> WriteResult<()> {
        authorize_admin(&refresh_api(tx.conn(), &caller.credential, tx.now_ms())?)?;
        let (profile, disabled_at) = profile_status(tx.conn(), &slug)?;
        if disabled_at.is_some() != disabled {
            tx.conn().prepare_cached(
                "UPDATE profiles SET disabled_at_ms = ?1, updated_at_ms = ?2 WHERE profile_id = ?3",
            )?.execute(params![disabled.then_some(tx.now_ms()), tx.now_ms(), profile.to_string()])?;
        }
        Ok(())
    };
    if disabled {
        state
            .storage
            .execute_priority(PriorityKind::DisableProfile, update)
            .await?;
    } else {
        state.storage.execute_work(bytes, update).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

fn profile_status(conn: &Connection, slug: &str) -> ApiResult<(ProfileId, Option<i64>)> {
    conn.prepare_cached("SELECT profile_id, disabled_at_ms FROM profiles WHERE slug = ?1")?
        .query_row([slug], |row| Ok((id(row, 0)?, row.get(1)?)))
        .optional()?
        .ok_or_else(ApiError::not_found)
}

fn read_summary(row: &Row<'_>) -> rusqlite::Result<ProfileSummary> {
    Ok(ProfileSummary {
        profile_id: id(row, 0)?,
        slug: row.get(1)?,
        discovery_mode: scalar(row, 2)?,
        published_version: row.get(3)?,
        disabled_at_ms: row.get(4)?,
        created_at_ms: row.get(5)?,
        updated_at_ms: row.get(6)?,
    })
}

pub(crate) fn read_profile(
    conn: &Connection,
    slug: &str,
) -> rusqlite::Result<Option<ProfileDetail>> {
    let draft = conn
        .prepare_cached(
            "SELECT profile_id, slug, discovery_mode, published_version, disabled_at_ms,
                created_at_ms, updated_at_ms, draft_bindings_json FROM profiles WHERE slug = ?1",
        )?
        .query_row([slug], |row| {
            Ok((read_summary(row)?, read_bindings(row, 7)?))
        })
        .optional()?;
    let Some((summary, draft_bindings)) = draft else {
        return Ok(None);
    };
    let published_edition = if summary.published_version == 0 {
        None
    } else {
        Some(
            read_edition(conn, summary.profile_id, summary.published_version)?
                .ok_or_else(|| invalid_text_msg(3, "missing current profile edition"))?,
        )
    };
    Ok(Some(ProfileDetail {
        summary,
        draft_bindings,
        published_edition,
    }))
}

pub(crate) fn read_edition(
    conn: &Connection,
    profile_id: ProfileId,
    version: u64,
) -> rusqlite::Result<Option<ProfileEditionSummary>> {
    let Ok(version_i64) = i64::try_from(version) else {
        return Ok(None);
    };
    conn.prepare_cached(
        "SELECT discovery_mode, published_by, published_at_ms, disabled_at_ms, bindings_json
         FROM profile_editions WHERE profile_id = ?1 AND version = ?2",
    )?
    .query_row(params![profile_id.to_string(), version_i64], |row| {
        Ok(ProfileEditionSummary {
            profile_id,
            version,
            discovery_mode: scalar(row, 0)?,
            published_by: id(row, 1)?,
            published_at_ms: row.get(2)?,
            disabled_at_ms: row.get(3)?,
            bindings: read_bindings(row, 4)?,
        })
    })
    .optional()
}

fn read_bindings(row: &Row<'_>, column: usize) -> rusqlite::Result<Vec<ProfileToolBinding>> {
    let bindings: Vec<_> = json(row, column)?;
    validate_profile_bindings(&bindings)
        .map_err(|_| invalid_text_msg(column, "invalid profile bindings"))?;
    Ok(bindings)
}

fn serialize_bindings(bindings: &[ProfileToolBinding]) -> ApiResult<String> {
    let serialized = serde_json::to_string(bindings).map_err(|_| ApiError::internal())?;
    if serialized.len() > MAX_PUBLISH_BYTES {
        return Err(ApiError::too_large());
    }
    Ok(serialized)
}

fn validate_dependencies_for_bindings(
    conn: &Connection,
    bindings: &[ProfileToolBinding],
) -> WriteResult<()> {
    let mut revisions = BTreeMap::<_, Vec<_>>::new();
    for binding in bindings {
        revisions
            .entry((binding.tool_id, binding.tool_version))
            .or_default()
            .push(binding);
    }
    for ((tool_id, version), bindings) in revisions {
        let revision =
            read_tool_revision(conn, tool_id, version)?.ok_or_else(ApiError::not_found)?;
        validate_dependencies(conn, &revision.definition)?;
        for binding in bindings {
            if let Some(node) = binding.fixed_node_id {
                validate_binding_node(conn, &revision.definition, node)?;
            }
        }
    }
    Ok(())
}

fn upsert_profile(
    tx: &WriteTx<'_>,
    slug: String,
    new_id: ProfileId,
    request: ProfilePut,
    bindings_json: String,
) -> WriteResult<ProfilePutResponse> {
    let ProfilePut {
        discovery_mode,
        bindings,
    } = request;
    let now = tx.now_ms();
    let Some(mut existing) = read_profile(tx.conn(), &slug)? else {
        tx.conn().prepare_cached(
            "INSERT INTO profiles(profile_id, slug, discovery_mode, created_at_ms, updated_at_ms, draft_bindings_json)
             VALUES (?1, ?2, ?3, ?4, ?4, ?5)",
        )?.execute(params![new_id.to_string(), &slug, scalar_text(discovery_mode)?, now, bindings_json])?;
        return Ok(ProfilePutResponse {
            outcome: Outcome::Created,
            profile: ProfileDetail {
                summary: ProfileSummary {
                    profile_id: new_id,
                    slug,
                    discovery_mode,
                    published_version: 0,
                    disabled_at_ms: None,
                    created_at_ms: now,
                    updated_at_ms: now,
                },
                draft_bindings: bindings,
                published_edition: None,
            },
        });
    };
    if existing.summary.discovery_mode == discovery_mode && existing.draft_bindings == bindings {
        return Ok(ProfilePutResponse {
            outcome: Outcome::Unchanged,
            profile: existing,
        });
    }
    tx.conn()
        .prepare_cached(
            "UPDATE profiles SET discovery_mode = ?1, draft_bindings_json = ?2, updated_at_ms = ?3
         WHERE profile_id = ?4",
        )?
        .execute(params![
            scalar_text(discovery_mode)?,
            bindings_json,
            now,
            existing.summary.profile_id.to_string()
        ])?;
    existing.summary.discovery_mode = discovery_mode;
    existing.summary.updated_at_ms = now;
    existing.draft_bindings = bindings;
    Ok(ProfilePutResponse {
        outcome: Outcome::Updated,
        profile: existing,
    })
}

fn publish_edition(
    tx: &mut WriteTx<'_>,
    profile: ProfileDetail,
    actor: PrincipalId,
) -> WriteResult<PublishResponse> {
    let ProfileDetail {
        summary,
        draft_bindings,
        published_edition,
    } = profile;
    if let Some(existing) = published_edition
        && existing.disabled_at_ms.is_none()
        && existing.discovery_mode == summary.discovery_mode
        && existing.bindings == draft_bindings
    {
        return Ok(PublishResponse {
            outcome: Outcome::Unchanged,
            edition: existing,
        });
    }
    let now = tx.now_ms();
    let version = summary
        .published_version
        .checked_add(1)
        .filter(|&version| i64::try_from(version).is_ok())
        .ok_or_else(ApiError::internal)?;
    let profile_id = summary.profile_id.to_string();
    let bindings_json = serialize_bindings(&draft_bindings)?;
    tx.conn().prepare_cached(
        "INSERT INTO profile_editions (profile_id, version, discovery_mode, published_by, published_at_ms, bindings_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?.execute(params![&profile_id, version, scalar_text(summary.discovery_mode)?, actor.to_string(), now, bindings_json])?;
    tx.conn()
        .prepare_cached(
            "UPDATE profiles SET published_version = ?1, updated_at_ms = ?2 WHERE profile_id = ?3",
        )?
        .execute(params![version, now, &profile_id])?;
    tx.append_event(
        ActorId::Principal(actor),
        Event::ProfilePublished(summary.profile_id),
    )?;
    Ok(PublishResponse {
        outcome: Outcome::Created,
        edition: ProfileEditionSummary {
            profile_id: summary.profile_id,
            version,
            discovery_mode: summary.discovery_mode,
            published_by: actor,
            published_at_ms: now,
            disabled_at_ms: None,
            bindings: draft_bindings,
        },
    })
}

#[cfg(test)]
mod tests;
