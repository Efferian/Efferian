use std::collections::HashMap;
use std::sync::Arc;

use axum::{Json, extract::State};
use efferian_authz::{
    AuthContext, AuthzError, ExecutionTarget, authorize_discovery_target,
    authorize_profile_discover,
};
use efferian_protocol::{
    ExecutionMode, NodeId, ProblemDetails, ProfileId, ProfileToolBinding, TargetSelector,
    ToolAnnotations, ToolDefinition, ToolSpec, UpstreamAccountMode, UpstreamId,
    validate_public_tool_name, validate_slug,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::catalog::profiles::{ProfileEditionSummary, read_edition};
use crate::catalog::tools::read_tool_revision;
use crate::catalog::upstreams::read_upstream_config;
use crate::http::{
    ApiCaller, ApiError, ApiPath, ApiQuery, ApiResult, AppState, Page, checked_page_limit,
};
use crate::vault::auth::refresh_api;

use super::published_profile;
use super::selection::{AvailableTarget, discovery_targets};

pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_tools))
        .routes(routes!(get_tool))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoverQuery {
    q: Option<String>,
    limit: Option<u16>,
    cursor: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct DiscoveredProfileTool {
    public_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    execution_mode: ExecutionMode,
    curated_featured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<ToolAnnotations>,
}

#[derive(Serialize, ToSchema)]
struct DiscoveredProfileToolDetail {
    #[serde(flatten)]
    summary: DiscoveredProfileTool,
    #[schema(value_type = Object)]
    input_schema: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed_node_id: Option<NodeId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    available_targets: Option<Vec<AvailableTarget>>,
}

enum Visibility {
    Hidden,
    Upstream,
    Nodes(Vec<AvailableTarget>),
}

#[derive(Hash, PartialEq, Eq)]
enum VisibilityKey {
    Upstream(UpstreamId, UpstreamAccountMode),
    Fixed {
        fixed: Option<NodeId>,
        node_ids: Vec<NodeId>,
    },
    Tag {
        fixed: Option<NodeId>,
        tag: String,
    },
}

#[utoipa::path(
    get, path = "/v1/profiles/{slug}/tools", tag = "Profiles",
    params(
        ("slug" = String, Path, description = "Profile slug"),
        ("q" = Option<String>, Query, description = "Case-insensitive name or description search"),
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Maximum results, defaults to 50"),
        ("cursor" = Option<String>, Query, description = "Last public tool name from the previous page"),
    ),
    security(("api_bearer" = [])),
    responses(
        (status = 200, description = "Tools visible in the active edition", body = Page<DiscoveredProfileTool>),
        (status = 404, description = "No active edition visible to this caller", body = ProblemDetails, content_type = "application/problem+json"),
    )
)]
async fn list_tools(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    ApiQuery(query): ApiQuery<DiscoverQuery>,
) -> ApiResult<Json<Page<DiscoveredProfileTool>>> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    let limit = checked_page_limit(query.limit)?;
    if let Some(cursor) = &query.cursor {
        validate_public_tool_name(cursor).map_err(|_| ApiError::bad_input())?;
    }
    let cursor = query.cursor;
    let search = query.q.as_deref().map(str::to_lowercase);
    let clock = Arc::clone(&state.clock);
    let page = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            let mut edition = active_edition(conn, &ctx, &slug)?;
            edition
                .bindings
                .sort_unstable_by(|a, b| a.public_name.cmp(&b.public_name));
            let mut items = Vec::new();
            let mut visibility_cache = HashMap::<VisibilityKey, bool>::new();
            for binding in edition.bindings {
                if cursor
                    .as_deref()
                    .is_some_and(|after| binding.public_name.as_str() <= after)
                {
                    continue;
                }
                let Some(revision) =
                    read_tool_revision(conn, binding.tool_id, binding.tool_version)?
                else {
                    continue;
                };
                if revision.disabled_at_ms.is_some() {
                    continue;
                }
                let summary = summary(&binding, &revision.definition);
                if let Some(search) = &search
                    && !summary.public_name.to_lowercase().contains(search)
                    && !summary
                        .description
                        .as_ref()
                        .is_some_and(|description| description.to_lowercase().contains(search))
                {
                    continue;
                }
                if !cached_visible(
                    conn,
                    &ctx,
                    edition.profile_id,
                    &binding,
                    &revision.definition,
                    &mut visibility_cache,
                )? {
                    continue;
                }
                items.push(summary);
                if items.len() > limit {
                    break;
                }
            }
            Ok(Page::from_rows(items, limit, |item| {
                item.public_name.clone()
            }))
        })
        .await?;
    Ok(Json(page))
}

#[utoipa::path(
    get, path = "/v1/profiles/{slug}/tools/{public_name}", tag = "Profiles",
    params(
        ("slug" = String, Path, description = "Profile slug"),
        ("public_name" = String, Path, description = "Published tool name"),
    ),
    security(("api_bearer" = [])),
    responses(
        (status = 200, description = "Tool schema and visible targets", body = DiscoveredProfileToolDetail),
        (status = 404, description = "No active published tool visible to this caller", body = ProblemDetails, content_type = "application/problem+json"),
    )
)]
async fn get_tool(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath((slug, public_name)): ApiPath<(String, String)>,
) -> ApiResult<Json<DiscoveredProfileToolDetail>> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    validate_public_tool_name(&public_name).map_err(|_| ApiError::bad_input())?;
    let clock = Arc::clone(&state.clock);
    let detail = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &caller.credential, clock.wall_now_ms())?;
            let edition = active_edition(conn, &ctx, &slug)?;
            let binding = edition
                .bindings
                .iter()
                .find(|binding| binding.public_name == public_name)
                .ok_or_else(ApiError::not_found)?;
            let revision = read_tool_revision(conn, binding.tool_id, binding.tool_version)?
                .filter(|revision| revision.disabled_at_ms.is_none())
                .ok_or_else(ApiError::not_found)?;
            let visible = tool_visibility(
                conn,
                &ctx,
                edition.profile_id,
                binding,
                &revision.definition,
                false,
            )?;
            let available_targets = match visible {
                Visibility::Hidden => return Err(ApiError::not_found()),
                Visibility::Upstream => None,
                Visibility::Nodes(nodes) => Some(nodes),
            };
            Ok(DiscoveredProfileToolDetail {
                summary: summary(binding, &revision.definition),
                input_schema: revision
                    .definition
                    .input_schema
                    .ok_or_else(ApiError::internal)?,
                fixed_node_id: binding.fixed_node_id,
                available_targets,
            })
        })
        .await?;
    Ok(Json(detail))
}

fn active_edition(
    conn: &Connection,
    ctx: &AuthContext,
    slug: &str,
) -> ApiResult<ProfileEditionSummary> {
    let profile = published_profile(conn, slug)?;
    authorize_profile_discover(ctx, profile.map(|(id, _)| id))?;
    let (id, version) = profile.ok_or_else(ApiError::not_found)?;
    read_edition(conn, id, version.get())?
        .filter(|edition| edition.disabled_at_ms.is_none())
        .ok_or_else(ApiError::not_found)
}

fn cached_visible(
    conn: &Connection,
    ctx: &AuthContext,
    profile_id: ProfileId,
    binding: &ProfileToolBinding,
    definition: &ToolDefinition,
    cache: &mut HashMap<VisibilityKey, bool>,
) -> ApiResult<bool> {
    let key = match &definition.spec {
        ToolSpec::UpstreamRef {
            upstream_id,
            account_mode,
            ..
        } => VisibilityKey::Upstream(*upstream_id, *account_mode),
        spec => match spec.target_selector().ok_or_else(ApiError::internal)? {
            TargetSelector::Fixed { node_ids } => {
                let mut sorted = node_ids.clone();
                sorted.sort_unstable();
                VisibilityKey::Fixed {
                    fixed: binding.fixed_node_id,
                    node_ids: sorted,
                }
            }
            TargetSelector::Tag { tag } => VisibilityKey::Tag {
                fixed: binding.fixed_node_id,
                tag: tag.clone(),
            },
        },
    };
    if let Some(&visible) = cache.get(&key) {
        return Ok(visible);
    }
    let visible = !matches!(
        tool_visibility(conn, ctx, profile_id, binding, definition, true)?,
        Visibility::Hidden,
    );
    cache.insert(key, visible);
    Ok(visible)
}

fn tool_visibility(
    conn: &Connection,
    ctx: &AuthContext,
    profile_id: ProfileId,
    binding: &ProfileToolBinding,
    definition: &ToolDefinition,
    first_only: bool,
) -> ApiResult<Visibility> {
    match &definition.spec {
        ToolSpec::UpstreamRef {
            upstream_id,
            account_mode,
            ..
        } => {
            let target = ExecutionTarget::Upstream {
                upstream_id: *upstream_id,
                account: *account_mode,
            };
            match authorize_discovery_target(ctx, profile_id, target) {
                Ok(()) => {}
                Err(AuthzError::ResourceNotFound | AuthzError::ScopeNarrowedOut) => {
                    return Ok(Visibility::Hidden);
                }
                Err(error) => return Err(error.into()),
            }
            if read_upstream_config(conn, *upstream_id)?
                .is_some_and(|upstream| upstream.disabled_at_ms.is_none())
            {
                Ok(Visibility::Upstream)
            } else {
                Ok(Visibility::Hidden)
            }
        }
        spec => {
            let selector = spec.target_selector().ok_or_else(ApiError::internal)?;
            let nodes = discovery_targets(
                conn,
                ctx,
                profile_id,
                selector,
                binding.fixed_node_id,
                first_only,
            )?;
            if nodes.is_empty() {
                Ok(Visibility::Hidden)
            } else {
                Ok(Visibility::Nodes(nodes))
            }
        }
    }
}

fn summary(binding: &ProfileToolBinding, definition: &ToolDefinition) -> DiscoveredProfileTool {
    DiscoveredProfileTool {
        public_name: binding.public_name.clone(),
        description: binding
            .description_override
            .clone()
            .or_else(|| definition.description.clone()),
        execution_mode: binding.execution_mode,
        curated_featured: binding.curated_featured,
        annotations: definition.annotations.clone(),
    }
}
