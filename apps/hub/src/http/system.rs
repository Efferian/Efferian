use std::sync::{Arc, OnceLock};

use axum::{
    Extension, Json,
    extract::State,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use efferian_protocol::{HubId, PROBLEM_JSON_MEDIA_TYPE, ProblemDetails};
use http::{
    HeaderMap, StatusCode,
    header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use utoipa::{
    Modify, OpenApi, ToSchema,
    openapi::{
        Content, Ref,
        path::Operation,
        response::ResponseBuilder,
        security::{Http, HttpAuthScheme, SecurityScheme},
    },
};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{ApiError, ApiResult, AppState};

#[derive(OpenApi)]
#[openapi(
    info(title = "Efferian Hub", version = env!("CARGO_PKG_VERSION")),
    components(schemas(ProblemDetails)),
    modifiers(&BearerSecurity)
)]
struct ApiDoc;

struct BearerSecurity;

impl Modify for BearerSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        for name in ["api_bearer", "enrollment_bearer", "node_bearer"] {
            components.add_security_scheme(
                name,
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
        }
    }
}

pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(health))
        .routes(routes!(info))
        .routes(routes!(openapi))
}

pub(super) fn document_boundary_errors(doc: &mut utoipa::openapi::OpenApi) {
    for path in doc.paths.paths.values_mut() {
        for (operation, checks_body) in [
            (&mut path.get, false),
            (&mut path.head, false),
            (&mut path.options, false),
            (&mut path.trace, false),
            (&mut path.post, true),
            (&mut path.put, true),
            (&mut path.patch, true),
            (&mut path.delete, true),
        ] {
            if let Some(operation) = operation {
                document_operation_errors(operation, checks_body);
            }
        }
    }
}

fn document_operation_errors(operation: &mut Operation, checks_body: bool) {
    use StatusCode as Status;

    let mut problems = vec![
        (Status::BAD_REQUEST, "A request header or input is invalid."),
        (Status::FORBIDDEN, "The request is forbidden."),
        (Status::CONFLICT, "The request targets a different Hub."),
    ];
    if operation
        .security
        .as_ref()
        .is_some_and(|rules| !rules.is_empty())
    {
        problems.extend([
            (
                Status::UNAUTHORIZED,
                "The credential is absent or inactive.",
            ),
            (
                Status::INTERNAL_SERVER_ERROR,
                "The Hub could not complete the request.",
            ),
            (
                Status::SERVICE_UNAVAILABLE,
                "The Hub is temporarily unable to admit the request.",
            ),
        ]);
    }
    if checks_body || operation.request_body.is_some() {
        problems.extend([
            (
                Status::REQUEST_TIMEOUT,
                "The request body stalled while being read.",
            ),
            (
                Status::PAYLOAD_TOO_LARGE,
                "The request body exceeds the route limit.",
            ),
        ]);
    }
    if operation
        .request_body
        .as_ref()
        .is_some_and(|body| body.content.contains_key("application/json"))
    {
        problems.push((
            Status::UNSUPPORTED_MEDIA_TYPE,
            "A JSON content type is required.",
        ));
    }

    for (status, description) in problems {
        operation
            .responses
            .responses
            .entry(status.as_str().to_owned())
            .or_insert_with(|| {
                ResponseBuilder::new()
                    .description(description)
                    .content(
                        PROBLEM_JSON_MEDIA_TYPE,
                        Content::new(Some(Ref::from_schema_name("ProblemDetails"))),
                    )
                    .build()
                    .into()
            });
    }
}

#[derive(Serialize, ToSchema)]
struct HubHealth {
    status: &'static str,
}

#[utoipa::path(
    get,
    path = "/v1/health",
    security(),
    responses((status = 200, body = HubHealth))
)]
async fn health() -> Json<HubHealth> {
    Json(HubHealth { status: "ok" })
}

#[derive(Serialize, ToSchema)]
struct HubInfo {
    hub_id: HubId,
    version: &'static str,
}

#[utoipa::path(
    get,
    path = "/v1/info",
    security(),
    responses((status = 200, body = HubInfo))
)]
async fn info(State(state): State<AppState>) -> Json<HubInfo> {
    Json(HubInfo {
        hub_id: *state.storage.hub_id(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[utoipa::path(
    get,
    path = "/v1/openapi.json",
    security(),
    responses(
        (status = 200, description = "OpenAPI 3.1 document", content_type = "application/json",
            headers(("ETag", description = "Current document version"))),
        (status = 304, description = "The document is unchanged",
            headers(("ETag", description = "Current document version")))
    )
)]
async fn openapi(
    Extension(artifact): Extension<Arc<OnceLock<OpenApiArtifact>>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let artifact = artifact.get().ok_or_else(ApiError::internal)?;
    if etag_matches(&headers, artifact.etag.as_bytes()) {
        return Ok((StatusCode::NOT_MODIFIED, [(ETAG, artifact.etag.as_str())]).into_response());
    }
    Ok((
        [
            (ETAG, artifact.etag.as_str()),
            (CONTENT_TYPE, "application/json"),
        ],
        artifact.bytes.clone(),
    )
        .into_response())
}

pub(super) struct OpenApiArtifact {
    bytes: Bytes,
    etag: String,
}

impl OpenApiArtifact {
    pub fn build(doc: &utoipa::openapi::OpenApi) -> Result<Self, serde_json::Error> {
        let bytes = build_openapi_bytes(doc)?;
        let digest = Sha256::digest(&bytes);
        let mut etag = String::with_capacity(66);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        etag.push('"');
        for byte in digest {
            etag.push(char::from(HEX[usize::from(byte >> 4)]));
            etag.push(char::from(HEX[usize::from(byte & 15)]));
        }
        etag.push('"');
        Ok(Self { bytes, etag })
    }
}

pub fn build_openapi_bytes(doc: &utoipa::openapi::OpenApi) -> Result<Bytes, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(doc)?;
    bytes.push(b'\n');
    Ok(Bytes::from(bytes))
}

fn etag_matches(headers: &HeaderMap, expected: &[u8]) -> bool {
    let values = headers.get_all(IF_NONE_MATCH);
    let mut fields = values.iter();
    let Some(first) = fields.next() else {
        return false;
    };
    if trim_ows(first.as_bytes()) == b"*" {
        return fields.next().is_none();
    }

    let mut matched = false;
    for field in std::iter::once(first).chain(fields) {
        let Some(field_match) = etag_list_matches(field.as_bytes(), expected) else {
            return false;
        };
        matched |= field_match;
    }
    matched
}

fn etag_list_matches(mut field: &[u8], expected: &[u8]) -> Option<bool> {
    let mut matched = false;
    loop {
        field = trim_ows(field);
        if field.is_empty() {
            return Some(matched);
        }
        if let Some(rest) = field.strip_prefix(b",") {
            field = rest;
            continue;
        }

        let tag = field.strip_prefix(b"W/").unwrap_or(field);
        let opaque = tag.strip_prefix(b"\"")?;
        let end = opaque.iter().position(|byte| *byte == b'"')?;
        if !opaque[..end]
            .iter()
            .all(|byte| matches!(byte, b'!' | b'#'..=b'~' | 0x80..=0xff))
        {
            return None;
        }
        let tag_end = end + 2;
        matched |= &tag[..tag_end] == expected;
        field = trim_ows(&tag[tag_end..]);
        if field.is_empty() {
            return Some(matched);
        }
        field = field.strip_prefix(b",")?;
    }
}

fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.first(), Some(b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    while matches!(bytes.last(), Some(b' ' | b'\t')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
