use std::collections::BTreeSet;

use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn generated_openapi_matches_the_committed_contract() -> TestResult {
    let snapshot = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/openapi-hub.json"
    ))?;
    assert!(
        snapshot == efferian_hub::openapi_bytes()?,
        "OpenAPI drift: regenerate contracts/openapi-hub.json with the export_openapi example"
    );
    Ok(())
}

#[test]
fn openapi_covers_the_complete_v1_surface() -> TestResult {
    let doc: Value = serde_json::from_slice(&efferian_hub::openapi_bytes()?)?;
    assert_eq!(doc["openapi"], "3.1.0");
    let paths = doc["paths"].as_object().ok_or("OpenAPI paths missing")?;
    assert_eq!(paths.len(), 48);
    let mut operations = BTreeSet::new();
    let mut operation_ids = BTreeSet::new();
    for (path, item) in paths {
        let item = item.as_object().ok_or("invalid OpenAPI path item")?;
        for (method, operation) in item {
            if METHODS.contains(&method.as_str()) {
                operations.insert(format!("{method} {path}"));
                let id = operation["operationId"]
                    .as_str()
                    .ok_or("missing operation ID")?;
                assert!(operation_ids.insert(id), "duplicate operation ID {id}");
                let expected_params: BTreeSet<_> = path
                    .split('/')
                    .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
                    .collect();
                let path_params: BTreeSet<_> = operation["parameters"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|param| param["in"] == "path")
                    .filter_map(|param| param["name"].as_str())
                    .collect();
                assert_eq!(path_params, expected_params, "{method} {path}");
                assert!(
                    ["101", "200", "201", "204"]
                        .iter()
                        .any(|status| operation["responses"][status].is_object()),
                    "missing success response for {method} {path}"
                );
                if let Some(schema) =
                    operation.pointer("/requestBody/content/application~1json/schema")
                    && path != "/v1/enrollment/exchange"
                {
                    assert!(
                        closed_input(schema, &doc, &mut BTreeSet::new()),
                        "open input schema for {method} {path}"
                    );
                }
            }
        }
    }
    let expected: BTreeSet<_> = OPERATIONS.lines().map(str::to_owned).collect();
    assert_eq!(operations.len(), 62);
    assert_eq!(operations, expected);
    assert_schema_references(&doc, &doc);

    for (path, method, statuses) in [
        (
            "/v1/bridge/connect",
            "get",
            &["101", "400", "426", "429", "503"][..],
        ),
        (
            "/v1/profiles/{slug}/invoke",
            "post",
            &["200", "202", "409", "410", "429", "503"],
        ),
        (
            "/v1/tools/{slug}/test",
            "post",
            &["200", "202", "409", "410", "429", "503"],
        ),
        ("/v1/executions/{id}/cancel", "post", &["200", "202"]),
        ("/v1/events", "get", &["200", "410"]),
        ("/v1/events/stream", "get", &["200", "410", "429"]),
        (
            "/v1/upstreams/{slug}/discover",
            "post",
            &["200", "409", "502", "504"],
        ),
    ] {
        for status in statuses {
            let response = &paths[path][method]["responses"][status];
            assert!(
                response.is_object(),
                "missing response {status} for {method} {path}"
            );
            if status.starts_with(['4', '5']) {
                assert_eq!(
                    response["content"]["application/problem+json"]["schema"]["$ref"],
                    "#/components/schemas/ProblemDetails",
                    "missing ProblemDetails for {status} {method} {path}"
                );
            }
        }
    }
    let handshake = &paths["/v1/bridge/connect"]["get"];
    assert!(handshake["security"][0]["node_bearer"].is_array());
    let stream = &paths["/v1/events/stream"]["get"];
    assert!(stream["security"][0]["api_bearer"].is_array());
    assert_eq!(
        stream["responses"]["200"]["content"]["application/x-ndjson"]["schema"]["$ref"],
        "#/components/schemas/EventStreamFrame"
    );
    assert!(stream["responses"]["200"]["headers"]["X-Accel-Buffering"].is_object());
    for path in ["/v1/events", "/v1/events/stream"] {
        let description = paths[path]["get"]["responses"]["410"]["description"]
            .as_str()
            .ok_or("missing resynchronization description")?;
        for part in [
            "resync_required",
            "extensions.oldest_available_seq",
            "extensions.latest_seq",
        ] {
            assert!(description.contains(part), "{path}: missing {part}");
        }
        let parameters = paths[path]["get"]["parameters"]
            .as_array()
            .ok_or("missing parameters")?;
        let kinds = parameters
            .iter()
            .find(|param| param["name"] == "kinds")
            .ok_or("missing kinds")?;
        assert_eq!(kinds["style"], "form");
        assert_eq!(kinds["explode"], false);
        assert_eq!(
            kinds["schema"]["items"]["$ref"],
            "#/components/schemas/EventKind"
        );
    }
    for path in ["/v1/profiles/{slug}/invoke", "/v1/tools/{slug}/test"] {
        let description = paths[path]["post"]["responses"]["400"]["description"]
            .as_str()
            .ok_or("missing target selection description")?;
        assert!(description.contains("ambiguous_target"));
        assert!(description.contains("extensions.available_targets"));
    }
    Ok(())
}

#[test]
fn openapi_preserves_page_items_and_execution_response_types() -> TestResult {
    let doc: Value = serde_json::from_slice(&efferian_hub::openapi_bytes()?)?;
    let paths = &doc["paths"];
    let schemas = &doc["components"]["schemas"];
    for (resource, item) in [
        ("accounts", "AccountMetadata"),
        ("account-bindings", "AccountBindingMetadata"),
        ("executions", "ExecutionMetadata"),
        ("profiles", "ProfileSummary"),
        ("profiles/{slug}/tools", "DiscoveredProfileTool"),
        ("tools", "ToolSummary"),
        ("upstreams", "UpstreamSummary"),
    ] {
        let path = format!("/v1/{resource}");
        let page = format!("Page_{item}");
        let op = &paths[path.as_str()]["get"];
        assert_eq!(
            op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            format!("#/components/schemas/{page}")
        );
        let properties = &schemas[page.as_str()]["properties"];
        assert_eq!(properties["items"]["type"], "array");
        assert!(schemas[item].is_object());
        assert_eq!(
            properties["items"]["items"]["$ref"],
            format!("#/components/schemas/{item}")
        );
        assert_eq!(
            properties["next_cursor"]["type"],
            serde_json::json!(["string", "null"])
        );
        let params = op["parameters"].as_array().ok_or("parameters missing")?;
        let limit = params
            .iter()
            .find(|param| param["name"] == "limit")
            .ok_or("page limit is missing")?;
        assert_eq!(limit["schema"]["minimum"], 1);
        assert_eq!(limit["schema"]["maximum"], 200);
        assert!(
            params.iter().any(|param| param["name"] == "cursor"),
            "page cursor is missing for {path}"
        );
    }

    assert!(schemas["ExecutionEventPayload"].is_object());
    let envelope_variants = schemas["EventEnvelope"]["oneOf"]
        .as_array()
        .ok_or("EventEnvelope.oneOf missing")?;
    for variant in &envelope_variants[..4] {
        assert_eq!(
            variant["properties"]["payload"]["$ref"],
            "#/components/schemas/ExecutionEventPayload"
        );
    }
    for (name, schema) in schemas.as_object().ok_or("components.schemas missing")? {
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (field, field_schema) in properties {
                if field == "version" || field.ends_with("_version") {
                    let is_integer = field_schema["type"] == "integer"
                        || field_schema["type"]
                            .as_array()
                            .is_some_and(|types| types.iter().any(|t| t == "integer"));
                    if is_integer {
                        let expected_min =
                            if name == "ProfileSummary" && field == "published_version" {
                                0
                            } else {
                                1
                            };
                        assert_eq!(
                            field_schema["minimum"], expected_min,
                            "unexpected minimum on {name}.{field}: {field_schema}"
                        );
                    }
                }
            }
        }
    }

    for (path, method, status, schema) in [
        ("/v1/tools/{slug}/test", "post", "200", "ExecutionDetail"),
        ("/v1/tools/{slug}/test", "post", "202", "ExecutionMetadata"),
        (
            "/v1/profiles/{slug}/invoke",
            "post",
            "200",
            "ExecutionDetail",
        ),
        (
            "/v1/profiles/{slug}/invoke",
            "post",
            "202",
            "ExecutionMetadata",
        ),
        ("/v1/executions/{id}", "get", "200", "ExecutionDetail"),
        (
            "/v1/executions/{id}/cancel",
            "post",
            "200",
            "ExecutionMetadata",
        ),
        (
            "/v1/executions/{id}/cancel",
            "post",
            "202",
            "ExecutionMetadata",
        ),
    ] {
        assert_eq!(
            paths[path][method]["responses"][status]["content"]["application/json"]["schema"]["$ref"],
            format!("#/components/schemas/{schema}")
        );
    }
    Ok(())
}

fn is_object_schema(schema: &Value) -> bool {
    schema["type"] == "object"
        || schema["type"]
            .as_array()
            .is_some_and(|types| types.iter().any(|t| t == "object"))
}

fn closed_input(schema: &Value, doc: &Value, visited: &mut BTreeSet<String>) -> bool {
    if let Some(reference) = schema["$ref"].as_str() {
        if !visited.insert(reference.to_owned()) {
            return true;
        }
        let ok = reference
            .strip_prefix('#')
            .and_then(|path| doc.pointer(path))
            .is_some_and(|resolved| closed_input(resolved, doc, visited));
        visited.remove(reference);
        return ok;
    }
    for combinator in ["oneOf", "anyOf", "allOf"] {
        if let Some(variants) = schema[combinator].as_array()
            && (variants.is_empty()
                || !variants
                    .iter()
                    .all(|variant| closed_input(variant, doc, visited)))
        {
            return false;
        }
    }
    if let Some(items) = schema.get("items")
        && !closed_input(items, doc, visited)
    {
        return false;
    }
    if is_object_schema(schema) {
        let is_closed = schema["additionalProperties"] == false;
        let is_typed_map = schema["additionalProperties"].is_object();
        if !is_closed && !is_typed_map {
            return false;
        }
        if is_typed_map && !closed_input(&schema["additionalProperties"], doc, visited) {
            return false;
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (name, prop) in properties {
                if matches!(name.as_str(), "arguments" | "input_schema") {
                    continue;
                }
                if !closed_input(prop, doc, visited) {
                    return false;
                }
            }
        }
    }
    true
}

fn assert_schema_references(value: &Value, doc: &Value) {
    match value {
        Value::Object(map) => {
            if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                assert!(
                    reference
                        .strip_prefix('#')
                        .and_then(|path| doc.pointer(path))
                        .is_some(),
                    "unresolved OpenAPI reference {reference}"
                );
            }
            for child in map.values() {
                assert_schema_references(child, doc);
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_schema_references(item, doc);
            }
        }
        _ => {}
    }
}

const METHODS: &[&str] = &[
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
];

const OPERATIONS: &str = "get /v1/health
get /v1/info
get /v1/openapi.json
get /v1/me
get /v1/admin/status
get /v1/principals
get /v1/principals/{principal_ref}
put /v1/principals/{principal_ref}
delete /v1/principals/{principal_ref}
post /v1/principals/{id}/disable
post /v1/principals/{id}/enable
get /v1/tokens
post /v1/tokens
post /v1/tokens/{id}/revoke
get /v1/grants
put /v1/grants
delete /v1/grants/{id}
post /v1/enrollment/tokens
post /v1/nodes/{id}/reenroll-tokens
post /v1/enrollment/exchange
get /v1/nodes
get /v1/nodes/{id}
post /v1/nodes/{id}/revoke
delete /v1/nodes/{id}
get /v1/bridge/connect
get /v1/upstreams
get /v1/upstreams/{slug}
put /v1/upstreams/{slug}
delete /v1/upstreams/{slug}
post /v1/upstreams/{slug}/disable
post /v1/upstreams/{slug}/enable
post /v1/upstreams/{slug}/discover
get /v1/accounts
get /v1/accounts/{slug}
put /v1/accounts/{slug}
delete /v1/accounts/{slug}
get /v1/account-bindings
put /v1/account-bindings/{principal_id_or_me}/{upstream_slug}
delete /v1/account-bindings/{principal_id_or_me}/{upstream_slug}
get /v1/tools
get /v1/tools/{slug}
put /v1/tools/{slug}
delete /v1/tools/{slug}
post /v1/tools/{slug}/test
post /v1/tools/{slug}/disable
post /v1/tools/{slug}/enable
get /v1/profiles
get /v1/profiles/{slug}
put /v1/profiles/{slug}
delete /v1/profiles/{slug}
post /v1/profiles/{slug}/publish
post /v1/profiles/{slug}/disable
post /v1/profiles/{slug}/enable
post /v1/profiles/{slug}/versions/{version}/disable
get /v1/profiles/{slug}/tools
get /v1/profiles/{slug}/tools/{public_name}
post /v1/profiles/{slug}/invoke
get /v1/executions
get /v1/executions/{id}
post /v1/executions/{id}/cancel
get /v1/events
get /v1/events/stream";
