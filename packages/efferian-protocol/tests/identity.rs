#![allow(clippy::expect_used)]

use std::{fmt::Debug, num::NonZeroU64, str::FromStr};

use efferian_protocol::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const V7: &str = "01936a00000070008000000000000001";
const V4: &str = "01936a00000040008000000000000001";

fn id_case<T>(value: T, prefix: &str)
where
    T: Debug + PartialEq + ToString + FromStr<Err = IdError> + Serialize + DeserializeOwned,
{
    let generated = value.to_string();
    assert!(generated.starts_with(prefix));
    assert_eq!(generated.len(), prefix.len() + V7.len());
    assert_eq!(generated.parse::<T>(), Ok(value));
    let wire = json!(generated);
    let decoded: T =
        serde_json::from_value(wire.clone()).expect("generated identifier round-trips");
    assert_eq!(json!(decoded), wire);

    let parse = |uuid| format!("{prefix}{uuid}").parse::<T>();
    assert!(parse(V7).is_ok());
    assert_eq!(parse(V4), Err(IdError::NotUuidV7));
    assert_eq!(
        parse("01936a0000007000c000000000000001"),
        Err(IdError::NotUuidV7)
    );
    assert_eq!(
        parse("01936A00000070008000000000000001"),
        Err(IdError::InvalidHex)
    );
    assert_eq!(
        parse("01936a00-0000-7000-8000-000000000001"),
        Err(IdError::InvalidLength)
    );
    assert_eq!(
        format!("unknown_{V7}").parse::<T>(),
        Err(IdError::InvalidPrefix)
    );
}

#[test]
fn branded_ids_validate_all_prefixes_and_uuid_bits() {
    id_case(HubId::new(), "hub_");
    id_case(PrincipalId::new_user(), "usr_");
    id_case(PrincipalId::new_agent(), "agt_");
    id_case(PrincipalId::new_service(), "sp_");
    id_case(TokenId::new_user_or_agent(), "tok_");
    id_case(TokenId::new_service(), "spk_");
    id_case(EnrollmentId::new(), "enr_");
    id_case(NodeId::new(), "node_");
    id_case(UpstreamId::new(), "up_");
    id_case(AccountId::new(), "acc_");
    id_case(ToolId::new(), "tool_");
    id_case(ProfileId::new(), "prof_");
    id_case(GrantId::new(), "grnt_");
    id_case(ExecutionId::new(), "exec_");
    id_case(EventId::new(), "evt_");
    id_case(TraceId::new(), "req_");

    for kind in [
        PrincipalKind::Admin,
        PrincipalKind::Member,
        PrincipalKind::Agent,
        PrincipalKind::Service,
    ] {
        let principal = PrincipalId::new_for_kind(kind);
        let token = TokenId::new_for_kind(kind);
        assert!(principal.matches_kind(kind));
        assert!(token.matches_kind(kind));
        assert_eq!(
            PrincipalId::new_user().matches_kind(kind),
            matches!(kind, PrincipalKind::Admin | PrincipalKind::Member)
        );
        assert_eq!(
            TokenId::new_service().matches_kind(kind),
            kind == PrincipalKind::Service
        );
    }

    let node = NodeId::new();
    assert_eq!(ActorId::parse(&node.to_string()), Ok(ActorId::Node(node)));
    assert_eq!(
        ActorId::parse(&format!("tool_{V7}")),
        Err(IdError::InvalidPrefix)
    );
    let execution = AggregateId::parse(&format!("exec_{V7}")).expect("execution aggregate");
    assert_eq!(execution.aggregate_type(), AggregateType::Execution);
    assert!(NodeId::parse(&format!("tool_{V7}")).is_err());
}

#[test]
fn request_id_normalizes_and_uses_inclusive_freshness_window() {
    let canonical = "01936a00-0000-7000-8000-000000000001";
    let id = RequestId::parse(canonical).expect("valid UUIDv7");
    for form in [
        V7.to_owned(),
        V7.to_uppercase(),
        canonical.to_owned(),
        canonical.to_uppercase(),
    ] {
        assert_eq!(RequestId::parse(&form), Ok(id));
        assert_eq!(
            serde_json::from_value::<RequestId>(json!(form)).expect("valid wire ID"),
            id
        );
    }
    assert_eq!(id.canonical_str(), canonical);
    assert_eq!(json!(id), json!(canonical));
    for bad in [
        format!("{{{canonical}}}"),
        format!("urn:uuid:{canonical}"),
        format!("req_{V7}"),
        format!(" {V7}"),
        V4.to_owned(),
    ] {
        assert!(RequestId::parse(&bad).is_err(), "accepted {bad}");
    }

    let ts = id.timestamp_ms();
    assert_eq!(ts, 0x0193_6a00_0000);
    let age = DEFAULT_REQUEST_ID_MAX_AGE_MS;
    let skew = DEFAULT_REQUEST_ID_MAX_FUTURE_SKEW_MS;
    assert_eq!(id.validate_freshness(ts + age, age, skew), Ok(()));
    assert_eq!(id.validate_freshness(ts - skew, age, skew), Ok(()));
    assert!(matches!(
        id.validate_freshness(ts + age + 1, age, skew),
        Err(RequestIdFreshnessError::Expired { .. })
    ));
    assert!(matches!(
        id.validate_freshness(ts - skew - 1, age, skew),
        Err(RequestIdFreshnessError::TooFarInFuture { .. })
    ));
}

#[test]
fn problem_has_known_emission_fields_and_accepts_future_extensions() -> serde_json::Result<()> {
    let trace_id = TraceId::parse(&format!("req_{V7}")).expect("valid trace ID");
    let problem = ProblemDetails::new(409, error_codes::RESYNC_REQUIRED, "Resync", true, trace_id)
        .with_extension("oldest_available_seq", 3)
        .with_extension("latest_seq", 8);
    let expected = json!({
        "type": "urn:efferian:problem:resync_required",
        "title": "Resync",
        "status": 409,
        "code": "resync_required",
        "retryable": true,
        "trace_id": format!("req_{V7}"),
        "extensions": {"oldest_available_seq": 3, "latest_seq": 8}
    });
    let positional = json!([
        problem.problem_type,
        problem.title,
        problem.status,
        problem.code,
        null,
        null,
        problem.retryable,
        trace_id,
        problem.extensions,
    ]);
    assert!(serde_json::from_value::<ProblemDetails>(positional).is_err());
    assert_eq!(serde_json::to_value(&problem)?, expected);
    let mut newer = expected.clone();
    newer["extra"] = json!(1);
    let decoded: ProblemDetails = serde_json::from_value(newer.clone())?;
    assert_eq!(decoded, problem);
    assert_eq!(serde_json::to_value(decoded)?, expected);

    newer["status"] = json!("409");
    assert!(serde_json::from_value::<ProblemDetails>(newer.clone()).is_err());
    newer["status"] = json!(409);
    newer.as_object_mut().expect("object").remove("trace_id");
    assert!(serde_json::from_value::<ProblemDetails>(newer).is_err());
    let duplicate =
        expected
            .to_string()
            .replacen("\"status\":409", "\"status\":409,\"status\":409", 1);
    assert!(serde_json::from_str::<ProblemDetails>(&duplicate).is_err());
    Ok(())
}

#[test]
fn canonical_digests_retain_client_intent() -> Result<(), Box<dyn std::error::Error>> {
    let schema = json!({
        "type": "object",
        "properties": {"z": {"type": "integer"}, "a": {"type": "string"}}
    });
    let properties = schema["properties"].as_object().expect("properties");
    assert_eq!(
        properties.keys().map(String::as_str).collect::<Vec<_>>(),
        ["z", "a"]
    );
    assert_eq!(
        canonical_json_bytes(&schema)?,
        br#"{"properties":{"a":{"type":"string"},"z":{"type":"integer"}},"type":"object"}"#
    );
    assert_eq!(
        compute_input_schema_sha256(&schema)?,
        "8ddb924cb6a3a84b7ec4ae24e099c457d0431637580a4055c6afdb165ff0a477"
    );
    let array = json!([{"z": 1, "a": 2}, "next"]);
    assert_eq!(canonical_json_bytes(&array)?, br#"[{"a":2,"z":1},"next"]"#);
    assert_ne!(
        canonical_json_sha256(&array)?,
        canonical_json_sha256(&json!(["next", {"a":2,"z":1}]))?
    );

    let arguments = json!({"z": 2, "a": 1});
    let tool_id = ToolId::parse(&format!("tool_{V7}"))?;
    let mut request = RequestDigestInput {
        invoke_kind: InvokeKind::ToolTest,
        profile_id: None,
        tool_id,
        public_name: "run",
        requested_target: None,
        fixed_node_id: None,
        arguments: arguments.as_object().expect("arguments"),
        requested_tool_version: None,
    };
    assert_eq!(
        canonical_json_bytes(&serde_json::to_value(&request)?)?,
        br#"{"arguments":{"a":1,"z":2},"fixed_node_id":null,"invoke_kind":"tool_test","profile_id":null,"public_name":"run","requested_target":null,"tool_id":"tool_01936a00000070008000000000000001"}"#
    );
    assert_eq!(
        compute_request_digest(&request)?,
        "164acf4548d01f8a1b55ee67bc71fea0302fea851d04833e57330d14b19390ce"
    );
    request.requested_tool_version = NonZeroU64::new(1);
    assert_eq!(
        canonical_json_bytes(&serde_json::to_value(&request)?)?,
        br#"{"arguments":{"a":1,"z":2},"fixed_node_id":null,"invoke_kind":"tool_test","profile_id":null,"public_name":"run","requested_target":null,"requested_tool_version":1,"tool_id":"tool_01936a00000070008000000000000001"}"#
    );
    let pinned = compute_request_digest(&request)?;
    assert_eq!(
        pinned,
        "84e12bb4d62f8201e04a7de7646d92d3fcd543b5a6a80ec57c5e16b50269318b"
    );
    request.requested_tool_version = NonZeroU64::new(2);
    assert_ne!(compute_request_digest(&request)?, pinned);

    request.invoke_kind = InvokeKind::Profile;
    request.profile_id = Some(ProfileId::parse(&format!("prof_{V7}"))?);
    assert!(matches!(
        compute_request_digest(&request),
        Err(DigestError::InvalidInvocation)
    ));
    request.requested_tool_version = None;
    let empty = json!({});
    request.arguments = empty.as_object().expect("empty arguments object");
    assert_eq!(
        compute_request_digest(&request)?,
        "9d26c4de2196821eb0adc54e5dba470bd3f2a4ea98e2b0ff8dd22c7a1462102c"
    );

    // A later publication changes both the tool and fixed node behind the alias.
    // A retry combines the client's selector with its recorded binding.
    let recorded = (tool_id, Some(NodeId::new()));
    let published = (ToolId::new(), Some(NodeId::new()));
    let with_binding = |(tool_id, fixed_node_id)| RequestDigestInput {
        tool_id,
        fixed_node_id,
        requested_target: Some("build-node"),
        ..request.clone()
    };
    let baseline = compute_request_digest(&with_binding(recorded))?;
    assert_ne!(compute_request_digest(&with_binding(published))?, baseline);
    assert_ne!(
        compute_request_digest(&with_binding((published.0, recorded.1)))?,
        baseline
    );
    assert_ne!(
        compute_request_digest(&with_binding((recorded.0, published.1)))?,
        baseline
    );
    let request = with_binding(recorded);
    for changed in [
        RequestDigestInput {
            public_name: "another-alias",
            ..request.clone()
        },
        RequestDigestInput {
            requested_target: Some("node-name"),
            ..request.clone()
        },
        RequestDigestInput {
            profile_id: Some(ProfileId::new()),
            ..request.clone()
        },
        RequestDigestInput {
            arguments: arguments.as_object().expect("arguments"),
            ..request
        },
    ] {
        assert_ne!(compute_request_digest(&changed)?, baseline);
    }
    assert!(serde_json::from_value::<NonZeroU64>(json!(0)).is_err());
    assert!(serde_json::from_value::<serde_json::Map<String, Value>>(Value::Null).is_err());

    // PreparedArgumentsDigest must produce the exact same digest as
    // compute_request_digest without rebuilding or re-serializing arguments.
    let nested = json!({
        "z": [{"b": 2, "a": 1}, true, null, "text"],
        "a": {"y": "hello", "x": 42}
    });
    let nested_map = nested.as_object().expect("nested object");
    let prepared = PreparedArgumentsDigest::new(nested_map)?;
    assert_eq!(
        prepared.canonical_bytes(),
        canonical_json_bytes(&nested)?.len()
    );
    let cases = [
        (InvokeKind::ToolTest, None, tool_id, "run", None, None, None),
        (
            InvokeKind::ToolTest,
            None,
            tool_id,
            "run",
            Some("build-node"),
            None,
            NonZeroU64::new(3),
        ),
        (
            InvokeKind::Profile,
            Some(ProfileId::parse(&format!("prof_{V7}"))?),
            tool_id,
            "alias",
            Some("node-a"),
            Some(NodeId::new()),
            None,
        ),
    ];
    for (
        invoke_kind,
        profile_id,
        tool_id,
        public_name,
        requested_target,
        fixed_node_id,
        requested_tool_version,
    ) in cases
    {
        let expected = compute_request_digest(&RequestDigestInput {
            invoke_kind,
            profile_id,
            tool_id,
            public_name,
            requested_target,
            fixed_node_id,
            arguments: nested_map,
            requested_tool_version,
        })?;
        let actual = prepared.finish(&RequestDigestMetadata {
            invoke_kind,
            profile_id,
            tool_id,
            public_name,
            requested_target,
            fixed_node_id,
            requested_tool_version,
        })?;
        assert_eq!(actual, expected);
    }
    assert!(matches!(
        prepared.finish(&RequestDigestMetadata {
            invoke_kind: InvokeKind::Profile,
            profile_id: Some(ProfileId::new()),
            tool_id,
            public_name: "alias",
            requested_target: None,
            fixed_node_id: None,
            requested_tool_version: NonZeroU64::new(1),
        }),
        Err(DigestError::InvalidInvocation)
    ));
    Ok(())
}

#[cfg(feature = "openapi")]
#[test]
fn openapi_identifier_schemas_agree_with_parsers() -> Result<(), Box<dyn std::error::Error>> {
    fn check<T: utoipa::PartialSchema + FromStr>(
        prefixes: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let validator = jsonschema::validator_for(&serde_json::to_value(T::schema())?)?;
        for prefix in prefixes {
            for suffix in [
                V7,
                V4,
                "00000000000000000000000000000000",
                "01936a00000070000000000000000001",
                "01936A00000070008000000000000001",
                "01936a00-0000-7000-8000-000000000001",
            ] {
                let input = format!("{prefix}_{suffix}");
                assert_eq!(
                    validator.is_valid(&json!(input)),
                    input.parse::<T>().is_ok(),
                    "{input}"
                );
            }
        }
        for input in [format!("bad_{V7}"), format!("{}_{V7}\n", prefixes[0])] {
            assert!(!validator.is_valid(&json!(input)));
        }
        Ok(())
    }

    check::<HubId>(&["hub"])?;
    check::<PrincipalId>(&["usr", "agt", "sp"])?;
    check::<TokenId>(&["tok", "spk"])?;
    check::<EnrollmentId>(&["enr"])?;
    check::<NodeId>(&["node"])?;
    check::<UpstreamId>(&["up"])?;
    check::<AccountId>(&["acc"])?;
    check::<ToolId>(&["tool"])?;
    check::<ProfileId>(&["prof"])?;
    check::<GrantId>(&["grnt"])?;
    check::<ExecutionId>(&["exec"])?;
    check::<EventId>(&["evt"])?;
    check::<TraceId>(&["req"])?;
    check::<ActorId>(&["usr", "agt", "sp", "node", "hub"])?;
    check::<AggregateId>(&["exec", "node", "prof", "usr", "agt", "sp", "tok", "spk"])?;

    use utoipa::PartialSchema as _;
    let input = jsonschema::validator_for(&serde_json::to_value(RequestId::schema())?)?;
    let output = jsonschema::validator_for(&serde_json::to_value(RequestId::canonical_schema())?)?;
    let canonical = "01936a00-0000-7000-8000-000000000001";
    for value in [
        V7.to_owned(),
        V7.to_uppercase(),
        canonical.to_owned(),
        canonical.to_uppercase(),
        V4.to_owned(),
        format!(" {V7}"),
        format!("{{{canonical}}}"),
    ] {
        let parsed = RequestId::parse(&value);
        assert_eq!(input.is_valid(&json!(value)), parsed.is_ok(), "{value}");
        assert_eq!(
            output.is_valid(&json!(value)),
            value == canonical,
            "{value}"
        );
        if let Ok(id) = parsed {
            assert!(output.is_valid(&json!(id)));
        }
    }

    let problem = serde_json::to_value(ProblemDetails::schema())?;
    let mut required = problem["required"]
        .as_array()
        .expect("required fields")
        .clone();
    required.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    assert_eq!(
        required,
        ["code", "retryable", "status", "title", "trace_id", "type"].map(Value::from)
    );
    Ok(())
}
