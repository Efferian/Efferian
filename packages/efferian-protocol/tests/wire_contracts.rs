#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use efferian_protocol::*;
use serde_json::{Value, json};

#[cfg(feature = "openapi")]
mod support;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn request() -> ExecuteReqPayload {
    ExecuteReqPayload {
        execution_id: ExecutionId::new(),
        action: ResolvedAction::Http {
            method: HttpMethod::Post,
            url: "https://example.org/api".into(),
            headers: BTreeMap::from([("content-type".into(), "text/plain".into())]),
            body: Some("body-marker".into()),
        },
        env_secrets: BTreeMap::new(),
        http_auth_headers: vec![("X-Key".into(), SecretString::new("secret-marker"))],
        ssh_key_pem: None,
        runtime_ms: 1000,
        max_output_bytes: 12,
    }
}

fn roster() -> RosterSyncPayload {
    RosterSyncPayload {
        platform_os: PlatformOs::Linux,
        platform_arch: "x86_64".into(),
        allowed_cwd_roots: vec!["/tmp/workspace".into()],
        max_concurrent_executions: 2,
        active_execution_ids: vec![ExecutionId::new()],
        pending_receipt_count: 1,
    }
}

fn receipt() -> ExecuteResPayload {
    ExecuteResPayload {
        execution_id: ExecutionId::new(),
        state: TerminalExecutionState::Succeeded,
        effect_may_have_occurred: true,
        exit_code: Some(0),
        http_status: None,
        error_code: None,
        error_message: None,
        stdout_b64: Some(STANDARD.encode("output-marker")),
        stderr_b64: None,
        truncated: false,
        output_discarded_reason: None,
        finished_at_ms: 100,
    }
}

#[test]
fn bridge_round_trips_all_frames_through_the_typed_codec() -> Result {
    let fixtures = [
        (
            "hello_ack",
            BridgeReceiver::Node,
            BridgeMessage::HelloAck(HelloAckPayload {
                hub_id: HubId::new(),
                node_id: NodeId::new(),
                session_epoch: 7,
            }),
        ),
        (
            "execute_req",
            BridgeReceiver::Node,
            BridgeMessage::ExecuteReq(request()),
        ),
        (
            "cancel_req",
            BridgeReceiver::Node,
            BridgeMessage::CancelReq(CancelReqPayload {
                execution_id: ExecutionId::new(),
            }),
        ),
        (
            "receipt_ack",
            BridgeReceiver::Node,
            BridgeMessage::ReceiptAck(ReceiptAckPayload {
                execution_ids: vec![ExecutionId::new()],
            }),
        ),
        (
            "roster_sync",
            BridgeReceiver::Hub,
            BridgeMessage::RosterSync(roster()),
        ),
        (
            "execute_ack",
            BridgeReceiver::Hub,
            BridgeMessage::ExecuteAck(ExecuteAckPayload {
                execution_id: ExecutionId::new(),
                started_at_ms: 6,
            }),
        ),
        (
            "execute_res",
            BridgeReceiver::Hub,
            BridgeMessage::ExecuteRes(receipt()),
        ),
        (
            "sync_complete",
            BridgeReceiver::Hub,
            BridgeMessage::SyncComplete(SyncCompletePayload {}),
        ),
    ];

    for (kind, receiver, message) in fixtures {
        let envelope = BridgeEnvelope { epoch: 7, message };
        let encoded = encode_bridge_frame(&envelope)?;
        let json: Value = serde_json::from_slice(&encoded)?;
        assert_eq!(
            json,
            json!({
                "v":1, "epoch":7, "kind":kind, "payload":match &envelope.message {
                    BridgeMessage::HelloAck(payload) => json!(payload),
                    BridgeMessage::ExecuteReq(payload) => json!(payload),
                    BridgeMessage::CancelReq(payload) => json!(payload),
                    BridgeMessage::ReceiptAck(payload) => json!(payload),
                    BridgeMessage::RosterSync(payload) => json!(payload),
                    BridgeMessage::ExecuteAck(payload) => json!(payload),
                    BridgeMessage::ExecuteRes(payload) => json!(payload),
                    BridgeMessage::SyncComplete(_) => json!({}),
                }
            })
        );
        assert_eq!(decode_bridge_frame(&encoded, receiver)?, envelope);
        let opposite = match receiver {
            BridgeReceiver::Hub => BridgeReceiver::Node,
            BridgeReceiver::Node => BridgeReceiver::Hub,
        };
        assert_eq!(
            decode_bridge_frame(&encoded, opposite),
            Err(BridgeCodecError::WrongDirection(envelope.kind(), opposite))
        );
    }
    Ok(())
}

#[test]
fn bridge_rejects_wrong_direction_before_decoding_payload_and_hides_input() -> Result {
    let malformed =
        br#"{"payload":{"token":"secret-marker"},"kind":"execute_req","epoch":7,"v":1}"#;
    assert_eq!(
        decode_bridge_frame(malformed, BridgeReceiver::Hub),
        Err(BridgeCodecError::WrongDirection(
            BridgeKind::ExecuteReq,
            BridgeReceiver::Hub
        ))
    );
    let err = decode_bridge_frame(malformed, BridgeReceiver::Node).expect_err("invalid payload");
    assert_eq!(err, BridgeCodecError::InvalidFrame);
    assert!(!format!("{err:?} {err}").contains("secret-marker"));

    let req = request();
    for debug in [
        format!("{req:?}"),
        format!("{:?}", req.action),
        format!(
            "{:?}",
            BridgeEnvelope {
                epoch: 7,
                message: BridgeMessage::ExecuteReq(req)
            }
        ),
    ] {
        assert!(!debug.contains("secret-marker") && !debug.contains("body-marker"));
    }
    let res = receipt();
    assert!(
        !format!("{res:?}").contains(res.stdout_b64.as_deref().ok_or("missing fixture output")?)
    );
    Ok(())
}

#[test]
fn bridge_enforces_frame_shape_version_epoch_and_bounds() -> Result {
    let mut good = br#"{"payload":{},"kind":"sync_complete","epoch":7,"v":1}"#.to_vec();
    assert_eq!(
        decode_bridge_frame(&good, BridgeReceiver::Hub)?.kind(),
        BridgeKind::SyncComplete
    );
    for bytes in [
        br#"{"v":1,"epoch":7,"kind":"sync_complete","payload":{"extra":false}}"#.as_slice(),
        br#"{"v":1,"epoch":7,"kind":"sync_complete","payload":[]}"#,
        br#"{"v":1,"epoch":7,"kind":"sync_complete","payload":null}"#,
        br#"{"v":1,"epoch":7,"kind":"sync_complete","payload":{},"extra":0}"#,
        br#"{"v":1,"epoch":7,"kind":"sync_complete","payload":{},"v":1}"#,
        br#"{"v":1,"epoch":7,"kind":"sync_complete","payload":{},"payload":{}}"#,
        br#"{"v":1,"epoch":7,"kind":"future_kind","payload":{}}"#,
        br#"[1,7,"sync_complete",{}]"#,
    ] {
        assert_eq!(
            decode_bridge_frame(bytes, BridgeReceiver::Hub),
            Err(BridgeCodecError::InvalidFrame)
        );
    }
    assert_eq!(
        decode_bridge_frame(
            br#"{"v":2,"epoch":7,"kind":"sync_complete","payload":{}}"#,
            BridgeReceiver::Hub
        ),
        Err(BridgeCodecError::UnsupportedVersion(2))
    );
    let no_match = json!({"v":1,"epoch":7,"kind":"hello_ack","payload":{
        "hub_id":HubId::new(), "node_id":NodeId::new(), "session_epoch":8
    }});
    assert_eq!(
        decode_bridge_frame(no_match.to_string().as_bytes(), BridgeReceiver::Node),
        Err(BridgeCodecError::EpochMismatch)
    );

    good.resize(MAX_BRIDGE_FRAME_BYTES, b' ');
    assert!(decode_bridge_frame(&good, BridgeReceiver::Hub).is_ok());
    good.push(b' ');
    assert_eq!(
        decode_bridge_frame(&good, BridgeReceiver::Hub),
        Err(BridgeCodecError::FrameTooLarge)
    );

    let mut req = request();
    let ResolvedAction::Http { body, .. } = &mut req.action else {
        return Err("wrong request fixture".into());
    };
    *body = Some(String::new());
    let mut frame = BridgeEnvelope {
        epoch: 7,
        message: BridgeMessage::ExecuteReq(req),
    };
    let overhead = encode_bridge_frame(&frame)?.len();
    for size in [MAX_BRIDGE_FRAME_BYTES, MAX_BRIDGE_FRAME_BYTES + 1] {
        let BridgeMessage::ExecuteReq(req) = &mut frame.message else {
            return Err("wrong frame fixture".into());
        };
        let ResolvedAction::Http { body, .. } = &mut req.action else {
            return Err("wrong action fixture".into());
        };
        *body = Some("x".repeat(size - overhead));
        let encoded = encode_bridge_frame(&frame);
        if size == MAX_BRIDGE_FRAME_BYTES {
            assert_eq!(encoded?.len(), size);
        } else {
            assert_eq!(encoded, Err(BridgeCodecError::FrameTooLarge));
        }
    }
    Ok(())
}

#[test]
fn bridge_checks_roster_limits_on_encode_and_decode() -> Result {
    fn check(roster: RosterSyncPayload, allowed: bool) -> Result {
        let fixture = json!({ "v":1, "epoch":7, "kind":"roster_sync", "payload":roster });
        let frame = BridgeEnvelope {
            epoch: 7,
            message: BridgeMessage::RosterSync(roster),
        };
        assert_eq!(encode_bridge_frame(&frame).is_ok(), allowed);
        assert_eq!(
            decode_bridge_frame(&serde_json::to_vec(&fixture)?, BridgeReceiver::Hub).is_ok(),
            allowed
        );
        Ok(())
    }

    let mut roster = roster();
    roster.allowed_cwd_roots = vec!["x".repeat(128); MAX_ROSTER_CWD_ROOTS];
    check(roster.clone(), true)?;
    roster.allowed_cwd_roots[0].push('x');
    check(roster.clone(), false)?;
    roster.allowed_cwd_roots[0].pop();
    roster.allowed_cwd_roots.push(String::new());
    check(roster.clone(), false)?;
    roster.allowed_cwd_roots.pop();
    roster.max_concurrent_executions = 0;
    check(roster.clone(), false)?;
    roster.max_concurrent_executions = 1;
    roster.active_execution_ids.push(ExecutionId::new());
    check(roster.clone(), true)?;
    roster.active_execution_ids.push(ExecutionId::new());
    check(roster, false)
}

#[test]
fn receipts_keep_unknown_pre_start_empty_and_discarded_distinct() -> Result {
    let active: ExecutionSummary = serde_json::from_str("{}")?;
    assert_eq!(active.effect_may_have_occurred, None);
    assert_eq!(json!(active), json!({}));

    let mut receipt = receipt();
    receipt.stdout_b64 = None;
    assert!(receipt.decode_and_validate_output(0)?.stdout.is_empty());
    assert_eq!(receipt.summary(None)?.output_discarded_reason, None);
    receipt.state = TerminalExecutionState::Unknown;
    receipt.effect_may_have_occurred = false;
    assert_eq!(
        receipt.decode_and_validate_output(0).unwrap_err(),
        ValidationError::InvalidReceipt
    );
    receipt.effect_may_have_occurred = true;
    assert_eq!(receipt.summary(None)?.effect_may_have_occurred, Some(true));
    receipt.state = TerminalExecutionState::Failed;
    receipt.effect_may_have_occurred = false;
    receipt.error_code = Some(error_codes::NODE_BUSY.into());
    assert_eq!(receipt.summary(None)?.effect_may_have_occurred, Some(false));
    receipt.error_code = Some("process_failed".into());
    receipt.exit_code = Some(97);
    receipt.output_discarded_reason = Some(OutputDiscardedReason::RamCap);
    assert_eq!(
        receipt.decode_and_validate_output(0).unwrap_err(),
        ValidationError::InvalidReceipt
    );
    receipt.truncated = true;
    let valid = BridgeEnvelope {
        epoch: 7,
        message: BridgeMessage::ExecuteRes(receipt.clone()),
    };
    assert_eq!(
        decode_bridge_frame(&encode_bridge_frame(&valid)?, BridgeReceiver::Hub)?,
        valid
    );
    let summary = receipt.summary(Some(10))?;
    assert_eq!(
        summary.output_discarded_reason,
        Some(OutputDiscardedReason::RamCap)
    );
    assert_eq!(summary.exit_code, Some(97));
    assert_eq!(summary.error_code.as_deref(), Some("process_failed"));
    let mut malformed = json!({"v":1,"epoch":7,"kind":"execute_res","payload":receipt});
    for (key, value) in [
        ("stdout_b64", json!("")),
        ("truncated", json!(false)),
        ("state", json!("running")),
    ] {
        let mut invalid = malformed.clone();
        invalid["payload"][key] = value;
        assert!(decode_bridge_frame(invalid.to_string().as_bytes(), BridgeReceiver::Hub).is_err());
    }
    malformed["payload"]
        .as_object_mut()
        .ok_or("receipt object")?
        .remove("effect_may_have_occurred");
    assert!(decode_bridge_frame(malformed.to_string().as_bytes(), BridgeReceiver::Hub).is_err());
    Ok(())
}

#[test]
fn receipt_checks_canonical_base64_and_combined_limits_before_lossy_decoding() -> Result {
    let mut receipt = receipt();
    receipt.stdout_b64 = Some("8A==".into());
    receipt.stderr_b64 = Some("n4iA".into());
    let out = receipt.decode_and_validate_output(4)?;
    assert_eq!(&out.stdout[..], &[0xf0]);
    assert_eq!(&out.stderr[..], &[0x9f, 0x88, 0x80]);
    assert_eq!(
        receipt.decode_and_validate_output(3).unwrap_err(),
        ValidationError::OutputLimit
    );
    assert_eq!(
        json!(StoredResult::managed_from_bytes(
            &out.stdout,
            &out.stderr,
            None,
            None,
            4
        )?),
        json!({"kind":"managed","stdout":"�","stderr":"���"})
    );
    for invalid in ["💣", "xxx", "xxx&", "8B==", "====", "____"] {
        let bytes = serde_json::to_vec(&json!({
            "v":1, "epoch":7, "kind":"execute_res", "payload":{
                "execution_id":receipt.execution_id, "state":"succeeded", "finished_at_ms":7,
                "effect_may_have_occurred":true, "truncated":false, "stdout_b64":invalid
            }
        }))?;
        assert_eq!(
            decode_bridge_frame(&bytes, BridgeReceiver::Hub),
            Err(BridgeCodecError::Validation(
                ValidationError::InvalidOutputEncoding
            )),
            "{invalid}"
        );
    }
    receipt.error_message = Some("é".repeat(256));
    assert!(receipt.decode_and_validate_output(4).is_ok());
    receipt
        .error_message
        .as_mut()
        .ok_or("error detail")?
        .push('x');
    assert!(receipt.decode_and_validate_output(4).is_err());

    let mut raw = vec![0; MAX_OUTPUT_BYTES as usize];
    let stored = StoredResult::managed_from_bytes(&raw, &[], None, None, MAX_OUTPUT_BYTES)?;
    let encoded = STANDARD.encode(&raw);
    assert_eq!(encoded.len(), 1_398_104);
    assert_eq!(serde_json::to_vec(&stored)?.len(), 6_291_498);
    receipt.stdout_b64 = Some(encoded);
    receipt.stderr_b64 = None;
    receipt.error_message = None;
    assert_eq!(
        receipt
            .decode_and_validate_output(MAX_OUTPUT_BYTES)?
            .stdout
            .len(),
        raw.len()
    );
    raw.push(0);
    assert_eq!(
        StoredResult::managed_from_bytes(&raw, &[], None, None, MAX_OUTPUT_BYTES),
        Err(ValidationError::OutputLimit)
    );
    assert!(
        serde_json::from_value::<StoredResult>(
            json!({"kind":"managed","stdout":"","stderr":"","foreign":1})
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn upstream_results_round_trip_sdk_wire_values() -> Result {
    let legacy = json!({"content":[{"type":"text","text":"hello"}]});
    let complete = json!({
        "resultType":"complete", "structuredContent":null, "isError":false,
        "_meta":{"progressToken":"p1"},
        "content":[{"type":"image","data":"AA==","mimeType":"image/png",
            "annotations":{"audience":["user"],"priority":0.9}, "_meta":{"image":"a"}}]
    });
    let structured =
        json!({"resultType":"complete","content":[],"structuredContent":{"list":[1,null]}});
    let error_flag = json!({"content":[],"isError":false});
    let empty = json!({"content":[]});
    for sdk in [&legacy, &complete, &structured, &error_flag, &empty] {
        let decoded: UpstreamMcpResult = serde_json::from_value(sdk.clone())?;
        let stored = StoredResult::UpstreamMcp { result: decoded };
        let round_trip: StoredResult = serde_json::from_slice(&serde_json::to_vec(&stored)?)?;
        let back = json!(round_trip);
        assert_eq!(back["result"], *sdk);
        assert_eq!(
            back["result"].get("structuredContent"),
            sdk.get("structuredContent")
        );
    }
    let null_only: UpstreamMcpResult =
        serde_json::from_value(json!({"structuredContent":null,"future":1}))?;
    assert_eq!(
        json!(null_only),
        json!({"content":[],"structuredContent":null})
    );
    let flag_only: UpstreamMcpResult = serde_json::from_value(json!({"isError":false}))?;
    assert_eq!(json!(flag_only), error_flag);
    for bad in [
        "{}",
        r#"{"_meta":{}}"#,
        r#"{"resultType":"complete"}"#,
        r#"{"resultType":"pending","content":[]}"#,
        r#"{"content":{},"structuredContent":null}"#,
        r#"{"content":[],"isError":"false"}"#,
        r#"{"structuredContent":null,"structuredContent":5}"#,
    ] {
        assert!(
            serde_json::from_str::<UpstreamMcpResult>(bad).is_err(),
            "{bad}"
        );
    }
    Ok(())
}

#[test]
fn grant_scope_rejects_extra_members_even_if_null() -> Result {
    let profile_id = ProfileId::new();
    for (scope, expected) in [
        (GrantScope::Global, json!({"scope_kind":"global"})),
        (
            GrantScope::Profile(profile_id),
            json!({"scope_kind":"profile","scope_id":profile_id}),
        ),
    ] {
        assert_eq!(json!(scope), expected);
        assert_eq!(serde_json::from_value::<GrantScope>(expected)?, scope);
    }
    for bad in [
        r#"{"scope_kind":"global","scope_id":null}"#,
        r#"{"scope_kind":"global","scope_kind":"global"}"#,
        r#"{"scope_kind":"global","extra":true}"#,
        r#"{"scope_kind":"profile"}"#,
        r#"{"scope_kind":"profile","scope_id":null}"#,
    ] {
        assert!(serde_json::from_str::<GrantScope>(bad).is_err(), "{bad}");
    }
    Ok(())
}

#[test]
fn event_frames_enforce_per_kind_payloads_and_aggregate_ids() -> Result {
    let payload = ExecutionEventPayload {
        execution_id: ExecutionId::new(),
        state: ExecutionState::Succeeded,
        profile_id: None,
        tool_id: ToolId::new(),
        public_name: "run".into(),
        node_id: Some(NodeId::new()),
        exit_code: Some(0),
        error_code: None,
        duration_ms: Some(11),
    };
    let fixtures = [
        (
            Event::ExecutionStarted(payload.clone()),
            "execution.started",
            "execution",
            "arguments",
        ),
        (
            Event::ExecutionFinished(payload.clone()),
            "execution.finished",
            "execution",
            "error_message",
        ),
        (
            Event::ExecutionCancelled(payload.clone()),
            "execution.cancelled",
            "execution",
            "arguments",
        ),
        (
            Event::ExecutionLateReceipt(payload),
            "execution.late_receipt",
            "execution",
            "error_message",
        ),
        (
            Event::NodeConnected(NodeId::new()),
            "node.connected",
            "node",
            "allowed_cwd_roots",
        ),
        (
            Event::NodeDisconnected(NodeId::new()),
            "node.disconnected",
            "node",
            "allowed_cwd_roots",
        ),
        (
            Event::NodeRevoked(NodeId::new()),
            "node.revoked",
            "node",
            "allowed_cwd_roots",
        ),
        (
            Event::ProfilePublished(ProfileId::new()),
            "profile.published",
            "profile",
            "tools",
        ),
        (
            Event::PrincipalRevoked(PrincipalId::new_user()),
            "auth.revoked",
            "principal",
            "token",
        ),
        (
            Event::TokenRevoked(TokenId::new_user_or_agent()),
            "auth.revoked",
            "token",
            "token",
        ),
    ];
    #[cfg(feature = "openapi")]
    let schema = support::schema_validator::<EventStreamFrame>()?;
    for (event, kind, aggregate_type, forbidden) in fixtures {
        let aggregate_id = event.aggregate_id();
        let frame = EventStreamFrame::Event {
            event: EventEnvelope {
                seq: 5,
                event_id: EventId::new(),
                source_id: HubId::new(),
                actor_id: ActorId::Node(NodeId::new()),
                created_at_ms: 6,
                event,
            },
        };
        let ndjson = format!("{}\n", serde_json::to_string(&frame)?);
        assert_eq!(serde_json::from_str::<EventStreamFrame>(&ndjson)?, frame);
        let valid: Value = serde_json::from_str(&ndjson)?;
        assert_eq!(valid["event"]["kind"], kind);
        assert_eq!(valid["event"]["source_kind"], "hub");
        assert_eq!(valid["event"]["aggregate_type"], aggregate_type);
        assert_eq!(valid["event"]["aggregate_id"], json!(aggregate_id));
        #[cfg(feature = "openapi")]
        assert!(
            schema.is_valid(&valid),
            "{kind}: {:?}",
            schema.validate(&valid)
        );

        let mut bad = valid.clone();
        bad["event"]["payload"][forbidden] = json!(true);
        assert!(serde_json::from_value::<EventStreamFrame>(bad.clone()).is_err());
        #[cfg(feature = "openapi")]
        assert!(!schema.is_valid(&bad), "{kind}: {forbidden}");
        let mut wrong = valid.clone();
        wrong["event"]["aggregate_id"] = json!(HubId::new());
        assert!(serde_json::from_value::<EventStreamFrame>(wrong.clone()).is_err());
        #[cfg(feature = "openapi")]
        assert!(!schema.is_valid(&wrong));
        if aggregate_type == "execution" {
            let mut wrong = valid.clone();
            wrong["event"]["payload"]["execution_id"] = json!(ExecutionId::new());
            assert!(serde_json::from_value::<EventStreamFrame>(wrong).is_err());
        }
    }
    assert_eq!(
        serde_json::to_string(&EventStreamFrame::Ping {})?,
        r#"{"type":"ping"}"#
    );
    for value in [
        json!({"type":"ping"}),
        json!({"type":"resync_required","oldest_available_seq":3,"latest_seq":8}),
    ] {
        let decoded: EventStreamFrame = serde_json::from_value(value.clone())?;
        assert_eq!(json!(decoded), value);
        #[cfg(feature = "openapi")]
        assert!(schema.is_valid(&value));
        let mut bad = value;
        bad["extra"] = json!(null);
        assert!(serde_json::from_value::<EventStreamFrame>(bad.clone()).is_err());
        #[cfg(feature = "openapi")]
        assert!(!schema.is_valid(&bad));
    }
    Ok(())
}
