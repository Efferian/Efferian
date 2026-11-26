use std::collections::BTreeMap;

use efferian_protocol::*;
use serde_json::{Map, json};

#[cfg(feature = "openapi")]
mod support;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn target() -> TargetSelector {
    TargetSelector::Tag {
        tag: "sandbox".into(),
    }
}

fn managed(spec: ToolSpec) -> ToolDefinition {
    ToolDefinition {
        description: Some("Run a managed tool".into()),
        input_schema: Some(json!({"type":"object"})),
        annotations: None,
        spec,
    }
}

fn arg(name: &str) -> ArgBinding {
    ArgBinding::Arg { name: name.into() }
}

fn command(account_id: Option<AccountId>) -> ToolDefinition {
    managed(ToolSpec::Command {
        program: "git".into(),
        args: vec![arg("value")],
        cwd: "/srv/tools".into(),
        env: if account_id.is_some() {
            BTreeMap::from([("API_KEY".into(), EnvBinding::Secret { key: "key".into() })])
        } else {
            BTreeMap::new()
        },
        account_id,
        target_selector: target(),
        runtime_ms: 100,
        max_output_bytes: MAX_OUTPUT_BYTES,
    })
}

fn http(base_url: &str, account_id: AccountId) -> ToolDefinition {
    managed(ToolSpec::Http {
        method: HttpMethod::Post,
        base_url: base_url.into(),
        path_segments: vec![arg("path")],
        query: BTreeMap::from([("q".into(), arg("query"))]),
        headers: BTreeMap::from([("X-Trace".into(), arg("header"))]),
        body: Some(HttpBodyBinding::ArgJson {
            name: "body".into(),
        }),
        account_id: Some(account_id),
        target_selector: target(),
        runtime_ms: 100,
        max_output_bytes: 31,
    })
}

#[test]
fn bindings_reject_secrets_in_argv_and_http_and_args_in_environment() -> Result {
    let mut definition = json!(command(None));
    definition["spec"]["args"] = json!([{"kind":"secret","key":"key"}]);
    let error = serde_json::from_value::<ToolDefinition>(definition)
        .err()
        .ok_or("accepted secret argv")?;
    assert!(error.to_string().contains("forbidden in argv"));

    let mut definition = json!(command(None));
    definition["spec"]["env"] = json!({"APP_ENV":{"kind":"arg","name":"key"}});
    let error = serde_json::from_value::<ToolDefinition>(definition)
        .err()
        .ok_or("accepted arg env")?;
    assert!(error.to_string().contains("forbidden in env"));

    let definition = json!(http("https://example.org", AccountId::new()));
    for key in ["path_segments", "query", "headers", "body"] {
        let binding = json!({"kind":"secret","key":"key"});
        let mut invalid = definition.clone();
        invalid["spec"][key] = match key {
            "path_segments" => json!([binding]),
            "headers" | "query" => json!({"key":binding}),
            _ => binding,
        };
        assert!(
            serde_json::from_value::<ToolDefinition>(invalid).is_err(),
            "{key}"
        );
    }
    let mut bad = definition;
    bad["spec"]["legacy"] = json!(true);
    assert!(serde_json::from_value::<ToolDefinition>(bad).is_err());
    assert!(serde_json::from_value::<ToolDefinition>(json!([null, null, null, {}])).is_err());

    let literal = ArgBinding::Literal {
        value: "abc".into(),
    };
    let mut remaining = 3;
    assert_eq!(literal.resolve_text(&Map::new(), &mut remaining)?, "abc");
    assert_eq!(remaining, 0);
    assert_eq!(
        literal.resolve_text(&Map::new(), &mut remaining),
        Err(ValidationError::ActionLimit)
    );
    for (value, expected) in [
        (json!(12), "12"),
        (json!(true), "true"),
        (json!(false), "false"),
    ] {
        let map = Map::from_iter([("v".into(), value)]);
        assert_eq!(arg("v").resolve_text(&map, &mut 20)?, expected);
    }
    for value in [json!(null), json!([]), json!({})] {
        let map = Map::from_iter([("v".into(), value)]);
        assert_eq!(
            arg("v").resolve_text(&map, &mut 20),
            Err(ValidationError::InvalidTextArgument)
        );
    }
    let body = HttpBodyBinding::LiteralJson {
        value: json!({"key":0}),
    };
    assert_eq!(
        body.resolve(&Map::new(), &mut 8),
        Err(ValidationError::ActionLimit)
    );
    assert_eq!(body.resolve(&Map::new(), &mut 9)?, r#"{"key":0}"#);
    Ok(())
}

#[test]
fn profile_bindings_validate_names_versions_and_waits() -> Result {
    let binding: ProfileToolBinding = serde_json::from_value(json!({
        "public_name":"run-test", "tool_id":ToolId::new(), "tool_version":1
    }))?;
    assert_eq!(binding.execution_mode, ExecutionMode::Auto);
    assert!(!binding.curated_featured);
    assert!(validate_profile_bindings(std::slice::from_ref(&binding)).is_ok());
    assert!(validate_profile_bindings(&[binding.clone(), binding.clone()]).is_err());
    let mut invalid = binding.clone();
    for name in RESERVED_CONTROL_TOOL_NAMES {
        invalid.public_name = name.to_owned();
        assert!(
            validate_profile_bindings(std::slice::from_ref(&invalid)).is_err(),
            "{name}"
        );
    }
    invalid = binding.clone();
    invalid.tool_version = 0;
    assert!(validate_profile_bindings(std::slice::from_ref(&invalid)).is_err());
    invalid.tool_version = 1;
    invalid.inline_wait_ms = Some(MAX_WAIT_MS + 1);
    assert!(validate_profile_bindings(std::slice::from_ref(&invalid)).is_err());
    invalid.inline_wait_ms = Some(MAX_WAIT_MS);
    assert!(validate_profile_bindings(std::slice::from_ref(&invalid)).is_ok());
    invalid.execution_mode = ExecutionMode::Async;
    assert!(validate_profile_bindings(std::slice::from_ref(&invalid)).is_err());
    invalid.inline_wait_ms = None;
    assert!(validate_profile_bindings(&[invalid]).is_ok());
    let mut unknown = json!(binding);
    unknown["legacy"] = json!(1);
    assert!(serde_json::from_value::<ProfileToolBinding>(unknown).is_err());
    Ok(())
}

#[test]
fn upstream_revision_captures_exact_discovery_schema_and_uses_both_deadlines() -> Result {
    let policy = EgressPolicy::default();
    let upstream_id = UpstreamId::new();
    let mut tool = ToolDefinition {
        description: None,
        input_schema: None,
        annotations: None,
        spec: ToolSpec::UpstreamRef {
            upstream_id,
            upstream_tool_name: "run".into(),
            account_mode: UpstreamAccountMode::CallerBound,
            shared_account_id: None,
            runtime_ms: 200,
        },
    };
    assert!(tool.validate(200, 400, &policy).is_ok());
    assert!(tool.validate(400, 200, &policy).is_ok());
    assert_eq!(
        tool.validate(199, 400, &policy),
        Err(ValidationError::RuntimeLimit)
    );
    assert_eq!(
        tool.validate(400, 199, &policy),
        Err(ValidationError::RuntimeLimit)
    );
    assert!(command(None).validate(200, 50, &policy).is_ok());
    tool.input_schema = Some(json!({"type":"object"}));
    assert!(tool.validate(200, 200, &policy).is_err());
    tool.input_schema = None;
    let mut unknown = json!(tool);
    unknown["spec"]
        .as_object_mut()
        .ok_or("spec fixture")?
        .remove("runtime_ms");
    assert!(serde_json::from_value::<ToolDefinition>(unknown).is_err());

    let schema =
        json!({"type":"object","properties":{"z":{"type":"integer"},"a":{"type":"string"}}});
    let mut discovered = DiscoveredUpstreamTool {
        upstream_id,
        tool_name: "run".into(),
        description: Some("Run remotely".into()),
        input_schema: schema.clone(),
        annotations: Some(ToolAnnotations {
            read_only_hint: Some(true),
            ..ToolAnnotations::default()
        }),
    };
    assert_eq!(
        tool.freeze_revision(None, 200, 200, &policy),
        Err(ValidationError::MissingUpstreamTool)
    );
    let wrong = DiscoveredUpstreamTool {
        upstream_id: UpstreamId::new(),
        ..discovered.clone()
    };
    assert_eq!(
        tool.freeze_revision(Some(&wrong), 200, 200, &policy),
        Err(ValidationError::MissingUpstreamTool)
    );
    let snapshot = tool.freeze_revision(Some(&discovered), 200, 200, &policy)?;
    assert_eq!(
        snapshot.definition.description.as_deref(),
        Some("Run remotely")
    );
    assert_eq!(snapshot.definition.annotations, discovered.annotations);
    assert_eq!(snapshot.definition.input_schema.as_ref(), Some(&schema));
    assert_eq!(
        snapshot.input_schema_sha256,
        "8ddb924cb6a3a84b7ec4ae24e099c457d0431637580a4055c6afdb165ff0a477"
    );
    discovered.input_schema = json!({"type":"object","additionalProperties":false});
    tool.description = Some("Override".into());
    let next = tool.freeze_revision(Some(&discovered), 200, 200, &policy)?;
    assert_eq!(next.definition.description.as_deref(), Some("Override"));
    assert_ne!(next.input_schema_sha256, snapshot.input_schema_sha256);
    assert_eq!(snapshot.definition.input_schema, Some(schema));
    Ok(())
}

#[test]
fn http_resolution_and_node_validation_share_the_credential_boundary() -> Result {
    let default = EgressPolicy::default();
    let id = AccountId::new();
    let tool = http("https://example.org/a//b/", id);
    let payload = AccountSecretPayload::HttpAuth {
        auth: HttpAuthSecret::Header {
            name: "X-Secret".into(),
            value: SecretString::new("sentinel"),
        },
    };
    let account = Some(ManagedAccount {
        account_id: id,
        upstream_id: None,
        payload: &payload,
    });
    let args = json!({"path":"a b","query":"v&k=1","header":"trace","body":{"x":1}});
    let args = args.as_object().ok_or("arguments")?;
    let id = ExecutionId::new();
    tool.validate(100, 1, &default)?;
    let request = tool.resolve_managed(id, args, account, 100, &default)?;
    let ResolvedAction::Http {
        url, headers, body, ..
    } = &request.action
    else {
        return Err("resolved action".into());
    };
    assert_eq!(url, "https://example.org/a//b/a%20b?q=v%26k%3D1");
    assert_eq!(headers.get("X-Trace").map(String::as_str), Some("trace"));
    assert_eq!(body.as_deref(), Some(r#"{"x":1}"#));
    assert_eq!(
        request.http_auth_headers,
        vec![("X-Secret".into(), SecretString::new("sentinel"))]
    );
    assert_eq!(request.runtime_ms, 100);

    let frame = BridgeEnvelope {
        epoch: 1,
        message: BridgeMessage::ExecuteReq(request.clone()),
    };
    let decoded = decode_bridge_frame(&encode_bridge_frame(&frame)?, BridgeReceiver::Node)?;
    let BridgeMessage::ExecuteReq(node_request) = decoded.message else {
        return Err("request frame".into());
    };
    node_request.validate_resolved(100, &default)?;
    assert!(node_request.validate_resolved(99, &default).is_err());
    for (key, value) in [
        ("path", json!("..")),
        ("path", json!("a%2Fb")),
        ("header", json!("a\r\nb")),
    ] {
        let mut bad = args.clone();
        bad.insert(key.into(), value);
        assert!(
            tool.resolve_managed(id, &bad, account, 100, &default)
                .is_err()
        );
    }

    let mut collision = tool.clone();
    let ToolSpec::Http { headers, .. } = &mut collision.spec else {
        return Err("HTTP fixture".into());
    };
    headers.insert("x-sECRET".into(), arg("header"));
    assert_eq!(
        collision.resolve_managed(id, args, account, 100, &default),
        Err(ValidationError::HeaderCollision)
    );
    let duplicate = serde_json::to_string(&tool)?.replace(
        r#""X-Trace":{"kind":"arg","name":"header"}"#,
        r#""X-Trace":{"kind":"arg","name":"header"},"X-Trace":{"kind":"arg","name":"header"}"#,
    );
    assert!(serde_json::from_str::<ToolDefinition>(&duplicate).is_err());

    let mut node_mismatch = request;
    node_mismatch
        .env_secrets
        .insert("APP_KEY".into(), SecretString::new("ignored"));
    assert_eq!(
        node_mismatch.validate_resolved(100, &default),
        Err(ValidationError::InvalidAccount)
    );

    let account_id = account.ok_or("account fixture")?.account_id;
    let local = http("http://[::ffff:127.0.0.1]/", account_id);
    let hub_policy = EgressPolicy::from_cidrs(&["127.0.0.0/8"], false)?;
    let local_request = local.resolve_managed(id, args, account, 100, &hub_policy)?;
    assert!(matches!(
        local_request.validate_resolved(100, &default),
        Err(ValidationError::Egress(SsrfError::DisallowedIp(_)))
    ));
    Ok(())
}

#[test]
fn managed_process_and_ssh_validate_after_argument_substitution() -> Result {
    let policy = EgressPolicy::default();
    let account_id = AccountId::new();
    let kv = AccountSecretPayload::SecretKv {
        entries: BTreeMap::from([("key".into(), SecretString::new("sentinel"))]),
    };
    let account = Some(ManagedAccount {
        account_id,
        upstream_id: None,
        payload: &kv,
    });
    let command = command(Some(account_id));
    let id = ExecutionId::new();
    let good = Map::from_iter([("value".into(), json!("a b"))]);
    let request = command.resolve_managed(id, &good, account, 100, &policy)?;
    assert_eq!(
        request.env_secrets.get("API_KEY"),
        Some(&SecretString::new("sentinel"))
    );
    let ResolvedAction::Command { args, env, .. } = request.action else {
        return Err("process action".into());
    };
    assert_eq!(args, ["a b"]);
    assert!(env.is_empty());
    assert_eq!(
        command.resolve_managed(id, &good, None, 100, &policy),
        Err(ValidationError::InvalidAccount)
    );

    let script = managed(ToolSpec::Script {
        interpreter: "/bin/sh".into(),
        code: "printf '%s'".into(),
        args: vec![arg("value")],
        cwd: "/tmp".into(),
        env: BTreeMap::new(),
        account_id: None,
        target_selector: target(),
        runtime_ms: 100,
        max_output_bytes: 100,
    });
    let ssh = managed(ToolSpec::Ssh {
        host: "ssh.example.org".into(),
        port: 22,
        user: "operator".into(),
        command: "echo".into(),
        args: vec![arg("value")],
        known_hosts_file: "/etc/ssh/ssh_known_hosts".into(),
        account_id: None,
        identity_file: Some("/etc/ssh/operator".into()),
        target_selector: target(),
        runtime_ms: 100,
        max_output_bytes: 100,
    });
    script.resolve_managed(id, &good, None, 100, &policy)?;
    ssh.resolve_managed(id, &good, None, 100, &policy)?;
    for value in ["a\0b", "x\r\ny"] {
        let args = Map::from_iter([("value".into(), json!(value))]);
        assert!(ssh.resolve_managed(id, &args, None, 100, &policy).is_err());
    }
    let invalid = Map::from_iter([("value".into(), json!("a\0b"))]);
    assert!(
        script
            .resolve_managed(id, &invalid, None, 100, &policy)
            .is_err()
    );
    assert!(
        command
            .resolve_managed(id, &invalid, account, 100, &policy)
            .is_err()
    );

    let mut repeated = script;
    let ToolSpec::Script { args, .. } = &mut repeated.spec else {
        return Err("script fixture".into());
    };
    args.push(arg("value"));
    let oversized = Map::from_iter([(
        "value".into(),
        json!("x".repeat(MAX_RESOLVED_ACTION_BYTES / 2)),
    )]);
    assert_eq!(
        repeated.resolve_managed(id, &oversized, None, 100, &policy),
        Err(ValidationError::ActionLimit)
    );
    Ok(())
}

#[test]
fn env_ssh_and_header_syntax_is_checked_in_context() -> Result {
    for name in [
        "LD_PRELOAD",
        "ld_library_path",
        "DYLD_INSERT_LIBRARIES",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "SHELLOPTS",
        "BASH_FUNC_foo%%",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "RUBYOPT",
        "PERL5OPT",
        "IFS",
        "GCONV_PATH",
        "SSH_AUTH_SOCK",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "PATH",
    ] {
        assert!(validate_env_var_name(name).is_err(), "{name}");
    }
    for name in ["APP_ENV", "RUST_LOG"] {
        validate_env_var_name(name)?;
    }
    for name in [
        "./run",
        "../bin/sh",
        "dir/tool",
        "/usr/../bin/tool",
        "/bin/",
    ] {
        assert!(validate_command_program(name).is_err(), "{name}");
    }
    for name in ["git", "/usr/bin/git"] {
        validate_command_program(name)?;
    }
    assert!(validate_script_interpreter("python3").is_err());
    validate_script_interpreter("/usr/bin/python3")?;

    for bad in [
        "-host",
        "ssh://host",
        "a/host",
        "user@host",
        "a..b",
        "[::1]",
        "fe80::1%eth0",
    ] {
        assert!(validate_ssh_host(bad).is_err(), "{bad}");
    }
    for good in ["a.b", "192.0.2.1", "2001:db8::1"] {
        validate_ssh_host(good)?;
    }
    for bad in ["-oGroup", "two words", &"a".repeat(65)] {
        assert!(validate_ssh_user(bad).is_err(), "{bad}");
    }
    validate_ssh_user("a-b_c.1")?;
    validate_ssh_user(&"a".repeat(64))?;
    assert!(validate_ssh_port(0).is_err());
    for path in [
        "known_hosts",
        "/ssh/%h",
        "/ssh/a b",
        "/ssh/\"a",
        "/ssh/../a",
    ] {
        assert!(validate_ssh_path(path).is_err(), "{path}");
    }
    validate_ssh_path("/etc/ssh/ssh_known_hosts")?;
    assert_eq!(shell_quote("O'Reilly"), "'O'\\''Reilly'");
    assert_eq!(
        build_ssh_remote_command("echo", &["a b".into(), String::new()])?,
        "'echo' 'a b' ''"
    );
    assert!(build_ssh_remote_command("echo", &["a\nb".into()]).is_err());
    assert!(build_ssh_remote_command("echo\r", &[]).is_err());

    for name in [
        "Host",
        "authorization",
        "proxy-Authorization",
        "cookie",
        "Transfer-Encoding",
        "Content-Length",
    ] {
        assert!(validate_http_tool_header_name(name).is_err(), "{name}");
    }
    assert!(validate_http_header_value("a\r\nb").is_err());
    assert!(validate_http_header_value("a\x7fb").is_err());
    validate_http_header_value("a\tb")?;
    let ordinary = BTreeMap::from([("X-Test".into(), ""), ("x-test".into(), "")]);
    assert_eq!(
        validate_http_headers_no_auth_collision(&ordinary, None),
        Err(ValidationError::HeaderCollision)
    );
    Ok(())
}

#[test]
fn schema_references_are_validated_only_in_schema_positions() -> Result {
    let mut command = command(None);
    let policy = EgressPolicy::default();
    for invalid in [
        json!({"type":"object","properties":{"a":{"$ref":"https://example.org/schema"}}}),
        json!({"type":"object","allOf":[{"$dynamicRef":"https://example.org/schema"}]}),
        json!({"type":"object","additionalProperties":{"$ref":12}}),
        json!({"type":"object","properties":{"a":{"items":{"$ref":"path.json"}}}}),
    ] {
        command.input_schema = Some(invalid);
        assert!(command.validate(100, 1, &policy).is_err());
    }
    for valid in [
        json!({"type":"object","properties":{"$ref":{"type":"string"},"$dynamicRef":{"type":"string"}}}),
        json!({"type":"object","$defs":{"a":{"type":"string"}},"properties":{"ref":{"$ref":"#/$defs/a"}}}),
        json!({"type":"object","const":{"$ref":"https://example.org/schema"},
            "default":{"$dynamicRef":"https://example.org/schema"},"examples":[{"$ref":"https://example.org/schema"}],
            "enum":[{"$ref":"https://example.org/schema"}]}),
        json!({"type":"object","properties":{"a":true}}),
    ] {
        command.input_schema = Some(valid.clone());
        command.validate(100, 1, &policy)?;
        assert_eq!(command.input_schema.as_ref(), Some(&valid));
    }
    Ok(())
}

#[cfg(feature = "openapi")]
#[test]
fn openapi_binding_schemas_match_their_wire_variants() -> Result {
    use utoipa::PartialSchema as _;

    let arg = support::schema_validator::<ArgBinding>()?;
    let env = support::schema_validator::<EnvBinding>()?;
    let tool = support::schema_validator::<ToolDefinition>()?;
    for (value, valid_arg, valid_env) in [
        (json!({"kind":"literal","value":"x"}), true, true),
        (json!({"kind":"arg","name":"x"}), true, false),
        (json!({"kind":"secret","key":"x"}), false, true),
        (
            json!({"kind":"literal","value":"x","extra":true}),
            false,
            false,
        ),
    ] {
        assert_eq!(
            arg.is_valid(&value),
            valid_arg,
            "{value}: {}",
            serde_json::to_string(&ArgBinding::schema())?
        );
        assert_eq!(
            env.is_valid(&value),
            valid_env,
            "{value}: {}",
            serde_json::to_string(&EnvBinding::schema())?
        );
    }
    let mut valid = json!(command(None));
    assert!(tool.is_valid(&valid), "{:?}", tool.validate(&valid));
    valid["spec"]["args"] = json!([{"kind":"secret","key":"key"}]);
    assert!(!tool.is_valid(&valid));
    Ok(())
}

#[test]
fn valid_target_names_and_fixed_node_limits() -> Result {
    validate_slug("abc-12")?;
    validate_resource_name("Abc.12")?;
    validate_node_tag("abc.12")?;
    assert!(validate_slug("abc.12").is_err());
    assert!(validate_node_tag("Abc").is_err());
    assert!(validate_resource_name("_abc").is_err());
    let ids: Vec<NodeId> = (0..MAX_FIXED_TARGET_NODES).map(|_| NodeId::new()).collect();
    assert!(
        TargetSelector::Fixed {
            node_ids: ids.clone()
        }
        .validate()
        .is_ok()
    );
    let mut too_many = ids;
    too_many.push(NodeId::new());
    assert!(
        TargetSelector::Fixed { node_ids: too_many }
            .validate()
            .is_err()
    );
    let id = NodeId::new();
    assert!(
        TargetSelector::Fixed {
            node_ids: vec![id, id]
        }
        .validate()
        .is_err()
    );
    assert!(
        TargetSelector::Fixed { node_ids: vec![] }
            .validate()
            .is_err()
    );

    let literal = ArgBinding::Literal {
        value: "x".repeat(MAX_TOOL_DEFINITION_BYTES),
    };
    let mut command = command(None);
    let ToolSpec::Command { args, .. } = &mut command.spec else {
        return Err("command fixture".into());
    };
    args.push(literal);
    assert_eq!(
        command.validate(100, 100, &EgressPolicy::default()),
        Err(ValidationError::DefinitionLimit)
    );
    let binding: EnvBinding = serde_json::from_value(json!({"kind":"secret","key":"good"}))?;
    assert_eq!(binding, EnvBinding::Secret { key: "good".into() });
    Ok(())
}
