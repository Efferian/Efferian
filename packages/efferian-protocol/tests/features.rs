use std::error::Error;

#[test]
fn openapi_is_opt_in_for_consumers() -> Result<(), Box<dyn Error>> {
    let manifest = include_str!("../Cargo.toml").parse::<toml::Table>()?;
    let features = &manifest["features"];
    assert_eq!(features["default"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        manifest["dependencies"]["utoipa"]["optional"].as_bool(),
        Some(true)
    );
    Ok(())
}

/// The component test normally builds with default features. Exercise the
/// schema-enabled integration tests as primary targets in the same offline cache.
#[cfg(not(feature = "openapi"))]
#[test]
fn openapi_contracts_pass_with_the_feature_enabled() -> Result<(), Box<dyn Error>> {
    let status = std::process::Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "test",
            "--offline",
            "--locked",
            "-p",
            "efferian-protocol",
            "--no-default-features",
            "--features",
            "openapi",
            "--tests",
        ])
        .status()?;
    assert!(status.success(), "OpenAPI contract tests failed: {status}");
    Ok(())
}
