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
