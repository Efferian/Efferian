use serde_json::Value;
use utoipa::ToSchema;

pub fn schema_validator<T: ToSchema>() -> Result<jsonschema::Validator, Box<dyn std::error::Error>>
{
    let mut schema = serde_json::to_value(T::schema())?;
    let mut components = Vec::new();
    T::schemas(&mut components);
    let schemas = components
        .into_iter()
        .map(|(name, schema)| Ok((name, serde_json::to_value(schema)?)))
        .collect::<serde_json::Result<serde_json::Map<String, Value>>>()?;
    schema["components"] = serde_json::json!({ "schemas": schemas });
    Ok(jsonschema::validator_for(&schema)?)
}
