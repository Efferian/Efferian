//! Bounded cache of validators for immutable tool revisions.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use efferian_protocol::{ToolId, validate_input_schema_structure};
use jsonschema::{Draft, Validator};
use serde_json::Value;

const CAPACITY: usize = 2048;

type Entry = (ToolId, u64, String, Arc<Validator>);

#[derive(Default)]
pub(crate) struct SchemaCache(Mutex<VecDeque<Entry>>);

#[derive(Clone, Copy, Debug)]
pub(crate) struct SchemaError;

pub(super) fn compile(schema: &Value) -> Result<Arc<Validator>, SchemaError> {
    validate_input_schema_structure(schema).map_err(|_| SchemaError)?;
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .build(schema)
        .map(Arc::new)
        .map_err(|_| SchemaError)
}

impl SchemaCache {
    pub(crate) fn get_or_compile(
        &self,
        tool_id: ToolId,
        version: u64,
        digest: &str,
        schema: &Value,
    ) -> Result<Arc<Validator>, SchemaError> {
        let same_key =
            |(id, ver, hash, _): &Entry| (*id, *ver, hash.as_str()) == (tool_id, version, digest);
        {
            let mut entries = self.0.lock().map_err(|_| SchemaError)?;
            if let Some(index) = entries.iter().position(same_key)
                && let Some(entry) = entries.remove(index)
            {
                let validator = Arc::clone(&entry.3);
                entries.push_back(entry);
                return Ok(validator);
            }
        }
        let validator = compile(schema)?;
        let mut entries = self.0.lock().map_err(|_| SchemaError)?;
        if let Some(index) = entries.iter().position(same_key) {
            entries.remove(index);
        } else if entries.len() == CAPACITY {
            entries.pop_front();
        }
        entries.push_back((tool_id, version, digest.to_owned(), Arc::clone(&validator)));
        Ok(validator)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "fixtures must compile")]

    use serde_json::json;

    use super::*;

    #[test]
    fn schema_compile_rejects_invalid_regex_and_remote_refs() {
        for schema in [
            json!({"type": "object", "patternProperties": {"[": {}}}),
            json!({"type": "object", "properties": {"x": {"$ref": "https://example.invalid/s"}}}),
            json!({"type": "object", "properties": {"x": {"$ref": "#/$defs/missing"}}}),
        ] {
            assert!(compile(&schema).is_err());
        }
        let schema = json!({
            "type": "object",
            "$defs": {"value": {"type": "integer"}},
            "properties": {"x": {"$ref": "#/$defs/value"}}
        });
        let validator = compile(&schema).unwrap();
        assert!(validator.is_valid(&json!({"x": 1})));
        assert!(!validator.is_valid(&json!({"x": "wrong"})));
    }

    #[test]
    fn cache_evicts_least_recent_revision() {
        let cache = SchemaCache::default();
        let id = ToolId::new();
        let schema = json!({"type": "object"});
        let get = |version| cache.get_or_compile(id, version, "hash", &schema).unwrap();
        let first = get(1);
        let second = get(2);
        for version in 3..=CAPACITY as u64 {
            get(version);
        }
        assert!(Arc::ptr_eq(&first, &get(1)));
        get(CAPACITY as u64 + 1);
        assert!(Arc::ptr_eq(&first, &get(1)));
        assert!(!Arc::ptr_eq(&second, &get(2)));
    }
}
