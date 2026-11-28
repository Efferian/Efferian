//! Bounded cache of validators for immutable tool revisions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use efferian_protocol::{ToolId, validate_input_schema_structure};
use jsonschema::{Draft, PatternOptions, Validator};
use serde_json::Value;

const CAPACITY: usize = 2048;
const MAX_CACHE_BYTES: usize = 32 * 1024 * 1024;
const REGEX_SIZE_LIMIT_BYTES: usize = 256 * 1024;

type CacheKey = (ToolId, u64, String);

struct Node {
    key: CacheKey,
    validator: Arc<Validator>,
    weight: usize,
    prev: Option<usize>,
    next: Option<usize>,
}

#[derive(Default)]
struct Lru {
    index: HashMap<CacheKey, usize>,
    nodes: Vec<Option<Node>>,
    free: Vec<usize>,
    head: Option<usize>, // least recently used
    tail: Option<usize>, // most recently used
    total_bytes: usize,
}

impl Lru {
    fn touch(&mut self, slot: usize) {
        if self.tail == Some(slot) {
            return;
        }
        self.unlink(slot);
        self.push_tail(slot);
    }

    fn unlink(&mut self, slot: usize) {
        let Some(node) = self.nodes[slot].as_mut() else {
            return;
        };
        let (prev, next) = (node.prev.take(), node.next.take());
        match prev {
            Some(prev) => {
                if let Some(prev_node) = self.nodes[prev].as_mut() {
                    prev_node.next = next;
                }
            }
            None => self.head = next,
        }
        match next {
            Some(next) => {
                if let Some(next_node) = self.nodes[next].as_mut() {
                    next_node.prev = prev;
                }
            }
            None => self.tail = prev,
        }
    }

    fn push_tail(&mut self, slot: usize) {
        let old_tail = self.tail;
        if let Some(node) = self.nodes[slot].as_mut() {
            node.prev = old_tail;
            node.next = None;
        }
        match old_tail {
            Some(prev) => {
                if let Some(prev_node) = self.nodes[prev].as_mut() {
                    prev_node.next = Some(slot);
                }
            }
            None => self.head = Some(slot),
        }
        self.tail = Some(slot);
    }

    fn evict_lru(&mut self) -> bool {
        let Some(slot) = self.head else {
            return false;
        };
        self.unlink(slot);
        if let Some(node) = self.nodes[slot].take() {
            self.index.remove(&node.key);
            self.total_bytes = self.total_bytes.saturating_sub(node.weight);
            self.free.push(slot);
            return true;
        }
        false
    }

    fn get(&mut self, key: &CacheKey) -> Option<Arc<Validator>> {
        let &slot = self.index.get(key)?;
        let validator = Arc::clone(&self.nodes[slot].as_ref()?.validator);
        self.touch(slot);
        Some(validator)
    }

    fn insert(&mut self, key: CacheKey, validator: Arc<Validator>, weight: usize) {
        if let Some(&slot) = self.index.get(&key) {
            if let Some(node) = self.nodes[slot].as_mut() {
                self.total_bytes = self
                    .total_bytes
                    .saturating_sub(node.weight)
                    .saturating_add(weight);
                node.weight = weight;
                node.validator = validator;
            }
            self.touch(slot);
            return;
        }
        while self.index.len() >= CAPACITY
            || (!self.index.is_empty() && self.total_bytes.saturating_add(weight) > MAX_CACHE_BYTES)
        {
            if !self.evict_lru() {
                break;
            }
        }
        let node = Node {
            key: key.clone(),
            validator,
            weight,
            prev: None,
            next: None,
        };
        let slot = if let Some(slot) = self.free.pop() {
            self.nodes[slot] = Some(node);
            slot
        } else {
            let slot = self.nodes.len();
            self.nodes.push(Some(node));
            slot
        };
        self.index.insert(key, slot);
        self.total_bytes = self.total_bytes.saturating_add(weight);
        self.push_tail(slot);
    }
}

#[derive(Default)]
pub(crate) struct SchemaCache(Mutex<Lru>);

#[derive(Clone, Copy, Debug)]
pub(crate) struct SchemaError;

pub(super) fn compile(schema: &Value) -> Result<Arc<Validator>, SchemaError> {
    validate_input_schema_structure(schema).map_err(|_| SchemaError)?;
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .offline()
        .with_pattern_options(
            PatternOptions::regex()
                .size_limit(REGEX_SIZE_LIMIT_BYTES)
                .dfa_size_limit(REGEX_SIZE_LIMIT_BYTES),
        )
        .build(schema)
        .map(Arc::new)
        .map_err(|_| SchemaError)
}

fn estimate_schema_weight(schema: &Value) -> usize {
    let mut weight = 64usize;
    let mut stack = vec![schema];
    while let Some(node) = stack.pop() {
        match node {
            Value::Null | Value::Bool(_) => weight = weight.saturating_add(8),
            Value::Number(_) => weight = weight.saturating_add(16),
            Value::String(s) => weight = weight.saturating_add(24 + s.len()),
            Value::Array(items) => {
                weight = weight.saturating_add(24);
                stack.extend(items);
            }
            Value::Object(map) => {
                weight = weight.saturating_add(48);
                for (k, v) in map {
                    weight = weight.saturating_add(24 + k.len());
                    if matches!(k.as_str(), "pattern" | "patternProperties") {
                        // Compiled regex automata dominate schema memory footprint.
                        weight = weight.saturating_add(8 * 1024);
                    }
                    stack.push(v);
                }
            }
        }
    }
    weight
}

impl SchemaCache {
    pub(crate) fn get_or_compile(
        &self,
        tool_id: ToolId,
        version: u64,
        digest: &str,
        schema: &Value,
    ) -> Result<Arc<Validator>, SchemaError> {
        let key = (tool_id, version, digest.to_owned());
        {
            let mut lru = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(validator) = lru.get(&key) {
                return Ok(validator);
            }
        }
        let validator = compile(schema)?;
        let weight = estimate_schema_weight(schema);
        let mut lru = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        lru.insert(key, Arc::clone(&validator), weight);
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
            json!({"type": "object", "definitions": {"hidden": {"$ref": "https://example.invalid/s"}}}),
            json!({"type": "object", "x-hidden": [{"$dynamicRef": "https://example.invalid/d"}]}),
            json!({"$schema": "http://json-schema.org/draft-07/schema#", "type": "object"}),
            json!({
                "type": "object",
                "properties": {"x": {"type": "string", "pattern": format!("^{}$", "[a-z]{100}".repeat(200))}}
            }),
        ] {
            assert!(compile(&schema).is_err(), "expected failure for {schema}");
        }
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
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

    #[test]
    fn cache_enforces_byte_budget_before_entry_capacity() {
        let mut lru = Lru::default();
        let id = ToolId::new();
        let validator = compile(&json!({"type": "object"})).unwrap();
        let heavy = MAX_CACHE_BYTES / 3 + 1;
        lru.insert((id, 1, "a".to_owned()), Arc::clone(&validator), heavy);
        lru.insert((id, 2, "b".to_owned()), Arc::clone(&validator), heavy);
        assert_eq!(lru.index.len(), 2);
        // Touch version 1 so version 2 becomes LRU before inserting version 3.
        assert!(lru.get(&(id, 1, "a".to_owned())).is_some());
        lru.insert((id, 3, "c".to_owned()), Arc::clone(&validator), heavy);
        assert_eq!(lru.index.len(), 2);
        assert!(lru.total_bytes <= MAX_CACHE_BYTES);
        assert!(lru.get(&(id, 1, "a".to_owned())).is_some());
        assert!(lru.get(&(id, 2, "b".to_owned())).is_none());
        assert!(lru.get(&(id, 3, "c".to_owned())).is_some());
    }
}
