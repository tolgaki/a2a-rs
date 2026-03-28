//! v0.3 ↔ v1.0 wire format conversion utilities.
//!
//! Since a2a-rs-core now serializes `kind`, roles, and task states in v0.3 style
//! natively (and accepts both formats on deserialization via serde aliases), the
//! only remaining conversion needed is structural: wrapping v0.3's internally-tagged
//! results into v1.0's externally-tagged format.

use serde_json::Value;

/// Strip `kind` discriminator fields from a v0.3 response value tree.
///
/// Useful when you want to clean up kind fields that were already consumed
/// for structural dispatch (e.g. by [`wrap_v03_result_as_v10`]).
pub fn strip_kind_fields(val: &mut Value) {
    match val {
        Value::Object(map) => {
            map.remove("kind");
            for v in map.values_mut() {
                strip_kind_fields(v);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                strip_kind_fields(v);
            }
        }
        _ => {}
    }
}

/// Wrap a v0.3 result (which has `kind: "task"` or `kind: "message"` at top level)
/// into v1.0 externally tagged format (`{"task": {...}}` or `{"message": {...}}`).
pub fn wrap_v03_result_as_v10(val: Value) -> Value {
    if let Some(kind) = val.get("kind").and_then(|k| k.as_str()) {
        let wrapper_key = match kind {
            "task" => "task",
            "message" => "message",
            "status-update" => "statusUpdate",
            "artifact-update" => "artifactUpdate",
            _ => return val,
        };
        let mut inner = val;
        // Strip kind before wrapping
        if let Value::Object(ref mut map) = inner {
            map.remove("kind");
        }
        let mut wrapper = serde_json::Map::new();
        wrapper.insert(wrapper_key.to_string(), inner);
        Value::Object(wrapper)
    } else {
        val
    }
}
