//! v0.3 ↔ v1.0 wire format conversion utilities.
//!
//! These functions transform `serde_json::Value` trees between the two formats.

use serde_json::Value;

/// Role string mapping: v1.0 → v0.3
fn role_v10_to_v03(s: &str) -> &str {
    match s {
        "ROLE_USER" => "user",
        "ROLE_AGENT" => "agent",
        "ROLE_UNSPECIFIED" => "unspecified",
        _ => s,
    }
}

/// Role string mapping: v0.3 → v1.0
fn role_v03_to_v10(s: &str) -> &str {
    match s {
        "user" => "ROLE_USER",
        "agent" => "ROLE_AGENT",
        "unspecified" => "ROLE_UNSPECIFIED",
        _ => s,
    }
}

/// TaskState string mapping: v1.0 → v0.3
pub fn state_v10_to_v03(s: &str) -> &str {
    match s {
        "TASK_STATE_SUBMITTED" => "submitted",
        "TASK_STATE_WORKING" => "working",
        "TASK_STATE_COMPLETED" => "completed",
        "TASK_STATE_FAILED" => "failed",
        "TASK_STATE_CANCELED" => "canceled",
        "TASK_STATE_INPUT_REQUIRED" => "input-required",
        "TASK_STATE_REJECTED" => "rejected",
        "TASK_STATE_AUTH_REQUIRED" => "auth-required",
        "TASK_STATE_UNSPECIFIED" => "unspecified",
        _ => s,
    }
}

/// TaskState string mapping: v0.3 → v1.0
fn state_v03_to_v10(s: &str) -> &str {
    match s {
        "submitted" => "TASK_STATE_SUBMITTED",
        "working" => "TASK_STATE_WORKING",
        "completed" => "TASK_STATE_COMPLETED",
        "failed" => "TASK_STATE_FAILED",
        "canceled" => "TASK_STATE_CANCELED",
        "input-required" => "TASK_STATE_INPUT_REQUIRED",
        "rejected" => "TASK_STATE_REJECTED",
        "auth-required" => "TASK_STATE_AUTH_REQUIRED",
        "unspecified" => "TASK_STATE_UNSPECIFIED",
        _ => s,
    }
}

/// Convert v1.0 request params to v0.3 format before sending.
///
/// Transforms:
/// - `ROLE_USER` → `user`, `ROLE_AGENT` → `agent`
/// - Adds `kind` field to parts
pub fn request_v10_to_v03(val: &mut Value) {
    convert_roles(val, role_v10_to_v03);
    add_kind_to_parts(val);
}

/// Convert v0.3 response to v1.0 format after receiving.
///
/// Transforms:
/// - `user` → `ROLE_USER`, `completed` → `TASK_STATE_COMPLETED`, etc.
/// - Removes `kind` discriminator fields
/// - Wraps bare result in externally tagged format
pub fn response_v03_to_v10(val: &mut Value) {
    convert_roles(val, role_v03_to_v10);
    convert_states(val, state_v03_to_v10);
    strip_kind_fields(val);
}

fn convert_roles(val: &mut Value, f: fn(&str) -> &str) {
    match val {
        Value::Object(map) => {
            if let Some(Value::String(role)) = map.get("role") {
                let converted = f(role).to_string();
                map.insert("role".to_string(), Value::String(converted));
            }
            for v in map.values_mut() {
                convert_roles(v, f);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                convert_roles(v, f);
            }
        }
        _ => {}
    }
}

fn convert_states(val: &mut Value, f: fn(&str) -> &str) {
    match val {
        Value::Object(map) => {
            if let Some(Value::String(state)) = map.get("state") {
                let converted = f(state).to_string();
                map.insert("state".to_string(), Value::String(converted));
            }
            for v in map.values_mut() {
                convert_states(v, f);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                convert_states(v, f);
            }
        }
        _ => {}
    }
}

fn add_kind_to_parts(val: &mut Value) {
    match val {
        Value::Object(map) => {
            // If this looks like a Part (has text/file/data but no kind), add kind
            if map.contains_key("text") && !map.contains_key("kind") && !map.contains_key("role") {
                map.insert("kind".to_string(), Value::String("text".to_string()));
            } else if map.contains_key("file") && !map.contains_key("kind") {
                map.insert("kind".to_string(), Value::String("file".to_string()));
            } else if map.contains_key("data")
                && !map.contains_key("kind")
                && !map.contains_key("role")
                && !map.contains_key("status")
            {
                map.insert("kind".to_string(), Value::String("data".to_string()));
            }
            for v in map.values_mut() {
                add_kind_to_parts(v);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                add_kind_to_parts(v);
            }
        }
        _ => {}
    }
}

fn strip_kind_fields(val: &mut Value) {
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
