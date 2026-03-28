//! Core data structures for A2A RC 1.0 JSON-RPC over HTTP.
//! Provides shared types for server/client plus minimal helpers for JSON-RPC envelopes and error codes.
//! Aligned with the authoritative proto definition (specification/a2a.proto).

use serde::{Deserialize, Serialize};
pub mod compat;

use std::collections::HashMap;

/// Deserialize a field that may be null, missing, or an array as Vec<T>.
/// Handles the common case where servers send `"field": null` instead of omitting it.
fn nullable_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<Vec<T>>::deserialize(deserializer).map(|v| v.unwrap_or_default())
}

/// Deserialize a field that may be null, missing, or a map as HashMap<K, V>.
fn nullable_map<'de, D, K, V>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + std::cmp::Eq + std::hash::Hash,
    V: Deserialize<'de>,
{
    Option::<HashMap<K, V>>::deserialize(deserializer).map(|v| v.unwrap_or_default())
}
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "1.0";

// ---------- Agent Card ----------

/// Complete Agent Card per A2A RC 1.0 proto spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    /// Agent display name (primary identifier per proto)
    pub name: String,
    /// Agent description (required in RC 1.0)
    pub description: String,
    /// Supported transport interfaces (contains endpoint URLs)
    #[serde(default, deserialize_with = "nullable_vec")]
    pub supported_interfaces: Vec<AgentInterface>,
    /// Provider/organization information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<AgentProvider>,
    /// Supported A2A protocol version (e.g., "1.0")
    pub version: String,
    /// Link to documentation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    /// Feature flags
    #[serde(default)]
    pub capabilities: AgentCapabilities,
    /// Named authentication schemes (map from scheme name to scheme)
    #[serde(default, deserialize_with = "nullable_map")]
    pub security_schemes: HashMap<String, SecurityScheme>,
    /// Required auth per operation
    #[serde(default, deserialize_with = "nullable_vec")]
    pub security_requirements: Vec<SecurityRequirement>,
    /// Default accepted input MIME types
    #[serde(default, deserialize_with = "nullable_vec")]
    pub default_input_modes: Vec<String>,
    /// Default output MIME types
    #[serde(default, deserialize_with = "nullable_vec")]
    pub default_output_modes: Vec<String>,
    /// Agent capabilities/functions
    #[serde(default, deserialize_with = "nullable_vec")]
    pub skills: Vec<AgentSkill>,
    /// Cryptographic signatures for verification
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable_vec")]
    pub signatures: Vec<AgentCardSignature>,
    /// Icon URL for the agent
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

impl AgentCard {
    /// Get the primary JSON-RPC endpoint URL from supported interfaces
    pub fn endpoint(&self) -> Option<&str> {
        self.supported_interfaces
            .iter()
            .find(|i| i.protocol_binding.eq_ignore_ascii_case("jsonrpc"))
            .map(|i| i.url.as_str())
    }
}

/// Agent interface / transport endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    pub url: String,
    pub protocol_binding: String,
    pub protocol_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Provider/organization information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentProvider {
    /// Organization name
    pub organization: String,
    /// Provider URL (required in RC 1.0)
    pub url: String,
}

/// Authentication scheme definition (externally tagged, proto oneof)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum SecurityScheme {
    ApiKeySecurityScheme(ApiKeySecurityScheme),
    HttpAuthSecurityScheme(HttpAuthSecurityScheme),
    Oauth2SecurityScheme(OAuth2SecurityScheme),
    OpenIdConnectSecurityScheme(OpenIdConnectSecurityScheme),
    MtlsSecurityScheme(MutualTlsSecurityScheme),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeySecurityScheme {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Location of the API key (e.g., "header", "query", "cookie")
    pub location: String,
    /// Name of the API key parameter
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpAuthSecurityScheme {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// HTTP auth scheme (e.g., "bearer", "basic")
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2SecurityScheme {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub flows: OAuthFlows,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_metadata_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenIdConnectSecurityScheme {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub open_id_connect_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MutualTlsSecurityScheme {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// OAuth2 flows — proto oneof
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum OAuthFlows {
    AuthorizationCode(AuthorizationCodeOAuthFlow),
    ClientCredentials(ClientCredentialsOAuthFlow),
    /// Deprecated per spec
    Implicit(ImplicitOAuthFlow),
    /// Deprecated per spec
    Password(PasswordOAuthFlow),
    DeviceCode(DeviceCodeOAuthFlow),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationCodeOAuthFlow {
    pub authorization_url: String,
    pub token_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
    #[serde(default)]
    pub scopes: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkce_required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClientCredentialsOAuthFlow {
    pub token_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
    #[serde(default)]
    pub scopes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImplicitOAuthFlow {
    pub authorization_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
    #[serde(default)]
    pub scopes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOAuthFlow {
    pub token_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
    #[serde(default)]
    pub scopes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCodeOAuthFlow {
    pub device_authorization_url: String,
    pub token_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
    #[serde(default)]
    pub scopes: HashMap<String, String>,
}

/// Helper struct for lists of strings in security requirements
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct StringList {
    #[serde(default)]
    pub list: Vec<String>,
}

/// Security requirement for operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityRequirement {
    /// Map from scheme name to required scopes
    #[serde(default)]
    pub schemes: HashMap<String, StringList>,
}

/// Cryptographic signature for Agent Card verification (JWS)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCardSignature {
    /// JWS protected header (base64url-encoded)
    pub protected: String,
    /// JWS signature
    pub signature: String,
    /// JWS unprotected header
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_notifications: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_agent_card: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable_vec")]
    pub extensions: Vec<AgentExtension>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentExtension {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// Agent skill/capability definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    /// Unique skill identifier
    pub id: String,
    /// Display name
    pub name: String,
    /// Capability description
    pub description: String,
    /// Classification tags
    #[serde(default, deserialize_with = "nullable_vec")]
    pub tags: Vec<String>,
    /// Example prompts or inputs
    #[serde(default, deserialize_with = "nullable_vec")]
    pub examples: Vec<String>,
    /// Accepted input MIME types
    #[serde(default, deserialize_with = "nullable_vec")]
    pub input_modes: Vec<String>,
    /// Produced output MIME types
    #[serde(default, deserialize_with = "nullable_vec")]
    pub output_modes: Vec<String>,
    /// Security requirements for this skill
    #[serde(default, deserialize_with = "nullable_vec")]
    pub security_requirements: Vec<SecurityRequirement>,
}

// ---------- Content Parts ----------

/// Part content — flat proto-JSON format per A2A v1.0 spec.
///
/// Uses custom serialization to produce flat JSON without a `kind` discriminator:
/// - `Part::Text` → `{"text": "..."}`
/// - `Part::File` → `{"file": {"uri": "...", "mimeType": "..."}}`
/// - `Part::Data` → `{"data": {...}}`
///
/// Deserialization detects the variant by which field is present.
#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    /// Text content part
    Text {
        /// The text content
        text: String,
        /// Part-level metadata
        metadata: Option<serde_json::Value>,
    },
    /// File content part (inline bytes or URI reference)
    File {
        /// File content
        file: FileContent,
        /// Part-level metadata
        metadata: Option<serde_json::Value>,
    },
    /// Structured data part
    Data {
        /// Structured JSON data
        data: serde_json::Value,
        /// Part-level metadata
        metadata: Option<serde_json::Value>,
    },
}

impl Serialize for Part {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Part::Text { text, metadata } => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("kind", "text")?;
                map.serialize_entry("text", text)?;
                if let Some(m) = metadata {
                    map.serialize_entry("metadata", m)?;
                }
                map.end()
            }
            Part::File { file, metadata } => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("kind", "file")?;
                map.serialize_entry("file", file)?;
                if let Some(m) = metadata {
                    map.serialize_entry("metadata", m)?;
                }
                map.end()
            }
            Part::Data { data, metadata } => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("kind", "data")?;
                map.serialize_entry("data", data)?;
                if let Some(m) = metadata {
                    map.serialize_entry("metadata", m)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Part {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let obj = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("expected object for Part"))?;
        let metadata = obj.get("metadata").cloned();

        if let Some(text) = obj.get("text") {
            Ok(Part::Text {
                text: text
                    .as_str()
                    .ok_or_else(|| serde::de::Error::custom("text must be a string"))?
                    .to_string(),
                metadata,
            })
        } else if let Some(file) = obj.get("file") {
            let file: FileContent = serde_json::from_value(file.clone())
                .map_err(serde::de::Error::custom)?;
            Ok(Part::File { file, metadata })
        } else if let Some(data) = obj.get("data") {
            Ok(Part::Data {
                data: data.clone(),
                metadata,
            })
        } else if obj.contains_key("raw") || obj.contains_key("url") {
            // Proto-style: raw/url as top-level fields (not nested under file)
            let file = FileContent {
                bytes: obj.get("raw").and_then(|v| v.as_str()).map(|s| s.to_string()),
                uri: obj.get("url").and_then(|v| v.as_str()).map(|s| s.to_string()),
                name: obj.get("filename").and_then(|v| v.as_str()).map(|s| s.to_string()),
                mime_type: obj
                    .get("mediaType")
                    .or_else(|| obj.get("mimeType"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            };
            Ok(Part::File { file, metadata })
        } else if obj.contains_key("kind") {
            // v0.3 compatibility: handle kind-discriminated parts
            let kind = obj["kind"].as_str().unwrap_or("");
            match kind {
                "text" => Ok(Part::Text {
                    text: obj
                        .get("text")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    metadata,
                }),
                "file" => {
                    let file: FileContent = serde_json::from_value(
                        obj.get("file").cloned().unwrap_or_default(),
                    )
                    .map_err(serde::de::Error::custom)?;
                    Ok(Part::File { file, metadata })
                }
                "data" => Ok(Part::Data {
                    data: obj.get("data").cloned().unwrap_or_default(),
                    metadata,
                }),
                _ => Err(serde::de::Error::custom(format!(
                    "unknown part kind: {kind}"
                ))),
            }
        } else {
            Err(serde::de::Error::custom(
                "Part must have text, file, or data field",
            ))
        }
    }
}

/// File content — either inline bytes or a URI reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileContent {
    /// Base64-encoded file bytes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    /// URI pointing to the file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// File name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// MIME type
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

impl Part {
    /// Create a text part
    pub fn text(text: impl Into<String>) -> Self {
        Part::Text {
            text: text.into(),
            metadata: None,
        }
    }

    /// Create a file part with a URI reference
    pub fn file_uri(uri: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Part::File {
            file: FileContent {
                bytes: None,
                uri: Some(uri.into()),
                name: None,
                mime_type: Some(mime_type.into()),
            },
            metadata: None,
        }
    }

    /// Create a file part with inline bytes (base64-encoded)
    pub fn file_bytes(bytes: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Part::File {
            file: FileContent {
                bytes: Some(bytes.into()),
                uri: None,
                name: None,
                mime_type: Some(mime_type.into()),
            },
            metadata: None,
        }
    }

    /// Create a structured data part
    pub fn data(data: serde_json::Value) -> Self {
        Part::Data {
            data,
            metadata: None,
        }
    }

    /// Get the text content, if this is a text part
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Part::Text { text, .. } => Some(text),
            _ => None,
        }
    }
}

// ---------- Messages, Tasks, Artifacts ----------

/// Message role — serializes as v0.3 style ("user"/"agent") for broad compat,
/// deserializes from both v0.3 and v1.0 protobuf style ("ROLE_USER"/"ROLE_AGENT").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum Role {
    #[serde(rename = "unspecified", alias = "ROLE_UNSPECIFIED")]
    Unspecified,
    #[serde(rename = "user", alias = "ROLE_USER")]
    User,
    #[serde(rename = "agent", alias = "ROLE_AGENT")]
    Agent,
}

/// Message structure per A2A RC 1.0 spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    /// Kind discriminator — always "message"
    #[serde(default = "default_message_kind")]
    pub kind: String,
    /// Unique message identifier
    pub message_id: String,
    /// Optional conversation context ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Optional task reference
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Message role (user or agent)
    pub role: Role,
    /// Message content parts
    pub parts: Vec<Part>,
    /// Custom metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Extension URIs
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable_vec")]
    pub extensions: Vec<String>,
    /// Optional related task IDs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_task_ids: Option<Vec<String>>,
}

fn default_message_kind() -> String {
    "message".to_string()
}

fn default_task_kind() -> String {
    "task".to_string()
}

fn default_status_update_kind() -> String {
    "status-update".to_string()
}

fn default_artifact_update_kind() -> String {
    "artifact-update".to_string()
}

/// Artifact output from task processing per proto spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    /// Unique artifact identifier
    pub artifact_id: String,
    /// Optional display name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Artifact content parts
    pub parts: Vec<Part>,
    /// Custom metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Extension URIs
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable_vec")]
    pub extensions: Vec<String>,
}

/// Task lifecycle state — serializes as v0.3 style for broad compat,
/// deserializes from both v0.3 and v1.0 protobuf style.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaskState {
    #[serde(rename = "unspecified", alias = "TASK_STATE_UNSPECIFIED")]
    Unspecified,
    #[serde(rename = "submitted", alias = "TASK_STATE_SUBMITTED")]
    Submitted,
    #[serde(rename = "working", alias = "TASK_STATE_WORKING")]
    Working,
    #[serde(rename = "completed", alias = "TASK_STATE_COMPLETED")]
    Completed,
    #[serde(rename = "failed", alias = "TASK_STATE_FAILED")]
    Failed,
    #[serde(rename = "canceled", alias = "TASK_STATE_CANCELED")]
    Canceled,
    #[serde(rename = "input-required", alias = "TASK_STATE_INPUT_REQUIRED")]
    InputRequired,
    #[serde(rename = "rejected", alias = "TASK_STATE_REJECTED")]
    Rejected,
    #[serde(rename = "auth-required", alias = "TASK_STATE_AUTH_REQUIRED")]
    AuthRequired,
}

/// Task status information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatus {
    /// Current lifecycle state
    pub state: TaskState,
    /// Optional status message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    /// ISO 8601 timestamp (e.g., "2023-10-27T10:00:00Z")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Task resource per A2A RC 1.0 spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Task {
    /// Kind discriminator — always "task"
    #[serde(default = "default_task_kind")]
    pub kind: String,
    /// Unique task identifier (UUID)
    pub id: String,
    /// Context identifier for grouping related interactions
    pub context_id: String,
    /// Current task status
    pub status: TaskStatus,
    /// Optional output artifacts
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<Artifact>>,
    /// Optional message history
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<Message>>,
    /// Custom metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl TaskState {
    /// Check if state is terminal (no further updates expected)
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Rejected
        )
    }
}

// ---------- SendMessage response ----------

/// Handler-level response from SendMessage — can be a Task or direct Message.
///
/// Uses externally tagged serialization for internal pattern matching.
/// For the wire format (JSON-RPC result field), use [`SendMessageResult`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SendMessageResponse {
    Task(Task),
    Message(Message),
}

/// Wire-format result for message/send — the value inside the JSON-RPC `result` field.
///
/// Uses externally tagged serialization per v1.0 proto-JSON:
/// - `{"task": {...}}` or `{"message": {...}}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SendMessageResult {
    Task(Task),
    Message(Message),
}

// ---------- JSON-RPC helper types ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
    pub id: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// JSON-RPC and A2A-specific error codes
pub mod errors {
    // Standard JSON-RPC 2.0 errors
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    // A2A-specific errors
    pub const TASK_NOT_FOUND: i32 = -32001;
    pub const TASK_NOT_CANCELABLE: i32 = -32002;
    pub const PUSH_NOTIFICATION_NOT_SUPPORTED: i32 = -32003;
    pub const UNSUPPORTED_OPERATION: i32 = -32004;
    pub const CONTENT_TYPE_NOT_SUPPORTED: i32 = -32005;
    pub const EXTENDED_AGENT_CARD_NOT_CONFIGURED: i32 = -32006;
    pub const VERSION_NOT_SUPPORTED: i32 = -32007;
    pub const INVALID_AGENT_RESPONSE: i32 = -32008;
    pub const EXTENSION_SUPPORT_REQUIRED: i32 = -32009;

    pub fn message_for_code(code: i32) -> &'static str {
        match code {
            PARSE_ERROR => "Parse error",
            INVALID_REQUEST => "Invalid request",
            METHOD_NOT_FOUND => "Method not found",
            INVALID_PARAMS => "Invalid params",
            INTERNAL_ERROR => "Internal error",
            TASK_NOT_FOUND => "Task not found",
            TASK_NOT_CANCELABLE => "Task not cancelable",
            PUSH_NOTIFICATION_NOT_SUPPORTED => "Push notifications not supported",
            UNSUPPORTED_OPERATION => "Unsupported operation",
            CONTENT_TYPE_NOT_SUPPORTED => "Content type not supported",
            EXTENDED_AGENT_CARD_NOT_CONFIGURED => "Extended agent card not configured",
            VERSION_NOT_SUPPORTED => "Protocol version not supported",
            INVALID_AGENT_RESPONSE => "Invalid agent response",
            EXTENSION_SUPPORT_REQUIRED => "Extension support required",
            _ => "Unknown error",
        }
    }
}

pub fn success(id: serde_json::Value, result: serde_json::Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(result),
        error: None,
    }
}

pub fn error(
    id: serde_json::Value,
    code: i32,
    message: &str,
    data: Option<serde_json::Value>,
) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.to_string(),
            data,
        }),
    }
}

// ---------- Method params ----------

/// Parameters for message/send operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    /// Optional tenant for multi-tenancy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// The message to send
    pub message: Message,
    /// Optional request configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<SendMessageConfiguration>,
    /// Custom metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Configuration for message send requests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageConfiguration {
    /// Preferred output MIME types
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_output_modes: Option<Vec<String>>,
    /// Push notification configuration for this request
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_notification_config: Option<PushNotificationConfig>,
    /// Message history depth (0 = omit, None = server default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
    /// Wait for task completion (default: false)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking: Option<bool>,
    /// Return immediately without waiting for completion (default: false).
    /// When true, the server returns the task in its current state even if non-terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_immediately: Option<bool>,
}

/// Parameters for tasks/get operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GetTaskRequest {
    /// Task ID
    pub id: String,
    /// Message history depth
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
    /// Optional tenant
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Parameters for tasks/cancel operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CancelTaskRequest {
    /// Task ID
    pub id: String,
    /// Optional tenant
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Parameters for tasks/list operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListTasksRequest {
    /// Filter by context ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Filter by task state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TaskState>,
    /// Results per page (1-100, default 50)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// Pagination cursor
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    /// History depth per task
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
    /// Filter by status timestamp after (ISO 8601 or millis)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_timestamp_after: Option<i64>,
    /// Include artifacts in response
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_artifacts: Option<bool>,
    /// Optional tenant
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Response for tasks/list operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TaskListResponse {
    /// Tasks matching the query
    pub tasks: Vec<Task>,
    /// Empty string if this is the final page
    pub next_page_token: String,
    /// Requested page size
    pub page_size: u32,
    /// Total matching tasks
    pub total_size: u32,
}

/// Parameters for tasks/subscribe operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeToTaskRequest {
    /// Task ID
    pub id: String,
    /// Optional tenant
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Push notification configuration per proto spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PushNotificationConfig {
    /// Configuration identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Webhook URL to receive notifications
    pub url: String,
    /// Token for webhook authentication
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Authentication details for webhook delivery
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<AuthenticationInfo>,
}

/// Authentication info for push notification delivery per proto spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInfo {
    /// Auth scheme (e.g., "bearer", "api_key")
    pub scheme: String,
    /// Credentials (e.g., token value) — optional in RC 1.0
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
}

/// Wrapper for push notification config with task context
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TaskPushNotificationConfig {
    /// Configuration ID
    pub id: String,
    /// Associated task ID
    pub task_id: String,
    /// The push notification configuration
    pub push_notification_config: PushNotificationConfig,
    /// Optional tenant
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Parameters for tasks/pushNotificationConfig/create
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreateTaskPushNotificationConfigRequest {
    /// Task ID
    pub task_id: String,
    /// Configuration identifier
    pub config_id: String,
    /// Configuration details
    pub push_notification_config: PushNotificationConfig,
    /// Optional tenant
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Parameters for tasks/pushNotificationConfig/get
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GetTaskPushNotificationConfigRequest {
    /// Config ID
    pub id: String,
    /// Task ID
    pub task_id: String,
    /// Optional tenant
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Parameters for tasks/pushNotificationConfig/list
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ListTaskPushNotificationConfigRequest {
    /// Task ID
    pub task_id: String,
    /// Max configs to return
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// Pagination cursor
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    /// Optional tenant
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Response for tasks/pushNotificationConfig/list
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ListTaskPushNotificationConfigResponse {
    /// Push notification configurations
    pub configs: Vec<TaskPushNotificationConfig>,
    /// Next page token
    #[serde(default)]
    pub next_page_token: String,
}

/// Parameters for tasks/pushNotificationConfig/delete
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeleteTaskPushNotificationConfigRequest {
    /// Config ID
    pub id: String,
    /// Task ID
    pub task_id: String,
    /// Optional tenant
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Parameters for agentCard/getExtended
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GetExtendedAgentCardRequest {
    /// Optional tenant
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

// ---------- Streaming event types ----------

/// Streaming response per proto spec — uses externally tagged oneof
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum StreamResponse {
    /// Complete task snapshot
    Task(Task),
    /// Direct message response
    Message(Message),
    /// Task status update event
    StatusUpdate(TaskStatusUpdateEvent),
    /// Task artifact update event
    ArtifactUpdate(TaskArtifactUpdateEvent),
}

/// Task status update event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatusUpdateEvent {
    /// Kind discriminator — always "status-update"
    #[serde(default = "default_status_update_kind")]
    pub kind: String,
    /// Task identifier
    pub task_id: String,
    /// Context identifier
    pub context_id: String,
    /// Updated status
    pub status: TaskStatus,
    /// Whether this is the final event in the stream
    #[serde(rename = "final", default)]
    pub is_final: bool,
    /// Custom metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Task artifact update event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TaskArtifactUpdateEvent {
    /// Kind discriminator — always "artifact-update"
    #[serde(default = "default_artifact_update_kind")]
    pub kind: String,
    /// Task identifier
    pub task_id: String,
    /// Context identifier
    pub context_id: String,
    /// New or updated artifact
    pub artifact: Artifact,
    /// Whether to append to existing artifact
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub append: Option<bool>,
    /// Whether this is the last chunk
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_chunk: Option<bool>,
    /// Custom metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Wire-format result for streaming events — the value inside each SSE JSON-RPC `result` field.
///
/// Uses externally tagged serialization per v1.0 proto-JSON:
/// - `{"statusUpdate": {...}}`, `{"artifactUpdate": {...}}`, `{"task": {...}}`, `{"message": {...}}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum StreamingMessageResult {
    StatusUpdate(TaskStatusUpdateEvent),
    ArtifactUpdate(TaskArtifactUpdateEvent),
    Task(Task),
    Message(Message),
}

// ---------- Helper functions ----------

/// Create a new message with text content
pub fn new_message(role: Role, text: &str, context_id: Option<String>) -> Message {
    Message {
        kind: "message".to_string(),
        message_id: Uuid::new_v4().to_string(),
        context_id,
        task_id: None,
        role,
        parts: vec![Part::text(text)],
        metadata: None,
        extensions: vec![],
        reference_task_ids: None,
    }
}

/// Create a completed task with text response
pub fn completed_task_with_text(user_message: Message, reply_text: &str) -> Task {
    let context_id = user_message
        .context_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let task_id = Uuid::new_v4().to_string();
    let agent_msg = new_message(Role::Agent, reply_text, Some(context_id.clone()));

    Task {
        kind: "task".to_string(),
        id: task_id,
        context_id,
        status: TaskStatus {
            state: TaskState::Completed,
            message: Some(agent_msg.clone()),
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
        },
        history: Some(vec![user_message, agent_msg]),
        artifacts: None,
        metadata: None,
    }
}

/// Generate ISO 8601 timestamp
pub fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Validate task ID format (UUID)
pub fn validate_task_id(id: &str) -> bool {
    Uuid::parse_str(id).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_helpers_round_trip() {
        let resp = success(serde_json::json!(1), serde_json::json!({"ok": true}));
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.error.is_none());
        assert!(resp.result.is_some());
    }

    #[test]
    fn task_state_is_terminal() {
        assert!(TaskState::Completed.is_terminal());
        assert!(TaskState::Failed.is_terminal());
        assert!(TaskState::Canceled.is_terminal());
        assert!(TaskState::Rejected.is_terminal());
        assert!(!TaskState::Working.is_terminal());
        assert!(!TaskState::Submitted.is_terminal());
        assert!(!TaskState::InputRequired.is_terminal());
    }

    #[test]
    fn task_state_serialization() {
        let state = TaskState::Working;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""working""#);

        // v0.3 style round-trips
        let parsed: TaskState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TaskState::Working);

        // v1.0 protobuf style still deserializes via alias
        let parsed: TaskState = serde_json::from_str(r#""TASK_STATE_WORKING""#).unwrap();
        assert_eq!(parsed, TaskState::Working);
    }

    #[test]
    fn role_serialization() {
        let role = Role::User;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, r#""user""#);

        // v1.0 protobuf style still deserializes via alias
        let parsed: Role = serde_json::from_str(r#""ROLE_USER""#).unwrap();
        assert_eq!(parsed, Role::User);
    }

    #[test]
    fn message_serialization() {
        let msg = new_message(Role::User, "hello", Some("ctx-123".to_string()));
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.role, Role::User);
        assert_eq!(parsed.parts.len(), 1);
        assert_eq!(parsed.parts[0].as_text(), Some("hello"));

        // Verify camelCase field names
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("messageId").is_some());
        assert!(value.get("contextId").is_some());
    }

    #[test]
    fn task_serialization() {
        let user_msg = new_message(Role::User, "test", None);
        let task = completed_task_with_text(user_msg, "response");
        let json = serde_json::to_string(&task).unwrap();
        let parsed: Task = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status.state, TaskState::Completed);
        assert!(parsed.history.is_some());
        assert_eq!(parsed.history.unwrap().len(), 2);

        // Verify camelCase
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("contextId").is_some());
    }

    #[test]
    fn part_text_serialization() {
        let part = Part::text("hello");
        let json = serde_json::to_string(&part).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value.get("kind").unwrap().as_str().unwrap(), "text");
        assert_eq!(value.get("text").unwrap().as_str().unwrap(), "hello");
    }

    #[test]
    fn part_text_round_trip() {
        let part = Part::text("hello");
        let json = serde_json::to_string(&part).unwrap();
        let parsed: Part = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, part);
        assert_eq!(parsed.as_text(), Some("hello"));
    }

    #[test]
    fn part_file_uri_serialization() {
        let part = Part::file_uri("https://example.com/file.pdf", "application/pdf");
        let json = serde_json::to_string(&part).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value.get("kind").unwrap().as_str().unwrap(), "file");
        let file = value.get("file").unwrap();
        assert_eq!(
            file.get("uri").unwrap().as_str().unwrap(),
            "https://example.com/file.pdf"
        );
        assert_eq!(
            file.get("mimeType").unwrap().as_str().unwrap(),
            "application/pdf"
        );
    }

    #[test]
    fn part_data_serialization() {
        let part = Part::data(serde_json::json!({"key": "value"}));
        let json = serde_json::to_string(&part).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value.get("kind").unwrap().as_str().unwrap(), "data");
        assert_eq!(
            value.get("data").unwrap(),
            &serde_json::json!({"key": "value"})
        );
    }

    #[test]
    fn part_deserialization_from_wire_format() {
        // v1.0 flat format (no kind)
        let text: Part = serde_json::from_str(r#"{"text":"hello"}"#).unwrap();
        assert_eq!(text.as_text(), Some("hello"));

        let file: Part = serde_json::from_str(
            r#"{"file":{"uri":"https://example.com/f.pdf","mimeType":"application/pdf"}}"#,
        )
        .unwrap();
        match &file {
            Part::File { file, .. } => {
                assert_eq!(file.uri.as_deref(), Some("https://example.com/f.pdf"));
                assert_eq!(file.mime_type.as_deref(), Some("application/pdf"));
            }
            _ => panic!("expected File part"),
        }

        let data: Part = serde_json::from_str(r#"{"data":{"k":"v"}}"#).unwrap();
        match &data {
            Part::Data { data, .. } => assert_eq!(data, &serde_json::json!({"k": "v"})),
            _ => panic!("expected Data part"),
        }

        // v0.3 kind-discriminated format (backward compat)
        let text_v03: Part =
            serde_json::from_str(r#"{"kind":"text","text":"hello v03"}"#).unwrap();
        assert_eq!(text_v03.as_text(), Some("hello v03"));
    }

    #[test]
    fn agent_card_with_security() {
        let card = AgentCard {
            name: "Test Agent".to_string(),
            description: "Test description".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: "https://example.com/v1/rpc".to_string(),
                protocol_binding: "JSONRPC".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                tenant: None,
            }],
            provider: Some(AgentProvider {
                organization: "Test Org".to_string(),
                url: "https://example.com".to_string(),
            }),
            version: PROTOCOL_VERSION.to_string(),
            documentation_url: None,
            capabilities: AgentCapabilities::default(),
            security_schemes: {
                let mut m = HashMap::new();
                m.insert(
                    "apiKey".to_string(),
                    SecurityScheme::ApiKeySecurityScheme(ApiKeySecurityScheme {
                        name: "X-API-Key".to_string(),
                        location: "header".to_string(),
                        description: None,
                    }),
                );
                m
            },
            security_requirements: vec![],
            default_input_modes: vec![],
            default_output_modes: vec![],
            skills: vec![],
            signatures: vec![],
            icon_url: None,
        };

        let json = serde_json::to_string(&card).unwrap();
        let parsed: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Test Agent");
        assert_eq!(parsed.security_schemes.len(), 1);
        assert_eq!(parsed.endpoint(), Some("https://example.com/v1/rpc"));

        // Verify camelCase
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("supportedInterfaces").is_some());
        assert!(value.get("securitySchemes").is_some());
        assert!(value.get("securityRequirements").is_some());
    }

    #[test]
    fn validate_task_id_helper() {
        let valid_uuid = Uuid::new_v4().to_string();
        assert!(validate_task_id(&valid_uuid));
        assert!(!validate_task_id("not-a-uuid"));
    }

    #[test]
    fn error_codes() {
        use errors::*;
        assert_eq!(message_for_code(TASK_NOT_FOUND), "Task not found");
        assert_eq!(
            message_for_code(VERSION_NOT_SUPPORTED),
            "Protocol version not supported"
        );
        assert_eq!(
            message_for_code(INVALID_AGENT_RESPONSE),
            "Invalid agent response"
        );
        assert_eq!(
            message_for_code(EXTENSION_SUPPORT_REQUIRED),
            "Extension support required"
        );
        assert_eq!(message_for_code(999), "Unknown error");
    }

    #[test]
    fn send_message_result_serialization() {
        let task = Task {
            kind: "task".to_string(),
            id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };

        // SendMessageResult (wire format) uses externally tagged: {"task": {...}}
        let result = SendMessageResult::Task(task.clone());
        let json = serde_json::to_string(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("task").is_some(), "should have task wrapper key");
        let inner = value.get("task").unwrap();
        assert_eq!(inner.get("id").unwrap().as_str().unwrap(), "t-1");

        // Round-trip
        let parsed: SendMessageResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SendMessageResult::Task(task));
    }

    #[test]
    fn stream_response_serialization() {
        let event = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
            kind: "status-update".to_string(),
            task_id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            is_final: false,
            metadata: None,
        });
        let json = serde_json::to_string(&event).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("statusUpdate").is_some());
    }

    #[test]
    fn push_notification_config_serialization() {
        let config = PushNotificationConfig {
            id: Some("cfg-1".to_string()),
            url: "https://example.com/webhook".to_string(),
            token: Some("secret".to_string()),
            authentication: Some(AuthenticationInfo {
                scheme: "bearer".to_string(),
                credentials: Some("token123".to_string()),
            }),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PushNotificationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url, "https://example.com/webhook");
        assert_eq!(parsed.authentication.unwrap().scheme, "bearer");
    }
}
