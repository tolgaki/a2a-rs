//! Core data structures for A2A v0.3.0 JSON-RPC over HTTP.
//! Provides shared types for server/client plus minimal helpers for JSON-RPC envelopes and error codes.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "0.3.0";
pub const TRANSPORT_JSONRPC: &str = "JSONRPC";

// ---------- Agent Card ----------

/// Complete Agent Card per A2A 0.3.0 spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCard {
    /// Unique agent identifier
    pub id: String,
    /// Display name
    pub name: String,
    /// Provider/organization information
    pub provider: AgentProvider,
    /// Supported A2A protocol version (e.g., "0.3")
    pub protocol_version: String,
    /// Optional capability summary
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Service endpoint URL
    pub endpoint: String,
    /// Feature flags
    pub capabilities: AgentCapabilities,
    /// Available authentication methods
    #[serde(default)]
    pub security_schemes: Vec<SecurityScheme>,
    /// Required auth per operation
    #[serde(default)]
    pub security: Vec<SecurityRequirement>,
    /// Agent capabilities/functions
    #[serde(default)]
    pub skills: Vec<AgentSkill>,
    /// Extended functionality
    #[serde(default)]
    pub extensions: Vec<AgentExtension>,
    /// Supports authenticated extended card access
    #[serde(default)]
    pub supports_extended_agent_card: bool,
    /// Cryptographic signature for verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<AgentCardSignature>,

    // Legacy fields for backward compatibility
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_interfaces: Vec<AgentInterface>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_input_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_output_modes: Vec<String>,
}

/// Provider/organization information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentProvider {
    /// Organization name
    pub name: String,
    /// Provider URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Contact email
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// Authentication scheme definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum SecurityScheme {
    /// API key in header/query/cookie
    #[serde(rename = "apiKey")]
    ApiKey {
        name: String,
        #[serde(rename = "in")]
        location: ApiKeyLocation,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    /// HTTP Basic or Bearer authentication
    Http {
        scheme: String, // "basic", "bearer"
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bearer_format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    /// OAuth 2.0 flows
    #[serde(rename = "oauth2")]
    OAuth2 {
        flows: OAuth2Flows,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    /// OpenID Connect Discovery
    #[serde(rename = "openIdConnect")]
    OpenIdConnect {
        open_id_connect_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    /// Mutual TLS
    #[serde(rename = "mutualTLS")]
    MutualTls {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ApiKeyLocation {
    Header,
    Query,
    Cookie,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct OAuth2Flows {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<OAuth2Flow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_credentials: Option<OAuth2Flow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implicit: Option<OAuth2Flow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<OAuth2Flow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OAuth2Flow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Security requirement for operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityRequirement {
    /// Name of the security scheme
    pub scheme_name: String,
    /// Required scopes (for OAuth2/OIDC)
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Cryptographic signature for Agent Card verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCardSignature {
    /// Signature algorithm (e.g., "RS256", "ES256")
    pub algorithm: String,
    /// Base64-encoded signature
    pub value: String,
    /// Public key or key ID for verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentInterface {
    pub url: String,
    pub transport: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AgentCapabilities {
    #[serde(default)]
    pub streaming: bool,
    #[serde(default)]
    pub push_notifications: bool,
    #[serde(default)]
    pub state_transition_history: bool,
    #[serde(default)]
    pub extensions: Vec<AgentExtension>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentExtension {
    pub uri: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: Option<bool>,
}

/// Agent skill/capability definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentSkill {
    /// Unique skill identifier
    pub id: String,
    /// Display name
    pub name: String,
    /// Capability description
    pub description: String,
    /// Input JSON schema
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    /// Output JSON schema
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// Classification tags
    #[serde(default)]
    pub tags: Vec<String>,
}

// ---------- Content Parts ----------

/// Message content part (text, file, or structured data)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum Part {
    /// Plain text or markdown content
    #[serde(rename = "text")]
    Text(TextPart),
    /// File reference or inline content
    #[serde(rename = "file")]
    File(FilePart),
    /// Structured JSON data
    #[serde(rename = "data")]
    Data(DataPart),
}

/// Text content part
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TextPart {
    /// Text content (plain text or markdown)
    pub text: String,
}

/// File content part per spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FilePart {
    /// File URL or reference
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Base64-encoded file bytes (alternative to url)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    /// MIME type (e.g., "image/png", "application/pdf")
    #[serde(rename = "mimeType")]
    pub media_type: String,
    /// Optional file name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Structured data part
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DataPart {
    /// MIME type (typically "application/json")
    pub media_type: String,
    /// Structured data payload
    pub data: serde_json::Value,
}

// ---------- Messages, Tasks, Artifacts ----------

/// Message role
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Role {
    /// User-generated message
    User,
    /// Agent-generated response
    Agent,
}

/// Message structure per A2A 0.3.0 spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    /// Unique message identifier
    pub id: String,
    /// Message role (user or agent)
    pub role: Role,
    /// Message content parts
    pub parts: Vec<Part>,
    /// Optional conversation context ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Optional related task IDs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_task_ids: Option<Vec<String>>,
    /// Custom metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Artifact output from task processing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Artifact {
    /// Unique artifact identifier
    pub id: String,
    /// Artifact content parts
    pub parts: Vec<Part>,
    /// Optional display name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Custom metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Task lifecycle state per A2A 0.3.0 spec
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum TaskState {
    /// Unspecified/default state
    Unspecified,
    /// Task has been submitted
    Submitted,
    /// Agent is processing the task
    Working,
    /// Task completed successfully
    Completed,
    /// Task failed with error
    Failed,
    /// Task was canceled
    Cancelled,
    /// Agent requires user input to continue
    InputRequired,
    /// Task was rejected (e.g., validation failed)
    Rejected,
    /// Authentication required to proceed
    AuthRequired,
}

/// Task status information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// Task resource per A2A 0.3.0 spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task {
    /// Unique task identifier (UUID)
    pub id: String,
    /// Context identifier for grouping related interactions
    pub context_id: String,
    /// Current task status
    pub status: TaskStatus,
    /// Optional message history
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<Message>>,
    /// Optional output artifacts
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<Artifact>>,
    /// Custom metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl TaskState {
    /// Check if state is terminal (no further updates expected)
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskState::Completed | TaskState::Failed | TaskState::Cancelled | TaskState::Rejected
        )
    }
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
    /// Task not found or not accessible
    pub const TASK_NOT_FOUND: i32 = -32001;
    /// Task is in non-cancelable state
    pub const TASK_NOT_CANCELABLE: i32 = -32002;
    /// Push notifications not supported by agent
    pub const PUSH_NOTIFICATION_NOT_SUPPORTED: i32 = -32003;
    /// Operation or feature not supported
    pub const UNSUPPORTED_OPERATION: i32 = -32004;
    /// Content type/media type not accepted
    pub const CONTENT_TYPE_NOT_SUPPORTED: i32 = -32005;
    /// Extended agent card not configured
    pub const EXTENDED_AGENT_CARD_NOT_CONFIGURED: i32 = -32006;
    /// Protocol version not supported
    pub const VERSION_NOT_SUPPORTED: i32 = -32007;

    /// Get error message for code
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

pub fn error(id: serde_json::Value, code: i32, message: &str, data: Option<serde_json::Value>) -> JsonRpcResponse {
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
pub struct MessageSendParams {
    /// The message to send
    pub message: Message,
    /// Optional request configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<MessageSendConfiguration>,
    /// Custom metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Configuration for message send requests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MessageSendConfiguration {
    /// Preferred output MIME types
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_output_modes: Option<Vec<String>>,
    /// Message history depth (0 = omit, None = server default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
    /// Wait for task completion (default: false)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking: Option<bool>,
    /// Push notification configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_notification_config: Option<TaskPushNotificationConfig>,
}

/// Parameters for tasks/get operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskQueryParams {
    /// Resource name: "tasks/{task_id}"
    pub name: String,
    /// Message history depth
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
}

/// Parameters for tasks/cancel operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskCancelParams {
    /// Resource name: "tasks/{task_id}"
    pub name: String,
}

/// Parameters for tasks/list operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TaskListParams {
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
    /// Filter by last updated after (milliseconds since epoch)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated_after: Option<i64>,
    /// Include artifacts in response
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_artifacts: Option<bool>,
}

/// Response for tasks/list operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
pub struct TaskSubscribeParams {
    /// Resource name: "tasks/{task_id}"
    pub name: String,
}

/// Push notification configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskPushNotificationConfig {
    /// Webhook URL to receive notifications
    pub url: String,
    /// Optional custom headers for webhook requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// Event types to subscribe to
    #[serde(default)]
    pub event_types: Vec<String>,
}

/// Parameters for tasks/pushNotificationConfig/set
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PushNotificationConfigSetParams {
    /// Parent resource: "tasks/{task_id}"
    pub parent: String,
    /// Configuration identifier
    pub config_id: String,
    /// Configuration details
    pub config: TaskPushNotificationConfig,
}

/// Parameters for tasks/pushNotificationConfig/get
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PushNotificationConfigGetParams {
    /// Resource name: "tasks/{task_id}/pushNotificationConfigs/{config_id}"
    pub name: String,
}

/// Parameters for tasks/pushNotificationConfig/list
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PushNotificationConfigListParams {
    /// Parent resource: "tasks/{task_id}"
    pub parent: String,
    /// Max configs to return
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// Pagination cursor
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

/// Response for tasks/pushNotificationConfig/list
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PushNotificationConfigListResponse {
    /// Push notification configurations
    pub configs: Vec<TaskPushNotificationConfig>,
    /// Next page token
    #[serde(default)]
    pub next_page_token: String,
}

/// Parameters for tasks/pushNotificationConfig/delete
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PushNotificationConfigDeleteParams {
    /// Resource name: "tasks/{task_id}/pushNotificationConfigs/{config_id}"
    pub name: String,
}

// ---------- Streaming event types ----------

/// Event types for streaming responses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "eventType", rename_all = "camelCase")]
#[non_exhaustive]
pub enum StreamEvent {
    /// Task state or status update
    #[serde(rename = "taskStatusUpdate")]
    TaskStatusUpdate(TaskStatusUpdateEvent),
    /// New or updated artifact
    #[serde(rename = "taskArtifactUpdate")]
    TaskArtifactUpdate(TaskArtifactUpdateEvent),
    /// Complete task snapshot
    #[serde(rename = "task")]
    Task(Task),
    /// Direct message response
    #[serde(rename = "message")]
    Message(Message),
}

/// Task status update event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskStatusUpdateEvent {
    /// Task identifier
    pub task_id: String,
    /// Updated status
    pub status: TaskStatus,
    /// ISO 8601 timestamp
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Task artifact update event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskArtifactUpdateEvent {
    /// Task identifier
    pub task_id: String,
    /// New or updated artifact
    pub artifact: Artifact,
    /// ISO 8601 timestamp
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

// ---------- Helper functions ----------

/// Create a new message with text content
pub fn new_message(role: Role, text: &str, context_id: Option<String>) -> Message {
    Message {
        id: Uuid::new_v4().to_string(),
        role,
        parts: vec![Part::Text(TextPart {
            text: text.to_string(),
        })],
        context_id,
        reference_task_ids: None,
        metadata: None,
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

/// Extract task ID from resource name (e.g., "tasks/123" -> "123")
pub fn extract_task_id(resource_name: &str) -> Option<String> {
    resource_name.strip_prefix("tasks/").map(|s| {
        // Handle nested resources like "tasks/123/pushNotificationConfigs/..."
        s.split('/').next().unwrap_or(s).to_string()
    })
}

/// Parsed A2A resource name
///
/// Resource names follow the pattern: `{type}/{id}` or `{type}/{id}/{subtype}/{subid}`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceName {
    /// Resource type (e.g., "tasks")
    pub resource_type: String,
    /// Resource ID
    pub resource_id: String,
    /// Optional sub-resource (type, id)
    pub sub_resource: Option<(String, String)>,
}

impl ResourceName {
    /// Parse a resource name string
    ///
    /// Supports formats:
    /// - `"tasks/abc-123"` -> type="tasks", id="abc-123"
    /// - `"tasks/abc-123/pushNotificationConfigs/cfg-1"` -> with sub_resource
    pub fn parse(name: &str) -> Option<Self> {
        let parts: Vec<&str> = name.split('/').collect();
        match parts.as_slice() {
            [res_type, res_id] => Some(Self {
                resource_type: (*res_type).to_string(),
                resource_id: (*res_id).to_string(),
                sub_resource: None,
            }),
            [res_type, res_id, sub_type, sub_id, ..] => Some(Self {
                resource_type: (*res_type).to_string(),
                resource_id: (*res_id).to_string(),
                sub_resource: Some(((*sub_type).to_string(), (*sub_id).to_string())),
            }),
            _ => None,
        }
    }

    /// Get task ID if this is a task resource
    pub fn task_id(&self) -> Option<&str> {
        if self.resource_type == "tasks" {
            Some(&self.resource_id)
        } else {
            None
        }
    }

    /// Get push notification config ID if this is a config sub-resource
    pub fn push_notification_config_id(&self) -> Option<&str> {
        match &self.sub_resource {
            Some((sub_type, sub_id)) if sub_type == "pushNotificationConfigs" => Some(sub_id),
            _ => None,
        }
    }
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
        assert!(TaskState::Cancelled.is_terminal());
        assert!(TaskState::Rejected.is_terminal());
        assert!(!TaskState::Working.is_terminal());
        assert!(!TaskState::Submitted.is_terminal());
        assert!(!TaskState::InputRequired.is_terminal());
    }

    #[test]
    fn message_serialization() {
        let msg = new_message(Role::User, "hello", Some("ctx-123".to_string()));
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.role, Role::User);
        assert_eq!(parsed.parts.len(), 1);
        if let Part::Text(text_part) = &parsed.parts[0] {
            assert_eq!(text_part.text, "hello");
        } else {
            panic!("Expected TextPart");
        }
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
    }

    #[test]
    fn agent_card_with_security() {
        let card = AgentCard {
            id: "agent-1".to_string(),
            name: "Test Agent".to_string(),
            provider: AgentProvider {
                name: "Test Org".to_string(),
                url: Some("https://example.com".to_string()),
                email: None,
            },
            protocol_version: PROTOCOL_VERSION.to_string(),
            description: Some("Test description".to_string()),
            endpoint: "https://example.com/rpc".to_string(),
            capabilities: AgentCapabilities::default(),
            security_schemes: vec![SecurityScheme::ApiKey {
                name: "X-API-Key".to_string(),
                location: ApiKeyLocation::Header,
                description: None,
            }],
            security: vec![],
            skills: vec![],
            extensions: vec![],
            supports_extended_agent_card: false,
            signature: None,
            url: None,
            preferred_transport: None,
            additional_interfaces: vec![],
            default_input_modes: vec![],
            default_output_modes: vec![],
        };

        let json = serde_json::to_string(&card).unwrap();
        let parsed: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "agent-1");
        assert_eq!(parsed.security_schemes.len(), 1);
    }

    #[test]
    fn file_part_with_url() {
        let part = Part::File(FilePart {
            url: Some("https://example.com/file.pdf".to_string()),
            bytes: None,
            media_type: "application/pdf".to_string(),
            name: Some("document.pdf".to_string()),
        });

        let json = serde_json::to_string(&part).unwrap();
        let parsed: Part = serde_json::from_str(&json).unwrap();

        if let Part::File(fp) = parsed {
            assert_eq!(fp.media_type, "application/pdf");
            assert_eq!(fp.url, Some("https://example.com/file.pdf".to_string()));
        } else {
            panic!("Expected FilePart");
        }
    }

    #[test]
    fn extract_task_id_helper() {
        assert_eq!(
            extract_task_id("tasks/abc-123"),
            Some("abc-123".to_string())
        );
        assert_eq!(extract_task_id("abc-123"), None);
        assert_eq!(extract_task_id("tasks/"), Some("".to_string()));
        // Now handles nested resources
        assert_eq!(
            extract_task_id("tasks/abc-123/pushNotificationConfigs/cfg-1"),
            Some("abc-123".to_string())
        );
    }

    #[test]
    fn resource_name_parsing() {
        // Simple task resource
        let res = ResourceName::parse("tasks/abc-123").unwrap();
        assert_eq!(res.resource_type, "tasks");
        assert_eq!(res.resource_id, "abc-123");
        assert!(res.sub_resource.is_none());
        assert_eq!(res.task_id(), Some("abc-123"));

        // Task with push notification config sub-resource
        let res = ResourceName::parse("tasks/abc-123/pushNotificationConfigs/cfg-1").unwrap();
        assert_eq!(res.resource_type, "tasks");
        assert_eq!(res.resource_id, "abc-123");
        assert_eq!(res.sub_resource, Some(("pushNotificationConfigs".to_string(), "cfg-1".to_string())));
        assert_eq!(res.task_id(), Some("abc-123"));
        assert_eq!(res.push_notification_config_id(), Some("cfg-1"));

        // Invalid - single segment
        assert!(ResourceName::parse("tasks").is_none());
        assert!(ResourceName::parse("").is_none());

        // Non-task resource
        let res = ResourceName::parse("users/user-1").unwrap();
        assert_eq!(res.resource_type, "users");
        assert!(res.task_id().is_none());
    }

    #[test]
    fn validate_task_id_helper() {
        let valid_uuid = Uuid::new_v4().to_string();
        assert!(validate_task_id(&valid_uuid));
        assert!(!validate_task_id("not-a-uuid"));
        assert!(!validate_task_id(""));
    }

    #[test]
    fn error_codes() {
        use errors::*;
        assert_eq!(message_for_code(TASK_NOT_FOUND), "Task not found");
        assert_eq!(message_for_code(VERSION_NOT_SUPPORTED), "Protocol version not supported");
        assert_eq!(message_for_code(999), "Unknown error");
    }
}
