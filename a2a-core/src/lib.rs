//! Core data structures for A2A v0.3.0 JSON-RPC over HTTP.
//! Provides shared types for server/client plus minimal helpers for JSON-RPC envelopes and error codes.
//! Aligned with the authoritative proto definition (specification/a2a.proto).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "0.3.0";
pub const TRANSPORT_JSONRPC: &str = "JSONRPC";

// ---------- Agent Card ----------

/// Complete Agent Card per A2A 0.3.0 proto spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    /// Agent display name (primary identifier per proto)
    pub name: String,
    /// Optional description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Supported transport interfaces (contains endpoint URLs)
    #[serde(default)]
    pub supported_interfaces: Vec<AgentInterface>,
    /// Provider/organization information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<AgentProvider>,
    /// Supported A2A protocol version (e.g., "0.3")
    pub version: String,
    /// Link to documentation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    /// Feature flags
    #[serde(default)]
    pub capabilities: AgentCapabilities,
    /// Named authentication schemes (map from scheme name to scheme)
    #[serde(default)]
    pub security_schemes: HashMap<String, SecurityScheme>,
    /// Required auth per operation
    #[serde(default)]
    pub security_requirements: Vec<SecurityRequirement>,
    /// Default accepted input MIME types
    #[serde(default)]
    pub default_input_modes: Vec<String>,
    /// Default output MIME types
    #[serde(default)]
    pub default_output_modes: Vec<String>,
    /// Agent capabilities/functions
    #[serde(default)]
    pub skills: Vec<AgentSkill>,
    /// Cryptographic signatures for verification
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
            .find(|i| i.transport.eq_ignore_ascii_case("jsonrpc"))
            .map(|i| i.url.as_str())
    }
}

/// Agent interface / transport endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    pub url: String,
    pub transport: String,
}

/// Provider/organization information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
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

/// Authentication scheme definition (OpenAPI-style tagged union)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
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
    #[serde(rename = "http")]
    Http {
        scheme: String,
        #[serde(default, skip_serializing_if = "Option::is_none", rename = "bearerFormat")]
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
        #[serde(rename = "openIdConnectUrl")]
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
#[serde(rename_all = "camelCase")]
pub struct OAuth2Flows {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<OAuth2Flow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_credentials: Option<OAuth2Flow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_code: Option<OAuth2Flow>,
    /// Deprecated per spec
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implicit: Option<OAuth2Flow>,
    /// Deprecated per spec
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<OAuth2Flow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct SecurityRequirement {
    /// Name of the security scheme
    pub scheme_name: String,
    /// Required scopes (for OAuth2/OIDC)
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Cryptographic signature for Agent Card verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCardSignature {
    /// Signature algorithm (e.g., "RS256", "ES256")
    pub algorithm: String,
    /// Base64-encoded signature
    pub value: String,
    /// Public key or key ID for verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
}

/// Agent skill/capability definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
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

/// Part content — flat struct matching proto3 oneof serialization.
///
/// Exactly one content field (text, raw, url, or data) should be set.
/// Shared fields (metadata, filename, media_type) can accompany any content type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    /// Text content (plain text or markdown)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Raw bytes content (base64-encoded)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// URL reference to content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Structured JSON data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Part-level metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Optional filename
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// MIME type (e.g., "text/plain", "image/png", "application/json")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

impl Part {
    /// Create a text part
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            raw: None,
            url: None,
            data: None,
            metadata: None,
            filename: None,
            media_type: None,
        }
    }

    /// Create a URL reference part
    pub fn url(url: impl Into<String>, media_type: impl Into<String>) -> Self {
        Self {
            text: None,
            raw: None,
            url: Some(url.into()),
            data: None,
            metadata: None,
            filename: None,
            media_type: Some(media_type.into()),
        }
    }

    /// Create a structured data part
    pub fn data(data: serde_json::Value, media_type: impl Into<String>) -> Self {
        Self {
            text: None,
            raw: None,
            url: None,
            data: Some(data),
            metadata: None,
            filename: None,
            media_type: Some(media_type.into()),
        }
    }

    /// Create a raw bytes part (base64-encoded)
    pub fn raw(raw: impl Into<String>, media_type: impl Into<String>) -> Self {
        Self {
            text: None,
            raw: Some(raw.into()),
            url: None,
            data: None,
            metadata: None,
            filename: None,
            media_type: Some(media_type.into()),
        }
    }
}

// ---------- Messages, Tasks, Artifacts ----------

/// Message role per proto spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum Role {
    #[serde(rename = "ROLE_UNSPECIFIED")]
    Unspecified,
    #[serde(rename = "ROLE_USER")]
    User,
    #[serde(rename = "ROLE_AGENT")]
    Agent,
}

/// Message structure per A2A 0.3.0 proto spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Message {
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    /// Optional related task IDs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_task_ids: Option<Vec<String>>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
}

/// Task lifecycle state per proto spec
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaskState {
    #[serde(rename = "TASK_STATE_UNSPECIFIED")]
    Unspecified,
    #[serde(rename = "TASK_STATE_SUBMITTED")]
    Submitted,
    #[serde(rename = "TASK_STATE_WORKING")]
    Working,
    #[serde(rename = "TASK_STATE_COMPLETED")]
    Completed,
    #[serde(rename = "TASK_STATE_FAILED")]
    Failed,
    #[serde(rename = "TASK_STATE_CANCELED")]
    Canceled,
    #[serde(rename = "TASK_STATE_INPUT_REQUIRED")]
    InputRequired,
    #[serde(rename = "TASK_STATE_REJECTED")]
    Rejected,
    #[serde(rename = "TASK_STATE_AUTH_REQUIRED")]
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

/// Task resource per A2A 0.3.0 proto spec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Task {
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

/// Response from SendMessage — can be a Task or direct Message per proto
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SendMessageResponse {
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
#[serde(rename_all = "camelCase")]
pub struct MessageSendParams {
    /// Optional tenant for multi-tenancy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
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
#[serde(rename_all = "camelCase")]
pub struct MessageSendConfiguration {
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
}

/// Parameters for tasks/get operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TaskQueryParams {
    /// Resource name: "tasks/{task_id}"
    pub name: String,
    /// Message history depth
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
}

/// Parameters for tasks/cancel operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TaskCancelParams {
    /// Resource name: "tasks/{task_id}"
    pub name: String,
}

/// Parameters for tasks/list operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
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
    /// Filter by status timestamp after (ISO 8601 or millis)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_timestamp_after: Option<i64>,
    /// Include artifacts in response
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_artifacts: Option<bool>,
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
pub struct TaskSubscribeParams {
    /// Resource name: "tasks/{task_id}"
    pub name: String,
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
    /// Credentials (e.g., token value)
    pub credentials: String,
}

/// Parameters for tasks/pushNotificationConfig/create
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PushNotificationConfigCreateParams {
    /// Parent resource: "tasks/{task_id}"
    pub parent: String,
    /// Configuration identifier
    pub config_id: String,
    /// Configuration details
    pub config: PushNotificationConfig,
}

/// Parameters for tasks/pushNotificationConfig/get
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PushNotificationConfigGetParams {
    /// Resource name: "tasks/{task_id}/pushNotificationConfigs/{config_id}"
    pub name: String,
}

/// Parameters for tasks/pushNotificationConfig/list
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct PushNotificationConfigListResponse {
    /// Push notification configurations
    pub configs: Vec<PushNotificationConfig>,
    /// Next page token
    #[serde(default)]
    pub next_page_token: String,
}

/// Parameters for tasks/pushNotificationConfig/delete
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PushNotificationConfigDeleteParams {
    /// Resource name: "tasks/{task_id}/pushNotificationConfigs/{config_id}"
    pub name: String,
}

// ---------- Streaming event types ----------

/// Streaming response per proto spec — uses externally tagged oneof
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum StreamEvent {
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
#[serde(rename_all = "camelCase")]
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
        s.split('/').next().unwrap_or(s).to_string()
    })
}

/// Parsed A2A resource name
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceName {
    pub resource_type: String,
    pub resource_id: String,
    pub sub_resource: Option<(String, String)>,
}

impl ResourceName {
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

    pub fn task_id(&self) -> Option<&str> {
        if self.resource_type == "tasks" {
            Some(&self.resource_id)
        } else {
            None
        }
    }

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
        assert_eq!(json, r#""TASK_STATE_WORKING""#);

        let parsed: TaskState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TaskState::Working);
    }

    #[test]
    fn role_serialization() {
        let role = Role::User;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, r#""ROLE_USER""#);
    }

    #[test]
    fn message_serialization() {
        let msg = new_message(Role::User, "hello", Some("ctx-123".to_string()));
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.role, Role::User);
        assert_eq!(parsed.parts.len(), 1);
        assert_eq!(parsed.parts[0].text.as_deref(), Some("hello"));

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
        assert_eq!(value.get("text").unwrap().as_str().unwrap(), "hello");
        // Should NOT have a "type" discriminator
        assert!(value.get("type").is_none());
    }

    #[test]
    fn part_url_serialization() {
        let part = Part::url("https://example.com/file.pdf", "application/pdf");
        let json = serde_json::to_string(&part).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value.get("url").unwrap().as_str().unwrap(), "https://example.com/file.pdf");
        assert_eq!(value.get("mediaType").unwrap().as_str().unwrap(), "application/pdf");
    }

    #[test]
    fn agent_card_with_security() {
        let card = AgentCard {
            name: "Test Agent".to_string(),
            description: Some("Test description".to_string()),
            supported_interfaces: vec![AgentInterface {
                url: "https://example.com/v1/rpc".to_string(),
                transport: "JSONRPC".to_string(),
            }],
            provider: Some(AgentProvider {
                name: "Test Org".to_string(),
                url: Some("https://example.com".to_string()),
                email: None,
            }),
            version: PROTOCOL_VERSION.to_string(),
            documentation_url: None,
            capabilities: AgentCapabilities::default(),
            security_schemes: {
                let mut m = HashMap::new();
                m.insert("apiKey".to_string(), SecurityScheme::ApiKey {
                    name: "X-API-Key".to_string(),
                    location: ApiKeyLocation::Header,
                    description: None,
                });
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
    fn extract_task_id_helper() {
        assert_eq!(extract_task_id("tasks/abc-123"), Some("abc-123".to_string()));
        assert_eq!(extract_task_id("abc-123"), None);
        assert_eq!(extract_task_id("tasks/"), Some("".to_string()));
        assert_eq!(
            extract_task_id("tasks/abc-123/pushNotificationConfigs/cfg-1"),
            Some("abc-123".to_string())
        );
    }

    #[test]
    fn resource_name_parsing() {
        let res = ResourceName::parse("tasks/abc-123").unwrap();
        assert_eq!(res.resource_type, "tasks");
        assert_eq!(res.resource_id, "abc-123");
        assert!(res.sub_resource.is_none());
        assert_eq!(res.task_id(), Some("abc-123"));

        let res = ResourceName::parse("tasks/abc-123/pushNotificationConfigs/cfg-1").unwrap();
        assert_eq!(res.task_id(), Some("abc-123"));
        assert_eq!(res.push_notification_config_id(), Some("cfg-1"));

        assert!(ResourceName::parse("tasks").is_none());
        assert!(ResourceName::parse("").is_none());
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
        assert_eq!(message_for_code(VERSION_NOT_SUPPORTED), "Protocol version not supported");
        assert_eq!(message_for_code(INVALID_AGENT_RESPONSE), "Invalid agent response");
        assert_eq!(message_for_code(999), "Unknown error");
    }

    #[test]
    fn send_message_response_serialization() {
        let task = Task {
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
        let resp = SendMessageResponse::Task(task);
        let json = serde_json::to_string(&resp).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("task").is_some());
    }

    #[test]
    fn stream_event_serialization() {
        let event = StreamEvent::StatusUpdate(TaskStatusUpdateEvent {
            task_id: "t-1".to_string(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            timestamp: None,
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
                credentials: "token123".to_string(),
            }),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PushNotificationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url, "https://example.com/webhook");
        assert_eq!(parsed.authentication.unwrap().scheme, "bearer");
    }
}
