//! Message handler trait for pluggable backends
//!
//! This module defines the core abstraction for implementing A2A agent backends.
//! Implement the `MessageHandler` trait to create your own agent backend.

use a2a_rs_core::{AgentCard, Message, SendMessageResponse, Task};
use async_trait::async_trait;
use std::sync::Arc;

/// Result type for handler operations
pub type HandlerResult<T> = Result<T, HandlerError>;

/// Error type for handler operations
#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error("Processing failed: {message}")]
    ProcessingFailed {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    #[error("Backend unavailable: {message}")]
    BackendUnavailable {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    #[error("Authentication required: {0}")]
    AuthRequired(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl HandlerError {
    pub fn processing_failed(msg: impl Into<String>) -> Self {
        Self::ProcessingFailed {
            message: msg.into(),
            source: None,
        }
    }

    pub fn processing_failed_with<E>(msg: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::ProcessingFailed {
            message: msg.into(),
            source: Some(Box::new(source)),
        }
    }

    pub fn backend_unavailable(msg: impl Into<String>) -> Self {
        Self::BackendUnavailable {
            message: msg.into(),
            source: None,
        }
    }

    pub fn backend_unavailable_with<E>(msg: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::BackendUnavailable {
            message: msg.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// Authentication context passed to handlers
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub user_id: String,
    pub access_token: String,
    pub metadata: Option<serde_json::Value>,
}

/// Trait for implementing A2A message handlers
///
/// Returns `SendMessageResponse` which can be either a Task or a direct Message.
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Process an incoming A2A message and return a Task or Message
    async fn handle_message(
        &self,
        message: Message,
        auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse>;

    /// Return the agent card for this handler
    fn agent_card(&self, base_url: &str) -> AgentCard;

    /// Optional: Handle task cancellation
    async fn cancel_task(&self, _task_id: &str) -> HandlerResult<()> {
        Ok(())
    }

    /// Optional: Check if handler supports streaming
    fn supports_streaming(&self) -> bool {
        false
    }

    /// Optional: Return an extended agent card for authenticated requests
    async fn extended_agent_card(
        &self,
        _base_url: &str,
        _auth: &AuthContext,
    ) -> Option<AgentCard> {
        None
    }
}

/// A simple echo handler for testing and demos
pub struct EchoHandler {
    pub prefix: String,
    pub agent_name: String,
}

impl Default for EchoHandler {
    fn default() -> Self {
        Self {
            prefix: "echo:".to_string(),
            agent_name: "Echo Agent".to_string(),
        }
    }
}

#[async_trait]
impl MessageHandler for EchoHandler {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        use a2a_rs_core::{now_iso8601, Part, Role, TaskState, TaskStatus};
        use uuid::Uuid;

        let text = message
            .parts
            .iter()
            .filter_map(|p| p.text.as_deref())
            .collect::<Vec<_>>()
            .join("\n");

        let task_id = Uuid::new_v4().to_string();
        let context_id = message.context_id.clone().unwrap_or_default();

        let response = Message {
            message_id: Uuid::new_v4().to_string(),
            context_id: message.context_id.clone(),
            task_id: None,
            role: Role::Agent,
            parts: vec![Part::text(format!("{} {}", self.prefix, text))],
            metadata: None,
            extensions: vec![],
            reference_task_ids: None,
        };

        Ok(SendMessageResponse::Task(Task {
            id: task_id,
            context_id,
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: Some(now_iso8601()),
            },
            history: Some(vec![message, response]),
            artifacts: None,
            metadata: None,
        }))
    }

    fn agent_card(&self, base_url: &str) -> AgentCard {
        use a2a_rs_core::{AgentCapabilities, AgentInterface, AgentProvider, AgentSkill, PROTOCOL_VERSION};

        AgentCard {
            name: self.agent_name.clone(),
            description: "Simple echo agent for testing A2A protocol".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: format!("{}/v1/rpc", base_url),
                protocol_binding: "JSONRPC".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                tenant: None,
            }],
            provider: Some(AgentProvider {
                organization: "A2A Demo".to_string(),
                url: "https://github.com/a2a-protocol".to_string(),
            }),
            version: PROTOCOL_VERSION.to_string(),
            documentation_url: None,
            capabilities: AgentCapabilities::default(),
            security_schemes: Default::default(),
            security_requirements: vec![],
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            skills: vec![AgentSkill {
                id: "echo".to_string(),
                name: "Echo".to_string(),
                description: "Echoes back the user's message".to_string(),
                tags: vec!["demo".to_string(), "echo".to_string()],
                examples: vec![],
                input_modes: vec![],
                output_modes: vec![],
                security_requirements: vec![],
            }],
            signatures: vec![],
            icon_url: None,
        }
    }
}

/// Type alias for a boxed handler
pub type BoxedHandler = Arc<dyn MessageHandler>;
