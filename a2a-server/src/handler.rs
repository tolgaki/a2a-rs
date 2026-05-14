//! Message handler trait for pluggable backends
//!
//! This module defines the core abstraction for implementing A2A agent backends.
//! Implement the `MessageHandler` trait to create your own agent backend.

use a2a_rs_core::{AgentCard, Message, SendMessageResponse, StreamResponse, Task};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::task_store::TaskStore;

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

/// Context passed to `handle_message_with_context`, giving the handler
/// access to server-owned state.
#[derive(Clone)]
pub struct HandlerContext {
    /// Broadcast channel for emitting streaming events (status updates, artifact chunks, etc.).
    pub event_tx: broadcast::Sender<StreamResponse>,
    /// Server's task store, for reading or mutating tasks outside of the normal request/response flow.
    pub task_store: TaskStore,
}

/// Trait for implementing A2A message handlers
///
/// Returns `SendMessageResponse` which can be either a Task or a direct Message.
///
/// Implementors should only implement [`MessageHandler::handle_message_with_context`].
///
/// [`MessageHandler::handle_message`] is kept for backwards compatibility.
/// The server always invokes the context variant and its default implementation forwards to `handle_message`.
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Process an incoming A2A message and return a Task or Message.
    ///
    /// Handlers must override either this method or [`MessageHandler::handle_message_with_context`].
    async fn handle_message(
        &self,
        _message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        Err(HandlerError::Internal(anyhow::anyhow!(
            "MessageHandler must implement handle_message or handle_message_with_context"
        )))
    }

    /// Process an incoming A2A message with access to server-owned state.
    ///
    /// The default forwards to [`MessageHandler::handle_message`] for backwards compatibilty.
    /// New implementations should implement this method.
    async fn handle_message_with_context(
        &self,
        message: Message,
        auth: Option<AuthContext>,
        _ctx: &HandlerContext,
    ) -> HandlerResult<SendMessageResponse> {
        self.handle_message(message, auth).await
    }

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
    async fn extended_agent_card(&self, _base_url: &str, _auth: &AuthContext) -> Option<AgentCard> {
        None
    }

    /// Optional: Delay before the server auto-completes a non-terminal task.
    ///
    /// When a handler returns a task in a non-terminal state (e.g. Working),
    /// the server can optionally schedule a background transition to the
    /// terminal state after this delay. Return `None` (the default) to
    /// disable auto-completion — the handler is fully responsible for
    /// completing tasks via the event channel.
    fn auto_complete_delay(&self) -> Option<std::time::Duration> {
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
            .filter_map(|p| p.as_text())
            .collect::<Vec<_>>()
            .join("\n");

        let task_id = Uuid::new_v4().to_string();
        let context_id = message
            .context_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let response = Message {
            kind: "message".to_string(),
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
            kind: "task".to_string(),
            id: task_id,
            context_id,
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(now_iso8601()),
            },
            history: Some(vec![message, response]),
            artifacts: None,
            metadata: None,
        }))
    }

    fn agent_card(&self, _base_url: &str) -> AgentCard {
        use a2a_rs_core::{
            AgentCapabilities, AgentInterface, AgentProvider, AgentSkill, PROTOCOL_VERSION,
        };

        AgentCard {
            name: self.agent_name.clone(),
            description: "Echo agent — reflects input, auto-completes after a short delay"
                .to_string(),
            supported_interfaces: vec![AgentInterface {
                // Leave URL empty — the server fills it in based on
                // bind address + configured rpc_path. Custom handlers
                // that know their public URL should set it explicitly.
                url: String::new(),
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
            capabilities: AgentCapabilities {
                streaming: Some(false),
                push_notifications: Some(false),
                extended_agent_card: Some(false),
                ..Default::default()
            },
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

    fn auto_complete_delay(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_secs(2))
    }
}

/// Type alias for a boxed handler
pub type BoxedHandler = Arc<dyn MessageHandler>;
