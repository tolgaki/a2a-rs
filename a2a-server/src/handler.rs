//! Message handler trait for pluggable backends
//!
//! This module defines the core abstraction for implementing A2A agent backends.
//! Implement the `MessageHandler` trait to create your own agent backend.

use a2a_core::{AgentCard, Message, Task};
use async_trait::async_trait;
use std::sync::Arc;

/// Result type for handler operations
pub type HandlerResult<T> = Result<T, HandlerError>;

/// Error type for handler operations
///
/// Each variant supports an optional source error for detailed error chains.
#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    /// Message processing failed
    #[error("Processing failed: {message}")]
    ProcessingFailed {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Backend service unavailable
    #[error("Backend unavailable: {message}")]
    BackendUnavailable {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Authentication required
    #[error("Authentication required: {0}")]
    AuthRequired(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl HandlerError {
    /// Create a processing failed error with just a message
    pub fn processing_failed(msg: impl Into<String>) -> Self {
        Self::ProcessingFailed {
            message: msg.into(),
            source: None,
        }
    }

    /// Create a processing failed error with a source error
    pub fn processing_failed_with<E>(msg: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::ProcessingFailed {
            message: msg.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a backend unavailable error with just a message
    pub fn backend_unavailable(msg: impl Into<String>) -> Self {
        Self::BackendUnavailable {
            message: msg.into(),
            source: None,
        }
    }

    /// Create a backend unavailable error with a source error
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
    /// User identifier (e.g., email, subject claim)
    pub user_id: String,
    /// Access token for backend API calls
    pub access_token: String,
    /// Optional additional claims/metadata
    pub metadata: Option<serde_json::Value>,
}

/// Trait for implementing A2A message handlers
///
/// This is the core abstraction for creating A2A agent backends.
/// Implement this trait to create your own agent (e.g., ChatGPT, Claude, custom).
///
/// # Example
///
/// ```rust,ignore
/// use a2a_server::{MessageHandler, HandlerResult, AuthContext};
/// use a2a_core::{AgentCard, Message, Task};
/// use async_trait::async_trait;
///
/// struct MyAgent {
///     // your backend client
/// }
///
/// #[async_trait]
/// impl MessageHandler for MyAgent {
///     async fn handle_message(
///         &self,
///         message: Message,
///         auth: Option<AuthContext>,
///     ) -> HandlerResult<Task> {
///         // Process message with your backend
///         todo!()
///     }
///
///     fn agent_card(&self, base_url: &str) -> AgentCard {
///         // Return your agent's card
///         todo!()
///     }
/// }
/// ```
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Process an incoming A2A message and return a Task
    ///
    /// The handler should:
    /// 1. Process the message (possibly async with backend)
    /// 2. Return a Task with appropriate state (Working, Completed, Failed, etc.)
    ///
    /// For async backends, return a Task in `Working` state and update it later
    /// via the task store.
    async fn handle_message(
        &self,
        message: Message,
        auth: Option<AuthContext>,
    ) -> HandlerResult<Task>;

    /// Return the agent card for this handler
    ///
    /// The `base_url` parameter provides the server's base URL for constructing
    /// endpoint URLs in the agent card.
    fn agent_card(&self, base_url: &str) -> AgentCard;

    /// Optional: Handle task cancellation
    ///
    /// Override this to implement custom cancellation logic (e.g., abort backend request).
    /// Default implementation does nothing.
    async fn cancel_task(&self, _task_id: &str) -> HandlerResult<()> {
        Ok(())
    }

    /// Optional: Check if handler supports streaming
    ///
    /// Default is false. Override to enable streaming support.
    fn supports_streaming(&self) -> bool {
        false
    }

    /// Optional: Return an extended agent card for authenticated requests
    ///
    /// Override to provide additional agent information to authenticated clients.
    /// Default returns None (extended card not supported).
    ///
    /// This method is async to allow I/O operations (e.g., database lookups).
    async fn extended_agent_card(
        &self,
        _base_url: &str,
        _auth: &AuthContext,
    ) -> Option<AgentCard> {
        None
    }
}

/// A simple echo handler for testing and demos
///
/// This handler simply echoes back the user's message with a prefix.
pub struct EchoHandler {
    /// Prefix to add to echoed messages
    pub prefix: String,
    /// Agent name for the card
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
    ) -> HandlerResult<Task> {
        use a2a_core::{now_iso8601, Part, Role, TaskState, TaskStatus, TextPart};
        use uuid::Uuid;

        // Extract text from message
        let text = message
            .parts
            .iter()
            .filter_map(|p| match p {
                Part::Text(t) => Some(t.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");

        let task_id = format!("tasks/{}", Uuid::new_v4());

        let context_id = message.context_id.clone().unwrap_or_default();
        
        let response = Message {
            id: Uuid::new_v4().to_string(),
            role: Role::Agent,
            parts: vec![Part::Text(TextPart {
                text: format!("{} {}", self.prefix, text),
            })],
            context_id: message.context_id.clone(),
            reference_task_ids: None,
            metadata: None,
        };

        Ok(Task {
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
        })
    }

    fn agent_card(&self, base_url: &str) -> AgentCard {
        use a2a_core::{AgentCapabilities, AgentProvider, AgentSkill, PROTOCOL_VERSION};

        AgentCard {
            id: "echo-agent".to_string(),
            name: self.agent_name.clone(),
            provider: AgentProvider {
                name: "A2A Demo".to_string(),
                url: Some("https://github.com/a2a-protocol".to_string()),
                email: None,
            },
            protocol_version: PROTOCOL_VERSION.to_string(),
            description: Some("Simple echo agent for testing A2A protocol".to_string()),
            endpoint: format!("{}/v1/rpc", base_url),
            capabilities: AgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: false,
                extensions: vec![],
            },
            security_schemes: vec![],
            security: vec![],
            skills: vec![AgentSkill {
                id: "echo".to_string(),
                name: "Echo".to_string(),
                description: "Echoes back the user's message".to_string(),
                input_schema: None,
                output_schema: None,
                tags: vec!["demo".to_string(), "echo".to_string()],
            }],
            extensions: vec![],
            supports_extended_agent_card: false,
            signature: None,
            url: Some(format!("{}/v1/rpc", base_url)),
            preferred_transport: Some("JSONRPC".to_string()),
            additional_interfaces: vec![],
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
        }
    }
}

/// Type alias for a boxed handler
pub type BoxedHandler = Arc<dyn MessageHandler>;
