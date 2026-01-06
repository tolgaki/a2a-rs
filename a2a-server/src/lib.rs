//! A2A Server Library
//!
//! This library provides a generic, pluggable A2A 0.3.0 compliant JSON-RPC server
//! framework. Implement the `MessageHandler` trait to create your own agent backend.
//!
//! # Generic Server Example
//!
//! ```rust,ignore
//! use a2a_server::{A2aServer, MessageHandler, HandlerResult, AuthContext, EchoHandler};
//! use a2a_core::{AgentCard, Message, Task};
//! use async_trait::async_trait;
//!
//! // Use the built-in echo handler for demos
//! A2aServer::echo()
//!     .bind("0.0.0.0:8080")
//!     .run()
//!     .await?;
//!
//! // Or implement your own handler
//! struct MyAgent { /* ... */ }
//!
//! #[async_trait]
//! impl MessageHandler for MyAgent {
//!     async fn handle_message(
//!         &self,
//!         message: Message,
//!         auth: Option<AuthContext>,
//!     ) -> HandlerResult<Task> {
//!         // Process message with your backend
//!         todo!()
//!     }
//!
//!     fn agent_card(&self, base_url: &str) -> AgentCard {
//!         // Return your agent's card
//!         todo!()
//!     }
//! }
//!
//! A2aServer::new(MyAgent { /* ... */ })
//!     .bind("0.0.0.0:8080")
//!     .auth_extractor(|headers| {
//!         // Extract auth from headers
//!         None
//!     })
//!     .run()
//!     .await?;
//! ```

mod handler;
mod server;
mod task_store;
mod webhook_delivery;
mod webhook_store;

// Re-export handler types
pub use handler::{AuthContext, BoxedHandler, EchoHandler, HandlerError, HandlerResult, MessageHandler};

// Re-export server types
pub use server::{A2aServer, AppState, AuthExtractor, ServerConfig, run_echo_server, run_server};

// Re-export task store
pub use task_store::TaskStore;

// Re-export webhook types
pub use webhook_delivery::{RetryConfig, WebhookDelivery, WebhookError};
pub use webhook_store::{StoredWebhookConfig, WebhookStore};
