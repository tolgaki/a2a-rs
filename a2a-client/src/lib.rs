//! A2A Client Library
//!
//! This library provides a reusable client for communicating with A2A 0.3.0 compliant agent servers.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use a2a_client::{A2aClient, ClientConfig};
//! use a2a_core::{Message, Part, Role};
//!
//! let config = ClientConfig {
//!     server_url: "http://localhost:8080".to_string(),
//!     max_polls: 30,
//!     poll_interval_ms: 2000,
//!     oauth: None,
//! };
//!
//! let client = A2aClient::new(config)?;
//! let card = client.fetch_agent_card().await?;
//!
//! let message = Message {
//!     message_id: uuid::Uuid::new_v4().to_string(),
//!     role: Role::User,
//!     parts: vec![Part::text("Hello")],
//!     context_id: None,
//!     task_id: None,
//!     extensions: vec![],
//!     reference_task_ids: None,
//!     metadata: None,
//! };
//!
//! let response = client.send_message(message, None).await?;
//! ```

mod client;

// Re-export the main client types
pub use client::{A2aClient, ClientConfig, OAuthConfig};

// Re-export utility functions for advanced usage
pub use client::{generate_code_challenge, generate_code_verifier, generate_random_string};
