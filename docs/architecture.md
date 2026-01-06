# Architecture

This document describes the architecture of the A2A Rust libraries.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Application                         │
└─────────────────────────────────────────────────────────────────┘
                    │                           │
                    ▼                           ▼
┌─────────────────────────────┐   ┌─────────────────────────────┐
│        a2a-client           │   │        a2a-server           │
│  • Agent discovery          │   │  • MessageHandler trait     │
│  • Message sending          │   │  • A2aServer builder        │
│  • Task polling             │   │  • TaskStore                │
│  • OAuth PKCE support       │   │  • Auth extractors          │
└─────────────────────────────┘   └─────────────────────────────┘
                    │                           │
                    └─────────────┬─────────────┘
                                  ▼
                    ┌─────────────────────────────┐
                    │         a2a-core            │
                    │  • A2A 0.3.0 types          │
                    │  • Security schemes         │
                    │  • JSON-RPC definitions     │
                    │  • Helper functions         │
                    └─────────────────────────────┘
```

## Crates

### a2a-core

**Purpose**: Shared types and definitions for the A2A 0.3.0 specification.

**Key Components**:

| Component | Description |
|-----------|-------------|
| `AgentCard` | Agent metadata including name, endpoint, capabilities, and security schemes |
| `Task` | Represents an A2A task with state, messages, and artifacts |
| `Message` | User or agent message containing parts (text, file, data) |
| `Part` | Message content: `TextPart`, `FilePart`, or `DataPart` |
| `TaskState` | Enum: `Submitted`, `Working`, `InputRequired`, `Completed`, `Cancelled`, `Failed`, `Rejected`, `AuthRequired` |
| `SecurityScheme` | Authentication: API Key, HTTP Bearer, OAuth2, OpenID Connect, Mutual TLS |
| `JsonRpcRequest/Response` | JSON-RPC 2.0 message types |

**Helper Functions**:

| Function | Description |
|----------|-------------|
| `new_message(role, text, context_id)` | Create a new message with text content |
| `completed_task_with_text(message, reply)` | Create a completed task with text response |
| `now_iso8601()` | Generate ISO 8601 timestamp |
| `validate_task_id(id)` | Check if string is valid UUID |
| `extract_task_id(name)` | Extract task ID from resource name |
| `success(id, result)` | Build successful JSON-RPC response |
| `error(id, code, message, data)` | Build error JSON-RPC response |

**Files**:
```
a2a-core/src/
└── lib.rs          # All type definitions and helpers (~860 lines)
```

---

### a2a-server

**Purpose**: Generic server framework for building A2A agents.

**Key Components**:

| Component | Description |
|-----------|-------------|
| `MessageHandler` | Trait for implementing custom agent backends |
| `A2aServer` | Builder pattern server with fluent configuration |
| `TaskStore` | Thread-safe in-memory task storage |
| `EchoHandler` | Built-in handler that echoes messages (for testing) |
| `AuthContext` | Authentication context passed to handlers |
| `HandlerError` | Error types for handler implementations |
| `AppState` | Shared application state for custom routes |

**MessageHandler Trait**:

```rust
use a2a_server::{MessageHandler, HandlerResult, AuthContext};
use a2a_core::{AgentCard, Message, Task};
use async_trait::async_trait;

#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Process a message and return the resulting task
    async fn handle_message(
        &self,
        message: Message,
        auth: Option<AuthContext>,
    ) -> HandlerResult<Task>;

    /// Return the agent card for this handler
    fn agent_card(&self, base_url: &str) -> AgentCard;

    /// Optional: Handle task cancellation (default: no-op)
    async fn cancel_task(&self, task_id: &str) -> HandlerResult<()> {
        Ok(())
    }

    /// Optional: Check if handler supports streaming (default: false)
    fn supports_streaming(&self) -> bool {
        false
    }
}
```

**A2aServer Builder**:

```rust
use a2a_server::{A2aServer, AuthContext};

// Minimal server with echo handler
A2aServer::echo()
    .bind("0.0.0.0:8080")
    .run()
    .await?;

// Full configuration
A2aServer::new(my_handler)
    .bind("0.0.0.0:8080")
    .task_store(custom_store)
    .auth_extractor(|headers| {
        // Extract auth from request headers
        let token = headers.get("authorization")?.to_str().ok()?;
        Some(AuthContext {
            user_id: "user-123".to_string(),
            access_token: token.to_string(),
            metadata: None,
        })
    })
    .additional_routes(custom_router)
    .run()
    .await?;
```

**HandlerError Variants**:

| Variant | Description | HTTP Status |
|---------|-------------|-------------|
| `ProcessingFailed(String)` | Message processing failed | 500 |
| `BackendUnavailable(String)` | Backend service unavailable | 503 |
| `AuthRequired(String)` | Authentication required | 401 |
| `InvalidInput(String)` | Invalid input parameters | 400 |
| `Internal(anyhow::Error)` | Internal error | 500 |

**Files**:
```
a2a-server/src/
├── lib.rs          # Re-exports
├── handler.rs      # MessageHandler trait, AuthContext, EchoHandler
├── server.rs       # A2aServer builder and HTTP routing
└── task_store.rs   # Thread-safe task storage
```

**HTTP Endpoints**:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/.well-known/agent-card.json` | GET | Agent card discovery |
| `/v1/rpc` | POST | JSON-RPC endpoint |

---

### a2a-client

**Purpose**: Client library for interacting with A2A agents.

**Key Components**:

| Component | Description |
|-----------|-------------|
| `A2aClient` | Main client for agent discovery and message sending |
| `ClientConfig` | Configuration: server URL, polling, OAuth |
| `OAuthConfig` | OAuth PKCE flow configuration |
| `fetch_agent_card()` | Fetches and caches Agent Cards (5-minute TTL) |
| `send_message()` | Sends JSON-RPC `message/send` requests |
| `poll_task()` | Polls for task status |
| `poll_until_complete()` | Polls until terminal state or max attempts |

**Client Configuration**:

```rust
use a2a_client::{A2aClient, ClientConfig, OAuthConfig};

// Simple client
let client = A2aClient::with_server("http://localhost:8080")?;

// Full configuration
let config = ClientConfig {
    server_url: "http://localhost:8080".to_string(),
    max_polls: 30,           // Maximum poll attempts
    poll_interval_ms: 2000,  // Milliseconds between polls
    oauth: Some(OAuthConfig {
        client_id: "my-app".to_string(),
        redirect_uri: "http://localhost:3000/callback".to_string(),
        scopes: vec!["read".to_string(), "write".to_string()],
        session_token: None,
    }),
};
let client = A2aClient::new(config)?;
```

**Client Methods**:

| Method | Description |
|--------|-------------|
| `fetch_agent_card()` | Get agent card (cached 5 minutes) |
| `invalidate_card_cache()` | Force cache refresh |
| `send_message(message, token)` | Send message, get task |
| `poll_task(task_id, token)` | Get task status |
| `poll_until_complete(task_id, token)` | Poll until done |
| `perform_oauth_interactive()` | Interactive OAuth flow |
| `start_oauth_flow()` | Programmatic OAuth start |

**Files**:
```
a2a-client/src/
├── lib.rs          # Re-exports
└── client.rs       # A2aClient implementation
```

---

## Data Flow

### Message Send Flow

```
Client                          Server                          Handler
  │                               │                               │
  │  POST /v1/rpc                 │                               │
  │  {"method":"message/send"}    │                               │
  │──────────────────────────────>│                               │
  │                               │                               │
  │                               │  Extract auth from headers    │
  │                               │                               │
  │                               │  handle_message(msg, auth)    │
  │                               │──────────────────────────────>│
  │                               │                               │
  │                               │      Process with backend     │
  │                               │                               │
  │                               │  Task { state: Completed }    │
  │                               │<──────────────────────────────│
  │                               │                               │
  │                               │  task_store.insert(task)      │
  │                               │                               │
  │  {"result": task}             │                               │
  │<──────────────────────────────│                               │
```

### Task Polling Flow

```
Client                          Server
  │                               │
  │  POST /v1/rpc                 │
  │  {"method":"tasks/get",       │
  │   "params":{"name":"tasks/x"}}│
  │──────────────────────────────>│
  │                               │
  │                               │  task_store.get_flexible(id)
  │                               │
  │  {"result": task}             │
  │<──────────────────────────────│
  │                               │
  │  (if not terminal, repeat)    │
  │                               │
```

### Task Cancel Flow

```
Client                          Server                          Handler
  │                               │                               │
  │  POST /v1/rpc                 │                               │
  │  {"method":"tasks/cancel"}    │                               │
  │──────────────────────────────>│                               │
  │                               │                               │
  │                               │  Check task is not terminal   │
  │                               │                               │
  │                               │  cancel_task(task_id)         │
  │                               │──────────────────────────────>│
  │                               │                               │
  │                               │  Update state to CANCELLED    │
  │                               │                               │
  │  {"result": task}             │                               │
  │<──────────────────────────────│                               │
```

---

## Extensibility

### Implementing a Custom Handler

To create your own agent backend, implement the `MessageHandler` trait:

```rust
use a2a_server::{MessageHandler, HandlerResult, HandlerError, AuthContext};
use a2a_core::{
    AgentCard, AgentCapabilities, AgentProvider, AgentSkill,
    Message, Task, Part, TextPart, Role, PROTOCOL_VERSION,
};
use async_trait::async_trait;

pub struct OpenAIHandler {
    api_key: String,
    model: String,
}

impl OpenAIHandler {
    pub fn new(api_key: String, model: String) -> Self {
        Self { api_key, model }
    }
}

#[async_trait]
impl MessageHandler for OpenAIHandler {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<Task> {
        // 1. Extract text from message parts
        let user_text: String = message.parts.iter()
            .filter_map(|p| match p {
                Part::Text(t) => Some(t.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");

        // 2. Call OpenAI API (pseudocode)
        let response = call_openai(&self.api_key, &self.model, &user_text)
            .await
            .map_err(|e| HandlerError::BackendUnavailable(e.to_string()))?;

        // 3. Return completed task with response
        Ok(a2a_core::completed_task_with_text(message, &response))
    }

    fn agent_card(&self, base_url: &str) -> AgentCard {
        AgentCard {
            id: "openai-agent".to_string(),
            name: "OpenAI Assistant".to_string(),
            provider: AgentProvider {
                name: "My Company".to_string(),
                url: Some("https://mycompany.com".to_string()),
                email: Some("support@mycompany.com".to_string()),
            },
            protocol_version: PROTOCOL_VERSION.to_string(),
            description: Some("AI assistant powered by OpenAI".to_string()),
            endpoint: format!("{}/v1/rpc", base_url),
            capabilities: AgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: false,
                extensions: vec![],
            },
            security_schemes: vec![],
            security: vec![],
            skills: vec![
                AgentSkill {
                    id: "chat".to_string(),
                    name: "Chat".to_string(),
                    description: "General conversation and Q&A".to_string(),
                    input_schema: None,
                    output_schema: None,
                    tags: vec!["chat".to_string(), "qa".to_string()],
                },
            ],
            extensions: vec![],
            supports_extended_agent_card: false,
            signature: None,
            url: None,
            preferred_transport: None,
            additional_interfaces: vec![],
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
        }
    }
}
```

### Using the Server

```rust
use a2a_server::A2aServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let handler = OpenAIHandler::new(
        std::env::var("OPENAI_API_KEY")?,
        "gpt-4".to_string(),
    );

    A2aServer::new(handler)
        .bind("0.0.0.0:8080")
        .run()
        .await
}
```

### Adding Authentication

```rust
use a2a_server::{A2aServer, AuthContext};
use axum::http::HeaderMap;

A2aServer::new(handler)
    .bind("0.0.0.0:8080")
    .auth_extractor(|headers: &HeaderMap| {
        // Extract Bearer token
        let auth_header = headers.get("authorization")?;
        let auth_str = auth_header.to_str().ok()?;
        let token = auth_str.strip_prefix("Bearer ")?;

        // Validate token (pseudocode)
        let claims = validate_jwt(token).ok()?;

        Some(AuthContext {
            user_id: claims.sub,
            access_token: token.to_string(),
            metadata: Some(serde_json::json!({
                "roles": claims.roles,
            })),
        })
    })
    .run()
    .await?;
```

### Adding Custom Routes

```rust
use a2a_server::{A2aServer, AppState};
use axum::{Router, routing::{get, post}, extract::State, Json};

async fn custom_endpoint(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let task_count = state.task_store().len().await;
    Json(serde_json::json!({
        "agent": state.agent_card().name,
        "active_tasks": task_count,
    }))
}

let custom_routes = Router::new()
    .route("/api/stats", get(custom_endpoint));

A2aServer::new(handler)
    .additional_routes(custom_routes)
    .run()
    .await?;
```

---

## Thread Safety

All components are designed for concurrent access:

- `TaskStore` uses `Arc<RwLock<HashMap>>` for thread-safe storage
- `MessageHandler` requires `Send + Sync`
- `A2aClient` is `Clone` and thread-safe
- Server handles multiple concurrent requests via Tokio

---

## Task State Machine

```
                    ┌─────────────┐
                    │ UNSPECIFIED │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
            ┌───────│  SUBMITTED  │───────┐
            │       └──────┬──────┘       │
            │              │              │
            │              ▼              │
            │       ┌─────────────┐       │
            │   ┌───│   WORKING   │───┐   │
            │   │   └──────┬──────┘   │   │
            │   │          │          │   │
            │   │          ▼          │   │
            │   │   ┌─────────────┐   │   │
            │   │   │INPUT_REQUIRED│──┼───┤
            │   │   └─────────────┘   │   │
            │   │                     │   │
            ▼   ▼                     ▼   ▼
     ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
     │COMPLETED │  │  FAILED  │  │CANCELLED │  │ REJECTED │
     └──────────┘  └──────────┘  └──────────┘  └──────────┘
         │              │              │              │
         └──────────────┴──────────────┴──────────────┘
                              │
                        Terminal States
```

**Terminal States** (checked via `TaskState::is_terminal()`):
- `Completed` - Task finished successfully
- `Failed` - Task failed with error
- `Cancelled` - Task was cancelled
- `Rejected` - Task was rejected (e.g., validation failed)

---

## Dependencies

| Crate | a2a-core | a2a-client | a2a-server |
|-------|:--------:|:----------:|:----------:|
| serde | ✓ | ✓ | ✓ |
| serde_json | ✓ | ✓ | ✓ |
| uuid | ✓ | ✓ | ✓ |
| chrono | ✓ | | |
| tokio | | ✓ | ✓ |
| reqwest | | ✓ | |
| axum | | | ✓ |
| async-trait | | | ✓ |
| thiserror | | | ✓ |
| anyhow | | ✓ | ✓ |
| tracing | | ✓ | ✓ |
| sha2 | | ✓ | |
| base64 | | ✓ | |
| rand | | ✓ | |
