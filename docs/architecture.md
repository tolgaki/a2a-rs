# Architecture

This document describes the architecture of the A2A Rust libraries.

## Overview

```
+---------------------------------------------------------------+
|                        Your Application                        |
+---------------------------------------------------------------+
                    |                           |
                    v                           v
+-----------------------------+   +-----------------------------+
|        a2a-rs-client           |   |        a2a-rs-server           |
|  - Agent discovery          |   |  - MessageHandler trait     |
|  - Message sending          |   |  - A2aServer builder        |
|  - Task polling             |   |  - TaskStore                |
|  - OAuth PKCE support       |   |  - Auth extractors          |
+-----------------------------+   +-----------------------------+
                    |                           |
                    +-------------+-------------+
                                  v
                    +-----------------------------+
                    |         a2a-rs-core            |
                    |  - A2A RC 1.0 types         |
                    |  - Security schemes         |
                    |  - JSON-RPC definitions     |
                    |  - Helper functions         |
                    +-----------------------------+
```

## Crates

### a2a-rs-core

**Purpose**: Shared types and definitions for the A2A RC 1.0 specification.

**Key Components**:

| Component | Description |
|-----------|-------------|
| `AgentCard` | Agent metadata including name, description, interfaces, capabilities, and security schemes |
| `AgentInterface` | Transport endpoint with `protocol_binding` (e.g., "JSONRPC") and URL |
| `Task` | Represents an A2A task with state, messages, and artifacts |
| `Message` | User or agent message containing parts (uses `message_id`, not `id`) |
| `Part` | Flat struct with optional fields: `text`, `raw`, `url`, `data`, `metadata`, `filename`, `media_type` |
| `TaskState` | Enum: `Submitted`, `Working`, `InputRequired`, `Completed`, `Canceled`, `Failed`, `Rejected`, `AuthRequired` |
| `SecurityScheme` | Externally tagged enum: `ApiKeySecurityScheme`, `HttpAuthSecurityScheme`, `Oauth2SecurityScheme`, `OpenIdConnectSecurityScheme`, `MtlsSecurityScheme` |
| `SendMessageResponse` | Externally tagged enum: `Task` or `Message` |
| `StreamResponse` | Externally tagged enum: `Task`, `Message`, `StatusUpdate`, `ArtifactUpdate` |
| `JsonRpcRequest/Response` | JSON-RPC 2.0 message types |

**Helper Functions**:

| Function | Description |
|----------|-------------|
| `new_message(role, text, context_id)` | Create a new message with text content |
| `completed_task_with_text(message, reply)` | Create a completed task with text response |
| `now_iso8601()` | Generate ISO 8601 timestamp |
| `validate_task_id(id)` | Check if string is valid UUID |
| `success(id, result)` | Build successful JSON-RPC response |
| `error(id, code, message, data)` | Build error JSON-RPC response |

**Files**:
```
a2a-rs-core/src/
└── lib.rs          # All type definitions and helpers
```

---

### a2a-rs-server

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
use a2a_rs_server::{MessageHandler, HandlerResult, AuthContext};
use a2a_rs_core::{AgentCard, Message, SendMessageResponse};
use async_trait::async_trait;

#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Process a message and return a Task or Message
    async fn handle_message(
        &self,
        message: Message,
        auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse>;

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
use a2a_rs_server::{A2aServer, AuthContext};

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

| Variant | Description |
|---------|-------------|
| `ProcessingFailed { message, source }` | Message processing failed |
| `BackendUnavailable { message, source }` | Backend service unavailable |
| `AuthRequired(String)` | Authentication required |
| `InvalidInput(String)` | Invalid input parameters |
| `Internal(anyhow::Error)` | Internal error |

**Files**:
```
a2a-rs-server/src/
├── lib.rs              # Re-exports
├── handler.rs          # MessageHandler trait, AuthContext, EchoHandler
├── server.rs           # A2aServer builder and HTTP routing
├── task_store.rs       # Thread-safe task storage
├── webhook_delivery.rs # Push notification delivery
└── webhook_store.rs    # Webhook configuration storage
```

**HTTP Endpoints**:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/.well-known/agent-card.json` | GET | Agent card discovery |
| `/v1/rpc` | POST | JSON-RPC endpoint (all methods) |

---

### a2a-rs-client

**Purpose**: Client library for interacting with A2A agents.

**Key Components**:

| Component | Description |
|-----------|-------------|
| `A2aClient` | Main client for agent discovery and message sending |
| `ClientConfig` | Configuration: server URL, polling, OAuth |
| `OAuthConfig` | OAuth PKCE flow configuration |
| `fetch_agent_card()` | Fetches and caches Agent Cards (5-minute TTL) |
| `send_message()` | Sends JSON-RPC `message/send` requests, returns `SendMessageResponse` |
| `poll_task()` | Polls for task status by ID |
| `poll_until_complete()` | Polls until terminal state or max attempts |

**Files**:
```
a2a-rs-client/src/
├── lib.rs          # Re-exports
└── client.rs       # A2aClient implementation
```

---

## Data Flow

### Message Send Flow

```
Client                          Server                          Handler
  |                               |                               |
  |  POST /v1/rpc                 |                               |
  |  {"method":"message/send"}    |                               |
  |------------------------------>|                               |
  |                               |                               |
  |                               |  Extract auth from headers    |
  |                               |                               |
  |                               |  handle_message(msg, auth)    |
  |                               |------------------------------>|
  |                               |                               |
  |                               |      Process with backend     |
  |                               |                               |
  |                               |  SendMessageResponse::Task    |
  |                               |<------------------------------|
  |                               |                               |
  |                               |  task_store.insert(task)      |
  |                               |                               |
  |  {"result": {"task": {...}}}  |                               |
  |<------------------------------|                               |
```

### Task Polling Flow

```
Client                          Server
  |                               |
  |  POST /v1/rpc                 |
  |  {"method":"tasks/get",       |
  |   "params":{"id":"abc-123"}}  |
  |------------------------------>|
  |                               |
  |                               |  task_store.get(id)
  |                               |
  |  {"result": task}             |
  |<------------------------------|
  |                               |
  |  (if not terminal, repeat)    |
  |                               |
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
                    +--------------+
                    | UNSPECIFIED  |
                    +------+-------+
                           |
                           v
                    +--------------+
            +-------|  SUBMITTED   |--------+
            |       +------+-------+        |
            |              |                |
            |              v                |
            |       +--------------+        |
            |   +---|   WORKING    |----+   |
            |   |   +------+-------+    |   |
            |   |          |            |   |
            |   |          v            |   |
            |   |   +--------------+    |   |
            |   |   |INPUT_REQUIRED|--+-+---+
            |   |   +--------------+    |   |
            |   |                       |   |
            v   v                       v   v
     +----------+  +----------+  +----------+  +----------+
     |COMPLETED |  |  FAILED  |  | CANCELED |  | REJECTED |
     +----------+  +----------+  +----------+  +----------+
         |              |              |              |
         +--------------+--------------+--------------+
                              |
                        Terminal States
```

**Terminal States** (checked via `TaskState::is_terminal()`):
- `Completed` - Task finished successfully
- `Failed` - Task failed with error
- `Canceled` - Task was cancelled
- `Rejected` - Task was rejected (e.g., validation failed)

---

## Dependencies

| Crate | a2a-rs-core | a2a-rs-client | a2a-rs-server |
|-------|:--------:|:----------:|:----------:|
| serde | x | x | x |
| serde_json | x | x | x |
| uuid | x | x | x |
| chrono | x | | x |
| tokio | | x | x |
| reqwest | | x | x |
| axum | | | x |
| async-trait | | | x |
| thiserror | | | x |
| anyhow | | x | x |
| tracing | | x | x |
| sha2 | | x | |
| base64 | | x | |
| rand | | x | |
