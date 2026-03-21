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
|        a2a-rs-client        |   |        a2a-rs-server        |
|  - Agent discovery          |   |  - MessageHandler trait     |
|  - Message sending          |   |  - A2aServer builder        |
|  - Streaming (SSE)          |   |  - Streaming (SSE)          |
|  - Task polling             |   |  - TaskStore                |
|  - OAuth PKCE support       |   |  - Auth extractors          |
+-----------------------------+   +-----------------------------+
                    |                           |
                    +-------------+-------------+
                                  v
                    +-----------------------------+
                    |         a2a-rs-core          |
                    |  - A2A types (Part, Task,    |
                    |    Message, AgentCard, etc.) |
                    |  - Security schemes          |
                    |  - JSON-RPC definitions      |
                    |  - Helper functions           |
                    +-----------------------------+
```

## Crates

### a2a-rs-core

**Purpose**: Shared types and definitions for the A2A protocol.

**Key Components**:

| Component | Description |
|-----------|-------------|
| `AgentCard` | Agent metadata including name, description, interfaces, capabilities, and security schemes |
| `AgentInterface` | Transport endpoint with `protocol_binding` (e.g., "JSONRPC") and URL |
| `Task` | Represents an A2A task with `kind: "task"`, state, messages, and artifacts |
| `Message` | User or agent message with `kind: "message"` containing parts |
| `Part` | Internally tagged enum (`kind` discriminator): `Text`, `File`, `Data` |
| `FileContent` | File data for `Part::File` — `bytes` (base64), `uri`, `name`, `mime_type` |
| `TaskState` | Enum: `submitted`, `working`, `input-required`, `completed`, `canceled`, `failed`, `rejected`, `auth-required` |
| `SecurityScheme` | Externally tagged enum: `ApiKeySecurityScheme`, `HttpAuthSecurityScheme`, `Oauth2SecurityScheme`, `OpenIdConnectSecurityScheme`, `MtlsSecurityScheme` |
| `SendMessageResponse` | Externally tagged enum (handler-internal): `Task` or `Message` |
| `SendMessageResult` | Untagged enum (wire format): bare Task or Message in JSON-RPC result field |
| `StreamResponse` | Externally tagged enum (server-internal broadcast): `Task`, `Message`, `StatusUpdate`, `ArtifactUpdate` |
| `StreamingMessageResult` | Untagged enum (SSE wire format): `Task`, `Message`, `TaskStatusUpdateEvent`, `TaskArtifactUpdateEvent` |
| `TaskStatusUpdateEvent` | Streaming event with `kind: "status-update"`, `is_final` flag |
| `TaskArtifactUpdateEvent` | Streaming event with `kind: "artifact-update"` |
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

**Part constructors**:

| Constructor | Wire format |
|-------------|-------------|
| `Part::text("hello")` | `{"kind":"text","text":"hello"}` |
| `Part::file_uri(url, mime)` | `{"kind":"file","file":{"uri":"...","mimeType":"..."}}` |
| `Part::file_bytes(b64, mime)` | `{"kind":"file","file":{"bytes":"...","mimeType":"..."}}` |
| `Part::data(json_value)` | `{"kind":"data","data":{...}}` |
| `part.as_text()` | Returns `Option<&str>` for text parts |

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
    async fn cancel_task(&self, task_id: &str) -> HandlerResult<()>;

    /// Optional: Check if handler supports streaming (default: false)
    fn supports_streaming(&self) -> bool;

    /// Optional: Return extended agent card for authenticated requests
    async fn extended_agent_card(&self, base_url: &str, auth: &AuthContext) -> Option<AgentCard>;
}
```

**HTTP Endpoints**:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/.well-known/agent-card.json` | GET | Agent card discovery |
| `/v1/rpc` | POST | JSON-RPC endpoint (all methods including streaming) |
| `/v1/tasks/:task_id/subscribe` | GET | SSE subscription for task updates |

**Streaming Architecture**:

The server uses a `broadcast::Sender<StreamResponse>` channel for event distribution:

1. Handler returns initial `SendMessageResponse::Task` from `handle_message()`
2. Server stores the task and broadcasts it
3. For `message/stream` requests, the server returns an SSE response
4. Background code pushes updates via `server.get_event_sender()`
5. SSE handler filters events by task ID and wraps each in a JSON-RPC envelope
6. Stream ends on `is_final: true` or terminal task state

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
| `send_message()` | Sends `message/send`, returns `SendMessageResult` (Task or Message) |
| `send_message_streaming()` | Sends `message/stream`, returns `Stream<Item = Result<StreamingMessageResult>>` |
| `poll_task()` | Polls for task status by ID |
| `poll_until_complete()` | Polls until terminal state or max attempts |

---

## Data Flow

### Message Send Flow

```
Client                          Server                          Handler
  |                               |                               |
  |  POST /v1/rpc                 |                               |
  |  {"method":"message/send"}    |                               |
  |------------------------------>|                               |
  |                               |  handle_message(msg, auth)    |
  |                               |------------------------------>|
  |                               |                               |
  |                               |  SendMessageResponse::Task    |
  |                               |<------------------------------|
  |                               |                               |
  |                               |  task_store.insert(task)      |
  |                               |                               |
  |  {"jsonrpc":"2.0","id":1,     |                               |
  |   "result":{"kind":"task",..}}|                               |
  |<------------------------------|                               |
```

### Streaming Flow

```
Client                          Server                          Handler
  |                               |                               |
  |  POST /v1/rpc                 |                               |
  |  {"method":"message/stream"}  |                               |
  |------------------------------>|                               |
  |                               |  handle_message(msg, auth)    |
  |                               |------------------------------>|
  |                               |  SendMessageResponse::Task    |
  |                               |<------------------------------|
  |                               |                               |
  |  Content-Type: text/event-stream                              |
  |<------------------------------|                               |
  |                               |                               |
  |  data: {"jsonrpc":"2.0",      |                               |
  |   "result":{"kind":"task"..}} |  (initial task)               |
  |<------------------------------|                               |
  |                               |                               |
  |                               |  broadcast_event(StatusUpdate)|
  |  data: {"jsonrpc":"2.0",      |  (from background processing)|
  |   "result":{"kind":           |                               |
  |    "status-update",...}}       |                               |
  |<------------------------------|                               |
  |                               |                               |
  |  data: {"jsonrpc":"2.0",      |                               |
  |   "result":{"kind":           |  broadcast_event(StatusUpdate |
  |    "status-update",           |    { is_final: true })        |
  |    "final":true,...}}          |                               |
  |<------------------------------|                               |
  |                               |                               |
  |  (stream ends)                |                               |
```

---

## Thread Safety

All components are designed for concurrent access:

- `TaskStore` uses `Arc<RwLock<HashMap>>` for thread-safe storage
- `MessageHandler` requires `Send + Sync`
- `A2aClient` is `Clone` and thread-safe
- Server handles multiple concurrent requests via Tokio
- Broadcast channel supports multiple concurrent SSE subscribers

---

## Task State Machine

```
                    +--------------+
                    | unspecified  |
                    +------+-------+
                           |
                           v
                    +--------------+
            +-------| submitted   |--------+
            |       +------+-------+       |
            |              |               |
            |              v               |
            |       +--------------+       |
            |   +---| working      |---+   |
            |   |   +------+-------+   |   |
            |   |          |           |   |
            |   |          v           |   |
            |   |   +----------------+ |   |
            |   |   |input-required  |-+---+
            |   |   +----------------+ |   |
            |   |                      |   |
            v   v                      v   v
     +----------+  +----------+  +----------+  +----------+
     |completed |  | failed   |  | canceled |  | rejected |
     +----------+  +----------+  +----------+  +----------+
         |              |              |              |
         +--------------+--------------+--------------+
                              |
                        Terminal States
```

**Terminal States** (checked via `TaskState::is_terminal()`):
- `completed` - Task finished successfully
- `failed` - Task failed with error
- `canceled` - Task was cancelled
- `rejected` - Task was rejected

---

## Wire Format Summary

All types use `camelCase` JSON serialization. Key discriminators:

| Type | `kind` value | Distinguishing fields |
|------|-------------|----------------------|
| `Part::Text` | `"text"` | `text` |
| `Part::File` | `"file"` | `file: {uri?, bytes?, mimeType?, name?}` |
| `Part::Data` | `"data"` | `data` |
| `Task` | `"task"` | `id`, `contextId`, `status` |
| `Message` | `"message"` | `messageId`, `role`, `parts` |
| `TaskStatusUpdateEvent` | `"status-update"` | `taskId`, `status`, `final` |
| `TaskArtifactUpdateEvent` | `"artifact-update"` | `taskId`, `artifact` |

Role values: `"user"`, `"agent"`. Task state values: `"submitted"`, `"working"`, `"completed"`, `"failed"`, `"canceled"`, `"input-required"`, `"rejected"`, `"auth-required"`.

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
| futures-core | | x | |
| async-stream | | x | x |
| tokio-stream | | x | x |
