# a2a-rs — Agent-to-Agent Protocol for Rust

[![crates.io](https://img.shields.io/crates/v/a2a-rs-server.svg)](https://crates.io/crates/a2a-rs-server)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![A2A Protocol](https://img.shields.io/badge/A2A-v1.0-green.svg)](https://github.com/a2aproject/A2A)

Production-ready Rust SDK for the [A2A (Agent-to-Agent) v1.0 protocol](https://github.com/a2aproject/A2A). Build interoperable AI agents that discover, communicate, and collaborate across any language or framework.

**Spec compliant.** Passes the [A2A TCK](https://github.com/a2aproject/a2a-tck) conformance suite. Tested for cross-language interoperability with Python, .NET, Go, Java, JS, and Swift SDKs.

## Crates

| Crate | Purpose |
|-------|---------|
| [`a2a-rs-core`](https://crates.io/crates/a2a-rs-core) | A2A v1.0 types, error codes, JSON-RPC definitions |
| [`a2a-rs-server`](https://crates.io/crates/a2a-rs-server) | Server framework — JSON-RPC + REST transports, streaming, push notifications |
| [`a2a-rs-client`](https://crates.io/crates/a2a-rs-client) | Client library — agent discovery, messaging, task polling, OAuth PKCE |

## Quick Start

```toml
# Cargo.toml
[dependencies]
a2a-rs-server = "1.0"
a2a-rs-core = "1.0"
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
```

### Minimal Server (5 lines)

```rust
use a2a_rs_server::A2aServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    A2aServer::echo().bind("0.0.0.0:8080")?.run().await
}
```

This gives you a working A2A agent with:
- Agent card at `GET /.well-known/agent-card.json`
- JSON-RPC at `POST /v1/rpc` (SendMessage, GetTask, CancelTask, ListTasks, streaming)
- REST at `GET/POST /v1/tasks/*`, `POST /v1/message:send`, `POST /v1/message:stream`
- Health check at `GET /health`

### Custom Agent

```rust
use a2a_rs_server::{A2aServer, MessageHandler, HandlerResult, AuthContext};
use a2a_rs_core::*;
use async_trait::async_trait;

struct MyAgent;

#[async_trait]
impl MessageHandler for MyAgent {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        let text = message.parts.iter()
            .filter_map(|p| p.as_text())
            .collect::<Vec<_>>()
            .join(" ");

        Ok(SendMessageResponse::Task(
            completed_task_with_text(message, &format!("You said: {text}"))
        ))
    }

    fn agent_card(&self, _base_url: &str) -> AgentCard {
        AgentCard {
            name: "My Agent".to_string(),
            description: "Does useful things".to_string(),
            version: PROTOCOL_VERSION.to_string(),
            skills: vec![AgentSkill {
                id: "chat".to_string(),
                name: "Chat".to_string(),
                description: "General conversation".to_string(),
                tags: vec!["chat".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    A2aServer::new(MyAgent).bind("0.0.0.0:8080")?.run().await
}
```

### Client

```toml
[dependencies]
a2a-rs-client = "1.0"
a2a-rs-core = "1.0"
tokio = { version = "1", features = ["full"] }
```

```rust
use a2a_rs_client::A2aClient;
use a2a_rs_core::{Message, Part, Role, SendMessageResult};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = A2aClient::with_server("http://localhost:8080")?;

    // Discover agent capabilities
    let card = client.fetch_agent_card().await?;
    println!("Connected to: {} ({})", card.name, card.description);

    // Send a message
    let msg = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        role: Role::User,
        parts: vec![Part::text("Hello, agent!")],
        ..Default::default()
    };
    let result = client.send_message(msg, None, None).await?;

    match result {
        SendMessageResult::Task(task) => println!("Task: {:?}", task.status.state),
        SendMessageResult::Message(msg) => {
            for p in &msg.parts { if let Some(t) = p.as_text() { println!("Agent: {t}"); } }
        }
    }
    Ok(())
}
```

## Examples

All examples showcase the A2A v1.0 protocol via the `a2a-rs-*` crates.

| Example | What it demonstrates | Run command |
|---------|---------------------|-------------|
| [`echo_server`](a2a-server/examples/echo_server.rs) | Minimal agent in 5 lines | `cargo run --example echo_server` |
| [`custom_handler`](a2a-server/examples/custom_handler.rs) | Skills, artifacts, agent card, routing | `cargo run --example custom_handler` |
| [`streaming_agent`](a2a-server/examples/streaming_agent.rs) | SSE streaming with incremental artifacts | `cargo run --example streaming_agent` |
| [`push_notifications`](a2a-server/examples/push_notifications.rs) | Webhook push notifications with receiver | `cargo run --example push_notifications` |
| [`multi_agent`](a2a-server/examples/multi_agent.rs) | Agent-to-agent delegation via client SDK | `cargo run --example multi_agent` |
| [`simple_client`](a2a-client/examples/simple_client.rs) | Agent discovery and message sending | `cargo run -p a2a-rs-client --example simple_client` |
| [`polling_client`](a2a-client/examples/polling_client.rs) | Task polling until completion | `cargo run -p a2a-rs-client --example polling_client` |
| [`tck_server`](a2a-server/examples/tck_server.rs) | TCK conformance SUT (all scenarios) | `cargo run --example tck_server` |

### Streaming Agent

The streaming example shows the full A2A SSE lifecycle: Working task, artifact chunks streamed word-by-word, then Completed.

```sh
# Terminal 1: Start the agent
cargo run --example streaming_agent

# Terminal 2: Stream via JSON-RPC
curl -N -X POST http://localhost:8080/v1/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage",
       "params":{"message":{"messageId":"s1","role":"ROLE_USER",
       "parts":[{"text":"Tell me a story"}]}}}'

# Or via REST
curl -N -X POST http://localhost:8080/v1/message:stream \
  -H "Content-Type: application/json" \
  -d '{"message":{"messageId":"s2","role":"ROLE_USER",
       "parts":[{"text":"Count to five"}]}}'
```

### Push Notifications

The push notification example runs a webhook receiver alongside the agent, demonstrating the full webhook lifecycle.

```sh
cargo run --example push_notifications

# The example starts both the agent (port 8080) and a webhook receiver (port 9090),
# then demonstrates: create config -> send message -> receive webhook -> cleanup
```

### Multi-Agent Delegation

Two agents collaborate: a Coordinator delegates work to a Worker.

```sh
cargo run --example multi_agent

# Worker agent starts on port 3002
# Coordinator starts on port 3001 and uses a2a-rs-client to call the Worker
```

## Transport Bindings

The server exposes both A2A v1.0 transport bindings simultaneously:

### JSON-RPC (default at `/v1/rpc`)

| Method | Description |
|--------|-------------|
| `SendMessage` | Send a message, get Task or Message back |
| `SendStreamingMessage` | SSE streaming response |
| `GetTask` | Retrieve task by ID |
| `ListTasks` | List/filter/paginate tasks |
| `CancelTask` | Cancel a running task |
| `SubscribeToTask` | SSE subscription to task updates |
| `GetExtendedAgentCard` | Authenticated extended card |
| `Create/Get/List/DeleteTaskPushNotificationConfig` | Push notification CRUD |

### REST / HTTP+JSON (default at `/v1`)

| Verb + Path | Operation |
|-------------|-----------|
| `POST /v1/message:send` | SendMessage |
| `POST /v1/message:stream` | SendStreamingMessage (SSE) |
| `GET /v1/tasks` | ListTasks (query params) |
| `GET /v1/tasks/{id}` | GetTask |
| `POST /v1/tasks/{id}:cancel` | CancelTask |
| `GET /v1/tasks/{id}:subscribe` | SubscribeToTask (SSE) |
| `GET /v1/extendedAgentCard` | GetExtendedAgentCard |
| `POST/GET/DELETE /v1/tasks/{id}/pushNotificationConfigs[/{configId}]` | Push config CRUD |

Error responses use [AIP-193](https://google.aip.dev/193) format with `google.rpc.ErrorInfo` details.

## Server Configuration

```rust
use a2a_rs_server::A2aServer;

A2aServer::new(handler)
    .bind("0.0.0.0:8080")?          // Listen address
    .rpc_path("/v1/rpc")             // JSON-RPC endpoint path
    .rest_prefix(Some("/v1"))        // REST prefix (None to disable)
    .auth_extractor(|headers| {      // Extract auth from requests
        let token = headers.get("authorization")?.to_str().ok()?;
        Some(a2a_rs_server::AuthContext {
            user_id: "user".into(),
            access_token: token.into(),
            metadata: None,
        })
    })
    .run()
    .await?;
```

## Data Model

### Parts (multimodal content)

```rust
use a2a_rs_core::Part;

// Text
let text = Part::text("Hello");

// File by URL (with filename)
let file = Part::file_uri_named("https://example.com/doc.pdf", "application/pdf", "doc.pdf");

// File by bytes (base64)
let bytes = Part::file_bytes_named("iVBORw0KGgo...", "image/png", "chart.png");

// Structured data
let data = Part::data(serde_json::json!({"temperature": 72, "unit": "F"}));
```

### Task States

```
SUBMITTED -> WORKING -> COMPLETED
                    \-> FAILED
                    \-> CANCELED
                    \-> INPUT_REQUIRED -> WORKING -> ...
                    \-> REJECTED
                    \-> AUTH_REQUIRED
```

### Error Codes

| Code | Name | HTTP Status |
|------|------|-------------|
| -32001 | TaskNotFound | 404 |
| -32002 | TaskNotCancelable | 409 |
| -32003 | PushNotificationNotSupported | 400 |
| -32004 | UnsupportedOperation | 400 |
| -32005 | ContentTypeNotSupported | 415 |
| -32006 | InvalidAgentResponse | 502 |
| -32007 | ExtendedAgentCardNotConfigured | 400 |
| -32008 | ExtensionSupportRequired | 400 |
| -32009 | VersionNotSupported | 400 |

## Wire Format

The SDK produces spec-compliant JSON. Parts are flat per the proto definition:

```json
{"text": "Hello"}
{"url": "https://example.com/file.pdf", "filename": "file.pdf", "mediaType": "application/pdf"}
{"raw": "iVBORw0KGgo...", "filename": "image.png", "mediaType": "image/png"}
{"data": {"key": "value"}}
```

Roles use proto-prefix style: `"ROLE_USER"`, `"ROLE_AGENT"`.
Task states use proto-prefix style: `"TASK_STATE_WORKING"`, `"TASK_STATE_COMPLETED"`, etc.
Timestamps use ISO 8601 with Z suffix: `"2024-01-01T00:00:00.000Z"`.

## Requirements

- Rust 1.75+
- Tokio async runtime

## License

Apache License 2.0. See [LICENSE](LICENSE).

Built on the [A2A Protocol](https://github.com/a2aproject/A2A) specification.
