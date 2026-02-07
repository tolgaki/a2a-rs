# A2A Rust Libraries

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![A2A Protocol](https://img.shields.io/badge/A2A-RC%201.0-green.svg)](https://github.com/google/A2A)

Rust libraries for building **Agent-to-Agent (A2A)** applications following the [A2A RC 1.0 specification](https://github.com/google/A2A). Build interoperable AI agents that can discover, communicate, and collaborate with each other.

## What is A2A?

The **Agent-to-Agent (A2A) protocol** is an open standard for machine-to-machine communication between AI agents. It enables:

- **Agent Discovery** - Agents publish their capabilities via Agent Cards
- **Standardized Messaging** - JSON-RPC 2.0 over HTTP for reliable communication
- **Task Management** - Track asynchronous operations with state machines
- **Security** - Built-in support for OAuth2, API keys, and mutual TLS

## Crates

| Crate | Description |
|-------|-------------|
| [`a2a-rs-core`](a2a-rs-core/) | Shared A2A RC 1.0 types, JSON-RPC definitions, and utilities |
| [`a2a-rs-server`](a2a-rs-server/) | Generic server framework with pluggable `MessageHandler` trait |
| [`a2a-rs-client`](a2a-rs-client/) | Client library for agent discovery and message sending |

## Quick Start

### Installation

Add the crates you need to your `Cargo.toml`:

```toml
[dependencies]
# For building agent servers
a2a-rs-server = "1.0"
a2a-rs-core = "1.0"

# For building clients
a2a-rs-client = "1.0"
a2a-rs-core = "1.0"

# Required async runtime
tokio = { version = "1", features = ["full"] }
```

### Build an Echo Server (5 lines)

```rust
use a2a_rs_server::A2aServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    A2aServer::echo().bind("0.0.0.0:8080").run().await
}
```

### Build a Custom Agent

Implement the `MessageHandler` trait to create your own AI agent:

```rust
use a2a_rs_server::{A2aServer, MessageHandler, HandlerResult, AuthContext};
use a2a_rs_core::{
    AgentCard, AgentCapabilities, AgentInterface, AgentProvider, AgentSkill,
    Message, SendMessageResponse, Part, Role, PROTOCOL_VERSION,
    completed_task_with_text,
};
use async_trait::async_trait;

struct MyAiAgent;

#[async_trait]
impl MessageHandler for MyAiAgent {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        // Extract text from message parts
        let user_text: String = message.parts.iter()
            .filter_map(|p| p.text.as_deref())
            .collect::<Vec<_>>()
            .join("\n");

        let response = format!("You said: {}", user_text);
        Ok(SendMessageResponse::Task(
            completed_task_with_text(message, &response),
        ))
    }

    fn agent_card(&self, base_url: &str) -> AgentCard {
        AgentCard {
            name: "My AI Agent".to_string(),
            description: "An AI agent that does amazing things".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: format!("{}/v1/rpc", base_url),
                protocol_binding: "JSONRPC".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                tenant: None,
            }],
            provider: Some(AgentProvider {
                organization: "My Organization".to_string(),
                url: "https://example.com".to_string(),
            }),
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
    A2aServer::new(MyAiAgent)
        .bind("0.0.0.0:8080")
        .run()
        .await
}
```

### Build a Client

```rust
use a2a_rs_client::A2aClient;
use a2a_rs_core::{Message, Part, Role, SendMessageResponse};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = A2aClient::with_server("http://localhost:8080")?;

    // Discover the agent's capabilities
    let card = client.fetch_agent_card().await?;
    println!("Connected to: {}", card.name);

    // Create and send a message
    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        role: Role::User,
        parts: vec![Part::text("Hello, agent!")],
        context_id: None,
        task_id: None,
        extensions: vec![],
        reference_task_ids: None,
        metadata: None,
    };

    let response = client.send_message(message, None).await?;

    match response {
        SendMessageResponse::Task(task) => {
            println!("Task state: {:?}", task.status.state);
            if let Some(history) = &task.history {
                for msg in history.iter().filter(|m| m.role == Role::Agent) {
                    for part in &msg.parts {
                        if let Some(text) = &part.text {
                            println!("Agent: {}", text);
                        }
                    }
                }
            }
        }
        SendMessageResponse::Message(msg) => {
            for part in &msg.parts {
                if let Some(text) = &part.text {
                    println!("Agent: {}", text);
                }
            }
        }
    }

    Ok(())
}
```

## Architecture

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

## Core Concepts

### Agent Card

Every A2A agent publishes an **Agent Card** that describes its capabilities:

```rust
use a2a_rs_core::{AgentCard, AgentInterface, AgentCapabilities, PROTOCOL_VERSION};

// Agents expose their card at /.well-known/agent-card.json
let card = AgentCard {
    name: "Weather Agent".to_string(),
    description: "Get weather forecasts for any location".to_string(),
    supported_interfaces: vec![AgentInterface {
        url: "https://api.example.com/v1/rpc".to_string(),
        protocol_binding: "JSONRPC".to_string(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        tenant: None,
    }],
    version: PROTOCOL_VERSION.to_string(),
    ..Default::default()
};
```

### Messages and Parts

Messages contain multimodal content via flat **Part** structs:

```rust
use a2a_rs_core::{Message, Part, Role};

// Text message
let msg = Message {
    message_id: "msg-1".to_string(),
    role: Role::User,
    parts: vec![Part::text("Analyze this document")],
    context_id: Some("conversation-123".to_string()),
    task_id: None,
    extensions: vec![],
    reference_task_ids: None,
    metadata: None,
};

// URL reference part
let url_part = Part::url("https://example.com/doc.pdf", "application/pdf");

// Structured data part
let data_part = Part::data(
    serde_json::json!({"location": "New York", "units": "celsius"}),
    "application/json",
);

// Raw bytes part (base64-encoded)
let raw_part = Part::raw("iVBORw0KGgoAAAANS...", "image/png");
```

### Tasks and States

Tasks track the lifecycle of agent operations:

```rust
use a2a_rs_core::{Task, TaskState, TaskStatus};

// Task states follow this lifecycle:
//
//   SUBMITTED -> WORKING -> COMPLETED
//                       \-> FAILED
//                       \-> CANCELED
//                       \-> INPUT_REQUIRED -> WORKING -> ...

// Check if task is done
if task.status.state.is_terminal() {
    println!("Task finished with state: {:?}", task.status.state);
}
```

## Server Features

### Authentication

Add authentication to your server:

```rust
use a2a_rs_server::{A2aServer, AuthContext};
use axum::http::HeaderMap;

A2aServer::new(my_handler)
    .bind("0.0.0.0:8080")
    .auth_extractor(|headers: &HeaderMap| {
        let auth_header = headers.get("authorization")?.to_str().ok()?;
        let token = auth_header.strip_prefix("Bearer ")?;

        Some(AuthContext {
            user_id: "user-123".to_string(),
            access_token: token.to_string(),
            metadata: None,
        })
    })
    .run()
    .await?;
```

### Custom Routes

Add additional HTTP endpoints:

```rust
use a2a_rs_server::{A2aServer, AppState};
use axum::{Router, routing::get, Json};

async fn custom_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"custom": "health"}))
}

let custom_routes = Router::new()
    .route("/custom/health", get(custom_health));

A2aServer::new(my_handler)
    .additional_routes(custom_routes)
    .run()
    .await?;
```

## Client Features

### Agent Card Caching

Agent cards are automatically cached for 5 minutes:

```rust
let client = A2aClient::with_server("http://localhost:8080")?;

let card = client.fetch_agent_card().await?;         // Fetches from server
let card = client.fetch_agent_card().await?;         // Uses cache
client.invalidate_card_cache().await;                // Force refresh
let card = client.fetch_agent_card().await?;         // Fetches fresh
```

### Configurable Polling

```rust
use a2a_rs_client::{A2aClient, ClientConfig};

let config = ClientConfig {
    server_url: "http://localhost:8080".to_string(),
    max_polls: 60,          // Maximum poll attempts
    poll_interval_ms: 1000, // 1 second between polls
    oauth: None,
};

let client = A2aClient::new(config)?;
let task = client.poll_until_complete("task-id", None).await?;
```

### OAuth PKCE Support

```rust
use a2a_rs_client::{A2aClient, ClientConfig, OAuthConfig};

let config = ClientConfig {
    server_url: "http://localhost:8080".to_string(),
    oauth: Some(OAuthConfig {
        client_id: "my-app".to_string(),
        redirect_uri: "http://localhost:3000/callback".to_string(),
        scopes: vec!["read".to_string(), "write".to_string()],
        session_token: None,
    }),
    ..Default::default()
};

let client = A2aClient::new(config)?;
let token = client.perform_oauth_interactive().await?;

// Or programmatic flow
let (auth_url, code_verifier) = client.start_oauth_flow().await?;
```

## JSON-RPC Methods

The A2A protocol defines these JSON-RPC methods:

| Method | Description |
|--------|-------------|
| `message/send` | Send a message to the agent |
| `message/sendStreaming` | Send with streaming response |
| `tasks/get` | Query a task by ID |
| `tasks/cancel` | Cancel a running task |
| `tasks/list` | List tasks |
| `tasks/subscribe` | Subscribe to task updates |
| `agentCard/getExtended` | Get extended agent card |

### Example: Raw JSON-RPC

```bash
# Discover agent
curl http://localhost:8080/.well-known/agent-card.json

# Send message
curl -X POST http://localhost:8080/v1/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "messageId": "msg-1",
        "role": "ROLE_USER",
        "parts": [{"text": "Hello!"}]
      }
    }
  }'

# Get task status
curl -X POST http://localhost:8080/v1/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tasks/get",
    "params": {"id": "abc-123"}
  }'
```

## Error Handling

### JSON-RPC Error Codes

```rust
use a2a_rs_core::errors;

// Standard JSON-RPC errors
errors::PARSE_ERROR;        // -32700
errors::INVALID_REQUEST;    // -32600
errors::METHOD_NOT_FOUND;   // -32601
errors::INVALID_PARAMS;     // -32602
errors::INTERNAL_ERROR;     // -32603

// A2A-specific errors
errors::TASK_NOT_FOUND;                 // -32001
errors::TASK_NOT_CANCELABLE;            // -32002
errors::UNSUPPORTED_OPERATION;          // -32004
errors::VERSION_NOT_SUPPORTED;          // -32007
errors::EXTENSION_SUPPORT_REQUIRED;     // -32009
```

## Security Schemes

The A2A protocol supports multiple authentication methods:

```rust
use a2a_rs_core::{
    SecurityScheme, ApiKeySecurityScheme, HttpAuthSecurityScheme,
    OAuth2SecurityScheme, MutualTlsSecurityScheme,
    OAuthFlows, AuthorizationCodeOAuthFlow,
};
use std::collections::HashMap;

// API Key authentication
let api_key = SecurityScheme::ApiKeySecurityScheme(ApiKeySecurityScheme {
    name: "X-API-Key".to_string(),
    location: "header".to_string(),
    description: None,
});

// Bearer token
let bearer = SecurityScheme::HttpAuthSecurityScheme(HttpAuthSecurityScheme {
    scheme: "bearer".to_string(),
    bearer_format: Some("JWT".to_string()),
    description: None,
});

// OAuth 2.0
let oauth = SecurityScheme::Oauth2SecurityScheme(OAuth2SecurityScheme {
    flows: OAuthFlows::AuthorizationCode(AuthorizationCodeOAuthFlow {
        authorization_url: "https://auth.example.com/authorize".to_string(),
        token_url: "https://auth.example.com/token".to_string(),
        refresh_url: None,
        scopes: HashMap::from([
            ("read".to_string(), "Read access".to_string()),
        ]),
        pkce_required: Some(true),
    }),
    description: None,
    oauth2_metadata_url: None,
});

// Mutual TLS
let mtls = SecurityScheme::MtlsSecurityScheme(MutualTlsSecurityScheme {
    description: Some("Client certificate required".to_string()),
});
```

## Documentation

- [Architecture Guide](docs/architecture.md) - Detailed crate structure and data flows
- [Getting Started](docs/getting-started.md) - Step-by-step tutorial
- [A2A Specification](https://github.com/google/A2A) - Official protocol spec

## Requirements

- Rust 1.75 or later
- Tokio async runtime

## Dependencies

These libraries use minimal, well-maintained dependencies:

| Dependency | Purpose |
|------------|---------|
| `serde` | JSON serialization |
| `tokio` | Async runtime |
| `axum` | HTTP server (a2a-rs-server) |
| `reqwest` | HTTP client (a2a-rs-client) |
| `uuid` | UUID generation |
| `async-trait` | Async trait support |

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgments

This implementation follows the [A2A Protocol Specification](https://github.com/google/A2A) developed by Google.
