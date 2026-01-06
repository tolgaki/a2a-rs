# A2A Rust Libraries

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![A2A Protocol](https://img.shields.io/badge/A2A-0.3.0-green.svg)](https://github.com/a2a-protocol/a2a-spec)

Production-ready Rust libraries for building **Agent-to-Agent (A2A)** applications following the [A2A 0.3.0 specification](https://github.com/a2a-protocol/a2a-spec). Build interoperable AI agents that can discover, communicate, and collaborate with each other.

## What is A2A?

The **Agent-to-Agent (A2A) protocol** is an open standard for machine-to-machine communication between AI agents. It enables:

- **Agent Discovery** - Agents publish their capabilities via Agent Cards
- **Standardized Messaging** - JSON-RPC 2.0 over HTTP for reliable communication
- **Task Management** - Track asynchronous operations with state machines
- **Security** - Built-in support for OAuth2, API keys, and mutual TLS

## Crates

| Crate | Description | Docs |
|-------|-------------|------|
| [`a2a-core`](a2a-core/) | Shared A2A 0.3.0 types, JSON-RPC definitions, and utilities | [API](a2a-core/) |
| [`a2a-server`](a2a-server/) | Generic server framework with pluggable `MessageHandler` trait | [API](a2a-server/) |
| [`a2a-client`](a2a-client/) | Client library for agent discovery and message sending | [API](a2a-client/) |

## Quick Start

### Installation

Add the crates you need to your `Cargo.toml`:

```toml
[dependencies]
# For building agent servers
a2a-server = "0.1"
a2a-core = "0.1"

# For building clients
a2a-client = "0.1"
a2a-core = "0.1"

# Required async runtime
tokio = { version = "1", features = ["full"] }
```

### Build an Echo Server (5 lines)

```rust
use a2a_server::A2aServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Start a server with the built-in echo handler
    A2aServer::echo().bind("0.0.0.0:8080").run().await
}
```

### Build a Custom Agent

Implement the `MessageHandler` trait to create your own AI agent:

```rust
use a2a_server::{A2aServer, MessageHandler, HandlerResult, AuthContext};
use a2a_core::{
    AgentCard, AgentCapabilities, AgentProvider, Message, Task, TaskStatus,
    TaskState, Part, TextPart, Role, PROTOCOL_VERSION,
};
use async_trait::async_trait;

struct MyAiAgent {
    // Your AI client (OpenAI, Anthropic, local model, etc.)
}

#[async_trait]
impl MessageHandler for MyAiAgent {
    async fn handle_message(
        &self,
        message: Message,
        auth: Option<AuthContext>,
    ) -> HandlerResult<Task> {
        // 1. Extract text from the message
        let user_text: String = message.parts.iter()
            .filter_map(|p| match p {
                Part::Text(t) => Some(t.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");

        // 2. Call your AI backend
        let response = format!("You said: {}", user_text);

        // 3. Return a completed task
        Ok(a2a_core::completed_task_with_text(message, &response))
    }

    fn agent_card(&self, base_url: &str) -> AgentCard {
        AgentCard {
            id: "my-ai-agent".to_string(),
            name: "My AI Agent".to_string(),
            provider: AgentProvider {
                name: "My Organization".to_string(),
                url: Some("https://example.com".to_string()),
                email: None,
            },
            protocol_version: PROTOCOL_VERSION.to_string(),
            description: Some("An AI agent that does amazing things".to_string()),
            endpoint: format!("{}/v1/rpc", base_url),
            capabilities: AgentCapabilities::default(),
            security_schemes: vec![],
            security: vec![],
            skills: vec![],
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let agent = MyAiAgent { /* ... */ };

    A2aServer::new(agent)
        .bind("0.0.0.0:8080")
        .run()
        .await
}
```

### Build a Client

```rust
use a2a_client::{A2aClient, ClientConfig};
use a2a_core::{Message, Part, TextPart, Role};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a client
    let client = A2aClient::with_server("http://localhost:8080")?;

    // Discover the agent's capabilities
    let card = client.fetch_agent_card().await?;
    println!("Connected to: {}", card.name);

    // Create a message
    let message = Message {
        id: uuid::Uuid::new_v4().to_string(),
        role: Role::User,
        parts: vec![Part::Text(TextPart {
            text: "Hello, agent!".to_string(),
        })],
        context_id: None,
        reference_task_ids: None,
        metadata: None,
    };

    // Send the message and get a task
    let task = client.send_message(message, None).await?;
    println!("Task state: {:?}", task.status.state);

    // For async agents, poll until completion
    let completed = client.poll_until_complete(&task.id, None).await?;

    // Extract the response
    if let Some(history) = &completed.history {
        for msg in history.iter().filter(|m| m.role == Role::Agent) {
            for part in &msg.parts {
                if let Part::Text(t) = part {
                    println!("Agent: {}", t.text);
                }
            }
        }
    }

    Ok(())
}
```

## Architecture

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

## Core Concepts

### Agent Card

Every A2A agent publishes an **Agent Card** that describes its capabilities:

```rust
use a2a_core::{AgentCard, AgentCapabilities, SecurityScheme, ApiKeyLocation};

// Agents expose their card at /.well-known/agent-card.json
let card = AgentCard {
    id: "weather-agent".to_string(),
    name: "Weather Agent".to_string(),
    description: Some("Get weather forecasts for any location".to_string()),
    endpoint: "https://api.example.com/v1/rpc".to_string(),
    capabilities: AgentCapabilities {
        streaming: true,
        push_notifications: false,
        state_transition_history: true,
        extensions: vec![],
    },
    security_schemes: vec![
        SecurityScheme::ApiKey {
            name: "X-API-Key".to_string(),
            location: ApiKeyLocation::Header,
            description: Some("API key for authentication".to_string()),
        },
    ],
    // ... other fields
};
```

### Messages and Parts

Messages contain multimodal content via **Parts**:

```rust
use a2a_core::{Message, Part, TextPart, FilePart, DataPart, Role};

// Text message
let text_msg = Message {
    id: "msg-1".to_string(),
    role: Role::User,
    parts: vec![Part::Text(TextPart {
        text: "Analyze this document".to_string(),
    })],
    context_id: Some("conversation-123".to_string()),
    reference_task_ids: None,
    metadata: None,
};

// Message with file attachment
let file_msg = Message {
    id: "msg-2".to_string(),
    role: Role::User,
    parts: vec![
        Part::Text(TextPart { text: "Here's the PDF".to_string() }),
        Part::File(FilePart {
            uri: Some("https://example.com/doc.pdf".to_string()),
            bytes: None, // Or base64-encoded bytes
            media_type: "application/pdf".to_string(),
            name: Some("report.pdf".to_string()),
        }),
    ],
    context_id: None,
    reference_task_ids: None,
    metadata: None,
};

// Message with structured data
let data_msg = Message {
    id: "msg-3".to_string(),
    role: Role::User,
    parts: vec![Part::Data(DataPart {
        media_type: "application/json".to_string(),
        data: serde_json::json!({
            "location": "New York",
            "units": "celsius"
        }),
    })],
    context_id: None,
    reference_task_ids: None,
    metadata: None,
};
```

### Tasks and States

Tasks track the lifecycle of agent operations:

```rust
use a2a_core::{Task, TaskState, TaskStatus};

// Task states follow this lifecycle:
//
//   SUBMITTED → WORKING → COMPLETED
//                    ↘ → FAILED
//                    ↘ → CANCELLED
//                    ↘ → INPUT_REQUIRED → WORKING → ...

let task = Task {
    id: "tasks/abc-123".to_string(),
    context_id: "conversation-456".to_string(),
    status: TaskStatus {
        state: TaskState::Working,
        message: None,
        timestamp: Some("2024-01-15T10:30:00Z".to_string()),
    },
    history: Some(vec![/* message history */]),
    artifacts: None, // Output files, data, etc.
    metadata: None,
};

// Check if task is done
if task.status.state.is_terminal() {
    println!("Task finished with state: {:?}", task.status.state);
}
```

## Server Features

### Authentication

Add authentication to your server:

```rust
use a2a_server::{A2aServer, AuthContext};
use axum::http::HeaderMap;

A2aServer::new(my_handler)
    .bind("0.0.0.0:8080")
    .auth_extractor(|headers: &HeaderMap| {
        // Extract Bearer token
        let auth_header = headers.get("authorization")?.to_str().ok()?;
        let token = auth_header.strip_prefix("Bearer ")?;

        // Validate token and return auth context
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
use a2a_server::{A2aServer, AppState};
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

### Task Store Access

Access the task store for background updates:

```rust
let server = A2aServer::new(my_handler);
let task_store = server.get_task_store();

// Update tasks from background processes
tokio::spawn(async move {
    // ... do background work ...
    task_store.update("task-id", |task| {
        task.status.state = TaskState::Completed;
    }).await;
});

server.run().await?;
```

## Client Features

### Agent Card Caching

Agent cards are automatically cached for 5 minutes:

```rust
let client = A2aClient::with_server("http://localhost:8080")?;

// First call fetches from server
let card1 = client.fetch_agent_card().await?;

// Subsequent calls use cache
let card2 = client.fetch_agent_card().await?; // Instant!

// Force refresh if needed
client.invalidate_card_cache().await;
let card3 = client.fetch_agent_card().await?; // Fetches fresh
```

### Configurable Polling

```rust
use a2a_client::{A2aClient, ClientConfig};

let config = ClientConfig {
    server_url: "http://localhost:8080".to_string(),
    max_polls: 60,          // Maximum poll attempts
    poll_interval_ms: 1000, // 1 second between polls
    oauth: None,
};

let client = A2aClient::new(config)?;

// Automatically polls until terminal state or max attempts
let task = client.poll_until_complete("task-id", None).await?;
```

### OAuth PKCE Support

```rust
use a2a_client::{A2aClient, ClientConfig, OAuthConfig};

let config = ClientConfig {
    server_url: "http://localhost:8080".to_string(),
    oauth: Some(OAuthConfig {
        client_id: "my-app".to_string(),
        redirect_uri: "http://localhost:3000/callback".to_string(),
        scopes: vec!["read".to_string(), "write".to_string()],
        session_token: None, // Or provide existing token
    }),
    ..Default::default()
};

let client = A2aClient::new(config)?;

// Interactive OAuth flow (prompts user)
let token = client.perform_oauth_interactive().await?;

// Or programmatic flow
let (auth_url, code_verifier) = client.start_oauth_flow().await?;
// ... handle callback, exchange code ...
```

## JSON-RPC Methods

The A2A protocol defines these JSON-RPC methods:

| Method | Description | Implementation |
|--------|-------------|----------------|
| `message/send` | Send a message to the agent | Server |
| `tasks/get` | Query a task by ID | Server |
| `tasks/cancel` | Cancel a running task | Server |

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
        "id": "msg-1",
        "role": "user",
        "parts": [{"kind": "text", "text": "Hello!"}]
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
    "params": {"name": "tasks/abc-123"}
  }'
```

## Error Handling

### Server-Side Errors

```rust
use a2a_server::{HandlerError, HandlerResult};
use a2a_core::Task;

async fn handle_message(...) -> HandlerResult<Task> {
    // Input validation
    if message.parts.is_empty() {
        return Err(HandlerError::InvalidInput("Message has no parts".into()));
    }

    // Auth errors
    let auth = auth.ok_or(HandlerError::AuthRequired("Token required".into()))?;

    // Backend errors
    let response = backend.call()
        .await
        .map_err(|e| HandlerError::BackendUnavailable(e.to_string()))?;

    // Internal errors (from anyhow)
    let data = some_fallible_op()?; // Uses HandlerError::Internal

    Ok(task)
}
```

### JSON-RPC Error Codes

```rust
use a2a_core::errors;

// Standard JSON-RPC errors
errors::PARSE_ERROR;        // -32700
errors::INVALID_REQUEST;    // -32600
errors::METHOD_NOT_FOUND;   // -32601
errors::INVALID_PARAMS;     // -32602
errors::INTERNAL_ERROR;     // -32603

// A2A-specific errors
errors::TASK_NOT_FOUND;              // -32001
errors::TASK_NOT_CANCELABLE;         // -32002
errors::UNSUPPORTED_OPERATION;       // -32004
errors::VERSION_NOT_SUPPORTED;       // -32007
```

## Security Schemes

The A2A protocol supports multiple authentication methods:

```rust
use a2a_core::{SecurityScheme, ApiKeyLocation, OAuth2Flows, OAuth2Flow};

// API Key authentication
let api_key = SecurityScheme::ApiKey {
    name: "X-API-Key".to_string(),
    location: ApiKeyLocation::Header,
    description: None,
};

// Bearer token
let bearer = SecurityScheme::Http {
    scheme: "bearer".to_string(),
    bearer_format: Some("JWT".to_string()),
    description: None,
};

// OAuth 2.0
let oauth = SecurityScheme::OAuth2 {
    flows: OAuth2Flows {
        authorization_code: Some(OAuth2Flow {
            authorization_url: Some("https://auth.example.com/authorize".to_string()),
            token_url: Some("https://auth.example.com/token".to_string()),
            refresh_url: None,
            scopes: vec!["read".to_string(), "write".to_string()],
        }),
        client_credentials: None,
        implicit: None,
        password: None,
    },
    description: None,
};

// Mutual TLS
let mtls = SecurityScheme::MutualTls {
    description: Some("Client certificate required".to_string()),
};
```

## Documentation

- [Architecture Guide](docs/architecture.md) - Detailed crate structure and data flows
- [Getting Started](docs/getting-started.md) - Step-by-step tutorial
- [A2A Specification](https://github.com/a2a-protocol/a2a-spec) - Official protocol spec

## Examples

See the [`chatapi/`](../chatapi/) directory for a complete example implementation with:
- Microsoft 365 Copilot backend
- OAuth 2.0 authentication with PKCE
- Interactive CLI client

## Requirements

- Rust 1.75 or later
- Tokio async runtime

## Dependencies

These libraries use minimal, well-maintained dependencies:

| Dependency | Purpose |
|------------|---------|
| `serde` | JSON serialization |
| `tokio` | Async runtime |
| `axum` | HTTP server (a2a-server) |
| `reqwest` | HTTP client (a2a-client) |
| `uuid` | UUID generation |
| `async-trait` | Async trait support |

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for details.

## Acknowledgments

This implementation follows the [A2A Protocol Specification](https://github.com/a2a-protocol/a2a-spec) developed by the Linux Foundation AI & Data.
