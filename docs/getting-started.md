# Getting Started

This guide shows you how to use the A2A libraries to build agents and clients.

## Installation

Add the crates to your `Cargo.toml`:

```toml
[dependencies]
# For building agent servers
a2a-server = "1.0"
a2a-core = "1.0"

# For building clients
a2a-client = "1.0"
a2a-core = "1.0"

# Required
tokio = { version = "1", features = ["full"] }
anyhow = "1"
async-trait = "0.1"  # Only needed for custom handlers
```

## Building an Agent Server

### 1. Start with the Echo Server

The simplest way to get started is with the built-in `EchoHandler`:

```rust
use a2a_server::A2aServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Starting A2A Echo Server on http://127.0.0.1:8080");

    A2aServer::echo()
        .bind("0.0.0.0:8080")
        .run()
        .await
}
```

Run it:
```bash
cargo run
```

Test it:
```bash
# Get the Agent Card
curl http://127.0.0.1:8080/.well-known/agent-card.json | jq

# Check health
curl http://127.0.0.1:8080/health

# Send a message
curl -X POST http://127.0.0.1:8080/v1/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "messageId": "msg-1",
        "role": "ROLE_USER",
        "parts": [{"text": "Hello, agent!"}]
      }
    }
  }'
```

### 2. Implement a Custom Handler

Create your own agent by implementing `MessageHandler`:

```rust
use a2a_server::{A2aServer, MessageHandler, HandlerResult, AuthContext};
use a2a_core::{
    AgentCard, AgentInterface, AgentProvider, AgentSkill,
    Message, SendMessageResponse, Part, Role, PROTOCOL_VERSION,
    completed_task_with_text,
};
use async_trait::async_trait;

pub struct GreetingHandler;

#[async_trait]
impl MessageHandler for GreetingHandler {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        // Extract text from the message
        let user_text: String = message.parts.iter()
            .filter_map(|p| p.text.as_deref())
            .collect::<Vec<_>>()
            .join(" ");

        let response_text = format!("Hello! You said: {}", user_text);
        Ok(SendMessageResponse::Task(
            completed_task_with_text(message, &response_text),
        ))
    }

    fn agent_card(&self, base_url: &str) -> AgentCard {
        AgentCard {
            name: "Greeting Agent".to_string(),
            description: "A friendly greeting agent".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: format!("{}/v1/rpc", base_url),
                protocol_binding: "JSONRPC".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                tenant: None,
            }],
            provider: Some(AgentProvider {
                organization: "My Company".to_string(),
                url: "https://example.com".to_string(),
            }),
            version: PROTOCOL_VERSION.to_string(),
            skills: vec![AgentSkill {
                id: "greet".to_string(),
                name: "Greet".to_string(),
                description: "Greets the user".to_string(),
                tags: vec!["greeting".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    A2aServer::new(GreetingHandler)
        .bind("0.0.0.0:8080")
        .run()
        .await
}
```

### 3. Add Authentication

Protect your agent with authentication:

```rust
use a2a_server::{A2aServer, AuthContext, HandlerError};
use axum::http::HeaderMap;

// Server with auth extractor
A2aServer::new(my_handler)
    .bind("0.0.0.0:8080")
    .auth_extractor(|headers: &HeaderMap| {
        let auth_header = headers.get("authorization")?;
        let auth_str = auth_header.to_str().ok()?;
        let token = auth_str.strip_prefix("Bearer ")?;

        // In production, validate the token here
        Some(AuthContext {
            user_id: "user-from-token".to_string(),
            access_token: token.to_string(),
            metadata: None,
        })
    })
    .run()
    .await?;
```

In your handler, require authentication:

```rust
async fn handle_message(
    &self,
    message: Message,
    auth: Option<AuthContext>,
) -> HandlerResult<SendMessageResponse> {
    let auth = auth.ok_or_else(|| {
        HandlerError::AuthRequired("Bearer token required".to_string())
    })?;

    println!("Request from user: {}", auth.user_id);

    // Process message...
    Ok(SendMessageResponse::Task(
        completed_task_with_text(message, "Authenticated response"),
    ))
}
```

---

## Building a Client

### 1. Discover an Agent

```rust
use a2a_client::A2aClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = A2aClient::with_server("http://127.0.0.1:8080")?;

    let card = client.fetch_agent_card().await?;

    println!("Agent: {}", card.name);
    println!("Description: {}", card.description);
    if let Some(endpoint) = card.endpoint() {
        println!("Endpoint: {}", endpoint);
    }

    if !card.skills.is_empty() {
        println!("Skills:");
        for skill in &card.skills {
            println!("  - {}: {}", skill.name, skill.description);
        }
    }

    Ok(())
}
```

### 2. Send a Message

```rust
use a2a_client::A2aClient;
use a2a_core::{Message, Part, Role, SendMessageResponse};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = A2aClient::with_server("http://127.0.0.1:8080")?;

    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        role: Role::User,
        parts: vec![Part::text("What is the capital of France?")],
        context_id: None,
        task_id: None,
        extensions: vec![],
        reference_task_ids: None,
        metadata: None,
    };

    let response = client.send_message(message, None).await?;

    match response {
        SendMessageResponse::Task(task) => {
            println!("Task ID: {}", task.id);
            println!("State: {:?}", task.status.state);
            if let Some(history) = &task.history {
                for msg in history.iter().filter(|m| m.role == Role::Agent) {
                    for part in &msg.parts {
                        if let Some(text) = &part.text {
                            println!("Response: {}", text);
                        }
                    }
                }
            }
        }
        SendMessageResponse::Message(msg) => {
            for part in &msg.parts {
                if let Some(text) = &part.text {
                    println!("Response: {}", text);
                }
            }
        }
    }

    Ok(())
}
```

### 3. Poll for Completion (Async Tasks)

For agents that process asynchronously:

```rust
use a2a_client::{A2aClient, ClientConfig};
use a2a_core::{Message, Part, Role, SendMessageResponse, TaskState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ClientConfig {
        server_url: "http://127.0.0.1:8080".to_string(),
        max_polls: 60,
        poll_interval_ms: 1000,
        oauth: None,
    };

    let client = A2aClient::new(config)?;

    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        role: Role::User,
        parts: vec![Part::text("Generate a long report...")],
        context_id: None,
        task_id: None,
        extensions: vec![],
        reference_task_ids: None,
        metadata: None,
    };

    let response = client.send_message(message, None).await?;
    let task_id = match &response {
        SendMessageResponse::Task(t) => t.id.clone(),
        SendMessageResponse::Message(_) => anyhow::bail!("Expected task response"),
    };

    println!("Task submitted: {}", task_id);

    let completed = client.poll_until_complete(&task_id, None).await?;

    match completed.status.state {
        TaskState::Completed => println!("Task completed successfully!"),
        TaskState::Failed => println!("Task failed!"),
        state => println!("Task ended in state: {:?}", state),
    }

    Ok(())
}
```

### 4. Using OAuth Authentication

```rust
use a2a_client::{A2aClient, ClientConfig, OAuthConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ClientConfig {
        server_url: "http://localhost:8080".to_string(),
        max_polls: 30,
        poll_interval_ms: 2000,
        oauth: Some(OAuthConfig {
            client_id: "my-app".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scopes: vec![
                "User.Read".to_string(),
                "offline_access".to_string(),
            ],
            session_token: None,
        }),
    };

    let client = A2aClient::new(config)?;

    // Interactive OAuth flow (opens browser, prompts user)
    let session_token = client.perform_oauth_interactive().await?;
    println!("Obtained session token!");

    // Now use the token for requests
    let message = a2a_core::new_message(
        a2a_core::Role::User,
        "Hello with auth!",
        None,
    );

    let response = client.send_message(message, Some(&session_token)).await?;
    println!("Authenticated request succeeded!");

    Ok(())
}
```

---

## Working with Messages

### Creating Messages

```rust
use a2a_core::{Message, Part, Role, new_message};

// Simple text message using helper
let simple_msg = new_message(Role::User, "Hello, world!", None);

// Text message with context ID
let text_msg = new_message(
    Role::User,
    "Continue our conversation",
    Some("conversation-123".to_string()),
);

// Manual message construction with multiple parts
let complex_msg = Message {
    message_id: uuid::Uuid::new_v4().to_string(),
    role: Role::User,
    parts: vec![
        Part::text("Please analyze this data:"),
        Part::data(
            serde_json::json!({
                "sales": [100, 200, 150],
                "period": "Q1 2024"
            }),
            "application/json",
        ),
    ],
    context_id: Some("analysis-session".to_string()),
    task_id: None,
    extensions: vec![],
    reference_task_ids: None,
    metadata: Some(serde_json::json!({"priority": "high"})),
};
```

### Multimodal Messages

```rust
use a2a_core::{Message, Part, Role};

// Message with URL reference
let file_msg = Message {
    message_id: uuid::Uuid::new_v4().to_string(),
    role: Role::User,
    parts: vec![
        Part::text("Summarize this document"),
        Part::url("https://example.com/report.pdf", "application/pdf"),
    ],
    context_id: None,
    task_id: None,
    extensions: vec![],
    reference_task_ids: None,
    metadata: None,
};

// Message with inline bytes (base64 encoded)
let image_msg = Message {
    message_id: uuid::Uuid::new_v4().to_string(),
    role: Role::User,
    parts: vec![
        Part::text("What's in this image?"),
        Part::raw("iVBORw0KGgoAAAANS...", "image/png"),
    ],
    context_id: None,
    task_id: None,
    extensions: vec![],
    reference_task_ids: None,
    metadata: None,
};
```

---

## Common Patterns

### Error Handling in Handlers

```rust
use a2a_server::{HandlerError, HandlerResult};
use a2a_core::{Message, Part, SendMessageResponse, completed_task_with_text};

async fn handle_message(
    message: Message,
    auth: Option<AuthContext>,
) -> HandlerResult<SendMessageResponse> {
    // Validate input
    if message.parts.is_empty() {
        return Err(HandlerError::InvalidInput(
            "Message must have at least one part".to_string()
        ));
    }

    // Require authentication
    let auth = auth.ok_or_else(|| {
        HandlerError::AuthRequired("This operation requires authentication".to_string())
    })?;

    // Handle backend errors
    let response = call_backend(&message)
        .await
        .map_err(|e| HandlerError::backend_unavailable(
            format!("Backend error: {}", e)
        ))?;

    Ok(SendMessageResponse::Task(
        completed_task_with_text(message, &response),
    ))
}
```

### Conversation Context

```rust
use a2a_core::{Message, Part, Role};
use uuid::Uuid;

// Start a new conversation
let context_id = Uuid::new_v4().to_string();

let msg1 = Message {
    message_id: Uuid::new_v4().to_string(),
    role: Role::User,
    parts: vec![Part::text("My name is Alice")],
    context_id: Some(context_id.clone()),
    task_id: None,
    extensions: vec![],
    reference_task_ids: None,
    metadata: None,
};

// Continue the same conversation
let msg2 = Message {
    message_id: Uuid::new_v4().to_string(),
    role: Role::User,
    parts: vec![Part::text("What's my name?")],
    context_id: Some(context_id.clone()), // Same context_id
    task_id: None,
    extensions: vec![],
    reference_task_ids: None,
    metadata: None,
};
```

---

## Testing Your Agent

### Unit Testing Handlers

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use a2a_core::{Role, TaskState, SendMessageResponse, new_message};

    #[tokio::test]
    async fn test_greeting_handler() {
        let handler = GreetingHandler;

        let message = new_message(Role::User, "Hello", None);
        let response = handler.handle_message(message, None).await.unwrap();

        match response {
            SendMessageResponse::Task(task) => {
                assert_eq!(task.status.state, TaskState::Completed);
                let history = task.history.unwrap();
                assert_eq!(history.len(), 2); // User message + agent response

                let agent_msg = &history[1];
                assert_eq!(agent_msg.role, Role::Agent);
                assert!(agent_msg.parts[0].text.as_deref().unwrap().contains("Hello"));
            }
            _ => panic!("Expected Task response"),
        }
    }
}
```

### Integration Testing with the Router

```rust
use a2a_server::A2aServer;
use axum::{body::Body, http::{Request, StatusCode}};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn test_echo_server() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": {
            "message": {
                "messageId": "msg-1",
                "role": "ROLE_USER",
                "parts": [{"text": "Hello!"}]
            }
        },
        "id": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
```

---

## Next Steps

1. **Read the [Architecture Guide](architecture.md)** for a deeper understanding of the crates
2. **Run the echo example** in `examples/echo_server.rs`
3. **Implement your handler** for your preferred AI backend (OpenAI, Anthropic, local models, etc.)
4. **Add authentication** appropriate for your use case
5. **Deploy** with proper monitoring and error handling
