# Getting Started

This guide shows you how to use the A2A libraries to build agents and clients.

## Installation

Add the crates to your `Cargo.toml`:

```toml
[dependencies]
# For building agent servers
a2a-server = "0.1"
a2a-core = "0.1"

# For building clients
a2a-client = "0.1"
a2a-core = "0.1"

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
        "id": "msg-1",
        "role": "user",
        "parts": [{"kind": "text", "text": "Hello, agent!"}]
      }
    }
  }'
```

### 2. Implement a Custom Handler

Create your own agent by implementing `MessageHandler`:

```rust
use a2a_server::{A2aServer, MessageHandler, HandlerResult, AuthContext};
use a2a_core::{
    AgentCard, AgentCapabilities, AgentProvider, AgentSkill,
    Message, Task, Part, TextPart, Role, PROTOCOL_VERSION,
};
use async_trait::async_trait;

pub struct GreetingHandler;

#[async_trait]
impl MessageHandler for GreetingHandler {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<Task> {
        // Extract text from the message
        let user_text: String = message.parts.iter()
            .filter_map(|p| match p {
                Part::Text(t) => Some(t.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(" ");

        // Generate a greeting response
        let response_text = format!("Hello! You said: {}", user_text);

        // Build the response task using the helper function
        Ok(a2a_core::completed_task_with_text(message, &response_text))
    }

    fn agent_card(&self, base_url: &str) -> AgentCard {
        AgentCard {
            id: "greeting-agent".to_string(),
            name: "Greeting Agent".to_string(),
            provider: AgentProvider {
                name: "My Company".to_string(),
                url: None,
                email: None,
            },
            protocol_version: PROTOCOL_VERSION.to_string(),
            description: Some("A friendly greeting agent".to_string()),
            endpoint: format!("{}/v1/rpc", base_url),
            capabilities: AgentCapabilities::default(),
            security_schemes: vec![],
            security: vec![],
            skills: vec![AgentSkill {
                id: "greet".to_string(),
                name: "Greet".to_string(),
                description: "Greets the user".to_string(),
                input_schema: None,
                output_schema: None,
                tags: vec!["greeting".to_string()],
            }],
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

// Handler that requires authentication
#[async_trait]
impl MessageHandler for SecureHandler {
    async fn handle_message(
        &self,
        message: Message,
        auth: Option<AuthContext>,
    ) -> HandlerResult<Task> {
        // Require authentication
        let auth = auth.ok_or_else(|| {
            HandlerError::AuthRequired("Bearer token required".to_string())
        })?;

        println!("Request from user: {}", auth.user_id);

        // Process message...
        Ok(a2a_core::completed_task_with_text(message, "Authenticated response"))
    }

    // ... agent_card implementation
}

// Server with auth extractor
A2aServer::new(SecureHandler)
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

---

## Building a Client

### 1. Discover an Agent

```rust
use a2a_client::A2aClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = A2aClient::with_server("http://127.0.0.1:8080")?;

    // Discover the agent's capabilities
    let agent_card = client.fetch_agent_card().await?;

    println!("Agent: {}", agent_card.name);
    println!("Description: {:?}", agent_card.description);
    println!("Endpoint: {}", agent_card.endpoint);
    println!("Capabilities:");
    println!("  - Streaming: {}", agent_card.capabilities.streaming);
    println!("  - Push notifications: {}", agent_card.capabilities.push_notifications);

    if !agent_card.skills.is_empty() {
        println!("Skills:");
        for skill in &agent_card.skills {
            println!("  - {}: {}", skill.name, skill.description);
        }
    }

    Ok(())
}
```

### 2. Send a Message

```rust
use a2a_client::A2aClient;
use a2a_core::{Message, Part, TextPart, Role};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = A2aClient::with_server("http://127.0.0.1:8080")?;

    // Create a message
    let message = Message {
        id: uuid::Uuid::new_v4().to_string(),
        role: Role::User,
        parts: vec![Part::Text(TextPart {
            text: "What is the capital of France?".to_string(),
        })],
        context_id: None,
        reference_task_ids: None,
        metadata: None,
    };

    // Send and get the task
    let task = client.send_message(message, None).await?;

    println!("Task ID: {}", task.id);
    println!("State: {:?}", task.status.state);

    // Extract response text from history
    if let Some(history) = &task.history {
        for msg in history.iter().filter(|m| m.role == Role::Agent) {
            for part in &msg.parts {
                if let Part::Text(t) = part {
                    println!("Response: {}", t.text);
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
use a2a_core::{Message, Part, TextPart, Role, TaskState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure polling behavior
    let config = ClientConfig {
        server_url: "http://127.0.0.1:8080".to_string(),
        max_polls: 60,          // Try up to 60 times
        poll_interval_ms: 1000, // Wait 1 second between polls
        oauth: None,
    };

    let client = A2aClient::new(config)?;

    let message = Message {
        id: uuid::Uuid::new_v4().to_string(),
        role: Role::User,
        parts: vec![Part::Text(TextPart {
            text: "Generate a long report...".to_string(),
        })],
        context_id: None,
        reference_task_ids: None,
        metadata: None,
    };

    // Send message
    let task = client.send_message(message, None).await?;
    println!("Task submitted: {}", task.id);

    // Poll until complete
    let completed = client.poll_until_complete(&task.id, None).await?;

    match completed.status.state {
        TaskState::Completed => {
            println!("Task completed successfully!");
            // Extract response...
        }
        TaskState::Failed => {
            println!("Task failed!");
        }
        state => {
            println!("Task ended in state: {:?}", state);
        }
    }

    Ok(())
}
```

### 4. Manual Polling Loop

For more control over the polling process:

```rust
use a2a_client::A2aClient;
use a2a_core::TaskState;
use std::time::Duration;

async fn wait_for_task(client: &A2aClient, task_id: &str) -> anyhow::Result<()> {
    let mut attempts = 0;
    let max_attempts = 30;

    loop {
        let task = client.poll_task(task_id, None).await?;

        println!("Attempt {}: state = {:?}", attempts + 1, task.status.state);

        if task.status.state.is_terminal() {
            match task.status.state {
                TaskState::Completed => {
                    println!("Success!");
                    return Ok(());
                }
                TaskState::Failed => {
                    anyhow::bail!("Task failed");
                }
                TaskState::Cancelled => {
                    anyhow::bail!("Task was cancelled");
                }
                _ => {
                    anyhow::bail!("Task ended unexpectedly: {:?}", task.status.state);
                }
            }
        }

        attempts += 1;
        if attempts >= max_attempts {
            anyhow::bail!("Max polling attempts exceeded");
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
```

### 5. Using OAuth Authentication

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
            session_token: None, // Will be obtained via OAuth flow
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

    let task = client.send_message(message, Some(&session_token)).await?;
    println!("Authenticated request succeeded: {:?}", task.status.state);

    Ok(())
}
```

---

## Working with Messages

### Creating Messages

```rust
use a2a_core::{Message, Part, TextPart, FilePart, DataPart, Role, new_message};

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
    id: uuid::Uuid::new_v4().to_string(),
    role: Role::User,
    parts: vec![
        Part::Text(TextPart {
            text: "Please analyze this data:".to_string(),
        }),
        Part::Data(DataPart {
            media_type: "application/json".to_string(),
            data: serde_json::json!({
                "sales": [100, 200, 150],
                "period": "Q1 2024"
            }),
        }),
    ],
    context_id: Some("analysis-session".to_string()),
    reference_task_ids: None,
    metadata: Some(serde_json::json!({
        "priority": "high"
    })),
};
```

### Multimodal Messages

```rust
use a2a_core::{Message, Part, TextPart, FilePart, Role};

// Message with file attachment (URL reference)
let file_url_msg = Message {
    id: uuid::Uuid::new_v4().to_string(),
    role: Role::User,
    parts: vec![
        Part::Text(TextPart {
            text: "Summarize this document".to_string(),
        }),
        Part::File(FilePart {
            uri: Some("https://example.com/report.pdf".to_string()),
            bytes: None,
            media_type: "application/pdf".to_string(),
            name: Some("quarterly-report.pdf".to_string()),
        }),
    ],
    context_id: None,
    reference_task_ids: None,
    metadata: None,
};

// Message with inline file (base64 encoded)
let file_inline_msg = Message {
    id: uuid::Uuid::new_v4().to_string(),
    role: Role::User,
    parts: vec![
        Part::Text(TextPart {
            text: "What's in this image?".to_string(),
        }),
        Part::File(FilePart {
            uri: None,
            bytes: Some("iVBORw0KGgoAAAANS...".to_string()), // base64 data
            media_type: "image/png".to_string(),
            name: Some("screenshot.png".to_string()),
        }),
    ],
    context_id: None,
    reference_task_ids: None,
    metadata: None,
};
```

---

## Common Patterns

### Error Handling in Handlers

```rust
use a2a_server::{HandlerError, HandlerResult};
use a2a_core::{Task, Message, Part};

async fn handle_message(
    message: Message,
    auth: Option<AuthContext>,
) -> HandlerResult<Task> {
    // Validate input
    if message.parts.is_empty() {
        return Err(HandlerError::InvalidInput(
            "Message must have at least one part".to_string()
        ));
    }

    // Check for text content
    let has_text = message.parts.iter().any(|p| matches!(p, Part::Text(_)));
    if !has_text {
        return Err(HandlerError::InvalidInput(
            "Message must contain text".to_string()
        ));
    }

    // Require authentication for certain operations
    let auth = auth.ok_or_else(|| {
        HandlerError::AuthRequired("This operation requires authentication".to_string())
    })?;

    // Handle backend errors gracefully
    let response = call_backend(&message)
        .await
        .map_err(|e| HandlerError::BackendUnavailable(
            format!("Backend error: {}", e)
        ))?;

    // Use ? for internal errors (converts via From<anyhow::Error>)
    let processed = process_response(response)?;

    Ok(a2a_core::completed_task_with_text(message, &processed))
}
```

### Conversation Context

```rust
use a2a_core::{Message, Part, TextPart, Role};
use uuid::Uuid;

// Start a new conversation
let context_id = Uuid::new_v4().to_string();

let msg1 = Message {
    id: Uuid::new_v4().to_string(),
    role: Role::User,
    parts: vec![Part::Text(TextPart {
        text: "My name is Alice".to_string(),
    })],
    context_id: Some(context_id.clone()),
    reference_task_ids: None,
    metadata: None,
};

// Continue the same conversation
let msg2 = Message {
    id: Uuid::new_v4().to_string(),
    role: Role::User,
    parts: vec![Part::Text(TextPart {
        text: "What's my name?".to_string(),
    })],
    context_id: Some(context_id.clone()), // Same context_id
    reference_task_ids: None,
    metadata: None,
};
```

### Accessing Task Store from Background Tasks

```rust
use a2a_server::{A2aServer, TaskStore};
use a2a_core::TaskState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server = A2aServer::new(my_handler);
    let task_store = server.get_task_store();

    // Spawn background worker
    let store_clone = task_store.clone();
    tokio::spawn(async move {
        // Simulate background processing
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Update a task
        store_clone.update("tasks/some-id", |task| {
            task.status.state = TaskState::Completed;
            task.status.timestamp = Some(a2a_core::now_iso8601());
        }).await;
    });

    server.run().await
}
```

---

## Testing Your Agent

### Unit Testing Handlers

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_greeting_handler() {
        let handler = GreetingHandler;

        let message = a2a_core::new_message(
            Role::User,
            "Hello",
            None,
        );

        let task = handler.handle_message(message, None).await.unwrap();

        assert_eq!(task.status.state, TaskState::Completed);
        assert!(task.history.is_some());

        let history = task.history.unwrap();
        assert_eq!(history.len(), 2); // User message + agent response

        // Check agent response
        let agent_msg = &history[1];
        assert_eq!(agent_msg.role, Role::Agent);

        if let Part::Text(t) = &agent_msg.parts[0] {
            assert!(t.text.contains("Hello"));
        } else {
            panic!("Expected text part");
        }
    }

    #[tokio::test]
    async fn test_handler_requires_auth() {
        let handler = SecureHandler;

        let message = a2a_core::new_message(Role::User, "Test", None);

        // Without auth should fail
        let result = handler.handle_message(message.clone(), None).await;
        assert!(matches!(result, Err(HandlerError::AuthRequired(_))));

        // With auth should succeed
        let auth = AuthContext {
            user_id: "test-user".to_string(),
            access_token: "test-token".to_string(),
            metadata: None,
        };
        let result = handler.handle_message(message, Some(auth)).await;
        assert!(result.is_ok());
    }
}
```

### Integration Testing with Client

```rust
#[tokio::test]
async fn test_server_client_integration() {
    // Start server in background
    let server_handle = tokio::spawn(async {
        A2aServer::echo()
            .bind("127.0.0.1:18080")
            .run()
            .await
            .unwrap();
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Test with client
    let client = A2aClient::with_server("http://127.0.0.1:18080").unwrap();

    let card = client.fetch_agent_card().await.unwrap();
    assert_eq!(card.name, "Echo Agent");

    let message = a2a_core::new_message(Role::User, "Test message", None);
    let task = client.send_message(message, None).await.unwrap();

    assert_eq!(task.status.state, TaskState::Completed);

    server_handle.abort();
}
```

---

## Next Steps

1. **Read the [Architecture Guide](architecture.md)** for a deeper understanding of the crates
2. **Check the examples** in `chatapi/` for a full implementation with Microsoft Copilot
3. **Implement your handler** for your preferred AI backend (OpenAI, Anthropic, local models, etc.)
4. **Add authentication** appropriate for your use case
5. **Deploy** with proper monitoring and error handling

## Troubleshooting

### Port Already in Use

```bash
# Find and kill process on port 8080
lsof -i :8080 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

### Connection Refused

Make sure:
1. Server is running and listening on the expected address
2. Firewall allows connections
3. Using correct protocol (http vs https)

```bash
# Check if server is listening
netstat -an | grep 8080

# Test connectivity
curl -v http://localhost:8080/health
```

### Serialization Errors

Ensure your types derive the correct traits:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyType { /* ... */ }
```

### Handler Panics

Wrap fallible operations in proper error handling:
```rust
// Bad: This will panic
let text = message.parts[0].as_text().unwrap();

// Good: Return an error
let text = message.parts.first()
    .and_then(|p| match p {
        Part::Text(t) => Some(t.text.as_str()),
        _ => None,
    })
    .ok_or_else(|| HandlerError::InvalidInput("No text part".to_string()))?;
```

### Agent Card Not Found

Ensure your server is returning the agent card:
```bash
curl -v http://localhost:8080/.well-known/agent-card.json
```

Check that your `MessageHandler::agent_card()` implementation returns a valid card.
