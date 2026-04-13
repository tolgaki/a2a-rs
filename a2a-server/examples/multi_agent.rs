//! Multi-agent communication example
//!
//! Demonstrates the agent-to-agent (A2A) pattern where a "Coordinator" agent
//! receives user messages and delegates work to a "Worker" agent using the
//! A2A v1.0 protocol over JSON-RPC.
//!
//! Architecture:
//!
//!   User  --->  Coordinator (port 3001)  --->  Worker (port 3002)
//!                  |                              |
//!                  |  1. Receives user message    |
//!                  |  2. Creates A2aClient        |
//!                  |  3. Fetches Worker card  --->|
//!                  |  4. Forwards message     --->|
//!                  |  5. Gets Worker result   <---|
//!                  |  6. Wraps combined result    |
//!          <---    |  7. Returns to user          |
//!
//! Run with:
//!   cargo run --example multi_agent
//!
//! Then test with:
//!   curl -s http://127.0.0.1:3001/.well-known/agent-card.json | jq .name
//!
//!   curl -s -X POST http://127.0.0.1:3001/v1/rpc \
//!     -H "Content-Type: application/json" \
//!     -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{
//!       "message":{"messageId":"m1","role":"user","parts":[{"kind":"text","text":"reverse hello world"}]}}}'
//!
//! The Coordinator will forward "hello world" to the Worker, which reverses the
//! text. The Coordinator then wraps the result with its own context.

use a2a_rs_client::{A2aClient, ClientConfig};
use a2a_rs_core::{
    AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill, Message, Part, Role,
    SendMessageResponse, SendMessageResult, Task, TaskState, TaskStatus, PROTOCOL_VERSION,
};
use a2a_rs_server::{A2aServer, AuthContext, HandlerError, HandlerResult, MessageHandler};
use async_trait::async_trait;

// ---------------------------------------------------------------------------
// Worker Agent (port 3002)
// ---------------------------------------------------------------------------

/// The Worker agent performs the actual text processing. It receives a message
/// and reverses the text content, returning the result as a completed Task.
struct WorkerAgent;

#[async_trait]
impl MessageHandler for WorkerAgent {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        let input = message
            .parts
            .iter()
            .filter_map(|p| p.as_text())
            .collect::<Vec<_>>()
            .join(" ");

        // The worker's job: reverse the text
        let reversed: String = input.chars().rev().collect();

        let context_id = message
            .context_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let task_id = uuid::Uuid::new_v4().to_string();

        let agent_message = Message {
            kind: "message".to_string(),
            message_id: uuid::Uuid::new_v4().to_string(),
            context_id: Some(context_id.clone()),
            task_id: Some(task_id.clone()),
            role: Role::Agent,
            parts: vec![Part::text(&reversed)],
            metadata: None,
            extensions: vec![],
            reference_task_ids: None,
        };

        let task = Task {
            kind: "task".to_string(),
            id: task_id,
            context_id,
            status: TaskStatus {
                state: TaskState::Completed,
                message: Some(agent_message.clone()),
                timestamp: Some(chrono::Utc::now().to_rfc3339()),
            },
            history: Some(vec![message, agent_message]),
            artifacts: None,
            metadata: None,
        };

        Ok(SendMessageResponse::Task(task))
    }

    fn agent_card(&self, base_url: &str) -> AgentCard {
        AgentCard {
            name: "Worker Agent".to_string(),
            description: "A worker agent that reverses text".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: format!("{}/v1/rpc", base_url),
                protocol_binding: "JSONRPC".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                tenant: None,
            }],
            provider: Some(AgentProvider {
                organization: "A2A Examples".to_string(),
                url: "https://github.com/tolgaki/a2a-rs".to_string(),
            }),
            version: PROTOCOL_VERSION.to_string(),
            capabilities: AgentCapabilities {
                streaming: Some(false),
                push_notifications: Some(false),
                ..Default::default()
            },
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            skills: vec![AgentSkill {
                id: "reverse".to_string(),
                name: "Text Reversal".to_string(),
                description: "Reverses the input text".to_string(),
                tags: vec!["text".to_string(), "utility".to_string()],
                examples: vec!["hello world".to_string()],
                input_modes: vec!["text/plain".to_string()],
                output_modes: vec!["text/plain".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Coordinator Agent (port 3001)
// ---------------------------------------------------------------------------

/// The Coordinator agent receives user messages, delegates to the Worker agent
/// via A2A protocol, and returns the combined result. This demonstrates how
/// agents can compose by using the A2A client to talk to other agents.
struct CoordinatorAgent {
    /// Base URL of the Worker agent
    worker_url: String,
}

#[async_trait]
impl MessageHandler for CoordinatorAgent {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        let input = message
            .parts
            .iter()
            .filter_map(|p| p.as_text())
            .collect::<Vec<_>>()
            .join(" ");

        // Strip the "reverse " command prefix if present, otherwise forward as-is
        let text_to_forward = input
            .strip_prefix("reverse ")
            .unwrap_or(&input)
            .to_string();

        // --- Step 1: Create an A2A client pointing at the Worker agent ---
        let client = A2aClient::new(ClientConfig {
            server_url: self.worker_url.clone(),
            ..Default::default()
        })
        .map_err(|e| HandlerError::Internal(e))?;

        // --- Step 2: Fetch the Worker's agent card ---
        let card = client.fetch_agent_card().await.map_err(|e| {
            HandlerError::Internal(e.context("Failed to fetch worker agent card"))
        })?;
        tracing::info!(
            worker_name = %card.name,
            worker_skills = card.skills.len(),
            "Discovered worker agent"
        );

        // --- Step 3: Forward the user's message to the Worker ---
        let forwarded_message = Message {
            kind: "message".to_string(),
            message_id: uuid::Uuid::new_v4().to_string(),
            context_id: message.context_id.clone(),
            task_id: None,
            role: Role::User,
            parts: vec![Part::text(&text_to_forward)],
            metadata: None,
            extensions: vec![],
            reference_task_ids: None,
        };

        let worker_result = client
            .send_message(forwarded_message, None, None)
            .await
            .map_err(|e| {
                HandlerError::Internal(e.context("Worker agent call failed"))
            })?;

        // --- Step 4: Extract the worker's reply ---
        let worker_reply = match &worker_result {
            SendMessageResult::Task(task) => {
                // Get text from the task's status message or history
                task.status
                    .message
                    .as_ref()
                    .and_then(|m| {
                        m.parts
                            .iter()
                            .filter_map(|p| p.as_text())
                            .next()
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "(no reply from worker)".to_string())
            }
            SendMessageResult::Message(msg) => msg
                .parts
                .iter()
                .filter_map(|p| p.as_text())
                .next()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "(no reply from worker)".to_string()),
        };

        // --- Step 5: Build the Coordinator's combined response ---
        let combined_text = format!(
            "[Coordinator] Sent '{}' to Worker '{}'. Result: {}",
            text_to_forward, card.name, worker_reply
        );

        let context_id = message
            .context_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let task_id = uuid::Uuid::new_v4().to_string();

        let agent_message = Message {
            kind: "message".to_string(),
            message_id: uuid::Uuid::new_v4().to_string(),
            context_id: Some(context_id.clone()),
            task_id: Some(task_id.clone()),
            role: Role::Agent,
            parts: vec![Part::text(&combined_text)],
            metadata: None,
            extensions: vec![],
            reference_task_ids: None,
        };

        let task = Task {
            kind: "task".to_string(),
            id: task_id,
            context_id,
            status: TaskStatus {
                state: TaskState::Completed,
                message: Some(agent_message.clone()),
                timestamp: Some(chrono::Utc::now().to_rfc3339()),
            },
            history: Some(vec![message, agent_message]),
            artifacts: None,
            metadata: None,
        };

        Ok(SendMessageResponse::Task(task))
    }

    fn agent_card(&self, base_url: &str) -> AgentCard {
        AgentCard {
            name: "Coordinator Agent".to_string(),
            description: "Coordinates work by delegating to other agents via A2A".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: format!("{}/v1/rpc", base_url),
                protocol_binding: "JSONRPC".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                tenant: None,
            }],
            provider: Some(AgentProvider {
                organization: "A2A Examples".to_string(),
                url: "https://github.com/tolgaki/a2a-rs".to_string(),
            }),
            version: PROTOCOL_VERSION.to_string(),
            capabilities: AgentCapabilities {
                streaming: Some(false),
                push_notifications: Some(false),
                ..Default::default()
            },
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            skills: vec![AgentSkill {
                id: "delegate".to_string(),
                name: "Delegation".to_string(),
                description: "Delegates text processing to a worker agent".to_string(),
                tags: vec!["coordination".to_string(), "delegation".to_string()],
                examples: vec!["reverse hello world".to_string()],
                input_modes: vec!["text/plain".to_string()],
                output_modes: vec!["text/plain".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let worker_addr = "127.0.0.1:3002";
    let coordinator_addr = "127.0.0.1:3001";
    let worker_url = format!("http://{}", worker_addr);

    // --- Start the Worker agent in a background task ---
    println!("Starting Worker Agent on http://{}", worker_addr);
    let worker_server = A2aServer::new(WorkerAgent).bind(worker_addr)?;
    let worker_handle = tokio::spawn(async move {
        if let Err(e) = worker_server.run().await {
            eprintln!("Worker agent error: {}", e);
        }
    });

    // Give the Worker a moment to bind its port
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // --- Start the Coordinator agent ---
    println!("Starting Coordinator Agent on http://{}", coordinator_addr);
    println!();
    println!("The Coordinator delegates to the Worker via A2A protocol.");
    println!();
    println!("Try:");
    println!(
        r#"  curl -s http://{}/.well-known/agent-card.json | jq .name"#,
        coordinator_addr
    );
    println!();
    println!(r#"  curl -s -X POST http://{}/v1/rpc \"#, coordinator_addr);
    println!(r#"    -H "Content-Type: application/json" \"#);
    println!(
        r#"    -d '{{"jsonrpc":"2.0","id":1,"method":"message/send","params":{{"message":{{"messageId":"m1","role":"user","parts":[{{"kind":"text","text":"reverse hello world"}}]}}}}}}' | jq ."#
    );

    let coordinator_server = A2aServer::new(CoordinatorAgent {
        worker_url: worker_url.clone(),
    })
    .bind(coordinator_addr)?;
    let coordinator_handle = tokio::spawn(async move {
        if let Err(e) = coordinator_server.run().await {
            eprintln!("Coordinator agent error: {}", e);
        }
    });

    // Wait for both servers (they run until Ctrl+C)
    tokio::select! {
        r = worker_handle => { r?; }
        r = coordinator_handle => { r?; }
    }

    Ok(())
}
