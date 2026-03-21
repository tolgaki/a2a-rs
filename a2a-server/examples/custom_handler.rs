//! Custom message handler example
//!
//! Demonstrates how to implement the `MessageHandler` trait to create your own
//! A2A agent with custom logic, skills, and a rich agent card.
//!
//! This example creates a "Greeting Agent" that can:
//! - Greet users by name
//! - Tell the current time
//!
//! Run with:
//!   cargo run --example custom_handler
//!
//! Then test with:
//!   # Fetch the agent card
//!   curl http://127.0.0.1:3000/.well-known/agent-card.json | jq
//!
//!   # Send a greeting
//!   curl -X POST http://127.0.0.1:3000/v1/rpc \
//!     -H "Content-Type: application/json" \
//!     -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{
//!       "message":{"messageId":"msg-1","role":"ROLE_USER","parts":[{"kind":"text","text":"Hello, my name is Alice"}]}}}'
//!
//!   # Ask for the time
//!   curl -X POST http://127.0.0.1:3000/v1/rpc \
//!     -H "Content-Type: application/json" \
//!     -d '{"jsonrpc":"2.0","id":2,"method":"message/send","params":{
//!       "message":{"messageId":"msg-2","role":"ROLE_USER","parts":[{"kind":"text","text":"time"}]}}}'

use a2a_rs_core::{
    AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill, Artifact, Message,
    Part, Role, SendMessageResponse, Task, TaskState, TaskStatus, PROTOCOL_VERSION,
};
use a2a_rs_server::{A2aServer, AuthContext, HandlerError, HandlerResult, MessageHandler};
use async_trait::async_trait;

/// A custom agent that handles greetings and time queries.
struct GreetingAgent;

#[async_trait]
impl MessageHandler for GreetingAgent {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        // Extract the text from incoming message parts
        let input = message
            .parts
            .iter()
            .filter_map(|p| p.as_text())
            .collect::<Vec<_>>()
            .join(" ");

        let input_lower = input.to_lowercase();

        // Route to the appropriate skill based on content
        let (reply_text, artifacts) = if input_lower.contains("time") {
            let now = chrono::Utc::now().to_rfc3339();
            (
                format!("The current UTC time is: {}", now),
                // Return time as a structured data artifact
                Some(vec![Artifact {
                    artifact_id: uuid::Uuid::new_v4().to_string(),
                    name: Some("current_time".to_string()),
                    description: Some("Current UTC timestamp".to_string()),
                    parts: vec![Part::data(serde_json::json!({ "utc": now }))],
                    metadata: None,
                    extensions: vec![],
                }]),
            )
        } else if input_lower.contains("name") || input_lower.contains("hello") {
            // Try to extract a name from the message
            let name = extract_name(&input).unwrap_or("friend");
            (format!("Hello, {}! Welcome to A2A.", name), None)
        } else {
            return Err(HandlerError::InvalidInput(format!(
                "I don't understand '{}'. Try greeting me or asking for the time.",
                input
            )));
        };

        // Build the response
        let context_id = message
            .context_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let task_id = uuid::Uuid::new_v4().to_string();

        let agent_message = Message {
            message_id: uuid::Uuid::new_v4().to_string(),
            context_id: Some(context_id.clone()),
            task_id: Some(task_id.clone()),
            role: Role::Agent,
            parts: vec![Part::text(&reply_text)],
            metadata: None,
            extensions: vec![],
            reference_task_ids: None,
        };

        let task = Task {
            id: task_id,
            context_id,
            status: TaskStatus {
                state: TaskState::Completed,
                message: Some(agent_message.clone()),
                timestamp: Some(chrono::Utc::now().to_rfc3339()),
            },
            history: Some(vec![message, agent_message]),
            artifacts,
            metadata: None,
        };

        Ok(SendMessageResponse::Task(task))
    }

    fn agent_card(&self, base_url: &str) -> AgentCard {
        AgentCard {
            name: "Greeting Agent".to_string(),
            description: "A friendly agent that greets users and tells the time".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: format!("{}/v1/rpc", base_url),
                protocol_binding: "JSONRPC".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                tenant: None,
            }],
            provider: Some(AgentProvider {
                organization: "A2A Examples".to_string(),
                url: "https://github.com/tkellogg/a2a-rs".to_string(),
            }),
            version: PROTOCOL_VERSION.to_string(),
            capabilities: AgentCapabilities {
                streaming: Some(false),
                push_notifications: Some(false),
                ..Default::default()
            },
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            skills: vec![
                AgentSkill {
                    id: "greet".to_string(),
                    name: "Greeting".to_string(),
                    description: "Greets the user by name".to_string(),
                    tags: vec!["greeting".to_string(), "hello".to_string()],
                    examples: vec![
                        "Hello, my name is Alice".to_string(),
                        "Hi there!".to_string(),
                    ],
                    input_modes: vec!["text/plain".to_string()],
                    output_modes: vec!["text/plain".to_string()],
                    ..Default::default()
                },
                AgentSkill {
                    id: "time".to_string(),
                    name: "Current Time".to_string(),
                    description: "Returns the current UTC time".to_string(),
                    tags: vec!["time".to_string(), "utility".to_string()],
                    examples: vec!["What time is it?".to_string()],
                    input_modes: vec!["text/plain".to_string()],
                    output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }
}

/// Simple name extraction from a greeting message.
fn extract_name(input: &str) -> Option<&str> {
    // Look for "name is X" or "I'm X" patterns
    if let Some(pos) = input.find("name is ") {
        let rest = &input[pos + 8..];
        return Some(
            rest.split_whitespace()
                .next()
                .unwrap_or(rest)
                .trim_end_matches('.'),
        );
    }
    if let Some(pos) = input.find("I'm ") {
        let rest = &input[pos + 4..];
        return Some(
            rest.split_whitespace()
                .next()
                .unwrap_or(rest)
                .trim_end_matches('.'),
        );
    }
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    println!("Starting Greeting Agent on http://127.0.0.1:3000");
    println!("Agent card: http://127.0.0.1:3000/.well-known/agent-card.json");
    println!();
    println!("Try:");
    println!(r#"  curl -s http://127.0.0.1:3000/.well-known/agent-card.json | jq .name"#);
    println!();
    println!(r#"  curl -s -X POST http://127.0.0.1:3000/v1/rpc \"#);
    println!(r#"    -H "Content-Type: application/json" \"#);
    println!(
        r#"    -d '{{"jsonrpc":"2.0","id":1,"method":"message/send","params":{{"message":{{"messageId":"m1","role":"ROLE_USER","parts":[{{"text":"Hello, my name is Alice"}}]}}}}}}'"#
    );

    A2aServer::new(GreetingAgent)
        .bind("127.0.0.1:3000")?
        .run()
        .await
}
