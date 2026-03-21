//! Simple A2A client example
//!
//! Demonstrates how to use `A2aClient` to:
//! 1. Connect to an A2A server and fetch its agent card
//! 2. Send a message and receive a response
//! 3. Handle both Task and Message response types
//!
//! Prerequisites: Start a server first, e.g.:
//!   cargo run --example echo_server
//!   # or
//!   cargo run --example custom_handler
//!
//! Then run this client:
//!   cargo run -p a2a-rs-client --example simple_client
//!
//! You can point to a different server:
//!   cargo run -p a2a-rs-client --example simple_client -- http://localhost:3000

use a2a_rs_client::{A2aClient, ClientConfig};
use a2a_rs_core::{Message, Part, Role, SendMessageResult};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Use server URL from args, or default to localhost:8080
    let server_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());

    println!("Connecting to A2A server at {}", server_url);

    // --- Step 1: Create the client ---
    let client = A2aClient::new(ClientConfig {
        server_url,
        ..Default::default()
    })?;

    // --- Step 2: Fetch and display the agent card ---
    let card = client.fetch_agent_card().await?;
    println!("\nAgent: {}", card.name);
    println!("Description: {}", card.description);
    println!("Version: {}", card.version);

    if !card.skills.is_empty() {
        println!("\nSkills:");
        for skill in &card.skills {
            println!("  - {} ({}): {}", skill.name, skill.id, skill.description);
        }
    }

    if let Some(endpoint) = card.endpoint() {
        println!("\nRPC endpoint: {}", endpoint);
    }

    // --- Step 3: Send a message ---
    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        context_id: None,
        task_id: None,
        role: Role::User,
        parts: vec![Part::text("Hello from the A2A Rust client!")],
        metadata: None,
        extensions: vec![],
        reference_task_ids: None,
    };

    println!("\nSending message...");
    let response = client.send_message(message, None).await?;

    // --- Step 4: Handle the response ---
    match response {
        SendMessageResult::Task(task) => {
            println!("\nReceived Task response:");
            println!("  Task ID: {}", task.id);
            println!("  Context: {}", task.context_id);
            println!("  State: {:?}", task.status.state);

            // Print the agent's reply from task history
            if let Some(history) = &task.history {
                for msg in history {
                    if msg.role == Role::Agent {
                        for part in &msg.parts {
                            if let Some(text) = part.as_text() {
                                println!("  Agent says: {}", text);
                            }
                        }
                    }
                }
            }

            // Print any artifacts
            if let Some(artifacts) = &task.artifacts {
                println!("\n  Artifacts:");
                for artifact in artifacts {
                    println!(
                        "    - {}: {}",
                        artifact.name.as_deref().unwrap_or("unnamed"),
                        artifact.description.as_deref().unwrap_or("")
                    );
                }
            }
        }
        SendMessageResult::Message(msg) => {
            println!("\nReceived Message response:");
            for part in &msg.parts {
                if let Some(text) = part.as_text() {
                    println!("  Agent says: {}", text);
                }
            }
        }
    }

    Ok(())
}
