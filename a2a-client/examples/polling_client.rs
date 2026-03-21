//! Task polling client example
//!
//! Demonstrates how to:
//! 1. Send a message and get a task back
//! 2. Poll the task until it reaches a terminal state
//! 3. Retrieve the final task result with `poll_until_complete`
//!
//! This is useful when the server returns a task in a non-terminal state
//! (e.g., TASK_STATE_WORKING) and you need to wait for completion.
//!
//! Prerequisites: Start a server first:
//!   cargo run --example echo_server
//!
//! Then run:
//!   cargo run -p a2a-rs-client --example polling_client

use a2a_rs_client::{A2aClient, ClientConfig};
use a2a_rs_core::{Message, Part, Role, SendMessageResult};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let server_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());

    // Create a client with custom polling settings
    let client = A2aClient::new(ClientConfig {
        server_url: server_url.clone(),
        max_polls: 10,          // try up to 10 times
        poll_interval_ms: 1000, // wait 1 second between polls
        oauth: None,
    })?;

    println!("Connected to {}", server_url);

    // Send a message
    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        context_id: None,
        task_id: None,
        role: Role::User,
        parts: vec![Part::text("Process this request")],
        metadata: None,
        extensions: vec![],
        reference_task_ids: None,
    };

    println!("Sending message...");
    let response = client.send_message(message, None).await?;

    match response {
        SendMessageResult::Task(task) => {
            println!("Got task: {} (state: {:?})", task.id, task.status.state);

            if task.status.state.is_terminal() {
                // Task already completed, no polling needed
                println!("Task already in terminal state.");
                print_task_result(&task);
            } else {
                // Task is still in progress - poll until done
                println!("Task is in progress, polling until complete...");
                let final_task = client.poll_until_complete(&task.id, None).await?;
                println!("Final state: {:?}", final_task.status.state);
                print_task_result(&final_task);
            }
        }
        SendMessageResult::Message(msg) => {
            println!("Got direct message response (no task to poll):");
            for part in &msg.parts {
                if let Some(text) = part.as_text() {
                    println!("  {}", text);
                }
            }
        }
    }

    Ok(())
}

fn print_task_result(task: &a2a_rs_core::Task) {
    // Print status message if present
    if let Some(msg) = &task.status.message {
        for part in &msg.parts {
            if let Some(text) = part.as_text() {
                println!("Status message: {}", text);
            }
        }
    }

    // Print history
    if let Some(history) = &task.history {
        println!("\nConversation ({} messages):", history.len());
        for msg in history {
            let role = match msg.role {
                Role::User => "User",
                Role::Agent => "Agent",
                _ => "Unknown",
            };
            for part in &msg.parts {
                if let Some(text) = part.as_text() {
                    println!("  {}: {}", role, text);
                }
            }
        }
    }
}
