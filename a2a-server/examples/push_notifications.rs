//! Push Notifications Example
//!
//! Demonstrates the A2A v1.0 push notification (webhook) feature end-to-end:
//!
//! 1. An A2A agent server with push_notifications enabled
//! 2. A mini webhook receiver on a separate port that logs incoming payloads
//! 3. A programmatic client flow that creates a task, registers a webhook,
//!    waits for auto-completion, and verifies the webhook received the event
//!
//! Run with:
//!   cargo run --example push_notifications
//!
//! ## Manual Testing with curl
//!
//! ### Step 1: Check the agent card (confirms push_notifications capability)
//!
//! ```sh
//! curl -s http://127.0.0.1:3000/.well-known/agent-card.json | jq .capabilities
//! # => { "pushNotifications": true }
//! ```
//!
//! ### Step 2: Send a message to create a task
//!
//! ```sh
//! curl -s -X POST http://127.0.0.1:3000/v1/rpc \
//!   -H "Content-Type: application/json" \
//!   -d '{
//!     "jsonrpc": "2.0",
//!     "id": 1,
//!     "method": "message/send",
//!     "params": {
//!       "message": {
//!         "messageId": "msg-1",
//!         "role": "user",
//!         "parts": [{"kind": "text", "text": "Hello push!"}]
//!       }
//!     }
//!   }' | jq .
//! ```
//!
//! Note the `result.id` — that is the task ID you will use below.
//!
//! ### Step 3: Register a push notification webhook for the task
//!
//! ```sh
//! curl -s -X POST http://127.0.0.1:3000/v1/rpc \
//!   -H "Content-Type: application/json" \
//!   -d '{
//!     "jsonrpc": "2.0",
//!     "id": 2,
//!     "method": "tasks/pushNotificationConfig/create",
//!     "params": {
//!       "taskId": "<TASK_ID>",
//!       "configId": "my-webhook",
//!       "url": "http://127.0.0.1:3001/webhook",
//!       "token": "my-secret-token"
//!     }
//!   }' | jq .
//! ```
//!
//! The response echoes back the created `TaskPushNotificationConfig`:
//! ```json
//! {
//!   "jsonrpc": "2.0",
//!   "id": 2,
//!   "result": {
//!     "id": "my-webhook",
//!     "taskId": "<TASK_ID>",
//!     "url": "http://127.0.0.1:3001/webhook",
//!     "token": "my-secret-token"
//!   }
//! }
//! ```
//!
//! ### Step 4: List push notification configs for the task
//!
//! ```sh
//! curl -s -X POST http://127.0.0.1:3000/v1/rpc \
//!   -H "Content-Type: application/json" \
//!   -d '{
//!     "jsonrpc": "2.0",
//!     "id": 3,
//!     "method": "tasks/pushNotificationConfig/list",
//!     "params": { "taskId": "<TASK_ID>" }
//!   }' | jq .
//! ```
//!
//! ### Step 5: Get a specific push notification config
//!
//! ```sh
//! curl -s -X POST http://127.0.0.1:3000/v1/rpc \
//!   -H "Content-Type: application/json" \
//!   -d '{
//!     "jsonrpc": "2.0",
//!     "id": 4,
//!     "method": "tasks/pushNotificationConfig/get",
//!     "params": { "taskId": "<TASK_ID>", "id": "my-webhook" }
//!   }' | jq .
//! ```
//!
//! ### Step 6: Wait for auto-completion (the echo handler completes after ~2s)
//!
//! Check the webhook receiver terminal — you should see a POST with a payload like:
//!
//! ```json
//! {
//!   "statusUpdate": {
//!     "taskId": "<TASK_ID>",
//!     "contextId": "<CONTEXT_ID>",
//!     "status": {
//!       "state": "TASK_STATE_COMPLETED",
//!       "timestamp": "2025-01-01T00:00:00.000Z"
//!     }
//!   }
//! }
//! ```
//!
//! The webhook delivery engine serializes `StreamResponse` events, which are
//! externally tagged. A `StatusUpdate` variant produces `{"statusUpdate": {...}}`,
//! a `Task` variant produces `{"task": {...}}`, etc.
//!
//! ### Step 7: Delete the push notification config
//!
//! ```sh
//! curl -s -X POST http://127.0.0.1:3000/v1/rpc \
//!   -H "Content-Type: application/json" \
//!   -d '{
//!     "jsonrpc": "2.0",
//!     "id": 5,
//!     "method": "tasks/pushNotificationConfig/delete",
//!     "params": { "taskId": "<TASK_ID>", "id": "my-webhook" }
//!   }' | jq .
//! ```
//!
//! Returns `{"jsonrpc":"2.0","id":5,"result":{}}` on success.

use a2a_rs_core::{
    AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill, Message, Part, Role,
    SendMessageResponse, Task, TaskState, TaskStatus, PROTOCOL_VERSION,
};
use a2a_rs_server::{A2aServer, AuthContext, HandlerResult, MessageHandler};
use async_trait::async_trait;
use axum::{
    extract::State as AxumState,
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// Webhook receiver — a tiny axum server that logs incoming notifications
// ---------------------------------------------------------------------------

/// Shared state for the webhook receiver so the main flow can observe deliveries.
#[derive(Clone)]
struct WebhookReceiverState {
    received_count: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

/// Handler for POST /webhook — logs the payload and signals the waiter.
async fn webhook_handler(
    AxumState(state): AxumState<WebhookReceiverState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> &'static str {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<none>");

    println!("\n========================================");
    println!("WEBHOOK RECEIVED");
    println!("  Authorization: {}", auth);
    println!(
        "  Payload:\n{}",
        serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string())
    );
    println!("========================================\n");

    state.received_count.fetch_add(1, Ordering::SeqCst);
    state.notify.notify_one();
    "ok"
}

/// Start the webhook receiver on the given port.
/// Returns the shared state so callers can wait on delivery.
async fn start_webhook_receiver(port: u16) -> WebhookReceiverState {
    let state = WebhookReceiverState {
        received_count: Arc::new(AtomicUsize::new(0)),
        notify: Arc::new(Notify::new()),
    };

    let app = Router::new()
        .route("/webhook", post(webhook_handler))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("failed to bind webhook receiver");

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    state
}

// ---------------------------------------------------------------------------
// Custom handler that advertises push_notifications: true
// ---------------------------------------------------------------------------

/// A handler similar to EchoHandler but with push notifications enabled.
///
/// The handler returns tasks in a non-terminal (Working) state. The server's
/// auto-complete mechanism transitions them to Completed after a short delay,
/// broadcasting a `StreamResponse::StatusUpdate` event. The webhook delivery
/// engine picks up that event and POSTs it to any registered webhooks.
struct PushEchoHandler;

#[async_trait]
impl MessageHandler for PushEchoHandler {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        let text = message
            .parts
            .iter()
            .filter_map(|p| p.as_text())
            .collect::<Vec<_>>()
            .join("\n");

        let task_id = uuid::Uuid::new_v4().to_string();
        let context_id = message
            .context_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let response = Message {
            kind: "message".to_string(),
            message_id: uuid::Uuid::new_v4().to_string(),
            context_id: message.context_id.clone(),
            task_id: None,
            role: Role::Agent,
            parts: vec![Part::text(format!("echo: {}", text))],
            metadata: None,
            extensions: vec![],
            reference_task_ids: None,
        };

        // Return a task in Working state — the server will auto-complete it
        // after `auto_complete_delay()`, triggering the webhook delivery.
        Ok(SendMessageResponse::Task(Task {
            kind: "task".to_string(),
            id: task_id,
            context_id,
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(a2a_rs_core::now_iso8601()),
            },
            history: Some(vec![message, response]),
            artifacts: None,
            metadata: None,
        }))
    }

    fn agent_card(&self, _base_url: &str) -> AgentCard {
        AgentCard {
            name: "Push Notification Demo Agent".to_string(),
            description: "Echoes messages and supports push notification webhooks".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: String::new(), // filled in by the server
                protocol_binding: "JSONRPC".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                tenant: None,
            }],
            provider: Some(AgentProvider {
                organization: "A2A Demo".to_string(),
                url: "https://github.com/a2a-protocol".to_string(),
            }),
            version: PROTOCOL_VERSION.to_string(),
            capabilities: AgentCapabilities {
                streaming: Some(false),
                push_notifications: Some(true), // <-- key capability
                extended_agent_card: Some(false),
                ..Default::default()
            },
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            skills: vec![AgentSkill {
                id: "echo".to_string(),
                name: "Echo".to_string(),
                description: "Echoes back the user's message".to_string(),
                tags: vec!["demo".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// Auto-complete after 2 seconds — this triggers the status update event
    /// that gets delivered to registered webhooks.
    fn auto_complete_delay(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_secs(2))
    }
}

// ---------------------------------------------------------------------------
// Programmatic client flow
// ---------------------------------------------------------------------------

/// Runs the demo flow: send message, register webhook, wait for delivery.
async fn run_demo(webhook_state: WebhookReceiverState) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let rpc_url = "http://127.0.0.1:3000/v1/rpc";

    // Give the server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // --- Step 1: Send a message to create a task ---
    println!("[demo] Sending message to create a task...");
    let send_resp: Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "messageId": "msg-push-demo",
                    "role": "user",
                    "parts": [{"kind": "text", "text": "Hello, push notifications!"}]
                }
            }
        }))
        .send()
        .await?
        .json()
        .await?;

    let task_id = send_resp["result"]["id"]
        .as_str()
        .expect("expected task id in result");
    println!("[demo] Task created: {}", task_id);

    // --- Step 2: Register a push notification webhook ---
    println!("[demo] Registering push notification webhook...");
    let create_resp: Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/pushNotificationConfig/create",
            "params": {
                "taskId": task_id,
                "configId": "demo-webhook",
                "url": "http://127.0.0.1:3001/webhook",
                "token": "my-secret-token"
            }
        }))
        .send()
        .await?
        .json()
        .await?;

    println!(
        "[demo] Webhook registered: {}",
        serde_json::to_string_pretty(&create_resp)?
    );

    // --- Step 3: List configs to confirm ---
    let list_resp: Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/pushNotificationConfig/list",
            "params": { "taskId": task_id }
        }))
        .send()
        .await?
        .json()
        .await?;

    println!(
        "[demo] Listed configs: {}",
        serde_json::to_string_pretty(&list_resp)?
    );

    // --- Step 4: Wait for the webhook to fire ---
    // The echo handler returns a Working task. The server auto-completes it
    // after 2 seconds, broadcasting a StatusUpdate event. The webhook delivery
    // engine then POSTs that event to our registered webhook.
    println!("[demo] Waiting for webhook delivery (task will auto-complete in ~2s)...");

    let timeout_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        webhook_state.notify.notified(),
    )
    .await;

    match timeout_result {
        Ok(()) => {
            let count = webhook_state.received_count.load(Ordering::SeqCst);
            println!("[demo] Webhook delivered! Total notifications received: {}", count);
        }
        Err(_) => {
            println!("[demo] Timed out waiting for webhook delivery");
        }
    }

    // --- Step 5: Get the task to confirm it completed ---
    let get_resp: Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/get",
            "params": { "id": task_id }
        }))
        .send()
        .await?
        .json()
        .await?;

    let final_state = get_resp["result"]["status"]["state"]
        .as_str()
        .unwrap_or("unknown");
    println!("[demo] Final task state: {}", final_state);

    // --- Step 6: Delete the webhook config ---
    println!("[demo] Deleting webhook config...");
    let delete_resp: Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tasks/pushNotificationConfig/delete",
            "params": { "taskId": task_id, "id": "demo-webhook" }
        }))
        .send()
        .await?
        .json()
        .await?;

    println!(
        "[demo] Delete response: {}",
        serde_json::to_string_pretty(&delete_resp)?
    );

    // Confirm it's gone
    let list_resp2: Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tasks/pushNotificationConfig/list",
            "params": { "taskId": task_id }
        }))
        .send()
        .await?
        .json()
        .await?;

    let remaining = list_resp2["result"]["configs"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    println!("[demo] Remaining configs after delete: {}", remaining);

    println!("\n[demo] Push notification demo complete!");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    println!("=== A2A Push Notifications Demo ===\n");

    // Start the webhook receiver on port 3001
    println!("[setup] Starting webhook receiver on http://127.0.0.1:3001/webhook");
    let webhook_state = start_webhook_receiver(3001).await;

    // Start the A2A server on port 3000 (in a background task)
    println!("[setup] Starting A2A server on http://127.0.0.1:3000");
    println!("[setup] Agent card: http://127.0.0.1:3000/.well-known/agent-card.json\n");

    let server = A2aServer::new(PushEchoHandler)
        .bind("127.0.0.1:3000")
        .expect("valid bind address");

    // Run the server in the background so we can drive the demo programmatically
    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.run().await {
            eprintln!("[server] Error: {}", e);
        }
    });

    // Run the demo client flow
    if let Err(e) = run_demo(webhook_state).await {
        eprintln!("[demo] Error: {}", e);
    }

    // Let the server keep running so you can also test with curl.
    // Press Ctrl+C to stop.
    println!("\nServer still running — try the curl commands from the doc comments.");
    println!("Press Ctrl+C to stop.\n");
    server_handle.await?;

    Ok(())
}
