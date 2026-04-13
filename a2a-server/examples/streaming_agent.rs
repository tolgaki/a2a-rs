//! Streaming agent example — demonstrates A2A v1.0 SSE streaming
//!
//! This example shows the canonical pattern for building a streaming A2A agent:
//!
//! 1. The `MessageHandler::handle_message` returns a `Task` in `Working` state immediately.
//! 2. A background `tokio::spawn` task sends incremental updates via the broadcast channel:
//!    - `StreamResponse::StatusUpdate` — progress messages while working
//!    - `StreamResponse::ArtifactUpdate` — artifact chunks (e.g. paragraphs of generated text)
//!    - `StreamResponse::StatusUpdate` with terminal state — signals completion
//! 3. The server's SSE handler picks up these broadcast events and delivers them to the
//!    client as `text/event-stream` with each event wrapped in a JSON-RPC success envelope.
//!
//! # How SSE streaming works in A2A v1.0
//!
//! When a client calls `SendStreamingMessage` (or `message/stream`), the server:
//! - Calls `handle_message` to get the initial Task
//! - Opens an SSE stream and yields the initial Task as the first event
//! - Listens on the broadcast channel for events matching the task ID
//! - Yields each matching `StatusUpdate` or `ArtifactUpdate` as an SSE event
//! - Closes the stream when a terminal state is received (Completed, Failed, Canceled)
//!
//! Each SSE `data:` line is a full JSON-RPC response envelope:
//! ```json
//! {"jsonrpc":"2.0","id":1,"result":{"statusUpdate":{"taskId":"...","contextId":"...","status":{...}}}}
//! {"jsonrpc":"2.0","id":1,"result":{"artifactUpdate":{"taskId":"...","contextId":"...","artifact":{...}}}}
//! ```
//!
//! # Event types
//!
//! - `StreamResponse::Task(Task)` — full task snapshot (sent as first event)
//! - `StreamResponse::StatusUpdate(TaskStatusUpdateEvent)` — status change with optional message
//! - `StreamResponse::ArtifactUpdate(TaskArtifactUpdateEvent)` — artifact content chunk
//! - `StreamResponse::Message(Message)` — direct message (less common in streaming)
//!
//! # Key pattern: getting the event sender
//!
//! The handler needs the server's broadcast channel to send streaming events, but
//! the server is constructed with the handler. This example solves the chicken-and-egg
//! problem using `OnceLock` behind an `Arc`:
//!
//! 1. Create the handler with an empty event sender slot (`Arc<OnceLock<...>>`)
//! 2. Clone the `Arc` before moving the handler into the server
//! 3. After server construction, call `get_event_sender()` and fill the slot
//! 4. Call `run()` — the handler can now send events on the server's channel
//!
//! # Running
//!
//! ```sh
//! cargo run --example streaming_agent
//! ```
//!
//! # Testing with curl
//!
//! Non-streaming (message/send) — returns the final task after completion:
//! ```sh
//! curl -X POST http://127.0.0.1:3000/v1/rpc \
//!   -H "Content-Type: application/json" \
//!   -d '{
//!     "jsonrpc": "2.0",
//!     "id": 1,
//!     "method": "message/send",
//!     "params": {
//!       "message": {
//!         "messageId": "msg-1",
//!         "role": "ROLE_USER",
//!         "parts": [{"text": "Write me a haiku about Rust"}]
//!       }
//!     }
//!   }'
//! ```
//!
//! Streaming (message/stream) — returns SSE events as they happen:
//! ```sh
//! curl -N -X POST http://127.0.0.1:3000/v1/rpc \
//!   -H "Content-Type: application/json" \
//!   -d '{
//!     "jsonrpc": "2.0",
//!     "id": 1,
//!     "method": "message/stream",
//!     "params": {
//!       "message": {
//!         "messageId": "msg-1",
//!         "role": "ROLE_USER",
//!         "parts": [{"text": "Write me a haiku about Rust"}]
//!       }
//!     }
//!   }'
//! ```
//!
//! You will see a sequence of SSE events: initial task (Working), status updates with
//! progress messages, artifact chunks with text content, and a final Completed status.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use a2a_rs_core::{
    now_iso8601, AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill, Artifact,
    Message, Part, Role, SendMessageResponse, StreamResponse, Task, TaskArtifactUpdateEvent,
    TaskState, TaskStatus, TaskStatusUpdateEvent, PROTOCOL_VERSION,
};
use a2a_rs_server::{A2aServer, AuthContext, HandlerResult, MessageHandler};
use async_trait::async_trait;
use tokio::sync::broadcast;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Shared event sender handle
// ---------------------------------------------------------------------------

/// A shared handle for the broadcast sender that can be initialized after
/// server construction. The `Arc<OnceLock<...>>` is cloned between `main`
/// and the handler so both reference the same slot.
type EventSenderSlot = Arc<OnceLock<broadcast::Sender<StreamResponse>>>;

/// Initialize the shared event sender slot.
fn init_event_sender(slot: &EventSenderSlot, tx: broadcast::Sender<StreamResponse>) {
    slot.set(tx)
        .expect("event sender already initialized");
}

/// Get a clone of the event sender from the shared slot.
fn get_event_sender(slot: &EventSenderSlot) -> broadcast::Sender<StreamResponse> {
    slot.get()
        .expect("event sender not initialized — call init_event_sender before handling requests")
        .clone()
}

// ---------------------------------------------------------------------------
// Streaming agent handler
// ---------------------------------------------------------------------------

/// A streaming agent that simulates generating text in chunks.
///
/// The handler returns a Working task immediately and spawns a background
/// task that emits progress updates and artifact chunks via the broadcast
/// channel. The server's SSE plumbing delivers these to connected clients.
struct StreamingAgent {
    /// Shared slot for the broadcast sender. Initialized after server
    /// construction in `main`, before `run()` is called.
    event_tx: EventSenderSlot,
}

#[async_trait]
impl MessageHandler for StreamingAgent {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        // Extract the user's text input
        let user_text = message
            .parts
            .iter()
            .filter_map(|p| p.as_text())
            .collect::<Vec<_>>()
            .join(" ");

        // Create a new task in Working state
        let task_id = Uuid::new_v4().to_string();
        let context_id = message
            .context_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let task = Task {
            kind: "task".to_string(),
            id: task_id.clone(),
            context_id: context_id.clone(),
            status: TaskStatus {
                state: TaskState::Working,
                message: Some(Message {
                    kind: "message".to_string(),
                    message_id: Uuid::new_v4().to_string(),
                    context_id: Some(context_id.clone()),
                    task_id: Some(task_id.clone()),
                    role: Role::Agent,
                    parts: vec![Part::text("Thinking...")],
                    metadata: None,
                    extensions: vec![],
                    reference_task_ids: None,
                }),
                timestamp: Some(now_iso8601()),
            },
            history: Some(vec![message]),
            artifacts: None,
            metadata: None,
        };

        // Get a clone of the broadcast sender for the background task
        let event_tx = get_event_sender(&self.event_tx);
        let task_id_bg = task_id.clone();
        let context_id_bg = context_id.clone();

        // Spawn a background task that sends incremental updates.
        // This is the key pattern: handle_message returns immediately,
        // the background task drives the streaming lifecycle.
        tokio::spawn(async move {
            // Simulate processing delay
            tokio::time::sleep(Duration::from_millis(500)).await;

            // --- Phase 1: Status update — "Generating response..." ---
            //
            // StatusUpdate events let the client show progress to the user.
            // The task stays in Working state while we prepare the output.
            let _ = event_tx.send(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                kind: "status-update".to_string(),
                task_id: task_id_bg.clone(),
                context_id: context_id_bg.clone(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: Some(Message {
                        kind: "message".to_string(),
                        message_id: Uuid::new_v4().to_string(),
                        context_id: Some(context_id_bg.clone()),
                        task_id: Some(task_id_bg.clone()),
                        role: Role::Agent,
                        parts: vec![Part::text(format!(
                            "Generating response for: \"{}\"",
                            user_text
                        ))],
                        metadata: None,
                        extensions: vec![],
                        reference_task_ids: None,
                    }),
                    timestamp: Some(now_iso8601()),
                },
                metadata: None,
            }));

            tokio::time::sleep(Duration::from_millis(500)).await;

            // --- Phase 2: Artifact chunks — send text in pieces ---
            //
            // ArtifactUpdate events deliver content incrementally. The first
            // chunk creates the artifact; subsequent chunks have `append: true`
            // to signal that they extend the previous content. The `last_chunk`
            // flag marks the final piece.
            let artifact_id = Uuid::new_v4().to_string();
            let chunks = [
                "Memory safe and fast,\n",
                "Borrow checker guards the code,\n",
                "Fearless concurrency.",
            ];

            for (i, chunk) in chunks.iter().enumerate() {
                let is_last = i == chunks.len() - 1;

                let _ = event_tx.send(StreamResponse::ArtifactUpdate(
                    TaskArtifactUpdateEvent {
                        kind: "artifact-update".to_string(),
                        task_id: task_id_bg.clone(),
                        context_id: context_id_bg.clone(),
                        artifact: Artifact {
                            artifact_id: artifact_id.clone(),
                            name: Some("haiku".to_string()),
                            description: Some("A haiku about Rust".to_string()),
                            parts: vec![Part::text(*chunk)],
                            metadata: None,
                            extensions: vec![],
                        },
                        // First chunk: not appending (creates the artifact).
                        // Subsequent chunks: append to the existing artifact.
                        append: if i == 0 { None } else { Some(true) },
                        last_chunk: Some(is_last),
                        metadata: None,
                    },
                ));

                tokio::time::sleep(Duration::from_millis(300)).await;
            }

            // --- Phase 3: Final status — Completed ---
            //
            // Sending a terminal state (Completed, Failed, Canceled) tells the
            // server's SSE handler to close the stream. This is how the client
            // knows the response is finished.
            let _ = event_tx.send(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                kind: "status-update".to_string(),
                task_id: task_id_bg.clone(),
                context_id: context_id_bg.clone(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: Some(Message {
                        kind: "message".to_string(),
                        message_id: Uuid::new_v4().to_string(),
                        context_id: Some(context_id_bg.clone()),
                        task_id: Some(task_id_bg.clone()),
                        role: Role::Agent,
                        parts: vec![Part::text("Done! Here is your haiku.")],
                        metadata: None,
                        extensions: vec![],
                        reference_task_ids: None,
                    }),
                    timestamp: Some(now_iso8601()),
                },
                metadata: None,
            }));
        });

        // Return the Working task immediately — the server streams it as the
        // first SSE event, then relays broadcast events until completion.
        Ok(SendMessageResponse::Task(task))
    }

    fn agent_card(&self, _base_url: &str) -> AgentCard {
        AgentCard {
            name: "Streaming Haiku Agent".to_string(),
            description: "A demo agent that streams a haiku in chunks via SSE".to_string(),
            supported_interfaces: vec![AgentInterface {
                // Leave URL empty — the server fills it in from bind address + rpc_path.
                url: String::new(),
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
                streaming: Some(true),
                push_notifications: Some(false),
                extended_agent_card: Some(false),
                ..Default::default()
            },
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            skills: vec![AgentSkill {
                id: "haiku".to_string(),
                name: "Haiku Generator".to_string(),
                description: "Generates a haiku about any topic, streamed in chunks".to_string(),
                tags: vec![
                    "demo".to_string(),
                    "streaming".to_string(),
                    "poetry".to_string(),
                ],
                examples: vec!["Write me a haiku about Rust".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn supports_streaming(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Step 1: Create a shared slot for the event sender.
    let event_sender_slot: EventSenderSlot = Arc::new(OnceLock::new());

    // Step 2: Create the handler, giving it a clone of the shared slot.
    let agent = StreamingAgent {
        event_tx: event_sender_slot.clone(),
    };

    // Step 3: Build the server. This creates the internal broadcast channel.
    // The handler is moved into the server here, but it shares the OnceLock
    // via the Arc we cloned above.
    let server = A2aServer::new(agent).bind("127.0.0.1:3000")?;

    // Step 4: Extract the event sender from the server's broadcast channel
    // and store it in the shared slot. The handler (now inside the server)
    // will read from this same slot when processing requests.
    init_event_sender(&event_sender_slot, server.get_event_sender());

    println!("Starting A2A Streaming Agent on http://127.0.0.1:3000");
    println!("Agent card:  http://127.0.0.1:3000/.well-known/agent-card.json");
    println!("JSON-RPC:    POST http://127.0.0.1:3000/v1/rpc");
    println!();
    println!("Test streaming with:");
    println!(
        r#"  curl -N -X POST http://127.0.0.1:3000/v1/rpc \
    -H "Content-Type: application/json" \
    -d '{{"jsonrpc":"2.0","id":1,"method":"message/stream","params":{{"message":{{"messageId":"msg-1","role":"ROLE_USER","parts":[{{"text":"Write me a haiku"}}]}}}}}}"#
    );

    // Step 5: Run the server. Blocks until shutdown signal (Ctrl+C).
    server.run().await
}
