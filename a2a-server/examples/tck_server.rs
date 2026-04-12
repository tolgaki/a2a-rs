//! TCK-compliant SUT (System Under Test) for A2A protocol conformance testing.
//!
//! Routes behavior based on `messageId` prefix per the TCK scenario contract
//! defined in `scenarios/core_operations.feature` and `scenarios/streaming.feature`.
//!
//! Run with: cargo run --example tck_server
//! Test with: python -m pytest tests/compatibility/ --sut-host=http://localhost:8080 --transport=jsonrpc

use a2a_rs_core::{
    now_iso8601, Artifact, Message, Part, Role, SendMessageResponse, Task, TaskState, TaskStatus,
    PROTOCOL_VERSION,
};
use a2a_rs_server::{AuthContext, HandlerError, HandlerResult, MessageHandler, A2aServer};
use async_trait::async_trait;
use uuid::Uuid;

/// TCK agent handler that routes behavior based on messageId prefix.
struct TckHandler;

impl TckHandler {
    fn new_agent_message(text: &str, context_id: Option<String>) -> Message {
        Message {
            kind: "message".to_string(),
            message_id: Uuid::new_v4().to_string(),
            context_id,
            task_id: None,
            role: Role::Agent,
            parts: vec![Part::text(text)],
            metadata: None,
            extensions: vec![],
            reference_task_ids: None,
        }
    }

    fn make_task(task_id: String, context_id: String, state: TaskState) -> Task {
        Task {
            kind: "task".to_string(),
            id: task_id,
            context_id,
            status: TaskStatus {
                state,
                message: None,
                timestamp: Some(now_iso8601()),
            },
            history: None,
            artifacts: None,
            metadata: None,
        }
    }
}

#[async_trait]
impl MessageHandler for TckHandler {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        let msg_id = &message.message_id;
        let ctx = message
            .context_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // --- Message response (no task) ---
        if msg_id.starts_with("tck-message-response") {
            let reply = Message {
                kind: "message".to_string(),
                message_id: Uuid::new_v4().to_string(),
                context_id: Some(ctx),
                task_id: None,
                role: Role::Agent,
                parts: vec![Part::text("Direct message response")],
                metadata: None,
                extensions: vec![],
                reference_task_ids: None,
            };
            return Ok(SendMessageResponse::Message(reply));
        }

        // --- Input required ---
        if msg_id.starts_with("tck-input-required") {
            let mut task = Self::make_task(msg_id.to_string(), ctx.clone(), TaskState::InputRequired);
            task.history = Some(vec![message]);
            return Ok(SendMessageResponse::Task(task));
        }

        // --- Reject task ---
        if msg_id.starts_with("tck-reject-task") {
            return Err(HandlerError::processing_failed("rejected"));
        }

        // --- Artifact: text ---
        if msg_id.starts_with("tck-artifact-text") {
            let mut task = Self::make_task(msg_id.to_string(), ctx.clone(), TaskState::Completed);
            task.artifacts = Some(vec![Artifact {
                artifact_id: Uuid::new_v4().to_string(),
                name: None,
                description: None,
                parts: vec![Part::text("Generated text content")],
                metadata: None,
                extensions: vec![],
            }]);
            task.history = Some(vec![message]);
            return Ok(SendMessageResponse::Task(task));
        }

        // --- Artifact: file (inline bytes) ---
        if msg_id.starts_with("tck-artifact-file-url") {
            let mut task = Self::make_task(msg_id.to_string(), ctx.clone(), TaskState::Completed);
            task.artifacts = Some(vec![Artifact {
                artifact_id: Uuid::new_v4().to_string(),
                name: None,
                description: None,
                parts: vec![Part::File {
                    file: a2a_rs_core::FileContent {
                        bytes: None,
                        uri: Some("https://example.com/output.txt".to_string()),
                        name: Some("output.txt".to_string()),
                        mime_type: Some("text/plain".to_string()),
                    },
                    metadata: None,
                    filename: None,
                    media_type: None,
                }],
                metadata: None,
                extensions: vec![],
            }]);
            task.history = Some(vec![message]);
            return Ok(SendMessageResponse::Task(task));
        }

        if msg_id.starts_with("tck-artifact-file") {
            let mut task = Self::make_task(msg_id.to_string(), ctx.clone(), TaskState::Completed);
            task.artifacts = Some(vec![Artifact {
                artifact_id: Uuid::new_v4().to_string(),
                name: None,
                description: None,
                parts: vec![Part::File {
                    file: a2a_rs_core::FileContent {
                        bytes: Some(base64::encode(b"tck")),
                        uri: None,
                        name: Some("output.txt".to_string()),
                        mime_type: Some("text/plain".to_string()),
                    },
                    metadata: None,
                    filename: None,
                    media_type: None,
                }],
                metadata: None,
                extensions: vec![],
            }]);
            task.history = Some(vec![message]);
            return Ok(SendMessageResponse::Task(task));
        }

        // --- Artifact: data ---
        if msg_id.starts_with("tck-artifact-data") {
            let mut task = Self::make_task(msg_id.to_string(), ctx.clone(), TaskState::Completed);
            task.artifacts = Some(vec![Artifact {
                artifact_id: Uuid::new_v4().to_string(),
                name: None,
                description: None,
                parts: vec![Part::data(
                    serde_json::json!({"key": "value", "count": 42}),
                )],
                metadata: None,
                extensions: vec![],
            }]);
            task.history = Some(vec![message]);
            return Ok(SendMessageResponse::Task(task));
        }

        // --- Complete task (default TCK behavior) ---
        if msg_id.starts_with("tck-complete-task") || msg_id.starts_with("tck-stream-") {
            let reply = Self::new_agent_message("Hello from TCK", Some(ctx.clone()));
            let mut task = Self::make_task(msg_id.to_string(), ctx, TaskState::Completed);
            task.status.message = Some(reply.clone());
            task.history = Some(vec![message, reply]);
            return Ok(SendMessageResponse::Task(task));
        }

        // --- Default: complete with echo ---
        let text = message
            .parts
            .iter()
            .filter_map(|p| p.as_text())
            .collect::<Vec<_>>()
            .join("\n");
        let reply = Self::new_agent_message(&format!("echo: {text}"), Some(ctx.clone()));
        let mut task = Self::make_task(msg_id.to_string(), ctx, TaskState::Completed);
        task.status.message = Some(reply.clone());
        task.history = Some(vec![message, reply]);
        Ok(SendMessageResponse::Task(task))
    }

    fn agent_card(&self, base_url: &str) -> a2a_rs_core::AgentCard {
        use a2a_rs_core::{AgentCapabilities, AgentInterface, AgentProvider, AgentSkill};

        a2a_rs_core::AgentCard {
            name: "A2A TCK SUT".to_string(),
            description: "System Under Test for A2A TCK conformance".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: format!("{}/", base_url),
                protocol_binding: "JSONRPC".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                tenant: None,
            }],
            provider: Some(AgentProvider {
                organization: "A2A Project".to_string(),
                url: "https://github.com/a2aproject".to_string(),
            }),
            version: PROTOCOL_VERSION.to_string(),
            documentation_url: None,
            capabilities: AgentCapabilities {
                streaming: Some(true),
                push_notifications: Some(false),
                extended_agent_card: Some(false),
                ..Default::default()
            },
            security_schemes: Default::default(),
            security_requirements: vec![],
            default_input_modes: vec!["text".to_string()],
            default_output_modes: vec!["text".to_string()],
            skills: vec![AgentSkill {
                id: "tck".to_string(),
                name: "TCK Conformance".to_string(),
                description: "Handles TCK conformance test messages".to_string(),
                tags: vec!["tck".to_string()],
                examples: vec![],
                input_modes: vec![],
                output_modes: vec![],
                security_requirements: vec![],
            }],
            signatures: vec![],
            icon_url: None,
        }
    }

    fn supports_streaming(&self) -> bool {
        true
    }
}

/// Simple base64 encoder (avoids adding a dependency).
mod base64 {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(input: &[u8]) -> String {
        let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[(triple >> 18 & 0x3F) as usize] as char);
            out.push(ALPHABET[(triple >> 12 & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(triple >> 6 & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[(triple & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind = format!("0.0.0.0:{port}");

    println!("Starting A2A TCK SUT on http://localhost:{port}");
    println!("Agent card: http://localhost:{port}/.well-known/agent-card.json");

    let server = A2aServer::new(TckHandler)
        .bind(&bind)
        .expect("valid bind address")
        .rpc_path("/");

    let event_tx = server.get_event_sender();

    // Spawn a background task that handles streaming scenarios.
    // The TckHandler returns completed tasks immediately; for streaming
    // tests the events are broadcast via the event channel.
    let _event_tx = event_tx; // retained for future streaming enhancements

    server.run().await
}
