//! Tests for the subscribe-before-snapshot invariant in the four streaming
//! endpoints. See `ISSUE.md` at the repo root for the bug analysis.
//!
//! Test taxonomy:
//!   - *Invariant* tests prove the structural reorder: when the handler is
//!     invoked, `event_tx.receiver_count() >= 1`. This is a property of the
//!     reorder itself, independent of timing.
//!   - *Behavioral* tests demonstrate the user-visible consequence: an event
//!     that would have been dropped by the old code now reaches the SSE
//!     stream. The synchronous-emit variant is deterministic (the handler
//!     sends BEFORE returning from `handle_message`); the Notify-gated
//!     variant proves post-subscribe events flow correctly.
//!
//! The snapshot-time invariant for `:subscribe` / `tasks/resubscribe`
//! (i.e. `receiver_count() >= 1` at the moment `get_flexible` runs) is not
//! tested directly here — it would require a feature-gated hook on
//! `TaskStore`. The reorder is symmetric to the handler-time invariant
//! tested for `:stream` / `message/stream`, and is verified by code review
//! of the four-place change. The behavioral tests below cover the
//! user-visible consequence for those two endpoints.

use a2a_rs_core::{
    now_iso8601, AgentCapabilities, AgentCard, AgentInterface, AgentSkill, Message, Part, Role,
    SendMessageResponse, StreamResponse, Task, TaskState, TaskStatus, TaskStatusUpdateEvent,
    PROTOCOL_VERSION,
};
use a2a_rs_server::{A2aServer, AuthContext, HandlerResult, MessageHandler};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{broadcast, Notify};
use tower::ServiceExt;
use uuid::Uuid;

// ── Shared helpers ────────────────────────────────────────────────────────

fn streaming_card(name: &str) -> AgentCard {
    AgentCard {
        name: name.to_string(),
        description: "test handler".to_string(),
        supported_interfaces: vec![AgentInterface {
            url: String::new(),
            protocol_binding: "JSONRPC".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            tenant: None,
        }],
        provider: None,
        version: PROTOCOL_VERSION.to_string(),
        documentation_url: None,
        capabilities: AgentCapabilities {
            streaming: Some(true),
            ..Default::default()
        },
        security_schemes: Default::default(),
        security_requirements: vec![],
        default_input_modes: vec!["text".to_string()],
        default_output_modes: vec!["text".to_string()],
        skills: vec![AgentSkill {
            id: "t".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            tags: vec!["test".to_string()],
            ..Default::default()
        }],
        signatures: vec![],
        icon_url: None,
    }
}

fn user_message(id: &str, text: &str) -> Message {
    Message {
        kind: "message".to_string(),
        message_id: id.to_string(),
        role: Role::User,
        parts: vec![Part::text(text)],
        context_id: None,
        task_id: None,
        extensions: vec![],
        reference_task_ids: None,
        metadata: None,
    }
}

fn working_task(task_id: &str, context_id: &str) -> Task {
    task_with_state(task_id, context_id, TaskState::Working)
}

fn task_with_state(task_id: &str, context_id: &str, state: TaskState) -> Task {
    Task {
        kind: "task".to_string(),
        id: task_id.to_string(),
        context_id: context_id.to_string(),
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

fn terminal_status_update(task_id: &str, context_id: &str) -> TaskStatusUpdateEvent {
    TaskStatusUpdateEvent {
        kind: "status-update".to_string(),
        task_id: task_id.to_string(),
        context_id: context_id.to_string(),
        status: TaskStatus {
            state: TaskState::Completed,
            message: None,
            timestamp: Some(now_iso8601()),
        },
        metadata: None,
    }
}

fn jsonrpc_stream_request(message_id: &str) -> Request<Body> {
    let body = json!({
        "jsonrpc": "2.0",
        "method": "message/stream",
        "params": { "message": user_message(message_id, "go") },
        "id": 1,
    });
    Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

fn rest_stream_request(message_id: &str) -> Request<Body> {
    let body = json!({ "message": user_message(message_id, "go") });
    Request::builder()
        .method("POST")
        .uri("/v1/message:stream")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

fn rest_subscribe_request(task_id: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/v1/tasks/{}:subscribe", task_id))
        .body(Body::empty())
        .unwrap()
}

fn jsonrpc_resubscribe_request(task_id: &str) -> Request<Body> {
    let body = json!({
        "jsonrpc": "2.0",
        "method": "tasks/resubscribe",
        "params": { "id": task_id },
        "id": 1,
    });
    Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

/// Drain an SSE response body and parse each `data:` line as JSON.
async fn drain_sse(
    response: axum::response::Response,
    timeout: Duration,
) -> Vec<serde_json::Value> {
    let bytes = tokio::time::timeout(timeout, response.into_body().collect())
        .await
        .expect("SSE body did not drain within timeout — stream is hanging")
        .expect("body collect failed")
        .to_bytes();
    let text = std::str::from_utf8(&bytes).unwrap_or("").to_string();
    let mut events = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            let rest = rest.trim();
            if rest.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(rest) {
                events.push(val);
            }
        }
    }
    events
}

/// Spawn a task that fires the terminal status update on `tx` once the
/// channel has at least one subscriber. Used by the behavioral tests for
/// `:subscribe` and `tasks/resubscribe` where no handler is invoked, so
/// the test itself plays the role of the external emitter.
fn spawn_terminal_on_subscribe(
    tx: broadcast::Sender<StreamResponse>,
    task_id: String,
    context_id: String,
) {
    tokio::spawn(async move {
        loop {
            if tx.receiver_count() >= 1 {
                let _ = tx.send(StreamResponse::StatusUpdate(terminal_status_update(
                    &task_id,
                    &context_id,
                )));
                return;
            }
            tokio::task::yield_now().await;
        }
    });
}

// ── Test handlers ─────────────────────────────────────────────────────────

/// Records `event_tx.receiver_count()` when `handle_message` is invoked.
struct CountingHandler {
    event_tx: Arc<OnceLock<broadcast::Sender<StreamResponse>>>,
    observed_count: Arc<AtomicUsize>,
    handler_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl MessageHandler for CountingHandler {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        let tx = self.event_tx.get().expect("event_tx not installed");
        self.observed_count
            .store(tx.receiver_count(), Ordering::SeqCst);
        self.handler_calls.fetch_add(1, Ordering::SeqCst);

        let task_id = Uuid::new_v4().to_string();
        let context_id = message
            .context_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        // Return a terminal task so the SSE stream closes immediately
        // (the streaming endpoint's `initial_is_terminal` short-circuit
        // fires). The invariant we care about — receiver_count at
        // handle_message time — has already been recorded above.
        Ok(SendMessageResponse::Task(task_with_state(
            &task_id,
            &context_id,
            TaskState::Completed,
        )))
    }

    fn agent_card(&self, _base_url: &str) -> AgentCard {
        streaming_card("Counting Handler")
    }
}

/// Emits a terminal `StatusUpdate` synchronously inside `handle_message`
/// (before returning the Task). The fix guarantees a subscriber is already
/// installed at this point, so the event reaches the SSE stream. Without
/// the fix, the send happens with `receiver_count == 0` and the event is
/// silently dropped — hanging the stream until the test timeout fires.
struct SyncEmitHandler {
    event_tx: Arc<OnceLock<broadcast::Sender<StreamResponse>>>,
}

#[async_trait]
impl MessageHandler for SyncEmitHandler {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        let tx = self.event_tx.get().expect("event_tx not installed");
        let task_id = Uuid::new_v4().to_string();
        let context_id = message
            .context_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let _ = tx.send(StreamResponse::StatusUpdate(terminal_status_update(
            &task_id,
            &context_id,
        )));

        Ok(SendMessageResponse::Task(working_task(&task_id, &context_id)))
    }

    fn agent_card(&self, _base_url: &str) -> AgentCard {
        streaming_card("Sync Emit Handler")
    }
}

/// Spawns a worker that awaits `notify`, then emits a terminal
/// `StatusUpdate`. The test triggers `notify` only after observing
/// `receiver_count() >= 1`, proving the SSE endpoint is subscribed when
/// the worker fires.
struct NotifyEmitHandler {
    event_tx: Arc<OnceLock<broadcast::Sender<StreamResponse>>>,
    notify: Arc<Notify>,
}

#[async_trait]
impl MessageHandler for NotifyEmitHandler {
    async fn handle_message(
        &self,
        message: Message,
        _auth: Option<AuthContext>,
    ) -> HandlerResult<SendMessageResponse> {
        let task_id = Uuid::new_v4().to_string();
        let context_id = message
            .context_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let tx = self
            .event_tx
            .get()
            .expect("event_tx not installed")
            .clone();
        let notify = self.notify.clone();
        let tid = task_id.clone();
        let cid = context_id.clone();
        tokio::spawn(async move {
            notify.notified().await;
            let _ = tx.send(StreamResponse::StatusUpdate(terminal_status_update(
                &tid, &cid,
            )));
        });

        Ok(SendMessageResponse::Task(working_task(&task_id, &context_id)))
    }

    fn agent_card(&self, _base_url: &str) -> AgentCard {
        streaming_card("Notify Emit Handler")
    }
}

// ── JSON-RPC envelope / SSE event helpers ─────────────────────────────────

/// Extract status-update states from JSON-RPC SSE envelopes.
///
/// Envelope shape: `{"jsonrpc":"2.0","id":N,"result":{"statusUpdate":{...,"status":{"state":"..."}}}}`.
fn extract_status_update_states_jsonrpc(events: &[serde_json::Value]) -> Vec<String> {
    events
        .iter()
        .filter_map(|env| {
            env.get("result")
                .and_then(|r| r.get("statusUpdate"))
                .and_then(|u| u.get("status"))
                .and_then(|s| s.get("state"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        })
        .collect()
}

/// Extract status-update states from REST SSE envelopes.
///
/// Envelope shape: `{"statusUpdate":{...,"status":{"state":"..."}}}`.
fn extract_status_update_states_rest(events: &[serde_json::Value]) -> Vec<String> {
    events
        .iter()
        .filter_map(|env| {
            env.get("statusUpdate")
                .and_then(|u| u.get("status"))
                .and_then(|s| s.get("state"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        })
        .collect()
}

// ── Invariant tests (subscribe before handler) ────────────────────────────

/// `message/stream` (JSON-RPC) must establish the broadcast subscription
/// before invoking the handler. Verified structurally: `event_tx.receiver_count()`
/// is observed from inside `handle_message`.
#[tokio::test]
async fn test_message_stream_subscribes_before_handler() {
    let event_tx: Arc<OnceLock<broadcast::Sender<StreamResponse>>> = Arc::new(OnceLock::new());
    let observed = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));

    let server = A2aServer::new(CountingHandler {
        event_tx: event_tx.clone(),
        observed_count: observed.clone(),
        handler_calls: calls.clone(),
    })
    .bind("127.0.0.1:0")
    .expect("valid address");
    event_tx.set(server.get_event_sender()).unwrap();
    let router = server.build_router();

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        router.oneshot(jsonrpc_stream_request("inv-jsonrpc")),
    )
    .await
    .expect("request timed out")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = drain_sse(response, Duration::from_secs(5)).await;

    assert_eq!(calls.load(Ordering::SeqCst), 1, "handler must be invoked");
    let count = observed.load(Ordering::SeqCst);
    assert!(
        count >= 1,
        "receiver_count must be >= 1 when handle_message runs (was {count}); \
         this is the structural invariant of the subscribe-before-handler reorder"
    );
}

/// REST `:stream` mirror of the JSON-RPC invariant test.
#[tokio::test]
async fn test_rest_message_stream_subscribes_before_handler() {
    let event_tx: Arc<OnceLock<broadcast::Sender<StreamResponse>>> = Arc::new(OnceLock::new());
    let observed = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));

    let server = A2aServer::new(CountingHandler {
        event_tx: event_tx.clone(),
        observed_count: observed.clone(),
        handler_calls: calls.clone(),
    })
    .bind("127.0.0.1:0")
    .expect("valid address");
    event_tx.set(server.get_event_sender()).unwrap();
    let router = server.build_router();

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        router.oneshot(rest_stream_request("inv-rest")),
    )
    .await
    .expect("request timed out")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = drain_sse(response, Duration::from_secs(5)).await;

    assert_eq!(calls.load(Ordering::SeqCst), 1, "handler must be invoked");
    let count = observed.load(Ordering::SeqCst);
    assert!(
        count >= 1,
        "receiver_count must be >= 1 when handle_message runs (was {count})"
    );
}

// ── Behavioral tests (handler-emitted terminal reaches SSE stream) ────────

/// Reproduces the original bug shape: handler sends a terminal `StatusUpdate`
/// synchronously inside `handle_message`. Pre-fix: send happens before
/// subscribe, terminal is dropped, the SSE loop awaits forever and the body
/// collect times out. Post-fix: subscribe happens before the handler runs,
/// the terminal lands on `rx`, and the stream closes cleanly.
#[tokio::test]
async fn test_message_stream_delivers_handler_sync_terminal() {
    let event_tx: Arc<OnceLock<broadcast::Sender<StreamResponse>>> = Arc::new(OnceLock::new());

    let server = A2aServer::new(SyncEmitHandler {
        event_tx: event_tx.clone(),
    })
    .bind("127.0.0.1:0")
    .expect("valid address");
    event_tx.set(server.get_event_sender()).unwrap();
    let router = server.build_router();

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        router.oneshot(jsonrpc_stream_request("sync-jsonrpc")),
    )
    .await
    .expect("request timed out")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let events = drain_sse(response, Duration::from_secs(5)).await;
    let terminals = extract_status_update_states_jsonrpc(&events);
    assert!(
        terminals.iter().any(|s| s == "TASK_STATE_COMPLETED"),
        "SSE stream must deliver the handler's synchronously-emitted terminal status; events = {events:?}"
    );
}

/// REST `:stream` mirror of the synchronous-emit behavioral test.
#[tokio::test]
async fn test_rest_message_stream_delivers_handler_sync_terminal() {
    let event_tx: Arc<OnceLock<broadcast::Sender<StreamResponse>>> = Arc::new(OnceLock::new());

    let server = A2aServer::new(SyncEmitHandler {
        event_tx: event_tx.clone(),
    })
    .bind("127.0.0.1:0")
    .expect("valid address");
    event_tx.set(server.get_event_sender()).unwrap();
    let router = server.build_router();

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        router.oneshot(rest_stream_request("sync-rest")),
    )
    .await
    .expect("request timed out")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let events = drain_sse(response, Duration::from_secs(5)).await;
    let terminals = extract_status_update_states_rest(&events);
    assert!(
        terminals.iter().any(|s| s == "TASK_STATE_COMPLETED"),
        "REST :stream must deliver the handler's synchronously-emitted terminal status; events = {events:?}"
    );
}

/// Behavioral test for `message/stream` using a Notify-gated worker: once
/// the test observes `receiver_count >= 1`, it triggers the worker which
/// emits the terminal status update. With the fix, the subscriber is
/// installed before the handler returns, so the worker's event arrives.
#[tokio::test]
async fn test_streaming_does_not_drop_async_worker_events() {
    let event_tx: Arc<OnceLock<broadcast::Sender<StreamResponse>>> = Arc::new(OnceLock::new());
    let notify = Arc::new(Notify::new());

    let server = A2aServer::new(NotifyEmitHandler {
        event_tx: event_tx.clone(),
        notify: notify.clone(),
    })
    .bind("127.0.0.1:0")
    .expect("valid address");
    let tx = server.get_event_sender();
    event_tx.set(tx.clone()).unwrap();
    let router = server.build_router();

    // Poll receiver_count from the test side. Once we see a subscriber,
    // wake the worker to emit the terminal event.
    let tx_for_poll = tx.clone();
    let notify_for_poll = notify.clone();
    tokio::spawn(async move {
        loop {
            if tx_for_poll.receiver_count() >= 1 {
                notify_for_poll.notify_one();
                return;
            }
            tokio::task::yield_now().await;
        }
    });

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        router.oneshot(jsonrpc_stream_request("notif-jsonrpc")),
    )
    .await
    .expect("request timed out")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let events = drain_sse(response, Duration::from_secs(5)).await;
    let terminals = extract_status_update_states_jsonrpc(&events);
    assert!(
        terminals.iter().any(|s| s == "TASK_STATE_COMPLETED"),
        "SSE stream must deliver the worker's terminal status; events = {events:?}"
    );
}

// ── Behavioral tests for `:subscribe` / `tasks/resubscribe` ────────────────
// These prove the post-subscribe event flow works correctly. The
// snapshot-time invariant for these endpoints is verified by code review;
// see the module-level comment.

/// REST `GET /tasks/{id}:subscribe`: after the endpoint subscribes, a
/// terminal `StatusUpdate` fired by an external party must reach the SSE
/// stream and close it cleanly.
#[tokio::test]
async fn test_rest_subscribe_delivers_post_subscribe_terminal() {
    let server = A2aServer::echo().bind("127.0.0.1:0").expect("valid address");
    let task_store = server.get_task_store();
    let tx = server.get_event_sender();
    let router = server.build_router();

    let task_id = Uuid::new_v4().to_string();
    let context_id = Uuid::new_v4().to_string();
    task_store.insert(working_task(&task_id, &context_id)).await;

    spawn_terminal_on_subscribe(tx.clone(), task_id.clone(), context_id.clone());

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        router.oneshot(rest_subscribe_request(&task_id)),
    )
    .await
    .expect("request timed out")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let events = drain_sse(response, Duration::from_secs(5)).await;
    let terminals = extract_status_update_states_rest(&events);
    assert!(
        terminals.iter().any(|s| s == "TASK_STATE_COMPLETED"),
        ":subscribe must deliver the post-subscribe terminal status; events = {events:?}"
    );
}

/// JSON-RPC `tasks/resubscribe` mirror of the `:subscribe` behavioral test.
#[tokio::test]
async fn test_resubscribe_delivers_post_subscribe_terminal() {
    let server = A2aServer::echo().bind("127.0.0.1:0").expect("valid address");
    let task_store = server.get_task_store();
    let tx = server.get_event_sender();
    let router = server.build_router();

    let task_id = Uuid::new_v4().to_string();
    let context_id = Uuid::new_v4().to_string();
    task_store.insert(working_task(&task_id, &context_id)).await;

    spawn_terminal_on_subscribe(tx.clone(), task_id.clone(), context_id.clone());

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        router.oneshot(jsonrpc_resubscribe_request(&task_id)),
    )
    .await
    .expect("request timed out")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let events = drain_sse(response, Duration::from_secs(5)).await;
    let terminals = extract_status_update_states_jsonrpc(&events);
    assert!(
        terminals.iter().any(|s| s == "TASK_STATE_COMPLETED"),
        "tasks/resubscribe must deliver the post-subscribe terminal status; events = {events:?}"
    );
}
