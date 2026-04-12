//! REST / HTTP+JSON transport binding for A2A v1.0
//!
//! Implements the A2A HTTP+JSON binding per spec Section 11, using RESTful
//! URLs, standard HTTP verbs, and AIP-193 error format.
//!
//! Routes:
//!   POST /message:send         → SendMessage
//!   POST /message:stream       → SendStreamingMessage (SSE)
//!   GET  /tasks/{id}           → GetTask
//!   GET  /tasks                → ListTasks
//!   POST /tasks/{id}:cancel    → CancelTask
//!   GET  /tasks/{id}:subscribe → SubscribeToTask (SSE)
//!   GET  /extendedAgentCard    → GetExtendedAgentCard
//!   POST /tasks/{task_id}/pushNotificationConfigs         → CreatePushConfig
//!   GET  /tasks/{task_id}/pushNotificationConfigs/{id}    → GetPushConfig
//!   GET  /tasks/{task_id}/pushNotificationConfigs         → ListPushConfigs
//!   DELETE /tasks/{task_id}/pushNotificationConfigs/{id}  → DeletePushConfig

use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::future::FutureExt;
use serde::Deserialize;
use tokio::sync::broadcast;

use a2a_rs_core::{
    errors, now_iso8601, ListTasksRequest, SendMessageRequest,
    SendMessageResponse, SendMessageResult, StreamResponse, StreamingMessageResult,
    TaskState, TaskStatusUpdateEvent,
};

use crate::handler::AuthContext;
use crate::server::AppState;
use crate::task_store::TaskStore;

// ── AIP-193 error helper ──────────────────────────────────────────────────

fn aip_error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    aip_error_with_reason(status, message, reason_for_status(status))
}

fn aip_error_with_reason(status: StatusCode, message: &str, reason: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({
            "error": {
                "code": status.as_u16(),
                "message": message,
                "status": grpc_status_for(status),
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": reason,
                    "domain": "a2a-protocol.org"
                }]
            }
        })),
    )
}

fn reason_for_status(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "INVALID_ARGUMENT",
        401 => "UNAUTHENTICATED",
        404 => "NOT_FOUND",
        405 => "METHOD_NOT_ALLOWED",
        409 => "FAILED_PRECONDITION",
        415 => "UNSUPPORTED_MEDIA_TYPE",
        500 => "INTERNAL",
        502 => "BAD_GATEWAY",
        _ => "UNKNOWN",
    }
}

fn grpc_status_for(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "INVALID_ARGUMENT",
        404 => "NOT_FOUND",
        405 => "INVALID_ARGUMENT",
        409 => "FAILED_PRECONDITION",
        415 => "INVALID_ARGUMENT",
        500 => "INTERNAL",
        502 => "INTERNAL",
        _ => "UNKNOWN",
    }
}

fn a2a_error_to_http(code: i32) -> StatusCode {
    match code {
        errors::TASK_NOT_FOUND => StatusCode::NOT_FOUND,                      // 404
        errors::TASK_NOT_CANCELABLE => StatusCode::CONFLICT,                  // 409
        errors::PUSH_NOTIFICATION_NOT_SUPPORTED => StatusCode::BAD_REQUEST,   // 400
        errors::UNSUPPORTED_OPERATION => StatusCode::BAD_REQUEST,             // 400
        errors::CONTENT_TYPE_NOT_SUPPORTED => StatusCode::UNSUPPORTED_MEDIA_TYPE, // 415
        errors::INVALID_AGENT_RESPONSE => StatusCode::BAD_GATEWAY,           // 502
        errors::EXTENDED_AGENT_CARD_NOT_CONFIGURED => StatusCode::BAD_REQUEST, // 400
        errors::EXTENSION_SUPPORT_REQUIRED => StatusCode::BAD_REQUEST,       // 400
        errors::VERSION_NOT_SUPPORTED => StatusCode::BAD_REQUEST,             // 400
        errors::INVALID_PARAMS => StatusCode::BAD_REQUEST,                    // 400
        errors::METHOD_NOT_FOUND => StatusCode::NOT_FOUND,                    // 404
        errors::INVALID_REQUEST => StatusCode::BAD_REQUEST,                   // 400
        errors::INTERNAL_ERROR => StatusCode::INTERNAL_SERVER_ERROR,          // 500
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn handler_error_response(e: &crate::handler::HandlerError) -> Response {
    let (code, _) = crate::server::handler_error_to_rpc(e);
    let status = a2a_error_to_http(code);
    let reason = a2a_error_reason(code);
    aip_error_with_reason(status, &e.to_string(), reason).into_response()
}

fn a2a_error_reason(code: i32) -> &'static str {
    match code {
        errors::TASK_NOT_FOUND => "TASK_NOT_FOUND",
        errors::TASK_NOT_CANCELABLE => "TASK_NOT_CANCELABLE",
        errors::PUSH_NOTIFICATION_NOT_SUPPORTED => "PUSH_NOTIFICATION_NOT_SUPPORTED",
        errors::UNSUPPORTED_OPERATION => "UNSUPPORTED_OPERATION",
        errors::CONTENT_TYPE_NOT_SUPPORTED => "CONTENT_TYPE_NOT_SUPPORTED",
        errors::INVALID_AGENT_RESPONSE => "INVALID_AGENT_RESPONSE",
        errors::EXTENDED_AGENT_CARD_NOT_CONFIGURED => "EXTENDED_AGENT_CARD_NOT_CONFIGURED",
        errors::EXTENSION_SUPPORT_REQUIRED => "EXTENSION_SUPPORT_REQUIRED",
        errors::VERSION_NOT_SUPPORTED => "VERSION_NOT_SUPPORTED",
        errors::INVALID_PARAMS => "INVALID_PARAMS",
        errors::METHOD_NOT_FOUND => "METHOD_NOT_FOUND",
        errors::INVALID_REQUEST => "INVALID_REQUEST",
        errors::INTERNAL_ERROR => "INTERNAL",
        _ => "UNKNOWN",
    }
}

fn apply_history_length(task: &mut a2a_rs_core::Task, history_length: Option<i32>) {
    crate::server::apply_history_length(task, history_length);
}

// ── Router ────────────────────────────────────────────────────────────────

/// Try to dispatch a request as a REST call. Returns `Some(response)` if
/// the path matches a REST route, `None` if it doesn't (so the caller can
/// fall through to JSON-RPC).
///
/// Called from the main router's fallback handler in server.rs.
/// Try to dispatch a request as a REST call. Returns `Some(response)` if
/// the path matches a REST route, `None` to fall through to JSON-RPC.
///
/// Called from the main router's fallback handler in server.rs.
pub(crate) async fn try_rest_dispatch(
    state: &AppState,
    method: &axum::http::Method,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    body: &axum::body::Bytes,
    rest_prefix: &str,
) -> Option<Response> {
    let path = uri.path();
    let sub = path.strip_prefix(rest_prefix)?;

    use axum::http::Method;

    // POST /message:send
    if *method == Method::POST && sub == "/message:send" {
        let params: SendMessageRequest = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => return Some(aip_error(StatusCode::BAD_REQUEST, &format!("invalid request: {e}")).into_response()),
        };
        return Some(rest_send_message(State(state.clone()), headers.clone(), Json(params)).await);
    }

    // POST /message:stream
    if *method == Method::POST && sub == "/message:stream" {
        let params: SendMessageRequest = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => return Some(aip_error(StatusCode::BAD_REQUEST, &format!("invalid request: {e}")).into_response()),
        };
        return Some(rest_send_streaming_message(State(state.clone()), headers.clone(), Json(params)).await);
    }

    // GET /tasks (list)
    if *method == Method::GET && (sub == "/tasks" || sub == "/tasks/") {
        let mut query = ListTasksQuery::default();
        if let Some(qs) = uri.query() {
            for pair in qs.split('&') {
                if let Some((key, val)) = pair.split_once('=') {
                    match key {
                        "contextId" => query.context_id = Some(val.to_string()),
                        "status" => query.status = serde_json::from_value(serde_json::Value::String(val.to_string())).ok(),
                        "pageSize" => query.page_size = val.parse().ok(),
                        "pageToken" => query.page_token = Some(val.to_string()),
                        "historyLength" => query.history_length = val.parse().ok(),
                        "statusTimestampAfter" => query.status_timestamp_after = Some(val.to_string()),
                        "includeArtifacts" => query.include_artifacts = val.parse().ok(),
                        _ => {}
                    }
                }
            }
        }
        return Some(rest_list_tasks(State(state.clone()), Query(query)).await.into_response());
    }

    // GET /extendedAgentCard
    if *method == Method::GET && sub == "/extendedAgentCard" {
        return Some(rest_get_extended_agent_card(State(state.clone()), headers.clone()).await);
    }

    // /tasks/{...} paths
    let tasks_rest = sub.strip_prefix("/tasks/")?;

    // Push notification config paths first (more specific match)
    if let Some(push_idx) = tasks_rest.find("/pushNotificationConfigs") {
        let task_id = tasks_rest[..push_idx].to_string();
        let after = &tasks_rest[push_idx + "/pushNotificationConfigs".len()..];
        let config_id = after.strip_prefix('/').unwrap_or("").to_string();

        return Some(match (method.as_str(), config_id.is_empty()) {
            ("POST", true) => rest_create_push_config(State(state.clone()), Path(task_id), Json(serde_json::from_slice(body).unwrap_or_default())).await,
            ("GET", true) => rest_list_push_configs(State(state.clone()), Path(task_id)).await,
            ("GET", false) => rest_get_push_config(State(state.clone()), Path((task_id, config_id))).await,
            ("DELETE", false) => rest_delete_push_config(State(state.clone()), Path((task_id, config_id))).await,
            _ => aip_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response(),
        });
    }

    // POST /tasks/{id}:cancel
    if *method == Method::POST {
        if let Some(id) = tasks_rest.strip_suffix(":cancel") {
            if !id.is_empty() && !id.contains('/') {
                return Some(rest_cancel_task(State(state.clone()), Path(id.to_string())).await);
            }
        }
    }

    // GET /tasks/{id}:subscribe
    if *method == Method::GET {
        if let Some(id) = tasks_rest.strip_suffix(":subscribe") {
            if !id.is_empty() && !id.contains('/') {
                return Some(rest_subscribe_to_task(State(state.clone()), Path(id.to_string())).await);
            }
        }
    }

    // GET /tasks/{id}
    if *method == Method::GET && !tasks_rest.contains('/') && !tasks_rest.contains(':') {
        let mut query = GetTaskQuery::default();
        if let Some(qs) = uri.query() {
            for pair in qs.split('&') {
                if let Some(val) = pair.strip_prefix("historyLength=") {
                    query.history_length = val.parse().ok();
                }
            }
        }
        return Some(rest_get_task(State(state.clone()), Path(tasks_rest.to_string()), Query(query)).await);
    }

    None
}

// ── Query param structs ───────────────────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct GetTaskQuery {
    history_length: Option<i32>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ListTasksQuery {
    context_id: Option<String>,
    status: Option<a2a_rs_core::TaskState>,
    page_size: Option<i32>,
    page_token: Option<String>,
    history_length: Option<i32>,
    status_timestamp_after: Option<String>,
    include_artifacts: Option<bool>,
}

// ── Auth helper ───────────────────────────────────────────────────────────

fn extract_auth(state: &AppState, headers: &HeaderMap) -> Option<AuthContext> {
    state
        .auth_extractor_ref()
        .and_then(|extractor| extractor(headers))
}

// ── Handlers ──────────────────────────────────────────────────────────────

async fn rest_send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(params): Json<SendMessageRequest>,
) -> Response {
    let auth = extract_auth(&state, &headers);

    if params.message.parts.is_empty() {
        return aip_error(StatusCode::BAD_REQUEST, "message parts must not be empty").into_response();
    }

    let continue_task_id = params.message.task_id.clone();
    let history_length = params.configuration.as_ref().and_then(|c| c.history_length);

    // Validate taskId references
    if let Some(ref tid) = continue_task_id {
        match state.task_store().get_flexible(tid).await {
            Some(task) if task.status.state.is_terminal() => {
                return aip_error(
                    StatusCode::BAD_REQUEST,
                    "cannot send message to a task in terminal state",
                )
                .into_response();
            }
            None => {
                return aip_error(StatusCode::NOT_FOUND, "task not found").into_response();
            }
            _ => {}
        }
    }

    match state
        .handler_ref()
        .handle_message(params.message, auth)
        .await
    {
        Ok(response) => match response {
            SendMessageResponse::Task(mut task) => {
                if let Some(ref tid) = continue_task_id {
                    if state.task_store().get_flexible(tid).await.is_some() {
                        task.id = tid.clone();
                    }
                }
                state.task_store().insert(task.clone()).await;
                state.broadcast_event(StreamResponse::Task(task.clone()));

                if !task.status.state.is_terminal() {
                    if let Some(delay) = state.handler_ref().auto_complete_delay() {
                        let ts = state.task_store().clone();
                        let tx = state.event_sender().clone();
                        let tid = task.id.clone();
                        let ctx = task.context_id.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let completed = ts
                                .update_flexible(&tid, |t| {
                                    if !t.status.state.is_terminal() {
                                        t.status.state = TaskState::Completed;
                                        t.status.timestamp = Some(now_iso8601());
                                        Ok(())
                                    } else {
                                        Err(0)
                                    }
                                })
                                .await;
                            if let Some(Ok(t)) = completed {
                                let _ = tx.send(StreamResponse::StatusUpdate(
                                    TaskStatusUpdateEvent {
                                        kind: "status-update".to_string(),
                                        task_id: t.id.clone(),
                                        context_id: ctx,
                                        status: t.status.clone(),
                                        metadata: None,
                                    },
                                ));
                            }
                        });
                    }
                }

                apply_history_length(&mut task, history_length);

                match serde_json::to_value(SendMessageResult::Task(task)) {
                    Ok(val) => (StatusCode::OK, Json(val)).into_response(),
                    Err(e) => aip_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("serialization failed: {e}"),
                    )
                    .into_response(),
                }
            }
            SendMessageResponse::Message(msg) => {
                match serde_json::to_value(SendMessageResult::Message(msg)) {
                    Ok(val) => (StatusCode::OK, Json(val)).into_response(),
                    Err(e) => aip_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("serialization failed: {e}"),
                    )
                    .into_response(),
                }
            }
        },
        Err(e) => handler_error_response(&e),
    }
}

async fn rest_send_streaming_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(params): Json<SendMessageRequest>,
) -> Response {
    let auth = extract_auth(&state, &headers);

    if !state.agent_card().capabilities.streaming.unwrap_or(false) {
        return aip_error(StatusCode::BAD_REQUEST, "streaming not supported by this agent")
            .into_response();
    }

    let continue_task_id = params.message.task_id.clone();

    let response = match state
        .handler_ref()
        .handle_message(params.message, auth)
        .await
    {
        Ok(r) => r,
        Err(e) => return handler_error_response(&e),
    };

    let mut task = match response {
        SendMessageResponse::Task(t) => t,
        SendMessageResponse::Message(msg) => {
            // Yield message as single SSE event
            let stream = async_stream::stream! {
                if let Ok(val) = serde_json::to_value(StreamingMessageResult::Message(msg)) {
                    let body = serde_json::to_string(&val).unwrap_or_default();
                    yield Ok::<_, Infallible>(Event::default().data(body));
                }
            };
            return Sse::new(stream)
                .keep_alive(KeepAlive::default())
                .into_response();
        }
    };

    if let Some(ref tid) = continue_task_id {
        if state.task_store().get_flexible(tid).await.is_some() {
            task.id = tid.clone();
        }
    }

    let task_id = task.id.clone();
    state.task_store().insert(task.clone()).await;

    let mut rx = state.subscribe_events();
    state.broadcast_event(StreamResponse::Task(task.clone()));

    let task_store = state.task_store().clone();
    let target_task_id = task_id;

    let stream = async_stream::stream! {
        let initial_is_terminal = task.status.state.is_terminal();

        if let Ok(val) = serde_json::to_value(StreamingMessageResult::Task(task)) {
            let body = serde_json::to_string(&val).unwrap_or_default();
            yield Ok::<_, Infallible>(Event::default().data(body));
        }

        if initial_is_terminal {
            return;
        }

        loop {
            match rx.recv().await {
                Ok(event) => {
                    let matches = match &event {
                        StreamResponse::Task(t) => t.id == target_task_id,
                        StreamResponse::StatusUpdate(e) => e.task_id == target_task_id,
                        StreamResponse::ArtifactUpdate(e) => e.task_id == target_task_id,
                        StreamResponse::Message(m) => {
                            m.context_id.as_ref().is_some_and(|ctx| {
                                task_store.get(&target_task_id).now_or_never()
                                    .flatten()
                                    .is_some_and(|t| t.context_id == *ctx)
                            })
                        }
                    };

                    if matches {
                        let val = match event.clone() {
                            StreamResponse::Task(t) => serde_json::to_value(StreamingMessageResult::Task(t)),
                            StreamResponse::Message(m) => serde_json::to_value(StreamingMessageResult::Message(m)),
                            StreamResponse::StatusUpdate(e) => serde_json::to_value(StreamingMessageResult::StatusUpdate(e)),
                            StreamResponse::ArtifactUpdate(e) => serde_json::to_value(StreamingMessageResult::ArtifactUpdate(e)),
                        };
                        if let Ok(val) = val {
                            let body = serde_json::to_string(&val).unwrap_or_default();
                            yield Ok(Event::default().data(body));
                        }

                        let is_terminal = match &event {
                            StreamResponse::Task(t) => t.status.state.is_terminal(),
                            StreamResponse::StatusUpdate(e) => e.status.state.is_terminal(),
                            _ => false,
                        };
                        if is_terminal {
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn rest_get_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<GetTaskQuery>,
) -> Response {
    match state.task_store().get_flexible(&id).await {
        Some(mut task) => {
            apply_history_length(&mut task, query.history_length);
            match serde_json::to_value(task) {
                Ok(val) => (StatusCode::OK, Json(val)).into_response(),
                Err(e) => aip_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("serialization failed: {e}"),
                )
                .into_response(),
            }
        }
        None => aip_error(StatusCode::NOT_FOUND, "task not found").into_response(),
    }
}

async fn rest_list_tasks(
    State(state): State<AppState>,
    Query(query): Query<ListTasksQuery>,
) -> Response {
    let params = ListTasksRequest {
        context_id: query.context_id,
        status: query.status,
        page_size: query.page_size,
        page_token: query.page_token,
        history_length: query.history_length,
        status_timestamp_after: query.status_timestamp_after.and_then(|s| {
            if let Ok(ms) = s.parse::<i64>() {
                Some(ms)
            } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&s) {
                Some(dt.timestamp_millis())
            } else {
                None
            }
        }),
        include_artifacts: query.include_artifacts,
        tenant: None,
    };

    if let Err(msg) = TaskStore::validate_list_params(&params) {
        return aip_error(StatusCode::BAD_REQUEST, msg).into_response();
    }

    let response = state.task_store().list_filtered(&params).await;
    match serde_json::to_value(response) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => aip_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("serialization failed: {e}"),
        )
        .into_response(),
    }
}

async fn rest_cancel_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let result = state
        .task_store()
        .update_flexible(&id, |task| {
            if task.status.state.is_terminal() {
                return Err(errors::TASK_NOT_CANCELABLE);
            }
            task.status.state = TaskState::Canceled;
            task.status.timestamp = Some(now_iso8601());
            Ok(())
        })
        .await;

    match result {
        Some(Ok(task)) => {
            if let Err(e) = state.handler_ref().cancel_task(&task.id).await {
                tracing::warn!("Handler cancel_task failed: {}", e);
            }
            state.broadcast_event(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                kind: "status-update".to_string(),
                task_id: task.id.clone(),
                context_id: task.context_id.clone(),
                status: task.status.clone(),
                metadata: None,
            }));
            match serde_json::to_value(task) {
                Ok(val) => (StatusCode::OK, Json(val)).into_response(),
                Err(e) => aip_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("serialization failed: {e}"),
                )
                .into_response(),
            }
        }
        Some(Err(_)) => aip_error(StatusCode::CONFLICT, "task not cancelable").into_response(),
        None => aip_error(StatusCode::NOT_FOUND, "task not found").into_response(),
    }
}

async fn rest_subscribe_to_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let task = match state.task_store().get_flexible(&id).await {
        Some(t) => t,
        None => return aip_error(StatusCode::NOT_FOUND, "task not found").into_response(),
    };

    if task.status.state.is_terminal() {
        return aip_error(
            StatusCode::BAD_REQUEST,
            "cannot subscribe to a task in terminal state",
        )
        .into_response();
    }

    let target_task_id = task.id.clone();
    let mut rx = state.subscribe_events();
    let task_store = state.task_store().clone();

    let stream = async_stream::stream! {
        if let Ok(val) = serde_json::to_value(StreamingMessageResult::Task(task.clone())) {
            let body = serde_json::to_string(&val).unwrap_or_default();
            yield Ok::<_, Infallible>(Event::default().data(body));
        }

        loop {
            match rx.recv().await {
                Ok(event) => {
                    let matches = match &event {
                        StreamResponse::Task(t) => t.id == target_task_id,
                        StreamResponse::StatusUpdate(e) => e.task_id == target_task_id,
                        StreamResponse::ArtifactUpdate(e) => e.task_id == target_task_id,
                        StreamResponse::Message(m) => {
                            m.context_id.as_ref().is_some_and(|ctx| {
                                task_store.get(&target_task_id).now_or_never()
                                    .flatten()
                                    .is_some_and(|t| t.context_id == *ctx)
                            })
                        }
                    };

                    if matches {
                        let val = match event.clone() {
                            StreamResponse::Task(t) => serde_json::to_value(StreamingMessageResult::Task(t)),
                            StreamResponse::Message(m) => serde_json::to_value(StreamingMessageResult::Message(m)),
                            StreamResponse::StatusUpdate(e) => serde_json::to_value(StreamingMessageResult::StatusUpdate(e)),
                            StreamResponse::ArtifactUpdate(e) => serde_json::to_value(StreamingMessageResult::ArtifactUpdate(e)),
                        };
                        if let Ok(val) = val {
                            let body = serde_json::to_string(&val).unwrap_or_default();
                            yield Ok(Event::default().data(body));
                        }

                        let is_terminal = match &event {
                            StreamResponse::Task(t) => t.status.state.is_terminal(),
                            StreamResponse::StatusUpdate(e) => e.status.state.is_terminal(),
                            _ => false,
                        };
                        if is_terminal {
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn rest_get_extended_agent_card(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let auth = extract_auth(&state, &headers);
    let has_auth_config = !state.agent_card().security_schemes.is_empty()
        || state.auth_extractor_ref().is_some();

    let auth = match auth {
        Some(a) => a,
        None if has_auth_config => {
            return aip_error(
                StatusCode::UNAUTHORIZED,
                "authentication required for extended agent card",
            )
            .into_response();
        }
        None => AuthContext {
            user_id: String::new(),
            access_token: String::new(),
            metadata: None,
        },
    };

    let rpc_path = state.rpc_path().to_string();
    let base_url = state.endpoint_url().trim_end_matches(rpc_path.as_str());

    match state.handler_ref().extended_agent_card(base_url, &auth).await {
        Some(card) => match serde_json::to_value(card) {
            Ok(val) => (StatusCode::OK, Json(val)).into_response(),
            Err(e) => aip_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("serialization failed: {e}"),
            )
            .into_response(),
        },
        None => aip_error(
            StatusCode::BAD_REQUEST,
            "extended agent card not configured",
        )
        .into_response(),
    }
}

// ── Push Notification Config Handlers ─────────────────────────────────────

async fn rest_create_push_config(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if !state.agent_card().capabilities.push_notifications.unwrap_or(false) {
        return aip_error(StatusCode::BAD_REQUEST, "push notifications not supported")
            .into_response();
    }

    if state.task_store().get_flexible(&task_id).await.is_none() {
        return aip_error(StatusCode::NOT_FOUND, "task not found").into_response();
    }

    let config_id = body
        .get("configId")
        .or_else(|| body.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();

    let push_config = match body.get("pushNotificationConfig") {
        Some(c) => match serde_json::from_value(c.clone()) {
            Ok(c) => c,
            Err(e) => {
                return aip_error(StatusCode::BAD_REQUEST, &format!("invalid config: {e}"))
                    .into_response()
            }
        },
        None => match serde_json::from_value(body.clone()) {
            Ok(c) => c,
            Err(e) => {
                return aip_error(StatusCode::BAD_REQUEST, &format!("invalid config: {e}"))
                    .into_response()
            }
        },
    };

    if let Err(e) = state
        .webhook_store_ref()
        .set(&task_id, &config_id, push_config)
        .await
    {
        return aip_error(StatusCode::BAD_REQUEST, &e.to_string()).into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "configId": config_id,
            "taskId": task_id,
        })),
    )
        .into_response()
}

async fn rest_get_push_config(
    State(state): State<AppState>,
    Path((task_id, config_id)): Path<(String, String)>,
) -> Response {
    if !state.agent_card().capabilities.push_notifications.unwrap_or(false) {
        return aip_error(StatusCode::BAD_REQUEST, "push notifications not supported")
            .into_response();
    }

    match state.webhook_store_ref().get(&task_id, &config_id).await {
        Some(config) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "configId": config_id,
                "config": config,
            })),
        )
            .into_response(),
        None => aip_error(StatusCode::NOT_FOUND, "push notification config not found").into_response(),
    }
}

async fn rest_list_push_configs(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Response {
    if !state.agent_card().capabilities.push_notifications.unwrap_or(false) {
        return aip_error(StatusCode::BAD_REQUEST, "push notifications not supported")
            .into_response();
    }

    let configs = state.webhook_store_ref().list(&task_id).await;
    let configs_json: Vec<_> = configs
        .iter()
        .map(|c| {
            serde_json::json!({
                "configId": c.config_id,
                "config": c.config,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "configs": configs_json,
            "nextPageToken": ""
        })),
    )
        .into_response()
}

async fn rest_delete_push_config(
    State(state): State<AppState>,
    Path((task_id, config_id)): Path<(String, String)>,
) -> Response {
    if !state.agent_card().capabilities.push_notifications.unwrap_or(false) {
        return aip_error(StatusCode::BAD_REQUEST, "push notifications not supported")
            .into_response();
    }

    if state.webhook_store_ref().delete(&task_id, &config_id).await {
        (StatusCode::OK, Json(serde_json::json!({}))).into_response()
    } else {
        aip_error(StatusCode::NOT_FOUND, "push notification config not found").into_response()
    }
}
