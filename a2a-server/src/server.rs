//! Generic A2A JSON-RPC Server

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use tokio::signal;
use tokio::time::timeout;
use tower::ServiceBuilder;

const BLOCKING_TIMEOUT: Duration = Duration::from_secs(300);
const BLOCKING_POLL_INTERVAL: Duration = Duration::from_millis(100);

use a2a_rs_core::{
    error, errors, now_iso8601, success, AgentCard, CancelTaskRequest,
    CreateTaskPushNotificationConfigRequest, DeleteTaskPushNotificationConfigRequest,
    GetTaskPushNotificationConfigRequest, GetTaskRequest, JsonRpcRequest, JsonRpcResponse,
    ListTaskPushNotificationConfigRequest, ListTasksRequest, SendMessageRequest,
    SendMessageResponse, StreamResponse, SubscribeToTaskRequest, Task, TaskState,
    TaskStatusUpdateEvent, PROTOCOL_VERSION,
};

const A2A_VERSION_HEADER: &str = "A2A-Version";
const SUPPORTED_VERSION_MAJOR: u32 = 1;
const SUPPORTED_VERSION_MINOR: u32 = 0;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::future::FutureExt;
use futures::stream::Stream;
use tokio::sync::broadcast;
use tracing::info;

use crate::handler::{AuthContext, BoxedHandler, EchoHandler, HandlerError};
use crate::task_store::TaskStore;
use crate::webhook_delivery::WebhookDelivery;
use crate::webhook_store::WebhookStore;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:8080".to_string(),
        }
    }
}

pub type AuthExtractor = Arc<dyn Fn(&HeaderMap) -> Option<AuthContext> + Send + Sync>;

const EVENT_CHANNEL_CAPACITY: usize = 1024;

pub struct A2aServer {
    config: ServerConfig,
    handler: BoxedHandler,
    task_store: TaskStore,
    webhook_store: WebhookStore,
    auth_extractor: Option<AuthExtractor>,
    additional_routes: Option<Router<AppState>>,
    event_tx: broadcast::Sender<StreamResponse>,
}

impl A2aServer {
    pub fn new(handler: impl crate::handler::MessageHandler + 'static) -> Self {
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            config: ServerConfig::default(),
            handler: Arc::new(handler),
            task_store: TaskStore::new(),
            webhook_store: WebhookStore::new(),
            auth_extractor: None,
            additional_routes: None,
            event_tx,
        }
    }

    pub fn echo() -> Self {
        Self::new(EchoHandler::default())
    }

    pub fn bind(mut self, address: &str) -> Result<Self, std::net::AddrParseError> {
        let _: SocketAddr = address.parse()?;
        self.config.bind_address = address.to_string();
        Ok(self)
    }

    pub fn bind_unchecked(mut self, address: &str) -> Self {
        self.config.bind_address = address.to_string();
        self
    }

    pub fn task_store(mut self, store: TaskStore) -> Self {
        self.task_store = store;
        self
    }

    pub fn auth_extractor<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&HeaderMap) -> Option<AuthContext> + Send + Sync + 'static,
    {
        self.auth_extractor = Some(Arc::new(extractor));
        self
    }

    pub fn additional_routes(mut self, routes: Router<AppState>) -> Self {
        self.additional_routes = Some(routes);
        self
    }

    pub fn get_task_store(&self) -> TaskStore {
        self.task_store.clone()
    }

    pub fn build_router(self) -> Router {
        let bind: SocketAddr = self.config.bind_address.parse().expect("Invalid bind address");
        let base_url = format!("http://{}", bind);
        let card = Arc::new(self.handler.agent_card(&base_url));

        let state = AppState {
            handler: self.handler,
            task_store: self.task_store,
            webhook_store: self.webhook_store,
            card,
            auth_extractor: self.auth_extractor,
            event_tx: self.event_tx,
        };

        let timed_routes = Router::new()
            .route("/health", get(health))
            .route("/.well-known/agent-card.json", get(agent_card))
            .route("/v1/rpc", post(handle_rpc))
            .layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(handle_timeout_error))
                    .timeout(Duration::from_secs(30)),
            );

        let sse_routes = Router::new()
            .route("/v1/tasks/:task_id/subscribe", get(handle_task_subscribe_sse))
            .route("/v1/message/stream", post(handle_message_stream_sse));

        let mut router = timed_routes.merge(sse_routes);

        if let Some(additional) = self.additional_routes {
            router = router.merge(additional);
        }

        router.with_state(state)
    }

    pub fn get_event_sender(&self) -> broadcast::Sender<StreamResponse> {
        self.event_tx.clone()
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr = self.config.bind_address.parse()?;

        let webhook_delivery = Arc::new(WebhookDelivery::new(self.webhook_store.clone()));
        webhook_delivery.start(self.event_tx.subscribe());

        let router = self.build_router();

        info!(%bind, "Starting A2A server");
        let listener = tokio::net::TcpListener::bind(bind).await?;
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await?;

        info!("Server shutdown complete");
        Ok(())
    }
}

async fn handle_timeout_error(err: tower::BoxError) -> (StatusCode, Json<JsonRpcResponse>) {
    if err.is::<tower::timeout::error::Elapsed>() {
        (
            StatusCode::REQUEST_TIMEOUT,
            Json(error(
                serde_json::Value::Null,
                errors::INTERNAL_ERROR,
                "Request timed out",
                None,
            )),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error(
                serde_json::Value::Null,
                errors::INTERNAL_ERROR,
                &format!("Internal error: {}", err),
                None,
            )),
        )
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, initiating graceful shutdown...");
}

#[derive(Clone)]
pub struct AppState {
    handler: BoxedHandler,
    task_store: TaskStore,
    webhook_store: WebhookStore,
    card: Arc<AgentCard>,
    auth_extractor: Option<AuthExtractor>,
    event_tx: broadcast::Sender<StreamResponse>,
}

impl AppState {
    pub fn task_store(&self) -> &TaskStore {
        &self.task_store
    }

    pub fn agent_card(&self) -> &AgentCard {
        &self.card
    }

    pub fn event_sender(&self) -> &broadcast::Sender<StreamResponse> {
        &self.event_tx
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<StreamResponse> {
        self.event_tx.subscribe()
    }

    pub fn broadcast_event(&self, event: StreamResponse) {
        let _ = self.event_tx.send(event);
    }

    /// Check if streaming is enabled in capabilities
    fn streaming_enabled(&self) -> bool {
        self.card.capabilities.streaming.unwrap_or(false)
    }

    /// Check if push notifications are enabled in capabilities
    fn push_notifications_enabled(&self) -> bool {
        self.card.capabilities.push_notifications.unwrap_or(false)
    }

    /// Get the endpoint URL from the agent card
    fn endpoint_url(&self) -> &str {
        self.card.endpoint().unwrap_or("")
    }
}

// ============ History Trimming ============

fn apply_history_length(task: &mut Task, history_length: Option<u32>) {
    match history_length {
        Some(0) => {
            task.history = None;
        }
        Some(n) => {
            if let Some(ref mut history) = task.history {
                let len = history.len();
                if len > n as usize {
                    *history = history.split_off(len - n as usize);
                }
            }
        }
        None => {}
    }
}

// ============ Version Validation ============

fn validate_a2a_version(headers: &HeaderMap, req_id: &serde_json::Value) -> Result<(), (StatusCode, Json<JsonRpcResponse>)> {
    if let Some(version_header) = headers.get(A2A_VERSION_HEADER) {
        let version_str = version_header.to_str().unwrap_or("");

        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.len() >= 2 {
            if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                if major == SUPPORTED_VERSION_MAJOR && minor == SUPPORTED_VERSION_MINOR {
                    return Ok(());
                }

                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(error(
                        req_id.clone(),
                        errors::VERSION_NOT_SUPPORTED,
                        &format!(
                            "Protocol version {}.{} not supported. Supported version: {}.{}",
                            major, minor, SUPPORTED_VERSION_MAJOR, SUPPORTED_VERSION_MINOR
                        ),
                        Some(serde_json::json!({
                            "requestedVersion": version_str,
                            "supportedVersion": format!("{}.{}", SUPPORTED_VERSION_MAJOR, SUPPORTED_VERSION_MINOR)
                        })),
                    )),
                ));
            }
        }

        // Also accept bare "1.0" without minor
        if version_str == "1" || version_str == "1.0" {
            return Ok(());
        }

        return Err((
            StatusCode::BAD_REQUEST,
            Json(error(
                req_id.clone(),
                errors::VERSION_NOT_SUPPORTED,
                &format!("Invalid version format: {}. Expected major.minor (e.g., '1.0')", version_str),
                None,
            )),
        ));
    }

    Ok(())
}

// ============ Error Response Helpers ============

#[allow(dead_code)]
pub fn rpc_error(
    id: serde_json::Value,
    code: i32,
    message: &str,
    status: StatusCode,
) -> (StatusCode, Json<JsonRpcResponse>) {
    (status, Json(error(id, code, message, None)))
}

#[allow(dead_code)]
pub fn rpc_error_with_data(
    id: serde_json::Value,
    code: i32,
    message: &str,
    data: serde_json::Value,
    status: StatusCode,
) -> (StatusCode, Json<JsonRpcResponse>) {
    (status, Json(error(id, code, message, Some(data))))
}

#[allow(dead_code)]
pub fn rpc_success(id: serde_json::Value, result: serde_json::Value) -> (StatusCode, Json<JsonRpcResponse>) {
    (StatusCode::OK, Json(success(id, result)))
}

// ============ Route Handlers ============

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok", "protocol": PROTOCOL_VERSION}))
}

async fn agent_card(State(state): State<AppState>) -> Json<AgentCard> {
    Json((*state.card).clone())
}

async fn handle_task_subscribe_sse(
    State(state): State<AppState>,
    axum::extract::Path(task_id): axum::extract::Path<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.subscribe_events();
    let task_store = state.task_store.clone();
    let target_task_id = task_id;

    let stream = async_stream::stream! {
        if let Some(task) = task_store.get_flexible(&target_task_id).await {
            let event = StreamResponse::Task(task);
            if let Ok(json) = serde_json::to_string(&event) {
                yield Ok(Event::default().data(json));
            }
        }

        loop {
            match rx.recv().await {
                Ok(event) => {
                    let matches = match &event {
                        StreamResponse::Task(t) => t.id == target_task_id,
                        StreamResponse::StatusUpdate(e) => e.task_id == target_task_id,
                        StreamResponse::ArtifactUpdate(e) => e.task_id == target_task_id,
                        StreamResponse::Message(_) => false,
                    };
                    if matches {
                        if let Ok(json) = serde_json::to_string(&event) {
                            yield Ok(Event::default().data(json));
                        }

                        if let StreamResponse::Task(t) = &event {
                            if t.status.state.is_terminal() {
                                break;
                            }
                        }
                        if let StreamResponse::StatusUpdate(e) = &event {
                            if e.status.state.is_terminal() {
                                break;
                            }
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn handle_rpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    if req.jsonrpc != "2.0" {
        let resp = error(req.id, errors::INVALID_REQUEST, "jsonrpc must be 2.0", None);
        return (StatusCode::BAD_REQUEST, Json(resp));
    }

    if let Err(err_response) = validate_a2a_version(&headers, &req.id) {
        return err_response;
    }

    let auth_context = state
        .auth_extractor
        .as_ref()
        .and_then(|extractor| extractor(&headers));

    match req.method.as_str() {
        // Spec method names per JSON-RPC binding
        "message/send" => handle_message_send(state, req, auth_context).await,
        "message/sendStreaming" => handle_message_stream_rpc(state, req).await,
        "tasks/get" => handle_tasks_get(state, req).await,
        "tasks/list" => handle_tasks_list(state, req).await,
        "tasks/cancel" => handle_tasks_cancel(state, req).await,
        "tasks/subscribe" => handle_tasks_subscribe(state, req).await,
        "tasks/pushNotificationConfig/create" => handle_push_config_create(state, req).await,
        "tasks/pushNotificationConfig/get" => handle_push_config_get(state, req).await,
        "tasks/pushNotificationConfig/list" => handle_push_config_list(state, req).await,
        "tasks/pushNotificationConfig/delete" => handle_push_config_delete(state, req).await,
        "agentCard/getExtended" => {
            handle_get_extended_agent_card(state, req, auth_context).await
        }
        _ => (
            StatusCode::NOT_FOUND,
            Json(error(
                req.id,
                errors::METHOD_NOT_FOUND,
                "method not found",
                None,
            )),
        ),
    }
}

fn handler_error_to_rpc(e: &HandlerError) -> (i32, StatusCode) {
    match e {
        HandlerError::InvalidInput(_) => (errors::INVALID_PARAMS, StatusCode::BAD_REQUEST),
        HandlerError::AuthRequired(_) => (errors::INVALID_REQUEST, StatusCode::UNAUTHORIZED),
        HandlerError::BackendUnavailable { .. } => (errors::INTERNAL_ERROR, StatusCode::SERVICE_UNAVAILABLE),
        HandlerError::ProcessingFailed { .. } => (errors::INTERNAL_ERROR, StatusCode::INTERNAL_SERVER_ERROR),
        HandlerError::Internal(_) => (errors::INTERNAL_ERROR, StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn handle_message_send(
    state: AppState,
    req: JsonRpcRequest,
    auth_context: Option<AuthContext>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let req_id = req.id.clone();

    let params: Result<SendMessageRequest, _> =
        serde_json::from_value(req.params.clone().unwrap_or_default());

    let params = match params {
        Ok(p) => p,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(error(
                    req_id,
                    errors::INVALID_PARAMS,
                    "invalid params",
                    Some(serde_json::json!({"error": err.to_string()})),
                )),
            );
        }
    };

    let blocking = params
        .configuration
        .as_ref()
        .and_then(|c| c.blocking)
        .unwrap_or(false);
    let history_length = params
        .configuration
        .as_ref()
        .and_then(|c| c.history_length);

    match state.handler.handle_message(params.message, auth_context).await {
        Ok(response) => {
            match response {
                SendMessageResponse::Task(mut task) => {
                    // Store the task and broadcast event
                    state.task_store.insert(task.clone()).await;
                    state.broadcast_event(StreamResponse::Task(task.clone()));

                    // If blocking mode, wait for task to reach terminal state
                    if blocking && !task.status.state.is_terminal() {
                        let task_id = task.id.clone();
                        let mut rx = state.subscribe_events();

                        let wait_result = timeout(BLOCKING_TIMEOUT, async {
                            loop {
                                tokio::select! {
                                    result = rx.recv() => {
                                        match result {
                                            Ok(StreamResponse::Task(t)) if t.id == task_id => {
                                                if t.status.state.is_terminal() {
                                                    return Some(t);
                                                }
                                            }
                                            Ok(StreamResponse::StatusUpdate(e)) if e.task_id == task_id => {
                                                if e.status.state.is_terminal() {
                                                    if let Some(t) = state.task_store.get(&task_id).await {
                                                        return Some(t);
                                                    }
                                                }
                                            }
                                            Err(broadcast::error::RecvError::Closed) => {
                                                return None;
                                            }
                                            _ => {}
                                        }
                                    }
                                    _ = tokio::time::sleep(BLOCKING_POLL_INTERVAL) => {
                                        if let Some(t) = state.task_store.get(&task_id).await {
                                            if t.status.state.is_terminal() {
                                                return Some(t);
                                            }
                                        }
                                    }
                                }
                            }
                        })
                        .await;

                        match wait_result {
                            Ok(Some(final_task)) => task = final_task,
                            Ok(None) => {
                                if let Some(t) = state.task_store.get(&task.id).await {
                                    task = t;
                                }
                            }
                            Err(_) => {
                                tracing::warn!("Blocking request timed out for task {}", task.id);
                                if let Some(t) = state.task_store.get(&task.id).await {
                                    task = t;
                                }
                            }
                        }
                    }

                    apply_history_length(&mut task, history_length);

                    // Wrap in SendMessageResponse for spec-compliant serialization
                    let resp = SendMessageResponse::Task(task);
                    match serde_json::to_value(resp) {
                        Ok(val) => (StatusCode::OK, Json(success(req_id, val))),
                        Err(e) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(error(
                                req_id,
                                errors::INTERNAL_ERROR,
                                "serialization failed",
                                Some(serde_json::json!({"error": e.to_string()})),
                            )),
                        ),
                    }
                }
                SendMessageResponse::Message(msg) => {
                    let resp = SendMessageResponse::Message(msg);
                    match serde_json::to_value(resp) {
                        Ok(val) => (StatusCode::OK, Json(success(req_id, val))),
                        Err(e) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(error(
                                req_id,
                                errors::INTERNAL_ERROR,
                                "serialization failed",
                                Some(serde_json::json!({"error": e.to_string()})),
                            )),
                        ),
                    }
                }
            }
        }
        Err(e) => {
            let (code, status) = handler_error_to_rpc(&e);
            (status, Json(error(req_id, code, &e.to_string(), None)))
        }
    }
}

async fn handle_message_stream_rpc(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    if !state.streaming_enabled() {
        return (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::UNSUPPORTED_OPERATION,
                "streaming not supported by this agent",
                None,
            )),
        );
    }

    let base_url = state.endpoint_url().trim_end_matches("/v1/rpc");
    let stream_url = format!("{}/v1/message/stream", base_url);

    (
        StatusCode::OK,
        Json(success(
            req.id,
            serde_json::json!({
                "streamUrl": stream_url,
                "protocol": "sse",
                "method": "POST"
            }),
        )),
    )
}

async fn handle_message_stream_sse(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(params): Json<SendMessageRequest>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, Json<JsonRpcResponse>)> {
    if !state.streaming_enabled() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(error(
                serde_json::Value::Null,
                errors::UNSUPPORTED_OPERATION,
                "streaming not supported by this agent",
                None,
            )),
        ));
    }

    let auth_context = state
        .auth_extractor
        .as_ref()
        .and_then(|extractor| extractor(&headers));

    let response = state
        .handler
        .handle_message(params.message, auth_context)
        .await
        .map_err(|e| {
            let (code, status) = handler_error_to_rpc(&e);
            (status, Json(error(serde_json::Value::Null, code, &e.to_string(), None)))
        })?;

    // Extract task from response (streaming only works with tasks)
    let task = match response {
        SendMessageResponse::Task(t) => t,
        SendMessageResponse::Message(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(error(
                    serde_json::Value::Null,
                    errors::UNSUPPORTED_OPERATION,
                    "handler returned a message, streaming requires a task",
                    None,
                )),
            ));
        }
    };

    let task_id = task.id.clone();
    state.task_store.insert(task.clone()).await;
    state.broadcast_event(StreamResponse::Task(task.clone()));

    let mut rx = state.subscribe_events();
    let task_store = state.task_store.clone();
    let target_task_id = task_id;

    let stream = async_stream::stream! {
        let event = StreamResponse::Task(task);
        if let Ok(json) = serde_json::to_string(&event) {
            yield Ok(Event::default().data(json));
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
                        if let Ok(json) = serde_json::to_string(&event) {
                            yield Ok(Event::default().data(json));
                        }

                        if let StreamResponse::Task(t) = &event {
                            if t.status.state.is_terminal() {
                                break;
                            }
                        }
                        if let StreamResponse::StatusUpdate(e) = &event {
                            if e.status.state.is_terminal() {
                                break;
                            }
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

async fn handle_tasks_get(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let params: Result<GetTaskRequest, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            match state.task_store.get_flexible(&p.id).await {
                Some(mut task) => {
                    apply_history_length(&mut task, p.history_length);

                    match serde_json::to_value(task) {
                        Ok(val) => (StatusCode::OK, Json(success(req.id, val))),
                        Err(e) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(error(
                                req.id,
                                errors::INTERNAL_ERROR,
                                "serialization failed",
                                Some(serde_json::json!({"error": e.to_string()})),
                            )),
                        ),
                    }
                }
                None => (
                    StatusCode::NOT_FOUND,
                    Json(error(req.id, errors::TASK_NOT_FOUND, "task not found", None)),
                ),
            }
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            )),
        ),
    }
}

async fn handle_tasks_cancel(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let params: Result<CancelTaskRequest, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            let result = state
                .task_store
                .update_flexible(&p.id, |task| {
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
                    if let Err(e) = state.handler.cancel_task(&task.id).await {
                        tracing::warn!("Handler cancel_task failed: {}", e);
                    }

                    state.broadcast_event(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                        task_id: task.id.clone(),
                        context_id: task.context_id.clone(),
                        status: task.status.clone(),
                        metadata: None,
                    }));

                    match serde_json::to_value(task) {
                        Ok(val) => (StatusCode::OK, Json(success(req.id, val))),
                        Err(e) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(error(
                                req.id,
                                errors::INTERNAL_ERROR,
                                "serialization failed",
                                Some(serde_json::json!({"error": e.to_string()})),
                            )),
                        ),
                    }
                }
                Some(Err(error_code)) => (
                    StatusCode::BAD_REQUEST,
                    Json(error(req.id, error_code, "task not cancelable", None)),
                ),
                None => (
                    StatusCode::NOT_FOUND,
                    Json(error(req.id, errors::TASK_NOT_FOUND, "task not found", None)),
                ),
            }
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            )),
        ),
    }
}

async fn handle_tasks_list(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let params: Result<ListTasksRequest, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            let response = state.task_store.list_filtered(&p).await;
            match serde_json::to_value(response) {
                Ok(val) => (StatusCode::OK, Json(success(req.id, val))),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(error(
                        req.id,
                        errors::INTERNAL_ERROR,
                        "serialization failed",
                        Some(serde_json::json!({"error": e.to_string()})),
                    )),
                ),
            }
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            )),
        ),
    }
}

async fn handle_tasks_subscribe(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let params: Result<SubscribeToTaskRequest, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            if state.task_store.get_flexible(&p.id).await.is_none() {
                return (
                    StatusCode::NOT_FOUND,
                    Json(error(req.id, errors::TASK_NOT_FOUND, "task not found", None)),
                );
            }

            let base_url = state.endpoint_url().trim_end_matches("/v1/rpc");
            let subscribe_url = format!("{}/v1/tasks/{}/subscribe", base_url, p.id);

            (
                StatusCode::OK,
                Json(success(
                    req.id,
                    serde_json::json!({
                        "subscribeUrl": subscribe_url,
                        "protocol": "sse"
                    }),
                )),
            )
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            )),
        ),
    }
}

async fn handle_get_extended_agent_card(
    state: AppState,
    req: JsonRpcRequest,
    auth_context: Option<AuthContext>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let Some(auth) = auth_context else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(error(
                req.id,
                errors::INVALID_REQUEST,
                "authentication required for extended agent card",
                None,
            )),
        );
    };

    let base_url = state.endpoint_url().trim_end_matches("/v1/rpc");

    match state.handler.extended_agent_card(base_url, &auth).await {
        Some(card) => match serde_json::to_value(card) {
            Ok(val) => (StatusCode::OK, Json(success(req.id, val))),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error(
                    req.id,
                    errors::INTERNAL_ERROR,
                    "serialization failed",
                    Some(serde_json::json!({"error": e.to_string()})),
                )),
            ),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(error(
                req.id,
                errors::EXTENDED_AGENT_CARD_NOT_CONFIGURED,
                "extended agent card not configured",
                None,
            )),
        ),
    }
}

// ============ Push Notification Config Handlers ============

async fn handle_push_config_create(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    if !state.push_notifications_enabled() {
        return (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::PUSH_NOTIFICATION_NOT_SUPPORTED,
                "push notifications not supported",
                None,
            )),
        );
    }

    let params: Result<CreateTaskPushNotificationConfigRequest, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            if state.task_store.get_flexible(&p.task_id).await.is_none() {
                return (
                    StatusCode::NOT_FOUND,
                    Json(error(req.id, errors::TASK_NOT_FOUND, "task not found", None)),
                );
            }

            if let Err(e) = state
                .webhook_store
                .set(&p.task_id, &p.config_id, p.push_notification_config.clone())
                .await
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(error(req.id, errors::INVALID_PARAMS, &e.to_string(), None)),
                );
            }

            (
                StatusCode::OK,
                Json(success(
                    req.id,
                    serde_json::json!({
                        "configId": p.config_id,
                        "config": p.push_notification_config
                    }),
                )),
            )
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            )),
        ),
    }
}

async fn handle_push_config_get(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    if !state.push_notifications_enabled() {
        return (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::PUSH_NOTIFICATION_NOT_SUPPORTED,
                "push notifications not supported",
                None,
            )),
        );
    }

    let params: Result<GetTaskPushNotificationConfigRequest, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            match state.webhook_store.get(&p.task_id, &p.id).await {
                Some(config) => (
                    StatusCode::OK,
                    Json(success(
                        req.id,
                        serde_json::json!({
                            "configId": p.id,
                            "config": config
                        }),
                    )),
                ),
                None => (
                    StatusCode::NOT_FOUND,
                    Json(error(req.id, errors::TASK_NOT_FOUND, "push notification config not found", None)),
                ),
            }
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            )),
        ),
    }
}

async fn handle_push_config_list(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    if !state.push_notifications_enabled() {
        return (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::PUSH_NOTIFICATION_NOT_SUPPORTED,
                "push notifications not supported",
                None,
            )),
        );
    }

    let params: Result<ListTaskPushNotificationConfigRequest, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            let configs = state.webhook_store.list(&p.task_id).await;

            let configs_json: Vec<_> = configs
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "configId": c.config_id,
                        "config": c.config
                    })
                })
                .collect();

            (
                StatusCode::OK,
                Json(success(
                    req.id,
                    serde_json::json!({
                        "configs": configs_json,
                        "nextPageToken": ""
                    }),
                )),
            )
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            )),
        ),
    }
}

async fn handle_push_config_delete(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    if !state.push_notifications_enabled() {
        return (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::PUSH_NOTIFICATION_NOT_SUPPORTED,
                "push notifications not supported",
                None,
            )),
        );
    }

    let params: Result<DeleteTaskPushNotificationConfigRequest, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            if state.webhook_store.delete(&p.task_id, &p.id).await {
                (StatusCode::OK, Json(success(req.id, serde_json::json!({}))))
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(error(req.id, errors::TASK_NOT_FOUND, "push notification config not found", None)),
                )
            }
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(error(
                req.id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            )),
        ),
    }
}

pub async fn run_server<H: crate::handler::MessageHandler + 'static>(
    bind_addr: &str,
    handler: H,
) -> anyhow::Result<()> {
    A2aServer::new(handler).bind(bind_addr)?.run().await
}

pub async fn run_echo_server(bind_addr: &str) -> anyhow::Result<()> {
    A2aServer::echo().bind(bind_addr)?.run().await
}
