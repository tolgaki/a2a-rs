//! Generic A2A JSON-RPC Server
//!
//! This module provides a generic, pluggable A2A server that can work with any
//! backend via the `MessageHandler` trait.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use tokio::signal;
use tower::ServiceBuilder;

use a2a_core::{
    error, errors, extract_task_id, now_iso8601, success, AgentCard, JsonRpcRequest,
    JsonRpcResponse, MessageSendParams, PushNotificationConfigDeleteParams,
    PushNotificationConfigGetParams, PushNotificationConfigListParams,
    PushNotificationConfigSetParams, StreamEvent, TaskCancelParams, TaskListParams,
    TaskQueryParams, TaskState, TaskStatusUpdateEvent, TaskSubscribeParams, PROTOCOL_VERSION,
};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::stream::Stream;
use tokio::sync::broadcast;
use tracing::info;

use crate::handler::{AuthContext, BoxedHandler, EchoHandler, HandlerError};
use crate::task_store::TaskStore;
use crate::webhook_delivery::WebhookDelivery;
use crate::webhook_store::WebhookStore;

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind the server to (e.g., "0.0.0.0:8080")
    pub bind_address: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:8080".to_string(),
        }
    }
}

/// Authentication callback type for extracting auth context from headers
pub type AuthExtractor = Arc<dyn Fn(&HeaderMap) -> Option<AuthContext> + Send + Sync>;

/// Broadcast channel capacity for streaming events
const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// A2A Server builder for configuring and running the server
pub struct A2aServer {
    config: ServerConfig,
    handler: BoxedHandler,
    task_store: TaskStore,
    webhook_store: WebhookStore,
    auth_extractor: Option<AuthExtractor>,
    additional_routes: Option<Router<AppState>>,
    event_tx: broadcast::Sender<StreamEvent>,
}

impl A2aServer {
    /// Create a new server builder with the given handler
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

    /// Create a server with the default echo handler
    pub fn echo() -> Self {
        Self::new(EchoHandler::default())
    }

    /// Set the bind address
    ///
    /// Returns an error if the address format is invalid.
    pub fn bind(mut self, address: &str) -> Result<Self, std::net::AddrParseError> {
        // Validate the address early to catch errors at configuration time
        let _: SocketAddr = address.parse()?;
        self.config.bind_address = address.to_string();
        Ok(self)
    }

    /// Set the bind address (unchecked)
    ///
    /// Panics at server start if the address is invalid.
    /// Prefer `bind()` which validates immediately.
    pub fn bind_unchecked(mut self, address: &str) -> Self {
        self.config.bind_address = address.to_string();
        self
    }

    /// Set a custom task store
    pub fn task_store(mut self, store: TaskStore) -> Self {
        self.task_store = store;
        self
    }

    /// Set an authentication extractor
    ///
    /// The extractor is called for each request to extract authentication context
    /// from the request headers.
    pub fn auth_extractor<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&HeaderMap) -> Option<AuthContext> + Send + Sync + 'static,
    {
        self.auth_extractor = Some(Arc::new(extractor));
        self
    }

    /// Add additional routes to the server
    ///
    /// Use this to add custom endpoints (e.g., OAuth, health checks, etc.)
    pub fn additional_routes(mut self, routes: Router<AppState>) -> Self {
        self.additional_routes = Some(routes);
        self
    }

    /// Get a reference to the task store
    ///
    /// Useful for updating tasks from background processes.
    pub fn get_task_store(&self) -> TaskStore {
        self.task_store.clone()
    }

    /// Build the router without starting the server
    ///
    /// Useful for testing or embedding in other servers.
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

        // Routes that should have a timeout (non-streaming)
        let timed_routes = Router::new()
            .route("/health", get(health))
            .route("/.well-known/agent-card.json", get(agent_card))
            .route("/v1/rpc", post(handle_rpc))
            .layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(handle_timeout_error))
                    .timeout(Duration::from_secs(30)),
            );

        // SSE routes without timeout (long-lived connections)
        let sse_routes = Router::new()
            .route("/v1/tasks/:task_id/subscribe", get(handle_task_subscribe_sse));

        let mut router = timed_routes.merge(sse_routes);

        if let Some(additional) = self.additional_routes {
            router = router.merge(additional);
        }

        router.with_state(state)
    }

    /// Get a reference to the event broadcast sender
    ///
    /// Useful for emitting events from background processes.
    pub fn get_event_sender(&self) -> broadcast::Sender<StreamEvent> {
        self.event_tx.clone()
    }

    /// Run the server
    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr = self.config.bind_address.parse()?;

        // Start webhook delivery engine for push notifications
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

/// Handle timeout errors from the timeout layer
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

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
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

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    handler: BoxedHandler,
    task_store: TaskStore,
    webhook_store: WebhookStore,
    card: Arc<AgentCard>,
    auth_extractor: Option<AuthExtractor>,
    /// Broadcast channel for streaming events
    event_tx: broadcast::Sender<StreamEvent>,
}

impl AppState {
    /// Get a reference to the task store
    pub fn task_store(&self) -> &TaskStore {
        &self.task_store
    }

    /// Get a reference to the agent card
    pub fn agent_card(&self) -> &AgentCard {
        &self.card
    }

    /// Get a reference to the event broadcast sender
    pub fn event_sender(&self) -> &broadcast::Sender<StreamEvent> {
        &self.event_tx
    }

    /// Subscribe to events
    pub fn subscribe_events(&self) -> broadcast::Receiver<StreamEvent> {
        self.event_tx.subscribe()
    }

    /// Broadcast a stream event
    pub fn broadcast_event(&self, event: StreamEvent) {
        // Ignore send errors (no receivers)
        let _ = self.event_tx.send(event);
    }
}

// ============ Error Response Helpers ============

/// Create a JSON-RPC error response tuple
///
/// Combines the HTTP status code with a JSON-RPC error response.
#[allow(dead_code)]
pub fn rpc_error(
    id: serde_json::Value,
    code: i32,
    message: &str,
    status: StatusCode,
) -> (StatusCode, Json<JsonRpcResponse>) {
    (status, Json(error(id, code, message, None)))
}

/// Create a JSON-RPC error response tuple with additional data
///
/// Combines the HTTP status code with a JSON-RPC error response that includes extra data.
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

/// Create a JSON-RPC success response tuple
///
/// Returns HTTP 200 OK with the JSON-RPC result.
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

/// SSE endpoint for task subscription
async fn handle_task_subscribe_sse(
    State(state): State<AppState>,
    axum::extract::Path(task_id): axum::extract::Path<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Extract only what we need to avoid capturing full AppState in the stream closure
    // This prevents memory leaks by not holding references to handler, webhook_store, etc.
    let mut rx = state.subscribe_events();
    let task_store = state.task_store.clone();
    let target_task_id = task_id;

    let stream = async_stream::stream! {
        // Send initial task state if it exists
        if let Some(task) = task_store.get_flexible(&target_task_id).await {
            let event = StreamEvent::Task(task);
            if let Ok(json) = serde_json::to_string(&event) {
                yield Ok(Event::default().data(json));
            }
        }

        // Stream subsequent updates
        loop {
            match rx.recv().await {
                Ok(event) => {
                    // Check if this event matches our target task
                    let matches = match &event {
                        StreamEvent::Task(t) => {
                            t.id == target_task_id
                                || extract_task_id(&t.id).as_deref() == Some(&target_task_id)
                        }
                        StreamEvent::TaskStatusUpdate(e) => {
                            e.task_id == target_task_id
                                || extract_task_id(&e.task_id).as_deref() == Some(&target_task_id)
                        }
                        StreamEvent::TaskArtifactUpdate(e) => {
                            e.task_id == target_task_id
                                || extract_task_id(&e.task_id).as_deref() == Some(&target_task_id)
                        }
                        StreamEvent::Message(_) => false,
                        // Handle future event types (non_exhaustive)
                        _ => false,
                    };
                    if matches {
                        if let Ok(json) = serde_json::to_string(&event) {
                            yield Ok(Event::default().data(json));
                        }

                        // Check if task is in terminal state
                        if let StreamEvent::Task(t) = &event {
                            if t.status.state.is_terminal() {
                                break;
                            }
                        }
                        if let StreamEvent::TaskStatusUpdate(e) = &event {
                            if e.status.state.is_terminal() {
                                break;
                            }
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Missed some events, continue
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

    // Extract auth context if extractor is configured
    let auth_context = state
        .auth_extractor
        .as_ref()
        .and_then(|extractor| extractor(&headers));

    match req.method.as_str() {
        "message/send" => handle_message_send(state, req, auth_context).await,
        "tasks/get" => handle_tasks_get(state, req).await,
        "tasks/list" => handle_tasks_list(state, req).await,
        "tasks/cancel" => handle_tasks_cancel(state, req).await,
        "tasks/subscribe" => handle_tasks_subscribe(state, req).await,
        "tasks/pushNotificationConfig/set" => handle_push_config_set(state, req).await,
        "tasks/pushNotificationConfig/get" => handle_push_config_get(state, req).await,
        "tasks/pushNotificationConfig/list" => handle_push_config_list(state, req).await,
        "tasks/pushNotificationConfig/delete" => handle_push_config_delete(state, req).await,
        "agent/getExtendedAgentCard" => {
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

async fn handle_message_send(
    state: AppState,
    req: JsonRpcRequest,
    auth_context: Option<AuthContext>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let req_id = req.id.clone();
    
    let params: Result<MessageSendParams, _> =
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

    // Call the handler
    match state.handler.handle_message(params.message, auth_context).await {
        Ok(task) => {
            // Store the task and broadcast event
            state.task_store.insert(task.clone()).await;
            state.broadcast_event(StreamEvent::Task(task.clone()));

            match serde_json::to_value(task) {
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
        Err(e) => {
            let (code, status) = match &e {
                HandlerError::InvalidInput(_) => (errors::INVALID_PARAMS, StatusCode::BAD_REQUEST),
                HandlerError::AuthRequired(_) => (errors::INVALID_REQUEST, StatusCode::UNAUTHORIZED),
                HandlerError::BackendUnavailable { .. } => (errors::INTERNAL_ERROR, StatusCode::SERVICE_UNAVAILABLE),
                HandlerError::ProcessingFailed { .. } => (errors::INTERNAL_ERROR, StatusCode::INTERNAL_SERVER_ERROR),
                HandlerError::Internal(_) => (errors::INTERNAL_ERROR, StatusCode::INTERNAL_SERVER_ERROR),
            };
            
            (
                status,
                Json(error(
                    req_id,
                    code,
                    &e.to_string(),
                    None,
                )),
            )
        }
    }
}

async fn handle_tasks_get(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let params: Result<TaskQueryParams, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            match state.task_store.get_flexible(&p.name).await {
                Some(task) => match serde_json::to_value(task) {
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
    let params: Result<TaskCancelParams, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            let task_id = extract_task_id(&p.name).unwrap_or_else(|| p.name.clone());

            // Atomic update - check and update in single operation to prevent race conditions
            let result = state
                .task_store
                .update_flexible(&task_id, |task| {
                    if task.status.state.is_terminal() {
                        return Err(errors::TASK_NOT_CANCELABLE);
                    }
                    task.status.state = TaskState::Cancelled;
                    task.status.timestamp = Some(now_iso8601());
                    Ok(())
                })
                .await;

            match result {
                Some(Ok(task)) => {
                    // Call handler's cancel method (best effort, after state change)
                    if let Err(e) = state.handler.cancel_task(&task.id).await {
                        tracing::warn!("Handler cancel_task failed: {}", e);
                    }

                    state.broadcast_event(StreamEvent::TaskStatusUpdate(TaskStatusUpdateEvent {
                        task_id: task.id.clone(),
                        status: task.status.clone(),
                        timestamp: Some(now_iso8601()),
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
    let params: Result<TaskListParams, _> =
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
    let params: Result<TaskSubscribeParams, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            // Extract task ID from resource name
            let task_id = extract_task_id(&p.name).unwrap_or_else(|| p.name.clone());

            // Check if task exists
            if state.task_store.get_flexible(&task_id).await.is_none() {
                return (
                    StatusCode::NOT_FOUND,
                    Json(error(req.id, errors::TASK_NOT_FOUND, "task not found", None)),
                );
            }

            // Return the SSE endpoint URL for this task
            let base_url = state.card.endpoint.trim_end_matches("/v1/rpc");
            let subscribe_url = format!("{}/v1/tasks/{}/subscribe", base_url, task_id);

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
    // Extended agent card requires authentication
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

    // Get base URL from the agent card
    let base_url = state.card.endpoint.trim_end_matches("/v1/rpc");

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

async fn handle_push_config_set(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    // Check if push notifications are supported
    if !state.card.capabilities.push_notifications {
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

    let params: Result<PushNotificationConfigSetParams, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            // Extract task ID from parent
            let task_id = extract_task_id(&p.parent).unwrap_or_else(|| p.parent.clone());

            // Check if task exists
            if state.task_store.get_flexible(&task_id).await.is_none() {
                return (
                    StatusCode::NOT_FOUND,
                    Json(error(req.id, errors::TASK_NOT_FOUND, "task not found", None)),
                );
            }

            // Store the config (with URL validation)
            if let Err(e) = state
                .webhook_store
                .set(&task_id, &p.config_id, p.config.clone())
                .await
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(error(
                        req.id,
                        errors::INVALID_PARAMS,
                        &e.to_string(),
                        None,
                    )),
                );
            }

            (
                StatusCode::OK,
                Json(success(
                    req.id,
                    serde_json::json!({
                        "configId": p.config_id,
                        "config": p.config
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
    if !state.card.capabilities.push_notifications {
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

    let params: Result<PushNotificationConfigGetParams, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            // Parse name: "tasks/{task_id}/pushNotificationConfigs/{config_id}"
            let parts: Vec<&str> = p.name.split('/').collect();
            if parts.len() < 4 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(error(
                        req.id,
                        errors::INVALID_PARAMS,
                        "invalid resource name format",
                        None,
                    )),
                );
            }
            let task_id = parts[1];
            let config_id = parts[3];

            match state.webhook_store.get(task_id, config_id).await {
                Some(config) => (
                    StatusCode::OK,
                    Json(success(
                        req.id,
                        serde_json::json!({
                            "configId": config_id,
                            "config": config
                        }),
                    )),
                ),
                None => (
                    StatusCode::NOT_FOUND,
                    Json(error(
                        req.id,
                        errors::TASK_NOT_FOUND,
                        "push notification config not found",
                        None,
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

async fn handle_push_config_list(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    if !state.card.capabilities.push_notifications {
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

    let params: Result<PushNotificationConfigListParams, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            let task_id = extract_task_id(&p.parent).unwrap_or_else(|| p.parent.clone());
            let configs = state.webhook_store.list(&task_id).await;

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
    if !state.card.capabilities.push_notifications {
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

    let params: Result<PushNotificationConfigDeleteParams, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => {
            // Parse name: "tasks/{task_id}/pushNotificationConfigs/{config_id}"
            let parts: Vec<&str> = p.name.split('/').collect();
            if parts.len() < 4 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(error(
                        req.id,
                        errors::INVALID_PARAMS,
                        "invalid resource name format",
                        None,
                    )),
                );
            }
            let task_id = parts[1];
            let config_id = parts[3];

            if state.webhook_store.delete(task_id, config_id).await {
                (StatusCode::OK, Json(success(req.id, serde_json::json!({}))))
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(error(
                        req.id,
                        errors::TASK_NOT_FOUND,
                        "push notification config not found",
                        None,
                    )),
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

/// Convenience function to run a server with a handler
pub async fn run_server<H: crate::handler::MessageHandler + 'static>(
    bind_addr: &str,
    handler: H,
) -> anyhow::Result<()> {
    A2aServer::new(handler).bind(bind_addr)?.run().await
}

/// Convenience function to run the default echo server
pub async fn run_echo_server(bind_addr: &str) -> anyhow::Result<()> {
    A2aServer::echo().bind(bind_addr)?.run().await
}
