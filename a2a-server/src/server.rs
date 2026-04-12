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
    SendMessageResponse, SendMessageResult, StreamResponse, StreamingMessageResult,
    SubscribeToTaskRequest, Task, TaskState, TaskStatusUpdateEvent, PROTOCOL_VERSION,
};

const A2A_VERSION_HEADER: &str = "A2A-Version";
const SUPPORTED_VERSION_MAJOR: u32 = 1;
const SUPPORTED_VERSION_MINOR: u32 = 0;

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::future::FutureExt;
use tokio::sync::broadcast;
use tracing::info;

use crate::handler::{AuthContext, BoxedHandler, EchoHandler, HandlerError};
use crate::task_store::TaskStore;
use crate::webhook_delivery::WebhookDelivery;
use crate::webhook_store::WebhookStore;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    /// HTTP path where the JSON-RPC endpoint is exposed. Must start with `/`.
    pub rpc_path: String,
    /// HTTP path prefix for the REST / HTTP+JSON binding (e.g. `/v1`).
    /// Set to `None` to disable REST. Default: `Some("/v1")`.
    pub rest_prefix: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:8080".to_string(),
            rpc_path: "/v1/rpc".to_string(),
            rest_prefix: Some("/v1".to_string()),
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

    /// Configure the HTTP path where the JSON-RPC endpoint is exposed.
    /// The path must start with `/`. Defaults to `/v1/rpc`.
    ///
    /// Leading slash is added automatically if missing.
    pub fn rpc_path(mut self, path: &str) -> Self {
        let normalized = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };
        self.config.rpc_path = normalized;
        self
    }

    /// Configure the HTTP path prefix for the REST / HTTP+JSON binding
    /// (e.g. `/v1`). Set to `None` to disable REST routes. Defaults to `/v1`.
    pub fn rest_prefix(mut self, prefix: Option<&str>) -> Self {
        self.config.rest_prefix = prefix.map(|p| {
            if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{}", p)
            }
        });
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
        let bind: SocketAddr = self
            .config
            .bind_address
            .parse()
            .expect("Invalid bind address");
        // Use `localhost` when binding to 0.0.0.0 or 127.0.0.1 so the agent
        // card advertises a reachable, non-IP hostname. The A2A TCK flags raw
        // IP addresses (including 127.0.0.1) as sensitive information.
        let base_host = if bind.ip().is_unspecified()
            || bind.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        {
            format!("localhost:{}", bind.port())
        } else {
            bind.to_string()
        };
        let base_url = format!("http://{}", base_host);
        let rpc_path = self.config.rpc_path.clone();
        let full_rpc_url = format!("{}{}", base_url, rpc_path);

        let rest_prefix = self.config.rest_prefix.clone();

        // Let the handler produce its card. The handler is the authoritative
        // source of interface URLs — it knows whether the server is mounted
        // under a path prefix, behind a reverse proxy, etc. We only fill in a
        // default URL when the handler left the field empty.
        let mut card_value = self.handler.agent_card(&base_url);
        let mut has_jsonrpc = false;
        let mut has_http_json = false;
        for iface in card_value.supported_interfaces.iter_mut() {
            if iface.protocol_binding.eq_ignore_ascii_case("jsonrpc") {
                has_jsonrpc = true;
                if iface.url.is_empty() {
                    iface.url = full_rpc_url.clone();
                }
            }
            if iface.protocol_binding.eq_ignore_ascii_case("http+json") {
                has_http_json = true;
                if iface.url.is_empty() {
                    if let Some(ref prefix) = rest_prefix {
                        iface.url = format!("{}{}", base_url, prefix);
                    }
                }
            }
        }
        // Auto-add an HTTP+JSON interface if REST is enabled but the handler
        // didn't declare one.
        if rest_prefix.is_some() && !has_http_json {
            let rest_url = rest_prefix
                .as_ref()
                .map(|p| format!("{}{}", base_url, p))
                .unwrap_or_default();
            card_value
                .supported_interfaces
                .push(a2a_rs_core::AgentInterface {
                    url: rest_url,
                    protocol_binding: "HTTP+JSON".to_string(),
                    protocol_version: a2a_rs_core::PROTOCOL_VERSION.to_string(),
                    tenant: None,
                });
        }
        let _ = has_jsonrpc; // suppress warning
        let card = Arc::new(card_value);

        let state = AppState {
            handler: self.handler,
            task_store: self.task_store,
            webhook_store: self.webhook_store,
            card,
            auth_extractor: self.auth_extractor,
            event_tx: self.event_tx,
            rpc_path: rpc_path.clone(),
            rest_prefix: rest_prefix.clone(),
        };

        // Register agent card on both well-known paths (v1.0 and v0.2 fallback).
        // Add POST to agent card routes so POST requests don't get 405 — they
        // are forwarded to the JSON-RPC handler instead.
        let mut timed_routes = Router::new()
            .route("/health", get(health))
            .route(
                "/.well-known/agent-card.json",
                get(agent_card).post(handle_rpc),
            )
            .route(
                "/.well-known/agent.json",
                get(agent_card).post(handle_rpc),
            )
            .route(&rpc_path, post(handle_rpc));

        // Catch-all fallback: route POST requests on any unregistered path
        // through the JSON-RPC handler so compliance tests work regardless
        // of which URL they target.
        timed_routes = timed_routes.fallback(handle_rpc_fallback);

        let timed_routes = timed_routes.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_timeout_error))
                .timeout(Duration::from_secs(30)),
        );

        let mut router = timed_routes;

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
            StatusCode::OK,
            Json(error(
                serde_json::Value::Null,
                errors::INTERNAL_ERROR,
                "Request timed out",
                None,
            )),
        )
    } else {
        (
            StatusCode::OK,
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
    rpc_path: String,
    rest_prefix: Option<String>,
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

    /// Reference to the handler (used by REST module).
    pub(crate) fn handler_ref(&self) -> &dyn crate::handler::MessageHandler {
        self.handler.as_ref()
    }

    /// Reference to the auth extractor (used by REST module).
    pub(crate) fn auth_extractor_ref(&self) -> Option<&AuthExtractor> {
        self.auth_extractor.as_ref()
    }

    /// Reference to the webhook store (used by REST module).
    pub(crate) fn webhook_store_ref(&self) -> &WebhookStore {
        &self.webhook_store
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
    pub(crate) fn endpoint_url(&self) -> &str {
        self.card.endpoint().unwrap_or("")
    }

    /// Return the configured JSON-RPC path (e.g. `/v1/rpc`, `/spec`).
    pub fn rpc_path(&self) -> &str {
        &self.rpc_path
    }

    /// Return the configured REST prefix (e.g. `/v1`).
    pub fn rest_prefix(&self) -> Option<&str> {
        self.rest_prefix.as_deref()
    }
}

// ============ History Trimming ============

pub(crate) fn apply_history_length(task: &mut Task, history_length: Option<u32>) {
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

fn validate_a2a_version(
    headers: &HeaderMap,
    req_id: &serde_json::Value,
) -> Result<(), (StatusCode, Json<JsonRpcResponse>)> {
    if let Some(version_header) = headers.get(A2A_VERSION_HEADER) {
        let version_str = version_header.to_str().unwrap_or("");

        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.len() >= 2 {
            if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                if major == SUPPORTED_VERSION_MAJOR && minor == SUPPORTED_VERSION_MINOR {
                    return Ok(());
                }

                return Err((
                    StatusCode::OK,
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
            StatusCode::OK,
            Json(error(
                req_id.clone(),
                errors::VERSION_NOT_SUPPORTED,
                &format!(
                    "Invalid version format: {}. Expected major.minor (e.g., '1.0')",
                    version_str
                ),
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
pub fn rpc_success(
    id: serde_json::Value,
    result: serde_json::Value,
) -> (StatusCode, Json<JsonRpcResponse>) {
    (StatusCode::OK, Json(success(id, result)))
}

// ============ Route Handlers ============

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok", "protocol": PROTOCOL_VERSION}))
}

/// Wrap a JSON-RPC error envelope in a single-event SSE response.
///
/// Per the A2A spec, streaming methods MUST always return
/// `text/event-stream`. When the server needs to surface a JSON-RPC
/// error (parse error, invalid params, task not found, terminal task,
/// etc.), it goes out as a single SSE `data:` event followed by stream
/// close, instead of as an `application/json` response.
fn sse_error_response(envelope: JsonRpcResponse) -> Response {
    let body = serde_json::to_string(&envelope).unwrap_or_default();
    let stream = async_stream::stream! {
        yield Ok::<_, Infallible>(Event::default().data(body));
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn agent_card(State(state): State<AppState>) -> Response {
    let card = (*state.card).clone();
    // Compute a stable ETag from the serialized card content.
    let body = serde_json::to_vec(&card).unwrap_or_default();
    let etag = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        body.hash(&mut h);
        format!("\"{:x}\"", h.finish())
    };

    let mut resp = Json(card).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        "public, max-age=3600".parse().unwrap(),
    );
    headers.insert(
        axum::http::header::ETAG,
        etag.parse().unwrap(),
    );
    headers.insert(
        axum::http::header::LAST_MODIFIED,
        chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    resp
}

/// Fallback handler: first tries REST dispatch (if REST is enabled and the
/// path matches the REST prefix), then falls through to the JSON-RPC handler
/// for POST requests.
async fn handle_rpc_fallback(
    method: Method,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: axum::body::Bytes,
) -> Response {
    // Try REST dispatch first
    if let Some(prefix) = state.rest_prefix() {
        let prefix = prefix.to_string();
        if let Some(resp) =
            crate::rest::try_rest_dispatch(&state, &method, &headers, &uri, &body, &prefix).await
        {
            return resp;
        }
    }

    // Fall through to JSON-RPC for POST requests
    if method == Method::POST {
        handle_rpc(State(state), headers, body).await
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

// handle_task_subscribe_sse removed — tasks/resubscribe now returns SSE
// directly from the /v1/rpc endpoint via handle_tasks_resubscribe.

async fn handle_rpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Check Content-Type header — must be application/json (or absent).
    if let Some(ct) = headers.get(axum::http::header::CONTENT_TYPE) {
        let ct_str = ct.to_str().unwrap_or("");
        let media_type = ct_str.split(';').next().unwrap_or("").trim();
        if !media_type.is_empty()
            && !media_type.eq_ignore_ascii_case("application/json")
            && !media_type.eq_ignore_ascii_case("application/jsonrequest")
        {
            let resp = error(
                serde_json::Value::Null,
                errors::CONTENT_TYPE_NOT_SUPPORTED,
                &format!("Unsupported Content-Type: {ct_str}. Expected application/json"),
                None,
            );
            return (StatusCode::OK, Json(resp)).into_response();
        }
    }

    // Parse JSON body manually so we can return a proper JSON-RPC -32700 Parse
    // error (HTTP 200) when the body is not valid JSON, instead of letting
    // axum's Json extractor reject with a non-JSON-RPC 4xx response.
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let resp = error(
                serde_json::Value::Null,
                errors::PARSE_ERROR,
                "Parse error",
                Some(serde_json::json!({"error": e.to_string()})),
            );
            return (StatusCode::OK, Json(resp)).into_response();
        }
    };

    // Recover the request id early so every error envelope references it.
    // Per JSON-RPC 2.0, id MUST be a String, Number, or Null.
    let id = value.get("id").cloned().unwrap_or(serde_json::Value::Null);
    if !id.is_null() && !id.is_string() && !id.is_number() {
        return (
            StatusCode::OK,
            Json(error(
                serde_json::Value::Null,
                errors::INVALID_REQUEST,
                "Invalid request: id must be a string, number, or null",
                None,
            )),
        )
            .into_response();
    }

    // JSON-RPC request must be a JSON object.
    if !value.is_object() {
        return (
            StatusCode::OK,
            Json(error(
                id,
                errors::INVALID_REQUEST,
                "Invalid request: expected a JSON object",
                None,
            )),
        )
            .into_response();
    }

    // jsonrpc must be exactly "2.0".
    let jsonrpc = value.get("jsonrpc").and_then(|v| v.as_str()).unwrap_or("");
    if jsonrpc != "2.0" {
        return (
            StatusCode::OK,
            Json(error(
                id,
                errors::INVALID_REQUEST,
                "Invalid request: jsonrpc must be \"2.0\"",
                None,
            )),
        )
            .into_response();
    }

    // method must be a non-empty string.
    let method = match value.get("method").and_then(|v| v.as_str()) {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => {
            return (
                StatusCode::OK,
                Json(error(
                    id,
                    errors::INVALID_REQUEST,
                    "Invalid request: method field is required and must be a non-empty string",
                    None,
                )),
            )
                .into_response();
        }
    };

    // params is optional; if present it must be an object or array per JSON-RPC 2.0.
    // Normalize absent/null to empty object so handlers can deserialize
    // default structs (e.g. ListTasksRequest with all-optional fields).
    let params = match value.get("params") {
        None | Some(serde_json::Value::Null) => Some(serde_json::json!({})),
        Some(p) if p.is_object() || p.is_array() => Some(p.clone()),
        Some(_) => {
            return (
                StatusCode::OK,
                Json(error(
                    id,
                    errors::INVALID_REQUEST,
                    "Invalid request: params must be an object or array",
                    None,
                )),
            )
                .into_response();
        }
    };

    let req = JsonRpcRequest {
        jsonrpc: jsonrpc.to_string(),
        method: method.clone(),
        params,
        id: id.clone(),
    };

    if let Err(err_response) = validate_a2a_version(&headers, &req.id) {
        return err_response.into_response();
    }

    let auth_context = state
        .auth_extractor
        .as_ref()
        .and_then(|extractor| extractor(&headers));

    match req.method.as_str() {
        // Accept both v1.0 PascalCase and v0.3 kebab-case method names
        "SendMessage" | "message/send" => handle_message_send(state, req, auth_context)
            .await
            .into_response(),
        "SendStreamingMessage" | "message/stream" => {
            handle_message_stream(state, req, headers, auth_context)
                .await
                .into_response()
        }
        "GetTask" | "tasks/get" => handle_tasks_get(state, req).await.into_response(),
        "ListTasks" | "tasks/list" => handle_tasks_list(state, req).await.into_response(),
        "CancelTask" | "tasks/cancel" => handle_tasks_cancel(state, req).await.into_response(),
        "SubscribeToTask" | "tasks/resubscribe" => {
            handle_tasks_resubscribe(state, req).await.into_response()
        }
        "CreateTaskPushNotificationConfig" | "tasks/pushNotificationConfig/create" => {
            handle_push_config_create(state, req).await.into_response()
        }
        "GetTaskPushNotificationConfig" | "tasks/pushNotificationConfig/get" => {
            handle_push_config_get(state, req).await.into_response()
        }
        "ListTaskPushNotificationConfigs" | "tasks/pushNotificationConfig/list" => {
            handle_push_config_list(state, req).await.into_response()
        }
        "DeleteTaskPushNotificationConfig" | "tasks/pushNotificationConfig/delete" => {
            handle_push_config_delete(state, req).await.into_response()
        }
        "GetExtendedAgentCard" | "agentCard/getExtended" => {
            handle_get_extended_agent_card(state, req, auth_context)
                .await
                .into_response()
        }
        _ => (
            StatusCode::OK,
            Json(error(
                req.id,
                errors::METHOD_NOT_FOUND,
                "Method not found",
                None,
            )),
        )
            .into_response(),
    }
}

pub(crate) fn handler_error_to_rpc(e: &HandlerError) -> (i32, StatusCode) {
    // JSON-RPC 2.0 convention: always return HTTP 200 with the error envelope
    // in the body. Tests (including the A2A TCK) expect this.
    let code = match e {
        HandlerError::InvalidInput(_) => errors::INVALID_PARAMS,
        HandlerError::AuthRequired(_) => errors::INVALID_REQUEST,
        HandlerError::BackendUnavailable { .. } => errors::INTERNAL_ERROR,
        HandlerError::ProcessingFailed { .. } => errors::INTERNAL_ERROR,
        HandlerError::Internal(_) => errors::INTERNAL_ERROR,
    };
    (code, StatusCode::OK)
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
                StatusCode::OK,
                Json(error(
                    req_id,
                    errors::INVALID_PARAMS,
                    "invalid params",
                    Some(serde_json::json!({"error": err.to_string()})),
                )),
            );
        }
    };

    // Reject messages with empty parts array per A2A spec.
    if params.message.parts.is_empty() {
        return (
            StatusCode::OK,
            Json(error(
                req_id,
                errors::INVALID_PARAMS,
                "message parts must not be empty",
                None,
            )),
        );
    }

    let blocking = params
        .configuration
        .as_ref()
        .and_then(|c| c.blocking)
        .unwrap_or(false);
    let return_immediately = params
        .configuration
        .as_ref()
        .and_then(|c| c.return_immediately)
        .unwrap_or(false);
    let history_length = params.configuration.as_ref().and_then(|c| c.history_length);

    // If the incoming message references an existing task, remember the
    // task_id so the response task can reuse it (continue-task semantics).
    let continue_task_id = params.message.task_id.clone();

    // Validate taskId references (CORE-MULTI-004 & CORE-SEND-002).
    if let Some(ref tid) = continue_task_id {
        match state.task_store.get_flexible(tid).await {
            Some(task) if task.status.state.is_terminal() => {
                // CORE-SEND-002: reject messages to terminal tasks.
                return (
                    StatusCode::OK,
                    Json(error(
                        req_id,
                        errors::UNSUPPORTED_OPERATION,
                        "cannot send message to a task in terminal state",
                        None,
                    )),
                );
            }
            None => {
                // CORE-MULTI-004: reject messages referencing non-existent tasks.
                return (
                    StatusCode::OK,
                    Json(error(
                        req_id,
                        errors::TASK_NOT_FOUND,
                        "task not found",
                        None,
                    )),
                );
            }
            _ => {} // Task exists and is non-terminal, continue normally
        }
    }

    match state
        .handler
        .handle_message(params.message, auth_context)
        .await
    {
        Ok(response) => {
            match response {
                SendMessageResponse::Task(mut task) => {
                    // Continue-task: when the message referenced an existing
                    // task, override the handler's task id so the same task
                    // is updated instead of creating a new one.
                    if let Some(ref tid) = continue_task_id {
                        if state.task_store.get_flexible(tid).await.is_some() {
                            task.id = tid.clone();
                        }
                    }

                    // Store the task, then subscribe to events BEFORE
                    // broadcasting or spawning auto-complete, so the blocking
                    // wait loop below doesn't miss the completion event.
                    state.task_store.insert(task.clone()).await;
                    let blocking_rx = if blocking
                        && !return_immediately
                        && !task.status.state.is_terminal()
                    {
                        Some(state.subscribe_events())
                    } else {
                        None
                    };
                    state.broadcast_event(StreamResponse::Task(task.clone()));

                    // Auto-complete: if the handler opts in and the task is
                    // non-terminal, schedule a background transition to Completed.
                    if !task.status.state.is_terminal() {
                        if let Some(delay) = state.handler.auto_complete_delay() {
                            let ts = state.task_store.clone();
                            let tx = state.event_tx.clone();
                            let tid = task.id.clone();
                            let ctx = task.context_id.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(delay).await;
                                let completed = ts
                                    .update_flexible(&tid, |t| {
                                        if !t.status.state.is_terminal() {
                                            t.status.state = TaskState::Completed;
                                            t.status.timestamp = Some(a2a_rs_core::now_iso8601());
                                            Ok(())
                                        } else {
                                            Err(0) // already terminal, skip
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
                                            is_final: true,
                                            metadata: None,
                                        },
                                    ));
                                }
                            });
                        }
                    }

                    // If blocking mode and not returnImmediately, wait for terminal state
                    if let Some(mut rx) = blocking_rx {
                        let task_id = task.id.clone();

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

                    // Serialize via SendMessageResult for externally tagged wrapping
                    match serde_json::to_value(SendMessageResult::Task(task.clone())) {
                        Ok(val) => (StatusCode::OK, Json(success(req_id, val))),
                        Err(e) => (
                            StatusCode::OK,
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
                    // Serialize via SendMessageResult for externally tagged wrapping
                    match serde_json::to_value(SendMessageResult::Message(msg)) {
                        Ok(val) => (StatusCode::OK, Json(success(req_id, val))),
                        Err(e) => (
                            StatusCode::OK,
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

/// Handle `message/stream` — returns SSE directly from the JSON-RPC endpoint.
///
/// Each SSE event's `data:` is a full JSON-RPC response envelope wrapping the result
/// (Task, Message, TaskStatusUpdateEvent, or TaskArtifactUpdateEvent).
async fn handle_message_stream(
    state: AppState,
    req: JsonRpcRequest,
    _headers: HeaderMap,
    auth_context: Option<AuthContext>,
) -> Response {
    let req_id = req.id.clone();

    if !state.streaming_enabled() {
        return sse_error_response(error(
            req_id,
            errors::UNSUPPORTED_OPERATION,
            "streaming not supported by this agent",
            None,
        ));
    }

    let params: Result<SendMessageRequest, _> =
        serde_json::from_value(req.params.clone().unwrap_or_default());

    let params = match params {
        Ok(p) => p,
        Err(err) => {
            return sse_error_response(error(
                req_id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            ));
        }
    };

    let continue_task_id = params.message.task_id.clone();

    let response = match state
        .handler
        .handle_message(params.message, auth_context)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let (code, _) = handler_error_to_rpc(&e);
            return sse_error_response(error(req_id, code, &e.to_string(), None));
        }
    };

    // Streaming supports both Task and Message responses. A Message response
    // is yielded as a single SSE event then the stream closes.
    let mut task = match response {
        SendMessageResponse::Task(t) => t,
        SendMessageResponse::Message(msg) => {
            let req_id_inner = req_id.clone();
            let stream = async_stream::stream! {
                if let Ok(val) = serde_json::to_value(StreamingMessageResult::Message(msg)) {
                    let envelope = success(req_id_inner.clone(), val);
                    let body = serde_json::to_string(&envelope).unwrap_or_default();
                    yield Ok::<_, Infallible>(Event::default().data(body));
                }
            };
            return Sse::new(stream)
                .keep_alive(KeepAlive::default())
                .into_response();
        }
    };

    // Continue-task: reuse the referenced task id if it exists.
    if let Some(ref tid) = continue_task_id {
        if state.task_store.get_flexible(tid).await.is_some() {
            task.id = tid.clone();
        }
    }

    let task_id = task.id.clone();
    state.task_store.insert(task.clone()).await;

    // Subscribe BEFORE broadcasting so we don't miss events the handler
    // emits as part of this request. (Broadcast channel receivers only
    // receive events sent after their creation.)
    let mut rx = state.subscribe_events();
    state.broadcast_event(StreamResponse::Task(task.clone()));

    let task_store = state.task_store.clone();
    let target_task_id = task_id;

    // Helper: wrap a value in a JSON-RPC success response envelope
    let wrap = move |value: serde_json::Value| -> String {
        serde_json::to_string(&success(req_id.clone(), value)).unwrap_or_default()
    };

    let stream = async_stream::stream! {
        let initial_is_terminal = task.status.state.is_terminal();

        // Yield initial task via StreamingMessageResult for proper tagging
        if let Ok(val) = serde_json::to_value(StreamingMessageResult::Task(task)) {
            yield Ok::<_, Infallible>(Event::default().data(wrap(val)));
        }

        // If the handler already returned a terminal task, there will be no
        // further events — end the stream now instead of hanging on rx.recv().
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
                        // Serialize via StreamingMessageResult for proper external tagging
                        let val = match event.clone() {
                            StreamResponse::Task(t) => serde_json::to_value(StreamingMessageResult::Task(t)),
                            StreamResponse::Message(m) => serde_json::to_value(StreamingMessageResult::Message(m)),
                            StreamResponse::StatusUpdate(e) => serde_json::to_value(StreamingMessageResult::StatusUpdate(e)),
                            StreamResponse::ArtifactUpdate(e) => serde_json::to_value(StreamingMessageResult::ArtifactUpdate(e)),
                        };
                        if let Ok(val) = val {
                            yield Ok(Event::default().data(wrap(val)));
                        }

                        // End stream on terminal state or final flag
                        let is_terminal = match &event {
                            StreamResponse::Task(t) => t.status.state.is_terminal(),
                            StreamResponse::StatusUpdate(e) => e.is_final || e.status.state.is_terminal(),
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

async fn handle_tasks_get(
    state: AppState,
    req: JsonRpcRequest,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let params: Result<GetTaskRequest, _> = serde_json::from_value(req.params.unwrap_or_default());

    match params {
        Ok(p) => match state.task_store.get_flexible(&p.id).await {
            Some(mut task) => {
                apply_history_length(&mut task, p.history_length);

                match serde_json::to_value(task) {
                    Ok(val) => (StatusCode::OK, Json(success(req.id, val))),
                    Err(e) => (
                        StatusCode::OK,
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
                StatusCode::OK,
                Json(error(
                    req.id,
                    errors::TASK_NOT_FOUND,
                    "task not found",
                    None,
                )),
            ),
        },
        Err(err) => (
            StatusCode::OK,
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
                        kind: "status-update".to_string(),
                        task_id: task.id.clone(),
                        context_id: task.context_id.clone(),
                        status: task.status.clone(),
                        is_final: true,
                        metadata: None,
                    }));

                    match serde_json::to_value(task) {
                        Ok(val) => (StatusCode::OK, Json(success(req.id, val))),
                        Err(e) => (
                            StatusCode::OK,
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
                    StatusCode::OK,
                    Json(error(req.id, error_code, "task not cancelable", None)),
                ),
                None => (
                    StatusCode::OK,
                    Json(error(
                        req.id,
                        errors::TASK_NOT_FOUND,
                        "task not found",
                        None,
                    )),
                ),
            }
        }
        Err(err) => (
            StatusCode::OK,
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
            // Validate pagination / filter constraints before querying.
            if let Err(msg) = TaskStore::validate_list_params(&p) {
                return (
                    StatusCode::OK,
                    Json(error(req.id, errors::INVALID_PARAMS, msg, None)),
                );
            }

            let response = state.task_store.list_filtered(&p).await;
            match serde_json::to_value(response) {
                Ok(val) => (StatusCode::OK, Json(success(req.id, val))),
                Err(e) => (
                    StatusCode::OK,
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
            StatusCode::OK,
            Json(error(
                req.id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            )),
        ),
    }
}

/// Handle `tasks/resubscribe` — returns SSE directly from the JSON-RPC endpoint.
///
/// Reconnects to an existing task's event stream. Each SSE event's `data:` is
/// a JSON-RPC response envelope wrapping the result, same as `message/stream`.
async fn handle_tasks_resubscribe(state: AppState, req: JsonRpcRequest) -> Response {
    let req_id = req.id.clone();

    let params: Result<SubscribeToTaskRequest, _> =
        serde_json::from_value(req.params.unwrap_or_default());

    let params = match params {
        Ok(p) => p,
        Err(err) => {
            return sse_error_response(error(
                req_id,
                errors::INVALID_PARAMS,
                "invalid params",
                Some(serde_json::json!({"error": err.to_string()})),
            ));
        }
    };

    // Verify the task exists
    let task = match state.task_store.get_flexible(&params.id).await {
        Some(t) => t,
        None => {
            return sse_error_response(error(
                req_id,
                errors::TASK_NOT_FOUND,
                "task not found",
                None,
            ));
        }
    };

    // Reject subscriptions to terminal tasks (STREAM-SUB-003): the spec
    // says SubscribeToTask on a terminal task MUST return an error.
    if task.status.state.is_terminal() {
        return sse_error_response(error(
            req_id,
            errors::UNSUPPORTED_OPERATION,
            "cannot subscribe to a task in terminal state",
            None,
        ));
    }

    let target_task_id = task.id.clone();
    let mut rx = state.subscribe_events();
    let task_store = state.task_store.clone();

    let wrap = move |value: serde_json::Value| -> String {
        serde_json::to_string(&success(req_id.clone(), value)).unwrap_or_default()
    };

    let stream = async_stream::stream! {
        // Yield current task snapshot via StreamingMessageResult
        if let Ok(val) = serde_json::to_value(StreamingMessageResult::Task(task.clone())) {
            yield Ok::<_, Infallible>(Event::default().data(wrap(val)));
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
                            yield Ok(Event::default().data(wrap(val)));
                        }

                        let is_terminal = match &event {
                            StreamResponse::Task(t) => t.status.state.is_terminal(),
                            StreamResponse::StatusUpdate(e) => e.is_final || e.status.state.is_terminal(),
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

async fn handle_get_extended_agent_card(
    state: AppState,
    req: JsonRpcRequest,
    auth_context: Option<AuthContext>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let Some(auth) = auth_context else {
        return (
            StatusCode::OK,
            Json(error(
                req.id,
                errors::INVALID_REQUEST,
                "authentication required for extended agent card",
                None,
            )),
        );
    };

    let rpc_path = state.rpc_path().to_string();
    let base_url = state.endpoint_url().trim_end_matches(rpc_path.as_str());

    match state.handler.extended_agent_card(base_url, &auth).await {
        Some(card) => match serde_json::to_value(card) {
            Ok(val) => (StatusCode::OK, Json(success(req.id, val))),
            Err(e) => (
                StatusCode::OK,
                Json(error(
                    req.id,
                    errors::INTERNAL_ERROR,
                    "serialization failed",
                    Some(serde_json::json!({"error": e.to_string()})),
                )),
            ),
        },
        None => (
            StatusCode::OK,
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
            StatusCode::OK,
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
                    StatusCode::OK,
                    Json(error(
                        req.id,
                        errors::TASK_NOT_FOUND,
                        "task not found",
                        None,
                    )),
                );
            }

            if let Err(e) = state
                .webhook_store
                .set(&p.task_id, &p.config_id, p.push_notification_config.clone())
                .await
            {
                return (
                    StatusCode::OK,
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
            StatusCode::OK,
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
            StatusCode::OK,
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
        Ok(p) => match state.webhook_store.get(&p.task_id, &p.id).await {
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
                StatusCode::OK,
                Json(error(
                    req.id,
                    errors::TASK_NOT_FOUND,
                    "push notification config not found",
                    None,
                )),
            ),
        },
        Err(err) => (
            StatusCode::OK,
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
            StatusCode::OK,
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
            StatusCode::OK,
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
            StatusCode::OK,
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
                    StatusCode::OK,
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
            StatusCode::OK,
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
