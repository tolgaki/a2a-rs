//! A2A Client implementation
//!
//! Provides a reusable client for A2A RC 1.0 agent communication.

use std::sync::Arc;
use std::time::{Duration, Instant};

use std::pin::Pin;

use a2a_rs_core::{
    compat, AgentCard, CancelTaskRequest, CreateTaskPushNotificationConfigRequest,
    DeleteTaskPushNotificationConfigRequest, GetTaskPushNotificationConfigRequest,
    GetTaskRequest, JsonRpcRequest, JsonRpcResponse, ListTaskPushNotificationConfigRequest,
    ListTaskPushNotificationConfigResponse, ListTasksRequest, Message, PushNotificationConfig,
    SendMessageConfiguration, SendMessageRequest, SendMessageResult, StreamingMessageResult,
    SubscribeToTaskRequest, Task, TaskListResponse, TaskPushNotificationConfig,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_core::Stream;
use rand::Rng;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn};

/// Duration to cache the agent card (5 minutes)
const AGENT_CARD_CACHE_TTL: Duration = Duration::from_secs(300);

/// Protocol version for A2A wire format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtocolVersion {
    /// A2A v1.0 — PascalCase methods, SCREAMING_SNAKE enums, externally tagged results
    #[default]
    V1_0,
    /// A2A v0.3 — kebab-case methods, lowercase enums, kind discriminators
    V0_3,
}

/// Transport binding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    /// JSON-RPC over HTTP POST
    #[default]
    JsonRpc,
    /// HTTP+JSON REST binding
    Rest,
}

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Base URL of the A2A server
    pub server_url: String,
    /// Maximum number of poll attempts for task completion
    pub max_polls: u32,
    /// Milliseconds between poll attempts
    pub poll_interval_ms: u64,
    /// OAuth configuration (if using OAuth authentication)
    pub oauth: Option<OAuthConfig>,
    /// Direct JSON-RPC endpoint URL — if set, skip agent card discovery
    pub endpoint_url: Option<String>,
    /// Pre-configured reqwest client (for custom headers, timeouts, etc.)
    ///
    /// If `None`, a default `reqwest::Client` is created.
    pub http_client: Option<Client>,
    /// Protocol version (default: V1_0)
    pub protocol_version: ProtocolVersion,
    /// Transport binding (default: JsonRpc)
    pub transport: Transport,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8080".to_string(),
            max_polls: 30,
            poll_interval_ms: 2000,
            oauth: None,
            endpoint_url: None,
            http_client: None,
            protocol_version: ProtocolVersion::V1_0,
            transport: Transport::JsonRpc,
        }
    }
}

/// OAuth configuration for client authentication
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Client ID for OAuth
    pub client_id: String,
    /// Redirect URI for OAuth callback
    pub redirect_uri: String,
    /// OAuth scopes to request
    pub scopes: Vec<String>,
    /// Pre-existing session token (skip OAuth flow if provided)
    pub session_token: Option<String>,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            client_id: "a2a-client".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scopes: vec![
                "User.Read".to_string(),
                "Sites.Read.All".to_string(),
                "Mail.Read".to_string(),
                "offline_access".to_string(),
            ],
            session_token: None,
        }
    }
}

/// Cached agent card with expiration
struct CachedCard {
    card: AgentCard,
    fetched_at: Instant,
}

impl CachedCard {
    fn is_valid(&self) -> bool {
        self.fetched_at.elapsed() < AGENT_CARD_CACHE_TTL
    }
}

/// A2A Client for communicating with A2A-compliant agent servers
#[derive(Clone)]
pub struct A2aClient {
    config: ClientConfig,
    http: Client,
    base_url: Url,
    /// Cached agent card to avoid repeated fetches
    card_cache: Arc<RwLock<Option<CachedCard>>>,
    /// Cached RPC endpoint URL for fast lookups (derived from agent card)
    endpoint_cache: Arc<RwLock<Option<String>>>,
}

impl std::fmt::Debug for A2aClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2aClient")
            .field("config", &self.config)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize)]
struct OAuthAuthorizeRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(Debug, Deserialize)]
struct OAuthAuthorizeResponse {
    authorization_url: String,
    #[allow(dead_code)]
    state: String,
}

impl A2aClient {
    /// Create a new A2A client with the given configuration
    pub fn new(config: ClientConfig) -> Result<Self> {
        let base_url = Url::parse(&config.server_url)
            .with_context(|| format!("Invalid server URL: {}", config.server_url))?;
        let http = config.http_client.clone().unwrap_or_default();

        Ok(Self {
            config,
            http,
            base_url,
            card_cache: Arc::new(RwLock::new(None)),
            endpoint_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a client with default configuration for a given server URL
    pub fn with_server(server_url: &str) -> Result<Self> {
        Self::new(ClientConfig {
            server_url: server_url.to_string(),
            ..Default::default()
        })
    }

    /// Get the server base URL
    pub fn server_url(&self) -> &str {
        &self.config.server_url
    }

    /// Fetch the agent card, using cache if available and valid
    pub async fn fetch_agent_card(&self) -> Result<AgentCard> {
        // Check cache first
        {
            let cache = self.card_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.is_valid() {
                    return Ok(cached.card.clone());
                }
            }
        }

        // Fetch fresh card
        let url = self.base_url.join("/.well-known/agent-card.json")?;
        let card: AgentCard = self
            .http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        // Update cache
        {
            let mut cache = self.card_cache.write().await;
            *cache = Some(CachedCard {
                card: card.clone(),
                fetched_at: Instant::now(),
            });
        }

        Ok(card)
    }

    /// Invalidate the cached agent card and endpoint
    pub async fn invalidate_card_cache(&self) {
        let mut cache = self.card_cache.write().await;
        *cache = None;
        let mut endpoint = self.endpoint_cache.write().await;
        *endpoint = None;
    }

    /// Get the cached RPC endpoint URL, fetching from agent card if needed.
    ///
    /// If `endpoint_url` is set in config, returns it directly (skips agent card discovery).
    async fn get_cached_endpoint(&self) -> Result<String> {
        // Direct endpoint overrides everything
        if let Some(endpoint) = &self.config.endpoint_url {
            return Ok(endpoint.clone());
        }

        // Check endpoint cache first
        {
            let cache = self.endpoint_cache.read().await;
            if let Some(endpoint) = cache.as_ref() {
                return Ok(endpoint.clone());
            }
        }

        // Fetch agent card and cache the endpoint
        let card = self.fetch_agent_card().await?;
        let endpoint = card
            .endpoint()
            .ok_or_else(|| anyhow!("Agent card has no JSONRPC endpoint"))?
            .to_string();

        {
            let mut cache = self.endpoint_cache.write().await;
            *cache = Some(endpoint.clone());
        }

        Ok(endpoint)
    }

    /// Get the JSON-RPC endpoint URL from the agent card
    #[inline]
    pub fn get_rpc_url(card: &AgentCard) -> Option<&str> {
        card.endpoint()
    }

    /// Resolve the wire method name based on protocol version
    fn wire_method<'a>(&self, method: &'a str) -> &'a str {
        if self.config.protocol_version == ProtocolVersion::V0_3 {
            return method;
        }
        match method {
            "message/send" => "SendMessage",
            "message/stream" => "SendStreamingMessage",
            "tasks/get" => "GetTask",
            "tasks/cancel" => "CancelTask",
            "tasks/list" => "ListTasks",
            "tasks/resubscribe" => "SubscribeToTask",
            "tasks/pushNotificationConfig/create" => "CreateTaskPushNotificationConfig",
            "tasks/pushNotificationConfig/get" => "GetTaskPushNotificationConfig",
            "tasks/pushNotificationConfig/list" => "ListTaskPushNotificationConfigs",
            "tasks/pushNotificationConfig/delete" => "DeleteTaskPushNotificationConfig",
            "agentCard/getExtended" => "GetExtendedAgentCard",
            _ => method,
        }
    }

    /// Send a JSON-RPC request and parse the response
    async fn json_rpc_call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
        session_token: Option<&str>,
    ) -> Result<R> {
        let rpc_url = self.get_cached_endpoint().await?;

        let mut params_val = serde_json::to_value(params)?;

        // v0.3: transform params to lowercase enums, add kind to parts
        if self.config.protocol_version == ProtocolVersion::V0_3 {
            compat::request_v10_to_v03(&mut params_val);
        }

        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: self.wire_method(method).into(),
            params: Some(params_val),
            id: serde_json::json!(1),
        };

        let mut req_builder = self.http.post(rpc_url).json(&request);
        if let Some(token) = session_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }
        if self.config.protocol_version == ProtocolVersion::V1_0 {
            req_builder = req_builder.header("A2A-Version", "1.0");
        }

        let mut resp: JsonRpcResponse =
            req_builder.send().await?.error_for_status()?.json().await?;

        if let Some(err) = resp.error.take() {
            anyhow::bail!("Server error {}: {}", err.code, err.message);
        }

        let result = resp
            .result
            .ok_or_else(|| anyhow!("Server returned no result"))?;

        // v0.3: transform response from lowercase enums back to SCREAMING_SNAKE,
        // and wrap kind-discriminated result into externally tagged format
        if self.config.protocol_version == ProtocolVersion::V0_3 {
            let wrapped = compat::wrap_v03_result_as_v10(result.clone());
            let mut converted = wrapped;
            compat::response_v03_to_v10(&mut converted);
            Ok(serde_json::from_value(converted)?)
        } else {
            Ok(serde_json::from_value(result)?)
        }
    }

    /// Make a REST API call (HTTP+JSON binding)
    async fn rest_call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<P>,
        session_token: Option<&str>,
    ) -> Result<R> {
        let base = self.get_cached_endpoint().await?;
        let url = format!("{}{}", base.trim_end_matches('/'), path);

        let mut req_builder = self.http.request(method, &url);
        req_builder = req_builder.header("A2A-Version", "1.0");
        if let Some(token) = session_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(body) = body {
            req_builder = req_builder.json(&body);
        }

        let resp = req_builder.send().await?.error_for_status()?;
        let result: R = resp.json().await?;
        Ok(result)
    }

    /// Make a REST SSE streaming call
    async fn rest_sse_call<P: Serialize>(
        &self,
        path: &str,
        body: Option<P>,
        session_token: Option<&str>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamingMessageResult>> + Send>>> {
        let base = self.get_cached_endpoint().await?;
        let url = format!("{}{}", base.trim_end_matches('/'), path);

        let mut req_builder = self.http.post(&url);
        req_builder = req_builder.header("A2A-Version", "1.0");
        if let Some(token) = session_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(body) = body {
            req_builder = req_builder.json(&body);
        }

        let resp = req_builder.send().await?.error_for_status()?;
        let stream = sse_stream_raw(resp);
        Ok(Box::pin(stream))
    }

    /// Send a message to the agent and receive a response (Task or Message)
    pub async fn send_message(
        &self,
        message: Message,
        session_token: Option<&str>,
        configuration: Option<SendMessageConfiguration>,
    ) -> Result<SendMessageResult> {
        let params = SendMessageRequest {
            tenant: None,
            message,
            configuration,
            metadata: None,
        };
        if self.config.transport == Transport::Rest {
            return self
                .rest_call(reqwest::Method::POST, "/message:send", Some(params), session_token)
                .await;
        }
        self.json_rpc_call("message/send", params, session_token)
            .await
    }

    /// Send a streaming message and receive a stream of events (SSE).
    ///
    /// Returns a `Stream` of `StreamingMessageResult` items. Each item is a
    /// Task, Message, TaskStatusUpdateEvent, or TaskArtifactUpdateEvent
    /// extracted from the JSON-RPC response envelopes in the SSE stream.
    pub async fn send_message_streaming(
        &self,
        message: Message,
        session_token: Option<&str>,
        configuration: Option<SendMessageConfiguration>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamingMessageResult>> + Send>>> {
        let params = SendMessageRequest {
            tenant: None,
            message,
            configuration,
            metadata: None,
        };

        if self.config.transport == Transport::Rest {
            return self
                .rest_sse_call("/message:stream", Some(params), session_token)
                .await;
        }

        let rpc_url = self.get_cached_endpoint().await?;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: self.wire_method("message/stream").into(),
            params: Some(serde_json::to_value(&params)?),
            id: serde_json::json!(1),
        };

        let mut req_builder = self.http.post(&rpc_url).json(&request);
        if let Some(token) = session_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }
        if self.config.protocol_version == ProtocolVersion::V1_0 {
            req_builder = req_builder.header("A2A-Version", "1.0");
        }

        let resp = req_builder.send().await?.error_for_status()?;

        // Check that we got SSE back
        let is_sse = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("text/event-stream"));

        if !is_sse {
            // Got a JSON error response instead of SSE
            let body: JsonRpcResponse = resp.json().await?;
            if let Some(err) = body.error {
                anyhow::bail!("Server error {}: {}", err.code, err.message);
            }
            anyhow::bail!("Expected SSE stream from server");
        }

        let stream = check_sse_error_stream(sse_stream(resp, self.config.protocol_version)).await?;
        Ok(stream)
    }

    /// Poll a task by ID
    pub async fn poll_task(&self, task_id: &str, session_token: Option<&str>) -> Result<Task> {
        let params = GetTaskRequest {
            id: task_id.to_string(),
            history_length: None,
            tenant: None,
        };
        self.json_rpc_call("tasks/get", params, session_token).await
    }

    /// Poll a task until it reaches a terminal state or max polls exceeded
    pub async fn poll_until_complete(
        &self,
        task_id: &str,
        session_token: Option<&str>,
    ) -> Result<Task> {
        let mut task = self.poll_task(task_id, session_token).await?;

        for i in 0..self.config.max_polls {
            if task.status.state.is_terminal() {
                return Ok(task);
            }

            sleep(Duration::from_millis(self.config.poll_interval_ms)).await;

            match self.poll_task(task_id, session_token).await {
                Ok(updated_task) => {
                    info!(
                        "Poll {}/{}: state={:?}",
                        i + 1,
                        self.config.max_polls,
                        updated_task.status.state
                    );
                    task = updated_task;
                }
                Err(e) => {
                    warn!("Poll {}/{} failed: {}", i + 1, self.config.max_polls, e);
                    // Continue polling, the task might still complete
                }
            }
        }

        Ok(task)
    }

    /// Poll a task by ID with a specific history length
    pub async fn get_task(
        &self,
        task_id: &str,
        history_length: Option<u32>,
        session_token: Option<&str>,
    ) -> Result<Task> {
        if self.config.transport == Transport::Rest {
            let mut path = format!("/tasks/{}", urlencoding::encode(task_id));
            if let Some(hl) = history_length {
                path = format!("{}?historyLength={}", path, hl);
            }
            return self
                .rest_call::<(), Task>(reqwest::Method::GET, &path, None, session_token)
                .await;
        }
        let params = GetTaskRequest {
            id: task_id.to_string(),
            history_length,
            tenant: None,
        };
        self.json_rpc_call("tasks/get", params, session_token).await
    }

    /// Cancel a task by ID
    pub async fn cancel_task(&self, task_id: &str, session_token: Option<&str>) -> Result<Task> {
        if self.config.transport == Transport::Rest {
            let path = format!("/tasks/{}:cancel", urlencoding::encode(task_id));
            return self
                .rest_call::<(), Task>(reqwest::Method::DELETE, &path, None, session_token)
                .await;
        }
        let params = CancelTaskRequest {
            id: task_id.to_string(),
            tenant: None,
        };
        self.json_rpc_call("tasks/cancel", params, session_token)
            .await
    }

    /// List tasks with optional filters
    pub async fn list_tasks(
        &self,
        request: ListTasksRequest,
        session_token: Option<&str>,
    ) -> Result<TaskListResponse> {
        if self.config.transport == Transport::Rest {
            return self
                .rest_call(reqwest::Method::GET, "/tasks", Some(request), session_token)
                .await;
        }
        self.json_rpc_call("tasks/list", request, session_token)
            .await
    }

    /// Subscribe to task updates via SSE streaming
    pub async fn subscribe_to_task(
        &self,
        task_id: &str,
        session_token: Option<&str>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamingMessageResult>> + Send>>> {
        if self.config.transport == Transport::Rest {
            let path = format!("/tasks/{}/subscribe", urlencoding::encode(task_id));
            return self
                .rest_sse_call::<()>(&path, None, session_token)
                .await;
        }

        let rpc_url = self.get_cached_endpoint().await?;

        let params = SubscribeToTaskRequest {
            id: task_id.to_string(),
            tenant: None,
        };

        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: self.wire_method("tasks/resubscribe").into(),
            params: Some(serde_json::to_value(&params)?),
            id: serde_json::json!(1),
        };

        let mut req_builder = self.http.post(&rpc_url).json(&request);
        if let Some(token) = session_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }
        if self.config.protocol_version == ProtocolVersion::V1_0 {
            req_builder = req_builder.header("A2A-Version", "1.0");
        }

        let resp = req_builder.send().await?.error_for_status()?;

        // Check that we got SSE back
        let is_sse = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("text/event-stream"));

        if !is_sse {
            let body: JsonRpcResponse = resp.json().await?;
            if let Some(err) = body.error {
                anyhow::bail!("Server error {}: {}", err.code, err.message);
            }
            anyhow::bail!("Expected SSE stream from server");
        }

        // Check if the first SSE event is an error (some servers return 200 + SSE
        // with an error event for non-existent tasks)
        let stream = check_sse_error_stream(sse_stream(resp, self.config.protocol_version)).await?;
        Ok(stream)
    }

    /// Create a push notification configuration for a task
    pub async fn create_push_notification_config(
        &self,
        task_id: &str,
        config_id: &str,
        config: PushNotificationConfig,
        session_token: Option<&str>,
    ) -> Result<TaskPushNotificationConfig> {
        let params = CreateTaskPushNotificationConfigRequest {
            task_id: task_id.to_string(),
            config_id: config_id.to_string(),
            push_notification_config: config,
            tenant: None,
        };
        self.json_rpc_call("tasks/pushNotificationConfig/create", params, session_token)
            .await
    }

    /// Get a push notification configuration
    pub async fn get_push_notification_config(
        &self,
        task_id: &str,
        config_id: &str,
        session_token: Option<&str>,
    ) -> Result<TaskPushNotificationConfig> {
        let params = GetTaskPushNotificationConfigRequest {
            id: config_id.to_string(),
            task_id: task_id.to_string(),
            tenant: None,
        };
        self.json_rpc_call("tasks/pushNotificationConfig/get", params, session_token)
            .await
    }

    /// List push notification configurations for a task
    pub async fn list_push_notification_configs(
        &self,
        task_id: &str,
        session_token: Option<&str>,
    ) -> Result<ListTaskPushNotificationConfigResponse> {
        let params = ListTaskPushNotificationConfigRequest {
            task_id: task_id.to_string(),
            page_size: None,
            page_token: None,
            tenant: None,
        };
        self.json_rpc_call("tasks/pushNotificationConfig/list", params, session_token)
            .await
    }

    /// Delete a push notification configuration
    pub async fn delete_push_notification_config(
        &self,
        task_id: &str,
        config_id: &str,
        session_token: Option<&str>,
    ) -> Result<()> {
        let params = DeleteTaskPushNotificationConfigRequest {
            id: config_id.to_string(),
            task_id: task_id.to_string(),
            tenant: None,
        };
        // Delete may return null result; use direct call instead of json_rpc_call
        let rpc_url = self.get_cached_endpoint().await?;
        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: self.wire_method("tasks/pushNotificationConfig/delete").into(),
            params: Some(serde_json::to_value(params)?),
            id: serde_json::json!(1),
        };
        let mut req_builder = self.http.post(rpc_url).json(&request);
        if let Some(token) = session_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }
        if self.config.protocol_version == ProtocolVersion::V1_0 {
            req_builder = req_builder.header("A2A-Version", "1.0");
        }
        let mut resp: JsonRpcResponse =
            req_builder.send().await?.error_for_status()?.json().await?;
        if let Some(err) = resp.error.take() {
            anyhow::bail!("Server error {}: {}", err.code, err.message);
        }
        Ok(())
    }

    /// Perform interactive OAuth flow (prompts user to visit URL and paste callback)
    pub async fn perform_oauth_interactive(&self) -> Result<String> {
        let oauth_config = self
            .config
            .oauth
            .as_ref()
            .ok_or_else(|| anyhow!("OAuth not configured"))?;

        // If we already have a session token, return it
        if let Some(token) = &oauth_config.session_token {
            return Ok(token.clone());
        }

        // Generate PKCE code verifier and challenge
        let code_verifier = generate_code_verifier();
        let code_challenge = generate_code_challenge(&code_verifier);
        let client_state = generate_random_string(32);

        let authorize_req = OAuthAuthorizeRequest {
            response_type: "code".to_string(),
            client_id: oauth_config.client_id.clone(),
            redirect_uri: oauth_config.redirect_uri.clone(),
            scope: oauth_config.scopes.join(" "),
            state: client_state.clone(),
            code_challenge,
            code_challenge_method: "S256".to_string(),
        };

        // Call /oauth/authorize endpoint
        let oauth_url = self.base_url.join("/oauth/authorize")?;
        let auth_response: OAuthAuthorizeResponse = self
            .http
            .post(oauth_url)
            .json(&authorize_req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        // Display authorization URL to user
        println!("\n🔐 OAuth Authentication Required");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Please visit this URL to authenticate:\n");
        println!("{}\n", auth_response.authorization_url);
        println!("After authentication, you'll be redirected to:");
        println!("{}?session_token=...", oauth_config.redirect_uri);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        // Prompt user to paste the session token
        println!("Paste the full redirect URL here:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();

        // Extract session_token from the redirect URL
        let parsed_url = Url::parse(input).or_else(|_| {
            if input.starts_with("session_token=") || input.contains("session_token=") {
                Ok(Url::parse(&format!(
                    "{}?{}",
                    oauth_config.redirect_uri, input
                ))?)
            } else {
                Err(anyhow!("Invalid URL or token format"))
            }
        })?;

        let session_token = parsed_url
            .query_pairs()
            .find(|(key, _)| key == "session_token")
            .map(|(_, value)| value.to_string())
            .ok_or_else(|| anyhow!("No session_token found in URL"))?;

        Ok(session_token)
    }

    /// Start OAuth flow and return authorization URL (for programmatic use)
    pub async fn start_oauth_flow(&self) -> Result<(String, String)> {
        let oauth_config = self
            .config
            .oauth
            .as_ref()
            .ok_or_else(|| anyhow!("OAuth not configured"))?;

        let code_verifier = generate_code_verifier();
        let code_challenge = generate_code_challenge(&code_verifier);
        let client_state = generate_random_string(32);

        let authorize_req = OAuthAuthorizeRequest {
            response_type: "code".to_string(),
            client_id: oauth_config.client_id.clone(),
            redirect_uri: oauth_config.redirect_uri.clone(),
            scope: oauth_config.scopes.join(" "),
            state: client_state.clone(),
            code_challenge,
            code_challenge_method: "S256".to_string(),
        };

        let oauth_url = self.base_url.join("/oauth/authorize")?;
        let auth_response: OAuthAuthorizeResponse = self
            .http
            .post(oauth_url)
            .json(&authorize_req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok((auth_response.authorization_url, code_verifier))
    }
}

/// Generate a PKCE code verifier (43-128 character random string)
pub fn generate_code_verifier() -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    URL_SAFE_NO_PAD.encode(&random_bytes)
}

/// Generate a PKCE code challenge from a code verifier using S256 method
pub fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

/// Generate a random string for state parameter
pub fn generate_random_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..length).map(|_| rng.gen()).collect();
    URL_SAFE_NO_PAD.encode(&random_bytes)
}

/// Parse an SSE response into a stream of `StreamingMessageResult` items.
///
/// Each SSE event's `data:` line contains a JSON-RPC response envelope.
/// Handles multi-line `data:` fields (concatenated with `\n`) and dispatches
/// on empty lines per the SSE spec. Also processes any remaining buffered
/// data when the stream ends.
fn sse_stream(
    resp: reqwest::Response,
    version: ProtocolVersion,
) -> impl Stream<Item = Result<StreamingMessageResult>> + Send {
    async_stream::try_stream! {
        use tokio_stream::StreamExt;

        let mut bytes_stream = resp.bytes_stream();
        let mut buffer = String::new();
        // Accumulated data: field values for the current event (multi-line support)
        let mut data_buf: Vec<String> = Vec::new();

        loop {
            // Read next chunk, or drain remaining buffer when stream ends
            let done = match bytes_stream.next().await {
                Some(Ok(chunk)) => {
                    buffer.push_str(&String::from_utf8_lossy(&chunk));
                    false
                }
                Some(Err(e)) => Err(e)?,
                None => true,
            };

            // Process complete lines
            while let Some(newline_pos) = buffer.find('\n') {
                let line = buffer[..newline_pos].trim_end_matches('\r').to_string();
                buffer = buffer[newline_pos + 1..].to_string();

                if line.is_empty() {
                    // Empty line = dispatch event
                    if !data_buf.is_empty() {
                        let data = data_buf.join("\n");
                        data_buf.clear();

                        let rpc_resp: JsonRpcResponse = serde_json::from_str(&data)?;

                        if let Some(err) = rpc_resp.error {
                            Err(anyhow!("Server error {}: {}", err.code, err.message))?;
                        }

                        if let Some(result) = rpc_resp.result {
                            let result = if version == ProtocolVersion::V0_3 {
                                let wrapped = compat::wrap_v03_result_as_v10(result);
                                let mut converted = wrapped;
                                compat::response_v03_to_v10(&mut converted);
                                converted
                            } else {
                                result
                            };
                            let event: StreamingMessageResult = serde_json::from_value(result)?;
                            yield event;
                        }
                    }
                } else if let Some(value) = line.strip_prefix("data:") {
                    // Accumulate data field (trim leading single space per SSE spec)
                    let value = value.strip_prefix(' ').unwrap_or(value);
                    data_buf.push(value.to_string());
                }
                // Ignore other fields (event:, id:, retry:) and comments (:)
            }

            if done {
                // Dispatch any remaining data when stream closes without trailing \n
                if !data_buf.is_empty() {
                    let data = data_buf.join("\n");
                    let rpc_resp: JsonRpcResponse = serde_json::from_str(&data)?;

                    if let Some(err) = rpc_resp.error {
                        Err(anyhow!("Server error {}: {}", err.code, err.message))?;
                    }

                    if let Some(result) = rpc_resp.result {
                        let result = if version == ProtocolVersion::V0_3 {
                            let wrapped = compat::wrap_v03_result_as_v10(result);
                            let mut converted = wrapped;
                            compat::response_v03_to_v10(&mut converted);
                            converted
                        } else {
                            result
                        };
                        let event: StreamingMessageResult = serde_json::from_value(result)?;
                        yield event;
                    }
                }
                break;
            }
        }
    }
}

/// Check if the first SSE event is an error, and if so, return Err immediately.
/// Otherwise, return the stream with the first event re-prepended.
async fn check_sse_error_stream(
    stream: impl Stream<Item = Result<StreamingMessageResult>> + Send + 'static,
) -> Result<Pin<Box<dyn Stream<Item = Result<StreamingMessageResult>> + Send>>> {
    use tokio_stream::StreamExt;

    let mut stream = Box::pin(stream);

    // Try to get the first item with a short timeout
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next()).await;

    match first {
        Ok(Some(Err(e))) => {
            // First event is an error — return it as the function error
            Err(e)
        }
        Ok(Some(Ok(item))) => {
            // First event is a valid result — prepend it to the stream
            let rest = stream;
            let combined = async_stream::stream! {
                yield Ok(item);
                let mut rest = rest;
                while let Some(item) = rest.next().await {
                    yield item;
                }
            };
            Ok(Box::pin(combined))
        }
        Ok(None) => {
            // Stream ended immediately
            anyhow::bail!("SSE stream ended without events")
        }
        Err(_) => {
            // Timeout reading first event — return the stream as-is
            Ok(stream)
        }
    }
}

/// Parse an SSE response where events contain raw results (no JSON-RPC wrapper).
/// Used for REST transport where SSE data is the result directly.
fn sse_stream_raw(
    resp: reqwest::Response,
) -> impl Stream<Item = Result<StreamingMessageResult>> + Send {
    async_stream::try_stream! {
        use tokio_stream::StreamExt;

        let mut bytes_stream = resp.bytes_stream();
        let mut buffer = String::new();
        let mut data_buf: Vec<String> = Vec::new();

        loop {
            let done = match bytes_stream.next().await {
                Some(Ok(chunk)) => {
                    buffer.push_str(&String::from_utf8_lossy(&chunk));
                    false
                }
                Some(Err(e)) => Err(e)?,
                None => true,
            };

            while let Some(newline_pos) = buffer.find('\n') {
                let line = buffer[..newline_pos].trim_end_matches('\r').to_string();
                buffer = buffer[newline_pos + 1..].to_string();

                if line.is_empty() {
                    if !data_buf.is_empty() {
                        let data = data_buf.join("\n");
                        data_buf.clear();
                        let event: StreamingMessageResult = serde_json::from_str(&data)?;
                        yield event;
                    }
                } else if let Some(value) = line.strip_prefix("data:") {
                    let value = value.strip_prefix(' ').unwrap_or(value);
                    data_buf.push(value.to_string());
                }
            }

            if done {
                if !data_buf.is_empty() {
                    let data = data_buf.join("\n");
                    let event: StreamingMessageResult = serde_json::from_str(&data)?;
                    yield event;
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();
        assert_eq!(config.server_url, "http://127.0.0.1:8080");
        assert_eq!(config.max_polls, 30);
        assert_eq!(config.poll_interval_ms, 2000);
        assert!(config.oauth.is_none());
    }

    #[test]
    fn test_code_challenge() {
        let verifier = generate_code_verifier();
        let challenge = generate_code_challenge(&verifier);

        // Verifier should be URL-safe base64
        assert!(verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        // Challenge should also be URL-safe base64
        assert!(challenge
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_client_creation() {
        let client = A2aClient::with_server("http://localhost:8080").unwrap();
        assert_eq!(client.server_url(), "http://localhost:8080");
    }
}
