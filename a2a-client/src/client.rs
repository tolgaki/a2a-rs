//! A2A Client implementation
//!
//! Provides a reusable client for A2A RC 1.0 agent communication.

use std::sync::Arc;
use std::time::{Duration, Instant};

use a2a_core::{
    AgentCard, GetTaskRequest, JsonRpcRequest, JsonRpcResponse, Message, SendMessageRequest,
    SendMessageResponse, Task,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn};

/// Duration to cache the agent card (5 minutes)
const AGENT_CARD_CACHE_TTL: Duration = Duration::from_secs(300);

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
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8080".to_string(),
            max_polls: 30,
            poll_interval_ms: 2000,
            oauth: None,
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

        Ok(Self {
            config,
            http: Client::new(),
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

    /// Get the cached RPC endpoint URL, fetching from agent card if needed
    async fn get_cached_endpoint(&self) -> Result<String> {
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

    /// Send a JSON-RPC request and parse the response
    async fn json_rpc_call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
        session_token: Option<&str>,
    ) -> Result<R> {
        let rpc_url = self.get_cached_endpoint().await?;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params: Some(serde_json::to_value(params)?),
            id: serde_json::json!(1),
        };

        let mut req_builder = self.http.post(rpc_url).json(&request);
        if let Some(token) = session_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }

        let mut resp: JsonRpcResponse = req_builder
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if let Some(err) = resp.error.take() {
            anyhow::bail!("Server error {}: {}", err.code, err.message);
        }

        resp.result
            .as_ref()
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()?
            .ok_or_else(|| anyhow!("Server returned no result"))
    }

    /// Send a message to the agent and receive a response (Task or Message)
    pub async fn send_message(
        &self,
        message: Message,
        session_token: Option<&str>,
    ) -> Result<SendMessageResponse> {
        let params = SendMessageRequest {
            tenant: None,
            message,
            configuration: None,
            metadata: None,
        };
        self.json_rpc_call("message/send", params, session_token).await
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
        assert!(verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        // Challenge should also be URL-safe base64
        assert!(challenge.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_client_creation() {
        let client = A2aClient::with_server("http://localhost:8080").unwrap();
        assert_eq!(client.server_url(), "http://localhost:8080");
    }
}
