//! Webhook delivery engine
//!
//! Handles delivery of push notification events to registered webhooks.

use a2a_core::{PushNotificationConfig, StreamResponse};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Semaphore};
use tracing::{debug, error, warn};

use crate::webhook_store::WebhookStore;

const DEFAULT_MAX_CONCURRENT: usize = 100;

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

pub struct WebhookDelivery {
    client: reqwest::Client,
    webhook_store: WebhookStore,
    retry_config: RetryConfig,
    concurrency_limit: Arc<Semaphore>,
}

impl WebhookDelivery {
    pub fn new(webhook_store: WebhookStore) -> Self {
        Self::with_config(webhook_store, RetryConfig::default(), DEFAULT_MAX_CONCURRENT)
    }

    pub fn with_config(
        webhook_store: WebhookStore,
        retry_config: RetryConfig,
        max_concurrent: usize,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            webhook_store,
            retry_config,
            concurrency_limit: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    pub fn start(self: Arc<Self>, mut event_rx: broadcast::Receiver<StreamResponse>) {
        tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        self.clone().handle_event(event).await;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Webhook delivery lagged, missed {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("Event channel closed, stopping webhook delivery");
                        break;
                    }
                }
            }
        });
    }

    async fn handle_event(self: Arc<Self>, event: StreamResponse) {
        let task_id = match &event {
            StreamResponse::Task(t) => &t.id,
            StreamResponse::StatusUpdate(e) => &e.task_id,
            StreamResponse::ArtifactUpdate(e) => &e.task_id,
            StreamResponse::Message(_) => return,
        };

        let configs = self.webhook_store.get_configs_for_task(task_id).await;
        if configs.is_empty() {
            return;
        }

        for config in configs {
            let self_clone = self.clone();
            let event_clone = event.clone();
            let config_clone = config.clone();
            let semaphore = self.concurrency_limit.clone();

            tokio::spawn(async move {
                let _permit = match semaphore.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        error!("Semaphore closed, cannot deliver webhook");
                        return;
                    }
                };

                if let Err(e) = self_clone
                    .deliver_with_retry(&config_clone, &event_clone)
                    .await
                {
                    error!("Failed to deliver webhook to {}: {}", config_clone.url, e);
                }
            });
        }
    }

    async fn deliver_with_retry(
        &self,
        config: &PushNotificationConfig,
        event: &StreamResponse,
    ) -> Result<(), WebhookError> {
        let payload =
            serde_json::to_string(event).map_err(|e| WebhookError::Serialization(e.to_string()))?;

        let mut delay = self.retry_config.initial_delay;
        let mut last_error = None;

        for attempt in 0..=self.retry_config.max_retries {
            if attempt > 0 {
                debug!("Retry attempt {} for webhook {}", attempt, config.url);
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(
                    Duration::from_secs_f64(delay.as_secs_f64() * self.retry_config.backoff_multiplier),
                    self.retry_config.max_delay,
                );
            }

            match self.send_request(config, &payload).await {
                Ok(()) => {
                    debug!("Successfully delivered webhook to {}", config.url);
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Webhook delivery to {} failed (attempt {}): {}",
                        config.url,
                        attempt + 1,
                        e
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(WebhookError::Unknown))
    }

    async fn send_request(
        &self,
        config: &PushNotificationConfig,
        payload: &str,
    ) -> Result<(), WebhookError> {
        let mut request = self
            .client
            .post(&config.url)
            .header("Content-Type", "application/json")
            .body(payload.to_string());

        // Add authentication if configured
        if let Some(auth) = &config.authentication {
            if let Some(credentials) = &auth.credentials {
                match auth.scheme.as_str() {
                    "bearer" => {
                        request = request.header("Authorization", format!("Bearer {}", credentials));
                    }
                    _ => {
                        request = request.header("Authorization", format!("{} {}", auth.scheme, credentials));
                    }
                }
            }
        } else if let Some(token) = &config.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request
            .send()
            .await
            .map_err(|e| WebhookError::Network(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else if status.is_server_error() {
            Err(WebhookError::ServerError(status.as_u16()))
        } else {
            Err(WebhookError::ClientError(status.as_u16()))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Server error: {0}")]
    ServerError(u16),
    #[error("Client error: {0}")]
    ClientError(u16),
    #[error("Unknown error")]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay, Duration::from_millis(500));
    }
}
