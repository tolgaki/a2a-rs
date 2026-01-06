//! Webhook configuration storage
//!
//! Provides thread-safe storage for push notification webhook configurations.

use a2a_core::TaskPushNotificationConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

/// Error when setting a webhook configuration
#[derive(Debug, thiserror::Error)]
pub enum WebhookValidationError {
    #[error("Invalid URL format: {0}")]
    InvalidUrl(String),
    #[error("URL scheme must be http or https, got: {0}")]
    InvalidScheme(String),
}

/// Stored webhook configuration with ID
#[derive(Debug, Clone)]
pub struct StoredWebhookConfig {
    /// Configuration ID
    pub config_id: String,
    /// The webhook configuration
    pub config: TaskPushNotificationConfig,
}

/// Thread-safe in-memory webhook configuration store
///
/// Uses nested HashMaps for O(1) lookup: task_id -> config_id -> config
#[derive(Clone)]
pub struct WebhookStore {
    /// Map of task_id -> (config_id -> config)
    configs: Arc<RwLock<HashMap<String, HashMap<String, TaskPushNotificationConfig>>>>,
}

impl Default for WebhookStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookStore {
    /// Create a new empty webhook store
    pub fn new() -> Self {
        Self {
            configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set a webhook configuration for a task
    ///
    /// If a config with the same ID exists, it will be replaced.
    /// Returns an error if the webhook URL is invalid.
    pub async fn set(
        &self,
        task_id: &str,
        config_id: &str,
        config: TaskPushNotificationConfig,
    ) -> Result<(), WebhookValidationError> {
        // Validate the webhook URL
        let parsed = Url::parse(&config.url)
            .map_err(|e| WebhookValidationError::InvalidUrl(e.to_string()))?;

        match parsed.scheme() {
            "http" | "https" => {}
            scheme => return Err(WebhookValidationError::InvalidScheme(scheme.to_string())),
        }

        self.configs
            .write()
            .await
            .entry(task_id.to_string())
            .or_default()
            .insert(config_id.to_string(), config);

        Ok(())
    }

    /// Get a specific webhook configuration (O(1) lookup)
    pub async fn get(&self, task_id: &str, config_id: &str) -> Option<TaskPushNotificationConfig> {
        self.configs
            .read()
            .await
            .get(task_id)?
            .get(config_id)
            .cloned()
    }

    /// List all webhook configurations for a task
    pub async fn list(&self, task_id: &str) -> Vec<StoredWebhookConfig> {
        let guard = self.configs.read().await;
        guard
            .get(task_id)
            .map(|configs| {
                configs
                    .iter()
                    .map(|(id, config)| StoredWebhookConfig {
                        config_id: id.clone(),
                        config: config.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Delete a specific webhook configuration (O(1) lookup)
    ///
    /// Returns true if the config was found and deleted.
    pub async fn delete(&self, task_id: &str, config_id: &str) -> bool {
        let mut guard = self.configs.write().await;
        if let Some(configs) = guard.get_mut(task_id) {
            let removed = configs.remove(config_id).is_some();
            // Clean up empty task entries
            if configs.is_empty() {
                guard.remove(task_id);
            }
            return removed;
        }
        false
    }

    /// Get all webhook configurations for a task (for delivery)
    pub async fn get_configs_for_task(&self, task_id: &str) -> Vec<TaskPushNotificationConfig> {
        let guard = self.configs.read().await;
        guard
            .get(task_id)
            .map(|configs| configs.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Remove all configurations for a task
    pub async fn remove_task(&self, task_id: &str) {
        self.configs.write().await.remove(task_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(url: &str) -> TaskPushNotificationConfig {
        TaskPushNotificationConfig {
            url: url.to_string(),
            headers: None,
            event_types: vec!["task_status_update".to_string()],
        }
    }

    #[tokio::test]
    async fn test_set_and_get() {
        let store = WebhookStore::new();
        let config = make_config("https://example.com/webhook");

        store.set("task-1", "config-1", config.clone()).await.unwrap();

        let retrieved = store.get("task-1", "config-1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().url, "https://example.com/webhook");
    }

    #[tokio::test]
    async fn test_list() {
        let store = WebhookStore::new();
        store
            .set("task-1", "config-1", make_config("https://a.com"))
            .await
            .unwrap();
        store
            .set("task-1", "config-2", make_config("https://b.com"))
            .await
            .unwrap();

        let configs = store.list("task-1").await;
        assert_eq!(configs.len(), 2);
    }

    #[tokio::test]
    async fn test_delete() {
        let store = WebhookStore::new();
        store
            .set("task-1", "config-1", make_config("https://a.com"))
            .await
            .unwrap();

        assert!(store.delete("task-1", "config-1").await);
        assert!(store.get("task-1", "config-1").await.is_none());
        assert!(!store.delete("task-1", "config-1").await);
    }

    #[tokio::test]
    async fn test_replace_existing() {
        let store = WebhookStore::new();
        store
            .set("task-1", "config-1", make_config("https://old.com"))
            .await
            .unwrap();
        store
            .set("task-1", "config-1", make_config("https://new.com"))
            .await
            .unwrap();

        let configs = store.list("task-1").await;
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].config.url, "https://new.com");
    }

    #[tokio::test]
    async fn test_invalid_url() {
        let store = WebhookStore::new();
        let config = make_config("not-a-valid-url");
        let result = store.set("task-1", "config-1", config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_scheme() {
        let store = WebhookStore::new();
        let config = make_config("ftp://example.com/webhook");
        let result = store.set("task-1", "config-1", config).await;
        assert!(matches!(result, Err(WebhookValidationError::InvalidScheme(_))));
    }

    #[tokio::test]
    async fn test_concurrent_sets() {
        let store = Arc::new(WebhookStore::new());

        // Spawn 100 concurrent sets across 10 tasks
        let handles: Vec<_> = (0..100)
            .map(|i| {
                let store = store.clone();
                tokio::spawn(async move {
                    let task_id = format!("task-{}", i % 10);
                    let config_id = format!("config-{}", i);
                    store
                        .set(&task_id, &config_id, make_config(&format!("https://example{}.com", i)))
                        .await
                })
            })
            .collect();

        for h in handles {
            let result = h.await.unwrap();
            assert!(result.is_ok());
        }

        // Each task should have 10 configs
        for i in 0..10 {
            let configs = store.list(&format!("task-{}", i)).await;
            assert_eq!(configs.len(), 10);
        }
    }

    #[tokio::test]
    async fn test_concurrent_reads_and_writes() {
        let store = Arc::new(WebhookStore::new());

        // Pre-populate
        for i in 0..10 {
            store
                .set("task-1", &format!("config-{}", i), make_config(&format!("https://pre{}.com", i)))
                .await
                .unwrap();
        }

        let mut handles = Vec::new();

        // Writers
        for i in 10..60 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store
                    .set("task-1", &format!("config-{}", i), make_config(&format!("https://new{}.com", i)))
                    .await
                    .unwrap();
            }));
        }

        // Readers
        for _ in 0..50 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                let _ = store.list("task-1").await;
            }));
        }

        // Deleters
        for i in 0..5 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store.delete("task-1", &format!("config-{}", i)).await;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Should have 55 configs (10 original - 5 deleted + 50 new)
        let configs = store.list("task-1").await;
        assert_eq!(configs.len(), 55);
    }
}
