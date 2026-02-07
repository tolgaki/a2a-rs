//! In-memory task store
//!
//! Provides thread-safe storage for A2A tasks.

use a2a_core::{Task, TaskListParams, TaskListResponse};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Thread-safe in-memory task store
#[derive(Clone)]
pub struct TaskStore {
    tasks: Arc<RwLock<HashMap<String, Task>>>,
}

impl Default for TaskStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskStore {
    /// Create a new empty task store
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Insert or update a task
    pub async fn insert(&self, task: Task) {
        let id = task.id.clone();
        self.tasks.write().await.insert(id, task);
    }

    /// Get a task by ID
    pub async fn get(&self, id: &str) -> Option<Task> {
        self.tasks.read().await.get(id).cloned()
    }

    /// Get a task, trying multiple key formats
    ///
    /// Tries: exact match, with "tasks/" prefix, without "tasks/" prefix
    pub async fn get_flexible(&self, id: &str) -> Option<Task> {
        let guard = self.tasks.read().await;
        
        // Try exact match
        if let Some(task) = guard.get(id) {
            return Some(task.clone());
        }

        // Try with "tasks/" prefix
        let prefixed = format!("tasks/{}", id);
        if let Some(task) = guard.get(&prefixed) {
            return Some(task.clone());
        }

        // Try without "tasks/" prefix
        if let Some(stripped) = id.strip_prefix("tasks/") {
            if let Some(task) = guard.get(stripped) {
                return Some(task.clone());
            }
        }

        None
    }

    /// Update a task's state
    pub async fn update<F>(&self, id: &str, f: F) -> Option<Task>
    where
        F: FnOnce(&mut Task),
    {
        let mut guard = self.tasks.write().await;
        if let Some(task) = guard.get_mut(id) {
            f(task);
            Some(task.clone())
        } else {
            None
        }
    }

    /// Update a task with a fallible closure, trying multiple key formats
    ///
    /// Returns:
    /// - `None` if task not found
    /// - `Some(Err(e))` if closure returned error
    /// - `Some(Ok(task))` if update succeeded
    pub async fn update_flexible<F, E>(&self, id: &str, f: F) -> Option<Result<Task, E>>
    where
        F: FnOnce(&mut Task) -> Result<(), E>,
    {
        let mut guard = self.tasks.write().await;

        // Try to find the task with flexible key matching
        let key = if guard.contains_key(id) {
            Some(id.to_string())
        } else {
            let prefixed = format!("tasks/{}", id);
            if guard.contains_key(&prefixed) {
                Some(prefixed)
            } else if let Some(stripped) = id.strip_prefix("tasks/") {
                if guard.contains_key(stripped) {
                    Some(stripped.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        };

        let key = key?;
        let task = guard.get_mut(&key)?;

        match f(task) {
            Ok(()) => Some(Ok(task.clone())),
            Err(e) => Some(Err(e)),
        }
    }

    /// Remove a task
    pub async fn remove(&self, id: &str) -> Option<Task> {
        self.tasks.write().await.remove(id)
    }

    /// List all tasks
    pub async fn list(&self) -> Vec<Task> {
        self.tasks.read().await.values().cloned().collect()
    }

    /// List tasks with filtering and pagination
    ///
    /// Returns a TaskListResponse with filtered tasks and pagination info.
    pub async fn list_filtered(&self, params: &TaskListParams) -> TaskListResponse {
        let guard = self.tasks.read().await;

        // Apply filters
        let mut filtered: Vec<_> = guard
            .values()
            .filter(|task| {
                // Filter by context_id
                if let Some(ref ctx) = params.context_id {
                    if task.context_id != *ctx {
                        return false;
                    }
                }
                // Filter by status
                if let Some(status) = params.status {
                    if task.status.state != status {
                        return false;
                    }
                }
                // Filter by status_timestamp_after (milliseconds since epoch)
                if let Some(after_ms) = params.status_timestamp_after {
                    if let Some(ref ts) = task.status.timestamp {
                        // Parse ISO8601 timestamp and compare
                        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                            if dt.timestamp_millis() <= after_ms {
                                return false;
                            }
                        }
                    } else {
                        // No timestamp means we can't determine if it's after, exclude it
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        let total_size = filtered.len() as u32;
        let page_size = params.page_size.unwrap_or(50).min(100);

        // Sort by task ID for consistent pagination (could be timestamp-based in production)
        filtered.sort_by(|a, b| a.id.cmp(&b.id));

        // Apply pagination using page_token as offset
        let offset: usize = params
            .page_token
            .as_ref()
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);

        let paginated: Vec<_> = filtered
            .into_iter()
            .skip(offset)
            .take(page_size as usize)
            .map(|mut task| {
                // Optionally trim history
                if let Some(len) = params.history_length {
                    if let Some(ref mut history) = task.history {
                        let keep = len as usize;
                        if history.len() > keep {
                            *history = history.iter().rev().take(keep).cloned().collect();
                            history.reverse();
                        }
                    }
                }
                // Optionally exclude artifacts
                if params.include_artifacts == Some(false) {
                    task.artifacts = None;
                }
                task
            })
            .collect();

        let next_offset = offset + paginated.len();
        let next_page_token = if next_offset < total_size as usize {
            next_offset.to_string()
        } else {
            String::new()
        };

        TaskListResponse {
            tasks: paginated,
            next_page_token,
            page_size,
            total_size,
        }
    }

    /// Get the number of stored tasks
    pub async fn len(&self) -> usize {
        self.tasks.read().await.len()
    }

    /// Check if the store is empty
    pub async fn is_empty(&self) -> bool {
        self.tasks.read().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use a2a_core::{TaskState, TaskStatus};

    fn make_task(id: &str) -> Task {
        Task {
            id: id.to_string(),
            context_id: "ctx".to_string(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            history: None,
            artifacts: None,
            metadata: None,
        }
    }

    #[tokio::test]
    async fn test_insert_and_get() {
        let store = TaskStore::new();
        let task = make_task("task-1");
        
        store.insert(task.clone()).await;
        
        let retrieved = store.get("task-1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "task-1");
    }

    #[tokio::test]
    async fn test_get_flexible() {
        let store = TaskStore::new();
        let task = make_task("tasks/abc-123");
        
        store.insert(task).await;
        
        // Exact match
        assert!(store.get_flexible("tasks/abc-123").await.is_some());
        
        // Without prefix
        assert!(store.get_flexible("abc-123").await.is_some());
    }

    #[tokio::test]
    async fn test_update() {
        let store = TaskStore::new();
        let task = make_task("task-1");
        store.insert(task).await;

        let updated = store
            .update("task-1", |t| {
                t.status.state = TaskState::Completed;
            })
            .await;

        assert!(updated.is_some());
        assert_eq!(updated.unwrap().status.state, TaskState::Completed);
    }

    #[tokio::test]
    async fn test_concurrent_inserts() {
        let store = Arc::new(TaskStore::new());

        // Spawn 100 concurrent inserts
        let handles: Vec<_> = (0..100)
            .map(|i| {
                let store = store.clone();
                tokio::spawn(async move {
                    store.insert(make_task(&format!("task-{}", i))).await;
                })
            })
            .collect();

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(store.len().await, 100);
    }

    #[tokio::test]
    async fn test_concurrent_reads_and_writes() {
        let store = Arc::new(TaskStore::new());

        // Pre-populate with some tasks
        for i in 0..10 {
            store.insert(make_task(&format!("task-{}", i))).await;
        }

        // Spawn concurrent readers and writers
        let mut handles = Vec::new();

        // Writers
        for i in 10..60 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store.insert(make_task(&format!("task-{}", i))).await;
            }));
        }

        // Readers
        for i in 0..10 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                let _ = store.get(&format!("task-{}", i)).await;
            }));
        }

        // Updaters
        for i in 0..10 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store
                    .update(&format!("task-{}", i), |t| {
                        t.status.state = TaskState::Completed;
                    })
                    .await;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Should have 60 tasks (10 original + 50 new)
        assert_eq!(store.len().await, 60);

        // All original tasks should be completed
        for i in 0..10 {
            let task = store.get(&format!("task-{}", i)).await.unwrap();
            assert_eq!(task.status.state, TaskState::Completed);
        }
    }

    #[tokio::test]
    async fn test_concurrent_update_flexible() {
        let store = Arc::new(TaskStore::new());
        store.insert(make_task("tasks/shared-task")).await;

        // Spawn concurrent updates on the same task
        let handles: Vec<_> = (0..50)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(async move {
                    store
                        .update_flexible("shared-task", |t| -> Result<(), ()> {
                            t.context_id = "updated".to_string();
                            Ok(())
                        })
                        .await
                })
            })
            .collect();

        for h in handles {
            let result = h.await.unwrap();
            assert!(result.is_some());
            assert!(result.unwrap().is_ok());
        }

        // Task should exist and be updated
        let task = store.get("tasks/shared-task").await.unwrap();
        assert_eq!(task.context_id, "updated");
    }
}
