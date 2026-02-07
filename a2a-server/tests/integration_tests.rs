//! Integration tests for A2A Server
//!
//! Tests the JSON-RPC endpoints end-to-end.

use a2a_core::{JsonRpcResponse, Message, Part, Role, SendMessageResponse, TaskState};
use a2a_server::A2aServer;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

/// Helper to build a JSON-RPC request
fn rpc_request(method: &str, params: serde_json::Value) -> Request<Body> {
    let body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

/// Helper to extract response body as JSON
async fn response_json(response: axum::response::Response) -> JsonRpcResponse {
    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper to create a test message
fn test_message(id: &str, text: &str) -> Message {
    Message {
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

/// Helper to extract Task from SendMessageResponse JSON
fn extract_task(result: serde_json::Value) -> a2a_core::Task {
    let resp: SendMessageResponse = serde_json::from_value(result).unwrap();
    match resp {
        SendMessageResponse::Task(t) => t,
        SendMessageResponse::Message(_) => panic!("Expected Task response, got Message"),
    }
}

#[tokio::test]
async fn test_message_send() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let message = test_message("msg-1", "Hello, echo!");

    let request = rpc_request(
        "message/send",
        json!({
            "message": message
        }),
    );

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let rpc_response = response_json(response).await;
    assert!(rpc_response.error.is_none());
    assert!(rpc_response.result.is_some());

    // Verify the task was created
    let task = extract_task(rpc_response.result.unwrap());
    assert_eq!(task.status.state, TaskState::Completed);
    assert!(task.id.contains("tasks/") || !task.id.is_empty());
}

#[tokio::test]
async fn test_message_send_and_poll() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    // Send a message
    let message = test_message("msg-1", "Test message");

    let request = rpc_request("message/send", json!({ "message": message }));
    let response = router.clone().oneshot(request).await.unwrap();
    let rpc_response = response_json(response).await;
    let task = extract_task(rpc_response.result.unwrap());
    let task_id = task.id.clone();

    // Poll the task
    let request = rpc_request("tasks/get", json!({ "name": task_id }));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let rpc_response = response_json(response).await;
    assert!(rpc_response.error.is_none());
    let polled_task: a2a_core::Task = serde_json::from_value(rpc_response.result.unwrap()).unwrap();
    assert_eq!(polled_task.id, task_id);
}

#[tokio::test]
async fn test_tasks_list() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    // Send two messages to create tasks
    for i in 0..2 {
        let message = test_message(&format!("msg-{}", i), &format!("Message {}", i));
        let request = rpc_request("message/send", json!({ "message": message }));
        router.clone().oneshot(request).await.unwrap();
    }

    // List tasks
    let request = rpc_request("tasks/list", json!({}));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let rpc_response = response_json(response).await;
    assert!(rpc_response.error.is_none());

    let result = rpc_response.result.unwrap();
    let tasks = result.get("tasks").unwrap().as_array().unwrap();
    assert_eq!(tasks.len(), 2);
}

#[tokio::test]
async fn test_agent_card_endpoint() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/agent-card.json")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    let card: a2a_core::AgentCard = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(card.name, "Echo Agent");
    assert!(card.endpoint().unwrap().contains("/v1/rpc"));
}

#[tokio::test]
async fn test_invalid_method() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let request = rpc_request("invalid/method", json!({}));
    let response = router.oneshot(request).await.unwrap();
    // Server returns 404 for unknown methods (method routing at HTTP level)
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_invalid_json() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from("not valid json"))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    // Parse error should return 400
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_task_not_found() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let request = rpc_request("tasks/get", json!({ "name": "tasks/nonexistent" }));
    let response = router.oneshot(request).await.unwrap();

    let rpc_response = response_json(response).await;
    assert!(rpc_response.error.is_some());
    let error = rpc_response.error.unwrap();
    assert_eq!(error.code, -32001); // TASK_NOT_FOUND
}

#[tokio::test]
async fn test_task_cancel() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    // First create a task
    let message = test_message("msg-cancel", "To be cancelled");
    let request = rpc_request("message/send", json!({ "message": message }));
    let response = router.clone().oneshot(request).await.unwrap();
    let rpc_response = response_json(response).await;
    let task = extract_task(rpc_response.result.unwrap());

    // Echo handler tasks complete immediately, so cancel should fail
    let request = rpc_request("tasks/cancel", json!({ "name": task.id }));
    let response = router.oneshot(request).await.unwrap();
    let rpc_response = response_json(response).await;

    // Should error because task is already completed
    assert!(rpc_response.error.is_some());
}

#[tokio::test]
async fn test_echo_response_content() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let message = test_message("msg-echo", "Hello World");

    let request = rpc_request("message/send", json!({ "message": message }));
    let response = router.oneshot(request).await.unwrap();
    let rpc_response = response_json(response).await;
    let task = extract_task(rpc_response.result.unwrap());

    // Check the echo response in history
    let history = task.history.expect("should have history");
    assert_eq!(history.len(), 2); // User message + Agent response

    let agent_msg = &history[1];
    assert_eq!(agent_msg.role, Role::Agent);

    let text = agent_msg.parts[0].text.as_deref().expect("Expected text part");
    assert!(text.contains("echo:"));
    assert!(text.contains("Hello World"));
}
