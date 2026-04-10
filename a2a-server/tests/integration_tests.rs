//! Integration tests for A2A Server
//!
//! Tests the JSON-RPC endpoints end-to-end.

use a2a_rs_core::{JsonRpcResponse, Message, Part, Role, SendMessageResult, TaskState};
use a2a_rs_server::A2aServer;
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
        kind: "message".to_string(),
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

/// Helper to extract Task from the JSON-RPC result field
fn extract_task(result: serde_json::Value) -> a2a_rs_core::Task {
    let resp: SendMessageResult = serde_json::from_value(result).unwrap();
    match resp {
        SendMessageResult::Task(t) => t,
        SendMessageResult::Message(_) => panic!("Expected Task response, got Message"),
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
    // EchoHandler now returns Working (auto-completes after delay)
    assert_eq!(task.status.state, TaskState::Working);
    assert!(!task.id.is_empty());
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

    // Poll the task using direct ID
    let request = rpc_request("tasks/get", json!({ "id": task_id }));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let rpc_response = response_json(response).await;
    assert!(rpc_response.error.is_none());
    let polled_task: a2a_rs_core::Task =
        serde_json::from_value(rpc_response.result.unwrap()).unwrap();
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
    let card: a2a_rs_core::AgentCard = serde_json::from_slice(&bytes).unwrap();

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
    // Per JSON-RPC 2.0: HTTP 200 with a -32601 error envelope.
    assert_eq!(response.status(), StatusCode::OK);
    let rpc_response = response_json(response).await;
    let error = rpc_response.error.expect("should have error");
    assert_eq!(error.code, -32601); // METHOD_NOT_FOUND
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
    // Per JSON-RPC 2.0: parse error is HTTP 200 with a -32700 error envelope.
    assert_eq!(response.status(), StatusCode::OK);
    let rpc_response = response_json(response).await;
    let error = rpc_response.error.expect("should have error");
    assert_eq!(error.code, -32700); // PARSE_ERROR
    assert!(rpc_response.id.is_null());
}

#[tokio::test]
async fn test_invalid_jsonrpc_version() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let body = json!({
        "jsonrpc": "1.0",
        "method": "message/send",
        "params": {},
        "id": 7
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc_response = response_json(response).await;
    let error = rpc_response.error.expect("should have error");
    assert_eq!(error.code, -32600); // INVALID_REQUEST
}

#[tokio::test]
async fn test_missing_method_field() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let body = json!({ "jsonrpc": "2.0", "id": 3 });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc_response = response_json(response).await;
    let error = rpc_response.error.expect("should have error");
    assert_eq!(error.code, -32600); // INVALID_REQUEST
}

#[tokio::test]
async fn test_custom_rpc_path() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address")
        .rpc_path("/spec");
    let router = server.build_router();

    // The original /v1/rpc path is also handled via the POST fallback
    // (all POST paths are routed through JSON-RPC for TCK compliance).
    let request = rpc_request(
        "message/send",
        json!({ "message": test_message("m", "hi") }),
    );
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The configured /spec path should respond.
    let body = json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": { "message": test_message("m", "hi") },
        "id": 1,
    });
    let request = Request::builder()
        .method("POST")
        .uri("/spec")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The agent card should advertise the custom path.
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/agent-card.json")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let card: a2a_rs_core::AgentCard = serde_json::from_slice(&bytes).unwrap();
    assert!(card.endpoint().unwrap().ends_with("/spec"));
}

#[tokio::test]
async fn test_task_not_found() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let request = rpc_request("tasks/get", json!({ "id": "nonexistent" }));
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

    // EchoHandler returns Working; cancel should succeed before auto-complete fires
    let request = rpc_request("tasks/cancel", json!({ "id": task.id }));
    let response = router.oneshot(request).await.unwrap();
    let rpc_response = response_json(response).await;
    assert!(
        rpc_response.error.is_none(),
        "cancel should succeed on Working task"
    );
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

    let text = agent_msg.parts[0].as_text().expect("Expected text part");
    assert!(text.contains("echo:"));
    assert!(text.contains("Hello World"));
}

#[tokio::test]
async fn test_list_tasks_page_size_validation() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    // pageSize=0 → -32602
    let request = rpc_request("tasks/list", json!({ "pageSize": 0 }));
    let rpc = response_json(router.clone().oneshot(request).await.unwrap()).await;
    assert_eq!(rpc.error.unwrap().code, -32602);

    // pageSize=101 → -32602
    let request = rpc_request("tasks/list", json!({ "pageSize": 101 }));
    let rpc = response_json(router.clone().oneshot(request).await.unwrap()).await;
    assert_eq!(rpc.error.unwrap().code, -32602);

    // invalid pageToken → -32602
    let request = rpc_request("tasks/list", json!({ "pageToken": "not-a-number" }));
    let rpc = response_json(router.clone().oneshot(request).await.unwrap()).await;
    assert_eq!(rpc.error.unwrap().code, -32602);
}

#[tokio::test]
async fn test_list_tasks_page_size_response() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    // Create 3 tasks
    for i in 0..3 {
        let msg = test_message(&format!("ps-{i}"), &format!("msg {i}"));
        let req = rpc_request("message/send", json!({ "message": msg }));
        router.clone().oneshot(req).await.unwrap();
    }

    // Request with pageSize=10 (larger than total)
    let request = rpc_request("tasks/list", json!({ "pageSize": 10 }));
    let rpc = response_json(router.oneshot(request).await.unwrap()).await;
    let result = rpc.result.unwrap();
    // pageSize in response is the actual number of items returned
    assert_eq!(result["pageSize"].as_u64().unwrap(), 3);
    assert_eq!(result["totalSize"].as_u64().unwrap(), 3);
    // Last page → empty nextPageToken
    assert_eq!(result["nextPageToken"].as_str().unwrap(), "");
}

#[tokio::test]
async fn test_list_tasks_artifacts_excluded_by_default() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let msg = test_message("art-1", "hello");
    let req = rpc_request("message/send", json!({ "message": msg }));
    router.clone().oneshot(req).await.unwrap();

    // List without includeArtifacts — artifacts should be absent
    let request = rpc_request("tasks/list", json!({}));
    let rpc = response_json(router.oneshot(request).await.unwrap()).await;
    let tasks = rpc.result.unwrap()["tasks"].as_array().unwrap().clone();
    for task in &tasks {
        assert!(
            task.get("artifacts").is_none() || task["artifacts"].is_null(),
            "artifacts should be excluded by default"
        );
    }
}

#[tokio::test]
async fn test_continue_task() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    // Create initial task
    let msg = test_message("cont-1", "first");
    let req = rpc_request("message/send", json!({ "message": msg }));
    let rpc = response_json(router.clone().oneshot(req).await.unwrap()).await;
    let task = extract_task(rpc.result.unwrap());
    let task_id = task.id.clone();

    // Send a follow-up referencing the same task
    let follow_up = json!({
        "message": {
            "kind": "message",
            "messageId": "cont-2",
            "role": "user",
            "parts": [{"kind": "text", "text": "follow up"}],
            "taskId": task_id,
        }
    });
    let req = rpc_request("message/send", follow_up);
    let rpc = response_json(router.oneshot(req).await.unwrap()).await;
    let task2 = extract_task(rpc.result.unwrap());

    // The response task should reuse the original task id
    assert_eq!(task2.id, task_id);
}

// ============ TCK Compliance Tests ============

/// TCK: test_rejects_malformed_json — malformed JSON must return -32700
#[tokio::test]
async fn test_tck_malformed_json() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"jsonrpc": "2.0", "method": "SendMessage"#)) // truncated
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc = response_json(response).await;
    let err = rpc.error.expect("should have error");
    assert_eq!(err.code, -32700); // PARSE_ERROR
}

/// TCK: test_raw_invalid_json — totally invalid bytes
#[tokio::test]
async fn test_tck_raw_invalid_json() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from("not json at all!!!"))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc = response_json(response).await;
    let err = rpc.error.expect("should have error");
    assert_eq!(err.code, -32700);
}

/// TCK: POST to any path should be handled by JSON-RPC (fallback)
#[tokio::test]
async fn test_tck_post_fallback_any_path() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    // POST to /spec (not the configured rpc_path) should still work
    let body = json!({
        "jsonrpc": "2.0",
        "method": "SendMessage",
        "params": { "message": test_message("fb-1", "hello") },
        "id": 42
    });
    let request = Request::builder()
        .method("POST")
        .uri("/spec")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc = response_json(response).await;
    assert!(rpc.error.is_none(), "should succeed via fallback");
    assert!(rpc.result.is_some());
}

/// TCK: malformed JSON to non-standard path must still return -32700
#[tokio::test]
async fn test_tck_malformed_json_on_fallback_path() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let request = Request::builder()
        .method("POST")
        .uri("/some/random/path")
        .header("content-type", "application/json")
        .body(Body::from("{bad json"))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc = response_json(response).await;
    assert_eq!(rpc.error.unwrap().code, -32700);
}

/// TCK: GET /.well-known/agent.json should return agent card (v0.2 fallback)
#[tokio::test]
async fn test_tck_agent_json_alias() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/agent.json")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let card: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(card.get("name").is_some());
    assert!(card.get("description").is_some());
    assert!(card.get("version").is_some());
    assert!(card.get("capabilities").is_some());
    assert!(card.get("defaultInputModes").is_some());
    assert!(card.get("defaultOutputModes").is_some());
    assert!(card.get("skills").is_some());
}

/// TCK: POST to /.well-known/agent-card.json should not return 405
#[tokio::test]
async fn test_tck_post_to_agent_card_path() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let body = json!({
        "jsonrpc": "2.0",
        "method": "GetTask",
        "params": { "id": "nonexistent" },
        "id": 1
    });
    let request = Request::builder()
        .method("POST")
        .uri("/.well-known/agent-card.json")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    // Should get 200 with JSON-RPC error, NOT 405
    assert_eq!(response.status(), StatusCode::OK);
    let rpc = response_json(response).await;
    assert_eq!(rpc.error.unwrap().code, -32001); // TASK_NOT_FOUND
}

/// TCK: ListTasks with no params should use default page size (50)
#[tokio::test]
async fn test_tck_list_tasks_default_page_size() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    // ListTasks with empty params
    let body = json!({
        "jsonrpc": "2.0",
        "method": "ListTasks",
        "params": {},
        "id": 1
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc = response_json(response).await;
    let result = rpc.result.unwrap();
    // pageSize == 0 when no items returned (actual count, not requested)
    assert_eq!(result["pageSize"].as_u64().unwrap(), 0);
    assert_eq!(result["totalSize"].as_u64().unwrap(), 0);
    assert_eq!(result["tasks"].as_array().unwrap().len(), 0);
    assert_eq!(result["nextPageToken"].as_str().unwrap(), "");
}

/// TCK: ListTasks with NO params field at all should work (params absent)
#[tokio::test]
async fn test_tck_list_tasks_absent_params() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    // JSON-RPC request without params field
    let body = json!({
        "jsonrpc": "2.0",
        "method": "ListTasks",
        "id": 1
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc = response_json(response).await;
    assert!(rpc.error.is_none(), "ListTasks with absent params should succeed");
    let result = rpc.result.unwrap();
    assert_eq!(result["pageSize"].as_u64().unwrap(), 0); // 0 items returned
}

/// TCK: PascalCase method names must work
#[tokio::test]
async fn test_tck_pascal_case_methods() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    // SendMessage (PascalCase)
    let body = json!({
        "jsonrpc": "2.0",
        "method": "SendMessage",
        "params": { "message": test_message("pc-1", "hello") },
        "id": 1
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc = response_json(response).await;
    assert!(rpc.error.is_none());
    let task = extract_task(rpc.result.unwrap());

    // GetTask (PascalCase)
    let body = json!({
        "jsonrpc": "2.0",
        "method": "GetTask",
        "params": { "id": task.id },
        "id": 2
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    let rpc = response_json(response).await;
    assert!(rpc.error.is_none());
    // GetTask returns task directly (no wrapper)
    let result = rpc.result.unwrap();
    assert_eq!(result["id"].as_str().unwrap(), task.id);

    // CancelTask (PascalCase)
    let body = json!({
        "jsonrpc": "2.0",
        "method": "CancelTask",
        "params": { "id": task.id },
        "id": 3
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let rpc = response_json(response).await;
    assert!(rpc.error.is_none());
    let result = rpc.result.unwrap();
    assert_eq!(result["status"]["state"].as_str().unwrap(), "TASK_STATE_CANCELED");
}

/// TCK: Agent card must advertise 127.0.0.1 when bound to 0.0.0.0
#[tokio::test]
async fn test_tck_agent_card_reachable_url() {
    let server = A2aServer::echo()
        .bind("0.0.0.0:0")
        .expect("valid address");
    let router = server.build_router();

    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/agent-card.json")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let card: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let iface = card["supportedInterfaces"]
        .as_array()
        .unwrap()
        .first()
        .unwrap();
    let url = iface["url"].as_str().unwrap();
    // Should use localhost, not 0.0.0.0 or raw IP
    assert!(
        url.contains("localhost"),
        "agent card should advertise localhost not raw IP, got: {url}"
    );
}

/// TCK: Push notification methods on agent without push support → -32003
#[tokio::test]
async fn test_tck_push_notification_not_supported() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let body = json!({
        "jsonrpc": "2.0",
        "method": "CreateTaskPushNotificationConfig",
        "params": {
            "taskId": "some-task",
            "configId": "cfg-1",
            "pushNotificationConfig": { "url": "https://example.com/hook" }
        },
        "id": 1
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/rpc")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc = response_json(response).await;
    assert_eq!(rpc.error.unwrap().code, -32003);
}

/// TCK: EchoHandler generates contextId when message doesn't provide one
#[tokio::test]
async fn test_tck_generated_context_id() {
    let server = A2aServer::echo()
        .bind("127.0.0.1:0")
        .expect("valid address");
    let router = server.build_router();

    let msg = test_message("ctx-1", "hello");
    let req = rpc_request("SendMessage", json!({ "message": msg }));
    let rpc = response_json(router.clone().oneshot(req).await.unwrap()).await;
    let task = extract_task(rpc.result.unwrap());
    assert!(!task.context_id.is_empty(), "should have a generated contextId");

    // Second task should get a different contextId
    let msg2 = test_message("ctx-2", "world");
    let req2 = rpc_request("SendMessage", json!({ "message": msg2 }));
    let rpc2 = response_json(router.oneshot(req2).await.unwrap()).await;
    let task2 = extract_task(rpc2.result.unwrap());
    assert_ne!(task.context_id, task2.context_id, "each task should get unique contextId");
}
