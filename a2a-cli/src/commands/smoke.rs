use a2a_rs_client::{A2aClient, ClientConfig, Transport};
use a2a_rs_core::{ListTasksRequest, Message, Part, Role, SendMessageResult};
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use tokio_stream::StreamExt;

pub async fn run(base_url: String, http: Client) -> Result<()> {
    let mut results: Vec<(String, Result<String>)> = Vec::new();

    results.push((
        "GET  /.well-known/agent-card.json".into(),
        fetch_card(&base_url, &http).await,
    ));

    let rpc = build_client(&base_url, &http, Transport::JsonRpc)?;
    let rest = build_client(&base_url, &http, Transport::Rest)?;

    results.push(("JSON-RPC SendMessage".into(), send_once(&rpc).await));
    results.push(("REST     SendMessage".into(), send_once(&rest).await));
    results.push((
        "JSON-RPC SendStreamingMessage".into(),
        stream_once(&rpc).await,
    ));
    results.push(("JSON-RPC ListTasks".into(), list_once(&rpc).await));

    let total = results.len();
    let passed = results.iter().filter(|(_, r)| r.is_ok()).count();

    println!("smoke results ({}/{} passed):", passed, total);
    for (name, result) in &results {
        match result {
            Ok(note) => println!("  PASS  {name}  {note}"),
            Err(e) => println!("  FAIL  {name}  {e}"),
        }
    }

    if passed == total {
        Ok(())
    } else {
        Err(anyhow!("{}/{} checks failed", total - passed, total))
    }
}

fn build_client(base_url: &str, http: &Client, transport: Transport) -> Result<A2aClient> {
    A2aClient::new(ClientConfig {
        server_url: base_url.to_string(),
        http_client: Some(http.clone()),
        transport,
        ..Default::default()
    })
}

async fn fetch_card(base_url: &str, http: &Client) -> Result<String> {
    let url = format!(
        "{}/.well-known/agent-card.json",
        base_url.trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()?;
    let value: serde_json::Value = resp.json().await?;
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("(unnamed)");
    Ok(format!("agent={name}"))
}

async fn send_once(client: &A2aClient) -> Result<String> {
    let result = client.send_message(smoke_message("smoke send"), None, None).await?;
    match result {
        SendMessageResult::Task(t) => Ok(format!("task={} state={:?}", t.id, t.status.state)),
        SendMessageResult::Message(_) => Ok("direct message".into()),
    }
}

async fn stream_once(client: &A2aClient) -> Result<String> {
    let mut stream = client
        .send_message_streaming(smoke_message("smoke stream"), None, None)
        .await?;
    let mut count = 0u32;
    while let Some(event) = stream.next().await {
        event?;
        count += 1;
        if count >= 1 {
            break;
        }
    }
    Ok(format!("{count} event(s)"))
}

async fn list_once(client: &A2aClient) -> Result<String> {
    let list = client
        .list_tasks(
            ListTasksRequest {
                page_size: Some(1),
                ..Default::default()
            },
            None,
        )
        .await?;
    Ok(format!("total={}", list.total_size))
}

fn smoke_message(text: &str) -> Message {
    Message {
        kind: "message".into(),
        message_id: uuid::Uuid::new_v4().to_string(),
        context_id: None,
        task_id: None,
        role: Role::User,
        parts: vec![Part::text(text)],
        metadata: None,
        extensions: vec![],
        reference_task_ids: None,
    }
}
