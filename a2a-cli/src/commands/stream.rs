use a2a_rs_client::A2aClient;
use a2a_rs_core::{Message, Part, Role, StreamingMessageResult, TaskState};
use anyhow::Result;
use tokio_stream::StreamExt;

use crate::cli::StreamArgs;
use crate::output::Renderer;

pub async fn run(client: &A2aClient, renderer: &Renderer, args: StreamArgs) -> Result<()> {
    let message = Message {
        kind: "message".into(),
        message_id: uuid::Uuid::new_v4().to_string(),
        context_id: None,
        task_id: None,
        role: Role::User,
        parts: vec![Part::text(args.text)],
        metadata: None,
        extensions: vec![],
        reference_task_ids: None,
    };

    let mut stream = client.send_message_streaming(message, None, None).await?;

    while let Some(event) = stream.next().await {
        let event = event?;
        renderer.stream_event(&event)?;
        if is_terminal(&event) {
            break;
        }
    }
    Ok(())
}

fn is_terminal(event: &StreamingMessageResult) -> bool {
    match event {
        StreamingMessageResult::StatusUpdate(u) => is_terminal_state(u.status.state),
        StreamingMessageResult::Task(t) => is_terminal_state(t.status.state),
        _ => false,
    }
}

fn is_terminal_state(state: TaskState) -> bool {
    state.is_terminal()
}
