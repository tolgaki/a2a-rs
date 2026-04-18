use a2a_rs_client::A2aClient;
use a2a_rs_core::{ListTasksRequest, StreamingMessageResult, TaskState};
use anyhow::Result;
use tokio_stream::StreamExt;

use crate::cli::TaskCommand;
use crate::output::Renderer;

pub async fn run(client: &A2aClient, renderer: &Renderer, cmd: TaskCommand) -> Result<()> {
    match cmd {
        TaskCommand::Get { task_id, history_length } => {
            let task = client.get_task(&task_id, history_length, None).await?;
            renderer.task(&task)
        }
        TaskCommand::List { context_id, page_size, page_token } => {
            let req = ListTasksRequest {
                context_id,
                page_size,
                page_token,
                ..Default::default()
            };
            let list = client.list_tasks(req, None).await?;
            renderer.task_list(&list)
        }
        TaskCommand::Cancel { task_id } => {
            let task = client.cancel_task(&task_id, None).await?;
            renderer.task(&task)
        }
        TaskCommand::Subscribe { task_id } => {
            let mut stream = client.subscribe_to_task(&task_id, None).await?;
            while let Some(event) = stream.next().await {
                let event = event?;
                renderer.stream_event(&event)?;
                if is_terminal(&event) {
                    break;
                }
            }
            Ok(())
        }
    }
}

fn is_terminal(event: &StreamingMessageResult) -> bool {
    let state = match event {
        StreamingMessageResult::StatusUpdate(u) => u.status.state,
        StreamingMessageResult::Task(t) => t.status.state,
        _ => return false,
    };
    matches!(
        state,
        TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Rejected
    )
}
