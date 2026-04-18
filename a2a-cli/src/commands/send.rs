use a2a_rs_client::A2aClient;
use a2a_rs_core::{Message, Part, Role, SendMessageResult};
use anyhow::Result;

use crate::cli::SendArgs;
use crate::output::Renderer;

pub async fn run(client: &A2aClient, renderer: &Renderer, args: SendArgs) -> Result<()> {
    let message = Message {
        kind: "message".into(),
        message_id: uuid::Uuid::new_v4().to_string(),
        context_id: args.context_id,
        task_id: args.task_id,
        role: Role::User,
        parts: vec![Part::text(args.text)],
        metadata: None,
        extensions: vec![],
        reference_task_ids: None,
    };

    let result = client.send_message(message, None, None).await?;

    match result {
        SendMessageResult::Task(task) => {
            if args.wait && !task.status.state.is_terminal() {
                let final_task = client.poll_until_complete(&task.id, None).await?;
                renderer.task(&final_task)
            } else {
                renderer.task(&task)
            }
        }
        SendMessageResult::Message(msg) => renderer.message(&msg),
    }
}
