use a2a_rs_client::A2aClient;
use a2a_rs_core::PushNotificationConfig;
use anyhow::Result;

use crate::cli::PushCommand;
use crate::output::Renderer;

pub async fn run(client: &A2aClient, renderer: &Renderer, cmd: PushCommand) -> Result<()> {
    match cmd {
        PushCommand::Add { task_id, url, config_id, token } => {
            let config_id = config_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let config = PushNotificationConfig {
                id: Some(config_id.clone()),
                url,
                token,
                authentication: None,
            };
            let created = client
                .create_push_notification_config(&task_id, &config_id, config, None)
                .await?;
            renderer.emit(&created)?;
            if !renderer.json {
                println!(
                    "Created push config {} for task {} -> {}",
                    created.id, created.task_id, created.url
                );
            }
            Ok(())
        }
    }
}
