use a2a_rs_client::A2aClient;
use anyhow::Result;

use crate::output::Renderer;

pub async fn run(client: &A2aClient, renderer: &Renderer) -> Result<()> {
    let card = client.fetch_agent_card().await?;
    renderer.card(&card)
}
