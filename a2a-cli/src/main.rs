mod cli;
mod commands;
mod output;

use a2a_rs_client::{A2aClient, ClientConfig, Transport};
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tracing_subscriber::EnvFilter;

use crate::cli::{Binding, Cli, Command, GlobalArgs};
use crate::output::Renderer;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.global.verbose);

    let renderer = Renderer::new(cli.global.json);
    let http = build_http_client(&cli.global)?;

    // Smoke builds its own per-transport clients; everything else shares one.
    if matches!(cli.command, Command::Smoke) {
        return commands::smoke::run(cli.global.base_url, http).await;
    }

    let transport = match cli.global.binding {
        Binding::Jsonrpc => Transport::JsonRpc,
        Binding::Rest => Transport::Rest,
    };
    let client = A2aClient::new(ClientConfig {
        server_url: cli.global.base_url.clone(),
        http_client: Some(http),
        transport,
        ..Default::default()
    })?;

    match cli.command {
        Command::Card => commands::card::run(&client, &renderer).await,
        Command::Send(args) => commands::send::run(&client, &renderer, args).await,
        Command::Stream(args) => commands::stream::run(&client, &renderer, args).await,
        Command::Task(cmd) => commands::task::run(&client, &renderer, cmd).await,
        Command::Push(cmd) => commands::push::run(&client, &renderer, cmd).await,
        Command::Smoke => unreachable!("handled above"),
    }
}

fn init_tracing(verbosity: u8) {
    let default = match verbosity {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn build_http_client(args: &GlobalArgs) -> Result<reqwest::Client> {
    let mut headers = HeaderMap::new();

    if let Some(token) = &args.bearer_token {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid --bearer-token value")?;
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }

    for raw in &args.headers {
        let (name, value) = raw
            .split_once(':')
            .ok_or_else(|| anyhow!("--header must be NAME:VALUE, got {raw:?}"))?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .with_context(|| format!("invalid header name: {name:?}"))?;
        let value = HeaderValue::from_str(value.trim())
            .with_context(|| format!("invalid header value for {name}"))?;
        headers.insert(name, value);
    }

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;
    Ok(client)
}
