use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum Binding {
    #[default]
    Jsonrpc,
    Rest,
}

#[derive(Debug, Parser)]
#[command(
    name = "a2a-cli",
    about = "Sample CLI for A2A v1.0 servers, built on a2a-rs-client",
    version
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Server base URL (omit path — e.g. http://localhost:8080).
    #[arg(long, default_value = "http://127.0.0.1:8080", global = true)]
    pub base_url: String,

    /// Transport binding (jsonrpc or rest). Both hit the same server.
    #[arg(long, value_enum, default_value_t = Binding::Jsonrpc, global = true)]
    pub binding: Binding,

    /// Bearer token; sent as `Authorization: Bearer <token>`.
    #[arg(long, global = true)]
    pub bearer_token: Option<String>,

    /// Extra headers. Repeatable: `--header X-Foo:bar --header X-Baz:qux`.
    #[arg(long = "header", value_name = "NAME:VALUE", global = true)]
    pub headers: Vec<String>,

    /// Emit machine-readable JSON instead of pretty text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Verbosity: -v for info, -vv for debug. Maps to RUST_LOG.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Fetch and display the agent card from /.well-known/agent-card.json.
    Card,
    /// Send a text message.
    Send(SendArgs),
    /// Send a streaming message and print each SSE event.
    Stream(StreamArgs),
    /// Task operations: get / list / cancel / subscribe.
    #[command(subcommand)]
    Task(TaskCommand),
    /// Push notification configuration — happy-path `add`.
    #[command(subcommand)]
    Push(PushCommand),
    /// Run a matrix of endpoint checks against a running server.
    Smoke,
}

#[derive(Debug, Args)]
pub struct SendArgs {
    /// Text to send.
    pub text: String,

    /// Wait (poll) until the task reaches a terminal state.
    #[arg(long)]
    pub wait: bool,

    /// Existing context ID to attach the message to.
    #[arg(long)]
    pub context_id: Option<String>,

    /// Existing task ID to attach the message to.
    #[arg(long)]
    pub task_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct StreamArgs {
    /// Text to send.
    pub text: String,
}

#[derive(Debug, Subcommand)]
pub enum TaskCommand {
    /// Get a task by ID.
    Get {
        task_id: String,
        /// Message history depth.
        #[arg(long)]
        history_length: Option<i32>,
    },
    /// List tasks, optionally filtered.
    List {
        /// Filter by context ID.
        #[arg(long)]
        context_id: Option<String>,
        /// Page size (1-100).
        #[arg(long)]
        page_size: Option<i32>,
        /// Pagination cursor.
        #[arg(long)]
        page_token: Option<String>,
    },
    /// Cancel a task.
    Cancel { task_id: String },
    /// Subscribe to task updates via SSE until a terminal event.
    Subscribe { task_id: String },
}

#[derive(Debug, Subcommand)]
pub enum PushCommand {
    /// Add a push notification config for a task.
    Add {
        task_id: String,
        /// Webhook URL that will receive notifications.
        #[arg(long)]
        url: String,
        /// Optional config ID (generated if omitted).
        #[arg(long)]
        config_id: Option<String>,
        /// Optional webhook auth token.
        #[arg(long)]
        token: Option<String>,
    },
}
