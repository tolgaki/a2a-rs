//! Echo server example
//!
//! Run with: cargo run --example echo_server
//!
//! Then test with:
//!   curl http://127.0.0.1:8080/.well-known/agent-card.json
//!   curl http://127.0.0.1:8080/health
//!   curl -X POST http://127.0.0.1:8080/v1/rpc \
//!     -H "Content-Type: application/json" \
//!     -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"messageId":"msg-1","role":"ROLE_USER","parts":[{"text":"Hello!"}]}}}'

use a2a_rs_server::A2aServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing for log output
    tracing_subscriber::fmt::init();

    println!("Starting A2A Echo Server on http://127.0.0.1:8080");
    println!("Agent card: http://127.0.0.1:8080/.well-known/agent-card.json");
    println!("Health:     http://127.0.0.1:8080/health");

    A2aServer::echo()
        .bind("127.0.0.1:8080")
        .expect("valid bind address")
        .run()
        .await
}
