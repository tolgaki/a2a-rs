# a2a-rs-server Examples

All examples demonstrate the [A2A v1.0 protocol](https://github.com/a2aproject/A2A) using the `a2a-rs-server` and `a2a-rs-core` crates.

## Running

```sh
# From the workspace root
cargo run --example <name>
```

## Examples

### `echo_server` — Minimal Agent

The simplest possible A2A agent. 5 lines of code, full protocol compliance.

```sh
cargo run --example echo_server
curl http://localhost:8080/.well-known/agent-card.json | jq .name
curl -X POST http://localhost:8080/ -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"Hello!"}]}}}'
```

**Key concept:** `A2aServer::echo()` gives you a ready-to-run agent with zero configuration.

---

### `custom_handler` — Skills, Artifacts, Routing

A greeting agent with two skills (greet and time). Shows how to:
- Implement `MessageHandler` to route messages by content
- Build a rich `AgentCard` with skills, provider info, and capabilities
- Return structured data as artifacts

```sh
cargo run --example custom_handler
curl -s http://localhost:3000/.well-known/agent-card.json | jq '.skills[].name'
# "Greeting"
# "Current Time"
```

**Key concept:** The `MessageHandler` trait is the only thing you implement. Everything else (routing, agent card serving, task storage, error handling) is handled by the framework.

---

### `streaming_agent` — SSE Streaming

Demonstrates the A2A streaming protocol where the agent returns incremental updates over Server-Sent Events.

```sh
cargo run --example streaming_agent
curl -N -X POST http://localhost:8080/v1/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{"message":{"messageId":"s1","role":"ROLE_USER","parts":[{"text":"Tell me a story"}]}}}'
```

You'll see SSE events arrive one by one:
```
data: {"jsonrpc":"2.0","id":1,"result":{"task":{...,"status":{"state":"TASK_STATE_WORKING"}}}}
data: {"jsonrpc":"2.0","id":1,"result":{"artifactUpdate":{...,"parts":[{"text":"Once upon a time, "}]}}}
data: {"jsonrpc":"2.0","id":1,"result":{"artifactUpdate":{...,"parts":[{"text":"in a land of agents, "}]}}}
...
data: {"jsonrpc":"2.0","id":1,"result":{"statusUpdate":{...,"status":{"state":"TASK_STATE_COMPLETED"}}}}
```

**Key concept:** The handler returns a Working task immediately. A background `tokio::spawn` sends incremental events via the broadcast channel (`event_tx`). The server delivers them as SSE.

---

### `push_notifications` — Webhook Delivery

Shows the push notification lifecycle: register a webhook, send a message, receive the webhook callback.

```sh
cargo run --example push_notifications
# Starts the agent (port 8080) AND a webhook receiver (port 9090)
# Then runs through the full lifecycle automatically
```

**Key concept:** The server has a built-in webhook delivery engine with retry, exponential backoff, and authentication. Just set `push_notifications: Some(true)` in capabilities.

---

### `multi_agent` — Agent-to-Agent Delegation

Two agents running on different ports. The Coordinator receives user messages and delegates to a Worker agent using `a2a-rs-client`.

```sh
cargo run --example multi_agent
# Worker starts on port 3002, Coordinator on port 3001
```

**Key concept:** A2A agents can be both servers AND clients. The coordinator uses `A2aClient` to discover and call the worker, then combines results.

---

## Internal Test Infrastructure

### `tck_server` — TCK Conformance SUT

*Not a user-facing sample.* This is a System Under Test for the [A2A TCK](https://github.com/a2aproject/a2a-tck) conformance suite. It routes behavior based on `messageId` prefix to exercise every protocol scenario. See [tck_server.rs](tck_server.rs) for details.
