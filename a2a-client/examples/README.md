# a2a-rs-client Examples

All examples demonstrate the [A2A v1.0 protocol](https://github.com/a2aproject/A2A) client side using the `a2a-rs-client` and `a2a-rs-core` crates.

## Running

Start a server first (any of the server examples), then:

```sh
cargo run -p a2a-rs-client --example <name> [-- <server_url>]
```

## Examples

### `simple_client` — Agent Discovery and Messaging

Connects to an A2A server, fetches the agent card, sends a message, and handles the response.

```sh
# Terminal 1: start a server
cargo run --example echo_server

# Terminal 2: run the client
cargo run -p a2a-rs-client --example simple_client
# Or point to a different server:
cargo run -p a2a-rs-client --example simple_client -- http://localhost:3000
```

Demonstrates:
- `A2aClient::new(config)` — creating a client
- `client.fetch_agent_card()` — discovering agent capabilities
- `client.send_message(msg, None, None)` — sending messages
- Handling `SendMessageResult::Task` vs `SendMessageResult::Message` responses

---

### `polling_client` — Task Polling

Sends a message to an agent that returns a non-terminal task (Working), then polls until the task reaches a terminal state.

```sh
# Terminal 1: start the echo server (auto-completes after 2s)
cargo run --example echo_server

# Terminal 2:
cargo run -p a2a-rs-client --example polling_client
```

Demonstrates:
- `client.get_task(task_id, history_length, token)` — fetching task status
- Polling loop with `TaskState::is_terminal()` check
- Configurable poll interval and max attempts via `ClientConfig`
