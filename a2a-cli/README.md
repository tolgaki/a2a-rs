# a2a-cli

Sample command-line client for A2A v1.0 servers. Exercises the full public
surface of `a2a-rs-client` and doubles as a dev tool for iterating on
`a2a-rs-server`.

Not published to crates.io (`publish = false`). Run from the workspace.

## Run against a local server

```sh
# Terminal 1 — start any example server from this repo.
cargo run -p a2a-rs-server --example echo_server

# Terminal 2 — talk to it.
cargo run -p a2a-cli -- card
cargo run -p a2a-cli -- send "hello"
cargo run -p a2a-cli -- send "do work" --wait
cargo run -p a2a-cli -- stream "count to five"
cargo run -p a2a-cli -- task list
cargo run -p a2a-cli -- smoke
```

## Subcommands

| Command | Purpose |
|---|---|
| `card` | Fetch `/.well-known/agent-card.json` and pretty-print. |
| `send <TEXT> [--wait] [--context-id] [--task-id]` | Send a message; with `--wait` polls to a terminal state. |
| `stream <TEXT>` | Send a streaming message and print each SSE event. |
| `task get <ID> [--history-length N]` | Retrieve a task. |
| `task list [--context-id] [--page-size] [--page-token]` | List tasks. |
| `task cancel <ID>` | Cancel a task. |
| `task subscribe <ID>` | Follow a task via SSE until terminal. |
| `push add <TASK_ID> --url <WEBHOOK> [--config-id] [--token]` | Create a push notification config. |
| `smoke` | Run the full endpoint matrix (JSON-RPC + REST) against a running server and print pass/fail per check. |

## Global flags

| Flag | Purpose |
|---|---|
| `--base-url <URL>` | Server base URL. Default `http://127.0.0.1:8080`. |
| `--binding jsonrpc\|rest` | Transport binding. Default `jsonrpc`. |
| `--bearer-token <T>` | Sent as `Authorization: Bearer <T>`. |
| `--header NAME:VALUE` | Extra header. Repeatable. |
| `--json` | Emit JSON instead of pretty text. |
| `-v`, `-vv` | Increase tracing verbosity. |

## Install locally

```sh
cargo install --path a2a-cli
a2a-cli card --base-url http://localhost:8080
```
