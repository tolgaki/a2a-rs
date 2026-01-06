# Changelog

All notable changes to the A2A Rust libraries will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Fixed
- Nothing yet

---

## [0.1.0] - 2024-01-15

### Added

#### a2a-core
- Complete A2A 0.3.0 specification type definitions
- `AgentCard` - Agent discovery and capability declaration
- `Message` - Multimodal message structure with `Part` variants:
  - `TextPart` - Plain text or markdown content
  - `FilePart` - File references (URI or base64 bytes)
  - `DataPart` - Structured JSON data
- `Task` - Task lifecycle management with state tracking
- `TaskState` - Full state machine: `Submitted`, `Working`, `InputRequired`, `Completed`, `Failed`, `Cancelled`, `Rejected`, `AuthRequired`
- `TaskStatus` - Status wrapper with optional message and timestamp
- `Artifact` - Output artifacts from task processing
- Security scheme definitions:
  - `ApiKey` - API key authentication (header, query, cookie)
  - `Http` - HTTP Basic/Bearer authentication
  - `OAuth2` - OAuth 2.0 flows (authorization code, client credentials, implicit, password)
  - `OpenIdConnect` - OpenID Connect discovery
  - `MutualTls` - Mutual TLS authentication
- JSON-RPC 2.0 types: `JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcError`
- A2A-specific error codes (`TASK_NOT_FOUND`, `TASK_NOT_CANCELABLE`, etc.)
- Helper functions:
  - `new_message()` - Create messages with text content
  - `completed_task_with_text()` - Create completed tasks with responses
  - `now_iso8601()` - Generate ISO 8601 timestamps
  - `validate_task_id()` - UUID validation
  - `extract_task_id()` - Parse resource names
  - `success()` / `error()` - JSON-RPC response builders
- Method parameter types: `MessageSendParams`, `TaskQueryParams`, `TaskCancelParams`, `TaskListParams`
- Streaming event types: `StreamEvent`, `TaskStatusUpdateEvent`, `TaskArtifactUpdateEvent`
- Push notification configuration types

#### a2a-server
- `MessageHandler` trait - Pluggable backend abstraction
  - `handle_message()` - Process incoming messages
  - `agent_card()` - Return agent capabilities
  - `cancel_task()` - Optional cancellation handling
  - `supports_streaming()` - Streaming capability flag
- `A2aServer` - Fluent builder for server configuration
  - `new()` - Create with custom handler
  - `echo()` - Create with built-in echo handler
  - `bind()` - Set server address
  - `task_store()` - Custom task storage
  - `auth_extractor()` - Authentication callback
  - `additional_routes()` - Custom HTTP endpoints
  - `build_router()` - Get Axum router for embedding
  - `run()` - Start the server
- `TaskStore` - Thread-safe in-memory task storage
  - `insert()` - Store tasks
  - `get()` - Retrieve by exact ID
  - `get_flexible()` - Retrieve with ID format normalization
  - `update()` - Modify tasks with closure
  - `remove()` - Delete tasks
  - `list()` - Get all tasks
- `EchoHandler` - Built-in demo handler
- `AuthContext` - Authentication context (user_id, access_token, metadata)
- `HandlerError` - Typed error variants:
  - `ProcessingFailed`
  - `BackendUnavailable`
  - `AuthRequired`
  - `InvalidInput`
  - `Internal`
- HTTP endpoints:
  - `GET /health` - Health check
  - `GET /.well-known/agent-card.json` - Agent card discovery
  - `POST /v1/rpc` - JSON-RPC endpoint
- JSON-RPC methods:
  - `message/send` - Send messages to agent
  - `tasks/get` - Query task status
  - `tasks/cancel` - Cancel running tasks
- `AppState` - Shared state for custom routes

#### a2a-client
- `A2aClient` - Full-featured A2A client
  - `new()` - Create with configuration
  - `with_server()` - Quick creation with server URL
  - `fetch_agent_card()` - Discover agent (5-minute cache)
  - `invalidate_card_cache()` - Force cache refresh
  - `send_message()` - Send messages to agents
  - `poll_task()` - Query task status
  - `poll_until_complete()` - Poll until terminal state
  - `perform_oauth_interactive()` - Interactive OAuth flow
  - `start_oauth_flow()` - Programmatic OAuth initiation
- `ClientConfig` - Client configuration
  - `server_url` - Base server URL
  - `max_polls` - Maximum polling attempts
  - `poll_interval_ms` - Polling interval
  - `oauth` - Optional OAuth configuration
- `OAuthConfig` - OAuth PKCE flow configuration
  - `client_id` - OAuth client ID
  - `redirect_uri` - Callback URL
  - `scopes` - Requested scopes
  - `session_token` - Pre-existing token
- PKCE utilities:
  - `generate_code_verifier()` - Random verifier generation
  - `generate_code_challenge()` - S256 challenge computation
  - `generate_random_string()` - State parameter generation

#### Documentation
- Comprehensive README with examples
- Architecture guide with diagrams
- Getting started tutorial
- Contributing guidelines

### Security
- PKCE S256 implementation for OAuth flows
- Bearer token authentication support
- Session-based authentication with JWT
- No hardcoded secrets in codebase

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.0 | 2024-01-15 | Initial release with full A2A 0.3.0 support |

---

## Migration Guides

### Upgrading to 0.1.0

This is the initial release. No migration required.

---

## Links

- [A2A Protocol Specification](https://github.com/a2a-protocol/a2a-spec)
- [Documentation](docs/)
- [Contributing](CONTRIBUTING.md)
- [Issue Tracker](../../issues)

[Unreleased]: ../../compare/v0.1.0...HEAD
[0.1.0]: ../../releases/tag/v0.1.0
