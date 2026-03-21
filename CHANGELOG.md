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

## [1.0.4] - 2026-03-21

### Added

#### a2a-rs-core
- `Task.kind` field — always `"task"` (with serde default)
- `TaskStatusUpdateEvent.kind` field — always `"status-update"`
- `TaskStatusUpdateEvent.is_final` field (serializes as `"final"`) — signals last event in stream
- `TaskArtifactUpdateEvent.kind` field — always `"artifact-update"`
- `StreamingMessageResult` — untagged enum (`Task | Message | TaskStatusUpdateEvent | TaskArtifactUpdateEvent`) for SSE wire format

#### a2a-rs-server
- `message/stream` method — returns SSE directly from `/v1/rpc` endpoint
- SSE events wrapped in JSON-RPC response envelopes matching the A2A reference SDK
- `handle_rpc` returns `axum::response::Response` to support both JSON and SSE responses

#### a2a-rs-client
- `send_message_streaming()` — POSTs `message/stream` JSON-RPC request, returns `Pin<Box<dyn Stream<Item = Result<StreamingMessageResult>>>>`
- SSE line parser over reqwest byte stream
- New dependencies: `futures-core`, `async-stream`, `tokio-stream`

### Changed
- Streaming method renamed from `message/sendStreaming` to `message/stream`
- Removed separate `/v1/message/stream` endpoint — streaming is handled on `/v1/rpc`
- Removed two-step URL redirect for streaming

---

## [1.0.3] - 2026-03-21

### Changed

#### a2a-rs-core
- **Breaking**: `Role` serialization — `"ROLE_USER"` → `"user"`, `"ROLE_AGENT"` → `"agent"`
- **Breaking**: `TaskState` serialization — `"TASK_STATE_WORKING"` → `"working"`, `"TASK_STATE_INPUT_REQUIRED"` → `"input-required"`, etc.
- Added `Message.kind` field — always `"message"` (with serde default)

These values match the A2A JSON wire format spec and the Python reference SDK.

---

## [1.0.2] - 2026-03-21

### Changed

#### a2a-rs-core
- **Breaking**: `Part` converted from flat struct to internally-tagged enum with `kind` discriminator
  - `Part::Text` (`"kind": "text"`) — text content
  - `Part::File` (`"kind": "file"`) — file bytes or URI via `FileContent` struct
  - `Part::Data` (`"kind": "data"`) — structured JSON data
- Added `FileContent` struct with `bytes`, `uri`, `name`, `mime_type` fields
- Added `Part::as_text()` accessor method
- Renamed constructors: `Part::url()` → `Part::file_uri()`, `Part::raw()` → `Part::file_bytes()`
- `Part::data()` no longer takes a `media_type` parameter
- Added `SendMessageResult` — untagged enum for wire format (Task or Message directly in JSON-RPC result field)

#### a2a-rs-server
- Server serializes Task/Message directly into JSON-RPC result field (no `{"task": {...}}` wrapper)

#### a2a-rs-client
- `send_message()` returns `SendMessageResult` (was `SendMessageResponse`)

---

## [1.0.0] - 2025-01-15

### Changed

This is a major release aligning all types with the **A2A RC 1.0 proto spec**.

#### a2a-rs-core
- **Breaking**: `PROTOCOL_VERSION` updated from `"0.3.0"` to `"1.0"`
- **Breaking**: `AgentCard` — `description` is now required `String` (was `Option<String>`)
- **Breaking**: `AgentCard` — removed `endpoint`, `url`, `preferred_transport`, `additional_interfaces` fields. Endpoints are now in `supported_interfaces: Vec<AgentInterface>`
- **Breaking**: `AgentCard` — `security_schemes` is now `HashMap<String, SecurityScheme>` (was `Vec<SecurityScheme>`)
- **Breaking**: `AgentCard` — `security` renamed to `security_requirements`
- **Breaking**: `AgentInterface` — `transport` renamed to `protocol_binding`, added `protocol_version` and `tenant` fields
- **Breaking**: `AgentProvider` — `name` renamed to `organization`, `url` is now required `String`, removed `email`
- **Breaking**: `SecurityScheme` — changed from internally tagged to externally tagged enum with wrapper structs
- **Breaking**: `OAuthFlows` — changed from struct with optional fields to externally tagged enum
- **Breaking**: `SecurityRequirement` — replaced `scheme_name`/`scopes` with `schemes: HashMap<String, StringList>`
- **Breaking**: `Part` — changed from tagged enum to flat struct with optional fields
- **Breaking**: `StreamEvent` renamed to `StreamResponse`
- **Breaking**: `TaskStatusUpdateEvent` — added required `context_id`, `metadata`; removed `timestamp`
- **Breaking**: `TaskArtifactUpdateEvent` — added required `context_id`, `append`, `last_chunk`, `metadata`
- **Breaking**: Request param types renamed
- **Breaking**: Task IDs are now direct UUIDs (no `tasks/` prefix)

#### a2a-rs-server
- Updated all handlers for RC 1.0 type changes
- `MessageHandler::handle_message` now returns `HandlerResult<SendMessageResponse>`

#### a2a-rs-client
- Updated for renamed request types and direct ID fields

---

## [0.1.0] - 2024-01-15

### Added
- Initial release with A2A 0.3.0 specification support
- `a2a-rs-core`: Complete type definitions, JSON-RPC types, helper functions
- `a2a-rs-server`: `MessageHandler` trait, `A2aServer` builder, `TaskStore`, `EchoHandler`
- `a2a-rs-client`: `A2aClient` with agent card caching, polling, OAuth PKCE support

---

## Links

- [A2A Protocol Specification](https://github.com/google/A2A)
- [Documentation](docs/)
- [Contributing](CONTRIBUTING.md)

[Unreleased]: ../../compare/v1.0.4...HEAD
[1.0.4]: ../../compare/v1.0.3...v1.0.4
[1.0.3]: ../../compare/v1.0.2...v1.0.3
[1.0.2]: ../../compare/v1.0.0...v1.0.2
[1.0.0]: ../../compare/v0.1.0...v1.0.0
[0.1.0]: ../../releases/tag/v0.1.0
