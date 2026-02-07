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
- **Breaking**: `SecurityScheme` — changed from internally tagged to externally tagged enum with wrapper structs: `ApiKeySecurityScheme`, `HttpAuthSecurityScheme`, `OAuth2SecurityScheme`, `OpenIdConnectSecurityScheme`, `MutualTlsSecurityScheme`
- **Breaking**: `OAuthFlows` — changed from struct with optional fields to externally tagged enum: `AuthorizationCode`, `ClientCredentials`, `Implicit`, `Password`, `DeviceCode`. Scopes changed from `Vec<String>` to `HashMap<String, String>`
- **Breaking**: `SecurityRequirement` — replaced `scheme_name`/`scopes` with `schemes: HashMap<String, StringList>`
- **Breaking**: `AgentCardSignature` — changed to JWS format: `protected`, `signature`, `header`
- **Breaking**: `AgentSkill` — removed `input_schema`/`output_schema`, added `examples`, `input_modes`, `output_modes`, `security_requirements`
- **Breaking**: `Part` — changed from tagged enum (`Part::Text(TextPart)`) to flat struct with optional fields (`text`, `raw`, `url`, `data`, `metadata`, `filename`, `media_type`)
- **Breaking**: `StreamEvent` renamed to `StreamResponse`
- **Breaking**: `TaskStatusUpdateEvent` — added required `context_id`, `metadata`; removed `timestamp`
- **Breaking**: `TaskArtifactUpdateEvent` — added required `context_id`, `append`, `last_chunk`, `metadata`; removed `timestamp`
- **Breaking**: `AuthenticationInfo.credentials` changed from `String` to `Option<String>`
- **Breaking**: Request param types renamed: `MessageSendParams` -> `SendMessageRequest`, `TaskQueryParams` -> `GetTaskRequest`, `TaskCancelParams` -> `CancelTaskRequest`, `TaskListParams` -> `ListTasksRequest`, `TaskSubscribeParams` -> `SubscribeToTaskRequest`
- **Breaking**: Push notification param types renamed and restructured with direct `task_id`/`id` fields instead of resource name parsing
- **Breaking**: Task IDs are now direct UUIDs (no `tasks/` prefix)
- **Breaking**: Removed `ApiKeyLocation` enum, `ResourceName` struct, `extract_task_id()` function, `TRANSPORT_JSONRPC` constant
- Added `DeviceCodeOAuthFlow` type
- Added `TaskPushNotificationConfig`, `ListTaskPushNotificationConfigResponse`, `GetExtendedAgentCardRequest` types
- Added `StringList` helper struct
- Added error code `EXTENSION_SUPPORT_REQUIRED` (-32009)
- Added `AgentExtension.params` field

#### a2a-rs-server
- Updated all handlers for RC 1.0 type changes
- `MessageHandler::handle_message` now returns `HandlerResult<SendMessageResponse>` (was `HandlerResult<Task>`)
- Updated `EchoHandler` for new `AgentCard`, `AgentProvider`, `AgentInterface`, `AgentSkill` types
- Updated all JSON-RPC method handlers for renamed request types and direct ID fields

#### a2a-rs-client
- Updated `send_message` to use `SendMessageRequest` (was `MessageSendParams`)
- Updated `poll_task` to use `GetTaskRequest` with direct `id` field (was `TaskQueryParams` with `name`)
- Updated endpoint resolution for new `AgentInterface.protocol_binding` field

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

[Unreleased]: ../../compare/v1.0.0...HEAD
[1.0.0]: ../../compare/v0.1.0...v1.0.0
[0.1.0]: ../../releases/tag/v0.1.0
