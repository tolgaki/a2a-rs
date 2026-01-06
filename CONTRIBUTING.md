# Contributing to A2A Rust Libraries

Thank you for your interest in contributing to the A2A Rust libraries! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Release Process](#release-process)
- [Getting Help](#getting-help)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

### Prerequisites

- **Rust 1.75 or later** - Install via [rustup](https://rustup.rs/)
- **Git** - For version control
- **A GitHub account** - For submitting pull requests

### Finding Issues to Work On

- Look for issues labeled [`good first issue`](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) for beginner-friendly tasks
- Issues labeled [`help wanted`](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) are ready for community contributions
- Feel free to ask questions on any issue before starting work

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/a2a.git
cd a2a/crates

# Add the upstream remote
git remote add upstream https://github.com/ORIGINAL_ORG/a2a.git
```

### 2. Build the Project

```bash
# Build all crates
cargo build

# Build with all features
cargo build --all-features
```

### 3. Run Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p a2a-core
cargo test -p a2a-server
cargo test -p a2a-client

# Run tests with output
cargo test -- --nocapture
```

### 4. Run the Echo Server (for manual testing)

```bash
# From the repository root
cargo run -p a2a-chat-server

# Test with curl
curl http://localhost:8080/.well-known/agent-card.json
```

## Making Changes

### 1. Create a Branch

```bash
# Sync with upstream
git fetch upstream
git checkout main
git merge upstream/main

# Create a feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

### 2. Make Your Changes

- Write clean, readable code following our [coding standards](#coding-standards)
- Add tests for new functionality
- Update documentation as needed
- Keep commits focused and atomic

### 3. Commit Your Changes

We follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages:

```bash
# Format: <type>(<scope>): <description>

# Examples:
git commit -m "feat(server): add support for streaming responses"
git commit -m "fix(client): handle timeout errors gracefully"
git commit -m "docs(readme): update installation instructions"
git commit -m "test(core): add tests for TaskState transitions"
git commit -m "refactor(handler): simplify error handling logic"
```

**Commit Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation changes
- `test` - Adding or updating tests
- `refactor` - Code refactoring (no functional changes)
- `perf` - Performance improvements
- `chore` - Maintenance tasks (dependencies, CI, etc.)

### 4. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Pull Request Process

### Before Submitting

1. **Run all checks locally:**
   ```bash
   # Format code
   cargo fmt

   # Run clippy lints
   cargo clippy -- -D warnings

   # Run tests
   cargo test

   # Check documentation builds
   cargo doc --no-deps
   ```

2. **Ensure your branch is up to date:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

### PR Requirements

- [ ] All tests pass
- [ ] Code is formatted with `cargo fmt`
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Documentation is updated (if applicable)
- [ ] Commit messages follow conventional commits
- [ ] PR description explains the changes

### PR Description Template

```markdown
## Summary
Brief description of what this PR does.

## Changes
- Change 1
- Change 2

## Testing
How was this tested?

## Related Issues
Fixes #123
```

### Review Process

1. A maintainer will review your PR
2. Address any requested changes
3. Once approved, a maintainer will merge the PR
4. Your contribution will be included in the next release

## Coding Standards

### Rust Style

We follow standard Rust conventions and use `rustfmt` for formatting:

```bash
# Format all code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check
```

### Code Guidelines

1. **Error Handling**
   - Use `Result<T, E>` for fallible operations
   - Prefer `thiserror` for library errors, `anyhow` for applications
   - Provide meaningful error messages

   ```rust
   // Good
   Err(HandlerError::InvalidInput("Message must contain at least one part".into()))

   // Avoid
   Err(HandlerError::InvalidInput("error".into()))
   ```

2. **Documentation**
   - Add doc comments to all public items
   - Include examples in doc comments where helpful

   ```rust
   /// Creates a new message with text content.
   ///
   /// # Arguments
   ///
   /// * `role` - The message role (User or Agent)
   /// * `text` - The text content
   /// * `context_id` - Optional conversation context ID
   ///
   /// # Example
   ///
   /// ```
   /// use a2a_core::{new_message, Role};
   ///
   /// let msg = new_message(Role::User, "Hello!", None);
   /// ```
   pub fn new_message(role: Role, text: &str, context_id: Option<String>) -> Message {
       // ...
   }
   ```

3. **Naming Conventions**
   - Use `snake_case` for functions, variables, modules
   - Use `PascalCase` for types and traits
   - Use `SCREAMING_SNAKE_CASE` for constants

4. **Async Code**
   - Use `async`/`await` consistently
   - Prefer `tokio` for async runtime
   - Use `async_trait` for async trait methods

5. **Dependencies**
   - Minimize dependencies where possible
   - Prefer well-maintained, widely-used crates
   - Document why a dependency is needed

### Clippy

We use clippy for additional linting:

```bash
cargo clippy -- -D warnings
```

Fix all warnings before submitting a PR.

## Testing

### Test Organization

```
crate/src/
├── lib.rs
├── module.rs
└── module/
    └── tests.rs  # Unit tests in separate file (optional)

# Or inline tests:
crate/src/lib.rs
    #[cfg(test)]
    mod tests {
        // ...
    }
```

### Writing Tests

1. **Unit Tests** - Test individual functions and modules

   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn test_task_state_is_terminal() {
           assert!(TaskState::Completed.is_terminal());
           assert!(TaskState::Failed.is_terminal());
           assert!(!TaskState::Working.is_terminal());
       }
   }
   ```

2. **Async Tests** - Use `#[tokio::test]`

   ```rust
   #[tokio::test]
   async fn test_client_fetch_agent_card() {
       let client = A2aClient::with_server("http://localhost:8080").unwrap();
       let card = client.fetch_agent_card().await.unwrap();
       assert!(!card.name.is_empty());
   }
   ```

3. **Integration Tests** - Place in `tests/` directory

   ```rust
   // tests/integration_test.rs
   use a2a_server::A2aServer;
   use a2a_client::A2aClient;

   #[tokio::test]
   async fn test_server_client_roundtrip() {
       // Start server, create client, test interaction
   }
   ```

### Test Coverage

- Aim for comprehensive test coverage of public APIs
- Test error cases, not just happy paths
- Test edge cases (empty inputs, large inputs, etc.)

## Documentation

### Types of Documentation

1. **Code Documentation** - Doc comments on public items
2. **README.md** - Project overview and quick start
3. **docs/** - Detailed guides and tutorials
4. **CHANGELOG.md** - Release notes

### Building Documentation

```bash
# Build and view documentation
cargo doc --no-deps --open

# Include private items
cargo doc --no-deps --document-private-items
```

### Documentation Guidelines

- Keep docs up-to-date with code changes
- Use examples that compile and run
- Link to related items using `[`item`]` syntax
- Explain "why" not just "what"

## Release Process

Releases are managed by maintainers. The general process:

1. Update version in `Cargo.toml` files
2. Update `CHANGELOG.md`
3. Create a git tag
4. Publish to crates.io

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** - Breaking API changes
- **MINOR** - New features (backwards compatible)
- **PATCH** - Bug fixes (backwards compatible)

## Project Structure

```
crates/
├── a2a-core/           # Shared types and utilities
│   └── src/
│       └── lib.rs      # All type definitions
├── a2a-server/         # Server framework
│   └── src/
│       ├── lib.rs      # Re-exports
│       ├── handler.rs  # MessageHandler trait
│       ├── server.rs   # A2aServer builder
│       └── task_store.rs
├── a2a-client/         # Client library
│   └── src/
│       ├── lib.rs      # Re-exports
│       └── client.rs   # A2aClient implementation
├── docs/               # Documentation
│   ├── architecture.md
│   └── getting-started.md
├── README.md
├── CONTRIBUTING.md     # This file
└── CHANGELOG.md
```

## Getting Help

- **Questions** - Open a [Discussion](../../discussions) or ask on an issue
- **Bugs** - Open an [Issue](../../issues/new?template=bug_report.md)
- **Features** - Open an [Issue](../../issues/new?template=feature_request.md)
- **Security** - See [SECURITY.md](SECURITY.md) for reporting vulnerabilities

## Recognition

Contributors are recognized in:
- Release notes
- The project README (for significant contributions)
- GitHub's contributor graph

Thank you for contributing to the A2A Rust libraries!
