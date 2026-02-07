# Contributing to A2A Rust Libraries

Thank you for your interest in contributing to the A2A Rust libraries! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- **Rust 1.75 or later** - Install via [rustup](https://rustup.rs/)
- **Git** - For version control

### Development Setup

```bash
# Clone the repository
git clone https://github.com/tkellogg/a2a-rs.git
cd a2a-rs

# Build all crates
cargo build

# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p a2a-rs-core
cargo test -p a2a-rs-server
cargo test -p a2a-rs-client
```

## Making Changes

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# Or for bug fixes
git checkout -b fix/issue-description
```

### 2. Make Your Changes

- Write clean, readable code
- Add tests for new functionality
- Update documentation as needed
- Keep commits focused and atomic

### 3. Run Checks

Before submitting, ensure everything passes:

```bash
cargo fmt              # Format code
cargo clippy -- -D warnings  # Lint
cargo test             # Run tests
cargo doc --no-deps    # Check docs build
```

### 4. Commit

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git commit -m "feat(server): add support for streaming responses"
git commit -m "fix(client): handle timeout errors gracefully"
git commit -m "docs(readme): update installation instructions"
```

**Commit Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`

## Pull Request Process

### PR Requirements

- [ ] All tests pass
- [ ] Code is formatted with `cargo fmt`
- [ ] No clippy warnings
- [ ] Documentation is updated (if applicable)
- [ ] PR description explains the changes

### Review Process

1. A maintainer will review your PR
2. Address any requested changes
3. Once approved, a maintainer will merge the PR

## Coding Standards

- Use `rustfmt` for formatting (`cargo fmt`)
- Use `clippy` for linting (`cargo clippy -- -D warnings`)
- Use `Result<T, E>` for fallible operations
- Prefer `thiserror` for library errors, `anyhow` for applications
- Add doc comments to all public items
- Follow standard Rust naming conventions

## Project Structure

```
a2a-rs/
├── a2a-rs-core/           # Shared types and utilities
│   └── src/
│       └── lib.rs      # All type definitions
├── a2a-rs-server/         # Server framework
│   ├── src/
│   │   ├── lib.rs      # Re-exports
│   │   ├── handler.rs  # MessageHandler trait
│   │   ├── server.rs   # A2aServer builder
│   │   ├── task_store.rs
│   │   ├── webhook_delivery.rs
│   │   └── webhook_store.rs
│   └── tests/
│       └── integration_tests.rs
├── a2a-rs-client/         # Client library
│   └── src/
│       ├── lib.rs      # Re-exports
│       └── client.rs   # A2aClient implementation
├── examples/           # Runnable examples
├── docs/               # Documentation
├── README.md
├── CONTRIBUTING.md     # This file
├── CHANGELOG.md
└── SECURITY.md
```

## Getting Help

- **Questions** - Open a [Discussion](../../discussions) or ask on an issue
- **Bugs** - Open an [Issue](../../issues)
- **Security** - See [SECURITY.md](SECURITY.md) for reporting vulnerabilities

Thank you for contributing!
