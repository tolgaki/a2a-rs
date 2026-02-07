# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

1. **GitHub Security Advisories** (Preferred)
   - Go to the repository's Security tab
   - Click "Report a vulnerability"
   - Fill out the security advisory form

2. **Email**
   - Open a private security advisory on GitHub

### What to Include

- A clear description of the vulnerability
- Impact assessment
- Affected crate(s) and version(s)
- Steps to reproduce
- Proof of concept (if applicable)

### Response Timeline

- **Acknowledgment** - Within 48 hours
- **Initial Assessment** - Within 7 days
- **Resolution** - Critical vulnerabilities within 30 days

## Security Considerations for Users

### Authentication

- Always use HTTPS in production
- Validate authentication tokens in your `auth_extractor`
- Use PKCE for OAuth flows (the client library enforces PKCE S256 by default)

### Input Validation

- Validate message content size in your handlers
- Sanitize file URIs before processing

### Network Security

- Bind to `127.0.0.1` for development, `0.0.0.0` only behind a reverse proxy
- Use a reverse proxy (Nginx, Caddy) for TLS termination and rate limiting

### In-Memory Task Store

The default `TaskStore` is in-memory:
- No persistence across restarts
- No automatic size limits or cleanup
- Consider implementing a custom store with TTL-based eviction for production

### Dependency Auditing

```bash
cargo install cargo-audit
cargo audit
```

We recommend running `cargo audit` regularly and in CI pipelines.
