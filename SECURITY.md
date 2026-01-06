# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to the repository's Security tab
   - Click "Report a vulnerability"
   - Fill out the security advisory form

2. **Email**
   - Send an email to: [security@example.com](mailto:security@example.com)
   - Use the subject line: `[SECURITY] A2A Rust Libraries - <brief description>`

### What to Include

Please include the following information in your report:

- **Description** - A clear description of the vulnerability
- **Impact** - What an attacker could achieve by exploiting this vulnerability
- **Affected Components** - Which crate(s) and version(s) are affected
- **Reproduction Steps** - Step-by-step instructions to reproduce the issue
- **Proof of Concept** - Code or commands that demonstrate the vulnerability (if applicable)
- **Suggested Fix** - If you have ideas on how to fix the issue (optional)

### Response Timeline

- **Acknowledgment** - We will acknowledge receipt within 48 hours
- **Initial Assessment** - We will provide an initial assessment within 7 days
- **Resolution** - We aim to resolve critical vulnerabilities within 30 days

### Disclosure Policy

- We follow [Coordinated Vulnerability Disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure)
- We will work with you to understand and resolve the issue
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We ask that you do not publicly disclose the vulnerability until we have released a fix

## Security Considerations

### For Library Users

When using the A2A libraries, consider the following security best practices:

#### Authentication

1. **Always use HTTPS in production**
   ```rust
   // Good - HTTPS
   let client = A2aClient::with_server("https://api.example.com")?;

   // Avoid in production - HTTP
   let client = A2aClient::with_server("http://api.example.com")?;
   ```

2. **Validate authentication tokens**
   ```rust
   A2aServer::new(handler)
       .auth_extractor(|headers| {
           let token = extract_bearer_token(headers)?;

           // Always validate tokens - don't just trust them
           let claims = validate_jwt(token)?;

           // Check expiration, issuer, audience, etc.
           if claims.exp < current_time() {
               return None;
           }

           Some(AuthContext { /* ... */ })
       })
       .run()
       .await?;
   ```

3. **Use PKCE for OAuth flows**
   - The client library enforces PKCE S256 by default
   - Never use the implicit flow for public clients

#### Input Validation

1. **Validate message content**
   ```rust
   async fn handle_message(
       &self,
       message: Message,
       auth: Option<AuthContext>,
   ) -> HandlerResult<Task> {
       // Validate message size
       let total_size: usize = message.parts.iter()
           .map(|p| match p {
               Part::Text(t) => t.text.len(),
               Part::File(f) => f.bytes.as_ref().map(|b| b.len()).unwrap_or(0),
               Part::Data(d) => d.data.to_string().len(),
           })
           .sum();

       if total_size > MAX_MESSAGE_SIZE {
           return Err(HandlerError::InvalidInput("Message too large".into()));
       }

       // Continue processing...
   }
   ```

2. **Sanitize file URIs**
   ```rust
   // Validate file URIs before processing
   fn validate_file_uri(uri: &str) -> bool {
       let url = match Url::parse(uri) {
           Ok(u) => u,
           Err(_) => return false,
       };

       // Only allow HTTPS
       if url.scheme() != "https" {
           return false;
       }

       // Block internal/private networks
       // ... additional validation

       true
   }
   ```

#### Secrets Management

1. **Never hardcode secrets**
   ```rust
   // Good - Use environment variables
   let api_key = std::env::var("API_KEY")?;

   // Bad - Hardcoded secret
   let api_key = "sk-1234567890abcdef";
   ```

2. **Use secure secret storage in production**
   - AWS Secrets Manager
   - HashiCorp Vault
   - Azure Key Vault
   - Google Secret Manager

#### Network Security

1. **Bind to localhost for development**
   ```rust
   // Development
   A2aServer::new(handler)
       .bind("127.0.0.1:8080")  // Only localhost
       .run()
       .await?;

   // Production - behind a reverse proxy
   A2aServer::new(handler)
       .bind("0.0.0.0:8080")  // All interfaces
       .run()
       .await?;
   ```

2. **Use a reverse proxy in production**
   - Nginx, Caddy, or cloud load balancers
   - Handle TLS termination at the proxy
   - Implement rate limiting
   - Add request size limits

### Known Security Considerations

#### In-Memory Task Store

The default `TaskStore` is in-memory and has the following characteristics:

- **No persistence** - Tasks are lost on restart
- **No size limits** - Can grow unbounded
- **No automatic cleanup** - Old tasks are not evicted

For production use, consider:
- Implementing a custom task store with persistence
- Adding TTL-based eviction
- Setting maximum task limits

```rust
// Example: Custom task store with limits
pub struct BoundedTaskStore {
    tasks: Arc<RwLock<HashMap<String, Task>>>,
    max_tasks: usize,
}

impl BoundedTaskStore {
    pub async fn insert(&self, task: Task) -> Result<(), Error> {
        let mut tasks = self.tasks.write().await;

        if tasks.len() >= self.max_tasks {
            // Evict oldest task or return error
            return Err(Error::StoreFull);
        }

        tasks.insert(task.id.clone(), task);
        Ok(())
    }
}
```

#### Error Information Disclosure

Be careful not to expose internal error details to clients:

```rust
// Bad - Exposes internal details
Err(HandlerError::Internal(anyhow!("Database connection failed: {}", db_error)))

// Good - Generic message, log details internally
tracing::error!("Database error: {}", db_error);
Err(HandlerError::BackendUnavailable("Service temporarily unavailable".into()))
```

### Dependency Security

We regularly audit dependencies for known vulnerabilities:

```bash
# Install cargo-audit
cargo install cargo-audit

# Check for vulnerabilities
cargo audit
```

### Security Updates

Security updates are released as patch versions (e.g., 0.1.1, 0.1.2) and announced via:

- GitHub Security Advisories
- Release notes in CHANGELOG.md
- GitHub Releases

We recommend:
- Subscribing to repository notifications
- Regularly updating dependencies
- Running `cargo audit` in CI/CD pipelines

## Security Checklist for Deployments

Before deploying to production, ensure:

- [ ] HTTPS is enabled for all endpoints
- [ ] Authentication is properly configured
- [ ] Input validation is implemented
- [ ] Rate limiting is in place
- [ ] Request size limits are configured
- [ ] Secrets are stored securely (not in code or config files)
- [ ] Logging does not include sensitive data
- [ ] Error messages do not expose internal details
- [ ] Dependencies are up to date
- [ ] `cargo audit` shows no vulnerabilities
- [ ] Server binds to appropriate interfaces
- [ ] Firewall rules are configured

## Acknowledgments

We thank the following individuals for responsibly disclosing security issues:

- *No security issues reported yet*

---

Thank you for helping keep the A2A ecosystem secure!
