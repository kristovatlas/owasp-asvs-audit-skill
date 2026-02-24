# V16: Security Logging and Error Handling

**ASVS Version:** 5.0.0
**Source file:** `5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md`

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

Security logs are distinct from error or performance logs and are used to record security-relevant events such as authentication decisions, access control decisions, and attempts to bypass security controls, such as input validation or business logic validation. Their purpose is to support detection, response, and investigation by providing high-signal, structured data for analysis tools like SIEMs.

Logs should not include sensitive personal data unless legally required, and any logged data must be protected as a high-value asset. Logging must not compromise privacy or system security. Applications must also fail securely, avoiding unnecessary disclosure or disruption.

For detailed implementation guidance, refer to the OWASP Cheat Sheets in the references section.

---

## V16.1: Security Logging Documentation

This section ensures a clear and complete inventory of logging across the application stack. This is essential for effective security monitoring, incident response, and compliance.

| # | Requirement | Level |
|---|-------------|-------|
| **16.1.1** | Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept. | 2 |

### Audit Guidance for V16.1

**General approach:** This is a documentation requirement. The sub-agent should look for evidence of a documented logging inventory that covers the application's logging posture comprehensively.

**16.1.1 — Logging inventory documentation:**

What to look for:
- Architecture or operations documentation describing the logging strategy: what is logged, where logs are stored, log formats in use, retention periods, and access controls.
- Logging configuration files that implicitly document the logging posture (e.g., `log4j2.xml`, `logback.xml`, `serilog.json`, `logging.conf`, `winston` transport configurations, `pino` configurations, Monolog handler definitions).
- Infrastructure-as-code files (Terraform, CloudFormation, Pulumi, Kubernetes manifests) that define log aggregation pipelines, log storage destinations (CloudWatch, Elasticsearch, Splunk, Datadog), and retention policies.
- README, ADR, wiki, or dedicated docs describing which layers produce logs (application, web server, database, infrastructure) and how they are collected.
- If logging is implemented in code but no documentation exists describing the overall inventory (what, where, how long, who can access), this is a finding -- the logging exists but the inventory documentation requirement is not met.

N/A conditions: This requirement cannot be N/A -- every application should have a logging inventory.

---

## V16.2: General Logging

This section provides requirements to ensure that security logs are consistently structured and contain the expected metadata. The goal is to make logs machine-readable and analyzable across distributed systems and tools.

Naturally, security events often involve sensitive data. If such data is logged without consideration, the logs themselves become classified and therefore subject to encryption requirements, stricter retention policies, and potential disclosure during audits.

Therefore, it is critical to log only what is necessary and to treat log data with the same care as other sensitive assets.

The requirements below establish foundational requirements for logging metadata, synchronization, format, and control.

| # | Requirement | Level |
|---|-------------|-------|
| **16.2.1** | Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens. | 2 |
| **16.2.2** | Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions. | 2 |
| **16.2.3** | Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory. | 2 |
| **16.2.4** | Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format. | 2 |
| **16.2.5** | Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially. | 2 |

### Audit Guidance for V16.2

**16.2.1 — Log entry metadata (when, where, who, what):**

What to look for:
- Log statements that include structured metadata fields: timestamp, source/component, user identity (user ID, session ID, IP address), and the event description.
- **Good patterns:** Structured logging libraries that automatically attach context -- `structlog` (Python), `serilog` (C#), `logrus`/`zap`/`slog` (Go), `winston`/`pino` (Node.js), `SLF4J` + MDC (Java), `Monolog` with processors (PHP), `SemanticLogger` (Ruby). These typically allow attaching request-scoped context (user ID, request ID, trace ID) to every log entry.
- **Good patterns:** Middleware or filters that set logging context per request -- `MDC.put("userId", ...)` (Java), `structlog.contextvars` (Python), `cls-hooked` / `AsyncLocalStorage` (Node.js), `Log::withContext()` (Laravel).
- **Red flags:** Plain `print()`, `console.log()`, `System.out.println()` used for security events with no structured metadata. Log messages that contain only a text string with no timestamp, user identifier, or source component.
- Check that security-relevant logs (authentication events, authorization failures, etc.) include at minimum: timestamp, user/session identifier, source IP or request identifier, and a description of the event.

Language-specific patterns:
- **Python:** `logging` module with custom formatters, `structlog` with bound loggers and context variables.
- **Node.js:** `winston` with `defaultMeta` or custom formats, `pino` with `child()` loggers carrying context, `bunyan` with serializers.
- **Java:** SLF4J with MDC (Mapped Diagnostic Context), Log4j2 `ThreadContext`, Logback with `%X{userId}` pattern.
- **PHP:** Monolog with processors (`WebProcessor`, `UidProcessor`, custom processors adding user context).
- **Ruby:** `Rails.logger` with `tagged()` logging, `SemanticLogger` with named tags.
- **Go:** `slog` with `With()` for context fields, `zap` with `With()` fields, `logrus` with `WithFields()`.
- **C#:** Serilog with `LogContext.PushProperty()`, NLog with `MappedDiagnosticsLogicalContext`, Microsoft.Extensions.Logging with scopes.

**16.2.2 — Synchronized time sources and UTC timestamps:**

What to look for:
- Logging configuration that specifies UTC or includes explicit timezone offsets in timestamp formats.
- **Good patterns:** Logging formatters configured with ISO 8601 format including timezone (`2024-01-15T14:30:00Z` or `2024-01-15T14:30:00+00:00`). Server/container infrastructure configured with NTP synchronization.
- **Red flags:** Timestamps in local time without timezone offset. Different components logging in different timezones. No explicit timestamp format configuration (relying on locale-dependent defaults).
- Check logging configuration files for timestamp format strings: `%Y-%m-%dT%H:%M:%S%z` (Python), `yyyy-MM-dd'T'HH:mm:ss.SSSZ` (Java), `toISOString()` (JavaScript).
- Infrastructure-level NTP configuration is typically outside application code scope -- mark as MANUAL_REVIEW if application-level timestamp configuration looks correct but infrastructure synchronization cannot be verified from code alone.

**16.2.3 — Logs stored only in documented destinations:**

What to look for:
- Compare actual log output destinations (configured transports, appenders, handlers) against what is documented in the logging inventory (per 16.1.1).
- **Red flags:** Ad-hoc logging to undocumented files (`open("debug.log", "a")`), logging to stdout/stderr in production without documented collection, third-party services receiving logs that are not documented, debug logging to local files left in production code.
- Check for development/debug logging configurations that might be active in production: `console` transports, file appenders writing to `/tmp`, debug log levels enabled.
- If no logging inventory documentation exists (16.1.1 fails), this requirement cannot be fully verified -- mark as MANUAL_REVIEW.

**16.2.4 — Logs readable and correlatable by the log processor:**

What to look for:
- **Good patterns:** Structured logging in JSON format (widely supported by log processors), Common Log Format, or other well-defined formats. Consistent use of a single logging format across the application.
- **Good patterns:** Correlation identifiers: request IDs, trace IDs (OpenTelemetry, Jaeger, Zipkin), session IDs present in log entries to enable cross-component correlation.
- **Red flags:** Mixed log formats across components (some JSON, some plaintext, some custom). Unstructured free-text log messages with no parseable fields. Multi-line log entries (stack traces) that are not properly delimited for log ingestion.
- Check logging library configurations for output format: JSON formatters, structured output, consistent field naming.

**16.2.5 — Sensitive data protection in logs:**

What to look for:
- **Critical red flags (FAIL):** Logging passwords, API keys, secret tokens, credit card numbers, social security numbers, or other credentials in plaintext. Look for log statements that include request bodies, authorization headers, or full user objects without filtering.
- **Red flags:** Logging full session tokens, JWTs, or bearer tokens in plaintext. Logging PII (email addresses, phone numbers, full names) without documented justification.
- **Good patterns:** Redaction/masking utilities applied before logging -- masking all but last 4 digits of card numbers, hashing session tokens before logging, filtering sensitive fields from request/response logs. Dedicated scrubbing middleware or log processors that strip sensitive fields.
- **Good patterns:** Logging frameworks configured with sensitive field filters -- Serilog `Destructure.ByTransforming`, Log4j2 pattern with `%replace`, custom formatters that redact known sensitive keys.

Language-specific patterns:
- **Node.js:** `pino` with `redact` option for paths like `["req.headers.authorization", "req.body.password"]`. Custom `serializers` in `pino`/`bunyan`.
- **Python:** `structlog` processors that filter sensitive keys, custom `logging.Filter` classes.
- **Java:** Log4j2 `PatternLayout` with `%replace` or custom `RewritePolicy`. Logback `MaskingPatternLayout`.
- **Rails:** `config.filter_parameters` for filtering sensitive params from logs (`:password`, `:token`, `:secret`).
- **Laravel:** Middleware or logging tap classes that redact sensitive request data.
- **Go:** Custom `slog.Handler` implementations that redact values for specific keys.

N/A conditions: This requirement cannot be N/A -- any application that logs must consider sensitive data handling.

---

## V16.3: Security Events

This section defines requirements for logging security-relevant events within the application. Capturing these events is critical for detecting suspicious behavior, supporting investigations, and fulfilling compliance obligations.

This section outlines the types of events that should be logged but does not attempt to provide exhaustive detail. Each application has unique risk factors and operational context.

Note that while ASVS includes logging of security events in scope, alerting and correlation (e.g., SIEM rules or monitoring infrastructure) are considered out of scope and are handled by operational and monitoring systems.

| # | Requirement | Level |
|---|-------------|-------|
| **16.3.1** | Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected. | 2 |
| **16.3.2** | Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself). | 2 |
| **16.3.3** | Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation. | 2 |
| **16.3.4** | Verify that the application logs unexpected errors and security control failures such as backend TLS failures. | 2 |

### Audit Guidance for V16.3

**16.3.1 — Authentication event logging:**

What to look for:
- Log statements in authentication flows (login, logout, registration, password reset, MFA challenge, token refresh) that capture both successful and failed outcomes.
- **Good patterns:** Authentication middleware or service layer that logs: event type (login_success, login_failure, logout, password_reset_requested), user identifier (username or user ID, not password), IP address, authentication method/factor used (password, OTP, SSO, API key), timestamp.
- **Red flags:** Authentication endpoints that return success/failure responses but produce no log entries. Login failures that are silently handled without logging. Only successful logins logged (missing failed attempts, which are critical for detecting brute-force attacks).
- Check authentication controllers, middleware, identity providers, and security filter chains for log statements.

Language-specific patterns:
- **Spring Security:** `AuthenticationSuccessHandler`/`AuthenticationFailureHandler` implementations, `ApplicationEventPublisher` with `AuthenticationSuccessEvent`/`AuthenticationFailureBadCredentialsEvent`, `AuditApplicationEvent`.
- **Django:** `django.contrib.auth.signals` (`user_logged_in`, `user_logged_out`, `user_login_failed`), `django-axes` for tracking failed attempts, custom authentication backend logging.
- **Rails/Devise:** `Warden::Manager.after_authentication`, `Warden::Manager.before_failure` callbacks, `devise` event hooks.
- **Node.js/Passport:** Logging in `passport.authenticate()` callbacks, custom middleware wrapping authentication routes.
- **Laravel:** Event listeners for `Illuminate\Auth\Events\Login`, `Illuminate\Auth\Events\Failed`, `Illuminate\Auth\Events\Logout`.
- **ASP.NET Identity:** `ILogger` in `SignInManager`, custom `ISecurityStampValidator`, Identity events.

**16.3.2 — Authorization event logging:**

What to look for:
- Log statements in authorization middleware, access control checks, and permission enforcement points that capture denied access attempts.
- **Good patterns:** Authorization middleware that logs when access is denied: resource requested, user identity, required permission/role, denial reason. At L3, logging all authorization decisions (both grants and denials) for sensitive resources.
- **Red flags:** Authorization checks that silently return 403/401 without logging. RBAC/ABAC enforcement with no audit trail. Access to sensitive data (financial records, PII, admin panels) with no logging of who accessed what.
- Check authorization decorators, middleware, policy classes, and guard implementations.

Language-specific patterns:
- **Spring Security:** `AccessDeniedHandler` with logging, `@PreAuthorize`/`@Secured` with AOP-based audit logging, Spring Security `AuthorizationEvent`.
- **Django:** Logging in permission classes, `django-guardian` audit, custom `has_permission()` overrides with logging.
- **Rails:** `Pundit` or `CanCanCan` with `rescue_from` handlers that log authorization failures.
- **Node.js:** Logging in CASL ability checks, custom middleware logging `req.user` and denied resource.
- **Laravel:** Logging in Gate/Policy checks, `Gate::after()` callback for audit logging.
- **Go:** Logging in middleware that checks JWT claims, RBAC middleware with denial logging.

**16.3.3 — Security event and bypass attempt logging:**

What to look for:
- Log statements that capture security-relevant events as defined by the application's documentation (per 16.1.1), including input validation failures, business logic violations, and anti-automation triggers.
- **Good patterns:** Input validation libraries or middleware that log rejected inputs with context (which field, what rule was violated, user/request identifier). Rate limiter middleware that logs when limits are exceeded. CSRF validation failures logged. Business rule violations (e.g., exceeding transaction limits) logged.
- **Red flags:** Validation frameworks that reject input and return error responses but produce no server-side log entry. Rate limiting that blocks requests silently. Security controls that fail without any logging trail.
- Check input validation middleware, CSRF protection, rate limiters, WAF integration, and business rule enforcement for log statements.

**16.3.4 — Unexpected error and security control failure logging:**

What to look for:
- Global error handlers, exception handlers, and catch blocks that log unexpected errors with sufficient context (error type, message, stack trace for internal logs, request context).
- **Good patterns:** Centralized error handling middleware that catches unhandled exceptions and logs them. TLS/SSL connection failure logging (e.g., when connecting to backend services, databases, external APIs). Circuit breaker libraries that log when backends become unavailable. Logging of certificate validation failures, connection timeouts to security-critical services.
- **Red flags:** Empty catch blocks (`catch (e) {}`), catch blocks that swallow errors without logging. Backend connection failures (database, cache, external API) that are silently retried or ignored. TLS errors suppressed or only surfaced as generic user-facing errors.
- Check error handling middleware, HTTP client configurations, database connection error handling, and TLS/SSL configuration for logging of failures.

Language-specific patterns:
- **Node.js:** `process.on('uncaughtException')`, `process.on('unhandledRejection')`, Express error middleware `app.use((err, req, res, next) => {...})`.
- **Python:** `logging.exception()` in except blocks, Django `LOGGING` configuration with `django.request` logger, Flask `@app.errorhandler`.
- **Java:** `@ControllerAdvice` / `@ExceptionHandler` (Spring), `javax.servlet.Filter` for error logging, Log4j2 with `%throwable`.
- **Go:** Error return value checking with logging, `recover()` in deferred functions with logging.
- **C#:** Global exception filters (`IExceptionFilter`), middleware `app.UseExceptionHandler()`, `Serilog.Exceptions`.
- **Ruby:** `rescue_from` in Rails controllers, Rack middleware for error logging, `config.exceptions_app`.

---

## V16.4: Log Protection

Logs are valuable forensic artifacts and must be protected. If logs can be easily modified or deleted, they lose their integrity and become unreliable for incident investigations or legal proceedings. Logs may expose internal application behavior or sensitive metadata, making them an attractive target for attackers.

This section defines requirements to ensure that logs are protected from unauthorized access, tampering, and disclosure, and that they are safely transmitted and stored in secure, isolated systems.

| # | Requirement | Level |
|---|-------------|-------|
| **16.4.1** | Verify that all logging components appropriately encode data to prevent log injection. | 2 |
| **16.4.2** | Verify that logs are protected from unauthorized access and cannot be modified. | 2 |
| **16.4.3** | Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised. | 2 |

### Audit Guidance for V16.4

**16.4.1 — Log injection prevention:**

What to look for:
- **Critical red flags (FAIL):** User-controlled input concatenated directly into log messages without encoding or sanitization. This can allow attackers to inject fake log entries, corrupt log structure, or exploit log viewers (e.g., terminal escape sequences, ANSI codes).
- **Attack vectors:** Newline injection (`\n`, `\r\n`) to forge log entries, CRLF injection, control characters, and format string attacks in languages that support them.
- **Good patterns:** Structured logging (JSON format) where user input is placed into data fields rather than the log message template -- this inherently prevents log injection because values are properly escaped by the serializer. Parameterized log messages: `logger.info("User {} logged in", userId)` rather than `logger.info("User " + userId + " logged in")`.
- **Good patterns:** Logging libraries that automatically encode or escape special characters. Log4j2 `%encode{%msg}` pattern, custom sanitization functions applied before logging user input.
- **Red flags:** String concatenation or interpolation of user input into log messages: `logger.info(f"Login attempt for {username}")` (Python), `logger.info("Login attempt for " + username)` (Java), `console.log(\`Login attempt for ${username}\`)` (JS).

Language-specific patterns:
- **Python:** Use `logger.info("Login for %s", username)` (parameterized) rather than f-strings. `structlog` with JSON rendering handles escaping automatically.
- **Java:** SLF4J parameterized logging `logger.info("Login for {}", username)` is safe. Log4j2 `%encode{CRLF}` layout option. Avoid `logger.info("Login for " + username)`.
- **Node.js:** `pino` and `winston` with JSON format handle this inherently. Avoid `console.log("Login for " + userInput)`.
- **Go:** `slog.Info("login", "user", username)` (structured) is safe. Avoid `log.Printf("Login for %s", username)` if username could contain newlines.
- **PHP:** Monolog with JSON formatter handles escaping. Avoid `error_log("Login for " . $username)`.
- **C#:** Serilog `Log.Information("Login for {Username}", username)` (structured) is safe. Avoid string interpolation `$"Login for {username}"` in log messages.

**16.4.2 — Log access control and integrity:**

What to look for:
- **Good patterns:** Log files with restrictive file permissions (e.g., readable only by the logging service account, not world-readable). Logs stored in append-only storage. Log management systems with role-based access controls. Immutable log storage (e.g., AWS CloudWatch, Azure Monitor, write-once storage buckets).
- **Red flags:** Log files stored in web-accessible directories. Log files with world-readable permissions (`chmod 644` or `777`). Application code that has delete or modify access to its own log files. Logs stored in the same database as application data without access controls.
- Check file permission configurations, log storage locations, and infrastructure-as-code for log access policies.
- This often requires infrastructure review beyond application code -- mark as MANUAL_REVIEW if log access controls are not configurable within the application codebase.

N/A conditions: This requirement cannot be N/A -- any application producing logs must protect them.

**16.4.3 — Secure log transmission to separate system:**

What to look for:
- **Good patterns:** Logs shipped to a centralized logging system (ELK/Elasticsearch, Splunk, Datadog, AWS CloudWatch, Azure Monitor, Google Cloud Logging) via encrypted channels (TLS). Log forwarders (Fluentd, Fluent Bit, Logstash, Filebeat, Vector) configured with TLS transport. Separate log aggregation infrastructure not co-located with the application.
- **Red flags:** Logs stored only on the application server's local filesystem with no forwarding. Log transmission over unencrypted channels (plaintext syslog over UDP). Log aggregation system running on the same server as the application (not logically separate).
- Check for log shipping configurations in infrastructure-as-code, Docker/Kubernetes logging drivers, sidecar containers for log forwarding, and logging library transport configurations.
- This is primarily an infrastructure concern -- mark as MANUAL_REVIEW if the application code configures log outputs but the transport and destination infrastructure cannot be verified from the codebase alone.

---

## V16.5: Error Handling

This section defines requirements to ensure that applications fail gracefully and securely without disclosing sensitive internal details.

| # | Requirement | Level |
|---|-------------|-------|
| **16.5.1** | Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens. | 2 |
| **16.5.2** | Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation. | 2 |
| **16.5.3** | Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic. | 2 |
| **16.5.4** | Verify that a "last resort" error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability. | 3 |

> Note: Certain languages, (including Swift, Go, and through common design practice, many functional languages,) do not support exceptions or last-resort event handlers. In this case, architects and developers should use a pattern, language, or framework-friendly way to ensure that applications can securely handle exceptional, unexpected, or security-related events.

### Audit Guidance for V16.5

**16.5.1 — Generic error messages (no information leakage):**

What to look for:
- **Critical red flags (FAIL):** Stack traces, SQL queries, internal file paths, framework version numbers, or debug information returned in HTTP responses to clients. Exception details (class names, line numbers, internal method names) exposed in API error responses. Database error messages (e.g., "ORA-", "SQLSTATE", "Duplicate entry for key") forwarded to the user. Secret keys, tokens, or connection strings in error responses.
- **Good patterns:** Generic error messages returned to users ("An unexpected error occurred. Please try again later.") with detailed errors logged server-side only. Custom error pages for 4xx/5xx responses that reveal no internal details. Centralized error response formatting that strips internal details before returning to the client.
- **Red flags per environment:** Debug mode enabled in production -- `DEBUG=True` (Django), `APP_DEBUG=true` (Laravel), `NODE_ENV=development` (Node.js), `ASPNETCORE_ENVIRONMENT=Development` (ASP.NET), `spring.profiles.active=dev` (Spring). Detailed error pages (e.g., Django debug page, Laravel Whoops, Spring Boot Whitelabel error page with stack trace) active in production configuration.

Language-specific patterns:
- **Django:** Check `settings.py` for `DEBUG = False` in production. Custom `handler500`, `handler404`. `REST_FRAMEWORK` exception handler configuration.
- **Express/Node.js:** Error middleware that sends `err.message` or `err.stack` to the client. Check for `app.use((err, req, res, next) => { res.status(500).json({ error: err.message }) })` -- `err.message` may leak internal details. Should return a generic message instead.
- **Spring Boot:** Check `server.error.include-stacktrace=never`, `server.error.include-message=never`. Custom `@ControllerAdvice` with `@ExceptionHandler` that returns generic messages. Avoid `ResponseEntity.status(500).body(exception.getMessage())`.
- **Laravel:** Check `.env` for `APP_DEBUG=false` in production. Custom exception rendering in `Handler.php` or `bootstrap/app.php`.
- **Rails:** Check `config/environments/production.rb` for `config.consider_all_requests_local = false`. Custom error pages in `public/500.html`.
- **Go:** Check HTTP handlers for `http.Error(w, err.Error(), 500)` -- this sends the internal error message to the client.
- **Flask:** Check for `app.debug = False` or `FLASK_DEBUG=0` in production. Custom error handlers via `@app.errorhandler(500)`.
- **ASP.NET:** Check for `app.UseDeveloperExceptionPage()` guarded by `if (env.IsDevelopment())`. Custom `UseExceptionHandler` middleware for production.

**16.5.2 — Secure operation when external resources fail:**

What to look for:
- **Good patterns:** Circuit breaker implementations (`resilience4j` in Java, `Polly` in C#, `opossum` in Node.js, `pybreaker` in Python, `circuitbreaker` in Go). Retry logic with backoff and maximum retry limits. Fallback/default values when external services are unavailable. Graceful degradation: disabling non-critical features when dependencies are down rather than failing entirely. Timeout configurations on all external connections (HTTP clients, database connections, cache connections).
- **Red flags:** External API calls with no timeout configured (can hang indefinitely). No error handling around external service calls (unhandled connection errors crash the application). Application health entirely dependent on external service availability with no fallback. Missing timeout on database connection pools.
- Check HTTP client configurations, database connection configurations, cache client configurations, and message queue consumers for timeout settings and error handling.

Language-specific patterns:
- **Java:** `resilience4j` CircuitBreaker, Retry, TimeLimiter. Spring `@Retryable`, `RestTemplate`/`WebClient` timeout configuration.
- **Node.js:** `axios` timeout configuration, `opossum` circuit breaker, `node-fetch` with `AbortController` timeout.
- **Python:** `requests` timeout parameter, `httpx` timeout, `tenacity` retry library, `pybreaker`.
- **Go:** `http.Client{Timeout: ...}`, context-based timeouts (`context.WithTimeout`), circuit breaker packages.
- **C#:** `Polly` for retry, circuit breaker, timeout, and fallback policies. `HttpClient` timeout configuration.
- **Ruby:** `faraday` with retry middleware, `circuit_breaker` gem, `Net::HTTP` timeout settings.

N/A conditions: May be N/A for applications with no external service dependencies (rare). If the application calls any external APIs, databases, caches, or message queues, this requirement applies.

**16.5.3 — Fail-secure (no fail-open conditions):**

What to look for:
- **Critical red flags (FAIL):** Catch blocks that swallow validation errors and proceed with processing: `try { validate(input) } catch { processAnyway(input) }`. Authorization checks wrapped in try-catch that default to allowing access on failure. Payment/transaction processing that continues despite validation errors. Security controls (CSRF checks, authentication, rate limiting) that fail open -- if the check throws an error, the request is allowed through.
- **Good patterns:** Security checks that default to deny on error. Validation errors that halt processing and return error responses. Transactions that roll back on any error. Security middleware that rejects the request if it cannot verify the security condition (e.g., if the auth token cannot be validated due to an error, deny access rather than allowing it).
- **Red flags:** Overly broad catch blocks (`catch (Exception e)`, `except Exception`, `rescue => e`) around security-critical code that continue execution on the happy path. Conditional logic where the error/default path permits the action: `isAuthorized = true; try { isAuthorized = checkAuth() } catch { /* use default */ }`.
- Check security middleware, input validation flows, payment processing, and authorization logic for error handling that might result in fail-open behavior.

**16.5.4 — Last-resort error handler (catch-all):**

What to look for:
- **Good patterns:** Global/last-resort exception handlers that catch any unhandled exception, log it with full context, and return a safe generic response.

Language-specific patterns:
- **Node.js:** `process.on('uncaughtException', handler)`, `process.on('unhandledRejection', handler)`. Express: final error-handling middleware `app.use((err, req, res, next) => {...})` registered last. Note: `uncaughtException` handler should log and gracefully shut down, not attempt to continue.
- **Python/Django:** Custom `MIDDLEWARE` exception handler at the top of the middleware stack. Django `handler500` view. Flask `@app.errorhandler(Exception)`. `sys.excepthook` for non-web applications.
- **Java/Spring:** `@ControllerAdvice` with `@ExceptionHandler(Exception.class)` as a catch-all. Servlet `error-page` configuration in `web.xml`. `Thread.setDefaultUncaughtExceptionHandler()`.
- **C#/ASP.NET:** `app.UseExceptionHandler()` middleware, global `IExceptionFilter`, `AppDomain.CurrentDomain.UnhandledException` handler.
- **Rails:** `rescue_from StandardError` in `ApplicationController`. Rack middleware for catch-all error handling.
- **PHP/Laravel:** `report()` and `render()` methods in the exception handler. `set_exception_handler()` and `set_error_handler()` at the PHP level.
- **Go:** `recover()` in deferred functions at the top of goroutine call stacks. HTTP middleware that wraps handler execution in a recover block. Note: Go does not have exceptions -- `recover()` catches panics, but the idiomatic approach is explicit error return value checking.
- **Swift:** No traditional exception handler -- use `do/catch` at top-level entry points and signal handlers for crashes. Ensure all `throws` functions are called within `do/catch` blocks.

> Note per ASVS: Certain languages (including Swift, Go, and through common design practice, many functional languages) do not support exceptions or last-resort event handlers. In this case, architects and developers should use a pattern, language, or framework-friendly way to ensure that applications can securely handle exceptional, unexpected, or security-related events.

N/A conditions: This requirement is L3 only. It cannot be N/A for L3 applications -- every application should have a last-resort error handler appropriate to its language and framework.

---

## References

For more information, see also:

* [OWASP Web Security Testing Guide: Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/README)
* [OWASP Authentication Cheat Sheet section about error messages](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages)
* [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
* [OWASP Application Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html)

---

## V16 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 0 | -- |
| L2 | 15 | 16.1.1, 16.2.1, 16.2.2, 16.2.3, 16.2.4, 16.2.5, 16.3.1, 16.3.2, 16.3.3, 16.3.4, 16.4.1, 16.4.2, 16.4.3, 16.5.1, 16.5.2, 16.5.3 |
| L3 | 1 | 16.5.4 |
| **Total** | **16** | |
