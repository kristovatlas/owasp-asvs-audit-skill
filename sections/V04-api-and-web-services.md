# V4: API and Web Service

**ASVS Version:** 5.0.0
**Source file:** `5.0/en/0x13-V4-API-and-Web-Service.md`

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

Several considerations apply specifically to applications that expose APIs for use by web browsers or other consumers (commonly using JSON, XML, or GraphQL). This chapter covers the relevant security configurations and mechanisms that should be applied.

Note that authentication, session management, and input validation concerns from other chapters also apply to APIs, so this chapter cannot be taken out of context or tested in isolation.

---

## V4.1: Generic Web Service Security

This section addresses general web service security considerations and, consequently, basic web service hygiene practices.

| # | Requirement | Level |
|---|-------------|-------|
| **4.1.1** | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | 1 |
| **4.1.2** | Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered. | 2 |
| **4.1.3** | Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID. | 2 |
| **4.1.4** | Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked. | 3 |
| **4.1.5** | Verify that per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems. | 3 |

### Audit Guidance for V4.1

**4.1.1 — Content-Type header with charset:**

What to look for:
- Every HTTP response that includes a body should set a `Content-Type` header that accurately reflects the media type and includes a `charset` parameter (e.g., `Content-Type: application/json; charset=utf-8`).
- Check framework-level defaults and any explicit overrides in response-building code.

Language-specific patterns:
- **Express/Node.js:** `res.type()`, `res.set('Content-Type', ...)`, `res.json()` (automatically sets `application/json; charset=utf-8`). Check that custom responses (e.g., `res.send()` with string content) also have a correct Content-Type. Look for middleware like `helmet` which can help enforce headers.
- **Django:** Responses created with `HttpResponse(content_type=...)` or `JsonResponse` (auto-sets `application/json`). Check that the `DEFAULT_CHARSET` setting is `utf-8` (default). Look for views returning raw `HttpResponse` without specifying content type.
- **Flask:** `make_response()` calls and `Response` objects. Check `response.content_type`. Flask sets `text/html; charset=utf-8` by default for string returns; `jsonify()` sets `application/json`.
- **Spring (Java):** `@Produces` annotations, `MediaType` constants, `ResponseEntity` builder with `.contentType()`. Check `application.properties` for `spring.http.encoding.charset=UTF-8`. Verify `@RestController` methods returning custom `ResponseEntity` objects set the Content-Type.
- **ASP.NET/C#:** Check `Response.ContentType` assignments, `Produces` attributes on controllers, and `Content()` or `Ok()` result helpers. `System.Text.Json` and `Newtonsoft.Json` serializers default to `application/json`.
- **Rails:** `render json:` auto-sets Content-Type. Check custom `render` calls and `send_data`/`send_file` for explicit content type setting.
- **Go:** `http.ResponseWriter.Header().Set("Content-Type", ...)`. Go's `net/http` does content sniffing via `http.DetectContentType()` if not set, which is unreliable. Check that handlers explicitly set Content-Type before writing the response body.
- **PHP:** `header('Content-Type: ...')` calls. Laravel's `response()->json()` sets it automatically. Check raw PHP scripts and custom response helpers.

Red flags:
- Responses that omit Content-Type entirely.
- Responses where Content-Type does not match the actual body content (e.g., returning JSON with `text/html`).
- Missing charset parameter, especially on `text/*` types.
- Reliance on browser content sniffing (no `X-Content-Type-Options: nosniff` header).

Safe patterns:
- Framework defaults that auto-set Content-Type with charset for standard response helpers (`res.json()`, `JsonResponse`, `jsonify()`, `render json:`).
- Middleware or filters that enforce Content-Type and `X-Content-Type-Options: nosniff` globally.

N/A conditions:
- Endpoints that return no body (e.g., `204 No Content`, `304 Not Modified`) do not need a Content-Type header.

**4.1.2 — HTTP-to-HTTPS redirect policy:**

What to look for:
- User-facing browser endpoints (HTML pages) may redirect HTTP to HTTPS. This is acceptable and common.
- API endpoints, machine-to-machine service endpoints, webhooks, and internal service endpoints should NOT automatically redirect from HTTP to HTTPS. They should either reject HTTP requests outright (return an error) or only listen on HTTPS.
- The concern is that transparent redirects mask the fact that the initial request was sent unencrypted, which could leak sensitive data (tokens, credentials, PII) in transit.

Language-specific patterns:
- **Nginx/Apache:** Check for blanket `return 301 https://...` or `RewriteRule` in server configs. Are they scoped only to user-facing locations, or do they apply to API paths as well?
- **Express/Node.js:** Middleware like `express-sslify`, `helmet.hsts()`, or custom redirect middleware. Check if redirect logic differentiates between browser and API routes.
- **Django:** `SECURE_SSL_REDIRECT` setting — if `True`, it redirects all HTTP to HTTPS. Check `SECURE_REDIRECT_EXEMPT` for API path exemptions. Ideally, API endpoints should return `400` or `403` on HTTP rather than redirect.
- **Spring:** `http.requiresChannel().anyRequest().requiresSecure()` redirects all. Check for differentiation between web and API security configurations.
- **Rails:** `config.force_ssl = true` applies a blanket redirect. Check if API routes are excluded from this behavior.

Red flags:
- Blanket HTTP-to-HTTPS redirect covering all endpoints including APIs.
- No mechanism to distinguish API from browser endpoints in redirect configuration.

Safe patterns:
- HTTPS-only listeners for API endpoints (no HTTP port open).
- API endpoints that return `400 Bad Request` or refuse connection on plain HTTP, while browser endpoints redirect.
- Reverse proxy configurations that separate API and web traffic handling.

N/A conditions:
- Applications that are HTTPS-only with no HTTP listener at all (PASS by default).
- Internal services that never accept external HTTP traffic.

**4.1.3 — Intermediary header field protection:**

What to look for:
- Headers set by intermediary layers (load balancers, reverse proxies, API gateways, BFF services) such as `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-User-ID`, `X-Request-ID`, or custom internal headers must not be spoofable by end users.
- The intermediary should strip or overwrite these headers from incoming client requests before adding its own values.

Language-specific patterns:
- **Nginx:** `proxy_set_header X-Real-IP $remote_addr;` overwrites client-supplied values. Check that the upstream application trusts only these proxy-set values. Verify `real_ip_header` and `set_real_ip_from` directives restrict trusted proxy sources.
- **Express/Node.js:** `app.set('trust proxy', ...)` — check the value. `trust proxy` set to `true` trusts all proxies (unsafe in some configurations). Prefer specific IP/CIDR ranges (`trust proxy`, `'loopback'`, `'10.0.0.0/8'`). Libraries: `express` built-in trust proxy, `proxy-addr`.
- **Django:** `SECURE_PROXY_SSL_HEADER` should be set carefully. `USE_X_FORWARDED_HOST`, `USE_X_FORWARDED_PORT` should only be enabled if the proxy is trusted and strips client-sent values. Check `ALLOWED_HOSTS`.
- **Spring:** `server.forward-headers-strategy` setting. If set to `NATIVE` or `FRAMEWORK`, Spring trusts forwarded headers. Ensure the reverse proxy strips/overwrites these before forwarding.
- **Go:** Check if the application reads `r.Header.Get("X-Forwarded-For")` or `r.Header.Get("X-Real-IP")` directly. If so, verify the proxy overwrites these headers.
- **Rails:** `ActionDispatch::RemoteIp` middleware — check `config.action_dispatch.trusted_proxies` to ensure only known proxies are trusted.

Red flags:
- Application reads `X-Forwarded-For` or `X-Real-IP` directly from the request without proxy-level header stripping.
- `trust proxy` set to `true` (trust all) in Express without known proxy infrastructure.
- No proxy configuration to strip or overwrite client-supplied intermediary headers.
- Custom internal headers (e.g., `X-User-ID` for internal auth) accepted without proxy-level enforcement.

Safe patterns:
- Reverse proxy configured to unconditionally overwrite forwarded headers with its own values.
- Application configured to trust only known proxy IP ranges.
- Internal headers accepted only from trusted internal network segments.

**4.1.4 — HTTP method restriction:**

What to look for:
- The application should only respond to HTTP methods that it explicitly supports. Unsupported methods (e.g., `TRACE`, `PUT`, `DELETE`, `PATCH` if unused, `CONNECT`) should return `405 Method Not Allowed`.
- `OPTIONS` must be allowed for CORS preflight requests if the API supports cross-origin access.

Language-specific patterns:
- **Express/Node.js:** Route definitions (`app.get()`, `app.post()`, etc.) inherently limit methods per route. Check for `app.all()` or `app.use()` that may accept any method. For `OPTIONS`, check CORS middleware (`cors` package).
- **Django:** `@require_http_methods(['GET', 'POST'])` decorator, or class-based views with `http_method_names`. Check for views that accept all methods by default.
- **Flask:** `@app.route(..., methods=['GET', 'POST'])` restricts methods. Routes without `methods` parameter default to GET only.
- **Spring:** `@GetMapping`, `@PostMapping`, etc. restrict methods per handler. Check for `@RequestMapping` without `method` parameter (accepts all methods).
- **Rails:** `routes.rb` defines methods via `get`, `post`, `put`, `patch`, `delete`, `resources`. Check for `match ... via: :all` which accepts all methods.
- **Nginx/Apache:** `limit_except` (Nginx) or `<LimitExcept>` (Apache) can block unwanted methods at the server level.
- **Go:** `http.HandleFunc` accepts all methods by default; check for method filtering in handler code (e.g., `if r.Method != http.MethodGet { ... }`). Go 1.22+ supports `http.ServeMux` pattern-based method matching.
- **ASP.NET/C#:** `[HttpGet]`, `[HttpPost]` attributes restrict methods. Check for `[Route]` without method constraint.

Red flags:
- `TRACE` method enabled (can be used for Cross-Site Tracing attacks).
- `app.all()` or equivalent wildcard method handlers on sensitive endpoints.
- No server-level or framework-level method restriction on any endpoint.
- `@RequestMapping` (Spring) or `match ... via: :all` (Rails) without method constraints.

Safe patterns:
- Explicit method declarations on all routes.
- Server-level blocking of `TRACE` and other unused methods.
- CORS middleware handling `OPTIONS` preflight automatically.

**4.1.5 — Per-message digital signatures:**

What to look for:
- For highly sensitive requests or transactions (e.g., financial transfers, cross-system messages, webhook payloads), per-message digital signatures provide integrity and authenticity assurance beyond TLS.
- This is a Level 3 requirement — applicable to high-security applications or transactions traversing multiple systems.

Language-specific patterns:
- **General:** Look for HMAC-based message signing (`HMAC-SHA256`, `HMAC-SHA512`), JWT signatures on individual request payloads (not just authentication tokens), or standards like HTTP Message Signatures (RFC 9421), XML Digital Signatures, or JWS (JSON Web Signature).
- **Node.js:** `crypto.createHmac()`, `crypto.sign()`, `jsonwebtoken` library for signing payloads, `http-message-signatures` library.
- **Python:** `hmac` module, `cryptography` library (`hazmat.primitives.asymmetric.padding`, `hazmat.primitives.hashes`), `python-jose` for JWS.
- **Java:** `javax.crypto.Mac` (HMAC), `java.security.Signature`, XML Signature API (`javax.xml.crypto.dsig`), Bouncy Castle library.
- **Go:** `crypto/hmac`, `crypto/rsa`, `crypto/ecdsa` packages.
- **C#:** `System.Security.Cryptography.HMACSHA256`, `System.Security.Cryptography.RSA.SignData()`.
- **PHP:** `hash_hmac()`, `openssl_sign()`.

Red flags:
- High-value transactions or cross-system messages with no message-level integrity protection beyond TLS.
- Webhook endpoints that accept payloads without signature verification.
- Use of weak/obsolete signing algorithms (MD5, SHA1 for HMAC in new code).

Safe patterns:
- HMAC signature headers on webhook payloads (e.g., GitHub's `X-Hub-Signature-256`, Stripe's `Stripe-Signature`).
- JWS-signed request bodies for sensitive API calls.
- HTTP Message Signatures (RFC 9421) implementation.
- Mutual TLS (mTLS) combined with message signing for high-assurance channels.

N/A conditions:
- Applications that do not handle highly sensitive transactions or do not traverse multiple systems. Standard CRUD applications at L1/L2 typically do not require per-message signatures.

---

## V4.2: HTTP Message Structure Validation

This section explains how the structure and header fields of an HTTP message should be validated to prevent attacks such as request smuggling, response splitting, header injection, and denial of service via overly long HTTP messages.

These requirements are relevant for general HTTP message processing and generation, but are especially important when converting HTTP messages between different HTTP versions.

| # | Requirement | Level |
|---|-------------|-------|
| **4.2.1** | Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames. | 2 |
| **4.2.2** | Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks. | 3 |
| **4.2.3** | Verify that the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks. | 3 |
| **4.2.4** | Verify that the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\r), LF (\n), or CRLF (\r\n) sequences, to prevent header injection attacks. | 3 |
| **4.2.5** | Verify that, if the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs (such as for API calls) or HTTP request header fields (such as Authorization or Cookie), which are too long to be accepted by the receiving component. This could cause a denial of service, such as when sending an overly long request (e.g., a long cookie header field), which results in the server always responding with an error status. | 3 |

### Audit Guidance for V4.2

**4.2.1 — HTTP request smuggling prevention:**

What to look for:
- This is primarily an infrastructure and configuration concern. The application stack (load balancers, reverse proxies, web servers, application frameworks) must agree on how to determine HTTP message boundaries.
- For HTTP/1.x: when both `Transfer-Encoding` and `Content-Length` are present, `Transfer-Encoding` takes precedence. Ensure all components in the chain follow this rule consistently.
- For HTTP/2 and HTTP/3: `Content-Length` must be consistent with DATA frame lengths.

Language-specific / infrastructure patterns:
- **Nginx:** Modern versions handle TE/CL correctly by default. Check Nginx version — older versions (pre-1.17) had edge cases. Verify `proxy_http_version` is set appropriately when proxying to backends.
- **HAProxy:** Supports HTTP/1.1 and HTTP/2 with correct TE/CL handling. Check `option http-use-htx` (modern HTTP processing) is enabled in older versions.
- **Apache:** `mod_proxy` in older versions had smuggling vulnerabilities. Ensure Apache is up to date. Check for `ProxyRequests Off` and correct `ProxyPass` configuration.
- **Express/Node.js:** Node.js's built-in HTTP parser (`llhttp`) has had smuggling vulnerabilities in older versions (CVE-2022-32213, CVE-2022-32214). Ensure Node.js is up to date. Check for the `--insecure-http-parser` flag (should NOT be used in production).
- **Java (Tomcat, Jetty, Netty):** Check server version for known smuggling CVEs. Tomcat's `rejectIllegalHeader` (default true in newer versions). Jetty's compliance modes for HTTP/1.1 parsing.
- **Go:** `net/http` server handles TE/CL correctly in recent versions. Check Go version.
- **Python (gunicorn, uvicorn, waitress):** Waitress had smuggling vulnerabilities (CVE-2022-24761). Ensure WSGI/ASGI servers are up to date.

Red flags:
- Multiple HTTP-processing components in the request path (CDN -> load balancer -> reverse proxy -> app server) with different HTTP parsers — higher smuggling risk.
- Use of `--insecure-http-parser` in Node.js.
- Outdated reverse proxies or web servers with known smuggling CVEs.
- Custom HTTP parsing code instead of using framework defaults.

Safe patterns:
- All components updated to recent versions with known smuggling fixes.
- Consistent HTTP version across the proxy chain (e.g., HTTP/2 end-to-end or controlled downgrade with correct handling).
- WAF rules that detect conflicting TE/CL headers.

**4.2.2 — Content-Length consistency in generated messages:**

What to look for:
- When the application generates HTTP responses (or outgoing HTTP requests as a client), the `Content-Length` header must accurately reflect the actual body length.
- Most frameworks handle this automatically. The risk arises when manually setting `Content-Length` or when streaming responses.

Language-specific patterns:
- **Express/Node.js:** `res.set('Content-Length', ...)` manually — verify it matches actual body size. `res.json()` and `res.send()` auto-calculate Content-Length.
- **Go:** `http.ResponseWriter` auto-sets Content-Length for small responses. Manually setting `w.Header().Set("Content-Length", ...)` before writing — verify correctness.
- **Python (Flask/Django):** Frameworks auto-set Content-Length for most responses. Check for manual `response['Content-Length'] = ...` assignments.
- **Java:** `HttpServletResponse.setContentLength()` — verify it matches actual output. Servlet containers auto-set for buffered responses.

Red flags:
- Manual `Content-Length` header setting without verifying against actual body length.
- Middleware or filters that modify the response body after Content-Length has been set.
- Streaming responses where Content-Length is set speculatively.

Safe patterns:
- Relying on framework auto-calculation of Content-Length.
- Using chunked transfer encoding instead of Content-Length for dynamic content.
- Not setting Content-Length manually in application code.

**4.2.3 — No connection-specific headers in HTTP/2 or HTTP/3:**

What to look for:
- HTTP/2 and HTTP/3 messages must not contain connection-specific header fields: `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Proxy-Connection`, `Upgrade`.
- The `TE` header is allowed in HTTP/2 only with the value `trailers`.
- Check both incoming request validation and outgoing response generation.

Language-specific patterns:
- **Nginx:** When acting as an HTTP/2 frontend proxying to HTTP/1.1 backends, Nginx handles protocol translation. Check that connection-specific headers from backends are stripped when forwarded over HTTP/2.
- **Node.js:** Node.js HTTP/2 module (`http2`) rejects connection-specific headers by default. Check for custom header manipulation that might re-add them.
- **Go:** `golang.org/x/net/http2` strips connection-specific headers. Verify custom middleware does not add them.
- **Java (Netty, Jetty):** HTTP/2 codec implementations typically strip these. Check for custom codec handlers.

Red flags:
- Custom code that adds `Transfer-Encoding`, `Connection`, or `Keep-Alive` headers to HTTP/2 responses.
- Protocol downgrade proxies that pass through connection-specific headers.

Safe patterns:
- Using standard HTTP/2 server implementations that handle header stripping automatically.
- HTTP/2 compliance testing in CI/CD pipelines.

**4.2.4 — No CRLF in HTTP/2 and HTTP/3 header fields:**

What to look for:
- HTTP/2 and HTTP/3 header field names and values must not contain CR (`\r`), LF (`\n`), or CRLF (`\r\n`) sequences.
- This prevents header injection attacks.
- Most HTTP/2 implementations reject these at the protocol level, but check for custom header-setting code.

Language-specific patterns:
- **Node.js:** The `http2` module validates headers by default. Check for `http2stream.respond()` or `http2stream.pushStream()` calls with user-controlled header values.
- **Go:** `net/http` and `golang.org/x/net/http2` reject headers containing newlines. Check for custom header manipulation.
- **Java:** Netty's HTTP/2 codec validates HPACK-decoded headers. Tomcat and Jetty validate as well. Check version for known bypasses.
- **Python:** `hyper-h2` library validates headers. Check for raw frame manipulation.

Red flags:
- User input directly interpolated into HTTP response header values without sanitization.
- Custom HTTP/2 frame construction bypassing library validation.
- Older HTTP/2 library versions with known header injection vulnerabilities.

Safe patterns:
- Using standard HTTP/2 library implementations that validate headers by default.
- Input sanitization stripping or rejecting `\r` and `\n` from any value used in headers.
- Framework-level middleware that validates all outgoing headers.

**4.2.5 — Prevention of overly long URIs and headers:**

What to look for:
- When the application constructs outgoing HTTP requests (e.g., calling external APIs, microservices, or rendering redirects), it should ensure that URIs and header values are not excessively long.
- An overly long cookie, authorization token, or URL could cause the receiving server to reject the request with a `413 Request Entity Too Large` or `431 Request Header Fields Too Large` error, creating a persistent denial of service.

Language-specific patterns:
- **Node.js:** `axios`, `node-fetch`, `got`, or `http.request()` — check if request URLs or headers are built from user input without length limits. Check `--max-http-header-size` flag (default 16 KB in Node.js).
- **Python:** `requests`, `httpx`, `aiohttp` — check URL construction from user input. Check `urllib.parse.urlencode()` with unbounded user data.
- **Java:** `HttpURLConnection`, `OkHttp`, `Apache HttpClient`, `WebClient` — check for URL or header construction from unvalidated input.
- **Go:** `http.NewRequest()` with user-controlled URL or headers. Check for length validation before sending.
- **General:** Check cookie-setting logic — if cookie values grow unboundedly (e.g., appending data to cookies on each request), this can create a permanent DoS for affected users.

Red flags:
- URL query parameters built from unbounded user input (e.g., serializing large arrays into query strings).
- Cookie values that grow with each request or accumulate user data without size limits.
- Authorization headers constructed from user-provided tokens without length validation.
- Redirect URLs built from user input without length checks.

Safe patterns:
- Maximum length validation on any user input used to construct URIs or headers.
- Cookie size limits enforced before setting cookies.
- Configuration of maximum header size on both sending and receiving sides.
- URL length validation before issuing outgoing requests.

N/A conditions:
- Applications that never make outgoing HTTP requests and do not set large cookies. Pure API servers that only receive and respond.

---

## V4.3: GraphQL

GraphQL is becoming more common as a way of creating data-rich clients that are not tightly coupled to a variety of backend services. This section covers security considerations for GraphQL.

| # | Requirement | Level |
|---|-------------|-------|
| **4.3.1** | Verify that a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries. | 2 |
| **4.3.2** | Verify that GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant to be used by other parties. | 2 |

### Audit Guidance for V4.3

**4.3.1 — GraphQL query complexity controls:**

What to look for:
- GraphQL APIs are vulnerable to DoS through deeply nested queries, queries that request large numbers of objects, or queries that resolve expensive fields. At least one of the following mitigations should be in place: query allowlisting (persisted queries), depth limiting, amount/pagination limiting, or query cost analysis.

Language-specific patterns:
- **Apollo Server (Node.js):** Check for plugins or configuration:
  - Depth limiting: `graphql-depth-limit` package, `depthLimit` validation rule.
  - Cost analysis: `graphql-cost-analysis`, `graphql-query-complexity`, `graphql-validation-complexity` packages.
  - Persisted queries: `apollo-server` automatic persisted queries (APQ) or custom persisted query implementation.
  - Amount limiting: `@listSize` directive, custom pagination enforcement, `first`/`last` argument limits.
- **graphql-yoga / Envelop (Node.js):** Check for Envelop plugins: `useDepthLimit`, `useDisableIntrospection`, `useQueryComplexity`.
- **Graphene (Python):** Check for middleware implementing depth or complexity limits. `graphene-django` with `graphql-core` validation rules.
- **Strawberry (Python):** Check for custom extensions implementing query complexity limits.
- **Spring GraphQL (Java):** Check for `RuntimeWiringConfigurer` with custom `Instrumentation` for depth/complexity limiting. `graphql-java` supports `MaxQueryDepthInstrumentation` and `MaxQueryComplexityInstrumentation`.
- **graphql-ruby:** Check for `max_depth`, `max_complexity` on schema definition. `GraphQL::Schema.max_depth` and `GraphQL::Schema.max_complexity` settings.
- **gqlgen (Go):** Check for middleware implementing complexity limits. `gqlgen` has built-in complexity support via `ComplexityLimit` configuration.
- **Hot Chocolate (C#):** Check for `MaxAllowedQueryDepth`, `MaxAllowedQueryComplexity` in schema configuration.

Red flags:
- No depth limit, no complexity analysis, no persisted queries, and no pagination enforcement on a production GraphQL API.
- Pagination arguments (`first`, `last`, `limit`) that accept unbounded values (e.g., `first: 999999`).
- Deeply nested relationships queryable without any limit (e.g., `user -> friends -> friends -> friends -> ...`).

Safe patterns:
- Depth limit set (typically 7-15 levels maximum).
- Query complexity/cost analysis with a defined maximum cost threshold.
- Persisted/allowlisted queries only (no arbitrary queries accepted in production).
- Default and maximum pagination limits on all list fields.

N/A conditions:
- Application does not use GraphQL.

**4.3.2 — GraphQL introspection disabled in production:**

What to look for:
- GraphQL introspection queries (`__schema`, `__type`) expose the entire API schema, including all types, fields, arguments, and descriptions. Unless the API is intended for public third-party consumption, introspection should be disabled in production.

Language-specific patterns:
- **Apollo Server (Node.js):** `introspection: false` in server options (default is `true` in Apollo Server 4+, was `true` only in development in older versions). Check environment-conditional configuration.
- **graphql-yoga (Node.js):** Use `useDisableIntrospection` Envelop plugin.
- **Graphene-Django (Python):** `GRAPHENE` setting `SCHEMA_INDENT` does not control introspection. Check for custom middleware or `graphql-core` validation rules that block introspection.
- **Strawberry (Python):** Custom extensions or middleware to disable introspection.
- **Spring GraphQL (Java):** Check for `Instrumentation` that blocks introspection queries. `graphql-java`'s `NoIntrospectionGraphqlFieldVisibility`.
- **graphql-ruby:** `disable_introspection_entry_points` on schema definition.
- **gqlgen (Go):** Set `introspection: false` in handler configuration, or use middleware to block introspection queries.
- **Hot Chocolate (C#):** `AllowIntrospection` option set to `false` for production.

Red flags:
- Introspection enabled in production without a clear business justification (e.g., the API is not a public developer API).
- No environment-based toggle for introspection (same configuration for dev and prod).
- Schema exposed through introspection revealing internal types, mutations, or field descriptions with sensitive information.

Safe patterns:
- Introspection explicitly disabled in production configuration.
- Environment-based configuration: enabled in development/staging, disabled in production.
- If introspection must remain enabled (public API), ensure no sensitive internal details are exposed in type descriptions.

N/A conditions:
- Application does not use GraphQL.
- GraphQL API is explicitly designed for third-party developer consumption (public API) and introspection is intentionally enabled.

---

## V4.4: WebSocket

WebSocket is a communications protocol that provides a simultaneous two-way communication channel over a single TCP connection. It was standardized by the IETF as RFC 6455 in 2011 and is distinct from HTTP, even though it is designed to work over HTTP ports 443 and 80.

This section provides key security requirements to prevent attacks related to communication security and session management that specifically exploit this real-time communication channel.

| # | Requirement | Level |
|---|-------------|-------|
| **4.4.1** | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | 1 |
| **4.4.2** | Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a list of origins allowed for the application. | 2 |
| **4.4.3** | Verify that, if the application's standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements. | 2 |
| **4.4.4** | Verify that dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel. | 2 |

### Audit Guidance for V4.4

**4.4.1 — WebSocket over TLS (WSS):**

What to look for:
- All WebSocket connections must use `wss://` (WebSocket Secure), not `ws://` (unencrypted).
- Check both client-side code (connection URLs) and server-side configuration (listener ports and protocols).

Language-specific patterns:
- **JavaScript (browser):** Search for `new WebSocket('ws://...')` — this is a FAIL. Should be `new WebSocket('wss://...')`. Check for dynamically constructed URLs that might use `ws://` in some environments.
- **Socket.IO (Node.js):** Check server configuration for `transports` and whether TLS is enforced. Client-side: `io('https://...')` or `io('wss://...')`. Check for `secure: true` in options.
- **ws (Node.js):** `new WebSocket.Server({ server: httpsServer })` — ensure the underlying server is HTTPS, not HTTP. Check for standalone `ws` server on plain TCP.
- **Django Channels:** Check `CHANNEL_LAYERS` configuration and deployment (Daphne or uvicorn) for TLS termination. Check routing configuration in `asgi.py`.
- **Spring WebSocket (Java):** Check `WebSocketConfigurer` or `@ServerEndpoint` annotations. TLS is typically handled at the reverse proxy or servlet container level. Verify Tomcat/Jetty is configured for HTTPS.
- **ActionCable (Rails):** Check `config.action_cable.allowed_request_origins` and deployment configuration. TLS usually handled by Nginx/reverse proxy.
- **SignalR (C#):** Check connection URL configuration. TLS is typically at the hosting level (Kestrel HTTPS configuration, IIS bindings).
- **Go:** `gorilla/websocket` or `nhooyr.io/websocket` — check if the upgrader is attached to an HTTPS handler or plain HTTP.

Red flags:
- `ws://` URLs in client-side code (hardcoded or conditionally used in production).
- WebSocket server listening on plain HTTP without TLS termination by a reverse proxy.
- Mixed content: HTTPS page connecting to `ws://` WebSocket endpoint.
- Environment-conditional WebSocket URLs where production might accidentally use `ws://`.

Safe patterns:
- All WebSocket URLs use `wss://` protocol.
- TLS termination at the reverse proxy (Nginx, HAProxy) in front of WebSocket servers.
- Relative WebSocket URLs derived from the page's own protocol (e.g., `wss://${window.location.host}/ws`).
- HSTS headers preventing protocol downgrade.

N/A conditions:
- Application does not use WebSocket connections.

**4.4.2 — Origin header validation on WebSocket handshake:**

What to look for:
- During the WebSocket upgrade handshake (the initial HTTP request), the server must validate the `Origin` header against an allowlist of permitted origins to prevent Cross-Site WebSocket Hijacking (CSWSH).
- Without origin validation, a malicious website can open a WebSocket connection to the target server, and the browser will include the user's cookies automatically.

Language-specific patterns:
- **ws (Node.js):** Check `verifyClient` callback in `WebSocket.Server` options. This is where origin checking should occur: `(info) => allowedOrigins.includes(info.origin)`.
- **Socket.IO (Node.js):** `cors` option in server configuration: `new Server(httpServer, { cors: { origin: ['https://example.com'] } })`. Check for `origin: '*'` (unsafe) or `origin: true` (reflects any origin — unsafe).
- **Django Channels:** Check `ALLOWED_HOSTS` and any custom WebSocket middleware that validates Origin. `channels` does not validate Origin by default — this must be added via middleware or consumer logic.
- **Spring WebSocket (Java):** `setAllowedOrigins()` or `setAllowedOriginPatterns()` on `WebSocketHandlerRegistry`. Check for `.setAllowedOrigins("*")` (unsafe).
- **ActionCable (Rails):** `config.action_cable.allowed_request_origins` — check it is set to specific origins, not a permissive regex like `/.*/`.
- **SignalR (C#):** CORS policy configuration in `Startup.cs` / `Program.cs`. Check `WithOrigins(...)` for specific origin list.
- **Go (gorilla/websocket):** `Upgrader.CheckOrigin` function. Default `CheckOrigin` allows all origins. Must be overridden: `CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "https://example.com" }`.

Red flags:
- No origin validation on WebSocket handshake (default behavior in many libraries).
- Origin check that allows all origins (`*`, `/.*/`, `CheckOrigin` returning `true`).
- Origin check that only logs but does not reject mismatched origins.
- `gorilla/websocket` default `CheckOrigin` (returns `true` for all requests with Origin header matching the Host, but allows all if no Origin header).

Safe patterns:
- Explicit allowlist of origins validated during WebSocket handshake.
- CSRF token required during WebSocket handshake (sent as query parameter or first message).
- Origin validation middleware applied to all WebSocket endpoints.

N/A conditions:
- Application does not use WebSocket connections.

**4.4.3 — Dedicated WebSocket session tokens:**

What to look for:
- If the application's standard session management (e.g., HTTP cookies) cannot be applied to WebSocket connections, dedicated tokens must be used for WebSocket session management.
- These tokens must comply with the same security requirements as standard session tokens (sufficient entropy, expiration, server-side validation, revocation).

Language-specific patterns:
- **Socket.IO (Node.js):** Check for `socket.handshake.auth` token or `socket.handshake.headers.cookie` for session binding. If using custom tokens, verify they are validated against a session store.
- **ws (Node.js):** Check `verifyClient` for token validation. Common patterns: JWT in query parameter (`?token=...`), or token sent as first WebSocket message after connection.
- **Django Channels:** Check consumer `connect()` method for authentication. `AuthMiddlewareStack` wraps the ASGI application for cookie-based auth. For token-based: custom middleware validating tokens from query string or headers.
- **Spring WebSocket (Java):** `HandshakeInterceptor` for extracting and validating tokens during upgrade. `ChannelInterceptor` for message-level authentication.
- **ActionCable (Rails):** `ApplicationCable::Connection#connect` method — check for `find_verified_user` or similar authentication logic.
- **SignalR (C#):** `IUserIdProvider` and authentication middleware. Token can be passed via query string: `HubConnectionBuilder` with `AccessTokenProvider`.

Red flags:
- WebSocket connections accepted without any authentication or session binding.
- Tokens passed in WebSocket URL query parameters without TLS (visible in logs, referrer headers).
- Tokens with no expiration or server-side validation.
- Using the same long-lived API key for WebSocket sessions without session-specific tokens.

Safe patterns:
- Short-lived, single-use tokens obtained via authenticated HTTPS endpoint, then used for WebSocket connection.
- Cookie-based session management that works transparently with WebSocket handshake.
- Token validation against a server-side session store with expiration enforcement.
- Token revocation on disconnect.

N/A conditions:
- Application does not use WebSocket connections.
- Standard cookie-based session management works for WebSocket connections (then this requirement is met by default).

**4.4.4 — WebSocket tokens obtained via authenticated HTTPS session:**

What to look for:
- When transitioning from an existing authenticated HTTPS session to a WebSocket channel, the WebSocket session token must be obtained or validated through that authenticated HTTPS session.
- This prevents unauthenticated WebSocket connections by ensuring the user was previously authenticated over HTTPS.

Language-specific patterns:
- **Common pattern (all languages):** A REST/HTTPS endpoint (e.g., `POST /api/ws-token`) issues a short-lived WebSocket token. The client then uses this token in the WebSocket handshake (query parameter or first message). The WebSocket server validates the token and binds the WebSocket to the authenticated user.
- **Cookie-based:** If the WebSocket handshake includes the same session cookie as the HTTPS session, and the server validates it, this requirement is met. Check that the `connect` handler reads and validates the session cookie.
- **Token-based:** Verify the token issuance endpoint requires authentication (session cookie, bearer token). Verify the issued WebSocket token is bound to the authenticated user and has a short TTL.

Red flags:
- WebSocket endpoints that accept connections without requiring any proof of prior HTTPS authentication.
- WebSocket tokens that can be obtained without authentication (e.g., anonymous endpoint issuing WebSocket tokens).
- Long-lived WebSocket tokens that persist beyond the HTTPS session lifetime.
- WebSocket token not bound to the user who requested it (reusable by other users).

Safe patterns:
- Authenticated HTTPS endpoint issues short-lived, user-bound WebSocket token.
- Cookie-based session automatically carried into WebSocket handshake and validated server-side.
- WebSocket token TTL matches or is shorter than the HTTPS session TTL.
- WebSocket connection terminated when the underlying HTTPS session expires or is revoked.

N/A conditions:
- Application does not use WebSocket connections.
- Application does not have authenticated HTTPS sessions (public WebSocket-only service).

---

## References

For more information, see also:

* [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
* Resources on GraphQL Authorization from [graphql.org](https://graphql.org/learn/authorization/) and [Apollo](https://www.apollographql.com/docs/apollo-server/security/authentication/#authorization-methods).
* [OWASP Web Security Testing Guide: GraphQL Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL)
* [OWASP Web Security Testing Guide: Testing WebSockets](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets)

---

## V4 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 2 | 4.1.1, 4.4.1 |
| L2 | 8 | 4.1.2, 4.1.3, 4.2.1, 4.3.1, 4.3.2, 4.4.2, 4.4.3, 4.4.4 |
| L3 | 6 | 4.1.4, 4.1.5, 4.2.2, 4.2.3, 4.2.4, 4.2.5 |
| **Total** | **16** | |
