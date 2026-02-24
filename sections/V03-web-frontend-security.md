# V3: Web Frontend Security

**ASVS Version:** 5.0.0
**Source file:** `5.0/en/0x12-V3-Web-Frontend-Security.md`

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

This category focuses on requirements designed to protect against attacks executed via a web frontend. These requirements do not apply to machine-to-machine solutions.

---

## V3.1: Web Frontend Security Documentation

This section outlines the browser security features that should be specified in the application's documentation.

| # | Requirement | Level |
|---|-------------|-------|
| **3.1.1** | Verify that application documentation states the expected security features that browsers using the application must support (such as HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), and other relevant HTTP security mechanisms). It must also define how the application must behave when some of these features are not available (such as warning the user or blocking access). | 3 |

### Audit Guidance for V3.1

**3.1.1 — Browser security feature documentation:**

What to look for:
- A documented list of browser security features the application depends on (HTTPS, HSTS, CSP, SameSite cookies, Subresource Integrity, CORS restrictions, etc.).
- A defined graceful-degradation or fail-closed policy for browsers that do not support required features (e.g., displaying a warning banner, blocking access entirely, or redirecting to an unsupported-browser page).
- Evidence that this documentation is maintained alongside the application (e.g., in a security design document, architecture decision record, or operational runbook).

Red flags:
- No documentation exists describing browser requirements.
- The application silently degrades security when a browser feature is missing (e.g., falls back to HTTP without warning).
- Documentation exists but is stale (references features or browser versions that are no longer relevant).

Safe patterns:
- A dedicated "Security Requirements" or "Browser Compatibility" section in project documentation that explicitly lists expected features and fallback behavior.
- Feature detection scripts (e.g., checking for `window.crypto.subtle`, `navigator.serviceWorker`, or CSP support) that trigger user-facing warnings when required features are absent.

N/A conditions:
- Machine-to-machine APIs that have no web frontend or browser-based consumers.

---

## V3.2: Unintended Content Interpretation

Rendering content or functionality in an incorrect context can result in malicious content being executed or displayed.

| # | Requirement | Level |
|---|-------------|-------|
| **3.2.1** | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | 1 |
| **3.2.2** | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | 1 |
| **3.2.3** | Verify that the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation. | 3 |

### Audit Guidance for V3.2

**3.2.1 — Preventing incorrect content rendering context:**

What to look for:
- API endpoints and file-serving routes that return content which could be misinterpreted by a browser when accessed directly (e.g., JSON responses rendered as HTML, user-uploaded SVG files with embedded scripts).
- Presence of `Sec-Fetch-Dest` and `Sec-Fetch-Site` header validation on server-side handlers to reject direct navigation requests to API or resource endpoints.
- Use of `Content-Disposition: attachment` on file download endpoints, especially for user-uploaded content.
- Use of `Content-Security-Policy: sandbox` on responses serving user-controlled content to prevent script execution.

Language-specific patterns:
- **Python (Django):** Check that `FileResponse` or `HttpResponse` for user uploads sets `Content-Disposition: attachment`. Look for `content_type` being set explicitly rather than inferred from user-provided filenames. Middleware or decorators that inspect `request.META.get('HTTP_SEC_FETCH_DEST')`.
- **Python (Flask):** `send_file(..., as_attachment=True)` or `send_from_directory(..., as_attachment=True)`. Custom `@before_request` handlers checking Sec-Fetch headers.
- **JavaScript/Node.js (Express):** `res.download()` or `res.set('Content-Disposition', 'attachment')` on file-serving routes. Middleware checking `req.headers['sec-fetch-dest']`.
- **Java (Spring):** `ResponseEntity` with `ContentDisposition.attachment()`. Servlet filters or Spring interceptors validating `Sec-Fetch-*` headers.
- **PHP:** `header('Content-Disposition: attachment; filename="..."')` on file download scripts. Checking `$_SERVER['HTTP_SEC_FETCH_DEST']`.
- **Go:** `w.Header().Set("Content-Disposition", "attachment")`. Middleware checking `r.Header.Get("Sec-Fetch-Dest")`.
- **C# (ASP.NET):** `FileResult` with `FileDownloadName` set, or `Content-Disposition` header on `FileStreamResult`. Action filters inspecting `Request.Headers["Sec-Fetch-Dest"]`.

Red flags:
- User-uploaded files served inline (without `Content-Disposition: attachment`) from the same origin as the application.
- JSON API responses that do not set `Content-Type: application/json` or that respond to direct browser navigation without any Sec-Fetch validation.
- SVG files served with `Content-Type: image/svg+xml` from the same origin without CSP sandbox restrictions (SVGs can contain JavaScript).

Safe patterns:
- User-uploaded content served from a separate domain or a sandboxed subdomain.
- All API endpoints returning `Content-Type: application/json` with `X-Content-Type-Options: nosniff`.
- File download endpoints always setting `Content-Disposition: attachment`.

**3.2.2 — Safe text rendering (avoid HTML interpretation):**

What to look for:
- Client-side JavaScript that inserts user-controlled data into the DOM using methods that interpret HTML.
- Use of `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()`, or jQuery's `.html()` with user-controlled content.

Language-specific patterns:
- **JavaScript (Vanilla):** Unsafe: `element.innerHTML = userInput`. Safe: `element.textContent = userInput` or `element.appendChild(document.createTextNode(userInput))`.
- **JavaScript (jQuery):** Unsafe: `$(selector).html(userInput)`, `$(userInput)`. Safe: `$(selector).text(userInput)`.
- **JavaScript (React):** Unsafe: `dangerouslySetInnerHTML={{__html: userInput}}`. Safe: JSX expressions like `{userInput}` which auto-escape.
- **JavaScript (Angular):** Unsafe: `[innerHTML]="userInput"` without sanitization, `bypassSecurityTrustHtml()`. Safe: Angular's default binding `{{userInput}}` which auto-escapes.
- **JavaScript (Vue):** Unsafe: `v-html="userInput"`. Safe: `{{ userInput }}` (mustache interpolation) which auto-escapes.

Red flags:
- `innerHTML` assignments where the source is any variable derived from user input, URL parameters, API responses, or database content.
- `document.write()` usage in any modern application — this is almost always unsafe and unnecessary.
- Templating libraries configured with auto-escaping disabled.

Safe patterns:
- Exclusive use of `textContent`, `createTextNode()`, or framework-level auto-escaping for text rendering.
- `innerHTML` used only with compile-time static strings or content that has been sanitized with a trusted library (e.g., DOMPurify).

**3.2.3 — DOM clobbering prevention:**

What to look for:
- Client-side JavaScript that relies on global variables accessed via `document.getElementById()` or directly from the `window`/`document` object where HTML elements with matching `id` or `name` attributes could shadow those variables.
- HTML attributes (`id`, `name`) on elements that share names with JavaScript variables or DOM API properties.

Red flags:
- Code that accesses `document.someProperty` or `window.someProperty` without first verifying the type of the returned value (e.g., it could be an `HTMLElement` instead of the expected string or object).
- Use of `document.getElementById()` return values without type checking (an attacker could inject an element with a conflicting `id`).
- Global variable declarations that are not explicitly scoped (e.g., missing `const`, `let`, or `var`; implicit globals).
- Libraries or templates that inject HTML with user-controlled `id` or `name` attributes.

Safe patterns:
- All variables declared with `const`, `let`, or `var` within scoped functions or modules (ES modules, IIFEs).
- Strict type checking on values retrieved from the DOM (e.g., `if (typeof value === 'string')` before use).
- Namespace isolation using modules, closures, or object namespaces rather than relying on global scope.
- Sanitization of user-controlled HTML that strips or restricts `id` and `name` attributes (e.g., DOMPurify with configuration to remove these attributes).

N/A conditions:
- Applications that do not use client-side JavaScript DOM manipulation (e.g., purely server-rendered pages with no JS, or applications that use a virtual DOM framework like React exclusively without direct DOM access).

---

## V3.3: Cookie Setup

This section outlines requirements for securely configuring sensitive cookies to provide a higher level of assurance that they were created by the application itself and to prevent their contents from leaking or being inappropriately modified.

| # | Requirement | Level |
|---|-------------|-------|
| **3.3.1** | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | 1 |
| **3.3.2** | Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | 2 |
| **3.3.3** | Verify that cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared with other hosts. | 2 |
| **3.3.4** | Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e. g. session token) must only be transferred to the client via the 'Set-Cookie' header field. | 2 |
| **3.3.5** | Verify that when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie. | 3 |

### Audit Guidance for V3.3

**3.3.1 — Secure attribute and cookie name prefixes:**

What to look for:
- Every `Set-Cookie` response header for sensitive cookies includes the `Secure` attribute.
- Cookie names use either the `__Host-` prefix or the `__Secure-` prefix.
- The `__Host-` prefix requires: `Secure` attribute, no `Domain` attribute, and `Path=/`.
- The `__Secure-` prefix requires only the `Secure` attribute.

Language-specific patterns:
- **Python (Django):** Check `settings.py` for `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True`, `SESSION_COOKIE_NAME` (should use a prefix like `__Host-sessionid` or `__Secure-sessionid`).
- **Python (Flask):** `app.config['SESSION_COOKIE_SECURE'] = True`, `app.config['SESSION_COOKIE_NAME']`. For custom cookies: `response.set_cookie(name, value, secure=True)`.
- **JavaScript/Node.js (Express):** `express-session` config: `cookie: { secure: true }`. Cookie-parser / manual `res.cookie()`: `res.cookie('__Host-session', value, { secure: true, path: '/' })`.
- **Java (Spring):** `server.servlet.session.cookie.secure=true` in `application.properties`. `server.servlet.session.cookie.name=__Host-JSESSIONID`. For manual cookies: `cookie.setSecure(true)`.
- **PHP:** `session.cookie_secure = 1` in `php.ini` or `ini_set()`. `session_name('__Host-PHPSESSID')`. `setcookie($name, $value, ['secure' => true])`.
- **Ruby (Rails):** `config.session_store :cookie_store, key: '__Host-_app_session', secure: true`. In `config/environments/production.rb`.
- **Go:** `http.Cookie{Name: "__Host-session", Value: val, Secure: true, Path: "/"}`.
- **C# (ASP.NET):** `options.Cookie.SecurePolicy = CookieSecurePolicy.Always` in `ConfigureServices`. `options.Cookie.Name = "__Host-.AspNetCore.Session"`.

Red flags:
- Cookies set without the `Secure` attribute (especially session cookies, authentication tokens, CSRF tokens).
- Cookie names that lack both the `__Host-` and `__Secure-` prefix.
- Development configurations (`Secure = false`) leaking into production.

Safe patterns:
- All sensitive cookies use `__Host-` prefix with `Secure`, `Path=/`, and no `Domain` attribute.
- Framework session configuration explicitly sets `Secure = true` in production configuration files.

**3.3.2 — SameSite attribute configured per cookie purpose:**

What to look for:
- Each cookie's `SameSite` attribute is explicitly set (not relying on browser defaults, which vary).
- Session cookies and CSRF tokens use `SameSite=Strict` or `SameSite=Lax` depending on whether cross-site navigation should send the cookie.
- Cookies intentionally shared cross-site (e.g., for SSO or third-party embedding) use `SameSite=None` with `Secure`.

Language-specific patterns:
- **Python (Django):** `SESSION_COOKIE_SAMESITE = 'Lax'` (or `'Strict'`), `CSRF_COOKIE_SAMESITE = 'Lax'`.
- **Python (Flask):** `app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'`.
- **JavaScript/Node.js (Express):** `res.cookie('name', value, { sameSite: 'lax' })`. `express-session` config: `cookie: { sameSite: 'lax' }`.
- **Java (Spring):** `server.servlet.session.cookie.same-site=lax` in `application.properties`. Spring Security `CookieCsrfTokenRepository` supports SameSite configuration.
- **PHP:** `session.cookie_samesite = "Lax"` in `php.ini`. `setcookie($name, $value, ['samesite' => 'Lax'])`.
- **Ruby (Rails):** `config.action_dispatch.cookies_same_site_protection = :lax` (Rails 6.1+).
- **Go:** `http.Cookie{SameSite: http.SameSiteLaxMode}`.
- **C# (ASP.NET):** `options.Cookie.SameSite = SameSiteMode.Lax`.

Red flags:
- `SameSite=None` used on session or authentication cookies without a clear cross-site use case.
- `SameSite` attribute not explicitly set, relying on inconsistent browser defaults.
- `SameSite=None` without the `Secure` attribute (browsers will reject this).

Safe patterns:
- Session cookies use `SameSite=Lax` or `SameSite=Strict`.
- Only cookies with a documented cross-site purpose use `SameSite=None; Secure`.

**3.3.3 — __Host- prefix for non-shared cookies:**

What to look for:
- Cookies that are not explicitly designed to be shared with subdomains or other hosts should use the `__Host-` prefix.
- The `__Host-` prefix enforces: `Secure`, no `Domain` attribute, `Path=/` — providing the strongest cookie integrity guarantees.

Red flags:
- Session cookies or authentication cookies using a `Domain` attribute (e.g., `Domain=.example.com`) when there is no documented need to share with subdomains.
- Cookies using `__Secure-` when `__Host-` would be appropriate (i.e., the cookie does not need to be shared across subdomains).

Safe patterns:
- All application-specific cookies use `__Host-` prefix and are scoped to the exact origin.
- Cookies that must be shared across subdomains have a documented justification and use `__Secure-` prefix.

N/A conditions:
- Cookies that are explicitly designed to be shared with other hosts (e.g., SSO cookies across subdomains) — these should use `__Secure-` prefix instead.

**3.3.4 — HttpOnly for server-only cookie values:**

What to look for:
- Session tokens and other sensitive cookie values are set with the `HttpOnly` attribute.
- The same sensitive value (e.g., session token) is not also exposed to client-side JavaScript through other channels (e.g., embedded in HTML, returned in API JSON responses, or set in `window` variables).

Language-specific patterns:
- **Python (Django):** `SESSION_COOKIE_HTTPONLY = True` (default). Check that session tokens are not also exposed in template context or API responses.
- **Python (Flask):** `app.config['SESSION_COOKIE_HTTPONLY'] = True`. Check for `response.set_cookie(..., httponly=True)` on custom cookies.
- **JavaScript/Node.js (Express):** `cookie: { httpOnly: true }` in `express-session` config. `res.cookie('name', value, { httpOnly: true })`.
- **Java (Spring):** `server.servlet.session.cookie.http-only=true`. `cookie.setHttpOnly(true)` for manual cookies.
- **PHP:** `session.cookie_httponly = 1`. `setcookie($name, $value, ['httponly' => true])`.
- **Ruby (Rails):** Session cookies are HttpOnly by default. Check custom cookie settings.
- **Go:** `http.Cookie{HttpOnly: true}`.
- **C# (ASP.NET):** `options.Cookie.HttpOnly = true`.

Red flags:
- Session token value also injected into HTML (e.g., in a `<meta>` tag or inline script) making HttpOnly pointless.
- Session token returned in JSON API response bodies.
- `HttpOnly` explicitly set to `false` on session cookies.

Safe patterns:
- Session tokens only ever transmitted via `Set-Cookie` headers with `HttpOnly`.
- Client-side functionality that needs a token uses a separate, non-session CSRF token.

**3.3.5 — Cookie size limit (4096 bytes):**

What to look for:
- Cookie name + value combined length. The 4096-byte limit is the maximum most browsers will reliably store.
- Applications that store large data structures in cookies (e.g., serialized session state, JWTs with many claims, user preferences).

Red flags:
- Session data serialized directly into cookie values (e.g., Flask's default client-side session without size monitoring, Rails `CookieStore` with large session payloads).
- JWTs stored in cookies with many custom claims, extensive user profile data, or embedded permissions that push the token size above limits.
- Multiple cookies on the same domain where total cookie header size approaches browser limits.

Safe patterns:
- Server-side session storage with only a short session identifier in the cookie.
- JWTs kept lean with minimal claims; large payloads fetched server-side.
- Cookie size monitoring or validation in application code before setting cookies.

N/A conditions:
- Applications that do not use cookies (e.g., purely token-based APIs where tokens are sent in Authorization headers).

---

## V3.4: Browser Security Mechanism Headers

This section describes which security headers should be set on HTTP responses to enable browser security features and restrictions when handling responses from the application.

| # | Requirement | Level |
|---|-------------|-------|
| **3.4.1** | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | 1 |
| **3.4.2** | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | 1 |
| **3.4.3** | Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined. | 2 |
| **3.4.4** | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser. | 2 |
| **3.4.5** | Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname. | 2 |
| **3.4.6** | Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon. | 2 |
| **3.4.7** | Verify that the Content-Security-Policy header field specifies a location to report violations. | 3 |
| **3.4.8** | Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross-Origin-Opener-Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting. | 3 |

### Audit Guidance for V3.4

**3.4.1 — Strict-Transport-Security (HSTS):**

What to look for:
- Every HTTP response includes `Strict-Transport-Security` with `max-age` of at least 31536000 (1 year).
- For L2 and above, `includeSubDomains` must be present.
- Header is set on all responses, not just on specific routes.

Language-specific patterns:
- **Python (Django):** `SECURE_HSTS_SECONDS = 31536000`, `SECURE_HSTS_INCLUDE_SUBDOMAINS = True`, `SECURE_HSTS_PRELOAD = True` in `settings.py`. Requires `SecurityMiddleware` to be active.
- **Python (Flask):** Use `flask-talisman`: `Talisman(app, strict_transport_security=True, strict_transport_security_max_age=31536000, strict_transport_security_include_subdomains=True)`.
- **JavaScript/Node.js (Express):** Use `helmet`: `app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }))`.
- **Java (Spring):** Spring Security default: `http.headers().httpStrictTransportSecurity().includeSubDomains(true).maxAgeInSeconds(31536000)`.
- **PHP:** `header('Strict-Transport-Security: max-age=31536000; includeSubDomains')` in a global middleware or `.htaccess`/`nginx.conf`.
- **Ruby (Rails):** `config.force_ssl = true` sets HSTS. Configure `config.ssl_options = { hsts: { subdomains: true, expires: 1.year } }`.
- **Go:** Middleware or handler adding `w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")`.
- **C# (ASP.NET):** `app.UseHsts()` with `services.AddHsts(options => { options.MaxAge = TimeSpan.FromDays(365); options.IncludeSubDomains = true; })`.

Red flags:
- `max-age` set to a low value (e.g., `max-age=0` or `max-age=300`).
- HSTS header only set on specific pages (e.g., login page) but not globally.
- Missing `includeSubDomains` for L2+ applications.
- HSTS header set on HTTP responses (it must be set on HTTPS responses only; most frameworks handle this automatically).

Safe patterns:
- Global middleware or server configuration that applies HSTS to all HTTPS responses.
- `max-age` of at least 1 year with `includeSubDomains`.

**3.4.2 — CORS Access-Control-Allow-Origin validation:**

What to look for:
- Whether `Access-Control-Allow-Origin` is a hardcoded fixed value, or if it dynamically reflects the `Origin` request header.
- If dynamic, whether the `Origin` value is validated against a strict allowlist before being reflected.
- If `Access-Control-Allow-Origin: *` is used, ensure the response does not include sensitive data and that `Access-Control-Allow-Credentials` is not also set to `true` (browsers block this combination, but the intent matters).

Language-specific patterns:
- **Python (Django):** `django-cors-headers` package: check `CORS_ALLOWED_ORIGINS` (allowlist) vs. `CORS_ALLOW_ALL_ORIGINS = True` (dangerous). Check `CORS_ALLOW_CREDENTIALS`.
- **Python (Flask):** `flask-cors`: check `origins` parameter. `CORS(app, origins="*")` is risky if responses contain sensitive data.
- **JavaScript/Node.js (Express):** `cors` package: check `origin` option. `origin: true` reflects any origin. Safe: `origin: ['https://trusted.example.com']`.
- **Java (Spring):** `@CrossOrigin(origins = "...")` annotations or `CorsConfiguration.setAllowedOrigins()`. Check for `"*"` in allowed origins with `setAllowCredentials(true)`.
- **PHP:** Manual `header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN'])` without validation — extremely dangerous.
- **Ruby (Rails):** `rack-cors` gem: check `origins` configuration in `config/initializers/cors.rb`.
- **Go:** Middleware like `rs/cors`: check `AllowedOrigins` configuration. `AllowedOrigins: []string{"*"}` with `AllowCredentials: true` is dangerous.
- **C# (ASP.NET):** `services.AddCors(options => { options.AddPolicy(...).WithOrigins("...") })`. Check for `.AllowAnyOrigin()` combined with `.AllowCredentials()`.

Red flags:
- `Origin` header value reflected directly into `Access-Control-Allow-Origin` without any validation.
- Regex-based origin matching with loose patterns (e.g., `/example\.com/` would match `evil-example.com`).
- `Access-Control-Allow-Origin: *` on endpoints that return user-specific or authenticated data.
- `null` origin explicitly allowed (can be forged via sandboxed iframes).

Safe patterns:
- Hardcoded `Access-Control-Allow-Origin` value.
- Strict allowlist of origins validated with exact string matching.
- Wildcard `*` used only on truly public, non-sensitive endpoints without credentials.

**3.4.3 — Content-Security-Policy (CSP):**

What to look for:
- CSP header present on HTML responses. At minimum: `object-src 'none'` and `base-uri 'none'`.
- Whether the policy defines a `default-src` and/or `script-src` directive.
- Whether the policy uses `'unsafe-inline'` or `'unsafe-eval'` (weakens CSP significantly).
- For L3: per-response nonces or hashes on `script-src` and `style-src`.

Language-specific patterns:
- **Python (Django):** `django-csp` middleware: check `CSP_DEFAULT_SRC`, `CSP_SCRIPT_SRC`, `CSP_OBJECT_SRC`, `CSP_BASE_URI` in `settings.py`.
- **Python (Flask):** `flask-talisman`: `Talisman(app, content_security_policy={...})`. Check for nonce support via `csp_nonce()`.
- **JavaScript/Node.js (Express):** `helmet.contentSecurityPolicy({ directives: { ... } })`. Check for `'unsafe-inline'` in `scriptSrc`.
- **Java (Spring):** `http.headers().contentSecurityPolicy("...")` in Spring Security configuration.
- **PHP:** `header("Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'")`.
- **Ruby (Rails):** `config.content_security_policy` block in `config/initializers/content_security_policy.rb`. Rails 6+ has built-in nonce generation via `content_security_policy_nonce_generator`.
- **Go:** Middleware setting `w.Header().Set("Content-Security-Policy", "...")`.
- **C# (ASP.NET):** Custom middleware or libraries like `NWebsec`: `app.UseCsp(options => options.DefaultSources(s => s.Self()).ObjectSources(s => s.None()))`.

Red flags:
- No CSP header at all on HTML responses.
- CSP with `'unsafe-inline'` in `script-src` without nonces/hashes (effectively disables XSS protection).
- CSP with `'unsafe-eval'` in `script-src` (allows `eval()`, `Function()`, etc.).
- Overly permissive `default-src` (e.g., `default-src *`).
- Missing `object-src 'none'` (allows Flash/plugin-based attacks).
- Missing `base-uri 'none'` or `base-uri 'self'` (allows base tag injection for relative URL hijacking).
- CSP in `report-only` mode in production without an enforcing policy alongside it.

Safe patterns:
- Strict CSP: `default-src 'self'; script-src 'nonce-{random}'; object-src 'none'; base-uri 'none'`.
- Per-response unique nonces generated server-side and injected into both the CSP header and `<script nonce="...">` tags.
- Hash-based CSP for static inline scripts.

**3.4.4 — X-Content-Type-Options: nosniff:**

What to look for:
- `X-Content-Type-Options: nosniff` present on all HTTP responses.
- Correct `Content-Type` header set on all responses (this header alone is not sufficient if `Content-Type` is missing or wrong).

Language-specific patterns:
- **Python (Django):** `SECURE_CONTENT_TYPE_NOSNIFF = True` in `settings.py` (enabled by default in Django 3.0+).
- **JavaScript/Node.js (Express):** `helmet.noSniff()` or `helmet()` (includes it by default).
- **Java (Spring):** Spring Security sets this by default: `http.headers().contentTypeOptions()`.
- **PHP:** `header('X-Content-Type-Options: nosniff')` globally.
- **Ruby (Rails):** Set by default in Rails 6+.
- **Go:** `w.Header().Set("X-Content-Type-Options", "nosniff")` in middleware.
- **C# (ASP.NET):** Set by default with security headers middleware. Or manually in middleware.

Red flags:
- Header missing on API responses or static file responses.
- `Content-Type` not explicitly set on responses (browser may sniff content type despite `nosniff`).

Safe patterns:
- Global middleware that adds `X-Content-Type-Options: nosniff` to every response.
- All response handlers explicitly set correct `Content-Type`.

**3.4.5 — Referrer-Policy:**

What to look for:
- A `Referrer-Policy` HTTP response header or `<meta name="referrer">` tag or `referrerpolicy` attributes on links/forms.
- Appropriate policy values that prevent leaking sensitive URL paths and query strings to third parties.

Recommended policy values:
- `no-referrer` — no referrer information sent at all.
- `strict-origin-when-cross-origin` — sends full URL for same-origin, only origin for cross-origin HTTPS, nothing for downgrade.
- `same-origin` — sends referrer only for same-origin requests.
- `no-referrer-when-downgrade` — browser default, but still leaks full URL cross-origin over HTTPS.

Language-specific patterns:
- **Python (Django):** `SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'` in `settings.py`.
- **JavaScript/Node.js (Express):** `helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' })`.
- **Java (Spring):** `http.headers().referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)`.
- **Ruby (Rails):** `config.action_dispatch.default_headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'`.
- **Go/PHP/C#:** Set header manually in middleware: `Referrer-Policy: strict-origin-when-cross-origin`.

Red flags:
- No `Referrer-Policy` set (browser default `no-referrer-when-downgrade` leaks full URLs cross-origin).
- `unsafe-url` policy (always sends full URL including query parameters to all destinations).
- Internal applications where the hostname itself is sensitive but Referrer-Policy is not set.

Safe patterns:
- `strict-origin-when-cross-origin` or `no-referrer` set globally.
- Sensitive pages additionally use `no-referrer` on outbound links.

**3.4.6 — frame-ancestors CSP directive:**

What to look for:
- `Content-Security-Policy: frame-ancestors 'none'` or `frame-ancestors 'self'` on all HTML responses.
- Whether the application relies solely on the deprecated `X-Frame-Options` header.

Red flags:
- No `frame-ancestors` directive in CSP.
- Using only `X-Frame-Options` without `frame-ancestors` (X-Frame-Options is obsolete per this requirement).
- `frame-ancestors *` or overly permissive origin lists.
- `frame-ancestors` missing on specific routes (e.g., login page, payment page).

Safe patterns:
- `frame-ancestors 'none'` as default, with specific exceptions documented and limited to necessary embedding scenarios.
- `frame-ancestors 'self'` when the application needs to embed itself in iframes on the same origin.

**3.4.7 — CSP violation reporting:**

What to look for:
- `report-uri` directive (deprecated but still widely supported) or `report-to` directive in the CSP header.
- A configured reporting endpoint that receives and processes CSP violation reports.
- Use of `Reporting-Endpoints` header in conjunction with `report-to`.

Red flags:
- No reporting directive in CSP at all.
- Reporting endpoint points to a third-party service without documented approval.
- Reporting endpoint is unreachable or returns errors.

Safe patterns:
- `Content-Security-Policy: ...; report-uri /csp-report; report-to csp-endpoint` with a functioning server-side handler.
- Use of services like report-uri.com, Sentry CSP reporting, or a custom logging endpoint.
- Both `report-uri` and `report-to` specified for cross-browser compatibility.

**3.4.8 — Cross-Origin-Opener-Policy (COOP):**

What to look for:
- `Cross-Origin-Opener-Policy: same-origin` or `Cross-Origin-Opener-Policy: same-origin-allow-popups` on all HTML document responses (`Content-Type: text/html`).
- This header prevents other origins from gaining a reference to the application's `window` object.

Red flags:
- Missing `Cross-Origin-Opener-Policy` header on HTML responses.
- `Cross-Origin-Opener-Policy: unsafe-none` explicitly set (disables protection).
- COOP only set on some pages but not others.

Safe patterns:
- `Cross-Origin-Opener-Policy: same-origin` as default for all HTML responses.
- `same-origin-allow-popups` used when the application legitimately needs to open popups to other origins and communicate with them.

N/A conditions:
- Non-HTML responses (API responses, static assets like images/CSS/JS) do not require this header.

---

## V3.5: Browser Origin Separation

When accepting a request to sensitive functionality on the server side, the application needs to ensure the request is initiated by the application itself or by a trusted party and has not been forged by an attacker.

Sensitive functionality in this context could include accepting form posts for authenticated and non-authenticated users (such as an authentication request), state-changing operations, or resource-demanding functionality (such as data export).

The key protections here are browser security policies like Same Origin Policy for JavaScript and also SameSite logic for cookies. Another common protection is the CORS preflight mechanism. This mechanism will be critical for endpoints designed to be called from a different origin, but it can also be a useful request forgery prevention mechanism for endpoints which are not designed to be called from a different origin.

| # | Requirement | Level |
|---|-------------|-------|
| **3.5.1** | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | 1 |
| **3.5.2** | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | 1 |
| **3.5.3** | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | 1 |
| **3.5.4** | Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies. | 2 |
| **3.5.5** | Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | 2 |
| **3.5.6** | Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks. | 3 |
| **3.5.7** | Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks. | 3 |
| **3.5.8** | Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content. | 3 |

### Audit Guidance for V3.5

**3.5.1 — CSRF protection via anti-forgery tokens or custom headers:**

What to look for:
- State-changing endpoints (POST, PUT, PATCH, DELETE) are protected by anti-forgery tokens (synchronizer tokens, double-submit cookies) or custom request headers that force a CORS preflight.
- The anti-forgery token is validated server-side on every state-changing request.
- Token is bound to the user's session and is cryptographically random.

Language-specific patterns:
- **Python (Django):** `CsrfViewMiddleware` enabled (check `MIDDLEWARE` setting). `{% csrf_token %}` in forms. For AJAX: `X-CSRFToken` header from cookie. Check that `@csrf_exempt` is not used broadly.
- **Python (Flask):** `flask-wtf` with `CSRFProtect(app)`. Forms use `{{ form.hidden_tag() }}` or `{{ csrf_token() }}`. Check for `@csrf.exempt` decorators.
- **JavaScript/Node.js (Express):** `csurf` middleware (deprecated) or `csrf-csrf` / `csrf-sync` packages. Check that CSRF middleware is applied to all state-changing routes. SPA approaches: custom header like `X-Requested-With`.
- **Java (Spring):** Spring Security CSRF enabled by default: `http.csrf()`. Check for `.csrf().disable()`. Thymeleaf auto-inserts CSRF tokens. For REST APIs: `CsrfTokenRequestAttributeHandler` or custom header approach.
- **PHP:** Laravel `@csrf` in Blade forms, `VerifyCsrfToken` middleware. Symfony `csrf_token()`. Check for routes excluded from CSRF middleware.
- **Ruby (Rails):** `protect_from_forgery with: :exception` in `ApplicationController`. `authenticity_token` in forms. Check for `skip_before_action :verify_authenticity_token`.
- **Go:** Libraries like `gorilla/csrf`: `csrf.Protect(authKey)(handler)`. Custom implementations using `crypto/rand` for token generation.
- **C# (ASP.NET):** `[ValidateAntiForgeryToken]` attribute on controller actions. `@Html.AntiForgeryToken()` in Razor views. `services.AddAntiforgery()` configuration.

Red flags:
- CSRF protection globally disabled or exempt on sensitive endpoints.
- Anti-forgery tokens not validated on the server side (token present in form but no server-side check).
- Token generation using predictable values (timestamps, sequential IDs).
- GET requests that perform state-changing operations (inherently unprotectable via CSRF tokens in the standard flow).

Safe patterns:
- Framework-provided CSRF middleware enabled globally with minimal exemptions.
- SPA applications using custom headers (e.g., `X-Requested-With: XMLHttpRequest`) that trigger CORS preflight for cross-origin requests.
- Double-submit cookie pattern with HMAC binding to session.

**3.5.2 — CORS preflight enforcement:**

What to look for:
- If the application relies on CORS preflight to prevent cross-origin abuse, verify that sensitive endpoints cannot be reached with "simple" requests (requests that do not trigger preflight).
- Simple requests use GET, HEAD, or POST with `Content-Type` of `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain` and only CORS-safelisted headers.

Red flags:
- Sensitive POST endpoints that accept `Content-Type: application/x-www-form-urlencoded` or `text/plain` without additional validation (these do not trigger preflight).
- No `Origin` header validation on endpoints that accept simple request content types.
- Endpoints that ignore the `Content-Type` header and parse the body regardless of the declared type.

Safe patterns:
- Sensitive endpoints require `Content-Type: application/json` (triggers preflight for cross-origin requests).
- Endpoints require a custom header (e.g., `X-Requested-With`) that is not CORS-safelisted (forces preflight).
- Server-side validation of `Origin` header against an allowlist.
- Server rejects requests where `Content-Type` does not match the expected value.

**3.5.3 — Appropriate HTTP methods for sensitive operations:**

What to look for:
- State-changing operations (creating, updating, deleting resources) use POST, PUT, PATCH, or DELETE.
- GET or HEAD requests do not trigger state changes, data mutations, or resource-intensive operations.
- Alternatively, `Sec-Fetch-*` header validation is used to reject inappropriate request contexts.

Red flags:
- GET endpoints that modify database records, trigger emails, process payments, or perform destructive actions.
- Links or image tags that trigger state changes when loaded (e.g., `<img src="/delete-account">`).
- GET-based logout endpoints (can be triggered by cross-site image loads or link prefetching).

Safe patterns:
- All state-changing operations mapped to POST/PUT/PATCH/DELETE.
- GET handlers are read-only and idempotent.
- Server-side middleware validating `Sec-Fetch-Site` and `Sec-Fetch-Mode` headers to reject unexpected cross-origin or navigation-initiated requests to API endpoints.

**3.5.4 — Separate hostnames for separate applications:**

What to look for:
- Multiple distinct applications (e.g., admin panel, user-facing app, API, documentation) hosted on the same hostname.
- Shared cookies across applications that should be isolated.

Red flags:
- Admin interface accessible at `/admin` on the same hostname as the public application (shares cookies, same-origin policy scope).
- Multiple microservices exposed under the same domain via path-based routing (e.g., `example.com/service-a`, `example.com/service-b`) without strong isolation.
- User-generated content served from the same origin as the application.

Safe patterns:
- `admin.example.com` for admin, `app.example.com` for the user-facing application, `api.example.com` for APIs.
- User-uploaded content served from a completely separate domain (e.g., `user-content.example-cdn.com`).
- Each application has its own cookie scope due to different hostnames.

**3.5.5 — postMessage origin and syntax validation:**

What to look for:
- Event listeners for `message` events that check `event.origin` before processing the message.
- Validation of message data structure/syntax before acting on it.
- Use of `targetOrigin` parameter in `postMessage()` calls (sender side).

Language-specific patterns (JavaScript):
- Unsafe: `window.addEventListener('message', (e) => { doSomething(e.data) })` — no origin check.
- Safe: `window.addEventListener('message', (e) => { if (e.origin !== 'https://trusted.example.com') return; if (!isValidSchema(e.data)) return; doSomething(e.data) })`.
- Unsafe (sender): `targetWindow.postMessage(data, '*')` — sends to any origin.
- Safe (sender): `targetWindow.postMessage(data, 'https://trusted.example.com')`.

Red flags:
- `event.origin` not checked at all.
- `event.origin` checked with `indexOf()` or loose string matching (e.g., `e.origin.indexOf('example.com')` matches `evil-example.com`).
- Message data used directly in `eval()`, `innerHTML`, or as a URL without validation.
- `postMessage()` called with `'*'` as `targetOrigin`.

Safe patterns:
- Strict `event.origin` comparison using `===` against a hardcoded trusted origin string.
- Message schema validation (e.g., checking for expected `type` field, expected data types).
- `targetOrigin` always set to the specific expected origin.

**3.5.6 — No JSONP functionality:**

What to look for:
- JSONP endpoints that wrap JSON responses in a callback function: `callbackName({...})`.
- URL parameters like `callback=`, `jsonp=`, `cb=` that control the function name wrapping the response.
- `<script>` tags used to load cross-origin data (classic JSONP pattern).

Red flags:
- Any endpoint that accepts a `callback` parameter and wraps the response in a JavaScript function call.
- Server-side code that constructs responses like `response.write(callback + '(' + JSON.stringify(data) + ')')`.
- Framework JSONP features enabled: Express `app.set('jsonp callback name', ...)` or `res.jsonp()`, Django `JsonResponse` with callback wrapping.

Safe patterns:
- CORS is used instead of JSONP for cross-origin data access.
- No endpoints accept callback parameters.
- JSONP-related framework features are explicitly disabled.

N/A conditions:
- Applications with no cross-origin data sharing requirements.

**3.5.7 — No authorized data in script responses:**

What to look for:
- JavaScript files or endpoints returning `Content-Type: application/javascript` or `text/javascript` that contain user-specific or authorization-dependent data.
- Dynamic JavaScript files that embed user data, authentication tokens, or permission information.

Red flags:
- JavaScript files that contain user-specific data (e.g., `var userData = { name: "John", email: "..." }`).
- Endpoints returning JavaScript that include API keys, tokens, or session-related data.
- Dynamic JS generation that embeds server-side data based on the authenticated user.

Safe patterns:
- JavaScript files are static and contain no user-specific data.
- User-specific data loaded via authenticated API calls (XHR/Fetch) with proper CORS restrictions, not embedded in script resources.
- Configuration data served as JSON via API endpoints (with proper CORS and authentication) rather than as JavaScript.

**3.5.8 — Authenticated resource loading protection:**

What to look for:
- `Sec-Fetch-*` header validation on endpoints serving authenticated resources (images, videos, documents).
- `Cross-Origin-Resource-Policy` (CORP) header on responses serving authenticated content.
- Whether authenticated resources can be loaded by an attacker's page via `<img>`, `<video>`, `<script>`, or `<link>` tags.

Red flags:
- Authenticated resources served without `Cross-Origin-Resource-Policy` header.
- No `Sec-Fetch-Site` or `Sec-Fetch-Dest` validation on authenticated resource endpoints.
- User avatars, private documents, or other authenticated resources loadable from any origin.

Safe patterns:
- `Cross-Origin-Resource-Policy: same-origin` on authenticated resources.
- `Cross-Origin-Resource-Policy: same-site` when resources need to be shared across subdomains.
- Server-side validation: reject requests where `Sec-Fetch-Site` is `cross-site` for private resources.
- Token-based resource access (e.g., signed URLs) that expires quickly instead of cookie-based authentication for embedded resources.

---

## V3.6: External Resource Integrity

This section provides guidance for the safe hosting of content on third-party sites.

| # | Requirement | Level |
|---|-------------|-------|
| **3.6.1** | Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource. | 3 |

### Audit Guidance for V3.6

**3.6.1 — Subresource Integrity (SRI) for external assets:**

What to look for:
- All `<script>` and `<link>` tags loading resources from external origins (CDNs, third-party domains) include an `integrity` attribute with a valid hash.
- The `crossorigin` attribute is set on elements using SRI (required for SRI to work with CORS).
- External resources are pinned to specific versions (not loading `latest` or unversioned URLs).

Example of correct SRI usage:
```html
<script src="https://cdn.example.com/lib@1.2.3/lib.min.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>
```

Red flags:
- External `<script>` or `<link>` tags without `integrity` attributes.
- SRI hashes using SHA-256 only (SHA-384 or SHA-512 preferred for stronger collision resistance).
- External resources loaded from unversioned URLs (e.g., `https://cdn.example.com/lib/latest/lib.js`).
- `crossorigin` attribute missing on SRI-protected elements (SRI check will fail silently).
- Dynamic loading of external scripts via JavaScript (`document.createElement('script')`) without integrity verification.

Safe patterns:
- All external assets versioned and SRI-protected with SHA-384 or SHA-512 hashes.
- Build tools (Webpack, Vite, Rollup) configured to generate SRI hashes automatically.
- Package managers used to vendor dependencies locally instead of relying on CDNs (eliminates the need for SRI).
- A documented security decision for any external resource where SRI cannot be applied (e.g., dynamically generated resources from a trusted third party).

N/A conditions:
- Applications that self-host all client-side assets (no external CDN dependencies).
- Applications where all JavaScript, CSS, and fonts are bundled and served from the same origin.

---

## V3.7: Other Browser Security Considerations

This section includes various other security controls and modern browser security features required for client-side browser security.

| # | Requirement | Level |
|---|-------------|-------|
| **3.7.1** | Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. | 2 |
| **3.7.2** | Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist. | 2 |
| **3.7.3** | Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation. | 3 |
| **3.7.4** | Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field. | 3 |
| **3.7.5** | Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features. | 3 |

### Audit Guidance for V3.7

**3.7.1 — No deprecated or insecure client-side technologies:**

What to look for:
- HTML `<object>`, `<embed>`, or `<applet>` tags referencing Flash (`.swf`), Shockwave, ActiveX controls, Silverlight (`.xap`), NaCl modules (`.nexe`, `.pexe`), or Java applets (`.jar`, `.class`).
- `<param>` elements within `<object>` tags configuring plugin-based content.
- MIME types in responses indicating plugin content: `application/x-shockwave-flash`, `application/x-silverlight`, `application/x-java-applet`.

Red flags:
- Any reference to Flash, Shockwave, ActiveX, Silverlight, NaCl, or Java applets in HTML templates, JavaScript, or server-side view code.
- `<embed type="application/x-shockwave-flash" ...>` or similar elements.
- Server-side code generating responses with plugin-related MIME types.
- Third-party integrations that require browser plugins (e.g., legacy document viewers, legacy rich-text editors).

Safe patterns:
- HTML5 `<video>` and `<audio>` elements used instead of Flash-based media players.
- WebAssembly (`.wasm`) used instead of NaCl or Java applets for client-side computation.
- Modern JavaScript frameworks for rich UI instead of Silverlight or Flash.

N/A conditions:
- Applications with no web frontend (pure API services).

**3.7.2 — External redirect allowlisting:**

What to look for:
- All code paths where the application performs HTTP redirects (3xx responses) or client-side redirects (`window.location`, `meta refresh`) based on user input or dynamic data.
- Whether redirect destinations to external domains are validated against an allowlist.

Language-specific patterns:
- **Python (Django):** `HttpResponseRedirect(url)`, `redirect(url)`. Check for `url_has_allowed_host_and_scheme()` (previously `is_safe_url()`). `LOGIN_REDIRECT_URL` and `LOGOUT_REDIRECT_URL` settings.
- **Python (Flask):** `redirect(url)`, `flask.url_for()`. Check for external URL validation before redirect.
- **JavaScript/Node.js (Express):** `res.redirect(url)`. Check if `url` is user-controlled and whether it is validated against a whitelist.
- **Java (Spring):** `RedirectView`, `"redirect:" + url` in controller returns. Check for `UriComponentsBuilder` validation.
- **PHP:** `header('Location: ' . $url)`. Check if `$url` is user-controlled.
- **Ruby (Rails):** `redirect_to(url)`. Check `allow_other_host: false` (Rails 7+ default).
- **Go:** `http.Redirect(w, r, url, http.StatusFound)`. Check if `url` is user-controlled.
- **C# (ASP.NET):** `Redirect(url)`, `RedirectToAction()`, `LocalRedirect(url)`. `LocalRedirect` only allows local URLs.

Red flags:
- Redirect URL taken directly from query parameters (e.g., `?redirect_url=`, `?next=`, `?return_to=`) without validation.
- Allowlist check using substring matching or `startsWith()` (e.g., `url.startsWith('https://example.com')` can be bypassed with `https://example.com.evil.com`).
- Open redirect on login/logout flows.

Safe patterns:
- `LocalRedirect()` (ASP.NET) or equivalent local-only redirect functions.
- Server-side allowlist of permitted external domains with exact hostname matching.
- Redirect URLs stored server-side (e.g., mapping tokens to URLs) rather than passed in query parameters.
- URL parsing with a trusted library and explicit hostname comparison before redirect.

**3.7.3 — User notification for external redirects:**

What to look for:
- Interstitial or confirmation pages shown before redirecting users to external URLs.
- An option for the user to cancel the navigation and return to the application.

Red flags:
- Automatic redirects to external URLs with no user notification.
- Warning page that auto-redirects after a timer without requiring user action.
- External links in the application that do not indicate they lead outside the application.

Safe patterns:
- An interstitial page: "You are about to leave [App Name] and visit [external URL]. [Continue] [Cancel]".
- External links visually indicated with an icon and opening in a new tab with `rel="noopener noreferrer"`.
- A centralized redirect service within the application that shows warnings before proceeding.

N/A conditions:
- Applications that have no external redirects or outbound links.
- Internal-only applications where all redirect destinations are within the organization's control.

**3.7.4 — HSTS preload list inclusion:**

What to look for:
- The application's top-level domain (e.g., `example.com`) submitted to and included in the HSTS preload list at [hstspreload.org](https://hstspreload.org/).
- The HSTS header includes `preload` directive: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.

Red flags:
- HSTS header does not include the `preload` directive.
- Domain not found on the HSTS preload list (check at https://hstspreload.org/).
- `max-age` less than 31536000 (1 year) or missing `includeSubDomains` — both are required for preload eligibility.
- Subdomains that cannot support HTTPS (preload with `includeSubDomains` will break them).

Safe patterns:
- Domain successfully submitted and present on the HSTS preload list.
- All subdomains support HTTPS (verified before preload submission).
- HSTS header includes `max-age=31536000; includeSubDomains; preload` on the bare domain.

N/A conditions:
- Applications hosted on shared domains or platforms where the top-level domain is not controlled by the application owner.
- Internal-only applications not accessible from the public internet.

**3.7.5 — Browser feature detection and documented behavior:**

What to look for:
- Client-side feature detection scripts that check for required browser capabilities.
- Behavior matches what is documented in V3.1.1 (warning users or blocking access when features are missing).
- Graceful degradation or fail-closed behavior when expected security features are not supported.

Red flags:
- No feature detection code present despite documented browser requirements.
- Feature detection exists but only logs warnings to the console (not visible to users).
- Application silently continues operating in a degraded security state without informing the user.
- Documentation says "block access" but the application merely shows a dismissible banner.

Safe patterns:
- JavaScript feature detection at application startup that checks for required APIs (e.g., `window.crypto.subtle`, CSP support, `fetch` API, `SameSite` cookie support).
- A prominent warning banner or modal when a required feature is missing, matching the documented behavior.
- Hard block (redirect to an unsupported-browser page) when critical security features are absent, if that is the documented policy.

N/A conditions:
- Applications that do not have documented browser security feature requirements (though this itself would be a V3.1.1 issue).
- Applications targeting only controlled environments where browser versions are managed (e.g., enterprise kiosk mode).

---

## References

For more information, see also:

* [Set-Cookie __Host- prefix details](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes)
* [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
* [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [HSTS Browser Preload List submission form](https://hstspreload.org/)
* [OWASP DOM Clobbering Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)

---

## V3 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 8 | 3.2.1, 3.2.2, 3.3.1, 3.4.1, 3.4.2, 3.5.1, 3.5.2, 3.5.3 |
| L2 | 11 | 3.3.2, 3.3.3, 3.3.4, 3.4.3, 3.4.4, 3.4.5, 3.4.6, 3.5.4, 3.5.5, 3.7.1, 3.7.2 |
| L3 | 12 | 3.1.1, 3.2.3, 3.3.5, 3.4.7, 3.4.8, 3.5.6, 3.5.7, 3.5.8, 3.6.1, 3.7.3, 3.7.4, 3.7.5 |
| **Total** | **31** | |
