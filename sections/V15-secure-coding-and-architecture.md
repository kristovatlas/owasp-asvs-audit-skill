# V15: Secure Coding and Architecture

**ASVS Version:** 5.0.0
**Source file:** `5.0/en/0x24-V15-Secure-Coding-and-Architecture.md`

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

Many ASVS requirements either relate to a particular area of security, such as authentication or authorization, or pertain to a particular type of application functionality, such as logging or file handling.

This chapter provides general security requirements to consider when designing and developing applications. These requirements focus not only on clean architecture and code quality but also on specific architecture and coding practices necessary for application security.

---

## V15.1: Secure Coding and Architecture Documentation

Many requirements for establishing a secure and defensible architecture depend on clear documentation of decisions made regarding the implementation of specific security controls and the components used within the application.

This section outlines the documentation requirements, including identifying components considered to contain "dangerous functionality" or to be "risky components."

A component with "dangerous functionality" may be an internally developed or third-party component that performs operations such as deserialization of untrusted data, raw file or binary data parsing, dynamic code execution, or direct memory manipulation. Vulnerabilities in these types of operations pose a high risk of compromising the application and potentially exposing its underlying infrastructure.

A "risky component" is a 3rd party library (i.e., not internally developed) with missing or poorly implemented security controls around its development processes or functionality. Examples include components that are poorly maintained, unsupported, at the end-of-life stage, or have a history of significant vulnerabilities.

This section also emphasizes the importance of defining appropriate timeframes for addressing vulnerabilities in third-party components.

| # | Requirement | Level |
|---|-------------|-------|
| **15.1.1** | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | 1 |
| **15.1.2** | Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories. | 2 |
| **15.1.3** | Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application. | 2 |
| **15.1.4** | Verify that application documentation highlights third-party libraries which are considered to be "risky components". | 3 |
| **15.1.5** | Verify that application documentation highlights parts of the application where "dangerous functionality" is being used. | 3 |

### Audit Guidance for V15.1

**General approach:** These are documentation requirements. The sub-agent should look for evidence of documented security architecture decisions, component inventories, and risk classifications in:
- README files, architecture docs, ADRs (Architecture Decision Records)
- Software Bill of Materials (SBOM) files (CycloneDX, SPDX formats)
- Dependency management files with documented policies (e.g., Dependabot config, Renovate config, `.nsprc`, audit policies)
- Threat model documents or risk assessment artifacts
- Wiki or docs directories in the repo

**15.1.1 -- Documented remediation timeframes for vulnerable components:**

What to look for:
- A documented vulnerability remediation policy specifying SLA timeframes by severity (e.g., critical within 48 hours, high within 7 days, medium within 30 days, low within 90 days).
- Dependabot or Renovate configuration with auto-merge policies and scheduled update windows, which may serve as implicit documentation of update cadence.
- A security policy file (`SECURITY.md`, `security-policy.md`) that defines how vulnerabilities in dependencies are handled.
- CI/CD pipelines that run `npm audit`, `pip audit`, `bundler-audit`, `OWASP Dependency-Check`, `Snyk`, `Trivy`, or similar tools, combined with documented thresholds for when builds should fail.
- **Red flags:** No documented policy at all; dependencies with known critical CVEs that have been unpatched for extended periods (check lock files against known vulnerability databases).

**15.1.2 -- Software Bill of Materials (SBOM) and trusted repositories:**

What to look for:
- SBOM files in CycloneDX (`bom.json`, `bom.xml`) or SPDX format (`*.spdx`, `*.spdx.json`).
- CI/CD steps that generate SBOMs as part of the build pipeline (e.g., `cyclonedx-bom`, `syft`, `cdxgen`).
- Lock files (`package-lock.json`, `yarn.lock`, `Pipfile.lock`, `poetry.lock`, `Gemfile.lock`, `go.sum`, `Cargo.lock`) serve as implicit dependency inventories but are not formal SBOMs.
- Registry configuration that restricts package sources to trusted repositories (`.npmrc` with registry setting, `pip.conf` with index-url, Maven `settings.xml` with mirror configuration, private Artifactory/Nexus configuration).
- **Red flags:** No lock files committed, no SBOM generation, packages sourced from arbitrary or unknown registries.

**15.1.3 -- Documented resource-demanding functionality:**

What to look for:
- Architecture documentation identifying endpoints or operations that are computationally expensive, memory-intensive, or involve large data processing (report generation, bulk exports, image/video processing, complex queries).
- Documentation of timeout strategies, queue-based processing, or async handling for expensive operations.
- Configuration for request timeouts, connection pool limits, or worker process limits.
- **Red flags:** No documentation of which operations are resource-intensive; no documented strategy for preventing resource exhaustion.

**15.1.4 -- Documented "risky components":**

What to look for:
- Documentation explicitly identifying third-party libraries that are poorly maintained, have a history of vulnerabilities, or are end-of-life.
- Risk assessments or dependency review documents that classify components by risk level.
- This is a Level 3 requirement and is commonly absent. Mark as FAIL if no such documentation exists, but note that the application may still have mitigations in place (covered in 15.2.5).

**15.1.5 -- Documented "dangerous functionality":**

What to look for:
- Documentation identifying code paths that perform deserialization of untrusted data, dynamic code execution (`eval`, `exec`, `Function()`, reflection-based invocation), raw binary parsing, direct memory manipulation, or native code interop (JNI, FFI, P/Invoke).
- Threat models or security design reviews that call out these areas of risk.
- This is a Level 3 requirement. Mark as FAIL if no such documentation exists. If you can identify dangerous functionality in code but it is not documented, note that as a finding.

---

## V15.2: Security Architecture and Dependencies

This section includes requirements for handling risky, outdated, or insecure dependencies and components through dependency management.

It also includes using architectural-level techniques such as sandboxing, encapsulation, containerization, and network isolation to reduce the impact of using "dangerous operations" or "risky components" (as defined in the previous section) and prevent loss of availability due to overusing resource-demanding functionality.

| # | Requirement | Level |
|---|-------------|-------|
| **15.2.1** | Verify that the application only contains components which have not breached the documented update and remediation time frames. | 1 |
| **15.2.2** | Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this. | 2 |
| **15.2.3** | Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality. | 2 |
| **15.2.4** | Verify that third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack. | 3 |
| **15.2.5** | Verify that the application implements additional protections around parts of the application which are documented as containing "dangerous functionality" or using third-party libraries considered to be "risky components". This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application. | 3 |

### Audit Guidance for V15.2

**15.2.1 -- Components within documented remediation timeframes:**

What to look for:
- Run or review results from dependency vulnerability scanners (`npm audit`, `pip audit`, `bundle audit`, `dotnet list package --vulnerable`, OWASP Dependency-Check, Snyk, Trivy, Grype).
- Compare findings against the documented remediation SLAs from 15.1.1. Any vulnerability that has exceeded its severity-based timeframe is a FAIL.
- Check lock files and manifest files for dependencies with known CVEs. Cross-reference dependency versions against public vulnerability databases (NVD, GitHub Advisory Database, OSV).
- **Good patterns:** CI/CD pipelines that block merges when critical or high vulnerabilities are detected; automated dependency update PRs (Dependabot, Renovate) that are reviewed and merged promptly.
- **Red flags:** `npm audit` or equivalent producing critical/high findings with no evidence of remediation; lock files containing dependencies with long-standing known vulnerabilities.

**15.2.2 -- Defenses against resource exhaustion:**

What to look for:
- Implementation of timeouts on expensive operations (database query timeouts, HTTP client timeouts, processing timeouts).
- Queue-based or async processing for long-running tasks (Celery, Sidekiq, Bull/BullMQ, AWS SQS, RabbitMQ).
- Resource limits: connection pool sizes, thread pool sizes, worker process limits, memory limits.
- Request-level protections: request body size limits, pagination enforcement on list endpoints, query complexity limits for GraphQL.
- Circuit breakers for external service calls (e.g., Hystrix, resilience4j, Polly, opossum).
- **Red flags:** Unbounded database queries (no `LIMIT`), synchronous processing of potentially large datasets in request handlers, no timeouts configured on external HTTP calls, endpoints that return unlimited result sets.

**15.2.3 -- No extraneous functionality in production:**

What to look for:
- **Test code in production builds:** Check for test files, test directories, test utilities, or test fixtures included in the production deployment artifact. Look for `__tests__`, `test/`, `spec/`, `*.test.*`, `*.spec.*` in production bundles.
- **Debug/development features:** Debug endpoints (`/debug`, `/phpinfo`, `/actuator` without authentication, `/graphiql`, `/swagger-ui` in production), development middleware left enabled (e.g., Django `DEBUG=True`, Express `errorHandler` with stack traces, Spring DevTools in production).
- **Sample code and defaults:** Default credentials, sample API keys, example configuration, boilerplate routes (`/hello`, `/test`, `/example`).
- **Build configuration:** Check that production builds use production mode (`NODE_ENV=production`, `RAILS_ENV=production`, `DJANGO_SETTINGS_MODULE` pointing to production settings). Check that `devDependencies` are not installed in production (`npm install --production` or equivalent).
- **Good patterns:** Separate Dockerfiles or build stages for development and production; `.dockerignore` excluding test files; build scripts that explicitly strip development artifacts.

**15.2.4 -- Dependency confusion prevention:**

What to look for:
- **Scoped packages / namespaces:** Are internal packages scoped under an organization namespace (e.g., `@company/package` in npm, organization-owned packages in PyPI/private index)?
- **Registry configuration:** `.npmrc`, `pip.conf`, `settings.xml`, `nuget.config` configured to resolve internal packages from private registries and public packages from official registries, with no ambiguity.
- **Lock files:** Presence of lock files that pin exact versions and registry sources. Check that lock files include integrity hashes and source URLs.
- **Namespace reservation:** Has the organization reserved its package names on public registries to prevent attackers from publishing malicious packages with the same names?
- **Red flags:** Internal package names that are not scoped/namespaced and could exist on public registries; no private registry configuration; mixed registry sources without explicit scoping rules.

**15.2.5 -- Isolation of dangerous functionality and risky components:**

What to look for:
- **Sandboxing:** Are deserialization, code execution, or file parsing operations executed in sandboxed environments (e.g., `vm2`/`isolated-vm` for Node.js, seccomp/AppArmor profiles, WebAssembly sandboxes)?
- **Containerization:** Are risky components deployed in separate containers with minimal privileges and restricted network access?
- **Network isolation:** Are components with dangerous functionality placed in separate network segments with firewall rules limiting their access to other services?
- **Process isolation:** Are dangerous operations run in separate processes with restricted permissions (e.g., separate worker processes, `chroot`, Linux namespaces)?
- **Principle of least privilege:** Do components performing dangerous operations run with minimal file system access, network access, and OS privileges?
- **Good patterns:** Microservice architecture where risky processing is isolated; container security contexts with `readOnlyRootFilesystem`, `runAsNonRoot`, dropped capabilities; separate Kubernetes namespaces with network policies.
- **Red flags:** Deserialization of untrusted data in the main application process with full access to all resources; dynamic code execution in the same process as sensitive data handling; no separation between dangerous functionality and the rest of the application.

---

## V15.3: Defensive Coding

This section covers vulnerability types, including type juggling, prototype pollution, and others, which result from using insecure coding patterns in a particular language. Some may not be relevant to all languages, whereas others will have language-specific fixes or may relate to how a particular language or framework handles a feature such as HTTP parameters. It also considers the risk of not cryptographically validating application updates.

It also considers the risks associated with using objects to represent data items and accepting and returning these via external APIs. In this case, the application must ensure that data fields that should not be writable are not modified by user input (mass assignment) and that the API is selective about what data fields get returned. Where field access depends on a user's permissions, this should be considered in the context of the field-level access control requirement in the Authorization chapter.

| # | Requirement | Level |
|---|-------------|-------|
| **15.3.1** | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | 1 |
| **15.3.2** | Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality. | 2 |
| **15.3.3** | Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action. | 2 |
| **15.3.4** | Verify that all proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls. | 2 |
| **15.3.5** | Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type. | 2 |
| **15.3.6** | Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals. | 2 |
| **15.3.7** | Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields). | 2 |

### Audit Guidance for V15.3

**15.3.1 -- Selective field return (no over-exposure of data):**

What to look for:
- **Good patterns:** DTOs (Data Transfer Objects) or serializers that explicitly list which fields to include in API responses. Response-specific view models separate from database entities. Serializer field whitelists (`fields = [...]` in Django REST Framework, `@JsonView` in Jackson, `@Expose` in class-transformer, GraphQL field resolvers that limit returned fields).
- **Red flags:** Database models or ORM entities returned directly as API responses (`res.json(user)` where `user` is a raw database object). `SELECT *` queries whose results are passed directly to responses. Serializers that use `fields = '__all__'` (Django) or include all model attributes without explicit exclusion of sensitive fields (password hashes, internal IDs, tokens, PII).
- Language-specific patterns:
  - **Express/Node.js:** Check if Mongoose `toJSON` transforms or manual field selection is used. Watch for `res.json(document.toObject())` without field filtering.
  - **Django REST Framework:** Check serializer `Meta.fields` — are sensitive fields excluded? Is `fields = '__all__'` used?
  - **Rails:** Check for `as_json` or `to_json` calls — are `only` or `except` options used? Are serializers (ActiveModelSerializers, Blueprinter, Alba) configured with explicit field lists?
  - **Spring:** Check for `@JsonIgnore` on sensitive fields, or dedicated response DTOs separate from JPA entities.
  - **Laravel:** Check for `$hidden` on Eloquent models, or API Resources with explicit field selection.

**15.3.2 -- Backend URL calls configured to not follow redirects:**

What to look for:
- HTTP client configurations in backend code. Check whether redirect-following is disabled by default or explicitly controlled.
- Language-specific patterns:
  - **Node.js (axios):** `maxRedirects: 0` or `followRedirect: false`. Default axios follows redirects.
  - **Node.js (node-fetch/undici):** `redirect: 'manual'` or `redirect: 'error'`. Default is `follow`.
  - **Python (requests):** `allow_redirects=False`. Default is `True` for GET.
  - **Java (HttpClient):** `HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)`.
  - **Go:** Custom `CheckRedirect` function on `http.Client` that returns an error.
  - **C# (HttpClient):** `HttpClientHandler.AllowAutoRedirect = false`.
- **Red flags:** Backend code that fetches user-supplied URLs (SSRF-prone patterns) with default redirect-following enabled. Webhook handlers, URL preview generators, or link validators that follow redirects to arbitrary destinations.
- **Context:** If the application intentionally follows redirects for a specific use case (e.g., OAuth flows), that should be documented and the redirect target should be validated. The key concern is uncontrolled redirect-following that could be exploited for SSRF.

**15.3.3 -- Mass assignment protection:**

What to look for:
- **Good patterns:**
  - **Rails:** Strong Parameters (`params.require(:model).permit(:field1, :field2)`) used consistently in controllers.
  - **Django:** ModelForm `Meta.fields` explicitly listing allowed fields (not `__all__`). DRF serializer `Meta.fields` with explicit lists.
  - **Spring:** `@ModelAttribute` with `@InitBinder` and `setAllowedFields()`, or dedicated request DTOs that only contain the expected fields.
  - **Express/Node.js:** Explicit destructuring or picking of expected fields from `req.body` before passing to ORM. Mongoose schema-level `select: false` for sensitive fields. Validation middleware (Joi, Zod) that strips unknown fields.
  - **Laravel:** `$fillable` (whitelist) on Eloquent models, or `$guarded` (blacklist, less preferred). Form Requests that validate only expected fields.
- **Red flags:** Passing `req.body` or request data directly to ORM `create()` or `update()` without field filtering. Models with no `$fillable`/`$guarded` (Laravel) or no strong parameters (Rails). Using `__all__` in Django form/serializer fields.
- Check for fields that should never be mass-assignable: `is_admin`, `role`, `permissions`, `email_verified`, `account_balance`, `created_at`, `id`.

**15.3.4 -- Correct IP address forwarding through proxies:**

What to look for:
- **Reverse proxy configuration:** Check nginx, Apache, HAProxy, or cloud load balancer configuration for correct `X-Forwarded-For` header handling. The proxy should set `X-Real-IP` or properly manage the `X-Forwarded-For` chain.
- **Application trust configuration:** The application must be configured to trust proxy headers only from known proxy IPs, not from any source.
  - **Express:** `app.set('trust proxy', ...)` — check that it is not set to `true` (trusts all), but rather to specific proxy IPs or `loopback`.
  - **Django:** `SECURE_PROXY_SSL_HEADER` and middleware for `X-Forwarded-For` parsing with trusted proxy configuration.
  - **Rails:** `config.action_dispatch.trusted_proxies` configuration.
  - **Spring:** `server.forward-headers-strategy` and `server.tomcat.remoteip.internal-proxies`.
- **Red flags:** Application reads `X-Forwarded-For` header directly from the request and trusts the first (leftmost) value, which is user-controlled. No trusted proxy configuration — any client can spoof their IP by setting `X-Forwarded-For`. Rate limiting or access control decisions based on an IP value that can be spoofed.

**15.3.5 -- Strict type checking and comparisons:**

What to look for:
- This is primarily relevant to dynamically-typed languages (JavaScript/TypeScript, PHP, Python, Ruby) but can also apply to languages with implicit type coercion.
- **JavaScript/TypeScript:**
  - Use of `===` and `!==` (strict equality) instead of `==` and `!=` (loose equality). ESLint rule `eqeqeq` enforced.
  - TypeScript with `strict: true` in `tsconfig.json` (enables `strictNullChecks`, `noImplicitAny`, etc.).
  - Explicit type validation of inputs before comparison (e.g., checking `typeof value === 'string'` before comparison).
- **PHP:**
  - Use of `===` instead of `==`. Especially critical for password comparison, authentication checks, and security-sensitive comparisons.
  - `declare(strict_types=1)` in PHP files.
  - Avoid `switch` statements with loose comparison; use `match` (PHP 8+) which uses strict comparison.
- **Python:** Generally less vulnerable to type juggling, but check for unsafe comparisons with `None` (use `is None`, not `== None`), and ensure numeric types are validated before arithmetic.
- **Red flags:** Security-critical comparisons (password checks, token validation, role checks, HMAC comparison) using loose equality. Input values assumed to be strings but not validated, allowing array/object injection in PHP or type coercion in JavaScript.

**15.3.6 -- Prototype pollution prevention (JavaScript):**

Mark as N/A if the application does not use JavaScript/TypeScript.

What to look for:
- **Vulnerable patterns:** Deep merge/extend utilities that recursively copy properties from user-controlled objects without filtering `__proto__`, `constructor`, or `prototype` keys. Libraries like older versions of `lodash.merge`, `deepmerge`, `jQuery.extend(true, ...)`.
- **Good patterns:**
  - Use of `Map()` and `Set()` instead of plain objects for user-controlled key-value data.
  - `Object.create(null)` for objects used as dictionaries (no prototype chain).
  - Input validation that rejects or strips `__proto__`, `constructor`, `prototype` keys from user input.
  - Use of `Object.freeze(Object.prototype)` as a defense-in-depth measure.
  - Updated versions of merge libraries that include prototype pollution protections.
- **Red flags:** Custom deep merge/clone functions that do not filter prototype-related keys. User-supplied JSON parsed and merged into configuration or template objects. Query parameter parsing that allows nested object creation (e.g., `qs` library with default settings).
- Check `package.json` / `package-lock.json` for known-vulnerable versions of libraries with prototype pollution CVEs.

**15.3.7 -- HTTP parameter pollution (HPP) defenses:**

What to look for:
- **Framework behavior awareness:** Different frameworks handle duplicate parameter names differently (first value, last value, array of values). The application should be aware of its framework's behavior and not make assumptions.
- **Good patterns:**
  - HPP middleware (e.g., `hpp` package for Express) that takes the last value for duplicate parameters.
  - Explicit parameter source specification — accessing parameters from a specific source (`req.query`, `req.body`) rather than a merged `req.params` or equivalent.
  - Input validation that rejects unexpected array values where scalars are expected.
- **Red flags:** Using framework-provided "merged" parameter objects that combine query string, body, and cookie values without distinguishing the source (e.g., PHP `$_REQUEST`, Express `req.param()` which is deprecated). Security logic (authentication, authorization) that reads from an ambiguous parameter source.
- **Context:** This is especially important for applications behind WAFs or proxies that may process parameters differently than the application server, allowing parameter smuggling.

---

## V15.4: Safe Concurrency

Concurrency issues such as race conditions, time-of-check to time-of-use (TOCTOU) vulnerabilities, deadlocks, livelocks, thread starvation, and improper synchronization can lead to unpredictable behavior and security risks. This section includes various techniques and strategies to help mitigate these risks.

| # | Requirement | Level |
|---|-------------|-------|
| **15.4.1** | Verify that shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption. | 3 |
| **15.4.2** | Verify that checks on a resource's state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user's access before granting it. | 3 |
| **15.4.3** | Verify that locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code. | 3 |
| **15.4.4** | Verify that resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe. | 3 |

### Audit Guidance for V15.4

**General approach:** All requirements in this section are Level 3. Concurrency issues are often difficult to detect through static analysis alone and may require code review combined with architectural understanding. These requirements are most relevant to applications that use multi-threading, async/await with shared state, or process shared resources concurrently. Mark as N/A for simple single-threaded applications with no shared mutable state.

**15.4.1 -- Thread-safe access to shared objects:**

What to look for:
- **Good patterns:**
  - **Java:** Use of `ConcurrentHashMap`, `AtomicInteger`, `volatile` fields, `synchronized` blocks/methods, `ReentrantLock`, `ReadWriteLock`. Classes from `java.util.concurrent`.
  - **C#/.NET:** `ConcurrentDictionary`, `lock` statements, `SemaphoreSlim`, `ReaderWriterLockSlim`, `Interlocked` class, thread-safe collections from `System.Collections.Concurrent`.
  - **Python:** `threading.Lock`, `threading.RLock`, `queue.Queue` for thread-safe communication, `multiprocessing.Manager` for shared state.
  - **Go:** `sync.Mutex`, `sync.RWMutex`, `sync.Map`, channels for goroutine communication, `atomic` package.
  - **Node.js:** Generally single-threaded, but check for `SharedArrayBuffer` usage with `Atomics`, or `worker_threads` with shared memory.
- **Red flags:** Global mutable variables accessed from multiple threads/goroutines without synchronization. Caches (in-memory, file-based) modified concurrently without locking. File writes from multiple threads without coordination. Non-thread-safe collections used in concurrent contexts.

**15.4.2 -- Atomic check-and-act operations (TOCTOU prevention):**

What to look for:
- **File operations:** Check-then-act patterns like `if (file.exists()) { file.open() }` — the file could be deleted or replaced between the check and the open. Use atomic operations or file locking instead.
- **Database operations:** Read-then-write patterns without row-level locking or optimistic concurrency control. For example, reading a balance, checking if sufficient, then updating — these should use `SELECT ... FOR UPDATE` or atomic updates (`UPDATE ... SET balance = balance - amount WHERE balance >= amount`).
- **Permission checks:** Verifying authorization and then performing the action in separate steps, where permissions could change between the check and the action.
- **Good patterns:** Atomic database operations, `SELECT ... FOR UPDATE`, optimistic locking with version columns, file locking (`flock`, `lockf`), atomic file operations (`rename` instead of read-delete-write), using transactions that encompass both the check and the action.
- **Red flags:** Separate read and write calls to the database for operations that should be atomic. File existence checks followed by file operations without locking. Authorization checks in middleware followed by resource access in handlers without re-verification within the same transaction.

**15.4.3 -- Consistent locking to prevent deadlocks and livelocks:**

What to look for:
- **Deadlock prevention:** Are locks always acquired in a consistent order across the codebase? If multiple locks are needed, is there a documented lock ordering convention?
- **Lock encapsulation:** Is locking logic encapsulated within the resource-managing class/module, rather than requiring callers to manage locks externally? External lock management increases the risk of forgetting to lock or locking incorrectly.
- **Timeout on lock acquisition:** Are lock attempts made with timeouts (e.g., `tryLock(timeout)` in Java, `Lock.acquire(timeout)` in Python) to prevent indefinite blocking?
- **Good patterns:** Lock encapsulation within resource managers, consistent lock ordering, lock timeout mechanisms, using higher-level concurrency abstractions (channels, actors, STM) that avoid explicit locking.
- **Red flags:** Nested lock acquisition in inconsistent order across different code paths. Locks exposed as public fields or returned from public methods. Infinite retry loops on lock acquisition without backoff or timeout. Locks acquired in callbacks or event handlers where ordering is unpredictable.

**15.4.4 -- Prevention of thread starvation:**

What to look for:
- **Thread pools:** Are thread pools used instead of unbounded thread creation? Check for `Executors.newFixedThreadPool()` (Java), `ThreadPoolExecutor` (Python), worker pool patterns (Go), `ThreadPool` (C#).
- **Fair scheduling:** Are fair locks or fair semaphores used where priority inversion could be a problem? (e.g., `ReentrantLock(true)` for fair lock in Java, `SemaphoreSlim` with FIFO ordering in C#).
- **Priority management:** If the application uses thread priorities, do lower-priority threads still get to execute within a reasonable timeframe? Is priority inversion handled (e.g., priority inheritance)?
- **Good patterns:** Bounded thread pools with appropriate sizing, work-stealing pools (`ForkJoinPool` in Java), fair lock implementations, task queues with guaranteed processing order, async/await patterns that avoid blocking thread pool threads.
- **Red flags:** Unbounded thread creation (new thread per request without limits), long-running tasks executing in shared thread pools without yielding, thread pools with no maximum size, high-priority threads monopolizing CPU with no mechanism for lower-priority work to proceed.

---

## References

For more information, see also:

* [OWASP Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
* [OWASP Mass Assignment Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
* [OWASP CycloneDX Bill of Materials Specification](https://owasp.org/www-project-cyclonedx/)
* [OWASP Web Security Testing Guide: Testing for HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)

---

## V15 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 3 | 15.1.1, 15.2.1, 15.3.1 |
| L2 | 10 | 15.1.2, 15.1.3, 15.2.2, 15.2.3, 15.3.2, 15.3.3, 15.3.4, 15.3.5, 15.3.6, 15.3.7 |
| L3 | 8 | 15.1.4, 15.1.5, 15.2.4, 15.2.5, 15.4.1, 15.4.2, 15.4.3, 15.4.4 |
| **Total** | **21** | |
