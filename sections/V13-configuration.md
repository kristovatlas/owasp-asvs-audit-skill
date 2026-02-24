# V13: Configuration

**ASVS Version:** 5.0.0
**ASVS Source:** `0x22-V13-Configuration.md` in the [OWASP ASVS v5.0.0 repo](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/)

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

The application's default configuration must be secure for use on the Internet.

This chapter provides guidance on the various configurations necessary to achieve this, including those applied during development, build, and deployment.

Topics covered include preventing data leakage, securely managing communication between components, and protecting secrets.

---

## V13.1: Configuration Documentation

This section outlines documentation requirements for how the application communicates with internal and external services, as well as techniques to prevent loss of availability due to service inaccessibility. It also addresses documentation related to secrets.

| # | Requirement | Level |
|---|-------------|-------|
| **13.1.1** | Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect. | 2 |
| **13.1.2** | Verify that for each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions. | 3 |
| **13.1.3** | Verify that the application documentation defines resource-management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource-release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back-off algorithms. For synchronous HTTP request-response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion. | 3 |
| **13.1.4** | Verify that the application's documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization's threat model and business requirements. | 3 |

### Audit Guidance for V13.1

**General approach:** These are documentation requirements. The sub-agent should look for evidence of documented configuration, communication needs, resource management strategies, and secret rotation policies in:
- README files, architecture docs, ADRs (Architecture Decision Records)
- Infrastructure-as-code files (Terraform, CloudFormation, Kubernetes manifests, Helm charts, Docker Compose)
- Configuration management docs, runbooks, or operations guides
- Inline code comments describing connection pool settings, timeouts, and retry logic
- Wiki or docs directories in the repo

**13.1.1 -- Documented communication needs:**

What to look for:
- Architecture diagrams or docs listing external services (databases, caches, message queues, third-party APIs, payment gateways, email services, storage services).
- Network configuration files that enumerate allowed outbound connections (firewall rules, security group definitions, network policies).
- Docker Compose or Kubernetes manifests revealing service dependencies.
- OpenAPI specs, service mesh configurations, or dependency documentation.
- Check whether user-controllable outbound connections (webhooks, SSRF-prone features like URL-based file imports) are documented.
- If service dependencies exist in code (connection strings, API client instantiations) but are not documented anywhere, this is a finding.

**13.1.2 -- Documented connection pool limits and fallback behavior:**

What to look for:
- Documentation or configuration of connection pool sizes for databases (e.g., HikariCP `maximumPoolSize`, SQLAlchemy `pool_size`, Django `CONN_MAX_AGE`, ActiveRecord `pool`), HTTP client pools, Redis connection pools, message queue connections.
- Documentation of what happens when pool limits are reached: queue requests, reject with error, circuit breaker activation.
- Configuration files that define pool settings (even without separate documentation, explicitly configured pool sizes count as partial evidence).
- If connection pools are configured in code/config but behavior when limits are reached is not documented, flag as partial.

**13.1.3 -- Documented resource management strategies:**

What to look for:
- Documentation of timeout settings for external service calls (connect timeout, read timeout, overall timeout).
- Retry logic documentation: retry count, delay between retries, exponential backoff, jitter.
- Resource cleanup/release procedures (connection closing, file handle cleanup, thread pool shutdown).
- Circuit breaker patterns (Hystrix, Resilience4j, Polly, `cockatiel`, `opossum`).
- For HTTP request-response operations, check that short timeouts are documented and retry is limited or disabled.
- This is a Level 3 requirement and likely absent in many codebases. Mark N/A only if the application has no external service dependencies.

**13.1.4 -- Documented secrets and rotation schedule:**

What to look for:
- Documentation listing secrets used by the application (database credentials, API keys, encryption keys, signing keys, OAuth client secrets, TLS certificates).
- A defined rotation schedule or policy (e.g., "API keys rotated every 90 days," "database passwords rotated quarterly").
- Secret management tool configuration (HashiCorp Vault with TTLs, AWS Secrets Manager rotation config, Azure Key Vault rotation policies).
- If secrets exist but no rotation schedule is documented, this is a finding.
- This is a Level 3 requirement. Mark N/A only if the application uses no secrets at all (extremely unlikely).

---

## V13.2: Backend Communication Configuration

Applications interact with multiple services, including APIs, databases, or other components. These may be considered internal to the application but not included in the application's standard access control mechanisms, or they may be entirely external. In either case, it is necessary to configure the application to interact securely with these components and, if required, protect that configuration.

> Note: The "Secure Communication" chapter provides guidance for encryption in transit.

| # | Requirement | Level |
|---|-------------|-------|
| **13.2.1** | Verify that communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access. | 2 |
| **13.2.2** | Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges. | 2 |
| **13.2.3** | Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin). | 2 |
| **13.2.4** | Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers. | 2 |
| **13.2.5** | Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from. | 2 |
| **13.2.6** | Verify that where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies. | 3 |

### Audit Guidance for V13.2

**13.2.1 -- Backend component authentication:**

What to look for:
- **Good patterns:** Service-to-service authentication using OAuth2 client credentials flow, mutual TLS (mTLS), short-lived JWT tokens, service mesh identity (Istio, Linkerd), AWS IAM roles, GCP service accounts, Azure Managed Identity.
- **Red flags:** Hardcoded static API keys or passwords in configuration files used for backend-to-backend communication. Shared credentials across multiple services. Long-lived tokens with no expiration. Using the same database user for all services.
- Check database connection strings: are they using individual service accounts or a shared `root`/`admin` account?
- Check message queue connections, cache connections, and internal API calls for authentication mechanism.

Language-specific patterns:
- **Python (Django/Flask):** Check `settings.py`, `config.py`, `.env` files for database credentials, API keys. Look for `DATABASES` configuration with specific service accounts vs. shared accounts.
- **Node.js (Express):** Check `config/`, `.env`, `process.env` references for service credentials. Look for database connection configs in ORM setup (Sequelize, Prisma, Knex).
- **Java (Spring):** Check `application.properties`/`application.yml` for `spring.datasource.username`, service credentials. Look for `@Value` or `@ConfigurationProperties` injecting secrets.
- **PHP (Laravel):** Check `.env`, `config/database.php`, `config/services.php` for credentials.
- **Ruby (Rails):** Check `config/database.yml`, `config/credentials.yml.enc`, initializers for service credentials.
- **Go:** Check environment variable reads, config structs, `viper` configuration for service credentials.
- **C# (.NET):** Check `appsettings.json`, `appsettings.Production.json`, `secrets.json` for connection strings and credentials.

**13.2.2 -- Least privilege for backend communications:**

What to look for:
- Database users/roles with minimal permissions (e.g., a read-only service uses a read-only database user, not a `db_owner` or `SUPERUSER` role).
- Service accounts with scoped permissions (e.g., an S3 bucket policy granting only `GetObject` and `PutObject`, not `s3:*`).
- Infrastructure-as-code (Terraform, CloudFormation) defining IAM roles with overly broad policies (`Action: "*"`, `Resource: "*"`).
- **Red flags:** Application connecting to the database as `root`, `sa`, `postgres`, or `admin`. Cloud service credentials with `AdministratorAccess` or equivalent. A single service account used across all services with full permissions.
- Kubernetes: check service account bindings for overly broad RBAC roles.

**13.2.3 -- No default credentials:**

What to look for:
- **Red flags:** Connection strings or configuration containing well-known default credentials: `root/root`, `admin/admin`, `admin/password`, `sa/sa`, `postgres/postgres`, `guest/guest` (RabbitMQ), `elastic/changeme` (Elasticsearch), `admin/secret`, `default/default`.
- Check database connection strings, message queue configs, cache configs, admin panel credentials.
- Check Docker Compose files and Kubernetes manifests for default environment variable values.
- Check for hardcoded credentials in test/development config files that may also be used in production (e.g., `docker-compose.yml` defining `POSTGRES_PASSWORD=postgres` without a production override).

Language-specific patterns:
- **Python:** Search for `PASSWORD`, `password`, `passwd` in settings files. Check Django `DATABASES` settings, Flask config.
- **Node.js:** Search `.env.example`, `config/default.json`, `docker-compose.yml` for default credential patterns.
- **Java:** Search `application.properties`, `application.yml` for `password=`, `spring.datasource.password`.
- **PHP:** Search `.env`, `.env.example`, `config/*.php` for password assignments.
- **Go:** Search for hardcoded string literals matching common default passwords in connection setup code.
- **C#:** Search `appsettings.json`, `appsettings.Development.json`, `web.config` for password fields.

N/A conditions: Only if the application has zero backend service connections (no database, no cache, no external APIs) -- extremely rare.

**13.2.4 -- Allowlist for external communications:**

What to look for:
- **Good patterns:** Application-level allowlists of permitted external URLs/hosts (e.g., a list of allowed webhook destinations, approved external API endpoints). Firewall rules or security group configurations restricting outbound traffic to known destinations. Content Security Policy (CSP) `connect-src` directives limiting browser-initiated connections. Network policies (Kubernetes NetworkPolicy, AWS security groups) restricting egress.
- **Red flags:** Application features that connect to arbitrary user-specified URLs without validation (webhook callbacks, URL-based file imports, URL preview/unfurling) with no allowlist. No egress filtering at any layer -- the application can connect to any external host.
- Check for SSRF-prone features: URL fetchers, image/file downloaders, webhook senders, PDF generators that load remote resources.

**13.2.5 -- Web/application server allowlist for outbound requests:**

What to look for:
- Web server configuration (nginx, Apache, IIS) restricting proxy destinations or outbound requests.
- Application server configuration limiting external connections.
- Proxy configuration or forward proxy settings that restrict outbound destinations.
- Container/pod-level network policies restricting egress.
- This is related to 13.2.4 but focuses specifically on the web/application server layer configuration rather than application logic.
- **Red flags:** Reverse proxy configured to forward requests to any upstream without restriction. No egress filtering at the server level.

**13.2.6 -- Following documented connection configuration:**

What to look for:
- Compare actual connection configurations in code/config against any documented specifications (from 13.1.2/13.1.3).
- Check that connection pool sizes, timeouts, and retry settings in code match documented values.
- Look for connection configurations using framework defaults rather than explicitly set values that match documentation.
- This is a Level 3 requirement. If no documentation exists (13.1.2/13.1.3 failed), note that this requirement cannot be fully verified without baseline documentation but evaluate whether connection configurations appear reasonable.

---

## V13.3: Secret Management

Secret management is an essential configuration task to ensure the protection of data used in the application. Specific requirements for cryptography can be found in the "Cryptography" chapter, but this section focuses on the management and handling aspects of secrets.

| # | Requirement | Level |
|---|-------------|-------|
| **13.3.1** | Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM. | 2 |
| **13.3.2** | Verify that access to secret assets adheres to the principle of least privilege. | 2 |
| **13.3.3** | Verify that all cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module. | 3 |
| **13.3.4** | Verify that secrets are configured to expire and be rotated based on the application's documentation. | 3 |

### Audit Guidance for V13.3

**13.3.1 -- Secrets management solution (no secrets in source or build artifacts):**

What to look for:
- **Good patterns:** Integration with a secrets management solution -- HashiCorp Vault, AWS Secrets Manager, AWS Systems Manager Parameter Store, Azure Key Vault, Google Cloud Secret Manager, CyberArk, Doppler, 1Password Secrets Automation. Environment variables injected at runtime from a secure source (Kubernetes Secrets, Docker secrets, CI/CD secret variables). Encrypted configuration files with keys stored separately.
- **Red flags (FAIL):** Secrets hardcoded directly in source code as string literals. API keys, passwords, or tokens committed to version control. Secrets in `.env` files that are committed to the repository (check `.gitignore` for `.env`). Secrets embedded in Docker images or build artifacts. Configuration files with plaintext secrets checked into source control. Base64-encoded secrets in Kubernetes manifests committed to the repo (base64 is encoding, not encryption).
- Check `.gitignore` for `.env`, `*.pem`, `*.key`, `credentials*`, `secrets*`.
- Search for common secret patterns in source code: strings matching API key formats, `password = "..."`, `secret = "..."`, `token = "..."`, private key headers (`-----BEGIN`).

Language-specific patterns:
- **Python:** Check for secrets in `settings.py`, `config.py`. Look for `os.environ.get()` or `os.getenv()` (better than hardcoded, but check where the env vars come from). Check for `python-dotenv` usage and whether `.env` is in `.gitignore`. Look for vault client libraries (`hvac`, `boto3` secrets manager calls).
- **Node.js:** Check for secrets in `config/`, `.env`, `package.json` scripts. Look for `process.env` usage. Check for vault SDKs (`node-vault`, `@aws-sdk/client-secrets-manager`). Verify `.env` is in `.gitignore`.
- **Java:** Check `application.properties`/`application.yml` for plaintext secrets. Look for Spring Cloud Vault integration, Jasypt encrypted properties, or AWS SDK SecretManager calls. Check for secrets in `pom.xml` or `build.gradle`.
- **PHP:** Check `.env`, `config/*.php` for secrets. Look for vault integrations. Check `composer.json` for secret management packages.
- **Ruby:** Check `config/credentials.yml.enc` (Rails encrypted credentials -- good pattern), `config/secrets.yml`, environment variable usage. Check for vault gems (`vault`, `aws-sdk-secretsmanager`).
- **Go:** Check for hardcoded strings in connection setup. Look for vault client libraries (`hashicorp/vault/api`, AWS SDK). Check config files.
- **C#:** Check `appsettings.json` for plaintext secrets. Look for Azure Key Vault integration (`Azure.Security.KeyVault`), user secrets (`secrets.json`), or `IConfiguration` patterns that pull from secure sources.

**13.3.2 -- Least privilege for secret access:**

What to look for:
- Vault policies or IAM policies restricting which services/roles can access which secrets.
- Kubernetes RBAC or service account configurations limiting Secret access to specific pods/namespaces.
- Infrastructure-as-code defining fine-grained secret access policies (e.g., Vault policies per service, AWS IAM policies scoping Secrets Manager access by ARN prefix).
- **Red flags:** A single vault token or IAM role granting access to all secrets. All services sharing the same secret access credentials. No access control differentiation between development and production secrets.
- This often requires infrastructure review beyond the application codebase. If vault/cloud secret manager integration exists, check the access policies. If secrets are in environment variables, check who/what can set those variables.

**13.3.3 -- Isolated security module for cryptographic operations:**

What to look for:
- Integration with HSMs (Hardware Security Modules), AWS CloudHSM, Azure Dedicated HSM, Google Cloud HSM, or vault transit/encryption backends.
- Key material that never leaves the security module -- crypto operations are performed via API calls to the module rather than by loading keys into application memory.
- **Good patterns:** Vault Transit secrets engine for encryption/decryption. AWS KMS for envelope encryption. Azure Key Vault performing sign/verify/encrypt/decrypt operations server-side. PKCS#11 integration with HSMs.
- **Red flags:** Cryptographic keys loaded from files or environment variables directly into application memory for use with language-level crypto libraries (this means keys exist outside the security module).
- This is a Level 3 requirement. Many applications will not meet this. Mark N/A only if the application performs no cryptographic operations.

**13.3.4 -- Secret expiration and rotation:**

What to look for:
- Vault dynamic secrets with TTLs (e.g., Vault database secrets engine generating short-lived credentials).
- AWS Secrets Manager automatic rotation configuration.
- Certificate renewal automation (cert-manager in Kubernetes, Let's Encrypt auto-renewal).
- Token expiration settings for service-to-service tokens.
- **Red flags:** Static credentials with no expiration configured. Long-lived API keys with no rotation mechanism. Secrets that have been unchanged since initial deployment (check git history for secret-related config changes if available).
- This is a Level 3 requirement. If no secret rotation infrastructure is in place, this is a finding.

---

## V13.4: Unintended Information Leakage

Production configurations should be hardened to avoid disclosing unnecessary data. Many of these issues are rarely rated as significant risks but are often chained with other vulnerabilities. If these issues are not present by default, it raises the bar for attacking an application.

For example, hiding the version of server-side components does not eliminate the need to patch all components, and disabling folder listing does not remove the need to use authorization controls or keep files away from the public folder, but it raises the bar.

| # | Requirement | Level |
|---|-------------|-------|
| **13.4.1** | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | 1 |
| **13.4.2** | Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage. | 2 |
| **13.4.3** | Verify that web servers do not expose directory listings to clients unless explicitly intended. | 2 |
| **13.4.4** | Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage. | 2 |
| **13.4.5** | Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | 2 |
| **13.4.6** | Verify that the application does not expose detailed version information of backend components. | 3 |
| **13.4.7** | Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage. | 3 |

### Audit Guidance for V13.4

**13.4.1 -- No source control metadata in deployment:**

What to look for:
- **Good patterns:** `.dockerignore` excluding `.git`, `.svn`, `.hg` directories. Build scripts or CI/CD pipelines that explicitly exclude VCS metadata from deployment artifacts. Dockerfile `COPY` commands that selectively copy only needed files rather than the entire repo. `.git` directory not present in production containers or deployment packages.
- **Red flags:** `COPY . .` in Dockerfiles without a `.dockerignore` that excludes `.git`. Deployment scripts that rsync or copy the entire repository directory including `.git`. No `.dockerignore` file when Docker is used.
- Check `.dockerignore` for `.git` exclusion.
- Check deployment scripts, CI/CD pipeline configs (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `buildspec.yml`) for how artifacts are packaged.

Language-specific patterns:
- **Python:** Check `MANIFEST.in`, `setup.py`, or `pyproject.toml` for file inclusion rules in packages.
- **Node.js:** Check `.npmignore` or `package.json` `files` field if publishing packages.
- **Java:** WAR/JAR packaging typically excludes `.git` by default, but check Maven/Gradle assembly plugins for custom packaging.
- **PHP:** Check deployment scripts, Deployer configs, or Composer archive settings.
- **Ruby:** Check `.gemspec` file inclusion, Capistrano deployment configs.

**13.4.2 -- Debug modes disabled in production:**

What to look for:
- **Red flags (FAIL):**
  - **Python/Django:** `DEBUG = True` in production settings, or `DEBUG` not set to `False` explicitly for production. Check `settings.py`, `settings/production.py`, environment variable handling for `DEBUG`.
  - **Python/Flask:** `app.run(debug=True)` or `FLASK_DEBUG=1` in production config.
  - **Node.js/Express:** `NODE_ENV` not set to `production`. Debug middleware like `morgan` with verbose logging in production config. `express-debug` or similar debug tools enabled.
  - **Java/Spring:** `spring.devtools` active in production profile. Actuator endpoints exposed without security. `debug=true` in `application.properties` for production.
  - **PHP/Laravel:** `APP_DEBUG=true` in production `.env`. `display_errors = On` in `php.ini` for production.
  - **Ruby/Rails:** `config.consider_all_requests_local = true` in production config. `config.action_dispatch.show_exceptions = :all` in production.
  - **C#/.NET:** `<compilation debug="true">` in production `web.config`. `ASPNETCORE_ENVIRONMENT=Development` in production.
  - **Go:** Verbose error output or debug logging enabled without environment checks.
- **Good patterns:** Environment-specific configuration that explicitly disables debug mode in production. Environment variable checks (`if os.environ.get('ENV') == 'production'`) gating debug features.

**13.4.3 -- No directory listings:**

What to look for:
- **Web server configuration:**
  - **nginx:** Check for `autoindex on;` -- this should be absent or set to `off` in production.
  - **Apache:** Check for `Options +Indexes` or `Options Indexes` -- this should be `-Indexes` or absent. Check `.htaccess` and `httpd.conf`/virtual host configs.
  - **IIS:** Check `web.config` for `<directoryBrowse enabled="true" />` -- should be `false` or absent.
- **Application-level:** Static file serving middleware should not enable directory browsing. Check `express.static` options (Node.js), `whitenoise` (Django), `config.public_file_server` (Rails).
- **Red flags:** Web server config explicitly enabling directory listings. No web server configuration found (relying on defaults which may enable listings depending on the server).

**13.4.4 -- HTTP TRACE method disabled:**

What to look for:
- **Web server configuration:**
  - **nginx:** TRACE is disabled by default in nginx. Check for custom configurations that explicitly enable it.
  - **Apache:** Check for `TraceEnable Off` directive (should be present). `TraceEnable On` is a red flag.
  - **IIS:** Check `web.config` for `<add verb="TRACE" allowed="false" />` in `<requestFiltering>`.
- **Application-level:** Framework-level route handlers that respond to TRACE requests.
- **Good patterns:** Explicit TRACE method disabling in web server or reverse proxy configuration. WAF rules blocking TRACE.
- N/A conditions: If the application is exclusively an API without a web server front-end and TRACE is not handled by any component.

**13.4.5 -- Internal documentation and monitoring endpoints not exposed:**

What to look for:
- **Red flags:**
  - Swagger UI / OpenAPI documentation endpoints accessible without authentication in production: `/swagger`, `/swagger-ui`, `/api-docs`, `/docs`, `/redoc`.
  - Monitoring/health endpoints exposing detailed system info: `/actuator` (Spring Boot), `/debug/`, `/metrics`, `/health` with verbose output, `/status`, `/server-info`, `/phpinfo.php`.
  - Profiling or debugging endpoints: `/debug/pprof` (Go), `/__debug__/` (Django Debug Toolbar), `/elmah.axd` (.NET).
  - Admin panels accessible without proper authentication: `/admin`, `/wp-admin`, `/console`.
- **Good patterns:** Documentation endpoints disabled or authentication-gated in production configuration. Health check endpoints returning only minimal status (e.g., `{"status": "ok"}`) without system details. Actuator endpoints secured with Spring Security. Monitoring endpoints accessible only from internal network.
- Check for environment-based conditional loading of documentation/debug middleware.

**13.4.6 -- No detailed version information exposed:**

What to look for:
- **HTTP response headers:** `Server: Apache/2.4.51 (Ubuntu)`, `X-Powered-By: Express`, `X-Powered-By: PHP/8.1.2`, `X-AspNet-Version`, `X-Runtime` (Rails). These should be removed or generalized.
- **Web server configuration:**
  - **nginx:** `server_tokens off;` should be set.
  - **Apache:** `ServerTokens Prod` and `ServerSignature Off` should be set.
  - **Express:** `app.disable('x-powered-by')` or use `helmet` middleware.
  - **PHP:** `expose_php = Off` in `php.ini`.
- **Error pages:** Default error pages that reveal framework/server versions.
- **API responses:** Version strings in response bodies or headers.
- **Good patterns:** Generic `Server` header or header removed entirely. `helmet` (Node.js), `secure_headers` (Rails/Python) middleware configured. Custom error pages without version information.
- This is a Level 3 requirement.

**13.4.7 -- Web tier serves only specific file extensions:**

What to look for:
- **Web server configuration:**
  - **nginx:** Check `location` blocks -- does the static file serving use explicit extensions (e.g., `location ~* \.(css|js|png|jpg|gif|ico|svg|woff|woff2|ttf|eot)$`) rather than serving everything from a directory?
  - **Apache:** Check for `FilesMatch` or `Files` directives restricting served file types. Check for `<FilesMatch "\.(env|config|yml|yaml|json|log|sql|bak|old)$">` deny rules.
  - **IIS:** Check `web.config` `<requestFiltering>` for `<fileExtensions>` restrictions.
- **Red flags:** Static file serving configured to serve all files in a directory without extension filtering. Files like `.env`, `.config`, `*.bak`, `*.log`, `*.sql`, `*.yml` potentially accessible from the web root.
- **Good patterns:** Explicit allowlist of served static file extensions. Deny rules for sensitive extensions. Static files served from a dedicated directory with only intended file types.
- This is a Level 3 requirement.

---

## References

For more information, see also:

* [OWASP Web Security Testing Guide: Configuration and Deployment Management Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing)

---

## V13 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 1 | 13.4.1 |
| L2 | 12 | 13.1.1, 13.2.1, 13.2.2, 13.2.3, 13.2.4, 13.2.5, 13.3.1, 13.3.2, 13.4.2, 13.4.3, 13.4.4, 13.4.5 |
| L3 | 8 | 13.1.2, 13.1.3, 13.1.4, 13.2.6, 13.3.3, 13.3.4, 13.4.6, 13.4.7 |
| **Total** | **21** | |
