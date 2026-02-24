# V12: Secure Communication

**ASVS Version:** 5.0.0
**ASVS Source:** `0x21-V12-Secure-Communication.md` in the [OWASP ASVS v5.0.0 repo](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/)

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

This chapter includes requirements related to the specific mechanisms that should be in place to protect data in transit, both between an end-user client and a backend service, as well as between internal and backend services.

The general concepts promoted by this chapter include:

* Ensuring that communications are encrypted externally, and ideally internally as well.
* Configuring encryption mechanisms using the latest guidance, including preferred algorithms and ciphers.
* Using signed certificates to ensure that communications are not being intercepted by unauthorized parties.

In addition to outlining general principles and best practices, the ASVS also provides more in-depth technical information about cryptographic strength in Appendix C - Cryptography Standards.

---

## V12.1: General TLS Security Guidance

This section provides initial guidance on how to secure TLS communications. Up-to-date tools should be used to review TLS configuration on an ongoing basis.

While the use of wildcard TLS certificates is not inherently insecure, a compromise of a certificate that is deployed across all owned environments (e.g., production, staging, development, and test) may lead to a compromise of the security posture of the applications using it. Proper protection, management, and the use of separate TLS certificates in different environments should be employed if possible.

| # | Requirement | Level |
|---|-------------|-------|
| **12.1.1** | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | 1 |
| **12.1.2** | Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy. | 2 |
| **12.1.3** | Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization. | 2 |
| **12.1.4** | Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured. | 3 |
| **12.1.5** | Verify that Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes. | 3 |

### Audit Guidance for V12.1

**12.1.1 — TLS protocol version enforcement (TLS 1.2+ only):**

What to look for:
- Configuration or code that explicitly sets the minimum TLS protocol version to TLS 1.2 or TLS 1.3. The latest version (TLS 1.3) should be the preferred option.
- **Red flags:** Any use of SSLv2, SSLv3, TLS 1.0, or TLS 1.1. These are deprecated and insecure. Look for explicit protocol version settings that allow older versions.

Language-specific patterns to check:
- **Python:** In `ssl` module, check for `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` with `context.minimum_version = ssl.TLSVersion.TLSv1_2`. Red flags: `ssl.PROTOCOL_TLSv1`, `ssl.PROTOCOL_TLSv1_1`, `ssl.PROTOCOL_SSLv23` without restricting minimum version. In `requests`/`urllib3`, check for custom `HTTPAdapter` with explicit TLS version settings.
- **Node.js:** In `https` or `tls` modules, check `secureProtocol` or `minVersion`/`maxVersion` options. Good: `minVersion: 'TLSv1.2'`. Red flags: `secureProtocol: 'TLSv1_method'`, absence of `minVersion` on older Node versions.
- **Java:** Check `SSLContext.getInstance()` calls — good: `TLSv1.2`, `TLSv1.3`. Red flags: `SSLv3`, `TLS`, `TLSv1`, `TLSv1.1`. Also check `jdk.tls.disabledAlgorithms` in `java.security` for system-level config. In Spring Boot, check `server.ssl.protocol` and `server.ssl.enabled-protocols` in `application.properties`/`application.yml`.
- **Go:** Check `tls.Config` struct — good: `MinVersion: tls.VersionTLS12`. Red flags: `MinVersion: tls.VersionTLS10`, `MinVersion: tls.VersionTLS11`, or no `MinVersion` set (defaults vary by Go version).
- **C# (.NET):** Check `ServicePointManager.SecurityProtocol` — good: `SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13`. Red flags: `SecurityProtocolType.Tls`, `SecurityProtocolType.Tls11`, `SecurityProtocolType.Ssl3`. In Kestrel, check `ConfigureHttpsDefaults` with `SslProtocols`.
- **PHP:** Check `curl_setopt` with `CURLOPT_SSLVERSION` — good: `CURL_SSLVERSION_TLSv1_2`. Red flags: `CURL_SSLVERSION_TLSv1_0`, `CURL_SSLVERSION_SSLv3`. Also check `stream_context_create` with `crypto_method` options.
- **Ruby:** Check `Net::HTTP` or `OpenSSL::SSL::SSLContext` — good: `ssl_version = :TLSv1_2`. Red flags: `:TLSv1`, `:SSLv3`, `:SSLv23`. Also check `min_version = OpenSSL::SSL::TLS1_2_VERSION`.
- **Web servers (nginx, Apache, IIS):** Check TLS configuration in server config files. Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`. Red flags: inclusion of `TLSv1`, `TLSv1.1`, `SSLv3`.

N/A conditions: If the application does not initiate or terminate TLS connections (e.g., TLS is handled entirely by a reverse proxy or load balancer external to the codebase), this may be N/A for the application code itself — but note that the TLS configuration must still be verified somewhere in the infrastructure.

**12.1.2 — Cipher suite configuration:**

What to look for:
- Explicit cipher suite configuration that restricts to strong, recommended ciphers. At L3, all cipher suites must provide forward secrecy (ECDHE or DHE key exchange).
- **Good patterns:** Cipher lists referencing only AEAD ciphers (AES-GCM, ChaCha20-Poly1305) with ECDHE key exchange. Mozilla "Modern" or "Intermediate" cipher suite configurations.
- **Red flags:** Cipher suites including `RC4`, `DES`, `3DES`, `MD5`, `NULL`, `EXPORT`, `anon`, `RSA` key exchange (no forward secrecy), `CBC` mode ciphers (vulnerable to BEAST/padding oracle attacks in older TLS versions).

Language-specific patterns to check:
- **Python (`ssl`):** `context.set_ciphers('...')` — check the cipher string.
- **Node.js:** `ciphers` option in `tls.createServer()` or `https.createServer()`.
- **Java:** `SSLSocket.setEnabledCipherSuites()` or `SSLEngine.setEnabledCipherSuites()`. Spring Boot: `server.ssl.ciphers`.
- **Go:** `tls.Config.CipherSuites` — check the cipher suite constants listed.
- **C# (.NET):** `SslStream` cipher suite configuration, or OS-level cipher suite policy.
- **Nginx:** `ssl_ciphers` directive. Apache: `SSLCipherSuite` directive.

N/A conditions: Same as 12.1.1 — if TLS termination is external to the codebase.

**12.1.3 — mTLS client certificate validation:**

What to look for:
- Where mTLS (mutual TLS) is used, the application must validate client certificates against a trusted CA or explicit trust store before using the certificate identity.
- **Good patterns:** Server-side TLS configuration that requires client certificates (`ssl_verify_client on` in nginx, `clientAuth: need` in Java/Spring, `ClientCertificateMode.RequireCertificate` in .NET). Validation of the client certificate chain against a specific CA bundle.
- **Red flags:** mTLS configured but client certificate validation disabled or set to optional without subsequent code-level validation. Using the certificate CN or SAN for authorization without verifying the certificate chain. Trusting any client certificate regardless of issuer.

N/A conditions: If the application does not use mTLS for any communication, mark N/A.

**12.1.4 — Certificate revocation checking (OCSP Stapling):**

What to look for:
- OCSP Stapling enabled in web server or application TLS configuration. This allows the server to provide a pre-fetched OCSP response during the TLS handshake, proving the certificate has not been revoked.
- **Good patterns:** Nginx: `ssl_stapling on; ssl_stapling_verify on;`. Apache: `SSLUseStapling On`. Application-level OCSP stapling configuration.
- **Red flags:** No revocation checking configured at all. CRL (Certificate Revocation List) reliance only without OCSP Stapling (CRLs can be large and slow).

N/A conditions: If the application does not directly manage TLS certificates (e.g., managed by a cloud provider or CDN that handles OCSP Stapling automatically), this may be N/A for the codebase — but should be verified at the infrastructure level.

**12.1.5 — Encrypted Client Hello (ECH):**

What to look for:
- ECH (formerly ESNI) configuration in TLS settings to encrypt the SNI field during the TLS handshake, preventing network observers from seeing which hostname the client is connecting to.
- **Good patterns:** Server and client TLS configuration enabling ECH. DNS HTTPS records publishing ECH keys.
- **Red flags:** No ECH support or configuration. Note that ECH is relatively new and support varies by platform and library version.

N/A conditions: ECH requires specific infrastructure support (DNS, TLS library versions). If the deployment environment does not yet support ECH, note this as a gap with a path to resolution rather than an outright failure. This is a Level 3 requirement.

---

## V12.2: HTTPS Communication with External Facing Services

Ensure all HTTP traffic to external-facing services which the application exposes is sent encrypted, with publicly trusted certificates.

| # | Requirement | Level |
|---|-------------|-------|
| **12.2.1** | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | 1 |
| **12.2.2** | Verify that external facing services use publicly trusted TLS certificates. | 1 |

### Audit Guidance for V12.2

**12.2.1 — TLS for all external-facing HTTP connectivity (no fallback to HTTP):**

What to look for:
- All external-facing endpoints must be served over HTTPS. Plain HTTP should either be disabled entirely or should redirect (301/302) to HTTPS.
- **HSTS (HTTP Strict-Transport-Security):** Check for the `Strict-Transport-Security` header being set on HTTPS responses. Good: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. This prevents clients from falling back to HTTP after the first visit.
- **Redirect configuration:** Check that HTTP requests are redirected to HTTPS at the server or load balancer level.

Language-specific patterns to check:
- **Express/Node.js:** Check for HTTPS-only middleware, HSTS middleware (`helmet.hsts()`), or redirect middleware that forces HTTP to HTTPS. Red flags: `http.createServer()` serving application content without redirect to HTTPS.
- **Django:** Check `SECURE_SSL_REDIRECT = True`, `SECURE_HSTS_SECONDS`, `SECURE_HSTS_INCLUDE_SUBDOMAINS`, `SECURE_HSTS_PRELOAD` in settings.
- **Rails:** Check `config.force_ssl = true` in environment configuration.
- **Spring Boot:** Check `server.ssl.enabled=true`, `security.require-ssl=true`, or Spring Security's `requiresChannel().anyRequest().requiresSecure()`.
- **ASP.NET:** Check `UseHttpsRedirection()` middleware, `UseHsts()`, `[RequireHttps]` attribute.
- **PHP/Laravel:** Check for `FORCE_HTTPS` or HTTPS redirect middleware. Check `.htaccess` or nginx config for HTTP-to-HTTPS redirect.
- **Web servers:** Nginx: check for `return 301 https://$host$request_uri;` in HTTP server block. Apache: `RewriteRule` redirecting to HTTPS, or `SSLRequireSSL`.

Red flags:
- Application serving content over both HTTP and HTTPS without redirect.
- Mixed content: HTTPS pages loading resources (scripts, stylesheets, images, iframes) over HTTP.
- API endpoints accessible over HTTP.
- No HSTS header set (allows SSL stripping attacks).

**12.2.2 — Publicly trusted TLS certificates:**

What to look for:
- External-facing services must use certificates issued by publicly trusted Certificate Authorities (CAs), not self-signed or internally-signed certificates.
- **Good patterns:** Certificates from well-known CAs (Let's Encrypt, DigiCert, Comodo, GlobalSign, etc.). Automated certificate management (certbot, ACME protocol).
- **Red flags in code:** Self-signed certificate generation for production use. Certificate files checked into the repository (may indicate self-signed certs). Configuration that adds self-signed certificates to the trust store for external-facing services.
- **Infrastructure check:** This is often an infrastructure/deployment concern rather than a code concern. Look for deployment configurations (Terraform, Kubernetes manifests, Helm charts, Docker Compose) that reference certificate sources.

N/A conditions: Rarely N/A — any application with external-facing HTTP services needs publicly trusted certificates.

---

## V12.3: General Service to Service Communication Security

Server communications (both internal and external) involve more than just HTTP. Connections to and from other systems must also be secure, ideally using TLS.

| # | Requirement | Level |
|---|-------------|-------|
| **12.3.1** | Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols. | 2 |
| **12.3.2** | Verify that TLS clients validate certificates received before communicating with a TLS server. | 2 |
| **12.3.3** | Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications. | 2 |
| **12.3.4** | Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates. | 2 |
| **12.3.5** | Verify that services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security. | 3 |

### Audit Guidance for V12.3

**12.3.1 — Encrypted protocols for all connections (databases, APIs, middleware, etc.):**

What to look for:
- All connections from the application to external services, databases, message brokers, caches, monitoring systems, and partner APIs should use encrypted transport (TLS/SSL).
- **Database connections:** Check connection strings and configuration for TLS/SSL parameters.

Language-specific patterns to check:
- **PostgreSQL:** Connection string should include `sslmode=require` (or `verify-ca`/`verify-full`). Red flag: `sslmode=disable` or `sslmode=prefer` (allows fallback).
- **MySQL:** Connection options should include `ssl: { ... }` or `--ssl-mode=REQUIRED`. Red flag: `ssl-mode=DISABLED`.
- **MongoDB:** Connection string should include `tls=true` or `ssl=true`. Red flag: `tls=false`.
- **Redis:** Check for TLS-enabled connections (`rediss://` scheme, or explicit TLS configuration). Red flag: plain `redis://` without TLS in production.
- **Message brokers (RabbitMQ, Kafka):** Check for TLS/SSL configuration in broker client settings. Kafka: `security.protocol=SSL` or `SASL_SSL`. RabbitMQ: `amqps://` scheme.
- **HTTP clients calling external APIs:** Check that URLs use `https://` not `http://`. Check that HTTP client libraries are configured with TLS.
- **SMTP:** Check for `STARTTLS` or direct TLS (`smtps://`, port 465). Red flag: plain SMTP on port 25 without TLS.
- **LDAP:** Check for `ldaps://` (LDAP over TLS) or `STARTTLS`. Red flag: plain `ldap://` without TLS.

Red flags:
- Any connection string or configuration using unencrypted protocols (`http://`, `redis://`, `amqp://`, `ldap://`, `smtp://` port 25) for production services.
- Environment variables or config files with database URLs missing SSL/TLS parameters.

**12.3.2 — TLS client certificate validation (no disabled verification):**

What to look for:
- TLS clients must validate server certificates. This means certificate verification must not be disabled or bypassed.
- **This is one of the most commonly violated security controls in codebases.** Developers frequently disable certificate verification during development and forget to re-enable it, or disable it to "fix" certificate errors.

Language-specific patterns to check:
- **Python (`requests`):** Red flag: `verify=False` in `requests.get()`, `requests.post()`, etc. Also: `urllib3.disable_warnings(InsecureRequestWarning)` — this often accompanies disabled verification. Good: `verify=True` (default) or `verify='/path/to/ca-bundle.crt'`.
- **Python (`urllib3`):** Red flag: `cert_reqs='CERT_NONE'` or `assert_hostname=False`.
- **Python (`ssl`):** Red flag: `context.check_hostname = False`, `context.verify_mode = ssl.CERT_NONE`.
- **Node.js:** Red flag: `rejectUnauthorized: false` in TLS/HTTPS options, or `NODE_TLS_REJECT_UNAUTHORIZED=0` environment variable. Good: `rejectUnauthorized: true` (default).
- **Java:** Red flag: Custom `TrustManager` that accepts all certificates (empty `checkServerTrusted` method), `HostnameVerifier` that returns `true` for all hostnames (`ALLOW_ALL_HOSTNAME_VERIFIER`). Check for `X509TrustManager` implementations with no-op methods.
- **Go:** Red flag: `InsecureSkipVerify: true` in `tls.Config`. Good: `InsecureSkipVerify: false` (default).
- **C# (.NET):** Red flag: `ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;` or `HttpClientHandler.ServerCertificateCustomValidationCallback` that always returns true. Good: default validation behavior.
- **PHP (curl):** Red flag: `CURLOPT_SSL_VERIFYPEER => false`, `CURLOPT_SSL_VERIFYHOST => 0`. Good: `CURLOPT_SSL_VERIFYPEER => true`, `CURLOPT_SSL_VERIFYHOST => 2`.
- **Ruby:** Red flag: `OpenSSL::SSL::VERIFY_NONE`, `verify_mode = OpenSSL::SSL::VERIFY_NONE`. Good: `verify_mode = OpenSSL::SSL::VERIFY_PEER`.

Red flags (cross-language):
- Any code comment containing "TODO: re-enable", "disable SSL", "skip verification", "ignore cert".
- Environment-based toggling that disables cert verification in non-production (risky if it leaks to production).

**12.3.3 — TLS for all internal HTTP service communication:**

What to look for:
- Internal service-to-service HTTP calls must use TLS, not plain HTTP. This applies to microservice architectures, backend-to-backend API calls, and any internal HTTP communication.
- **Good patterns:** All internal service URLs configured as `https://`. Service mesh (Istio, Linkerd) providing automatic mTLS between services. Kubernetes network policies combined with TLS.
- **Red flags:** Internal service URLs using `http://` (e.g., `http://user-service:8080/api/users`). Comments like "internal traffic, no TLS needed" or "TLS not required for internal services".
- Check service discovery configuration, Kubernetes service definitions, Docker Compose service URLs, and environment variables for internal service endpoints.

**12.3.4 — Trusted certificates for internal TLS connections:**

What to look for:
- Internal TLS connections should use certificates from a trusted internal CA, not randomly generated self-signed certificates trusted by default. Where self-signed certificates are used, the consuming service must be configured to trust only those specific certificates (certificate pinning or explicit CA trust store).
- **Good patterns:** Internal PKI (Private CA) issuing certificates to internal services. Services configured with a custom CA bundle that includes only the internal CA. Service mesh handling certificate issuance and rotation automatically (e.g., Istio Citadel, Linkerd identity).
- **Red flags:** Services configured to trust all certificates (see 12.3.2 patterns). Self-signed certificates with no pinning or explicit trust configuration. Internal services using the system-wide CA bundle to validate internal certificates (should use a restricted internal CA bundle).

Language-specific patterns to check:
- Look for custom CA bundle paths in TLS client configuration (e.g., `SSL_CERT_FILE` environment variable, `ca:` option in Node.js TLS, `verify='/path/to/internal-ca.pem'` in Python requests, `trustStore` in Java).
- Certificate files in the repository — check if they are internal CA certificates with appropriate trust configuration, not just self-signed certificates trusted blindly.

**12.3.5 — Strong authentication for intra-service communication (mTLS):**

What to look for:
- Internal services must authenticate each other using strong mechanisms, typically mTLS (mutual TLS), where both client and server present certificates. This prevents unauthorized services from joining the internal network and making requests.
- **Good patterns:** mTLS configured between all internal services. Service mesh providing automatic mTLS (Istio with `PeerAuthentication` policy set to `STRICT`, Linkerd automatic mTLS). SPIFFE/SPIRE for workload identity. Each service has its own certificate and key pair, and validates the peer's certificate.
- **Red flags:** Internal services relying solely on network-level isolation (e.g., VPC/firewall rules) without authentication. Services using shared API keys or passwords for authentication instead of certificate-based authentication. No authentication between internal services at all.
- Check for: client certificate configuration in HTTP clients making internal calls, server-side configuration requiring client certificates for internal endpoints.

N/A conditions: If the application is a monolith with no internal service-to-service communication, this requirement may be N/A. However, if the application communicates with any internal services (databases don't typically count — this is about service-to-service), it applies.

---

## References

For more information, see also:

* [OWASP - Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
* [Mozilla's Server Side TLS configuration guide](https://wiki.mozilla.org/Security/Server_Side_TLS)
* [Mozilla's tool to generate known good TLS configurations](https://ssl-config.mozilla.org/).
* [O-Saft - OWASP Project to validate TLS configuration](https://owasp.org/www-project-o-saft/)

---

## V12 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 3 | 12.1.1, 12.2.1, 12.2.2 |
| L2 | 6 | 12.1.2, 12.1.3, 12.3.1, 12.3.2, 12.3.3, 12.3.4 |
| L3 | 3 | 12.1.4, 12.1.5, 12.3.5 |
| **Total** | **12** | |
