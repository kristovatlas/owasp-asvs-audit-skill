# V14: Data Protection

**ASVS Version:** 5.0.0
**ASVS Source:** `0x23-V14-Data-Protection.md` in the [OWASP ASVS v5.0.0 repo](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/)

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

Applications cannot account for all usage patterns and user behaviors, and should therefore implement controls to limit unauthorized access to sensitive data on client devices.

This chapter includes requirements related to defining what data needs to be protected, how it should be protected, and specific mechanisms to implement or pitfalls to avoid.

Another consideration for data protection is bulk extraction, modification, or excessive usage. Each system's requirements are likely to be very different, so determining what is "abnormal" must consider the threat model and business risk. From an ASVS perspective, detecting these issues is handled in the "Security Logging and Error Handling" chapter, and setting limits is handled in the "Validation and Business Logic" chapter.

---

## V14.1: Data Protection Documentation

A key prerequisite for being able to protect data is to categorize what data should be considered sensitive. There are likely to be several different levels of sensitivity, and for each level, the controls required to protect data at that level will be different.

There are various privacy regulations and laws that affect how applications must approach the storage, use, and transmission of sensitive personal information. This section no longer tries to duplicate these types of data protection or privacy legislation, but rather focuses on key technical considerations for protecting sensitive data. Please consult local laws and regulations, and consult a qualified privacy specialist or lawyer as required.

| # | Requirement | Level |
|---|-------------|-------|
| **14.1.1** | Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with. | 2 |
| **14.1.2** | Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements. | 2 |

### Audit Guidance for V14.1

**General approach:** These are documentation requirements. The sub-agent should look for evidence of data classification policies, data inventories, and documented protection requirements in:
- README files, architecture docs, ADRs (Architecture Decision Records)
- Data classification policies or data handling guidelines
- Compliance documentation (GDPR Data Protection Impact Assessments, privacy policies)
- Configuration files or comments describing data sensitivity tiers
- Database schema annotations or ORM model comments indicating sensitivity

**14.1.1 — Sensitive data identification and classification:**

What to look for:
- A data inventory or data map that lists the types of sensitive data the application handles (PII, financial data, health records, credentials, session tokens, etc.).
- Classification labels or tiers (e.g., "public", "internal", "confidential", "restricted") applied to data elements.
- Evidence that Base64-encoded or JWT payload data is recognized as readable/sensitive and not treated as "encrypted."
- ORM model definitions, database schema docs, or API specs that annotate fields as sensitive or PII.
- Privacy-related documentation referencing applicable regulations (GDPR, CCPA, HIPAA, PCI DSS).

Red flags:
- No documented data classification — the application handles PII or financial data but has no written inventory of what is sensitive.
- Base64-encoded values treated as protected data without actual encryption.
- JWT payloads containing PII or sensitive claims with no acknowledgment that the payload is readable.

N/A conditions:
- This requirement is unlikely to be N/A for any application that handles user data. If the application processes only fully public data with no user accounts, it may be N/A.

**14.1.2 — Documented protection requirements per classification level:**

What to look for:
- For each data sensitivity level, documented requirements covering: encryption at rest and in transit, integrity verification, retention periods, logging constraints, database-level encryption, and privacy-enhancing technologies.
- Configuration files or infrastructure-as-code specifying encryption settings, key management, and retention policies.
- Logging policies that explicitly address what sensitive data must be redacted from logs.
- Database encryption configuration (Transparent Data Encryption, column-level encryption).

Red flags:
- Sensitive data classifications exist but no corresponding protection requirements are documented.
- Encryption or retention policies referenced in code comments but not formally documented.
- Logs containing PII or sensitive data with no documented policy about what must be masked or excluded.

---

## V14.2: General Data Protection

This section contains various practical requirements related to the protection of data. Most are specific to particular issues such as unintended data leakage, but there is also a general requirement to implement protection controls based on the protection level required for each data item.

| # | Requirement | Level |
|---|-------------|-------|
| **14.2.1** | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | 1 |
| **14.2.2** | Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use. | 2 |
| **14.2.3** | Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application's control. | 2 |
| **14.2.4** | Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data's protection level. | 2 |
| **14.2.5** | Verify that caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks. | 3 |
| **14.2.6** | Verify that the application only returns the minimum required sensitive data for the application's functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it. | 3 |
| **14.2.7** | Verify that sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires. | 3 |
| **14.2.8** | Verify that sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user. | 3 |

### Audit Guidance for V14.2

**14.2.1 — No sensitive data in URLs or query strings:**

What to look for:
- API endpoints, form actions, and link constructions that pass sensitive data as URL parameters or query strings.
- Search for patterns where tokens, credentials, PII, or API keys appear in URL paths or query parameters.
- Check routing definitions and client-side code for URL construction patterns.

Language-specific patterns to check:
- **Express/Node.js:** Check for `req.query` or `req.params` being used to receive tokens, passwords, or API keys. Look for URL construction using template literals or string concatenation that embeds secrets.
- **Django:** Check URL patterns (`urls.py`) and views for sensitive data passed via `request.GET`. Look for `redirect()` calls that embed tokens in URLs.
- **Rails:** Check routes for sensitive parameters in path segments. Look for `params` usage in GET routes that receive credentials.
- **Spring:** Check `@RequestParam` and `@PathVariable` annotations that accept sensitive data on GET endpoints. Look for `@GetMapping` endpoints receiving tokens or credentials.
- **Flask:** Check `request.args` for sensitive data retrieval. Look for URL construction with `url_for()` embedding sensitive values.
- **Laravel:** Check `$request->query()` and route parameters for sensitive data. Look for `redirect()->route()` calls embedding tokens.

Red flags:
- Session tokens or API keys passed as query parameters (e.g., `?token=abc123`, `?api_key=xyz`).
- User credentials or PII in GET request URLs.
- OAuth tokens or authorization codes logged via access logs because they were in the URL.
- Redirect URLs that embed sensitive data as query parameters.

Safe patterns:
- Sensitive data sent exclusively in POST/PUT request bodies.
- Tokens and API keys sent in HTTP headers (e.g., `Authorization: Bearer ...`, custom header fields).
- Form submissions using `method="POST"`.

**14.2.2 — Server-side cache protection for sensitive data:**

What to look for:
- Cache-Control headers set on responses containing sensitive data: `Cache-Control: no-store` is the recommended directive.
- Application-level caching (Redis, Memcached, in-memory caches) of sensitive data — check for TTL/expiration settings and secure purging.
- CDN or reverse proxy configurations that might cache authenticated or personalized responses.
- Framework-level cache middleware and whether it distinguishes between public and authenticated content.

Language-specific patterns to check:
- **Express/Node.js:** Middleware setting `res.set('Cache-Control', 'no-store')` on sensitive routes. Check for Redis/Memcached caching of user-specific data and TTL settings.
- **Django:** `@never_cache` decorator, `UpdateCacheMiddleware`/`FetchFromCacheMiddleware` configuration, `CACHE_MIDDLEWARE_SECONDS` settings.
- **Rails:** `expires_now`, `response.headers['Cache-Control']` settings, `Rails.cache` usage for sensitive data.
- **Spring:** `@CacheEvict`, `CacheControl.noStore()`, cache manager configurations.
- **Nginx/Apache:** Check proxy cache configuration for `proxy_cache_bypass`, `proxy_no_cache` directives on authenticated routes.

Red flags:
- Responses containing PII or financial data with no `Cache-Control` header or with `Cache-Control: public`.
- Full user profiles or sensitive records cached in Redis/Memcached with no expiration.
- CDN caching of authenticated API responses.

Safe patterns:
- `Cache-Control: no-store` on all authenticated or sensitive responses.
- Cache entries for sensitive data with short TTLs and explicit purge mechanisms.
- Vary headers used correctly to prevent serving cached authenticated content to other users.

**14.2.3 — No sensitive data sent to untrusted parties:**

What to look for:
- Third-party analytics, tracking, or advertising scripts (Google Analytics, Facebook Pixel, Mixpanel, Segment, etc.) that may receive PII or sensitive data.
- Check for user data being passed to third-party scripts via data layers, event properties, or URL parameters.
- Review Content Security Policy (CSP) headers and script-src directives to understand what third-party domains are authorized.
- Examine frontend code for calls to external analytics endpoints that include user data.

Red flags:
- Analytics tracking calls that include email addresses, names, phone numbers, financial data, or health information.
- Third-party scripts with access to the full DOM that could scrape sensitive form fields.
- Data layer pushes (e.g., `dataLayer.push()`, `analytics.track()`) containing PII.
- External API calls from the backend that send user data to third-party services without data minimization.

Safe patterns:
- Analytics configured to anonymize IP addresses and avoid PII collection.
- Data layer events containing only anonymized identifiers and non-sensitive behavioral data.
- CSP headers restricting which third-party domains can receive data.
- Privacy-preserving analytics (self-hosted solutions, aggregated metrics only).

**14.2.4 — Protection controls match documented requirements:**

What to look for:
- Cross-reference the data protection documentation (from 14.1.2) with actual implementation.
- Check that encryption requirements are implemented (at rest and in transit).
- Check that logging constraints are enforced — sensitive fields masked or excluded from logs.
- Check that retention policies are implemented in code or database configuration.
- Verify access controls on sensitive data in logs (log files not world-readable, log aggregation systems have access controls).

Red flags:
- Documentation specifies encryption for a data category, but data is stored in plaintext.
- Retention policies documented but no automated deletion mechanism exists.
- Logging policy says "no PII in logs" but log statements include user email, name, or other PII.

N/A conditions:
- If 14.1.2 resulted in N/A or no documentation exists, this requirement cannot be fully assessed. Flag for MANUAL_REVIEW.

**14.2.5 — Cache configuration to prevent Web Cache Deception:**

What to look for:
- Web server and CDN cache configurations that validate `Content-Type` before caching.
- Check that the web server returns 404 for non-existent resources rather than falling back to a different valid resource (e.g., SPA catch-all routes that serve `index.html` for any path).
- Cache key configuration — does the cache distinguish between different content types for the same URL path?
- Review CDN or reverse proxy rules that might cache responses based on file extension rather than actual content type.

Red flags:
- SPA configurations where any URL path (e.g., `/account/settings/evil.css`) serves the authenticated application page, and this response gets cached by a CDN or proxy.
- Cache rules based on URL file extensions (`.css`, `.js`, `.jpg`) without verifying the actual `Content-Type` of the response.
- Missing or permissive `Cache-Control` headers on dynamic, authenticated endpoints.

Safe patterns:
- CDN configured to cache only responses with expected static content types (image/*, text/css, application/javascript).
- Web server returns 404 for unknown file paths rather than falling through to dynamic application routes.
- Strict cache key policies that include `Content-Type` or `Vary` headers.

**14.2.6 — Data minimization (minimum required sensitive data returned):**

What to look for:
- API responses and UI rendering that return full sensitive data when only partial data is needed.
- Check serializers, views, and API response builders for what fields are included.
- Look for masking or truncation logic for credit card numbers, SSNs, phone numbers, etc.

Language-specific patterns to check:
- **Express/Node.js:** Check response objects for full PII exposure. Look for `select` or `projection` in database queries that limit returned fields.
- **Django:** Check serializer `fields` definitions — are sensitive fields excluded or read-only? Look for `values()` or `only()` queryset methods.
- **Rails:** Check `as_json` or serializer configurations for field inclusion/exclusion. Look for `select` in ActiveRecord queries.
- **Spring:** Check DTO/response objects vs. entity objects — are full entities returned directly, or are DTOs with limited fields used?

Red flags:
- Full credit card numbers, SSNs, or bank account numbers returned in API responses when only last 4 digits are needed.
- User profile endpoints returning all fields including sensitive ones (password hashes, security questions, full SSN) when only basic profile info is needed.
- Database queries selecting all columns (`SELECT *`) when only a subset is required.

Safe patterns:
- Masking functions applied to sensitive fields before response serialization (e.g., `****-****-****-1234`).
- Separate API endpoints or response modes for full vs. masked data, with the full data requiring explicit user action.
- DTOs/view models that expose only the necessary subset of entity fields.

**14.2.7 — Data retention and automated deletion:**

What to look for:
- Scheduled jobs or cron tasks that delete expired or outdated sensitive data.
- Database TTL configurations, retention policies, or archival mechanisms.
- Application code or configuration that defines retention periods for different data types.

Red flags:
- No evidence of any data deletion mechanism — sensitive data accumulated indefinitely.
- Retention periods documented but no automated deletion process exists.
- Soft-delete patterns where data is marked as deleted but never actually purged.

Safe patterns:
- Scheduled background jobs (cron, Celery tasks, Sidekiq jobs, Spring `@Scheduled`) that purge expired data.
- Database-level TTL (e.g., MongoDB TTL indexes, DynamoDB TTL, PostgreSQL `pg_cron`).
- Data lifecycle management policies implemented in code with clear retention periods.

N/A conditions:
- If the application does not store persistent sensitive data (stateless proxy, purely read-only public data), this may be N/A.

**14.2.8 — Metadata removal from user-submitted files:**

What to look for:
- File upload handling code that strips EXIF data, document metadata, or other embedded information from user-submitted files.
- Libraries used for metadata stripping: `exiftool`, `Pillow` (Python), `sharp` (Node.js), `ImageMagick`, `Apache Tika`, `mat2`.
- Configuration or processing pipelines that handle uploaded files before storage.

Red flags:
- Image uploads stored directly without EXIF stripping — GPS coordinates, device information, and timestamps may be exposed to other users.
- Document uploads (PDF, DOCX) stored and served without metadata removal — author names, revision history, comments may be exposed.
- No file processing pipeline between upload and storage/serving.

Safe patterns:
- File upload pipeline that re-encodes images (stripping EXIF) before storage.
- Explicit metadata removal step using dedicated libraries.
- User consent mechanism for metadata retention (e.g., "Keep photo location data?" toggle).

N/A conditions:
- If the application does not accept user file uploads, this requirement is N/A.

---

## V14.3: Client-side Data Protection

This section contains requirements preventing data from leaking in specific ways at the client or user agent side of an application.

| # | Requirement | Level |
|---|-------------|-------|
| **14.3.1** | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | 1 |
| **14.3.2** | Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers. | 2 |
| **14.3.3** | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens. | 2 |

### Audit Guidance for V14.3

**14.3.1 — Client-side data cleanup on session termination:**

What to look for:
- Logout handlers that clear client-side storage (localStorage, sessionStorage, IndexedDB, cookies).
- `Clear-Site-Data` response header sent on logout endpoints (e.g., `Clear-Site-Data: "cache", "cookies", "storage"`).
- JavaScript cleanup code in logout flows that explicitly removes stored data.
- SPA frameworks' route guards or auth state managers that clear data on session expiry.

Language-specific patterns to check:
- **React/Angular/Vue SPAs:** Check logout functions for `localStorage.clear()`, `sessionStorage.clear()`, IndexedDB deletion, cookie clearing. Look for auth state reset in Redux/NgRx/Vuex/Pinia stores.
- **Server-rendered apps:** Check logout endpoints for `Clear-Site-Data` header, `Set-Cookie` with expired dates to clear cookies, redirect behavior after logout.
- **Mobile web / PWA:** Check service worker cache cleanup on logout.

Red flags:
- Logout endpoint that invalidates the server-side session but does not clear client-side storage.
- No `Clear-Site-Data` header and no JavaScript cleanup on logout.
- Sensitive data persists in localStorage or IndexedDB after the user logs out (verifiable by inspecting storage after logout flow in code).
- SPA that stores user profile, tokens, or sensitive data in memory/store but has no cleanup mechanism when the session ends.

Safe patterns:
- `Clear-Site-Data: "cache", "cookies", "storage"` header on the logout response.
- Explicit `localStorage.removeItem()` / `sessionStorage.clear()` calls in logout handlers.
- Auth state management that resets all sensitive state on session termination.
- Both server-side header and client-side cleanup (defense in depth — client can clean up even if server is unreachable).

**14.3.2 — Anti-caching headers for sensitive responses:**

What to look for:
- HTTP response headers on pages and API endpoints that return sensitive data.
- The recommended header is `Cache-Control: no-store`. Additional headers like `Pragma: no-cache` may be present for legacy HTTP/1.0 compatibility.
- Framework-level middleware or decorators that set anti-caching headers globally or per-route.

Language-specific patterns to check:
- **Express/Node.js:** Middleware like `helmet` (which sets `Cache-Control`), or manual `res.set('Cache-Control', 'no-store')` on sensitive routes.
- **Django:** `@never_cache` decorator, `SecurityMiddleware` settings, or custom middleware setting cache headers.
- **Rails:** `expires_now` in controllers, `response.headers['Cache-Control'] = 'no-store'`.
- **Spring:** `CacheControl.noStore()` in response entity builders, or `WebContentInterceptor` configuration.
- **Nginx/Apache:** Server-level configuration adding `Cache-Control` headers for application routes.

Red flags:
- Authenticated API responses or pages returning sensitive data with no `Cache-Control` header.
- `Cache-Control: public` or `Cache-Control: max-age=3600` on responses containing PII or authenticated content.
- Only static assets have cache headers set; dynamic/authenticated routes have no cache directives.

Safe patterns:
- `Cache-Control: no-store` set globally for all authenticated responses via middleware.
- Per-route anti-caching headers on endpoints returning sensitive data.
- `Pragma: no-cache` and `Expires: 0` as supplementary headers for legacy browser support.

**14.3.3 — No sensitive data in browser storage (except session tokens):**

What to look for:
- Frontend JavaScript code that writes to `localStorage`, `sessionStorage`, `IndexedDB`, or sets cookies.
- Check what data is being stored — session tokens in cookies are acceptable; PII, credentials, financial data, or other sensitive information is not.
- Review frontend state management (Redux/NgRx/Vuex/Pinia) for persist-to-storage plugins that may serialize sensitive state.

Red flags:
- `localStorage.setItem('user', JSON.stringify(userProfile))` where `userProfile` contains email, phone, address, or other PII.
- Sensitive API responses cached in IndexedDB for offline access without encryption.
- Cookies containing PII beyond session identifiers (e.g., `username=john@example.com` cookie).
- Redux/Vuex state persistence plugins (`redux-persist`, `vuex-persistedstate`) that save entire application state including sensitive user data to localStorage.
- Access tokens stored in localStorage (while technically a session token, localStorage is accessible to XSS — httpOnly cookies are preferred).

Safe patterns:
- Session tokens stored in httpOnly, Secure cookies (not accessible to JavaScript).
- localStorage/sessionStorage containing only non-sensitive preferences (theme, language, UI state).
- If offline storage of sensitive data is required, it is encrypted before being written to IndexedDB.
- Frontend state management only persists non-sensitive UI state, not user data or tokens.

N/A conditions:
- If the application has no client-side component (pure API backend with no frontend), browser storage requirements may be N/A. However, if the API sets cookies or cache headers, 14.3.2 still applies.

---

## References

For more information, see also:

* [Consider using the Security Headers website to check security and anti-caching header fields](https://securityheaders.com/)
* [Documentation about anti-caching headers by Mozilla](https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching)
* [OWASP Secure Headers project](https://owasp.org/www-project-secure-headers/)
* [OWASP Privacy Risks Project](https://owasp.org/www-project-top-10-privacy-risks/)
* [OWASP User Privacy Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [Australian Privacy Principle 11 - Security of personal information](https://www.oaic.gov.au/privacy/australian-privacy-principles/australian-privacy-principles-guidelines/chapter-11-app-11-security-of-personal-information)
* [European Union General Data Protection Regulation (GDPR) overview](https://www.edps.europa.eu/data-protection_en)
* [European Union Data Protection Supervisor - Internet Privacy Engineering Network](https://www.edps.europa.eu/data-protection/ipen-internet-privacy-engineering-network_en)
* [Information on the "Clear-Site-Data" header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data)
* [White paper on Web Cache Deception](https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack-wp.pdf)

---

## V14 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 2 | 14.2.1, 14.3.1 |
| L2 | 7 | 14.1.1, 14.1.2, 14.2.2, 14.2.3, 14.2.4, 14.3.2, 14.3.3 |
| L3 | 4 | 14.2.5, 14.2.6, 14.2.7, 14.2.8 |
| **Total** | **13** | |
