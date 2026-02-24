# V7: Session Management

**ASVS Version:** 5.0.0
**ASVS Source:** `0x16-V7-Session-Management.md` in the [OWASP ASVS v5.0.0 repo](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/)

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

Session management mechanisms allow applications to correlate user and device interactions over time, even when using stateless communication protocols (such as HTTP). Modern applications may use multiple session tokens with distinct characteristics and purposes. A secure session management system is one that prevents attackers from obtaining, utilizing, or otherwise abusing a victim's session. Applications maintaining sessions must ensure that the following high-level session management requirements are met:

* Sessions are unique to each individual and cannot be guessed or shared.
* Sessions are invalidated when no longer required and are timed out during periods of inactivity.

Many of the requirements in this chapter relate to selected [NIST SP 800-63 Digital Identity Guidelines](https://pages.nist.gov/800-63-4/) controls, focusing on common threats and commonly exploited authentication weaknesses.

Note that requirements for specific implementation details of certain session management mechanisms can be found elsewhere:

* HTTP Cookies are a common mechanism for securing session tokens. Specific security requirements for cookies can be found in the "Web Frontend Security" chapter.
* Self-contained tokens are frequently used as a way of maintaining sessions. Specific security requirements can be found in the "Self-contained Tokens" chapter.

---

## V7.1: Session Management Documentation

There is no single pattern that suits all applications. Therefore, it is not feasible to define universal boundaries and limits that suit all cases. A risk analysis with documented security decisions related to session handling must be conducted as a prerequisite to implementation and testing. This ensures that the session management system is tailored to the specific requirements of the application.

Regardless of whether a stateful or "stateless" session mechanism is chosen, the analysis must be complete and documented to demonstrate that the selected solution is capable of satisfying all relevant security requirements. Interaction with any Single Sign-on (SSO) mechanisms in use should also be considered.

| # | Requirement | Level |
|---|-------------|-------|
| **7.1.1** | Verify that the user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements. | 2 |
| **7.1.2** | Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached. | 2 |
| **7.1.3** | Verify that all systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication. | 2 |

### Audit Guidance for V7.1

**General approach:** These are documentation requirements. The sub-agent should look for evidence of documented session management decisions in:
- README files, architecture docs, ADRs (Architecture Decision Records)
- Security design documentation describing session strategy
- Configuration files with documented timeout values and their rationale
- Inline code comments or docstrings explaining session configuration choices
- Wiki or docs directories in the repo
- SSO/federation integration documentation

**7.1.1 — Documented session inactivity timeout and absolute lifetime:**

What to look for:
- Documentation that explicitly states the session inactivity timeout value (e.g., "sessions expire after 15 minutes of inactivity") and the absolute maximum session lifetime (e.g., "sessions expire after 12 hours regardless of activity").
- Justification for chosen values, especially if they deviate from NIST SP 800-63B guidelines (which recommends re-authentication after 30 minutes of inactivity for AAL1, and 15 minutes for AAL2+).
- Configuration files with session timeout settings count as partial evidence, but the requirement asks for documentation that includes *justification*, not just the configured values.
- **Red flags:** Session timeout values set in code or configuration with no accompanying documentation explaining why those values were chosen. Default framework timeouts left unchanged without documented acknowledgment.

Language-specific configuration locations:
- **Express/Node.js:** `express-session` options (`cookie.maxAge`, `rolling`), `connect-redis` TTL settings, JWT `expiresIn` values.
- **Django:** `SESSION_COOKIE_AGE`, `SESSION_EXPIRE_AT_BROWSER_CLOSE`, `SESSION_SAVE_EVERY_REQUEST` in `settings.py`.
- **Spring:** `server.servlet.session.timeout` in `application.properties`/`application.yml`, Spring Session configuration.
- **Rails:** `expire_after` in session store configuration, Devise `timeout_in` setting.
- **Laravel:** `lifetime` and `expire_on_close` in `config/session.php`.
- **ASP.NET:** `IdleTimeout`, `Cookie.MaxAge` in session middleware configuration.
- **Flask:** `PERMANENT_SESSION_LIFETIME` in app config.

**7.1.2 — Documented concurrent session policy:**

What to look for:
- Documentation stating how many simultaneous sessions a single user account can maintain (e.g., "users may have up to 3 active sessions" or "unlimited concurrent sessions are allowed").
- Documentation of the behavior when the limit is reached: is the oldest session terminated? Is the new login blocked? Is the user notified?
- If no concurrent session limit exists, the documentation should state this as a deliberate decision.
- **Red flags:** No mention anywhere of concurrent session handling. Session management implementation that does not track or limit concurrent sessions, with no documented rationale.

**7.1.3 — Documented federated session management:**

What to look for:
- Documentation of SSO/federated identity systems in use (e.g., SAML, OIDC, OAuth2 providers such as Okta, Auth0, Azure AD, Keycloak).
- Description of how session lifetimes are coordinated between the IdP and the application (RP). For example, does IdP session expiry trigger application session expiry?
- Documentation of re-authentication triggers and how logout propagates across federated systems (single logout / SLO).
- Mark N/A if the application does not participate in any federated identity or SSO ecosystem — but confirm this by checking for SAML/OIDC/OAuth2 libraries and configuration.

---

## V7.2: Fundamental Session Management Security

This section satisfies the essential requirements of secure sessions by verifying that session tokens are securely generated and validated.

| # | Requirement | Level |
|---|-------------|-------|
| **7.2.1** | Verify that the application performs all session token verification using a trusted, backend service. | 1 |
| **7.2.2** | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | 1 |
| **7.2.3** | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | 1 |
| **7.2.4** | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | 1 |

### Audit Guidance for V7.2

**7.2.1 — Backend session token verification:**

What to look for:
- Session token validation (signature verification for JWTs, session store lookup for reference tokens) must occur on the server side, not in client-side code.
- **Red flags:** JWT signature verification performed in browser JavaScript (e.g., using `jsonwebtoken` or `jose` in frontend bundles). Session validity checks that rely solely on client-side cookie presence or token decoding without server verification. API endpoints that trust a client-provided user ID or role claim without verifying the session token on the backend.
- **Safe patterns:** Server-side middleware that validates session tokens before any route handler executes.

Language-specific patterns:
- **Express/Node.js:** `express-session` middleware validates session IDs against a session store (Redis, MongoDB, etc.). For JWTs, `passport-jwt`, `express-jwt`, or `jose` used in server-side middleware. Check that JWT verification is not happening in React/Angular/Vue code.
- **Django:** Django's built-in session framework performs server-side validation via `SessionMiddleware`. For DRF, `rest_framework_simplejwt` validates tokens server-side.
- **Spring:** Spring Security's session management or `spring-security-oauth2-resource-server` handles server-side token validation. Check for `@EnableResourceServer` or `SecurityFilterChain` with JWT decoder configuration.
- **Rails:** Rails session management validates server-side by default. For API-only apps using JWT, check that `jwt` gem verification is in a controller concern or middleware, not in frontend code.
- **Laravel:** Laravel's session driver validates server-side. For Sanctum or Passport, token verification is server-side by default.
- **Flask:** `flask-session` with server-side store, or `flask-jwt-extended` performing server-side JWT validation.
- **ASP.NET:** `UseAuthentication()` middleware with `AddJwtBearer()` or session middleware handles server-side validation.
- **Go:** `gorilla/sessions`, `scs` (alexedwards), or JWT middleware like `go-jwt-middleware` performing validation in HTTP handlers/middleware.

**7.2.2 — Dynamic session tokens (no static secrets/keys):**

What to look for:
- Session tokens must be dynamically generated per session, not static API keys or hardcoded secrets used to identify users.
- **Red flags:** Static API keys stored in the database and sent with every request as the sole mechanism for session identification. Hardcoded tokens or secrets used for authentication (e.g., `Authorization: Bearer hardcoded-secret-123`). Configuration files with static tokens assigned to user accounts.
- **Safe patterns:** Session IDs generated per login by session frameworks. JWTs issued with unique `jti` claims and `iat`/`exp` timestamps. OAuth2 access tokens issued dynamically per authentication flow.
- Check for static values in environment variables or configuration that are used as bearer tokens for user-facing sessions (this is distinct from service-to-service API keys, which are outside the scope of this requirement).

**7.2.3 — CSPRNG and 128-bit entropy for reference tokens:**

What to look for:
- If the application uses reference (opaque) session tokens (not JWTs), verify they are generated using a cryptographically secure random number generator with at least 128 bits of entropy (16 bytes or more of random data, typically represented as 32+ hex characters or 22+ base64 characters).
- **Safe patterns:** Framework-default session ID generation — most mature frameworks already use CSPRNGs: Python's `secrets` module or `os.urandom()`, Node.js `crypto.randomBytes()`, Java `SecureRandom`, Ruby `SecureRandom`, Go `crypto/rand`, C# `RandomNumberGenerator`.
- **Red flags:** Custom session token generation using `Math.random()` (JavaScript), `random.random()` (Python), `java.util.Random` (Java), `rand()` (PHP without `random_bytes()`), `rand` (Go's `math/rand` instead of `crypto/rand`). Short session tokens (less than 16 bytes of randomness). Sequential or predictable session identifiers. UUIDs used as session tokens — UUIDv4 provides ~122 bits of randomness which is close but technically under 128; UUIDv1 is predictable and a FAIL.
- If using a standard session framework (Express session, Django sessions, Rails sessions, Spring Session, Laravel sessions), the default token generation is typically safe — note this and check for any custom overrides.
- Mark N/A if the application exclusively uses self-contained tokens (JWTs) for sessions.

**7.2.4 — New session token on authentication:**

What to look for:
- After successful login (or re-authentication), the application must issue a new session token and invalidate/terminate the old one. This prevents session fixation attacks.
- **Safe patterns:** Session regeneration on login — `request.session.cycle_id` or `request.session.create()` (Django), `req.session.regenerate()` (Express), `reset_session` (Rails), `session.invalidate()` followed by new session creation (Spring), `Session::regenerate()` (Laravel), `HttpContext.Session.Clear()` + new session (ASP.NET).
- **Red flags:** Login handlers that authenticate the user and set user data into the existing session without regenerating the session ID. Reuse of pre-authentication session tokens after login.
- For JWT-based sessions: verify that a new JWT is issued on each authentication event and any previously issued tokens are invalidated or no longer accepted (e.g., by tracking token issuance time or using a blocklist).

---

## V7.3: Session Timeout

Session timeout mechanisms serve to minimize the window of opportunity for session hijacking and other forms of session abuse. Timeouts must satisfy documented security decisions.

| # | Requirement | Level |
|---|-------------|-------|
| **7.3.1** | Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions. | 2 |
| **7.3.2** | Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions. | 2 |

### Audit Guidance for V7.3

**7.3.1 — Inactivity timeout enforcement:**

What to look for:
- The application must expire sessions after a period of user inactivity (no requests received). When a session times out due to inactivity, the user must re-authenticate.
- **Safe patterns:** Server-side session stores with TTL that resets on each request (sliding expiration). Session middleware that tracks last activity timestamp and compares against a configured inactivity threshold.

Language-specific patterns:
- **Express/Node.js:** `express-session` with `rolling: true` and `cookie.maxAge` configured. Redis session store with TTL that resets on access. For JWTs, short-lived access tokens with refresh token rotation.
- **Django:** `SESSION_COOKIE_AGE` combined with `SESSION_SAVE_EVERY_REQUEST = True` (sliding expiration). Without `SESSION_SAVE_EVERY_REQUEST`, Django uses absolute expiry from session creation, which does not count as an inactivity timeout.
- **Spring:** `server.servlet.session.timeout` controls the inactivity timeout. Spring Session with Redis sets TTL on each access.
- **Rails:** `expire_after` option in session store configuration. Devise's `timeoutable` module.
- **Laravel:** `lifetime` in `config/session.php` controls the inactivity timeout (minutes since last activity).
- **Flask:** `PERMANENT_SESSION_LIFETIME` combined with `session.permanent = True`. Custom middleware tracking last activity.
- **ASP.NET:** `options.IdleTimeout` in session configuration. Sliding expiration for cookie authentication via `SlidingExpiration = true`.
- **Go:** `scs.Lifetime` or `scs.IdleTimeout` in session manager configuration. Custom middleware tracking last access.

- **Red flags:** No session timeout configured (sessions live indefinitely). Very long inactivity timeouts (e.g., 24 hours) without documented justification. Client-side-only timeout (JavaScript timer that redirects to login) without server-side enforcement — the session remains valid on the server.

**7.3.2 — Absolute maximum session lifetime:**

What to look for:
- Regardless of activity, sessions must have an absolute maximum lifetime after which re-authentication is required. This limits the damage window if a session is compromised.
- **Safe patterns:** Session records that store a creation timestamp and are invalidated when the absolute lifetime is exceeded, even if the user is actively using the application. JWT `exp` claims that set a hard upper bound on token validity. Separate tracking of session creation time distinct from last-activity time.
- **Red flags:** Only inactivity timeout configured with no absolute lifetime — an actively used compromised session could persist indefinitely. JWT refresh tokens that can be used indefinitely to obtain new access tokens without ever requiring re-authentication. Rolling session expiry (sliding window) as the only timeout mechanism.
- For JWT-based sessions: check that refresh tokens have an absolute expiry and cannot be refreshed indefinitely. Even with short-lived access tokens, the refresh chain must have a hard stop.
- This is distinct from 7.3.1 — an application can pass 7.3.1 (inactivity timeout) but fail 7.3.2 if there is no absolute cap on session duration.

---

## V7.4: Session Termination

Session termination may be handled either by the application itself or by the SSO provider if the SSO provider is handling session management instead of the application. It may be necessary to decide whether the SSO provider is in scope when considering the requirements in this section as some may be controlled by the provider.

Session termination should result in requiring re-authentication and be effective across the application, federated login (if present), and any relying parties.

For stateful session mechanisms, termination typically involves invalidating the session on the backend. In the case of self-contained tokens, additional measures are required to revoke or block these tokens, as they may otherwise remain valid until expiration.

| # | Requirement | Level |
|---|-------------|-------|
| **7.4.1** | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | 1 |
| **7.4.2** | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | 1 |
| **7.4.3** | Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update). | 2 |
| **7.4.4** | Verify that all pages that require authentication have easy and visible access to logout functionality. | 2 |
| **7.4.5** | Verify that application administrators are able to terminate active sessions for an individual user or for all users. | 2 |

### Audit Guidance for V7.4

**7.4.1 — Effective session invalidation on termination:**

What to look for:
- When a user logs out or a session expires, the session must be fully invalidated on the server side. Subsequent requests with the old session token must be rejected.
- **Stateful sessions (reference tokens):** The session record must be deleted or marked invalid in the session store (database, Redis, memcached). Simply clearing the client-side cookie is insufficient.

Language-specific patterns:
- **Express/Node.js:** `req.session.destroy()` must be called on logout, not just `req.session = null` or clearing the cookie. Check that the session store entry is removed.
- **Django:** `request.session.flush()` (deletes session data and regenerates key) or `django.contrib.auth.logout()` which calls `flush()`. Simply calling `del request.session['key']` for individual keys is insufficient.
- **Spring:** `session.invalidate()` or `SecurityContextHolder.clearContext()`. Spring Security's logout handler should be configured to invalidate the HTTP session.
- **Rails:** `reset_session` on logout. Check that Devise's `sign_out` properly destroys the session.
- **Laravel:** `Auth::logout()` combined with `$request->session()->invalidate()` and `$request->session()->regenerateToken()`.
- **Flask:** `session.clear()` combined with server-side session store deletion. For `flask-login`, `logout_user()`.
- **ASP.NET:** `HttpContext.SignOutAsync()` and `HttpContext.Session.Clear()`.
- **Go:** Session store `Destroy()` method. For `gorilla/sessions`, setting `MaxAge` to -1 and saving.

- **JWT/self-contained tokens:** Since JWTs cannot be "deleted" from the server, check for: token blocklist/denylist (storing invalidated `jti` values), per-user token version or `iat` threshold tracking (rejecting tokens issued before logout), per-user signing key rotation on logout. **Red flag:** JWT-based sessions where logout only clears the client-side token with no server-side revocation mechanism — the token remains valid until expiry.

**7.4.2 — Session termination on account disable/delete:**

What to look for:
- When an account is disabled or deleted (admin action, user self-deletion, automated deactivation), all active sessions for that user must be immediately terminated.
- **Safe patterns:** Account deactivation logic that explicitly queries and destroys all sessions for the user in the session store. User model with a "session version" or "last-valid-token-time" field that is updated on account disable, causing all existing sessions/tokens to become invalid. Event-driven architecture where account disable/delete events trigger session cleanup.
- **Red flags:** Account disable logic that only sets a flag in the database without touching sessions — the user remains logged in until their session naturally expires. Session store that cannot be queried by user ID (e.g., default file-based sessions with opaque keys), making bulk invalidation impossible.
- For JWT-based systems: check that a mechanism exists to reject tokens for disabled accounts (e.g., checking account status on each request, per-user signing key invalidation, or token blocklist).
- Check the admin panel or account management code paths for explicit session cleanup logic.

**7.4.3 — Session termination option after credential change:**

What to look for:
- After a password change, password reset, or MFA configuration change, the application should offer the user the option to terminate all other active sessions (or do so automatically).
- **Safe patterns:** Password change handler that invalidates all sessions except the current one. "Log out of all other devices" option presented after credential changes. Per-user session version counter incremented on credential change.
- **Red flags:** Password change or MFA update handlers that only update the credential in the database without any session management logic. No mechanism to invalidate other sessions after a security-sensitive change.
- Check password change, password reset, and MFA configuration endpoints for session invalidation calls.
- Note: this requires the *option* to terminate other sessions, not necessarily automatic termination — though automatic termination also satisfies the requirement.

**7.4.4 — Visible logout functionality:**

What to look for:
- This is primarily a UI/UX requirement. In a static analysis context, check that:
  - A logout route/endpoint exists and is functional.
  - Frontend templates or components for authenticated pages include a logout link/button.
  - The logout action is not buried in deep navigation or hidden behind multiple clicks.
- **Red flags:** No logout endpoint defined. Authenticated page templates with no logout link in the navigation/header. Logout functionality only accessible via direct URL (not linked in UI).
- For single-page applications (SPAs): check that the main layout/navigation component includes a logout action.
- Mark with moderate confidence for static analysis — full verification requires UI testing.

**7.4.5 — Admin session termination capability:**

What to look for:
- Administrative interfaces or APIs that allow administrators to terminate sessions for a specific user or for all users.
- **Safe patterns:** Admin panel with "force logout" or "terminate session" functionality per user. Admin API endpoint for session revocation (e.g., `DELETE /admin/users/{id}/sessions`). "Terminate all sessions" button in admin dashboard. Management commands for bulk session termination.
- **Red flags:** No admin-accessible session management functionality. Admin can disable accounts but has no way to force-terminate active sessions immediately.
- Check admin routes, admin controllers/views, and admin panel templates for session management features.
- For JWT-based systems: admin must be able to add tokens to a blocklist or update per-user signing keys/version counters to force re-authentication.

---

## V7.5: Defenses Against Session Abuse

This section provides requirements to mitigate the risk posed by active sessions that are either hijacked or abused through vectors that rely on the existence and capabilities of active user sessions. For example, using malicious content execution to force an authenticated victim browser to perform an action using the victim's session.

> Note that the level-specific guidance in the "Authentication" chapter should be taken into account when considering requirements in this section.

| # | Requirement | Level |
|---|-------------|-------|
| **7.5.1** | Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery. | 2 |
| **7.5.2** | Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions. | 2 |
| **7.5.3** | Verify that the application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations. | 3 |

### Audit Guidance for V7.5

**7.5.1 — Re-authentication before sensitive attribute changes:**

What to look for:
- Before allowing changes to email address, phone number, MFA configuration, or recovery information, the application must require the user to re-enter their password (or complete another full authentication challenge).
- **Safe patterns:** "Confirm password" prompt before allowing email/phone/MFA changes. Separate API endpoint for sensitive changes that requires current password as a parameter. Sudo mode / elevated session (e.g., GitHub's "sudo mode") that requires recent re-authentication.
- **Red flags:** Account settings endpoints that allow changing email, phone, or MFA settings with only a valid session token and no re-authentication. Profile update API that accepts email/phone changes in the same request as non-sensitive changes (name, avatar) without additional authentication.

Language-specific patterns:
- **Django:** Check views for email/phone/MFA changes — do they call `authenticate()` or check `request.POST['current_password']` before processing?
- **Rails/Devise:** Check for `current_password` validation in `RegistrationsController#update` or equivalent.
- **Spring:** Check for `@AuthenticationPrincipal` re-validation or password confirmation in sensitive update endpoints.
- **Express/Node.js:** Check middleware or handler logic for password re-verification before account attribute changes.
- **Laravel:** Check for `Hash::check()` against provided current password before sensitive updates.
- **ASP.NET:** Check for `UserManager.CheckPasswordAsync()` or equivalent before allowing sensitive attribute modifications.
- **Go:** Check handler logic for password verification (e.g., `bcrypt.CompareHashAndPassword()`) before processing sensitive updates.

- Identify all endpoints that modify authentication-related attributes and verify each one requires re-authentication.

**7.5.2 — User session visibility and termination:**

What to look for:
- Users must be able to view a list of their active sessions (with useful metadata like device, location, last active time) and terminate any or all of them after re-authenticating with at least one factor.
- **Safe patterns:** "Active sessions" or "Logged-in devices" page in account settings. API endpoints like `GET /account/sessions` and `DELETE /account/sessions/{id}`. Session listing with metadata (IP address, user agent, last activity, creation time). Require password or OTP confirmation before terminating other sessions.
- **Red flags:** No user-facing session management interface. Session store that does not support listing sessions by user (e.g., default cookie-based sessions, default in-memory sessions). Users can terminate sessions without any re-authentication.
- This requires the session store to support querying by user ID — check whether the session architecture supports this. Server-side session stores (Redis, database) typically can; encrypted cookie sessions cannot.

**7.5.3 — Step-up authentication for sensitive operations:**

This is a Level 3 requirement.

What to look for:
- Before performing highly sensitive operations (large financial transfers, administrative actions, data export, destructive operations), the application must require additional authentication — re-entering password, confirming with MFA, or another verification step.
- **Safe patterns:** Transaction signing or confirmation flows. Step-up authentication middleware that checks for recent re-authentication before sensitive endpoints. Time-limited elevated session ("sudo mode") requiring password/MFA for sensitive actions.
- **Red flags:** High-value operations (fund transfers, account deletion, role changes, bulk data export) that execute with only a standard session token and no additional verification.
- This is distinct from 7.5.1 (which focuses on account attribute changes) — this covers any highly sensitive business operation.
- Determining what constitutes a "highly sensitive transaction" requires business context. Mark with moderate confidence and flag for MANUAL_REVIEW if sensitive operations are identified but it is unclear whether they warrant step-up authentication.

---

## V7.6: Federated Re-authentication

This section relates to those writing Relying Party (RP) or Identity Provider (IdP) code. These requirements are derived from the [NIST SP 800-63C](https://pages.nist.gov/800-63-4/sp800-63c.html) for Federation & Assertions.

| # | Requirement | Level |
|---|-------------|-------|
| **7.6.1** | Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached. | 2 |
| **7.6.2** | Verify that creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction. | 2 |

### Audit Guidance for V7.6

**General note:** These requirements apply only to applications that participate in a federated identity ecosystem (SAML, OIDC, OAuth2). Mark N/A if the application does not integrate with any Identity Provider or act as a Relying Party. To confirm, check for the presence of federation libraries and configuration.

Libraries/dependencies to look for:
- **Node.js:** `passport-saml`, `openid-client`, `passport-openidconnect`, `oidc-provider`, `next-auth` with OIDC providers.
- **Python/Django:** `django-allauth`, `python-social-auth`, `mozilla-django-oidc`, `pysaml2`, `python3-saml`.
- **Python/Flask:** `flask-oidc`, `authlib`.
- **Spring:** `spring-security-saml2-service-provider`, `spring-security-oauth2-client`, `spring-security-oauth2-resource-server`.
- **Rails:** `omniauth`, `omniauth-saml`, `omniauth-openid-connect`.
- **Laravel:** `laravel/socialite`, `aacotroneo/laravel-saml2`, `socialiteproviders/*`.
- **ASP.NET:** `Microsoft.AspNetCore.Authentication.OpenIdConnect`, `Sustainsys.Saml2`, `Microsoft.Identity.Web`.
- **Go:** `coreos/go-oidc`, `crewjam/saml`.

**7.6.1 — Coordinated session lifetime with IdP:**

What to look for:
- The application (RP) must respect session lifetime constraints imposed by the IdP and enforce re-authentication when the IdP session or assertion expires.
- **Safe patterns:** OIDC `max_age` parameter sent in authentication requests to enforce maximum authentication age. Checking `auth_time` claim in ID tokens and requiring re-authentication when it exceeds the configured threshold. SAML `SessionNotOnOrAfter` attribute being respected. Application session lifetime configured to not exceed IdP assertion validity.
- **Red flags:** Application creates a long-lived local session from a short-lived IdP assertion and never re-checks with the IdP. OIDC `id_token` `auth_time` claim ignored — the application never verifies how recently the user authenticated at the IdP. No `max_age` or `prompt=login` parameter used when re-authentication should be required.
- Check the OIDC/SAML callback handler: does it extract and store IdP authentication timestamp? Is there periodic validation against the IdP (e.g., checking the userinfo endpoint or refreshing tokens)?

**7.6.2 — Session creation requires user consent or explicit action:**

What to look for:
- The application must not silently create sessions via federated login without user interaction. This prevents scenarios where an attacker can force session creation by redirecting the victim to the IdP callback with a valid assertion.
- **Safe patterns:** OIDC `prompt=consent` or `prompt=login` parameters requiring explicit user interaction at the IdP. Login page requiring the user to click a "Sign in with [Provider]" button before initiating the federation flow. CSRF protection on the federation callback endpoint (state parameter validation in OAuth2/OIDC). Checking that the authentication request originated from the application (validating the `state` parameter or `nonce`).
- **Red flags:** Automatic session creation when visiting a federated callback URL with valid tokens. Silent SSO that creates sessions without any user-facing prompt or interaction. Missing `state` parameter validation in OIDC/OAuth2 callback — allows CSRF-based session injection.
- In OIDC flows: verify that the `state` parameter is generated, stored, and validated on callback. Verify that `nonce` is checked in the ID token.
- In SAML flows: verify that `InResponseTo` is validated against the original authentication request.

---

## References

For more information, see also:

* [OWASP Web Security Testing Guide: Session Management Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing)
* [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

## V7 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 6 | 7.2.1, 7.2.2, 7.2.3, 7.2.4, 7.4.1, 7.4.2 |
| L2 | 12 | 7.1.1, 7.1.2, 7.1.3, 7.3.1, 7.3.2, 7.4.3, 7.4.4, 7.4.5, 7.5.1, 7.5.2, 7.6.1, 7.6.2 |
| L3 | 1 | 7.5.3 |
| **Total** | **19** | |
