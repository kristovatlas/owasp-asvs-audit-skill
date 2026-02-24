# V10: OAuth and OIDC

**ASVS Version:** 5.0.0
**Source file:** `5.0/en/0x19-V10-OAuth-and-OIDC.md`

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

OAuth2 (referred to as OAuth in this chapter) is an industry-standard framework for delegated authorization. For example, using OAuth, a client application can obtain access to APIs (server resources) on a user's behalf, provided the user has authorized the client application to do so.

By itself, OAuth is not designed for user authentication. The OpenID Connect (OIDC) framework extends OAuth by adding a user identity layer on top of OAuth. OIDC provides support for features including standardized user information, Single Sign-On (SSO), and session management. As OIDC is an extension of OAuth, the OAuth requirements in this chapter also apply to OIDC.

The following roles are defined in OAuth:

* The OAuth client is the application that attempts to obtain access to server resources (e.g., by calling an API using the issued access token). The OAuth client is often a server-side application.
    * A confidential client is a client capable of maintaining the confidentiality of the credentials it uses to authenticate itself with the authorization server.
    * A public client is not capable of maintaining the confidentiality of credentials for authenticating with the authorization server. Therefore, instead of authenticating itself (e.g., using 'client_id' and 'client_secret' parameters), it only identifies itself (using a 'client_id' parameter).
* The OAuth resource server (RS) is the server API exposing resources to OAuth clients.
* The OAuth authorization server (AS) is a server application that issues access tokens to OAuth clients. These access tokens allow OAuth clients to access RS resources, either on behalf of an end-user or on the OAuth client's own behalf. The AS is often a separate application, but (if appropriate) it may be integrated into a suitable RS.
* The resource owner (RO) is the end-user who authorizes OAuth clients to obtain limited access to resources hosted on the resource server on their behalf. The resource owner consents to this delegated authorization by interacting with the authorization server.

The following roles are defined in OIDC:

* The relying party (RP) is the client application requesting end-user authentication through the OpenID Provider. It assumes the role of an OAuth client.
* The OpenID Provider (OP) is an OAuth AS that is capable of authenticating the end-user and provides OIDC claims to an RP. The OP may be the identity provider (IdP), but in federated scenarios, the OP and the identity provider (where the end-user authenticates) may be different server applications.

OAuth and OIDC were initially designed for third-party applications. Today, they are often used by first-party applications as well. However, when used in first-party scenarios, such as authentication and session management, the protocol adds some complexity, which may introduce new security challenges.

OAuth and OIDC can be used for many types of applications, but the focus for ASVS and the requirements in this chapter is on web applications and APIs.

Since OAuth and OIDC can be considered logic on top of web technologies, general requirements from other chapters always apply, and this chapter cannot be taken out of context.

This chapter addresses best current practices for OAuth2 and OIDC aligned with specifications found at <https://oauth.net/2/> and <https://openid.net/developers/specs/>. Even if RFCs are considered mature, they are updated frequently. Thus, it is important to align with the latest versions when applying the requirements in this chapter. See the references section for more details.

Given the complexity of the area, it is vitally important for a secure OAuth or OIDC solution to use well-known industry-standard authorization servers and apply the recommended security configuration.

Terminology used in this chapter aligns with OAuth RFCs and OIDC specifications, but note that OIDC terminology is only used for OIDC-specific requirements; otherwise, OAuth terminology is used.

In the context of OAuth and OIDC, the term "token" in this chapter refers to:

* Access tokens, which shall only be consumed by the RS and can either be reference tokens that are validated using introspection or self-contained tokens that are validated using some key material.
* Refresh tokens, which shall only be consumed by the authorization server that issued the token.
* OIDC ID Tokens, which shall only be consumed by the client that triggered the authorization flow.

The risk levels for some of the requirements in this chapter depend on whether the client is a confidential client or regarded as a public client. Since using strong client authentication mitigates many attack vectors, a few requirements might be relaxed when using a confidential client for L1 applications.

---

## V10.1: Generic OAuth and OIDC Security

This section covers generic architectural requirements that apply to all applications using OAuth or OIDC.

| # | Requirement | Level |
|---|-------------|-------|
| **10.1.1** | Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend. | 2 |
| **10.1.2** | Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', 'state' or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started. | 2 |

### Audit Guidance for V10.1

**10.1.1 -- Token exposure minimization:**

What to look for:
- **Backend-for-frontend (BFF) pattern:** If the application is a browser-based SPA with a backend, verify that access tokens and refresh tokens are stored and managed exclusively on the backend. The frontend should only receive a session cookie, never raw OAuth tokens.
- **Token storage in browser:** Search for access tokens or refresh tokens stored in `localStorage`, `sessionStorage`, or non-HttpOnly cookies. These are red flags for browser-based applications.
- **Token forwarding:** Check that backend services do not blindly forward access tokens to downstream services that do not need them. Each service should receive only the tokens scoped to its requirements.
- **Good patterns (Node.js/Express):** BFF middleware that handles token exchange server-side, session cookies with `httpOnly`, `secure`, and `sameSite` attributes. Libraries like `express-session` or `iron-session` storing tokens server-side.
- **Good patterns (Spring Security):** `spring-cloud-gateway` acting as a BFF with `TokenRelay` filter. The `spring-security-oauth2-client` module managing tokens in the server-side session.
- **Good patterns (Django):** `django-oauth-toolkit` or `authlib` integration with Django sessions, tokens stored in the session backend (database, Redis), never exposed to the browser.
- **Red flags:** SPAs calling the token endpoint directly and storing tokens in the browser. Backend APIs returning raw tokens in JSON responses to the frontend. Tokens included in URL query parameters or fragments.

**10.1.2 -- Transaction binding (PKCE, state, nonce):**

What to look for:
- **PKCE implementation:** Verify that the authorization request includes a `code_challenge` parameter and the token request includes a `code_verifier`. The `code_verifier` should be generated with a cryptographically secure random generator (at least 32 bytes of entropy) and the `code_challenge_method` should be `S256`, not `plain`.
- **State parameter:** If PKCE is not used (or in addition to PKCE), verify the `state` parameter is generated with sufficient randomness, stored in the user's session before the redirect, and validated upon callback. Check that the comparison is constant-time or at least exact-match.
- **OIDC nonce:** For OIDC flows, verify the `nonce` parameter is generated, sent in the authentication request, stored in the session, and validated against the `nonce` claim in the returned ID Token.
- **Session binding:** Verify that `code_verifier`, `state`, or `nonce` values are bound to the user's session (server-side session or encrypted cookie), not just stored in the browser's `localStorage` or a plain cookie that could be read by other scripts.
- **Library-specific checks:**
    - **passport.js (Node.js):** Check `passport-oauth2` strategy configuration for `state: true` option or PKCE support. Look for custom `store` implementations for state management.
    - **authlib (Python):** Check that `code_challenge_method='S256'` is set in the OAuth client configuration. Verify `session` is used for state storage.
    - **Spring Security OAuth2:** Check `application.yml` / `application.properties` for `spring.security.oauth2.client.registration.*` settings. Spring Security enables PKCE by default for public clients since Spring Security 5.7+.
    - **OmniAuth (Ruby):** Check strategy options for `state` and `nonce` configuration. Verify that `OmniAuth.config.allowed_request_methods` is restricted.
    - **golang.org/x/oauth2:** Check that `oauth2.GenerateVerifier()` and `oauth2.S256ChallengeOption(verifier)` are used. Verify state parameter generation and validation in the callback handler.
- **Red flags:** Hard-coded or predictable state/nonce values. Missing PKCE entirely. State stored in a query parameter and not validated. No session binding for PKCE verifiers.

---

## V10.2: OAuth Client

These requirements detail the responsibilities for OAuth client applications. The client can be, for example, a web server backend (often acting as a Backend For Frontend, BFF), a backend service integration, or a frontend Single Page Application (SPA, aka browser-based application).

In general, backend clients are regarded as confidential clients and frontend clients are regarded as public clients. However, native applications running on the end-user device can be regarded as confidential when using OAuth dynamic client registration.

| # | Requirement | Level |
|---|-------------|-------|
| **10.2.1** | Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state' parameter that was sent in the authorization request. | 2 |
| **10.2.2** | Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss' parameter value and validate it in the authorization response and the token response. | 2 |
| **10.2.3** | Verify that the OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server. | 3 |

### Audit Guidance for V10.2

**10.2.1 -- CSRF protection on authorization code flow:**

What to look for:
- This requirement specifically targets the code flow callback. When the authorization server redirects back to the client with an authorization code, a CSRF attack could inject a malicious code.
- **PKCE (preferred):** Verify the client implements PKCE as described in V10.1.2 guidance. PKCE inherently protects against CSRF on the token request because the attacker cannot provide the correct `code_verifier`.
- **State parameter (alternative):** If PKCE is not used, verify the `state` parameter is validated in the callback. The state must be generated per-transaction, stored server-side in the session, and compared on callback.
- **Library-specific checks:**
    - **passport.js:** Check that the OAuth2 strategy has `state: true` or that PKCE is configured. Without `state: true`, passport-oauth2 does not generate or validate the state parameter by default.
    - **authlib (Python):** The `OAuth` client class handles state automatically when using `client.authorize_redirect()` and `client.authorize_access_token()`. Verify these methods are used rather than manual redirect construction.
    - **Spring Security OAuth2 Client:** PKCE is enabled by default for public clients. For confidential clients, check that `spring.security.oauth2.client.registration.*.redirect-uri` handling includes state validation (handled automatically by the framework).
    - **OmniAuth (Ruby):** State is typically enabled by default in modern versions. Verify `provider :oauth2, ..., state: true` or that the strategy generates state.
    - **golang.org/x/oauth2:** Check that the callback handler calls `oauth2Config.Exchange()` with the correct context and that state is validated manually before the exchange.
- **Red flags:** Custom OAuth callback handlers that do not check `state` and do not use PKCE. Callback endpoints that directly exchange the authorization code without any anti-forgery validation.

**10.2.2 -- Mix-up attack defense:**

What to look for:
- This is relevant only when the client is configured with multiple authorization servers (e.g., "Login with Google" and "Login with GitHub").
- **Issuer validation:** Check that the client validates the `iss` parameter in the authorization response (per RFC 9207) and in the token response. The `iss` value must match the expected authorization server for the flow that was initiated.
- **Per-AS state:** An alternative defense is to use a unique redirect URI per authorization server, or to encode the expected AS identity into the state parameter and validate it on callback.
- **Library-specific checks:**
    - **passport.js:** Each strategy instance is typically bound to a single provider, which provides implicit mix-up protection. However, if a generic OAuth2 strategy is reused across multiple providers, verify issuer validation.
    - **authlib (Python):** Check that each registered OAuth client has a distinct name and that the callback handler verifies which provider was used.
    - **Spring Security:** Each `registration` in `spring.security.oauth2.client.registration.*` is bound to a specific provider, providing implicit protection.
- If the application only integrates with a single authorization server, this requirement may be marked N/A with a note explaining the single-AS architecture.

**10.2.3 -- Minimal scope requests (L3):**

What to look for:
- Review the OAuth client configuration for the scopes requested in authorization requests. The client should request only the scopes necessary for its functionality.
- **Search patterns:** Look for `scope` parameters in OAuth configuration files, strategy definitions, or authorization request construction. Common scopes to scrutinize: requesting `admin` or broad scopes when only user-level access is needed; requesting `write` scopes when only `read` is required.
- **Good patterns:** Scopes defined in configuration files with comments explaining why each scope is needed. Minimal scope sets like `openid profile email` for authentication-only use cases.
- **Red flags:** Requesting wildcard or overly broad scopes such as `*`, `all`, `full_access`. Requesting scopes like `offline_access` (for refresh tokens) when not needed. Copy-pasted scope lists from documentation examples without trimming.

---

## V10.3: OAuth Resource Server

In the context of ASVS and this chapter, the resource server is an API. To provide secure access, the resource server must:

* Validate the access token, according to the token format and relevant protocol specifications, e.g., JWT-validation or OAuth token introspection.
* If valid, enforce authorization decisions based on the information from the access token and permissions which have been granted. For example, the resource server needs to verify that the client (acting on behalf of RO) is authorized to access the requested resource.

Therefore, the requirements listed here are OAuth or OIDC specific and should be performed after token validation and before performing authorization based on information from the token.

| # | Requirement | Level |
|---|-------------|-------|
| **10.3.1** | Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud' claim in JWT), or it can be checked using the token introspection endpoint. | 2 |
| **10.3.2** | Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization_details' are present, they must be part of the decision. | 2 |
| **10.3.3** | Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss' and 'sub' claims. | 2 |
| **10.3.4** | Verify that, if the resource server requires specific authentication strength, methods, or recentness, it verifies that the presented access token satisfies these constraints. For example, if present, using the OIDC 'acr', 'amr' and 'auth_time' claims respectively. | 2 |
| **10.3.5** | Verify that the resource server prevents the use of stolen access tokens or replay of access tokens (from unauthorized parties) by requiring sender-constrained access tokens, either Mutual TLS for OAuth 2 or OAuth 2 Demonstration of Proof of Possession (DPoP). | 3 |

### Audit Guidance for V10.3

**10.3.1 -- Audience validation:**

What to look for:
- **JWT-based tokens:** Verify that the resource server checks the `aud` claim in the JWT access token and rejects tokens where the audience does not match the resource server's own identifier. The audience should be a specific value (e.g., `https://api.example.com`) not a wildcard.
- **Introspection-based tokens:** Verify that when using opaque/reference tokens and the token introspection endpoint (RFC 7662), the resource server checks the audience field in the introspection response.
- **Library-specific checks:**
    - **Spring Security Resource Server:** Check for `spring.security.oauth2.resourceserver.jwt.audiences` configuration or a custom `JwtDecoder` with audience validation. Spring does not validate audience by default; a custom `JwtAuthenticationConverter` or `OAuth2TokenValidator` is required.
    - **express-jwt / jose (Node.js):** Check for `audience` option in JWT verification: `jwt.verify(token, key, { audience: 'expected-audience' })`. If using `express-oauth2-jwt-bearer`, check the `audience` configuration.
    - **authlib (Python):** Check `ResourceProtector` configuration for claims validation including `aud`.
    - **IdentityServer (.NET):** Check `ApiResource` and `ApiScope` configuration. Audience validation is typically handled by the `AddJwtBearer` middleware with `TokenValidationParameters.ValidAudience`.
    - **golang.org/x/oauth2 / go-jose:** Check that JWT validation includes audience checking, e.g., `jwt.Expected{Audience: []string{"expected"}}`.
- **Red flags:** JWT validation that only checks signature and expiration but ignores the `aud` claim. Accepting tokens with any audience value or no audience claim.

**10.3.2 -- Claims-based authorization enforcement:**

What to look for:
- **Scope enforcement:** Verify that API endpoints check the `scope` claim from the access token and reject requests where the required scope is not present. For example, a `GET /users` endpoint should require `read:users` scope and a `POST /users` endpoint should require `write:users`.
- **Subject enforcement:** Verify that when a user-specific resource is accessed, the `sub` claim is used to ensure the resource belongs to the authenticated user (preventing IDOR via token misuse).
- **Authorization details:** If using Rich Authorization Requests (RFC 9396), verify that `authorization_details` claims are checked.
- **Library-specific checks:**
    - **Spring Security:** Check for `@PreAuthorize("hasAuthority('SCOPE_read:users')")` or `.requestMatchers().hasAuthority()` configurations. Spring maps JWT scopes to granted authorities with a `SCOPE_` prefix by default.
    - **Express (Node.js):** Check for middleware that extracts and validates scopes from `req.auth.scope` or similar. Libraries like `express-oauth2-jwt-bearer` provide `requiredScopes()` middleware.
    - **Django REST Framework:** Check for custom permission classes that validate token scopes, or integration with `django-oauth-toolkit` which provides `TokenHasScope` permission.
    - **IdentityServer / ASP.NET:** Check for `[Authorize(Policy = "...")]` attributes and policy definitions that check scope claims.
- **Red flags:** Endpoints that accept any valid token without checking scopes. Authorization logic that only checks user identity but ignores delegated authorization scopes.

**10.3.3 -- Stable user identification (iss + sub):**

What to look for:
- Verify that the resource server identifies users by the combination of `iss` (issuer) and `sub` (subject) claims, not by mutable claims like `email`, `preferred_username`, or `name`.
- **Why this matters:** An email address can be reassigned to a different user. The `sub` claim from a given issuer is guaranteed to be stable and unique for that user.
- **Search patterns:** Look for user lookup or creation logic triggered by access token claims. Check which claim is used as the primary key or unique identifier. Search for patterns like `user = User.find_by(email: token['email'])` which are incorrect.
- **Good patterns:** `user = User.find_by(issuer: token['iss'], subject: token['sub'])` or equivalent. Mapping table that links `(iss, sub)` pairs to internal user IDs.
- **Red flags:** Using `email` claim as the sole user identifier. Using `sub` without `iss` when the system could accept tokens from multiple issuers.

**10.3.4 -- Authentication strength verification (acr, amr, auth_time):**

What to look for:
- This is relevant for resource servers that have endpoints requiring step-up authentication (e.g., financial transactions requiring MFA, or actions requiring recent authentication).
- **Claims to check:** `acr` (Authentication Context Class Reference) indicates the authentication level. `amr` (Authentication Methods References) indicates methods used (e.g., `["pwd", "otp"]`). `auth_time` indicates when the user last authenticated.
- **Search patterns:** Look for middleware or guards that inspect these claims before allowing access to sensitive endpoints. Check for `auth_time` comparisons against a maximum age threshold.
- **Good patterns:** A custom middleware that checks `acr` claim value against a required level (e.g., `urn:mace:incommon:iap:silver` or a numeric level) before allowing access to high-value operations. Checking `auth_time` to ensure authentication happened within the last N minutes for sensitive operations.
- If the application does not have endpoints requiring step-up authentication or varying authentication strength, this may be marked N/A with justification.

**10.3.5 -- Sender-constrained access tokens (L3):**

What to look for:
- **mTLS (RFC 8705):** Verify that the resource server validates the client certificate thumbprint (`cnf.x5t#S256`) in the JWT access token against the TLS client certificate presented in the request.
- **DPoP (RFC 9449):** Verify that the resource server requires a `DPoP` proof header, validates the DPoP proof JWT (signature, `jti`, `htm`, `htu`, `iat`), and checks the `cnf.jkt` claim in the access token against the DPoP proof's public key.
- **Library-specific checks:**
    - **Spring Security:** Check for mTLS configuration in the servlet container and custom token validators that check certificate binding. DPoP support may require custom implementation or a specific library.
    - **IdentityServer (.NET):** Check for `MutualTlsTokenEndpoint` configuration or DPoP validation middleware.
    - **Node.js:** Check for custom middleware that validates DPoP proof JWTs and binds them to access tokens.
- **Red flags:** Bearer tokens accepted without any sender constraint. No TLS client certificate requirement and no DPoP proof validation. This is an L3 requirement and may not be present in L1/L2 applications.

---

## V10.4: OAuth Authorization Server

These requirements detail the responsibilities for OAuth authorization servers, including OpenID Providers.

For client authentication, the 'self_signed_tls_client_auth' method is allowed with the prerequisites required by [section 2.2](https://datatracker.ietf.org/doc/html/rfc8705#name-self-signed-certificate-mut) of [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705).

| # | Requirement | Level |
|---|-------------|-------|
| **10.4.1** | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | 1 |
| **10.4.2** | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | 1 |
| **10.4.3** | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | 1 |
| **10.4.4** | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | 1 |
| **10.4.5** | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | 1 |
| **10.4.6** | Verify that, if the code grant is used, the authorization server mitigates authorization code interception attacks by requiring proof key for code exchange (PKCE). For authorization requests, the authorization server must require a valid 'code_challenge' value and must not accept a 'code_challenge_method' value of 'plain'. For a token request, it must require validation of the 'code_verifier' parameter. | 2 |
| **10.4.7** | Verify that if the authorization server supports unauthenticated dynamic client registration, it mitigates the risk of malicious client applications. It must validate client metadata such as any registered URIs, ensure the user's consent, and warn the user before processing an authorization request with an untrusted client application. | 2 |
| **10.4.8** | Verify that refresh tokens have an absolute expiration, including if sliding refresh token expiration is applied. | 2 |
| **10.4.9** | Verify that refresh tokens and reference access tokens can be revoked by an authorized user using the authorization server user interface, to mitigate the risk of malicious clients or stolen tokens. | 2 |
| **10.4.10** | Verify that confidential client is authenticated for client-to-authorized server backchannel requests such as token requests, pushed authorization requests (PAR), and token revocation requests. | 2 |
| **10.4.11** | Verify that the authorization server configuration only assigns the required scopes to the OAuth client. | 2 |
| **10.4.12** | Verify that for a given client, the authorization server only allows the 'response_mode' value that this client needs to use. For example, by having the authorization server validate this value against the expected values or by using pushed authorization request (PAR) or JWT-secured Authorization Request (JAR). | 3 |
| **10.4.13** | Verify that grant type 'code' is always used together with pushed authorization requests (PAR). | 3 |
| **10.4.14** | Verify that the authorization server issues only sender-constrained (Proof-of-Possession) access tokens, either with certificate-bound access tokens using mutual TLS (mTLS) or DPoP-bound access tokens (Demonstration of Proof of Possession). | 3 |
| **10.4.15** | Verify that, for a server-side client (which is not executed on the end-user device), the authorization server ensures that the 'authorization_details' parameter value is from the client backend and that the user has not tampered with it. For example, by requiring the usage of pushed authorization request (PAR) or JWT-secured Authorization Request (JAR). | 3 |
| **10.4.16** | Verify that the client is confidential and the authorization server requires the use of strong client authentication methods (based on public-key cryptography and resistant to replay attacks), such as mutual TLS ('tls_client_auth', 'self_signed_tls_client_auth') or private key JWT ('private_key_jwt'). | 3 |

### Audit Guidance for V10.4

This is the largest subsection with 16 requirements. Guidance is grouped by theme where requirements are closely related.

**10.4.1 -- Redirect URI validation (exact match):**

What to look for:
- **Authorization server configuration:** Check how redirect URIs are registered for each client. The AS must store a list of pre-registered redirect URIs per client and compare the `redirect_uri` from the authorization request using exact string comparison (not substring, not pattern matching, not allowing wildcards).
- **Library-specific checks:**
    - **Spring Authorization Server:** Check `RegisteredClient` configuration for `redirectUri()` entries. Spring Authorization Server performs exact match by default.
    - **IdentityServer (.NET):** Check `Client.RedirectUris` configuration. IdentityServer performs exact match by default but custom `IRedirectUriValidator` implementations may weaken this.
    - **oauth2-server (Node.js / node-oauth2-server):** Check the `model.getClient()` implementation and how `redirectUri` validation is performed. The library delegates validation to the model implementation.
    - **authlib (Python, server-side):** Check `AuthorizationServer` client registration and the redirect URI validation logic in `validate_authorization_request()`.
    - **Keycloak / Okta / Auth0:** Check the admin console or configuration for registered redirect URIs. Keycloak supports wildcards in redirect URIs, which would be a FAIL for this requirement.
- **Red flags:** Wildcard redirect URIs (e.g., `https://example.com/*`), subdomain wildcards, regex-based matching, partial string comparison, localhost redirect URIs in production. Any pattern-based matching of redirect URIs is a vulnerability (open redirect leading to authorization code theft).

**10.4.2 -- Authorization code single-use enforcement:**

What to look for:
- Verify that the authorization server marks an authorization code as used after the first successful token exchange and rejects subsequent attempts to use the same code.
- **Critical behavior:** When a code is presented a second time, the AS must not only reject the request but also revoke any tokens that were issued using that code. This is a defense against authorization code replay.
- **Implementation patterns:** Authorization codes stored in a database or cache with a `used` flag or deleted after first use. Race condition protection (two simultaneous token requests with the same code) via database-level unique constraints or atomic operations.
- **Red flags:** In-memory code storage without atomic single-use enforcement. No token revocation when a reused code is detected.
- Most well-maintained authorization server libraries (Spring Authorization Server, IdentityServer, Keycloak, authlib) handle this correctly by default. Verify that custom implementations also enforce this.

**10.4.3 -- Authorization code short lifetime:**

What to look for:
- Check the configured lifetime/expiration for authorization codes. The maximum is 10 minutes for L1/L2 and 1 minute for L3.
- **Search patterns:** Look for configuration values related to authorization code expiration: `authorization_code_lifetime`, `code_lifetime`, `authorization_code_expiry`, TTL settings for code storage.
- **Library-specific checks:**
    - **Spring Authorization Server:** Check `TokenSettings.builder().authorizationCodeTimeToLive()`.
    - **IdentityServer (.NET):** Check `Client.AuthorizationCodeLifetime` (default is 300 seconds / 5 minutes).
    - **Keycloak:** Check realm settings for "Access Code Lifespan."
    - **authlib (Python):** Check the authorization code grant configuration for expiration settings.
- **Red flags:** Authorization codes that never expire. Lifetime exceeding 10 minutes. No explicit expiration configured (relying on unknown defaults).

**10.4.4 -- Grant type restriction (no implicit, no ROPC):**

What to look for:
- Verify that each client is configured with only the grant types it needs, and that the `token` (Implicit) and `password` (Resource Owner Password Credentials) grants are disabled entirely.
- **Search patterns:** Look for grant type configuration: `grant_types`, `allowed_grant_types`, `response_types`. Check for `implicit`, `token`, `password`, `resource_owner_password_credentials` in any configuration.
- **Library-specific checks:**
    - **Spring Authorization Server:** Check `RegisteredClient` for `.authorizationGrantType()` values. Ensure `AuthorizationGrantType.IMPLICIT` and `AuthorizationGrantType.PASSWORD` are not used.
    - **IdentityServer (.NET):** Check `Client.AllowedGrantTypes`. Ensure `GrantType.Implicit` and `GrantType.ResourceOwnerPassword` are not included.
    - **Keycloak:** Check client configuration for "Valid Grant Types." Ensure Implicit and Direct Access Grants (ROPC) are disabled.
    - **oauth2-server (Node.js):** Check which grant handlers are registered. Ensure `PasswordGrant` and `ImplicitGrant` are not included.
- **Red flags:** Any configuration or code enabling the Implicit flow or Resource Owner Password Credentials flow. These are deprecated in OAuth 2.1 and must not be used.

**10.4.5 -- Refresh token replay mitigation:**

What to look for:
- **Sender-constrained refresh tokens (preferred):** Check for DPoP or mTLS binding of refresh tokens.
- **Refresh token rotation (acceptable for L1/L2):** Verify that each time a refresh token is used, a new refresh token is issued and the old one is invalidated. Additionally, if a previously used (invalidated) refresh token is presented, all refresh tokens for that authorization grant should be revoked (family revocation).
- **Library-specific checks:**
    - **Spring Authorization Server:** Check `TokenSettings.builder().reuseRefreshTokens(false)` to enable rotation.
    - **IdentityServer (.NET):** Check `Client.RefreshTokenUsage = TokenUsage.OneTimeOnly` for rotation and `Client.UpdateAccessTokenClaimsOnRefresh`.
    - **Keycloak:** Check "Revoke Refresh Token" setting in realm configuration.
    - **Auth0:** Check "Refresh Token Rotation" settings in the application configuration. Auth0 supports automatic reuse detection.
- **Red flags:** Refresh tokens that can be used multiple times without rotation. No reuse detection mechanism. No family revocation when reuse is detected.

**10.4.6 -- PKCE enforcement by AS:**

What to look for:
- Verify that the authorization server requires PKCE for all authorization code grants, requires `code_challenge` in authorization requests, rejects `code_challenge_method=plain`, and validates `code_verifier` in token requests.
- **Library-specific checks:**
    - **Spring Authorization Server:** Check `ClientSettings.builder().requireProofKey(true)`. Verify `S256` is required.
    - **IdentityServer (.NET):** Check for PKCE configuration. IdentityServer 4+ supports PKCE. Verify `RequirePkce = true` on client configuration.
    - **Keycloak:** Check "Proof Key for Code Exchange Code Challenge Method" in client configuration. Should be set to `S256`.
    - **authlib (Python):** Check the `CodeChallenge` extension configuration and whether `plain` method is rejected.
- **Red flags:** PKCE not required (optional). `plain` challenge method accepted. Missing `code_verifier` validation on the token endpoint. PKCE enabled per-client rather than globally (some clients may be missed).

**10.4.7 -- Dynamic client registration security:**

What to look for:
- If the authorization server supports unauthenticated dynamic client registration (RFC 7591), it must treat dynamically registered clients as untrusted.
- **Search patterns:** Look for dynamic registration endpoint configuration (`/register`, `/connect/register`). Check whether the endpoint requires authentication (bearer token) or is open.
- **Key controls:** Client metadata validation (reject invalid URIs, check URI schemes), user consent prompts that clearly indicate the client is unverified, warnings displayed to users before authorizing untrusted clients.
- If dynamic client registration is not supported, this requirement is N/A.

**10.4.8 -- Refresh token absolute expiration:**

What to look for:
- Even when sliding/rolling expiration is used (extending token lifetime on each use), there must be an absolute maximum lifetime after which the refresh token expires regardless of activity.
- **Search patterns:** Look for configuration like `absolute_refresh_token_lifetime`, `refresh_token_max_lifetime`, `refresh_token_absolute_expiry`.
- **Library-specific checks:**
    - **IdentityServer (.NET):** Check `Client.AbsoluteRefreshTokenLifetime` (default 2592000 seconds / 30 days).
    - **Keycloak:** Check "SSO Session Max Lifespan" and "Client Session Max Lifespan."
    - **Spring Authorization Server:** Check `TokenSettings.builder().refreshTokenTimeToLive()`.
- **Red flags:** Refresh tokens with no absolute expiration. Sliding expiration that can extend token lifetime indefinitely.

**10.4.9 -- Token revocation UI:**

What to look for:
- Verify that the authorization server provides a user-facing interface where authenticated users can view and revoke their active refresh tokens and reference access tokens.
- **Search patterns:** Look for user consent management pages, token management dashboards, "active sessions" or "authorized applications" UI pages.
- **Key controls:** Users can see which clients have active tokens, users can revoke individual tokens or all tokens for a client, revocation takes effect immediately.
- For managed services (Keycloak, Auth0, Okta), check the user account management portal configuration.
- This is more of a feature verification than a code audit. Flag for MANUAL_REVIEW if the authorization server is a third-party service where the user portal must be checked manually.

**10.4.10 -- Confidential client authentication on backchannel:**

What to look for:
- Verify that all backchannel requests from confidential clients (token endpoint, PAR endpoint, revocation endpoint) require client authentication.
- **Authentication methods:** `client_secret_basic` (HTTP Basic auth), `client_secret_post` (secret in POST body), `private_key_jwt` (signed JWT), `tls_client_auth` or `self_signed_tls_client_auth` (mTLS).
- **Search patterns:** Check token endpoint middleware for client authentication enforcement. Look for client credential extraction and validation logic.
- **Red flags:** Token endpoint accepting requests without client authentication for confidential clients. Client secrets transmitted in query parameters. No authentication required on the revocation endpoint.

**10.4.11 -- Minimal scope assignment:**

What to look for:
- Verify that the authorization server configuration only assigns the scopes each client actually needs, following the principle of least privilege.
- **Search patterns:** Review client registrations in the AS configuration for `allowed_scopes`, `scopes`, `default_scopes`. Check whether clients have broad scope assignments (e.g., all available scopes) or targeted ones.
- **Red flags:** All clients having access to all scopes. Admin-level scopes assigned to public-facing clients. No differentiation in scope assignments across different client types.

**10.4.12 through 10.4.16 -- L3 advanced requirements (PAR, sender-constrained tokens, strong client auth):**

These are Level 3 requirements that collectively aim to achieve FAPI 2.0-level security. They should be audited together as they represent a cohesive security posture.

**10.4.12 -- Response mode restriction:**

What to look for:
- Verify that each client has a configured set of allowed `response_mode` values and the AS rejects requests with unexpected response modes.
- Use of PAR or JAR to ensure request parameters (including `response_mode`) cannot be tampered with.

**10.4.13 -- PAR required with code grant:**

What to look for:
- Verify that the authorization server requires pushed authorization requests (RFC 9126) for the code grant flow. The AS should reject authorization requests that were not initiated via the PAR endpoint.
- **Search patterns:** Look for PAR endpoint configuration (`/par`, `/as/par`). Check for a flag like `require_pushed_authorization_requests = true`.
- **Library-specific checks:**
    - **Spring Authorization Server:** Check for `AuthorizationServerSettings.builder().requirePushedAuthorizationRequests(true)`.
    - **Keycloak:** Check "Pushed Authorization Request Required" setting in client configuration.
    - **IdentityServer (.NET):** Check for PAR endpoint configuration and enforcement flags.
    - **authlib (Python):** Check whether the PAR endpoint is configured and whether regular authorization requests are rejected when PAR is available.

**10.4.14 -- Sender-constrained access tokens only:**

What to look for:
- The AS must issue only sender-constrained tokens (mTLS-bound or DPoP-bound), never plain bearer tokens. Check the token issuance logic for certificate thumbprint binding (`cnf.x5t#S256`) or DPoP key binding (`cnf.jkt`).
- **Search patterns:** Look for DPoP or mTLS configuration in the AS settings. Check the token generation logic for `cnf` claim inclusion.
- **Red flags:** Tokens issued as plain bearer tokens without any proof-of-possession binding. DPoP or mTLS available but optional rather than required.

**10.4.15 -- Authorization details integrity (PAR/JAR):**

What to look for:
- For server-side clients, verify that the `authorization_details` parameter comes from the client backend (not the browser) by requiring PAR or JAR. This prevents users from tampering with fine-grained authorization parameters.
- **Search patterns:** Check whether the AS accepts `authorization_details` in regular authorization requests (via query parameter) or only via PAR/JAR. Check for enforcement that server-side clients must use PAR or JAR.

**10.4.16 -- Strong client authentication (public-key based):**

What to look for:
- Verify that the AS requires public-key-based client authentication: `tls_client_auth`, `self_signed_tls_client_auth`, or `private_key_jwt`. Shared-secret methods (`client_secret_basic`, `client_secret_post`, `client_secret_jwt`) are not sufficient for L3.
- **Search patterns:** Check client authentication method configuration. Look for `token_endpoint_auth_method` in client registrations.
- **Red flags:** Client secrets stored in configuration. `client_secret_basic` or `client_secret_post` authentication method configured for any client. No public-key-based authentication enforced.

---

## V10.5: OIDC Client

As the OIDC relying party acts as an OAuth client, the requirements from the section "OAuth Client" apply as well.

> Note that the "Authentication with an Identity Provider" section in the "Authentication" chapter also contains relevant general requirements.

| # | Requirement | Level |
|---|-------------|-------|
| **10.5.1** | Verify that the client (as the relying party) mitigates ID Token replay attacks. For example, by ensuring that the 'nonce' claim in the ID Token matches the 'nonce' value sent in the authentication request to the OpenID Provider (in OAuth2 refereed to as the authorization request sent to the authorization server). | 2 |
| **10.5.2** | Verify that the client uniquely identifies the user from ID Token claims, usually the 'sub' claim, which cannot be reassigned to other users (for the scope of an identity provider). | 2 |
| **10.5.3** | Verify that the client rejects attempts by a malicious authorization server to impersonate another authorization server through authorization server metadata. The client must reject authorization server metadata if the issuer URL in the authorization server metadata does not exactly match the pre-configured issuer URL expected by the client. | 2 |
| **10.5.4** | Verify that the client validates that the ID Token is intended to be used for that client (audience) by checking that the 'aud' claim from the token is equal to the 'client_id' value for the client. | 2 |
| **10.5.5** | Verify that, when using OIDC back-channel logout, the relying party mitigates denial of service through forced logout and cross-JWT confusion in the logout flow. The client must verify that the logout token is correctly typed with a value of 'logout+jwt', contains the 'event' claim with the correct member name, and does not contain a 'nonce' claim. Note that it is also recommended to have a short expiration (e.g., 2 minutes). | 2 |

### Audit Guidance for V10.5

**10.5.1 -- ID Token replay mitigation (nonce validation):**

What to look for:
- Verify that the client generates a unique `nonce` value for each authentication request, stores it in the user's session, sends it in the authentication request to the OP, and then validates that the `nonce` claim in the returned ID Token matches the stored value.
- **Library-specific checks:**
    - **passport.js (openid-client / passport-openidconnect):** Check that `nonce` is generated and validated. The `openid-client` library handles nonce automatically when using `client.callback()` with the stored nonce.
    - **authlib (Python):** Check that nonce generation and validation is enabled in the OIDC client configuration. `authlib` handles this automatically via `session`.
    - **Spring Security OIDC:** Nonce validation is handled automatically by `OidcIdTokenDecoderFactory`. Check that the default ID token validator has not been overridden to skip nonce validation.
    - **OmniAuth (Ruby):** Check `openid_connect` strategy for nonce support.
    - **Microsoft.Identity.Web (.NET):** Nonce validation is handled by default. Verify it has not been disabled.
- **Red flags:** No nonce sent in the authentication request. Nonce generated but not validated in the ID Token. Custom ID Token parsing that skips nonce verification. Nonce stored in a client-side cookie without integrity protection.

**10.5.2 -- User identification via sub claim:**

What to look for:
- Verify that the client identifies users from the `sub` claim in the ID Token, not from mutable claims like `email` or `preferred_username`.
- **Search patterns:** Look for user creation or lookup logic triggered after OIDC authentication. Check which claim is used to match or create the user record.
- **Good patterns:** User table with `oidc_issuer` and `oidc_subject` columns. User lookup by `(iss, sub)` pair.
- **Red flags:** `User.find_by(email: id_token['email'])` or equivalent. Using `preferred_username` as a unique identifier. Account linking based solely on email match without verification.

**10.5.3 -- Authorization server metadata issuer validation:**

What to look for:
- Verify that when the client fetches the OpenID Provider's discovery document (`.well-known/openid-configuration`), it validates that the `issuer` value in the metadata exactly matches the expected issuer URL configured in the client.
- This prevents a malicious server from serving a discovery document with a different issuer's endpoints.
- **Library-specific checks:**
    - **openid-client (Node.js):** The `Issuer.discover()` method validates the issuer by default. Verify it has not been bypassed.
    - **authlib (Python):** Check that the OIDC client configuration includes a pre-configured `issuer` value and that metadata discovery validates it.
    - **Spring Security OIDC:** Issuer validation is performed by default when using `spring.security.oauth2.client.provider.*.issuer-uri`.
- **Red flags:** Fetching discovery documents without validating the issuer field. Accepting metadata from arbitrary URLs without pre-configured expected issuers. Custom discovery logic that skips issuer comparison.

**10.5.4 -- ID Token audience validation:**

What to look for:
- Verify that the client checks that the `aud` claim in the ID Token matches its own `client_id`. If the `aud` claim is an array, the client's `client_id` must be one of the values, and if there are multiple audiences, the `azp` (authorized party) claim should also be checked.
- **Library-specific checks:**
    - Most well-maintained OIDC libraries (openid-client, authlib, Spring Security, Microsoft.Identity.Web) validate audience by default. Verify that custom ID Token validation logic has not disabled audience checking.
    - **passport.js / openid-client:** Audience validation is automatic in `client.callback()`. Check for custom `processIdToken` functions that may skip it.
- **Red flags:** Custom JWT validation that ignores the `aud` claim. Accepting ID Tokens intended for other clients. No audience check when manually parsing ID Tokens with generic JWT libraries (e.g., `jsonwebtoken`, `jose`).

**10.5.5 -- Back-channel logout token validation:**

What to look for:
- This is relevant only if the application implements OIDC Back-Channel Logout. If not implemented, mark N/A.
- **Logout token validation checklist:**
    - Token `typ` header must be `logout+jwt`.
    - Token must contain an `events` claim with the member `http://schemas.openid.net/event/backchannel-logout`.
    - Token must NOT contain a `nonce` claim (to prevent confusion with ID Tokens).
    - Token expiration (`exp`) should be short (recommended 2 minutes).
    - Token `iss` and `aud` must be validated.
    - Token signature must be verified.
- **Search patterns:** Look for a back-channel logout endpoint (e.g., `/logout/backchannel`, `/oidc/logout`). Check the token validation logic at that endpoint.
- **Red flags:** Accepting logout tokens without verifying the `typ` header. Not checking for the absence of `nonce`. No expiration validation. Accepting logout tokens that are actually ID Tokens (cross-JWT confusion).

---

## V10.6: OpenID Provider

As OpenID Providers act as OAuth authorization servers, the requirements from the section "OAuth Authorization Server" apply as well.

> Note that if using the ID Token flow (not the code flow), no access tokens are issued, and many of the requirements for OAuth AS are not applicable.

| # | Requirement | Level |
|---|-------------|-------|
| **10.6.1** | Verify that the OpenID Provider only allows values 'code', 'ciba', 'id_token', or 'id_token code' for response mode. Note that 'code' is preferred over 'id_token code' (the OIDC Hybrid flow), and 'token' (any Implicit flow) must not be used. | 2 |
| **10.6.2** | Verify that the OpenID Provider mitigates denial of service through forced logout. By obtaining explicit confirmation from the end-user or, if present, validating parameters in the logout request (initiated by the relying party), such as the 'id_token_hint'. | 2 |

### Audit Guidance for V10.6

**10.6.1 -- Allowed response types:**

What to look for:
- Verify that the OpenID Provider configuration restricts the allowed `response_type` values to: `code`, `ciba`, `id_token`, or `id_token code`. The value `token` (Implicit flow) and any combination including `token` (e.g., `id_token token`, `code id_token token`) must be rejected.
- **Search patterns:** Look for response type configuration in the OP's settings: `allowed_response_types`, `supported_response_types`, `response_types_supported` in the discovery document.
- **Library-specific checks:**
    - **IdentityServer (.NET):** Check `Client.AllowedGrantTypes` and ensure no implicit-related types are included.
    - **Keycloak:** Check client settings and ensure "Implicit Flow Enabled" is off.
    - **Spring Authorization Server:** Check supported response types configuration.
- **Red flags:** `token` appearing in any allowed response type. Implicit flow enabled for any client. `response_types_supported` in the discovery document including `token`.

**10.6.2 -- Forced logout mitigation:**

What to look for:
- Verify that the OP's logout endpoint (RP-Initiated Logout) does not immediately log the user out upon receiving a GET request. Instead, it should either:
    - Prompt the user for explicit confirmation ("Are you sure you want to log out?"), or
    - Validate the `id_token_hint` parameter and optionally the `post_logout_redirect_uri` against registered values before processing.
- **Red flags:** Logout endpoint that processes logout on GET request without any confirmation or validation. An attacker could embed `<img src="https://op.example.com/logout">` to force user logout (denial of service).
- **Search patterns:** Look for the logout endpoint handler. Check whether it renders a confirmation page or directly invalidates the session.

---

## V10.7: Consent Management

These requirements cover the verification of the user's consent by the authorization server. Without proper user consent verification, a malicious actor may obtain permissions on the user's behalf through spoofing or social-engineering.

| # | Requirement | Level |
|---|-------------|-------|
| **10.7.1** | Verify that the authorization server ensures that the user consents to each authorization request. If the identity of the client cannot be assured, the authorization server must always explicitly prompt the user for consent. | 2 |
| **10.7.2** | Verify that when the authorization server prompts for user consent, it presents sufficient and clear information about what is being consented to. When applicable, this should include the nature of the requested authorizations (typically based on scope, resource server, Rich Authorization Requests (RAR) authorization details), the identity of the authorized application, and the lifetime of these authorizations. | 2 |
| **10.7.3** | Verify that the user can review, modify, and revoke consents which the user has granted through the authorization server. | 2 |

### Audit Guidance for V10.7

**10.7.1 -- Consent enforcement:**

What to look for:
- Verify that the authorization server prompts the user for consent during the authorization flow, especially for third-party clients. For first-party clients where the identity is assured, consent may be pre-approved, but for any client whose identity cannot be verified, explicit consent must always be required.
- **Search patterns:** Look for consent screen configuration, consent skip logic, auto-approval settings. Check for flags like `skip_consent`, `auto_approve`, `prompt=none` handling.
- **Library-specific checks:**
    - **Keycloak:** Check "Consent Required" setting on each client.
    - **IdentityServer (.NET):** Check `Client.RequireConsent` property.
    - **Spring Authorization Server:** Check `ClientSettings.builder().requireAuthorizationConsent()`.
    - **authlib (Python):** Check whether the `authorize` endpoint renders a consent page.
- **Red flags:** Consent disabled globally or for all clients. Auto-approval for dynamically registered (untrusted) clients. No consent prompt even for third-party applications.

**10.7.2 -- Clear consent information:**

What to look for:
- Review the consent screen template/page. It should display:
    - The name and identity of the requesting application.
    - The specific permissions/scopes being requested, described in user-friendly language.
    - For RAR, the specific authorization details.
    - The lifetime of the authorization (if applicable).
- **Search patterns:** Look for consent page templates (HTML/JSX/Blade/Thymeleaf), consent screen customization, scope display configuration.
- **Red flags:** Consent screen showing only technical scope names (e.g., `openid profile email` without human-readable descriptions). No application name shown. No indication of what the permissions allow.
- This is partially a UX review. Flag for MANUAL_REVIEW if the consent screen template exists but the quality of information presented requires human evaluation.

**10.7.3 -- Consent review and revocation:**

What to look for:
- Verify that the authorization server provides a user-facing interface where users can:
    - View their active consent grants (which applications have been authorized).
    - Modify consents (e.g., reduce granted scopes).
    - Revoke consents entirely (which should also revoke associated tokens).
- **Search patterns:** Look for user account management pages, consent management UI, "authorized applications" pages.
- **Library-specific checks:**
    - **Keycloak:** User account console at `/realms/{realm}/account` provides "Applications" tab for consent management.
    - **IdentityServer (.NET):** Check for a grants management page in the IdentityServer UI.
    - **Auth0:** Check the user dashboard configuration.
- **Red flags:** No user-facing consent management interface. Consents that cannot be revoked. No way for users to see which applications have been authorized.

---

## References

For more information on OAuth, please see:

* [oauth.net](https://oauth.net/)
* [OWASP OAuth 2.0 Protocol Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

For OAuth-related requirements in ASVS following published and in draft status RFC-s are used:

* [RFC6749 The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
* [RFC6750 The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
* [RFC6819 OAuth 2.0 Threat Model and Security Considerations](https://datatracker.ietf.org/doc/html/rfc6819)
* [RFC7636 Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
* [RFC7591 OAuth 2.0 Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/html/rfc7591)
* [RFC8628 OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
* [RFC8707 Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)
* [RFC9068 JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)
* [RFC9126 OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
* [RFC9207 OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
* [RFC9396 OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)
* [RFC9449 OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
* [RFC9700 Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700)
* [draft OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
* [draft The OAuth 2.1 Authorization Framework](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12)

For more information on OpenID Connect, please see:

* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
* [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)

---

## V10 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 5 | 10.4.1, 10.4.2, 10.4.3, 10.4.4, 10.4.5 |
| L2 | 24 | 10.1.1, 10.1.2, 10.2.1, 10.2.2, 10.3.1, 10.3.2, 10.3.3, 10.3.4, 10.4.6, 10.4.7, 10.4.8, 10.4.9, 10.4.10, 10.4.11, 10.5.1, 10.5.2, 10.5.3, 10.5.4, 10.5.5, 10.6.1, 10.6.2, 10.7.1, 10.7.2, 10.7.3 |
| L3 | 7 | 10.2.3, 10.3.5, 10.4.12, 10.4.13, 10.4.14, 10.4.15, 10.4.16 |
| **Total** | **36** | |
