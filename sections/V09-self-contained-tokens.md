# V9: Self-contained Tokens

**ASVS Version:** 5.0.0
**ASVS Source:** `0x18-V9-Self-contained-Tokens.md` in the [OWASP ASVS v5.0.0 repo](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/)

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

The concept of a self-contained token is mentioned in the original RFC 6749 OAuth 2.0 from 2012. It refers to a token containing data or claims on which a receiving service will rely to make security decisions. This should be differentiated from a simple token containing only an identifier, which a receiving service uses to look up data locally. The most common examples of self-contained tokens are JSON Web Tokens (JWTs) and SAML assertions.

The use of self-contained tokens has become very widespread, even outside of OAuth and OIDC. At the same time, the security of this mechanism relies on the ability to validate the integrity of the token and to ensure that the token is valid for a particular context. There are many pitfalls with this process, and this chapter provides specific details of the mechanisms that applications should have in place to prevent them.

---

## V9.1: Token Source and Integrity

This section includes requirements to ensure that the token has been produced by a trusted party and has not been tampered with.

| # | Requirement | Level |
|---|-------------|-------|
| **9.1.1** | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | 1 |
| **9.1.2** | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | 1 |
| **9.1.3** | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | 1 |

### Audit Guidance for V9.1

**General approach:** These requirements target the foundational integrity mechanisms for self-contained tokens (primarily JWTs, but also PASETO, SAML assertions, etc.). The sub-agent should identify where tokens are created, parsed, and validated in the codebase, and assess whether signature/MAC verification, algorithm restrictions, and key source controls are properly implemented.

**9.1.1 — Signature or MAC validation before accepting token contents:**

What to look for:
- Every code path that receives a self-contained token must verify its signature or MAC *before* reading claims from the token payload. Parsing the payload without verification is a FAIL.
- Check that the verification function is actually called and that its return value or exception is properly handled. A common mistake is calling a decode/parse function that does not verify signatures by default.

Language-specific patterns to check:
- **Python (PyJWT):** `jwt.decode(token, key, algorithms=[...])` is the correct verified decode. Red flag: `jwt.decode(token, options={"verify_signature": False})` or the legacy `jwt.decode(token, verify=False)`. Also check `python-jose`: `jose.jwt.decode(token, key, algorithms=[...])`.
- **JavaScript/TypeScript (jsonwebtoken):** `jwt.verify(token, secret)` performs verification. Red flag: `jwt.decode(token)` which only decodes without verifying. For `jose` library: `jwtVerify(token, key)` is correct; manual `decodeJwt(token)` without verification is a red flag.
- **Java (jjwt):** `Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token)` performs verification. Red flag: `Jwts.parserBuilder().build().parseClaimsJwt(token)` (note `Jwt` vs `Jws` -- the former does not verify). For `nimbus-jose-jwt`: ensure `JWSVerifier.verify()` is called.
- **PHP (firebase/php-jwt):** `Firebase\JWT\JWT::decode($token, $keyOrKeyArray)` verifies by default. Red flag: manually base64-decoding the payload without calling decode.
- **Ruby (ruby-jwt):** `JWT.decode(token, key, true, algorithms: [...])` -- the third argument (`true`) enables verification. Red flag: `JWT.decode(token, nil, false)` which disables verification.
- **Go (golang-jwt):** `jwt.Parse(tokenString, keyFunc)` or `jwt.ParseWithClaims(tokenString, claims, keyFunc)` verifies. Red flag: using `jwt.Parse` with a keyFunc that returns `nil` or skipping error checking on the returned token's `Valid` field.
- **C# (System.IdentityModel.Tokens.Jwt):** `JwtSecurityTokenHandler.ValidateToken(token, validationParameters, out _)` performs verification. Red flag: `JwtSecurityTokenHandler.ReadJwtToken(token)` without subsequent validation, or `TokenValidationParameters` with `ValidateIssuerSigningKey = false`.

Red flags (cross-language):
- Token payload extracted via base64 decoding without any library verification call.
- Verification errors caught and silently ignored (empty catch blocks, error callbacks that proceed anyway).
- Conditional verification that can be bypassed (e.g., only verifying in production, skipping in test/debug modes that could leak into production).

**9.1.2 — Algorithm allowlist (no 'None' algorithm):**

What to look for:
- The token verification code must explicitly specify which algorithms are permitted. Relying on the library default (which may accept any algorithm) is a finding.
- The `none` algorithm must not be accepted. This is the classic JWT "alg:none" attack where an attacker sets the algorithm header to `none` and provides no signature.
- Ideally, only symmetric (HMAC) *or* asymmetric (RSA/ECDSA/EdDSA) algorithms should be allowed in a given context, not both. Allowing both opens the door to key confusion attacks (e.g., using an RSA public key as an HMAC secret).

Language-specific patterns to check:
- **Python (PyJWT):** `jwt.decode(token, key, algorithms=["RS256"])` -- the `algorithms` parameter must be explicitly provided. Red flag: omitting `algorithms` parameter entirely (older versions may default to allowing all).
- **JavaScript (jsonwebtoken):** `jwt.verify(token, key, { algorithms: ["RS256"] })` -- the `algorithms` option must be set. Red flag: not specifying algorithms, allowing the token's header to dictate which algorithm is used.
- **Java (jjwt):** Algorithm restriction is typically implicit based on the key type, but check for explicit algorithm validation. For `nimbus-jose-jwt`: `JWSAlgorithm.RS256` should be specified when creating the verifier.
- **PHP (firebase/php-jwt):** v6+ uses `Key` objects or `KeyArray` that bind keys to algorithms. Red flag: older versions without algorithm restriction.
- **Ruby (ruby-jwt):** `JWT.decode(token, key, true, algorithms: ['RS256'])` -- the `algorithms` option must restrict allowed algorithms.
- **Go (golang-jwt):** The `keyFunc` should validate `token.Method` (the algorithm) before returning the key. Red flag: `keyFunc` that returns a key without checking `token.Method`.
- **C# (System.IdentityModel.Tokens.Jwt):** Check `TokenValidationParameters.ValidAlgorithms` to ensure it restricts algorithms.

Red flags (cross-language):
- No algorithm restriction -- the library accepts whatever algorithm the token header specifies.
- `none` or `None` in the allowed algorithms list.
- Both HMAC and RSA/ECDSA algorithms permitted in the same verification context without additional key-type checks (key confusion vulnerability).
- Algorithm validation performed on the token header *after* verification rather than as a verification parameter (TOCTOU).

**9.1.3 — Key material from trusted pre-configured sources:**

What to look for:
- Signing keys / verification keys should be loaded from trusted, pre-configured sources: environment variables, configuration files, secrets managers (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or well-known JWKS endpoints from trusted issuers.
- For JWKS (JSON Web Key Set) endpoints: the JWKS URL must be hardcoded or configured, not derived from the token itself. The `jku` (JWK Set URL), `x5u` (X.509 URL), and `jwk` (JSON Web Key) headers in the JWT must NOT be blindly trusted.

Language-specific patterns to check:
- **Python (PyJWT / python-jose):** Check if the `key` parameter is sourced from configuration or if any code reads `jku`/`x5u`/`jwk` from the token header and fetches keys from there.
- **JavaScript (jsonwebtoken / jose):** Check `jwks-rsa` or `jose.createRemoteJWKSet()` -- the JWKS URL should be hardcoded or from configuration, not from the token. Red flag: extracting the `jku` header from an unverified token and fetching keys from that URL.
- **Java (nimbus-jose-jwt):** `JWKSource` should be configured with a trusted URL. Red flag: `JWSHeader.getJWKURL()` used to dynamically fetch keys from the token header.
- **PHP (firebase/php-jwt):** Check that key material is loaded from configuration, not from token headers.
- **Ruby (ruby-jwt):** Check that key selection logic does not read untrusted headers from the token.
- **Go (golang-jwt):** Check that `keyFunc` does not extract key source information from the unverified token header.
- **C# (System.IdentityModel.Tokens.Jwt):** Check `TokenValidationParameters.IssuerSigningKeyResolver` -- if a custom resolver is used, ensure it does not trust token header values for key retrieval.

Red flags (cross-language):
- Any code that reads `jku`, `x5u`, or `jwk` from the token header and uses it to fetch or select verification keys without validation against an allowlist.
- JWKS endpoint URLs constructed from user input or token claims.
- Key material embedded in code or committed to version control (separate security concern, but worth flagging).

Safe patterns:
- JWKS URL hardcoded or loaded from environment/config, with caching and periodic refresh.
- Keys loaded from a secrets manager at application startup.
- Key ID (`kid`) header used only to select from a pre-loaded set of trusted keys.

N/A conditions for V9.1:
- Application does not use self-contained tokens (no JWT/PASETO/SAML parsing or generation). If the application uses only opaque session tokens or database-backed tokens, V9.1 is N/A.

---

## V9.2: Token Content

Before making security decisions based on the content of a self-contained token, it is necessary to validate that the token has been presented within its validity period and that it is intended for use by the receiving service and for the purpose for which it was presented. This helps avoid insecure cross-usage between different services or with different token types from the same issuer.

Specific requirements for OAuth and OIDC are covered in the dedicated chapter.

| # | Requirement | Level |
|---|-------------|-------|
| **9.2.1** | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | 1 |
| **9.2.2** | Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication. | 2 |
| **9.2.3** | Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service. | 2 |
| **9.2.4** | Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation. | 2 |

### Audit Guidance for V9.2

**General approach:** These requirements ensure that token *content* is validated beyond just integrity. The sub-agent should check that token lifetime, type, and audience are verified before security decisions are made based on token claims.

**9.2.1 — Validity time span (exp/nbf) enforcement:**

What to look for:
- Token verification must check that the current time is within the token's validity period. For JWTs, this means the `exp` (expiration) and `nbf` (not before) claims are validated.
- Most JWT libraries verify `exp` by default, but some allow disabling it. Check that expiration verification is not disabled.
- `nbf` is less commonly checked by default -- verify that it is enabled if tokens use this claim.

Language-specific patterns to check:
- **Python (PyJWT):** `exp` and `nbf` are verified by default. Red flag: `jwt.decode(token, key, algorithms=[...], options={"verify_exp": False})` or `options={"verify_nbf": False}`.
- **JavaScript (jsonwebtoken):** `exp` is verified by default in `jwt.verify()`. Red flag: `{ ignoreExpiration: true }` option. For `nbf`: check `{ ignoreNotBefore: true }`.
- **Java (jjwt):** Expiration is verified by default in `parseClaimsJws()`. For `nimbus-jose-jwt`: check that `JWTClaimsSet` verification includes time-based checks via `DefaultJWTClaimsVerifier`.
- **PHP (firebase/php-jwt):** `exp` and `nbf` are verified by default in `JWT::decode()`. Check for custom timestamp overrides via `JWT::$timestamp`.
- **Ruby (ruby-jwt):** `exp` verification requires `{ verify_expiration: true }` (not enabled by default in some versions). Red flag: `{ verify_expiration: false }`. For `nbf`: check `{ verify_not_before: true }`.
- **Go (golang-jwt):** v5+ verifies `exp` by default with `WithExpirationRequired()` on the parser. In v4, check for `parser.WithoutClaimsValidation()` which disables all claims validation.
- **C# (System.IdentityModel.Tokens.Jwt):** `TokenValidationParameters.ValidateLifetime` controls this. Red flag: `ValidateLifetime = false`.

Red flags (cross-language):
- Expiration checking explicitly disabled via library options.
- Custom token parsing that reads claims but does not check `exp` or `nbf`.
- Very long token lifetimes (e.g., `exp` set days or weeks in the future for access tokens) -- while not strictly a validation issue, it increases risk and should be noted.
- Clock skew tolerance set excessively high (e.g., more than 5 minutes), effectively weakening expiration enforcement.

Safe patterns:
- Library defaults used without disabling time validation.
- Explicit clock skew tolerance of 30-60 seconds configured.
- Short-lived access tokens (minutes, not hours) with refresh token rotation.

**9.2.2 — Token type validation (access token vs. ID token vs. refresh token):**

What to look for:
- The service must distinguish between different token types and only accept the correct type for each operation. For example, an API authorization endpoint should reject an ID token, and a user-info endpoint should reject a refresh token.
- For JWTs, token type can be indicated by: the `typ` header (e.g., `at+jwt` for access tokens per RFC 9068), a custom `token_type` claim, the presence or absence of specific claims (e.g., ID tokens have `nonce`, `auth_time`; access tokens have `scope`), or the issuing endpoint.

Language-specific patterns to check:
- Check if middleware or token validation logic inspects the token type before proceeding. Look for checks on JWT `typ` header, `token_type` claim, or structural validation of expected claims.
- **OAuth2/OIDC libraries:** `openid-client` (Node.js), `authlib` (Python), Spring Security OAuth2 (Java), `IdentityServer` (.NET) -- these typically handle token type differentiation. Check that they are configured correctly and that custom endpoints do not bypass these checks.
- **Custom implementations:** Look for explicit checks like `if token.header["typ"] != "at+jwt"` or `if "scope" not in claims` that enforce token type constraints.

Red flags:
- A single `verifyToken()` function used everywhere that does not distinguish between token types.
- API endpoints that accept any valid JWT without checking whether it is an access token, ID token, or some other type.
- ID tokens used for API authorization (they are meant for the client application, not for resource server authorization).
- Refresh tokens accepted at resource endpoints.

Safe patterns:
- Explicit `typ` header validation (`at+jwt` for access tokens per RFC 9068).
- Separate validation functions or middleware for different token types.
- Claim structure validation: access tokens expected to have `scope`/`permissions`, ID tokens expected to have `sub`/`nonce`/`auth_time`.

N/A conditions:
- Application uses only one type of self-contained token and there is no risk of cross-type confusion. Document this reasoning if marking N/A.

**9.2.3 — Audience (aud) validation:**

What to look for:
- The service must verify that the token's `aud` (audience) claim matches the service's own identifier. This prevents tokens issued for Service A from being replayed against Service B.
- The expected audience value should be configured in the service (not derived from the token itself).

Language-specific patterns to check:
- **Python (PyJWT):** `jwt.decode(token, key, algorithms=[...], audience="my-service")` -- the `audience` parameter must be provided. Red flag: omitting the `audience` parameter.
- **JavaScript (jsonwebtoken):** `jwt.verify(token, key, { audience: "my-service" })` -- the `audience` option must be set. Red flag: not specifying audience.
- **Java (jjwt):** `Jwts.parserBuilder().requireAudience("my-service")...` or manual claim check after parsing. For `nimbus-jose-jwt`: check `JWTClaimsSet.getAudience()` is validated.
- **PHP (firebase/php-jwt):** Audience is not checked by default -- manual validation of the `aud` claim is needed after decode.
- **Ruby (ruby-jwt):** `JWT.decode(token, key, true, { aud: "my-service", verify_aud: true })`.
- **Go (golang-jwt):** v5+: `jwt.WithAudience("my-service")` parser option. v4: manual check on `claims.VerifyAudience("my-service", true)`.
- **C# (System.IdentityModel.Tokens.Jwt):** `TokenValidationParameters.ValidAudience` or `ValidAudiences` must be set, and `ValidateAudience` must be `true` (it is `true` by default).

Red flags:
- No audience validation configured -- any valid token from the same issuer is accepted regardless of intended audience.
- `ValidateAudience = false` or equivalent in any language.
- Audience value derived from the token itself rather than from service configuration.

Safe patterns:
- Audience explicitly configured per-service from environment variables or configuration.
- Multiple valid audiences allowed only when the service legitimately serves multiple audiences (documented and intentional).

**9.2.4 — Audience restriction in issued tokens (issuer-side):**

What to look for:
- This requirement applies to the *token issuer* side. If the same signing key is used to issue tokens to multiple audiences, each token must contain an `aud` claim that uniquely identifies the intended audience.
- Without audience restriction, a token issued to Client A could be replayed to Client B if they share the same issuer and signing key.

Language-specific patterns to check:
- Look at token creation/signing code. Check that the `aud` claim is always set when creating tokens.
- If the application acts as an authorization server or token issuer: verify that every issued token includes an audience claim.
- If audience identifiers are dynamically provisioned (e.g., client registration), check that the issuer validates these identifiers to prevent audience impersonation (e.g., Client B registering with Client A's audience identifier).

Red flags:
- Token creation code that omits the `aud` claim entirely.
- Same signing key used across multiple services/audiences with no `aud` differentiation.
- Dynamic audience registration without validation or uniqueness enforcement.
- Audience values that are generic or shared (e.g., `aud: "api"` used by all services).

Safe patterns:
- Unique audience identifier per service/client.
- Audience claim always set during token creation.
- Client registration process that enforces unique audience identifiers.
- Different signing keys per audience (eliminates cross-audience replay even without `aud`).

N/A conditions:
- Application does not issue self-contained tokens (it only consumes them). In this case, 9.2.4 is N/A as it applies to the issuer side.
- Application uses a single audience and a single signing key pair -- no cross-audience confusion is possible.

---

## References

For more information, see also:

* [OWASP JSON Web Token Cheat Sheet for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) (but has useful general guidance)

---

## V9 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 4 | 9.1.1, 9.1.2, 9.1.3, 9.2.1 |
| L2 | 3 | 9.2.2, 9.2.3, 9.2.4 |
| L3 | 0 | |
| **Total** | **7** | |
