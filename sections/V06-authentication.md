# V6: Authentication

**ASVS Version:** 5.0.0
**Source file:** `5.0/en/0x15-V6-Authentication.md`

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

Authentication is the process of establishing or confirming the authenticity of an individual or device. It involves verifying claims made by a person or about a device, ensuring resistance to impersonation, and preventing the recovery or interception of passwords.

[NIST SP 800-63](https://pages.nist.gov/800-63-3/) is a modern, evidence-based standard that is valuable for organizations worldwide, but is particularly relevant to US agencies and those interacting with US agencies.

While many of the requirements in this chapter are based on the second section of the standard (known as NIST SP 800-63B "Digital Identity Guidelines - Authentication and Lifecycle Management"), the chapter focuses on common threats and frequently exploited authentication weaknesses. It does not attempt to comprehensively cover every point in the standard. For cases where full NIST SP 800-63 compliance is necessary, please refer to NIST SP 800-63.

Additionally, NIST SP 800-63 terminology may sometimes differ, and this chapter often uses more commonly understood terminology to improve clarity.

A common feature of more advanced applications is the ability to adapt authentication stages required based on various risk factors. This feature is covered in the "Authorization" chapter, since these mechanisms also need to be considered for authorization decisions.

---

## V6.1: Authentication Documentation

This section contains requirements detailing the authentication documentation that should be maintained for an application. This is crucial for implementing and assessing how the relevant authentication controls should be configured.

| # | Requirement | Level |
|---|-------------|-------|
| **6.1.1** | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | 1 |
| **6.1.2** | Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar. | 2 |
| **6.1.3** | Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them. | 2 |

### Audit Guidance for V6.1

**6.1.1 — Authentication defense documentation:**

What to look for:
- Documentation (security design docs, README, wiki, architecture decision records) that describes how the application defends against credential stuffing and password brute force attacks.
- Specific configuration details: What rate limiting thresholds are used? How many failed attempts before lockout/delay? What anti-automation mechanisms are in place (CAPTCHA, progressive delays, IP-based throttling)?
- Confirmation that the documented controls prevent malicious account lockout (e.g., attacker cannot lock out a legitimate user by deliberately failing authentication). Look for approaches like temporary lockout with exponential backoff rather than permanent lockout, or CAPTCHA challenges instead of lockout.

Where to look in code:
- **Python (Django):** `django-axes`, `django-ratelimit`, `django-defender` configurations. Check `settings.py` for `AXES_*` settings.
- **Python (Flask):** `flask-limiter` configuration, custom rate-limiting middleware.
- **Node.js (Express):** `express-rate-limit`, `rate-limiter-flexible`, `express-brute` middleware configuration.
- **Java (Spring):** Spring Security `AuthenticationFailureHandler`, custom filters, Bucket4j or Resilience4j rate limiting.
- **PHP (Laravel):** `ThrottleRequests` middleware, `RateLimiter` facade configuration in `RouteServiceProvider`.
- **Ruby (Rails):** `rack-attack` gem configuration in `config/initializers/rack_attack.rb`.
- **Go:** Custom middleware, `golang.org/x/time/rate`, `ulule/limiter`.
- **C# (ASP.NET):** `AspNetCoreRateLimit` package, custom `IActionFilter` implementations, ASP.NET Core Identity lockout settings.

N/A conditions: This is a documentation requirement. If the application has no user authentication (e.g., purely public API with API key auth only), this may be N/A.

**6.1.2 — Context-specific password blocklist documentation:**

What to look for:
- A documented list of context-specific words that should be blocked from use in passwords.
- The list should include: organization name, product names, system identifiers, project codenames, department or role names, and permutations of these.
- This is a documentation requirement (L2). The enforcement of this list is covered in 6.2.11.

**6.1.3 — Multiple authentication pathway documentation:**

What to look for:
- If the application supports multiple ways to authenticate (e.g., username/password, SSO, OAuth, API keys, magic links), all pathways must be documented together.
- Check that security controls and authentication strength are documented as consistent across all pathways.
- Look for undocumented or "shadow" authentication pathways (e.g., a legacy login endpoint, a debug/test login, a backdoor admin endpoint).

N/A conditions: If the application has only a single authentication pathway, this requirement may be N/A.

---

## V6.2: Password Security

Passwords, called "Memorized Secrets" by NIST SP 800-63, include passwords, passphrases, PINs, unlock patterns, and picking the correct kitten or another image element. They are generally considered "something you know" and are often used as a single-factor authentication mechanism.

As such, this section contains requirements for making sure that passwords are created and handled securely. Most of the requirements are L1 as they are most important at that level. From L2 onwards, multi-factor authentication mechanisms are required, where passwords may be one of those factors.

The requirements in this section mostly relate to [&sect; 5.1.1.2](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver) of [NIST's Guidance](https://pages.nist.gov/800-63-3/sp800-63b.html).

| # | Requirement | Level |
|---|-------------|-------|
| **6.2.1** | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | 1 |
| **6.2.2** | Verify that users can change their password. | 1 |
| **6.2.3** | Verify that password change functionality requires the user's current and new password. | 1 |
| **6.2.4** | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | 1 |
| **6.2.5** | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | 1 |
| **6.2.6** | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | 1 |
| **6.2.7** | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | 1 |
| **6.2.8** | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | 1 |
| **6.2.9** | Verify that passwords of at least 64 characters are permitted. | 2 |
| **6.2.10** | Verify that a user's password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation. | 2 |
| **6.2.11** | Verify that the documented list of context specific words is used to prevent easy to guess passwords being created. | 2 |
| **6.2.12** | Verify that passwords submitted during account registration or password changes are checked against a set of breached passwords. | 2 |

### Audit Guidance for V6.2

**6.2.1 through 6.2.5, 6.2.9 — Password policy requirements (consolidated):**

These requirements collectively define the password composition and length policy. They should be audited together by examining the password validation logic.

What to look for:
- A minimum password length of 8 characters enforced at registration and password change (6.2.1). Check both client-side and server-side validation. Server-side enforcement is mandatory.
- A maximum password length of at least 64 characters (6.2.9, L2). Look for maximum length restrictions that are too short. Common red flags include database column limits (e.g., `VARCHAR(20)`) that silently truncate passwords.
- No composition rules that restrict character types (6.2.5). Red flags include regex patterns like `/(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%])/` that mandate specific character classes. The NIST guidance explicitly recommends against composition rules.
- No blocklist of character types (6.2.5). The application must allow all Unicode characters, spaces, and special characters in passwords.
- Passwords checked against top 3000 common passwords (6.2.4). Look for a password blocklist file or API integration.

Language-specific patterns:

- **Python (Django):** Check `AUTH_PASSWORD_VALIDATORS` in `settings.py`. Django ships with `MinimumLengthValidator`, `CommonPasswordValidator` (checks against ~20,000 common passwords), `UserAttributeSimilarityValidator`. Look for custom validators that impose composition rules (red flag). Check `CommonPasswordValidator` is enabled for 6.2.4.
- **Python (Flask):** Check for custom password validation in registration/change routes. Look for libraries like `password-strength`, `zxcvbn-python`.
- **Node.js:** Check for `zxcvbn` library, custom validation middleware, `joi` or `yup` validation schemas with password rules. Check for `validator.isStrongPassword()` which by default requires composition rules (red flag unless configured to only check length).
- **Java (Spring Security):** Check `PasswordEncoder` usage, custom `ConstraintValidator` implementations for password policy. Look for libraries like `passay` for password policy enforcement.
- **PHP (Laravel):** Check `Password::min(8)` rule and related password validation rules in form requests or controllers. Laravel's `Password::uncompromised()` integrates with Have I Been Pwned (for 6.2.12).
- **Ruby (Rails):** Check `validates :password, length: { minimum: 8 }` in User model. Look for gems like `devise` and its password length configuration, `zxcvbn-ruby`.
- **Go:** Check for password validation in handler functions, custom middleware, or libraries like `go-password-validator`.
- **C# (ASP.NET Identity):** Check `PasswordOptions` in `Startup.cs` or `Program.cs`: `RequiredLength`, `RequireDigit`, `RequireLowercase`, `RequireUppercase`, `RequireNonAlphanumeric`. If composition requirements are set to `true`, this is a red flag for 6.2.5.

**6.2.2 and 6.2.3 — Password change functionality:**

What to look for:
- A password change endpoint or page exists and is accessible to authenticated users (6.2.2).
- The password change form requires both the current (old) password and the new password (6.2.3). Red flag: password change that only requires the new password without verifying the current password (allows account takeover if session is hijacked).
- Check that the password change endpoint enforces the same password policy as registration.

**6.2.6 — Password field masking:**

What to look for:
- HTML password input fields use `type="password"` attribute.
- If a "show password" toggle is present, verify it changes the input type to `type="text"` temporarily and reverts on toggle-off.
- Red flag: Password fields using `type="text"` by default.

Where to look: HTML templates, JSX/TSX components, frontend form code.

**6.2.7 — Paste and password manager support:**

What to look for:
- JavaScript that prevents paste into password fields: event listeners for `onpaste` that call `event.preventDefault()`, or `onpaste="return false"` attributes.
- `autocomplete="off"` on password fields (this interferes with password managers). The correct value for new passwords is `autocomplete="new-password"` and for login fields is `autocomplete="current-password"`.
- CSS or JavaScript tricks that block autofill (e.g., dynamically replacing input fields, using non-standard field names to confuse password managers).

Red flags: Any code that explicitly blocks paste or autocomplete on password fields.

**6.2.8 — Password verified without modification:**

What to look for:
- Password truncation before hashing or comparison. Look for `password[:N]`, `password.substring(0, N)`, or database column length limits that silently truncate.
- Case transformation: `password.lower()`, `password.toUpperCase()`, `strtolower($password)` before hashing.
- Whitespace stripping: `password.strip()`, `password.trim()` before hashing. Note: Some frameworks do this by default.
- Unicode normalization that changes the password. While NIST recommends Unicode NFKC normalization, the application must be consistent between setting and verifying the password.

Language-specific patterns:
- **Python:** `password.strip()`, `password.lower()`, `password[:N]` before passing to `bcrypt.hashpw()` or similar.
- **Node.js:** `password.trim()`, `password.toLowerCase()`, `password.slice(0, N)` before hashing.
- **PHP:** `trim($password)`, `strtolower($password)`, `substr($password, 0, N)` before `password_hash()`.
- **Java:** `password.trim()`, `password.toLowerCase()`, `password.substring(0, N)` before hashing.

**6.2.10 — No periodic credential rotation:**

What to look for:
- Database fields like `password_expires_at`, `password_last_changed`, `credential_expiry`, `must_change_password_after_days`.
- Scheduled jobs or middleware that forces password change after a time period.
- Configuration settings like `PASSWORD_EXPIRY_DAYS`, `MAX_PASSWORD_AGE`.
- Red flag: Any logic that compares the current date against a password age and forces a reset.

Safe pattern: Password only flagged for change when discovered in a breach (6.2.12) or explicitly rotated by the user.

**6.2.11 — Context-specific word blocklist enforcement:**

What to look for:
- The application enforces the documented context-specific word blocklist from 6.1.2 during password creation and change.
- Check that password validation includes a check against organization-specific terms.
- This is L2. The blocklist should be maintained separately from the common password list (6.2.4).

**6.2.12 — Breached password checking:**

What to look for:
- Integration with a breached password database during registration and password change.
- Common approaches: Have I Been Pwned (HIBP) Passwords API using k-anonymity (send first 5 characters of SHA-1 hash, check response), local database of breached password hashes, third-party breach-checking services.

Language-specific patterns:
- **Python:** `pwnedpasswords` library, `django-pwned-passwords`, custom HIBP API integration.
- **Node.js:** `hibp` library, `haveibeenpwned` package, custom fetch to `api.pwnedpasswords.com`.
- **PHP (Laravel):** `Password::uncompromised()` validation rule (built-in HIBP integration).
- **Ruby:** `pwned` gem, `devise-pwned_password` gem.
- **Java:** Custom HIBP API client, Spring Security integration.
- **Go:** Custom HIBP API client.
- **C#:** `Pwnedpasswords` NuGet package, custom HIBP API integration.

Red flags: No breach checking at all. Also check that the check is done server-side, not only client-side.

---

## V6.3: General Authentication Security

This section contains general requirements for the security of authentication mechanisms as well as setting out the different expectations for levels. L2 applications must force the use of multi-factor authentication (MFA). L3 applications must use hardware-based authentication, performed in an attested and trusted execution environment (TEE). This could include device-bound passkeys, eIDAS Level of Assurance (LoA) High enforced authenticators, authenticators with NIST Authenticator Assurance Level 3 (AAL3) assurance, or an equivalent mechanism.

While this is a relatively aggressive stance on MFA, it is critical to raise the bar around this to protect users, and any attempt to relax these requirements should be accompanied by a clear plan on how the risks around authentication will be mitigated, taking into account NIST's guidance and research on the topic.

Note that at the time of release, NIST SP 800-63 considers email as [not acceptable](https://pages.nist.gov/800-63-FAQ/#q-b11) as an authentication mechanism ([archived copy](https://web.archive.org/web/20250330115328/https://pages.nist.gov/800-63-FAQ/#q-b11)).

The requirements in this section relate to a variety of sections of [NIST's Guidance](https://pages.nist.gov/800-63-3/sp800-63b.html), including: [&sect; 4.2.1](https://pages.nist.gov/800-63-3/sp800-63b.html#421-permitted-authenticator-types), [&sect; 4.3.1](https://pages.nist.gov/800-63-3/sp800-63b.html#431-permitted-authenticator-types), [&sect; 5.2.2](https://pages.nist.gov/800-63-3/sp800-63b.html#522-rate-limiting-throttling), and [&sect; 6.1.2](https://pages.nist.gov/800-63-3/sp800-63b.html#-612-post-enrollment-binding).

| # | Requirement | Level |
|---|-------------|-------|
| **6.3.1** | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | 1 |
| **6.3.2** | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | 1 |
| **6.3.3** | Verify that either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms, must be used in order to access the application. For L3, one of the factors must be a hardware-based authentication mechanism which provides compromise and impersonation resistance against phishing attacks while verifying the intent to authenticate by requiring a user-initiated action (such as a button press on a FIDO hardware key or a mobile phone). Relaxing any of the considerations in this requirement requires a fully documented rationale and a comprehensive set of mitigating controls. | 2 |
| **6.3.4** | Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently. | 2 |
| **6.3.5** | Verify that users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts. | 3 |
| **6.3.6** | Verify that email is not used as either a single-factor or multi-factor authentication mechanism. | 3 |
| **6.3.7** | Verify that users are notified after updates to authentication details, such as credential resets or modification of the username or email address. | 3 |
| **6.3.8** | Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection. | 3 |

### Audit Guidance for V6.3

**6.3.1 — Rate limiting and brute force protection implementation:**

What to look for:
- Verify that the controls documented in 6.1.1 are actually implemented in code.
- Check for rate limiting on the login endpoint. Look for middleware or decorators that limit login attempts per IP, per username, or both.
- Check for account lockout policies and whether they align with the documentation.
- Look for CAPTCHA or proof-of-work challenges after repeated failed attempts.
- Check for progressive delays (e.g., increasing wait time after each failed attempt).

Language-specific patterns:
- **Python (Django):** `django-axes` middleware, `django-ratelimit` decorator (`@ratelimit`), custom `AuthenticationBackend` with lockout logic.
- **Python (Flask):** `flask-limiter` decorators on login routes, custom failed-attempt tracking.
- **Node.js (Express):** `express-rate-limit` middleware on `/login` or `/auth` routes, `rate-limiter-flexible` with Redis/memory store.
- **Java (Spring):** `@RateLimiter` annotations, custom `AuthenticationFailureHandler` that tracks and limits attempts, Spring Security `LockoutPolicy`.
- **PHP (Laravel):** `ThrottleRequests` middleware on login route, `RateLimiter::for('login', ...)` in `RouteServiceProvider`, Fortify's built-in throttling.
- **Ruby (Rails):** `rack-attack` throttle rules in initializer, Devise `Lockable` module configuration.
- **Go:** Custom middleware with `golang.org/x/time/rate`, Redis-backed rate limiting.
- **C# (ASP.NET):** ASP.NET Core Identity `LockoutOptions` (MaxFailedAccessAttempts, DefaultLockoutTimeSpan), `AspNetCoreRateLimit` middleware.

Red flags:
- No rate limiting on authentication endpoints at all.
- Rate limiting only on IP (easily bypassed with distributed attacks) without per-account limiting.
- Permanent account lockout (enables denial-of-service against legitimate users).
- Rate limiting only on the client side (bypassable).

**6.3.2 — Default account removal:**

What to look for:
- Database seed files, migration scripts, or initialization code that creates default accounts with known credentials.
- Hardcoded credentials in source code: search for strings like `"admin"`, `"root"`, `"sa"`, `"administrator"`, `"test"`, `"user"`, `"default"`, `"guest"` in authentication-related code and configuration.
- Check deployment scripts, Docker entrypoint scripts, and infrastructure-as-code for default account creation.
- Check if default accounts, even if created during setup, are disabled or require immediate password change.

Patterns to search for:
- `User.create(username: "admin", password: ...)` in seeds or migrations.
- `INSERT INTO users` with hardcoded usernames in SQL migration files.
- Environment variables or config files with default admin credentials.

**6.3.3 — Multi-factor authentication (MFA):**

What to look for:
- For L2: The application must require MFA or a combination of single-factor mechanisms. Check that MFA is mandatory, not optional.
- For L3: One factor must be hardware-based with phishing resistance (FIDO2/WebAuthn, hardware security keys). Check for WebAuthn integration.
- If MFA requirements are relaxed, look for documented rationale and mitigating controls.

Where to look:
- **Python (Django):** `django-otp`, `django-two-factor-auth`, `django-mfa2` packages. Check if MFA is enforced globally or only for specific users/roles.
- **Node.js:** `speakeasy`, `otplib`, `@simplewebauthn/server` packages. Check middleware that enforces MFA completion before granting access.
- **Java (Spring):** Spring Security MFA configuration, custom `AuthenticationProvider` chains. Check for TOTP or WebAuthn integration.
- **PHP (Laravel):** `laravel-google2fa`, `pragmarx/google2fa-laravel`, Fortify two-factor features.
- **Ruby (Rails):** `devise-two-factor`, `rotp` gem, `webauthn-ruby` gem.
- **C# (ASP.NET):** ASP.NET Core Identity `TwoFactorEnabled`, `AddDefaultTokenProviders()`, FIDO2 libraries like `Fido2NetLib`.

Red flags:
- MFA is available but not enforced (users can skip enrollment).
- MFA can be bypassed via alternative authentication pathways (e.g., API key auth that does not require MFA).
- "Remember this device" feature that effectively disables MFA for extended periods without re-verification.

**6.3.4 — Consistent authentication across pathways:**

What to look for:
- Enumerate all authentication endpoints: login page, API authentication, OAuth/OIDC callbacks, SAML endpoints, magic link endpoints, API key endpoints, admin backdoors.
- Verify that all pathways enforce the same security controls (rate limiting, MFA, password policy).
- Look for endpoints that bypass the main authentication flow: debug endpoints, test endpoints, legacy endpoints, internal-only endpoints that are exposed.

**6.3.5 — Suspicious authentication notification (L3):**

What to look for:
- Logic that detects and notifies on: new device/browser, new geographic location, authentication after long inactivity, successful login after multiple failures, login from unusual IP ranges.
- Notification mechanisms: email, SMS, push notification, in-app notification.
- Check for device fingerprinting, IP geolocation, or user-agent tracking in the authentication flow.

**6.3.6 — Email not used as authentication factor (L3):**

What to look for:
- "Magic link" login (email-only authentication). This is explicitly prohibited at L3.
- Email-based OTP as an MFA factor. At L3, email must not be used as any authentication factor.
- Check authentication configuration for email-based verification as a login mechanism (distinct from email-based password reset, which is a recovery mechanism covered in V6.4).

**6.3.7 — Notification on authentication detail changes (L3):**

What to look for:
- Email/SMS notifications sent when: password is changed, email address is changed, username is changed, MFA settings are modified, new authentication factor is enrolled.
- Check that notifications go to both the old and new contact information when contact details change (e.g., email change notification sent to both old and new email).

**6.3.8 — User enumeration prevention (L3):**

What to look for:
- Different error messages for "user not found" vs "wrong password" on login. Both should return a generic message like "Invalid credentials."
- Different HTTP response codes for valid vs invalid usernames.
- Timing differences: if the application hashes the password only when the user exists, it creates a measurable timing difference. The application should always perform the hash operation (e.g., hash against a dummy value) even if the user does not exist.
- Registration endpoint revealing whether an email/username is already taken. Should use generic messages like "If this email is registered, you will receive a confirmation."
- Forgot password endpoint revealing whether an email exists. Same generic messaging approach.

Language-specific patterns:
- **Python (Django):** Django's built-in auth views already mitigate timing attacks by always running the password hasher. Check custom views.
- **Node.js:** Check for early returns when user not found (`if (!user) return error` without hashing). Use `bcrypt.compare()` against a dummy hash even when user is not found.
- **Java:** Similar pattern — ensure `passwordEncoder.matches()` is called even when user lookup fails.
- **PHP:** `password_verify()` should be called against a dummy hash when user is not found.

Red flags:
- `if user: check_password(...)  else: return "User not found"` — different error messages.
- Registration endpoint: `if User.exists(email): return "Email already registered"`.
- Forgot password endpoint that says "Email not found" for non-existent users.

---

## V6.4: Authentication Factor Lifecycle and Recovery

Authentication factors may include passwords, soft tokens, hardware tokens, and biometric devices. Securely handling the lifecycle of these mechanisms is critical to the security of an application, and this section includes requirements related to this.

The requirements in this section mostly relate to [&sect; 5.1.1.2](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver) or [&sect; 6.1.2.3](https://pages.nist.gov/800-63-3/sp800-63b.html#replacement) of [NIST's Guidance](https://pages.nist.gov/800-63-3/sp800-63b.html).

| # | Requirement | Level |
|---|-------------|-------|
| **6.4.1** | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | 1 |
| **6.4.2** | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | 1 |
| **6.4.3** | Verify that a secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms. | 2 |
| **6.4.4** | Verify that if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment. | 2 |
| **6.4.5** | Verify that renewal instructions for authentication mechanisms which expire are sent with enough time to be carried out before the old authentication mechanism expires, configuring automated reminders if necessary. | 3 |
| **6.4.6** | Verify that administrative users can initiate the password reset process for the user, but that this does not allow them to change or choose the user's password. This prevents a situation where they know the user's password. | 3 |

### Audit Guidance for V6.4

**6.4.1 — System-generated initial passwords and activation codes:**

What to look for:
- How initial passwords or activation codes are generated. They must use a cryptographically secure random number generator (CSPRNG).
- Check that initial passwords/codes expire after a short time (e.g., 24-72 hours) or after first use.
- Check that users are forced to set a new password after using the initial password. Red flag: initial password can remain as the permanent password.
- Check that initial passwords follow the same password policy (minimum length, etc.).

Language-specific patterns:
- **Python:** `secrets.token_urlsafe()`, `secrets.token_hex()`, `os.urandom()` — safe. `random.choice()`, `random.randint()` — unsafe (not cryptographically secure).
- **Node.js:** `crypto.randomBytes()`, `crypto.randomUUID()` — safe. `Math.random()` — unsafe.
- **Java:** `SecureRandom` — safe. `java.util.Random` — unsafe.
- **PHP:** `random_bytes()`, `random_int()` — safe. `rand()`, `mt_rand()` — unsafe.
- **Ruby:** `SecureRandom.hex()`, `SecureRandom.urlsafe_base64()` — safe. `rand()` — unsafe.
- **Go:** `crypto/rand` — safe. `math/rand` — unsafe.
- **C#:** `RandomNumberGenerator.GetBytes()`, `RandomNumberGenerator.GetInt32()` — safe. `System.Random` — unsafe.

Red flags:
- Sequential or predictable activation codes (e.g., auto-incrementing IDs, timestamp-based codes).
- No expiration on initial passwords or activation codes.
- No forced password change after first use of initial credentials.

**6.4.2 — No password hints or secret questions:**

What to look for:
- Database columns like `security_question`, `security_answer`, `password_hint`, `secret_question`.
- User registration or profile forms with "security question" or "password hint" fields.
- Password recovery flows that ask knowledge-based questions ("What is your mother's maiden name?", "What was your first pet?").
- This is an L1 requirement. Any presence of password hints or secret questions is a finding.

**6.4.3 — Secure password reset process (L2):**

What to look for:
- Password reset flow that bypasses MFA. Red flag: if a user has MFA enabled but the password reset flow allows them to set a new password and log in without completing MFA.
- Password reset tokens: check they are long, random, single-use, and time-limited.
- Check that the reset token is invalidated after use and after expiration.
- Check that the reset flow does not reveal whether a user account exists (related to 6.3.8).

Language-specific patterns:
- **Python (Django):** `PasswordResetView` uses `PasswordResetTokenGenerator` which generates HMAC-based tokens. Check custom reset views for proper token handling.
- **Node.js:** Check for custom token generation. Look for `crypto.randomBytes()` for token generation, token storage with expiration.
- **PHP (Laravel):** Built-in `Password::sendResetLink()` and `Password::reset()`. Check `passwords` config in `config/auth.php` for token expiration.
- **Ruby (Rails/Devise):** `Devise::Recoverable` module. Check `reset_password_within` configuration.

Red flags:
- Password reset link that does not expire.
- Password reset token that is predictable (e.g., base64-encoded user ID or email).
- Password reset that allows setting the password without re-verifying MFA.
- Multiple valid reset tokens for the same user (previous tokens not invalidated).

**6.4.4 — MFA factor recovery requires equivalent identity proofing (L2):**

What to look for:
- What happens when a user reports a lost MFA device? The recovery process should verify identity at the same level as the original enrollment.
- Check for backup/recovery codes that were issued during MFA enrollment. These are acceptable as a recovery mechanism.
- Red flag: MFA recovery that only requires email confirmation or a phone call (lower assurance than the original MFA enrollment).
- Look for admin-initiated MFA resets that do not require identity proofing.

**6.4.5 — Expiry renewal reminders (L3):**

What to look for:
- Applicable when authentication mechanisms have expiration dates (e.g., client certificates, hardware token batteries, time-limited credentials).
- Check for automated reminder systems that notify users before expiration.
- Look for scheduled jobs/cron tasks that scan for upcoming expirations and send notifications.

N/A conditions: If no authentication mechanisms in use have expiration dates, this may be N/A.

**6.4.6 — Admin-initiated password reset without password knowledge (L3):**

What to look for:
- Admin panel or admin API for user management. Check whether admins can directly set a user's password (red flag) or can only trigger a password reset flow where the user sets their own password (safe).
- Red flag: Admin form with a "New Password" field for the user. The admin should only be able to click "Send Reset Link" or "Initiate Reset."
- Check that the admin-initiated reset follows the same secure reset flow as the self-service reset (token-based, time-limited).

---

## V6.5: General Multi-factor Authentication Requirements

This section provides general guidance that will be relevant to various different multi-factor authentication methods.

The mechanisms include:

* Lookup Secrets
* Time based One-time Passwords (TOTPs)
* Out-of-Band mechanisms

Lookup secrets are pre-generated lists of secret codes, similar to Transaction Authorization Numbers (TAN), social media recovery codes, or a grid containing a set of random values. This type of authentication mechanism is considered "something you have" because the codes are deliberately not memorable so will need to be stored somewhere.

Time based One-time Passwords (TOTPs) are physical or soft tokens that display a continually changing pseudo-random one-time challenge. This type of authentication mechanism is considered "something you have". Multi-factor TOTPs are similar to single-factor TOTPs, but require a valid PIN code, biometric unlocking, USB insertion or NFC pairing, or some additional value (such as transaction signing calculators) to be entered to create the final One-time Password (OTP).

Details on out-of-band mechanisms will be provided in the next section.

The requirements in these sections mostly relate to [&sect; 5.1.2](https://pages.nist.gov/800-63-3/sp800-63b.html#-512-look-up-secrets), [&sect; 5.1.3](https://pages.nist.gov/800-63-3/sp800-63b.html#-513-out-of-band-devices), [&sect; 5.1.4.2](https://pages.nist.gov/800-63-3/sp800-63b.html#5142-single-factor-otp-verifiers), [&sect; 5.1.5.2](https://pages.nist.gov/800-63-3/sp800-63b.html#5152-multi-factor-otp-verifiers), [&sect; 5.2.1](https://pages.nist.gov/800-63-3/sp800-63b.html#521-physical-authenticators), and [&sect; 5.2.3](https://pages.nist.gov/800-63-3/sp800-63b.html#523-use-of-biometrics) of [NIST's Guidance](https://pages.nist.gov/800-63-3/sp800-63b.html).

| # | Requirement | Level |
|---|-------------|-------|
| **6.5.1** | Verify that lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once. | 2 |
| **6.5.2** | Verify that, when being stored in the application's backend, lookup secrets with less than 112 bits of entropy (19 random alphanumeric characters or 34 random digits) are hashed with an approved password storage hashing algorithm that incorporates a 32-bit random salt. A standard hash function can be used if the secret has 112 bits of entropy or more. | 2 |
| **6.5.3** | Verify that lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to avoid predictable values. | 2 |
| **6.5.4** | Verify that lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4 random alphanumeric characters or 6 random digits is sufficient). | 2 |
| **6.5.5** | Verify that out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs) have a defined lifetime. Out of band requests must have a maximum lifetime of 10 minutes and for TOTP a maximum lifetime of 30 seconds. | 2 |
| **6.5.6** | Verify that any authentication factor (including physical devices) can be revoked in case of theft or other loss. | 3 |
| **6.5.7** | Verify that biometric authentication mechanisms are only used as secondary factors together with either something you have or something you know. | 3 |
| **6.5.8** | Verify that time-based one-time passwords (TOTPs) are checked based on a time source from a trusted service and not from an untrusted or client provided time. | 3 |

### Audit Guidance for V6.5

**6.5.1 — One-time use of authentication codes:**

What to look for:
- After a lookup secret (recovery code), OOB code, or TOTP is used successfully, it must be invalidated so it cannot be reused.
- For lookup secrets / recovery codes: check that used codes are marked as consumed in the database (e.g., a `used` boolean flag or deletion after use).
- For OOB codes: check that the code is invalidated after successful verification or expiration.
- For TOTP: check that the application tracks the last successfully used TOTP counter/time-step and rejects any code with the same or earlier time-step. This prevents replay within the same 30-second window.

Language-specific patterns:
- **Python:** `pyotp` library — check for replay prevention. By default, `pyotp.TOTP.verify()` does not prevent replay within the same time step; the application must track `valid_window` and last used timestamp.
- **Node.js:** `otplib` or `speakeasy` — check for `window` parameter and replay tracking.
- **Java:** Check TOTP libraries for replay prevention. Libraries like `GoogleAuth` or `java-otp` may need custom replay tracking.

Red flags:
- No tracking of used codes. If the database schema for recovery codes has no `used_at` or `is_used` column, codes may be reusable.
- TOTP verification that does not track last used time step.

**6.5.2 — Storage of lookup secrets:**

What to look for:
- How recovery codes / lookup secrets are stored in the database.
- If codes have less than 112 bits of entropy (which is typical — most recovery codes are 8-10 alphanumeric characters), they must be hashed with an approved password hashing algorithm (bcrypt, argon2, scrypt, PBKDF2) with a 32-bit random salt.
- If codes have 112 bits or more of entropy (19+ random alphanumeric characters), a standard hash function (SHA-256, SHA-512) is acceptable.

Red flags:
- Recovery codes stored in plaintext in the database.
- Recovery codes stored with a fast hash (MD5, SHA-1 without salt) when they have low entropy.
- Recovery codes stored encrypted (reversible) rather than hashed (irreversible).

Safe patterns:
- Recovery codes hashed with bcrypt/argon2 individually with unique salts.
- Recovery codes displayed to the user once at generation time, then only the hash is stored.

**6.5.3 — CSPRNG for authentication code generation:**

What to look for:
- The same CSPRNG requirements as 6.4.1 apply here. Lookup secrets, OOB codes, and TOTP seeds must be generated using cryptographically secure randomness.
- For TOTP seeds: check that the seed/secret key is generated using CSPRNG, not a predictable source.

Language-specific patterns: Same as 6.4.1 (see `secrets`, `crypto.randomBytes`, `SecureRandom`, etc.).

Red flags:
- TOTP seed generated from `Math.random()`, `random.randint()`, or any non-cryptographic PRNG.
- OOB codes generated sequentially or based on timestamps.

**6.5.4 — Minimum entropy for codes:**

What to look for:
- Lookup secrets (recovery codes): at least 20 bits of entropy. 4 random alphanumeric characters (26+26+10 = 62 options, 4 chars = ~23.8 bits) or 6 random digits (10^6 = ~19.9 bits) meet this threshold.
- OOB codes (e.g., SMS OTP): typically 6 digits, which provides ~19.9 bits. This is the minimum acceptable.
- Check the code generation logic to verify the character space and length.

Red flags:
- 4-digit numeric OTP (10^4 = ~13.3 bits) — insufficient entropy.
- Codes with limited character sets that reduce entropy below 20 bits.

**6.5.5 — Code lifetime limits:**

What to look for:
- OOB codes/tokens (SMS, push notification, email): maximum 10-minute lifetime. Check the expiration logic in code and database.
- TOTP: maximum 30-second validity window. Check the `period` parameter in TOTP configuration (default is usually 30 seconds). Also check the `valid_window` or `drift` parameter — a window of 1 (allowing the previous and next period) is common and acceptable, but larger windows extend the effective lifetime.
- Check for codes that never expire (no `expires_at` field or expiration check).

Language-specific patterns:
- **Python (`pyotp`):** `pyotp.TOTP(secret, interval=30)` — check `interval` parameter. Check `valid_window` in `verify()`.
- **Node.js (`otplib`):** `authenticator.options = { step: 30, window: 1 }` — check `step` and `window`.
- **Node.js (`speakeasy`):** `speakeasy.totp.verify({ ..., window: 1, step: 30 })`.
- **Java:** Check TOTP library configuration for time step and window size.

Red flags:
- OOB codes with no expiration or expiration longer than 10 minutes.
- TOTP with `valid_window` greater than 2 or 3 (excessively long acceptance window).
- No expiration timestamp stored with OOB codes.

**6.5.6 — Authentication factor revocation (L3):**

What to look for:
- User interface or API endpoint that allows users to revoke/remove authentication factors (TOTP apps, hardware keys, registered devices).
- Admin interface that allows revoking user authentication factors.
- Check that revocation takes immediate effect (the revoked factor cannot be used in the next authentication attempt).

N/A conditions: If the application does not support any revocable authentication factors beyond passwords (which are covered by password change), this may have limited applicability.

**6.5.7 — Biometrics as secondary factor only (L3):**

What to look for:
- If biometric authentication is supported (fingerprint, face recognition, voice recognition), check that it is only used in combination with another factor ("something you have" like a device, or "something you know" like a PIN).
- Biometrics alone must not be sufficient for authentication.
- Common safe patterns: device-bound biometric (e.g., fingerprint unlock on a phone that holds a private key) — the biometric unlocks the device (something you have), making it multi-factor.
- Red flag: Biometric-only authentication without any other factor.

**6.5.8 — Trusted time source for TOTP (L3):**

What to look for:
- The server validating TOTP codes must use its own trusted time source (system clock synchronized via NTP), not a time value provided by the client.
- Check that the TOTP verification function uses server-side time, not a client-supplied timestamp.
- Check that the server's time is synchronized with a reliable NTP source.

Red flags:
- TOTP verification that accepts a client-provided timestamp parameter.
- Server with no NTP synchronization (time drift can cause TOTP validation failures and may tempt developers to use client time).

---

## V6.6: Out-of-Band Authentication Mechanisms

This usually involves the authentication server communicating with a physical device over a secure secondary channel. For example, sending push notifications to mobile devices. This type of authentication mechanism is considered "something you have".

Unsafe out-of-band authentication mechanisms such as e-mail and VOIP are not permitted. PSTN and SMS authentication are currently considered to be ["restricted" authentication mechanisms](https://pages.nist.gov/800-63-FAQ/#q-b01) by NIST and should be deprecated in favor of Time based One-time Passwords (TOTPs), a cryptographic mechanism, or similar. NIST SP 800-63B [&sect; 5.1.3.3](https://pages.nist.gov/800-63-3/sp800-63b.html#-5133-authentication-using-the-public-switched-telephone-network) recommends addressing the risks of device swap, SIM change, number porting, or other abnormal behavior, if telephone or SMS out-of-band authentication absolutely has to be supported. While this ASVS section does not mandate this as a requirement, not taking these precautions for a sensitive L2 app or an L3 app should be seen as a significant red flag.

Note that NIST has also recently provided guidance which [discourages the use of push notifications](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/#fig-3). While this ASVS section does not do so, it is important to be aware of the risks of "push bombing".

| # | Requirement | Level |
|---|-------------|-------|
| **6.6.1** | Verify that authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords (OTPs) via phone or SMS are offered only when the phone number has previously been validated, alternate stronger methods (such as Time based One-time Passwords) are also offered, and the service provides information on their security risks to users. For L3 applications, phone and SMS must not be available as options. | 2 |
| **6.6.2** | Verify that out-of-band authentication requests, codes, or tokens are bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one. | 2 |
| **6.6.3** | Verify that a code based out-of-band authentication mechanism is protected against brute force attacks by using rate limiting. Consider also using a code with at least 64 bits of entropy. | 2 |
| **6.6.4** | Verify that, where push notifications are used for multi-factor authentication, rate limiting is used to prevent push bombing attacks. Number matching may also mitigate this risk. | 3 |

### Audit Guidance for V6.6

**6.6.1 — PSTN/SMS OTP restrictions:**

What to look for:
- If SMS or phone call OTP is offered, verify three conditions: (a) the phone number was previously validated, (b) stronger alternatives like TOTP are also offered, and (c) users are informed of the security risks of SMS-based authentication.
- For L3 audits: SMS and phone-based OTP must not be available at all. Check that these options are disabled or not present.
- Check for phone number validation during enrollment (e.g., sending a verification code before accepting the number for MFA use).

Red flags:
- SMS OTP as the only MFA option with no stronger alternatives.
- No phone number validation before using it for OTP delivery.
- SMS OTP available in L3 applications.

**6.6.2 — OOB code binding to authentication request:**

What to look for:
- OOB codes must be bound to the specific authentication session that triggered them. This means the code cannot be used for a different authentication attempt.
- Check that the OOB code is associated with a session ID, authentication request ID, or user session token in the database.
- Check that the verification endpoint validates the binding (e.g., the code is checked against the session that requested it, not just the user).

Red flags:
- OOB code stored only with the user ID, not bound to a specific session or authentication request. This allows an attacker who obtains a code to use it from a different session.
- OOB code verification that only checks `user_id + code` without checking the associated session.

**6.6.3 — Brute force protection for OOB codes:**

What to look for:
- Rate limiting on the OOB code verification endpoint. Check for limits on the number of verification attempts per session, per code, or per user.
- Account lockout or session invalidation after a number of failed OOB code attempts.
- Code invalidation after a certain number of failed attempts.
- Consider whether the code has sufficient entropy. 64 bits of entropy makes brute force infeasible, but typical 6-digit codes (~20 bits) require strong rate limiting.

Language-specific patterns:
- Check for rate limiting middleware specifically on the OOB verification endpoint (same patterns as 6.3.1 but applied to the verification endpoint, not the login endpoint).

Red flags:
- No rate limiting on OOB code verification.
- Unlimited attempts to guess a 6-digit code.
- No account lockout or code invalidation after failed attempts.

**6.6.4 — Push notification rate limiting (L3):**

What to look for:
- If push-based MFA is used (e.g., "Approve this login" push notifications), check for rate limiting on how many push notifications can be sent in a given time window.
- "Push bombing" or "MFA fatigue" attacks send many push requests hoping the user will accidentally approve one.
- Check for number matching (displaying a number on the login screen that the user must enter in the push notification app) as an additional mitigation.

Red flags:
- No limit on how many push notifications can be sent for a single authentication attempt.
- No cooldown between push notification requests.
- Push notification with simple "Approve/Deny" without number matching or additional context.

---

## V6.7: Cryptographic Authentication Mechanism

Cryptographic authentication mechanisms include smart cards or FIDO keys, where the user has to plug in or pair the cryptographic device to the computer to complete authentication. The authentication server will send a challenge nonce to the cryptographic device or software, and the device or software calculates a response based upon a securely stored cryptographic key. The requirements in this section provide implementation-specific guidance for these mechanisms, with guidance on cryptographic algorithms being covered in the "Cryptography" chapter.

Where shared or secret keys are used for cryptographic authentication, these should be stored using the same mechanisms as other system secrets, as documented in the "Secret Management" section in the "Configuration" chapter.

The requirements in this section mostly relate to [&sect; 5.1.7.2](https://pages.nist.gov/800-63-3/sp800-63b.html#sfcdv) of [NIST's Guidance](https://pages.nist.gov/800-63-3/sp800-63b.html).

| # | Requirement | Level |
|---|-------------|-------|
| **6.7.1** | Verify that the certificates used to verify cryptographic authentication assertions are stored in a way protects them from modification. | 3 |
| **6.7.2** | Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device. | 3 |

### Audit Guidance for V6.7

**6.7.1 — Certificate storage integrity (L3):**

What to look for:
- Certificates used for verifying cryptographic authentication (e.g., FIDO2/WebAuthn public keys, X.509 certificates for client certificate authentication, smart card CA certificates) must be stored securely and protected from unauthorized modification.
- Check how public keys or certificates are stored: database with access controls, file system with restricted permissions, hardware security module (HSM), key vault services (AWS KMS, Azure Key Vault, Google Cloud KMS, HashiCorp Vault).
- Check for integrity verification mechanisms: digital signatures on stored certificates, database integrity constraints, audit logging of certificate modifications.

Red flags:
- Public keys or certificates stored in a world-writable directory or database table with no access restrictions.
- No audit trail for changes to stored certificates.
- Certificates stored in application configuration files that are version-controlled with broad write access.

N/A conditions: If the application does not use cryptographic authentication mechanisms (FIDO2, client certificates, smart cards), this may be N/A.

**6.7.2 — Challenge nonce requirements (L3):**

What to look for:
- The challenge nonce sent to cryptographic authentication devices must be at least 64 bits (8 bytes) in length.
- The nonce must be statistically unique (generated using CSPRNG) or guaranteed unique over the lifetime of the device (e.g., using a counter).
- For WebAuthn/FIDO2: check the `challenge` parameter in `PublicKeyCredentialRequestOptions`. Libraries typically generate this correctly, but verify.

Language-specific patterns:
- **Python (`py_webauthn`, `fido2`):** Check challenge generation. `py_webauthn.generate_authentication_options()` typically handles this correctly.
- **Node.js (`@simplewebauthn/server`):** Check `generateAuthenticationOptions()` challenge parameter.
- **Java (`java-webauthn-server` by Yubico):** Check `RelyingParty.startAssertion()` challenge generation.
- **Ruby (`webauthn-ruby`):** Check `WebAuthn::Credential.options_for_get()` challenge generation.
- **Go (`go-webauthn`):** Check `webauthn.BeginLogin()` challenge generation.
- **C# (`Fido2NetLib`):** Check `MakeAssertionOptions()` challenge generation.

Red flags:
- Challenge shorter than 8 bytes.
- Challenge generated using non-cryptographic PRNG.
- Static or predictable challenge values.
- Challenge reuse across authentication attempts.

N/A conditions: Same as 6.7.1 — only applicable if cryptographic authentication is used.

---

## V6.8: Authentication with an Identity Provider

Identity Providers (IdPs) provide federated identity for users. Users will often have more than one identity with multiple IdPs, such as an enterprise identity using Azure AD, Okta, Ping Identity, or Google, or consumer identity using Facebook, Twitter, Google, or WeChat, to name just a few common alternatives. This list is not an endorsement of these companies or services, but simply an encouragement for developers to consider the reality that many users have many established identities. Organizations should consider integrating with existing user identities, as per the risk profile of the IdP's strength of identity proofing. For example, it is unlikely a government organization would accept a social media identity as a login for sensitive systems, as it is easy to create fake or throwaway identities, whereas a mobile game company may well need to integrate with major social media platforms to grow their active player base.

Secure use of external identity providers requires careful configuration and verification to prevent identity spoofing or forged assertions. This section provides requirements to address these risks.

| # | Requirement | Level |
|---|-------------|-------|
| **6.8.1** | Verify that, if the application supports multiple identity providers (IdPs), the user's identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user's ID in the IdP. | 2 |
| **6.8.2** | Verify that the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures. | 2 |
| **6.8.3** | Verify that SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks. | 2 |
| **6.8.4** | Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as 'acr', 'amr', and 'auth_time' (if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password). | 2 |

### Audit Guidance for V6.8

**6.8.1 — IdP identity spoofing prevention:**

What to look for:
- If the application supports multiple identity providers, check how user accounts are identified internally. The user record must include both the IdP identifier (namespace) and the user's ID within that IdP.
- Red flag: Using only the user's email or a single identifier field that could be the same across different IdPs. For example, if Google and Facebook both report a user with email `user@example.com`, they must be treated as potentially different users unless explicitly linked.
- Check the user model / database schema: look for fields like `provider` + `provider_id`, `idp_id` + `subject`, or a composite unique key.

Language-specific patterns:
- **Python (Django):** `django-allauth` stores `SocialAccount` with `provider` and `uid`. Check for custom OAuth implementations that only store email.
- **Node.js:** `passport.js` strategies — check how user identity is constructed. Look for `profile.id` combined with provider name.
- **Ruby (Rails):** `omniauth` gem — check the callback handler. Look for `auth.provider` + `auth.uid` in the user lookup/creation logic.
- **Java (Spring Security):** `OAuth2UserService` — check how `OAuth2User` identity is mapped to local user accounts.
- **PHP (Laravel):** `Socialite` — check how `$user->getId()` from different providers is handled.

Red flags:
- `User.find_by(email: oauth_user.email)` without considering the provider — allows account takeover.
- Single `external_id` column without a `provider` column.
- User merging logic that automatically links accounts from different IdPs based on email alone without user confirmation.

**6.8.2 — Signature validation on authentication assertions:**

What to look for:
- **JWT (OIDC ID Tokens):** Check that the application validates the JWT signature against the IdP's public keys (fetched from the JWKS endpoint). Check that unsigned JWTs (`"alg": "none"`) are rejected. Check for algorithm confusion attacks (e.g., accepting `HS256` when `RS256` is expected).
- **SAML Assertions:** Check that SAML assertion signatures are validated against the IdP's certificate. Check that unsigned assertions are rejected. Check for XML signature wrapping attacks.

Language-specific patterns:
- **Python:** `PyJWT` — check `jwt.decode(token, key, algorithms=["RS256"])`. Red flag: `algorithms` not specified (allows `none`), or `options={"verify_signature": False}`. `python3-saml` — check signature validation configuration.
- **Node.js:** `jsonwebtoken` — check `jwt.verify(token, key, { algorithms: ['RS256'] })`. Red flag: using `jwt.decode()` instead of `jwt.verify()` (decode does not verify signature). `passport-saml` — check `wantAssertionsSigned: true`.
- **Java:** Check `JwtDecoder` or `JwtParser` configuration for signature verification. For SAML, check `OpenSAML` signature validation.
- **PHP:** `firebase/php-jwt` — check `JWT::decode($jwt, $key, ['RS256'])`. For SAML, check `onelogin/php-saml` configuration.
- **Ruby:** `ruby-jwt` — check `JWT.decode(token, key, true, algorithm: 'RS256')`. For SAML, check `ruby-saml` settings.
- **Go:** `golang-jwt/jwt` — check `Parse()` with proper `KeyFunc` validation.
- **C#:** Check `TokenValidationParameters` in ASP.NET Core — `ValidateIssuerSigningKey = true`.

Red flags:
- JWT signature verification disabled (critical vulnerability).
- JWT `alg: none` accepted.
- SAML assertion processed without signature verification.
- Algorithm not explicitly restricted (allows algorithm substitution attacks).
- Using `jwt.decode()` (no verification) instead of `jwt.verify()` in Node.js.

**6.8.3 — SAML assertion replay prevention:**

What to look for:
- SAML assertions must be processed only once. Check for assertion ID tracking and replay detection.
- The application should store processed assertion IDs (the `ID` attribute on `<saml:Assertion>`) and reject any assertion with a previously seen ID within the validity period.
- Check `NotBefore` and `NotOnOrAfter` condition validation.

Language-specific patterns:
- **Python (`python3-saml`, `pysaml2`):** Check for replay detection configuration. `pysaml2` has built-in assertion cache.
- **Node.js (`passport-saml`, `saml2-js`):** Check for assertion ID caching and replay prevention.
- **Java (Spring Security SAML, OpenSAML):** Check for `AssertionConsumerService` replay detection.
- **PHP (`onelogin/php-saml`):** Check `processResponse()` for assertion uniqueness enforcement.
- **Ruby (`ruby-saml`):** Check for assertion ID tracking.

N/A conditions: If the application does not use SAML (only OIDC/OAuth), this requirement is N/A.

Red flags:
- No assertion ID tracking or caching.
- No time-based validity checking (NotBefore/NotOnOrAfter).
- Assertions accepted indefinitely without expiration checks.

**6.8.4 — Authentication strength verification from IdP:**

What to look for:
- If the application requires specific authentication strength for certain functions (e.g., step-up authentication for sensitive operations), it must verify this using IdP-provided claims.
- For OIDC: Check validation of `acr` (Authentication Context Class Reference), `amr` (Authentication Methods References), and `auth_time` claims in the ID token.
- For SAML: Check validation of `AuthnContextClassRef` in the SAML assertion.
- If the IdP does not provide authentication strength information, the application must have a documented fallback that assumes the weakest possible authentication.

Red flags:
- Application requests step-up authentication but does not verify the IdP's response claims.
- Application blindly trusts that the IdP performed strong authentication without checking claims.
- No fallback documented or implemented when IdP does not provide `acr`/`amr` claims.
- `auth_time` not checked when recentness of authentication matters (e.g., for sensitive operations, the authentication should be recent).

N/A conditions: If the application does not use an external IdP, this entire section is N/A.

---

## References

For more information, see also:

* [NIST SP 800-63 - Digital Identity Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf)
* [NIST SP 800-63B - Authentication and Lifecycle Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf)
* [NIST SP 800-63 FAQ](https://pages.nist.gov/800-63-FAQ/)
* [OWASP Web Security Testing Guide: Testing for Authentication](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing)
* [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
* [OWASP Choosing and Using Security Questions Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html)
* [CISA Guidance on "Number Matching"](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf)
* [Details on the FIDO Alliance](https://fidoalliance.org/)

---

## General Audit Approach for V6

When auditing this chapter, the sub-agent should:

1. **Map all authentication pathways** — Identify every way a user can authenticate: login page, API authentication, OAuth/SSO, SAML, API keys, magic links, mobile app auth, admin panels. Each pathway must meet the same security bar.
2. **Review password policy enforcement** — Check that server-side validation enforces the ASVS password policy (minimum 8 chars, no composition rules, common password blocklist, breached password check). Client-side validation alone is insufficient.
3. **Verify MFA implementation** — For L2+, confirm MFA is enforced (not optional). Check that MFA cannot be bypassed through alternative authentication pathways, password reset flows, or API access.
4. **Check credential storage** — While password hashing is covered in V8 (Data Protection), verify that lookup secrets and recovery codes are properly hashed. Verify TOTP seeds are encrypted at rest.
5. **Test for user enumeration** — Check login, registration, and forgot-password endpoints for differential responses (error messages, timing, HTTP status codes) that reveal whether an account exists.
6. **Review rate limiting** — Verify rate limiting on all authentication-related endpoints: login, MFA verification, password reset request, password reset completion, account registration.
7. **Audit IdP integration** — If the application uses external IdPs, verify signature validation on JWTs/SAML assertions, proper user identity namespacing, and assertion replay prevention.

---

## V6 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 13 | 6.1.1, 6.2.1, 6.2.2, 6.2.3, 6.2.4, 6.2.5, 6.2.6, 6.2.7, 6.2.8, 6.3.1, 6.3.2, 6.4.1, 6.4.2 |
| L2 | 22 | 6.1.2, 6.1.3, 6.2.9, 6.2.10, 6.2.11, 6.2.12, 6.3.3, 6.3.4, 6.4.3, 6.4.4, 6.5.1, 6.5.2, 6.5.3, 6.5.4, 6.5.5, 6.6.1, 6.6.2, 6.6.3, 6.8.1, 6.8.2, 6.8.3, 6.8.4 |
| L3 | 12 | 6.3.5, 6.3.6, 6.3.7, 6.3.8, 6.4.5, 6.4.6, 6.5.6, 6.5.7, 6.5.8, 6.6.4, 6.7.1, 6.7.2 |
| **Total** | **47** | |
