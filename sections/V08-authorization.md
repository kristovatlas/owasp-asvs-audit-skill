# V8: Authorization

**ASVS Version:** 5.0.0
**ASVS Source:** `0x17-V8-Authorization.md` in the [OWASP ASVS v5.0.0 repo](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/)

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

Authorization ensures that access is granted only to permitted consumers (users, servers, and other clients). To enforce the Principle of Least Privilege (POLP), verified applications must meet the following high-level requirements:

* Document authorization rules, including decision-making factors and environmental contexts.
* Consumers should have access only to resources permitted by their defined entitlements.

---

## V8.1: Authorization Documentation

Comprehensive authorization documentation is essential to ensure that security decisions are consistently applied, auditable, and aligned with organizational policies. This reduces the risk of unauthorized access by making security requirements clear and actionable for developers, administrators, and testers.

| # | Requirement | Level |
|---|-------------|-------|
| **8.1.1** | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | 1 |
| **8.1.2** | Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status. | 2 |
| **8.1.3** | Verify that the application's documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization. | 3 |
| **8.1.4** | Verify that authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication). | 3 |

### Audit Guidance for V8.1

**General approach:** These are documentation requirements. The sub-agent should look for evidence of documented authorization rules and policies in:
- README files, architecture docs, ADRs (Architecture Decision Records)
- API documentation (OpenAPI/Swagger specs with security schemes, GraphQL schemas with directives)
- Role/permission matrices, RBAC/ABAC policy definition files
- Inline code comments or docstrings describing authorization expectations
- Configuration files defining roles, permissions, and policies (e.g., Casbin policy files, OPA Rego policies, Spring Security configuration)
- Wiki or docs directories in the repo

**8.1.1 -- Documented function-level and data-specific authorization rules:**

What to look for:
- Documentation that defines which roles or permissions are required for each function/endpoint (e.g., "only admins can delete users," "only the resource owner can update their profile").
- Role-permission mapping tables, access control matrices, or RBAC configuration documents.
- API specs (OpenAPI/Swagger) with `security` schemes defined per operation.
- Policy files for authorization frameworks: Casbin model/policy files, OPA Rego policies, AWS IAM policy documents, Keycloak realm configuration.
- Framework-specific authorization configuration that is self-documenting: Spring Security `@PreAuthorize` annotations with clear role expressions, Django `permission_classes`, Rails `CanCanCan` ability definitions, Laravel Gates/Policies.
- If authorization is implemented in code but not documented anywhere external, this is a partial finding -- the enforcement exists but the explicit documentation requirement is not fully met.

**8.1.2 -- Documented field-level access restrictions:**

What to look for:
- Documentation describing which fields are readable/writable by which roles or under which conditions (e.g., "salary field visible only to HR and the employee themselves," "status field writable only when record is in draft state").
- API response schemas that vary by role (different serializer classes per role in DRF, GraphQL field-level `@auth` directives, conditional field inclusion in JSON:API).
- Field-level permission configuration: Django REST Framework field-level permissions, GraphQL schema directives (`@hasRole`), custom serializer logic that filters fields based on user role.
- State-dependent field access rules (e.g., "order total is only editable when status is 'pending'").
- This is commonly absent or implicit. Mark MANUAL_REVIEW if no documentation is found but field-level restrictions may exist in code that requires business context to evaluate.

**8.1.3 -- Documented environmental and contextual attributes:**

What to look for:
- Documentation that lists environmental attributes used in security decisions: IP address, geolocation, time of day, device fingerprint, browser type, network location (corporate VPN vs. public internet).
- Configuration for adaptive authentication or conditional access policies (e.g., Azure AD Conditional Access, Okta sign-on policies, AWS IAM condition keys).
- Risk scoring documentation that describes what factors contribute to risk assessment.
- This is a Level 3 requirement and is commonly absent in most applications. If the application does not use contextual factors in authorization, document this as N/A with explanation.

**8.1.4 -- Documented environmental/contextual decision-making logic:**

What to look for:
- Documentation that goes beyond listing attributes (8.1.3) to describe *how* they influence decisions: thresholds, scoring rules, decision trees.
- Examples: "If login from new country, require MFA step-up," "If IP not in allowlist, deny admin access," "If outside business hours, require additional approval for financial transactions."
- Policy engine documentation (OPA, Casbin, custom rule engines) with decision logic explained.
- This is a Level 3 requirement. If the application has no adaptive/contextual security logic, mark N/A.

---

## V8.2: General Authorization Design

Implementing granular authorization controls at the function, data, and field levels ensures that consumers can access only what has been explicitly granted to them.

| # | Requirement | Level |
|---|-------------|-------|
| **8.2.1** | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | 1 |
| **8.2.2** | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | 1 |
| **8.2.3** | Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA). | 2 |
| **8.2.4** | Verify that adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session. | 3 |

### Audit Guidance for V8.2

**8.2.1 -- Function-level access control enforcement:**

This requirement addresses Broken Function Level Authorization (BFLA) -- ensuring that each endpoint/function checks that the caller has the required permission or role before executing.

What to look for:
- **Good patterns:** Centralized authorization middleware or decorators applied consistently across all routes/endpoints.
- **Red flags:** Endpoints that lack any authorization check, especially administrative or privileged operations. Reliance on obscurity (hidden URLs) rather than explicit permission checks. Inconsistent application of authorization -- some endpoints protected, others not.

Language-specific patterns to check:

- **Django/DRF:** Are views protected with `permission_classes` (e.g., `IsAuthenticated`, `IsAdminUser`, custom permissions)? Are `@permission_required` or `@login_required` decorators used on function-based views? Check for views that inherit from `APIView` without setting `permission_classes`. Look for `DEFAULT_PERMISSION_CLASSES` in `REST_FRAMEWORK` settings -- if set to `AllowAny`, every view must explicitly override.
- **Flask:** Are routes protected with decorators like `@login_required` (Flask-Login), `@roles_required`, `@roles_accepted` (Flask-Security), or custom authorization decorators? Check for Flask-Principal, Flask-RBAC, or Flask-Authorize usage. Undecorated routes in authenticated applications are red flags.
- **Express/Node.js:** Is authorization middleware applied to routes? Check for middleware like `passport.authenticate()`, custom `isAdmin` or `hasRole()` middleware, `express-jwt` + custom role checks, `casl` ability checks, `accesscontrol` library. Look for routes registered without any middleware in the chain.
- **Spring (Java):** Are endpoints annotated with `@PreAuthorize`, `@Secured`, `@RolesAllowed`? Is method-level security enabled via `@EnableMethodSecurity` or `@EnableGlobalMethodSecurity`? Check `SecurityFilterChain` / `HttpSecurity` configuration for URL-based authorization rules (`.requestMatchers(...).hasRole(...)`). Look for controllers with no security annotations and not covered by URL patterns.
- **Laravel (PHP):** Are routes protected with `middleware('auth')`, `middleware('can:...')`, or `Gate::authorize()`? Check for Policy classes and `$this->authorize()` calls in controllers. Look for routes in `web.php` or `api.php` without auth middleware. Check `AuthServiceProvider` for Gate/Policy definitions.
- **Rails:** Is authorization enforced via gems like Pundit (`authorize @resource`), CanCanCan (`load_and_authorize_resource`, `authorize!`), or Action Policy? Check for `before_action` callbacks that verify permissions. Look for controllers without any authorization calls. Check `ApplicationController` for default authorization enforcement.
- **Go:** Check for authorization middleware in the HTTP handler chain (e.g., middleware functions wrapping handlers, `casbin` enforcement, custom auth middleware). Look for handler functions that access request context for user roles/permissions.
- **C#/.NET:** Are controllers or actions decorated with `[Authorize]`, `[Authorize(Roles = "...")]`, `[Authorize(Policy = "...")]`? Check `Program.cs`/`Startup.cs` for `AddAuthorization()` policy definitions and `UseAuthorization()` middleware. Look for controllers with `[AllowAnonymous]` on sensitive operations. Check for `IAuthorizationService` usage in complex scenarios.

**8.2.2 -- Data-specific access control (IDOR/BOLA prevention):**

This requirement addresses Insecure Direct Object Reference (IDOR) and Broken Object Level Authorization (BOLA) -- ensuring that when a consumer requests a specific data item by ID, the application verifies the consumer has permission to access *that specific item*.

What to look for:
- **Critical pattern:** Every endpoint that retrieves, updates, or deletes a resource by identifier (e.g., `/api/users/{id}`, `/api/orders/{orderId}`) must verify that the authenticated consumer is authorized to access that specific resource.
- **Red flags:**
  - Fetching a record by ID from the database and returning it without checking ownership or permission (e.g., `Order.objects.get(id=order_id)` without filtering by user).
  - Using sequential/predictable integer IDs without authorization checks (UUIDs alone are NOT a sufficient mitigation -- authorization must still be checked).
  - Endpoints where changing the ID parameter in the URL returns another user's data.
  - Admin-only data accessible by changing an ID in a non-admin endpoint.
- **Good patterns:**
  - Scoping queries to the authenticated user: `Order.objects.filter(user=request.user, id=order_id)` (Django), `current_user.orders.find(params[:id])` (Rails), `WHERE user_id = ? AND id = ?` (raw SQL).
  - Authorization checks after fetching: `if order.user_id != current_user.id: raise PermissionDenied`.
  - Policy-based authorization that checks object ownership: Pundit policies (Rails), Laravel Policies with `$user->id === $order->user_id`, Spring `@PreAuthorize("@authService.isOwner(#id)")`.
  - ORM-level default scoping or multi-tenancy libraries that automatically filter by tenant/user.

Language-specific patterns to check:

- **Django/DRF:** Does `get_queryset()` filter by `self.request.user`? Are `get_object()` overrides checking ownership? Does the permission class implement `has_object_permission()`? Check for raw `Model.objects.get(pk=id)` without user filtering.
- **Express/Node.js:** After fetching a resource from the database, is there a check like `if (resource.userId !== req.user.id)`? Are Mongoose/Sequelize queries scoped: `Model.findOne({ _id: id, userId: req.user.id })`? Check for `Model.findById(req.params.id)` without subsequent ownership checks.
- **Spring (Java):** Are JPA/Hibernate queries filtering by the authenticated user? Is `@PreAuthorize` used with SpEL expressions that reference the resource? Check for `repository.findById(id)` without ownership verification.
- **Laravel (PHP):** Are Eloquent queries scoped: `auth()->user()->orders()->findOrFail($id)`? Are Policy methods checking ownership? Check for `Model::find($id)` without authorization.
- **Rails:** Is `current_user.orders.find(params[:id])` used instead of `Order.find(params[:id])`? Are Pundit/CanCanCan policies checking resource ownership?
- **Go:** After fetching a resource from the database, is the owner/tenant field compared against the authenticated user from the request context?
- **C#/.NET:** Are LINQ/EF Core queries filtered by the authenticated user: `.Where(o => o.UserId == userId)`? Are authorization handlers implementing `IAuthorizationHandler` checking resource ownership?

**8.2.3 -- Field-level access control (BOPLA prevention):**

This requirement addresses Broken Object Property Level Authorization (BOPLA) -- ensuring that consumers can only read or write fields they are permitted to access.

What to look for:
- **Red flags:**
  - Mass assignment vulnerabilities: accepting all fields from user input without whitelisting. For example, a user updating their profile and being able to set `is_admin=true` or `role=admin` because all fields are accepted.
  - API responses that return all database columns regardless of the consumer's role (e.g., returning `password_hash`, `internal_notes`, `salary` fields to unauthorized consumers).
  - GraphQL APIs that expose all fields on a type without field-level authorization directives.
- **Good patterns:**
  - Explicit field whitelisting on input: Django serializer `fields` / `read_only_fields`, Rails `strong_parameters` (`permit`), Laravel `$fillable` / `$guarded`, Spring `@JsonIgnore` on sensitive fields, `class-validator` + DTOs (NestJS).
  - Role-based serialization: different serializer classes or field sets per role (e.g., `AdminUserSerializer` vs. `UserSerializer` in DRF, conditional `@JsonView` in Spring).
  - GraphQL field-level auth: `@auth` directives, field-level resolvers with permission checks, custom middleware that inspects field access.
  - Separate read/write schemas (different request vs. response models).

Language-specific patterns to check:

- **Django/DRF:** Check serializer `Meta.fields` -- are sensitive fields excluded? Are `read_only_fields` set appropriately? Do different roles get different serializers? Check for `ModelSerializer` with `fields = '__all__'` (red flag).
- **Express/Node.js:** Are response objects filtered before sending (e.g., picking specific fields, using DTOs)? Check for `res.json(dbRecord)` that sends the full database record. Look for `_.pick()` or explicit field selection.
- **Spring (Java):** Are DTOs used to control input/output fields (separate request/response DTOs), or are JPA entities exposed directly? Check for `@JsonIgnore` on sensitive fields. Look for `@JsonView` for role-based serialization.
- **Laravel (PHP):** Are API Resources used with conditional fields (`$this->when()`)? Check `$fillable` and `$guarded` on Eloquent models. Look for `$model->fill($request->all())` (mass assignment risk).
- **Rails:** Are `strong_parameters` (`permit`) restrictive enough? Are Jbuilder/ActiveModelSerializers filtering output fields? Check for `params.permit!` (permits everything -- red flag).
- **C#/.NET:** Are DTOs/ViewModels used instead of exposing EF entities directly? Check for `[JsonIgnore]` on sensitive properties. Look for `AutoMapper` profiles that may inadvertently map sensitive fields.

**8.2.4 -- Adaptive/contextual security controls:**

This is a Level 3 requirement. It requires that authorization decisions incorporate environmental and contextual attributes (time of day, location, IP, device) both at session establishment and during ongoing sessions.

What to look for:
- Middleware or filters that evaluate contextual attributes on each request (not just at login).
- Integration with adaptive authentication services: Azure AD Conditional Access, Okta Adaptive MFA, AWS IAM context conditions.
- Custom implementations that check IP geolocation, device fingerprinting, or time-based restrictions.
- Continuous session evaluation: does the application re-evaluate authorization context during a session, not just at login?
- **Red flags:** Authorization decisions based solely on role/permission with no contextual factors considered. No session re-evaluation after initial authentication.
- If the application does not implement any contextual/adaptive controls, this fails at L3. Mark N/A only if the application's documentation explicitly states that contextual controls are not applicable to its threat model (unlikely for L3 applications).

---

## V8.3: Operation Level Authorization

The immediate application of authorization changes in the appropriate tier of an application's architecture is crucial to preventing unauthorized actions, especially in dynamic environments.

| # | Requirement | Level |
|---|-------------|-------|
| **8.3.1** | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | 1 |
| **8.3.2** | Verify that changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage. | 3 |
| **8.3.3** | Verify that access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer's token, rather than a machine-to-machine token from the first service, to make permission decisions. | 3 |

### Audit Guidance for V8.3

**8.3.1 -- Server-side authorization enforcement:**

This requirement ensures that authorization decisions are made on the server side (trusted service layer) and not in client-side code that a consumer could tamper with.

What to look for:
- **Red flags:**
  - Authorization logic implemented only in frontend JavaScript (e.g., hiding UI elements based on role but not enforcing on the backend, checking `user.role === 'admin'` in the browser to decide whether to show a button but not verifying on the API endpoint).
  - API endpoints that trust client-supplied role or permission claims without server-side verification.
  - Client-side routing guards (React Router, Vue Router, Angular guards) as the sole access control mechanism without corresponding server-side checks.
  - Hidden form fields or client-side variables that control authorization decisions.
- **Good patterns:**
  - Every API endpoint independently verifies authorization on the server, regardless of what the client UI shows or hides.
  - Authorization middleware/filters in the server-side request pipeline.
  - Server-side session or token-based role resolution -- roles/permissions derived from the authenticated session on the server, not from client-supplied data.

Language-specific patterns to check:

- **React/Vue/Angular frontends:** Check if frontend route guards or conditional rendering are the *only* access control. The frontend may hide elements, but the corresponding API must independently enforce access control. Search for API calls to unprotected endpoints.
- **Django:** Authorization should be in views (`permission_classes`, `@permission_required`), not solely in templates (`{% if user.is_admin %}`).
- **Express/Node.js:** Authorization middleware should be applied to routes on the server. Check that role checks happen in server middleware, not just in frontend API call logic.
- **Spring:** `@PreAuthorize`, `@Secured`, or `HttpSecurity` configuration should enforce access. Check that Thymeleaf `sec:authorize` is not the sole control.
- **Laravel:** `middleware('can:...')`, `Gate::authorize()`, or Policy checks should exist server-side. Blade `@can` directives are for UI only.
- **Rails:** `before_action` authorization callbacks or Pundit/CanCanCan in controllers. ERB `<% if can? %>` is UI-only.

**8.3.2 -- Immediate application of authorization changes:**

This is a Level 3 requirement. It requires that when a consumer's permissions change (e.g., role revocation, account deactivation), the change takes effect immediately, or if that is not possible (e.g., with JWTs), compensating controls exist.

What to look for:
- **Token-based authentication (JWT/self-contained tokens):**
  - If the application uses JWTs for authorization, permissions are embedded in the token and changes won't take effect until the token expires.
  - **Red flags:** Long-lived JWTs (hours or days) with no token revocation mechanism. No server-side check against current permissions on each request.
  - **Good patterns:** Short-lived access tokens (5-15 minutes) with refresh token rotation. Token revocation lists or blacklists (Redis-based, database-based). Server-side permission checks on each request in addition to token validation (hybrid approach). Audit logging that detects and alerts on actions performed with stale permissions.
- **Session-based authentication:**
  - Changes to user permissions should be reflected in the session immediately or on the next request. Check whether the application reloads permissions from the database on each request or caches them in the session.
  - **Good patterns:** Permissions loaded from database on each request (performance impact but most secure). Session invalidation on permission change. Cache invalidation triggered by permission updates.
  - **Red flags:** Permissions cached in session indefinitely without refresh. No mechanism to invalidate active sessions when permissions change.

Language-specific patterns to check:

- **Django:** Check `SESSION_ENGINE` and whether user permissions are re-evaluated per request. `update_session_auth_hash()` invalidates sessions on password change -- is there equivalent logic for permission changes?
- **Express/Node.js:** If using `express-session`, are permissions stored in the session object and never refreshed? If using JWTs, what is the token lifetime (`expiresIn`)? Is there a token blacklist?
- **Spring:** Check `SecurityContext` management. Is `SessionRegistry` used for session management? Can active sessions be invalidated (`expireNow()`)? For JWT, check token lifetime and whether a revocation mechanism exists.
- **Laravel:** Check if `Auth::user()` reloads from database or is cached. Session driver configuration. Sanctum/Passport token revocation support.
- **Rails:** Devise session management. Check whether `current_user` reloads permissions. Warden callbacks for session invalidation.

**8.3.3 -- Authorization based on originating subject's permissions:**

This is a Level 3 requirement. In service-to-service communication, the downstream service must authorize based on the original consumer's identity and permissions, not on the intermediary service's permissions.

What to look for:
- **Microservice architectures:** When Service A calls Service B on behalf of a user, Service B should receive and validate the *user's* token/identity, not Service A's service account credentials.
- **Red flags:**
  - Service-to-service calls using a shared service account token that has broad permissions, effectively bypassing per-user authorization.
  - Intermediary services that authenticate to downstream services with their own credentials and forward user identity only as an unauthenticated header (e.g., `X-User-Id` without cryptographic verification).
  - "God mode" service accounts used for internal communication.
- **Good patterns:**
  - Token forwarding: The user's JWT or access token is passed through the service chain (Authorization header propagation).
  - OAuth2 Token Exchange (RFC 8693): The intermediary service exchanges the user's token for a new token scoped to the downstream service but still representing the user.
  - On-behalf-of (OBO) flows: Azure AD OBO flow, similar patterns in other identity providers.
  - Cryptographically signed user identity propagation (e.g., mTLS with user claims, signed request headers).
  - Service mesh identity propagation (Istio, Linkerd) with user context in request metadata.

Language-specific patterns to check:

- **Spring (Java):** Check for `OAuth2RestTemplate` or `WebClient` with token relay. Look for `SecurityContextHolder.getContext().getAuthentication()` being used to extract and forward user tokens. Check for Spring Cloud Gateway token relay configuration.
- **Express/Node.js:** Check whether HTTP clients (axios, fetch, node-fetch) forward the `Authorization` header from the incoming request to downstream service calls. Look for middleware that extracts and propagates user context.
- **Go:** Check whether `http.Client` calls to downstream services include the user's bearer token from the incoming request context.
- **C#/.NET:** Check for `IHttpClientFactory` with token propagation. Look for `HttpContext.GetTokenAsync("access_token")` being used to forward tokens. Check Dapr or similar middleware for identity propagation.
- **General:** Search for service-to-service authentication configuration. Look for environment variables or config keys like `SERVICE_TOKEN`, `INTERNAL_API_KEY`, `MACHINE_TO_MACHINE_SECRET` -- these may indicate service-level auth that bypasses user-level authorization.

---

## V8.4: Other Authorization Considerations

Additional considerations for authorization, particularly for administrative interfaces and multi-tenant environments, help prevent unauthorized access.

| # | Requirement | Level |
|---|-------------|-------|
| **8.4.1** | Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact. | 2 |
| **8.4.2** | Verify that access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access. | 3 |

### Audit Guidance for V8.4

**8.4.1 -- Multi-tenant isolation:**

Applicable if the application is multi-tenant (serves multiple organizations, teams, or isolated customer environments from a shared infrastructure). Mark N/A if the application is single-tenant.

What to look for:
- **Critical pattern:** Every database query, API call, and resource access must be scoped to the authenticated consumer's tenant. A consumer in Tenant A must never be able to read, write, or affect data belonging to Tenant B.
- **Red flags:**
  - Database queries that lack a `tenant_id` filter -- e.g., `SELECT * FROM orders WHERE id = ?` without `AND tenant_id = ?`.
  - Tenant identifier derived from user-controllable input (URL parameter, header, subdomain) without server-side validation against the authenticated session.
  - Shared database tables without row-level security or application-level tenant filtering.
  - API endpoints where changing a resource ID could return data from another tenant (cross-tenant IDOR).
  - Background jobs or scheduled tasks that process data without tenant context.
  - Caching without tenant-scoped cache keys (one tenant's cached data served to another).
- **Good patterns:**
  - ORM-level tenant scoping: automatic query filters that always include `tenant_id`. Libraries: `django-tenants`, `apartment` (Rails), `Finbuckle.MultiTenant` (.NET), Hibernate filters (Java).
  - Database-per-tenant or schema-per-tenant isolation.
  - Row-level security (RLS) at the database level (PostgreSQL RLS, SQL Server RLS).
  - Middleware that sets tenant context from the authenticated session (not from URL or headers alone) and applies it to all subsequent queries.
  - Tenant-scoped cache keys: `cache.get(f"tenant:{tenant_id}:orders:{order_id}")`.

Language-specific patterns to check:

- **Django:** Check for `django-tenants` or `django-multitenant`. Are querysets filtered by tenant? Is there a middleware that sets `connection.set_tenant()`? Check for raw SQL queries that may bypass ORM tenant filtering.
- **Express/Node.js:** Is tenant context extracted from the authenticated user and applied to all database queries? Check Mongoose discriminators or middleware that injects tenant filters. Look for Sequelize default scopes with tenant filtering.
- **Spring (Java):** Check for Hibernate multi-tenancy configuration (`MultiTenantConnectionProvider`, `CurrentTenantIdentifierResolver`). Are JPA queries using `@Filter` or `@Where` with tenant conditions? Check for `@TenantId` annotations.
- **Laravel (PHP):** Check for tenant scoping packages (`tenancy/tenancy`, `stancl/tenancy`). Are Eloquent global scopes used for tenant filtering? Check for `BelongsToTenant` traits or similar patterns.
- **Rails:** Check for `apartment` or `acts_as_tenant` gems. Are `default_scope` or `ActiveRecord` callbacks enforcing tenant isolation? Look for unscoped queries that bypass tenant filters.
- **C#/.NET:** Check for `Finbuckle.MultiTenant`, EF Core global query filters (`HasQueryFilter`), or custom `IDbContextFactory` with tenant context.
- **Go:** Check whether database query builders or ORM layers (GORM, sqlx) include tenant ID conditions. Look for middleware that sets tenant context in `context.Context`.

**8.4.2 -- Multi-layered administrative interface security:**

This is a Level 3 requirement. It requires that access to administrative interfaces goes beyond simple authentication to include continuous identity verification, device posture assessment, and contextual risk analysis.

What to look for:
- **Red flags:**
  - Admin panels accessible with just a username and password, with no additional security layers.
  - Admin access controlled solely by network location (IP allowlist or VPN requirement) without additional authentication factors.
  - No distinction in security controls between admin and regular user interfaces.
  - Admin sessions that never re-verify identity (no step-up authentication, no session timeout, no re-authentication for sensitive operations).
- **Good patterns:**
  - MFA required for admin access (and enforced, not optional).
  - Step-up authentication for administrative actions (re-authentication before destructive operations).
  - Admin interface on a separate domain/port with additional network controls *in addition to* (not instead of) authentication controls.
  - Device posture checks: MDM enrollment verification, certificate-based device authentication, device compliance checks.
  - Continuous session monitoring: unusual activity detection, session timeout, forced re-authentication after inactivity.
  - Contextual checks: IP geolocation, time-based restrictions, anomaly detection.
  - Admin audit logging: all administrative actions logged with user identity, timestamp, IP, device information.

Language-specific patterns to check:

- **Django:** Is the admin interface (`/admin/`) protected beyond basic authentication? Check for django-otp, django-mfa2, or similar MFA packages on admin. Look at `ADMIN_URL` customization, IP restriction middleware for admin paths, and `AdminSite` customization.
- **Express/Node.js:** Are admin routes behind additional middleware layers (MFA verification, IP restriction, rate limiting)? Check for separate Express apps or routers for admin functionality with stricter middleware chains.
- **Spring (Java):** Is Spring Security configured with stricter rules for admin endpoints (stronger authentication requirements, IP restrictions)? Check for `@PreAuthorize` with compound expressions on admin controllers. Look for Spring Boot Actuator endpoint security.
- **Laravel (PHP):** Are admin routes (e.g., Nova, Filament, custom admin) behind additional middleware? Check for MFA enforcement on admin guard, IP restriction middleware, custom admin authentication.
- **Rails:** Are admin namespaces (e.g., `/admin/`) behind additional `before_action` checks? Check for ActiveAdmin or Administrate with extra security layers. Look for Devise `:lockable` and `:timeoutable` configurations on admin users.
- **C#/.NET:** Are admin areas configured with stricter authorization policies? Check for `[Authorize(Policy = "AdminAccess")]` with multi-factor requirements. Look for `IdentityServer` or Duende configuration for admin clients.

---

## References

For more information, see also:

* [OWASP Web Security Testing Guide: Authorization](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing)
* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

---

## V8 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 4 | 8.1.1, 8.2.1, 8.2.2, 8.3.1 |
| L2 | 3 | 8.1.2, 8.2.3, 8.4.1 |
| L3 | 6 | 8.1.3, 8.1.4, 8.2.4, 8.3.2, 8.3.3, 8.4.2 |
| **Total** | **13** | |
