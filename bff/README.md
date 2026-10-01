# BFF — Backend For Frontend

**WP-UI-01.** Spring Boot 4.1.1, Java 27.

A Java service, despite serving the UI track. It sits at the browser trust boundary and exists only to serve [`frontend/`](../frontend) — it holds that app's tokens, owns its session cookie, and has no purpose independent of it. §27.1 scopes the two as one work package for that reason, even though they are separate builds.

## The decision that shapes everything here

[**ADR-SEC-007**](../adr/ADR-SEC-007-bff-and-browser-token-custody.md) — the browser never receives, stores or transmits an OAuth token.

This service is a confidential OAuth client. It performs the Authorization Code + PKCE exchange, keeps the resulting tokens **server-side**, and hands the browser nothing but an opaque `HttpOnly` session cookie. When it forwards to a Resource Server it attaches an audience-restricted access token the browser has never seen.

The consequence, stated plainly because it is a real cost: **cookie authentication is ambient, so CSRF is back in scope.** The browser attaches the session cookie to qualifying cross-site requests without the page's involvement. `SameSite` is defence in depth; the control is an explicit anti-CSRF token on every state-changing request. That token *is* readable by JavaScript — it is not a credential. The session cookie is, and that one is `HttpOnly`.

## Run

```bash
./gradlew bootRun     # :8080
```

`bootRun` performs OIDC discovery at startup, so the [Authorization Server](../backend/authorization-server) must be running on `:9000` first.

## Status

The login flow works end to end (verified on the deployed stack).

**Present:** session cookie configuration (`HttpOnly`, `Secure`, `SameSite`), cookie-based CSRF with the token cookie issued on every response, HSTS and CSP headers, deny-by-default authorization, the confidential OAuth client with **PKCE**, Redis-backed sessions across replicas, `/api/session`, `/api/session/logout` (ends both the BFF and Authorization Server sessions), and `/api/auth/register` (relayed to the Authorization Server over the cluster-internal address).

**API forwarding (`/api/documents/**`, `/api/tenants`).** For each call the BFF exchanges the login token (RFC 8693) for one aimed at the API and narrowed to the single scope that route needs, then forwards. The login token, the cookie and anything the browser sent in `Authorization` are never relayed. Deny by default: only listed routes exist, ids are constrained so a crafted one cannot escape the API's path, and if the exchange fails the call fails - the broad login token is never sent in its place.

**Login token storage.** The token is kept in the HTTP session (shared through Redis), not in Spring's default in-memory service: that one is local to a pod, so with two replicas every other request reached a pod that had never heard of the user and bounced them to sign in again.

**Not present:** token refresh handling beyond the framework's, and everything in WP-UI-02 and WP-UI-03 beyond login, registration, MFA hand-off and documents.

**Assurance.** `/api/session` reports what the session actually proved, read from the ID token's `amr` claim (`PASSWORD` or `MFA`), plus the Authorization Server link where two-step verification is managed. A missing claim means `PASSWORD`, never `MFA`. The interactive sign-in enforces the second factor for accounts that have one (see the Authorization Server).

**Boot 4 note.** `spring.session.store-type` no longer exists, and the plain `spring-session-data-redis` dependency no longer auto-configures — the Boot starter is required, or sessions silently stay in each pod's memory and a login started on one replica fails on another. The `local` and `test` profiles exclude the Redis auto-configuration instead.

## Two configuration notes

**OAuth provider config lives in profiles, not the base YAML.** The issuer differs per environment, and keeping it out of the base lets the context test supply explicit endpoints instead of triggering OIDC discovery. A test that needs another service running is a test that gets disabled.

**Sessions are in-memory under the `local` profile — single replica only.** §27.8 flags this: shared session storage is required before more than one replica can serve the interactive flow, or an authorization code minted on one pod fails its exchange on another. The `dev` profile uses Redis-backed sessions for that reason.

## Related

| | |
|---|---|
| [`frontend/`](../frontend) | The React app this service exists to serve |
| [`backend/`](../backend) | Authorization Server and Resource Servers |
| WP-UI-02 | Register, verify-email, login, MFA, passkeys, recovery, step-up — [ADR-SEC-004](../adr/ADR-SEC-004-mfa-webauthn-step-up.md), [005](../adr/ADR-SEC-005-recovery-assurance-tiers.md), [006](../adr/ADR-SEC-006-authentication-ux-assurance.md) |
| WP-UI-03 | Security Center — [ADR-SEC-011](../adr/ADR-SEC-011-session-device-revocation-model.md), [012](../adr/ADR-SEC-012-user-facing-security-transparency.md) |
