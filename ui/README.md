# UI / BFF

The UI track from the architecture document — §27.1, work packages **WP-UI-01**, **WP-UI-02**, **WP-UI-03**.

```
ui/
├── frontend/   React 19.3 + Vite 8 + TypeScript 7
└── bff/        Spring Boot 4.1.1 Backend For Frontend (Java 27)
```

Both live here because WP-UI-01 scopes them as one work package: the browser trust boundary is the pair, not either half.

## The decision that shapes everything here

[**ADR-SEC-007**](../adr/ADR-SEC-007-bff-and-browser-token-custody.md) — the browser never receives, stores or transmits an OAuth token.

The React app holds no access token, no refresh token, and nothing it could exfiltrate. Its only credential is an opaque `HttpOnly` session cookie it cannot read. The BFF is a confidential OAuth client that performs the Authorization Code + PKCE exchange, keeps the tokens server-side, and attaches an audience-restricted token when forwarding to Resource Servers.

The consequence, stated plainly because it is a real cost: **cookie authentication is ambient, so CSRF is back in scope.** The browser attaches the session cookie to qualifying cross-site requests without the page's involvement. `SameSite` is defence in depth; the control is an explicit anti-CSRF token on every state-changing request. That token *is* readable by JavaScript — it is not a credential. The session cookie is, and that one is `HttpOnly`.

## Work packages

| WP | Scope | Key ADRs |
|---|---|---|
| WP-UI-01 | React shell, BFF, cookie lifecycle, CSRF, CORS, CSP, OAuth client, PKCE orchestration, API forwarding, logout | [003](../adr/ADR-SEC-003-oidc-authorization-code-pkce.md), [007](../adr/ADR-SEC-007-bff-and-browser-token-custody.md) |
| WP-UI-02 | Register, verify-email, login, MFA setup, passkeys, forgot/reset password, recovery, step-up | [004](../adr/ADR-SEC-004-mfa-webauthn-step-up.md), [005](../adr/ADR-SEC-005-recovery-assurance-tiers.md), [006](../adr/ADR-SEC-006-authentication-ux-assurance.md) |
| WP-UI-03 | Security Center: factors, recovery methods, devices, sessions, security activity | [011](../adr/ADR-SEC-011-session-device-revocation-model.md), [012](../adr/ADR-SEC-012-user-facing-security-transparency.md) |

## Build and run

```bash
cd bff && ./gradlew bootRun          # :8080
```

```bash
cd frontend && npm install && npm run dev    # :5173
```

The Vite dev server proxies `/api` to the BFF, so the browser stays **same-origin** in development. That is deliberate: an `HttpOnly`, `SameSite` cookie would not be sent cross-origin, so a cross-origin dev setup would quietly diverge from production and hide exactly the bugs this arrangement exists to catch.

`bootRun` performs OIDC discovery at startup, so the Authorization Server must be running on `:9000` first.

## Status

**WP-UI-01 skeleton.** Builds, starts, and enforces the security posture. It does not authenticate anyone yet — `/api/session` reports whether a session exists, and `oauth2Login` is wired but no login UI exists.

Present: session cookie configuration (`HttpOnly`, `Secure`, `SameSite`), cookie-based CSRF, HSTS and CSP headers, deny-by-default authorization, the confidential OAuth client, and an API client that deliberately contains no token handling.

Not present: every route in WP-UI-02 and WP-UI-03.

## Two configuration notes

**OAuth provider config lives in profiles, not the base YAML.** The issuer differs per environment, and keeping it out of the base lets the context test supply explicit endpoints instead of triggering discovery. A test that needs another service running is a test that gets disabled.

**Sessions are in-memory under the `local` profile — single replica only.** §27.8 flags this: shared session storage is required before more than one replica can serve the interactive flow, or an authorization code minted on one pod fails its exchange on another. The `dev` profile uses Redis-backed sessions for that reason.
