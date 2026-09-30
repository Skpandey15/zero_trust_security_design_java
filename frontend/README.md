# Frontend

**WP-UI-01 · 02 · 03.** React 19.3 + Vite 8 + TypeScript 7.

The security console. It talks only to the [BFF](../bff) — never to the Authorization Server, and never to a Resource Server directly.

## What makes this different from a normal SPA

[**ADR-SEC-007**](../adr/ADR-SEC-007-bff-and-browser-token-custody.md) — **there is no token handling in this codebase, by design.**

No `Authorization` header is ever set. Nothing is written to or read from `localStorage` or `sessionStorage`. No token is parsed, refreshed, or scheduled for refresh. The only credential the browser holds is an `HttpOnly` session cookie it cannot read.

That is the whole point: an XSS defect here yields a session an attacker can abuse *while the page is open*, not a credential they can exfiltrate and replay from their own machine.

`src/api/client.ts` is where this is enforced. If a future change adds token storage, it goes there first — and it should be rejected there.

The one thing the client does carry is the anti-CSRF token, read from a readable cookie. That is deliberate: it is not a credential, and cookie authentication is ambient, so CSRF protection has to be explicit rather than left to `SameSite`.

## Run

```bash
npm install
npm run dev      # :5173
```

The dev server proxies `/api` to the BFF on `:8080`, so the browser stays **same-origin** in development. That is deliberate: an `HttpOnly`, `SameSite` cookie would not be sent cross-origin, so a cross-origin dev setup would quietly diverge from production and hide exactly the bugs this arrangement exists to catch.

```bash
npm run build      # tsc -b && vite build
npm run typecheck
```

## Status

**Working end to end** (verified against the deployed stack): `/` (session state, sign out), `/login`, `/register`.

- `/login` is deliberately not a credentials form. It sends the browser to the Authorization Server's own sign-in page (Authorization Code + PKCE, run by the BFF), so no password ever passes through this app.
- `/register` posts to the BFF, which relays to the Authorization Server.
- Sign-out ends the BFF session and the Authorization Server's.

**Still to build** — WP-UI-02: `/verify-email`, `/mfa/setup`, `/passkeys`, `/forgot-password`, `/reset-password`, `/recovery`, `/step-up`. WP-UI-03: the Security Center. Each needs an Authorization Server capability that does not exist yet (email verification, WebAuthn, recovery flows, a device/session API), and `/mfa/setup` is blocked by the token split described below.

**Blocked, and why.** The Authorization Server has two token systems. Its own `/api` (including `/api/users/me/mfa/*`) accepts only tokens with its own audience, and refuses OIDC tokens on purpose (ADR-SEC-008). The BFF holds an OIDC token, so it cannot call MFA setup until token exchange (ADR-SEC-016) exists. Sign-in is therefore password-only for now.

Two constraints those routes inherit, both from ADRs rather than taste:

- **[ADR-SEC-006](../adr/ADR-SEC-006-authentication-ux-assurance.md)** — the interface must not offer a route to a lower assurance level than policy permits. Fallbacks are not peers; no affordance silently selects a weaker factor.
- **[ADR-SEC-012](../adr/ADR-SEC-012-user-facing-security-transparency.md)** — no raw tokens, secrets or audit internals, and inferred facts are shown as inferences. Device and location are guesses from user-agent and IP; presenting them as certainty teaches users to trust a spoofable signal.

## Related

| | |
|---|---|
| [`bff/`](../bff) | The Spring Boot service this app talks to |
| [`backend/`](../backend) | Authorization Server and Resource Servers |
