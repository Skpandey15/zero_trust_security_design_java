# ADR-SEC-007 — BFF and Browser Token Custody

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-UI-01 |
| **Consolidates** | ADR-SEC-001, ADR-005 (former numbering) |
| **Related** | [ADR-SEC-003](ADR-SEC-003-oidc-authorization-code-pkce.md), [ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md), [ADR-SEC-011](ADR-SEC-011-session-device-revocation-model.md), [ADR-SEC-012](ADR-SEC-012-user-facing-security-transparency.md) |

## Context

A browser-based client needs to call protected APIs on behalf of a signed-in user. Something has to hold the OAuth credentials, and where they are held determines what an attacker gets when — not if — the front end is compromised.

The dominant SPA pattern stores the access token, and often the refresh token, in `localStorage` or `sessionStorage`. This is convenient and it is why the pattern spread. It also means any script executing in the page origin can read both. A single cross-site scripting defect, a compromised npm dependency, a malicious browser extension with host permissions, or a tag-manager injection gives the attacker the tokens themselves — bearer credentials that work from the attacker's own machine, outside the victim's browser, for as long as the refresh token lives. The user cannot see it, the server cannot distinguish the sessions, and revocation depends on someone noticing.

Refresh tokens make this materially worse than access tokens. A 10-minute access token bounds the damage to 10 minutes. A 7-day refresh token in `localStorage` is a 7-day account takeover that survives the victim closing the tab, and rotation does not help: the attacker rotates too, and the legitimate client is the one that gets locked out by reuse detection.

The platform's threat model (§15) treats XSS as a realistic event rather than a defect to be eliminated. A modern front end has a large transitive dependency tree and a long-lived build supply chain; "we will not have XSS" is not a control. The question this ADR answers is what an attacker gains when script execution in the page is achieved.

The constraint pulling the other way is that a browser-only architecture is simpler to build and deploy. Introducing a server component for the front end adds a deployable, a session store, and a request hop on every API call.

## Decision

**The browser never receives, stores, or transmits an OAuth access or refresh token. A Backend For Frontend (BFF) owns all OAuth credentials; the browser holds only an opaque session cookie.**

Specifically:

1. The React application authenticates against the BFF, not against the Authorization Server directly. It has no OAuth client credentials and does not parse tokens.
2. The BFF is a confidential OAuth client. It performs the Authorization Code + PKCE S256 flow ([ADR-SEC-003](ADR-SEC-003-oidc-authorization-code-pkce.md)), exchanges the code, and retains the resulting tokens server-side.
3. The browser receives a single opaque session identifier as a cookie with `HttpOnly`, `Secure`, and `SameSite` set. `HttpOnly` is the load-bearing attribute: it removes the credential from JavaScript's reach entirely.
4. The BFF attaches an audience-restricted access token when forwarding to Resource Servers. Tokens travel only between the BFF and the backend, never across the browser boundary.
5. Session state — the mapping from cookie to tokens, user, device and assurance level — lives in the server-side session store ([ADR-SEC-011](ADR-SEC-011-session-device-revocation-model.md)).
6. **CSRF protection is mandatory and separate.** Cookie authentication is ambient: the browser attaches the cookie to qualifying cross-site requests without the page's involvement. `SameSite` is defence in depth, not the control. The BFF enforces an explicit anti-CSRF token on every state-changing request.

## Alternatives considered

### A. Tokens in `localStorage` / `sessionStorage`

The common SPA pattern. No server component, trivial to implement, works with any static host.

**Rejected because** it makes any script execution in the origin equivalent to full credential theft, and exfiltrated tokens are replayable off-device. `sessionStorage` narrows the window to the tab's lifetime but does not change the failure mode. This trades the platform's primary browser threat for build-time convenience.

### B. Access token in memory, refresh token in an `HttpOnly` cookie

A real improvement over A, and a defensible position. The long-lived credential is out of JavaScript's reach; only the short-lived one is exposed, and only for its lifetime.

**Rejected because** it leaves the access token readable by injected script, so an attacker still gets a bearer credential usable off-device for its full TTL, and can silently refresh while the page is open. It also splits credential custody across two mechanisms with different lifetimes and revocation paths, which complicates [ADR-SEC-009](ADR-SEC-009-security-epoch-model.md) and [ADR-SEC-011](ADR-SEC-011-session-device-revocation-model.md). Accepted as a fallback only for clients where a BFF genuinely cannot be deployed; not the platform default.

### C. Service worker token custody

Hold tokens in a service worker and have it attach the `Authorization` header, keeping them out of page scripts.

**Rejected because** the isolation is weaker than it appears: an attacker with script execution can often register or replace a service worker, or simply make the worker issue the calls for them, achieving the same effect without ever reading the token. It also fails on first load before the worker is active, and adds an upgrade and cache-invalidation problem to the security-critical path.

### D. Sender-constrained tokens (DPoP) held in the browser

Bind tokens to a key held in non-extractable `CryptoKey` storage so a stolen token cannot be replayed elsewhere.

**Rejected as a substitute**, retained as complementary. DPoP raises the cost of exfiltration meaningfully, but script running in the origin can still use the key to sign requests in place. It defeats off-device replay, not on-device abuse. Scope for adoption is [ADR-SEC-017](ADR-SEC-017-sender-constrained-tokens.md).

## Consequences

### Positive

- An XSS defect no longer yields a portable credential. The attacker can act through the victim's session while the page is open — which CSP, output encoding and action-level authorization must address — but cannot walk away with a token that works from their own machine.
- Revocation becomes immediate and complete: terminating the server-side session cuts API access at once, without waiting for an access token to expire.
- The browser holds no material worth stealing, so `localStorage`, browser sync, memory dumps and extension access stop being credential-exposure surfaces.
- Session, device and assurance state is server-authoritative, which is what [ADR-SEC-011](ADR-SEC-011-session-device-revocation-model.md) and §24.4 require and what a browser-held token cannot provide.
- The Authorization Server sees a confidential client rather than a public one, so client authentication is real.

### Negative

- **A new deployable on the critical path.** The BFF is an availability dependency for the entire front end and must be sized, monitored and scaled accordingly.
- **The BFF becomes a high-value target.** It holds tokens for every active user. It needs the same hardening posture as the Authorization Server, not the posture of a web tier.
- **Server-side session state.** The stateless-JWT property is deliberately given up at the browser boundary. Session storage must be shared across replicas, or the BFF cannot scale horizontally — the single-replica trap noted in §27.8.
- **CSRF is now in scope.** Moving from an `Authorization` header to a cookie reintroduces a class of attack that bearer tokens had removed. This is a genuine cost, paid deliberately, and mitigated by explicit anti-CSRF tokens rather than by `SameSite` alone.
- **One extra hop** on every API call, with its latency and failure modes.

### Neutral

- The front end becomes simpler: no token parsing, refresh scheduling, expiry handling or storage decisions. Most of the OAuth complexity leaves the browser.
- Native and machine clients are unaffected; they remain direct OAuth clients and do not use the BFF.

## Verification

Gated by WP-UI-01, per §27.6:

- No OAuth access or refresh token is reachable from page JavaScript. Asserted by inspecting `localStorage`, `sessionStorage`, IndexedDB and `document.cookie` after a complete login, and by confirming the session cookie carries `HttpOnly`, `Secure` and `SameSite`.
- Every state-changing BFF route rejects a request carrying a valid session cookie but no valid anti-CSRF token.
- Logout invalidates the server-side session such that a replayed cookie fails, rather than relying on cookie expiry.
- Token values never appear in BFF access logs, error responses or client-visible payloads.

## References

- §5.1 Login flow (BFF and PKCE), §5.2 Session record, §27.1 WP-UI-01 scope
- §15 Threat model — XSS token theft row
- RFC 9700, OAuth 2.0 Security Best Current Practice
