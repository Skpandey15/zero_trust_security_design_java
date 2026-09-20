# ADR-SEC-003 — OIDC Authorization Code + PKCE S256

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-01.1, WP-UI-01 |
| **Consolidates** | ADR-003 (former numbering) |
| **Related** | [ADR-SEC-007](ADR-SEC-007-bff-and-browser-token-custody.md), [ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md) |

## Context

The platform must issue tokens to browser, native and machine clients through a standards-compliant flow, so that any OIDC-aware resource server can integrate without bespoke work. The choice of grant determines what an attacker who intercepts a redirect, reads a log, or controls a competing app on the same device can do.

The implicit grant returns tokens directly in the redirect fragment, exposing them to browser history, referrer headers and any script on the page. Authorization code without PKCE is vulnerable to code interception, particularly on mobile where a malicious app can register the same custom URI scheme.

## Decision

**Authorization Code with PKCE S256 for every interactive client. Client credentials for machine-to-machine. No implicit grant, no resource owner password credentials grant.**

- PKCE is **mandatory**, including for confidential clients. The `plain` challenge method is rejected; only `S256` is accepted.
- Redirect URIs are registered and matched exactly — no wildcards, no prefix matching.
- `state` is required and validated for CSRF protection on the callback; `nonce` is required and validated in the ID token.
- Authorization codes are single-use, short-lived, and bound to the issuing client and redirect URI. Replay is detected and rejected.
- ID tokens authenticate the end-user to the client. They are **never** accepted as API authorization tokens ([ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md)).

## Alternatives considered

**Implicit grant.** Rejected — deprecated by RFC 9700 and exposes tokens in the URL fragment.

**Resource owner password credentials.** Rejected — requires the client to handle the user's password directly, which is incompatible with passkeys, MFA and step-up, and removes the Authorization Server's ability to interpose risk decisions.

**Authorization code without PKCE for confidential clients.** Defensible on paper since the client secret already binds the exchange. Rejected for uniformity: one flow, always PKCE, removes a per-client judgement call that is easy to get wrong and hard to audit.

## Consequences

**Positive.** Tokens never appear in URLs. Code interception is defeated without relying on client secrecy. Any OIDC resource server integrates via discovery and JWKS with no shared secret.

**Negative.** More round trips than implicit. PKCE requires clients to generate and retain a verifier across the redirect. Native clients need correct custom-scheme or app-link registration.

**Neutral.** The interactive login backing this flow must itself enforce MFA, lockout and step-up; a standards-compliant flow over a weak authentication is still a weak authentication.

## Verification

Authorization code replay is rejected. A mismatched or absent `state` fails the callback. A PKCE verifier that does not match the challenge fails the exchange. `plain` is refused.

## References
§5.1 Login flow, §6 Token design, §23 target architecture · RFC 9700 · OpenID FAPI 2.0
