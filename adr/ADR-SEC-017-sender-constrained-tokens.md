# ADR-SEC-017 — Sender-Constrained Token Adoption Scope (DPoP / mTLS)

| | |
|---|---|
| **Status** | Accepted — scoped adoption |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-02 (high-value APIs first) |
| **Consolidates** | ADR-SEC-008 (former numbering) |
| **Related** | [ADR-SEC-007](ADR-SEC-007-bff-and-browser-token-custody.md), [ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md) |

## Context

A bearer token works for whoever holds it. Every control around it — short TTL, audience restriction, revocation — reduces the window or the scope, but none stops a stolen token from being replayed from the attacker's machine. Sender constraining does: the token is bound to a key the client proves possession of per request, so a token without its key is inert.

The cost is operational. DPoP requires client key management and per-request proof generation. mTLS requires certificate provisioning, rotation and a TLS-terminating path that preserves the client certificate. Support varies across client platforms and intermediaries.

## Decision

**Sender-constrained tokens where replay risk justifies the complexity, starting with high-value APIs. Not a blanket requirement.**

- Adoption is risk-ordered: privileged administrative APIs and high-value financial operations first, then broader rollout as ecosystem support matures.
- mTLS binding is preferred where the platform already terminates mutual TLS ([ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md)); DPoP where clients are external or mTLS is impractical.
- **Browser clients are out of scope for this decision.** [ADR-SEC-007](ADR-SEC-007-bff-and-browser-token-custody.md) keeps tokens out of the browser entirely, which addresses the dominant theft path without per-request proofs.
- Sender constraining is layered on top of, not instead of, short TTL, audience restriction and revocation.

## Alternatives considered

**Blanket DPoP for all tokens.** Strongest; rejected on cost and ecosystem readiness — every client, SDK and intermediary must support it, and partial support fails closed in ways that look like outages.

**Bearer tokens only, relying on short TTL.** The status quo; rejected for high-value operations, where a TTL-bounded replay window is still a successful attack.

**mTLS everywhere including browsers.** Rejected — client certificate UX in browsers is poor and provisioning to end users is impractical.

## Consequences

**Positive.** Stolen tokens become unusable off-device on the routes that matter most. Complements rather than duplicates existing controls.

**Negative.** Client complexity and key management. Certificate rotation becomes an availability concern. Partial adoption means two token-handling paths coexist, which must be explicit rather than accidental.

**Neutral.** Scope expands over time; this ADR is expected to be superseded as ecosystem support broadens.

## Verification

On routes where it is enabled: a token presented without valid proof of possession is rejected. A valid token replayed from a different key fails.

## References
§6 Token design, §15 threat model — bearer-token replay row · RFC 9700 · OpenID FAPI 2.0
