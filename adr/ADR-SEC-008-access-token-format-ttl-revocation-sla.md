# ADR-SEC-008 — Access-Token Format, TTL and Revocation SLA

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-01.1 |
| **Consolidates** | ADR-SEC-002, part of ADR-006 (former numbering) |
| **Related** | [ADR-SEC-009](ADR-SEC-009-security-epoch-model.md), [ADR-SEC-016](ADR-SEC-016-token-exchange-downscoping.md), [ADR-SEC-017](ADR-SEC-017-sender-constrained-tokens.md) |

## Context

An access token is a bearer credential: whoever holds it can use it. Its format determines who can validate it and at what cost; its lifetime determines the exposure window when it leaks; its claims determine what an attacker gains.

Two failure modes matter most. First, **token substitution** — a token minted for one audience being accepted by a different API under the same issuer and key. This is not hypothetical: a platform that co-hosts an OAuth authorization server with its own APIs will, by default, have both accept each other's tokens, because the standard Spring Security issuer validator does not check audience. Minting an `aud` claim is not the same as validating one.

Second, **over-broad claims** — a token carrying every entitlement the subject holds becomes a complete credential dump when it leaks.

## Decision

**RS256 JWT following the RFC 9068 `at+jwt` access-token profile, short-lived, audience-restricted, minimal claims.**

1. **Asymmetric signing (RS256).** Resource Servers verify with the public key from JWKS and can never mint tokens, unlike a shared HMAC secret.
2. **`typ: at+jwt`** in the JOSE header, so an access token cannot be substituted for an ID token or any other JWT.
3. **Required claims:** `iss`, `aud`, `exp`, `iat`, `jti`, `sub`, `client_id`. Minimal PII; no claim that is not needed for an authorization decision.
4. **Audience is validated, not merely asserted.** Every Resource Server pins the audience it accepts. An audience validator that cannot be omitted by accident is strongly preferred to one that must be remembered.
5. **ID tokens are never accepted as API authorization tokens.**
6. **TTL is derived, not fixed by convention.** 5–10 minutes is a starting point, set per route from the threat model, the revocation SLA ([ADR-SEC-009](ADR-SEC-009-security-epoch-model.md)), latency and availability needs, and token-endpoint capacity. A 5-minute token can be too long for privileged administration and needlessly short for a low-risk machine workflow.
7. **Down-scoped per audience across service hops** rather than forwarding one broad token ([ADR-SEC-016](ADR-SEC-016-token-exchange-downscoping.md)).

## Alternatives considered

**Opaque tokens with introspection.** Exact revocation, and rejected as the default because it makes the Authorization Server a synchronous dependency of every request (§16). Retained for specific high-risk routes.

**HS256 shared secret.** Simpler key distribution; rejected because every verifier can forge tokens, so a single compromised Resource Server compromises the platform.

**Long-lived access tokens without refresh.** Rejected — maximises the exposure window and removes the rotation signal that makes theft detectable ([ADR-SEC-010](ADR-SEC-010-refresh-token-rotation-reuse.md)).

**Rich tokens carrying full entitlements.** Saves lookups; rejected because it converts a leaked token into a complete authorization dump and freezes entitlements for the token lifetime.

## Consequences

**Positive.** Offline validation keeps Resource Servers independent of the Authorization Server for signature, issuer, audience and expiry. Audience pinning blocks cross-API substitution. The `at+jwt` profile blocks token-type confusion.

**Negative.** Adopting the profile is a **coordinated issuer-and-validator change**: a validator enforcing `at+jwt` rejects every token minted without the header and `client_id`, so issuance must lead deployment or run a bounded dual-accept window. Short TTLs push load onto the token endpoint. Minimal claims mean Resource Servers look up what they need.

## Verification

Gated by WP-BE-01 (§27.6): `rejectsTokenWithWrongIssuer`, `rejectsTokenWithWrongAudience`, `rejectsExpiredToken`, `rejectsTokenWithWrongTypHeader`, `rejectsTokenMissingClientId`, `rejectsUnsignedOrInvalidSignatureToken`. The audience test must assert the failure is *about* the audience — a token rejected for an unrelated reason passes a naive assertion while the invariant is absent.

## References
§2.3 Access-token contract, §6 Token design, §25.1 RFC 9068 profile · RFC 9068 · RFC 9700
