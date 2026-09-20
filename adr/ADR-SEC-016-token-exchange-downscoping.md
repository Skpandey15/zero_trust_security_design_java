# ADR-SEC-016 — Service-to-Service Token Exchange and Downscoping

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-02 |
| **Consolidates** | ADR-SEC-007 (former numbering) |
| **Related** | [ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md), [ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md) |

## Context

When service A calls service B on a user's behalf, the easy option is to forward the token it received. That token was minted for A's audience and carries the subject's full entitlements, so forwarding it means B accepts a credential not intended for it, and every service in the chain holds a credential valid everywhere in the chain. One compromised service in a five-hop path holds a token usable against all five.

Token exchange fixes the audience and scope problem, and introduces cost: an extra round trip per hop, and a revocation limitation — an exchanged token chain cannot be revoked the way a refresh-token chain can, so exchange is not an instant global revocation mechanism.

## Decision

**Obtain an audience-specific, down-scoped token for the target service rather than propagating a broad user token.**

- Each hop acquires a token whose `aud` is the next service and whose scope is the minimum that call needs.
- Delegation is explicit. A service acting on a user's behalf carries that fact in the token; it does not silently impersonate.
- **Exchange is not free and is not used reflexively.** Internal fan-out where the callee needs no user context uses workload identity ([ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md)) instead. Exchange is for genuine delegation or downscoping, per §24.4.
- Because an exchanged chain is not instantly revocable, exchanged tokens are short-lived and revocation relies on the security epoch ([ADR-SEC-009](ADR-SEC-009-security-epoch-model.md)) plus TTL, not on chain revocation.
- No silent fallback to a broader token when exchange fails. Failure is a failure.

## Alternatives considered

**Forward the original token.** Zero cost; rejected — it is precisely the substitution [ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md) blocks, and it maximises blast radius per compromised service.

**Workload identity only, dropping user context.** Correct for many internal calls and adopted for those. Rejected as universal: it loses the subject, so the callee cannot make user-scoped authorization decisions or produce attributable audit.

**A single broad token with per-service filtering at the callee.** Rejected — relies on every callee filtering correctly, which is the assumption that fails.

## Consequences

**Positive.** A compromised service holds credentials valid only for what it legitimately calls. Audience validation is meaningful because audiences differ. Delegation is auditable.

**Negative.** A round trip per exchange, with latency and Authorization Server load — §24.4 requires fan-out to be modelled so this does not multiply. Exchanged chains are not instantly revocable, so TTL discipline matters more.

## Verification

A token minted for service B is rejected by service C. Exchange failure does not fall back to the original token. Delegation is visible in the audit record.

## References
§2 Keycloak token-exchange finding, §6 Token design, §24.4 latency budget
