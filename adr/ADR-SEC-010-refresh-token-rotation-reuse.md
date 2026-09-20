# ADR-SEC-010 — Refresh-Token Rotation and Reuse Response

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-01.1 |
| **Consolidates** | ADR-SEC-004, part of ADR-006 (former numbering) |
| **Related** | [ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md), [ADR-SEC-009](ADR-SEC-009-security-epoch-model.md), [ADR-SEC-011](ADR-SEC-011-session-device-revocation-model.md), [ADR-SEC-023](ADR-SEC-023-security-telemetry-incident-revocation.md) |

## Context

Short access-token lifetimes ([ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md)) require a longer-lived credential to obtain new ones without re-prompting the user. That credential is the highest-value secret the platform issues to a client: possession of a refresh token means the ability to mint access tokens for as long as it remains valid.

A static refresh token has no theft signal. If it is exfiltrated — from a log, a backup, a proxy, a compromised device — the attacker uses it alongside the legitimate client, indefinitely, and nothing distinguishes the two. The platform learns about the compromise from its consequences.

Rotation changes that. If each refresh consumes the presented token and issues a new one, then a stolen token is only useful until the legitimate client next refreshes, and a *used* token being presented again is evidence: under normal operation it never happens. That evidence is the entire point — rotation without acting on the signal converts theft-detection into a shorter theft window.

Two details decide whether the mechanism works or merely appears to:

**Concurrency.** Two requests may present the same valid token simultaneously — a tab duplicated, a retry after a timeout, a mobile client resuming. A naive `if (token.isActive()) { revoke(); issue(); }` is check-then-act: both requests read "active", both proceed, both succeed. The detection has a race, and worse, a legitimate double-refresh looks identical to theft.

**Transactionality.** Reuse detection must revoke a family and then reject the request. If the revocation participates in the transaction that the rejection rolls back, the revocation is undone. The system logs an alert, tells the attacker to sign in again, and leaves every token in the family live. This failure is silent and passes any test that only asserts the 401.

## Decision

**Refresh tokens are opaque, stored hashed, rotated on every use, and grouped into families. Presenting an already-rotated token revokes the entire family.**

1. **Opaque and high-entropy.** 48 bytes from a CSPRNG, URL-safe encoded. Not a JWT — there is nothing a client should read, and no offline validation is wanted.
2. **Hashed at rest.** Only SHA-256 of the raw value is persisted, under a unique index. A database disclosure yields no usable credential. No salt or work factor is used or needed: the input already carries 384 bits of entropy, so the preimage space defeats brute force and per-row salting buys nothing against it.
3. **One family per login.** Every token descending from a single authentication shares a `family_id`, which is the unit of revocation.
4. **Rotation is claimed atomically.** The presented token is consumed with a single conditional update — revoke *where the row is currently not revoked* — and the affected row count decides the outcome. Exactly one concurrent caller can win. Losing the race is treated as reuse.
5. **Reuse revokes the family.** Presenting a token already marked rotated revokes every token sharing its `family_id`, and the request is rejected. The user must re-authenticate.
6. **Family revocation runs in its own transaction.** It must commit independently of the rejection that follows, or the rollback undoes it.
7. **Expiry is not theft.** A token that was never rotated and is simply past its TTL is a benign expiry: reject the request, do not revoke the family, do not raise an incident.
8. **Reuse is a security event, not a log line.** It is proven credential compromise and pages, per [ADR-SEC-023](ADR-SEC-023-security-telemetry-incident-revocation.md).

## Alternatives considered

### A. Long-lived static refresh tokens

Issue once, accept until expiry.

**Rejected because** it provides no theft signal at all and makes the exposure window equal to the token lifetime. Every compromise is silent and open-ended.

### B. Rotation without reuse detection

Rotate on each use, but treat a stale token as an ordinary invalid credential.

**Rejected because** it discards the signal rotation exists to produce. The stolen token stops working once the legitimate client refreshes — but the attacker who refreshes *first* takes over the family, and the legitimate client's next refresh is the one that fails. Without reuse detection the platform cannot tell which of the two it just locked out, and the theft is never recorded.

### C. Revoke only the presented token on reuse

On detecting reuse, invalidate that token and let the rest of the family stand.

**Rejected because** it fails against the realistic scenario. Reuse means two parties hold tokens from one lineage; one of them is an attacker, and the platform cannot tell which. Revoking only the presented token leaves the other party — quite possibly the attacker, if they rotated first — in possession of a working credential. The family is the correct blast radius precisely because the ambiguity cannot be resolved in the moment.

### D. Sender-constrained refresh tokens (DPoP / mTLS)

Bind the refresh token to a client key so a stolen token cannot be redeemed elsewhere.

**Deferred, not rejected.** This is strictly stronger and prevents rather than detects. It requires client-side key management and ecosystem support that varies by platform. Scope and sequencing are [ADR-SEC-017](ADR-SEC-017-sender-constrained-tokens.md); for browser clients, [ADR-SEC-007](ADR-SEC-007-bff-and-browser-token-custody.md) already keeps the refresh token out of the browser entirely, which addresses the dominant theft path.

## Consequences

### Positive

- Token theft produces a detectable, actionable event rather than silent ongoing access.
- The exposure window collapses to the interval before the next legitimate refresh, instead of the token's full lifetime.
- Database disclosure does not yield usable refresh credentials.
- Family-level revocation gives incident response a single, correctly-scoped action.
- `auth_refresh_token_reuse_total` is a high-signal alert: under correct operation it is zero, so any non-zero value means either proven theft or a client bug worth finding.

### Negative

- **Legitimate concurrent refresh can trigger detection.** A duplicated tab, an aggressive retry, or a client resuming from sleep can present the same token twice and get the family revoked, logging a real user out. This is a genuine false-positive cost, accepted because the alternative — tolerating replay — removes the signal. Clients must serialise refresh; a small grace window is a tuning option, but every widening of it is a widening of the attacker's window too, and must be decided deliberately.
- **Write on every refresh.** Rotation makes refresh a write path, with the contention and storage growth that implies. Expired and revoked rows need a retention policy.
- **State is required.** Refresh validation is not offline; it is a database lookup by hash on every refresh.
- **Two subtle implementation traps** that a passing test suite will not reveal: a non-atomic claim, and a family revocation that rolls back with the rejecting transaction. Both were live defects in the reference implementation before they were found, and both are invisible to any test that asserts only the response status.

### Neutral

- Reuse detection cannot distinguish attacker from victim, and does not try. Revoking the family and forcing re-authentication is the safe response under that ambiguity.

## Verification

Gated by WP-BE-01, per §27.6:

- Rotation succeeds and the presented token stops working.
- Replaying a rotated token revokes the whole family — asserted by confirming that a *different, still-unused* token from that family is also rejected afterwards. Asserting only the 401 on the replayed token passes even when family revocation silently rolled back.
- A never-rotated, expired token is rejected **without** family revocation.
- Concurrent refresh with the same token yields exactly one success.
- Reuse emits the security event and increments the counter.

## References

- §2.5 Refresh rotation and theft detection, §6 Token design, §14 Incident response
- §15 Threat model — refresh-token theft row
- RFC 9700, OAuth 2.0 Security Best Current Practice — refresh token rotation and replay detection
