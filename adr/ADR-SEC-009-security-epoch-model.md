# ADR-SEC-009 — `token_valid_after` / Security-Epoch Model

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-01.1 |
| **Consolidates** | ADR-SEC-003, part of ADR-006 (former numbering) |
| **Related** | [ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md), [ADR-SEC-010](ADR-SEC-010-refresh-token-rotation-reuse.md), [ADR-SEC-011](ADR-SEC-011-session-device-revocation-model.md), [ADR-SEC-024](ADR-SEC-024-fail-open-fail-closed-matrix.md) |

## Context

A signed JWT is, by construction, valid until it expires. Verification is offline: signature, issuer, audience and expiry are all checkable from the token and the public key, with no call to the issuer. That property is why JWTs scale, and it is also the standard criticism of them — nothing in the token reflects what has happened since it was minted.

That gap matters at exactly the moments it must not. When a user clicks "log out everywhere" after losing a laptop, when an administrator disables a compromised account, when a password is reset following a phishing report, or when MFA is enrolled and the trust level of the session changes, the expectation is that access stops. With plain offline validation, it stops when the access token expires. A 10-minute TTL therefore means a 10-minute window in which a known-compromised credential still works, and no operator action can close it.

Shortening the TTL narrows the window but never closes it, and pays for the reduction with token-endpoint load on every client. Discarding JWTs in favour of opaque tokens with introspection closes it completely, at the cost of a synchronous call to the Authorization Server on every request — which makes that server a hard availability dependency for every API in the platform (§16).

This decision is about how a stateless token participates in a revocation event. The related question of how fast that revocation must take effect, and what it costs to check, is bounded by §25.2.

## Decision

**Each user carries a `token_valid_after` watermark. Any access token issued before that instant is rejected on every request, regardless of its expiry.**

1. `user_security_state.token_valid_after` is a timestamp, initially null, stored server-side.
2. Resource Servers add a validator to the decoder chain that compares the token's `iat` against the subject's current watermark and rejects when `iat < token_valid_after`.
3. The watermark is advanced by any event that invalidates existing sessions: logout-all-devices, account disable or suspension, password or credential change, MFA enrolment or factor change, recovery completion at any assurance tier, and administrative revocation during incident response.
4. **Comparison is at second granularity.** JWT `iat` is expressed in whole epoch seconds. A token minted in the same second the watermark is set must be treated as still valid, or a user who logs out and immediately logs back in is rejected by their own logout.
5. A companion `credential_version` counter covers cases where a monotonic timestamp is not sufficient to express which generation of credentials a token belongs to.
6. The lookup that backs this check is **not** part of "local JWT validation" for the purposes of the §25.2 latency budget. It is a state read, budgeted and instrumented separately.

## Alternatives considered

### A. Short TTL alone

Set the access-token lifetime low enough — 60 to 120 seconds — that the revocation window is acceptable without any state check.

**Rejected because** it converts a security requirement into a load problem and still does not reach zero. Every client refreshes constantly, making the token endpoint a throughput bottleneck and a single point of failure; an outage there logs the entire platform out within two minutes. It also gives no answer at all to account disable, where "60 seconds of continued access for a terminated employee" is a policy statement nobody intends to make.

### B. Opaque tokens with introspection on every request

Abandon offline validation. Resource Servers call the Authorization Server to validate each token.

**Rejected as the default**, retained for specific high-risk routes. Revocation becomes exact, which is genuinely attractive. The price is that every protected request in the platform depends synchronously on the Authorization Server being reachable and fast — the enterprise-wide single point of failure §16 exists to prevent. Reserved for operations where the revocation SLA is measured in seconds and the request volume is low enough to bear it.

### C. Per-token denylist (`jti` blocklist)

Record revoked token identifiers and check each incoming `jti` against the list.

**Rejected because** it revokes tokens, not trust. The operator's intent in every triggering event is "this user's existing sessions are no longer valid", which requires enumerating and listing every outstanding token for that user — the Authorization Server must therefore track all issued tokens, giving up statelessness anyway, and get the enumeration right under concurrency. A per-user watermark expresses the same intent in a single comparison against one row, and cannot miss a token it never knew about.

### D. Push-based revocation to Resource Servers

Broadcast revocation events so each Resource Server maintains a local view.

**Rejected as the sole mechanism**, adopted as an optimisation. Push alone is unsafe: a Resource Server that misses an event, starts cold, or partitions from the bus fails open silently, and nothing in the request path detects it. Push plus a bounded TTL over the authoritative read is the target shape — push for latency, TTL as the safety net that bounds how wrong a stale cache can be.

## Consequences

### Positive

- Access tokens become revocable mid-life. Logout-all, disable, credential change and incident response take effect against live tokens rather than at expiry.
- Revocation intent is expressed once per user, not per token. There is no enumeration step to get wrong, and no token can escape by being unknown to the revocation path.
- One row, one comparison — cheap to reason about, and trivially correct under concurrent token issuance, because an advancing watermark invalidates everything before it without needing to know what exists.
- Access-token TTL can be set from the threat model rather than pushed to an extreme to compensate for the absence of revocation ([ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md)).

### Negative

- **Offline validation is given up.** Every authenticated request now reads user security state. This is the central cost, and it is real: it introduces a database dependency into a path that was previously pure computation.
- **Cache TTL becomes revocation latency.** Caching the state read is necessary at scale, and the moment it is cached, the effective revocation SLA is at least `cache TTL + propagation time`. The cache setting is therefore a security control, not a performance knob, and §25.2 requires it to be documented as such.
- **Revocation is all-or-nothing per user.** The watermark cannot revoke one session while sparing another; that granularity belongs to [ADR-SEC-011](ADR-SEC-011-session-device-revocation-model.md) and the session store. "Revoke this one device" must not be implemented by advancing the watermark.
- **Clock sensitivity.** Comparison against `iat` assumes the issuer's clock is sane. Significant skew between issuer and the watermark writer can reject valid tokens or accept invalidated ones within the skew window.
- **Second granularity is a deliberate one-second hole.** A token minted in the same second as the watermark survives. This is accepted knowingly: the alternative breaks immediate re-login, and one second is not a meaningful attack window relative to the events that trigger revocation.

### Neutral

- Tokens issued by the OAuth authorization server for other audiences are outside this mechanism unless they carry a subject this platform owns; [ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md) governs which tokens the API boundary accepts at all.

## Verification

Gated by WP-BE-01, per §27.6:

- `rejectsRevokedOrPreSecurityEpochSession` — a token valid a moment ago is rejected once the watermark advances, with expiry untouched.
- `revocationBecomesEffectiveWithinConfiguredSla` — a time-bounded assertion that revocation propagates within the configured SLA. Correctness and latency are gated together; a control that is eventually right is not a revocation control.
- Same-second re-login succeeds: logout followed immediately by login yields a usable token.
- Cache behaviour is asserted explicitly — a stale cached state must not extend access beyond the configured TTL.

## References

- §2.3 Access-token contract, §5.3 Global revocation, §25.2 Continuous-verification latency budget
- §16 Availability and fail-secure design
