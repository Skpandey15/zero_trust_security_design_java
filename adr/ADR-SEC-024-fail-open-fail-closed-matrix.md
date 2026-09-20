# ADR-SEC-024 — Fail-Open / Fail-Closed Matrix for Security Dependencies

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | Cross-cutting — constrains every WP |
| **Consolidates** | ADR-SEC-012 (former numbering) |
| **Related** | [ADR-SEC-001](ADR-SEC-001-zero-trust-boundaries.md), [ADR-SEC-014](ADR-SEC-014-pdp-pep-architecture.md), [ADR-SEC-009](ADR-SEC-009-security-epoch-model.md) |

## Context

Every control added by this register is also a dependency. The Authorization Server, the PDP, the risk engine, SPIRE, KMS and the SIEM are each now on a path that previously did not need them. Left unexamined, a zero-trust programme builds an enterprise-wide single point of failure and calls it security.

The failure is usually discovered during an outage, when someone makes the fail-open decision live, under pressure, without a policy — and the platform either denies everything or, worse, quietly starts allowing everything.

## Decision

**Every security dependency has a documented, pre-decided failure behaviour, classified by the risk of the operation. Nothing is decided during the incident.**

| Dependency unavailable | Behaviour |
|---|---|
| Identity Provider | Existing short-lived sessions may continue within explicitly defined limits. **No new authentication and no privilege elevation.** |
| PDP | **Fail closed for privileged writes.** Signed, versioned cached decisions may serve explicitly classified low-risk reads. |
| Risk engine | **UNKNOWN is never interpreted as LOW.** Conservative fallback policy applies. |
| SPIRE / workload identity renewal | Grace only within certificate validity and operational policy; alert before expiry. **No insecure plaintext fallback.** |
| KMS / HSM | Operations requiring key use fail closed; cached verification material may serve within its defined lifetime. |
| SIEM | Events buffer and queue. Authorization does not depend synchronously on SIEM availability. |

Principles behind the table:

- **Classify by operation risk, not by component.** The same dependency may fail closed for a privileged write and degrade gracefully for a low-risk read.
- **Degradation is explicit and bounded**, expressed as a TTL or a validity window, never as indefinite best-effort.
- **Silence is not a signal.** A missing answer is not a permit. This is the concrete form of [ADR-SEC-001](ADR-SEC-001-zero-trust-boundaries.md).
- **Failure paths are exercised**, not assumed. A fail-closed path that has never been run is a hypothesis.

## Alternatives considered

**Fail open everywhere for availability.** Rejected — it converts any dependency outage into a full authorization bypass, and outages are exactly when attacks are noticed.

**Fail closed everywhere, no exceptions.** Rejected as operationally unusable: it makes every security component a total-platform outage, which creates pressure to disable the controls entirely.

**Decide during the incident.** The unstated default in most systems. Rejected — the decision then gets made by whoever is on call, under pressure, without context, and is rarely recorded.

## Consequences

**Positive.** Zero trust does not become a single point of failure. Behaviour under partial failure is predictable and reviewable in advance. Responders execute a decision rather than making one.

**Negative.** Some operations become unavailable during a security-dependency outage, by design, and this will be escalated as an incident even when it is correct behaviour. Every new dependency requires a matrix entry, which is ongoing work. Graceful degradation paths are themselves code that must be tested.

## Verification

Each row is exercised in chaos or game-day testing rather than reasoned about. `deniesPolicyDecisionOnPrivilegedWriteWhenPdpUnavailable` gates the PDP row specifically. Degraded-mode behaviour is asserted to expire at its stated bound.

## References
§16 Availability and fail-secure design, §24.4 resilience budget, §20 review checklist
