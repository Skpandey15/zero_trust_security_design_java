# ADR-SEC-023 — Security Telemetry Schema and Incident Revocation

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-03 |
| **Consolidates** | ADR-SEC-011 (former numbering) |
| **Related** | [ADR-SEC-009](ADR-SEC-009-security-epoch-model.md), [ADR-SEC-010](ADR-SEC-010-refresh-token-rotation-reuse.md), [ADR-SEC-024](ADR-SEC-024-fail-open-fail-closed-matrix.md) |

## Context

Detection that cannot be acted on is not detection. Most security logging fails in one of two ways: it records that a request happened without recording why it was allowed, or it produces so much undifferentiated volume that the signal is unreachable.

The specific question an incident asks is "why was this permitted?" — which requires the decision, the policy and version behind it, the subject, the workload and a correlation identifier. A log line saying `200 GET /payments/987` answers none of it.

## Decision

**Structured, correlated security events with a defined schema, routed to SIEM, wired to automated response.**

| Event | Minimum fields |
|---|---|
| Authentication | subject, session, device, method and assurance level, result, reason, trace id |
| Authorization | subject or workload, action, resource, decision, policy id and version, reason |
| Token | `jti` / `sid` / family metadata, issuance, refresh, reuse, revocation — **never token values** |
| Admin | actor, target, before/after intent, approval or change reference |
| Workload | SPIFFE identity, destination identity, operation, mTLS or authz failure |
| Runtime | container, process, file and network signals correlated to deployment digest and workload identity |

- **Every privileged mutation is attributable** to subject, session, workload, policy version, request and trace id, and target resource.
- Correlation identifiers propagate across services and appear on every line produced during a request.
- **PII discipline:** passwords, OTP codes, token values, secrets and query strings are never logged. Emails and IPs appear only where operationally necessary; the audit tables remain the authoritative forensic record.
- Routine allows may be sampled; **privileged decisions are retained in full.**
- High-signal events drive automated response: refresh-token reuse pages immediately and triggers family revocation; bursts of lockouts or throttling raise an attack-in-progress alert.
- **Application authorization never depends synchronously on SIEM availability.** Events buffer; the request path does not block ([ADR-SEC-024](ADR-SEC-024-fail-open-fail-closed-matrix.md)).

## Alternatives considered

**Application logs only, no schema.** Rejected — unqueryable at incident time, and the "why was this allowed" field is never there when needed.

**Log everything at full fidelity.** Rejected on cost and signal-to-noise; sampling routine allows while retaining privileged decisions keeps both.

**Synchronous SIEM write on the request path.** Rejected — it makes the SIEM an availability dependency of every authenticated request.

## Consequences

**Positive.** Incidents can be reconstructed, including why access was granted. Automated revocation is driven by proven-compromise signals rather than human triage latency. Alert rules have stable field names to bind to.

**Negative.** Schema changes become a coordination problem across producers and consumers. Retention of privileged decisions has a storage cost. Buffering means bounded event loss in a severe outage — bounded, and accepted, rather than blocking requests.

## Verification

`recordsCorrelatedSecurityDecisionEvent` gates the authorization path. Token values never appear in any log. Refresh-token reuse triggers both the alert and the family revocation. Tabletop exercises for token theft and service compromise are completed (§27 WP-BE-03 exit).

## References
§2.9 Logging and observability, §14 Security observability and incident response, §3.2 Metrics
