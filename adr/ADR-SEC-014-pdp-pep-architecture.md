# ADR-SEC-014 — PDP / PEP Authorization Architecture

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-02 |
| **Consolidates** | ADR-008 (former numbering) |
| **Related** | [ADR-SEC-013](ADR-SEC-013-rbac-abac-domain-authorization.md), [ADR-SEC-024](ADR-SEC-024-fail-open-fail-closed-matrix.md) |

## Context

Authorization logic embedded in every service drifts. The same rule gets implemented three times with three subtle differences, changes require a coordinated release, and nobody can answer which policy version allowed a given decision six months ago.

Externalising policy to a decision point fixes governance and introduces a dependency on the request path. That dependency has two failure modes, and most designs only plan for one: the PDP being *down*, which is obvious and detectable, and the PDP being *slow*, which is far more common and degrades the whole platform without failing anything.

## Decision

**Policy Enforcement Points in every service; a Policy Decision Point for centrally governed rules; domain invariants stay local.**

- The PEP is the service. It gathers subject, action, resource, tenant and context, calls the PDP where a rule is centrally governed, and enforces the result.
- The PDP contract returns `decision` (`ALLOW` / `DENY` / `STEP_UP`), `policyId`, `policyVersion`, `obligations` and `reasonCode`. The version is recorded in the audit trail.
- **Latency is budgeted, not assumed:** p95 under 15 ms, p99 under 30 ms in-region, with one policy call per protected boundary where possible. Fan-out across service hops must be modelled so authorization calls do not multiply uncontrolled.
- Decision caching is permitted with a key covering subject, action, resource and context, TTL 0–30 s by policy sensitivity. High-risk decisions are not blanket-cached.
- **Slowness is engineered for separately from unavailability:** timeouts, circuit breaking, bounded retries, connection pooling, and mandatory telemetry on cache hit ratio, evaluation latency and fallback rate.
- On PDP unavailability: **fail closed for privileged writes.** Signed, versioned cached decisions may serve explicitly classified low-risk reads ([ADR-SEC-024](ADR-SEC-024-fail-open-fail-closed-matrix.md)).

## Alternatives considered

**All policy in application code.** No new dependency; rejected on drift, auditability and release coupling.

**All policy in the PDP, including domain invariants.** Rejected — see [ADR-SEC-013](ADR-SEC-013-rbac-abac-domain-authorization.md); invariants must survive PDP outage.

**PDP as a sidecar library rather than a service.** Lower latency and no network dependency; a legitimate option, deferred rather than rejected. It trades the latency problem for a policy-distribution and version-skew problem, which is the better trade only once policy change frequency is known.

## Consequences

**Positive.** Policy is governed, versioned and auditable in one place. Decisions carry the policy version that produced them. Rule changes need not ship a service release.

**Negative.** A synchronous dependency on the authorization path, with the latency budget and failure engineering that requires. Cache TTL becomes the staleness bound on entitlement changes. Operating a PDP is its own workload.

## Verification

`deniesPolicyDecisionOnPrivilegedWriteWhenPdpUnavailable` and `recordsCorrelatedSecurityDecisionEvent` gate here. PDP latency is load-tested against the budget, not only functionally tested.

## References
§7.1 PEP/PDP contract, §16 Availability, §24.4 Authorization performance and resilience budget
