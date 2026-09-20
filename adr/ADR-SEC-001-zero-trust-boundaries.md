# ADR-SEC-001 — Zero-Trust Security Boundaries and Trust Zones

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | Cross-cutting — constrains every WP |
| **Consolidates** | ADR-001 (former numbering) |
| **Related** | [ADR-SEC-013](ADR-SEC-013-rbac-abac-domain-authorization.md), [ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md), [ADR-SEC-024](ADR-SEC-024-fail-open-fail-closed-matrix.md) |

## Context

Perimeter models grant trust by location: inside the network, inside the VPN, inside the cluster. That assumption fails against the threat this platform actually faces — an attacker who is already inside, via a compromised pod, a stolen credential, a malicious dependency, or a phished employee. Once inside, a perimeter model offers nothing further.

The practical question is not whether to "adopt zero trust" as a label, but where the platform's trust boundaries are drawn and what is re-verified at each.

## Decision

**Trust is never inferred from network location, namespace, cluster membership, or the fact that a request arrived. Authorization is evaluated independently at five boundaries: edge/gateway, service, resource, workload, and data.**

- Each boundary verifies explicitly and denies by default. An absent policy, a failed dependency, a malformed identity or an ambiguous tenant context resolves to DENY, never ALLOW.
- Both ends of every connection are authenticated: the calling subject or workload, and the target service.
- A successful authentication is not an authorization. Passing one boundary grants nothing at the next.
- Compromise of any single identity — pod, service, database user, or human — must not yield lateral access to unrelated resources.

## Alternatives considered

**Perimeter with internal trust.** Cheaper and compatible with existing tooling. Rejected: it has no answer to an attacker already inside, which is the assumed starting condition.

**Service mesh mTLS as the authorization boundary.** Rejected as sufficient. mTLS answers *which workload is on this connection*; it does not answer *may that workload perform this action on this resource*. Both are required, and conflating them is the most common zero-trust implementation error.

**Namespace isolation as a trust boundary.** Rejected. Kubernetes namespaces are an administrative grouping, not an authentication boundary, and treating them as one produces confident but unfounded isolation claims.

## Consequences

**Positive.** Blast radius is bounded by design rather than by hope. Every access decision is attributable. The architecture degrades safely because denial is the default.

**Negative.** More checks on every path, with latency and complexity cost (§25.2 budgets this). Teams must justify access explicitly rather than inheriting it, which is slower. Security controls become availability dependencies, which §16 and [ADR-SEC-024](ADR-SEC-024-fail-open-fail-closed-matrix.md) exist to bound.

**Neutral.** This is a constraint on every other decision in the register rather than a standalone implementation.

## Verification

Every WP inherits the deny-by-default assertion: an unlisted route, an unknown identity, or an unavailable policy dependency must not produce an ALLOW. Tested per §27.6 rather than in one place.

## References
§1 Executive architecture decision, §3 Security invariants, §4 HLD trust zones · NIST SP 800-207
