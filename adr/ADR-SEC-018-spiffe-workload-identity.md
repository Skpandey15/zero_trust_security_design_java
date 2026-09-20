# ADR-SEC-018 — SPIFFE/SPIRE Workload Identity and Trust-Domain Topology

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-03 |
| **Consolidates** | ADR-SEC-006, ADR-009 (former numbering) |
| **Related** | [ADR-SEC-002](ADR-SEC-002-identity-model.md), [ADR-SEC-019](ADR-SEC-019-data-messaging-least-privilege.md) |

## Context

Service-to-service trust is commonly established by network position: the caller is in the right namespace, on the right subnet, behind the right firewall. All of these are properties of where a packet came from, not of what is running there. A compromised pod inherits every one of them.

Static shared secrets are the other common answer, and they do not rotate, appear in configuration and logs, and are indistinguishable when leaked.

## Decision

**Cryptographic workload identity via SPIFFE/SPIRE, with mTLS between workloads. Network location never establishes trust.**

- Each workload is attested by the platform and issued a SPIFFE ID with a short-lived X.509 SVID.
- Service-to-service calls use mTLS; both ends authenticate.
- Authorization policy names SPIFFE IDs, not IP ranges or namespaces.
- **mTLS is authentication, not authorization.** It answers which workload is on the connection. Whether that workload may perform an action on a resource is a separate check that must also happen — conflating the two is the most common implementation error in this area.
- Trust domains and any federation between them are explicit topology decisions, not defaults.
- SVID renewal is monitored with alerting before expiry; there is no insecure plaintext fallback when renewal fails ([ADR-SEC-024](ADR-SEC-024-fail-open-fail-closed-matrix.md)).

## Alternatives considered

**Static service credentials.** Simple; rejected — long-lived, rarely rotated, leak through configuration and logs, and grant identical access to anyone holding them.

**Network policy as the trust boundary.** Rejected — it constrains reachability, which is useful defence in depth, but a compromised pod inside the allowed set has full access.

**Service mesh mTLS treated as sufficient authorization.** Rejected explicitly; see above. Adopted for transport authentication only.

## Consequences

**Positive.** Workload identity is cryptographic, short-lived and automatically rotated. A compromised pod holds an identity scoped to that workload alone. Lateral movement requires compromising each target's policy, not just reaching it.

**Negative.** SPIRE is infrastructure to run and keep available; its failure blocks renewal and therefore, eventually, traffic. Certificate lifetimes must be tuned against renewal reliability. Debugging mTLS failures is harder than debugging plaintext.

**Neutral.** Kubernetes NetworkPolicy remains as defence in depth, not as the trust boundary.

## Verification

A workload presenting no SVID is refused. A workload with a valid SVID but no authorization policy for the operation is refused. Compromise of one workload is demonstrated not to yield access to unrelated services (§27 WP-BE-03 exit criteria).

## References
§9 Workload identity and east-west zero trust, §10 Kubernetes controls · NIST SP 800-207A
