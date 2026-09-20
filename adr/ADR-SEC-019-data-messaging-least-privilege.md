# ADR-SEC-019 — Database, Kafka and Cache Least-Privilege Identities

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-03 |
| **Consolidates** | part of ADR-010 (former numbering) |
| **Related** | [ADR-SEC-015](ADR-SEC-015-tenant-isolation-membership.md), [ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md) |

## Context

Application-layer authorization is worth little if every service connects to the database as the same high-privilege user. A single SQL injection or compromised pod then reads and writes everything, and the audit trail attributes it to a shared account that tells you nothing.

The same applies to messaging: a service that can produce to any topic can forge events other services trust, and a service that can consume any topic can read data it has no business seeing.

## Decision

**One identity per service per data system, scoped to what that service actually uses.**

- **PostgreSQL:** per-service database user with privileges on only its own schema and objects. No shared superuser. Migrations run under a separate elevated identity used only for migration, never by the application at runtime.
- **Kafka:** per-service ACLs on specific topics and consumer groups, with produce, consume and admin rights granted separately. Schema governance applies; sensitive payloads are avoided unless necessary.
- **Cache (Redis):** private network path plus authentication and TLS, key namespacing and ACLs, short TTLs. The cache is not authoritative authorization state without an explicit consistency design — see the TTL-as-revocation-bound problem in [ADR-SEC-009](ADR-SEC-009-security-epoch-model.md).
- **Object storage and backups:** separate identities, encryption, immutability and retention where required, tested restores, and audited access.
- Sensitive-field encryption is applied where the threat model requires it, with key version metadata to support rotation ([ADR-SEC-020](ADR-SEC-020-secrets-kms-key-rotation.md)).

## Alternatives considered

**Shared application database user.** Operationally simple; rejected — it makes every service's compromise equivalent to total data compromise and destroys attribution.

**Application-layer authorization only.** Rejected — it assumes the application is never bypassed, which injection, deserialisation flaws and direct pod access all disprove.

**Row-level security as the primary control.** Adopted as defence in depth, rejected as primary; see [ADR-SEC-015](ADR-SEC-015-tenant-isolation-membership.md) on pooled-connection session variables.

## Consequences

**Positive.** Blast radius of a compromised service is bounded by that service's grants. Database and broker audit logs are attributable. Migration privileges are not available at runtime.

**Negative.** More identities and grants to provision, rotate and review. Least-privilege grant sets drift as features change and need periodic verification. Cross-service data access must be designed as an API rather than a shared table.

## Verification

Per-service least-privilege matrices are verified, and a rotation game day is completed (§27 WP-BE-03 exit). A service attempting access outside its grants is refused by the data system, not only by the application.

## References
§12 Data and Kafka security, §10 platform controls, §27.1 WP-BE-03 scope
