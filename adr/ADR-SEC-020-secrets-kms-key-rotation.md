# ADR-SEC-020 — Secrets, KMS/HSM and Key-Rotation Lifecycle

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-03 |
| **Consolidates** | ADR-SEC-009, part of ADR-010 (former numbering) |
| **Related** | [ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md), [ADR-SEC-021](ADR-SEC-021-crypto-agility-pqc.md) |

## Context

Keys that cannot be rotated without downtime do not get rotated. That is the operative constraint: rotation policy is decided by whether rotation is survivable, not by what the policy document says. A signing key that invalidates every live token when replaced will be rotated once, during an incident, badly.

Using one key for several purposes makes this worse — rotating it for one reason forces the blast radius of every other use.

## Decision

**Purpose-separated keys, custody in KMS/HSM, and a rotation lifecycle that permits overlap.**

1. **Separate keys per purpose:** OIDC token signing, workload CA, application field encryption, database and storage encryption, backup encryption, artifact signing. No key serves two purposes.
2. **Lifecycle:** `GENERATE → ACTIVATE → DUAL-PUBLISH/GRACE → ROTATE → RETIRE → DESTROY`. Every stage is an operation that can be exercised, not a diagram.
3. **Signing keys publish overlapping JWKS during rotation**, so tokens issued under the outgoing key remain verifiable for their remaining lifetime. Without overlap, rotation is an outage.
4. **Encryption keys carry version metadata**, with a defined re-encryption strategy. Data encrypted under a retired key must remain readable until re-encrypted.
5. **High-value key material stays in KMS/HSM.** Services receive permission to *use* a key, never the raw master key.
6. **Secrets come from an external manager or workload-authenticated retrieval** — never from Git, never from a plain ConfigMap. Short-lived dynamic credentials are preferred where the backing system supports them.
7. **Rotation is exercised, not documented.** A rotation game day is an exit criterion, because an untested rotation path is an assumption.

## Alternatives considered

**Single signing key, rotated rarely.** Simple; rejected — it makes rotation an outage, which means it does not happen, which means compromise is unbounded in time.

**Keys in application configuration or environment variables.** Rejected — they leak through process dumps, logs, CI artifacts and backups, and rotating them requires redeploying everything.

**Application-held master keys instead of KMS.** Rejected — key custody becomes every service's problem, and compromise of any service yields the key itself rather than the ability to ask for an operation.

## Consequences

**Positive.** Rotation is survivable, therefore routine. A compromised key has a bounded purpose and a bounded blast radius. Services never hold master key material.

**Negative.** KMS/HSM is an availability dependency on the signing and encryption paths. Key version metadata must be carried with encrypted data forever. Overlapping JWKS means two valid signing keys during grace, which verifiers must handle correctly.

## Verification

Key rollover is performed without downtime; tokens issued under the previous key verify through the grace window. Old and new trust overlap is asserted. A rotation game day is completed (§27 WP-BE-03 exit).

## References
§11 Secrets, PKI and key rotation, §12 data security, §18 Security SLOs
