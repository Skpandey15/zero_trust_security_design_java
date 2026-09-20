# ADR-SEC-021 — Cryptographic Agility and Post-Quantum Migration

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-03 |
| **Consolidates** | ADR-SEC-PQC-001 (proposed in v1.3; renumbered in v1.6, content unchanged) |
| **Related** | [ADR-SEC-020](ADR-SEC-020-secrets-kms-key-rotation.md), [ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md) |

## Context

A cryptographically relevant quantum computer would break the public-key cryptography this platform depends on: RS256 token signatures, TLS key exchange, workload certificates, artifact signing. The timeline is uncertain; the exposure is not evenly distributed in time. Data with a long confidentiality lifetime is at risk **now** under harvest-now-decrypt-later, because an adversary can capture traffic today and decrypt it when capability arrives.

The wrong response is to replace every primitive immediately with algorithms whose implementations and interoperability are still settling. The right response is to be able to change algorithms when it matters — which is a property most systems lack, because algorithm choices are baked into contracts, storage formats and domain models.

## Decision

**Treat PQC as a migration and crypto-agility problem, not an immediate replacement programme.**

1. **Maintain a cryptographic inventory:** TLS and mTLS certificates, JWT/JWS signing, artifact signing, backup encryption, KMS/HSM keys, service identities, database and client certificates, external integrations.
2. **Classify data by confidentiality lifetime** and identify harvest-now-decrypt-later exposure. Long-lived sensitive data migrates first.
3. **Design agility in:** algorithm choice lives behind replaceable providers and configuration, expressed in JWKS and key metadata, certificate issuance, trust bundles and verification libraries. **Algorithm changes must not require domain-model changes.**
4. **Track the NIST standards** — FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) — and migrate through supported protocols and providers rather than bespoke implementations.
5. **Hybrid first, in a non-production interoperability track**, before PQC is mandatory on any browser, TLS, SPIFFE or JWT path.
6. **Never implement custom cryptographic algorithms.** Use standards-conformant maintained providers, and validated modules where compliance requires them.
7. **Test agility explicitly:** key rollover, algorithm allow-list changes, old/new trust overlap, verifier compatibility, rollback, and emergency algorithm disablement.

## Alternatives considered

**Do nothing until quantum capability is demonstrated.** Rejected — harvest-now-decrypt-later means long-lived data is already exposed, and a platform with no agility cannot respond quickly when it must.

**Immediate full PQC migration.** Rejected — interoperability, performance and library maturity are still moving, and a unilateral migration breaks every integration that has not moved with it.

**Custom or experimental primitives.** Rejected outright.

## Consequences

**Positive.** The platform can change algorithms without redesign. Long-lived sensitive data is prioritised on evidence rather than intuition. Emergency algorithm disablement becomes a supported operation.

**Negative.** Agility costs indirection — algorithm-parameterised code and metadata everywhere a key is used. Hybrid modes increase handshake size and cost. An inventory is only useful if kept current, which is ongoing work.

**Neutral.** This ADR is expected to be superseded as standards and platform support mature.

## Verification

Algorithm allow-list change, key rollover with old/new overlap, verifier compatibility across the change, rollback, and emergency disablement are all exercised rather than documented.

## References
§25.3 Post-quantum readiness and cryptographic agility · NIST FIPS 203 / 204 / 205
