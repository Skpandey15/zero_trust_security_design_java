# Architecture Decision Register

The decisions behind the [Java Zero-Trust Security Architecture](../README.md). Section 19 of the design document lists these as decision statements; this directory holds the decisions themselves — context, alternatives considered, consequences and verification.

## Conventions

- `ADR-SEC-nnn` is the only ADR namespace. It consolidates two earlier sequences that had drifted apart (`ADR-SEC-001..012` from §19 and `ADR-001..010` from §23); the **Consolidates** column below maps the former numbering so older references stay traceable.
- Numbers are never reused.
- An ADR is **superseded, never edited in place.** A superseding ADR references the one it replaces.
- ADRs map **many-to-one** onto work packages. A work package does not get an ADR because it exists; a decision gets an ADR because it was decided.

## Register

| ADR | Decision | Work package | Consolidates |
|---|---|---|---|
| [ADR-SEC-001](ADR-SEC-001-zero-trust-boundaries.md) | Zero-trust security boundaries and trust zones | cross-cutting | ADR-001 |
| [ADR-SEC-002](ADR-SEC-002-identity-model.md) | Human, device and workload identity model | WP-BE-01.1 | ADR-002 |
| [ADR-SEC-003](ADR-SEC-003-oidc-authorization-code-pkce.md) | OIDC Authorization Code + PKCE S256 | WP-BE-01.1, WP-UI-01 | ADR-003 |
| [ADR-SEC-004](ADR-SEC-004-mfa-webauthn-step-up.md) | MFA, WebAuthn and step-up authentication | WP-BE-01.2, WP-UI-02 | ADR-004 |
| [ADR-SEC-005](ADR-SEC-005-recovery-assurance-tiers.md) | Account recovery assurance tiers R1–R4 | WP-BE-01.2, WP-UI-02 | new in v1.6 |
| [ADR-SEC-006](ADR-SEC-006-authentication-ux-assurance.md) | Authentication UX assurance preservation | WP-UI-02 | new in v1.5 |
| [ADR-SEC-007](ADR-SEC-007-bff-and-browser-token-custody.md) | BFF and browser token custody | WP-UI-01 | ADR-SEC-001, ADR-005 |
| [ADR-SEC-008](ADR-SEC-008-access-token-format-ttl-revocation-sla.md) | Access-token format, TTL and revocation SLA | WP-BE-01.1 | ADR-SEC-002, part of ADR-006 |
| [ADR-SEC-009](ADR-SEC-009-security-epoch-model.md) | `token_valid_after` / security-epoch model | WP-BE-01.1 | ADR-SEC-003, part of ADR-006 |
| [ADR-SEC-010](ADR-SEC-010-refresh-token-rotation-reuse.md) | Refresh-token rotation and reuse response | WP-BE-01.1 | ADR-SEC-004, part of ADR-006 |
| [ADR-SEC-011](ADR-SEC-011-session-device-revocation-model.md) | Session, device and revocation model | WP-BE-01 | part of ADR-006 |
| [ADR-SEC-012](ADR-SEC-012-user-facing-security-transparency.md) | User-facing security transparency and control | WP-UI-03 | new in v1.5 |
| [ADR-SEC-013](ADR-SEC-013-rbac-abac-domain-authorization.md) | RBAC + ABAC + domain-authorization boundaries | WP-BE-02 | ADR-SEC-005, ADR-007 |
| [ADR-SEC-014](ADR-SEC-014-pdp-pep-architecture.md) | PDP / PEP authorization architecture | WP-BE-02 | ADR-008 |
| [ADR-SEC-015](ADR-SEC-015-tenant-isolation-membership.md) | Tenant isolation and membership model | WP-BE-01.1, WP-BE-02 | new in v1.5 |
| [ADR-SEC-016](ADR-SEC-016-token-exchange-downscoping.md) | Service-to-service token exchange and downscoping | WP-BE-02 | ADR-SEC-007 |
| [ADR-SEC-017](ADR-SEC-017-sender-constrained-tokens.md) | Sender-constrained token adoption scope (DPoP / mTLS) | WP-BE-02 | ADR-SEC-008 |
| [ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md) | SPIFFE/SPIRE workload identity and trust-domain topology | WP-BE-03 | ADR-SEC-006, ADR-009 |
| [ADR-SEC-019](ADR-SEC-019-data-messaging-least-privilege.md) | Database, Kafka and cache least-privilege identities | WP-BE-03 | part of ADR-010 |
| [ADR-SEC-020](ADR-SEC-020-secrets-kms-key-rotation.md) | Secrets, KMS/HSM and key-rotation lifecycle | WP-BE-03 | ADR-SEC-009, part of ADR-010 |
| [ADR-SEC-021](ADR-SEC-021-crypto-agility-pqc.md) | Cryptographic agility and post-quantum migration | WP-BE-03 | ADR-SEC-PQC-001 |
| [ADR-SEC-022](ADR-SEC-022-supply-chain-signing-admission.md) | Software supply-chain signing, provenance and admission | deferred (§23) | ADR-SEC-010 |
| [ADR-SEC-023](ADR-SEC-023-security-telemetry-incident-revocation.md) | Security telemetry schema and incident revocation | WP-BE-03 | ADR-SEC-011 |
| [ADR-SEC-024](ADR-SEC-024-fail-open-fail-closed-matrix.md) | Fail-open / fail-closed matrix for security dependencies | cross-cutting | ADR-SEC-012 |

## Reading order

The four decisions carrying the most weight, and the best entry points:

| | Why it matters |
|---|---|
| [ADR-SEC-007](ADR-SEC-007-bff-and-browser-token-custody.md) — BFF and browser token custody | Determines what an attacker gains from an XSS defect. The difference between a session they can abuse while the page is open and a credential they can walk away with. |
| [ADR-SEC-009](ADR-SEC-009-security-epoch-model.md) — Security epoch | How a stateless JWT participates in revocation at all, and why cache TTL is a security control rather than a performance knob. |
| [ADR-SEC-010](ADR-SEC-010-refresh-token-rotation-reuse.md) — Rotation and reuse | Turns token theft from silent ongoing access into a detectable event, with two implementation traps that a passing test suite will not reveal. |
| [ADR-SEC-015](ADR-SEC-015-tenant-isolation-membership.md) — Tenant isolation | The highest-impact authorization failure available, and why a tenant identifier in a request is context rather than proof. |

## Grouping

**Foundations** — 001, 002, 024

**Human identity and authentication** — 003, 004, 005, 006

**Browser and token custody** — 007, 008, 009, 010, 011, 012

**Authorization** — 013, 014, 015, 016, 017

**Workload, data and platform** — 018, 019, 020, 021, 022, 023

## Status

All twenty-four are **Accepted**. Two carry qualifiers: ADR-SEC-017 is accepted with scoped, risk-ordered adoption rather than blanket application, and ADR-SEC-022 is accepted as a decision with implementation deferred to the delivery architecture phase (§23), so that later work builds to it rather than retrofitting.
