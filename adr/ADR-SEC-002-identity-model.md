# ADR-SEC-002 — Human, Device and Workload Identity Model

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-01.1 |
| **Consolidates** | ADR-002 (former numbering) |
| **Related** | [ADR-SEC-011](ADR-SEC-011-session-device-revocation-model.md), [ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md) |

## Context

"Identity" covers three different things that are routinely conflated: the human who authenticates, the device they authenticate from, and the workload that calls another workload. Each has a different lifecycle, a different attestation mechanism, and a different revocation path. Modelling them as one — typically by issuing service accounts from the human identity system, or by treating a device as a user — produces credentials that cannot be revoked independently and audit trails that cannot answer who did what.

## Decision

**Three identity types, modelled separately, each with its own issuance, attestation and revocation.**

| Type | Established by | Credential | Revoked by |
|---|---|---|---|
| Human | Authentication (password, passkey, MFA) | Session + access token | Session revocation, security epoch ([ADR-SEC-009](ADR-SEC-009-security-epoch-model.md)) |
| Device | Registration bound to a human session | Device record, optionally a bound authenticator | Device revocation, independent of the user |
| Workload | Platform attestation | SPIFFE SVID, short-lived ([ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md)) | SVID expiry, identity withdrawal |

- A workload identity is never derived from a human identity, and services do not act "as" a user unless a delegation decision is explicit ([ADR-SEC-016](ADR-SEC-016-token-exchange-downscoping.md)).
- Device identity is an attribute of a session, not a credential that authenticates on its own. Device inference from user-agent and IP is a hint and must be represented as one ([ADR-SEC-012](ADR-SEC-012-user-facing-security-transparency.md)).
- Every privileged action is attributable to a subject *and*, where relevant, the workload that carried it.

## Alternatives considered

**One identity system for humans and services.** Operationally simpler; rejected because service credentials then inherit human lifecycles — password policies, MFA prompts, offboarding — none of which fit, and the usual outcome is a long-lived static secret exempted from all of them.

**Device as an authentication factor in its own right.** Rejected: device identifiers are inferable and spoofable. A registered device can *raise* confidence; it cannot substitute for a factor.

## Consequences

**Positive.** Independent revocation per identity type — §20's "can I revoke one session, one device, one user, one workload, one credential independently?" becomes answerable. Audit records distinguish subject from workload.

**Negative.** Three issuance and lifecycle paths to build and operate rather than one. Delegation becomes an explicit design problem instead of an accident.

## Verification

Revoking each identity type independently is asserted per WP-BE-01 and WP-BE-03. A workload credential must not be obtainable through the human authentication path.

## References
§1.3 Zero-trust control map, §2.1 Data model, §9 Workload identity · NIST SP 800-207A
