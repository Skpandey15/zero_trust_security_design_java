# ADR-SEC-011 — Session, Device and Revocation Model

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-01.1 (core), WP-BE-01.2 (devices) |
| **Consolidates** | part of ADR-006 (former numbering) |
| **Related** | [ADR-SEC-007](ADR-SEC-007-bff-and-browser-token-custody.md), [ADR-SEC-009](ADR-SEC-009-security-epoch-model.md), [ADR-SEC-012](ADR-SEC-012-user-facing-security-transparency.md) |

## Context

The security epoch ([ADR-SEC-009](ADR-SEC-009-security-epoch-model.md)) revokes everything for a user at once. That is the right tool for account compromise and it is the wrong tool for "sign me out of the laptop I left at the office" — which must not log the user out of the phone they are holding.

Per-session revocation needs a server-side record of what sessions exist. That record is also what the BFF binds its cookie to, what an authorization decision reads to learn the achieved assurance level, and what the user inspects in the Security Center.

## Decision

**Server-side session records, with device as an attribute of a session, revocable individually or in bulk.**

- A `security_session` carries: session id, user, device, refresh-token family, `auth_time`, `last_seen_at`, achieved authentication level, risk score, status, expiry, and hashed network and user-agent values.
- **Device is an attribute of a session, not a credential.** One device has many sessions over time. Device identity does not authenticate on its own ([ADR-SEC-002](ADR-SEC-002-identity-model.md)).
- Revocation exists at four independent scopes: one session, one device, all sessions for a user, and the security epoch. Each is a distinct operation with distinct blast radius.
- Revoking a session revokes its refresh-token family ([ADR-SEC-010](ADR-SEC-010-refresh-token-rotation-reuse.md)). The relationship is one-directional: family reuse revokes the family, which terminates the session.
- **Logout-all advances the epoch; revoke-one does not.** Using the epoch for single-session revocation would log the user out everywhere — a correctness bug that looks like a security feature.
- Network address and user-agent are stored hashed. They are forensic and risk signals, not identifiers to display verbatim.

## Alternatives considered

**Stateless sessions, epoch-only revocation.** Simplest; rejected because it cannot express per-session or per-device revocation, which §20 requires and users expect.

**Session state in the token.** Rejected — it freezes assurance level and risk score at issuance, so a step-up or a risk change cannot affect a live session.

**Device as a first-class credential.** Rejected: device identifiers are inferable and spoofable, so treating one as a credential grants access on a guessable value.

## Consequences

**Positive.** Granular revocation, answering §20 directly. Assurance level and risk are readable at decision time rather than frozen. The BFF has somewhere to anchor its cookie.

**Negative.** Session storage must be shared across replicas or the BFF cannot scale horizontally. A session read joins the per-request cost budgeted in §25.2. Session and family lifecycles must stay consistent under concurrency.

## Verification

Revoking one session leaves others working. Revoking a device terminates only its sessions. Logout-all terminates every session *and* invalidates live access tokens. A revoked session's refresh family is dead.

## References
§5.2 Session record, §5.3 Global revocation, §20 review checklist, §25.2 latency budget
