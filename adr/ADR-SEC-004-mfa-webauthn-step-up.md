# ADR-SEC-004 — MFA, WebAuthn and Step-Up Authentication

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-01.2, WP-UI-02 |
| **Consolidates** | ADR-004 (former numbering) |
| **Related** | [ADR-SEC-005](ADR-SEC-005-recovery-assurance-tiers.md), [ADR-SEC-006](ADR-SEC-006-authentication-ux-assurance.md), [ADR-SEC-014](ADR-SEC-014-pdp-pep-architecture.md) |

## Context

Passwords fail to phishing, credential stuffing and reuse. Second factors help unevenly: TOTP resists reuse and stuffing but not real-time phishing, because the user can be induced to read a code to an attacker-controlled site. SMS adds SIM-swap and interception. Only origin-bound cryptographic authentication — WebAuthn/FIDO2 — actually defeats phishing, because the authenticator refuses to sign for the wrong origin.

Requiring the strongest factor everywhere is not viable: enrolment takes time, recovery gets harder, and some users lack a capable authenticator. The design needs graded assurance rather than a single bar.

## Decision

**Assurance is graded, and the required level is a property of the operation, not of the account.**

| Level | Mechanism | Permitted for |
|---|---|---|
| High — phishing-resistant | WebAuthn / passkeys | Everything, including privileged operations |
| Medium | TOTP (RFC 6238), single-use per step | Normal operations; not privileged ones |
| Low | SMS / email OTP | Fallback and recovery signal only; never satisfies a phishing-resistant requirement |

- **Step-up** re-authenticates at a higher level for a specific operation, rather than gating the whole session. The pending operation is held server-side, never in a query parameter.
- Sensitive changes — adding or replacing a factor, changing a password, revoking sessions — require recent authentication, not merely an authenticated session.
- TOTP codes are single-use: the accepted time step is recorded and a step is never accepted twice, closing the replay window inside the validity period.
- A step-up demand must be satisfiable. Demanding a factor the subject does not possess, without offering an enrolment path, is a lockout rather than a control.

## Alternatives considered

**Mandatory passkeys for all users.** Strongest, and rejected only on reachability: it excludes users without a capable authenticator and makes recovery the weakest link for everyone. Revisit as platform support broadens.

**Optional MFA with no step-up.** Rejected — leaves privileged operations protected by a password.

**SMS as a primary second factor.** Rejected — SIM swap and SS7 interception are demonstrated at scale, and its presence as an equal option silently caps the achievable assurance ([ADR-SEC-006](ADR-SEC-006-authentication-ux-assurance.md)).

## Consequences

**Positive.** Privileged operations are protected against real-time phishing. Assurance is expressible in policy and enforceable per operation. Step-up avoids forcing maximal friction on every session.

**Negative.** Multiple authenticator types to implement, enrol, recover and support. Step-up adds a mid-flow state machine. Recovery becomes the bypass to worry about — which is why it has its own decision ([ADR-SEC-005](ADR-SEC-005-recovery-assurance-tiers.md)).

## Verification

Password-only login is refused where MFA is enrolled. A replayed TOTP code is rejected within its own validity window. A privileged operation refuses a medium-assurance session and offers a satisfiable step-up. `rejectsMissingRequiredAuthenticationLevel` gates the API side.

## References
§2.4 Login with MFA, §24.7 Password and MFA position, §27 WP-UI-02 · RFC 6238 · W3C WebAuthn
