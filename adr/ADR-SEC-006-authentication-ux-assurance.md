# ADR-SEC-006 — Authentication UX Assurance Preservation

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-UI-02 |
| **Consolidates** | — (new in v1.5, provisionally ADR-SEC-013) |
| **Related** | [ADR-SEC-004](ADR-SEC-004-mfa-webauthn-step-up.md), [ADR-SEC-005](ADR-SEC-005-recovery-assurance-tiers.md), [ADR-SEC-012](ADR-SEC-012-user-facing-security-transparency.md) |

## Context

Assurance levels are set in policy and enforced in the backend, but they are *achieved* in the interface. A platform can require phishing-resistant authentication and still find most users on TOTP, because the passkey enrolment step was skippable and the TOTP path was one click shorter. Nothing is misconfigured; the policy simply lost to the default.

The failure is not a bug, it is design: a prominent "use a code instead" link, a "remind me later" on enrolment, an email OTP offered beside a passkey as an equal choice. Each is reasonable in isolation, and together they set the platform's real assurance level — usually to the weakest option on offer.

## Decision

**The interface must not present a route to a lower assurance level than policy permits for the operation in progress.**

1. **Fallbacks are not peers.** Where a lower-assurance mechanism is permitted at all, it appears behind an explicit action, never as an equal option beside a phishing-resistant one.
2. **No silent downgrade.** The UI never selects a weaker factor automatically because it is faster, already enrolled, or previously used.
3. **Enrolment prompts state what is being declined.** A deferred passkey enrolment is a decision made with the consequence visible, not a dismissable notice.
4. **Step-up names what it protects.** The prompt states the pending operation, so a user can recognise a step-up they did not initiate — a phishing signal they can only act on if told.
5. **Security errors are generic to the user and specific in telemetry.** The interface reveals nothing about account existence, factor enrolment, or which check failed.
6. **Accessibility is in scope.** A security flow that cannot be completed with assistive technology pushes those users onto a weaker path, so accessibility failures are assurance failures.

## Alternatives considered

**Treat UX as out of scope for security decisions.** The default position, and the reason this ADR exists. Rejected: it leaves the achieved assurance level to whoever writes the login page.

**Enforce solely in the backend.** Rejected as insufficient. The backend can refuse a weak factor for a privileged operation, but cannot stop the interface steering every user to the weakest acceptable option for everything else.

**Remove all fallbacks.** Cleanest, rejected on reachability — it converts every lost or unsupported authenticator into a recovery event.

## Consequences

**Positive.** The assurance level policy intends is the one users reach. Phishing-resistant enrolment becomes the path of least resistance rather than the path least taken.

**Negative.** Some flows are deliberately less convenient. Enrolment completion may fall before it rises, and will be reported as a UX regression. Security review becomes part of front-end design review, not only API review.

## Verification

Named negative tests in WP-UI-02: no path reaches a privileged operation at medium assurance; no affordance selects a weaker factor without explicit user action; error and enumeration responses are indistinguishable across existing and non-existing accounts.

## References
§24.2 Recovery threat model, §24.7 Password and MFA position, §27.6 test ownership
