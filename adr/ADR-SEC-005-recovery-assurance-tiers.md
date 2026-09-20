# ADR-SEC-005 — Account Recovery Assurance Tiers R1–R4

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-01.2, WP-UI-02 |
| **Consolidates** | — (new in v1.6; §24.2 specified the tiers with no decision record) |
| **Related** | [ADR-SEC-004](ADR-SEC-004-mfa-webauthn-step-up.md), [ADR-SEC-006](ADR-SEC-006-authentication-ux-assurance.md), [ADR-SEC-009](ADR-SEC-009-security-epoch-model.md) |

## Context

Recovery is where strong authentication goes to die. An organisation can deploy passkeys everywhere and still be compromised through a password reset link sent to an email account the attacker controls, or a help-desk agent socially engineered into clearing a second factor. The attacker does not break the authentication; they walk around it.

Recovery is therefore not an administrative convenience. It is an authentication path, and it must be held to the assurance level of the account it recovers — otherwise it defines that account's real security level, regardless of what the login page enforces.

## Decision

**Four recovery tiers. Recovery never provides a lower-assurance route to an account than that account's normal authentication requires.**

| Tier | Subject | Minimum controls | Post-recovery |
|---|---|---|---|
| R1 | Standard user, verified email | Single-use, short-lived, transaction-bound reset token; rate limiting; enumeration resistance; no security questions | Revoke refresh family, rotate session, notify, emit event |
| R2 | User with MFA or passkey enrolled | Verified channel **plus** an existing factor or recovery code; stronger risk checks | Revoke all sessions; review factor re-enrolment; notify all verified channels |
| R3 | Admin, support, security-sensitive | **No email-only reset.** Phishing-resistant factor, or controlled manual recovery under dual approval | Global revocation; privileged hold until re-verification; immutable audit |
| R4 | All factors lost | High-friction identity proofing, cooling-off period, dual control; **no unilateral help-desk override** | Global revocation; delayed restoration; alerts; mandatory re-enrolment |

Additional invariants:

- **Support agents cannot bypass authentication policy.** High-risk recovery requires dual approval, captured evidence, a reason code and immutable audit.
- SMS and email OTP are low-assurance channels ([ADR-SEC-004](ADR-SEC-004-mfa-webauthn-step-up.md)) and never satisfy R3.
- Recovery responses are enumeration-resistant: registration, forgot-password and recovery reveal nothing about whether an account exists.
- Reset tokens are stored protected, single-use, expiring, invalidated on success, and replay is detected.
- **Successful recovery advances the security epoch** ([ADR-SEC-009](ADR-SEC-009-security-epoch-model.md)) at the tier's scope.
- Adding or replacing a factor is itself a sensitive operation requiring recent authentication or controlled recovery — otherwise recovery becomes a silent factor-downgrade path.

## Alternatives considered

**Email-only reset for all accounts.** Universal and familiar. Rejected: it makes every account exactly as strong as its email account, which for R3 subjects is unacceptable and invisible.

**Security questions.** Rejected — answers are researchable, reused across services, and breached in bulk. They lower assurance while appearing to raise it.

**No self-service recovery.** Strongest, rejected on operability: it turns every lost factor into a support ticket and creates pressure for exactly the informal overrides this decision forbids.

## Consequences

**Positive.** Phishing-resistant authentication is not undone by its recovery path. Privileged accounts cannot be recovered through a consumer-grade channel. Help-desk social engineering has a structural answer rather than a training answer.

**Negative.** R3 and R4 are deliberately inconvenient and will generate escalations. Dual approval requires staffing. Cooling-off periods mean a legitimate user waits.

## Verification

Gated by WP-UI-02 and WP-BE-01.2 as **negative** tests, not a happy path: email-account takeover followed by a recovery attempt on an R3 subject; help-desk social-engineering attempt; reset-link theft and replay; factor replacement through recovery; enumeration probing across all three entry points.

## References
§24.2 Account recovery threat model, §24.8 Additional attack simulations, §27 WP-UI-02
