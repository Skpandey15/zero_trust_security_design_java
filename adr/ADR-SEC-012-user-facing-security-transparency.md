# ADR-SEC-012 — User-Facing Security Transparency and Control

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-UI-03 |
| **Consolidates** | — (new in v1.5, provisionally ADR-SEC-014) |
| **Related** | [ADR-SEC-011](ADR-SEC-011-session-device-revocation-model.md), [ADR-SEC-023](ADR-SEC-023-security-telemetry-incident-revocation.md) |

## Context

Users are the only party who can recognise that a session is not theirs. A Security Center showing active sessions, devices and recent authentication events turns each account holder into a detection capability the platform cannot otherwise buy.

The hazard is that this surface leaks. A session list is derived from data an attacker partly controls — the user-agent string — and partly from inference — geolocation from IP. Rendering "iPhone · Safari · Bengaluru" as a statement of fact presents a guess as evidence. A user who learns to trust that line can be reassured by an attacker who sets a matching user-agent and uses a nearby exit node. The feature then works against the user.

## Decision

**Users get explicit visibility and control over their authentication state. The interface must not expose raw secrets, internal audit detail, or false certainty about inferred facts.**

1. Exposed: current session, other active sessions, device labels, last-seen times, coarse location, enrolled factors, recovery methods, and recent security events.
2. Actions: revoke a selected session, revoke a device, log out of all devices, manage factors and recovery methods.
3. **Never exposed:** token values, session identifiers usable as credentials, TOTP secrets after enrolment, recovery codes after first display, password hashes, internal policy identifiers, or raw audit rows.
4. **Inferred facts are presented as inferences.** Device and location derive from user-agent and IP, both attacker-influenced. The interface states this rather than implying certainty.
5. The security activity feed shows what the user can act on — sign-ins, failed sign-ins, password changes, factor enrolment, recovery, session revocation — not the platform's full internal telemetry.
6. Sensitive changes made from this surface require recent authentication ([ADR-SEC-004](ADR-SEC-004-mfa-webauthn-step-up.md)).

## Alternatives considered

**No user-facing security surface.** Smallest attack surface; rejected because it discards the only detection capability that scales with the user base, and users cannot act on compromise they cannot see.

**Full audit transparency.** Rejected — internal event detail helps an attacker who already has session access map the platform's detection, and confuses everyone else.

**Precise device fingerprinting for certainty.** Rejected: it would require fingerprinting users to make the display trustworthy, trading a privacy harm for a security display, and remains spoofable.

## Consequences

**Positive.** Users can detect and terminate sessions they do not recognise. Revocation controls are self-service. Honest presentation of inference means the display is not itself a false assurance.

**Negative.** An attacker with session access also sees this surface, learning which sessions exist. Hedged device labels read as less polished than confident ones, and will be questioned in design review.

## Verification

No response from any Security Center endpoint contains token values, secrets or raw audit internals. Revoke-one and logout-all take effect immediately. Sensitive changes are refused without recent authentication.

## References
§23 user-facing security capabilities, §27.1 WP-UI-03 scope
