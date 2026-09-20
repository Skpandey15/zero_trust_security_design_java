# ADR-SEC-013 — RBAC + ABAC + Domain-Authorization Boundaries

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-02 |
| **Consolidates** | ADR-SEC-005, ADR-007 (former numbering) |
| **Related** | [ADR-SEC-014](ADR-SEC-014-pdp-pep-architecture.md), [ADR-SEC-015](ADR-SEC-015-tenant-isolation-membership.md) |

## Context

Role checks are the most common authorization mechanism and the most commonly insufficient one. `hasRole('MANAGER')` answers "is this subject a manager" — not "may this subject approve *this* payment, in *this* tenant, at *this* amount, given that they raised it". Every one of those qualifiers is where the real decision lives, and a role check passes all of them blindly.

Pure attribute-based policy solves the expressiveness problem and creates another: business invariants such as maker-checker separation or aggregate consistency end up encoded in an external policy engine, where they are invisible to the domain model and silently absent when that engine is unavailable.

## Decision

**Three layers, each answering a different question, none sufficient alone.**

```
RBAC        coarse entitlement    may this subject do this class of thing at all?
ABAC        contextual decision   given tenant, resource, amount, risk, auth level?
Domain      invariants in Java    maker != checker; aggregate stays consistent
```

- The decision function is `subject + action + resource + tenant + context + risk + policyVersion`, not `subject + role`.
- Tenant membership is evaluated before role and attribute checks ([ADR-SEC-015](ADR-SEC-015-tenant-isolation-membership.md)).
- **Domain invariants stay in Java**, inside the aggregate, even when an external PDP is in use. Maker-checker separation must not disappear because a policy service is unreachable.
- Every decision yields `ALLOW`, `DENY` or `STEP_UP`, and carries the policy identifier and version that produced it.
- Enforcement is two-layer: coarse URL rules plus a fine-grained per-operation check. The coarse layer is a filter, never the authorization.

## Alternatives considered

**RBAC only.** Rejected — cannot express resource-level or contextual constraints, and produces the broken-object-authorization class of defect directly.

**ABAC only, all policy external.** Rejected — moves domain invariants outside the domain, where they cannot be unit-tested with the aggregate and vanish when the PDP is down.

**Domain checks only, no policy layer.** Rejected — authorization logic scatters across handlers with no central auditability, and "which policy allowed this?" becomes unanswerable.

## Consequences

**Positive.** Authorization is resource- and action-specific. Decisions are auditable with policy version. Domain correctness survives policy-service outages.

**Negative.** Three layers to keep coherent, with real risk of a rule expressed in two places that drift. More per-request work (§25.2). Developers must learn which layer a new rule belongs in.

## Verification

Gated by WP-BE-02: no API relies solely on authentication or a role check. `rejectsMissingRequiredAuthenticationLevel` and the cross-tenant suite both gate here. Domain invariants are asserted with the PDP unavailable.

## References
§7 Authorization LLD, §2.2 Authorization model, §18 Security SLOs
