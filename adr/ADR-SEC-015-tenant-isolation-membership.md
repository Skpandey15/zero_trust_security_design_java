# ADR-SEC-015 — Tenant Isolation and Membership Model

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Work package** | WP-BE-01.1 (schema), WP-BE-02 (enforcement) |
| **Consolidates** | — (new in v1.5; backfills §24.3, which had no decision record) |
| **Related** | [ADR-SEC-013](ADR-SEC-013-rbac-abac-domain-authorization.md), [ADR-SEC-014](ADR-SEC-014-pdp-pep-architecture.md), [ADR-SEC-019](ADR-SEC-019-data-messaging-least-privilege.md) |

## Context

The platform serves multiple tenants from shared services and a shared database. Cross-tenant access is the highest-impact authorization failure available: it is a confidentiality breach affecting a party who has no relationship with the attacker, it is usually silent, and it is reportable.

The failure is rarely exotic. It is almost always one of:

- An identifier in a URL path or query string that the handler trusts and loads without checking who owns it — broken object-level authorization, the most common serious API defect in the field.
- A tenant identifier taken from a header, a request body, or a JWT claim, and used *as the filter* rather than checked against the resource's actual owner. The attacker changes one value and reads another tenant's data.
- A list or export endpoint whose query omits the tenant predicate that every single-record endpoint remembers.
- An administrative path that implicitly spans tenants because "admins can see everything" was never scoped.

What these share is a single root cause: **the request was allowed to tell the system which tenant it was operating in.** Once tenant context is attacker-influenced input, every downstream check inherits the compromise, and a correct-looking RBAC rule (`hasRole('MANAGER')`) passes while reading someone else's data.

A second complication is that subjects are not confined to one tenant. Consultants, support staff, partners and platform administrators legitimately hold access to several. A model that assumes one tenant per user collapses the moment those accounts exist — usually by someone adding a "current tenant" field and trusting it.

## Decision

**Tenant isolation is server-enforced. A tenant identifier arriving in a request is context, never proof. Resource tenancy is derived from authoritative server-side state and checked against explicit subject membership.**

1. **Resource tenancy is derived, not supplied.** The handler loads the resource by its identifier and reads `resource.tenant_id` from the stored record. The tenant is never taken from the URL, header, body, or a token claim for the purpose of the decision.
2. **Membership is explicit and relational.** `subject_tenant_membership` records which subjects may act in which tenants, with the role or entitlement held there. Absence of a row is denial — there is no implicit or inherited membership.
3. **The authorization order is fixed:**

   ```
   load resource by id
        → derive resource.tenant_id from the stored record
        → membership(subject, resource.tenant_id)?  ── no ──► DENY
        → RBAC + ABAC + resource rules + domain invariants
        → ALLOW / DENY / STEP_UP
   ```

   Membership is evaluated **before** role and attribute checks, so a correct role in the wrong tenant can never reach a permit.
4. **Active tenant context is a convenience, not an authority.** A session may carry an active tenant to disambiguate listings and defaults. It is never the basis of an access decision, and switching it is an explicit operation that re-verifies membership. Privileged switches may require step-up.
5. **Platform administrators do not get implicit cross-tenant access.** Cross-tenant capability is a distinct, separately-granted authorization path requiring a recorded reason and producing its own audit trail. "Admin" is not a tenancy bypass.
6. **Tenant scoping belongs at the data-access boundary.** Repositories and query abstractions carry the tenant predicate, so a forgotten `WHERE` clause in a new endpoint is a compile-or-review failure rather than a silent breach. Defence in depth, not a replacement for the explicit check.
7. **Enumeration is assumed.** Resource identifiers are treated as guessable. Opaque or random identifiers are preferred, but the authorization check — not identifier obscurity — is the control.

## Alternatives considered

### A. Tenant claim in the access token, used as the filter

Put `tenant_id` in the JWT and scope every query by it.

**Rejected because** it makes a signed assertion about *the subject's context* into the authority over *the resource's ownership*. Those are different facts. It is defensible only while the claim is unforgeable and the subject belongs to exactly one tenant, and it breaks immediately for multi-tenant subjects and for any token minted with a stale or broad context. It also tightly couples revocation of tenant access to token lifetime: removing a user from a tenant does not take effect until their token expires.

### B. Database-per-tenant or schema-per-tenant

Physical separation — connection routing decides the tenant.

**Not rejected as unsound**; rejected for this platform's operating model. It offers the strongest isolation and is the right answer where regulation demands it. The costs are migration fan-out across hundreds of schemas, per-tenant connection-pool pressure, cross-tenant reporting becoming a distributed query, and tenant onboarding turning into an infrastructure operation. It also does not remove this decision: a routing layer that picks the datasource from a request-supplied value reintroduces exactly the same flaw one level down.

### C. Row-level security in PostgreSQL

Enforce tenancy in the database via RLS policies and a session variable.

**Adopted as defence in depth where practical, rejected as the primary control.** RLS is valuable precisely because it catches the forgotten predicate. But it depends on a session variable being set correctly on every connection — and a pooled connection that carries the previous request's tenant is a breach with no application-layer symptom. It also cannot express the membership and step-up semantics this decision needs. Useful as a backstop beneath an explicit check, dangerous as a substitute for one.

### D. Trust the URL, validate on write only

Accept the tenant from the path for reads; check ownership on mutations.

**Rejected outright.** Cross-tenant *reads* are the breach. This inverts the risk.

## Consequences

### Positive

- The dominant multi-tenant failure mode is removed structurally: the attacker's ability to influence tenant context no longer affects the decision, because the decision reads the stored record.
- Multi-tenant subjects are a first-class case rather than a special case bolted onto a single-tenant assumption.
- Membership changes take effect immediately, because membership is read at decision time rather than frozen into a token.
- Administrative cross-tenant access is visible, attributable and reason-coded instead of ambient.
- The failure mode is fail-closed: a missing membership row denies.

### Negative

- **The resource must be loaded before authorization can be decided.** This inverts the usual "authorize then fetch" ordering and means a denied request still costs a read. Handlers must be careful that the loaded resource does not leak through error messages, timing, or response shape before the check completes.
- **A membership lookup on every request**, with the caching question that follows — and cached membership has the same property as cached revocation state ([ADR-SEC-009](ADR-SEC-009-security-epoch-model.md)): the TTL is the upper bound on how long a removed user retains access.
- **List and search endpoints need explicit design.** The pattern above is written for single-resource access. Collections must scope at the query, and that scoping cannot be derived per-row after the fact without either leaking counts or performing badly.
- **Existing single-tenant code does not migrate trivially.** Every handler that currently takes a tenant from context must be revisited individually; there is no mechanical transformation.

### Neutral

- Physical isolation remains available per-tenant for customers whose contracts require it, without changing this model for everyone else.

## Verification

Gated by WP-BE-02, per §27.6. `rejectsCrossTenantResourceAccess` is not one test but a suite, and per §24.3 it must cover:

- A guessed or enumerated identifier belonging to another tenant.
- A tampered tenant header or body field while the session's real membership is unchanged.
- A stale active-tenant context after membership was revoked.
- A multi-tenant subject reaching a tenant they hold no membership in.
- Administrative paths, which must not span tenants implicitly.
- **Bulk, list, search and export endpoints**, which are where the predicate is forgotten.

Every one of these asserts a denial. A suite that only proves the permit path proves nothing about isolation.

## References

- §24.3 Multi-tenancy security model, §7 Authorization LLD, §27.5 Data model corrections
- §15 Threat model — broken object authorization row
- §18 Security SLOs — "cross-tenant authorization test suite must remain at 100% pass rate"
