# Backend

The Backend track from the architecture document — §27.1, work packages **WP-BE-01**, **WP-BE-02**, **WP-BE-03**.

A Gradle multi-project build. Java 27, Spring Boot 4.1.1, Gradle 9.7.1.

```
backend/
├── authorization-server/    WP-BE-01  identity, OIDC, tokens, sessions
├── resource-server/         WP-BE-02  API authorization, tenancy, PDP/PEP
└── security-test-support/   the shared security-test module (§24.6)
```

## Modules

| Module | Work package | Owns | Key ADRs |
|---|---|---|---|
| `authorization-server` | WP-BE-01 | Registration, credentials, OIDC + PKCE, token issuance, JWKS, refresh-token families, sessions, devices, recovery, security epoch | [002](../adr/ADR-SEC-002-identity-model.md), [003](../adr/ADR-SEC-003-oidc-authorization-code-pkce.md), [004](../adr/ADR-SEC-004-mfa-webauthn-step-up.md), [005](../adr/ADR-SEC-005-recovery-assurance-tiers.md), [008](../adr/ADR-SEC-008-access-token-format-ttl-revocation-sla.md), [009](../adr/ADR-SEC-009-security-epoch-model.md), [010](../adr/ADR-SEC-010-refresh-token-rotation-reuse.md), [011](../adr/ADR-SEC-011-session-device-revocation-model.md) |
| `resource-server` | WP-BE-02 | Token validation, RBAC + ABAC, tenant membership, resource authorization, PEP/PDP | [008](../adr/ADR-SEC-008-access-token-format-ttl-revocation-sla.md), [013](../adr/ADR-SEC-013-rbac-abac-domain-authorization.md), [014](../adr/ADR-SEC-014-pdp-pep-architecture.md), [015](../adr/ADR-SEC-015-tenant-isolation-membership.md) |
| `security-test-support` | shared | The fitness-function contract every service implements | — |

## Build

```bash
./gradlew build
```

Java 27 is downloaded automatically if it is not installed — the foojay toolchain resolver is configured in `settings.gradle`.

**Note on 27 vs 25.** Java 27 (15 Sep 2026) is the latest release but is **not LTS** — Java 25 is the current LTS, and 29 is next. 27 is pinned here for two reasons: it is the newest, and **JEP 527** brings post-quantum hybrid key exchange for TLS 1.3 into the platform, which is the TLS half of [ADR-SEC-021](../adr/ADR-SEC-021-crypto-agility-pqc.md). If a support window matters more than that, `JavaLanguageVersion.of(25)` in `build.gradle` is the one-line revert.

## Run

```bash
./gradlew :authorization-server:bootRun    # :9000
./gradlew :resource-server:bootRun         # :9100
```

The default `local` profile uses in-memory H2 with Flyway applying `V1`–`V6`. `dev` uses PostgreSQL via `DB_URL` / `DB_USER` / `DB_PASSWORD`.

## What is here, and what is not

`authorization-server` is **not a skeleton** — it is the ported `zero-trust-auth-service`, upgraded to Spring Boot 4.1 / Spring Security 7, with **21 tests passing**. It authenticates, issues RFC 9068 tokens, rotates refresh families with reuse detection, and enforces continuous verification. See its [README](authorization-server/README.md) for the migration notes and what remains.

`resource-server` is **real** (WP-BE-02): it validates tokens strictly and serves a *documents* domain that exercises every layer the ADRs describe. A document is written by one person and must be approved by another.

- **Tenancy first (ADR-SEC-015).** A document's tenant is read from the stored record, never from the request. The order is fixed: load the resource, derive its tenant, check membership (no row means *not found*, deliberately indistinguishable from a missing id), and only then roles. Lists are built from membership, and the repository has no unscoped "find all".
- **Three layers (ADR-SEC-013).** Scope (coarse), role *in that tenant* (RBAC), and assurance (ABAC): approving needs a proved second factor, and a password-only session is answered with `STEP_UP` (RFC 9470), not a flat refusal. Maker-is-not-checker and the state machine live in the aggregate, so they hold even if the policy point is down.
- **Fails closed (ADR-SEC-024).** If membership or the policy point cannot answer, the call is refused with 503; an outage never approves anything.
- **Every decision is logged (ADR-SEC-023)** with the policy and version that made it and a correlation id (`security.decisions`).
- **Its own database identity (ADR-SEC-019).** Role `resource_app` owns the `app` schema and can SELECT exactly `tenants` and `subject_tenant_membership` from the identity schema, nothing else. `deploy/scripts/bootstrap-db.sh` creates it.

The Authorization Server also performs **token exchange (RFC 8693, ADR-SEC-016)**: the BFF trades its login token for a short-lived token for one API audience and one scope. Exchange can only narrow - the framework checks the requested scope against the *client's* registrations, not the login token's, so that rule is enforced separately (a test proves it: without it a read-only login could be traded for approval).

Schema: the ported `V1`–`V5` plus `V6__tenancy.sql`, which adds the `tenants`, `subject_tenant_membership` and `password_history` tables the v1.5 review found missing from the proposed model — [ADR-SEC-015](../adr/ADR-SEC-015-tenant-isolation-membership.md) and WP-BE-02 depend on them.

## Two things worth reading before changing the token code

Both are in `ResourceServerSecurityConfig`, and both are mistakes that pass code review:

**`createDefaultWithIssuer()` does not validate audience.** It wires only the timestamp and issuer validators. Any token minted under the same issuer and signing key is accepted — including OAuth2 tokens intended for a different audience. `createAtJwtValidator()` is used instead precisely because it *refuses to build* without an audience, which turns the omission into a startup failure rather than a silent hole.

**`NimbusJwtDecoder` rejects `at+jwt` before any validator runs.** Its default JOSE type verifier allows only `typ=JWT`, so an RFC 9068 access token fails at the Nimbus layer and the error looks like a claim problem. `validateType(false)` moves type checking into the validator chain, where the at+jwt profile enforces it correctly.

## Tests

`ApplicationContextTest` in each module is the gate that keeps a service startable — a service that compiles but cannot start is not a service.

`security-test-support` defines the fitness functions from §24.6. Ownership follows the thing being tested: token-validation tests belong to WP-BE-01, which issues tokens, **not** to WP-BE-02. Deferring them to WP-BE-02 would ship the first slice with no validation gate — which is how an unvalidated audience claim reached the earlier reference implementation.
