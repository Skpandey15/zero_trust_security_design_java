# Authorization Server — WP-BE-01

Ported from [`zero-trust-auth-service`](https://github.com/Skpandey15/zero-trust-auth-service) and upgraded **Spring Boot 3.5 → 4.1** (Spring Security 6.5 → 7), per §27.8: this work package *evolves* that codebase rather than starting clean. The upgrade was overdue — the 3.5 line passed its open-source support window in June 2026.

**21 tests, 0 failures.**

## What works today

Registration, password login with Argon2id, OIDC discovery + JWKS, Authorization Code + PKCE, `client_credentials`, RFC 9068 `at+jwt` access tokens with a pinned audience, refresh-token families with rotation and atomic reuse detection, TOTP with replay protection, continuous verification against `token_valid_after`, per-account lockout, per-IP throttling, and audit events.

## Boot 4 / Security 7 migration notes

Five breakages, all found by compiling and running rather than by reading release notes. Recorded because the next module to migrate will hit the same ones:

**1. `OAuth2AuthorizationServerConfigurer` moved and lost its factory method.** It now lives in `spring-security-config` under `org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization`, and the `authorizationServer()` static factory is gone — construct it directly. The authorization-server artifact itself no longer contains any `*Configurer` class.

**2. `@AutoConfigureMockMvc` moved.** Boot 4 split the test autoconfiguration out of the umbrella starter: it is now `org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc` in `spring-boot-webmvc-test`, which must be added explicitly. `MockMvc` itself stays put.

**3. Flyway needs its starter.** A bare `org.flywaydb:flyway-core` dependency is no longer autoconfigured. Without `spring-boot-starter-flyway`, migrations silently never run and the first symptom is Hibernate schema validation failing on a missing table — which looks like a schema bug, not a dependency one.

**4. Jackson 3 is the default.** `com.fasterxml.jackson.databind.ObjectMapper` is no longer a bean; the packages moved to `tools.jackson.*`. Application code here used no Jackson types directly, so only three tests needed changing.

**5. Logback profile bug (pre-existing, fixed here).** `logback-spring.xml` scoped its console appender to `dev,default` while the default active profile is `local` — so a local run matched neither block, the root logger got no appender, and every `security.events` line went nowhere. The audit logging the architecture centres on was silently dead. Now `local,dev,default`.

## Schema

The ported `V1`–`V5` are authoritative: they match the working code. `V6__tenancy.sql` adds what the v1.5 review found missing —`tenants`, `subject_tenant_membership` (which [ADR-SEC-015](../../adr/ADR-SEC-015-tenant-isolation-membership.md) and WP-BE-02 depend on) and `password_history`.

The richer model sketched in §27.4 — splitting the password hash into a `credentials` table, `security_sessions`, `refresh_token_families` as an entity — is **WP-BE-01.2** work. The current model stores the hash on `users` and family as a column on the token.

## Held back

| | Why |
|---|---|
| AI security insights (`ai/`) | Spring AI 1.0 compatibility with Boot 4.1 is unverified. One admin endpoint reading the login audit table; held back so a dependency problem there cannot block the auth core. |
| springdoc-openapi | The 2.x line targets Boot 3. Boot 4 needs a newer major version; `OpenApiConfig` is held back with it. |

Both are tracked, not abandoned. Neither is on the authentication path.

## Run

```bash
../gradlew :authorization-server:bootRun     # :9000
```

`local` (default) uses in-memory H2 with Flyway applying V1–V6. `dev` uses PostgreSQL via `DB_URL` / `DB_USER` / `DB_PASSWORD`.

## Still to build for WP-BE-01

Email verification, WebAuthn/passkeys, recovery codes and the R1–R4 recovery flows, the device registry, and the server-side session store the BFF needs. Plus a known constraint carried over: the OAuth2 authorization state and form-login session are in-memory, so the interactive flow cannot yet serve more than one replica (§27.8).
