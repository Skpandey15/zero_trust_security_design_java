# Java Zero-Trust Security Architecture

A principal-engineer-level reference architecture for zero-trust identity and authorization on the Java / Spring Boot / Kubernetes stack — HLD, LLD, threat model, and implementation roadmap.

**Current revision: [v1.6](Java_Zero_Trust_Security_Architecture_Principal_Engineer_v1.6.docx)**

---

## What this is

A design document for a high-value platform built on the principle that network location, namespace, possession of a bearer token, or a successful login is never by itself sufficient. Authorization is evaluated at the gateway, service, resource, workload and data boundaries.

It covers:

| Area | Contents |
|---|---|
| **HLD** | Trust zones, component view, architectural decision table with rationale |
| **LLD** | Authentication and browser/BFF design, session and revocation records, token contracts, RBAC + ABAC + domain authorization, PEP/PDP contract, Spring Boot enforcement |
| **Workload identity** | SPIFFE/SPIRE, mTLS, and why mesh mTLS is not authorization |
| **Platform** | Kubernetes segmentation, admission policy, pod security, secrets and key rotation |
| **Data** | PostgreSQL least privilege, Kafka ACLs, cache consistency, backup isolation |
| **Supply chain** | SBOM, SCA, provenance, Cosign signing, admission verification |
| **Threat model** | Attack-to-control mapping with an explicit residual-risk column |
| **Availability** | Fail-open/fail-closed matrix, so the security architecture is not itself a single point of failure |
| **Delivery** | Six work packages across a UI/BFF and a Backend track, sequenced as vertical slices so a working end-to-end flow exists from the first slice; resourcing estimates; security SLOs expressed as executable fitness functions |

## Architecture at a glance

![Architecture](Security%20Architecture.png)

Section 24.1 of the document is the normative text view; the diagram above is the illustrative component view, carrying the UI, data-store and integration detail the text omits.

## Design position

The runtime platform implements identity in Java — Spring Boot, Spring Security, Spring Authorization Server, PostgreSQL and a dedicated Backend For Frontend — rather than depending on an off-the-shelf Identity Provider.

This is deliberate, and the document is explicit that it is **not** the general recommendation: for most production organizations a hardened, well-operated managed or off-the-shelf IdP remains the default unless there is justified reason to own identity-server implementation risk. This build exists to make the mechanics, controls, failure modes and verification obligations explicit.

## Revision history

| Version | Added |
|---|---|
| v1.0 | HLD, LLD, threat model, roadmap, ADR baseline |
| v1.1 | Custom authentication & authorization platform; BFF and PKCE flow; five work packages |
| v1.2 | Account recovery threat model (R1–R4 assurance tiers); multi-tenancy isolation model; authorization latency and resilience budget; resourcing estimates; fitness functions as executable tests |
| v1.3 | RFC 9068 access-token validation; continuous-verification latency budget with cache TTL bound to revocation SLA; post-quantum readiness and crypto-agility position |
| v1.4 | `at+jwt` documented as a coordinated issuer-and-validator change; two additional negative tests; figure restored |
| v1.5 | Delivery restructured into UI/BFF and Backend tracks — six work packages, vertical-slice sequencing with a thin first slice; ADR register split resolved and four decisions added; security-test ownership moved to the work package that issues tokens; tenancy schema and resourcing re-mapped |
| v1.6 | Architecture Decision Register consolidated — two overlapping ADR sequences merged into a single 24-entry register under one namespace, with supersession mapping; recovery assurance tiers given the decision record they lacked |

Each revision responded to an adversarial review of the one before it; §24–§28 record what each round closed.

## Principles the document holds to

- **Default deny.** An absent policy, failed dependency, malformed identity or ambiguous tenant context never becomes ALLOW.
- **Authenticate both ends** — the subject and the target workload.
- **A role is not a business authorization decision.** Authorization is resource- and action-specific.
- **Every token has an explicit issuer, audience, expiry and intended use**; token substitution across APIs is rejected.
- **Compromise of one pod, service or database identity must not grant lateral access** to unrelated resources.
- **Security controls are testable in CI and observable in production** — a fitness function is not a control until it executes.

## Related

The accompanying implementation lives in [`zero-trust-auth-service`](https://github.com/Skpandey15/zero-trust-auth-service) — Spring Boot 3.5, RS256 JWT with continuous verification, rotating refresh-token families with reuse detection, Argon2id, TOTP MFA, and an OAuth2.1 / OIDC provider.

## Note on format

The documents are Word files because they carry tables, figures and page structure that survive review and circulation. `Security Architecture.png` is the source diagram, also embedded in v1.1 and from v1.4 onward.
