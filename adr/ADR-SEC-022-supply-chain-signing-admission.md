# ADR-SEC-022 — Software Supply-Chain Signing, Provenance and Admission

| | |
|---|---|
| **Status** | Accepted — implementation deferred |
| **Date** | 2026-09-20 |
| **Work package** | Deferred to the delivery architecture phase (§23) |
| **Consolidates** | ADR-SEC-010 (former numbering) |
| **Related** | [ADR-SEC-018](ADR-SEC-018-spiffe-workload-identity.md), [ADR-SEC-020](ADR-SEC-020-secrets-kms-key-rotation.md) |

## Context

Every control in this register assumes the software running is the software that was reviewed. A compromised dependency, a poisoned build, or a mutable image tag repointed after approval defeats all of them at once, and none of the runtime controls will notice: the attacker's code runs with legitimate workload identity, legitimate database grants and legitimate network policy.

Registry trust is not sufficient. "It came from our registry" says where the bytes were stored, not who produced them or from what source.

## Decision

**Nothing reaches production that is not signed, scanned, attested and admitted by digest.**

```
PR → review → build → tests → SAST + secret scan + SCA → SBOM
   → image build → image scan → immutable digest → provenance attestation
   → signature → registry → admission verifies → deploy
```

- SBOM generated in CI (CycloneDX or SPDX) and scanned; vulnerabilities are a release gate with governed, time-bounded exceptions.
- Images are signed, with keyless identity-based signing preferred over long-lived signing keys.
- **Admission verifies the expected signer identity, the build workflow that produced the artifact, and the digest** — not merely that *a* signature exists.
- Production deploys pin by digest. Mutable tags are rejected at admission.
- Admission also rejects privileged pod specs and policy violations.

**A signature is provenance, not review.** Signed vulnerable software is still vulnerable; signing answers who built it, not whether it is safe.

## Alternatives considered

**Trust the registry.** Rejected — registry access controls say nothing about artifact origin, and a compromised build pipeline pushes legitimately.

**Scan without blocking.** Rejected — an advisory gate is not a gate; findings accumulate and ship.

**Sign without verifying signer identity at admission.** Rejected — verifying that any signature exists accepts an attacker's signature.

## Consequences

**Positive.** The provenance chain from source to running container is verifiable. A poisoned artifact cannot reach production without also compromising the signing identity and the admission policy.

**Negative.** CI becomes a security-critical, availability-critical system. Vulnerability gates block releases, so exception governance must be real or the gate gets disabled. Keyless signing ties deployment to an external identity provider's availability.

**Neutral.** Implementation is explicitly deferred (§23). The decision stands so that later delivery work builds to it rather than retrofitting.

## Verification

An unsigned image, a mutable tag, an unexpected signer identity, and a digest not matching its attestation are each rejected at admission (§27 exit criteria for the deferred phase).

## References
§13 Supply-chain security, §23 explicitly deferred scope · Sigstore Cosign · Trivy
