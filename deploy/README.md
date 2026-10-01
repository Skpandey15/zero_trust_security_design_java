# Deploy

Container images, Kubernetes manifests and scripts for running the platform on the local k3d cluster (`k3d-dev`, in WSL2), laid out the way a production deployment would be: the app is a portable **base**, everything environment-specific is an **overlay**.

```
deploy/
├── scripts/
│   ├── build-images.sh     four images, tagged with the git SHA (never :latest)
│   ├── deploy-local.sh     bootstrap: cert-manager -> cluster config -> secrets, then build -> import -> apply
│   ├── smoke-test.sh       end-to-end sign-in journey on the deployed stack (register, sign in, turn on MFA, refuse a password alone)
│   ├── cluster-up.sh       after a reboot: start any stopped node, wait until the platform is healthy
│   ├── apply.sh            render the overlay and apply it (shared by deploy-local and Jenkins)
│   └── teardown-local.sh   removes the zero-trust namespace; leaves other namespaces alone
├── docker/                 packaging-only Dockerfiles (CI builds the jar once, Kaniko packages it)
├── registry/               in-cluster image registry
├── jenkins/                Jenkins platform: RBAC, caches, cert, Helm values, install.sh
└── k8s/
    ├── bootstrap/          the namespace (applied by the platform step, not the pipeline)
    ├── base/               the application - no environment assumptions
    ├── overlays/k3d/       ingress, hostnames, edge certificate, Traefik middlewares
    └── cluster/k3d/        cluster-scoped: private CA, DNS override, admission policy
```

```bash
# from WSL, repo root
deploy/scripts/deploy-local.sh
```

Then `https://zerotrust.localtest.me:8443`. `localtest.me` resolves to `127.0.0.1` through public wildcard DNS, so no `hosts` edit is needed. The certificate comes from a private CA; the script writes it to `deploy/.local/zero-trust-ca.crt` — import it into the browser, or use `curl --cacert`.

## After a reboot

```bash
deploy/scripts/cluster-up.sh
```

After the machine restarts, `k3d cluster start` can leave a node stopped (an agent that races the control plane exits with "failed to start networking"). Volumes are pinned to nodes, so one missing agent takes the registry, Postgres and the Gradle cache with it, and the symptoms look unrelated — `ImagePullBackOff`, `CrashLoopBackOff`, a Jenkins build that "failed". The script starts the control plane first, then any node still down, waits for every node and then each workload in dependency order, and reports what is still unhealthy. It only judges this platform's namespaces; another project sharing the cluster is mentioned but never fails it. On a healthy cluster it just verifies, in about eight seconds.

## Pipeline (Jenkins)

Jenkins runs **in the cluster** (`https://jenkins.zerotrust.localtest.me:8443`), and every build runs in a disposable pod agent defined by the [`Jenkinsfile`](../Jenkinsfile). Nothing builds on the controller.

```
checkout -> build+test (JVM services ‖ frontend) -> validate manifests (server dry-run)
         -> package (Kaniko) -> scan (Trivy) -> deploy (main only) -> rollout verification
```

```bash
deploy/scripts/deploy-local.sh    # once: platform, secrets, first deploy
deploy/jenkins/install.sh         # once: registry + Jenkins
```

- **The jar that is tested is the jar that ships.** Gradle builds and tests once, on a cached volume; Kaniko packages that artefact (`deploy/docker/`). No Docker socket, no privileged pod.
- **Two identities, two scopes.** A human/platform step owns the cluster (cert-manager, CA, DNS, admission policy, secrets, namespace). The pipeline's `jenkins-agent` ServiceAccount can only apply the application objects in `zero-trust` — it cannot read secrets, delete, exec, or touch cluster-scoped objects.
- **Validation is server-side.** `kubectl apply --dry-run=server` checks real schemas, CRDs and admission (including the image policy) without changing anything.
- **Deploys are `main`-only**, by immutable git-SHA tag, gated on `rollout status`.
- **Trigger:** the job polls the repo every 5 minutes (multibranch over plain git). A local cluster has no public address, so a webhook cannot reach it; pull requests are not discovered without the GitHub branch-source plugin.
- Login: user `admin`, password from the `jenkins` secret (command printed by `install.sh`).

## Topology

```
browser ──TLS──> Traefik ──> frontend            (static, 2 replicas)
                        ├─> bff ──> redis        (sessions, 2 replicas)
                        │     ├──> resource-server  (2 replicas)
                        │     └──> issuer URL ──(TLS, private CA)──┐
                        └─> authorization-server ─> postgres       │
                              ^───────────────────────────────────┘
```

Two hostnames: `zerotrust.localtest.me` (app) and `auth.zerotrust.localtest.me` (issuer). The issuer is **one URL everywhere** — the browser is redirected to it, the BFF discovers it, the Resource Server checks `iss` against it — so a CoreDNS override points that name at the ingress controller from inside the cluster.

## What makes it production-shaped

| Concern | Here |
|---|---|
| Pod hardening | Namespace enforces **Pod Security `restricted`**. Every container: non-root fixed uid, read-only root filesystem, all capabilities dropped, no privilege escalation, `RuntimeDefault` seccomp |
| Network | **Default deny** ingress and egress; one allow rule per real dependency (`base/networkpolicies.yaml` draws the call graph). Postgres reachable only from the Authorization Server, Redis only from the BFF |
| Identity of workloads | One ServiceAccount each, **no API token mounted** — nothing here talks to the Kubernetes API |
| Transport | TLS at the edge via cert-manager; the BFF trusts the private CA through an init-built trust store, not by disabling verification |
| Edge exposure | Only listed paths are routed. Actuator, H2 console and the admin API are not reachable from outside. Rate limit and security headers on the issuer |
| Admission | `ValidatingAdmissionPolicy` (fail closed): no `:latest`, image source allowlist, memory limit on every container, no `hostNetwork` |
| Secrets | Generated on first deploy, held only in the cluster, never in git, **never rotated by a re-run**. Stable RSA signing key so tokens survive a restart |
| Availability | Rolling updates with `maxUnavailable: 0`, PodDisruptionBudgets, topology spread, startup/liveness/readiness probes, requests and limits |
| Rollback | Immutable git-SHA tags: `kubectl rollout undo` goes to an image that still exists |

## Not production-equivalent yet — read before trusting it

These are real gaps, listed rather than hidden:

- **No workload mTLS / SPIFFE** ([ADR-SEC-018](../adr/ADR-SEC-018-spiffe-workload-identity.md)). Service-to-service traffic inside the namespace is plain HTTP, constrained only by NetworkPolicy. Network policy is not authentication.
- **No image signature verification** ([ADR-SEC-022](../adr/ADR-SEC-022-supply-chain-signing-admission.md)). The pipeline builds, scans (Trivy) and pushes to the registry, but does not sign (Cosign) or attach an SBOM/provenance; the admission policy checks source and tag, not provenance.
- **Registry has no auth or TLS**, and Kaniko runs as root inside an unprivileged container (namespace enforces Pod Security `baseline`, not `restricted`). Jenkins plugins are not version-pinned, and the `jenkins` namespace has no NetworkPolicies.
- **Secrets are Kubernetes Secrets** — base64 in etcd, not KMS-backed or externally managed ([ADR-SEC-020](../adr/ADR-SEC-020-secrets-kms-key-rotation.md)). No key-rotation procedure yet.
- **Authorization Server is a single replica** — its authorization state and login session are still in memory (design document 27.8).
- **Postgres and Redis are in-cluster single instances**, Redis unencrypted. Production would use managed, replicated, encrypted services.
- **No observability stack.** Actuator exposes Prometheus metrics, but nothing scrapes them in this cluster and there is no log shipping or tracing.
- **Two-step verification is TOTP only, with sharp edges.** It is enforced on the interactive sign-in page (lockout, throttle, single-use codes). But there is no way to switch it off or recover from a lost authenticator (ADR-SEC-005), no QR code (manual key or `otpauth://` link only), no WebAuthn/passkeys, and an account without it signs in at password assurance rather than being refused: the risk-based step-up exists on the token API only, where it can answer with an enrolment token, whereas the sign-in page cannot, and a refusal with no way to comply is a lockout.
- **`amr` is recorded but not yet demanded.** Tokens now say what the session proved, but nothing requires MFA assurance for any operation: the Resource Server has no endpoints yet.
- **The smoke test is not in the pipeline.** `deploy/scripts/smoke-test.sh` drives the real ingress; a Jenkins agent pod cannot reach `*.localtest.me` (it resolves to its own loopback), so it is run by hand after a deploy.

## Verified on the local cluster

All nine pods Ready; TLS at the edge with the private CA; OIDC discovery served at the issuer URL and the BFF discovering it from inside the cluster; `/api/session` reachable through the BFF; HTTP redirects to HTTPS; security headers present; the frontend pod cannot reach Postgres or the BFF (NetworkPolicy); Pod Security rejects a non-compliant pod.

Quirk of sharing the cluster with `tiny-url`: its hostless catch-all ingress answers any path the edge does *not* route — so `https://auth.zerotrust.localtest.me:8443/actuator/health` returns the Tiny URL page, not the actuator. Nothing is exposed; a dedicated cluster would return 404.

## Shared-cluster footprint

The k3d cluster also runs `tiny-url`. This deployment leaves it alone and adds: the `zero-trust` namespace; cert-manager (its own namespace, cluster CRDs); a `zt-edge` Service and a `coredns-custom` ConfigMap in `kube-system`; and one ValidatingAdmissionPolicy scoped to `zero-trust`. `teardown-local.sh` removes all of it except cert-manager.
