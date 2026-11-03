# Threat Model (draft)

Status: living document. Update it whenever a change touches a trust boundary: network paths, credentials or signatures.

Method: STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege).

## System summary

Tagwarden mirrors selected container images and Helm charts from upstream registries into a target OCI registry inside an air-gapped network.

- `ClusterMirrorTarget` (cluster-scoped, owned by the platform team) defines the target registry, credentials Secret, CA bundle, proxy settings, allowed sources, allowed namespaces and default policy.
- `ArtifactMirror` (namespaced, owned by tenants) defines a source, artifact type, tag filters, schedule, verification and prune settings.
- The controller turns each `ArtifactMirror` into a CronJob. The Job runs the same binary in `sync` mode. It lists upstream tags through the proxy, selects tags, verifies signatures, copies by digest (index and referrers) and reports the result in its termination message.
- Sync Jobs never call the Kubernetes API. They run without a ServiceAccount token.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Target registry content | Everything in the air-gapped network pulls from it. Poisoned content runs in production. |
| Robot credentials | Push access to the target registry. Stored in a Secret referenced by `ClusterMirrorTarget`. |
| Proxy CA trust | The CA bundle used to trust a TLS-inspecting proxy. Whoever holds that CA key can impersonate any upstream. |
| Signing keys (later phase) | KMS or HSM keys used to re-sign mirrored artifacts. They vouch for content inside the network. |
| Operator image | Runs with controller RBAC and runs every sync Job. A compromised image compromises every mirror. |

## Trust boundaries

1. **Upstream registries over the internet.** Untrusted. Reached only through the HTTPS proxy.
2. **Proxy with TLS inspection.** Partially trusted. It can read and modify traffic if Tagwarden trusts its CA.
3. **Cluster.** The controller and sync Jobs run here. The API server and Secrets are inside this boundary.
4. **Target registry.** Trusted store. Tagwarden writes to it with robot credentials.
5. **Tenant namespaces vs platform team.** Tenants create `ArtifactMirror` objects. Only the platform team creates `ClusterMirrorTarget` objects and decides which sources and namespaces are allowed.

## Threats

Phase column: when the mitigation lands. "Now" means the MVP. Later phases follow the roadmap.

| # | Threat | STRIDE | Mitigation | Phase |
|---|--------|--------|------------|-------|
| T1 | Compromised upstream image (malicious content published under a valid tag) | T | Allow only sources listed in `ClusterMirrorTarget.allowedSources`. Cosign signature verification against configured identities before copy. Trivy vulnerability gate with `VulnerabilityException` (expiry and approver). SBOM attached as referrer. | Now: allowed sources. Later: cosign, Trivy, SBOM |
| T2 | Malicious upstream tag mutation (existing tag re-pointed to new content) | T, R | Resolve each tag to a digest once and copy by digest. Record the mirrored digest. Detect when an upstream tag now points to a different digest, refuse to overwrite the target tag and report it. | Now: digest-first copy. Later: mutation detection |
| T3 | Proxy MITM or abuse of the TLS-inspection CA | S, T | Trust the proxy CA only for the sync Job, from an explicit CA reference, never system-wide. Never skip TLS verification. Digest checks catch altered blobs. Signature verification catches altered manifests even if the CA is abused. | Now: CA scoping, no skip-verify. Later: cosign |
| T4 | Stolen robot token | S, E | Token lives only in a Secret referenced by `ClusterMirrorTarget`. Mounted only into the sync Job. Use a robot account scoped to the mirror projects with push and pull only. Document rotation. Re-signing with a KMS or HSM key lets consumers reject artifacts pushed with a stolen token but not signed. | Now: scoping, docs. Later: re-sign |
| T5 | Tenant mirrors into another tenant's project | E | `ClusterMirrorTarget.allowedNamespaces` controls which namespaces may use a target. Target path derives from the target config and namespace, not from free user input. Validating webhook rejects paths outside the allowed prefix. | Now |
| T6 | Tenant mirrors from a disallowed source | E, T | Webhook and controller both check the source against `allowedSources`. The sync Job re-checks before any network call. | Now |
| T7 | ReDoS through user-supplied tag regex | D | Go `regexp` uses RE2, which runs in linear time. Cap pattern length. Reject invalid patterns at admission. | Now |
| T8 | Credential leakage through status, logs or Events | I | Credentials come only from Secret references. Never written to status, Events, logs, errors or the termination message. Tests assert that secret values do not appear in any of these outputs. Redact registry auth headers in transport debug logs. | Now |
| T9 | Operator image compromise (project supply chain) | T, E | Pin GitHub Actions by commit SHA. Least-privilege workflow permissions. `govulncheck` in CI. Distroless nonroot base. Signed releases, SBOM and SLSA L3 provenance. FIPS build variant. | Now: CI hardening. Later: signed releases, SLSA L3, FIPS |
| T10 | Denial of service by huge images or many tags | D | `keepLatest` capped at 100. Per-Job concurrency limit for blob copies. CronJob `concurrencyPolicy: Forbid`, `activeDeadlineSeconds` and resource limits on sync Jobs. Configurable maximum artifact size. | Now: caps, limits. Later: size limit |
| T11 | Privilege escalation from the sync Job pod | E | No ServiceAccount token (`automountServiceAccountToken: false`). Distroless nonroot, read-only root filesystem, all capabilities dropped, seccomp `RuntimeDefault`, no privilege escalation. Only the target credentials Secret and CA are mounted. | Now |
| T12 | Tampered or forged sync result | R, T | The controller treats the termination message as untrusted input: size-limited, schema-validated, never executed. Mirrored digests can be checked against the target registry. | Now |
| T13 | Prune deletes content the operator did not create | T, D | Prune only tags recorded as created by Tagwarden. Prune is opt-in per `ArtifactMirror`. | Later: prune |

## Open questions

- How signing identities for cosign verification are configured and who may change them.
- Whether the target project path is fully derived or partly user-chosen within an allowed prefix.
- Audit trail format for regulated environments (Events, logs or a separate record).
