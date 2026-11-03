# Threat Model (draft)

Status: living document. Update it whenever a change touches a trust boundary: network paths, credentials or signatures.

Method: STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege).

## System summary

Tagwarden mirrors selected container images and Helm charts from upstream registries into a target OCI registry inside an air-gapped network.

- `ClusterMirrorTarget` (cluster-scoped, owned by the platform team) defines the target registry, credentials Secret, CA bundle, proxy settings, allowed sources, the projects tenants may push to with the namespaces allowed to use each one, and default policy.
- `ArtifactMirror` (namespaced, owned by tenants) defines a source, artifact type, tag filters, schedule, verification and prune settings.
- The controller renders each `ArtifactMirror` into a CronJob in the operator namespace (`tagwarden-system`). Sync Jobs never run in tenant namespaces. The link is cross-namespace, so cleanup uses a finalizer on the `ArtifactMirror` and labels on the CronJob, not ownerReferences.
- The Job runs the same binary in `sync` mode. It lists upstream tags through the proxy, selects tags, verifies signatures, copies by digest (index and referrers) and reports the result in its termination message.
- Sync Jobs never call the Kubernetes API. They run under a dedicated ServiceAccount with `automountServiceAccountToken: false`.
- `VulnerabilityException` (cluster-scoped, owned by the security team) allows a known vulnerability through the scan gate until it expires.
- Phase 1 has no admission webhook. Validation is CEL in the CRD schema plus the same checks in the controller at reconcile time.

## Roadmap phases

Each mitigation names the phase that delivers it.

| Phase | Scope |
|-------|-------|
| 1 | MVP images: CRDs with CEL validation, tag selection, proxy and CA transport, sync engine by digest, CronJob controller, Helm chart for the operator, signed operator images |
| 2 | Helm chart sources: OCI and classic repositories with `.prov` |
| 3 | Supply chain: cosign verification with offline trusted root, referrers copy, re-signing with a KMS key, SBOM, Trivy gate, `VulnerabilityException` |
| 4 | Lifecycle: prune of operator-created tags, tag mutation policy, registry tag immutability |
| 5 | Hardening and operations: metrics, OTel, audit log, NetworkPolicy per Job, FIPS build, concurrency limits |
| 6 | Release and open source: goreleaser, SLSA L3, Scorecard publishing, public repository |

## Assets

| Asset | Why it matters |
|-------|----------------|
| Target registry content | Everything in the air-gapped network pulls from it. Poisoned content runs in production. |
| Target push credentials | Push access to the target registry. Stored in a Secret in the operator namespace, referenced by `ClusterMirrorTarget`. |
| Upstream pull and proxy credentials | Access to private upstream sources and to the egress proxy. |
| Proxy CA trust | The CA bundle used to trust a TLS-inspecting proxy. Whoever holds that CA key can impersonate any upstream. |
| Verification config | Cosign trusted root and signer identities. Whoever changes them decides what counts as signed. |
| Signing keys (phase 3) | KMS or HSM keys used to re-sign mirrored artifacts. They vouch for content inside the network. |
| Operator image | Runs with controller RBAC and runs every sync Job. A compromised image compromises every mirror. |

## Trust boundaries

1. **Upstream registries over the internet.** Untrusted. Reached only through the HTTPS proxy.
2. **Proxy with TLS inspection.** Fully trusted for content until phase 3 signature verification. It can read and modify traffic if Tagwarden trusts its CA.
3. **Operator namespace.** The controller, CronJobs, sync Jobs and target credentials live here. Tenants have no access.
4. **Tenant namespaces.** Tenants create `ArtifactMirror` objects and nothing else that Tagwarden acts on.
5. **Target registry.** Trusted store. Tagwarden writes to it with push credentials.
6. **Platform team and security team.** Only the platform team creates `ClusterMirrorTarget` objects. Only the security team creates `VulnerabilityException` objects.

## Threats

| # | Threat | STRIDE | Mitigation | Phase |
|---|--------|--------|------------|-------|
| T1 | Compromised upstream image (malicious content published under a valid tag) | T | Allow only sources listed in `ClusterMirrorTarget.allowedSources`. Cosign signature verification against configured identities before copy. Trivy gate with `VulnerabilityException`. SBOM attached as referrer. | 1: allowed sources. 3: cosign, Trivy, SBOM |
| T2 | Upstream tag mutation (existing tag re-pointed to new content) | T, R | Resolve each tag to a digest once and copy by digest. Record the mirrored digest. Detect when an upstream tag now points to a different digest, refuse to overwrite the target tag and report it. Use registry tag immutability where the target supports it. | 1: digest-first copy. 4: mutation policy, immutability |
| T3 | Proxy MITM or abuse of the TLS-inspection CA | S, T | Trust the proxy CA only in the sync Job, from an explicit CA reference, never system-wide. Never skip TLS verification. Digest checks do not help here: the proxy also serves the tag-to-digest resolution, so it can return a forged manifest with matching blobs. Until phase 3 the proxy CA is fully trusted. Whoever holds its key can replace any mirrored artifact. Signature verification against pinned identities and an offline trusted root (T19) closes this. | 1: CA scoping, no skip-verify. 3: cosign |
| T4 | Stolen target push credentials | S, E | Credentials live only in a Secret in the operator namespace (T14). Use a robot account scoped to the mirror projects with push and pull only. Document rotation. Re-signing with a KMS or HSM key lets consumers reject artifacts pushed with a stolen token but not signed. | 1: scoping, docs. 3: re-sign |
| T5 | Tenant mirrors into another tenant's project | E | `ClusterMirrorTarget.projects` lists every project a mirror may push to, each with a required `namespaceSelector`. A mirror may push only to a listed project whose selector matches its namespace. A shared project such as `mirror` with an empty selector (`{}`) lets all teams share mirrored sources. Team projects use label selectors. The target path derives from the target config and the source (T17), not from free user input. CEL in the CRD schema rejects malformed paths. The controller checks at reconcile that the project is listed and its selector matches the labels of the mirror's namespace. On failure it sets Ready=False with reason `ProjectNotAllowed`, records an Event and removes the CronJob and spec ConfigMap. Namespace label changes trigger a re-check. | 1: controller enforcement in place |
| T6 | Tenant mirrors from a disallowed source | E, T | CEL rejects malformed source references. `allowedSources` applies to every project of a target, so a team that needs a source other teams must not use gets its own target. CEL cannot read `ClusterMirrorTarget`, so the controller checks the source against `allowedSources` at reconcile. The controller passes `allowedSources` in the Job spec, and the sync Job re-checks the source registry before any network call: exact `host[:port]` match, case-insensitive, with `docker.io`, `index.docker.io` and `registry-1.docker.io` treated as one registry. A mismatch fails the Job with a config error. The controller uses the same check and sets Ready=False with reason `SourceNotAllowed`, also for a source that is a literal internal address (T16), and renders no CronJob. | 1: controller and Job enforcement in place |
| T7 | ReDoS or resource exhaustion through tag filters | D | Go `regexp` uses RE2, which runs in linear time. Cap the number of patterns and their length in CEL. Reject a pattern whose compiled program exceeds 2000 instructions. Cap the semver constraint length. Reject invalid patterns and constraints at reconcile. | 1 |
| T8 | Credential leakage through status, logs, Events or errors | I | Credentials come only from Secret references. This covers target push, upstream pull and proxy credentials. Never write them to status, Events, logs, errors or the termination message. Redact userinfo in every URL before it reaches an error or log, including proxy URLs of the form `user:pass@host`. Redact auth headers in transport debug logs. Tests assert that secret values do not appear in any of these outputs. | 1 |
| T9 | Operator image compromise (project supply chain) | T, E | Pin GitHub Actions by commit SHA. Least-privilege workflow permissions. `govulncheck` and CodeQL in CI. Distroless nonroot base. Signed operator images. SLSA L3 provenance and published Scorecard results. | 1: CI hardening, signed images. 6: SLSA L3, Scorecard |
| T10 | Denial of service by huge images or many mirrors | D | `keepLatest` capped at 100. CronJob `concurrencyPolicy: Forbid`, `activeDeadlineSeconds` and resource limits on sync Jobs. Global and per-Job concurrency limits. Configurable maximum artifact size. | 1: caps, limits. 5: concurrency limits, size limit |
| T11 | Privilege escalation from the sync Job pod | E | Dedicated ServiceAccount with `automountServiceAccountToken: false`. Distroless nonroot, read-only root filesystem, all capabilities dropped, seccomp `RuntimeDefault`, no privilege escalation. Only the target credentials, the target and proxy CAs and the target client certificate are mounted, at fixed paths. Proxy credentials come in as env from a Secret reference. Tenant fields reach the Job only through the spec file in a ConfigMap, never as image, command, env or volumes. The controller renders the pod with the `tagwarden-sync` ServiceAccount (no RBAC bindings), `enableServiceLinks: false`, resource limits, and Secrets only as volume or `secretKeyRef` references, never as values. Exit code 3 (config error) fails the Job without retries. A hand edit of the `tagwarden.dev/` pod labels, image, args, ServiceAccount, token mount, security contexts, host namespaces and aliases, DNS config, node, runtime class, pull secrets, volumes, mounts or env of a sync CronJob is reverted on the next reconcile. | 1: controller rendering in place |
| T12 | Tampered or forged sync result | R, T | The controller treats the termination message as untrusted input. It reads it only from a pod controlled by the mirror's Job, refuses a message over 4096 bytes, of another version, with negative counts or with an invalid tag or digest, and then reports `Crashed` instead. Unknown fields are ignored. Quoted errors are cut to 256 bytes. The report only fills in status and Events; it never decides what a mirror may do. Mirrored digests can be checked against the target registry. | 1: controller enforcement in place |
| T13 | Prune deletes content the operator did not create, or still in use | T, D | Prune only tags recorded as created by Tagwarden. Prune is opt-in per `ArtifactMirror`. A tag shared by several mirrors is deleted only when no mirror selects it any more (T17). | 4 |
| T14 | Target credentials exposed to tenants | I, E | Sync Jobs and CronJobs run only in the operator namespace. Target push credentials never leave it. No tenant pod mounts them. The controller reads Secrets only in its own namespace. | 1 |
| T15 | Controller privilege escalation | E | The controller creates Jobs, CronJobs and ConfigMaps only in its own namespace, through a Role, not a ClusterRole. It reads Secrets only in its own namespace. Cluster-wide access is limited to Tagwarden CRDs. RBAC markers are the source of truth and are reviewed on every change. | 1 |
| T16 | SSRF or lateral movement from a sync Job through crafted sources or redirects | S, E, I | The sync Job reaches the network only through the proxy. Refuse link-local, cloud metadata, loopback and cluster pod and service CIDRs as source hosts, at reconcile and in the Job. The Job resolves the source host itself before any network call and refuses it if any address is loopback, link-local, unspecified, in `0.0.0.0/8`, a metadata address (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`), a NAT64 address (`64:ff9b::/96`) that embeds one of these, or inside `deniedCIDRs` (the controller fills in the pod and service CIDRs). The source transport repeats this check on the host of every request, including each redirect hop, and on the resolved address of every direct connection, so a name cannot be rebound between check and connect. Connections to the proxy itself are not checked. `allowedSources` applies to the first source host only, not to redirect hosts, because registries redirect blob downloads to storage hosts. Limitation: with a proxy, the proxy resolves names, not the Job. The Job check catches literal internal addresses and names that the cluster DNS maps to internal addresses, but not a name that only the proxy resolves to an internal address. When a request goes through the proxy, any lookup error passes, because the proxy resolves the name and its ACL is the control; this covers NXDOMAIN, common in air-gapped clusters. Each host is resolved once per run. During the startup window (below) a temporary lookup error (timeout, server failure, refused query) is retried and not cached, so a race at pod start neither fails the run nor lets a proxied host skip the check. NXDOMAIN is not retried. Without a proxy a lookup error fails the run as transient (exit 1), and every direct connection is still checked on its resolved address at dial time. Refusals are config errors (exit 3). The Job ignores proxy variables other than the `HTTPS_PROXY` and `NO_PROXY` the controller sets. The proxy's own ACL must also deny internal ranges, because the proxy resolves names. Sync pods carry `tagwarden.dev/target` (the target name, or `h-` and a sha256 prefix when the name is not a valid label value) and `tagwarden.dev/egress` (`proxy` or `direct`), so cluster admins can enforce the egress path per target with NetworkPolicies: `proxy` pods reach only the proxy, the target and DNS. The controller reverts hand edits of these labels. NetworkPolicy enforcement at pod start is CNI-dependent (kindnet, for example, can pass the first packets of a new pod), so the in-Job checks are the primary control. Other CNIs (the k3s embedded NetworkPolicy controller, for example) reject a new pod's packets until its allow rules are programmed, about a second after start. Only during the first ~35 s of a run, which ends early at the first successful request, both transports retry a request whose connection to the registry or the proxy failed at dial time (refused, unreachable, timeout, temporary DNS failure), with exponential backoff up to about 30 s per request. Nothing was sent on such a connection. Refusals by the host and connect checks are never retried, nor are TLS errors, proxy authentication failures or errors after a connection was set up. | 1: host, redirect and connect checks, egress labels. 5: NetworkPolicy |
| T17 | Target path collision (two sources write the same target repository) | T | The default target path is `<project>/<source-registry>/<source-repo>`, for example `mirror/docker.io/library/nginx`. Different sources never collide by default. Several mirrors may share a target repository when they have the same source: their tag sets are unioned and each tag records which mirrors selected it. If a different source maps to an already-claimed path, which is only possible through an explicit target override, the controller sets Ready=False with reason `TargetConflict` and does not sync. The oldest mirror (by creation time, then namespace and name) that is allowed to use the project owns the path, so a mirror refused for its project cannot block it. Sources compare after folding the Docker Hub names and adding the implicit `library/` prefix. The default path turns `host:port` into `host-port`, which can collide with a registry whose host name is literally `host-port`; the sources differ, so the conflict check catches it. The controller never updates or deletes a CronJob or ConfigMap whose annotations name another mirror (`OwnershipConflict`). The check covers mirrors of the same `ClusterMirrorTarget`. | 1: controller enforcement in place |
| T18 | `VulnerabilityException` abuse (tenant approves its own exception) | E, R | `VulnerabilityException` is cluster-scoped. A separate ClusterRole held by the security team grants write access. Tenants have none. Every exception has an expiry and an approver. The controller ignores expired exceptions. | 3 |
| T19 | Forged or stale cosign trust root, or changed signer identities | S, T | Verification runs offline against a trusted root delivered with the operator or from a Secret in the operator namespace, never fetched through the proxy at verify time. Reject a trusted root past its validity and document how to refresh it. Signer identities are set per allowed source in `ClusterMirrorTarget`, so only the platform team can change them. Tenants cannot disable verification that the target requires. | 3 |
| T20 | Repudiation: no record of who mirrored what | R | Status and Events record the mirrored digests per tag. An audit log records each sync: the requesting `ArtifactMirror`, source reference, digest, target reference, verification result and time. The Kubernetes audit log records who created or changed the `ArtifactMirror`. | 1: status, Events, one JSON line per artifact on the Job stdout. 5: audit log |
| T21 | Tampered classic Helm repository | T, D | Require HTTPS for repository and chart URLs. Verify `.prov` against a per-source keyring when configured. Cap the `index.yaml` size. Resolve relative chart URLs against the index URL and apply the source host checks (T16) to absolute ones. | 2 |
| T22 | Unbounded upstream tag lists | D | Cap the number of pagination pages per source. A listing of more than 10000 tags stops with an error instead of a truncated list, so the selection never runs on partial input. The error is reported in status. | 1 |

## Compliance items

These are requirements of regulated environments, not threat mitigations.

- FIPS 140 build variant of the operator image. Phase 5.

## Resolved questions

- Signer identities for cosign verification are configured per allowed source in `ClusterMirrorTarget` and changed only by the platform team (T19).
- The target path is derived from the source by default. An explicit override is possible but cannot claim a path owned by another source (T17).
- Audit trail: status and Events in phase 1, a dedicated audit log in phase 5 (T20).

## Open questions

- Distribution format of the offline trusted root: bundled in the image, a Secret, or both.
- Whether tenants may add stricter signer identities on top of those in `ClusterMirrorTarget`.
