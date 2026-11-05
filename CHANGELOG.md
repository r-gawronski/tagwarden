# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1-rc.1] - 2026-11-05

### Highlights

Harbor targets delete tags through the Harbor API. A ClusterMirrorTarget can set its own `maxListedTags` limit. Adds the SBOM design and the SBOM referrer package.

### Added

- **registry:** Harbor tag delete through the Harbor API (#88)
- **api:** Configurable maxListedTags limit per ClusterMirrorTarget (#87)
- **sbom:** Design and SBOM referrer package (#85)

## [0.1.0] - 2026-11-05

### Highlights

First stable release. Same code as 0.1.0-rc.2, promoted after it ran without problems. See the release candidates below for the full list of changes.

## [0.1.0-rc.2] - 2026-11-04

### Highlights

A sync that selects no tags is now a warning (`NoTagsSelected`) instead of a silent success. Release notes come from this changelog.

### Fixed

- Report an empty tag selection loudly (#81)

### Documentation

- Add CHANGELOG and use it for release notes (#82)

## [0.1.0-rc.1] - 2026-11-04

### Highlights

First release candidate. Mirrors container images and Helm OCI charts with tag selection by regex, semver range and keep-latest. Reaches registries through an HTTP proxy and custom CA bundles. Isolates tenants with ClusterMirrorTarget projects and policy limits. Pulls with source credentials and authenticates to Azure Container Registry, Amazon ECR and Google Artifact Registry with workload identity. Mirrors images of annotated pods automatically. A vulnerability gate scans with Trivy, accepts VulnerabilityException objects, and re-scans mirrored tags to untag vulnerable ones. Images and charts are signed with cosign and carry an SBOM.

### Security

- **controller:** Restore hand-edited security fields of sync CronJobs
- **deps:** Bump google.golang.org/grpc to v1.83.2 (CVE-2026-84445)

### Added

- **tags:** Add tag selection with regex, semver range and keep latest
- **api:** Add v1alpha1 types with CEL validation
- **api:** Per-project namespace access, stricter hosts, paths and schedules
- **registry:** Add transport with proxy, custom CA and mTLS
- **sync:** Copy selected tags by digest with referrers and mutation policy
- **BREAKING** **api:** Rename platforms to requiredPlatforms
- **sync:** Sync referrers of up-to-date tags
- **syncspec:** Add spec contract between controller and sync job
- **sync:** Report the selected tags in order
- **cmd:** Add sync subcommand with termination-log result and audit log
- **cmd:** Check the source registry before any network call
- **registry:** Add host and dial checks to the transport
- **sync:** Record per-artifact audit details
- **cmd:** Check every source request, redirect and connection
- **controller:** Report ClusterMirrorTarget Secret readiness
- **controller:** Render each ArtifactMirror into a hardened CronJob
- **controller:** Report sync results from finished Jobs
- Wire the controllers with operator namespace, sync image and RBAC
- **chart:** Add schema, image digests, sync image, denied CIDRs and mirrors
- **controller:** Label sync pods with target and egress mode
- **chart:** Allow manager pod annotations and labels
- **api:** Add allowRepositoryOverride to target projects
- **api:** Add ClusterMirrorTarget spec.limits
- **controller:** Refuse schedules below minSyncInterval
- **controller:** Cap mirrors per namespace, keepLatest and explicit tags
- **sync:** Refuse artifacts larger than maxArtifactSize
- **api:** Add sync-now annotation and sync request status
- **controller:** Start a sync Job for each new sync-now request
- **controller:** Show sync CronJobs under the mirror's Argo CD app
- **chart:** Add argocd.tracking and argocd.instanceLabel values
- **api:** Add sourceCredentials and sourceCABundles to ClusterMirrorTarget
- **sync:** Pull with source credentials and trust a per-source CA
- **controller:** Validate source credential and CA Secrets of a target
- **controller:** Mount only the source Secrets of a mirror's registry
- **controller:** Readable names for generated CronJobs and ConfigMaps (#40)
- **api:** Add workload identity and Azure registry auth to ClusterMirrorTarget
- **sync:** Authenticate to Azure Container Registry with workload identity
- **controller:** Run Azure-auth sync pods with a projected workload identity token
- **api:** Add AWS IRSA and Amazon ECR registry auth to ClusterMirrorTarget
- **sync:** Authenticate to Amazon ECR with IRSA
- **controller:** Run AWS-auth sync pods with a projected STS-audience token
- **api:** Add autoMirror to ClusterMirrorTarget
- **controller:** Parse pod image refs for auto-mirror
- **controller:** Mirror images of annotated pods
- **api:** Add GCP workload identity federation and Artifact Registry auth to ClusterMirrorTarget
- **sync:** Authenticate to Google Artifact Registry with workload identity federation
- **controller:** Run GCP-auth sync pods with a projected provider-audience token
- **vuln:** Report parser and verdicts for the vulnerability gate (#21) (#53)
- **chart:** Add the in-chart Trivy server for the vulnerability gate (#52)
- Vulnerability gate API and VulnerabilityException (#21) (#54)
- **controller:** Probe the Trivy server for scanner readiness (#21) (#55)
- **sync:** Scan gated tags through the Trivy sidecar before copying (#21) (#56)
- **controller:** Render the Trivy sidecar for gated sync Jobs (#21) (#57)
- **controller:** Record gate results in status and relay them to pods (#21) (#59)
- Re-scan mirrored tags of gated mirrors and untag vulnerable ones (#21) (#65)

### Fixed

- **tags:** Strict semver tags, prerelease opt-in, explicit tags and program size cap
- **tags:** Reject leading zeros and clarify prerelease opt-in
- **sync:** Fall back to GET when HEAD gives no digest
- **sync:** Report an overwritten tag as mutated only after the copy
- **sync:** Treat arm64 and arm64/v8 as the same platform
- **sync:** Rune-safe messages, fixed page cap and review comments
- **sync:** Check target before fetching referrers of up-to-date tags
- **sync:** Never turn a registry error on HEAD into a GET
- **sync:** Report the target digest of an ignored mutated tag
- **cmd:** Exit 3 on config errors and 1 on panics and transient errors
- **cmd:** Keep the first errors when truncating the termination message
- **cmd:** Deterministic auth choice and clearer audit lines
- **cmd:** Ignore env proxy, cache lookups and document crash exit code
- **controller:** Guard foreign objects and re-check shared target paths
- **config:** Set SYNC_IMAGE from the final manager image in config/default
- **controller:** Compare host, DNS and scheduling fields of sync pods
- **chart:** Require the sync image and denied CIDR flags in manager.args
- **chart:** Keep chart-managed targets and mirrors on uninstall
- **chart:** Default the sync image tag to the manager image tag
- **controller:** Restore only tagwarden.dev pod labels
- **registry:** Retry connection errors while network policy settles
- **cmd:** Retry temporary DNS errors while network policy settles
- **registry:** Retry only during a shared startup window
- **controller:** Refuse target repository overrides in shared projects
- **controller:** Refuse targets whose allowedSources share a path segment
- **sync:** Cap referrers of an artifact at maxArtifactSize
- **controller:** Check schedule gaps over five years
- **controller:** Keep the LimitExceeded message stable for mirror counts
- **controller:** Make the CronJob the controller of manual sync Jobs
- **controller:** Read Jobs past the cache when handling sync requests
- **controller:** Refuse a sync-now value whose Job already finished
- Limit Azure workload identity to ACR hosts, known authorities and the ACR scope
- **sync:** Fold only ASCII letters when matching ACR hosts
- **sync:** Drop the default port from the ACR token exchange host
- **sync:** Request one-hour STS sessions for ECR tokens and expand IRSA docs
- **controller:** Harden auto-mirror against bad images, drift and name clashes
- **sync:** Keep Google access tokens on the registry host and narrow the impersonated scope
- **sync:** Resolve explicit-only tags without listing the source (#62)
- **gate:** Fail fast and loud when the scanner sidecar does not start (#21) (#63)

### Changed

- Share source checks and tag policy validation
- **controller:** Re-check namespace mirror counts only when they can change
- **controller:** Cache schedule gap checks (#33)

### Documentation

- Add security policy, contributing guide and threat model draft
- Forbid customer and industry names in CLAUDE.md
- Add govulncheck to pre-PR checks and describe DCO check
- Add fix target, embargo limit and reporting status to security policy
- Rework threat model around roadmap phases and design decisions
- Add phase 0 spike results
- Describe project-based tenant isolation and tag filter caps in threat model
- **threat-model:** List sync job mounts and phase 1 audit lines
- **threat-model:** Describe the job source checks and their limits
- **threat-model:** Describe redirect and connect checks and exit codes
- Record phase 1 controller enforcement in the threat model
- Align T16 and T17 with the controller and note namespace moves
- Describe the Helm chart, its generation and install
- Note that secure metrics scraping needs the CA in prometheus.tlsConfig
- Describe the end-to-end tests
- **threat-model:** Note that NetworkPolicy enforcement at pod start depends on the CNI
- Describe the sync pod egress labels and example NetworkPolicies
- Describe dial retries while network policy settles
- Describe CI path filters, the e2e label and the merge checklist
- Note that a skipped e2e check shows as success
- Rewrite README and move install and network policy docs
- Clearer how-it-works diagram
- Styled how-it-works diagram and D2 alternative
- Add sync run sequence diagram
- Hand-drawn diagram variants
- Theme-aware hand-drawn diagrams, drop D2 variants
- Diagram colors readable on light and dark backgrounds
- Add use cases to the README
- Explain why Renovate needs a filtered mirror
- Move the general motivation into the why section
- Add banner, logo and diagram images to the README
- Replace the Renovate mermaid diagram with an image
- Document allowRepositoryOverride and path squatting (T23)
- **api:** Note that target.repository needs allowRepositoryOverride
- Note allowedSources uniqueness and artifact type in T17, T23
- Describe per-target limits and complementary quotas
- Note that the size check counts shared layers per platform
- Add Argo CD sync-now action and health checks
- Note in T10 that sync-now requests respect minSyncInterval
- **argocd:** Set the sync-now annotation to the current time
- Explain how requested sync Jobs interact with the CronJob
- Show sync Jobs in the Argo CD app tree
- Describe source credentials and per-source CA bundles
- Scope per-source CA wording and correct the credential redirect claim
- **argocd:** Explain project destinations, inherit trust and OutOfSync display
- Describe Azure Container Registry auth with workload identity
- Per-target ServiceAccounts, host limits and missing ServiceAccount for Azure auth
- Mark the fixed ACR scope as public-cloud and national clouds as untested
- Describe Amazon ECR auth with IRSA
- Auto-mirror from pod annotations
- Auto-mirror limits and threat model T30
- Match T30 to the trimmed pod cache
- Describe Google Artifact Registry auth with workload identity federation
- Tighten Google workload identity federation setup and threat model
- Design for the vulnerability gate (#21)
- Narrow the vulnerability gate to auto-mirror, add scanner modes and quarantine (#21)
- Make the vulnerability gate report by default with Block and Quarantine actions (#21)
- Use one Trivy client/server scanner for the vulnerability gate and drop quarantine (#21)
- Finalize the vulnerability gate design (#21)
- Record the Trivy client/server spike for the vulnerability gate (#21) (#51)
- Vulnerability gate install guide, README and threat model (#21) (#72)
