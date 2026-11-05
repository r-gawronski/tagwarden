# Features

How to turn on each feature, who owns the setting, what the default is
and how to check that it works. Each section links to the longer guide.

This file is the feature reference. Every change that adds, removes or
changes a user-visible feature, field, flag, chart value, condition,
Event or metric updates it in the same pull request.

Owners:

- **platform**: the platform team, in a `ClusterMirrorTarget` or the
  chart values.
- **team**: a tenant team, in an `ArtifactMirror` in its namespace.
- **security**: the security team, in a `VulnerabilityException`.

## Index

| Feature | Owner | Default | Where |
| --- | --- | --- | --- |
| [Image mirror](#image-mirror) | team | on | `ArtifactMirror` |
| [Helm OCI chart mirror](#helm-oci-chart-mirror) | team | off | `spec.type: HelmOCI` |
| [Tag selection](#tag-selection) | team | required | `spec.tags` |
| [Prereleases](#prereleases) | team | off | `spec.tags.allowPrerelease` |
| [Required platforms](#required-platforms) | team | off | `spec.requiredPlatforms` |
| [Suspend](#suspend) | team | off | `spec.suspend` |
| [Sync now](#sync-now) | team | off | annotation `tagwarden.dev/sync-now` |
| [Custom target path](#custom-target-path) | platform + team | off | `allowRepositoryOverride`, `target.repository` |
| [Projects and namespace access](#projects-and-namespace-access) | platform | required | `spec.projects` |
| [Allowed sources](#allowed-sources) | platform | required | `spec.allowedSources` |
| [Limits](#limits) | platform | on, with defaults | `spec.limits` |
| [Moving tags](#moving-tags) | platform | `Fail` | `spec.policy.onTagMutation` |
| [Proxy](#proxy) | platform | off | `spec.proxy` |
| [Target CA and mTLS](#target-ca-and-mtls) | platform | off | `caBundleSecretRef`, `clientCertSecretRef` |
| [Push credentials](#push-credentials) | platform | required | `credentialsSecretRef` or `auth` |
| [Private sources](#private-sources) | platform | anonymous | `sourceCredentials`, `sourceCABundles` |
| [Cloud workload identity](#cloud-workload-identity) | platform | off | `auth`, `workloadIdentity` |
| [Harbor tag delete](#harbor-tag-delete) | platform | off | `spec.registryFlavor: Harbor` |
| [Denied CIDRs](#denied-cidrs) | platform | empty | chart `deniedCIDRs` |
| [Network policies](#network-policies) | platform | off | your own NetworkPolicy, chart `networkPolicy` |
| [Auto-mirror](#auto-mirror) | platform + team | off | `spec.autoMirror`, pod annotation |
| [Vulnerability gate](#vulnerability-gate) | platform | off | `spec.autoMirror.vulnerabilityGate`, chart `trivy` |
| [Re-scan and untag](#re-scan-and-untag) | platform | off | `rescanInterval`, `onVulnerableTag` |
| [Vulnerability exceptions](#vulnerability-exceptions) | security | none | `VulnerabilityException` |
| [Signatures and referrers](#signatures-and-referrers) | - | always on | - |
| [Metrics](#metrics) | platform | on | chart `metrics`, `prometheus` |
| [Audit log](#audit-log) | - | always on | sync Job stdout |
| [Argo CD integration](#argo-cd-integration) | platform | off | `argocd-cm`, chart `argocd` |
| [RBAC helper roles](#rbac-helper-roles) | platform | off | chart `rbac.helpers.enabled` |

## Mirroring

### Image mirror

Owner: team. On for every `ArtifactMirror`; `spec.type` defaults to
`Image`.

```yaml
apiVersion: mirror.tagwarden.dev/v1alpha1
kind: ArtifactMirror
metadata: {name: nginx, namespace: team-web}
spec:
  targetRef: registry               # a ClusterMirrorTarget
  schedule: "0 3 * * *"             # 5-field cron or @daily, @hourly, ...
  source: {registry: docker.io, repository: library/nginx}
  target: {project: mirror}
  tags: {semverRange: ">=1.30.0", keepLatest: 3}
```

Needs: a `ClusterMirrorTarget` whose `allowedSources` lists the source
registry and whose project allows the namespace.

Check: `kubectl -n team-web get artifactmirror nginx` shows `Ready` and
`Synced`; `status.syncedTags` lists tags and digests.

Artifacts land at `<registry>/<project>/<source registry>/<source
repository>`. More: [README, Examples](../README.md#examples).

### Helm OCI chart mirror

Owner: team. Off; set `spec.type: HelmOCI`.

```yaml
spec:
  type: HelmOCI
  source: {registry: ghcr.io, repository: prometheus-community/charts/kube-prometheus-stack}
  target: {project: mirror}
  tags: {semverRange: ">=75.0.0", keepLatest: 5}
```

Classic Helm repositories (`HelmRepo`) are not supported yet.

### Tag selection

Owner: team. Required: set at least one of `include`, `semverRange`,
`keepLatest` or `tags`.

```yaml
spec:
  tags:
    include: ['^v\d+\.\d+\.\d+$']   # RE2, not anchored: use ^...$
    exclude: ['-debug$']
    semverRange: ">=1.11.0 <2.0.0"
    keepLatest: 3                   # N highest semver tags after filtering
    tags: [v1.10.4]                 # exact tags, bypass all filters
```

`include`, `semverRange` and `keepLatest` list the whole source; a source
with more tags than `limits.maxListedTags` fails the run. Explicit `tags`
never list the source.

Check: an empty selection sets `Synced=False` with reason
`NoTagsSelected` and a message with counts per filter. A missing explicit
tag gives a `TagNotFound` Event. Alert on
`tagwarden_mirror_selected_tags == 0`. More:
[README, When nothing is selected](../README.md#when-nothing-is-selected).

### Prereleases

Owner: team. Off: `semverRange` and `keepLatest` drop prereleases.

```yaml
spec:
  tags:
    semverRange: ">=1.11.0-0"
    allowPrerelease: true           # needed even when the range names a prerelease
```

### Required platforms

Owner: team. Off.

```yaml
spec:
  requiredPlatforms: [linux/amd64, linux/arm64]   # os/arch[/variant]
```

A tag that lacks a listed platform fails and is not copied. The whole
index is always copied, so digests and signatures stay valid.

### Suspend

Owner: team. Off.

```yaml
spec:
  suspend: true
```

The CronJob is suspended. Sync now requests are refused while suspended.

### Sync now

Owner: team. Set the annotation to a new value; each value is one
request. Needs `patch` on the mirror.

```sh
kubectl -n team-a annotate artifactmirror ingress-nginx --overwrite \
  tagwarden.dev/sync-now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

Check: `status.lastSyncRequest.result` is `Started`, `Deferred` (a sync
runs, or `minSyncInterval` has not passed) or `Refused` (mirror not Ready
or suspended). More: [README, Sync now](../README.md#sync-now).

### Custom target path

Owner: platform opens it, team uses it. Off: mirrors use the default
path.

```yaml
# ClusterMirrorTarget
spec:
  projects:
    - name: team-net
      namespaceSelector: {matchLabels: {example.com/team: net}}
      allowRepositoryOverride: true
---
# ArtifactMirror
spec:
  target: {project: team-net, repository: ingress/controller}
```

Enable it only for a project owned by one team. Without it, a mirror
that sets `target.repository` is refused.

## Tenancy and policy

### Projects and namespace access

Owner: platform. Required: at least one project.

```yaml
spec:
  projects:
    - name: mirror
      namespaceSelector: {}         # every namespace
    - name: team-net
      namespaceSelector: {matchLabels: {example.com/team: net}}
```

A mirror may push only to a listed project whose selector matches its
namespace. Two mirrors cannot write different sources to the same path.

### Allowed sources

Owner: platform. Required.

```yaml
spec:
  allowedSources: [registry.k8s.io, ghcr.io, quay.io, docker.io]
```

A mirror with any other source registry is refused.

### Limits

Owner: platform. On with defaults; `spec.limits` overrides them.

| Field | Default | Bounds |
| --- | --- | --- |
| `minSyncInterval` | 1h | at least 5m |
| `maxMirrorsPerNamespace` | 50 | |
| `maxKeepLatest` | 20 | up to 100 |
| `maxExplicitTags` | 50 | up to 100 |
| `maxListedTags` | 10000 | up to 100000 |
| `maxArtifactSize` | no limit | |

```yaml
spec:
  limits:
    minSyncInterval: 6h
    maxArtifactSize: 5Gi
```

Check: a mirror over a limit gets `Ready=False` with reason
`ScheduleTooFrequent` or `LimitExceeded` and loses its CronJob. More:
[README, Limits](../README.md#limits), [install, Tenant limits](install.md#tenant-limits).

### Moving tags

Owner: platform. Default `Fail`: the target tag stays and the mutation
is reported.

```yaml
spec:
  policy:
    onTagMutation: Overwrite        # Fail | Overwrite | Ignore
```

## Network and credentials

### Proxy

Owner: platform. Off: sync Jobs connect directly.

```yaml
spec:
  proxy:
    httpsProxy: http://proxy.example.internal:3128   # no credentials in the URL
    noProxy: [registry.example.internal]
    credentialsSecretRef: {name: proxy-credentials}  # kubernetes.io/basic-auth
    caBundleSecretRef: {name: proxy-ca, key: ca.crt} # TLS-inspecting proxy
```

Sync pods get the label `tagwarden.dev/egress: proxy`.

### Target CA and mTLS

Owner: platform. Off: system roots, no client certificate.

```yaml
spec:
  caBundleSecretRef: {name: registry-ca, key: ca.crt}
  clientCertSecretRef: {name: registry-client}       # kubernetes.io/tls
```

### Push credentials

Owner: platform. Required: set `credentialsSecretRef` or `auth`.

```sh
kubectl -n tagwarden-system create secret docker-registry registry-push \
  --docker-server=registry.example.internal \
  --docker-username=<robot> --docker-password=<token>
```

```yaml
spec:
  credentialsSecretRef: {name: registry-push}
```

Secrets live in the operator namespace. Check: the target's `Ready`
condition reports missing or unreadable Secrets.

### Private sources

Owner: platform. Default: anonymous pull with system roots.

```yaml
spec:
  sourceCredentials:                # kubernetes.io/dockerconfigjson
    - registry: ghcr.io
      secretRef: {name: ghcr-pull}
  sourceCABundles:
    - registry: registry.corp.example.internal
      secretRef: {name: corp-registry-ca, key: ca.crt}
```

A sync Job gets only the entry of its own source. More:
[install, Private sources](install.md#private-sources).

### Cloud workload identity

Owner: platform. Off. Push to or pull from Azure Container Registry,
Amazon ECR or Google Artifact Registry without a static Secret.

```yaml
spec:
  auth:
    awsWorkloadIdentity: {}         # or azureWorkloadIdentity, gcpWorkloadIdentity
  workloadIdentity:
    serviceAccountName: tagwarden-sync-aws
    aws: {roleARN: arn:aws:iam::123456789012:role/tagwarden-sync, region: eu-west-1}
  sourceCredentials:
    - registry: 123456789012.dkr.ecr.eu-west-1.amazonaws.com
      awsWorkloadIdentity: {}
```

The cloud side (identity, federation, roles) is in the install guide:
[Azure](install.md#azure-container-registry-with-workload-identity),
[AWS](install.md#amazon-ecr-with-irsa),
[Google](install.md#google-artifact-registry-with-workload-identity-federation).

### Harbor tag delete

Owner: platform. Off: tag delete uses OCI distribution, which Harbor
refuses.

```yaml
spec:
  registryFlavor: Harbor
```

Used by [re-scan and untag](#re-scan-and-untag). The push credentials
need Harbor's delete tag permission. More:
[install, Harbor](install.md#7-harbor).

### Denied CIDRs

Owner: platform. Chart value, empty by default. Set it to the pod and
service CIDRs; sync Jobs refuse sources that resolve into these ranges,
on top of the built-in loopback, link-local and cloud metadata checks.

```yaml
# values.yaml
deniedCIDRs: [10.244.0.0/16, 10.96.0.0/12]
```

### Network policies

Owner: platform. Off. Sync pods carry `tagwarden.dev/target` and
`tagwarden.dev/egress` (`proxy` or `direct`) for your egress policies.
Chart `networkPolicy.enabled: true` adds a policy for metrics traffic
and, with Trivy, for the Trivy server. More:
[network-policies.md](network-policies.md).

## Auto-mirror and vulnerability gate

### Auto-mirror

Owner: platform enables it per target, teams annotate pods. Off.

```yaml
# ClusterMirrorTarget
spec:
  autoMirror:
    enabled: true
    project: shared                 # listed in projects, no allowRepositoryOverride
    schedule: "0 */6 * * *"         # default
    maxMirrorsPerNamespace: 20      # default, up to 200
---
# Pod or pod template
metadata:
  annotations:
    tagwarden.dev/auto-mirror: default   # ClusterMirrorTarget name
```

Check: generated mirrors are labeled `tagwarden.dev/generated=true`; the
pod gets `MirrorRequested`, `MirrorRefused` or `AutoMirrorDisabled`
Events. More: [README, Auto-mirror](../README.md#auto-mirror-from-pod-annotations),
[design](design/auto-mirror.md).

### Vulnerability gate

Owner: platform. Off. Scans only generated (auto-mirror) mirrors. Needs
a Trivy server: the chart deploys one with `trivy.enabled: true`, with
its database taken from your registry.

```yaml
spec:
  autoMirror:
    enabled: true
    project: shared
    vulnerabilityGate:
      enabled: true
      action: Report                # Report (default) | Block
      severity: Critical            # default
      onScanError: Report           # default; Report | Block
      maxDBAge: 72h                 # default
      ignoreUnfixed: false
```

With `Block` in `action` or `onScanError`, the auto-mirror project is
reserved for generated mirrors.

Check: the target's `ScannerReady` condition; `status.findings` on the
generated mirror; gauge `tagwarden_vulnerability_gate_unscanned` is 1
when the gate has no usable scanner. Full setup:
[install, Enable the vulnerability gate](install.md#enable-the-vulnerability-gate).

### Re-scan and untag

Owner: platform. Off.

```yaml
spec:
  autoMirror:
    vulnerabilityGate:
      action: Block                 # Untag needs Block
      rescanInterval: 24h           # at least 1h
      onVulnerableTag: Untag        # default Report
```

Findings go to `status.vulnerable`. Untag deletes the tag, not the
digest. On Harbor, also set [`registryFlavor: Harbor`](#harbor-tag-delete).
More: [install, Re-scan](install.md#6-re-scan).

### Vulnerability exceptions

Owner: security. Optional. Accepts chosen CVEs or digests for generated
mirrors until `expires`, at most `maxExceptionDuration` (default 90 days)
after creation.

```yaml
apiVersion: mirror.tagwarden.dev/v1alpha1
kind: VulnerabilityException
metadata: {name: nginx-cve}         # cluster-scoped
spec:
  targetRef: default
  namespaces: [team-web]
  repository: docker.io/library/nginx
  vulnerabilities: [CVE-2026-12345]
  expires: "2026-12-31T00:00:00Z"
  approvedBy: security-team
  reason: Not reachable in our configuration.
```

Chart: `vulnerabilityExceptions.approvers` binds the approver
ClusterRole; `approvedByPolicy` requires `approvedBy` to equal the
requesting user. Check: condition `Active`; `False` with reason
`Expired`, `TooLong` or `TargetNotFound`. More:
[install, Exceptions](install.md#5-exceptions).

## Always on

### Signatures and referrers

OCI referrers and cosign `.sig`, `.att` and `.sbom` tags are copied with
each image, also later for tags already mirrored. Nothing to enable.

### Audit log

Each sync Job writes one JSON line per selected tag to stdout: source
digest, target, action, referrers and, with the gate, the scan result.
Collect it with your log pipeline.

## Operations

### Metrics

Owner: platform. On, HTTPS with authn and authz on port 8443.

```yaml
# values.yaml
metrics: {enabled: true, port: 8443, secure: true}
prometheus:
  enabled: true                     # Prometheus Operator ServiceMonitor
  tlsConfig: {}                     # CA of the metrics certificate
```

Tagwarden metrics: `tagwarden_mirror_selected_tags`,
`tagwarden_vulnerability_gate_unscanned`,
`tagwarden_scanner_start_failures_total`.

### Argo CD integration

Owner: platform. Off. A **Sync now** button and health checks come from
an `argocd-cm` snippet. Sync Jobs show in the app tree with:

```yaml
# values.yaml
argocd:
  tracking: inherit
```

More: [argocd.md](argocd.md).

### RBAC helper roles

Owner: platform. Off. Chart `rbac.helpers.enabled: true` installs admin, editor and viewer
ClusterRoles for the Tagwarden CRDs. They never grant the exception
approver role.
