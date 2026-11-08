# Helm values

Every value the chart in `dist/chart` accepts. `values.schema.json` rejects
unknown keys, so this list is complete: a key missing here is not a value.
`go test -tags=chart ./test/chart/` fails when a schema key is not listed.

Types: `string`, `int`, `bool`, `list`, `map` (string to string) and
`object` (passed through to a Kubernetes field; the API server validates
it, the schema does not). Constraints in the Notes column are enforced by
the schema at `helm install`, `helm upgrade` and `helm template`.

## Names

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `nameOverride` | string | `""` | Replaces the chart name in object names. The release name is kept. |
| `fullnameOverride` | string | `""` | Replaces the whole object name prefix. |

## Manager

The controller manager Deployment.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `manager.replicas` | int | `1` | Minimum 0. More than one needs `leaderElection.enabled`. |
| `manager.image.repository` | string | `registry.example.internal/tagwarden/tagwarden` | Required, not empty. |
| `manager.image.tag` | string | `""` | Empty means the chart `appVersion`. |
| `manager.image.digest` | string | `""` | `sha256:<64 hex>` or empty. When set, the image is pulled as `repo:tag@sha256:...`. |
| `manager.image.pullPolicy` | string | `IfNotPresent` | `Always`, `IfNotPresent` or `Never`. |
| `manager.args` | list of string | see below | Required. Must keep a `--sync-image=` and a `--denied-cidrs=` entry. Items are rendered with `tpl`. |
| `manager.healthProbe.port` | int | `8081` | Required. 1 to 65535. Liveness and readiness probe port. |
| `manager.env` | list of object | `POD_NAMESPACE` from the downward API | Required. Keep `POD_NAMESPACE`: the release namespace is the operator namespace. |
| `manager.imagePullSecrets` | list | `[]` | Items `{name: <secret>}`. |
| `manager.imagePullSecrets[].name` | string | | Required. Name of a pull Secret in the release namespace. |
| `manager.podSecurityContext` | object | `runAsNonRoot: true`, seccomp `RuntimeDefault` | Pod `securityContext`. |
| `manager.securityContext` | object | no privilege escalation, drop `ALL`, read-only root FS | Container `securityContext`. |
| `manager.resources` | object | requests `10m`/`64Mi`, limits `500m`/`128Mi` | Container `resources`. |
| `manager.affinity` | object | `{}` | |
| `manager.nodeSelector` | map | `{}` | |
| `manager.tolerations` | list of object | `[]` | |
| `manager.topologySpreadConstraints` | list of object | unset | |
| `manager.strategy` | object | unset | Deployment `strategy`. |
| `manager.priorityClassName` | string | unset | |
| `manager.terminationGracePeriodSeconds` | int | `10` | Minimum 0. |
| `manager.labels` | map | unset | Extra labels on the Deployment. The chart's own labels win. |
| `manager.annotations` | map | unset | Annotations on the Deployment. |
| `manager.pod.labels` | map | `{}` | Extra labels on the manager pod. |
| `manager.pod.annotations` | map | `{}` | Annotations on the manager pod, for example `k8s.grafana.com/scrape: "true"`. |

Default `manager.args`. Each line wires one value below into a manager flag,
so override the values rather than the args. If you replace the list, copy
these lines and add yours.

```yaml
manager:
  args:
    - --leader-elect={{ .Values.leaderElection.enabled }}
    - --sync-image={{ include "tagwarden.syncImage" . }}
    - --denied-cidrs={{ join "," .Values.deniedCIDRs }}
    - --cluster-domain={{ .Values.clusterDomain }}
    - --argocd-tracking={{ .Values.argocd.tracking }}
    - --argocd-instance-label={{ .Values.argocd.instanceLabel }}
```

The chart adds the metrics flags (from `metrics.*`), the health probe flag
(from `manager.healthProbe.port`) and, with `trivy.enabled`,
`--trivy-image`, `--trivy-version`, `--trivy-url` and
`--scanner-start-timeout` on its own.

## Sync Jobs and network

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `syncImage.repository` | string | `""` | Image of the sync Jobs. Empty means `manager.image.repository`. |
| `syncImage.tag` | string | `""` | Empty means `manager.image.tag`. |
| `syncImage.digest` | string | `""` | `sha256:<64 hex>` or empty. |
| `deniedCIDRs` | list of string | `[]` | CIDRs that sources must not resolve to. Set the pod and service CIDRs of the cluster. Rendered as `--denied-cidrs`. |
| `clusterDomain` | string | `cluster.local` | DNS domain of the cluster, no trailing dot. The manager dials Trivy as `<service>.<namespace>.svc.<clusterDomain>.`. |
| `leaderElection.enabled` | bool | `true` | Rendered as `--leader-elect`. |

## Argo CD

See [argocd.md](argocd.md).

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `argocd.tracking` | string | `""` | `""` (off) or `inherit`: sync CronJobs show up in the Argo CD app of their mirror. |
| `argocd.instanceLabel` | string | `app.kubernetes.io/instance` | Label Argo CD uses in label tracking mode. |

## ServiceAccount and RBAC

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `serviceAccount.enabled` | bool | `true` | Required. Render the manager ServiceAccount. The `tagwarden-sync` ServiceAccount of the sync Jobs is always rendered. |
| `serviceAccount.name` | string | unset | Required when `enabled` is false: an existing ServiceAccount. Use `default` for the namespace default. |
| `serviceAccount.labels` | map | unset | |
| `serviceAccount.annotations` | map | unset | For example a workload identity annotation. |
| `rbac.helpers.enabled` | bool | `false` | Admin, editor and viewer ClusterRoles for the CRDs. `VulnerabilityException` gets a viewer only. |

## CRDs

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `crd.enabled` | bool | `true` | Required. Install and upgrade the CRDs with the chart. Set false when the CRDs are managed elsewhere. |
| `crd.keep` | bool | `true` | Required. Keep the CRDs, and with them every mirror and target, on `helm uninstall`. |

## Metrics

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `metrics.enabled` | bool | `true` | Required. Metrics Service and endpoint. |
| `metrics.port` | int | `8443` | Required. 1 to 65535. |
| `metrics.secure` | bool | `true` | Required. HTTPS with authn and authz (true) or plain HTTP (false). |
| `prometheus.enabled` | bool | `false` | Required. Prometheus Operator ServiceMonitor. |
| `prometheus.tlsConfig` | object | `{}` | ServiceMonitor endpoint `tlsConfig` when `metrics.secure` is true, for example `ca: {secret: {name: <secret>, key: ca.crt}}`. The chart sets `serverName`. |
| `prometheus.labels` | map | unset | Labels on the ServiceMonitor, for example the selector label of your Prometheus. |
| `prometheus.annotations` | map | unset | |
| `networkPolicy.enabled` | bool | `false` | NetworkPolicy that admits metrics traffic from namespaces labelled `metrics: enabled`. Also turns on the Trivy NetworkPolicy. |

## Vulnerability exceptions

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `vulnerabilityExceptions.approvers` | list | `[]` | Subjects bound to the `<release>-exception-approver` ClusterRole (create, update, delete exceptions). The role is always rendered; empty means no binding. |
| `vulnerabilityExceptions.approvers[].kind` | string | | Required. `User`, `Group` or `ServiceAccount`. |
| `vulnerabilityExceptions.approvers[].name` | string | | Required. |
| `vulnerabilityExceptions.approvers[].namespace` | string | | For `ServiceAccount`. |
| `vulnerabilityExceptions.approvers[].apiGroup` | string | | `rbac.authorization.k8s.io` for `User` and `Group`. |
| `vulnerabilityExceptions.approvedByPolicy.enabled` | bool | `false` | ValidatingAdmissionPolicy: `spec.approvedBy` must equal the user who creates or updates the exception. GitOps then needs `approvedBy` set to its ServiceAccount user. |

## Trivy server

In-chart Trivy server for the vulnerability gate. See
[Enable the vulnerability gate](install.md#enable-the-vulnerability-gate)
and [design/vulnerability-gate.md](design/vulnerability-gate.md).

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `trivy.enabled` | bool | `false` | Required. When true the schema also requires `trivy.image.repository`, `.tag`, `.digest` and `trivy.db.repository`. |
| `trivy.image.repository` | string | `""` | Trivy image in your registry. |
| `trivy.image.tag` | string | `""` | The Trivy version, for example `0.76.1`. The gate checks it against the server. |
| `trivy.image.digest` | string | `""` | `sha256:<64 hex>`. Required when enabled. |
| `trivy.image.pullPolicy` | string | `IfNotPresent` | `Always`, `IfNotPresent` or `Never`. |
| `trivy.imagePullSecrets` | list | `[]` | Items `{name: <secret>}`. |
| `trivy.imagePullSecrets[].name` | string | | Required. Name of a pull Secret in the release namespace. |
| `trivy.scannerStartTimeout` | string | `5m` | Go duration. How long the scanner sidecar of a gated sync Job may fail to start before the Job is deleted. Rendered as `--scanner-start-timeout`. |
| `trivy.replicas` | int | `1` | 0 or 1. Scans need one cache. |
| `trivy.db.repository` | string | `""` | Vulnerability DB in the target registry, for example `registry.example.internal/platform/ghcr.io/aquasecurity/trivy-db:2`. Required when enabled. |
| `trivy.db.credentialsSecretRef.name` | string | unset | `kubernetes.io/dockerconfigjson` Secret with a pull-only account. |
| `trivy.db.caBundleSecretRef.name` | string | unset | Secret with the registry CA, passed as `SSL_CERT_FILE`. Set together with `.key`. |
| `trivy.db.caBundleSecretRef.key` | string | unset | Key in that Secret, for example `ca.crt`. |
| `trivy.persistence.size` | string | `10Gi` | Cache PVC size. Quantity like `10Gi`. |
| `trivy.persistence.storageClassName` | string | `""` | Empty means the default StorageClass. |
| `trivy.tmp.sizeLimit` | string | `2Gi` | `/tmp` emptyDir for the DB download. At least `1Gi`, in `Gi` or `Ti`. |
| `trivy.token.existingSecret` | string | `""` | Secret with a `token` key. Empty: the chart generates one and keeps it on upgrades. GitOps installs (Argo CD, `helm template`) must set it, or every render rotates the token. |
| `trivy.resources` | object | requests `100m`/`256Mi`, limits `2`/`1Gi` | |
| `trivy.networkPolicy.registryEgress` | list | `[]` | Egress beyond DNS. Needs `networkPolicy.enabled`. |
| `trivy.networkPolicy.registryEgress[].cidr` | string | | Required. For example `10.0.0.0/24`. |
| `trivy.networkPolicy.registryEgress[].port` | int | | Required. 1 to 65535. |
| `trivy.nodeSelector` | map | `{}` | |
| `trivy.tolerations` | list of object | `[]` | |
| `trivy.affinity` | object | `{}` | |

## Targets and mirrors

Most setups keep targets and mirrors as plain manifests. From values they
render only once the CRDs are served, so the first install skips them and
the next `helm upgrade` creates them. Secrets a target references live in
the release namespace.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `targets` | list | `[]` | `ClusterMirrorTarget` objects to create. |
| `targets[].name` | string | | Required. DNS subdomain. |
| `targets[].spec` | object | | Required. Passed through as the target `spec`. |
| `mirrors` | list | `[]` | `ArtifactMirror` objects to create. |
| `mirrors[].name` | string | | Required. DNS subdomain. |
| `mirrors[].namespace` | string | | Required. DNS label. |
| `mirrors[].spec` | object | | Required. Passed through as the mirror `spec`. |

```yaml
targets:
  - name: default
    spec:
      registry: registry.example.internal
      credentialsSecretRef: {name: registry-push}
      allowedSources: [registry.k8s.io]
      projects:
        - name: mirror
          namespaceSelector: {}
mirrors:
  - name: pause
    namespace: team-a
    spec:
      targetRef: default
      schedule: "0 3 * * *"
      type: Image
      source: {registry: registry.k8s.io, repository: pause}
      target: {project: mirror}
      tags: {include: ['^\d+\.\d+$'], keepLatest: 3}
```

The fields of `spec` are described in [features.md](features.md).
