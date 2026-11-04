# Helm chart

The chart in `dist/chart` installs the operator. `config/` stays the source
of truth: `make helm` regenerates the chart from it, and the CI
`generate-check` job fails when the committed chart differs from a
regeneration. The `chart` job lints the chart and validates its output.

## Generation

`make helm`:

1. builds `config/helm`, an overlay of `config/default`, into
   `dist/helm-input.yaml` (not committed);
2. runs `kubebuilder edit --plugins=helm/v2-alpha --manifests=dist/helm-input.yaml`
   (kubebuilder v4.16.0, installed into `bin/` at the version in the
   Makefile);
3. deletes `.github/workflows/test-chart.yml`, which the plugin writes on
   every run (the kind install test belongs to the e2e workflow);
4. points the image line of `templates/manager/manager.yaml` at the
   `tagwarden.managerImage` helper, so the image can carry a digest. The
   target fails if the generated line no longer matches.

Plugin limits worked around in config:

- It keeps one ServiceAccount. `config/helm` removes the `tagwarden-sync`
  ServiceAccount, and the chart renders it from a hand-maintained template.
- It writes one template per object name. The namespaced manager Role and
  RoleBinding (from the `namespace=system` RBAC markers) are renamed in
  `config/rbac` to `manager-namespaced-role` and
  `manager-namespaced-rolebinding`, so they no longer collide with the
  ClusterRole and ClusterRoleBinding.

Passing `--manifests` also keeps the plugin from running
`make build-installer`, which rewrites `config/manager/kustomization.yaml`.
Run `make helm` without `IMG` overrides; the chart takes the image from
values.

## Generated and hand-maintained files

| File | Owner |
|------|-------|
| `Chart.yaml` | hand; the plugin never overwrites it |
| `values.yaml`, `values.schema.json` | hand; keep them in sync |
| `templates/_helpers.tpl`, `templates/NOTES.txt`, `.helmignore` | hand; the plugin keeps them |
| `templates/prometheus/*`, `templates/network-policy/*` | hand; the plugin keeps them |
| `templates/sync/serviceaccount.yaml` | hand |
| `templates/trivy/*` | hand; rendered only with `trivy.enabled` |
| `templates/mirror/resources.yaml` | hand |
| `templates/vulnerability-exceptions/*` | hand; approver ClusterRole and the `approvedBy` admission policy |
| `templates/crd/*`, `templates/rbac/*`, `templates/manager/*`, `templates/metrics/*` | generated on every `make helm` |

`kubebuilder edit --plugins=helm/v2-alpha --force` overwrites the
hand-maintained files except `Chart.yaml`. Do not use it.

Hand changes to the ServiceMonitor: the generated template set
`insecureSkipVerify: true` unless cert-manager was enabled. The chart has no
cert-manager integration, so the template takes `prometheus.tlsConfig` from
values instead and never skips verification. With `metrics.secure: true` (the
default) Prometheus can scrape only when `prometheus.tlsConfig` holds the CA
that signed the metrics certificate, for example
`ca: {secret: {name: <secret>, key: ca.crt}}`. The manager's built-in
self-signed certificate cannot be verified, and the chart does not mount a
metrics certificate yet; until it does, scraping through the ServiceMonitor
needs `metrics.secure: false` behind the NetworkPolicy.

## Values

`values.schema.json` sets `additionalProperties: false` on every object the
chart defines, so `helm install` and `helm template` reject unknown keys.
Objects passed through to Kubernetes fields (`securityContext`, `resources`,
`affinity`, `tolerations`, `env`, `strategy`, `prometheus.tlsConfig`) and
the `spec` of targets and mirrors are not described in the schema; the API
server validates them against the Kubernetes and CRD schemas.

| Value | Default | Notes |
|-------|---------|-------|
| `manager.image.repository`, `.tag`, `.digest`, `.pullPolicy` | `registry.example.internal/tagwarden/tagwarden`, appVersion, none, `IfNotPresent` | the digest is appended as `repo:tag@sha256:...` |
| `syncImage.repository`, `.tag`, `.digest` | empty | empty repository means the manager image; empty tag means `manager.image.tag` |
| `deniedCIDRs` | `[]` | rendered as `--denied-cidrs`; set the pod and service CIDRs |
| `leaderElection.enabled` | `true` | |
| `metrics.enabled`, `.port`, `.secure` | `true`, `8443`, `true` | |
| `manager.imagePullSecrets`, `.nodeSelector`, `.tolerations`, `.affinity` | empty | |
| `manager.podSecurityContext`, `.securityContext`, `.resources` | hardened | runAsNonRoot, seccomp RuntimeDefault, read-only root FS, no privilege escalation, drop ALL, limits set |
| `crd.enabled`, `crd.keep` | `true`, `true` | see below |
| `rbac.helpers.enabled` | `false` | admin, editor and viewer ClusterRoles for the CRDs; `VulnerabilityException` gets a viewer only |
| `trivy.enabled` | `false` | in-chart Trivy server for the vulnerability gate, see below |
| `vulnerabilityExceptions.approvers` | `[]` | subjects bound to the `<release>-exception-approver` ClusterRole (write exceptions); the role is always rendered |
| `vulnerabilityExceptions.approvedByPolicy.enabled` | `false` | ValidatingAdmissionPolicy: `spec.approvedBy` must equal the requesting user on create and update |
| `targets` | `[]` | items `{name, spec}` render `ClusterMirrorTarget` |
| `mirrors` | `[]` | items `{name, namespace, spec}` render `ArtifactMirror` |

The manager args in `manager.args` are templates that wire leader election,
the sync image and the denied CIDRs. The schema rejects a list without a
`--sync-image=` and a `--denied-cidrs=` entry, so an override cannot drop
them silently. With `deniedCIDRs: []` the chart renders `--denied-cidrs=`,
which the manager accepts as an empty list.
`POD_NAMESPACE` comes from the downward API, so the release namespace is the
operator namespace. Secrets referenced by targets must exist there.

## Trivy server

`trivy.enabled: true` renders, in the release namespace, a one-replica
StatefulSet with a cache PVC (`trivy.persistence`, 10Gi), a Service on 4954,
a ServiceAccount without token, a token Secret and, with
`networkPolicy.enabled`, a NetworkPolicy. The Secret is generated once and
kept on upgrades (annotated `helm.sh/resource-policy: keep`), or
`trivy.token.existingSecret` names one with a `token` key. The generated token
is kept through `lookup`, which returns nothing under `helm template` and Argo
CD, so every render there would rotate it: GitOps installs must set
`trivy.token.existingSecret`. The server pod carries a `checksum/token`
annotation, so a changed token restarts it. A startup probe on `/healthz`
allows 15 minutes for the first DB download. With `networkPolicy.enabled:
false` the server is protected by the token only. The schema requires `trivy.image` (repository, tag, digest),
`trivy.db.repository` and a `trivy.tmp.sizeLimit` of at least 1Gi, and caps
`trivy.replicas` at 1. `trivy.image.tag` is the Trivy version. The NetworkPolicy
admits pods labeled `tagwarden.dev/scanner: trivy` and the manager, and
allows egress to DNS and `trivy.networkPolicy.registryEgress`.

With the server enabled the manager gets `--trivy-image`, `--trivy-version`
and `--trivy-url`. The manager.yaml line that adds them is patched by
`make helm`, like the image line. `scanner.url` for an external server
belongs to the `ClusterMirrorTarget` API, not to the chart. Design:
[vulnerability-gate.md](vulnerability-gate.md).

## CRDs

Options:

- `crds/` directory: Helm installs the CRDs before anything else but never
  upgrades or deletes them. A new chart version with a changed CRD schema
  would leave the old schema in the cluster.
- Templates gated by `crd.enabled`, with `helm.sh/resource-policy: keep`
  when `crd.keep` is true.

Decision: templates with keep, both on by default. Upgrades update the CRDs
with the chart, and `helm uninstall` leaves the CRDs, and with them every
mirror and target, in place. Chart-managed targets and mirrors carry the
same keep policy (see Uninstall). The plugin generates exactly this
(`crd.enabled` and `crd.keep`), so the value names follow the plugin rather
than `crds.install`. Set `crd.enabled: false` when the CRDs are managed
elsewhere.

Cost: Helm cannot build objects of a kind the cluster does not serve yet, so
CRDs and custom resources cannot be created by the same first install
(`resource mapping not found`, also for hooks, checked with Helm 4.1.4).
The `targets` and `mirrors` templates render only when
`.Capabilities.APIVersions` has `mirror.tagwarden.dev/v1alpha1`. On a first
install they are skipped and NOTES says so; the next `helm upgrade` creates
them. GitOps tools that render with the cluster's API versions converge on
the next sync. `helm template` without a cluster needs
`--api-versions mirror.tagwarden.dev/v1alpha1` to render them.

Helm 4 `--wait` also waits for targets and mirrors to become Ready; a target
whose Secrets are missing makes the upgrade time out.

## Uninstall

With `crd.keep: true` (the default) `helm uninstall` keeps the CRDs and the
targets and mirrors from values (`helm.sh/resource-policy: keep`). Deleting
mirrors together with the manager would leave them Terminating: a mirror
keeps its finalizer until the manager removes its CronJob and ConfigMap.
Reinstalling with the same release name and namespace adopts the kept
objects. To remove mirrors, delete them (or drop them from `mirrors` and
upgrade) while the operator still runs, and wait until
`kubectl get cronjobs -l tagwarden.dev/mirror -n <release namespace>` is
empty. With `crd.keep: false` uninstall deletes targets, mirrors and CRDs,
and mirrors still pending cleanup stay Terminating.

Future option: a pre-delete hook Job that deletes the mirrors and waits for
their CronJobs before the manager goes away.

## RBAC

The chart RBAC comes from `config/rbac`, which the RBAC markers generate:

- ClusterRole `manager-role`: Tagwarden CRDs, namespaces, events.
- Role `manager-namespaced-role` in the release namespace: secrets, pods,
  jobs, cronjobs, configmaps.
- Leader election Role, metrics auth roles.
- `tagwarden-sync` ServiceAccount with `automountServiceAccountToken: false`
  and no bindings.

The plugin's `rbac.namespaced` switch is not exposed: it would turn the
ClusterRole into a Role, which cannot grant access to namespaces or
cluster-scoped CRDs.

## CI checks

`make chart-check`, run by the `chart` job:

- `helm lint --strict`;
- `helm template` with the default values and with
  `test/chart/example-values.yaml` (one target, one mirror) and
  `test/chart/trivy-values.yaml` (gate enabled), validated by
  kubeconform (`go tool`, version in `go.mod`) in strict mode against the
  Kubernetes schemas. CRDs, Tagwarden kinds and ServiceMonitor are skipped:
  kubeconform has no schema for them;
- `go test -tags=chart ./test/chart/`: decodes the rendered targets and
  mirrors strictly into the API types, checks the image, sync image and
  denied CIDR args, checks that the schema rejects unknown keys, that
  `trivy.enabled: false` renders nothing about Trivy and that the schema
  requires the Trivy digest and a `tmp.sizeLimit` of at least 1Gi.

Helm comes from `azure/setup-helm`, pinned by commit, at the version in the
workflow.
