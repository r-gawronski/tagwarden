# Install

Tagwarden runs as one manager Deployment. Each `ArtifactMirror` becomes a
CronJob in the operator namespace; its Jobs run the same image in `sync`
mode.

## Requirements

- Kubernetes 1.30 or newer.
- An OCI registry to mirror into (Harbor, zot, distribution, a cloud
  registry) and credentials that can push to it.
- Optional: an HTTPS proxy for upstream traffic.

## Helm (recommended)

Releases ship as a signed OCI chart, starting with v0.1.0:

```sh
helm install tagwarden oci://ghcr.io/r-gawronski/charts/tagwarden \
  --version <version> \
  --namespace tagwarden-system --create-namespace \
  --set 'deniedCIDRs={10.244.0.0/16,10.96.0.0/12}'
```

To install from source instead, build and push the image, then use the
chart in `dist/chart`:

```sh
make docker-build docker-push IMG=<registry>/tagwarden:<tag>
helm install tagwarden dist/chart \
  --namespace tagwarden-system --create-namespace \
  --set manager.image.repository=<registry>/tagwarden \
  --set manager.image.tag=<tag> \
  --set 'deniedCIDRs={10.244.0.0/16,10.96.0.0/12}'
```

- The release namespace becomes the operator namespace. Secrets that a
  `ClusterMirrorTarget` references must live there.
- Set `deniedCIDRs` to the pod and service CIDRs of your cluster. Sources
  that resolve into these ranges are refused.
- The chart can also create targets and mirrors from `targets` and
  `mirrors` values. Most setups keep them as plain manifests instead (see
  the [README](../README.md#quick-start)). If you use the values, run
  `helm upgrade` once more after the first install: the CRDs are not served
  yet when Helm first renders them.
- `values.schema.json` rejects unknown keys, and the manager args must keep
  `--sync-image` and `--denied-cidrs`.

Details on values and on how the chart is generated:
[design/helm-chart.md](design/helm-chart.md).

### Uninstall

`helm uninstall` keeps the CRDs, targets and mirrors, so user data survives
a reinstall under the same release name. To remove mirrors, delete them
while the operator still runs: their finalizer removes the CronJobs.

## Kustomize

```sh
make docker-build docker-push IMG=<registry>/tagwarden:<tag>
make install                      # CRDs
make deploy IMG=<registry>/tagwarden:<tag>
```

Add `--denied-cidrs=<pod CIDR>,<service CIDR>` to the manager args in
`config/manager/manager.yaml`. Remove with `make undeploy` and
`make uninstall`.

## Private sources

Sources are pulled anonymously unless the target says otherwise. Create the
Secrets in the operator namespace and list them on the
`ClusterMirrorTarget`. Tenants never reference them.

```sh
kubectl -n tagwarden-system create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io \
  --docker-username=<user> --docker-password=<token>
kubectl -n tagwarden-system create secret generic corp-registry-ca \
  --from-file=ca.crt=./corp-registry-ca.pem
```

```yaml
spec:
  sourceCredentials:
    - registry: ghcr.io
      secretRef: {name: ghcr-pull}
  sourceCABundles:
    - registry: registry.corp.example.internal
      secretRef: {name: corp-registry-ca}   # key defaults to ca.crt
```

- The credentials Secret must be of type `kubernetes.io/dockerconfigjson`
  with an `auths` entry for that registry. Credential helpers are not
  supported. The Docker Hub names `docker.io`, `index.docker.io` and
  `registry-1.docker.io` count as one registry, and listing a registry
  twice, under any of its names, gives `Ready=False` with reason
  `InvalidSpec`.
- The CA Secret holds PEM certificates under the key. The CA is mounted
  only in sync pods of that source, and trusted there for every host the
  source transport reaches (the registry, its redirect and token hosts),
  never for the target. It adds to the system roots.
- Ports are not folded: `ghcr.io` and `ghcr.io:443` are different entries.
  Use the host exactly as mirrors name it.
- Use one Secret per source. One invalid source Secret sets the target
  `Ready=False` and stops all its mirrors.
- A missing or malformed Secret turns the target `Ready=False`
  (`SecretNotFound` or `InvalidSecret`); the message names the Secret and
  never its content.
- Each sync Job mounts only the Secrets of its own source registry.
- Before this, the only way to trust a private source CA was
  `proxy.caBundleSecretRef`. Use `sourceCABundles` instead; the proxy CA
  is for the proxy.

## Tenant limits

`ClusterMirrorTarget.spec.limits` caps schedules, mirrors per namespace,
tags and artifact size (see the [README](../README.md#limits)). Two
controls outside Tagwarden complement it:

- A Kubernetes ResourceQuota on `count/artifactmirrors.mirror.tagwarden.dev`
  caps the mirrors a namespace can create at all, across every target:

  ```yaml
  apiVersion: v1
  kind: ResourceQuota
  metadata:
    name: artifactmirrors
    namespace: team-a
  spec:
    hard:
      count/artifactmirrors.mirror.tagwarden.dev: "20"
  ```

- A storage quota on each registry project caps what all mirrors of the
  project can store together, which `maxArtifactSize` does not.

Upgrading from a release without limits: the defaults refuse mirrors with
schedules more frequent than hourly or `keepLatest` above 20. Set `limits`
on the target before upgrading if you need more.

## Changing the operator namespace

The controller only manages objects in the current operator namespace.
CronJobs and ConfigMaps left in an old namespace stay there:

```sh
kubectl delete cronjobs,configmaps -l tagwarden.dev/mirror -n <old namespace>
```

## Next steps

- Restrict sync pod egress: [network-policies.md](network-policies.md).
- Read what the operator trusts and why: [threat-model.md](threat-model.md).
