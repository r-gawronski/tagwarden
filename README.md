# tagwarden
// TODO(user): Add simple overview of use/purpose

## Description
// TODO(user): An in-depth paragraph about your project and overview of use

## Getting Started

### Prerequisites
- go version v1.24.6+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/tagwarden:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/tagwarden:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

Sync Jobs run the same image in `sync` mode, in the operator namespace
`tagwarden-system`. Add `--denied-cidrs=<pod CIDR>,<service CIDR>` to the
manager args in `config/manager/manager.yaml` so that sources cannot resolve
to cluster addresses. The Secrets a `ClusterMirrorTarget` references must
exist in `tagwarden-system`.

Changing the operator namespace leaves the CronJobs and ConfigMaps in the
old namespace behind. Delete them there, for example with
`kubectl delete cronjobs,configmaps -l tagwarden.dev/mirror -n <old namespace>`.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Network policies

Sync pods carry two labels, so cluster admins can restrict their egress
per path:

- `tagwarden.dev/target`: the `ClusterMirrorTarget` name. A name that is not
  a valid label value (longer than 63 characters, for example) becomes `h-`
  and the first 20 hex characters of its sha256.
- `tagwarden.dev/egress`: `proxy` when the target sets `spec.proxy`, else
  `direct`.

The controller restores both labels when someone edits them by hand. The
example lets `proxy` pods reach only the proxy, the target registry and
DNS, and `direct` pods reach the target, DNS and port 443 outside private
and cluster ranges. Add `tagwarden.dev/target` to `podSelector` for a policy
per target.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sync-egress-proxy
  namespace: tagwarden-system
spec:
  podSelector:
    matchLabels:
      tagwarden.dev/egress: proxy
  policyTypes: [Egress]
  egress:
  - to: [{ipBlock: {cidr: 10.0.0.10/32}}]   # proxy
    ports: [{port: 3128, protocol: TCP}]
  - to: [{ipBlock: {cidr: 10.0.0.20/32}}]   # target registry
    ports: [{port: 8443, protocol: TCP}]
  - to: [{namespaceSelector: {}, podSelector: {matchLabels: {k8s-app: kube-dns}}}]
    ports: [{port: 53, protocol: UDP}, {port: 53, protocol: TCP}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sync-egress-direct
  namespace: tagwarden-system
spec:
  podSelector:
    matchLabels:
      tagwarden.dev/egress: direct
  policyTypes: [Egress]
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16]
    ports: [{port: 443, protocol: TCP}]
  - to: [{ipBlock: {cidr: 10.0.0.20/32}}]   # target registry
    ports: [{port: 8443, protocol: TCP}]
  - to: [{namespaceSelector: {}, podSelector: {matchLabels: {k8s-app: kube-dns}}}]
    ports: [{port: 53, protocol: UDP}, {port: 53, protocol: TCP}]
```

Add your pod and service CIDRs to `except` when they are outside these
ranges. NetworkPolicies are a second layer: the sync Job checks every
source address itself (threat model T16).

Some CNIs reject the packets of a new pod until its policy is programmed,
usually for a second or so. The sync Job retries connections that fail at
dial time (for example `proxyconnect tcp: ... connection refused`) for about
30 s. If a sync still fails with such an error, check that the policy allows
the proxy or registry address and port.

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/tagwarden:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/tagwarden/<tag or branch>/dist/install.yaml
```

### With the Helm chart

The chart lives in `dist/chart`. The release namespace becomes the operator
namespace. Set `deniedCIDRs` to the pod and service CIDRs of the cluster:

```sh
helm install tagwarden dist/chart --namespace tagwarden-system --create-namespace \
  --set manager.image.repository=<some-registry>/tagwarden \
  --set manager.image.tag=<tag> \
  --set 'deniedCIDRs={10.244.0.0/16,10.96.0.0/12}'
```

`targets` and `mirrors` in the values create `ClusterMirrorTarget` and
`ArtifactMirror` objects. On the first install the CRDs are not served yet,
so run `helm upgrade` with the same values once more to create them.
`helm uninstall` keeps the CRDs, targets and mirrors; reinstalling with the
same release name adopts them. To remove mirrors, delete them while the
operator still runs. See
[docs/design/helm-chart.md](docs/design/helm-chart.md) for the values and
for how the chart is generated (`make helm`).

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2026 The Tagwarden Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

