# Network policies

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

Targets with cloud workload identity also reach the token endpoints
through the same path as the registry: the Microsoft Entra authority
host (`login.microsoftonline.com` by default) for Azure,
`sts.<region>.amazonaws.com`, `api.ecr.<region>.amazonaws.com` and the
region's S3 endpoints for ECR layers for AWS, and `sts.googleapis.com`
and `iamcredentials.googleapis.com` for Google. Allow them at the proxy,
or in the `direct` policy.

Add your pod and service CIDRs to `except` when they are outside these
ranges. NetworkPolicies are a second layer: the sync Job checks every
source address itself ([threat model](threat-model.md) T16).

Some CNIs reject the packets of a new pod until its policy is programmed,
usually for a second or so. Only during the first ~35 s of a run, the sync
Job retries connections that fail at dial time (for example
`proxyconnect tcp: ... connection refused`) and temporary DNS errors. If a
sync still fails with such an error, check that the policy allows DNS and
the proxy or registry address and port.

## Gated sync pods

Generated mirrors of a target with the [vulnerability
gate](install.md#enable-the-vulnerability-gate) also carry
`tagwarden.dev/scanner: trivy`. Their sidecar and sync container call the
Trivy Service on TCP 4954 (the chart's Service is `<release>-trivy`; DNS is
already allowed above). Policies add up, so a separate policy for the label
is enough:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sync-egress-trivy
  namespace: tagwarden-system
spec:
  podSelector:
    matchLabels:
      tagwarden.dev/scanner: trivy
  policyTypes: [Egress]
  egress:
  - to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/component: trivy
    ports: [{port: 4954, protocol: TCP}]
```

The selector matches the pods of the chart's Trivy server. For an
external server use an `ipBlock` instead. The chart's own Trivy policy
(with `networkPolicy.enabled`) allows ingress to the server only from pods with that label and from the manager, and its
egress only to DNS and `trivy.networkPolicy.registryEgress`. If the server
is unreachable, the run reports `ScannerUnavailable` after a short retry
window.
