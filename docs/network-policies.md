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

Add your pod and service CIDRs to `except` when they are outside these
ranges. NetworkPolicies are a second layer: the sync Job checks every
source address itself ([threat model](threat-model.md) T16).

Some CNIs reject the packets of a new pod until its policy is programmed,
usually for a second or so. Only during the first ~35 s of a run, the sync
Job retries connections that fail at dial time (for example
`proxyconnect tcp: ... connection refused`) and temporary DNS errors. If a
sync still fails with such an error, check that the policy allows DNS and
the proxy or registry address and port.
