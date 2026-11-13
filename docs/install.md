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

Every value with its default: [helm-values.md](helm-values.md). How the
chart is generated: [design/helm-chart.md](design/helm-chart.md).

### Helm 4 panics with `--wait`

Helm 4 with `--wait=watcher` (what a bare `--wait` means there) can crash with
`panic: send on closed channel` in the kstatus watcher
(`fluxcd/cli-utils`, `object_status_reporter.go`). The race is still in
`fluxcd/cli-utils` v1.4.0, which Helm main uses. Rerun the command, or pass
`--wait=legacy` to use the Helm 3 wait logic.

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

## Azure Container Registry with workload identity

The sync Job can push to and pull from Azure Container Registry with a
Microsoft Entra workload identity instead of a Secret. It exchanges a
projected ServiceAccount token for an Entra access token, and that for a
registry refresh token, with plain HTTPS calls through the target's proxy.
The cluster needs a public OIDC issuer that Microsoft Entra ID can reach
(on AKS, enable the OIDC issuer). The Azure Workload Identity webhook is
not needed: the controller renders the token volume itself.

1. Create a user-assigned managed identity, or an app registration, and
   note its client ID and your tenant ID:

   ```sh
   az identity create -g <group> -n tagwarden-sync
   az identity show -g <group> -n tagwarden-sync --query clientId -o tsv
   ```

2. Add a federated credential for the sync ServiceAccount. The subject is
   `system:serviceaccount:<operator namespace>:<ServiceAccount>`, the
   issuer is the cluster's OIDC issuer URL and the audience is
   `api://AzureADTokenExchange`:

   ```sh
   az identity federated-credential create -g <group> \
     --identity-name tagwarden-sync --name tagwarden-sync \
     --issuer "<cluster OIDC issuer URL>" \
     --subject system:serviceaccount:tagwarden-system:tagwarden-sync-azure \
     --audience api://AzureADTokenExchange
   ```

3. Grant the identity `AcrPush` on the target registry and `AcrPull` on
   each source registry. Registries that use ABAC repository permissions
   need the matching repository roles instead.

   ```sh
   az role assignment create --assignee <client ID> --role AcrPush \
     --scope $(az acr show -n myregistry --query id -o tsv)
   ```

4. Create the ServiceAccount in the operator namespace. Tagwarden does not
   create it and needs no RBAC for it; the pods only reference it. Give it
   no RBAC bindings.

   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: tagwarden-sync-azure
     namespace: tagwarden-system
   automountServiceAccountToken: false
   ```

5. Point the target at the identity:

   ```yaml
   apiVersion: mirror.tagwarden.dev/v1alpha1
   kind: ClusterMirrorTarget
   metadata:
     name: acr
   spec:
     registry: myregistry.azurecr.io
     auth:
       azureWorkloadIdentity: {}       # instead of credentialsSecretRef
     workloadIdentity:
       serviceAccountName: tagwarden-sync-azure
       azure:
         clientID: 00000000-0000-0000-0000-000000000000
         tenantID: 00000000-0000-0000-0000-000000000000
         # authorityHost: https://login.microsoftonline.us/   # national clouds
     sourceCredentials:
       - registry: upstream.azurecr.io
         azureWorkloadIdentity: {}     # pull with the same identity
     allowedSources: [upstream.azurecr.io, registry.k8s.io]
     projects:
       - name: mirror
         namespaceSelector: {}
     proxy:
       httpsProxy: http://proxy.example.internal:3128
   ```

- Allow the authority host (`login.microsoftonline.com`, or your national
  cloud's) and every Azure registry in the proxy allowlist and in
  NetworkPolicies. Registries also redirect blob downloads to
  `*.blob.core.windows.net` or their data endpoints.
- Only pods that use Azure auth run as `serviceAccountName` and mount the
  projected token (audience `api://AzureADTokenExchange`, one hour). The
  other pods keep `tagwarden-sync`. No pod gets a Kubernetes API token.
- Every mirror of the target shares the identity. Use separate targets,
  ServiceAccounts and identities when teams need different registry
  rights.
- Give each target whose identity differs its own ServiceAccount and its
  own federated credential, and always set `serviceAccountName`. Entra
  matches a federated credential by the token's subject, the
  ServiceAccount. If two targets share one ServiceAccount (the default
  `tagwarden-sync`, for example), the projected token in a pod of one
  target is also accepted for the other target's identity, so a
  compromised sync pod of one target can act as the other.
- Azure auth works only with Azure Container Registry login servers
  (`*.azurecr.io`, `*.azurecr.us`, `*.azurecr.cn`, port 443 at most), for
  the target and for source entries. The CRD refuses other hosts, and the
  sync Job checks again before it sends a token.
- `authorityHost` accepts only `https://login.microsoftonline.com/`
  (default), `https://login.microsoftonline.us/`,
  `https://login.partner.microsoftonline.cn/` and
  `https://login.chinacloudapi.cn/`. Another authority, such as one of a
  disconnected or on-premises Azure, needs a code change in two places:
  the CEL rule on `authorityHost` and `syncspec.AzureAuthority`.
- The registry token is always requested for
  `https://containerregistry.azure.net/.default`, the documented
  public-cloud ACR audience. US Government and China clouds are untested
  and may need another audience; there the token request fails closed
  with an Entra error and no token leaks. A Resource Manager scope is
  never used, so no management token reaches the registry.
- A missing ServiceAccount does not change the target: it stays `Ready`
  and so do its mirrors. The Job cannot create its pod, and the only sign
  is a `FailedCreate` Event on the Job
  (`kubectl -n tagwarden-system get events --field-selector reason=FailedCreate`).
  Create the ServiceAccount before the target.
- Entra and registry errors show the HTTP status and the Entra error code
  (for example `invalid_client AADSTS700016`), never a token.
- Real-cloud tests are manual; CI uses fakes for Entra and the registry.

## Amazon ECR with IRSA

The sync Job can push to and pull from Amazon ECR private registries with
IAM roles for service accounts (IRSA) instead of a Secret. It sends a
projected ServiceAccount token to AWS STS (`AssumeRoleWithWebIdentity`),
signs an ECR `GetAuthorizationToken` call with the temporary credentials
(SigV4), and uses the returned password for user `AWS`. All calls are
plain HTTPS through the target's proxy; there is no AWS SDK. The cluster
needs an OIDC issuer that IAM trusts (on EKS, the cluster's OIDC
provider). The EKS Pod Identity webhook is not needed: the controller
renders the token volume itself.

EKS Pod Identity is not supported. Its agent listens on a link-local
address, and the sync Job refuses link-local addresses by design (T16).

1. Create an IAM OIDC provider for the cluster's issuer, with client ID
   `sts.amazonaws.com`. On EKS:

   ```sh
   eksctl utils associate-iam-oidc-provider --cluster <cluster> --approve
   ```

2. Create a role that trusts the provider for the sync ServiceAccount.
   The subject is `system:serviceaccount:<operator namespace>:<ServiceAccount>`
   and the audience `sts.amazonaws.com`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/<issuer without https://>"},
       "Action": "sts:AssumeRoleWithWebIdentity",
       "Condition": {"StringEquals": {
         "<issuer without https://>:sub": "system:serviceaccount:tagwarden-system:tagwarden-sync-aws",
         "<issuer without https://>:aud": "sts.amazonaws.com"
       }}
     }]
   }
   ```

   ```sh
   aws iam create-role --role-name tagwarden-sync --assume-role-policy-document file://trust.json
   ```

3. Allow the role to get a registry token, push to the target
   repositories and pull from the source repositories:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
       {"Effect": "Allow", "Resource": "arn:aws:ecr:eu-west-1:123456789012:repository/mirror/*",
        "Action": ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
                   "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage",
                   "ecr:ListImages", "ecr:DescribeImages"]},
       {"Effect": "Allow", "Resource": "arn:aws:ecr:eu-west-1:210987654321:repository/upstream/*",
        "Action": ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
                   "ecr:ListImages", "ecr:DescribeImages"]}
     ]
   }
   ```

   A source in another account also needs a repository policy there that
   allows the role. ECR refuses pushes to repositories that do not exist;
   create the target repositories (`<project>/<path>`) first unless the
   registry creates them on push.

4. Create the ServiceAccount in the operator namespace. Tagwarden does not
   create it and needs no RBAC for it. The `eks.amazonaws.com/role-arn`
   annotation is not needed: the role comes from the target.

   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: tagwarden-sync-aws
     namespace: tagwarden-system
   automountServiceAccountToken: false
   ```

5. Point the target at the role:

   ```yaml
   apiVersion: mirror.tagwarden.dev/v1alpha1
   kind: ClusterMirrorTarget
   metadata:
     name: ecr
   spec:
     registry: 123456789012.dkr.ecr.eu-west-1.amazonaws.com
     auth:
       awsWorkloadIdentity: {}         # instead of credentialsSecretRef
     workloadIdentity:
       serviceAccountName: tagwarden-sync-aws
       aws:
         roleARN: arn:aws:iam::123456789012:role/tagwarden-sync
         region: eu-west-1
     sourceCredentials:
       - registry: 210987654321.dkr.ecr.eu-west-1.amazonaws.com
         awsWorkloadIdentity: {}       # pull with the same role
     allowedSources: [210987654321.dkr.ecr.eu-west-1.amazonaws.com, registry.k8s.io]
     projects:
       - name: mirror
         namespaceSelector: {}
     proxy:
       httpsProxy: http://proxy.example.internal:3128
   ```

- Allow `sts.<region>.amazonaws.com`, `api.ecr.<region>.amazonaws.com`
  and every ECR registry host in the proxy allowlist and in
  NetworkPolicies. ECR serves layers from the S3 bucket
  `prod-<region>-starport-layer-bucket`, so also allow the region's S3
  endpoints (for example `*.s3.<region>.amazonaws.com`). China regions use
  `amazonaws.com.cn` instead of `amazonaws.com`. In `us-east-1`, layer
  redirects may also use the global `s3.amazonaws.com` name; allow both.
- The STS and ECR API endpoints come from `region`; there is no endpoint
  field. A FIPS registry host (`<account>.dkr.ecr-fips.<region>.amazonaws.com`)
  gets its token from `ecr-fips.<region>.amazonaws.com`; STS stays the
  regional endpoint (in GovCloud that endpoint is FIPS). Dual-stack hosts
  (`*.on.aws`), ECR Public and VPC endpoint DNS names are not accepted.
- Only pods that use AWS auth run as `serviceAccountName` and mount the
  projected token (audience `sts.amazonaws.com`, one hour). The other
  pods keep `tagwarden-sync`. No pod gets a Kubernetes API token. A pod
  that pushes with AWS and pulls with Azure gets both tokens, each with
  its own audience and file.
- AWS auth works only with ECR private registry hosts
  (`<account>.dkr.ecr[-fips].<region>.amazonaws.com[.cn]`, port 443 at
  most). The CRD refuses other hosts. The sync Job checks again before it
  sends a token, and also refuses a registry whose region differs from
  `workloadIdentity.aws.region`, so a token for one region never goes to
  another. Only the Job checks the region, not the CRD: a mismatch shows
  at run time as a failed sync with a config error (exit 3).
- The STS session is `tagwarden-<hash of the mirror>` and lasts one
  hour, as long as a sync Job may run, because the ECR token may expire
  with the session. The role's maximum session duration must be at least
  one hour (the IAM default). CloudTrail shows it in `AssumeRoleWithWebIdentity` and in the
  ECR calls.
- Use one ServiceAccount per role, and one trust policy subject per
  ServiceAccount, and always set `serviceAccountName`. STS accepts the
  projected token for every role whose trust policy names its
  ServiceAccount. If two targets with different roles share one
  ServiceAccount (the default `tagwarden-sync`, for example), a
  compromised sync pod of one target can assume the other target's role.
  Every mirror of a target shares its role.
- A missing ServiceAccount leaves the target `Ready`; the Job's pod is not
  created and only a `FailedCreate` Event shows it.
- STS and ECR errors show the HTTP status and the AWS error code (for
  example `HTTP 400 InvalidIdentityToken`), never a token or a key.
- `HTTP 400 InvalidSignatureException` from ECR usually means the node
  clock is off: SigV4 signatures expire after a few minutes of skew. It
  is a config error (exit 3) and the Job is not retried; fix NTP on the
  nodes.
- China and GovCloud are untested. Real-cloud tests are manual; CI uses
  fakes for STS, ECR and the registry.

## Google Artifact Registry with Workload Identity Federation

The sync Job can push to and pull from Google Artifact Registry with
Workload Identity Federation instead of a Secret. It sends a projected
ServiceAccount token to the Security Token Service
(`https://sts.googleapis.com/v1/token`) for a federated access token.
With `serviceAccountEmail` it then exchanges that token at
`https://iamcredentials.googleapis.com` (`generateAccessToken`, one hour)
for an access token of a Google service account. The registry gets the
access token as the password of user `oauth2accesstoken`. All calls are
plain HTTPS through the target's proxy; there is no Google SDK. The
cluster needs an OIDC issuer: any Kubernetes cluster has one, GKE
included.

The GKE metadata server (`169.254.169.254`, `metadata.google.internal`)
is not used on purpose: it is link-local, and the sync Job refuses
link-local addresses by design (T16). Workload Identity Federation for
GKE does not need to be enabled on the cluster or node pool.

1. Create a workload identity pool and an OIDC provider for the
   cluster's issuer, mapping the token subject:

   ```sh
   kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
   kubectl get --raw /openid/v1/jwks > cluster-jwks.json

   gcloud iam workload-identity-pools create tagwarden --location=global
   gcloud iam workload-identity-pools providers create-oidc cluster \
     --location=global --workload-identity-pool=tagwarden \
     --issuer-uri=<issuer> \
     --attribute-mapping=google.subject=assertion.sub \
     --attribute-condition="assertion.sub=='system:serviceaccount:tagwarden-system:tagwarden-sync-gcp'" \
     --jwk-json-path=cluster-jwks.json
   ```

   The attribute condition makes STS refuse tokens of every other
   ServiceAccount in the cluster, so a pod elsewhere cannot get a Google
   token from this provider at all.

   `--jwk-json-path` uploads the cluster's signing keys, so Google never
   needs to reach the cluster. Tokens signed with a key that is not
   uploaded fail with `invalid_grant`: when the cluster rotates its
   service account signing keys, upload a JWKS with the old and the new
   keys (`gcloud iam workload-identity-pools providers update-oidc ...
   --jwk-json-path=...`) before the switch, and drop the old key after
   the old tokens expired. Leave the flag out when the issuer serves its discovery document
   publicly. Keep the provider's default allowed audience: the projected
   token is issued for
   `https://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`.

2. Grant the registry roles. Artifact Registry accepts federated
   principals directly, so a Google service account is optional. The
   principal of the sync ServiceAccount is:

   ```text
   principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/subject/system:serviceaccount:tagwarden-system:tagwarden-sync-gcp
   ```

   ```sh
   gcloud artifacts repositories add-iam-policy-binding mirror \
     --location=europe-west1 --role=roles/artifactregistry.writer \
     --member=principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/subject/system:serviceaccount:tagwarden-system:tagwarden-sync-gcp
   gcloud artifacts repositories add-iam-policy-binding upstream \
     --location=europe-west1 --role=roles/artifactregistry.reader \
     --member=principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/subject/system:serviceaccount:tagwarden-system:tagwarden-sync-gcp
   ```

   Bind exactly this `principal://` subject. Do not grant the roles to a
   `principalSet://` of the pool (or of an attribute): that would give
   every ServiceAccount of the cluster, or of every cluster the pool
   trusts, the registry roles.

   To impersonate a service account instead (for example when policy
   requires service accounts in IAM bindings), grant the roles above to
   the service account, allow the principal to mint its tokens, and set
   `serviceAccountEmail`. `serviceAccountEmail` must be a user-managed
   service account (`<name>@<project ID>.iam.gserviceaccount.com`);
   service accounts of domain-scoped projects and Google-managed service
   accounts do not match the pattern and are refused.

   ```sh
   gcloud iam service-accounts add-iam-policy-binding \
     tagwarden-sync@example-project.iam.gserviceaccount.com \
     --role=roles/iam.serviceAccountTokenCreator \
     --member=principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/subject/system:serviceaccount:tagwarden-system:tagwarden-sync-gcp
   ```

   Artifact Registry refuses pushes to repositories that do not exist:
   create the Artifact Registry repository (the first path segment after
   the host) first.

3. Create the ServiceAccount in the operator namespace. Tagwarden does not
   create it and needs no RBAC for it. The `iam.gke.io/gcp-service-account`
   annotation is not needed.

   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: tagwarden-sync-gcp
     namespace: tagwarden-system
   automountServiceAccountToken: false
   ```

4. Point the target at the provider:

   ```yaml
   apiVersion: mirror.tagwarden.dev/v1alpha1
   kind: ClusterMirrorTarget
   metadata:
     name: gar
   spec:
     registry: europe-west1-docker.pkg.dev
     auth:
       gcpWorkloadIdentity: {}         # instead of credentialsSecretRef
     workloadIdentity:
       serviceAccountName: tagwarden-sync-gcp
       gcp:
         audience: //iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/providers/cluster
         # serviceAccountEmail: tagwarden-sync@example-project.iam.gserviceaccount.com
     sourceCredentials:
       - registry: us-docker.pkg.dev
         gcpWorkloadIdentity: {}       # pull with the same identity
     allowedSources: [us-docker.pkg.dev, registry.k8s.io]
     projects:
       - name: example-project
         namespaceSelector: {}
     proxy:
       httpsProxy: http://proxy.example.internal:3128
   ```

   Artifact Registry paths are `<host>/<project ID>/<repository>/<image>`,
   so the Tagwarden project is the Google Cloud project ID and the
   mirror's target path starts with the repository.

- Allow `sts.googleapis.com`, `iamcredentials.googleapis.com` (only with
  `serviceAccountEmail`) and every registry host in the proxy allowlist
  and in NetworkPolicies. Google does not document other hosts for
  Artifact Registry. Layer downloads observed for `pkg.dev` and `gcr.io`
  redirect to `/artifacts-downloads/` on the registry host itself; this
  is observed behaviour, not documented. If pulls fail behind the proxy
  with a blob download error, check the proxy log for a redirect to
  another host such as `storage.googleapis.com` and allow it. The Job
  follows such redirects only without credentials.
- The STS and IAM Credentials endpoints are fixed; there is no endpoint
  field. Regional STS endpoints are not used.
- Only pods that use GCP auth run as `serviceAccountName` and mount the
  projected token (the provider audience, one hour). The other pods keep
  `tagwarden-sync`. No pod gets a Kubernetes API token. A pod that needs
  several providers gets one token per provider, each with its own
  audience and file.
- GCP auth works only with Artifact Registry Docker hosts
  (`<location>-docker.pkg.dev`, and `gcr.io`, `us.gcr.io`, `eu.gcr.io`,
  `asia.gcr.io`, which Artifact Registry serves for `gcr.io`
  repositories), port 443 at most. The CRD refuses other hosts, and the
  sync Job checks again before it sends a token. `mirror.gcr.io` and
  other `*.gcr.io` names are refused.
- Federated tokens use the `cloud-platform` scope, which they also need
  to call IAM Credentials; the principal's IAM roles limit what they can do.
  Impersonated tokens use the narrower Cloud Storage scope
  `devstorage.read_write`, which Artifact Registry accepts for Docker
  push and pull. The narrower scope is untested against a real registry:
  check a push and a pull after setting `serviceAccountEmail`. A federated
  token lasts up to an hour, an impersonated one exactly one hour, as long
  as a sync Job may run.
- The access token goes only to the registry host. The Job refuses a
  registry whose bearer token realm is on another host before any token
  request (config error), and refuses any request with credentials to
  another host while it runs.
- Use one ServiceAccount per identity, and always set
  `serviceAccountName`. The principal is the Kubernetes ServiceAccount, so
  two targets that share one ServiceAccount share every role granted to
  it. Every mirror of a target shares its identity.
- A missing ServiceAccount leaves the target `Ready`; the Job's pod is not
  created and only a `FailedCreate` Event shows it.
- STS and IAM errors show the HTTP status and the OAuth error or Google
  API status (for example `HTTP 400 invalid_grant` or
  `HTTP 403 PERMISSION_DENIED`), never a token. `invalid_grant` from STS
  usually means the audience, the issuer or the uploaded keys do not
  match the cluster.
- Real-cloud tests are manual; CI uses fakes for STS, IAM Credentials and
  the registry.

## Enable the vulnerability gate

The gate scans the images that auto-mirror copies, with a Trivy server in
client/server mode. It is off by default and never applies to
`ArtifactMirror` objects you wrote yourself. Design:
[vulnerability-gate.md](design/vulnerability-gate.md).

### 1. Mirror the Trivy image and the databases

The server and the sync pods pull from your registry, never the internet.
Mirror these with ordinary user-defined mirrors on a platform-owned target:

- the Trivy image (pin it by digest),
- `ghcr.io/aquasecurity/trivy-db` tag `2`,
- `ghcr.io/aquasecurity/trivy-java-db` tag `1`, only if you set
  `javaDB: PerJob` (about 1 GB).

The database tags move several times a day, so the target needs
`policy.onTagMutation: Overwrite` and must hold only these feeds. Only the
platform team may push to its project: whoever can push the database decides
what counts as vulnerable.

```yaml
apiVersion: mirror.tagwarden.dev/v1alpha1
kind: ClusterMirrorTarget
metadata:
  name: scanner-feeds
spec:
  registry: registry.example.internal
  credentialsSecretRef: {name: registry-push}
  allowedSources: [ghcr.io]
  projects:
    - name: platform
      namespaceSelector:
        matchLabels: {kubernetes.io/metadata.name: tagwarden-system}
  policy: {onTagMutation: Overwrite}
  limits: {minSyncInterval: 1h, maxArtifactSize: 2Gi}
---
apiVersion: mirror.tagwarden.dev/v1alpha1
kind: ArtifactMirror
metadata: {name: trivy-db, namespace: tagwarden-system}
spec:
  targetRef: scanner-feeds
  schedule: "0 */6 * * *"
  source: {registry: ghcr.io, repository: aquasecurity/trivy-db}
  target: {project: platform}
  tags: {tags: ["2"]}
```

Give the server a pull-only account for the project (a
`kubernetes.io/dockerconfigjson` Secret in the operator namespace).

### 2. Turn on the Trivy server

```yaml
# values.yaml
networkPolicy:
  enabled: true
clusterDomain: cluster.local        # your cluster's DNS domain
trivy:
  enabled: true
  image:
    repository: registry.example.internal/platform/ghcr.io/aquasecurity/trivy
    tag: "0.76.1"                   # the Trivy version; the gate checks it
    digest: sha256:<64 hex>         # required
  imagePullSecrets: [{name: registry-pull}]
  db:
    repository: registry.example.internal/platform/ghcr.io/aquasecurity/trivy-db:2
    credentialsSecretRef: {name: trivy-db-pull}
    caBundleSecretRef: {name: registry-ca, key: ca.crt}
  networkPolicy:
    registryEgress: [{cidr: 10.0.0.0/24, port: 443}]
  token:
    existingSecret: trivy-token     # Secret with a "token" key, see below
vulnerabilityExceptions:
  approvers:
    - {kind: Group, name: security-team, apiGroup: rbac.authorization.k8s.io}
```

- The chart renders a single-replica StatefulSet with a PVC
  (`trivy.persistence`), a Service on port 4954 and a token Secret. It
  passes `--trivy-image`, `--trivy-version`, `--trivy-url`,
  `--trivy-token-secret` and `--scanner-start-timeout` (value
  `trivy.scannerStartTimeout`, default `5m`) to the manager. The flags are
  all empty or all set. The manager refuses an image that is not pinned by
  digest.
- The chart generates the token if `trivy.token.existingSecret` is empty
  and keeps it on upgrades. Under Argo CD or `helm template` the lookup
  returns nothing and the token would rotate on every render, so GitOps
  installs create the Secret themselves and set `existingSecret`.
- Service names are dialed as `<service>.<namespace>.svc.<clusterDomain>.`,
  with a trailing dot, so `resolv.conf` search domains never apply. Set
  `clusterDomain` (manager flag `--cluster-domain`) when yours is not
  `cluster.local`.
- Client and server must share major.minor. Update the server and
  `trivy.image.tag` together, as a deliberate step; never use a floating
  tag.
- The in-chart server speaks plain HTTP. The token and the NetworkPolicy
  guard it. If you need encryption on the pod network, use a service mesh
  with mTLS, or an external https server.

To use an external server instead, leave `trivy.enabled: false` and set
`vulnerabilityGate.scanner` on the target (`url`, `caBundleSecretRef`,
`tokenSecretRef`, `image` and `version` together). The URL must be https
unless it is a cluster Service name. A target with its own `url` gets no
token unless it names one in `tokenSecretRef`.

### 3. Enable the gate on a target

```yaml
spec:
  autoMirror:
    enabled: true
    project: shared
    vulnerabilityGate:
      enabled: true
      action: Report            # Report | Block
      severity: Critical        # Critical | High | Medium | Low
      ignoreUnfixed: false
      includeUnknown: false     # count findings without a vendor severity
      maxDBAge: 72h             # at least 1h
      onScanError: Report       # Report | Block
      rescanInterval: 24h       # unset: no re-scan; at least 1h
      onVulnerableTag: Report   # Report | Untag (Untag needs action: Block)
      maxExceptionDuration: 2160h
      scanner:
        javaDB: Disabled        # Disabled (default) | PerJob
```

- `action` decides what happens to a tag with findings. `onScanError`
  decides what happens to a tag the gate could not judge. A database older
  than `maxDBAge` is a scan error. With `Report` the image is copied and
  the finding or error is recorded. With `Block` it is not copied.
- With `action` or `onScanError` set to `Block`, `autoMirror.project` is
  reserved for generated mirrors. A hand-written mirror there gets
  `Ready=False` with reason `ProjectReservedForAutoMirror`. The check spans
  every target on the same registry.
- `javaDB: Disabled` skips JAR, WAR, EAR and PAR files. Their findings are
  missing, and `status.javaScanned` and the audit line say
  `javaScanned: false`. `PerJob` needs `scanner.javaDBRepository` (a
  mirrored Java DB in the target registry) and downloads about 1 GB, with
  about 2.5 GiB of ephemeral disk, in every sync Job that has something to
  scan.
- Only generated Jobs of a gated target get the scanner sidecar. Other
  Jobs and mirrors are unchanged.

### 4. NetworkPolicy

Gated sync pods carry the label `tagwarden.dev/scanner: trivy`. With
`networkPolicy.enabled` the chart's Trivy policy allows ingress on 4954
only from pods with that label and from the manager. Its egress allows DNS
and the `trivy.networkPolicy.registryEgress` ranges (the registry holding
the database). If you restrict sync pod egress yourself, allow gated pods
to reach the Trivy Service too: see
[network-policies.md](network-policies.md#gated-sync-pods).

Without an enforcing CNI any pod can call the server with a stolen token.

### 5. Exceptions

The chart always renders the `<release>-exception-approver` ClusterRole
(create, update and delete `VulnerabilityException`). The RBAC helper roles
never grant it. Bind it to the security team with
`vulnerabilityExceptions.approvers`. Tenants get no write access.

```yaml
apiVersion: mirror.tagwarden.dev/v1alpha1
kind: VulnerabilityException
metadata: {name: web-nginx-cve-2026-12345}
spec:
  targetRef: default
  namespaces: [team-web]
  repository: docker.io/library/nginx
  vulnerabilities: [CVE-2026-12345]   # and/or digests: [sha256:...]
  expires: "2026-12-01T00:00:00Z"
  approvedBy: alice@example.internal
  reason: Not reachable, fix scheduled with the next base image.
```

Set `digests`, `vulnerabilities` or both. An exception for a whole
repository is rejected. `approvedBy` is a claim. Set
`vulnerabilityExceptions.approvedByPolicy.enabled: true` to render a
ValidatingAdmissionPolicy that requires it to equal the requesting user.
GitOps tools then need `approvedBy` set to their own ServiceAccount user.
An exception that expires later than `maxExceptionDuration` after its
creation is ignored (`Active=False`, reason `TooLong`). The object also
reports `Expired` and `TargetNotFound`, each with a Warning Event
(`ExceptionExpired`, `ExceptionTooLong`, `TargetNotFound`).

### 6. Re-scan

With `rescanInterval` set, the controller starts a re-scan Job per
generated mirror at spread slots, at most two per target at once. The Job
reads the target registry, never upstream, and scans each selected tag
again. Findings go to `status.vulnerable`. `onVulnerableTag: Untag` (with
`action: Block`) deletes the target tag, never the digest, and only tags
no other mirror of the same path selects. A tag another mirror holds is
reported as `UntagRefused`. The target credentials need delete rights for
Untag.

### 7. Harbor

- Harbor refuses tag DELETE on `/v2`. Set `registryFlavor: Harbor` on the
  `ClusterMirrorTarget` and the Jobs delete the tag through the Harbor API
  instead, scoped to the digest they resolved. It needs
  `credentialsSecretRef` (no workload identity). The robot account needs
  the "delete tag" permission on the mirror projects, besides push and
  pull. A Harbor 404 (tag gone or moved to another digest) is reported as
  `UntagRefused`; other failures as `UntagFailed`. Either way the tag
  stays. Without `registryFlavor`, Untag on Harbor reports `UntagFailed`.
  Prune on Harbor needs the same settings.
- Use Harbor's own scanning as a second layer. It also covers
  hand-written mirrors and images mirrored under `Report`: scan on push, a
  daily "scan all" on the mirror projects, "prevent vulnerable images from
  running" with the same threshold as the gate's `severity`, and Harbor's
  Trivy adapter pointed at the same mirrored database repository.

### See the results

```sh
kubectl get clustermirrortarget default -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}{"\n"}{end}'
kubectl -n team-web get artifactmirror <auto-...> -o yaml   # status.findings, status.vulnerable
kubectl -n team-web get events --field-selector involvedObject.kind=Pod
```

- Target conditions: `ScannerReady` (False with `ScannerUnavailable`,
  `VersionMismatch` or `NotConfigured`) and `VulnerabilityDBReady` (False
  with `DBStale`). The target's `Ready` and hand-written mirrors are not
  affected.
- Generated mirror: condition `VulnerabilitiesFound` (reason `Reported`,
  `Blocked` or `Clear`), condition `VulnerabilityGate` (False when tags
  could not be judged; reasons `DBStale`, `ScannerUnavailable`,
  `VersionMismatch`, `ScanFailed`), condition `Rescanned` (reason
  `Rescanned` or `RescanFailed`), `status.findings`, `status.vulnerable`,
  `status.lastRescan` and `status.javaScanned`. `Ready` and `Synced` stay
  True when the sync worked.
- Events on the mirror: `VulnerabilitiesFound`, `VulnerabilityScanFailed`,
  `VulnerableTagFound`, `TagUntagged`, and `VulnerabilityExceptionApplied`
  (Normal) when exceptions turn a tag's verdict from findings to accepted.
  It names the exception, the IDs and the tag, once per tag and exception.
  `status.gate.accepted` lists them. On the pod: `VulnerabilitiesFound`
  (Report), `MirrorRefused` with `VulnerabilityBlocked` or `ScanFailed`
  (Block), `VulnerabilityScanFailed` and `MirroredImageVulnerable`
  (re-scan). On an exception: `ExceptionExpired`, `ExceptionTooLong`, `TargetNotFound`.
- Metrics: `tagwarden_vulnerability_gate_unscanned{target}` and
  `tagwarden_scanner_start_failures_total{target,reason}`. Alert on both.
- The audit line of each artifact carries the verdict, scanner version and
  database time.

### When the scanner is not configured

A gate that is enabled but cannot scan fails loudly, not silently. When the
target has no scanner URL or no client image and version (neither on the
target nor from the chart):

- the target gets `ScannerReady=False` with reason `NotConfigured` and a
  Warning Event;
- `tagwarden_vulnerability_gate_unscanned{target="<name>"}` is 1;
- under `onScanError: Report`, each generated mirror gets
  `VulnerabilityGate=False` (`NotConfigured`), its Jobs run without a
  sidecar and the images are copied unscanned. Under `Block` the mirror
  gets `Ready=False` (`ScannerUnavailable`) and no CronJob, so nothing is
  copied;
- pods using those images get `VulnerabilityScanFailed` (Report) or
  `MirrorRefused` (Block).

If the scanner sidecar cannot start (image pull error, crash loop), the Job
is deleted after `trivy.scannerStartTimeout`, nothing is copied, and
`tagwarden_scanner_start_failures_total` increases.

## Prune tags a mirror no longer selects

Prune is opt-in: `spec.tags.prune: true` on an `ArtifactMirror`. It is off
by default. With it, a sync deletes the tags that the mirror created and
no longer selects, for example after `keepLatest` moved on.

- **Only recorded tags.** The controller records each tag that a mirror
  copies or overwrites in `status.owned`. A tag the sync only skipped (it
  was already on the target) is not recorded, even when its digest matches. Only those tags are candidates. Tags that were
  on the target before the mirror recorded them (pushed before the upgrade,
  or by hand) are not in `status.owned` and are never pruned. There is no
  backfill. `status.owned` keeps up to 200 tags; the oldest are dropped from
  the record, so they are never pruned.
- **Tags only.** Prune deletes the tag, never the digest. The manifest
  stays on the registry until garbage collection removes untagged
  artifacts. Run it on Harbor with "Delete untagged artifacts" (Administration,
  Clean Up, Garbage Collection). Other registries have their own rules.
- **Harbor.** Set `registryFlavor: Harbor` on the `ClusterMirrorTarget`, as
  for Untag. The robot account needs the "delete tag" permission on the
  mirror projects, besides push and pull.
- **Skipped runs.** A run prunes nothing when a copy failed or was blocked
  by the gate, when the selection is empty, or when the listing failed. If
  another mirror of the same target repository selects tags by pattern,
  prune does nothing and the Synced message says so. Tags named in
  `spec.tags.tags` are never pruned.
- **Check.** `status.owned` lists the recorded tags. The Synced message
  includes `pruned N`, and each deleted tag gets a Normal `TagPruned`
  Event.

Example and the full field list: [features.md, Prune](features.md#prune).

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
- Scan auto-mirrored images: [Enable the vulnerability gate](#enable-the-vulnerability-gate).
- Read what the operator trusts and why: [threat-model.md](threat-model.md).
