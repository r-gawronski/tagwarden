/*
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
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RegistryHost is a registry host name or bracketed IP address with an
// optional port, for example registry.example.internal:8443 or [::1]:5000.
// It has no scheme, credentials or path.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:XValidation:rule=`self.matches(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*|\[[0-9a-fA-F:.]+\])(:[0-9]{1,5})?$')`,message="must be host[:port] without a scheme, credentials or path"
type RegistryHost string

// ProjectName is a single path segment in the target registry.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=255
// +kubebuilder:validation:Pattern=`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*$`
type ProjectName string

// SecretRef names a Secret in the operator namespace.
type SecretRef struct {
	// name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`
}

// SecretKeyRef names a key in a Secret in the operator namespace.
type SecretKeyRef struct {
	// name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`

	// key in the Secret that holds the PEM data.
	// +kubebuilder:default="ca.crt"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Key string `json:"key,omitempty"`
}

// ProxySpec configures the HTTP(S) proxy used for upstream traffic.
type ProxySpec struct {
	// httpsProxy is the proxy URL, for example http://proxy.example.internal:3128.
	// Credentials must not be part of the URL. Use credentialsSecretRef.
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:XValidation:rule="isURL(self) && (self.startsWith('http://') || self.startsWith('https://'))",message="must be an http or https URL"
	// +kubebuilder:validation:XValidation:rule="!self.contains('@')",message="must not contain credentials, use credentialsSecretRef"
	// +required
	HTTPSProxy string `json:"httpsProxy"`

	// noProxy lists hosts, domains and CIDRs that bypass the proxy.
	// +kubebuilder:validation:MaxItems=100
	// +kubebuilder:validation:items:MaxLength=253
	// +listType=set
	// +optional
	NoProxy []string `json:"noProxy,omitempty"`

	// caBundleSecretRef holds the CA that signs the proxy certificates, for example a TLS-inspection CA.
	// It is trusted only by the sync Job.
	// +optional
	CABundleSecretRef *SecretKeyRef `json:"caBundleSecretRef,omitempty"`

	// credentialsSecretRef holds the proxy username and password
	// (a kubernetes.io/basic-auth Secret).
	// +optional
	CredentialsSecretRef *SecretRef `json:"credentialsSecretRef,omitempty"`
}

// SourceCredential holds the pull credentials for one source registry:
// a Secret or a cloud workload identity.
// +kubebuilder:validation:XValidation:rule="[has(self.secretRef), has(self.azureWorkloadIdentity), has(self.awsWorkloadIdentity), has(self.gcpWorkloadIdentity)].filter(x, x).size() == 1",message="set exactly one of secretRef, azureWorkloadIdentity, awsWorkloadIdentity or gcpWorkloadIdentity"
// +kubebuilder:validation:XValidation:rule=`!has(self.azureWorkloadIdentity) || self.registry.lowerAscii().matches(r'^[a-z0-9]+(-[a-z0-9]+)?\.azurecr\.(io|us|cn)(:443)?$')`,message="azureWorkloadIdentity needs an Azure Container Registry host (*.azurecr.io, *.azurecr.us or *.azurecr.cn)"
// +kubebuilder:validation:XValidation:rule=`!has(self.awsWorkloadIdentity) || self.registry.lowerAscii().matches(r'^[0-9]{12}\.dkr\.ecr(-fips)?\.[a-z0-9-]+\.amazonaws\.com(\.cn)?(:443)?$')`,message="awsWorkloadIdentity needs an Amazon ECR private registry host (<account>.dkr.ecr.<region>.amazonaws.com)"
// +kubebuilder:validation:XValidation:rule=`!has(self.gcpWorkloadIdentity) || self.registry.lowerAscii().matches(r'^([a-z0-9]+(-[a-z0-9]+)*-docker\.pkg\.dev|((us|eu|asia)\.)?gcr\.io)(:443)?$')`,message="gcpWorkloadIdentity needs a Google Artifact Registry host (<location>-docker.pkg.dev, gcr.io, us.gcr.io, eu.gcr.io or asia.gcr.io)"
type SourceCredential struct {
	// registry is the source registry these credentials are for. The Docker
	// Hub names docker.io, index.docker.io and registry-1.docker.io count as
	// one registry.
	// +required
	Registry RegistryHost `json:"registry"`

	// secretRef is a kubernetes.io/dockerconfigjson Secret in the operator
	// namespace with an auths entry for the registry.
	// +optional
	SecretRef *SecretRef `json:"secretRef,omitempty"`

	// azureWorkloadIdentity pulls from an Azure Container Registry with
	// the identity in spec.workloadIdentity.azure.
	// +optional
	AzureWorkloadIdentity *AzureWorkloadIdentityAuth `json:"azureWorkloadIdentity,omitempty"`

	// awsWorkloadIdentity pulls from an Amazon ECR private registry with
	// the role in spec.workloadIdentity.aws.
	// +optional
	AWSWorkloadIdentity *AWSWorkloadIdentityAuth `json:"awsWorkloadIdentity,omitempty"`

	// gcpWorkloadIdentity pulls from Google Artifact Registry with the
	// identity in spec.workloadIdentity.gcp.
	// +optional
	GCPWorkloadIdentity *GCPWorkloadIdentityAuth `json:"gcpWorkloadIdentity,omitempty"`
}

// GCPWorkloadIdentityAuth selects Google Cloud Workload Identity
// Federation for a registry. It has no fields: the identity is
// spec.workloadIdentity.gcp.
type GCPWorkloadIdentityAuth struct{}

// AWSWorkloadIdentityAuth selects AWS IAM roles for service accounts
// (IRSA) for a registry. It has no fields: the role is
// spec.workloadIdentity.aws.
type AWSWorkloadIdentityAuth struct{}

// AzureWorkloadIdentityAuth selects Azure workload identity for a
// registry. It has no fields: the identity is spec.workloadIdentity.azure.
type AzureWorkloadIdentityAuth struct{}

// RegistryAuth selects how the sync Job authenticates to the target
// registry when it has no credentialsSecretRef.
// +kubebuilder:validation:XValidation:rule="[has(self.azureWorkloadIdentity), has(self.awsWorkloadIdentity), has(self.gcpWorkloadIdentity)].filter(x, x).size() == 1",message="set exactly one provider"
type RegistryAuth struct {
	// azureWorkloadIdentity pushes to an Azure Container Registry with
	// the identity in spec.workloadIdentity.azure.
	// +optional
	AzureWorkloadIdentity *AzureWorkloadIdentityAuth `json:"azureWorkloadIdentity,omitempty"`

	// awsWorkloadIdentity pushes to an Amazon ECR private registry with
	// the role in spec.workloadIdentity.aws.
	// +optional
	AWSWorkloadIdentity *AWSWorkloadIdentityAuth `json:"awsWorkloadIdentity,omitempty"`

	// gcpWorkloadIdentity pushes to Google Artifact Registry with the
	// identity in spec.workloadIdentity.gcp.
	// +optional
	GCPWorkloadIdentity *GCPWorkloadIdentityAuth `json:"gcpWorkloadIdentity,omitempty"`
}

// WorkloadIdentity is the cloud identity of the sync pods that use cloud
// registry auth. The platform team creates the ServiceAccount and links it
// to the cloud identity; the controller only references it.
type WorkloadIdentity struct {
	// serviceAccountName is the ServiceAccount in the operator namespace
	// that sync pods run as when they use cloud registry auth. Its token
	// is never mounted; the pods get only a projected token with the
	// cloud audience. Defaults to tagwarden-sync.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// azure is the Microsoft Entra application or user-assigned managed
	// identity with a federated credential for the ServiceAccount.
	// +optional
	Azure *AzureIdentity `json:"azure,omitempty"`

	// aws is the IAM role that trusts the cluster's OIDC provider for the
	// ServiceAccount (IAM roles for service accounts).
	// +optional
	AWS *AWSIdentity `json:"aws,omitempty"`

	// gcp is the Google Cloud Workload Identity Federation provider that
	// trusts the cluster's OIDC issuer.
	// +optional
	GCP *GCPIdentity `json:"gcp,omitempty"`
}

// GCPIdentity is a Workload Identity Federation provider. The sync Job
// exchanges the projected ServiceAccount token at
// https://sts.googleapis.com/v1/token and, with serviceAccountEmail, gets
// an access token for that service account from
// https://iamcredentials.googleapis.com. The GKE metadata server is not
// used: it is link-local, which the sync Job refuses.
type GCPIdentity struct {
	// audience is the full resource name of the workload identity pool
	// provider, for example
	// //iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/providers/cluster.
	// The projected token gets the provider's default audience, this name
	// with the https: prefix.
	// +kubebuilder:validation:MaxLength=200
	// +kubebuilder:validation:Pattern=`^//iam\.googleapis\.com/projects/[0-9]{1,20}/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$`
	// +required
	Audience string `json:"audience"`

	// serviceAccountEmail is a Google service account the federated
	// principal impersonates. Leave it empty to grant the Artifact
	// Registry roles to the principal directly.
	// +kubebuilder:validation:MaxLength=100
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]{6,30}@[a-z0-9-]{6,30}\.iam\.gserviceaccount\.com$`
	// +optional
	ServiceAccountEmail string `json:"serviceAccountEmail,omitempty"`
}

// AWSIdentity is an IAM role assumed with the projected ServiceAccount
// token. The STS and ECR API endpoints are derived from the region:
// https://sts.<region>.amazonaws.com and
// https://api.ecr.<region>.amazonaws.com (amazonaws.com.cn in China).
// +kubebuilder:validation:XValidation:rule="self.roleARN.startsWith('arn:aws-cn:') == self.region.startsWith('cn-') && self.roleARN.startsWith('arn:aws-us-gov:') == self.region.startsWith('us-gov-')",message="roleARN and region must be in the same AWS partition"
type AWSIdentity struct {
	// roleARN is the IAM role, for example
	// arn:aws:iam::123456789012:role/tagwarden-sync.
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^arn:aws(-cn|-us-gov)?:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,576}$`
	// +required
	RoleARN string `json:"roleARN"`

	// region is the AWS Region of the STS and ECR API endpoints, for
	// example eu-west-1. Registries that use this role must be in it.
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^((us|eu|ap|sa|ca|me|af|il|mx|cn)-[a-z]+|us-gov-[a-z]+)-[0-9]{1,2}$`
	// +required
	Region string `json:"region"`
}

// AzureIdentity is a Microsoft Entra workload identity.
type AzureIdentity struct {
	// clientID is the application (client) ID of the identity.
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	// +required
	ClientID string `json:"clientID"`

	// tenantID is the directory (tenant) ID of the identity.
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	// +required
	TenantID string `json:"tenantID"`

	// authorityHost is the Microsoft Entra endpoint: one of
	// https://login.microsoftonline.com/ (the default),
	// https://login.microsoftonline.us/,
	// https://login.partner.microsoftonline.cn/ or
	// https://login.chinacloudapi.cn/. The registry token is always
	// requested for https://containerregistry.azure.net/.default.
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:XValidation:rule=`self.matches(r'^https://(login\.microsoftonline\.(com|us)|login\.partner\.microsoftonline\.cn|login\.chinacloudapi\.cn)/?$')`,message="must be a known Microsoft Entra authority host"
	// +optional
	AuthorityHost string `json:"authorityHost,omitempty"`
}

// SourceCABundle holds extra root CAs for one source registry.
type SourceCABundle struct {
	// registry is the source registry that trusts the CA. The Docker Hub
	// names count as one registry.
	// +required
	Registry RegistryHost `json:"registry"`

	// secretRef is a Secret in the operator namespace with PEM
	// certificates under the key.
	// +required
	SecretRef SecretKeyRef `json:"secretRef"`
}

// OnTagMutation is the action taken when an upstream tag points to a new digest.
// +kubebuilder:validation:Enum=Fail;Overwrite;Ignore
type OnTagMutation string

const (
	// OnTagMutationFail keeps the target tag and reports the mutation.
	OnTagMutationFail OnTagMutation = "Fail"
	// OnTagMutationOverwrite re-points the target tag to the new digest.
	OnTagMutationOverwrite OnTagMutation = "Overwrite"
	// OnTagMutationIgnore keeps the target tag and does not report it.
	OnTagMutationIgnore OnTagMutation = "Ignore"
)

// TargetPolicy holds the default policy for mirrors that use this target.
type TargetPolicy struct {
	// onTagMutation is the action taken when an upstream tag points to a new digest.
	// +kubebuilder:default=Fail
	// +optional
	OnTagMutation OnTagMutation `json:"onTagMutation,omitempty"`
}

// TargetProject is a project in the target registry and the namespaces allowed to use it.
type TargetProject struct {
	// name of the project, a single path segment.
	// +required
	Name ProjectName `json:"name"`

	// namespaceSelector selects the namespaces whose ArtifactMirrors may push
	// to this project. It is required so that access is always an explicit
	// decision. An empty selector ({}) allows every namespace, which suits a
	// shared project. Team projects use a label selector.
	// +required
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector"`

	// allowRepositoryOverride lets ArtifactMirrors in this project set
	// target.repository to a path other than the default. When false, they
	// must use the default path <source-registry>/<source-repository>, so a
	// tenant cannot claim the path of another source. Enable it only for
	// projects owned by a single team.
	// +optional
	AllowRepositoryOverride bool `json:"allowRepositoryOverride,omitempty"`
}

// TargetLimits caps what the mirrors of a target may ask for. An absent
// field uses its default; the controller applies the defaults.
type TargetLimits struct {
	// minSyncInterval is the smallest allowed gap between two runs of a
	// mirror's schedule. A mirror whose schedule runs more often gets
	// Ready=False with reason ScheduleTooFrequent. Defaults to 1h. At least 5m.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('5m')",message="must be at least 5m"
	// +optional
	MinSyncInterval *metav1.Duration `json:"minSyncInterval,omitempty"`

	// maxMirrorsPerNamespace caps the ArtifactMirrors of one namespace that
	// use this target. The oldest ones win, by creation time and then name;
	// the others get Ready=False with reason LimitExceeded. Defaults to 50.
	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxMirrorsPerNamespace *int32 `json:"maxMirrorsPerNamespace,omitempty"`

	// maxKeepLatest caps tags.keepLatest of a mirror. Defaults to 20.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +optional
	MaxKeepLatest *int32 `json:"maxKeepLatest,omitempty"`

	// maxExplicitTags caps the number of tags.tags of a mirror. Defaults to 50.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +optional
	MaxExplicitTags *int32 `json:"maxExplicitTags,omitempty"`

	// maxListedTags caps the source tags a sync run lists for include,
	// semverRange or keepLatest. A larger source fails the run; selection
	// never runs on a truncated list. Defaults to 10000.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100000
	// +optional
	MaxListedTags *int32 `json:"maxListedTags,omitempty"`

	// maxArtifactSize caps the size of one artifact: config and layers of
	// the manifest, or of every manifest in an index. The referrers copied
	// for an artifact in one run, such as signatures and SBOMs, share a
	// separate budget of the same size. The sync Job reports a larger
	// artifact as failed and copies nothing of it; for oversized referrers
	// the tag fails and does not move. No limit when absent.
	// +kubebuilder:validation:XValidation:rule="quantity(string(self)).isGreaterThan(quantity('0'))",message="must be positive"
	// +optional
	MaxArtifactSize *resource.Quantity `json:"maxArtifactSize,omitempty"`
}

// Auto-mirror names. A pod annotated with AutoMirrorAnnotation: <target>
// gets its images mirrored by generated ArtifactMirrors.
const (
	AutoMirrorAnnotation = "tagwarden.dev/auto-mirror"
	// LabelGenerated is "true" on ArtifactMirrors the controller generated.
	LabelGenerated = "tagwarden.dev/generated"
	// LabelAutoTarget names the ClusterMirrorTarget of a generated mirror.
	LabelAutoTarget = "tagwarden.dev/auto-target"
)

// AutoMirror lets pods ask for their images to be mirrored with the
// tagwarden.dev/auto-mirror annotation. Generated mirrors go through the
// same checks as any ArtifactMirror: project, allowedSources and limits.
type AutoMirror struct {
	// enabled turns annotation-driven mirroring on for this target. Without
	// it the annotation only produces a Warning Event on the pod.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// project is the target project of generated mirrors. It must be listed
	// in projects and allow the namespace of the pod.
	// +required
	Project ProjectName `json:"project"`

	// schedule is the cron schedule of generated mirrors. It must respect
	// limits.minSyncInterval. New tags also trigger a sync right away.
	// +kubebuilder:default="0 */6 * * *"
	// +kubebuilder:validation:MaxLength=100
	// +kubebuilder:validation:XValidation:rule="self.matches('^(@(yearly|annually|monthly|weekly|daily|midnight|hourly)|[0-9A-Za-z*/,?-]+( +[0-9A-Za-z*/,?-]+){4})$')",message="must be a 5-field cron expression or a macro such as @daily"
	// +optional
	Schedule string `json:"schedule,omitempty"`

	// maxMirrorsPerNamespace caps the generated mirrors of one namespace for
	// this target. Defaults to 20.
	// +kubebuilder:default=20
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=200
	// +optional
	MaxMirrorsPerNamespace *int32 `json:"maxMirrorsPerNamespace,omitempty"`

	// vulnerabilityGate scans the images of generated mirrors with a Trivy
	// server and acts on known vulnerabilities. User-defined mirrors are
	// never scanned.
	// +optional
	VulnerabilityGate *VulnerabilityGate `json:"vulnerabilityGate,omitempty"`
}

// GateAction is what the vulnerability gate does with a tag it cannot pass.
// +kubebuilder:validation:Enum=Report;Block
type GateAction string

const (
	// GateActionReport copies the tag and records the findings or the scan
	// error.
	GateActionReport GateAction = "Report"
	// GateActionBlock does not copy the tag.
	GateActionBlock GateAction = "Block"
)

// SeverityThreshold is the lowest severity that counts against a tag.
// +kubebuilder:validation:Enum=Critical;High;Medium;Low
type SeverityThreshold string

// Severity thresholds.
const (
	SeverityThresholdCritical SeverityThreshold = "Critical"
	SeverityThresholdHigh     SeverityThreshold = "High"
	SeverityThresholdMedium   SeverityThreshold = "Medium"
	SeverityThresholdLow      SeverityThreshold = "Low"
)

// OnVulnerableTag is what a re-scan does with a mirrored tag that has
// findings.
// +kubebuilder:validation:Enum=Report;Untag
type OnVulnerableTag string

const (
	// OnVulnerableTagReport keeps the tag and reports it.
	OnVulnerableTagReport OnVulnerableTag = "Report"
	// OnVulnerableTagUntag deletes the target tag, not the digest.
	OnVulnerableTagUntag OnVulnerableTag = "Untag"
)

// JavaDBMode selects how the scanner gets the Trivy Java DB.
// +kubebuilder:validation:Enum=Disabled;PerJob
type JavaDBMode string

const (
	// JavaDBDisabled skips JAR, WAR, EAR and PAR files. Their findings are
	// missing, which status and audit report as javaScanned: false.
	JavaDBDisabled JavaDBMode = "Disabled"
	// JavaDBPerJob pulls the Java DB from javaDBRepository in each sync
	// Job that has something to scan.
	JavaDBPerJob JavaDBMode = "PerJob"
)

// VulnerabilityGate is the scan policy for the generated mirrors of a
// target. Generated mirrors carry no policy of their own.
// +kubebuilder:validation:XValidation:rule="!has(self.onVulnerableTag) || self.onVulnerableTag != 'Untag' || (has(self.action) && self.action == 'Block')",message="onVulnerableTag Untag needs action Block"
type VulnerabilityGate struct {
	// enabled turns the gate on. With action or onScanError Block,
	// autoMirror.project is reserved for generated mirrors: a user-defined
	// mirror there gets Ready=False with reason ProjectReservedForAutoMirror.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// action is what happens to a tag with findings: Report copies it and
	// records the findings, Block does not copy it.
	// +kubebuilder:default=Report
	// +optional
	Action GateAction `json:"action,omitempty"`

	// severity is the lowest severity that counts against a tag.
	// +kubebuilder:default=Critical
	// +optional
	Severity SeverityThreshold `json:"severity,omitempty"`

	// ignoreUnfixed does not count findings without a fixed version.
	// +optional
	IgnoreUnfixed bool `json:"ignoreUnfixed,omitempty"`

	// includeUnknown counts findings without a vendor severity as if they
	// were at the severity threshold. They are always reported.
	// +optional
	IncludeUnknown bool `json:"includeUnknown,omitempty"`

	// maxDBAge is the oldest server vulnerability DB a scan may use. An
	// older DB is a scan error. At least 1h.
	// +kubebuilder:default="72h"
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1h')",message="must be at least 1h"
	// +optional
	MaxDBAge *metav1.Duration `json:"maxDBAge,omitempty"`

	// onScanError is what happens to a tag the gate could not judge:
	// Report copies it and records the error, Block does not copy it.
	// +kubebuilder:default=Report
	// +optional
	OnScanError GateAction `json:"onScanError,omitempty"`

	// rescanInterval re-scans mirrored tags from the target registry this
	// often. No re-scan when unset. At least 1h.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1h')",message="must be at least 1h"
	// +optional
	RescanInterval *metav1.Duration `json:"rescanInterval,omitempty"`

	// onVulnerableTag is what a re-scan does with a mirrored tag that has
	// findings. Untag needs action Block.
	// +kubebuilder:default=Report
	// +optional
	OnVulnerableTag OnVulnerableTag `json:"onVulnerableTag,omitempty"`

	// maxExceptionDuration caps how far after its creation a
	// VulnerabilityException for this target may expire. Longer ones are
	// ignored. Between 1h and 2160h (90 days).
	// +kubebuilder:default="2160h"
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1h') && duration(self) <= duration('2160h')",message="must be between 1h and 2160h"
	// +optional
	MaxExceptionDuration *metav1.Duration `json:"maxExceptionDuration,omitempty"`

	// scanner configures the Trivy server and the client sidecar. All
	// fields are optional with the server the chart deploys.
	// +optional
	Scanner *ScannerSpec `json:"scanner,omitempty"`
}

// TokenSecretKeyRef names a key in a Secret in the operator namespace
// that holds a token.
type TokenSecretKeyRef struct {
	// name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`

	// key in the Secret that holds the token.
	// +kubebuilder:default="token"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Key string `json:"key,omitempty"`
}

// ScannerSpec is the Trivy server and the client image of the gate.
// +kubebuilder:validation:XValidation:rule="has(self.image) == has(self.version)",message="set image and version together"
// +kubebuilder:validation:XValidation:rule="!has(self.javaDB) || self.javaDB != 'PerJob' || has(self.javaDBRepository)",message="javaDB PerJob needs javaDBRepository"
type ScannerSpec struct {
	// url of the Trivy server. Defaults to the server the chart deploys.
	// It must be https unless the host is <service>.<namespace>.svc or
	// <service>.<namespace>.svc.cluster.local, with an optional port and
	// no path.
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:XValidation:rule="isURL(self) && (self.startsWith('https://') || self.startsWith('http://'))",message="must be an http or https URL"
	// +kubebuilder:validation:XValidation:rule="!self.contains('@') && !self.contains('?') && !self.contains('#')",message="must not contain credentials, a query or a fragment"
	// +kubebuilder:validation:XValidation:rule=`self.startsWith('https://') || self.matches(r'^http://[a-z0-9]([-a-z0-9]*[a-z0-9])?\.[a-z0-9]([-a-z0-9]*[a-z0-9])?\.svc(\.cluster\.local\.?)?(:[0-9]{1,5})?/?$')`,message="must be https unless the host is <service>.<namespace>.svc or <service>.<namespace>.svc.cluster.local"
	// +optional
	URL string `json:"url,omitempty"`

	// caBundleSecretRef holds the CA of an https server. It is mounted
	// only in the scanner sidecar and read by the controller.
	// +optional
	CABundleSecretRef *SecretKeyRef `json:"caBundleSecretRef,omitempty"`

	// tokenSecretRef holds the server token, sent in the Trivy-Token
	// header. Defaults to the token Secret the chart creates, but only
	// when url is empty: an external server without tokenSecretRef gets
	// no token. Only the scanner sidecar gets it.
	// +optional
	TokenSecretRef *TokenSecretKeyRef `json:"tokenSecretRef,omitempty"`

	// image is the Trivy client image, pinned by digest, for example
	// registry.example.internal/platform/ghcr.io/aquasecurity/trivy@sha256:<digest>.
	// Defaults to the chart's Trivy image. Set it together with version.
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:XValidation:rule=`self.matches(r'^[^@\s]+@sha256:[0-9a-f]{64}$')`,message="must be pinned by digest: <repository>@sha256:<64 hex>"
	// +optional
	Image string `json:"image,omitempty"`

	// version is the Trivy version of image, for example 0.76.1. The
	// server must have the same major and minor version.
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^[0-9]+\.[0-9]+\.[0-9]+$`
	// +optional
	Version string `json:"version,omitempty"`

	// javaDB selects how JAR files are scanned. Disabled skips them and
	// reports javaScanned: false; PerJob pulls the Java DB in each Job.
	// +kubebuilder:default=Disabled
	// +optional
	JavaDB JavaDBMode `json:"javaDB,omitempty"`

	// javaDBRepository is the Java DB in spec.registry with its tag, for
	// example registry.example.internal/platform/ghcr.io/aquasecurity/trivy-java-db:1.
	// Required with javaDB PerJob.
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:XValidation:rule=`self.matches(r'^[^/@\s]+(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)+:[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$')`,message="must be <registry>/<repository>:<tag>"
	// +optional
	JavaDBRepository string `json:"javaDBRepository,omitempty"`

	// timeout of one manifest scan. Between 1m and 1h.
	// +kubebuilder:default="10m"
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1m') && duration(self) <= duration('1h')",message="must be between 1m and 1h"
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// storage is the size limit of the emptyDir that holds the artifact
	// being scanned.
	// +kubebuilder:default="20Gi"
	// +kubebuilder:validation:XValidation:rule="quantity(string(self)).isGreaterThan(quantity('0'))",message="must be positive"
	// +optional
	Storage *resource.Quantity `json:"storage,omitempty"`

	// resources of the scanner sidecar. Defaults to requests 100m and
	// 256Mi, limits 2 CPUs and 2Gi.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}

// ClusterMirrorTargetSpec defines the target registry and what tenants may mirror into it.
// +kubebuilder:validation:XValidation:rule="!has(self.autoMirror) || self.projects.exists(p, p.name == self.autoMirror.project)",message="autoMirror.project must be listed in projects"
// +kubebuilder:validation:XValidation:rule="!has(self.autoMirror) || self.projects.all(p, p.name != self.autoMirror.project || !has(p.allowRepositoryOverride) || !p.allowRepositoryOverride)",message="autoMirror.project must not allow repository overrides, so node pulls through a path rewrite stay bound to one source"
// +kubebuilder:validation:XValidation:rule="!has(self.autoMirror) || !has(self.autoMirror.vulnerabilityGate) || !has(self.autoMirror.vulnerabilityGate.scanner) || !has(self.autoMirror.vulnerabilityGate.scanner.javaDBRepository) || self.autoMirror.vulnerabilityGate.scanner.javaDBRepository.startsWith(self.registry + '/')",message="autoMirror.vulnerabilityGate.scanner.javaDBRepository must be in spec.registry"
// +kubebuilder:validation:XValidation:rule="has(self.credentialsSecretRef) != has(self.auth)",message="set exactly one of credentialsSecretRef or auth"
// +kubebuilder:validation:XValidation:rule=`!has(self.auth) || !has(self.auth.azureWorkloadIdentity) || self.registry.lowerAscii().matches(r'^[a-z0-9]+(-[a-z0-9]+)?\.azurecr\.(io|us|cn)(:443)?$')`,message="auth.azureWorkloadIdentity needs an Azure Container Registry host (*.azurecr.io, *.azurecr.us or *.azurecr.cn)"
// +kubebuilder:validation:XValidation:rule=`!has(self.auth) || !has(self.auth.awsWorkloadIdentity) || self.registry.lowerAscii().matches(r'^[0-9]{12}\.dkr\.ecr(-fips)?\.[a-z0-9-]+\.amazonaws\.com(\.cn)?(:443)?$')`,message="auth.awsWorkloadIdentity needs an Amazon ECR private registry host (<account>.dkr.ecr.<region>.amazonaws.com)"
// +kubebuilder:validation:XValidation:rule=`!has(self.auth) || !has(self.auth.gcpWorkloadIdentity) || self.registry.lowerAscii().matches(r'^([a-z0-9]+(-[a-z0-9]+)*-docker\.pkg\.dev|((us|eu|asia)\.)?gcr\.io)(:443)?$')`,message="auth.gcpWorkloadIdentity needs a Google Artifact Registry host (<location>-docker.pkg.dev, gcr.io, us.gcr.io, eu.gcr.io or asia.gcr.io)"
type ClusterMirrorTargetSpec struct {
	// registry is the target registry as host[:port], without a scheme.
	// +required
	Registry RegistryHost `json:"registry"`

	// credentialsSecretRef holds the push credentials for the target registry
	// (a kubernetes.io/dockerconfigjson Secret in the operator namespace).
	// Set it or auth.
	// +optional
	CredentialsSecretRef *SecretRef `json:"credentialsSecretRef,omitempty"`

	// auth pushes to the target registry with a cloud workload identity
	// instead of credentialsSecretRef.
	// +optional
	Auth *RegistryAuth `json:"auth,omitempty"`

	// workloadIdentity is the cloud identity used by auth and by
	// sourceCredentials entries that name a cloud provider. Required when
	// any of them does.
	// +optional
	WorkloadIdentity *WorkloadIdentity `json:"workloadIdentity,omitempty"`

	// caBundleSecretRef holds the CA bundle for the target registry.
	// +optional
	CABundleSecretRef *SecretKeyRef `json:"caBundleSecretRef,omitempty"`

	// clientCertSecretRef holds a client certificate for mTLS to the target registry
	// (a kubernetes.io/tls Secret).
	// +optional
	ClientCertSecretRef *SecretRef `json:"clientCertSecretRef,omitempty"`

	// proxy configures the proxy for upstream traffic.
	// +optional
	Proxy *ProxySpec `json:"proxy,omitempty"`

	// sourceCredentials lists pull credentials per source registry. A sync
	// Job gets only the entry for its own source; a source without an entry
	// is pulled anonymously. Tenants never see or reference these Secrets:
	// the platform team decides which sources have accounts. At most one
	// entry per registry; the controller rejects duplicates, Docker Hub
	// names included.
	// +kubebuilder:validation:MaxItems=50
	// +listType=map
	// +listMapKey=registry
	// +optional
	SourceCredentials []SourceCredential `json:"sourceCredentials,omitempty"`

	// sourceCABundles lists extra root CAs per source registry, for
	// upstreams signed by a private CA. Each CA is mounted only in sync
	// pods of that source and trusted there for every host the source
	// transport reaches (the registry, its redirect and token hosts), never
	// for the target. It adds to the system roots. Tenants never see or
	// reference these Secrets: the platform team decides which sources
	// have private CAs. At most one entry per registry.
	// +kubebuilder:validation:MaxItems=50
	// +listType=map
	// +listMapKey=registry
	// +optional
	SourceCABundles []SourceCABundle `json:"sourceCABundles,omitempty"`

	// allowedSources lists the upstream registry hosts that mirrors may pull from.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +listType=set
	// +required
	AllowedSources []RegistryHost `json:"allowedSources"`

	// projects lists the target registry projects that mirrors may push to,
	// and which namespaces may use each one. A mirror may push only to a
	// listed project whose namespaceSelector matches the mirror's namespace.
	// The controller enforces this at reconcile.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +listType=map
	// +listMapKey=name
	// +required
	Projects []TargetProject `json:"projects"`

	// policy holds the default policy for mirrors that use this target.
	// +kubebuilder:default={}
	// +optional
	Policy TargetPolicy `json:"policy,omitzero"`

	// limits caps schedules, mirrors, tags and artifact sizes per tenant.
	// Defaults apply when it is absent.
	// +optional
	Limits *TargetLimits `json:"limits,omitempty"`

	// autoMirror lets annotated pods request mirrors of their images.
	// +optional
	AutoMirror *AutoMirror `json:"autoMirror,omitempty"`
}

// ClusterMirrorTargetStatus defines the observed state of ClusterMirrorTarget.
type ClusterMirrorTargetStatus struct {
	// conditions represent the current state. The Ready condition reports
	// whether the resource is usable.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Registry",type=string,JSONPath=`.spec.registry`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClusterMirrorTarget is a target registry owned by the platform team.
type ClusterMirrorTarget struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ClusterMirrorTarget
	// +required
	Spec ClusterMirrorTargetSpec `json:"spec"`

	// status defines the observed state of ClusterMirrorTarget
	// +optional
	Status ClusterMirrorTargetStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ClusterMirrorTargetList contains a list of ClusterMirrorTarget
type ClusterMirrorTargetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ClusterMirrorTarget `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ClusterMirrorTarget{}, &ClusterMirrorTargetList{})
		return nil
	})
}
