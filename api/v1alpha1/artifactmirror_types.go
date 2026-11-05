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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ArtifactType is the kind of artifact to mirror.
// +kubebuilder:validation:Enum=Image;HelmOCI;HelmRepo
type ArtifactType string

const (
	// ArtifactTypeImage is a container image.
	ArtifactTypeImage ArtifactType = "Image"
	// ArtifactTypeHelmOCI is a Helm chart stored in an OCI registry.
	ArtifactTypeHelmOCI ArtifactType = "HelmOCI"
	// ArtifactTypeHelmRepo is a Helm chart in a classic Helm repository.
	ArtifactTypeHelmRepo ArtifactType = "HelmRepo"
)

// Source is the upstream artifact. Phase 2 extends it with the fields
// a classic Helm repository needs.
type Source struct {
	// registry is the upstream registry as host[:port], without a scheme.
	// It must be listed in the target's allowedSources.
	// +required
	Registry RegistryHost `json:"registry"`

	// repository is the path in the upstream registry, for example library/nginx.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$`
	// +required
	Repository string `json:"repository"`
}

// Target is where the artifact lands in the target registry.
type Target struct {
	// project is the top-level project in the target registry. It must be
	// listed in the target's projects with a namespaceSelector that matches
	// this mirror's namespace.
	// +required
	Project ProjectName `json:"project"`

	// repository overrides the path inside the project.
	// Defaults to <source registry>/<source repository>. A different path
	// requires allowRepositoryOverride: true on the project in the
	// ClusterMirrorTarget; otherwise the mirror is refused.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$`
	// +optional
	Repository string `json:"repository,omitempty"`
}

// TagSelector selects the upstream tags to mirror. At least one of include,
// semverRange, keepLatest or tags must be set, so that a mirror never copies
// every tag by accident.
// +kubebuilder:validation:XValidation:rule="has(self.include) || has(self.semverRange) || has(self.keepLatest) || has(self.tags)",message="set at least one of include, semverRange, keepLatest or tags"
type TagSelector struct {
	// include keeps a tag if any pattern matches. Patterns are Go RE2
	// regular expressions and are not anchored: use ^...$ for a full match.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=20
	// +kubebuilder:validation:items:MaxLength=256
	// +listType=set
	// +optional
	Include []string `json:"include,omitempty"`

	// exclude drops a tag if any pattern matches.
	// +kubebuilder:validation:MaxItems=20
	// +kubebuilder:validation:items:MaxLength=256
	// +listType=set
	// +optional
	Exclude []string `json:"exclude,omitempty"`

	// semverRange keeps semver tags within the constraint, for example ">=1.10.0 <2.0.0".
	// Tags that are not semver are dropped.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +optional
	SemverRange string `json:"semverRange,omitempty"`

	// keepLatest keeps only the N highest semver tags after filtering.
	// Tags that are not semver are dropped.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +optional
	KeepLatest *int32 `json:"keepLatest,omitempty"`

	// allowPrerelease keeps prerelease versions when semverRange or
	// keepLatest is set. They are dropped by default. A semverRange that
	// names a prerelease, such as ">=1.11.0-0", still needs
	// allowPrerelease: true to select prereleases.
	// +optional
	AllowPrerelease bool `json:"allowPrerelease,omitempty"`

	// tags lists exact tags to mirror in addition to the selected ones.
	// They bypass all filters. When include, semverRange and keepLatest are
	// unset, only these tags are mirrored.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +kubebuilder:validation:items:Pattern=`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`
	// +listType=set
	// +optional
	Tags []string `json:"tags,omitempty"`

	// prune deletes the tags this mirror created on the target (status.owned)
	// once the selection no longer includes them. Only the tag goes, never
	// the digest. Tags another mirror of the same target repository selects
	// stay, and so do tags the mirror did not create. Off by default.
	// +optional
	Prune bool `json:"prune,omitempty"`
}

// ArtifactMirrorSpec defines what to mirror, where and when.
type ArtifactMirrorSpec struct {
	// targetRef is the name of the ClusterMirrorTarget to mirror into.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	TargetRef string `json:"targetRef"`

	// schedule is a cron expression with 5 fields, or one of @yearly,
	// @annually, @monthly, @weekly, @daily, @midnight, @hourly.
	// Time zone prefixes and @every are not supported.
	// +kubebuilder:validation:MaxLength=100
	// +kubebuilder:validation:XValidation:rule="self.matches('^(@(yearly|annually|monthly|weekly|daily|midnight|hourly)|[0-9A-Za-z*/,?-]+( +[0-9A-Za-z*/,?-]+){4})$')",message="must be a 5-field cron expression or a macro such as @daily"
	// +required
	Schedule string `json:"schedule"`

	// type is the kind of artifact to mirror.
	// +kubebuilder:default=Image
	// +optional
	Type ArtifactType `json:"type,omitempty"`

	// source is the upstream artifact.
	// +required
	Source Source `json:"source"`

	// target is where the artifact lands in the target registry.
	// +required
	Target Target `json:"target"`

	// tags selects the upstream tags to mirror.
	// +required
	Tags TagSelector `json:"tags"`

	// requiredPlatforms lists platforms, as os/arch[/variant], that must
	// exist in the source. A tag missing any of them fails and is not
	// mirrored. The whole index is always mirrored so digests and
	// signatures stay valid.
	// +kubebuilder:validation:MaxItems=20
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`
	// +listType=set
	// +optional
	RequiredPlatforms []string `json:"requiredPlatforms,omitempty"`

	// suspend stops scheduling new syncs.
	// +optional
	Suspend bool `json:"suspend,omitempty"`
}

// SyncedTag records a mirrored tag and its digest.
type SyncedTag struct {
	// tag is the mirrored tag.
	Tag string `json:"tag"`
	// digest is the manifest digest the tag was copied by.
	Digest string `json:"digest"`
}

// SyncNowAnnotation requests a sync outside the schedule. Each new value
// is one request; the controller reports it in status.lastSyncRequest.
const SyncNowAnnotation = "tagwarden.dev/sync-now"

// SyncRequestResult is how the controller handled a sync request.
// +kubebuilder:validation:Enum=Started;Deferred;Refused
type SyncRequestResult string

const (
	// SyncRequestStarted means a sync Job was created for the request.
	SyncRequestStarted SyncRequestResult = "Started"
	// SyncRequestDeferred means the request waits for a running Job or
	// for limits.minSyncInterval of the target.
	SyncRequestDeferred SyncRequestResult = "Deferred"
	// SyncRequestRefused means the request was dropped, for example
	// because the mirror is not Ready or is suspended.
	SyncRequestRefused SyncRequestResult = "Refused"
)

// SyncRequest records the last handled tagwarden.dev/sync-now request.
type SyncRequest struct {
	// value of the annotation, cut to 256 bytes.
	// +kubebuilder:validation:MaxLength=256
	// +required
	Value string `json:"value"`

	// handledAt is when the controller last changed the result.
	// +required
	HandledAt metav1.Time `json:"handledAt"`

	// result is Started, Deferred or Refused.
	// +required
	Result SyncRequestResult `json:"result"`

	// message describes the result, such as the Job created or why the
	// request waits or was refused.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Message string `json:"message,omitempty"`
}

// Severity is the severity of a vulnerability finding.
// +kubebuilder:validation:Enum=Critical;High;Medium;Low;Unknown
type Severity string

// Severities.
const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityUnknown  Severity = "Unknown"
)

// FindingVerdict is the gate verdict of a tag listed in status.findings.
// +kubebuilder:validation:Enum=Findings;ScanError
type FindingVerdict string

const (
	// VerdictFindings means at least one finding at or above the severity
	// threshold that no exception covers.
	VerdictFindings FindingVerdict = "Findings"
	// VerdictScanError means the gate could not judge the tag.
	VerdictScanError FindingVerdict = "ScanError"
)

// FindingOutcome is what the gate did with a tag.
// +kubebuilder:validation:Enum=Copied;Blocked
type FindingOutcome string

const (
	// OutcomeCopied means the tag was copied to the target.
	OutcomeCopied FindingOutcome = "Copied"
	// OutcomeBlocked means the tag was not copied.
	OutcomeBlocked FindingOutcome = "Blocked"
)

// SeverityCounts counts findings per severity.
type SeverityCounts struct {
	// +kubebuilder:validation:Minimum=0
	// +optional
	Critical int32 `json:"critical,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +optional
	High int32 `json:"high,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +optional
	Medium int32 `json:"medium,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +optional
	Low int32 `json:"low,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +optional
	Unknown int32 `json:"unknown,omitempty"`
}

// VulnerabilityFinding is the gate result of one tag with findings or a
// scan error. Full detail is in the audit log.
type VulnerabilityFinding struct {
	// tag is the upstream tag.
	// +kubebuilder:validation:MaxLength=128
	// +required
	Tag string `json:"tag"`

	// digest is the index or manifest digest the tag resolved to.
	// +kubebuilder:validation:MaxLength=71
	// +required
	Digest string `json:"digest"`

	// verdict is Findings or ScanError.
	// +required
	Verdict FindingVerdict `json:"verdict"`

	// outcome is Copied or Blocked.
	// +required
	Outcome FindingOutcome `json:"outcome"`

	// presentOnTarget is true when the tag was already on the target, for
	// example copied by a generated mirror of another namespace.
	// +optional
	PresentOnTarget bool `json:"presentOnTarget,omitempty"`

	// severity is the highest severity among the findings.
	// +optional
	Severity Severity `json:"severity,omitempty"`

	// counts are the findings per severity.
	// +optional
	Counts SeverityCounts `json:"counts,omitzero"`

	// topIDs are up to five vulnerability IDs, highest severity first.
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:items:Pattern=`^[A-Z]+-[0-9A-Za-z-]{1,64}$`
	// +listType=atomic
	// +optional
	TopIDs []string `json:"topIDs,omitempty"`

	// scanError is the reason the tag could not be judged: DBStale,
	// ScannerUnavailable, VersionMismatch or ScanFailed.
	// +kubebuilder:validation:Enum=DBStale;ScannerUnavailable;VersionMismatch;ScanFailed
	// +optional
	ScanError string `json:"scanError,omitempty"`

	// javaScanned is false when JAR files were not scanned.
	// +required
	JavaScanned bool `json:"javaScanned"`

	// scannedAt is when the tag was scanned.
	// +required
	ScannedAt metav1.Time `json:"scannedAt"`
}

// VulnerableTagAction is what a re-scan did with a mirrored tag that has
// findings.
// +kubebuilder:validation:Enum=Kept;Untagged;UntagFailed;UntagRefused
type VulnerableTagAction string

const (
	// VulnerableKept means the tag stays on the target (onVulnerableTag
	// Report).
	VulnerableKept VulnerableTagAction = "Kept"
	// VulnerableUntagged means the target tag was deleted; the digest stays.
	VulnerableUntagged VulnerableTagAction = "Untagged"
	// VulnerableUntagFailed means the registry refused the tag delete; the
	// tag stays, as under Report.
	VulnerableUntagFailed VulnerableTagAction = "UntagFailed"
	// VulnerableUntagRefused means the deletion rules kept the tag: this
	// mirror has not recorded it, or another mirror selects it.
	VulnerableUntagRefused VulnerableTagAction = "UntagRefused"
)

// VulnerableTag is a tag on the target that a re-scan found vulnerable.
type VulnerableTag struct {
	// tag is the target tag.
	// +kubebuilder:validation:MaxLength=128
	// +required
	Tag string `json:"tag"`

	// digest is the index or manifest digest the target tag pointed to.
	// +kubebuilder:validation:MaxLength=71
	// +required
	Digest string `json:"digest"`

	// severity is the highest severity among the findings.
	// +optional
	Severity Severity `json:"severity,omitempty"`

	// counts are the findings per severity.
	// +optional
	Counts SeverityCounts `json:"counts,omitzero"`

	// topIDs are up to five vulnerability IDs, highest severity first.
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:items:Pattern=`^[A-Z]+-[0-9A-Za-z-]{1,64}$`
	// +listType=atomic
	// +optional
	TopIDs []string `json:"topIDs,omitempty"`

	// action is what the re-scan did with the tag.
	// +required
	Action VulnerableTagAction `json:"action"`

	// scannedAt is when the tag was scanned.
	// +required
	ScannedAt metav1.Time `json:"scannedAt"`
}

// JudgedTag is a tag and digest with a final gate verdict.
type JudgedTag struct {
	// tag is the target tag.
	// +kubebuilder:validation:MaxLength=128
	// +required
	Tag string `json:"tag"`

	// digest is the index or manifest digest that was judged.
	// +kubebuilder:validation:MaxLength=71
	// +required
	Digest string `json:"digest"`

	// judgedAt is the start of the Job that judged the pair, set by the
	// controller. With rescanInterval set, a pair older than the interval,
	// or without judgedAt, is judged again.
	// +optional
	JudgedAt *metav1.Time `json:"judgedAt,omitempty"`
}

// GateStatus holds the judged verdicts of a generated mirror of a gated
// target. The controller passes them back to the sync Job, which skips the
// scan of a judged tag and digest while the fingerprint still matches.
type GateStatus struct {
	// judgedFingerprint is the policy fingerprint the judged list was made
	// under: the gate policy, the active exceptions and the scanner
	// major.minor. A Job under another fingerprint judges every tag again.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	// +optional
	JudgedFingerprint string `json:"judgedFingerprint,omitempty"`

	// judged lists the tags and digests a gated run gave a final verdict
	// (passed, accepted or findings), never scan errors. At most 200; tags
	// that do not fit are scanned again.
	// +kubebuilder:validation:MaxItems=200
	// +listType=atomic
	// +optional
	Judged []JudgedTag `json:"judged,omitempty"`
}

// ArtifactMirrorStatus defines the observed state of ArtifactMirror.
type ArtifactMirrorStatus struct {
	// lastSyncStartTime is when the last sync Job started, scheduled or
	// requested. Requests wait until limits.minSyncInterval of the target
	// has passed since then.
	// +optional
	LastSyncStartTime *metav1.Time `json:"lastSyncStartTime,omitempty"`

	// lastSyncRequest is the last tagwarden.dev/sync-now request the
	// controller handled.
	// +optional
	LastSyncRequest *SyncRequest `json:"lastSyncRequest,omitempty"`

	// lastSyncTime is when the last sync finished.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// lastSuccessfulSyncTime is when the last successful sync finished.
	// +optional
	LastSuccessfulSyncTime *metav1.Time `json:"lastSuccessfulSyncTime,omitempty"`

	// synced lists the mirrored tags and their digests, newest first. The
	// controller keeps at most 200 entries and sets the Synced condition
	// reason Truncated when the list is cut.
	// +kubebuilder:validation:MaxItems=200
	// +listType=atomic
	// +optional
	Synced []SyncedTag `json:"synced,omitempty"`

	// owned lists the tags this mirror put on the target and the digest
	// each had when it did. Prune deletes only these. It is kept with
	// spec.tags.prune off, so turning prune on later covers the tags the
	// mirror created meanwhile. The controller keeps at most 200 entries;
	// when it is cut, the oldest versions are no longer recorded and are
	// never pruned.
	// +kubebuilder:validation:MaxItems=200
	// +listType=atomic
	// +optional
	Owned []SyncedTag `json:"owned,omitempty"`

	// findings lists the tags of a generated mirror that the vulnerability
	// gate found vulnerable or could not judge, at most 20.
	// +kubebuilder:validation:MaxItems=20
	// +listType=atomic
	// +optional
	Findings []VulnerabilityFinding `json:"findings,omitempty"`

	// javaScanned is false on generated mirrors of a gated target while
	// scanner.javaDB is Disabled, so the JAR files that are not scanned
	// stay visible. Absent on mirrors that are not gated.
	// +optional
	JavaScanned *bool `json:"javaScanned,omitempty"`

	// gate holds the judged verdicts of a generated mirror of a gated
	// target. Absent on mirrors that are not gated.
	// +optional
	Gate *GateStatus `json:"gate,omitempty"`

	// vulnerable lists the tags on the target that the last re-scan found
	// vulnerable, most severe first, at most 20. A later sync that judges
	// a tag again replaces its entry with one in findings.
	// +kubebuilder:validation:MaxItems=20
	// +listType=atomic
	// +optional
	Vulnerable []VulnerableTag `json:"vulnerable,omitempty"`

	// lastRescan is when the controller last started a re-scan Job.
	// +optional
	LastRescan *metav1.Time `json:"lastRescan,omitempty"`

	// observedGeneration is the spec generation the status refers to.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state. The Ready condition reports
	// whether the resource is usable.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.spec.source.repository`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Suspend",type=boolean,JSONPath=`.spec.suspend`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ArtifactMirror is a tenant request to mirror an artifact into a ClusterMirrorTarget.
type ArtifactMirror struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ArtifactMirror
	// +required
	Spec ArtifactMirrorSpec `json:"spec"`

	// status defines the observed state of ArtifactMirror
	// +optional
	Status ArtifactMirrorStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ArtifactMirrorList contains a list of ArtifactMirror
type ArtifactMirrorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ArtifactMirror `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ArtifactMirror{}, &ArtifactMirrorList{})
		return nil
	})
}
