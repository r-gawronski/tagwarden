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
	// Defaults to <source registry>/<source repository>.
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

// ArtifactMirrorStatus defines the observed state of ArtifactMirror.
type ArtifactMirrorStatus struct {
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
