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
}

// ClusterMirrorTargetSpec defines the target registry and what tenants may mirror into it.
type ClusterMirrorTargetSpec struct {
	// registry is the target registry as host[:port], without a scheme.
	// +required
	Registry RegistryHost `json:"registry"`

	// credentialsSecretRef holds the push credentials for the target registry
	// (a kubernetes.io/dockerconfigjson Secret in the operator namespace).
	// +required
	CredentialsSecretRef SecretRef `json:"credentialsSecretRef"`

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
