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

package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// ClusterMirrorTargetReconciler checks that the Secrets a ClusterMirrorTarget
// references exist and have the expected shape, and reports it in the Ready
// condition. Secret contents never leave this check.
type ClusterMirrorTargetReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
	// Namespace is the operator namespace that holds the referenced Secrets.
	Namespace string
}

// +kubebuilder:rbac:groups=mirror.tagwarden.dev,resources=clustermirrortargets,verbs=get;list;watch
// +kubebuilder:rbac:groups=mirror.tagwarden.dev,resources=clustermirrortargets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",namespace=system,resources=secrets,verbs=get;list;watch

// Reconcile sets the Ready condition of a ClusterMirrorTarget.
func (r *ClusterMirrorTargetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var t mirrorv1alpha1.ClusterMirrorTarget
	if err := r.Get(ctx, req.NamespacedName, &t); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	cond := metav1.Condition{
		Type: ConditionReady, Status: metav1.ConditionTrue, Reason: ReasonReady,
		Message: "all referenced Secrets are valid", ObservedGeneration: t.Generation,
	}
	reason, msg := ambiguousSources(&t)
	if reason == "" {
		reason, msg = duplicateSourceRegistries(&t)
	}
	if reason == "" {
		reason, msg = missingIdentity(&t)
	}
	if reason == "" {
		var err error
		if reason, msg, err = r.check(ctx, &t); err != nil {
			return ctrl.Result{}, err
		}
	}
	if reason != "" {
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, reason, msg
	}
	old := meta.FindStatusCondition(t.Status.Conditions, ConditionReady)
	newReason := reason != "" && (old == nil || old.Reason != reason)
	if !meta.SetStatusCondition(&t.Status.Conditions, cond) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Update(ctx, &t); err != nil {
		return ctrl.Result{}, err
	}
	if newReason {
		r.Recorder.Eventf(&t, nil, corev1.EventTypeWarning, reason, "Reconcile", "%s", msg)
	}
	return ctrl.Result{}, nil
}

// ambiguousSources refuses allowedSources of different registries that
// map to the same segment of the default target path, such as
// reg.example.internal:5000 and reg.example.internal-5000. Default paths
// stay unique per source only without such pairs (threat model T23).
func ambiguousSources(t *mirrorv1alpha1.ClusterMirrorTarget) (string, string) {
	seen := map[string]mirrorv1alpha1.RegistryHost{}
	for _, a := range t.Spec.AllowedSources {
		seg := registrySegment(a)
		if b, ok := seen[seg]; ok && syncspec.CanonicalRegistry(string(a)) != syncspec.CanonicalRegistry(string(b)) {
			return ReasonAmbiguousAllowedSources, fmt.Sprintf("allowedSources %s and %s both map to target path %s", b, a, seg)
		}
		seen[seg] = a
	}
	return "", ""
}

// duplicateSourceRegistries refuses two sourceCredentials or two
// sourceCABundles entries for one registry. The CRD keys the lists by the
// literal host, so the controller compares the canonical form (case, Docker
// Hub names).
func duplicateSourceRegistries(t *mirrorv1alpha1.ClusterMirrorTarget) (string, string) {
	dup := func(field string, hosts []mirrorv1alpha1.RegistryHost) (string, string) {
		seen := map[string]mirrorv1alpha1.RegistryHost{}
		for _, h := range hosts {
			c := syncspec.CanonicalRegistry(string(h))
			if prev, ok := seen[c]; ok {
				return ReasonInvalidSpec, fmt.Sprintf("%s has two entries for registry %s: %s and %s", field, c, prev, h)
			}
			seen[c] = h
		}
		return "", ""
	}
	creds := make([]mirrorv1alpha1.RegistryHost, 0, len(t.Spec.SourceCredentials))
	cas := make([]mirrorv1alpha1.RegistryHost, 0, len(t.Spec.SourceCABundles))
	for _, c := range t.Spec.SourceCredentials {
		creds = append(creds, c.Registry)
	}
	for _, c := range t.Spec.SourceCABundles {
		cas = append(cas, c.Registry)
	}
	if reason, msg := dup("sourceCredentials", creds); reason != "" {
		return reason, msg
	}
	return dup("sourceCABundles", cas)
}

// missingIdentity refuses cloud workload identity auth without the
// matching identity in spec.workloadIdentity.
func missingIdentity(t *mirrorv1alpha1.ClusterMirrorTarget) (string, string) {
	wi := t.Spec.WorkloadIdentity
	if usesAuth(t, syncspec.AuthAzureWorkloadIdentity) && (wi == nil || wi.Azure == nil) {
		return ReasonInvalidSpec, "azureWorkloadIdentity requires spec.workloadIdentity.azure"
	}
	if usesAuth(t, syncspec.AuthAWSWorkloadIdentity) && (wi == nil || wi.AWS == nil) {
		return ReasonInvalidSpec, "awsWorkloadIdentity requires spec.workloadIdentity.aws"
	}
	if usesAuth(t, syncspec.AuthGCPWorkloadIdentity) && (wi == nil || wi.GCP == nil) {
		return ReasonInvalidSpec, "gcpWorkloadIdentity requires spec.workloadIdentity.gcp"
	}
	return "", ""
}

// usesAuth reports whether the target push or any source entry uses the
// cloud provider.
func usesAuth(t *mirrorv1alpha1.ClusterMirrorTarget, provider string) bool {
	return targetAuth(t) == provider || slices.ContainsFunc(t.Spec.SourceCredentials,
		func(c mirrorv1alpha1.SourceCredential) bool { return sourceAuth(&c) == provider })
}

// sourceRefs returns the credentials and CA entries for a source
// registry, or nil. The first entry wins; duplicates make the target not Ready.
func sourceRefs(t *mirrorv1alpha1.ClusterMirrorTarget, registry string) (cred *mirrorv1alpha1.SourceCredential, ca *mirrorv1alpha1.SecretKeyRef) {
	c := syncspec.CanonicalRegistry(registry)
	for i := range t.Spec.SourceCredentials {
		if e := &t.Spec.SourceCredentials[i]; cred == nil && syncspec.CanonicalRegistry(string(e.Registry)) == c {
			cred = e
		}
	}
	for i := range t.Spec.SourceCABundles {
		if e := &t.Spec.SourceCABundles[i]; ca == nil && syncspec.CanonicalRegistry(string(e.Registry)) == c {
			ca = &e.SecretRef
		}
	}
	return cred, ca
}

// check returns a reason and message for the first invalid Secret, or an
// empty reason. Messages name Secrets and keys, never their content.
func (r *ClusterMirrorTargetReconciler) check(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget) (string, string, error) {
	type dockerRef struct {
		secret   string
		registry mirrorv1alpha1.RegistryHost
	}
	var docker []dockerRef
	if ref := t.Spec.CredentialsSecretRef; ref != nil {
		docker = append(docker, dockerRef{ref.Name, t.Spec.Registry})
	}
	for _, c := range t.Spec.SourceCredentials {
		if c.SecretRef != nil {
			docker = append(docker, dockerRef{c.SecretRef.Name, c.Registry})
		}
	}
	var (
		s           *corev1.Secret
		reason, msg string
		err         error
	)
	for _, d := range docker {
		if s, reason, msg, err = r.secret(ctx, d.secret); s == nil {
			return reason, msg, err
		}
		if s.Type != corev1.SecretTypeDockerConfigJson {
			return ReasonInvalidSecret, fmt.Sprintf("Secret %s is of type %s, want %s", s.Name, s.Type, corev1.SecretTypeDockerConfigJson), nil
		}
		if !hasAuth(s.Data[corev1.DockerConfigJsonKey], string(d.registry)) {
			return ReasonInvalidSecret, fmt.Sprintf("Secret %s has no auths entry for %s", s.Name, d.registry), nil
		}
	}
	cas := []*mirrorv1alpha1.SecretKeyRef{t.Spec.CABundleSecretRef}
	for i := range t.Spec.SourceCABundles {
		cas = append(cas, &t.Spec.SourceCABundles[i].SecretRef)
	}
	if p := t.Spec.Proxy; p != nil {
		cas = append(cas, p.CABundleSecretRef)
	}
	for _, ref := range cas {
		if ref == nil {
			continue
		}
		if s, reason, msg, err = r.secret(ctx, ref.Name); s == nil {
			return reason, msg, err
		}
		if !x509.NewCertPool().AppendCertsFromPEM(s.Data[ref.Key]) {
			return ReasonInvalidSecret, fmt.Sprintf("Secret %s key %s holds no PEM certificate", s.Name, ref.Key), nil
		}
	}
	if ref := t.Spec.ClientCertSecretRef; ref != nil {
		if s, reason, msg, err = r.secret(ctx, ref.Name); s == nil {
			return reason, msg, err
		}
		if s.Type != corev1.SecretTypeTLS {
			return ReasonInvalidSecret, fmt.Sprintf("Secret %s is of type %s, want %s", s.Name, s.Type, corev1.SecretTypeTLS), nil
		}
	}
	if p := t.Spec.Proxy; p != nil && p.CredentialsSecretRef != nil {
		if s, reason, msg, err = r.secret(ctx, p.CredentialsSecretRef.Name); s == nil {
			return reason, msg, err
		}
		for _, k := range []string{corev1.BasicAuthUsernameKey, corev1.BasicAuthPasswordKey} {
			if len(s.Data[k]) == 0 {
				return ReasonInvalidSecret, fmt.Sprintf("Secret %s has no key %s", s.Name, k), nil
			}
		}
	}
	return "", "", nil
}

// secret returns the named Secret in the operator namespace, or nil with a
// reason when it does not exist.
func (r *ClusterMirrorTargetReconciler) secret(ctx context.Context, name string) (*corev1.Secret, string, string, error) {
	var s corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: name}, &s)
	switch {
	case apierrors.IsNotFound(err):
		return nil, ReasonSecretNotFound, fmt.Sprintf("Secret %s not found in namespace %s", name, r.Namespace), nil
	case err != nil:
		return nil, "", "", err
	}
	return &s, "", "", nil
}

// hasAuth reports whether a dockerconfigjson has an auths entry for host.
// It matches keys the way the sync Job does and reads nothing but the keys.
func hasAuth(data []byte, host string) bool {
	var cfg struct {
		Auths map[string]json.RawMessage `json:"auths"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return false
	}
	for k := range cfg.Auths {
		if syncspec.CanonicalRegistry(syncspec.AuthKeyHost(k)) == syncspec.CanonicalRegistry(host) {
			return true
		}
	}
	return false
}

// referencesSecret reports whether t references the named Secret.
func referencesSecret(t *mirrorv1alpha1.ClusterMirrorTarget, name string) bool {
	var names []string
	if r := t.Spec.CredentialsSecretRef; r != nil {
		names = append(names, r.Name)
	}
	if r := t.Spec.CABundleSecretRef; r != nil {
		names = append(names, r.Name)
	}
	if r := t.Spec.ClientCertSecretRef; r != nil {
		names = append(names, r.Name)
	}
	for _, c := range t.Spec.SourceCredentials {
		if c.SecretRef != nil {
			names = append(names, c.SecretRef.Name)
		}
	}
	for _, c := range t.Spec.SourceCABundles {
		names = append(names, c.SecretRef.Name)
	}
	if p := t.Spec.Proxy; p != nil {
		if p.CABundleSecretRef != nil {
			names = append(names, p.CABundleSecretRef.Name)
		}
		if p.CredentialsSecretRef != nil {
			names = append(names, p.CredentialsSecretRef.Name)
		}
	}
	return slices.Contains(names, name)
}

// targetsForSecret maps a Secret in the operator namespace to the targets
// that reference it.
func (r *ClusterMirrorTargetReconciler) targetsForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	if obj.GetNamespace() != r.Namespace {
		return nil
	}
	var list mirrorv1alpha1.ClusterMirrorTargetList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		if referencesSecret(&list.Items[i], obj.GetName()) {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: list.Items[i].Name}})
		}
	}
	return reqs
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterMirrorTargetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mirrorv1alpha1.ClusterMirrorTarget{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.targetsForSecret)).
		Named("clustermirrortarget").
		Complete(r)
}
