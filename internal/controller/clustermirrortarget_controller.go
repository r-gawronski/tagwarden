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
	"strings"

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

// check returns a reason and message for the first invalid Secret, or an
// empty reason. Messages name Secrets and keys, never their content.
func (r *ClusterMirrorTargetReconciler) check(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget) (string, string, error) {
	s, reason, msg, err := r.secret(ctx, t.Spec.CredentialsSecretRef.Name)
	if s == nil {
		return reason, msg, err
	}
	if s.Type != corev1.SecretTypeDockerConfigJson {
		return ReasonInvalidSecret, fmt.Sprintf("Secret %s is of type %s, want %s", s.Name, s.Type, corev1.SecretTypeDockerConfigJson), nil
	}
	if !hasAuth(s.Data[corev1.DockerConfigJsonKey], string(t.Spec.Registry)) {
		return ReasonInvalidSecret, fmt.Sprintf("Secret %s has no auths entry for %s", s.Name, t.Spec.Registry), nil
	}
	cas := []*mirrorv1alpha1.SecretKeyRef{t.Spec.CABundleSecretRef}
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
		if strings.EqualFold(syncspec.AuthKeyHost(k), host) {
			return true
		}
	}
	return false
}

// referencesSecret reports whether t references the named Secret.
func referencesSecret(t *mirrorv1alpha1.ClusterMirrorTarget, name string) bool {
	names := []string{t.Spec.CredentialsSecretRef.Name}
	if r := t.Spec.CABundleSecretRef; r != nil {
		names = append(names, r.Name)
	}
	if r := t.Spec.ClientCertSecretRef; r != nil {
		names = append(names, r.Name)
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
