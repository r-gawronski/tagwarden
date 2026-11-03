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
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
	"github.com/r-gawronski/tagwarden/internal/tags"
)

const (
	// Finalizer removes the CronJob and ConfigMap of a deleted mirror. They
	// live in the operator namespace, so ownerReferences cannot do it.
	Finalizer = "tagwarden.dev/cleanup"

	indexTargetName = "spec.targetRef"
	indexTargetKey  = ".tagwarden.targetKey"

	// conflictRetry rechecks a mirror that lost a target repository.
	conflictRetry = time.Minute
)

// ArtifactMirrorReconciler renders each ArtifactMirror into a CronJob and a
// spec ConfigMap in the operator namespace, after checking it against its
// ClusterMirrorTarget, and reports sync results from finished Jobs.
type ArtifactMirrorReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
	// Namespace is the operator namespace for CronJobs, Jobs and ConfigMaps.
	Namespace string
	// SyncImage runs the sync Jobs.
	SyncImage string
	// DeniedCIDRs are the cluster pod and service CIDRs, refused as sources.
	DeniedCIDRs []string
}

// +kubebuilder:rbac:groups=mirror.tagwarden.dev,resources=artifactmirrors,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=mirror.tagwarden.dev,resources=artifactmirrors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mirror.tagwarden.dev,resources=artifactmirrors/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=batch,namespace=system,resources=cronjobs,verbs=get;list;watch;create;update;patch;delete;deletecollection
// +kubebuilder:rbac:groups="",namespace=system,resources=configmaps,verbs=get;list;watch;create;update;patch;delete;deletecollection

// Reconcile checks a mirror and renders its CronJob.
func (r *ArtifactMirrorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var m mirrorv1alpha1.ArtifactMirror
	if err := r.Get(ctx, req.NamespacedName, &m); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !m.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&m, Finalizer) {
			return ctrl.Result{}, nil
		}
		if err := r.cleanup(ctx, &m); err != nil {
			return ctrl.Result{}, err
		}
		controllerutil.RemoveFinalizer(&m, Finalizer)
		return ctrl.Result{}, r.Update(ctx, &m)
	}
	if controllerutil.AddFinalizer(&m, Finalizer) {
		if err := r.Update(ctx, &m); err != nil {
			return ctrl.Result{}, err
		}
	}

	old := m.Status.DeepCopy()
	oldReady := meta.FindStatusCondition(old.Conditions, ConditionReady)
	res, err := r.reconcile(ctx, &m)
	if err != nil {
		return ctrl.Result{}, err
	}
	m.Status.ObservedGeneration = m.Generation
	if ready := meta.FindStatusCondition(m.Status.Conditions, ConditionReady); ready != nil &&
		ready.Status == metav1.ConditionFalse && (oldReady == nil || oldReady.Reason != ready.Reason) {
		r.Recorder.Eventf(&m, nil, corev1.EventTypeWarning, ready.Reason, "Reconcile", "%s", ready.Message)
	}
	if !equality.Semantic.DeepEqual(old, &m.Status) {
		if err := r.Status().Update(ctx, &m); err != nil {
			return ctrl.Result{}, err
		}
	}
	return res, nil
}

// reconcile sets the Ready condition and renders or removes the CronJob.
func (r *ArtifactMirrorReconciler) reconcile(ctx context.Context, m *mirrorv1alpha1.ArtifactMirror) (ctrl.Result, error) {
	notReady := func(reason, msg string) (ctrl.Result, error) {
		r.setReady(m, metav1.ConditionFalse, reason, msg)
		var res ctrl.Result
		if reason == ReasonTargetConflict {
			res.RequeueAfter = conflictRetry
		}
		return res, r.cleanup(ctx, m)
	}

	var t mirrorv1alpha1.ClusterMirrorTarget
	err := r.Get(ctx, types.NamespacedName{Name: m.Spec.TargetRef}, &t)
	switch {
	case apierrors.IsNotFound(err):
		return notReady(ReasonTargetNotReady, fmt.Sprintf("ClusterMirrorTarget %s not found", m.Spec.TargetRef))
	case err != nil:
		return ctrl.Result{}, err
	case !meta.IsStatusConditionTrue(t.Status.Conditions, ConditionReady):
		return notReady(ReasonTargetNotReady, fmt.Sprintf("ClusterMirrorTarget %s is not Ready", t.Name))
	}
	reason, msg, err := r.authorize(ctx, &t, m)
	if err != nil {
		return ctrl.Result{}, err
	}
	if reason == "" {
		reason, msg, err = r.conflict(ctx, &t, m)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	if reason != "" {
		return notReady(reason, msg)
	}

	spec, err := json.MarshalIndent(syncSpec(&t, m, r.DeniedCIDRs), "", "  ")
	if err != nil {
		return ctrl.Result{}, err
	}
	// The Job decodes the spec the same way; refuse here what it would refuse.
	if _, err := syncspec.Decode(bytes.NewReader(spec)); err != nil {
		return notReady(ReasonInvalidSpec, err.Error())
	}

	key := types.NamespacedName{Namespace: r.Namespace, Name: objectName(m)}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		renderConfigMap(cm, m, spec)
		return nil
	}); err != nil {
		return ctrl.Result{}, err
	}
	cj := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, cj, func() error {
		renderCronJob(cj, &t, m, r.SyncImage, spec)
		return nil
	})
	if apierrors.IsInvalid(err) {
		return notReady(ReasonInvalidSpec, err.Error())
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if op == controllerutil.OperationResultCreated {
		r.Recorder.Eventf(m, nil, corev1.EventTypeNormal, "Created", "Reconcile", "Created CronJob %s/%s", key.Namespace, key.Name)
	}
	r.setReady(m, metav1.ConditionTrue, ReasonReady, fmt.Sprintf("CronJob %s/%s mirrors to %s", key.Namespace, key.Name, targetRepo(&t, m)))
	return ctrl.Result{}, nil
}

func (r *ArtifactMirrorReconciler) setReady(m *mirrorv1alpha1.ArtifactMirror, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&m.Status.Conditions, metav1.Condition{
		Type: ConditionReady, Status: status, Reason: reason, Message: msg, ObservedGeneration: m.Generation,
	})
}

// authorize checks that the mirror may use the target: the project allows
// its namespace, the source is allowed and not an internal address, and
// the spec is valid (threat model T5, T6, T7, T16). It returns a reason and
// message when it may not.
func (r *ArtifactMirrorReconciler) authorize(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (string, string, error) {
	i := slices.IndexFunc(t.Spec.Projects, func(p mirrorv1alpha1.TargetProject) bool { return p.Name == m.Spec.Target.Project })
	if i < 0 {
		return ReasonProjectNotAllowed, fmt.Sprintf("project %s is not listed in ClusterMirrorTarget %s", m.Spec.Target.Project, t.Name), nil
	}
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: m.Namespace}, &ns); err != nil {
		return "", "", err
	}
	sel, err := metav1.LabelSelectorAsSelector(t.Spec.Projects[i].NamespaceSelector)
	if err != nil || !sel.Matches(labels.Set(ns.Labels)) {
		return ReasonProjectNotAllowed, fmt.Sprintf("project %s does not allow namespace %s", m.Spec.Target.Project, m.Namespace), nil
	}

	host := string(m.Spec.Source.Registry)
	allowed := make([]string, 0, len(t.Spec.AllowedSources))
	for _, a := range t.Spec.AllowedSources {
		allowed = append(allowed, string(a))
	}
	if !syncspec.AllowedSource(host, allowed) {
		return ReasonSourceNotAllowed, fmt.Sprintf("registry %s is not in allowedSources of ClusterMirrorTarget %s", host, t.Name), nil
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if err := syncspec.CheckAddr(a, r.deniedPrefixes()); err != nil {
			return ReasonSourceNotAllowed, "source " + err.Error(), nil
		}
	}

	if m.Spec.Type == mirrorv1alpha1.ArtifactTypeHelmRepo {
		return ReasonInvalidSpec, "type HelmRepo is not supported yet", nil
	}
	if err := tags.Validate(tagPolicy(m.Spec.Tags)); err != nil {
		return ReasonInvalidSpec, "tags: " + err.Error(), nil
	}
	if _, err := name.NewRepository(targetRepo(t, m), name.StrictValidation); err != nil {
		return ReasonInvalidSpec, fmt.Sprintf("target %s is not a valid repository, set target.repository", targetRepo(t, m)), nil
	}
	return "", "", nil
}

func (r *ArtifactMirrorReconciler) deniedPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range r.DeniedCIDRs {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// conflict refuses a mirror whose target repository belongs to another
// source (threat model T17). The oldest authorized mirror of a target
// repository owns it; mirrors with the owner's source may share it.
func (r *ArtifactMirrorReconciler) conflict(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (string, string, error) {
	var list mirrorv1alpha1.ArtifactMirrorList
	if err := r.List(ctx, &list, client.MatchingFields{indexTargetKey: targetKey(m)}); err != nil {
		return "", "", err
	}
	owner := m
	for i := range list.Items {
		o := &list.Items[i]
		if o.UID == m.UID || !o.DeletionTimestamp.IsZero() || !older(o, owner) {
			continue
		}
		// A mirror that may not use the project cannot claim a path in it.
		reason, _, err := r.authorize(ctx, t, o)
		if err != nil {
			return "", "", err
		}
		if reason == "" {
			owner = o
		}
	}
	if src := canonicalSource(owner.Spec.Source); src != canonicalSource(m.Spec.Source) {
		return ReasonTargetConflict, fmt.Sprintf("target %s is claimed by %s/%s with source %s",
			targetRepo(t, m), owner.Namespace, owner.Name, src), nil
	}
	return "", "", nil
}

// older orders mirrors by creation time, then namespace and name.
func older(a, b *mirrorv1alpha1.ArtifactMirror) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name)) < 0
}

// cleanup removes the CronJob, with its Jobs, and the ConfigMap of a mirror.
func (r *ArtifactMirrorReconciler) cleanup(ctx context.Context, m *mirrorv1alpha1.ArtifactMirror) error {
	opts := []client.DeleteAllOfOption{
		client.InNamespace(r.Namespace),
		client.MatchingLabels{LabelMirror: mirrorHash(m.Namespace, m.Name)},
		client.PropagationPolicy(metav1.DeletePropagationBackground),
	}
	if err := r.DeleteAllOf(ctx, &batchv1.CronJob{}, opts...); err != nil {
		return err
	}
	return r.DeleteAllOf(ctx, &corev1.ConfigMap{}, opts...)
}

// mirrorFromAnnotations maps an object in the operator namespace to the
// mirror named in its annotations.
func (r *ArtifactMirrorReconciler) mirrorFromAnnotations(_ context.Context, obj client.Object) []reconcile.Request {
	a := obj.GetAnnotations()
	ns, n := a[AnnotationMirrorNamespace], a[AnnotationMirrorName]
	if obj.GetNamespace() != r.Namespace || ns == "" || n == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ns, Name: n}}}
}

func (r *ArtifactMirrorReconciler) mirrorsMatching(ctx context.Context, opts ...client.ListOption) []reconcile.Request {
	var list mirrorv1alpha1.ArtifactMirrorList
	if err := r.List(ctx, &list, opts...); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for _, m := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: m.Namespace, Name: m.Name}})
	}
	return reqs
}

// SetupWithManager sets up the controller and its field indexes.
func (r *ArtifactMirrorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	idx := mgr.GetFieldIndexer()
	if err := idx.IndexField(ctx, &mirrorv1alpha1.ArtifactMirror{}, indexTargetName, func(o client.Object) []string {
		return []string{o.(*mirrorv1alpha1.ArtifactMirror).Spec.TargetRef}
	}); err != nil {
		return err
	}
	if err := idx.IndexField(ctx, &mirrorv1alpha1.ArtifactMirror{}, indexTargetKey, func(o client.Object) []string {
		return []string{targetKey(o.(*mirrorv1alpha1.ArtifactMirror))}
	}); err != nil {
		return err
	}
	byAnnotations := handler.EnqueueRequestsFromMapFunc(r.mirrorFromAnnotations)
	return ctrl.NewControllerManagedBy(mgr).
		For(&mirrorv1alpha1.ArtifactMirror{}).
		Watches(&mirrorv1alpha1.ClusterMirrorTarget{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				return r.mirrorsMatching(ctx, client.MatchingFields{indexTargetName: o.GetName()})
			})).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				return r.mirrorsMatching(ctx, client.InNamespace(o.GetName()))
			}), builder.WithPredicates(predicate.LabelChangedPredicate{})).
		Watches(&batchv1.CronJob{}, byAnnotations).
		Watches(&corev1.ConfigMap{}, byAnnotations).
		Named("artifactmirror").
		Complete(r)
}
