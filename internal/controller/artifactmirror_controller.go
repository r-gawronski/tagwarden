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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
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
	ctrlevent "sigs.k8s.io/controller-runtime/pkg/event"
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
// Jobs and pods carry the mirror annotations, so their events map back to
// the mirror.
type ArtifactMirrorReconciler struct {
	client.Client
	// APIReader reads Jobs past the cache when a sync request is handled.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Recorder  events.EventRecorder
	// Namespace is the operator namespace for CronJobs, Jobs and ConfigMaps.
	Namespace string
	// SyncImage runs the sync Jobs.
	SyncImage string
	// DeniedCIDRs are the cluster pod and service CIDRs, refused as sources.
	DeniedCIDRs []string
	// ArgoCDTracking is "inherit" to show sync CronJobs in the Argo CD app of
	// their mirror, or empty.
	ArgoCDTracking string
	// ArgoCDInstanceLabel is Argo CD's label for label tracking mode.
	ArgoCDInstanceLabel string

	// trackingMismatch holds the tracking id last reported per mirror.
	trackingMismatch sync.Map
}

// +kubebuilder:rbac:groups=mirror.tagwarden.dev,resources=artifactmirrors,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=mirror.tagwarden.dev,resources=artifactmirrors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mirror.tagwarden.dev,resources=artifactmirrors/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=batch,namespace=system,resources=cronjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=batch,namespace=system,resources=cronjobs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",namespace=system,resources=configmaps,verbs=get;list;watch;create;update;patch;delete

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
	var ev pending
	res, err := r.reconcile(ctx, &m, &ev)
	if err != nil {
		return ctrl.Result{}, err
	}
	m.Status.ObservedGeneration = m.Generation
	if ready := meta.FindStatusCondition(m.Status.Conditions, ConditionReady); ready != nil &&
		ready.Status == metav1.ConditionFalse && (oldReady == nil || oldReady.Reason != ready.Reason) {
		ev.add(corev1.EventTypeWarning, ready.Reason, "Reconcile", ready.Message)
	}
	if !equality.Semantic.DeepEqual(old, &m.Status) {
		if err := r.Status().Update(ctx, &m); err != nil {
			return ctrl.Result{}, err
		}
	}
	// Events follow the status they describe, so a failed update does not
	// leave an Event for a state that was never recorded.
	for _, e := range ev {
		r.Recorder.Eventf(&m, nil, e.typ, e.reason, e.action, "%s", e.note)
	}
	return res, nil
}

type event struct{ typ, reason, action, note string }

// pending collects the Events of one reconcile.
type pending []event

func (p *pending) add(typ, reason, action, note string) {
	*p = append(*p, event{typ, reason, action, note})
}

// ownershipError reports an object in the operator namespace whose
// annotations name another mirror.
type ownershipError struct {
	kind, name, owner string
}

func (e *ownershipError) Error() string {
	return fmt.Sprintf("%s %s already exists and belongs to mirror %q", e.kind, e.name, e.owner)
}

// ownedBy reports whether obj is new or names m in its annotations.
func ownedBy(obj client.Object, m *mirrorv1alpha1.ArtifactMirror) bool {
	a := obj.GetAnnotations()
	return obj.GetResourceVersion() == "" ||
		a[AnnotationMirrorNamespace] == m.Namespace && a[AnnotationMirrorName] == m.Name
}

// checkOwner returns an ownershipError when obj belongs to another mirror.
func checkOwner(kind string, obj client.Object, m *mirrorv1alpha1.ArtifactMirror) error {
	if ownedBy(obj, m) {
		return nil
	}
	a := obj.GetAnnotations()
	return &ownershipError{kind, obj.GetNamespace() + "/" + obj.GetName(), a[AnnotationMirrorNamespace] + "/" + a[AnnotationMirrorName]}
}

// reconcile sets the Ready condition and renders or removes the CronJob.
func (r *ArtifactMirrorReconciler) reconcile(ctx context.Context, m *mirrorv1alpha1.ArtifactMirror, ev *pending) (ctrl.Result, error) {
	notReady := func(reason, msg string) (ctrl.Result, error) {
		r.setReady(m, metav1.ConditionFalse, reason, msg)
		if v := pendingRequest(m); v != "" {
			recordRequest(m, ev, v, mirrorv1alpha1.SyncRequestRefused, "ArtifactMirror is not Ready: "+reason)
		}
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
	if err := r.removeRenamed(ctx, m, key.Name); err != nil {
		return ctrl.Result{}, err
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		if err := checkOwner("ConfigMap", cm, m); err != nil {
			return err
		}
		renderConfigMap(cm, m, spec)
		return nil
	})
	var op controllerutil.OperationResult
	var mismatch string
	cj := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
	if err == nil {
		desired := cj.DeepCopy()
		var trackLabels, trackAnnotations map[string]string
		trackLabels, trackAnnotations, mismatch = argoTracking(r.ArgoCDTracking, r.ArgoCDInstanceLabel, m, key.Namespace, key.Name)
		renderCronJob(desired, &t, m, r.SyncImage, spec, trackLabels, trackAnnotations)
		op, err = controllerutil.CreateOrUpdate(ctx, r.Client, cj, func() error {
			if err := checkOwner("CronJob", cj, m); err != nil {
				return err
			}
			// The server defaults fields the rendered spec leaves empty, so
			// compare checksums instead of specs to avoid no-op updates, and
			// restore hand edits of the pod labels and security-relevant fields.
			if cj.Annotations[annotationCronJobChecksum] != desired.Annotations[annotationCronJobChecksum] ||
				securityDrift(&cj.Spec.JobTemplate.Spec.Template, &desired.Spec.JobTemplate.Spec.Template) ||
				trackingDrift(cj.Annotations, desired.Annotations, cj.Labels, desired.Labels, r.ArgoCDInstanceLabel) {
				cj.Labels, cj.Annotations, cj.Spec = desired.Labels, desired.Annotations, desired.Spec
			}
			return nil
		})
	}
	var owner *ownershipError
	switch {
	case errors.As(err, &owner):
		return notReady(ReasonOwnershipConflict, owner.Error())
	case apierrors.IsInvalid(err):
		return notReady(ReasonInvalidSpec, err.Error())
	case err != nil:
		return ctrl.Result{}, err
	}
	r.reportTrackingMismatch(m, mismatch, ev)
	if op == controllerutil.OperationResultCreated {
		ev.add(corev1.EventTypeNormal, "Created", "Reconcile", fmt.Sprintf("Created CronJob %s/%s", key.Namespace, key.Name))
	}
	r.setReady(m, metav1.ConditionTrue, ReasonReady, fmt.Sprintf("CronJob %s/%s mirrors to %s", key.Namespace, key.Name, targetRepo(&t, m)))
	if err := r.syncStatus(ctx, m, ev); err != nil {
		return ctrl.Result{}, err
	}
	return r.syncNow(ctx, &t, m, cj, ev)
}

// reportTrackingMismatch queues a Warning Event when the tracking id of a
// mirror names another object, once per id.
func (r *ArtifactMirrorReconciler) reportTrackingMismatch(m *mirrorv1alpha1.ArtifactMirror, id string, ev *pending) {
	k := client.ObjectKeyFromObject(m)
	if id == "" {
		r.trackingMismatch.Delete(k)
		return
	}
	if prev, _ := r.trackingMismatch.Swap(k, id); prev != id {
		ev.add(corev1.EventTypeWarning, reasonTrackingMismatch, "Reconcile",
			fmt.Sprintf("Annotation %s %q does not name this ArtifactMirror; the sync CronJob is not tracked", annotationArgoTrackingID, id))
	}
}

func (r *ArtifactMirrorReconciler) setReady(m *mirrorv1alpha1.ArtifactMirror, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&m.Status.Conditions, metav1.Condition{
		Type: ConditionReady, Status: status, Reason: reason, Message: msg, ObservedGeneration: m.Generation,
	})
}

// authorize checks that the mirror may use the target: the project allows
// its namespace and any target.repository override, the source is allowed
// and not an internal address, the spec is valid and within the target's
// limits, and stays out of a project reserved for generated mirrors (threat
// model T5, T6, T7, T10, T16, T23, T36). It returns a reason and
// message when it may not.
func (r *ArtifactMirrorReconciler) authorize(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (string, string, error) {
	if reason, msg, err := r.reserved(ctx, t, m); err != nil || reason != "" {
		return reason, msg, err
	}
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
	if p := targetPath(m); p != defaultTargetPath(m) && !t.Spec.Projects[i].AllowRepositoryOverride {
		return ReasonRepositoryOverrideNotAllowed, fmt.Sprintf("project %s does not allow target.repository %s, use the default path %s",
			m.Spec.Target.Project, p, defaultTargetPath(m)), nil
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
	return r.checkLimits(ctx, t, m)
}

// reserved refuses a user mirror in a project that a target on the same
// registry reserves for its generated mirrors. Any target counts, not only
// the mirror's own: two targets on one registry write the same paths.
func (r *ArtifactMirrorReconciler) reserved(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (string, string, error) {
	var list mirrorv1alpha1.ClusterMirrorTargetList
	if err := r.List(ctx, &list); err != nil {
		return "", "", err
	}
	for i := range list.Items {
		o := &list.Items[i]
		if projectReserved(o) && o.Spec.AutoMirror.Project == m.Spec.Target.Project &&
			registryKey(o.Spec.Registry) == registryKey(t.Spec.Registry) && !isGenerated(o, m) {
			return ReasonProjectReservedForAutoMirror, fmt.Sprintf("project %s of registry %s is reserved for generated mirrors of ClusterMirrorTarget %s, whose vulnerability gate can block; use another project",
				m.Spec.Target.Project, t.Spec.Registry, o.Name), nil
		}
	}
	return "", "", nil
}

// registryKey is a registry host in lower case without the default port.
func registryKey(h mirrorv1alpha1.RegistryHost) string {
	return strings.TrimSuffix(strings.ToLower(string(h)), ":443")
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
		// A mirror that may not use the project or its override cannot
		// claim a path in it.
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

// mirrorObjects lists the CronJobs and ConfigMaps in the operator namespace
// that carry the hash label of m and name m in their annotations.
func (r *ArtifactMirrorReconciler) mirrorObjects(ctx context.Context, m *mirrorv1alpha1.ArtifactMirror) ([]client.Object, error) {
	opts := []client.ListOption{
		client.InNamespace(r.Namespace),
		client.MatchingLabels{LabelMirror: mirrorHash(m.Namespace, m.Name)},
	}
	var cronJobs batchv1.CronJobList
	var configMaps corev1.ConfigMapList
	if err := r.List(ctx, &cronJobs, opts...); err != nil {
		return nil, err
	}
	if err := r.List(ctx, &configMaps, opts...); err != nil {
		return nil, err
	}
	var objs []client.Object
	for i := range cronJobs.Items {
		if ownedBy(&cronJobs.Items[i], m) {
			objs = append(objs, &cronJobs.Items[i])
		}
	}
	for i := range configMaps.Items {
		if ownedBy(&configMaps.Items[i], m) {
			objs = append(objs, &configMaps.Items[i])
		}
	}
	return objs, nil
}

// deleteObjects deletes objs with the propagation policy, tolerating
// objects that are already gone or were replaced meanwhile.
func (r *ArtifactMirrorReconciler) deleteObjects(ctx context.Context, objs []client.Object, policy metav1.DeletionPropagation) error {
	for _, o := range objs {
		err := r.Delete(ctx, o, client.PropagationPolicy(policy), client.Preconditions{UID: new(o.GetUID())})
		if client.IgnoreNotFound(err) != nil && !apierrors.IsConflict(err) {
			return err
		}
	}
	return nil
}

// cleanup removes the CronJob, with its Jobs, and the ConfigMap of a
// mirror. It deletes only objects whose annotations name the mirror.
func (r *ArtifactMirrorReconciler) cleanup(ctx context.Context, m *mirrorv1alpha1.ArtifactMirror) error {
	r.trackingMismatch.Delete(client.ObjectKeyFromObject(m))
	objs, err := r.mirrorObjects(ctx, m)
	if err != nil {
		return err
	}
	return r.deleteObjects(ctx, objs, metav1.DeletePropagationBackground)
}

// removeRenamed deletes the objects of m that sit under another name, such
// as the tagwarden-<hash> names of earlier versions. Orphan keeps a running
// sync Job alive until it finishes; its TTL then cleans it up.
func (r *ArtifactMirrorReconciler) removeRenamed(ctx context.Context, m *mirrorv1alpha1.ArtifactMirror, current string) error {
	objs, err := r.mirrorObjects(ctx, m)
	if err != nil {
		return err
	}
	old := objs[:0]
	for _, o := range objs {
		if o.GetName() != current {
			old = append(old, o)
		}
	}
	return r.deleteObjects(ctx, old, metav1.DeletePropagationOrphan)
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
		// A mirror that moves onto, leaves or claims a path changes who owns
		// it, so the other mirrors of the path are checked again.
		Watches(&mirrorv1alpha1.ArtifactMirror{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				return r.mirrorsMatching(ctx, client.MatchingFields{indexTargetKey: targetKey(o.(*mirrorv1alpha1.ArtifactMirror))})
			})).
		// A mirror that comes, goes or changes target changes which mirrors
		// of its namespace fit the target's maxMirrorsPerNamespace.
		Watches(&mirrorv1alpha1.ArtifactMirror{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				return r.mirrorsMatching(ctx, client.InNamespace(o.GetNamespace()),
					client.MatchingFields{indexTargetName: o.(*mirrorv1alpha1.ArtifactMirror).Spec.TargetRef})
			}), builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(e ctrlevent.UpdateEvent) bool {
				o, n := e.ObjectOld.(*mirrorv1alpha1.ArtifactMirror), e.ObjectNew.(*mirrorv1alpha1.ArtifactMirror)
				return o.Spec.TargetRef != n.Spec.TargetRef || o.DeletionTimestamp.IsZero() != n.DeletionTimestamp.IsZero()
			},
			GenericFunc: func(ctrlevent.GenericEvent) bool { return false },
		})).
		// A target change can reserve a project for every target on its
		// registry, so the mirrors of all of them are checked again.
		Watches(&mirrorv1alpha1.ClusterMirrorTarget{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				var targets mirrorv1alpha1.ClusterMirrorTargetList
				if err := r.List(ctx, &targets); err != nil {
					return nil
				}
				key := registryKey(o.(*mirrorv1alpha1.ClusterMirrorTarget).Spec.Registry)
				reqs := r.mirrorsMatching(ctx, client.MatchingFields{indexTargetName: o.GetName()})
				for i := range targets.Items {
					if t := &targets.Items[i]; t.Name != o.GetName() && registryKey(t.Spec.Registry) == key {
						reqs = append(reqs, r.mirrorsMatching(ctx, client.MatchingFields{indexTargetName: t.Name})...)
					}
				}
				return reqs
			})).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				return r.mirrorsMatching(ctx, client.InNamespace(o.GetName()))
			}), builder.WithPredicates(predicate.LabelChangedPredicate{})).
		Watches(&batchv1.CronJob{}, byAnnotations).
		Watches(&batchv1.Job{}, byAnnotations).
		Watches(&corev1.Pod{}, byAnnotations).
		Watches(&corev1.ConfigMap{}, byAnnotations).
		Named("artifactmirror").
		Complete(r)
}
