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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlevent "sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const (
	trueValue             = "true"
	defaultAutoMaxMirrors = 20
	// maxAutoTags is the tag cap of a generated mirror, further limited by
	// the target's maxExplicitTags.
	maxAutoTags = 100
	// maxTrackedStates bounds the Event dedupe map.
	maxTrackedStates = 10000
)

// Event reasons on pods.
const (
	reasonMirrorRequested    = "MirrorRequested"
	reasonMirrorRefused      = "MirrorRefused"
	reasonAutoMirrorDisabled = "AutoMirrorDisabled"
	reasonAlreadyMirrored    = "AlreadyMirrored"
	reasonTooManyTags        = "TooManyTags"
	reasonQuotaExceeded      = "QuotaExceeded"
	reasonNameConflict       = "NameConflict"
	reasonSyncFailed         = "SyncFailed"
)

// AutoMirrorReconciler turns the tagwarden.dev/auto-mirror annotation of a
// pod into generated ArtifactMirrors, one per namespace and source
// repository. Generated mirrors are ordinary ArtifactMirrors: the
// ArtifactMirror controller authorizes and syncs them, and this controller
// reports their Ready and Synced conditions back as pod Events.
type AutoMirrorReconciler struct {
	client.Client
	// APIReader counts generated mirrors past the cache before a create.
	APIReader client.Reader
	// Pods reads pods cluster-wide from a trimmed cache.
	Pods     ctrlcache.Cache
	Recorder events.EventRecorder

	mu sync.Mutex
	// states holds the last reported state per pod and image, so an Event
	// is recorded only when it changes.
	states map[types.NamespacedName]map[string]string
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=mirror.tagwarden.dev,resources=artifactmirrors,verbs=create;patch

// trimPod keeps what auto-mirror needs of a pod to bound cache memory.
func trimPod(obj any) (any, error) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	t := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.Name, Namespace: p.Namespace, UID: p.UID, ResourceVersion: p.ResourceVersion,
			DeletionTimestamp: p.DeletionTimestamp, Annotations: p.Annotations, Labels: p.Labels, OwnerReferences: p.OwnerReferences,
		},
		Status: corev1.PodStatus{Phase: p.Status.Phase},
	}
	for _, c := range p.Spec.InitContainers {
		t.Spec.InitContainers = append(t.Spec.InitContainers, corev1.Container{Name: c.Name, Image: c.Image})
	}
	for _, c := range p.Spec.Containers {
		t.Spec.Containers = append(t.Spec.Containers, corev1.Container{Name: c.Name, Image: c.Image})
	}
	return t, nil
}

func (r *AutoMirrorReconciler) report(pod *corev1.Pod, key, state, typ, reason, msg string) {
	k := client.ObjectKeyFromObject(pod)
	r.mu.Lock()
	if r.states == nil || len(r.states) > maxTrackedStates {
		r.states = map[types.NamespacedName]map[string]string{}
	}
	m := r.states[k]
	if m == nil {
		m = map[string]string{}
		r.states[k] = m
	}
	changed := m[key] != state
	m[key] = state
	r.mu.Unlock()
	if changed {
		r.Recorder.Eventf(pod, nil, typ, reason, "AutoMirror", "%s", msg)
	}
}

func (r *AutoMirrorReconciler) forget(k types.NamespacedName) {
	r.mu.Lock()
	delete(r.states, k)
	r.mu.Unlock()
}

// Reconcile makes sure every image of an annotated pod is in a generated mirror.
func (r *AutoMirrorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod corev1.Pod
	if err := r.Pods.Get(ctx, req.NamespacedName, &pod); err != nil {
		r.forget(req.NamespacedName)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	targetName := pod.Annotations[mirrorv1alpha1.AutoMirrorAnnotation]
	if targetName == "" || !pod.DeletionTimestamp.IsZero() {
		r.forget(req.NamespacedName)
		return ctrl.Result{}, nil
	}

	var t mirrorv1alpha1.ClusterMirrorTarget
	err := r.Get(ctx, types.NamespacedName{Name: targetName}, &t)
	switch {
	case apierrors.IsNotFound(err):
		r.report(&pod, "", "notfound", corev1.EventTypeWarning, reasonMirrorRefused,
			fmt.Sprintf("ClusterMirrorTarget %s not found", targetName))
		return ctrl.Result{}, nil
	case err != nil:
		return ctrl.Result{}, err
	case t.Spec.AutoMirror == nil || !t.Spec.AutoMirror.Enabled:
		r.report(&pod, "", "disabled", corev1.EventTypeWarning, reasonAutoMirrorDisabled,
			fmt.Sprintf("ClusterMirrorTarget %s does not enable autoMirror; ask the platform team", targetName))
		return ctrl.Result{}, nil
	case !meta.IsStatusConditionTrue(t.Status.Conditions, ConditionReady):
		r.report(&pod, "", "notready", corev1.EventTypeWarning, reasonMirrorRefused,
			fmt.Sprintf("%s: ClusterMirrorTarget %s is not Ready", ReasonTargetNotReady, targetName))
		return ctrl.Result{}, nil
	}

	r.mu.Lock()
	delete(r.states[req.NamespacedName], "")
	r.mu.Unlock()

	tagsBySource := map[string][]string{}
	sources := map[string]imageSource{}
	var images []string
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		images = append(images, c.Image)
	}
	for _, img := range images {
		s, err := parseImage(img, &t)
		if err != nil {
			reason := reasonInvalidImage
			if errors.Is(err, errDigestOnly) {
				reason = reasonDigestOnly
			}
			r.report(&pod, img, reason, corev1.EventTypeWarning, reason, fmt.Sprintf("image %s: %v", img, err))
			continue
		}
		sources[s.key()] = s
		if !slices.Contains(tagsBySource[s.key()], s.Tag) {
			tagsBySource[s.key()] = append(tagsBySource[s.key()], s.Tag)
		}
	}
	var requeue bool
	for _, k := range slices.Sorted(maps.Keys(sources)) {
		if err := r.ensure(ctx, &pod, &t, sources[k], tagsBySource[k]); err != nil {
			requeue = true
			if !apierrors.IsConflict(err) {
				return ctrl.Result{}, err
			}
		}
	}
	if requeue {
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	return ctrl.Result{}, nil
}

// generatedName is auto-<16 hex of sha256(registry/repository)>.
func generatedName(s imageSource) string {
	sum := sha256.Sum256([]byte(s.key()))
	return "auto-" + hex.EncodeToString(sum[:])[:16]
}

// ensure creates or extends the generated mirror of one source repository
// and reports its state on the pod.
func (r *AutoMirrorReconciler) ensure(ctx context.Context, pod *corev1.Pod, t *mirrorv1alpha1.ClusterMirrorTarget, s imageSource, want []string) error {
	am := t.Spec.AutoMirror
	desired := &mirrorv1alpha1.ArtifactMirror{
		ObjectMeta: metav1.ObjectMeta{Name: generatedName(s), Namespace: pod.Namespace},
		Spec: mirrorv1alpha1.ArtifactMirrorSpec{
			TargetRef: t.Name, Schedule: am.Schedule, Type: mirrorv1alpha1.ArtifactTypeImage,
			Source: mirrorv1alpha1.Source{Registry: mirrorv1alpha1.RegistryHost(s.Registry), Repository: s.Repository},
			Target: mirrorv1alpha1.Target{Project: am.Project},
		},
	}
	if desired.Spec.Schedule == "" {
		desired.Spec.Schedule = "0 */6 * * *"
	}
	state := s.key()

	// A user-defined mirror of the same source and path wins.
	var list mirrorv1alpha1.ArtifactMirrorList
	if err := r.List(ctx, &list, client.InNamespace(pod.Namespace), client.MatchingFields{indexTargetKey: targetKey(desired)}); err != nil {
		return err
	}
	for i := range list.Items {
		o := &list.Items[i]
		if o.Labels[mirrorv1alpha1.LabelGenerated] != trueValue && o.DeletionTimestamp.IsZero() && canonicalSource(o.Spec.Source) == canonicalSource(desired.Spec.Source) {
			r.report(pod, state, "already:"+o.Name, corev1.EventTypeNormal, reasonAlreadyMirrored,
				fmt.Sprintf("%s is mirrored by ArtifactMirror %s/%s", state, o.Namespace, o.Name))
			return nil
		}
	}

	maxTags := min(maxAutoTags, int(limitOr(limitsOf(t).MaxExplicitTags, defaultMaxExplicitTags)))
	var cur mirrorv1alpha1.ArtifactMirror
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), &cur)
	switch {
	case apierrors.IsNotFound(err):
		var all mirrorv1alpha1.ArtifactMirrorList
		if err := r.APIReader.List(ctx, &all, client.InNamespace(pod.Namespace), client.MatchingLabels{
			mirrorv1alpha1.LabelGenerated: trueValue, mirrorv1alpha1.LabelAutoTarget: targetLabel(t.Name)}); err != nil {
			return err
		}
		if limit := int(limitOr(am.MaxMirrorsPerNamespace, defaultAutoMaxMirrors)); len(all.Items) >= limit {
			r.report(pod, state, reasonQuotaExceeded, corev1.EventTypeWarning, reasonMirrorRefused,
				fmt.Sprintf("%s: %d generated mirrors in namespace %s already use autoMirror.maxMirrorsPerNamespace %d of %s",
					reasonQuotaExceeded, len(all.Items), pod.Namespace, limit, t.Name))
			return nil
		}
		tags := sortedUnique(want)
		if len(tags) > maxTags {
			r.report(pod, state+"#tags", "toomany", corev1.EventTypeWarning, reasonTooManyTags,
				fmt.Sprintf("%s has more than %d tags, the rest are not mirrored", state, maxTags))
			tags = tags[:maxTags]
		}
		desired.Labels = map[string]string{mirrorv1alpha1.LabelGenerated: trueValue, mirrorv1alpha1.LabelAutoTarget: targetLabel(t.Name)}
		desired.Annotations = map[string]string{mirrorv1alpha1.SyncNowAnnotation: syncNowValue()}
		desired.Spec.Tags.Tags = tags
		if err := r.Create(ctx, desired); err != nil {
			return err
		}
		r.report(pod, state, "requested", corev1.EventTypeNormal, reasonMirrorRequested,
			fmt.Sprintf("Requested mirror of %s tags %v as ArtifactMirror %s", state, tags, desired.Name))
		return nil
	case err != nil:
		return err
	case cur.Labels[mirrorv1alpha1.LabelGenerated] != trueValue:
		r.report(pod, state, reasonNameConflict, corev1.EventTypeWarning, reasonMirrorRefused,
			fmt.Sprintf("%s: ArtifactMirror %s/%s exists and is not generated", reasonNameConflict, cur.Namespace, cur.Name))
		return nil
	}

	// Add the missing tags; never remove any, never touch anything else.
	have := cur.Spec.Tags.Tags
	var missing []string
	for _, tag := range sortedUnique(want) {
		if !slices.Contains(have, tag) {
			missing = append(missing, tag)
		}
	}
	if len(missing) > 0 {
		room := max(0, maxTags-len(have))
		if len(missing) > room {
			r.report(pod, state+"#tags", "toomany", corev1.EventTypeWarning, reasonTooManyTags,
				fmt.Sprintf("%s already has %d of at most %d tags, %v are not mirrored", state, len(have), maxTags, missing[room:]))
			missing = missing[:room]
		}
	}
	if len(missing) > 0 {
		next := cur.DeepCopy()
		next.Spec.Tags.Tags = sortedUnique(slices.Concat(have, missing))
		if next.Annotations == nil {
			next.Annotations = map[string]string{}
		}
		next.Annotations[mirrorv1alpha1.SyncNowAnnotation] = syncNowValue()
		if err := r.Patch(ctx, next, client.MergeFromWithOptions(&cur, client.MergeFromWithOptimisticLock{})); err != nil {
			return err
		}
		cur = *next
	}

	// Surface whatever the mirror reports, whatever the reason: the sync
	// path and any future gate (such as a vulnerability gate) set the
	// conditions, this controller only relays them.
	if c := meta.FindStatusCondition(cur.Status.Conditions, ConditionReady); c != nil && c.Status == metav1.ConditionFalse {
		r.report(pod, state, "ready:"+c.Reason+c.Message, corev1.EventTypeWarning, reasonMirrorRefused,
			fmt.Sprintf("%s: %s", c.Reason, c.Message))
		return nil
	}
	if c := meta.FindStatusCondition(cur.Status.Conditions, ConditionSynced); c != nil && c.Status == metav1.ConditionFalse {
		r.report(pod, state, "synced:"+c.Reason+c.Message, corev1.EventTypeWarning, reasonSyncFailed,
			fmt.Sprintf("%s: %s", c.Reason, c.Message))
		return nil
	}
	r.report(pod, state, "requested", corev1.EventTypeNormal, reasonMirrorRequested,
		fmt.Sprintf("Mirror of %s tags %v requested as ArtifactMirror %s", state, want, cur.Name))
	return nil
}

func limitsOf(t *mirrorv1alpha1.ClusterMirrorTarget) mirrorv1alpha1.TargetLimits {
	if t.Spec.Limits == nil {
		return mirrorv1alpha1.TargetLimits{}
	}
	return *t.Spec.Limits
}

func sortedUnique(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

func syncNowValue() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// SetupWithManager watches annotated pods cluster-wide through a trimmed
// cache of their own, and generated mirrors and targets for state changes.
func (r *AutoMirrorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	podCache, err := ctrlcache.New(mgr.GetConfig(), ctrlcache.Options{
		Scheme: mgr.GetScheme(), Mapper: mgr.GetRESTMapper(),
		ByObject: map[client.Object]ctrlcache.ByObject{&corev1.Pod{}: {Transform: cache.TransformFunc(trimPod)}},
	})
	if err != nil {
		return err
	}
	if err := mgr.Add(podCache); err != nil {
		return err
	}
	r.Pods = podCache

	has := func(o client.Object) bool { return o.GetAnnotations()[mirrorv1alpha1.AutoMirrorAnnotation] != "" }
	podPred := predicate.Funcs{
		CreateFunc: func(e ctrlevent.CreateEvent) bool { return has(e.Object) },
		// An update that removes the annotation still has to clear the state.
		UpdateFunc: func(e ctrlevent.UpdateEvent) bool {
			return has(e.ObjectNew) || has(e.ObjectOld)
		},
		DeleteFunc:  func(e ctrlevent.DeleteEvent) bool { return has(e.Object) },
		GenericFunc: func(ctrlevent.GenericEvent) bool { return false },
	}
	podsOf := func(ctx context.Context, target string, opts ...client.ListOption) []reconcile.Request {
		var pods corev1.PodList
		if err := r.Pods.List(ctx, &pods, opts...); err != nil {
			return nil
		}
		var reqs []reconcile.Request
		for i := range pods.Items {
			if v := pods.Items[i].Annotations[mirrorv1alpha1.AutoMirrorAnnotation]; v != "" && (target == "" || v == target) {
				reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&pods.Items[i])})
			}
		}
		return reqs
	}
	generated := predicate.NewPredicateFuncs(func(o client.Object) bool { return o.GetLabels()[mirrorv1alpha1.LabelGenerated] == trueValue })
	return ctrl.NewControllerManagedBy(mgr).
		Named("automirror").
		WatchesRawSource(source.Kind(podCache, &corev1.Pod{}, &handler.TypedEnqueueRequestForObject[*corev1.Pod]{},
			predicate.TypedFuncs[*corev1.Pod]{
				CreateFunc: func(e ctrlevent.TypedCreateEvent[*corev1.Pod]) bool {
					return podPred.Create(ctrlevent.CreateEvent{Object: e.Object})
				},
				UpdateFunc: func(e ctrlevent.TypedUpdateEvent[*corev1.Pod]) bool {
					return podPred.Update(ctrlevent.UpdateEvent{ObjectOld: e.ObjectOld, ObjectNew: e.ObjectNew})
				},
				DeleteFunc: func(e ctrlevent.TypedDeleteEvent[*corev1.Pod]) bool {
					return podPred.Delete(ctrlevent.DeleteEvent{Object: e.Object})
				},
				GenericFunc: func(ctrlevent.TypedGenericEvent[*corev1.Pod]) bool { return false },
			})).
		Watches(&mirrorv1alpha1.ArtifactMirror{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				return podsOf(ctx, o.(*mirrorv1alpha1.ArtifactMirror).Spec.TargetRef, client.InNamespace(o.GetNamespace()))
			}), builder.WithPredicates(generated)).
		Watches(&mirrorv1alpha1.ClusterMirrorTarget{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				return podsOf(ctx, o.GetName())
			})).
		Complete(r)
}
