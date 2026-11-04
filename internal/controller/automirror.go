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
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
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
	reasonProjectNotAllowed  = ReasonProjectNotAllowed
	reasonImplicitLatest     = "ImplicitLatestNotSupported"
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

// trimPod keeps what auto-mirror needs of a pod to bound cache memory: the
// identity, the auto-mirror annotation and the container images. A pod
// without the annotation keeps no containers. The informer still lists and
// watches every pod, so the API server and CPU cost grow with the pod count
// even though the memory does not.
func trimPod(obj any) (any, error) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	t := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: p.Name, Namespace: p.Namespace, UID: p.UID, ResourceVersion: p.ResourceVersion, DeletionTimestamp: p.DeletionTimestamp,
	}}
	v := p.Annotations[mirrorv1alpha1.AutoMirrorAnnotation]
	if v == "" {
		return t, nil
	}
	t.Annotations = map[string]string{mirrorv1alpha1.AutoMirrorAnnotation: v}
	for _, c := range p.Spec.InitContainers {
		t.Spec.InitContainers = append(t.Spec.InitContainers, corev1.Container{Name: c.Name, Image: c.Image})
	}
	for _, c := range p.Spec.Containers {
		t.Spec.Containers = append(t.Spec.Containers, corev1.Container{Name: c.Name, Image: c.Image})
	}
	return t, nil
}

func podImages(p *corev1.Pod) []string {
	out := make([]string, 0, len(p.Spec.InitContainers)+len(p.Spec.Containers))
	for _, c := range slices.Concat(p.Spec.InitContainers, p.Spec.Containers) {
		out = append(out, c.Image)
	}
	return out
}

func (r *AutoMirrorReconciler) report(pod *corev1.Pod, key, state, typ, reason, msg string) {
	k := client.ObjectKeyFromObject(pod)
	r.mu.Lock()
	if r.states == nil {
		r.states = map[types.NamespacedName]map[string]string{}
	}
	m := r.states[k]
	if m == nil {
		if len(r.states) >= maxTrackedStates {
			// Evict one other pod; its next state change records an Event again.
			for old := range r.states {
				delete(r.states, old)
				break
			}
		}
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

// clear drops the reported state of key, so the next report records an
// Event again.
func (r *AutoMirrorReconciler) clear(pod *corev1.Pod, key string) {
	r.mu.Lock()
	delete(r.states[client.ObjectKeyFromObject(pod)], key)
	r.mu.Unlock()
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
	for _, img := range podImages(&pod) {
		s, err := parseImage(img, &t)
		if err != nil {
			reason := reasonInvalidImage
			switch {
			case errors.Is(err, errDigestOnly):
				reason = reasonDigestOnly
			case errors.Is(err, errImplicitLatest):
				reason = reasonImplicitLatest
			}
			r.report(&pod, img, reason, corev1.EventTypeWarning, reason, fmt.Sprintf("image %s: %v", img, err))
			continue
		}
		sources[s.key()] = s
		if !slices.Contains(tagsBySource[s.key()], s.Tag) {
			tagsBySource[s.key()] = append(tagsBySource[s.key()], s.Tag)
		}
	}
	// One bad source must not stop the others.
	var requeue bool
	var errs []error
	for _, k := range slices.Sorted(maps.Keys(sources)) {
		switch err := r.ensure(ctx, &pod, &t, sources[k], tagsBySource[k]); {
		case err == nil:
		case apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err):
			requeue = true
		default:
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return ctrl.Result{}, err
	}
	if requeue {
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	return ctrl.Result{}, nil
}

// generatedName is auto-<16 hex of sha256(registry/repository)>.
func generatedName(s imageSource) string { return generatedNameOf(s.key()) }

func generatedNameOf(src string) string {
	sum := sha256.Sum256([]byte(src))
	return "auto-" + hex.EncodeToString(sum[:])[:16]
}

// isGenerated reports whether m is a generated mirror of t: the labels, the
// name, the project and the default path that auto-mirror sets. A mirror
// missing any of them, such as a generated name without the label, is a
// user mirror.
func isGenerated(t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) bool {
	return t.Spec.AutoMirror != nil &&
		m.Labels[mirrorv1alpha1.LabelGenerated] == trueValue &&
		m.Labels[mirrorv1alpha1.LabelAutoTarget] == targetLabel(t.Name) &&
		m.Spec.TargetRef == t.Name &&
		m.Spec.Type == mirrorv1alpha1.ArtifactTypeImage &&
		m.Spec.Target.Project == t.Spec.AutoMirror.Project &&
		m.Spec.Target.Repository == "" &&
		m.Name == generatedNameOf(canonicalSource(m.Spec.Source))
}

// projectReserved reports whether autoMirror.project of t is reserved for
// generated mirrors: the vulnerability gate is on and can block, so a user
// mirror there would let an image skip the block (threat model T36).
func projectReserved(t *mirrorv1alpha1.ClusterMirrorTarget) bool {
	if t.Spec.AutoMirror == nil || t.Spec.AutoMirror.VulnerabilityGate == nil {
		return false
	}
	g := t.Spec.AutoMirror.VulnerabilityGate
	return g.Enabled && (g.Action == mirrorv1alpha1.GateActionBlock || g.OnScanError == mirrorv1alpha1.GateActionBlock)
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

	// A user-defined mirror of the same source and path wins, unless the
	// project is reserved: then it is refused and the generated one is used.
	if !projectReserved(t) {
		if o, err := r.userMirror(ctx, desired); err != nil || o != nil {
			if o != nil {
				r.report(pod, state, "already:"+o.Name, corev1.EventTypeNormal, reasonAlreadyMirrored,
					fmt.Sprintf("%s is mirrored by ArtifactMirror %s/%s", state, o.Namespace, o.Name))
			}
			return err
		}
	}

	maxTags := min(maxAutoTags, int(limitOr(limitsOf(t).MaxExplicitTags, defaultMaxExplicitTags)))
	var cur mirrorv1alpha1.ArtifactMirror
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), &cur)
	switch {
	case apierrors.IsNotFound(err):
		if refused, err := r.projectRefusal(ctx, pod, t); err != nil || refused != "" {
			if refused != "" {
				r.report(pod, state, "project", corev1.EventTypeWarning, reasonMirrorRefused, refused)
			}
			return err
		}
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
		if err := r.Create(ctx, desired); apierrors.IsInvalid(err) {
			r.report(pod, state, "invalid", corev1.EventTypeWarning, reasonInvalidImage,
				fmt.Sprintf("%s cannot be mirrored: %v", state, err))
			return nil
		} else if err != nil {
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
	case cur.Spec.TargetRef != desired.Spec.TargetRef || canonicalSource(cur.Spec.Source) != canonicalSource(desired.Spec.Source):
		r.report(pod, state, reasonNameConflict, corev1.EventTypeWarning, reasonMirrorRefused,
			fmt.Sprintf("%s: ArtifactMirror %s/%s carries the generated label but mirrors another source or target", reasonNameConflict, cur.Namespace, cur.Name))
		return nil
	}

	// Add the missing tags; never remove any. Restore the project and
	// schedule when the platform team changed autoMirror.
	next := cur.DeepCopy()
	next.Spec.Target = desired.Spec.Target
	next.Spec.Schedule = desired.Spec.Schedule
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
		next.Spec.Tags.Tags = sortedUnique(slices.Concat(have, missing))
		if next.Annotations == nil {
			next.Annotations = map[string]string{}
		}
		next.Annotations[mirrorv1alpha1.SyncNowAnnotation] = syncNowValue()
	}
	if !equality.Semantic.DeepEqual(cur.Spec, next.Spec) || len(missing) > 0 {
		if err := r.Patch(ctx, next, client.MergeFromWithOptions(&cur, client.MergeFromWithOptimisticLock{})); apierrors.IsInvalid(err) {
			r.report(pod, state, "invalid", corev1.EventTypeWarning, reasonInvalidImage,
				fmt.Sprintf("%s cannot be updated: %v", state, err))
			return nil
		} else if err != nil {
			return err
		}
		cur = *next
	}

	r.relay(pod, state, &cur, want)
	r.relayGate(pod, t, state, &cur, want)
	return nil
}

// userMirror returns a user-defined mirror with the source and target path
// of desired, or nil.
func (r *AutoMirrorReconciler) userMirror(ctx context.Context, desired *mirrorv1alpha1.ArtifactMirror) (*mirrorv1alpha1.ArtifactMirror, error) {
	var list mirrorv1alpha1.ArtifactMirrorList
	if err := r.List(ctx, &list, client.InNamespace(desired.Namespace), client.MatchingFields{indexTargetKey: targetKey(desired)}); err != nil {
		return nil, err
	}
	for i := range list.Items {
		o := &list.Items[i]
		if o.Labels[mirrorv1alpha1.LabelGenerated] != trueValue && o.DeletionTimestamp.IsZero() && canonicalSource(o.Spec.Source) == canonicalSource(desired.Spec.Source) {
			return o, nil
		}
	}
	return nil, nil
}

// relay reports the state of a generated mirror on the pod, whatever the
// reason: the sync path and any future gate (such as a vulnerability gate)
// set the conditions, this controller only passes them on.
func (r *AutoMirrorReconciler) relay(pod *corev1.Pod, state string, cur *mirrorv1alpha1.ArtifactMirror, want []string) {
	if c := meta.FindStatusCondition(cur.Status.Conditions, ConditionReady); c != nil && c.Status == metav1.ConditionFalse {
		r.report(pod, state, "ready:"+c.Reason+c.Message, corev1.EventTypeWarning, reasonMirrorRefused,
			fmt.Sprintf("%s: %s", c.Reason, c.Message))
		return
	}
	if c := meta.FindStatusCondition(cur.Status.Conditions, ConditionSynced); c != nil && c.Status == metav1.ConditionFalse {
		r.report(pod, state, "synced:"+c.Reason+c.Message, corev1.EventTypeWarning, reasonSyncFailed,
			fmt.Sprintf("%s: %s", c.Reason, c.Message))
		return
	}
	if c := meta.FindStatusCondition(cur.Status.Conditions, ConditionRescanned); c != nil && c.Status == metav1.ConditionFalse {
		r.report(pod, state, "rescanned:"+c.Reason+c.Message, corev1.EventTypeWarning, ReasonRescanFailed,
			fmt.Sprintf("%s: %s", c.Reason, c.Message))
		return
	}
	r.report(pod, state, "requested", corev1.EventTypeNormal, reasonMirrorRequested,
		fmt.Sprintf("Mirror of %s tags %v requested as ArtifactMirror %s", state, want, cur.Name))
}

// relayGate reports gate outcomes on the pod: the target's ScannerReady
// once per source, and for each tag the pod uses, its entries in the
// generated mirror's status.findings and status.vulnerable (re-scan,
// MirroredImageVulnerable). Ready and Synced stay True for gate outcomes,
// so relay does not see them. Pods using other tags get nothing;
// accepted findings are not in status.findings. Each key records an Event
// only when its state changes, and is cleared when the outcome goes away.
func (r *AutoMirrorReconciler) relayGate(pod *corev1.Pod, t *mirrorv1alpha1.ClusterMirrorTarget, state string, cur *mirrorv1alpha1.ArtifactMirror, want []string) {
	g := gateOf(t)
	if g == nil || meta.IsStatusConditionFalse(cur.Status.Conditions, ConditionReady) {
		return
	}
	see := fmt.Sprintf("see ArtifactMirror %s/%s", cur.Namespace, cur.Name)
	scannerKey := state + "#scanner"
	if c := meta.FindStatusCondition(t.Status.Conditions, ConditionScannerReady); c != nil && c.Status == metav1.ConditionFalse {
		reason, what := reasonVulnerabilityScanFail, "images are mirrored without scan"
		if g.OnScanError == mirrorv1alpha1.GateActionBlock {
			reason, what = reasonMirrorRefused, "images are not mirrored"
		}
		r.report(pod, scannerKey, c.Reason+c.Message, corev1.EventTypeWarning, reason,
			fmt.Sprintf("%s: scanner of ClusterMirrorTarget %s: %s; %s", c.Reason, t.Name, c.Message, what))
	} else {
		r.clear(pod, scannerKey)
	}
	startKey := state + "#start"
	if c := meta.FindStatusCondition(cur.Status.Conditions, ConditionVulnerabilityGate); c != nil && c.Status == metav1.ConditionFalse &&
		c.Reason == ReasonScannerUnavailable && strings.HasPrefix(c.Message, scannerStartPrefix) {
		reason := reasonVulnerabilityScanFail
		if g.OnScanError == mirrorv1alpha1.GateActionBlock {
			reason = reasonMirrorRefused
		}
		r.report(pod, startKey, c.Message, corev1.EventTypeWarning, reason,
			fmt.Sprintf("%s: %s; %s", c.Reason, c.Message, see))
	} else {
		r.clear(pod, startKey)
	}
	for _, tag := range want {
		key := state + "#gate:" + tag
		i := slices.IndexFunc(cur.Status.Findings, func(f mirrorv1alpha1.VulnerabilityFinding) bool { return f.Tag == tag })
		if i < 0 {
			r.clear(pod, key)
			continue
		}
		f := cur.Status.Findings[i]
		image := state + ":" + tag
		var reason, msg string
		switch blocked := f.Outcome == mirrorv1alpha1.OutcomeBlocked; {
		case f.Verdict == mirrorv1alpha1.VerdictScanError && blocked:
			reason, msg = reasonMirrorRefused, fmt.Sprintf("%s: %s could not be scanned and is not mirrored; %s", f.ScanError, image, see)
		case f.Verdict == mirrorv1alpha1.VerdictScanError:
			reason, msg = reasonVulnerabilityScanFail, fmt.Sprintf("%s: %s mirrored without scan; %s", f.ScanError, image, see)
		case blocked:
			reason, msg = reasonMirrorRefused, fmt.Sprintf("%s: %s has %s; %s", reasonVulnerabilityBlocked, image, findingSummary(f), see)
		default:
			reason, msg = reasonVulnerabilitiesFound, fmt.Sprintf("%s has %s, mirrored anyway; %s", image, findingSummary(f), see)
		}
		r.report(pod, key, string(f.Verdict)+"/"+string(f.Outcome)+"/"+f.Digest, corev1.EventTypeWarning, reason, capMessage(msg))
	}
	for _, tag := range want {
		key := state + "#rescan:" + tag
		i := slices.IndexFunc(cur.Status.Vulnerable, func(v mirrorv1alpha1.VulnerableTag) bool { return v.Tag == tag })
		if i < 0 {
			r.clear(pod, key)
			continue
		}
		v := cur.Status.Vulnerable[i]
		r.report(pod, key, string(v.Action)+"/"+v.Digest, corev1.EventTypeWarning, reasonImageVulnerable,
			capMessage(fmt.Sprintf("%s:%s found vulnerable by re-scan: %s; %s; %s", state, tag, findingSummary(vulnerableFinding(v)), untagText(v.Action), see)))
	}
}

// projectRefusal returns a message when the project of autoMirror does not
// allow the namespace of the pod, so no object is created for it.
func (r *AutoMirrorReconciler) projectRefusal(ctx context.Context, pod *corev1.Pod, t *mirrorv1alpha1.ClusterMirrorTarget) (string, error) {
	project := t.Spec.AutoMirror.Project
	i := slices.IndexFunc(t.Spec.Projects, func(p mirrorv1alpha1.TargetProject) bool { return p.Name == project })
	if i < 0 {
		return fmt.Sprintf("%s: project %s is not listed in ClusterMirrorTarget %s", reasonProjectNotAllowed, project, t.Name), nil
	}
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: pod.Namespace}, &ns); err != nil {
		return "", err
	}
	sel, err := metav1.LabelSelectorAsSelector(t.Spec.Projects[i].NamespaceSelector)
	if err != nil || !sel.Matches(labels.Set(ns.Labels)) {
		return fmt.Sprintf("%s: project %s does not allow namespace %s", reasonProjectNotAllowed, project, pod.Namespace), nil
	}
	return "", nil
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
	// Pods matter on create, delete and when the annotation, the images or
	// the deletion state change. An update that removes the annotation still
	// has to clear the state.
	podPred := predicate.TypedFuncs[*corev1.Pod]{
		CreateFunc: func(e ctrlevent.TypedCreateEvent[*corev1.Pod]) bool { return has(e.Object) },
		UpdateFunc: func(e ctrlevent.TypedUpdateEvent[*corev1.Pod]) bool {
			o, n := e.ObjectOld, e.ObjectNew
			return (has(o) || has(n)) && (o.Annotations[mirrorv1alpha1.AutoMirrorAnnotation] != n.Annotations[mirrorv1alpha1.AutoMirrorAnnotation] ||
				!slices.Equal(podImages(o), podImages(n)) || o.DeletionTimestamp.IsZero() != n.DeletionTimestamp.IsZero())
		},
		DeleteFunc:  func(e ctrlevent.TypedDeleteEvent[*corev1.Pod]) bool { return has(e.Object) },
		GenericFunc: func(ctrlevent.TypedGenericEvent[*corev1.Pod]) bool { return false },
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
	// The conditions that become pod Events, as one comparable string.
	relayed := func(m *mirrorv1alpha1.ArtifactMirror) string {
		var out strings.Builder
		for _, t := range []string{ConditionReady, ConditionSynced, ConditionRescanned, ConditionVulnerabilityGate} {
			if c := meta.FindStatusCondition(m.Status.Conditions, t); c != nil {
				fmt.Fprintf(&out, "%s=%s/%s/%s;", t, c.Status, c.Reason, c.Message)
			}
		}
		for _, f := range m.Status.Findings {
			fmt.Fprintf(&out, "%s=%s/%s/%s;", f.Tag, f.Verdict, f.Outcome, f.Digest)
		}
		for _, v := range m.Status.Vulnerable {
			fmt.Fprintf(&out, "rescan:%s=%s/%s;", v.Tag, v.Action, v.Digest)
		}
		return out.String()
	}
	isGenerated := func(o client.Object) bool { return o.GetLabels()[mirrorv1alpha1.LabelGenerated] == trueValue }
	mirrorPred := predicate.Funcs{
		CreateFunc: func(e ctrlevent.CreateEvent) bool { return isGenerated(e.Object) },
		UpdateFunc: func(e ctrlevent.UpdateEvent) bool {
			o, n := e.ObjectOld.(*mirrorv1alpha1.ArtifactMirror), e.ObjectNew.(*mirrorv1alpha1.ArtifactMirror)
			return isGenerated(n) && (o.Generation != n.Generation || relayed(o) != relayed(n))
		},
		DeleteFunc:  func(e ctrlevent.DeleteEvent) bool { return isGenerated(e.Object) },
		GenericFunc: func(ctrlevent.GenericEvent) bool { return false },
	}
	// Targets matter when the spec, their readiness or their scanner
	// state changes.
	scannerState := func(t *mirrorv1alpha1.ClusterMirrorTarget) string {
		if c := meta.FindStatusCondition(t.Status.Conditions, ConditionScannerReady); c != nil {
			return string(c.Status) + c.Reason + c.Message
		}
		return ""
	}
	targetPred := predicate.Funcs{
		UpdateFunc: func(e ctrlevent.UpdateEvent) bool {
			o, n := e.ObjectOld.(*mirrorv1alpha1.ClusterMirrorTarget), e.ObjectNew.(*mirrorv1alpha1.ClusterMirrorTarget)
			return o.Generation != n.Generation ||
				meta.IsStatusConditionTrue(o.Status.Conditions, ConditionReady) != meta.IsStatusConditionTrue(n.Status.Conditions, ConditionReady) ||
				scannerState(o) != scannerState(n)
		},
		GenericFunc: func(ctrlevent.GenericEvent) bool { return false },
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("automirror").
		WatchesRawSource(source.Kind(podCache, &corev1.Pod{}, &handler.TypedEnqueueRequestForObject[*corev1.Pod]{}, podPred)).
		Watches(&mirrorv1alpha1.ArtifactMirror{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				return podsOf(ctx, o.(*mirrorv1alpha1.ArtifactMirror).Spec.TargetRef, client.InNamespace(o.GetNamespace()))
			}), builder.WithPredicates(mirrorPred)).
		Watches(&mirrorv1alpha1.ClusterMirrorTarget{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				return podsOf(ctx, o.GetName())
			}), builder.WithPredicates(targetPred)).
		Complete(r)
}
