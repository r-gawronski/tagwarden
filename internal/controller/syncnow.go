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
	"fmt"
	"maps"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const (
	// AnnotationTrigger is TriggerManual on a sync Job created for a
	// sync-now request.
	AnnotationTrigger = "tagwarden.dev/trigger"
	TriggerManual     = "manual"

	// maxRequestValue caps the request value kept in status, as the CRD
	// schema does.
	maxRequestValue = 256
)

// manualJobName names the sync Job of a request after the CronJob and a
// hash of the value, so one request never starts two Jobs.
func manualJobName(m *mirrorv1alpha1.ArtifactMirror, value string) string {
	sum := sha256.Sum256([]byte(value))
	return objectName(m) + "-manual-" + hex.EncodeToString(sum[:])[:10]
}

// pendingRequest returns the sync-now value of m that still needs
// handling, cut to maxRequestValue bytes, or "".
func pendingRequest(m *mirrorv1alpha1.ArtifactMirror) string {
	v := cut(m.Annotations[mirrorv1alpha1.SyncNowAnnotation], maxRequestValue)
	if r := m.Status.LastSyncRequest; r != nil && r.Value == v && r.Result != mirrorv1alpha1.SyncRequestDeferred {
		return ""
	}
	return v
}

// recordRequest sets status.lastSyncRequest and adds an Event when the
// result or message changes.
func recordRequest(m *mirrorv1alpha1.ArtifactMirror, ev *pending, value string, result mirrorv1alpha1.SyncRequestResult, msg string) {
	if r := m.Status.LastSyncRequest; r != nil && r.Value == value && r.Result == result && r.Message == msg {
		return
	}
	m.Status.LastSyncRequest = &mirrorv1alpha1.SyncRequest{Value: value, HandledAt: metav1.Now(), Result: result, Message: msg}
	switch result {
	case mirrorv1alpha1.SyncRequestStarted:
		ev.add(corev1.EventTypeNormal, "SyncRequested", "SyncNow", msg)
	case mirrorv1alpha1.SyncRequestDeferred:
		ev.add(corev1.EventTypeNormal, "SyncDeferred", "SyncNow", msg)
	default:
		ev.add(corev1.EventTypeWarning, "SyncRefused", "SyncNow", msg)
	}
}

// syncNow handles a sync-now request of a Ready mirror: it starts a Job
// from the CronJob template unless a Job of the mirror runs or the last
// one started within limits.minSyncInterval of the target. A deferred
// request is retried when the running Job finishes or the interval ends.
func (r *ArtifactMirrorReconciler) syncNow(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror,
	cj *batchv1.CronJob, ev *pending) (ctrl.Result, error) {
	value := pendingRequest(m)
	if value == "" {
		return ctrl.Result{}, nil
	}
	if m.Spec.Suspend {
		recordRequest(m, ev, value, mirrorv1alpha1.SyncRequestRefused, "ArtifactMirror is suspended")
		return ctrl.Result{}, nil
	}
	// The cache can miss a Job created moments ago, by this controller or
	// the CronJob controller, so read Jobs from the API server.
	var jobs batchv1.JobList
	if err := r.APIReader.List(ctx, &jobs, client.InNamespace(r.Namespace),
		client.MatchingLabels{LabelMirror: mirrorHash(m.Namespace, m.Name)}); err != nil {
		return ctrl.Result{}, err
	}
	name := manualJobName(m, value)
	last := m.Status.LastSyncStartTime
	for i := range jobs.Items {
		j := &jobs.Items[i]
		if !ownedBy(j, m) {
			continue
		}
		if j.Name == name {
			if finished(j) != nil {
				recordRequest(m, ev, value, mirrorv1alpha1.SyncRequestRefused,
					fmt.Sprintf("value already used by Job %s/%s; set a new value", j.Namespace, j.Name))
			} else {
				// Started before, but the status update was lost.
				recordRequest(m, ev, value, mirrorv1alpha1.SyncRequestStarted, fmt.Sprintf("Created Job %s/%s", j.Namespace, j.Name))
			}
			return ctrl.Result{}, nil
		}
		if finished(j) == nil && j.DeletionTimestamp.IsZero() {
			recordRequest(m, ev, value, mirrorv1alpha1.SyncRequestDeferred, fmt.Sprintf("Job %s/%s is running", j.Namespace, j.Name))
			return ctrl.Result{}, nil
		}
		start := j.CreationTimestamp
		if j.Status.StartTime != nil {
			start = *j.Status.StartTime
		}
		if last == nil || last.Before(&start) {
			last = &start
		}
	}
	interval := minSyncInterval(t)
	if last != nil {
		next := last.Add(interval)
		if wait := time.Until(next); wait > 0 {
			recordRequest(m, ev, value, mirrorv1alpha1.SyncRequestDeferred, fmt.Sprintf(
				"minSyncInterval %s of ClusterMirrorTarget %s allows the next sync at %s", interval, t.Name, next.UTC().Format(time.RFC3339)))
			return ctrl.Result{RequeueAfter: wait}, nil
		}
	}

	tmpl := cj.Spec.JobTemplate
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: cj.Namespace,
			Labels:      maps.Clone(tmpl.Labels),
			Annotations: maps.Clone(tmpl.Annotations),
			// As with kubectl create job --from=cronjob, the CronJob
			// controls the Job: its history limits and garbage collection
			// cover it. The CronJob controller does not add it to
			// status.active, so concurrencyPolicy does not see it, and it
			// records an UnexpectedJob Event while the Job runs.
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cj, batchv1.SchemeGroupVersion.WithKind("CronJob"))},
		},
		Spec: *tmpl.Spec.DeepCopy(),
	}
	if job.Annotations == nil {
		job.Annotations = map[string]string{}
	}
	job.Annotations[AnnotationTrigger] = TriggerManual
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return ctrl.Result{}, err
	}
	m.Status.LastSyncStartTime = new(metav1.Now())
	recordRequest(m, ev, value, mirrorv1alpha1.SyncRequestStarted, fmt.Sprintf("Created Job %s/%s", job.Namespace, job.Name))
	return ctrl.Result{}, nil
}

// trackSyncStart moves status.lastSyncStartTime to the latest start of a
// sync Job of m. Jobs that have not started yet do not count; a request
// sets the time when it creates its Job.
func trackSyncStart(m *mirrorv1alpha1.ArtifactMirror, jobs []batchv1.Job) {
	for i := range jobs {
		s := jobs[i].Status.StartTime
		if s != nil && ownedBy(&jobs[i], m) && (m.Status.LastSyncStartTime == nil || m.Status.LastSyncStartTime.Before(s)) {
			m.Status.LastSyncStartTime = s.DeepCopy()
		}
	}
}
