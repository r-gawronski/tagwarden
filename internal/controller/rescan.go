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
	"encoding/binary"
	"encoding/hex"
	"fmt"
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
	// TriggerRescan is the AnnotationTrigger value of a re-scan Job, which
	// runs the sync container with --rescan.
	TriggerRescan = "rescan"
	// ArgRescan is the fixed argument of a re-scan Job.
	ArgRescan = "--rescan"
	// maxRescansPerTarget caps the re-scan Jobs that run at once per
	// target, so they do not pile up on the single Trivy server replica.
	// ponytail: fixed; make it a target field if a large target falls behind.
	maxRescansPerTarget = 2
	// rescanRetry rechecks a re-scan deferred by the cap.
	rescanRetry = time.Minute
)

// rescanSuffix is "-rescan-" plus 10 hex characters.
const rescanSuffix = len("-rescan-") + 10

// nextRescan returns the first re-scan slot of m after base. The slots of
// a mirror are interval apart, at an offset taken from its namespace and
// name, so the re-scans of a target's mirrors spread over the interval
// instead of starting together.
func nextRescan(m *mirrorv1alpha1.ArtifactMirror, base time.Time, interval time.Duration) time.Time {
	sum := sha256.Sum256([]byte(m.Namespace + "/" + m.Name))
	phase := int64(binary.BigEndian.Uint64(sum[:8]) % uint64(interval)) //nolint:gosec // interval is positive
	k := (base.UnixNano()-phase)/int64(interval) + 1
	return time.Unix(0, phase+k*int64(interval))
}

// rescan starts a re-scan Job of a gated mirror with rescanInterval when
// its next slot after status.lastRescan (or, before the first re-scan,
// after the last successful sync, or the last sync that left tags) has come. Like a sync-now request it
// waits while a Job of the mirror runs; in addition at most
// maxRescansPerTarget re-scans of the target run at once. The Job comes
// from the CronJob template with the fixed argument --rescan.
func (r *ArtifactMirrorReconciler) rescan(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror,
	cj *batchv1.CronJob, ev *pending) (ctrl.Result, error) {
	g := gateOf(t)
	if g == nil || g.RescanInterval == nil || g.RescanInterval.Duration <= 0 || m.Spec.Suspend {
		return ctrl.Result{}, nil
	}
	interval := g.RescanInterval.Duration
	base := m.Status.LastRescan
	if base == nil {
		base = m.Status.LastSuccessfulSyncTime
	}
	if base == nil && len(m.Status.Synced) > 0 {
		// A partial sync left tags on the target.
		base = m.Status.LastSyncTime
	}
	if base == nil {
		// Nothing is on the target yet; the first sync judges every tag.
		return ctrl.Result{}, nil
	}
	due := nextRescan(m, base.Time, interval)
	if wait := time.Until(due); wait > 0 {
		return ctrl.Result{RequeueAfter: wait}, nil
	}
	// Read past the cache, like sync-now, so a Job created moments ago counts.
	var jobs batchv1.JobList
	if err := r.APIReader.List(ctx, &jobs, client.InNamespace(r.Namespace),
		client.MatchingLabels{LabelTarget: targetLabel(t.Name)}); err != nil {
		return ctrl.Result{}, err
	}
	running := 0
	for i := range jobs.Items {
		j := &jobs.Items[i]
		if finished(j) != nil || !j.DeletionTimestamp.IsZero() {
			continue
		}
		if ownedBy(j, m) {
			// Its end reconciles the mirror again.
			return ctrl.Result{}, nil
		}
		if j.Annotations[AnnotationTrigger] == TriggerRescan {
			running++
		}
	}
	if running >= maxRescansPerTarget {
		return ctrl.Result{RequeueAfter: rescanRetry}, nil
	}

	sum := sha256.Sum256([]byte(due.UTC().Format(time.RFC3339Nano)))
	job := jobFrom(cj, boundedName(m, 63-rescanSuffix)+"-rescan-"+hex.EncodeToString(sum[:])[:10], TriggerRescan)
	for i := range job.Spec.Template.Spec.Containers {
		if c := &job.Spec.Template.Spec.Containers[i]; c.Name == syncContainer {
			c.Args = append(c.Args, ArgRescan)
		}
	}
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return ctrl.Result{}, err
	}
	now := metav1.Now()
	m.Status.LastRescan = &now
	ev.add(corev1.EventTypeNormal, "RescanStarted", "Rescan", fmt.Sprintf("Created Job %s/%s", job.Namespace, job.Name))
	return ctrl.Result{RequeueAfter: time.Until(nextRescan(m, now.Time, interval))}, nil
}

// sooner merges two reconcile results: the shorter non-zero requeue wins.
func sooner(a, b ctrl.Result) ctrl.Result {
	if a.RequeueAfter == 0 || b.RequeueAfter != 0 && b.RequeueAfter < a.RequeueAfter {
		a.RequeueAfter = b.RequeueAfter
	}
	return a
}
