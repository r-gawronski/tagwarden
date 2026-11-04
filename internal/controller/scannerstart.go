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
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

// DefaultScannerStartTimeout is how long the scanner sidecar of a gated
// sync pod may fail to start before the Job is deleted.
const DefaultScannerStartTimeout = 5 * time.Minute

// scannerStartPrefix starts the VulnerabilityGate message of a scanner
// that did not start; the pod relay recognises it.
const scannerStartPrefix = "scanner sidecar did not start"

// scannerStartReasons are the waiting reasons of a sidecar that will not
// start without help. Anything else (such as PodInitializing) is normal.
var scannerStartReasons = map[string]bool{
	"ErrImagePull": true, "ImagePullBackOff": true, "InvalidImageName": true,
	"CreateContainerConfigError": true, "CrashLoopBackOff": true,
}

// scannerWaiting returns the waiting reason of the scanner sidecar of
// pod when it is one of scannerStartReasons and the sync container cannot
// have started (the pod is Pending). A sidecar that dies in the middle of a
// run is a scan error, reported by the Job itself.
func scannerWaiting(pod *corev1.Pod) string {
	if pod.Status.Phase != corev1.PodPending {
		return ""
	}
	for _, s := range pod.Status.InitContainerStatuses {
		if w := s.State.Waiting; s.Name == scannerContainer && w != nil && scannerStartReasons[w.Reason] {
			return w.Reason
		}
	}
	return ""
}

// scannerStartFailure is scannerWaiting once the pod is older than grace.
// The kubelet does not record when a container began waiting, so the pod's
// age stands in.
func scannerStartFailure(pod *corev1.Pod, now time.Time, grace time.Duration) string {
	if now.Sub(pod.CreationTimestamp.Time) < grace {
		return ""
	}
	return scannerWaiting(pod)
}

// scannerStart deletes the unfinished Jobs of m whose scanner sidecar does
// not start, so the CronJob retries on its next schedule, and says so on
// the mirror, its target and (through the mirror) the pods that use it.
// Nothing was copied by such a run, so this stays fail-closed. It returns
// when to look again while a sidecar is failing within its grace period.
func (r *ArtifactMirrorReconciler) scannerStart(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror, ev *pending) (time.Duration, error) {
	grace := r.ScannerStartTimeout
	if grace <= 0 {
		grace = DefaultScannerStartTimeout
	}
	var jobs batchv1.JobList
	if err := r.List(ctx, &jobs, client.InNamespace(r.Namespace),
		client.MatchingLabels{LabelMirror: mirrorHash(m.Namespace, m.Name)}); err != nil {
		return 0, err
	}
	var requeue time.Duration
	for i := range jobs.Items {
		job := &jobs.Items[i]
		if finished(job) != nil || !job.DeletionTimestamp.IsZero() ||
			job.Annotations[AnnotationMirrorNamespace] != m.Namespace || job.Annotations[AnnotationMirrorName] != m.Name {
			continue
		}
		var pods corev1.PodList
		if err := r.List(ctx, &pods, client.InNamespace(r.Namespace),
			client.MatchingLabels{batchv1.JobNameLabel: job.Name}); err != nil {
			return 0, err
		}
		for j := range pods.Items {
			pod := &pods.Items[j]
			if !metav1.IsControlledBy(pod, job) {
				continue
			}
			reason := scannerStartFailure(pod, time.Now(), grace)
			if reason == "" {
				if left := time.Until(pod.CreationTimestamp.Add(grace)); left > 0 && scannerWaiting(pod) != "" && (requeue == 0 || left < requeue) {
					requeue = left
				}
				continue
			}
			// The UID precondition and the NotFound check make this the
			// one reconcile that deletes the Job, so the Events are not
			// repeated.
			err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground),
				client.Preconditions{UID: &job.UID})
			if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
				break
			} else if err != nil {
				return 0, err
			}
			msg := fmt.Sprintf("%s (%s); sync Job deleted, nothing copied", scannerStartPrefix, reason)
			meta.SetStatusCondition(&m.Status.Conditions, metav1.Condition{Type: ConditionVulnerabilityGate, Status: metav1.ConditionFalse,
				Reason: ReasonScannerUnavailable, Message: msg, ObservedGeneration: m.Generation})
			ev.add(corev1.EventTypeWarning, ReasonScannerUnavailable, "Sync", msg)
			r.Recorder.Eventf(t, nil, corev1.EventTypeWarning, ReasonScannerUnavailable, "Sync", "%s", msg)
			scannerStartFailures.WithLabelValues(t.Name, reason).Inc()
			break
		}
	}
	return requeue, nil
}
