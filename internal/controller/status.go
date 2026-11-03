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
	"strings"
	"unicode/utf8"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

const (
	// maxSynced caps status.synced, as the CRD schema does.
	maxSynced = 200
	// maxErrorLen caps a sync error quoted in a condition or Event.
	maxErrorLen = 256
	// exitCrashed is the Go runtime exit code for an unrecovered crash.
	exitCrashed = 2
)

// +kubebuilder:rbac:groups=batch,namespace=system,resources=jobs,verbs=get;list;watch;create
// +kubebuilder:rbac:groups="",namespace=system,resources=pods,verbs=get;list;watch

// syncStatus records the result of the most recent finished Job of m. The
// termination message is untrusted: it only fills in status and is never
// used to decide what a mirror may do (threat model T12).
func (r *ArtifactMirrorReconciler) syncStatus(ctx context.Context, m *mirrorv1alpha1.ArtifactMirror, ev *pending) error {
	var jobs batchv1.JobList
	if err := r.List(ctx, &jobs, client.InNamespace(r.Namespace),
		client.MatchingLabels{LabelMirror: mirrorHash(m.Namespace, m.Name)}); err != nil {
		return err
	}
	trackSyncStart(m, jobs.Items)
	job, done := latestFinished(jobs.Items, m)
	last := m.Status.LastSyncTime
	if job == nil || last != nil && done.LastTransitionTime.Before(last) {
		return nil
	}
	isNew := last == nil || !last.Equal(&done.LastTransitionTime)
	term, err := r.termination(ctx, job)
	if err != nil {
		return err
	}
	if term == nil && !isNew {
		// The pod is gone; keep what was read while it existed.
		return nil
	}

	cond := applyResult(m, job, done, term)
	m.Status.LastSyncTime = &done.LastTransitionTime
	meta.SetStatusCondition(&m.Status.Conditions, cond)
	if isNew {
		eventType := corev1.EventTypeWarning
		if cond.Status == metav1.ConditionTrue {
			eventType = corev1.EventTypeNormal
		}
		ev.add(eventType, cond.Reason, "Sync", cond.Message)
	}
	return nil
}

// latestFinished returns the most recently finished Job of m that is not
// being deleted, and its finished condition.
func latestFinished(jobs []batchv1.Job, m *mirrorv1alpha1.ArtifactMirror) (*batchv1.Job, *batchv1.JobCondition) {
	var job *batchv1.Job
	var done *batchv1.JobCondition
	for i := range jobs {
		j := &jobs[i]
		c := finished(j)
		if c == nil || !j.DeletionTimestamp.IsZero() ||
			j.Annotations[AnnotationMirrorNamespace] != m.Namespace || j.Annotations[AnnotationMirrorName] != m.Name {
			continue
		}
		if job == nil || done.LastTransitionTime.Before(&c.LastTransitionTime) ||
			done.LastTransitionTime.Equal(&c.LastTransitionTime) && j.Name > job.Name {
			job, done = j, c
		}
	}
	return job, done
}

// applyResult sets synced and lastSuccessfulSyncTime from the result of a
// finished Job and returns its Synced condition. term is nil when the
// sync container left no result.
func applyResult(m *mirrorv1alpha1.ArtifactMirror, job *batchv1.Job, done *batchv1.JobCondition, term *corev1.ContainerStateTerminated) metav1.Condition {
	cond := metav1.Condition{Type: ConditionSynced, Status: metav1.ConditionFalse, ObservedGeneration: m.Generation}
	var rep syncspec.Report
	repErr := fmt.Errorf("no sync container result: %s", done.Reason)
	if term != nil {
		rep, repErr = syncspec.ParseReport(term.Message)
	}
	switch {
	case term == nil || term.ExitCode == exitCrashed || repErr != nil:
		cond.Reason = ReasonCrashed
		code := "unknown"
		if term != nil {
			code = fmt.Sprint(term.ExitCode)
		}
		cond.Message = fmt.Sprintf("Job %s exited with code %s", job.Name, code)
		if repErr != nil {
			cond.Message += ": " + repErr.Error()
		}
	case term.ExitCode == syncspec.ExitOK:
		cond.Status, cond.Reason = metav1.ConditionTrue, ReasonSynced
		m.Status.LastSuccessfulSyncTime = &done.LastTransitionTime
	case term.ExitCode == syncspec.ExitConfig:
		cond.Reason = ReasonConfigRejected
	default:
		cond.Reason = ReasonSyncFailed
	}
	if repErr == nil {
		synced := rep.Synced
		if len(synced) > maxSynced {
			synced, rep.Truncated = synced[:maxSynced], true
		}
		m.Status.Synced = make([]mirrorv1alpha1.SyncedTag, 0, len(synced))
		for _, s := range synced {
			m.Status.Synced = append(m.Status.Synced, mirrorv1alpha1.SyncedTag{Tag: s.Tag, Digest: s.Digest})
		}
		if rep.Truncated && cond.Status == metav1.ConditionTrue {
			cond.Reason = ReasonTruncated
		}
		cond.Message = strings.TrimPrefix(cond.Message+"; ", "; ") + summary(rep)
	}
	return cond
}

// finished returns the Complete or Failed condition of a finished Job.
func finished(j *batchv1.Job) *batchv1.JobCondition {
	for i, c := range j.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) && c.Status == corev1.ConditionTrue {
			return &j.Status.Conditions[i]
		}
	}
	return nil
}

// termination returns the latest terminated state of the sync container
// among the pods the Job controls, or nil.
func (r *ArtifactMirrorReconciler) termination(ctx context.Context, job *batchv1.Job) (*corev1.ContainerStateTerminated, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(r.Namespace),
		client.MatchingLabels{batchv1.JobNameLabel: job.Name}); err != nil {
		return nil, err
	}
	var out *corev1.ContainerStateTerminated
	for i := range pods.Items {
		if !metav1.IsControlledBy(&pods.Items[i], job) {
			continue
		}
		for _, s := range pods.Items[i].Status.ContainerStatuses {
			if t := s.State.Terminated; s.Name == syncContainer && t != nil &&
				(out == nil || out.FinishedAt.Before(&t.FinishedAt)) {
				out = t
			}
		}
	}
	return out, nil
}

// summary describes a report in one line. Sync errors never hold secrets
// (threat model T8); they are still cut and cleaned since the Job is not
// trusted.
func summary(r syncspec.Report) string {
	s := fmt.Sprintf("copied %d, skipped %d, mutated %d, failed %d", r.Copied, r.Skipped, r.Mutated, r.Failed)
	if r.Truncated {
		s += fmt.Sprintf("; synced list truncated to %d tags", min(len(r.Synced), maxSynced))
	}
	if len(r.Errors) > 0 {
		e := strings.ToValidUTF8(r.Errors[0], "?")
		if c := cut(e, maxErrorLen); c != e {
			e = c + "..."
		}
		s += fmt.Sprintf("; %d errors, first: %s", len(r.Errors), e)
	}
	return s
}

// cut shortens s to at most n bytes without splitting a UTF-8 sequence.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
