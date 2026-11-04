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
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

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

// +kubebuilder:rbac:groups=batch,namespace=system,resources=jobs,verbs=get;list;watch;create;patch;delete
// +kubebuilder:rbac:groups="",namespace=system,resources=pods,verbs=get;list;watch

// AnnotationApplied marks a finished Job whose result is in the status of
// its mirror, so it is applied once.
const AnnotationApplied = "tagwarden.dev/result-applied"

// syncStatus records the result of every finished Job of m that is not
// marked applied, in finish order, a sync before a re-scan that finished
// in the same second: a sync and a re-scan can finish between two
// reconciles, and neither may hide the other. It appends the Jobs it
// recorded to applied; markApplied marks them once the status is saved.
// The termination message is untrusted: it only fills in status and is
// never used to decide what a mirror may do (threat model T12).
// For a gated mirror it also records the gate fields of the report.
func (r *ArtifactMirrorReconciler) syncStatus(ctx context.Context, m *mirrorv1alpha1.ArtifactMirror, gated bool, ev *pending, applied *[]*batchv1.Job) error {
	var jobs batchv1.JobList
	if err := r.List(ctx, &jobs, client.InNamespace(r.Namespace),
		client.MatchingLabels{LabelMirror: mirrorHash(m.Namespace, m.Name)}); err != nil {
		return err
	}
	trackSyncStart(m, jobs.Items)
	for _, f := range finishedJobs(jobs.Items, m) {
		if _, done := f.job.Annotations[AnnotationApplied]; done {
			continue
		}
		// A sync that finished before the one recorded is stale.
		if last := m.Status.LastSyncTime; rank(f.job) == 0 && last != nil && f.done.LastTransitionTime.Before(last) {
			*applied = append(*applied, f.job)
			continue
		}
		term, err := r.termination(ctx, f.job)
		if err != nil {
			return err
		}
		recordJob(m, f.job, f.done, term, gated, ev)
		*applied = append(*applied, f.job)
	}
	return nil
}

// markApplied annotates Jobs whose result was saved. A failure only means
// the Job is applied again, with the same outcome.
func (r *ArtifactMirrorReconciler) markApplied(ctx context.Context, jobs []*batchv1.Job) {
	for _, j := range jobs {
		patch := client.MergeFrom(j.DeepCopy())
		j.Annotations[AnnotationApplied] = "true"
		if err := r.Patch(ctx, j, patch); err != nil && !apierrors.IsNotFound(err) {
			log.FromContext(ctx).Error(err, "marking Job applied", "job", j.Name)
		}
	}
}

// recordJob applies the result of one finished Job to the status of m. A
// re-scan, marked by the controller-set trigger annotation, never touches
// the Synced condition or the last successful sync time.
func recordJob(m *mirrorv1alpha1.ArtifactMirror, job *batchv1.Job, done *batchv1.JobCondition, term *corev1.ContainerStateTerminated, gated bool, ev *pending) {
	rescan := job.Annotations[AnnotationTrigger] == TriggerRescan
	cond, rep := applyResult(m, job, done, term, rescan)
	action := "Rescan"
	if !rescan {
		m.Status.LastSyncTime = &done.LastTransitionTime
		action = "Sync"
	}
	meta.SetStatusCondition(&m.Status.Conditions, cond)
	eventType := corev1.EventTypeWarning
	if cond.Status == metav1.ConditionTrue {
		eventType = corev1.EventTypeNormal
	}
	ev.add(eventType, cond.Reason, action, cond.Message)
	// A report that claims another kind than the Job's only fills the condition.
	if gated && rep != nil && rep.V == syncspec.ReportVersionGate && rep.Rescan == rescan {
		start := job.CreationTimestamp.Time
		if job.Status.StartTime != nil {
			start = job.Status.StartTime.Time
		}
		apply := applyGate
		if rescan {
			apply = applyRescan
		}
		apply(m, rep, term.ExitCode == syncspec.ExitOK, true, start, ev)
	}
}

func rank(j *batchv1.Job) int {
	if j.Annotations[AnnotationTrigger] == TriggerRescan {
		return 1
	}
	return 0
}

type finishedJob struct {
	job  *batchv1.Job
	done *batchv1.JobCondition
}

// finishedJobs returns the finished Jobs of m that are not being deleted,
// oldest finish first. The time has a resolution of a second, so a tie
// puts a sync before a re-scan: the re-scan read the target after it, and
// its untag must be the last word. Remaining ties go by name.
func finishedJobs(jobs []batchv1.Job, m *mirrorv1alpha1.ArtifactMirror) []finishedJob {
	var out []finishedJob
	for i := range jobs {
		j := &jobs[i]
		c := finished(j)
		if c == nil || !j.DeletionTimestamp.IsZero() ||
			j.Annotations[AnnotationMirrorNamespace] != m.Namespace || j.Annotations[AnnotationMirrorName] != m.Name {
			continue
		}
		out = append(out, finishedJob{j, c})
	}
	slices.SortFunc(out, func(a, b finishedJob) int {
		return cmp.Or(a.done.LastTransitionTime.Compare(b.done.LastTransitionTime.Time), cmp.Compare(rank(a.job), rank(b.job)), strings.Compare(a.job.Name, b.job.Name))
	})
	return out
}

// applyResult sets synced and, for a sync, lastSuccessfulSyncTime from the
// result of a finished Job and returns its Synced (re-scan: Rescanned)
// condition and the parsed report, or nil. term is nil when the sync
// container left no result.
func applyResult(m *mirrorv1alpha1.ArtifactMirror, job *batchv1.Job, done *batchv1.JobCondition, term *corev1.ContainerStateTerminated, rescan bool) (metav1.Condition, *syncspec.Report) {
	cond := metav1.Condition{Type: ConditionSynced, Status: metav1.ConditionFalse, ObservedGeneration: m.Generation}
	if rescan {
		cond.Type = ConditionRescanned
	}
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
		if rescan {
			cond.Reason = ReasonRescanned
		} else {
			m.Status.LastSuccessfulSyncTime = &done.LastTransitionTime
		}
	case term.ExitCode == syncspec.ExitConfig && (rep.Gate == syncspec.GateDBStale || rep.Gate == syncspec.GateVersionMismatch):
		// A gated Job blocked by a stale DB or a scanner version mismatch
		// exits 3 so it is not retried; the platform has to act, not the
		// mirror's owner.
		cond.Reason = rep.Gate
	case term.ExitCode == syncspec.ExitConfig:
		cond.Reason = ReasonConfigRejected
	case rescan:
		cond.Reason = ReasonRescanFailed
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
		if rescan && cond.Status != metav1.ConditionTrue {
			cond.Message = strings.TrimPrefix(cond.Message+"; ", "; ") + "rescan failed: " + summary(rep)
			return cond, &rep
		}
		cond.Message = strings.TrimPrefix(cond.Message+"; ", "; ") + summary(rep)
		return cond, &rep
	}
	return cond, nil
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
