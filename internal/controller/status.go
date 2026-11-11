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
	maxErrorLen = 1024
	// exitCrashed is the Go runtime exit code for an unrecovered crash.
	exitCrashed = 2
	// jobBackoffLimit and jobDeadlineSeconds bound each sync Job.
	jobBackoffLimit    = 2
	jobDeadlineSeconds = 3600
	// maxErrorTags caps the tags named in a summary of several errors.
	maxErrorTags = 10
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
		if j.Annotations == nil {
			j.Annotations = map[string]string{}
		}
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
	if rep != nil && !rescan {
		prunedEvents(ev, rep.Pruned)
	}
	if rep != nil && !rescan && rep.Selection != nil {
		sel := rep.Selection
		selectedTags.WithLabelValues(m.Namespace, m.Name).Set(float64(sel.Selected))
		if sel.Missing > 0 {
			ev.add(corev1.EventTypeWarning, ReasonTagNotFound, action, "explicit tags not found upstream: "+missingList(sel))
		}
	}
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
	var repErr error
	if term != nil {
		if rep, repErr = syncspec.ParseReport(term.Message); repErr == nil {
			repErr = checkPruned(m, rep)
		}
	}
	switch {
	case term == nil:
		cond.Reason = ReasonCrashed
		cond.Message = fmt.Sprintf("Job %s ended without a sync result (%s)", job.Name, jobEndReason(done.Reason))
		return cond, nil
	case term.ExitCode == exitCrashed || repErr != nil:
		cond.Reason = ReasonCrashed
		cond.Message = fmt.Sprintf("Job %s exited with code %d", job.Name, term.ExitCode)
		if repErr != nil {
			cond.Message += ": " + repErr.Error()
		}
	case term.ExitCode == syncspec.ExitOK && !rescan && rep.Selection != nil && rep.Selection.Selected == 0:
		// Exit 0, so the Job is not retried, but the mirror is not in sync.
		cond.Reason = ReasonNoTagsSelected
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
	if repErr != nil {
		return cond, nil
	}
	return applyReport(m, cond, rep, rescan)
}

// applyReport records the synced and owned tags of a parsed report on the
// mirror and completes the condition message.
func applyReport(m *mirrorv1alpha1.ArtifactMirror, cond metav1.Condition, rep syncspec.Report, rescan bool) (metav1.Condition, *syncspec.Report) {
	synced := rep.Synced
	if len(synced) > maxSynced {
		synced, rep.Truncated = synced[:maxSynced], true
		rep.Synced = synced
	}
	m.Status.Synced = make([]mirrorv1alpha1.SyncedTag, 0, len(synced))
	for _, s := range synced {
		m.Status.Synced = append(m.Status.Synced, mirrorv1alpha1.SyncedTag{Tag: s.Tag, Digest: s.Digest})
	}
	if rep.Truncated && cond.Status == metav1.ConditionTrue {
		cond.Reason = ReasonTruncated
	}
	var ownedCut bool
	if !rescan {
		m.Status.Owned, ownedCut = mergeOwned(m.Status.Owned, rep)
	}
	if rescan && cond.Status != metav1.ConditionTrue {
		cond.Message = clauses(cond.Message, "rescan failed: "+summary(rep, false))
		return cond, &rep
	}
	var note string
	if sel := rep.Selection; !rescan && sel != nil && (sel.Selected == 0 || sel.Missing > 0) {
		note = selectionNote(sel)
	}
	var owned string
	if ownedCut {
		owned = fmt.Sprintf("owned list truncated to %d tags, the oldest are never pruned", maxOwned)
	}
	cond.Message = clauses(cond.Message, note, summary(rep, cond.Status == metav1.ConditionTrue), owned)
	return cond, &rep
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

// jobEndReason explains why a Job ended without a sync result.
func jobEndReason(reason string) string {
	switch reason {
	case batchv1.JobReasonDeadlineExceeded:
		return fmt.Sprintf("%s: the Job ran longer than its %d-minute deadline; select fewer tags, for example with tags.keepLatest, so one run copies less",
			reason, jobDeadlineSeconds/60)
	case batchv1.JobReasonBackoffLimitExceeded:
		return fmt.Sprintf("%s: the sync pod failed %d times without writing a result; its log shows why", reason, jobBackoffLimit+1)
	}
	return cmp.Or(reason, "no reason given")
}

// clauses joins the non-empty parts with "; ".
func clauses(parts ...string) string {
	return strings.Join(slices.DeleteFunc(parts, func(p string) bool { return p == "" }), "; ")
}

// summary describes a report in one line. A successful run keeps all four
// counters, so the healthy message always reads the same; a failed one
// keeps the non-zero counters only, so the error comes first. Sync errors
// never hold secrets (threat model T8); they are still cut and cleaned
// since the Job is not trusted.
func summary(r syncspec.Report, ok bool) string {
	var counts []string
	for i, c := range []struct {
		n      int
		format string
	}{
		{r.Copied, "copied %d"}, {r.Skipped, "skipped %d"}, {r.Mutated, "mutated %d"}, {r.Failed, "failed %d"},
		{r.Blocked, "blocked %d by the vulnerability gate"}, {len(r.Pruned), "pruned %d"},
	} {
		if c.n > 0 || ok && i < 4 {
			counts = append(counts, fmt.Sprintf(c.format, c.n))
		}
	}
	var truncated string
	if r.Truncated {
		truncated = fmt.Sprintf("synced list truncated to %d tags", min(len(r.Synced), maxSynced))
	}
	return clauses(strings.Join(counts, ", "), truncated, errorsNote(r))
}

// errorsNote quotes the first error and, for several, counts them and
// names the tags they belong to.
func errorsNote(r syncspec.Report) string {
	if len(r.Errors) == 0 {
		return ""
	}
	first := strings.ToValidUTF8(r.Errors[0], "?")
	if c := cut(first, maxErrorLen); c != first {
		first = c + "..."
	}
	n := max(len(r.Errors), r.Failed)
	s := "1 error: " + first
	if n > 1 {
		s = fmt.Sprintf("%d errors%s, first: %s", n, errorTags(r.Errors, n), first)
	}
	if r.ErrorsTruncated {
		s += "; the sync Job cut the error list, its pod log has every error"
	}
	return s
}

// errorTags names the tags of per-tag errors ("<tag>: <message>") out of
// n errors in all.
func errorTags(errs []string, n int) string {
	var tags []string
	for _, e := range errs {
		if t, _, ok := strings.Cut(e, ": "); ok && syncspec.ValidTag(t) && len(tags) < maxErrorTags {
			tags = append(tags, t)
		}
	}
	if len(tags) == 0 {
		return ""
	}
	s := " in tags " + strings.Join(tags, ", ")
	if more := n - len(tags); more > 0 {
		s += fmt.Sprintf(" and %d more", more)
	}
	return s
}

// selectionNote explains an empty selection or missing explicit tags.
func selectionNote(sel *syncspec.Selection) string {
	var s []string
	if sel.Selected == 0 {
		var why []string
		for _, c := range []struct {
			n    int
			text string
		}{
			{sel.Filtered, "%d removed by tags.include/tags.exclude"},
			{sel.NotSemver, "%d not semver (skipped by tags.semverRange)"},
			{sel.OutOfRange, "%d outside tags.semverRange"},
			{sel.Prerelease, "%d " + plural(sel.Prerelease, "prerelease") + " skipped (set tags.allowPrerelease: true to keep prereleases)"},
			{sel.Trimmed, "%d dropped by tags.keepLatest"},
		} {
			if c.n > 0 {
				why = append(why, fmt.Sprintf(c.text, c.n))
			}
		}
		switch {
		case sel.Listed == 0:
			s = append(s, "no tags selected: the source repository lists no tags")
		case len(why) == 0:
			s = append(s, fmt.Sprintf("no tags selected from %d listed", sel.Listed))
		default:
			s = append(s, fmt.Sprintf("no tags selected from %d listed: %s", sel.Listed, strings.Join(why, ", ")))
		}
	}
	if sel.Missing > 0 {
		s = append(s, "tags.tags not found upstream: "+missingList(sel))
	}
	return clauses(s...)
}

// plural adds an "s" to noun unless n is 1.
func plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}

// missingList names the missing explicit tags. The names come from the
// Job, so they are cleaned and cut like a sync error.
func missingList(sel *syncspec.Selection) string {
	names := make([]string, 0, len(sel.MissingTags))
	for _, t := range sel.MissingTags {
		names = append(names, cut(strings.ToValidUTF8(t, "?"), maxErrorLen))
	}
	out := strings.Join(names, ", ")
	if more := sel.Missing - len(names); more > 0 {
		out += fmt.Sprintf(" and %d more", more)
	}
	return out
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
