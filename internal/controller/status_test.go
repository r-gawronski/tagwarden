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
	"encoding/json"
	"slices"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

func finishedJobAt(name, trigger string, at time.Time) *batchv1.Job {
	j := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{
		AnnotationMirrorNamespace: "ns", AnnotationMirrorName: "m"}}}
	if trigger != "" {
		j.Annotations[AnnotationTrigger] = trigger
	}
	j.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(at)}}
	return j
}

func termination(t *testing.T, code int32, rep *syncspec.Report) *corev1.ContainerStateTerminated {
	t.Helper()
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	return &corev1.ContainerStateTerminated{ExitCode: code, Message: string(b)}
}

func TestRecordJobRescanLeavesSyncState(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name       string
		code       int32
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{"all scanned", syncspec.ExitOK, metav1.ConditionTrue, ReasonRescanned},
		{"scan errors fail the run", syncspec.ExitSyncFailed, metav1.ConditionFalse, ReasonSyncFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synced := metav1.NewTime(t0.Add(-time.Hour))
			m := &mirrorv1alpha1.ArtifactMirror{}
			m.Status.LastSuccessfulSyncTime = &synced
			meta.SetStatusCondition(&m.Status.Conditions, metav1.Condition{Type: ConditionSynced, Status: metav1.ConditionTrue, Reason: ReasonSynced})
			job := finishedJobAt("j", TriggerRescan, t0)
			var ev pending
			recordJob(m, job, finished(job), termination(t, tc.code, &syncspec.Report{V: syncspec.ReportVersion}), false, true, &ev)

			if c := meta.FindStatusCondition(m.Status.Conditions, ConditionRescanned); c == nil || c.Status != tc.wantStatus || c.Reason != tc.wantReason {
				t.Errorf("Rescanned %+v", c)
			}
			if c := meta.FindStatusCondition(m.Status.Conditions, ConditionSynced); c.Status != metav1.ConditionTrue || c.Reason != ReasonSynced {
				t.Errorf("Synced changed: %+v", c)
			}
			if !m.Status.LastSuccessfulSyncTime.Equal(&synced) {
				t.Errorf("lastSuccessfulSyncTime moved to %v", m.Status.LastSuccessfulSyncTime)
			}
			if len(ev) != 1 || ev[0].action != "Rescan" {
				t.Errorf("events %+v", ev)
			}
		})
	}
}

// A sync and a re-scan that finish between two reconciles are both applied,
// the sync first.
func TestRecordJobsSyncAndRescanTogether(t *testing.T) {
	const tag11 = "1.1"
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	m := &mirrorv1alpha1.ArtifactMirror{}
	m.Namespace, m.Name = "ns", "m"
	rescanJob, syncJob := finishedJobAt("b-rescan", TriggerRescan, t0.Add(time.Minute)), finishedJobAt("a-sync", "", t0)
	jobs := finishedJobs([]batchv1.Job{*rescanJob, *syncJob}, m)
	if len(jobs) != 2 || jobs[0].job.Name != "a-sync" {
		t.Fatalf("order %v", jobs)
	}
	reports := map[string]*corev1.ContainerStateTerminated{
		"a-sync": termination(t, syncspec.ExitOK, v2(fpA, syncspec.GateOK, []string{tag11, tag10}, []string{tag11, tag10})),
		"b-rescan": termination(t, syncspec.ExitOK, rescanReport(fpA, []string{tag10}, []string{tag11, tag10},
			rescanFinding(tag11, t0.Add(time.Minute), mirrorv1alpha1.VulnerableUntagged))),
	}
	var ev pending
	for _, f := range jobs {
		recordJob(m, f.job, f.done, reports[f.job.Name], true, true, &ev)
	}
	if len(m.Status.Vulnerable) != 1 || m.Status.Vulnerable[0].Action != mirrorv1alpha1.VulnerableUntagged {
		t.Errorf("vulnerable %+v", m.Status.Vulnerable)
	}
	if c := meta.FindStatusCondition(m.Status.Conditions, ConditionSynced); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Synced %+v", c)
	}
	if !meta.IsStatusConditionTrue(m.Status.Conditions, ConditionRescanned) {
		t.Error("Rescanned not set")
	}
	reasons := tagsOf(ev, func(e event) string { return e.reason })
	if !slices.Contains(reasons, reasonTagUntagged) {
		t.Errorf("events %v", reasons)
	}
}

func TestTrackSyncStartIgnoresRescan(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	m := &mirrorv1alpha1.ArtifactMirror{}
	m.Namespace, m.Name = "ns", "m"
	syncJob, rescanJob := finishedJobAt("s", "", t0), finishedJobAt("r", TriggerRescan, t0.Add(time.Hour))
	syncJob.Status.StartTime = &metav1.Time{Time: t0}
	rescanJob.Status.StartTime = &metav1.Time{Time: t0.Add(time.Hour)}
	trackSyncStart(m, []batchv1.Job{*syncJob, *rescanJob})
	if m.Status.LastSyncStartTime == nil || !m.Status.LastSyncStartTime.Time.Equal(t0) {
		t.Errorf("lastSyncStartTime %v, want %v", m.Status.LastSyncStartTime, t0)
	}
}

// A mirror whose sync failed in part has tags in status.synced but no
// successful sync; its re-scan still comes due.
func TestRescanBase(t *testing.T) {
	for _, tc := range []struct {
		name   string
		synced []mirrorv1alpha1.SyncedTag
		want   int
	}{
		{"tags on the target", []mirrorv1alpha1.SyncedTag{{Tag: tag10}}, 1},
		{"nothing synced", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg, m := gatedFixture(mirrorv1alpha1.VulnerabilityGate{Enabled: true, Action: mirrorv1alpha1.GateActionBlock,
				RescanInterval: &metav1.Duration{Duration: time.Hour}})
			old := metav1.NewTime(time.Now().Add(-48 * time.Hour))
			m.Status.Synced, m.Status.LastSyncTime = tc.synced, &old
			s := goldenScheme(t)
			if err := batchv1.AddToScheme(s); err != nil {
				t.Fatal(err)
			}
			c := fake.NewClientBuilder().WithScheme(s).Build()
			r := &ArtifactMirrorReconciler{Client: c, APIReader: c, Namespace: "ops"}
			cj := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "ops", Name: "cj", UID: "u"}}
			cj.Spec.JobTemplate.Spec.Template.Spec.Containers = []corev1.Container{{Name: syncContainer}}
			if _, err := r.rescan(context.Background(), tg, m, cj, &pending{}); err != nil {
				t.Fatal(err)
			}
			var jobs batchv1.JobList
			if err := c.List(context.Background(), &jobs); err != nil || len(jobs.Items) != tc.want {
				t.Fatalf("jobs %d, err %v, want %d", len(jobs.Items), err, tc.want)
			}
		})
	}
}
