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
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

const (
	syncName = "b-sync"
	opsNS    = "ops"
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
		{"scan errors fail the run", syncspec.ExitSyncFailed, metav1.ConditionFalse, ReasonRescanFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synced := metav1.NewTime(t0.Add(-time.Hour))
			m := &mirrorv1alpha1.ArtifactMirror{}
			m.Status.LastSuccessfulSyncTime = &synced
			meta.SetStatusCondition(&m.Status.Conditions, metav1.Condition{Type: ConditionSynced, Status: metav1.ConditionTrue, Reason: ReasonSynced})
			job := finishedJobAt("j", TriggerRescan, t0)
			var ev pending
			recordJob(m, job, finished(job), termination(t, tc.code, &syncspec.Report{V: syncspec.ReportVersion}), false, &ev)

			if c := meta.FindStatusCondition(m.Status.Conditions, ConditionRescanned); c == nil || c.Status != tc.wantStatus || c.Reason != tc.wantReason {
				t.Errorf("Rescanned %+v", c)
			}
			if c := meta.FindStatusCondition(m.Status.Conditions, ConditionSynced); c.Status != metav1.ConditionTrue || c.Reason != ReasonSynced {
				t.Errorf("Synced changed: %+v", c)
			}
			if !m.Status.LastSuccessfulSyncTime.Equal(&synced) {
				t.Errorf("lastSuccessfulSyncTime moved to %v", m.Status.LastSuccessfulSyncTime)
			}
			if c := meta.FindStatusCondition(m.Status.Conditions, ConditionRescanned); c.Status == metav1.ConditionFalse && !strings.Contains(c.Message, "rescan failed") {
				t.Errorf("message %q", c.Message)
			}
			if m.Status.LastSyncTime != nil {
				t.Errorf("lastSyncTime moved to %v", m.Status.LastSyncTime)
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
	// Same second: the sync still goes first although its name sorts last.
	rescanJob, syncJob := finishedJobAt("a-rescan", TriggerRescan, t0), finishedJobAt(syncName, "", t0)
	jobs := finishedJobs([]batchv1.Job{*rescanJob, *syncJob}, m)
	if len(jobs) != 2 || jobs[0].job.Name != syncName {
		t.Fatalf("order %v", jobs)
	}
	reports := map[string]*corev1.ContainerStateTerminated{
		syncName: termination(t, syncspec.ExitOK, v2(fpA, syncspec.GateOK, []string{tag11, tag10}, []string{tag11, tag10})),
		"a-rescan": termination(t, syncspec.ExitOK, rescanReport(fpA, []string{tag10}, []string{tag11, tag10},
			rescanFinding(tag11, t0, mirrorv1alpha1.VulnerableUntagged))),
	}
	var ev pending
	for _, f := range jobs {
		recordJob(m, f.job, f.done, reports[f.job.Name], true, &ev)
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
			r := &ArtifactMirrorReconciler{Client: c, APIReader: c, Namespace: opsNS}
			cj := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: opsNS, Name: "cj", UID: "u"}}
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

// Reconciling twice applies each finished Job once and keeps the untag.
func TestSyncStatusAppliesEachJobOnce(t *testing.T) {
	const tag11 = "1.1"
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	m := &mirrorv1alpha1.ArtifactMirror{}
	m.Namespace, m.Name = "ns", "m"
	s := goldenScheme(t)
	for _, add := range []func(*runtime.Scheme) error{batchv1.AddToScheme, corev1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	objs := make([]client.Object, 0, 4)
	for _, j := range []struct {
		name, trigger string
		term          *corev1.ContainerStateTerminated
	}{
		{syncName, "", termination(t, syncspec.ExitOK, v2(fpA, syncspec.GateOK, []string{tag11, tag10}, []string{tag11, tag10}))},
		{"a-rescan", TriggerRescan, termination(t, syncspec.ExitOK, rescanReport(fpA, []string{tag10}, []string{tag11, tag10},
			rescanFinding(tag11, t0, mirrorv1alpha1.VulnerableUntagged)))},
	} {
		job := finishedJobAt(j.name, j.trigger, t0)
		job.Namespace, job.UID = opsNS, types.UID(j.name)
		job.Labels = map[string]string{LabelMirror: mirrorHash("ns", "m")}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: opsNS, Name: j.name + "-pod",
			Labels: map[string]string{batchv1.JobNameLabel: j.name}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(job, batchv1.SchemeGroupVersion.WithKind("Job"))}},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: syncContainer, State: corev1.ContainerState{Terminated: j.term}}}}}
		objs = append(objs, job, pod)
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	r := &ArtifactMirrorReconciler{Client: c, Namespace: opsNS}

	events := make([]event, 0, 8)
	for range 2 {
		var ev pending
		var applied []*batchv1.Job
		if err := r.syncStatus(context.Background(), m, true, &ev, &applied); err != nil {
			t.Fatal(err)
		}
		r.markApplied(context.Background(), applied)
		events = append(events, ev...)
	}
	if len(m.Status.Vulnerable) != 1 || m.Status.Vulnerable[0].Tag != tag11 || m.Status.Vulnerable[0].Action != mirrorv1alpha1.VulnerableUntagged {
		t.Errorf("vulnerable %+v", m.Status.Vulnerable)
	}
	if got := tagsOf(m.Status.Synced, func(s mirrorv1alpha1.SyncedTag) string { return s.Tag }); !slices.Equal(got, []string{tag10}) {
		t.Errorf("synced %v", got)
	}
	count := map[string]int{}
	for _, e := range events {
		count[e.action+"/"+e.reason]++
	}
	for _, k := range []string{"Sync/" + ReasonSynced, "Rescan/" + ReasonRescanned, "Rescan/" + reasonTagUntagged} {
		if count[k] != 1 {
			t.Errorf("event %s x%d in %v", k, count[k], count)
		}
	}
	if m.Status.LastSyncTime == nil || !m.Status.LastSyncTime.Time.Equal(t0) {
		t.Errorf("lastSyncTime %v", m.Status.LastSyncTime)
	}
}
