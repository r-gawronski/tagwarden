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
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

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

func syncWithSelection(t *testing.T, sel *syncspec.Selection) (*mirrorv1alpha1.ArtifactMirror, pending) {
	t.Helper()
	m := &mirrorv1alpha1.ArtifactMirror{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sel"}}
	job := finishedJobAt("j", "", time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC))
	var ev pending
	recordJob(m, job, finished(job), termination(t, syncspec.ExitOK, &syncspec.Report{V: syncspec.ReportVersion, Selection: sel}), false, &ev)
	return m, ev
}

func TestRecordJobNoTagsSelected(t *testing.T) {
	m, ev := syncWithSelection(t, &syncspec.Selection{Listed: 2, Filtered: 1, Prerelease: 1})
	c := meta.FindStatusCondition(m.Status.Conditions, ConditionSynced)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != ReasonNoTagsSelected {
		t.Fatalf("Synced %+v", c)
	}
	for _, want := range []string{"2 listed", "1 removed by include/exclude", "1 prerelease skipped; set allowPrerelease"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message %q lacks %q", c.Message, want)
		}
	}
	if m.Status.LastSuccessfulSyncTime != nil {
		t.Errorf("lastSuccessfulSyncTime %v", m.Status.LastSuccessfulSyncTime)
	}
	if len(ev) != 1 || ev[0].typ != corev1.EventTypeWarning || ev[0].reason != ReasonNoTagsSelected {
		t.Errorf("events %+v", ev)
	}
	if v := gaugeValue(t, "ns", "sel"); v != 0 {
		t.Errorf("gauge %v", v)
	}
}

func TestRecordJobTagNotFound(t *testing.T) {
	m, ev := syncWithSelection(t, &syncspec.Selection{Listed: 0, Selected: 1, Missing: 7, MissingTags: []string{"v9", "v8"}})
	c := meta.FindStatusCondition(m.Status.Conditions, ConditionSynced)
	if c == nil || c.Status != metav1.ConditionTrue || c.Reason != ReasonSynced || m.Status.LastSuccessfulSyncTime == nil {
		t.Fatalf("Synced %+v", c)
	}
	if !strings.Contains(c.Message, "v9, v8 and 5 more") {
		t.Errorf("message %q", c.Message)
	}
	if len(ev) != 2 || ev[0].reason != ReasonSynced || ev[1].typ != corev1.EventTypeWarning || ev[1].reason != ReasonTagNotFound ||
		!strings.Contains(ev[1].note, "v9, v8") {
		t.Errorf("events %+v", ev)
	}
	if v := gaugeValue(t, "ns", "sel"); v != 1 {
		t.Errorf("gauge %v", v)
	}
}

func TestRecordJobSelectionLeavesOthersAlone(t *testing.T) {
	// No selection (an older Job) and a re-scan never raise NoTagsSelected.
	m, _ := syncWithSelection(t, nil)
	if c := meta.FindStatusCondition(m.Status.Conditions, ConditionSynced); c.Reason != ReasonSynced {
		t.Errorf("no selection: %+v", c)
	}
	m = &mirrorv1alpha1.ArtifactMirror{}
	job := finishedJobAt("j", TriggerRescan, time.Now())
	var ev pending
	recordJob(m, job, finished(job), termination(t, syncspec.ExitOK, &syncspec.Report{V: syncspec.ReportVersion, Selection: &syncspec.Selection{}}), false, &ev)
	if c := meta.FindStatusCondition(m.Status.Conditions, ConditionRescanned); c.Reason != ReasonRescanned {
		t.Errorf("rescan: %+v", c)
	}
}

func gaugeValue(t *testing.T, ns, name string) float64 {
	t.Helper()
	var d dto.Metric
	if err := selectedTags.WithLabelValues(ns, name).Write(&d); err != nil {
		t.Fatal(err)
	}
	return d.GetGauge().GetValue()
}

func TestReconcileDeletedMirrorDropsSelectedTagsSeries(t *testing.T) {
	selectedTags.WithLabelValues("gone", "m").Set(3)
	s := runtime.NewScheme()
	if err := mirrorv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	r := &ArtifactMirrorReconciler{Client: fake.NewClientBuilder().WithScheme(s).Build(), Namespace: opsNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "gone", Name: "m"}}); err != nil {
		t.Fatal(err)
	}
	if n := testutilCount("gone"); n != 0 {
		t.Errorf("series kept: %d", n)
	}
}

func testutilCount(ns string) int {
	mfs, _ := metrics.Registry.Gather()
	n := 0
	for _, mf := range mfs {
		if mf.GetName() != "tagwarden_mirror_selected_tags" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "namespace" && l.GetValue() == ns {
					n++
				}
			}
		}
	}
	return n
}

const (
	dig1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dig2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// A sync records its tags in status.owned, also with prune off; a re-scan
// and an unreadable report leave the record alone.
func TestRecordJobOwned(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	m := &mirrorv1alpha1.ArtifactMirror{}
	m.Status.Owned = []mirrorv1alpha1.SyncedTag{{Tag: "1", Digest: dig1}}
	run := func(trigger string, code int32, rep *syncspec.Report) {
		job := finishedJobAt("j", trigger, t0)
		var ev pending
		recordJob(m, job, finished(job), termination(t, code, rep), false, &ev)
	}
	run("", syncspec.ExitOK, &syncspec.Report{V: 1, Synced: []syncspec.SyncedTag{{Tag: "2", Digest: dig2}}})
	want := []mirrorv1alpha1.SyncedTag{{Tag: "2", Digest: dig2}, {Tag: "1", Digest: dig1}}
	if !slices.Equal(m.Status.Owned, want) {
		t.Fatalf("owned %v, want %v", m.Status.Owned, want)
	}
	run(TriggerRescan, syncspec.ExitOK, &syncspec.Report{V: 1, Synced: []syncspec.SyncedTag{{Tag: "3", Digest: dig1}}})
	run("", syncspec.ExitSyncFailed, &syncspec.Report{V: 1, Synced: []syncspec.SyncedTag{}, Failed: 1})
	if !slices.Equal(m.Status.Owned, want) {
		t.Errorf("owned %v, want %v", m.Status.Owned, want)
	}
}

func TestRecordJobPruned(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	owned := []mirrorv1alpha1.SyncedTag{{Tag: "1", Digest: dig1}, {Tag: "2", Digest: dig2}, {Tag: "3", Digest: dig1}}
	mirror := func(prune bool) *mirrorv1alpha1.ArtifactMirror {
		m := &mirrorv1alpha1.ArtifactMirror{}
		m.Spec.Tags = mirrorv1alpha1.TagSelector{Prune: prune, Tags: []string{"named"}}
		m.Status.Owned = slices.Clone(owned)
		return m
	}
	st := func(tag, d string) syncspec.SyncedTag { return syncspec.SyncedTag{Tag: tag, Digest: d} }
	run := func(m *mirrorv1alpha1.ArtifactMirror, trigger string, rep *syncspec.Report) pending {
		job := finishedJobAt("j", trigger, t0)
		var ev pending
		recordJob(m, job, finished(job), termination(t, syncspec.ExitOK, rep), false, &ev)
		return ev
	}

	t.Run("pruned and dropped tags leave the record", func(t *testing.T) {
		m := mirror(true)
		ev := run(m, "", &syncspec.Report{V: 1, Synced: []syncspec.SyncedTag{st("4", dig2)}, Pruned: []syncspec.SyncedTag{st("1", dig1)},
			Dropped: []syncspec.SyncedTag{st("2", dig2), st("gone", dig1)}})
		want := []mirrorv1alpha1.SyncedTag{{Tag: "4", Digest: dig2}, {Tag: "3", Digest: dig1}}
		if !slices.Equal(m.Status.Owned, want) {
			t.Errorf("owned %v, want %v", m.Status.Owned, want)
		}
		c := meta.FindStatusCondition(m.Status.Conditions, ConditionSynced)
		if c.Status != metav1.ConditionTrue || !strings.Contains(c.Message, "pruned 1") {
			t.Errorf("Synced %+v", c)
		}
		if len(ev) != 2 || ev[1].reason != reasonTagPruned || ev[1].typ != corev1.EventTypeNormal || !strings.Contains(ev[1].note, dig1) {
			t.Errorf("events %+v", ev)
		}
	})
	t.Run("no pruned tags, no counter", func(t *testing.T) {
		m := mirror(true)
		ev := run(m, "", &syncspec.Report{V: 1, Synced: []syncspec.SyncedTag{}})
		if c := meta.FindStatusCondition(m.Status.Conditions, ConditionSynced); strings.Contains(c.Message, "pruned") || len(ev) != 1 {
			t.Errorf("Synced %+v, events %+v", c, ev)
		}
	})
	t.Run("events are capped", func(t *testing.T) {
		m := mirror(true)
		var pruned []syncspec.SyncedTag
		m.Status.Owned = nil
		for i := range maxGateEvents + 5 {
			s := st(fmt.Sprint("t", i), dig1)
			pruned = append(pruned, s)
			m.Status.Owned = append(m.Status.Owned, mirrorv1alpha1.SyncedTag{Tag: s.Tag, Digest: s.Digest})
		}
		if ev := run(m, "", &syncspec.Report{V: 1, Synced: []syncspec.SyncedTag{}, Pruned: pruned}); len(ev) != 1+maxGateEvents {
			t.Errorf("%d events", len(ev))
		}
	})

	// A report that prunes what the controller did not offer is not trusted
	// at all (threat model T12).
	for name, tc := range map[string]struct {
		m   *mirrorv1alpha1.ArtifactMirror
		rep *syncspec.Report
	}{
		"tag not owned": {mirror(true), &syncspec.Report{V: 1, Synced: []syncspec.SyncedTag{}, Pruned: []syncspec.SyncedTag{st("other", dig1)}}},
		"prune off":     {mirror(false), &syncspec.Report{V: 1, Synced: []syncspec.SyncedTag{}, Pruned: []syncspec.SyncedTag{st("1", dig1)}}},
		"tag named in the spec": {func() *mirrorv1alpha1.ArtifactMirror {
			m := mirror(true)
			m.Status.Owned = append(m.Status.Owned, mirrorv1alpha1.SyncedTag{Tag: "named", Digest: dig1})
			return m
		}(), &syncspec.Report{V: 1, Synced: []syncspec.SyncedTag{}, Pruned: []syncspec.SyncedTag{st("named", dig1)}}},
		"tag also synced": {mirror(true), &syncspec.Report{V: 1, Synced: []syncspec.SyncedTag{st("1", dig1)}, Pruned: []syncspec.SyncedTag{st("1", dig1)}}},
	} {
		t.Run(name, func(t *testing.T) {
			before := slices.Clone(tc.m.Status.Owned)
			ev := run(tc.m, "", tc.rep)
			c := meta.FindStatusCondition(tc.m.Status.Conditions, ConditionSynced)
			if c.Reason != ReasonCrashed || c.Status != metav1.ConditionFalse || !slices.Equal(tc.m.Status.Owned, before) || tc.m.Status.Synced != nil {
				t.Errorf("Synced %+v, owned %v", c, tc.m.Status.Owned)
			}
			for _, e := range ev {
				if e.reason == reasonTagPruned {
					t.Errorf("event %+v", e)
				}
			}
		})
	}
}
