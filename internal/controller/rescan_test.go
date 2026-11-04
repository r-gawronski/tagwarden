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
	"slices"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

func TestNextRescan(t *testing.T) {
	interval := 24 * time.Hour
	base := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	seen := map[time.Time]bool{}
	for _, name := range []string{"auto-a", "auto-b", "auto-c", "auto-d"} {
		m := &mirrorv1alpha1.ArtifactMirror{ObjectMeta: metav1.ObjectMeta{Namespace: teamA, Name: name}}
		due := nextRescan(m, base, interval)
		if !due.After(base) || due.After(base.Add(interval)) {
			t.Errorf("%s: due %s, want in (%s, %s]", name, due, base, base.Add(interval))
		}
		// Slots are interval apart: a re-scan at its slot is followed by
		// the next slot, also when it starts a little late.
		if next := nextRescan(m, due.Add(time.Minute), interval); !next.Equal(due.Add(interval)) {
			t.Errorf("%s: after %s comes %s", name, due, next)
		}
		seen[due] = true
	}
	if len(seen) < 3 {
		t.Errorf("re-scans not spread: %v", seen)
	}
}

const tag39 = "3.9"

func TestUntaggable(t *testing.T) {
	tg, m := gatedFixture(mirrorv1alpha1.VulnerabilityGate{Enabled: true, Action: mirrorv1alpha1.GateActionBlock,
		OnVulnerableTag: mirrorv1alpha1.OnVulnerableTagUntag})
	// Same registry as validTarget's, in another spelling.
	tg.Spec.Registry = "Registry.Example.Internal:8443"
	m.UID = "self"
	m.Spec.Tags.Tags = []string{v310, tag39, "4.0"}
	// "old" is no longer selected; 4.0 was never recorded.
	m.Status.Synced = []mirrorv1alpha1.SyncedTag{{Tag: v310}, {Tag: tag39}, {Tag: "old"}}
	peer := func(ns, target string, sel mirrorv1alpha1.TagSelector) *mirrorv1alpha1.ArtifactMirror {
		o := m.DeepCopy()
		o.Namespace, o.UID, o.Spec.TargetRef, o.Spec.Tags, o.Status = ns, types.UID(ns), target, sel, mirrorv1alpha1.ArtifactMirrorStatus{}
		return o
	}
	other := validTarget("same-registry")
	elsewhere := validTarget("elsewhere")
	elsewhere.Spec.Registry = "other.example.internal"
	deleting := peer("deleting", tg.Name, mirrorv1alpha1.TagSelector{Tags: []string{v310}})
	deleting.DeletionTimestamp, deleting.Finalizers = &metav1.Time{Time: time.Now()}, []string{Finalizer}
	deletingOther := peer("deleting-other", "same-registry", mirrorv1alpha1.TagSelector{Tags: []string{tag39}})
	deletingOther.DeletionTimestamp, deletingOther.Finalizers = deleting.DeletionTimestamp, deleting.Finalizers

	untaggable := func(objs ...client.Object) []string {
		t.Helper()
		c := fake.NewClientBuilder().WithScheme(goldenScheme(t)).
			WithIndex(&mirrorv1alpha1.ArtifactMirror{}, indexTargetKey, func(o client.Object) []string {
				return []string{targetKey(o.(*mirrorv1alpha1.ArtifactMirror))}
			}).
			WithObjects(append([]client.Object{tg, other, elsewhere, m.DeepCopy()}, objs...)...).Build()
		got, err := (&ArtifactMirrorReconciler{Client: c}).untaggable(context.Background(), tg, m)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := untaggable(deleting, deletingOther); !slices.Equal(got, []string{v310, tag39}) {
		t.Errorf("alone: %v", got)
	}
	// Another namespace on the same target, and one through another
	// target on the same registry, hold their tags.
	if got := untaggable(peer(teamB, tg.Name, mirrorv1alpha1.TagSelector{Tags: []string{tag39}}),
		peer("ns-c", other.Name, mirrorv1alpha1.TagSelector{Tags: []string{v310}})); len(got) != 0 {
		t.Errorf("shared: %v", got)
	}
	if got := untaggable(peer(teamB, elsewhere.Name, mirrorv1alpha1.TagSelector{Tags: []string{v310}})); !slices.Equal(got, []string{v310, tag39}) {
		t.Errorf("other registry: %v", got)
	}
	if got := untaggable(peer(teamB, tg.Name, mirrorv1alpha1.TagSelector{Include: []string{"^3"}})); got != nil {
		t.Errorf("pattern mirror: %v", got)
	}

	// The spec carries the list under Untag only.
	r := reconcilerWith(t)
	r.Client = fake.NewClientBuilder().WithScheme(goldenScheme(t)).
		WithIndex(&mirrorv1alpha1.ArtifactMirror{}, indexTargetKey, func(o client.Object) []string {
			return []string{targetKey(o.(*mirrorv1alpha1.ArtifactMirror))}
		}).WithObjects(tg).Build()
	_, spec := renderGated(t, r, tg, m)
	if !slices.Equal(spec.Gate.Untaggable, []string{v310, tag39}) || spec.Gate.OnVulnerableTag != mirrorv1alpha1.OnVulnerableTagUntag {
		t.Errorf("spec untaggable %v %s", spec.Gate.Untaggable, spec.Gate.OnVulnerableTag)
	}
	tg.Spec.AutoMirror.VulnerabilityGate.OnVulnerableTag = mirrorv1alpha1.OnVulnerableTagReport
	if _, spec := renderGated(t, r, tg, m); spec.Gate.Untaggable != nil {
		t.Errorf("Report: untaggable %v", spec.Gate.Untaggable)
	}
}

func rescanReport(fp string, synced, judged []string, findings ...syncspec.TagFinding) *syncspec.Report {
	r := v2(fp, syncspec.GateOK, synced, judged, findings...)
	r.Rescan = true
	return r
}

func rescanFinding(tag string, at time.Time, action mirrorv1alpha1.VulnerableTagAction) syncspec.TagFinding {
	f := tagFinding(tag, at, mirrorv1alpha1.SeverityCritical, mirrorv1alpha1.OutcomeCopied)
	f.PresentOnTarget, f.RescanAction = true, action
	if action == mirrorv1alpha1.VulnerableUntagged {
		f.Outcome = mirrorv1alpha1.OutcomeBlocked
	}
	return f
}

func TestApplyRescan(t *testing.T) {
	const tag11 = "1.1"
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	t1, t2 := t0.Add(time.Hour), t0.Add(2*time.Hour)
	m := &mirrorv1alpha1.ArtifactMirror{}
	vf := ConditionVulnerabilitiesFound
	yes, no := metav1.ConditionTrue, metav1.ConditionFalse
	vulnerable := func() string {
		return strings.Join(tagsOf(m.Status.Vulnerable, func(v mirrorv1alpha1.VulnerableTag) string {
			return v.Tag + "=" + string(v.Action)
		}), " ")
	}
	reasons := func(ev pending) []string { return tagsOf(ev, func(e event) string { return e.reason }) }

	// A sync copied both tags clean.
	var ev pending
	applyGate(m, v2(fpA, syncspec.GateOK, []string{tag11, tag10}, []string{tag11, tag10}), true, true, t0, &ev)
	wantGate(t, "sync", m, "", tag11+" "+tag10, vf, no, ReasonClear)

	// A re-scan finds 1.0 vulnerable after a DB update and keeps it.
	ev = nil
	applyRescan(m, rescanReport(fpA, []string{tag11, tag10}, []string{tag11, tag10}, rescanFinding(tag10, t1, mirrorv1alpha1.VulnerableKept)),
		true, true, t1, &ev)
	wantGate(t, "re-scan", m, "", tag11+" "+tag10, vf, yes, ReasonReported)
	if got := vulnerable(); got != tag10+"=Kept" {
		t.Errorf("vulnerable %q", got)
	}
	for _, j := range m.Status.Gate.Judged {
		if j.JudgedAt == nil || !j.JudgedAt.Time.Equal(t1) {
			t.Errorf("judged %s at %v, want the re-scan Job start", j.Tag, j.JudgedAt)
		}
	}
	if got := reasons(ev); !slices.Equal(got, []string{reasonVulnerableTagFound}) {
		t.Errorf("events %v", got)
	}
	// Applied again while the pod exists: nothing new.
	ev = nil
	applyRescan(m, rescanReport(fpA, []string{tag11, tag10}, []string{tag11, tag10}, rescanFinding(tag10, t1, mirrorv1alpha1.VulnerableKept)),
		true, false, t1, &ev)
	if vulnerable() != tag10+"=Kept" || len(ev) != 0 {
		t.Errorf("not idempotent: %q %v", vulnerable(), ev)
	}

	// Under Untag the next re-scan deletes the tag; it is no longer
	// judged, so the next sync scans it again.
	ev = nil
	applyRescan(m, rescanReport(fpA, []string{tag11}, []string{tag11, tag10}, rescanFinding(tag10, t2, mirrorv1alpha1.VulnerableUntagged)),
		true, true, t2, &ev)
	wantGate(t, "untag", m, "", tag11, vf, yes, ReasonBlocked)
	if got := vulnerable(); got != tag10+"=Untagged" || !slices.Equal(reasons(ev), []string{reasonTagUntagged}) {
		t.Errorf("vulnerable %q, events %v", got, reasons(ev))
	}

	// That sync blocks 1.0: the finding replaces the re-scan entry.
	applyGate(m, v2(fpA, syncspec.GateOK, []string{tag11}, nil,
		tagFinding(tag10, t2.Add(time.Hour), mirrorv1alpha1.SeverityCritical, mirrorv1alpha1.OutcomeBlocked)), true, true, t2, &pending{})
	wantGate(t, "blocked", m, tag10, tag11, vf, yes, ReasonBlocked)
	if m.Status.Vulnerable != nil {
		t.Errorf("vulnerable %q after the sync judged the tag", vulnerable())
	}

	// A re-scan supersedes sync findings of the tags it judged and lists
	// its scan errors in findings.
	m = &mirrorv1alpha1.ArtifactMirror{}
	applyGate(m, v2(fpA, syncspec.GateOK, []string{tag11, tag10}, []string{tag11, tag10},
		tagFinding(tag10, t0, mirrorv1alpha1.SeverityHigh, mirrorv1alpha1.OutcomeCopied)), true, true, t0, &pending{})
	applyRescan(m, rescanReport(fpA, []string{tag11, tag10}, []string{tag10}, scanError(tag11, t1, syncspec.GateScanFailed)),
		true, true, t1, &pending{})
	wantGate(t, "re-scan errors", m, tag11, tag10, ConditionVulnerabilityGate, no, ReasonScanFailed)
	if m.Status.Vulnerable != nil || meta.IsStatusConditionTrue(m.Status.Conditions, vf) {
		t.Errorf("vulnerable %q", vulnerable())
	}
}

var _ = Describe("re-scan", Ordered, func() {
	const (
		target = "rescan-target"
		ns     = "rescan-ns"
		image  = ghcrRegistry + "/org/rescan"
	)
	var gen *mirrorv1alpha1.ArtifactMirror
	var pod *corev1.Pod

	status := func() mirrorv1alpha1.ArtifactMirrorStatus {
		var got mirrorv1alpha1.ArtifactMirror
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gen), &got)).To(Succeed())
		return got.Status
	}
	rescanJobs := func() []batchv1.Job {
		var jobs batchv1.JobList
		Expect(k8sClient.List(ctx, &jobs, client.InNamespace(operatorNamespace),
			client.MatchingLabels{LabelMirror: mirrorHash(gen.Namespace, gen.Name)})).To(Succeed())
		var out []batchv1.Job
		for _, j := range jobs.Items {
			if j.Annotations[AnnotationTrigger] == TriggerRescan {
				out = append(out, j)
			}
		}
		return out
	}
	setLastRescan := func(at time.Time) {
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var m mirrorv1alpha1.ArtifactMirror
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(gen), &m); err != nil {
				return err
			}
			m.Status.LastRescan = &metav1.Time{Time: at}
			return k8sClient.Status().Update(ctx, &m)
		})).To(Succeed())
	}

	BeforeAll(func() {
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		createReadyTarget(target, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.AllowedSources = []mirrorv1alpha1.RegistryHost{ghcrRegistry}
			t.Spec.Projects = []mirrorv1alpha1.TargetProject{{Name: otherProject, NamespaceSelector: &metav1.LabelSelector{}}}
			t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: otherProject,
				VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{Enabled: true, Action: mirrorv1alpha1.GateActionBlock,
					OnVulnerableTag: mirrorv1alpha1.OnVulnerableTagUntag, RescanInterval: &metav1.Duration{Duration: time.Hour},
					Scanner: &mirrorv1alpha1.ScannerSpec{URL: inChartURL}}}
		})
		DeferCleanup(func() {
			Expect(k8sClient.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace(ns), client.GracePeriodSeconds(0))).To(Succeed())
			time.Sleep(500 * time.Millisecond)
			deleteAndWait(gen)
			deleteAndWait(&mirrorv1alpha1.ClusterMirrorTarget{ObjectMeta: metav1.ObjectMeta{Name: target}})
		})
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "uses-1-0", Namespace: ns, Annotations: map[string]string{mirrorv1alpha1.AutoMirrorAnnotation: target}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image + ":1.0"}}},
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		gen = &mirrorv1alpha1.ArtifactMirror{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: generatedNameOf(image)}}
		Eventually(mirrorReady(gen)).Should(HaveField("Status", metav1.ConditionTrue))
		// The first sync of a new generated mirror is a sync-now Job, which
		// never finishes here; while it runs no re-scan may start.
		var jobs batchv1.JobList
		Eventually(func() []batchv1.Job {
			Expect(k8sClient.List(ctx, &jobs, client.InNamespace(operatorNamespace),
				client.MatchingLabels{LabelMirror: mirrorHash(gen.Namespace, gen.Name)})).To(Succeed())
			return jobs.Items
		}).Should(ConsistOf(HaveField("ObjectMeta.Annotations", HaveKeyWithValue(AnnotationTrigger, TriggerManual))))
		setLastRescan(time.Now().Add(-2 * time.Hour))
		Consistently(rescanJobs, 2*time.Second).Should(BeEmpty())
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var m mirrorv1alpha1.ArtifactMirror
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(gen), &m); err != nil {
				return err
			}
			m.Status.LastRescan = nil
			return k8sClient.Status().Update(ctx, &m)
		})).To(Succeed())
		Expect(k8sClient.Delete(ctx, &jobs.Items[0], client.PropagationPolicy(metav1.DeletePropagationBackground))).To(Succeed())
	})

	It("waits for the first sync and then for the mirror's slot", func() {
		Consistently(rescanJobs, 2*time.Second).Should(BeEmpty())
		// The slot after a sync that just finished is ahead; the slot after
		// a re-scan two hours ago has passed.
		finishSyncJob(gen, objectName(gen)+"-1", time.Now(), 0,
			`{"v":2,"copied":1,"synced":[{"tag":"1.0","digest":"`+hexDigest("1")+`"}],"gate":"ok","javaScanned":false,`+
				`"judgedFingerprint":"`+fpA+`","judged":[{"tag":"1.0","digest":"`+hexDigest("1")+`"}]}`, false)
		Eventually(func() []string { return judgedTags(&mirrorv1alpha1.ArtifactMirror{Status: status()}) }).Should(Equal([]string{tag10}))
		Expect(status().LastRescan).To(BeNil())
		Expect(nextRescan(gen, status().LastSuccessfulSyncTime.Time, time.Hour)).To(BeTemporally(">", time.Now()))
		Consistently(rescanJobs, 2*time.Second).Should(BeEmpty())

		before := time.Now().Add(-time.Second)
		setLastRescan(time.Now().Add(-2 * time.Hour))
		Eventually(rescanJobs).Should(HaveLen(1))
		job := rescanJobs()[0]
		Expect(job.Spec.Template.Spec.Containers[0].Args).To(Equal([]string{"sync", "--spec", syncspec.SpecFile, ArgRescan}))
		Expect(job.Spec.Template.Spec.InitContainers).To(HaveLen(1), "the scanner sidecar")
		Expect(job.OwnerReferences).To(ConsistOf(HaveField("Kind", "CronJob")))
		Eventually(func() *metav1.Time { return status().LastRescan }).Should(HaveField("Time", BeTemporally(">", before)))
		Eventually(func() []string { return recorder.Events(ns, gen.Name) }).Should(ContainElement(ContainSubstring("Normal RescanStarted")))

		By("starting no second re-scan in the same interval")
		Consistently(rescanJobs, 2*time.Second).Should(HaveLen(1))
		Expect(k8sClient.Delete(ctx, &job, client.PropagationPolicy(metav1.DeletePropagationBackground))).To(Succeed())
	})

	It("records a vulnerable tag and tells the pods using it", func() {
		finishJob(gen, objectName(gen)+"-rescan-x", time.Now(), 0,
			`{"v":2,"skipped":0,"synced":[],"gate":"ok","javaScanned":false,"rescan":true,"findings":1,`+
				`"judgedFingerprint":"`+fpA+`","judged":[{"tag":"1.0","digest":"`+hexDigest("1")+`"}],`+
				`"tagFindings":[{"tag":"1.0","digest":"`+hexDigest("1")+`","verdict":"Findings","outcome":"Blocked","presentOnTarget":true,`+
				`"severity":"Critical","counts":{"critical":1},"topIDs":["`+testCVE+`"],"scannedAt":"2026-11-04T10:00:00Z","rescanAction":"Untagged"}]}`,
			false, TriggerRescan)
		Eventually(func() []mirrorv1alpha1.VulnerableTag { return status().Vulnerable }).Should(ConsistOf(And(
			HaveField("Tag", "1.0"), HaveField("Action", mirrorv1alpha1.VulnerableUntagged), HaveField("TopIDs", ConsistOf(testCVE)))))
		st := status()
		Expect(meta.FindStatusCondition(st.Conditions, ConditionVulnerabilitiesFound)).To(And(
			HaveField("Status", metav1.ConditionTrue), HaveField("Reason", ReasonBlocked)))
		Expect(judgedTags(&mirrorv1alpha1.ArtifactMirror{Status: st})).To(BeEmpty(), "an untagged tag is not judged")
		Eventually(func() []string { return recorder.Events(ns, gen.Name) }).Should(ContainElement(ContainSubstring("Warning " + reasonTagUntagged + " re-scan: tag 1.0")))
		Eventually(func() string { return strings.Join(recorder.Events(pod.Namespace, pod.Name), "\n") }).Should(ContainSubstring(
			"Warning " + reasonImageVulnerable + " " + image + ":1.0 found vulnerable by re-scan: 1 Critical (" + testCVE +
				"); tag deleted from the target, the digest stays; see ArtifactMirror " + ns + "/" + gen.Name))
	})

	It("ignores a re-scan report from a sync Job", func() {
		before := status()
		finishSyncJob(gen, objectName(gen)+"-forged", time.Now().Add(time.Second), 0,
			`{"v":2,"synced":[],"gate":"ok","javaScanned":false,"rescan":true,"judgedFingerprint":"`+fpA+`"}`, false)
		Eventually(func() *metav1.Time { return status().LastSyncTime }).ShouldNot(Equal(before.LastSyncTime))
		Expect(status().Vulnerable).To(Equal(before.Vulnerable))
	})

	It("drops the re-scan status when the gate is turned off", func() {
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var t mirrorv1alpha1.ClusterMirrorTarget
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: target}, &t); err != nil {
				return err
			}
			t.Spec.AutoMirror.VulnerabilityGate.Enabled = false
			return k8sClient.Update(ctx, &t)
		})).To(Succeed())
		Eventually(func() []mirrorv1alpha1.VulnerableTag { return status().Vulnerable }).Should(BeNil())
		Expect(status().LastRescan).To(BeNil())
	})
})
