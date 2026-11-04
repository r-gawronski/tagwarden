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
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"

	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

func hexDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }

// jobStart is the start of the Job whose report applyGate records.
var jobStart = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)

var (
	fpA = strings.Repeat("a", 64)
	fpB = strings.Repeat("b", 64)
)

// v2 is a gated report; scanned at at.
func v2(fp, gate string, synced []string, judged []string, findings ...syncspec.TagFinding) *syncspec.Report {
	r := &syncspec.Report{V: syncspec.ReportVersionGate, JudgedFingerprint: fp, Gate: gate, JavaScanned: new(false), TagFindings: findings}
	for _, t := range synced {
		r.Synced = append(r.Synced, syncspec.SyncedTag{Tag: t, Digest: hexDigest("1")})
	}
	for _, t := range judged {
		r.Judged = append(r.Judged, syncspec.SyncedTag{Tag: t, Digest: hexDigest("1")})
	}
	return r
}

func tagFinding(tag string, at time.Time, sev mirrorv1alpha1.Severity, outcome mirrorv1alpha1.FindingOutcome) syncspec.TagFinding {
	return syncspec.TagFinding{Tag: tag, Digest: hexDigest("1"), Verdict: mirrorv1alpha1.VerdictFindings, Outcome: outcome,
		Severity: sev, Counts: mirrorv1alpha1.SeverityCounts{Critical: 1, High: 2}, TopIDs: []string{testCVE, "CVE-2026-2"}, ScannedAt: at}
}

func scanError(tag string, at time.Time, reason string) syncspec.TagFinding {
	return syncspec.TagFinding{Tag: tag, Digest: hexDigest("1"), Verdict: mirrorv1alpha1.VerdictScanError,
		Outcome: mirrorv1alpha1.OutcomeCopied, ScanError: reason, ScannedAt: at}
}

func tagsOf[T any](items []T, tag func(T) string) []string {
	out := make([]string, 0, len(items))
	for _, i := range items {
		out = append(out, tag(i))
	}
	return out
}

func findingTags(m *mirrorv1alpha1.ArtifactMirror) []string {
	return tagsOf(m.Status.Findings, func(f mirrorv1alpha1.VulnerabilityFinding) string { return f.Tag })
}

func judgedTags(m *mirrorv1alpha1.ArtifactMirror) []string {
	if m.Status.Gate == nil {
		return nil
	}
	return tagsOf(m.Status.Gate.Judged, func(j mirrorv1alpha1.JudgedTag) string { return j.Tag })
}

// wantGate checks the finding and judged tags of m, joined by spaces, and
// the status of a condition.
func wantGate(t *testing.T, step string, m *mirrorv1alpha1.ArtifactMirror, findings, judged, cond string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	if got := strings.Join(findingTags(m), " "); got != findings {
		t.Errorf("%s: findings %q, want %q", step, got, findings)
	}
	if got := strings.Join(judgedTags(m), " "); got != judged {
		t.Errorf("%s: judged %q, want %q", step, got, judged)
	}
	if c := meta.FindStatusCondition(m.Status.Conditions, cond); c == nil || c.Status != status || c.Reason != reason {
		t.Errorf("%s: %s = %+v, want %s %s", step, cond, c, status, reason)
	}
}

func TestApplyGate(t *testing.T) {
	const (
		tag11, tag12 = "1.1", "1.2"
		both         = tag11 + " " + tag10
		// 1.2 is blocked, not on the target, so it is never judged.
		all = tag10 + " " + tag11
	)
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	m := &mirrorv1alpha1.ArtifactMirror{}
	var ev pending
	vf, vg := ConditionVulnerabilitiesFound, ConditionVulnerabilityGate
	yes, no := metav1.ConditionTrue, metav1.ConditionFalse

	// First run: 1.0 has findings (copied), 1.1 passed.
	rep := v2(fpA, syncspec.GateOK, []string{tag11, tag10}, []string{tag11, tag10},
		tagFinding(tag10, t0, mirrorv1alpha1.SeverityCritical, mirrorv1alpha1.OutcomeCopied))
	applyGate(m, rep, true, true, jobStart, &ev)
	wantGate(t, "first run", m, tag10, both, vf, yes, ReasonReported)
	wantGate(t, "first run", m, tag10, both, vg, yes, ReasonReady)
	f := m.Status.Findings[0]
	if f.JavaScanned || !f.ScannedAt.Equal(&metav1.Time{Time: t0}) || f.Counts.Critical != 1 || len(f.TopIDs) != 2 {
		t.Errorf("finding = %+v", f)
	}
	if *m.Status.JavaScanned || m.Status.Gate.JudgedFingerprint != fpA {
		t.Errorf("status = %v %+v", *m.Status.JavaScanned, m.Status.Gate)
	}
	if c := meta.FindStatusCondition(m.Status.Conditions, vf); !strings.Contains(c.Message, tag10+" Critical ("+testCVE) ||
		!strings.HasSuffix(c.Message, javaNotScanned) {
		t.Errorf("VulnerabilitiesFound message = %q", c.Message)
	}
	if len(ev) != 1 || ev[0].reason != reasonVulnerabilitiesFound || !strings.Contains(ev[0].note, "1 Critical") {
		t.Errorf("events = %+v", ev)
	}

	// The same report again changes nothing and records no Event.
	before := m.Status.DeepCopy()
	ev = nil
	applyGate(m, rep, true, false, jobStart, &ev)
	if !equality.Semantic.DeepEqual(before, &m.Status) || len(ev) != 0 {
		t.Errorf("applying the report twice changed the status or recorded %v", ev)
	}

	applyGate(m, v2(fpA, "", []string{tag11, tag10}, nil), true, true, jobStart, &ev)
	wantGate(t, "nothing scanned", m, tag10, both, vf, yes, ReasonReported)

	// 1.2 is new and blocked, 1.0 now passes.
	applyGate(m, v2(fpA, syncspec.GateOK, []string{tag11, tag10}, []string{tag12, tag10},
		tagFinding(tag12, t1, mirrorv1alpha1.SeverityHigh, mirrorv1alpha1.OutcomeBlocked)), true, true, jobStart, &ev)
	wantGate(t, "blocked", m, tag12, all, vf, yes, ReasonBlocked)

	// A failed run or a truncated synced list does not prune; a
	// successful, complete one does.
	applyGate(m, v2(fpA, "", nil, nil), false, true, jobStart, &ev)
	wantGate(t, "failed run", m, tag12, all, vf, yes, ReasonBlocked)
	truncated := v2(fpA, "", []string{tag10}, nil)
	truncated.Truncated = true
	applyGate(m, truncated, true, true, jobStart, &ev)
	wantGate(t, "truncated", m, tag12, all, vf, yes, ReasonBlocked)
	applyGate(m, v2(fpA, "", []string{tag10}, nil), true, true, jobStart, &ev)
	wantGate(t, "pruned", m, "", tag10, vf, no, ReasonClear)

	// Another fingerprint drops the stored judged pairs.
	applyGate(m, v2(fpB, syncspec.GateOK, []string{tag10, tag11}, []string{tag11}), true, true, jobStart, &ev)
	wantGate(t, "new fingerprint", m, "", tag11, vf, no, ReasonClear)

	// A stale DB: scan errors and the run-level gate set VulnerabilityGate.
	applyGate(m, v2(fpB, syncspec.GateDBStale, []string{tag10, tag11}, nil, scanError(tag10, t1, syncspec.GateDBStale)), true, true, jobStart, &ev)
	wantGate(t, "stale DB", m, tag10, tag11, vg, no, ReasonDBStale)
	if c := meta.FindStatusCondition(m.Status.Conditions, vg); !strings.Contains(c.Message, tag10+" (DBStale)") {
		t.Errorf("VulnerabilityGate message = %q", c.Message)
	}
	if ev[len(ev)-1].reason != reasonVulnerabilityScanFail {
		t.Errorf("last event = %+v", ev[len(ev)-1])
	}
}

// TestApplyGateJudgedFeedback checks that only judged pairs the run also
// reports on the target, with the same digest and no scan error, are kept:
// judged is the one report field fed back into later Jobs.
func TestApplyGateJudgedFeedback(t *testing.T) {
	m := &mirrorv1alpha1.ArtifactMirror{}
	rep := v2(fpA, syncspec.GateOK, []string{tag10, "1.1"}, nil,
		scanError("1.1", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), syncspec.GateScanFailed))
	rep.Judged = []syncspec.SyncedTag{
		{Tag: tag10, Digest: hexDigest("1")}, // on the target
		{Tag: "1.1", Digest: hexDigest("1")}, // also a scan error
		{Tag: "1.2", Digest: hexDigest("1")}, // not on the target
		{Tag: "1.3", Digest: hexDigest("9")}, // not synced
	}
	rep.Synced = append(rep.Synced, syncspec.SyncedTag{Tag: "1.4", Digest: hexDigest("1")})
	rep.Judged = append(rep.Judged, syncspec.SyncedTag{Tag: "1.4", Digest: hexDigest("2")}) // other digest
	applyGate(m, rep, true, false, jobStart, &pending{})
	if got := strings.Join(judgedTags(m), " "); got != tag10 {
		t.Errorf("judged %q, want only 1.0", got)
	}
}

func TestApplyGateOrderAndCap(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	m := &mirrorv1alpha1.ArtifactMirror{}
	old := make([]syncspec.TagFinding, 0, 15)
	synced := make([]string, 0, 25)
	for i := range 15 {
		tag := fmt.Sprintf("0.%d", i)
		old = append(old, tagFinding(tag, t0, mirrorv1alpha1.SeverityLow, mirrorv1alpha1.OutcomeCopied))
		synced = append(synced, tag)
	}
	var ev pending
	applyGate(m, v2(fpA, syncspec.GateOK, synced, nil, old...), true, true, jobStart, &ev)
	if len(ev) != maxGateEvents {
		t.Errorf("%d events, want %d", len(ev), maxGateEvents)
	}
	run := make([]syncspec.TagFinding, 0, 10)
	for i := range 10 {
		tag := fmt.Sprintf("1.%d", i)
		sev := mirrorv1alpha1.SeverityHigh
		if i == 9 {
			sev = mirrorv1alpha1.SeverityCritical
		}
		run = append(run, tagFinding(tag, t0.Add(time.Hour), sev, mirrorv1alpha1.OutcomeCopied))
		synced = append(synced, tag)
	}
	applyGate(m, v2(fpA, syncspec.GateOK, synced, nil, run...), true, false, jobStart, &ev)
	if len(m.Status.Findings) != maxFindings {
		t.Fatalf("%d findings, want %d", len(m.Status.Findings), maxFindings)
	}
	if got := m.Status.Findings[0]; got.Tag != "1.9" {
		t.Errorf("first finding %s, want the newest Critical 1.9", got.Tag)
	}
	if got := m.Status.Findings[10]; !strings.HasPrefix(got.Tag, "0.") {
		t.Errorf("finding 10 = %s, want an older one", got.Tag)
	}
}

func TestGateConditions(t *testing.T) {
	m := &mirrorv1alpha1.ArtifactMirror{Status: mirrorv1alpha1.ArtifactMirrorStatus{
		Findings: []mirrorv1alpha1.VulnerabilityFinding{{Tag: tag10}}, JavaScanned: new(false),
		Gate: &mirrorv1alpha1.GateStatus{JudgedFingerprint: fpA},
		Conditions: []metav1.Condition{
			{Type: ConditionVulnerabilitiesFound, Status: metav1.ConditionTrue, Reason: ReasonReported},
			{Type: ConditionVulnerabilityGate, Status: metav1.ConditionTrue, Reason: ReasonReady},
		},
	}}
	var ev pending
	gateConditions(m, true, nil, &ev)
	gateConditions(m, true, nil, &ev)
	if vg := meta.FindStatusCondition(m.Status.Conditions, ConditionVulnerabilityGate); vg.Reason != ReasonNotConfigured || vg.Message != notConfigured {
		t.Errorf("VulnerabilityGate = %+v", vg)
	}
	if len(ev) != 1 || ev[0].typ != corev1.EventTypeWarning || ev[0].reason != ReasonNotConfigured {
		t.Errorf("events = %+v, want one Warning", ev)
	}
	gateConditions(m, true, &sidecar{}, &ev)
	if meta.FindStatusCondition(m.Status.Conditions, ConditionVulnerabilityGate) != nil {
		t.Error("the not-configured condition stays once the scanner is configured")
	}
	gateConditions(m, false, nil, &ev)
	if m.Status.Findings != nil || m.Status.JavaScanned != nil || m.Status.Gate != nil || len(m.Status.Conditions) != 0 {
		t.Errorf("ungated mirror keeps gate status: %+v", m.Status)
	}
}

func TestApplyResultGateExitCodes(t *testing.T) {
	job := &batchv1.Job{}
	job.Name = "j"
	done := &batchv1.JobCondition{Type: batchv1.JobFailed, LastTransitionTime: metav1.Now()}
	for _, tc := range []struct {
		msg, reason string
	}{
		{`{"v":2,"synced":[],"gate":"DBStale","javaScanned":false}`, ReasonDBStale},
		{`{"v":2,"synced":[],"gate":"VersionMismatch","javaScanned":false}`, ReasonVersionMismatch},
		{`{"v":2,"synced":[],"gate":"ok","javaScanned":false}`, ReasonConfigRejected},
		{`{"v":1,"synced":[]}`, ReasonConfigRejected},
	} {
		m := &mirrorv1alpha1.ArtifactMirror{}
		cond, rep := applyResult(m, job, done, &corev1.ContainerStateTerminated{ExitCode: syncspec.ExitConfig, Message: tc.msg}, false)
		if cond.Reason != tc.reason || rep == nil {
			t.Errorf("%s: reason %s, report %v; want %s", tc.msg, cond.Reason, rep, tc.reason)
		}
	}
}

var _ = Describe("vulnerability gate status and pod Events", Ordered, func() {
	const (
		target = "gate-relay"
		ns     = "gate-relay-ns"
		image  = ghcrRegistry + "/org/vuln"
	)
	var gen *mirrorv1alpha1.ArtifactMirror
	var vulnPod, otherPod *corev1.Pod
	var jobs int
	start := time.Now().Add(-time.Hour).Truncate(time.Second)

	podEvents := func(p *corev1.Pod) func() string {
		return func() string { return strings.Join(recorder.Events(p.Namespace, p.Name), "\n") }
	}
	newPod := func(name, img string) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: map[string]string{mirrorv1alpha1.AutoMirrorAnnotation: target}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: img}}},
		}
		Expect(k8sClient.Create(ctx, p)).To(Succeed())
		return p
	}
	finish := func(exitCode int32, report string) {
		jobs++
		finishSyncJob(gen, fmt.Sprintf("%s-%d", objectName(gen), jobs), start.Add(time.Duration(jobs)*time.Minute), exitCode, report, false)
	}
	status := func() mirrorv1alpha1.ArtifactMirrorStatus {
		var got mirrorv1alpha1.ArtifactMirror
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gen), &got)).To(Succeed())
		return got.Status
	}
	condition := func(typ string) func() *metav1.Condition {
		return func() *metav1.Condition { return meta.FindStatusCondition(status().Conditions, typ) }
	}
	setAction := func(a mirrorv1alpha1.GateAction) {
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var t mirrorv1alpha1.ClusterMirrorTarget
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: target}, &t); err != nil {
				return err
			}
			t.Spec.AutoMirror.VulnerabilityGate.Action = a
			return k8sClient.Update(ctx, &t)
		})).To(Succeed())
	}
	report := func(tag, outcome string) string {
		return `{"v":2,"copied":1,"synced":[{"tag":"2.0","digest":"` + hexDigest("2") + `"},{"tag":"1.0","digest":"` + hexDigest("1") + `"}],` +
			`"findings":1,"gate":"ok","javaScanned":false,"judgedFingerprint":"` + fpA + `",` +
			`"judged":[{"tag":"2.0","digest":"` + hexDigest("2") + `"},{"tag":"1.0","digest":"` + hexDigest("1") + `"}],` +
			`"tagFindings":[{"tag":"` + tag + `","digest":"` + hexDigest("1") + `","verdict":"Findings","outcome":"` + outcome + `",` +
			`"severity":"Critical","counts":{"critical":1,"high":2},"topIDs":["` + testCVE + `","CVE-2026-2"],"scannedAt":"2026-11-01T10:00:00Z"}]}`
	}

	BeforeAll(func() {
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		createReadyTarget(target, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.AllowedSources = []mirrorv1alpha1.RegistryHost{ghcrRegistry}
			t.Spec.Projects = []mirrorv1alpha1.TargetProject{{Name: otherProject, NamespaceSelector: &metav1.LabelSelector{}}}
			t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: otherProject,
				VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{Enabled: true, Scanner: &mirrorv1alpha1.ScannerSpec{URL: inChartURL}}}
		})
		DeferCleanup(func() {
			Expect(k8sClient.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace(ns), client.GracePeriodSeconds(0))).To(Succeed())
			time.Sleep(500 * time.Millisecond)
			deleteAndWait(gen)
			deleteAndWait(&mirrorv1alpha1.ClusterMirrorTarget{ObjectMeta: metav1.ObjectMeta{Name: target}})
		})
		vulnPod = newPod("uses-1-0", image+":1.0")
		otherPod = newPod("uses-2-0", image+":2.0")
		gen = &mirrorv1alpha1.ArtifactMirror{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: generatedNameOf(image)}}
		Eventually(mirrorReady(gen)).Should(HaveField("Status", metav1.ConditionTrue))
	})

	It("relays a scanner that is not ready on the target", func() {
		// The in-chart Service does not resolve in the test environment.
		Eventually(podEvents(vulnPod), 20*time.Second).Should(And(ContainSubstring("Warning "+reasonVulnerabilityScanFail),
			ContainSubstring(ReasonScannerUnavailable+": scanner of ClusterMirrorTarget "+target), ContainSubstring("mirrored without scan")))
	})

	It("records findings and tells only the pods using the tag", func() {
		finish(0, report("1.0", "Copied"))
		Eventually(condition(ConditionVulnerabilitiesFound)).Should(And(HaveField("Status", metav1.ConditionTrue),
			HaveField("Reason", ReasonReported), HaveField("Message", HaveSuffix(javaNotScanned))))
		st := status()
		Expect(st.Findings).To(HaveLen(1))
		Expect(st.Findings[0]).To(And(HaveField("Tag", "1.0"), HaveField("JavaScanned", false), HaveField("TopIDs", ConsistOf(testCVE, "CVE-2026-2"))))
		Expect(*st.JavaScanned).To(BeFalse())
		judgedAt := metav1.NewTime(start.Add(time.Duration(jobs)*time.Minute - time.Second))
		Expect(st.Gate).To(Equal(&mirrorv1alpha1.GateStatus{JudgedFingerprint: fpA, Judged: []mirrorv1alpha1.JudgedTag{
			{Tag: "2.0", Digest: hexDigest("2"), JudgedAt: &judgedAt}, {Tag: tag10, Digest: hexDigest("1"), JudgedAt: &judgedAt}}}))
		Expect(meta.IsStatusConditionTrue(st.Conditions, ConditionSynced)).To(BeTrue())
		Expect(meta.IsStatusConditionTrue(st.Conditions, ConditionVulnerabilityGate)).To(BeTrue())
		Eventually(func() []string { return recorder.Events(ns, gen.Name) }).Should(ContainElement(ContainSubstring("Warning " + reasonVulnerabilitiesFound)))

		Eventually(podEvents(vulnPod)).Should(ContainSubstring("Warning " + reasonVulnerabilitiesFound + " " + image +
			":1.0 has 1 Critical (" + testCVE + ", CVE-2026-2), mirrored anyway; see ArtifactMirror " + ns + "/" + gen.Name))
		Consistently(podEvents(otherPod), time.Second).ShouldNot(ContainSubstring(reasonVulnerabilitiesFound))

		By("not repeating the Event on later reconciles")
		count := func() int { return strings.Count(podEvents(vulnPod)(), "Warning "+reasonVulnerabilitiesFound) }
		Expect(count()).To(Equal(1))
		// A schedule drift reconciles the pods; auto-mirror patches it back.
		updateMirror(gen, func(m *mirrorv1alpha1.ArtifactMirror) { m.Spec.Schedule = "0 1 * * *" })
		Eventually(func() string {
			var m mirrorv1alpha1.ArtifactMirror
			_ = k8sClient.Get(ctx, client.ObjectKeyFromObject(gen), &m)
			return m.Spec.Schedule
		}).
			ShouldNot(Equal("0 1 * * *"))
		Consistently(count, 2*time.Second).Should(Equal(1))
	})

	It("relays a blocked tag as MirrorRefused", func() {
		setAction(mirrorv1alpha1.GateActionBlock)
		finish(0, report("1.0", "Blocked"))
		Eventually(condition(ConditionVulnerabilitiesFound)).Should(HaveField("Reason", ReasonBlocked))
		Eventually(podEvents(vulnPod)).Should(ContainSubstring("Warning " + reasonMirrorRefused + " " + reasonVulnerabilityBlocked + ": " +
			image + ":1.0 has 1 Critical"))
		Expect(podEvents(otherPod)()).NotTo(ContainSubstring(reasonVulnerabilityBlocked))
	})

	It("keeps findings when a run scans nothing", func() {
		finish(0, `{"v":2,"skipped":2,"synced":[{"tag":"2.0","digest":"`+hexDigest("2")+`"},{"tag":"1.0","digest":"`+hexDigest("1")+`"}],`+
			`"javaScanned":false,"judgedFingerprint":"`+fpA+`"}`)
		Eventually(func() *metav1.Time { return status().LastSyncTime }).Should(HaveField("Time",
			BeTemporally("==", start.Add(time.Duration(jobs)*time.Minute))))
		Expect(status().Findings).To(HaveLen(1))
		Expect(meta.IsStatusConditionTrue(status().Conditions, ConditionVulnerabilitiesFound)).To(BeTrue())
	})

	It("reports a stale DB under Block as DBStale, not a config refusal", func() {
		finish(syncspec.ExitConfig, `{"v":2,"blocked":1,"scanErrors":1,"synced":[],"gate":"DBStale","javaScanned":false,`+
			`"judgedFingerprint":"`+fpA+`","tagFindings":[{"tag":"2.0","digest":"`+hexDigest("2")+`","verdict":"ScanError",`+
			`"outcome":"Blocked","scanError":"DBStale","scannedAt":"2026-11-01T11:00:00Z"}]}`)
		Eventually(condition(ConditionSynced)).Should(And(HaveField("Status", metav1.ConditionFalse), HaveField("Reason", ReasonDBStale)))
		Eventually(condition(ConditionVulnerabilityGate)).Should(And(HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", ReasonDBStale), HaveField("Message", ContainSubstring("2.0 (DBStale)"))))
		Eventually(podEvents(otherPod)).Should(ContainSubstring("Warning " + reasonMirrorRefused + " DBStale: " + image +
			":2.0 could not be scanned and is not mirrored"))
	})

	It("drops the gate status when the gate is turned off", func() {
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var t mirrorv1alpha1.ClusterMirrorTarget
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: target}, &t); err != nil {
				return err
			}
			t.Spec.AutoMirror.VulnerabilityGate.Enabled = false
			return k8sClient.Update(ctx, &t)
		})).To(Succeed())
		Eventually(func() []mirrorv1alpha1.VulnerabilityFinding { return status().Findings }).Should(BeEmpty())
		st := status()
		Expect(st.Gate).To(BeNil())
		Expect(st.JavaScanned).To(BeNil())
		Expect(meta.FindStatusCondition(st.Conditions, ConditionVulnerabilitiesFound)).To(BeNil())
		Expect(meta.FindStatusCondition(st.Conditions, ConditionVulnerabilityGate)).To(BeNil())
	})
})

// TestApplyResultUntrustedGateReport checks that a forged version 2 report
// is refused as a crash and leaves no gate fields (threat model T12).
func TestApplyResultUntrustedGateReport(t *testing.T) {
	job := &batchv1.Job{}
	job.Name = "j"
	done := &batchv1.JobCondition{Type: batchv1.JobComplete, LastTransitionTime: metav1.Now()}
	for _, msg := range []string{
		`{"v":2,"synced":[],"tagFindings":[{"tag":"1.0","digest":"sha256:x","verdict":"Findings","outcome":"Copied","scannedAt":"2026-11-01T10:00:00Z"}]}`,
		`{"v":2,"synced":[],"gate":"Clean"}`,
		`{"v":2,"synced":[],"judgedFingerprint":"zz"}`,
		`{"v":2,"synced":[],"judged":[{"tag":"-x","digest":"` + hexDigest("1") + `"}]}`,
		`{"v":2,"synced":[],"tagFindings":[{"tag":"1.0","digest":"` + hexDigest("1") + `","verdict":"Findings","outcome":"Copied","topIDs":["rm -rf"],"scannedAt":"2026-11-01T10:00:00Z"}]}`,
		// Status requires scannedAt: a zero time would fail every status update.
		`{"v":2,"synced":[],"tagFindings":[{"tag":"1.0","digest":"` + hexDigest("1") + `","verdict":"Findings","outcome":"Copied"}]}`,
		`{"v":2,"synced":[],"tagFindings":[{"tag":"1.0","digest":"` + hexDigest("1") + `","verdict":"Findings","outcome":"Copied","scannedAt":"0001-01-01T00:00:00Z"}]}`,
		`{"v":2,"synced":[],"tagFindings":[{"tag":"1.0","digest":"` + hexDigest("1") + `","verdict":"Findings","outcome":"Copied","scannedAt":"2099-01-01T00:00:00Z"}]}`,
		`{"v":1,"synced":[],"gate":"ok"}`,
		`{"v":3,"synced":[]}`,
	} {
		m := &mirrorv1alpha1.ArtifactMirror{}
		cond, rep := applyResult(m, job, done, &corev1.ContainerStateTerminated{ExitCode: 0, Message: msg}, false)
		if cond.Reason != ReasonCrashed || rep != nil {
			t.Errorf("%s: reason %s, report %v", msg, cond.Reason, rep)
		}
	}
}

var _ = Describe("vulnerability gate without a scanner", func() {
	podEvents := func(p *corev1.Pod) func() string {
		return func() string { return strings.Join(recorder.Events(p.Namespace, p.Name), "\n") }
	}
	// setup creates a target with the gate on and no scanner.url (the
	// suite has no in-chart server), a namespace and a pod using an image.
	setup := func(name string, onScanError mirrorv1alpha1.GateAction) (*corev1.Pod, *mirrorv1alpha1.ArtifactMirror) {
		ns := name + "-ns"
		image := ghcrRegistry + "/org/" + name
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		createReadyTarget(name, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.AllowedSources = []mirrorv1alpha1.RegistryHost{ghcrRegistry}
			t.Spec.Projects = []mirrorv1alpha1.TargetProject{{Name: otherProject, NamespaceSelector: &metav1.LabelSelector{}}}
			t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: otherProject,
				VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{Enabled: true, OnScanError: onScanError}}
		})
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: ns, Annotations: map[string]string{mirrorv1alpha1.AutoMirrorAnnotation: name}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image + ":1.0"}}},
		}
		Expect(k8sClient.Create(ctx, p)).To(Succeed())
		gen := &mirrorv1alpha1.ArtifactMirror{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: generatedNameOf(image)}}
		DeferCleanup(func() {
			Expect(k8sClient.Delete(ctx, p, client.GracePeriodSeconds(0))).To(Succeed())
			time.Sleep(500 * time.Millisecond)
			deleteAndWait(gen)
			deleteAndWait(&mirrorv1alpha1.ClusterMirrorTarget{ObjectMeta: metav1.ObjectMeta{Name: name}})
		})
		return p, gen
	}
	gauge := func(target string) func() float64 {
		return func() float64 { return gateValues()[target] }
	}
	targetEvents := func(name string) func() string {
		return func() string { return strings.Join(recorder.Events("", name), "\n") }
	}

	It("is loud under onScanError Report: target, mirror, pod and metric", func() {
		const target = "gate-unconfigured-report"
		p, gen := setup(target, mirrorv1alpha1.GateActionReport)
		Eventually(targetCondition(target, ConditionScannerReady)).Should(And(
			HaveField("Status", metav1.ConditionFalse), HaveField("Reason", ReasonNotConfigured)))
		Eventually(targetEvents(target)).Should(ContainSubstring("Warning " + ReasonNotConfigured))
		Eventually(gauge(target)).Should(Equal(1.0))

		Eventually(func() *metav1.Condition {
			var m mirrorv1alpha1.ArtifactMirror
			if k8sClient.Get(ctx, client.ObjectKeyFromObject(gen), &m) != nil {
				return nil
			}
			return meta.FindStatusCondition(m.Status.Conditions, ConditionVulnerabilityGate)
		}).Should(And(HaveField("Status", metav1.ConditionFalse), HaveField("Reason", ReasonNotConfigured),
			HaveField("Message", notConfigured)))
		Expect(mirrorReady(gen)()).To(HaveField("Status", metav1.ConditionTrue))
		Eventually(podEvents(p)).Should(And(ContainSubstring("Warning "+reasonVulnerabilityScanFail+" "+ReasonNotConfigured),
			ContainSubstring("mirrored without scan")))

		By("recording the mirror Event once")
		mirrorWarnings := func() int {
			return strings.Count(strings.Join(recorder.Events(gen.Namespace, gen.Name), "\n"), "Warning "+ReasonNotConfigured)
		}
		Eventually(mirrorWarnings).Should(Equal(1))
		updateMirror(gen, func(m *mirrorv1alpha1.ArtifactMirror) { m.Annotations = map[string]string{"example.com/poke": "1"} })
		Consistently(mirrorWarnings, 2*time.Second).Should(Equal(1))

		By("clearing the metric when the gate is turned off")
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var t mirrorv1alpha1.ClusterMirrorTarget
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: target}, &t); err != nil {
				return err
			}
			t.Spec.AutoMirror.VulnerabilityGate.Enabled = false
			return k8sClient.Update(ctx, &t)
		})).To(Succeed())
		Eventually(gateValues).ShouldNot(HaveKey(target))
	})

	It("refuses the mirror under onScanError Block", func() {
		const target = "gate-unconfigured-block"
		p, gen := setup(target, mirrorv1alpha1.GateActionBlock)
		Eventually(gauge(target)).Should(Equal(1.0))
		Eventually(mirrorReady(gen)).Should(And(HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", ReasonScannerUnavailable), HaveField("Message", ContainSubstring("gate enabled but scanner not configured"))))
		_, err := cronJob(gen)()
		Expect(notFound(err)).To(BeTrue())
		Eventually(podEvents(p)).Should(And(ContainSubstring("Warning "+reasonMirrorRefused+" "+ReasonScannerUnavailable),
			ContainSubstring("gate enabled but scanner not configured")))
	})
})

// gateValues returns the unscanned gauge per target label.
func gateValues() map[string]float64 {
	ch := make(chan prometheus.Metric, 100)
	gateUnscanned.Collect(ch)
	close(ch)
	out := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if m.Write(&pb) == nil && len(pb.GetLabel()) == 1 {
			out[pb.GetLabel()[0].GetValue()] = pb.GetGauge().GetValue()
		}
	}
	return out
}
