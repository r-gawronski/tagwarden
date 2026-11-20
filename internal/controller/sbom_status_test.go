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
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	dto "github.com/prometheus/client_model/go"
	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

const (
	sbomStatusTarget = "sbom-status-unit"
	sbomTag          = "4.2"
)

func sbomReport(generated int, failures ...syncspec.SBOMFailure) syncspec.Report {
	return syncspec.Report{V: syncspec.ReportVersionGate, SBOMGenerated: generated, SBOMFailed: len(failures), SBOMFailures: failures}
}

func sbomFailure(tag, reason string, published bool) syncspec.SBOMFailure {
	return syncspec.SBOMFailure{Tag: tag, Digest: hexDigest("1"), Reason: reason, Published: published}
}

func sbomCond(m *mirrorv1alpha1.ArtifactMirror) *metav1.Condition {
	return meta.FindStatusCondition(m.Status.Conditions, ConditionSBOM)
}

func TestApplySBOM(t *testing.T) {
	m := &mirrorv1alpha1.ArtifactMirror{}
	m.Spec.TargetRef = sbomStatusTarget
	var ev pending

	// A failed run without SBOM failures says nothing about SBOMs.
	applySBOM(m, sbomReport(0), false, nil, &ev)
	if c := sbomCond(m); c != nil || len(ev) != 0 {
		t.Fatalf("failed run: %+v %v", c, ev)
	}
	applySBOM(m, sbomReport(2), true, nil, &ev)
	if c := sbomCond(m); c == nil || c.Status != metav1.ConditionTrue || c.Reason != ReasonSBOMAttached ||
		!strings.Contains(c.Message, "attached 2 generated and 0 upstream") {
		t.Fatalf("attached: %+v", c)
	}

	counter := func(reason, published string) float64 {
		var pb dto.Metric
		if err := sbomFailures.WithLabelValues(sbomStatusTarget, reason, published).Write(&pb); err != nil {
			t.Fatal(err)
		}
		return pb.GetCounter().GetValue()
	}
	before := counter(syncspec.SBOMGenerationFailed, "false")
	rep := sbomReport(0, sbomFailure("1.1", syncspec.SBOMMissing, true), sbomFailure(sbomTag, syncspec.SBOMGenerationFailed, false))
	seen := applySBOM(m, rep, false, nil, &ev)
	c := sbomCond(m)
	if c.Status != metav1.ConditionFalse || c.Reason != ReasonSBOMGenerationFailed ||
		c.Message != "not published: 4.2@"+hexDigest("1")+" (GenerationFailed); published without an SBOM: 1.1@"+hexDigest("1")+" (Missing)" {
		t.Errorf("failures: %+v", c)
	}
	if len(ev) != 2 || ev[0].reason != reasonSBOMFailed || ev[0].typ != corev1.EventTypeWarning ||
		!strings.Contains(ev[0].note, "tag 1.1 ("+hexDigest("1")+"): SBOM Missing, published without an SBOM") ||
		!strings.HasSuffix(ev[1].note, "SBOM GenerationFailed, not published") {
		t.Errorf("events: %+v", ev)
	}
	if got := counter(syncspec.SBOMGenerationFailed, "false") - before; got != 1 {
		t.Errorf("counter grew by %v", got)
	}

	// The same pairs on the next run: no new Events, the counter counts.
	ev = nil
	seen = applySBOM(m, rep, false, seen, &ev)
	if len(ev) != 0 || counter(syncspec.SBOMGenerationFailed, "false")-before != 2 {
		t.Errorf("repeated events %v", ev)
	}
	// A new digest of the same tag is a new failure.
	moved := sbomFailure(sbomTag, syncspec.SBOMGenerationFailed, false)
	moved.Digest = hexDigest("2")
	applySBOM(m, sbomReport(0, moved), false, seen, &ev)
	if len(ev) != 1 {
		t.Errorf("events for a new digest: %v", ev)
	}
}

func TestApplySBOMReasonsAndCap(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failures []syncspec.SBOMFailure
		want     string
	}{
		{"too large", []syncspec.SBOMFailure{sbomFailure("1", syncspec.SBOMTooLarge, false)}, ReasonSBOMGenerationFailed},
		{"attach", []syncspec.SBOMFailure{sbomFailure("1", syncspec.SBOMAttachFailed, false)}, ReasonSBOMAttachFailed},
		{"missing only", []syncspec.SBOMFailure{sbomFailure("1", syncspec.SBOMMissing, true)}, ReasonSBOMMissing},
		// An unpublished tag names the reason before a published one.
		{"unpublished first", []syncspec.SBOMFailure{sbomFailure("1", syncspec.SBOMMissing, true),
			sbomFailure("2", syncspec.SBOMAttachFailed, false)}, ReasonSBOMAttachFailed},
	} {
		m := &mirrorv1alpha1.ArtifactMirror{}
		applySBOM(m, sbomReport(0, tc.failures...), false, nil, &pending{})
		if c := sbomCond(m); c.Reason != tc.want {
			t.Errorf("%s: reason %s, want %s", tc.name, c.Reason, tc.want)
		}
	}

	failures := make([]syncspec.SBOMFailure, 0, syncspec.MaxSBOMFailures)
	for i := range syncspec.MaxSBOMFailures {
		failures = append(failures, sbomFailure(strings.Repeat("t", 120)+string(rune('a'+i)), syncspec.SBOMGenerationFailed, false))
	}
	rep := sbomReport(0, failures...)
	rep.SBOMFailed = 15
	m := &mirrorv1alpha1.ArtifactMirror{}
	applySBOM(m, rep, false, nil, &pending{})
	if c := sbomCond(m); len(c.Message) > maxGateMessage || !strings.HasPrefix(c.Message, sbomNotPublished) || !strings.HasSuffix(c.Message, "...") {
		t.Errorf("message of %d bytes: %q", len(c.Message), c.Message)
	}
	rep = sbomReport(0, sbomFailure("1", syncspec.SBOMGenerationFailed, false))
	rep.SBOMFailed = 6
	applySBOM(m, rep, false, nil, &pending{})
	if c := sbomCond(m); !strings.HasSuffix(c.Message, "; 5 more tags failed, the sync Job log lists them") {
		t.Errorf("more: %q", c.Message)
	}
}

// recordSBOM reads only sync Jobs that ran the generator.
func TestRecordSBOM(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	failing := sbomReport(0, sbomFailure(sbomTag, syncspec.SBOMGenerationFailed, false))
	for _, tc := range []struct {
		name    string
		label   string
		trigger string
		term    func(t *testing.T) *corev1.ContainerStateTerminated
		applied bool
	}{
		{"generator", SBOMTrivy, "", func(t *testing.T) *corev1.ContainerStateTerminated {
			return termination(t, syncspec.ExitSyncFailed, &failing)
		}, true},
		{"no generator", "", "", func(t *testing.T) *corev1.ContainerStateTerminated {
			return termination(t, syncspec.ExitSyncFailed, &failing)
		}, false},
		{"rescan", SBOMTrivy, TriggerRescan, func(t *testing.T) *corev1.ContainerStateTerminated {
			return termination(t, syncspec.ExitSyncFailed, &failing)
		}, false},
		{"unparsable report", SBOMTrivy, "", func(*testing.T) *corev1.ContainerStateTerminated {
			return &corev1.ContainerStateTerminated{ExitCode: 1, Message: "{"}
		}, false},
		{"version 1", SBOMTrivy, "", func(t *testing.T) *corev1.ContainerStateTerminated {
			return termination(t, syncspec.ExitOK, &syncspec.Report{V: syncspec.ReportVersion})
		}, false},
		{"no result", SBOMTrivy, "", func(*testing.T) *corev1.ContainerStateTerminated { return nil }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := finishedJobAt("j", tc.trigger, t0)
			job.Spec.Template.Labels = map[string]string{LabelSBOM: tc.label}
			m := &mirrorv1alpha1.ArtifactMirror{}
			m.Namespace, m.Name = "ns", "m"
			var ev pending
			r := &ArtifactMirrorReconciler{}
			r.recordSBOM(m, job, tc.term(t), &ev)
			if got := sbomCond(m) != nil; got != tc.applied {
				t.Errorf("applied %t, want %t", got, tc.applied)
			}
		})
	}
}

// A tag not published for its SBOM fails the run: Synced is False and its
// message counts the SBOM failure.
func TestSBOMFailureFailsSync(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	rep := sbomReport(0, sbomFailure(sbomTag, syncspec.SBOMGenerationFailed, false))
	rep.Failed = 1
	m := &mirrorv1alpha1.ArtifactMirror{}
	job := finishedJobAt("j", "", t0)
	job.Status.Conditions[0].Type = batchv1.JobFailed
	recordJob(m, job, finished(job), termination(t, syncspec.ExitSyncFailed, &rep), false, &pending{})
	c := meta.FindStatusCondition(m.Status.Conditions, ConditionSynced)
	if c.Status != metav1.ConditionFalse || c.Reason != ReasonSyncFailed || !strings.Contains(c.Message, "SBOM failed for 1") {
		t.Errorf("synced %+v", c)
	}
}

func TestRelaySBOMMissing(t *testing.T) {
	rec := &testRecorder{}
	r := &AutoMirrorReconciler{Recorder: rec}
	pod := &corev1.Pod{}
	pod.Namespace, pod.Name = "ns", "p"
	cur := &mirrorv1alpha1.ArtifactMirror{}
	cur.Namespace, cur.Name = "ns", "gen"
	set := func(c metav1.Condition) { meta.SetStatusCondition(&cur.Status.Conditions, c) }
	set(metav1.Condition{Type: ConditionSynced, Status: metav1.ConditionFalse, Reason: ReasonSyncFailed, Message: "failed 1"})
	set(metav1.Condition{Type: ConditionSBOM, Status: metav1.ConditionFalse, Reason: ReasonSBOMGenerationFailed,
		Message: sbomNotPublished + "4.2@" + hexDigest("1") + " (GenerationFailed)"})
	r.relay(pod, "registry.k8s.io/pause", cur, []string{sbomTag})
	got := rec.Events("ns", "p")
	if len(got) != 1 || !strings.Contains(got[0], "Warning "+reasonMirrorRefused+" "+reasonSBOMMissingRelay+": not published: 4.2@") {
		t.Errorf("events %v", got)
	}

	// Published without an SBOM: the pod runs, the relay says what Synced says.
	rec = &testRecorder{}
	r = &AutoMirrorReconciler{Recorder: rec}
	set(metav1.Condition{Type: ConditionSBOM, Status: metav1.ConditionFalse, Reason: ReasonSBOMMissing,
		Message: "published without an SBOM: 4.2@" + hexDigest("1") + " (Missing)"})
	r.relay(pod, "registry.k8s.io/pause", cur, []string{sbomTag})
	if got := rec.Events("ns", "p"); len(got) != 1 || !strings.Contains(got[0], "Warning "+reasonSyncFailed) {
		t.Errorf("events %v", got)
	}
}
