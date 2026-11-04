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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// gate resolves the vulnerability gate of a generated mirror of a gated
// target into s.Gate and the scanner sidecar. Every other mirror gets
// neither and renders as before. ScannerReady does not matter here: a Job
// finds an unreachable or mismatched server itself and applies
// onScanError. Without a usable scanner configuration there is no sidecar
// to render: under onScanError Block the mirror is refused with the
// returned message, so nothing is copied unscanned; under Report it
// renders ungated and copies, as a scan error would.
func (r *ArtifactMirrorReconciler) gate(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror, s *syncspec.Spec) (*sidecar, string, error) {
	g := gateOf(t)
	if g == nil || !isGenerated(t, m) {
		return nil, "", nil
	}
	var list mirrorv1alpha1.VulnerabilityExceptionList
	if err := r.List(ctx, &list); err != nil {
		return nil, "", err
	}
	var judged []syncspec.SyncedTag
	var fingerprint string
	if gs := m.Status.Gate; gs != nil {
		fingerprint = gs.JudgedFingerprint
		for _, j := range gs.Judged {
			judged = append(judged, syncspec.SyncedTag{Tag: j.Tag, Digest: j.Digest})
		}
	}
	_, problem := effectiveScanner(g.Scanner, r.Scanner)
	var out *syncspec.Gate
	if problem == "" {
		var err error
		out, err = syncspec.NewGate(g, syncspec.ScannerDefaults{URL: r.Scanner.URL, Version: r.Scanner.Version, Image: r.Scanner.Image},
			cmp.Or(r.ClusterDomain, DefaultClusterDomain), activeExceptions(list.Items, t, m, time.Now()), judged, fingerprint)
		if err != nil {
			problem = "invalid scanner URL"
		}
	}
	if problem != "" {
		if g.OnScanError == mirrorv1alpha1.GateActionBlock {
			return nil, fmt.Sprintf("gate enabled but scanner not configured on ClusterMirrorTarget %s (%s); onScanError is Block, images are not copied", t.Name, problem), nil
		}
		return nil, "", nil
	}
	s.Gate = out
	sc := &sidecar{gate: out, scanner: g.Scanner}
	// The in-chart token goes only to the in-chart server: an external
	// scanner.url without tokenSecretRef gets no token (threat model T33).
	switch {
	case g.Scanner != nil && g.Scanner.TokenSecretRef != nil:
		sc.token = g.Scanner.TokenSecretRef
	case (g.Scanner == nil || g.Scanner.URL == "") && r.Scanner.TokenSecret != "":
		sc.token = &mirrorv1alpha1.TokenSecretKeyRef{Name: r.Scanner.TokenSecret, Key: defaultTokenKey}
	}
	return sc, "", nil
}

// activeExceptions returns the exceptions that apply to m at now, sorted by
// name so the spec does not change with list order: same target, m's
// namespace and source, not expired and within maxExceptionDuration. The
// Job checks expiry again against its own clock.
func activeExceptions(excs []mirrorv1alpha1.VulnerabilityException, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror, now time.Time) []mirrorv1alpha1.VulnerabilityException {
	maxDuration := defaultMaxExceptionDuration
	if g := gateOf(t); g != nil && g.MaxExceptionDuration != nil {
		maxDuration = g.MaxExceptionDuration.Duration
	}
	src := canonicalSource(m.Spec.Source)
	var out []mirrorv1alpha1.VulnerabilityException
	for _, e := range excs {
		if e.Spec.TargetRef == t.Name && slices.Contains(e.Spec.Namespaces, m.Namespace) && e.Spec.Repository == src &&
			e.DeletionTimestamp.IsZero() && now.Before(e.Spec.Expires.Time) && !e.Spec.Expires.After(e.CreationTimestamp.Add(maxDuration)) {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b mirrorv1alpha1.VulnerabilityException) int { return strings.Compare(a.Name, b.Name) })
	return out
}

const (
	// maxFindings caps status.findings, as the CRD schema does.
	maxFindings = 20
	// maxJudged caps status.gate.judged, as the CRD schema does.
	maxJudged = 200
	// maxGateMessage caps the gate condition messages.
	maxGateMessage = 1024
	// maxGateEvents caps the gate Events on a mirror per sync.
	maxGateEvents = 5
	// javaNotScanned ends gate messages while javaDB is Disabled.
	javaNotScanned = "JAR files not scanned"
	// notConfigured is the VulnerabilityGate message of a gated mirror
	// rendered without a scanner.
	notConfigured = "gate enabled but scanner not configured; images are copied unscanned"
)

// Event reasons of the gate, on mirrors and pods.
const (
	reasonVulnerabilitiesFound  = "VulnerabilitiesFound"
	reasonVulnerabilityScanFail = "VulnerabilityScanFailed"
	reasonVulnerabilityBlocked  = "VulnerabilityBlocked"
)

// gateConditions keeps the gate status of m in line with its rendering:
// none on mirrors that are not gated, VulnerabilityGate False with a
// Warning Event when a gated mirror gets no usable scanner (sc nil), and
// no stale not-configured condition once it has one.
func gateConditions(m *mirrorv1alpha1.ArtifactMirror, gated bool, sc *sidecar, ev *pending) {
	st := &m.Status
	switch {
	case !gated:
		st.Findings, st.JavaScanned, st.Gate = nil, nil, nil
		meta.RemoveStatusCondition(&st.Conditions, ConditionVulnerabilitiesFound)
		meta.RemoveStatusCondition(&st.Conditions, ConditionVulnerabilityGate)
	case sc == nil:
		if c := meta.FindStatusCondition(st.Conditions, ConditionVulnerabilityGate); c == nil || c.Reason != ReasonNotConfigured {
			ev.add(corev1.EventTypeWarning, ReasonNotConfigured, "Reconcile", notConfigured)
		}
		meta.SetStatusCondition(&st.Conditions, metav1.Condition{Type: ConditionVulnerabilityGate, Status: metav1.ConditionFalse,
			Reason: ReasonNotConfigured, Message: notConfigured, ObservedGeneration: m.Generation})
	default:
		if c := meta.FindStatusCondition(st.Conditions, ConditionVulnerabilityGate); c != nil && c.Reason == ReasonNotConfigured {
			meta.RemoveStatusCondition(&st.Conditions, ConditionVulnerabilityGate)
		}
	}
}

// applyGate records the gate fields of a version 2 report. It is applied
// again on every reconcile while the pod exists, so it must be idempotent.
// Tags this run judged or reported replace their old entries; the others
// keep theirs, because a run with nothing to scan (gate "") skips tags
// judged earlier. Judged pairs from another fingerprint are dropped. Only
// a successful run with a complete synced list prunes tags that are no
// longer selected; a pruned judged tag is only scanned again.
func applyGate(m *mirrorv1alpha1.ArtifactMirror, rep *syncspec.Report, ok bool, isNew bool, ev *pending) {
	st := &m.Status
	if rep.JavaScanned != nil {
		st.JavaScanned = new(*rep.JavaScanned)
	}
	javaScanned := st.JavaScanned == nil || *st.JavaScanned
	run := map[string]bool{}
	for _, j := range rep.Judged {
		run[j.Tag] = true
	}
	for _, f := range rep.TagFindings {
		run[f.Tag] = true
	}
	present := map[string]string{}
	for _, s := range rep.Synced {
		present[s.Tag] = s.Digest
	}
	scanErr := map[string]bool{}
	for _, f := range rep.TagFindings {
		scanErr[f.Tag] = f.Verdict == mirrorv1alpha1.VerdictScanError
	}
	keep := func(tag string) bool { _, on := present[tag]; return !run[tag] && (!ok || rep.Truncated || on) }

	// Judged pairs: this run first, then the stored ones under the same
	// fingerprint. judged is the one report field fed back into later
	// Jobs, so only pairs the run also reports on the target with the same
	// digest, and not as a scan error, are kept (threat model T12, T34).
	var judged []mirrorv1alpha1.SyncedTag
	for _, j := range rep.Judged {
		if d, on := present[j.Tag]; on && d == j.Digest && !scanErr[j.Tag] {
			judged = append(judged, mirrorv1alpha1.SyncedTag{Tag: j.Tag, Digest: j.Digest})
		}
	}
	if old := st.Gate; old != nil && old.JudgedFingerprint == rep.JudgedFingerprint {
		for _, j := range old.Judged {
			if keep(j.Tag) {
				judged = append(judged, j)
			}
		}
	}
	st.Gate = &mirrorv1alpha1.GateStatus{JudgedFingerprint: rep.JudgedFingerprint, Judged: judged[:min(len(judged), maxJudged)]}

	findings := make([]mirrorv1alpha1.VulnerabilityFinding, 0, len(rep.TagFindings)+len(st.Findings))
	for _, f := range rep.TagFindings {
		findings = append(findings, mirrorv1alpha1.VulnerabilityFinding{
			Tag: f.Tag, Digest: f.Digest, Verdict: f.Verdict, Outcome: f.Outcome, PresentOnTarget: f.PresentOnTarget,
			Severity: f.Severity, Counts: f.Counts, TopIDs: f.TopIDs, ScanError: f.ScanError,
			JavaScanned: javaScanned, ScannedAt: metav1.NewTime(f.ScannedAt),
		})
	}
	if isNew {
		gateEvents(ev, st.Findings, findings)
	}
	for _, f := range st.Findings {
		if keep(f.Tag) {
			findings = append(findings, f)
		}
	}
	// Newest scan first, then the most severe.
	slices.SortStableFunc(findings, func(a, b mirrorv1alpha1.VulnerabilityFinding) int {
		return cmp.Or(b.ScannedAt.Compare(a.ScannedAt.Time), cmp.Compare(severityRank(b), severityRank(a)), strings.Compare(a.Tag, b.Tag))
	})
	setGateConditions(m, findings, rep.Gate, javaScanned)
	st.Findings = findings[:min(len(findings), maxFindings)]
	if len(st.Findings) == 0 {
		st.Findings = nil
	}
}

// severityRank orders findings: scan errors and higher severities first.
func severityRank(f mirrorv1alpha1.VulnerabilityFinding) int {
	if f.Verdict == mirrorv1alpha1.VerdictScanError {
		return 6
	}
	return map[mirrorv1alpha1.Severity]int{
		mirrorv1alpha1.SeverityCritical: 5, mirrorv1alpha1.SeverityHigh: 4, mirrorv1alpha1.SeverityMedium: 3,
		mirrorv1alpha1.SeverityLow: 2, mirrorv1alpha1.SeverityUnknown: 1,
	}[f.Severity]
}

// setGateConditions sets VulnerabilitiesFound and VulnerabilityGate from
// all findings, before the status cap, and the run-level gate state.
func setGateConditions(m *mirrorv1alpha1.ArtifactMirror, findings []mirrorv1alpha1.VulnerabilityFinding, gate string, javaScanned bool) {
	suffix := ""
	if !javaScanned {
		suffix = "; " + javaNotScanned
	}
	var vulnerable, failed []string
	blocked := false
	scanReason := ""
	for _, f := range findings {
		switch f.Verdict {
		case mirrorv1alpha1.VerdictFindings:
			vulnerable = append(vulnerable, fmt.Sprintf("%s %s (%s)", f.Tag, f.Severity, strings.Join(f.TopIDs, ", ")))
			blocked = blocked || f.Outcome == mirrorv1alpha1.OutcomeBlocked
		case mirrorv1alpha1.VerdictScanError:
			failed = append(failed, fmt.Sprintf("%s (%s)", f.Tag, f.ScanError))
			scanReason = cmp.Or(scanReason, f.ScanError)
		}
	}
	msg := func(prefix string, items []string) string {
		s := prefix + strings.Join(items, "; ")
		if n := maxGateMessage - len(suffix); len(s) > n {
			s = cut(s, n-3) + "..."
		}
		return s + suffix
	}
	vf := metav1.Condition{Type: ConditionVulnerabilitiesFound, Status: metav1.ConditionFalse, Reason: ReasonClear,
		Message: "no selected tag has findings" + suffix, ObservedGeneration: m.Generation}
	if len(vulnerable) > 0 {
		vf.Status, vf.Reason, vf.Message = metav1.ConditionTrue, ReasonReported, msg("tags with findings: ", vulnerable)
		if blocked {
			vf.Reason = ReasonBlocked
		}
	}
	meta.SetStatusCondition(&m.Status.Conditions, vf)

	vg := metav1.Condition{Type: ConditionVulnerabilityGate, Status: metav1.ConditionTrue, Reason: ReasonReady,
		Message: "every scanned tag was judged" + suffix, ObservedGeneration: m.Generation}
	if gate != "" && gate != syncspec.GateOK {
		scanReason = gate
	}
	if scanReason != "" {
		vg.Status, vg.Reason, vg.Message = metav1.ConditionFalse, scanReason, msg("tags not judged: ", failed)
	}
	meta.SetStatusCondition(&m.Status.Conditions, vg)
}

// gateEvents queues one Warning per tag and digest that is new in this
// run's findings, at most maxGateEvents.
func gateEvents(ev *pending, old, run []mirrorv1alpha1.VulnerabilityFinding) {
	n := 0
	for _, f := range run {
		if slices.ContainsFunc(old, func(o mirrorv1alpha1.VulnerabilityFinding) bool {
			return o.Tag == f.Tag && o.Digest == f.Digest && o.Verdict == f.Verdict && o.Outcome == f.Outcome
		}) {
			continue
		}
		if n++; n > maxGateEvents {
			return
		}
		outcome := "copied"
		if f.Outcome == mirrorv1alpha1.OutcomeBlocked {
			outcome = "blocked"
		}
		if f.Verdict == mirrorv1alpha1.VerdictScanError {
			ev.add(corev1.EventTypeWarning, reasonVulnerabilityScanFail, "Scan",
				fmt.Sprintf("%s: tag %s (%s) could not be scanned, %s", f.ScanError, f.Tag, f.Digest, outcome))
			continue
		}
		ev.add(corev1.EventTypeWarning, reasonVulnerabilitiesFound, "Scan",
			fmt.Sprintf("tag %s (%s): %s, %s", f.Tag, f.Digest, findingSummary(f), outcome))
	}
}

// findingSummary is "<n> <severity> (<top three IDs>)".
func findingSummary(f mirrorv1alpha1.VulnerabilityFinding) string {
	n := map[mirrorv1alpha1.Severity]int32{
		mirrorv1alpha1.SeverityCritical: f.Counts.Critical, mirrorv1alpha1.SeverityHigh: f.Counts.High,
		mirrorv1alpha1.SeverityMedium: f.Counts.Medium, mirrorv1alpha1.SeverityLow: f.Counts.Low,
		mirrorv1alpha1.SeverityUnknown: f.Counts.Unknown,
	}[f.Severity]
	return fmt.Sprintf("%d %s (%s)", n, f.Severity, strings.Join(f.TopIDs[:min(len(f.TopIDs), 3)], ", "))
}
