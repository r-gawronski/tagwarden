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
	"strconv"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// ConditionSBOMReady reports on a target with an SBOM policy whether the
// policy can run and is not undercut by another target.
const ConditionSBOMReady = "SBOMReady"

// ReasonWeakerTargetOnRegistry: another target on the same registry lists
// a project of a target with required: true under a weaker SBOM policy.
const ReasonWeakerTargetOnRegistry = "WeakerTargetOnRegistry"

// ReasonSBOMNotConfigured: the target requires SBOMs but has no generator
// image, so its image mirrors get no CronJob.
const ReasonSBOMNotConfigured = "SBOMNotConfigured"

// defaultSBOMTimeout is the generation timeout of one platform child
// without sbom.generator.timeout.
const defaultSBOMTimeout = 10 * time.Minute

// sbomOf returns the SBOM policy of t, or nil when it is off.
func sbomOf(t *mirrorv1alpha1.ClusterMirrorTarget) *mirrorv1alpha1.SBOMPolicy {
	if p := t.Spec.SBOM; p != nil && p.Mode != "" && p.Mode != mirrorv1alpha1.SBOMModeDisabled {
		return p
	}
	return nil
}

// sbomFormat returns the format of p, CycloneDX when unset.
func sbomFormat(p *mirrorv1alpha1.SBOMPolicy) mirrorv1alpha1.SBOMFormat {
	return cmp.Or(p.Format, mirrorv1alpha1.SBOMFormatCycloneDX)
}

// effectiveGenerator overlays the generator image and version of p on the
// manager's --trivy-image and --trivy-version. It returns a message when
// there is no image to run.
func effectiveGenerator(p *mirrorv1alpha1.SBOMPolicy, defaults ScannerConfig) (image, version, problem string) {
	image, version = defaults.Image, defaults.Version
	if g := p.Generator; g != nil && g.Image != "" {
		image, version = g.Image, g.Version
	}
	if image == "" || version == "" {
		return image, version, "no SBOM generator: set sbom.generator.image and sbom.generator.version, or trivy.image in the chart"
	}
	return image, version, ""
}

// weakerSBOM returns why other publishes tags that p would not, or "".
// Only a policy with required: true can be undercut.
func weakerSBOM(p *mirrorv1alpha1.SBOMPolicy, other *mirrorv1alpha1.ClusterMirrorTarget) string {
	o := sbomOf(other)
	switch {
	case o == nil:
		return "no SBOM policy"
	case !o.Required:
		return "SBOM not required"
	case sbomFormat(o) != sbomFormat(p):
		return fmt.Sprintf("format %s", sbomFormat(o))
	case p.Mode == mirrorv1alpha1.SBOMModeGenerate && o.Mode != mirrorv1alpha1.SBOMModeGenerate:
		return fmt.Sprintf("mode %s", o.Mode)
	}
	return ""
}

// weakerTargets lists the other targets on the registry of t that list a
// project of t under a weaker SBOM policy, sorted by name. Tags pushed
// through them reach the same repositories without the SBOM t requires.
func weakerTargets(t *mirrorv1alpha1.ClusterMirrorTarget, targets []mirrorv1alpha1.ClusterMirrorTarget) []string {
	p := sbomOf(t)
	if p == nil || !p.Required {
		return nil
	}
	projects := map[mirrorv1alpha1.ProjectName]bool{}
	for _, pr := range t.Spec.Projects {
		projects[pr.Name] = true
	}
	var out []string
	for i := range targets {
		o := &targets[i]
		if o.Name == t.Name || !o.DeletionTimestamp.IsZero() || registryKey(o.Spec.Registry) != registryKey(t.Spec.Registry) {
			continue
		}
		var shared []string
		for _, pr := range o.Spec.Projects {
			if projects[pr.Name] {
				shared = append(shared, string(pr.Name))
			}
		}
		if why := weakerSBOM(p, o); why != "" && len(shared) > 0 {
			out = append(out, fmt.Sprintf("%s (projects %s: %s)", o.Name, strings.Join(shared, ", "), why))
		}
	}
	slices.Sort(out)
	return out
}

// sbomCondition returns the SBOMReady condition of a target with an SBOM
// policy. targets are all targets, t included; they are only read when the
// policy is required.
func sbomCondition(t *mirrorv1alpha1.ClusterMirrorTarget, targets []mirrorv1alpha1.ClusterMirrorTarget, defaults ScannerConfig) metav1.Condition {
	p := sbomOf(t)
	c := metav1.Condition{Type: ConditionSBOMReady, Status: metav1.ConditionFalse, ObservedGeneration: t.Generation}
	_, version, problem := effectiveGenerator(p, defaults)
	if problem != "" {
		effect := "Jobs run without the generator"
		if p.Required {
			effect = "image mirrors get no CronJob"
		}
		c.Reason, c.Message = ReasonNotConfigured, fmt.Sprintf("mode %s but %s; %s", p.Mode, problem, effect)
		return c
	}
	if weak := weakerTargets(t, targets); len(weak) > 0 {
		msg := fmt.Sprintf("other ClusterMirrorTargets on registry %s publish to the same projects with a weaker SBOM policy: %s",
			t.Spec.Registry, strings.Join(weak, "; "))
		c.Reason, c.Message = ReasonWeakerTargetOnRegistry, capCondition(msg)
		return c
	}
	c.Status, c.Reason = metav1.ConditionTrue, ReasonReady
	c.Message = fmt.Sprintf("mode %s, format %s, required %t, generator trivy/%s",
		p.Mode, sbomFormat(p), p.Required, version)
	return c
}

// capCondition cuts a condition message to maxGateMessage bytes.
func capCondition(s string) string {
	if len(s) <= maxGateMessage {
		return s
	}
	return cut(s, maxGateMessage-3) + "..."
}

// targetsWithRequiredSBOM maps a changed target to the other targets that
// require SBOMs, so that WeakerTargetOnRegistry follows changes of the
// other side. All of them, not only those on the target's registry: an
// update may have moved it off their registry.
func (r *ClusterMirrorTargetReconciler) targetsWithRequiredSBOM(ctx context.Context, obj client.Object) []reconcile.Request {
	var list mirrorv1alpha1.ClusterMirrorTargetList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		t := &list.Items[i]
		if p := sbomOf(t); p != nil && p.Required && t.Name != obj.GetName() {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(t)})
		}
	}
	return reqs
}

// sbomSidecar resolves the SBOM policy of t for m into s.SBOM and returns
// the sidecar that generates: sc with the generator added for a gated Job
// (one sidecar for both, with the gate scanner's image, version and Java
// DB, which the Job requires), or a new sbom sidecar. Helm mirrors and
// targets without a policy get sc unchanged. Without a generator image it
// returns sc unchanged and a message: a required policy then refuses the
// mirror (sbomConditions), an optional one renders without the generator.
func sbomSidecar(t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror, s *syncspec.Spec, sc *sidecar, defaults ScannerConfig) (*sidecar, string) {
	p := sbomOf(t)
	if p == nil || cmp.Or(m.Spec.Type, mirrorv1alpha1.ArtifactTypeImage) != mirrorv1alpha1.ArtifactTypeImage {
		return sc, ""
	}
	image, version, problem := effectiveGenerator(p, defaults)
	if problem != "" {
		effect := "Jobs run without the generator"
		if p.Required {
			effect = "SBOMs are required, images are not copied"
		}
		return sc, fmt.Sprintf("ClusterMirrorTarget %s has %s; %s", t.Name, problem, effect)
	}
	g := syncspec.SBOMGenerator{Version: version, Image: image,
		Timeout: metav1.Duration{Duration: defaultSBOMTimeout}, JavaDB: mirrorv1alpha1.JavaDBDisabled}
	if pg := p.Generator; pg != nil {
		if pg.Timeout != nil {
			g.Timeout = *pg.Timeout
		}
		g.JavaDB = cmp.Or(pg.JavaDB, g.JavaDB)
		g.JavaDBRepository = pg.JavaDBRepository
	}
	if sc != nil && sc.gate != nil {
		gs := sc.gate.Scanner
		g.Image, g.Version, g.JavaDB, g.JavaDBRepository = gs.Image, gs.Version, gs.JavaDB, gs.JavaDBRepository
	} else {
		sc = &sidecar{}
	}
	s.SBOM = &syncspec.SBOM{Mode: p.Mode, Format: sbomFormat(p), Required: p.Required, Generator: g}
	sc.sbom, sc.generator = &s.SBOM.Generator, p.Generator
	return sc, ""
}

// ConditionSBOM reports on an image mirror of a target with an SBOM policy
// whether every selected tag on the target has an SBOM.
const ConditionSBOM = "SBOM"

// Reasons of the SBOM condition.
const (
	ReasonSBOMAttached         = "Attached"
	ReasonSBOMGenerationFailed = "GenerationFailed"
	ReasonSBOMAttachFailed     = "AttachFailed"
	ReasonSBOMMissing          = "Missing"
	// reasonSBOMFailed is the Event of a tag whose SBOM failed.
	reasonSBOMFailed = "SBOMFailed"
	// reasonSBOMMissingRelay is the pod Event reason of a generated mirror
	// that did not publish a tag for its SBOM.
	reasonSBOMMissingRelay = "SBOMMissing"
)

// sbomNotPublished starts an SBOM condition message that lists tags the
// policy kept from being published; the pod relay recognises it.
const sbomNotPublished = "not published: "

// sbomConditions sets or removes the SBOM condition of m before its Job is
// rendered: absent without a policy that applies, NotConfigured with the
// message problem from sbomSidecar. It reports whether the policy is
// required and not configured, so the mirror must be refused.
func (r *ArtifactMirrorReconciler) sbomConditions(t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror, problem string, ev *pending) bool {
	st := &m.Status
	p := sbomOf(t)
	old := meta.FindStatusCondition(st.Conditions, ConditionSBOM)
	switch {
	case p == nil || cmp.Or(m.Spec.Type, mirrorv1alpha1.ArtifactTypeImage) != mirrorv1alpha1.ArtifactTypeImage:
		meta.RemoveStatusCondition(&st.Conditions, ConditionSBOM)
		r.sbomEvents.Delete(client.ObjectKeyFromObject(m))
	case problem != "":
		// A required policy gets the Ready Event instead.
		if !p.Required && (old == nil || old.Reason != ReasonNotConfigured) {
			ev.add(corev1.EventTypeWarning, ReasonNotConfigured, "Reconcile", problem)
		}
		meta.SetStatusCondition(&st.Conditions, metav1.Condition{Type: ConditionSBOM, Status: metav1.ConditionFalse,
			Reason: ReasonNotConfigured, Message: capCondition(problem), ObservedGeneration: m.Generation})
		return p.Required
	case old != nil && old.Reason == ReasonNotConfigured:
		meta.RemoveStatusCondition(&st.Conditions, ConditionSBOM)
	}
	return false
}

// recordSBOM applies the SBOM fields of the report of a finished sync Job
// that ran the generator. Re-scans and Jobs rendered without the
// generator are skipped, and so is a report that does not parse (the
// Synced condition says Crashed).
func (r *ArtifactMirrorReconciler) recordSBOM(m *mirrorv1alpha1.ArtifactMirror, job *batchv1.Job, term *corev1.ContainerStateTerminated, ev *pending) {
	if term == nil || job.Annotations[AnnotationTrigger] == TriggerRescan || job.Spec.Template.Labels[LabelSBOM] != SBOMTrivy {
		return
	}
	rep, err := syncspec.ParseReport(term.Message)
	if err != nil || rep.V != syncspec.ReportVersionGate {
		return
	}
	key := client.ObjectKeyFromObject(m)
	var seen map[string]bool
	if v, ok := r.sbomEvents.Load(key); ok {
		seen = v.(map[string]bool)
	}
	r.sbomEvents.Store(key, applySBOM(m, rep, term.ExitCode == syncspec.ExitOK, seen, ev))
}

// applySBOM sets the SBOM condition from a report, records one SBOMFailed
// Event per failing tag and digest not in seen, counts the failures and
// returns the failing pairs of this report. The report is untrusted: its
// tags, digests and reasons were checked by ParseReport (threat model T12).
func applySBOM(m *mirrorv1alpha1.ArtifactMirror, rep syncspec.Report, ok bool, seen map[string]bool, ev *pending) map[string]bool {
	cond := metav1.Condition{Type: ConditionSBOM, Status: metav1.ConditionFalse, ObservedGeneration: m.Generation}
	next := map[string]bool{}
	if len(rep.SBOMFailures) == 0 {
		// A failed run without SBOM failures did not check every tag.
		if ok {
			cond.Status, cond.Reason = metav1.ConditionTrue, ReasonSBOMAttached
			cond.Message = fmt.Sprintf("every selected tag on the target has an SBOM; this run attached %d generated and %d upstream",
				rep.SBOMGenerated, rep.SBOMUpstream)
			meta.SetStatusCondition(&m.Status.Conditions, cond)
		}
		return next
	}
	var unpublished, published []string
	for _, f := range rep.SBOMFailures {
		pair := f.Tag + "@" + f.Digest
		state := "published without an SBOM"
		if !f.Published {
			state = "not published"
		}
		if !seen[pair] && !next[pair] {
			ev.add(corev1.EventTypeWarning, reasonSBOMFailed, "Sync", fmt.Sprintf("tag %s (%s): SBOM %s, %s", f.Tag, f.Digest, f.Reason, state))
		}
		next[pair] = true
		sbomFailures.WithLabelValues(m.Spec.TargetRef, f.Reason, strconv.FormatBool(f.Published)).Inc()
		entry := fmt.Sprintf("%s (%s)", pair, f.Reason)
		if f.Published {
			published = append(published, entry)
			continue
		}
		unpublished = append(unpublished, entry)
		if cond.Reason == "" {
			cond.Reason = sbomConditionReason(f.Reason)
		}
	}
	cond.Reason = cmp.Or(cond.Reason, sbomConditionReason(rep.SBOMFailures[0].Reason))
	var parts []string
	if len(unpublished) > 0 {
		parts = append(parts, sbomNotPublished+strings.Join(unpublished, ", "))
	}
	if len(published) > 0 {
		parts = append(parts, "published without an SBOM: "+strings.Join(published, ", "))
	}
	if more := rep.SBOMFailed - len(rep.SBOMFailures); more > 0 {
		parts = append(parts, fmt.Sprintf("%d more tags failed, the sync Job log lists them", more))
	}
	cond.Message = capCondition(strings.Join(parts, "; "))
	meta.SetStatusCondition(&m.Status.Conditions, cond)
	return next
}

// sbomConditionReason maps a report failure reason to a condition reason.
// A document that is too large or cannot be signed was not generated.
func sbomConditionReason(reason string) string {
	switch reason {
	case syncspec.SBOMAttachFailed:
		return ReasonSBOMAttachFailed
	case syncspec.SBOMMissing:
		return ReasonSBOMMissing
	}
	return ReasonSBOMGenerationFailed
}
