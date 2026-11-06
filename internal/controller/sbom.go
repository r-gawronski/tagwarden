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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

// ConditionSBOMReady reports on a target with an SBOM policy whether the
// policy can run and is not undercut by another target.
const ConditionSBOMReady = "SBOMReady"

// ReasonWeakerTargetOnRegistry: another target on the same registry lists
// a project of a target with required: true under a weaker SBOM policy.
const ReasonWeakerTargetOnRegistry = "WeakerTargetOnRegistry"

// sbomNotApplied ends the SBOMReady messages until sync Jobs generate
// SBOMs (docs/design/sbom.md, step 3).
const sbomNotApplied = "sync Jobs do not generate or require SBOMs yet"

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
		c.Reason, c.Message = ReasonNotConfigured, fmt.Sprintf("mode %s but %s; %s", p.Mode, problem, sbomNotApplied)
		return c
	}
	if weak := weakerTargets(t, targets); len(weak) > 0 {
		msg := fmt.Sprintf("other ClusterMirrorTargets on registry %s publish to the same projects with a weaker SBOM policy: %s; %s",
			t.Spec.Registry, strings.Join(weak, "; "), sbomNotApplied)
		c.Reason, c.Message = ReasonWeakerTargetOnRegistry, capCondition(msg)
		return c
	}
	c.Status, c.Reason = metav1.ConditionTrue, ReasonReady
	c.Message = fmt.Sprintf("mode %s, format %s, required %t, generator trivy/%s; %s",
		p.Mode, sbomFormat(p), p.Required, version, sbomNotApplied)
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
