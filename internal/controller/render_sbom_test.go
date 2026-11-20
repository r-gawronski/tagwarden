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
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// testJavaDBRepo is a Java DB in the target registry of validTarget.
const testJavaDBRepo = "registry.example.internal:8443/platform/trivy-java-db:1"

// sidecarCommand is the command of every Trivy sidecar.
var sidecarCommand = []string{"/bin/sh", "-c", syncspec.SidecarScript}

const otherTrivyImage = "registry.example.internal/platform/trivy@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// withSBOM sets an SBOM policy on the target.
func withSBOM(p mirrorv1alpha1.SBOMPolicy) func(*mirrorv1alpha1.ClusterMirrorTarget) {
	return func(tg *mirrorv1alpha1.ClusterMirrorTarget) { tg.Spec.SBOM = &p }
}

// renderSBOM resolves the gate and the SBOM policy the way reconcile does
// and renders the CronJob. It fails when the Job would refuse the spec.
func renderSBOM(t *testing.T, r *ArtifactMirrorReconciler, tg *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (*batchv1.CronJob, *corev1.ConfigMap, syncspec.Spec) {
	t.Helper()
	s := syncSpec(tg, m, []string{deniedCIDR})
	sc, msg, err := r.gate(context.Background(), tg, m, &s)
	if err != nil || msg != "" {
		t.Fatalf("gate: %v %q", err, msg)
	}
	sc, msg = sbomSidecar(tg, m, &s, sc, r.Scanner)
	if msg != "" {
		t.Fatalf("sbom: %q", msg)
	}
	spec, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := syncspec.Decode(bytes.NewReader(spec))
	if err != nil {
		t.Fatalf("the Job would refuse the spec: %v", err)
	}
	cm := &corev1.ConfigMap{}
	cm.Name = objectName(m)
	renderConfigMap(cm, m, spec)
	cj := &batchv1.CronJob{}
	cj.Name = objectName(m)
	renderCronJob(cj, tg, m, syncImage, spec, sc, nil, nil)
	return cj, cm, decoded
}

// TestNoSBOMPolicyRendersAsBefore checks that a policy that does not apply
// (Disabled, or a Helm mirror) renders byte for byte like no policy.
func TestNoSBOMPolicyRendersAsBefore(t *testing.T) {
	on := mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeGenerate, Required: true}
	for _, tc := range []struct {
		name   string
		policy mirrorv1alpha1.SBOMPolicy
		mirror func(*mirrorv1alpha1.ArtifactMirror)
	}{
		{name: "mode Disabled", policy: mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeDisabled, Format: mirrorv1alpha1.SBOMFormatSPDX}},
		{name: "empty mode", policy: mirrorv1alpha1.SBOMPolicy{}},
		{name: "helm oci", policy: on, mirror: func(m *mirrorv1alpha1.ArtifactMirror) { m.Spec.Type = mirrorv1alpha1.ArtifactTypeHelmOCI }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := validMirror("render")
			if tc.mirror != nil {
				tc.mirror(m)
			}
			tg := validTarget(m.Spec.TargetRef)
			wantCJ, wantCM := renderUngated(t, tg, m)
			withSBOM(tc.policy)(tg)
			gotCJ, gotCM, spec := renderSBOM(t, reconcilerWith(t), tg, m)
			if spec.SBOM != nil {
				t.Errorf("spec sbom = %+v", spec.SBOM)
			}
			// Only the target differs; the rendered objects must not.
			if !equality.Semantic.DeepEqual(gotCM, wantCM) || !equality.Semantic.DeepEqual(gotCJ, wantCJ) {
				t.Error("the render differs from the render without a policy")
			}
		})
	}
}

func TestSBOMRender(t *testing.T) {
	m := validMirror("render")
	tg := validTarget(m.Spec.TargetRef)
	withSBOM(mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeGenerate, Format: mirrorv1alpha1.SBOMFormatSPDX, Required: true})(tg)
	cj, _, spec := renderSBOM(t, reconcilerWith(t), tg, m)
	pod := cj.Spec.JobTemplate.Spec.Template

	want := &syncspec.SBOM{Mode: mirrorv1alpha1.SBOMModeGenerate, Format: mirrorv1alpha1.SBOMFormatSPDX, Required: true,
		Generator: syncspec.SBOMGenerator{Version: trivyVersion, Image: trivyImage,
			Timeout: metav1.Duration{Duration: 10 * time.Minute}, JavaDB: mirrorv1alpha1.JavaDBDisabled}}
	if !equality.Semantic.DeepEqual(spec.SBOM, want) {
		t.Errorf("spec sbom = %+v, want %+v", spec.SBOM, want)
	}
	if spec.Gate != nil {
		t.Errorf("spec gate = %+v", spec.Gate)
	}
	if pod.Labels[LabelSBOM] != SBOMTrivy || pod.Labels[LabelScanner] != "" {
		t.Errorf("pod labels = %v", pod.Labels)
	}
	if len(pod.Spec.InitContainers) != 1 {
		t.Fatalf("init containers = %d", len(pod.Spec.InitContainers))
	}
	sc, sync := pod.Spec.InitContainers[0], pod.Spec.Containers[0]
	if sc.Name != sbomContainer || sc.Image != trivyImage || ptr.Deref(sc.RestartPolicy, "") != corev1.ContainerRestartPolicyAlways {
		t.Errorf("sidecar = %s %s %v", sc.Name, sc.Image, sc.RestartPolicy)
	}
	if !slices.Equal(sc.Command, sidecarCommand) || sc.Args != nil {
		t.Errorf("sidecar command = %q args %q", sc.Command, sc.Args)
	}
	if !equality.Semantic.DeepEqual(sc.SecurityContext, sync.SecurityContext) {
		t.Errorf("sidecar security context %+v differs from sync %+v", sc.SecurityContext, sync.SecurityContext)
	}
	if want := resource.MustParse("2Gi"); !sc.Resources.Limits.Memory().Equal(want) {
		t.Errorf("sidecar memory limit = %s", sc.Resources.Limits.Memory())
	}
	// No scanner URL, no template, no token, no proxy: only these.
	wantEnv := []corev1.EnvVar{
		{Name: syncspec.ScannerJavaDBEnv, Value: string(mirrorv1alpha1.JavaDBDisabled)},
		{Name: syncspec.SBOMTimeoutEnv, Value: "10m0s"},
		{Name: "HOME", Value: syncspec.ScanDir},
		{Name: "TMPDIR", Value: syncspec.ScanDir},
		{Name: "NO_PROXY", Value: "*"},
	}
	if !equality.Semantic.DeepEqual(sc.Env, wantEnv) || sc.EnvFrom != nil {
		t.Errorf("sidecar env = %+v", sc.Env)
	}
	checkGatedVolumes(t, pod.Spec, sc, sync)
	if ptr.Deref(pod.Spec.AutomountServiceAccountToken, true) {
		t.Error("the SBOM pod mounts a ServiceAccount token")
	}
}

// TestSBOMRenderGenerator checks the generator settings of the target.
func TestSBOMRenderGenerator(t *testing.T) {
	m := validMirror("render")
	tg := validTarget(m.Spec.TargetRef)
	storage, limits := resource.MustParse("5Gi"), corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("4Gi")}}
	withSBOM(mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModePreferUpstream, Generator: &mirrorv1alpha1.SBOMGenerator{
		Image: otherTrivyImage, Version: nextVersion, JavaDB: mirrorv1alpha1.JavaDBPerJob,
		JavaDBRepository: testJavaDBRepo,
		Timeout:          &metav1.Duration{Duration: 3 * time.Minute}, Storage: &storage, Resources: &limits,
	}})(tg)
	// Without the manager's image the target's generator still runs.
	r := reconcilerWith(t)
	r.Scanner = ScannerConfig{}
	cj, _, spec := renderSBOM(t, r, tg, m)
	pod := cj.Spec.JobTemplate.Spec.Template
	g := spec.SBOM.Generator
	if spec.SBOM.Mode != mirrorv1alpha1.SBOMModePreferUpstream || spec.SBOM.Format != mirrorv1alpha1.SBOMFormatCycloneDX ||
		g.Image != otherTrivyImage || g.Version != nextVersion || g.JavaDB != mirrorv1alpha1.JavaDBPerJob || g.Timeout.Duration != 3*time.Minute {
		t.Errorf("spec sbom = %+v", spec.SBOM)
	}
	sc := pod.Spec.InitContainers[0]
	if sc.Image != otherTrivyImage || !equality.Semantic.DeepEqual(sc.Resources, limits) {
		t.Errorf("sidecar image %s resources %+v", sc.Image, sc.Resources)
	}
	env := map[string]string{}
	for _, e := range sc.Env {
		env[e.Name] = e.Value
	}
	if env[syncspec.ScannerJavaDBEnv] != "PerJob" || env[syncspec.SBOMTimeoutEnv] != "3m0s" {
		t.Errorf("sidecar env = %v", env)
	}
	sizes := map[string]string{}
	for _, v := range pod.Spec.Volumes {
		if v.EmptyDir != nil && v.EmptyDir.SizeLimit != nil {
			sizes[v.Name] = v.EmptyDir.SizeLimit.String()
		}
	}
	if sizes[workVolume] != "5Gi" || sizes[scanVolume] != "3Gi" {
		t.Errorf("volume sizes = %v", sizes)
	}
}

// TestSBOMRenderGated checks that a gated Job runs one sidecar for the
// gate and SBOMs, with the gate scanner's image, version and Java DB.
func TestSBOMRenderGated(t *testing.T) {
	tg, m := gatedFixture(mirrorv1alpha1.VulnerabilityGate{Enabled: true, Action: mirrorv1alpha1.GateActionBlock,
		Scanner: &mirrorv1alpha1.ScannerSpec{Image: otherTrivyImage, Version: nextVersion, JavaDB: mirrorv1alpha1.JavaDBPerJob,
			JavaDBRepository: testJavaDBRepo}})
	gatedCJ, _ := renderGated(t, reconcilerWith(t), tg, m)
	storage := resource.MustParse("40Gi")
	withSBOM(mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeGenerate, Generator: &mirrorv1alpha1.SBOMGenerator{
		JavaDB: mirrorv1alpha1.JavaDBDisabled, Timeout: &metav1.Duration{Duration: 2 * time.Minute}, Storage: &storage}})(tg)
	cj, _, spec := renderSBOM(t, reconcilerWith(t), tg, m)
	pod := cj.Spec.JobTemplate.Spec.Template

	g := spec.SBOM.Generator
	if g.Image != otherTrivyImage || g.Version != nextVersion || g.JavaDB != mirrorv1alpha1.JavaDBPerJob ||
		g.JavaDBRepository != spec.Gate.Scanner.JavaDBRepository || g.Timeout.Duration != 2*time.Minute {
		t.Errorf("generator = %+v, gate scanner %+v", g, spec.Gate.Scanner)
	}
	if pod.Labels[LabelSBOM] != SBOMTrivy || pod.Labels[LabelScanner] != ScannerTrivy {
		t.Errorf("pod labels = %v", pod.Labels)
	}
	if len(pod.Spec.InitContainers) != 1 || pod.Spec.InitContainers[0].Name != scannerContainer {
		t.Fatalf("init containers = %+v", pod.Spec.InitContainers)
	}
	// The gated sidecar gains the SBOM timeout and nothing else.
	sc, before := pod.Spec.InitContainers[0], gatedCJ.Spec.JobTemplate.Spec.Template.Spec.InitContainers[0]
	var added []string
	for _, e := range sc.Env {
		if !slices.ContainsFunc(before.Env, func(b corev1.EnvVar) bool { return equality.Semantic.DeepEqual(b, e) }) {
			added = append(added, e.Name+"="+e.Value)
		}
	}
	if !slices.Equal(added, []string{syncspec.SBOMTimeoutEnv + "=2m0s"}) || len(sc.Env) != len(before.Env)+1 {
		t.Errorf("env added to the gated sidecar = %v", added)
	}
	if sc.Image != before.Image || !equality.Semantic.DeepEqual(sc.Resources, before.Resources) {
		t.Errorf("sidecar image %s resources %+v", sc.Image, sc.Resources)
	}
	// The larger of the two storage settings holds the layout.
	for _, v := range pod.Spec.Volumes {
		if v.Name == workVolume && v.EmptyDir.SizeLimit.String() != "40Gi" {
			t.Errorf("work size = %s", v.EmptyDir.SizeLimit)
		}
	}
}

// TestSBOMRenderNotConfigured: without a generator image a required
// policy refuses the mirror, an optional one renders without generator.
func TestSBOMRenderNotConfigured(t *testing.T) {
	for _, required := range []bool{true, false} {
		m := validMirror("render")
		tg := validTarget(m.Spec.TargetRef)
		withSBOM(mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeGenerate, Required: required})(tg)
		s := syncSpec(tg, m, nil)
		sc, msg := sbomSidecar(tg, m, &s, nil, ScannerConfig{URL: inChartURL})
		if sc != nil || s.SBOM != nil || !strings.Contains(msg, "no SBOM generator") {
			t.Errorf("required %t: sidecar %+v, message %q, spec %+v", required, sc, msg, s.SBOM)
		}
		var ev pending
		r := &ArtifactMirrorReconciler{}
		if refuse := r.sbomConditions(tg, m, msg, &ev); refuse != required {
			t.Errorf("required %t: refuse %t", required, refuse)
		}
		c := meta.FindStatusCondition(m.Status.Conditions, ConditionSBOM)
		if c == nil || c.Status != metav1.ConditionFalse || c.Reason != ReasonNotConfigured || c.Message != msg {
			t.Errorf("required %t: condition %+v", required, c)
		}
		// Only an optional policy gets its own Event; a required one has Ready's.
		if len(ev) != map[bool]int{true: 0, false: 1}[required] {
			t.Errorf("required %t: events %+v", required, ev)
		}
	}
}

func TestSecurityDriftSBOMSidecar(t *testing.T) {
	m := validMirror("render")
	tg := validTarget(m.Spec.TargetRef)
	withSBOM(mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeGenerate})(tg)
	cj, _, _ := renderSBOM(t, reconcilerWith(t), tg, m)
	want := &cj.Spec.JobTemplate.Spec.Template
	for name, edit := range map[string]func(*corev1.PodTemplateSpec){
		"image": func(p *corev1.PodTemplateSpec) { p.Spec.InitContainers[0].Image = "registry.example.internal/evil:1" },
		"command": func(p *corev1.PodTemplateSpec) {
			p.Spec.InitContainers[0].Command = nil
		},
		"env": func(p *corev1.PodTemplateSpec) {
			p.Spec.InitContainers[0].Env = append(p.Spec.InitContainers[0].Env, corev1.EnvVar{Name: "HTTPS_PROXY", Value: "http://x"})
		},
		"mounts":  func(p *corev1.PodTemplateSpec) { p.Spec.InitContainers[0].VolumeMounts[0].ReadOnly = false },
		"removed": func(p *corev1.PodTemplateSpec) { p.Spec.InitContainers = nil },
		"label":   func(p *corev1.PodTemplateSpec) { delete(p.Labels, LabelSBOM) },
	} {
		live := want.DeepCopy()
		edit(live)
		if !securityDrift(live, want) {
			t.Errorf("an edit of the SBOM sidecar %s is not drift", name)
		}
	}
}
