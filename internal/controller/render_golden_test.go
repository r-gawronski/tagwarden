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
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/*.golden.json")

// TestUngatedRenderGolden pins the CronJob and spec of mirrors without the
// vulnerability gate. The golden files were written before the gate
// existed, so a diff means ungated Jobs no longer render as before.
func TestUngatedRenderGolden(t *testing.T) {
	gatedOff := func(tg *mirrorv1alpha1.ClusterMirrorTarget) {
		tg.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: teamA,
			VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{Enabled: false, Action: mirrorv1alpha1.GateActionBlock}}
	}
	gatedOn := func(tg *mirrorv1alpha1.ClusterMirrorTarget) {
		tg.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: teamA,
			VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{Enabled: true, Action: mirrorv1alpha1.GateActionBlock}}
	}
	generated := func(m *mirrorv1alpha1.ArtifactMirror) {
		m.Namespace = teamA
		m.Spec.Source = mirrorv1alpha1.Source{Registry: k8sHost, Repository: "pause"}
		m.Spec.Target = mirrorv1alpha1.Target{Project: teamA}
		m.Name = generatedNameOf(canonicalSource(m.Spec.Source))
		m.Labels = map[string]string{mirrorv1alpha1.LabelGenerated: trueValue, mirrorv1alpha1.LabelAutoTarget: "default"}
	}
	for _, tc := range []struct {
		name   string
		target func(*mirrorv1alpha1.ClusterMirrorTarget)
		mirror func(*mirrorv1alpha1.ArtifactMirror)
	}{
		{name: "plain"},
		{name: "azure", target: useAzure},
		{name: "gcp", target: useGCP},
		// The gate is off: a generated mirror renders like any other.
		{name: "generated-gate-off", target: gatedOff, mirror: generated},
		// A user mirror on a gated target is never gated.
		{name: "user-on-gated-target", target: gatedOn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg, m := validTarget("default"), validMirror("render")
			if tc.target != nil {
				tc.target(tg)
			}
			if tc.mirror != nil {
				tc.mirror(m)
			}
			cj, cm := renderUngated(t, tg, m)
			got, err := json.MarshalIndent(map[string]any{"cronJob": cj, "configMap": cm}, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join("testdata", "ungated-"+tc.name+".golden.json")
			if *updateGolden {
				if err := os.WriteFile(file, append(got, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(append(got, '\n'), want) {
				t.Errorf("render of %s differs from %s:\n%s", tc.name, file, got)
			}
		})
	}
}

// renderUngated renders the spec ConfigMap and CronJob the way reconcile
// does for a mirror without the gate.
func renderUngated(t *testing.T, tg *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (*batchv1.CronJob, *corev1.ConfigMap) {
	t.Helper()
	spec, err := json.MarshalIndent(syncSpec(tg, m, []string{deniedCIDR}), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{}
	cm.Name = objectName(m)
	renderConfigMap(cm, m, spec)
	cj := &batchv1.CronJob{}
	cj.Name = objectName(m)
	renderCronJob(cj, tg, m, syncImage, spec, nil, nil)
	return cj, cm
}
