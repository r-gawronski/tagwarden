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

package syncspec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const (
	keyJavaDB  = "javaDB"
	keyTimeout = "timeout"
	keyVersion = "version"
)

const javaDBRepo = "registry.example.internal/platform/trivy-java-db:1"

func TestDecodeSBOM(t *testing.T) {
	base := func(extra string) string {
		return `{"mirror":{"namespace":"team-a","name":"nginx"},"source":"docker.io/library/nginx",
			"target":"registry.example.internal/team-a/nginx","tags":{"tags":["1.27"]},
			"onTagMutation":"Fail","allowedSources":["docker.io"]` + extra + `}`
	}
	gen := func() map[string]any {
		return map[string]any{keyVersion: scannerVersion, keyTimeout: "10m", keyJavaDB: string(v1alpha1.JavaDBDisabled)}
	}
	policy := func(mod func(p, g map[string]any)) string {
		g := gen()
		p := map[string]any{"mode": "Generate", "format": "CycloneDX", "required": true, "generator": g}
		mod(p, g)
		b, _ := json.Marshal(p)
		return `,"sbom":` + string(b)
	}
	s, err := Decode(strings.NewReader(base(policy(func(_, _ map[string]any) {}))))
	if err != nil || s.SBOM == nil || s.SBOM.Mode != v1alpha1.SBOMModeGenerate || !s.SBOM.Required ||
		s.SBOM.Generator.Timeout.Minutes() != 10 {
		t.Fatalf("spec %+v, err %v", s.SBOM, err)
	}
	if s, err := Decode(strings.NewReader(base(""))); err != nil || s.SBOM != nil {
		t.Fatalf("no policy: %+v, %v", s.SBOM, err)
	}
	for _, mod := range []func(p, g map[string]any){
		func(p, _ map[string]any) { p["mode"], p["format"], p["required"] = "PreferUpstream", "SPDX", false },
		func(_, g map[string]any) {
			g[keyJavaDB], g["javaDBRepository"] = string(v1alpha1.JavaDBPerJob), javaDBRepo
		},
	} {
		if _, err := Decode(strings.NewReader(base(policy(mod)))); err != nil {
			t.Errorf("valid policy refused: %v", err)
		}
	}
	for name, mod := range map[string]func(p, g map[string]any){
		"mode Disabled":     func(p, _ map[string]any) { p["mode"] = string(v1alpha1.SBOMModeDisabled) },
		"no mode":           func(p, _ map[string]any) { delete(p, "mode") },
		"format":            func(p, _ map[string]any) { p["format"] = "spdx-json" },
		"bad version":       func(_, g map[string]any) { g[keyVersion] = "latest" },
		"long timeout":      func(_, g map[string]any) { g[keyTimeout] = "2h" },
		"no timeout":        func(_, g map[string]any) { delete(g, keyTimeout) },
		"javaDB value":      func(_, g map[string]any) { g[keyJavaDB] = "Shared" },
		"PerJob without DB": func(_, g map[string]any) { g[keyJavaDB] = string(v1alpha1.JavaDBPerJob) },
		"DB in other host": func(_, g map[string]any) {
			g[keyJavaDB], g["javaDBRepository"] = string(v1alpha1.JavaDBPerJob), "ghcr.io/aquasecurity/trivy-java-db:1"
		},
		"signing not yet": func(p, _ map[string]any) { p["signing"] = map[string]any{} },
	} {
		if _, err := Decode(strings.NewReader(base(policy(mod)))); err == nil {
			t.Errorf("%s: want error", name)
		}
	}

	gate := `,"gate":{"action":"Block","severity":"Critical","onScanError":"Report","maxDBAge":"72h",
		"scanner":{"url":"http://tagwarden-trivy.tagwarden-system.svc:4954","version":"` + scannerVersion + `","image":"img@sha256:1","timeout":"10m","javaDB":"` + string(v1alpha1.JavaDBDisabled) + `"}}`
	if _, err := Decode(strings.NewReader(base(gate + policy(func(_, g map[string]any) { g["image"] = "img@sha256:1" })))); err != nil {
		t.Fatalf("gated: %v", err)
	}
	for name, mod := range map[string]func(p, g map[string]any){
		"other version": func(_, g map[string]any) { g[keyVersion] = nextMinor },
		"other image":   func(_, g map[string]any) { g["image"] = "other@sha256:1" },
		"other javaDB": func(_, g map[string]any) {
			g[keyJavaDB], g["javaDBRepository"] = string(v1alpha1.JavaDBPerJob), javaDBRepo
		},
	} {
		if _, err := Decode(strings.NewReader(base(gate + policy(mod)))); err == nil {
			t.Errorf("gated, %s: want error", name)
		}
	}
}

func TestParseReportSBOM(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	failure := `{"tag":"v1","digest":"` + digest + `","reason":"GenerationFailed","published":true}`
	r, err := ParseReport(`{"v":2,"synced":[],"javaScanned":false,"sbomGenerated":2,"sbomUpstream":1,"sbomFailed":1,"sbomFailures":[` + failure + `]}`)
	if err != nil || r.SBOMGenerated != 2 || r.SBOMUpstream != 1 || r.SBOMFailed != 1 || len(r.SBOMFailures) != 1 ||
		!r.SBOMFailures[0].Published || r.SBOMFailures[0].Reason != SBOMGenerationFailed {
		t.Fatalf("report %+v, err %v", r, err)
	}
	for _, reason := range sbomReasons {
		if _, err := ParseReport(`{"v":2,"sbomFailures":[` + strings.Replace(failure, "GenerationFailed", reason, 1) + `]}`); err != nil {
			t.Errorf("%s: %v", reason, err)
		}
	}
	bad := map[string]string{
		"counts in v1":    `{"v":1,"sbomGenerated":1}`,
		"failures in v1":  `{"v":1,"sbomFailures":[` + failure + `]}`,
		"negative failed": `{"v":2,"sbomFailed":-1}`,
		"reason":          `{"v":2,"sbomFailures":[` + strings.Replace(failure, "GenerationFailed", "Oops", 1) + `]}`,
		caseBadTag:        `{"v":2,"sbomFailures":[` + strings.Replace(failure, `"v1"`, `"../x"`, 1) + `]}`,
		"digest":          `{"v":2,"sbomFailures":[` + strings.Replace(failure, digest, "sha256:1", 1) + `]}`,
		"over the cap":    `{"v":2,"sbomFailures":[` + strings.Repeat(failure+",", MaxSBOMFailures) + failure + `]}`,
	}
	for name, msg := range bad {
		if _, err := ParseReport(msg); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
