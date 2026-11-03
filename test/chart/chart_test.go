//go:build chart

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

// Package chart checks the rendered Helm chart. It needs helm on PATH.
package chart

import (
	"os/exec"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const chartDir = "../../dist/chart"

func render(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("helm", append([]string{"template", "tagwarden", chartDir,
		"--namespace", "tagwarden-system", "--api-versions", "mirror.tagwarden.dev/v1alpha1"}, args...)...) //nolint:gosec
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestCustomResources decodes the rendered targets and mirrors strictly
// into the API types, so a template or example typo fails.
func TestCustomResources(t *testing.T) {
	out, err := render(t, "-f", "example-values.yaml")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	kinds := map[string]int{}
	for doc := range strings.SplitSeq(out, "\n---\n") {
		var meta struct{ Kind string }
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("decode: %v\n%s", err, doc)
		}
		var obj any
		switch meta.Kind {
		case "ClusterMirrorTarget":
			obj = &mirrorv1alpha1.ClusterMirrorTarget{}
		case "ArtifactMirror":
			obj = &mirrorv1alpha1.ArtifactMirror{}
		default:
			continue
		}
		if err := yaml.UnmarshalStrict([]byte(doc), obj); err != nil {
			t.Errorf("%s: %v\n%s", meta.Kind, err, doc)
		}
		kinds[meta.Kind]++
	}
	if kinds["ClusterMirrorTarget"] != 1 || kinds["ArtifactMirror"] != 1 {
		t.Errorf("rendered custom resources = %v, want one of each", kinds)
	}
	for _, want := range []string{
		`image: "registry.example.internal/platform/tagwarden:0.1.0@sha256:0123456789abcdef`,
		"- --sync-image=registry.example.internal/platform/tagwarden-sync:0.1.0\n",
		"- --denied-cidrs=10.244.0.0/16,10.96.0.0/12\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered chart lacks %q", want)
		}
	}
}

func TestValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		ok   bool
		want string
	}{
		{name: "defaults", ok: true, want: "- --sync-image=registry.example.internal/tagwarden/tagwarden:0.1.0\n"},
		{name: "empty denied CIDRs", ok: true, want: "- --denied-cidrs=\n"},
		{name: "unknown top-level key", args: []string{"--set", "bogus=1"}},
		{name: "unknown nested key", args: []string{"--set", "manager.image.registry=x"}},
		{name: "unknown mirror key", args: []string{"--set", "mirrors[0].name=a,mirrors[0].namespace=b,mirrors[0].spec.x=1,mirrors[0].extra=1"}},
		{name: "namespaced rbac", args: []string{"--set", "rbac.namespaced=true"}},
		{name: "unknown service account key", args: []string{"--set", "serviceAccount.create=true"}},
		{name: "bad digest", args: []string{"--set", "manager.image.digest=latest"}},
		{name: "args without denied CIDRs", args: []string{"--set", "manager.args={--leader-elect,--sync-image=x}"}},
		{name: "args without sync image", args: []string{"--set", "manager.args={--denied-cidrs=}"}},
		{name: "args with both flags", ok: true, args: []string{"--set", "manager.args={--sync-image=x,--denied-cidrs=}"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := render(t, tc.args...)
			if (err == nil) != tc.ok {
				t.Fatalf("helm template error = %v, want ok = %v\n%s", err, tc.ok, out)
			}
			if tc.want != "" && !strings.Contains(out, tc.want) {
				t.Errorf("rendered chart lacks %q", tc.want)
			}
		})
	}
}
