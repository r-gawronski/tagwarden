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
		if !strings.Contains(doc, `"helm.sh/resource-policy": keep`) {
			t.Errorf("%s is not kept on uninstall", meta.Kind)
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
		{name: "sync image tag from manager", ok: true,
			args: []string{"--set", "manager.image.tag=1.2.3,syncImage.repository=registry.example.internal/sync"},
			want: "- --sync-image=registry.example.internal/sync:1.2.3\n"},
		{name: "argocd tracking off by default", ok: true, want: "- --argocd-tracking=\n"},
		{name: "default cluster domain", ok: true, want: "- --cluster-domain=cluster.local\n"},
		{name: "cluster domain", ok: true, args: []string{"--set", "clusterDomain=corp.example"},
			want: "- --cluster-domain=corp.example\n"},
		{name: "cluster domain with a trailing dot", args: []string{"--set", "clusterDomain=cluster.local."}},
		{name: "upper-case cluster domain", args: []string{"--set", "clusterDomain=Cluster.Local"}},
		{name: "default instance label", ok: true, want: "- --argocd-instance-label=app.kubernetes.io/instance\n"},
		{name: "argocd tracking inherit", ok: true, args: []string{"--set", "argocd.tracking=inherit"},
			want: "- --argocd-tracking=inherit\n"},
		{name: "argocd instance label", ok: true, args: []string{"--set", "argocd.instanceLabel=example.com/app"},
			want: "- --argocd-instance-label=example.com/app\n"},
		{name: "bad argocd tracking", args: []string{"--set", "argocd.tracking=all"}},
		{name: "unknown argocd key", args: []string{"--set", "argocd.extra=1"}},
		{name: "unknown top-level key", args: []string{"--set", "bogus=1"}},
		{name: "unknown nested key", args: []string{"--set", "manager.image.registry=x"}},
		{name: "unknown mirror key", args: []string{"--set", "mirrors[0].name=a,mirrors[0].namespace=b,mirrors[0].spec.x=1,mirrors[0].extra=1"}},
		{name: "namespaced rbac", args: []string{"--set", "rbac.namespaced=true"}},
		{name: "unknown service account key", args: []string{"--set", "serviceAccount.create=true"}},
		{name: "bad digest", args: []string{"--set", "manager.image.digest=latest"}},
		{name: "args without denied CIDRs", args: []string{"--set", "manager.args={--leader-elect,--sync-image=x}"}},
		{name: "args without sync image", args: []string{"--set", "manager.args={--denied-cidrs=}"}},
		{name: "args with both flags", ok: true, args: []string{"--set", "manager.args={--sync-image=x,--denied-cidrs=}"}},
		{name: "pod annotation", ok: true, args: []string{"--set-string", `manager.pod.annotations.k8s\.grafana\.com/scrape=true`},
			want: "        k8s.grafana.com/scrape: \"true\"\n"},
		{name: "pod label", ok: true, args: []string{"--set", `manager.pod.labels.example\.com/team=platform`},
			want: "        example.com/team: platform\n"},
		{name: "non-string pod annotation", args: []string{"--set", `manager.pod.annotations.k8s\.grafana\.com/scrape=true`}},
		{name: "trivy without digest", args: []string{"--set", "trivy.enabled=true,trivy.image.repository=r,trivy.image.tag=0.76.1,trivy.db.repository=d"}},
		{name: "trivy tmp below 1Gi", args: []string{"-f", "trivy-values.yaml", "--set", "trivy.tmp.sizeLimit=512Mi"}},
		{name: "trivy tmp 1Gi", ok: true, args: []string{"-f", "trivy-values.yaml", "--set", "trivy.tmp.sizeLimit=1Gi"}},
		{name: "trivy two replicas", args: []string{"-f", "trivy-values.yaml", "--set", "trivy.replicas=2"}},
		{name: "trivy without db repository", args: []string{"-f", "trivy-values.yaml", "--set", "trivy.db.repository="}},
		{name: "unknown trivy key", args: []string{"--set", "trivy.bogus=1"}},
		{name: "unknown pod key", args: []string{"--set", "manager.pod.extra=1"}},
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

func TestTrivyDisabled(t *testing.T) {
	out, err := render(t, "-f", "example-values.yaml")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// CRD descriptions name Trivy; objects and flags must not.
	for doc := range strings.SplitSeq(out, "\n---\n") {
		if !strings.Contains(doc, "kind: CustomResourceDefinition\n") && strings.Contains(strings.ToLower(doc), "trivy") {
			t.Errorf("trivy.enabled=false renders trivy objects or flags:\n%s", doc)
		}
	}
}

func TestTrivyEnabled(t *testing.T) {
	out, err := render(t, "-f", "trivy-values.yaml")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	kinds := map[string]bool{}
	for doc := range strings.SplitSeq(out, "\n---\n") {
		var meta struct{ Kind string }
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("decode: %v\n%s", err, doc)
		}
		if strings.Contains(doc, "component: trivy") {
			kinds[meta.Kind] = true
		}
	}
	for _, k := range []string{"StatefulSet", "Service", "ServiceAccount", "Secret", "NetworkPolicy"} {
		if !kinds[k] {
			t.Errorf("no trivy %s rendered", k)
		}
	}
	for _, want := range []string{
		"- --trivy-image=registry.example.internal/platform/trivy:0.76.1@sha256:",
		"- --trivy-version=0.76.1\n",
		"- --trivy-url=http://tagwarden-trivy.tagwarden-system.svc.cluster.local.:4954\n",
		"- --listen=0.0.0.0:4954\n",
		"runAsUser: 65532\n",
		"readOnlyRootFilesystem: true\n",
		"automountServiceAccountToken: false\n",
		"sizeLimit: 2Gi\n",
		"tagwarden.dev/scanner: trivy\n",
		"name: SSL_CERT_FILE\n",
		"startupProbe:\n",
		"failureThreshold: 90\n",
		"checksum/token: ",
		"helm.sh/resource-policy: keep\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered chart lacks %q", want)
		}
	}
	if strings.Contains(out, "initialDelaySeconds: 30") {
		t.Error("liveness probe still has initialDelaySeconds")
	}
	existing, err := render(t, "-f", "trivy-values.yaml", "--set", "trivy.token.existingSecret=mine")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, existing)
	}
	if strings.Contains(existing, "tagwarden-trivy-token") || !strings.Contains(existing, "name: mine\n") {
		t.Error("existing token Secret is not used instead of the generated one")
	}
}

// TestVulnerabilityExceptions checks that the approver ClusterRole is
// always rendered, and its binding and the approvedBy policy only on request.
func TestVulnerabilityExceptions(t *testing.T) {
	const (
		role    = "kind: ClusterRole\nmetadata:\n  labels:\n    app.kubernetes.io/managed-by: Helm\n    app.kubernetes.io/name: tagwarden\n    helm.sh/chart: tagwarden-0.1.0\n    app.kubernetes.io/instance: tagwarden\n  name: tagwarden-exception-approver\n"
		binding = "kind: ClusterRoleBinding\nmetadata:\n  labels:\n    app.kubernetes.io/managed-by: Helm\n    app.kubernetes.io/name: tagwarden\n    helm.sh/chart: tagwarden-0.1.0\n    app.kubernetes.io/instance: tagwarden\n  name: tagwarden-exception-approver\n"
		policy  = "expression: (request.operation == 'UPDATE' && object.spec == oldObject.spec) || object.spec.approvedBy == request.userInfo.username\n"
		subject = "- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: security-team\n"
	)
	for _, tc := range []struct {
		name      string
		args      []string
		ok        bool
		want, not []string
	}{
		{name: "defaults", ok: true, want: []string{role}, not: []string{binding, "kind: ValidatingAdmissionPolicy"}},
		{name: "approvers", ok: true,
			args: []string{"--set", "vulnerabilityExceptions.approvers[0].kind=Group,vulnerabilityExceptions.approvers[0].name=security-team," +
				"vulnerabilityExceptions.approvers[0].apiGroup=rbac.authorization.k8s.io"},
			want: []string{role, binding, subject}},
		{name: "approvedBy policy", ok: true, args: []string{"--set", "vulnerabilityExceptions.approvedByPolicy.enabled=true"},
			want: []string{policy, "kind: ValidatingAdmissionPolicyBinding\n", "validationActions: [\"Deny\"]\n", "failurePolicy: Fail\n"}},
		{name: "unknown approver kind", args: []string{"--set", "vulnerabilityExceptions.approvers[0].kind=Role,vulnerabilityExceptions.approvers[0].name=x"}},
		{name: "approver without name", args: []string{"--set", "vulnerabilityExceptions.approvers[0].kind=User"}},
		{name: "unknown key", args: []string{"--set", "vulnerabilityExceptions.extra=1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := render(t, tc.args...)
			if (err == nil) != tc.ok {
				t.Fatalf("helm template error = %v, want ok = %v\n%s", err, tc.ok, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("rendered chart lacks %q", w)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(out, n) {
					t.Errorf("rendered chart has %q", n)
				}
			}
		})
	}
}
