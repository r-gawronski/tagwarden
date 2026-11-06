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
	"context"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const sbomRegistry = "sbom.example.internal"

// sbomTarget is a target on sbomRegistry with the given projects and policy.
func sbomTarget(name string, p *mirrorv1alpha1.SBOMPolicy, projects ...mirrorv1alpha1.ProjectName) *mirrorv1alpha1.ClusterMirrorTarget {
	t := newTarget(name)
	t.Spec.Registry = sbomRegistry
	t.Spec.Projects = nil
	for _, pr := range projects {
		t.Spec.Projects = append(t.Spec.Projects, mirrorv1alpha1.TargetProject{Name: pr, NamespaceSelector: &metav1.LabelSelector{}})
	}
	t.Spec.SBOM = p
	return t
}

func required(mode mirrorv1alpha1.SBOMMode, format mirrorv1alpha1.SBOMFormat) *mirrorv1alpha1.SBOMPolicy {
	return &mirrorv1alpha1.SBOMPolicy{Mode: mode, Format: format, Required: true}
}

func TestSBOMOf(t *testing.T) {
	for name, tc := range map[string]struct {
		p  *mirrorv1alpha1.SBOMPolicy
		on bool
	}{
		"absent":         {},
		"empty mode":     {p: &mirrorv1alpha1.SBOMPolicy{}},
		"disabled":       {p: &mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeDisabled}},
		"prefer":         {p: &mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModePreferUpstream}, on: true},
		"generate":       {p: &mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeGenerate}, on: true},
		"generate, req.": {p: required(mirrorv1alpha1.SBOMModeGenerate, ""), on: true},
	} {
		tg := sbomTarget("t", tc.p, "shared")
		if got := sbomOf(tg) != nil; got != tc.on {
			t.Errorf("%s: sbomOf on = %t, want %t", name, got, tc.on)
		}
	}
}

func TestEffectiveGenerator(t *testing.T) {
	const otherImage = "registry.example.internal/platform/trivy@sha256:" + "ab" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
	generate := func(g *mirrorv1alpha1.SBOMGenerator) *mirrorv1alpha1.SBOMPolicy {
		return &mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeGenerate, Generator: g}
	}
	for _, tc := range []struct {
		name           string
		p              *mirrorv1alpha1.SBOMPolicy
		defaults       ScannerConfig
		image, version string
		problem        bool
	}{
		{name: "manager defaults", p: generate(nil), defaults: suiteScanner, image: trivyImage, version: trivyVersion},
		{name: "generator without image", p: generate(&mirrorv1alpha1.SBOMGenerator{JavaDB: mirrorv1alpha1.JavaDBDisabled}),
			defaults: suiteScanner, image: trivyImage, version: trivyVersion},
		{name: "generator overrides", p: generate(&mirrorv1alpha1.SBOMGenerator{Image: otherImage, Version: nextVersion}),
			defaults: suiteScanner, image: otherImage, version: nextVersion},
		{name: "generator without defaults", p: generate(&mirrorv1alpha1.SBOMGenerator{Image: otherImage, Version: nextVersion}),
			image: otherImage, version: nextVersion},
		{name: "nothing", p: generate(nil), problem: true},
		{name: "image without version", p: generate(nil), defaults: ScannerConfig{Image: trivyImage}, problem: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image, version, problem := effectiveGenerator(tc.p, tc.defaults)
			if (problem != "") != tc.problem {
				t.Fatalf("problem = %q, want problem %t", problem, tc.problem)
			}
			if !tc.problem && (image != tc.image || version != tc.version) {
				t.Errorf("got %s %s, want %s %s", image, version, tc.image, tc.version)
			}
		})
	}
}

func TestWeakerTargets(t *testing.T) {
	const (
		gen    = mirrorv1alpha1.SBOMModeGenerate
		prefer = mirrorv1alpha1.SBOMModePreferUpstream
		cdx    = mirrorv1alpha1.SBOMFormatCycloneDX
		spdx   = mirrorv1alpha1.SBOMFormatSPDX
	)
	strict := sbomTarget("strict", required(gen, cdx), "shared", "team-a")
	for _, tc := range []struct {
		name  string
		self  *mirrorv1alpha1.ClusterMirrorTarget
		other *mirrorv1alpha1.ClusterMirrorTarget
		want  string
	}{
		{name: "no policy", self: strict, other: sbomTarget("o", nil, "shared"), want: "o (projects shared: no SBOM policy)"},
		{name: "disabled", self: strict, other: sbomTarget("o", &mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeDisabled}, "team-a"),
			want: "o (projects team-a: no SBOM policy)"},
		{name: "not required", self: strict, other: sbomTarget("o", &mirrorv1alpha1.SBOMPolicy{Mode: gen, Format: cdx}, "shared", "team-a"),
			want: "o (projects shared, team-a: SBOM not required)"},
		{name: "other format", self: strict, other: sbomTarget("o", required(gen, spdx), "shared"), want: "o (projects shared: format SPDX)"},
		{name: "prefer upstream under generate", self: strict, other: sbomTarget("o", required(prefer, cdx), "shared"),
			want: "o (projects shared: mode PreferUpstream)"},
		{name: "default format counts as CycloneDX", self: strict, other: sbomTarget("o", required(gen, ""), "shared")},
		{name: "generate under prefer upstream", self: sbomTarget("strict", required(prefer, cdx), "shared"),
			other: sbomTarget("o", required(gen, cdx), "shared")},
		{name: "same policy", self: strict, other: sbomTarget("o", required(gen, cdx), "shared")},
		{name: "other projects", self: strict, other: sbomTarget("o", nil, "team-b")},
		{name: "other registry", self: strict, other: func() *mirrorv1alpha1.ClusterMirrorTarget {
			o := sbomTarget("o", nil, "shared")
			o.Spec.Registry = "elsewhere.example.internal"
			return o
		}()},
		{name: "same registry in another case and port 443", self: strict, other: func() *mirrorv1alpha1.ClusterMirrorTarget {
			o := sbomTarget("o", nil, "shared")
			o.Spec.Registry = "SBOM.example.internal:443"
			return o
		}(), want: "o (projects shared: no SBOM policy)"},
		{name: "being deleted", self: strict, other: func() *mirrorv1alpha1.ClusterMirrorTarget {
			o := sbomTarget("o", nil, "shared")
			now := metav1.Now()
			o.DeletionTimestamp = &now
			return o
		}()},
		{name: "self not required", self: sbomTarget("strict", &mirrorv1alpha1.SBOMPolicy{Mode: gen}, "shared"),
			other: sbomTarget("o", nil, "shared")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(weakerTargets(tc.self, []mirrorv1alpha1.ClusterMirrorTarget{*tc.self, *tc.other}), "|")
			if got != tc.want {
				t.Errorf("weakerTargets = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSBOMCondition(t *testing.T) {
	strict := sbomTarget("strict", required(mirrorv1alpha1.SBOMModeGenerate, ""), "shared")
	strict.Generation = 3
	open := sbomTarget("open", nil, "shared")

	c := sbomCondition(strict, []mirrorv1alpha1.ClusterMirrorTarget{*strict}, suiteScanner)
	if c.Status != metav1.ConditionTrue || c.Reason != ReasonReady || c.ObservedGeneration != 3 ||
		!strings.Contains(c.Message, "mode Generate, format CycloneDX, required true, generator trivy/"+trivyVersion) ||
		!strings.HasSuffix(c.Message, sbomNotApplied) {
		t.Errorf("ready: %+v", c)
	}
	c = sbomCondition(strict, nil, ScannerConfig{})
	if c.Status != metav1.ConditionFalse || c.Reason != ReasonNotConfigured || !strings.Contains(c.Message, "sbom.generator.image") {
		t.Errorf("not configured: %+v", c)
	}
	// Not configured wins over a weaker target.
	c = sbomCondition(strict, []mirrorv1alpha1.ClusterMirrorTarget{*strict, *open}, ScannerConfig{})
	if c.Reason != ReasonNotConfigured {
		t.Errorf("not configured and weaker: %+v", c)
	}
	c = sbomCondition(strict, []mirrorv1alpha1.ClusterMirrorTarget{*strict, *open}, suiteScanner)
	if c.Status != metav1.ConditionFalse || c.Reason != ReasonWeakerTargetOnRegistry ||
		!strings.Contains(c.Message, "registry sbom.example.internal") || !strings.Contains(c.Message, "open (projects shared: no SBOM policy)") {
		t.Errorf("weaker: %+v", c)
	}

	// Many weaker targets: the message stays within the cap.
	many := make([]mirrorv1alpha1.ClusterMirrorTarget, 0, 101)
	many = append(many, *strict)
	for i := range 100 {
		many = append(many, *sbomTarget(strings.Repeat("x", 40)+string(rune('a'+i%26))+string(rune('a'+i/26)), nil, "shared"))
	}
	c = sbomCondition(strict, many, suiteScanner)
	if len(c.Message) > maxGateMessage || !strings.HasSuffix(c.Message, "...") {
		t.Errorf("message of %d bytes: %q", len(c.Message), c.Message)
	}
}

// unconfiguredTarget is the target of TestReconcileSBOMNotConfigured.
const unconfiguredTarget = "sbom-unit-unconfigured"

// sbomGauge returns the not-configured gauge of unconfiguredTarget, or -1
// when the series does not exist.
func sbomGauge() float64 {
	ch := make(chan prometheus.Metric, 100)
	sbomNotConfigured.Collect(ch)
	close(ch)
	for m := range ch {
		var pb dto.Metric
		if m.Write(&pb) == nil && len(pb.GetLabel()) == 1 && pb.GetLabel()[0].GetValue() == unconfiguredTarget {
			return pb.GetGauge().GetValue()
		}
	}
	return -1
}

func TestReconcileSBOMNotConfigured(t *testing.T) {
	const name = unconfiguredTarget
	tg := sbomTarget(name, &mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModePreferUpstream}, "shared")
	sch := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(sch); err != nil {
		t.Fatal(err)
	}
	if err := mirrorv1alpha1.AddToScheme(sch); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(sch).WithObjects(tg).
		WithStatusSubresource(&mirrorv1alpha1.ClusterMirrorTarget{}).Build()
	rec := &testRecorder{}
	r := &ClusterMirrorTargetReconciler{Client: c, Recorder: rec, Namespace: operatorNamespace}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}
	ctx := context.Background()
	condition := func() *metav1.Condition {
		var got mirrorv1alpha1.ClusterMirrorTarget
		if err := c.Get(ctx, req.NamespacedName, &got); err != nil {
			t.Fatal(err)
		}
		return meta.FindStatusCondition(got.Status.Conditions, ConditionSBOMReady)
	}
	warnings := func() int {
		n := 0
		for _, e := range rec.Events("", name) {
			if strings.Contains(e, " Warning "+ReasonNotConfigured+" ") {
				n++
			}
		}
		return n
	}

	for range 2 {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	if got := condition(); got == nil || got.Reason != ReasonNotConfigured {
		t.Fatalf("SBOMReady = %+v, want NotConfigured", got)
	}
	if g := sbomGauge(); g != 1 {
		t.Errorf("gauge = %v, want 1", g)
	}
	if n := warnings(); n != 1 {
		t.Errorf("%d NotConfigured Warnings, want 1 (only on change): %v", n, rec.Events("", name))
	}

	// The manager flags configure the generator.
	r.Scanner = suiteScanner
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got := condition(); got == nil || got.Status != metav1.ConditionTrue {
		t.Errorf("SBOMReady = %+v, want True", got)
	}
	if g := sbomGauge(); g != -1 {
		t.Errorf("gauge = %v, want no series", g)
	}
	if !strings.Contains(strings.Join(rec.Events("", name), "\n"), " Normal "+ConditionSBOMReady+" ") {
		t.Errorf("no Normal SBOMReady Event: %v", rec.Events("", name))
	}

	// Deleted: the series goes.
	r.Scanner = ScannerConfig{}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if g := sbomGauge(); g != 1 {
		t.Fatalf("gauge = %v, want 1", g)
	}
	if err := c.Delete(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if g := sbomGauge(); g != -1 {
		t.Errorf("gauge after delete = %v, want no series", g)
	}
}

var _ = Describe("SBOM policy", func() {
	sbomReady := func(name string) func() *metav1.Condition {
		return func() *metav1.Condition {
			var t mirrorv1alpha1.ClusterMirrorTarget
			if k8sClient.Get(ctx, types.NamespacedName{Name: name}, &t) != nil {
				return nil
			}
			return meta.FindStatusCondition(t.Status.Conditions, ConditionSBOMReady)
		}
	}
	update := func(name string, mutate func(*mirrorv1alpha1.ClusterMirrorTarget)) {
		ExpectWithOffset(1, retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var t mirrorv1alpha1.ClusterMirrorTarget
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: name}, &t); err != nil {
				return err
			}
			mutate(&t)
			return k8sClient.Update(ctx, &t)
		})).To(Succeed())
	}

	It("defaults the policy and reports SBOMReady with the manager's Trivy image", func() {
		t := sbomTarget("sbom-defaults", &mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeGenerate,
			Generator: &mirrorv1alpha1.SBOMGenerator{}}, "solo")
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, t)
		Expect(t.Spec.SBOM.Format).To(Equal(mirrorv1alpha1.SBOMFormatCycloneDX))
		Expect(t.Spec.SBOM.Generator.JavaDB).To(Equal(mirrorv1alpha1.JavaDBDisabled))
		Expect(t.Spec.SBOM.Generator.Timeout.Duration.String()).To(Equal("10m0s"))
		Expect(t.Spec.SBOM.Generator.Storage.String()).To(Equal("20Gi"))

		Eventually(sbomReady(t.Name)).Should(And(HaveField("Status", metav1.ConditionTrue), HaveField("Reason", ReasonReady),
			HaveField("Message", ContainSubstring("generator trivy/"+trivyVersion))))
		Eventually(func() []string { return recorder.Events("", t.Name) }).Should(
			ContainElement(ContainSubstring("Normal " + ConditionSBOMReady)))

		By("removing the condition when the policy is turned off")
		update(t.Name, func(t *mirrorv1alpha1.ClusterMirrorTarget) { t.Spec.SBOM.Mode = mirrorv1alpha1.SBOMModeDisabled })
		Eventually(sbomReady(t.Name)).Should(BeNil())
	})

	It("reports a weaker target on the same registry and follows its changes", func() {
		strict := sbomTarget("sbom-strict", required(mirrorv1alpha1.SBOMModeGenerate, mirrorv1alpha1.SBOMFormatCycloneDX), "sbom-shared")
		Expect(k8sClient.Create(ctx, strict)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, strict)
		Eventually(sbomReady(strict.Name)).Should(HaveField("Status", metav1.ConditionTrue))

		open := sbomTarget("sbom-open", nil, "sbom-shared")
		Expect(k8sClient.Create(ctx, open)).To(Succeed())
		DeferCleanup(func() error { return client.IgnoreNotFound(k8sClient.Delete(ctx, open)) })
		Eventually(sbomReady(strict.Name)).Should(And(HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", ReasonWeakerTargetOnRegistry), HaveField("Message", ContainSubstring("sbom-open (projects sbom-shared: no SBOM policy)"))))
		Eventually(func() []string { return recorder.Events("", strict.Name) }).Should(
			ContainElement(ContainSubstring("Warning " + ReasonWeakerTargetOnRegistry)))
		// The weaker target itself is not flagged: it does not require SBOMs.
		Consistently(sbomReady(open.Name), "1s").Should(BeNil())

		By("clearing the reason when the other target requires the same policy")
		update(open.Name, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.SBOM = required(mirrorv1alpha1.SBOMModeGenerate, mirrorv1alpha1.SBOMFormatCycloneDX)
		})
		Eventually(sbomReady(strict.Name)).Should(HaveField("Status", metav1.ConditionTrue))

		By("reporting it again when the other target moves to the weaker format")
		update(open.Name, func(t *mirrorv1alpha1.ClusterMirrorTarget) { t.Spec.SBOM.Format = mirrorv1alpha1.SBOMFormatSPDX })
		Eventually(sbomReady(strict.Name)).Should(HaveField("Reason", ReasonWeakerTargetOnRegistry))

		By("clearing it when the other target is deleted")
		Expect(k8sClient.Delete(ctx, open)).To(Succeed())
		Eventually(sbomReady(strict.Name)).Should(HaveField("Status", metav1.ConditionTrue))
	})

	DescribeTable("rejects an invalid policy",
		func(mutate func(*mirrorv1alpha1.ClusterMirrorTarget), message string) {
			obj := sbomTarget("sbom-invalid", &mirrorv1alpha1.SBOMPolicy{Mode: mirrorv1alpha1.SBOMModeGenerate}, "shared")
			mutate(obj)
			err := k8sClient.Create(ctx, obj)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(message))
		},
		Entry("required without a mode", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SBOM = &mirrorv1alpha1.SBOMPolicy{Required: true}
		}, "required needs mode PreferUpstream or Generate"),
		Entry("required with mode Disabled", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SBOM = required(mirrorv1alpha1.SBOMModeDisabled, "")
		}, "required needs mode PreferUpstream or Generate"),
		Entry("unknown mode", func(o *mirrorv1alpha1.ClusterMirrorTarget) { o.Spec.SBOM.Mode = "Always" }, "spec.sbom.mode"),
		Entry("Trivy flag name as format", func(o *mirrorv1alpha1.ClusterMirrorTarget) { o.Spec.SBOM.Format = "spdx-json" }, "spec.sbom.format"),
		Entry("image without version", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SBOM.Generator = &mirrorv1alpha1.SBOMGenerator{Image: trivyImage}
		}, "set image and version together"),
		Entry("image by tag", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SBOM.Generator = &mirrorv1alpha1.SBOMGenerator{Image: "registry.example.internal/trivy:0.76.1", Version: trivyVersion}
		}, "must be pinned by digest"),
		Entry("javaDB PerJob without repository", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SBOM.Generator = &mirrorv1alpha1.SBOMGenerator{JavaDB: mirrorv1alpha1.JavaDBPerJob}
		}, "javaDB PerJob needs javaDBRepository"),
		Entry("Java DB outside the target registry", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SBOM.Generator = &mirrorv1alpha1.SBOMGenerator{JavaDB: mirrorv1alpha1.JavaDBPerJob,
				JavaDBRepository: "elsewhere.example.internal/trivy-java-db:1"}
		}, "sbom.generator.javaDBRepository must be in spec.registry"),
		Entry("timeout below 1m", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SBOM.Generator = &mirrorv1alpha1.SBOMGenerator{Timeout: &metav1.Duration{Duration: 30e9}}
		}, "must be between 1m and 1h"),
		Entry("generator image other than the scanner image", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SBOM.Generator = &mirrorv1alpha1.SBOMGenerator{Image: trivyImage, Version: trivyVersion}
			o.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Project: "shared", VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{
				Scanner: &mirrorv1alpha1.ScannerSpec{Image: trivyImage, Version: nextVersion}}}
		}, "must equal autoMirror.vulnerabilityGate.scanner image and version"),
	)

	It("accepts a full policy with a matching scanner image", func() {
		obj := sbomTarget("sbom-full", required(mirrorv1alpha1.SBOMModePreferUpstream, mirrorv1alpha1.SBOMFormatSPDX), "shared")
		obj.Spec.SBOM.Generator = &mirrorv1alpha1.SBOMGenerator{Image: trivyImage, Version: trivyVersion,
			JavaDB: mirrorv1alpha1.JavaDBPerJob, JavaDBRepository: sbomRegistry + "/platform/trivy-java-db:1",
			Timeout: &metav1.Duration{Duration: 3600e9}}
		obj.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Project: "shared", VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{
			Scanner: &mirrorv1alpha1.ScannerSpec{Image: trivyImage, Version: trivyVersion}}}
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
	})
})
