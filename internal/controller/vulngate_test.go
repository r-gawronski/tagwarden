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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

const (
	trivyDigest  = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	trivyImage   = "registry.example.internal/platform/ghcr.io/aquasecurity/trivy" + trivyDigest
	trivyVersion = "0.76.1"
)

// gatedTarget is validTarget with autoMirror on team-a and the gate on.
func gatedTarget(name string) *mirrorv1alpha1.ClusterMirrorTarget {
	t := validTarget(name)
	t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: teamA,
		VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{Enabled: true}}
	return t
}

func gate(t *mirrorv1alpha1.ClusterMirrorTarget) *mirrorv1alpha1.VulnerabilityGate {
	return t.Spec.AutoMirror.VulnerabilityGate
}

func scanner(t *mirrorv1alpha1.ClusterMirrorTarget) *mirrorv1alpha1.ScannerSpec {
	if gate(t).Scanner == nil {
		gate(t).Scanner = &mirrorv1alpha1.ScannerSpec{}
	}
	return gate(t).Scanner
}

func duration(d time.Duration) *metav1.Duration { return &metav1.Duration{Duration: d} }

var _ = Describe("vulnerability gate API", func() {
	DescribeTable("accepts a valid gate",
		func(mutate func(*mirrorv1alpha1.ClusterMirrorTarget)) {
			t := gatedTarget("valid-gate")
			mutate(t)
			Expect(k8sClient.Create(ctx, t)).To(Succeed())
			Expect(k8sClient.Delete(ctx, t)).To(Succeed())
		},
		Entry("enabled only", func(*mirrorv1alpha1.ClusterMirrorTarget) {}),
		Entry("full example", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			storage := resource.MustParse("40Gi")
			*gate(t) = mirrorv1alpha1.VulnerabilityGate{
				Enabled: true, Action: mirrorv1alpha1.GateActionBlock, Severity: mirrorv1alpha1.SeverityThresholdHigh,
				IgnoreUnfixed: true, IncludeUnknown: true, MaxDBAge: duration(48 * time.Hour),
				OnScanError: mirrorv1alpha1.GateActionBlock, RescanInterval: duration(24 * time.Hour),
				OnVulnerableTag: mirrorv1alpha1.OnVulnerableTagUntag, MaxExceptionDuration: duration(720 * time.Hour),
				Scanner: &mirrorv1alpha1.ScannerSpec{
					URL:               "https://trivy.scanners.example.internal:4954",
					CABundleSecretRef: &mirrorv1alpha1.SecretKeyRef{Name: "trivy-ca", Key: caKey},
					TokenSecretRef:    &mirrorv1alpha1.TokenSecretKeyRef{Name: "trivy-token", Key: "token"},
					Image:             trivyImage, Version: trivyVersion,
					JavaDB:           mirrorv1alpha1.JavaDBPerJob,
					JavaDBRepository: "registry.example.internal:8443/platform/ghcr.io/aquasecurity/trivy-java-db:1",
					Timeout:          duration(5 * time.Minute), Storage: &storage,
					Resources: &corev1.ResourceRequirements{Limits: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("3Gi")}},
				},
			}
		}),
		Entry("plain HTTP to a cluster Service", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://tagwarden-trivy.tagwarden-system.svc:4954"
		}),
		Entry("plain HTTP to a cluster Service with the cluster domain", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://tagwarden-trivy.tagwarden-system.svc.cluster.local:4954"
		}),
		Entry("plain HTTP to a fully qualified cluster Service name", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://tagwarden-trivy.tagwarden-system.svc.cluster.local.:4954"
		}),
		Entry("plain HTTP to a cluster Service with a trailing slash", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://tagwarden-trivy.tagwarden-system.svc/"
		}),
		Entry("onScanError Block with action Report", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			gate(t).OnScanError = mirrorv1alpha1.GateActionBlock
		}),
		Entry("disabled gate with settings", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			*gate(t) = mirrorv1alpha1.VulnerabilityGate{Action: mirrorv1alpha1.GateActionBlock}
		}),
	)

	It("defaults the gate", func() {
		t := gatedTarget("default-gate")
		scanner(t).TokenSecretRef = &mirrorv1alpha1.TokenSecretKeyRef{Name: "trivy-token"}
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, t)
		g := gate(t)
		Expect(g.Action).To(Equal(mirrorv1alpha1.GateActionReport))
		Expect(g.OnScanError).To(Equal(mirrorv1alpha1.GateActionReport))
		Expect(g.Severity).To(Equal(mirrorv1alpha1.SeverityThresholdCritical))
		Expect(g.IgnoreUnfixed).To(BeFalse())
		Expect(g.IncludeUnknown).To(BeFalse())
		Expect(g.MaxDBAge.Duration).To(Equal(72 * time.Hour))
		Expect(g.RescanInterval).To(BeNil())
		Expect(g.OnVulnerableTag).To(Equal(mirrorv1alpha1.OnVulnerableTagReport))
		Expect(g.MaxExceptionDuration.Duration).To(Equal(2160 * time.Hour))
		s := g.Scanner
		Expect(s.JavaDB).To(Equal(mirrorv1alpha1.JavaDBDisabled))
		Expect(s.Timeout.Duration).To(Equal(10 * time.Minute))
		Expect(s.Storage.String()).To(Equal("20Gi"))
		Expect(s.TokenSecretRef.Key).To(Equal("token"))
		Expect(s.URL).To(BeEmpty())
		Expect(s.Image).To(BeEmpty())
	})

	It("does not enable the gate by default", func() {
		t := gatedTarget("off-gate")
		*gate(t) = mirrorv1alpha1.VulnerabilityGate{}
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, t)
		Expect(gate(t).Enabled).To(BeFalse())
	})

	DescribeTable("rejects an invalid gate",
		func(mutate func(*mirrorv1alpha1.ClusterMirrorTarget)) {
			t := gatedTarget("invalid-gate")
			mutate(t)
			err := k8sClient.Create(ctx, t)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected Invalid, got %v", err)
		},
		Entry("unknown action", func(t *mirrorv1alpha1.ClusterMirrorTarget) { gate(t).Action = "Quarantine" }),
		Entry("unknown onScanError", func(t *mirrorv1alpha1.ClusterMirrorTarget) { gate(t).OnScanError = "Ignore" }),
		Entry("severity Unknown", func(t *mirrorv1alpha1.ClusterMirrorTarget) { gate(t).Severity = "Unknown" }),
		Entry("maxDBAge below 1h", func(t *mirrorv1alpha1.ClusterMirrorTarget) { gate(t).MaxDBAge = duration(30 * time.Minute) }),
		Entry("rescanInterval below 1h", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			gate(t).RescanInterval = duration(10 * time.Minute)
		}),
		Entry("maxExceptionDuration above 90 days", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			gate(t).MaxExceptionDuration = duration(2161 * time.Hour)
		}),
		Entry("maxExceptionDuration below 1h", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			gate(t).MaxExceptionDuration = duration(time.Minute)
		}),
		Entry("Untag with action Report", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			gate(t).OnVulnerableTag = mirrorv1alpha1.OnVulnerableTagUntag
		}),
		Entry("plain HTTP to an external host", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://trivy.scanners.example.internal:4954"
		}),
		Entry("plain HTTP to a look-alike Service name", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://trivy.svc.example.com:4954"
		}),
		Entry("plain HTTP to a Service name under another domain", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://trivy.ns.svc.attacker.example/"
		}),
		Entry("plain HTTP to a Service name with a custom cluster domain", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://trivy.ns.svc.cluster.example:4954"
		}),
		Entry("plain HTTP to a Service with a userinfo-like path", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://trivy.ns.svc.cluster.local.attacker.example"
		}),
		Entry("plain HTTP to a Service name under the svc top-level domain", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://trivy.ns.svc.:4954"
		}),
		Entry("plain HTTP to a fully qualified Service name with a trailing path dot", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://trivy.ns.svc.cluster.local..:4954"
		}),
		Entry("plain HTTP to a short Service name", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "http://trivy:4954"
		}),
		Entry("URL with credentials", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "https://user:pass@trivy.scanners.example.internal"
		}),
		Entry("URL with a query", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "https://trivy.scanners.example.internal/?token=x"
		}),
		Entry("non-HTTP URL", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).URL = "grpc://trivy.scanners.example.internal:4954"
		}),
		Entry("image by tag", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).Image, scanner(t).Version = "ghcr.io/aquasecurity/trivy:0.76.1", trivyVersion
		}),
		Entry("image with a short digest", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).Image, scanner(t).Version = "ghcr.io/aquasecurity/trivy@sha256:abc", trivyVersion
		}),
		Entry("image without version", func(t *mirrorv1alpha1.ClusterMirrorTarget) { scanner(t).Image = trivyImage }),
		Entry("version without image", func(t *mirrorv1alpha1.ClusterMirrorTarget) { scanner(t).Version = trivyVersion }),
		Entry("version with a prefix", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).Image, scanner(t).Version = trivyImage, "v0.76.1"
		}),
		Entry("unknown javaDB", func(t *mirrorv1alpha1.ClusterMirrorTarget) { scanner(t).JavaDB = "Shared" }),
		Entry("PerJob without a repository", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).JavaDB = mirrorv1alpha1.JavaDBPerJob
		}),
		Entry("Java DB outside the target registry", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).JavaDB = mirrorv1alpha1.JavaDBPerJob
			scanner(t).JavaDBRepository = "ghcr.io/aquasecurity/trivy-java-db:1"
		}),
		Entry("Java DB on a look-alike registry", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).JavaDB = mirrorv1alpha1.JavaDBPerJob
			scanner(t).JavaDBRepository = "registry.example.internal:84430/platform/trivy-java-db:1"
		}),
		Entry("Java DB without a tag", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			scanner(t).JavaDB = mirrorv1alpha1.JavaDBPerJob
			scanner(t).JavaDBRepository = "registry.example.internal:8443/platform/trivy-java-db"
		}),
		Entry("timeout below 1m", func(t *mirrorv1alpha1.ClusterMirrorTarget) { scanner(t).Timeout = duration(30 * time.Second) }),
		Entry("timeout above 1h", func(t *mirrorv1alpha1.ClusterMirrorTarget) { scanner(t).Timeout = duration(2 * time.Hour) }),
		Entry("storage 0", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			q := resource.MustParse("0")
			scanner(t).Storage = &q
		}),
	)
})

var _ = Describe("reserved autoMirror project", func() {
	const pauseTag = "3.10"
	// reservedTarget creates a Ready target whose autoMirror project is
	// shared, with the gate g.
	// A reservation applies to every target on the registry, which the
	// other suites share, so the target is deleted after the spec.
	reservedTarget := func(name string, g mirrorv1alpha1.VulnerabilityGate) {
		DeferCleanup(func() { deleteAndWait(&mirrorv1alpha1.ClusterMirrorTarget{ObjectMeta: metav1.ObjectMeta{Name: name}}) })
		createReadyTarget(name, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.Projects = []mirrorv1alpha1.TargetProject{
				{Name: sharedProject, NamespaceSelector: &metav1.LabelSelector{}},
				{Name: otherProject, NamespaceSelector: &metav1.LabelSelector{}},
			}
			t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: sharedProject, VulnerabilityGate: &g}
		})
	}
	// userMirror is a mirror of registry.k8s.io/pause in project.
	userMirror := func(target, name, project string) *mirrorv1alpha1.ArtifactMirror {
		m := newMirror(teamB, name)
		m.Spec.TargetRef = target
		m.Spec.Target = mirrorv1alpha1.Target{Project: mirrorv1alpha1.ProjectName(project)}
		m.Spec.Tags = mirrorv1alpha1.TagSelector{Tags: []string{pauseTag}}
		return m
	}
	pauseName := generatedNameOf(k8sHost + "/pause")
	expectRefused := func(m *mirrorv1alpha1.ArtifactMirror) {
		EventuallyWithOffset(1, mirrorReady(m)).Should(And(
			HaveField("Status", metav1.ConditionFalse), HaveField("Reason", ReasonProjectReservedForAutoMirror),
			HaveField("Message", ContainSubstring("reserved for generated mirrors"))))
		_, err := cronJob(m)()
		ExpectWithOffset(1, notFound(err)).To(BeTrue())
		ExpectWithOffset(1, recorder.Events(m.Namespace, m.Name)).To(ContainElement(ContainSubstring("Warning " + ReasonProjectReservedForAutoMirror)))
	}
	expectReady := func(m *mirrorv1alpha1.ArtifactMirror) {
		EventuallyWithOffset(1, mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
	}
	block := mirrorv1alpha1.VulnerabilityGate{Enabled: true, Action: mirrorv1alpha1.GateActionBlock, OnScanError: mirrorv1alpha1.GateActionReport}

	DescribeTable("refuses a user mirror when the gate can block",
		func(target string, g mirrorv1alpha1.VulnerabilityGate) {
			reservedTarget(target, g)
			m := userMirror(target, "user-pause", sharedProject)
			createMirror(m)
			expectRefused(m)

			other := userMirror(target, "user-pause-other", otherProject)
			createMirror(other)
			expectReady(other)
		},
		Entry("action Block", "reserved-action", block),
		Entry("onScanError Block", "reserved-scan-error", mirrorv1alpha1.VulnerabilityGate{
			Enabled: true, Action: mirrorv1alpha1.GateActionReport, OnScanError: mirrorv1alpha1.GateActionBlock}),
	)

	It("treats a generated name without the label as a user mirror", func() {
		const target = "reserved-unlabelled"
		reservedTarget(target, block)
		m := userMirror(target, pauseName, sharedProject)
		m.Labels = map[string]string{mirrorv1alpha1.LabelAutoTarget: target}
		createMirror(m)
		expectRefused(m)
	})

	It("treats a labelled mirror with the wrong name as a user mirror", func() {
		const target = "reserved-wrong-name"
		reservedTarget(target, block)
		m := userMirror(target, "auto-0000000000000000", sharedProject)
		m.Labels = map[string]string{mirrorv1alpha1.LabelGenerated: trueValue, mirrorv1alpha1.LabelAutoTarget: target}
		createMirror(m)
		expectRefused(m)
	})

	It("lets a generated mirror use the project", func() {
		const target = "reserved-generated"
		reservedTarget(target, block)
		m := userMirror(target, pauseName, sharedProject)
		m.Labels = map[string]string{mirrorv1alpha1.LabelGenerated: trueValue, mirrorv1alpha1.LabelAutoTarget: target}
		createMirror(m)
		expectReady(m)
	})

	It("refuses a user mirror of another target on the same registry", func() {
		const (
			gated = "reserved-registry-a"
			plain = "reserved-registry-b"
		)
		// Target B: the same registry as A in upper case, no gate.
		DeferCleanup(func() { deleteAndWait(&mirrorv1alpha1.ClusterMirrorTarget{ObjectMeta: metav1.ObjectMeta{Name: plain}}) })
		createReadyTarget(plain, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.Registry = "REGISTRY.EXAMPLE.INTERNAL:8443"
			t.Spec.Projects = []mirrorv1alpha1.TargetProject{
				{Name: sharedProject, NamespaceSelector: &metav1.LabelSelector{}},
				{Name: otherProject, NamespaceSelector: &metav1.LabelSelector{}},
			}
		})
		viaB := userMirror(plain, "via-b", sharedProject)
		createMirror(viaB)
		expectReady(viaB)
		viaBOther := userMirror(plain, "via-b-other", otherProject)
		createMirror(viaBOther)
		expectReady(viaBOther)

		// A appears with Block: B's mirror in the reserved project is refused.
		reservedTarget(gated, block)
		expectRefused(viaB)
		Consistently(mirrorReady(viaBOther), time.Second).Should(HaveField("Status", metav1.ConditionTrue))

		// A generated mirror of A is still allowed.
		gen := userMirror(gated, pauseName, sharedProject)
		gen.Labels = map[string]string{mirrorv1alpha1.LabelGenerated: trueValue, mirrorv1alpha1.LabelAutoTarget: gated}
		createMirror(gen)
		expectReady(gen)

		// A drops Block: B's mirror is allowed again.
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var t mirrorv1alpha1.ClusterMirrorTarget
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: gated}, &t); err != nil {
				return err
			}
			t.Spec.AutoMirror.VulnerabilityGate.Action = mirrorv1alpha1.GateActionReport
			return k8sClient.Update(ctx, &t)
		})).To(Succeed())
		expectReady(viaB)
	})

	DescribeTable("does not reserve the project when the gate cannot block",
		func(target string, g mirrorv1alpha1.VulnerabilityGate) {
			reservedTarget(target, g)
			m := userMirror(target, pauseName, sharedProject)
			createMirror(m)
			expectReady(m)
		},
		Entry("Report", "unreserved-report", mirrorv1alpha1.VulnerabilityGate{
			Enabled: true, Action: mirrorv1alpha1.GateActionReport, OnScanError: mirrorv1alpha1.GateActionReport}),
		Entry("gate off", "unreserved-off", mirrorv1alpha1.VulnerabilityGate{
			Action: mirrorv1alpha1.GateActionBlock, OnScanError: mirrorv1alpha1.GateActionBlock}),
	)

	It("refuses a user mirror once the target moves to Block, and generates a mirror for pods", func() {
		const target = "reserved-switch"
		reservedTarget(target, mirrorv1alpha1.VulnerabilityGate{
			Enabled: true, Action: mirrorv1alpha1.GateActionReport, OnScanError: mirrorv1alpha1.GateActionReport})
		m := userMirror(target, "user-switch", sharedProject)
		createMirror(m)
		expectReady(m)

		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var t mirrorv1alpha1.ClusterMirrorTarget
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: target}, &t); err != nil {
				return err
			}
			t.Spec.AutoMirror.VulnerabilityGate.Action = mirrorv1alpha1.GateActionBlock
			return k8sClient.Update(ctx, &t)
		})).To(Succeed())
		expectRefused(m)

		// The refused user mirror no longer wins over a generated one.
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "reserved-pod", Namespace: teamB,
				Annotations: map[string]string{mirrorv1alpha1.AutoMirrorAnnotation: target}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: k8sHost + "/pause:" + pauseTag}}},
		}
		Expect(k8sClient.Create(ctx, p)).To(Succeed())
		gen := &mirrorv1alpha1.ArtifactMirror{ObjectMeta: metav1.ObjectMeta{Namespace: teamB, Name: pauseName}}
		DeferCleanup(func() {
			Expect(k8sClient.Delete(ctx, p, client.GracePeriodSeconds(0))).To(Succeed())
			time.Sleep(500 * time.Millisecond)
			deleteAndWait(gen)
		})
		Eventually(mirrorReady(gen)).Should(HaveField("Status", metav1.ConditionTrue))
		Expect(recorder.Events(teamB, p.Name)).NotTo(ContainElement(ContainSubstring(reasonAlreadyMirrored)))
	})
})

var _ = Describe("gated sync CronJob", func() {
	It("renders the scanner sidecar for generated mirrors of a gated target only", func() {
		const target = "gated-render"
		DeferCleanup(func() {
			deleteAndWait(&mirrorv1alpha1.ClusterMirrorTarget{ObjectMeta: metav1.ObjectMeta{Name: target}})
		})
		createReadyTarget(target, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.Projects = []mirrorv1alpha1.TargetProject{{Name: otherProject, NamespaceSelector: &metav1.LabelSelector{}}}
			t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: otherProject,
				VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{Enabled: true}}
		})
		gen := newMirror(teamB, generatedNameOf(k8sHost+"/pause"))
		gen.Spec.TargetRef = target
		gen.Spec.Target = mirrorv1alpha1.Target{Project: otherProject}
		gen.Spec.Tags = mirrorv1alpha1.TagSelector{Tags: []string{v310}}
		gen.Labels = map[string]string{mirrorv1alpha1.LabelGenerated: trueValue, mirrorv1alpha1.LabelAutoTarget: target}
		createMirror(gen)

		sidecarImage := func() string {
			cj, err := cronJob(gen)()
			if err != nil || len(cj.Spec.JobTemplate.Spec.Template.Spec.InitContainers) == 0 {
				return ""
			}
			return cj.Spec.JobTemplate.Spec.Template.Spec.InitContainers[0].Image
		}
		Eventually(sidecarImage).Should(Equal(trivyImage))
		cj, err := cronJob(gen)()
		Expect(err).NotTo(HaveOccurred())
		Expect(cj.Spec.JobTemplate.Spec.Template.Labels).To(HaveKeyWithValue(LabelScanner, ScannerTrivy))
		specOf := func() syncspec.Spec {
			var cm corev1.ConfigMap
			if k8sClient.Get(ctx, objectKey(gen), &cm) != nil {
				return syncspec.Spec{}
			}
			s, err := syncspec.Decode(strings.NewReader(cm.Data[specKey]))
			if err != nil {
				return syncspec.Spec{}
			}
			return s
		}
		Expect(specOf().Gate).NotTo(BeNil())

		By("restoring a hand edit of the sidecar")
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			cj, err := cronJob(gen)()
			if err != nil {
				return err
			}
			cj.Spec.JobTemplate.Spec.Template.Spec.InitContainers[0].Image = "registry.example.internal/other@sha256:" + strings.Repeat("0", 64)
			return k8sClient.Update(ctx, cj)
		})).To(Succeed())
		Eventually(sidecarImage).Should(Equal(trivyImage))

		By("passing an exception for the mirror into the spec")
		e := &mirrorv1alpha1.VulnerabilityException{
			ObjectMeta: metav1.ObjectMeta{Name: "gated-render-pause"},
			Spec: mirrorv1alpha1.VulnerabilityExceptionSpec{
				TargetRef: target, Namespaces: []string{teamB}, Repository: k8sHost + "/pause",
				Vulnerabilities: []string{testCVE}, Expires: metav1.NewTime(time.Now().Add(24 * time.Hour)),
				ApprovedBy: "security@example.com", Reason: "not reachable in this image",
			},
		}
		Expect(k8sClient.Create(ctx, e)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, e))).To(Succeed()) })
		Eventually(func() int {
			if g := specOf().Gate; g != nil {
				return len(g.Exceptions)
			}
			return -1
		}).Should(Equal(1))

		By("rendering a user mirror of the gated target without the sidecar")
		user := newMirror(teamB, "gated-render-user")
		user.Spec.TargetRef = target
		user.Spec.Source = mirrorv1alpha1.Source{Registry: ghcrRegistry, Repository: "example/gated-render"}
		user.Spec.Target = mirrorv1alpha1.Target{Project: otherProject}
		user.Spec.Tags = mirrorv1alpha1.TagSelector{Tags: []string{v310}}
		createMirror(user)
		Eventually(cronJob(user)).Should(WithTransform(func(cj *batchv1.CronJob) int {
			return len(cj.Spec.JobTemplate.Spec.Template.Spec.Containers)
		}, Equal(1)))
		cj, err = cronJob(user)()
		Expect(err).NotTo(HaveOccurred())
		Expect(cj.Spec.JobTemplate.Spec.Template.Spec.InitContainers).To(BeEmpty())
		Expect(cj.Spec.JobTemplate.Spec.Template.Labels).NotTo(HaveKey(LabelScanner))

		By("dropping the sidecar when the gate is turned off")
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var t mirrorv1alpha1.ClusterMirrorTarget
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: target}, &t); err != nil {
				return err
			}
			t.Spec.AutoMirror.VulnerabilityGate.Enabled = false
			return k8sClient.Update(ctx, &t)
		})).To(Succeed())
		Eventually(sidecarImage).Should(BeEmpty())
		Expect(specOf().Gate).To(BeNil())
	})
})

func TestRegistryKey(t *testing.T) {
	for _, tc := range []struct{ a, b mirrorv1alpha1.RegistryHost }{
		{"reg.example.internal", "REG.example.internal:443"},
		{"registry.example.internal:8443", "Registry.Example.Internal:8443"},
		{"[::1]", "[::1]:443"},
	} {
		if registryKey(tc.a) != registryKey(tc.b) {
			t.Errorf("registryKey(%q) != registryKey(%q)", tc.a, tc.b)
		}
	}
	if registryKey("reg.example.internal") == registryKey("reg.example.internal:8443") {
		t.Error("different ports map to one key")
	}
}
