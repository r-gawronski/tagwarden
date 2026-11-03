package controller

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const (
	targetRegistry = "registry.example.internal:8443"
	tag10          = "1.0"
)

var autoSeq atomic.Int64

var _ = Describe("auto-mirror", func() {
	const (
		autoTarget  = "auto-target"
		plainTarget = "plain-target"
	)

	BeforeEach(func() {
		if targetReady(autoTarget) == nil {
			createReadyTarget(autoTarget, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
				t.Spec.AllowedSources = []mirrorv1alpha1.RegistryHost{dockerHubHost, ghcrRegistry}
				t.Spec.Projects = []mirrorv1alpha1.TargetProject{{Name: sharedProject, NamespaceSelector: &metav1.LabelSelector{}}}
				t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: sharedProject, Schedule: "0 */6 * * *",
					MaxMirrorsPerNamespace: ptr.To[int32](2)}
			})
			createReadyTarget(plainTarget)
		}
	})

	newNS := func() string {
		ns := fmt.Sprintf("auto-ns-%d", autoSeq.Add(1))
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		DeferCleanup(func() {
			// Pods first, or the controller recreates the mirrors.
			Expect(k8sClient.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace(ns), client.GracePeriodSeconds(0))).To(Succeed())
			time.Sleep(500 * time.Millisecond)
			var l mirrorv1alpha1.ArtifactMirrorList
			Expect(k8sClient.List(ctx, &l, client.InNamespace(ns))).To(Succeed())
			for i := range l.Items {
				deleteAndWait(&l.Items[i])
			}
		})
		return ns
	}
	pod := func(ns, target string, images ...string) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("p%d", autoSeq.Add(1)), Namespace: ns,
				Annotations: map[string]string{mirrorv1alpha1.AutoMirrorAnnotation: target}},
		}
		for i, img := range images {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: fmt.Sprintf("c%d", i), Image: img})
		}
		Expect(k8sClient.Create(ctx, p)).To(Succeed())
		return p
	}
	generated := func(ns string) func() []mirrorv1alpha1.ArtifactMirror {
		return func() []mirrorv1alpha1.ArtifactMirror {
			var l mirrorv1alpha1.ArtifactMirrorList
			Expect(k8sClient.List(ctx, &l, client.InNamespace(ns), client.MatchingLabels{mirrorv1alpha1.LabelGenerated: "true"})).To(Succeed())
			return l.Items
		}
	}
	events := func(p *corev1.Pod) func() string {
		return func() string { return strings.Join(recorder.Events(p.Namespace, p.Name), "\n") }
	}
	only := func(ns string) mirrorv1alpha1.ArtifactMirror {
		var got []mirrorv1alpha1.ArtifactMirror
		EventuallyWithOffset(1, func() int { got = generated(ns)(); return len(got) }).Should(Equal(1))
		return got[0]
	}

	It("rejects an autoMirror project that is not listed", func() {
		t := newTarget("auto-bad")
		t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: "unlisted"}
		Expect(k8sClient.Create(ctx, t)).To(MatchError(ContainSubstring("autoMirror.project must be listed in projects")))
	})

	It("only warns when the target has no autoMirror", func() {
		ns := newNS()
		p := pod(ns, plainTarget, "nginx:1.27")
		Eventually(events(p)).Should(ContainSubstring("Warning AutoMirrorDisabled"))
		Consistently(generated(ns), "1s").Should(BeEmpty())
	})

	It("generates one mirror per repository with the union of tags and asks for a sync", func() {
		ns := newNS()
		p := pod(ns, autoTarget, "nginx:1.27", "docker.io/library/nginx:1.26", "ghcr.io/org/app:v1@sha256:"+strings.Repeat("a", 64))
		_ = p
		var all []mirrorv1alpha1.ArtifactMirror
		Eventually(func() int { all = generated(ns)(); return len(all) }).Should(Equal(2))
		var nginx mirrorv1alpha1.ArtifactMirror
		for _, m := range all {
			if m.Spec.Source.Repository == libraryNginx {
				nginx = m
			}
		}
		Expect(nginx.Name).To(Equal(generatedName(imageSource{Registry: dockerHubHost, Repository: libraryNginx})))
		Expect(nginx.Spec.Tags.Tags).To(Equal([]string{"1.26", tag127}))
		Expect(nginx.Spec.Source.Registry).To(BeEquivalentTo(dockerHubHost))
		Expect(nginx.Spec.Target.Project).To(BeEquivalentTo(sharedProject))
		Expect(nginx.Spec.Schedule).To(Equal("0 */6 * * *"))
		Expect(nginx.Labels).To(HaveKeyWithValue(mirrorv1alpha1.LabelAutoTarget, autoTarget))
		Expect(nginx.Annotations).To(HaveKey(mirrorv1alpha1.SyncNowAnnotation))
		Eventually(events(p)).Should(ContainSubstring("Normal MirrorRequested"))
		Eventually(mirrorReady(&nginx)).Should(HaveField("Status", metav1.ConditionTrue))
	})

	It("reuses the mirror for a second pod and adds a new tag with a new sync-now value", func() {
		ns := newNS()
		pod(ns, autoTarget, "nginx:1.27")
		m := only(ns)
		first := m.Annotations[mirrorv1alpha1.SyncNowAnnotation]
		pod(ns, autoTarget, "nginx:1.27")
		Consistently(generated(ns), "1s").Should(HaveLen(1))
		Expect(only(ns).Annotations[mirrorv1alpha1.SyncNowAnnotation]).To(Equal(first))

		pod(ns, autoTarget, "nginx:1.28")
		Eventually(func() []string { return only(ns).Spec.Tags.Tags }).Should(Equal([]string{tag127, "1.28"}))
		Expect(only(ns).Annotations[mirrorv1alpha1.SyncNowAnnotation]).NotTo(Equal(first))
	})

	It("maps refs that point at the target registry back to the source", func() {
		ns := newNS()
		pod(ns, autoTarget, targetRegistry+"/shared/ghcr.io/org/tool:v2")
		m := only(ns)
		Expect(m.Spec.Source.Registry).To(BeEquivalentTo(ghcrRegistry))
		Expect(m.Spec.Source.Repository).To(Equal("org/tool"))
		Expect(m.Spec.Tags.Tags).To(Equal([]string{"v2"}))
	})

	It("skips digest-only refs with an Event", func() {
		ns := newNS()
		p := pod(ns, autoTarget, "ghcr.io/org/app@sha256:"+strings.Repeat("b", 64))
		Eventually(events(p)).Should(ContainSubstring("Warning DigestOnlyNotSupported"))
		Consistently(generated(ns), "1s").Should(BeEmpty())
	})

	It("stops at maxMirrorsPerNamespace", func() {
		ns := newNS()
		pod(ns, autoTarget, "ghcr.io/org/a:1", "ghcr.io/org/b:1")
		Eventually(func() int { return len(generated(ns)()) }).Should(Equal(2))
		p := pod(ns, autoTarget, "ghcr.io/org/c:1")
		Eventually(events(p)).Should(And(ContainSubstring("MirrorRefused"), ContainSubstring("QuotaExceeded")))
		Consistently(generated(ns), "1s").Should(HaveLen(2))
	})

	It("leaves a user-defined mirror of the same source alone", func() {
		ns := newNS()
		m := newMirror(ns, "mine")
		m.Spec.TargetRef = autoTarget
		m.Spec.Source = mirrorv1alpha1.Source{Registry: dockerHubHost, Repository: libraryNginx}
		m.Spec.Target = mirrorv1alpha1.Target{Project: sharedProject}
		m.Spec.Tags = mirrorv1alpha1.TagSelector{Tags: []string{tag10}}
		createMirror(m)
		p := pod(ns, autoTarget, "nginx:1.27")
		Eventually(events(p)).Should(ContainSubstring("AlreadyMirrored"))
		Consistently(generated(ns), "1s").Should(BeEmpty())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(m), m)).To(Succeed())
		Expect(m.Spec.Tags.Tags).To(Equal([]string{tag10}))
	})

	It("relays a mirror that is not Ready as MirrorRefused", func() {
		ns := newNS()
		p := pod(ns, autoTarget, "quay.io/org/app:1")
		m := only(ns)
		Eventually(mirrorReady(&m)).Should(And(HaveField("Status", metav1.ConditionFalse), HaveField("Reason", ReasonSourceNotAllowed)))
		Eventually(events(p)).Should(And(ContainSubstring("Warning MirrorRefused"), ContainSubstring(ReasonSourceNotAllowed)))
	})

	It("relays a failed Synced condition as SyncFailed", func() {
		ns := newNS()
		p := pod(ns, autoTarget, "ghcr.io/org/failing:1")
		m := only(ns)
		Eventually(mirrorReady(&m)).Should(HaveField("Status", metav1.ConditionTrue))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(&m), &m)).To(Succeed())
		meta.SetStatusCondition(&m.Status.Conditions, metav1.Condition{Type: ConditionSynced, Status: metav1.ConditionFalse,
			Reason: "VulnerabilityBlocked", Message: "critical finding", ObservedGeneration: m.Generation})
		Expect(k8sClient.Status().Update(ctx, &m)).To(Succeed())
		Eventually(events(p)).Should(And(ContainSubstring("SyncFailed"), ContainSubstring("VulnerabilityBlocked: critical finding")))
	})
})
