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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

const (
	mirrorTarget = "mirror-target"
	teamA        = "team-a"
	teamB        = "team-b"
	sharedRepo   = "shared/app"
	v310         = "3.10"
	teamLabel    = "example.com/team"
	ghcrRegistry = "ghcr.io"
	// sharedProject allows every namespace and no target.repository override.
	sharedProject = "shared"
)

// deleteAndWait deletes obj and waits until the finalizer is gone.
func deleteAndWait(obj client.Object) {
	ExpectWithOffset(1, client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed())
	EventuallyWithOffset(1, func() bool {
		return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj))
	}).Should(BeTrue())
}

func newMirror(namespace, name string) *mirrorv1alpha1.ArtifactMirror {
	m := validMirror(name)
	m.Namespace = namespace
	m.Spec.TargetRef = mirrorTarget
	return m
}

func createMirror(m *mirrorv1alpha1.ArtifactMirror) {
	ExpectWithOffset(1, k8sClient.Create(ctx, m)).To(Succeed())
	DeferCleanup(deleteAndWait, m)
}

// updateMirror reads m, applies mutate and writes it back, retrying on
// conflicts with the controller's status updates.
func updateMirror(m *mirrorv1alpha1.ArtifactMirror, mutate func(*mirrorv1alpha1.ArtifactMirror)) {
	ExpectWithOffset(1, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(m), m); err != nil {
			return err
		}
		mutate(m)
		return k8sClient.Update(ctx, m)
	})).To(Succeed())
}

func mirrorReady(m *mirrorv1alpha1.ArtifactMirror) func() *metav1.Condition {
	return func() *metav1.Condition {
		var got mirrorv1alpha1.ArtifactMirror
		if k8sClient.Get(ctx, client.ObjectKeyFromObject(m), &got) != nil {
			return nil
		}
		return meta.FindStatusCondition(got.Status.Conditions, ConditionReady)
	}
}

func objectKey(m *mirrorv1alpha1.ArtifactMirror) types.NamespacedName {
	return types.NamespacedName{Namespace: operatorNamespace, Name: objectName(m)}
}

func cronJob(m *mirrorv1alpha1.ArtifactMirror) func() (*batchv1.CronJob, error) {
	return func() (*batchv1.CronJob, error) {
		var cj batchv1.CronJob
		err := k8sClient.Get(ctx, objectKey(m), &cj)
		return &cj, err
	}
}

func notFound(err error) bool { return apierrors.IsNotFound(err) }

// createMirrorFixtures creates the tenant namespaces and the target the
// mirror tests share. The suite calls it once.
func createMirrorFixtures() {
	for ns, labels := range map[string]map[string]string{teamA: {teamLabel: "a"}, teamB: nil} {
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: labels}})).To(Succeed())
	}
	createReadyTarget(mirrorTarget, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
		t.Spec.AllowedSources = append(t.Spec.AllowedSources, dockerHubHost, "169.254.169.254", "10.96.0.10")
		t.Spec.Projects = append(t.Spec.Projects, mirrorv1alpha1.TargetProject{
			Name: sharedProject, NamespaceSelector: &metav1.LabelSelector{}})
	})
}

var _ = Describe("ArtifactMirror Controller", func() {
	It("renders a hardened CronJob and its spec ConfigMap", func() {
		m := newMirror(teamA, "render")
		createMirror(m)
		Eventually(mirrorReady(m)).Should(And(
			HaveField("Status", metav1.ConditionTrue), HaveField("Reason", ReasonReady)))
		Expect(recorder.Events(teamA, m.Name)).To(ContainElement(ContainSubstring("Normal Created Created CronJob")))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(m), m)).To(Succeed())
		Expect(m.Finalizers).To(ContainElement(Finalizer))
		Expect(m.Status.ObservedGeneration).To(Equal(m.Generation))

		var cm corev1.ConfigMap
		Expect(k8sClient.Get(ctx, objectKey(m), &cm)).To(Succeed())
		spec, err := syncspec.Decode(bytes.NewReader([]byte(cm.Data["spec.json"])))
		Expect(err).NotTo(HaveOccurred())
		Expect(spec.Mirror).To(Equal(syncspec.Mirror{Namespace: teamA, Name: "render"}))
		Expect(spec.Source).To(Equal("registry.k8s.io/pause"))
		Expect(spec.Target).To(Equal("registry.example.internal:8443/mirror/k8s/pause"))
		Expect(spec.AllowedSources).To(ContainElements(k8sHost, "ghcr.io"))
		Expect(spec.DeniedCIDRs).To(Equal([]string{deniedCIDR}))
		Expect(spec.MaxTags).To(Equal(10000))
		Expect(spec.OnTagMutation).To(Equal(mirrorv1alpha1.OnTagMutationFail))
		Expect(spec.Tags.KeepLatest).To(Equal(3))
		Expect(spec.RequiredPlatforms).To(Equal(m.Spec.RequiredPlatforms))

		cj, err := cronJob(m)()
		Expect(err).NotTo(HaveOccurred())
		hash := mirrorHash(teamA, "render")
		for _, o := range []metav1.Object{cj, &cm, &cj.Spec.JobTemplate} {
			Expect(o.GetLabels()).To(HaveKeyWithValue(LabelMirror, hash))
			Expect(o.GetAnnotations()).To(And(
				HaveKeyWithValue(AnnotationMirrorNamespace, teamA), HaveKeyWithValue(AnnotationMirrorName, "render")))
		}
		Expect(cj.Spec.Schedule).To(Equal("0 3 * * *"))
		Expect(*cj.Spec.Suspend).To(BeFalse())
		Expect(cj.Spec.ConcurrencyPolicy).To(Equal(batchv1.ForbidConcurrent))
		Expect(*cj.Spec.StartingDeadlineSeconds).To(BeEquivalentTo(300))
		Expect(*cj.Spec.SuccessfulJobsHistoryLimit).To(BeEquivalentTo(3))
		Expect(*cj.Spec.FailedJobsHistoryLimit).To(BeEquivalentTo(3))
		job := cj.Spec.JobTemplate.Spec
		Expect(*job.BackoffLimit).To(BeEquivalentTo(2))
		Expect(*job.ActiveDeadlineSeconds).To(BeEquivalentTo(3600))
		Expect(*job.TTLSecondsAfterFinished).To(BeEquivalentTo(86400))

		pod := job.Template.Spec
		Expect(pod.ServiceAccountName).To(Equal("tagwarden-sync"))
		Expect(*pod.AutomountServiceAccountToken).To(BeFalse())
		Expect(pod.RestartPolicy).To(Equal(corev1.RestartPolicyNever))
		Expect(*pod.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*pod.SecurityContext.RunAsUser).To(BeEquivalentTo(65532))
		Expect(*pod.SecurityContext.RunAsGroup).To(BeEquivalentTo(65532))
		Expect(*pod.SecurityContext.FSGroup).To(BeEquivalentTo(65532))
		Expect(pod.SecurityContext.SeccompProfile.Type).To(Equal(corev1.SeccompProfileTypeRuntimeDefault))
		Expect(pod.Containers).To(HaveLen(1))
		c := pod.Containers[0]
		Expect(c.Image).To(Equal(syncImage))
		Expect(c.Command).To(BeEmpty())
		Expect(c.Args).To(Equal([]string{"sync", "--spec", "/etc/tagwarden/spec.json"}))
		Expect(*c.SecurityContext.ReadOnlyRootFilesystem).To(BeTrue())
		Expect(*c.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(c.SecurityContext.Capabilities.Drop).To(Equal([]corev1.Capability{"ALL"}))
		Expect(c.Resources.Requests.Cpu().String()).To(Equal("50m"))
		Expect(c.Resources.Requests.Memory().String()).To(Equal("64Mi"))
		Expect(c.Resources.Limits.Cpu().String()).To(Equal("1"))
		Expect(c.Resources.Limits.Memory().String()).To(Equal("512Mi"))
		Expect(c.TerminationMessagePolicy).To(Equal(corev1.TerminationMessageReadFile))

		mounts := map[string]string{}
		for _, vm := range c.VolumeMounts {
			mounts[vm.Name] = vm.MountPath
			Expect(vm.ReadOnly || vm.Name == "tmp").To(BeTrue(), vm.Name)
		}
		Expect(mounts).To(Equal(map[string]string{
			"spec":        "/etc/tagwarden",
			"target-auth": filepath.Dir(syncspec.TargetAuthFile),
			"target-ca":   filepath.Dir(syncspec.TargetCAFile),
			"proxy-ca":    filepath.Dir(syncspec.ProxyCAFile),
			"client-cert": syncspec.ClientCertDir,
			"tmp":         "/tmp",
		}))
		volumes := map[string]corev1.VolumeSource{}
		for _, v := range pod.Volumes {
			volumes[v.Name] = v.VolumeSource
		}
		Expect(volumes["spec"].ConfigMap.Name).To(Equal(cm.Name))
		Expect(volumes["target-auth"].Secret.SecretName).To(Equal(mirrorTarget + "-push"))
		Expect(volumes["target-auth"].Secret.Items).To(Equal([]corev1.KeyToPath{{Key: dockerCfgFile, Path: dockerCfgFile}}))
		Expect(volumes["target-ca"].Secret.SecretName).To(Equal(mirrorTarget + "-ca"))
		Expect(volumes["proxy-ca"].Secret.SecretName).To(Equal(mirrorTarget + "-proxy-ca"))
		Expect(volumes["client-cert"].Secret.SecretName).To(Equal(mirrorTarget + "-client-tls"))
		Expect(volumes["tmp"].EmptyDir).NotTo(BeNil())

		env := map[string]corev1.EnvVar{}
		for _, e := range c.Env {
			env[e.Name] = e
		}
		Expect(env["HTTPS_PROXY"].Value).To(Equal("http://proxy.example.internal:3128"))
		Expect(env["NO_PROXY"].Value).To(Equal(".example.internal,10.0.0.0/8"))
		for k, key := range map[string]string{syncspec.ProxyUserEnv: usernameKey, syncspec.ProxyPasswordEnv: passwordKey} {
			Expect(env[k].Value).To(BeEmpty())
			Expect(env[k].ValueFrom.SecretKeyRef.Name).To(Equal(mirrorTarget + "-proxy-auth"))
			Expect(env[k].ValueFrom.SecretKeyRef.Key).To(Equal(key))
		}

		rendered, err := json.Marshal([]any{cj, &cm, m})
		Expect(err).NotTo(HaveOccurred())
		expectNoSecrets(string(rendered))
		expectNoSecrets(recorder.Events(teamA, m.Name)...)
	})

	It("updates the CronJob when the mirror changes", func() {
		m := newMirror(teamA, "update")
		createMirror(m)
		Eventually(mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
		Eventually(cronJob(m)).Should(HaveField("Spec.Schedule", "0 3 * * *"))
		cj, _ := cronJob(m)()
		sum := cj.Spec.JobTemplate.Spec.Template.Annotations[annotationSpecChecksum]
		Expect(sum).NotTo(BeEmpty())

		updateMirror(m, func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Schedule = "@hourly"
			m.Spec.Suspend = true
		})
		Eventually(cronJob(m)).Should(And(
			HaveField("Spec.Schedule", "@hourly"), HaveField("Spec.Suspend", HaveValue(BeTrue()))))
		cj, _ = cronJob(m)()
		Expect(cj.Spec.JobTemplate.Spec.Template.Annotations[annotationSpecChecksum]).To(Equal(sum))

		updateMirror(m, func(m *mirrorv1alpha1.ArtifactMirror) { m.Spec.Tags.Tags = []string{"3.9"} })
		Eventually(func() string {
			cj, _ := cronJob(m)()
			return cj.Spec.JobTemplate.Spec.Template.Annotations[annotationSpecChecksum]
		}).ShouldNot(Equal(sum))
	})

	It("leaves an unchanged CronJob and ConfigMap alone", func() {
		m := newMirror(teamA, "steady")
		createMirror(m)
		Eventually(mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
		cj, _ := cronJob(m)()
		var cm corev1.ConfigMap
		Expect(k8sClient.Get(ctx, objectKey(m), &cm)).To(Succeed())
		updates := writes.Load()

		// A metadata change reconciles the mirror without changing its spec.
		updateMirror(m, func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Labels = map[string]string{"example.com/touch": "1"}
		})
		Consistently(func() []string {
			got, _ := cronJob(m)()
			var gotCM corev1.ConfigMap
			_ = k8sClient.Get(ctx, objectKey(m), &gotCM)
			return []string{got.ResourceVersion, gotCM.ResourceVersion}
		}, "2s").Should(Equal([]string{cj.ResourceVersion, cm.ResourceVersion}))
		Expect(writes.Load()).To(Equal(updates), "CronJob or ConfigMap update calls")
	})

	It("restores hand-edited security fields of the CronJob", func() {
		m := newMirror(teamA, "hand-edit")
		createMirror(m)
		Eventually(mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
		cj, _ := cronJob(m)()
		pod := &cj.Spec.JobTemplate.Spec.Template.Spec
		pod.Containers[0].Image = "registry.example.internal/evil:latest"
		pod.Containers[0].SecurityContext.Privileged = new(true)
		pod.Containers[0].SecurityContext.AllowPrivilegeEscalation = new(true)
		pod.SecurityContext.RunAsNonRoot = new(false)
		pod.HostAliases = []corev1.HostAlias{{IP: "10.0.0.1", Hostnames: []string{"source.example.internal"}}}
		Expect(k8sClient.Update(ctx, cj)).To(Succeed())

		Eventually(func(g Gomega) {
			got, err := cronJob(m)()
			g.Expect(err).NotTo(HaveOccurred())
			p := got.Spec.JobTemplate.Spec.Template.Spec
			g.Expect(p.Containers[0].Image).To(Equal(syncImage))
			g.Expect(p.Containers[0].SecurityContext.Privileged).To(BeNil())
			g.Expect(*p.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			g.Expect(*p.SecurityContext.RunAsNonRoot).To(BeTrue())
			g.Expect(p.HostAliases).To(BeEmpty())
		}).Should(Succeed())
	})

	It("labels sync pods with the target and its egress mode", func() {
		expectLabels := func(m *mirrorv1alpha1.ArtifactMirror, target, egress string) {
			EventuallyWithOffset(1, func(g Gomega) {
				cj, err := cronJob(m)()
				g.Expect(err).NotTo(HaveOccurred())
				for _, l := range []map[string]string{cj.Labels, cj.Spec.JobTemplate.Labels, cj.Spec.JobTemplate.Spec.Template.Labels} {
					g.Expect(l).To(And(HaveKeyWithValue(LabelTarget, target), HaveKeyWithValue(LabelEgress, egress)))
				}
			}).Should(Succeed())
		}
		proxied := newMirror(teamA, "egress-proxy")
		createMirror(proxied)
		expectLabels(proxied, mirrorTarget, EgressProxy)

		// NetworkPolicies select by these labels, so a hand edit is reverted.
		// Labels outside tagwarden.dev/, such as from a webhook, stay.
		cj, _ := cronJob(proxied)()
		podLabels := cj.Spec.JobTemplate.Spec.Template.Labels
		podLabels["example.com/injected"] = "yes"
		Expect(k8sClient.Update(ctx, cj)).To(Succeed())
		Consistently(func() map[string]string {
			got, _ := cronJob(proxied)()
			return got.Spec.JobTemplate.Spec.Template.Labels
		}, "2s").Should(HaveKeyWithValue("example.com/injected", "yes"))

		for _, edit := range []func(map[string]string){
			func(l map[string]string) { delete(l, LabelEgress) },
			func(l map[string]string) { l[LabelEgress] = EgressDirect },
			func(l map[string]string) { l[LabelTarget] = "other-target" },
		} {
			cj, _ = cronJob(proxied)()
			edit(cj.Spec.JobTemplate.Spec.Template.Labels)
			Expect(k8sClient.Update(ctx, cj)).To(Succeed())
			expectLabels(proxied, mirrorTarget, EgressProxy)
		}

		t := createReadyTarget("direct-target", func(t *mirrorv1alpha1.ClusterMirrorTarget) { t.Spec.Proxy = nil })
		direct := newMirror(teamA, "egress-direct")
		direct.Spec.TargetRef = t.Name
		createMirror(direct)
		expectLabels(direct, t.Name, EgressDirect)

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(t), t)).To(Succeed())
		t.Spec.Proxy = newTarget(t.Name).Spec.Proxy
		Expect(k8sClient.Update(ctx, t)).To(Succeed())
		expectLabels(direct, t.Name, EgressProxy)
	})

	It("hashes a target name that is not a valid label value", func() {
		long := strings.Repeat("t", 64) + ".example"
		createReadyTarget(long)
		m := newMirror(teamA, "long-target")
		m.Spec.TargetRef = long
		createMirror(m)
		sum := sha256.Sum256([]byte(long))
		want := "h-" + hex.EncodeToString(sum[:])[:20]
		Eventually(func() map[string]string {
			cj, _ := cronJob(m)()
			return cj.Spec.JobTemplate.Spec.Template.Labels
		}).Should(HaveKeyWithValue(LabelTarget, want))
	})

	It("never touches a CronJob or ConfigMap that names another mirror", func() {
		m := newMirror(teamA, "squatted")
		foreign := func() (*batchv1.CronJob, *corev1.ConfigMap) {
			labels := map[string]string{LabelMirror: mirrorHash(teamA, "squatted")}
			annotations := map[string]string{AnnotationMirrorNamespace: "elsewhere", AnnotationMirrorName: "owner"}
			om := metav1.ObjectMeta{Name: objectName(m), Namespace: operatorNamespace, Labels: labels, Annotations: annotations}
			pod := corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever,
				Containers: []corev1.Container{{Name: syncContainer, Image: syncImage}}}
			return &batchv1.CronJob{ObjectMeta: om, Spec: batchv1.CronJobSpec{Schedule: "@daily",
					JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: pod}}}}},
				&corev1.ConfigMap{ObjectMeta: *om.DeepCopy(), Data: map[string]string{"spec.json": "{}"}}
		}
		cj, cm := foreign()
		Expect(k8sClient.Create(ctx, cj)).To(Succeed())
		Expect(k8sClient.Create(ctx, cm)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, cj)
		DeferCleanup(k8sClient.Delete, ctx, cm)

		Expect(k8sClient.Create(ctx, m)).To(Succeed())
		Eventually(mirrorReady(m)).Should(And(
			HaveField("Status", metav1.ConditionFalse), HaveField("Reason", ReasonOwnershipConflict),
			HaveField("Message", ContainSubstring("elsewhere/owner"))))
		Expect(recorder.Events(teamA, m.Name)).To(ContainElement(ContainSubstring("Warning " + ReasonOwnershipConflict)))
		deleteAndWait(m)

		got, err := cronJob(m)()
		Expect(err).NotTo(HaveOccurred())
		Expect(got.ResourceVersion).To(Equal(cj.ResourceVersion))
		var gotCM corev1.ConfigMap
		Expect(k8sClient.Get(ctx, objectKey(m), &gotCM)).To(Succeed())
		Expect(gotCM.ResourceVersion).To(Equal(cm.ResourceVersion))
	})

	It("removes the CronJob when the namespace loses its project label", func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a-2", Labels: map[string]string{teamLabel: "a"}}}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		m := newMirror(ns.Name, "labelled")
		m.Spec.Target = mirrorv1alpha1.Target{Project: teamA}
		createMirror(m)
		Eventually(func() error { _, err := cronJob(m)(); return err }).Should(Succeed())

		ns.Labels = nil
		Expect(k8sClient.Update(ctx, ns)).To(Succeed())
		Eventually(mirrorReady(m)).Should(HaveField("Reason", ReasonProjectNotAllowed))
		_, err := cronJob(m)()
		Expect(notFound(err)).To(BeTrue())
	})

	DescribeTable("refuses a mirror and renders no CronJob",
		func(namespace string, mutate func(*mirrorv1alpha1.ArtifactMirror), reason, message string) {
			m := newMirror(namespace, "refused")
			mutate(m)
			createMirror(m)
			Eventually(mirrorReady(m)).Should(And(
				HaveField("Status", metav1.ConditionFalse),
				HaveField("Reason", reason),
				HaveField("Message", ContainSubstring(message))))
			_, err := cronJob(m)()
			Expect(notFound(err)).To(BeTrue())
			Expect(recorder.Events(namespace, m.Name)).To(ContainElement(ContainSubstring("Warning " + reason)))
		},
		Entry("project not allowed for the namespace", teamB, func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Target.Project = teamA
		}, ReasonProjectNotAllowed, "does not allow namespace team-b"),
		Entry("project not listed", teamA, func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Target.Project = "other"
		}, ReasonProjectNotAllowed, "not listed"),
		Entry("source not allowed", teamA, func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Source.Registry = "quay.io"
		}, ReasonSourceNotAllowed, "quay.io is not in allowedSources"),
		Entry("metadata address as source", teamA, func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Source.Registry = "169.254.169.254"
		}, ReasonSourceNotAllowed, "internal address"),
		Entry("service CIDR address as source", teamA, func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Source.Registry = "10.96.0.10"
		}, ReasonSourceNotAllowed, "denied CIDR"),
		Entry("unknown target", teamA, func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.TargetRef = "missing"
		}, ReasonTargetNotReady, "missing not found"),
		Entry("tag pattern that does not compile", teamA, func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Tags.Include = []string{"("}
		}, ReasonInvalidSpec, "include"),
		Entry("classic Helm repository", teamA, func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Type = mirrorv1alpha1.ArtifactTypeHelmRepo
		}, ReasonInvalidSpec, "HelmRepo"),
	)

	It("lets the older mirror keep a target repository claimed by another source", func() {
		first := newMirror(teamA, "claim-a")
		first.Spec.Target.Repository = sharedRepo
		createMirror(first)
		Eventually(mirrorReady(first)).Should(HaveField("Status", metav1.ConditionTrue))

		other := newMirror(teamA, "claim-b")
		other.Spec.Target.Repository = sharedRepo
		other.Spec.Source.Registry = ghcrRegistry
		createMirror(other)
		same := newMirror(teamB, "claim-c")
		same.Spec.Target.Repository = sharedRepo
		createMirror(same)

		Eventually(mirrorReady(other)).Should(And(
			HaveField("Reason", ReasonTargetConflict),
			HaveField("Message", ContainSubstring("claimed by team-a/claim-a with source registry.k8s.io/pause"))))
		Eventually(mirrorReady(same)).Should(HaveField("Status", metav1.ConditionTrue))
		Expect(mirrorReady(first)()).To(HaveField("Status", metav1.ConditionTrue))
		_, err := cronJob(other)()
		Expect(notFound(err)).To(BeTrue())
	})

	It("re-checks the other mirrors of a path when an older mirror moves onto it", func() {
		older := newMirror(teamA, "move-a")
		older.Spec.Target.Repository = "moved/before"
		older.Spec.Source.Registry = ghcrRegistry
		createMirror(older)
		Eventually(mirrorReady(older)).Should(HaveField("Status", metav1.ConditionTrue))
		newer := newMirror(teamA, "move-b")
		newer.Spec.Target.Repository = "moved/app"
		createMirror(newer)
		Eventually(mirrorReady(newer)).Should(HaveField("Status", metav1.ConditionTrue))

		updateMirror(older, func(m *mirrorv1alpha1.ArtifactMirror) { m.Spec.Target.Repository = "moved/app" })
		Eventually(mirrorReady(newer)).Should(HaveField("Reason", ReasonTargetConflict))
		_, err := cronJob(newer)()
		Expect(notFound(err)).To(BeTrue())
		Expect(mirrorReady(older)()).To(HaveField("Status", metav1.ConditionTrue))
	})

	It("hands a path to the next mirror when its owner is deleted", func() {
		owner := newMirror(teamA, "owner-a")
		owner.Spec.Target.Repository = "handover/app"
		createMirror(owner)
		Eventually(mirrorReady(owner)).Should(HaveField("Status", metav1.ConditionTrue))
		next := newMirror(teamA, "owner-b")
		next.Spec.Target.Repository = "handover/app"
		next.Spec.Source.Registry = ghcrRegistry
		createMirror(next)
		Eventually(mirrorReady(next)).Should(HaveField("Reason", ReasonTargetConflict))

		deleteAndWait(owner)
		Eventually(mirrorReady(next)).Should(HaveField("Status", metav1.ConditionTrue))
		Eventually(func() error { _, err := cronJob(next)(); return err }).Should(Succeed())
	})

	Describe("target.repository override", func() {
		// validMirror sets target.repository: k8s/pause.
		shared := func(namespace, name string) *mirrorv1alpha1.ArtifactMirror {
			m := newMirror(namespace, name)
			m.Spec.Target.Project = sharedProject
			return m
		}

		It("refuses an override in a project that does not allow it", func() {
			m := shared(teamA, "override-refused")
			createMirror(m)
			Eventually(mirrorReady(m)).Should(And(
				HaveField("Status", metav1.ConditionFalse),
				HaveField("Reason", ReasonRepositoryOverrideNotAllowed),
				HaveField("Message", ContainSubstring("registry.k8s.io/pause"))))
			Expect(recorder.Events(teamA, m.Name)).To(ContainElement(ContainSubstring("Warning " + ReasonRepositoryOverrideNotAllowed)))
			_, err := cronJob(m)()
			Expect(notFound(err)).To(BeTrue())
		})

		It("accepts an override equal to the default path", func() {
			m := shared(teamA, "override-default")
			m.Spec.Target.Repository = "registry.k8s.io/pause"
			createMirror(m)
			Eventually(mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
		})

		It("accepts an override in a project that allows it", func() {
			m := newMirror(teamA, "override-allowed")
			createMirror(m)
			Eventually(mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
		})

		It("keeps a default path for its source when an older mirror squats it", func() {
			squatter := shared(teamA, "squat-a")
			squatter.Spec.Source = mirrorv1alpha1.Source{Registry: ghcrRegistry, Repository: "someone/nginx"}
			squatter.Spec.Target.Repository = "docker.io/library/nginx"
			createMirror(squatter)
			Eventually(mirrorReady(squatter)).Should(HaveField("Reason", ReasonRepositoryOverrideNotAllowed))

			nginx := shared(teamB, "squat-b")
			nginx.Spec.Source = mirrorv1alpha1.Source{Registry: dockerHubHost, Repository: "nginx"}
			nginx.Spec.Target.Repository = ""
			createMirror(nginx)
			Eventually(mirrorReady(nginx)).Should(HaveField("Status", metav1.ConditionTrue))
			Eventually(func() error { _, err := cronJob(nginx)(); return err }).Should(Succeed())
			_, err := cronJob(squatter)()
			Expect(notFound(err)).To(BeTrue())
		})

		It("removes the CronJob when the project stops allowing overrides", func() {
			t := createReadyTarget("override-target")
			m := newMirror(teamA, "override-toggle")
			m.Spec.TargetRef = t.Name
			createMirror(m)
			Eventually(func() error { _, err := cronJob(m)(); return err }).Should(Succeed())

			Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(t), t); err != nil {
					return err
				}
				t.Spec.Projects[0].AllowRepositoryOverride = false
				return k8sClient.Update(ctx, t)
			})).To(Succeed())
			Eventually(mirrorReady(m)).Should(HaveField("Reason", ReasonRepositoryOverrideNotAllowed))
			_, err := cronJob(m)()
			Expect(notFound(err)).To(BeTrue())
		})
	})

	It("removes the CronJob and ConfigMap when the mirror is deleted", func() {
		m := newMirror(teamA, "delete")
		Expect(k8sClient.Create(ctx, m)).To(Succeed())
		Eventually(cronJob(m)).Should(Not(BeNil()))
		Eventually(func() error { _, err := cronJob(m)(); return err }).Should(Succeed())
		deleteAndWait(m)
		_, err := cronJob(m)()
		Expect(notFound(err)).To(BeTrue())
		Expect(notFound(k8sClient.Get(ctx, objectKey(m), &corev1.ConfigMap{}))).To(BeTrue())
	})

	It("stops mirroring when the target is no longer Ready", func() {
		createReadyTarget("fragile-target")
		m := newMirror(teamA, "fragile")
		m.Spec.TargetRef = "fragile-target"
		createMirror(m)
		Eventually(func() error { _, err := cronJob(m)(); return err }).Should(Succeed())

		Expect(k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: "fragile-target-push", Namespace: operatorNamespace,
		}})).To(Succeed())
		Eventually(mirrorReady(m)).Should(HaveField("Reason", ReasonTargetNotReady))
		_, err := cronJob(m)()
		Expect(notFound(err)).To(BeTrue())
	})
})

var _ = Describe("ArtifactMirror sync status", Ordered, func() {
	var m *mirrorv1alpha1.ArtifactMirror
	var jobs int
	start := time.Now().Add(-time.Hour).Truncate(time.Second)
	digest := "sha256:" + strings.Repeat("a", 64)

	BeforeAll(func() {
		m = newMirror(teamA, "status")
		createMirror(m)
		Eventually(mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
	})

	// finishJob creates a finished Job and its pod with the given sync
	// container result, the way the Job controller and kubelet would.
	finishJob := func(exitCode int32, message string, foreignPod ...bool) time.Time {
		jobs++
		at := start.Add(time.Duration(jobs) * time.Minute)
		labels, annotations := mirrorMeta(m)
		podSpec := corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{Name: syncContainer, Image: syncImage}}}
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%d", objectName(m), jobs), Namespace: operatorNamespace,
				Labels: labels, Annotations: annotations},
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec}},
		}
		Expect(k8sClient.Create(ctx, job)).To(Succeed())
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: job.Name + "-pod", Namespace: operatorNamespace,
				Labels: map[string]string{batchv1.JobNameLabel: job.Name}, Annotations: annotations,
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name,
					UID: job.UID, Controller: new(true)}}},
			Spec: podSpec,
		}
		if len(foreignPod) > 0 {
			pod.OwnerReferences = nil
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		pod.Status.Phase = corev1.PodFailed
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: syncContainer, Image: syncImage, ImageID: syncImage,
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				ExitCode: exitCode, Message: message, StartedAt: metav1.NewTime(at.Add(-time.Second)), FinishedAt: metav1.NewTime(at),
			}}}}
		if exitCode == 0 {
			pod.Status.Phase = corev1.PodSucceeded
		}
		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

		now := metav1.NewTime(at)
		job.Status.StartTime = &metav1.Time{Time: at.Add(-time.Second)}
		if exitCode == 0 {
			job.Status.Succeeded = 1
			job.Status.CompletionTime = &now
			job.Status.Conditions = []batchv1.JobCondition{
				{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue, LastTransitionTime: now},
				{Type: batchv1.JobComplete, Status: corev1.ConditionTrue, LastTransitionTime: now},
			}
		} else {
			job.Status.Failed = 1
			job.Status.Conditions = []batchv1.JobCondition{
				{Type: batchv1.JobFailureTarget, Status: corev1.ConditionTrue, LastTransitionTime: now, Reason: "BackoffLimitExceeded"},
				{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, LastTransitionTime: now, Reason: "BackoffLimitExceeded"},
			}
		}
		Expect(k8sClient.Status().Update(ctx, job)).To(Succeed())
		return at
	}

	status := func() mirrorv1alpha1.ArtifactMirrorStatus {
		var got mirrorv1alpha1.ArtifactMirror
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(m), &got)).To(Succeed())
		return got.Status
	}
	synced := func() *metav1.Condition { return meta.FindStatusCondition(status().Conditions, ConditionSynced) }

	It("records a successful sync", func() {
		at := finishJob(0, `{"v":1,"copied":1,"skipped":1,"synced":[{"tag":"`+v310+`","digest":"`+digest+`"},{"tag":"3.9","digest":"`+digest+`"}]}`)
		Eventually(synced).Should(And(HaveField("Status", metav1.ConditionTrue), HaveField("Reason", ReasonSynced),
			HaveField("Message", "copied 1, skipped 1, mutated 0, failed 0")))
		st := status()
		Expect(st.LastSyncTime.Time).To(BeTemporally("==", at))
		Expect(st.LastSuccessfulSyncTime.Time).To(BeTemporally("==", at))
		Expect(st.Synced).To(Equal([]mirrorv1alpha1.SyncedTag{{Tag: v310, Digest: digest}, {Tag: "3.9", Digest: digest}}))
		Expect(meta.IsStatusConditionTrue(st.Conditions, ConditionReady)).To(BeTrue())
		Expect(recorder.Events(teamA, m.Name)).To(ContainElement(HaveSuffix("Normal Synced copied 1, skipped 1, mutated 0, failed 0")))
	})

	It("reports a truncated synced list", func() {
		finishJob(0, `{"v":1,"skipped":1,"truncated":true,"synced":[{"tag":"`+v310+`","digest":"`+digest+`"}]}`)
		Eventually(synced).Should(And(HaveField("Status", metav1.ConditionTrue), HaveField("Reason", ReasonTruncated)))
	})

	DescribeTable("reports a failed sync and keeps the last success",
		func(exitCode int32, message, reason, text string) {
			success := status().LastSuccessfulSyncTime
			at := finishJob(exitCode, message)
			Eventually(synced).Should(And(HaveField("Status", metav1.ConditionFalse), HaveField("Reason", reason),
				HaveField("Message", ContainSubstring(text))))
			st := status()
			Expect(st.LastSyncTime.Time).To(BeTemporally("==", at))
			Expect(st.LastSuccessfulSyncTime).To(Equal(success))
			Expect(len(st.Synced)).To(BeNumerically("<=", maxSynced))
			Expect(recorder.Events(teamA, m.Name)).To(ContainElement(ContainSubstring("Warning " + reason)))
		},
		Entry("sync error", int32(1), `{"v":1,"failed":1,"errors":["`+v310+`: `+strings.Repeat("x", 300)+`"]}`,
			ReasonSyncFailed, "failed 1; 1 errors, first: "+v310+": xxx"),
		Entry("config error", int32(3), `{"v":1,"synced":[],"errors":["source: registry quay.io is not in allowedSources"]}`,
			ReasonConfigRejected, "not in allowedSources"),
		Entry("crash", int32(2), "", ReasonCrashed, "exited with code 2"),
		Entry("garbage message", int32(1), "panic: \x00\xff not json", ReasonCrashed, "exited with code 1: report: not valid JSON"),
		Entry("giant message", int32(0), `{"v":1,"errors":["`+strings.Repeat("x", 64*1024)+`"]}`, ReasonCrashed, "larger than 4096"),
		Entry("invalid synced entry", int32(0), `{"v":1,"synced":[{"tag":"`+v310+`","digest":"sha256:evil"}]}`, ReasonCrashed, "invalid synced entry"),
	)

	It("ignores a pod the Job does not control", func() {
		finishJob(0, `{"v":1,"copied":5}`, true)
		Eventually(synced).Should(And(HaveField("Reason", ReasonCrashed),
			HaveField("Message", ContainSubstring("no sync container result"))))
	})

	It("ignores an older Job finishing late", func() {
		before := status()
		jobs -= 10
		finishJob(0, `{"v":1}`)
		Consistently(status).Should(HaveField("LastSyncTime", before.LastSyncTime))
	})
})

var _ = Describe("naming", func() {
	DescribeTable("default target path",
		func(registry, repository, want string) {
			m := &mirrorv1alpha1.ArtifactMirror{Spec: mirrorv1alpha1.ArtifactMirrorSpec{
				Source: mirrorv1alpha1.Source{Registry: mirrorv1alpha1.RegistryHost(registry), Repository: repository},
			}}
			Expect(targetPath(m)).To(Equal(want))
		},
		Entry("plain", k8sHost, "pause", "registry.k8s.io/pause"),
		Entry("nested", "ghcr.io", "org/team/app", "ghcr.io/org/team/app"),
		Entry("docker hub official image", dockerHubHost, "nginx", "docker.io/library/nginx"),
		Entry("docker hub index alias", "index.docker.io", "nginx", "docker.io/library/nginx"),
		Entry("docker hub registry alias", "registry-1.docker.io", "library/nginx", "docker.io/library/nginx"),
		Entry("docker hub user image", "Docker.IO", "bitnami/redis", "docker.io/bitnami/redis"),
		Entry("port", "registry.example.com:5000", "app", "registry.example.com-5000/app"),
		Entry("IPv6", "[2001:db8::1]:5000", "app", "2001-db8--1-5000/app"),
	)

	It("uses the override as the target path", func() {
		m := validMirror("override")
		Expect(targetPath(m)).To(Equal("k8s/pause"))
	})

	It("hashes namespace and name into a short stable suffix", func() {
		Expect(mirrorHash("team-a", "pause")).To(HaveLen(20))
		Expect(mirrorHash("team-a", "pause")).To(Equal(mirrorHash("team-a", "pause")))
		Expect(mirrorHash("team-a", "pause")).NotTo(Equal(mirrorHash("team-a-pause", "")))
		Expect(mirrorHash("a", "b/c")).NotTo(Equal(mirrorHash("b", "c")))
		m := validMirror("pause")
		Expect(objectName(m)).To(MatchRegexp("^tagwarden-[0-9a-f]{20}$"))
	})
})
