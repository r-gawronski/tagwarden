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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dto "github.com/prometheus/client_model/go"
	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

func TestScannerStartFailure(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	grace := 5 * time.Minute
	old := metav1.NewTime(now.Add(-10 * time.Minute))
	young := metav1.NewTime(now.Add(-time.Minute))
	waiting := func(reason string) corev1.ContainerStatus {
		return corev1.ContainerStatus{Name: scannerContainer, State: corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: "registry.example.com secret text"}}}
	}
	pod := func(created metav1.Time, phase corev1.PodPhase, init ...corev1.ContainerStatus) *corev1.Pod {
		p := &corev1.Pod{}
		p.CreationTimestamp, p.Status.Phase, p.Status.InitContainerStatuses = created, phase, init
		return p
	}
	for _, c := range []struct {
		name string
		pod  *corev1.Pod
		want string
	}{
		{"pull error", pod(old, corev1.PodPending, waiting("ErrImagePull")), "ErrImagePull"},
		{"pull backoff", pod(old, corev1.PodPending, waiting("ImagePullBackOff")), "ImagePullBackOff"},
		{"invalid image", pod(old, corev1.PodPending, waiting("InvalidImageName")), "InvalidImageName"},
		{"bad config", pod(old, corev1.PodPending, waiting("CreateContainerConfigError")), "CreateContainerConfigError"},
		{"crash loop", pod(old, corev1.PodPending, waiting("CrashLoopBackOff")), "CrashLoopBackOff"},
		{"within the grace period", pod(young, corev1.PodPending, waiting("ErrImagePull")), ""},
		{"still pulling", pod(old, corev1.PodPending, waiting("PodInitializing")), ""},
		{"unknown reason", pod(old, corev1.PodPending, waiting("Whatever")), ""},
		{"sync is running", pod(old, corev1.PodRunning, waiting("CrashLoopBackOff")), ""},
		{"other init container", pod(old, corev1.PodPending, corev1.ContainerStatus{Name: "extra", State: waiting("ErrImagePull").State}), ""},
		{"running sidecar", pod(old, corev1.PodPending, corev1.ContainerStatus{Name: scannerContainer,
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}), ""},
		{"no status yet", pod(old, corev1.PodPending), ""},
	} {
		if got := scannerStartFailure(c.pod, now, grace); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

var _ = Describe("scanner sidecar that does not start", Ordered, func() {
	const (
		target  = "gate-nostart"
		ns      = "gate-nostart-ns"
		image   = ghcrRegistry + "/org/nostart"
		kubelet = "Back-off pulling image registry.example.com/secret/path: pull access denied"
	)
	var gen *mirrorv1alpha1.ArtifactMirror
	var appPod *corev1.Pod

	// stuckJob creates an unfinished Job of gen with a Pending pod whose
	// sidecar waits with reason, and a sync container that has not started.
	stuckJob := func(name, reason string, syncRunning bool) *batchv1.Job {
		labels, annotations := mirrorMeta(gen)
		podSpec := corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever,
			InitContainers: []corev1.Container{{Name: scannerContainer, Image: syncImage, RestartPolicy: new(corev1.ContainerRestartPolicyAlways)}},
			Containers:     []corev1.Container{{Name: syncContainer, Image: syncImage}}}
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: operatorNamespace, Labels: labels, Annotations: annotations},
			Spec:       batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec}},
		}
		Expect(k8sClient.Create(ctx, job)).To(Succeed())
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name + "-pod", Namespace: operatorNamespace,
				Labels: map[string]string{batchv1.JobNameLabel: name}, Annotations: annotations,
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: name, UID: job.UID, Controller: new(true)}}},
			Spec: podSpec,
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		pod.Status.Phase = corev1.PodPending
		pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: scannerContainer, Image: syncImage, ImageID: syncImage,
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: kubelet}}}}
		if syncRunning {
			pod.Status.Phase = corev1.PodRunning
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: syncContainer, Image: syncImage, ImageID: syncImage,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}
		}
		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
		return job
	}
	jobGone := func(name string) func() bool {
		return func() bool {
			var j batchv1.Job
			return notFound(k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: name}, &j))
		}
	}

	BeforeAll(func() {
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		createReadyTarget(target, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.AllowedSources = []mirrorv1alpha1.RegistryHost{ghcrRegistry}
			t.Spec.Projects = []mirrorv1alpha1.TargetProject{{Name: otherProject, NamespaceSelector: &metav1.LabelSelector{}}}
			t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: otherProject,
				VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{Enabled: true, Scanner: &mirrorv1alpha1.ScannerSpec{URL: inChartURL}}}
		})
		appPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: ns, Annotations: map[string]string{mirrorv1alpha1.AutoMirrorAnnotation: target}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image + ":1.0"}}},
		}
		Expect(k8sClient.Create(ctx, appPod)).To(Succeed())
		gen = &mirrorv1alpha1.ArtifactMirror{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: generatedNameOf(image)}}
		DeferCleanup(func() {
			Expect(k8sClient.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace(ns), client.GracePeriodSeconds(0))).To(Succeed())
			time.Sleep(500 * time.Millisecond)
			deleteAndWait(gen)
			deleteAndWait(&mirrorv1alpha1.ClusterMirrorTarget{ObjectMeta: metav1.ObjectMeta{Name: target}})
		})
		Eventually(mirrorReady(gen)).Should(HaveField("Status", metav1.ConditionTrue))
	})

	It("leaves a Job alone whose sync container is running", func() {
		stuckJob("nostart-running", "CrashLoopBackOff", true)
		Consistently(jobGone("nostart-running"), 5*time.Second).Should(BeFalse())
		Expect(k8sClient.DeleteAllOf(ctx, &batchv1.Job{}, client.InNamespace(operatorNamespace),
			client.MatchingLabels(map[string]string{LabelMirror: mirrorHash(gen.Namespace, gen.Name)}),
			client.PropagationPolicy(metav1.DeletePropagationBackground))).To(Succeed())
	})

	It("deletes the Job and says so everywhere", func() {
		before := startFailures(target, "ErrImagePull")
		stuckJob("nostart-pull", "ErrImagePull", false)
		Eventually(jobGone("nostart-pull")).Should(BeTrue())

		want := "scanner sidecar did not start (ErrImagePull); sync Job deleted, nothing copied"
		Eventually(func() *metav1.Condition {
			var m mirrorv1alpha1.ArtifactMirror
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gen), &m)).To(Succeed())
			return meta.FindStatusCondition(m.Status.Conditions, ConditionVulnerabilityGate)
		}).Should(And(HaveField("Status", metav1.ConditionFalse), HaveField("Reason", ReasonScannerUnavailable), HaveField("Message", want)))

		events := func(ns, name string) string { return strings.Join(recorder.Events(ns, name), "\n") }
		Eventually(func() string { return events(ns, gen.Name) }).Should(ContainSubstring("Warning " + ReasonScannerUnavailable + " " + want))
		Eventually(func() string { return events("", target) }).Should(ContainSubstring("Warning " + ReasonScannerUnavailable + " " + want))
		Eventually(func() string { return events(ns, appPod.Name) }).Should(And(
			ContainSubstring("Warning "+reasonVulnerabilityScanFail+" "+ReasonScannerUnavailable+": "+want), ContainSubstring("nothing copied")))
		Expect(startFailures(target, "ErrImagePull")).To(Equal(before + 1))
		for _, s := range []string{events(ns, gen.Name), events("", target), events(ns, appPod.Name)} {
			Expect(s).NotTo(ContainSubstring("secret/path"))
		}

		By("recording each Event once")
		Consistently(func() int {
			return strings.Count(events(ns, gen.Name), "Warning "+ReasonScannerUnavailable+" "+want)
		}, 2*time.Second).Should(Equal(1))
	})

	It("relays as MirrorRefused under Block", func() {
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var t mirrorv1alpha1.ClusterMirrorTarget
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: target}, &t); err != nil {
				return err
			}
			t.Spec.AutoMirror.VulnerabilityGate.OnScanError = mirrorv1alpha1.GateActionBlock
			return k8sClient.Update(ctx, &t)
		})).To(Succeed())
		stuckJob("nostart-crash", "CrashLoopBackOff", false)
		Eventually(jobGone("nostart-crash")).Should(BeTrue())
		Eventually(func() string { return strings.Join(recorder.Events(ns, appPod.Name), "\n") }).Should(
			ContainSubstring("Warning " + reasonMirrorRefused + " " + ReasonScannerUnavailable + ": scanner sidecar did not start (CrashLoopBackOff)"))
	})
})

// startFailures returns the scanner start failure counter of a target and reason.
func startFailures(target, reason string) float64 {
	var pb dto.Metric
	Expect(scannerStartFailures.WithLabelValues(target, reason).Write(&pb)).To(Succeed())
	return pb.GetCounter().GetValue()
}
