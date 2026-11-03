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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

var _ = Describe("sync-now", Ordered, func() {
	const syncNowTarget = "sync-now-target"
	interval := 5 * time.Minute

	BeforeAll(func() {
		createReadyTarget(syncNowTarget, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.Limits = &mirrorv1alpha1.TargetLimits{MinSyncInterval: &metav1.Duration{Duration: interval}}
		})
	})

	readyMirror := func(name string) *mirrorv1alpha1.ArtifactMirror {
		m := newMirror(teamA, name)
		m.Spec.TargetRef = syncNowTarget
		createMirror(m)
		EventuallyWithOffset(1, func() error { _, err := cronJob(m)(); return err }).Should(Succeed())
		return m
	}
	request := func(m *mirrorv1alpha1.ArtifactMirror, value string) {
		updateMirror(m, func(m *mirrorv1alpha1.ArtifactMirror) {
			if m.Annotations == nil {
				m.Annotations = map[string]string{}
			}
			m.Annotations[mirrorv1alpha1.SyncNowAnnotation] = value
		})
	}
	status := func(m *mirrorv1alpha1.ArtifactMirror) func() mirrorv1alpha1.ArtifactMirrorStatus {
		return func() mirrorv1alpha1.ArtifactMirrorStatus {
			var got mirrorv1alpha1.ArtifactMirror
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(m), &got)).To(Succeed())
			return got.Status
		}
	}
	lastRequest := func(m *mirrorv1alpha1.ArtifactMirror) func() *mirrorv1alpha1.SyncRequest {
		return func() *mirrorv1alpha1.SyncRequest { return status(m)().LastSyncRequest }
	}
	manualJobs := func(m *mirrorv1alpha1.ArtifactMirror) func() []batchv1.Job {
		return func() []batchv1.Job {
			var jobs batchv1.JobList
			Expect(k8sClient.List(ctx, &jobs, client.InNamespace(operatorNamespace),
				client.MatchingLabels{LabelMirror: mirrorHash(m.Namespace, m.Name)})).To(Succeed())
			var out []batchv1.Job
			for _, j := range jobs.Items {
				if j.Annotations[AnnotationTrigger] == TriggerManual {
					out = append(out, j)
				}
			}
			return out
		}
	}
	countEvents := func(m *mirrorv1alpha1.ArtifactMirror, reason string) int {
		n := 0
		for _, e := range recorder.Events(m.Namespace, m.Name) {
			if strings.Contains(e, " "+reason+" ") {
				n++
			}
		}
		return n
	}
	// startJob creates a running sync Job of m that started at start, the
	// way the CronJob and Job controllers would.
	startJob := func(m *mirrorv1alpha1.ArtifactMirror, start time.Time) *batchv1.Job {
		labels, annotations := mirrorMeta(m)
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: objectName(m) + "-1", Namespace: operatorNamespace,
				Labels: labels, Annotations: annotations},
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever,
				Containers: []corev1.Container{{Name: syncContainer, Image: syncImage}}}}},
		}
		Expect(k8sClient.Create(ctx, job)).To(Succeed())
		job.Status.StartTime = &metav1.Time{Time: start}
		Expect(k8sClient.Status().Update(ctx, job)).To(Succeed())
		return job
	}
	completeJob := func(job *batchv1.Job) {
		now := metav1.Now()
		if job.Status.StartTime == nil {
			job.Status.StartTime = &now
		}
		job.Status.Succeeded = 1
		job.Status.CompletionTime = &now
		job.Status.Conditions = []batchv1.JobCondition{
			{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue, LastTransitionTime: now},
			{Type: batchv1.JobComplete, Status: corev1.ConditionTrue, LastTransitionTime: now},
		}
		Expect(k8sClient.Status().Update(ctx, job)).To(Succeed())
	}

	It("starts one Job from the CronJob template per request value", func() {
		m := readyMirror("sync-now")
		cj, err := cronJob(m)()
		Expect(err).NotTo(HaveOccurred())
		request(m, "2026-11-03T10:00:00Z")

		Eventually(lastRequest(m)).Should(And(Not(BeNil()),
			HaveField("Value", "2026-11-03T10:00:00Z"), HaveField("Result", mirrorv1alpha1.SyncRequestStarted)))
		jobs := manualJobs(m)()
		Expect(jobs).To(HaveLen(1))
		job := jobs[0]
		Expect(job.Name).To(Equal(manualJobName(m, "2026-11-03T10:00:00Z")))
		tmpl := cj.Spec.JobTemplate
		for k, v := range tmpl.Labels {
			Expect(job.Labels).To(HaveKeyWithValue(k, v))
		}
		for k, v := range tmpl.Spec.Template.Labels {
			Expect(job.Spec.Template.Labels).To(HaveKeyWithValue(k, v))
		}
		for k, v := range tmpl.Annotations {
			Expect(job.Annotations).To(HaveKeyWithValue(k, v))
		}
		Expect(job.Annotations).To(HaveKeyWithValue(AnnotationTrigger, TriggerManual))
		Expect(job.Spec.Template.Annotations).To(Equal(tmpl.Spec.Template.Annotations))
		Expect(job.Spec.Template.Spec).To(Equal(tmpl.Spec.Template.Spec))
		Expect(job.Spec.BackoffLimit).To(Equal(tmpl.Spec.BackoffLimit))
		Expect(job.Spec.ActiveDeadlineSeconds).To(Equal(tmpl.Spec.ActiveDeadlineSeconds))
		Expect(job.Spec.TTLSecondsAfterFinished).To(Equal(tmpl.Spec.TTLSecondsAfterFinished))
		Expect(job.Spec.PodFailurePolicy).To(Equal(tmpl.Spec.PodFailurePolicy))
		// Like kubectl create job --from=cronjob: the CronJob controls it.
		Expect(job.OwnerReferences).To(ConsistOf(And(HaveField("APIVersion", "batch/v1"), HaveField("Kind", "CronJob"),
			HaveField("Name", cj.Name), HaveField("UID", cj.UID),
			HaveField("Controller", HaveValue(BeTrue())), HaveField("BlockOwnerDeletion", HaveValue(BeTrue())))))
		Expect(status(m)().LastSyncStartTime).NotTo(BeNil())
		Expect(recorder.Events(teamA, m.Name)).To(ContainElement(ContainSubstring("Normal SyncRequested Created Job " +
			operatorNamespace + "/" + job.Name)))

		By("ignoring the same value")
		updateMirror(m, func(m *mirrorv1alpha1.ArtifactMirror) { m.Labels = map[string]string{"touched": "true"} })
		Consistently(manualJobs(m), 2*time.Second).Should(HaveLen(1))
		Expect(countEvents(m, "SyncRequested")).To(Equal(1))
	})

	It("defers a request while a Job runs and starts it when the Job finishes", func() {
		m := readyMirror("sync-busy")
		running := startJob(m, time.Now().Add(-2*interval))
		request(m, "busy")

		Eventually(lastRequest(m)).Should(And(Not(BeNil()), HaveField("Result", mirrorv1alpha1.SyncRequestDeferred),
			HaveField("Message", "Job "+operatorNamespace+"/"+running.Name+" is running")))
		Expect(recorder.Events(teamA, m.Name)).To(ContainElement(ContainSubstring("Normal SyncDeferred Job")))
		Consistently(manualJobs(m), time.Second).Should(BeEmpty())

		completeJob(running)
		Eventually(lastRequest(m)).Should(HaveField("Result", mirrorv1alpha1.SyncRequestStarted))
		Expect(manualJobs(m)()).To(HaveLen(1))
	})

	It("defers a request until minSyncInterval has passed since the last start", func() {
		m := readyMirror("sync-interval")
		start := time.Now().Add(-interval + 4*time.Second).Truncate(time.Second)
		completeJob(startJob(m, start))
		request(m, "soon")

		next := start.Add(interval).UTC().Format(time.RFC3339)
		Eventually(lastRequest(m)).Should(And(Not(BeNil()), HaveField("Result", mirrorv1alpha1.SyncRequestDeferred),
			HaveField("Message", "minSyncInterval 5m0s of ClusterMirrorTarget "+syncNowTarget+" allows the next sync at "+next)))
		Expect(status(m)().LastSyncStartTime.Time).To(BeTemporally("==", start))
		Expect(manualJobs(m)()).To(BeEmpty())
		Expect(recorder.Events(teamA, m.Name)).To(ContainElement(ContainSubstring("Normal SyncDeferred minSyncInterval")))

		// RequeueAfter starts it without another change to the mirror.
		Eventually(lastRequest(m), 15*time.Second).Should(HaveField("Result", mirrorv1alpha1.SyncRequestStarted))
		Expect(manualJobs(m)()).To(HaveLen(1))
		Expect(countEvents(m, "SyncDeferred")).To(Equal(1))
	})

	It("counts a Job that the status does not know about yet", func() {
		m := readyMirror("sync-unknown-job")
		// A Job of an earlier request whose status update was lost, not
		// started yet.
		labels, annotations := mirrorMeta(m)
		annotations[AnnotationTrigger] = TriggerManual
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: manualJobName(m, "earlier"), Namespace: operatorNamespace,
				Labels: labels, Annotations: annotations},
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever,
				Containers: []corev1.Container{{Name: syncContainer, Image: syncImage}}}}},
		}
		Expect(k8sClient.Create(ctx, job)).To(Succeed())
		request(m, "later")

		Eventually(lastRequest(m)).Should(And(Not(BeNil()), HaveField("Value", "later"),
			HaveField("Result", mirrorv1alpha1.SyncRequestDeferred), HaveField("Message", ContainSubstring("is running"))))
		Expect(status(m)().LastSyncStartTime).To(BeNil())

		completeJob(job)
		Eventually(lastRequest(m)).Should(HaveField("Message", ContainSubstring("minSyncInterval 5m0s")))
		Expect(manualJobs(m)()).To(HaveLen(1))
	})

	It("refuses a value whose Job already finished", func() {
		m := readyMirror("sync-reuse")
		request(m, "first")
		Eventually(lastRequest(m)).Should(And(Not(BeNil()), HaveField("Value", "first"),
			HaveField("Result", mirrorv1alpha1.SyncRequestStarted)))
		first := manualJobs(m)()
		Expect(first).To(HaveLen(1))
		completeJob(&first[0])

		request(m, "second")
		Eventually(lastRequest(m)).Should(And(HaveField("Value", "second"), HaveField("Result", mirrorv1alpha1.SyncRequestDeferred)))
		request(m, "first")
		msg := "value already used by Job " + operatorNamespace + "/" + first[0].Name + "; set a new value"
		Eventually(lastRequest(m)).Should(And(HaveField("Value", "first"),
			HaveField("Result", mirrorv1alpha1.SyncRequestRefused), HaveField("Message", msg)))
		Expect(recorder.Events(teamA, m.Name)).To(ContainElement(ContainSubstring("Warning SyncRefused " + msg)))
		Expect(manualJobs(m)()).To(HaveLen(1))
	})

	DescribeTable("refuses a request",
		func(mutate func(*mirrorv1alpha1.ArtifactMirror), message string) {
			m := newMirror(teamA, "sync-refused")
			m.Spec.TargetRef = syncNowTarget
			mutate(m)
			createMirror(m)
			Eventually(mirrorReady(m)).ShouldNot(BeNil())
			request(m, "refused")

			Eventually(lastRequest(m)).Should(And(Not(BeNil()), HaveField("Value", "refused"),
				HaveField("Result", mirrorv1alpha1.SyncRequestRefused), HaveField("Message", ContainSubstring(message))))
			Expect(recorder.Events(teamA, m.Name)).To(ContainElement(ContainSubstring("Warning SyncRefused " + message)))
			Consistently(manualJobs(m), time.Second).Should(BeEmpty())
		},
		Entry("when the mirror is not Ready", func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Source.Registry = "quay.io"
		}, "ArtifactMirror is not Ready: SourceNotAllowed"),
		Entry("when the mirror is suspended", func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Suspend = true
		}, "ArtifactMirror is suspended"),
	)

	It("names the Job of a request deterministically", func() {
		m := newMirror(teamA, strings.Repeat("n", 253))
		a := manualJobName(m, "a")
		Expect(a).To(Equal(manualJobName(m, "a")))
		Expect(a).NotTo(Equal(manualJobName(m, "b")))
		Expect(a).To(MatchRegexp(`-[0-9a-f]{8}-manual-[0-9a-f]{10}$`))
		Expect(len(manualJobName(m, strings.Repeat("x", 4096)))).To(BeNumerically("<=", 63))
	})
})
