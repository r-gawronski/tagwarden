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
	"math"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

var _ = Describe("minGap", func() {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	DescribeTable("finds the shortest gap between runs",
		func(schedule string, want time.Duration) {
			Expect(minGap(schedule, from)).To(Equal(want))
		},
		Entry("every minute", "* * * * *", time.Minute),
		Entry("every 5 minutes", "*/5 * * * *", 5*time.Minute),
		Entry("hourly macro", "@hourly", time.Hour),
		Entry("daily macro", "@daily", 24*time.Hour),
		Entry("midnight macro", "@midnight", 24*time.Hour),
		Entry("weekly macro", "@weekly", 7*24*time.Hour),
		Entry("uneven minutes", "0,50 * * * *", 10*time.Minute),
		Entry("across midnight", "59 23 * * *", 24*time.Hour),
		Entry("two runs close together once a day", "0,10 3 * * *", 10*time.Minute),
		Entry("weekday steps", "*/15 1-5 ? * MON-FRI", 15*time.Minute),
		Entry("only on 1 January", "0,30 0 1 1 *", 30*time.Minute),
		Entry("never runs", "0 0 30 2 *", time.Duration(math.MaxInt64)),
	)

	It("refuses what the CronJob controller refuses", func() {
		_, err := minGap("61 * * * *", from)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("ClusterMirrorTarget limits", func() {
	limited := func(name string, l mirrorv1alpha1.TargetLimits) *mirrorv1alpha1.ClusterMirrorTarget {
		return createReadyTarget(name, func(t *mirrorv1alpha1.ClusterMirrorTarget) { t.Spec.Limits = &l })
	}
	mirrorOf := func(t *mirrorv1alpha1.ClusterMirrorTarget, namespace, name string) *mirrorv1alpha1.ArtifactMirror {
		m := newMirror(namespace, name)
		m.Spec.TargetRef = t.Name
		return m
	}
	expectRefused := func(m *mirrorv1alpha1.ArtifactMirror, reason, message string) {
		EventuallyWithOffset(1, mirrorReady(m)).Should(And(
			HaveField("Status", metav1.ConditionFalse), HaveField("Reason", reason),
			HaveField("Message", ContainSubstring(message))))
		_, err := cronJob(m)()
		ExpectWithOffset(1, notFound(err)).To(BeTrue())
		ExpectWithOffset(1, recorder.Events(m.Namespace, m.Name)).To(ContainElement(ContainSubstring("Warning " + reason)))
	}
	expectReady := func(m *mirrorv1alpha1.ArtifactMirror) {
		EventuallyWithOffset(1, mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
		EventuallyWithOffset(1, func() error { _, err := cronJob(m)(); return err }).Should(Succeed())
	}

	DescribeTable("refuses a mirror over the default limits",
		func(mutate func(*mirrorv1alpha1.ArtifactMirror), reason, message string) {
			m := newMirror(teamA, "over-default")
			mutate(m)
			createMirror(m)
			expectRefused(m, reason, message)
		},
		Entry("schedule more often than hourly", func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Schedule = "*/30 * * * *"
		}, ReasonScheduleTooFrequent, "runs every 30m0s at its most frequent, below minSyncInterval 1h0m0s"),
		Entry("schedule that runs twice within a minute of a day", func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Schedule = "0,1 3 * * *"
		}, ReasonScheduleTooFrequent, "runs every 1m0s"),
		Entry("schedule that the CronJob controller cannot parse", func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Schedule = "61 * * * *"
		}, ReasonInvalidSpec, "schedule"),
	)

	It("applies the limits set on the target", func() {
		t := limited("limits-explicit", mirrorv1alpha1.TargetLimits{
			MinSyncInterval: &metav1.Duration{Duration: 5 * time.Minute},
		})
		m := mirrorOf(t, teamA, "explicit-ok")
		m.Spec.Schedule = "*/5 * * * *"
		createMirror(m)
		expectReady(m)

		updateMirror(m, func(m *mirrorv1alpha1.ArtifactMirror) { m.Spec.Schedule = "*/4 * * * *" })
		expectRefused(m, ReasonScheduleTooFrequent, "below minSyncInterval 5m0s")
	})

	It("removes the CronJob when the target tightens a limit", func() {
		t := limited("limits-tighten", mirrorv1alpha1.TargetLimits{})
		m := mirrorOf(t, teamA, "tighten")
		createMirror(m)
		expectReady(m)

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(t), t)).To(Succeed())
		t.Spec.Limits = &mirrorv1alpha1.TargetLimits{MinSyncInterval: &metav1.Duration{Duration: 48 * time.Hour}}
		Expect(k8sClient.Update(ctx, t)).To(Succeed())
		expectRefused(m, ReasonScheduleTooFrequent, "below minSyncInterval 48h0m0s")
	})
})
