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
	"fmt"
	"math"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// leapDayHour runs one hour apart only from 23:00 on 29 February to
// midnight on 1 March, the next time in 2028.
const leapDayHour = "0 0,6,12,18,23 1,3,5,7,9,11,13,15,17,19,21,23,25,27,29 * *"

var _ = Describe("minGap", func() {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	DescribeTable("finds the shortest gap between runs",
		func(schedule string, want time.Duration) {
			Expect(minGap(schedule, from, 0)).To(Equal(want))
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
		Entry("one hour only from 29 February to 1 March", leapDayHour, time.Hour),
	)

	It("stops at the first gap below the limit", func() {
		Expect(minGap(leapDayHour, from, 6*time.Hour)).To(Equal(5 * time.Hour))
	})

	It("looks five years ahead", func() {
		Expect(minGap(leapDayHour, time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC), 0)).To(Equal(time.Hour))
		// 2100 is no leap year, so the next 29 February is in 2104.
		Expect(minGap(leapDayHour, time.Date(2096, 3, 1, 0, 0, 0, 0, time.UTC), 0)).To(Equal(5 * time.Hour))
	})

	It("refuses what the CronJob controller refuses", func() {
		_, err := minGap("61 * * * *", from, 0)
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
		}, ReasonScheduleTooFrequent, "runs 30m0s apart at least once, below minSyncInterval 1h0m0s"),
		Entry("schedule that runs twice within a minute of a day", func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Schedule = "0,1 3 * * *"
		}, ReasonScheduleTooFrequent, "runs 1m0s apart"),
		Entry("keepLatest above 20", func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Tags.KeepLatest = ptr.To[int32](21)
		}, ReasonLimitExceeded, "tags.keepLatest 21 exceeds maxKeepLatest 20"),
		Entry("more than 50 explicit tags", func(m *mirrorv1alpha1.ArtifactMirror) {
			m.Spec.Tags.Tags = nil
			for i := range 51 {
				m.Spec.Tags.Tags = append(m.Spec.Tags.Tags, fmt.Sprintf("1.%d", i))
			}
		}, ReasonLimitExceeded, "tags.tags has 51 entries, more than maxExplicitTags 50"),
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

	It("applies the tag limits set on the target", func() {
		t := limited("limits-tags", mirrorv1alpha1.TargetLimits{
			MaxKeepLatest:   ptr.To[int32](50),
			MaxExplicitTags: ptr.To[int32](1),
		})
		m := mirrorOf(t, teamA, "tag-limits")
		m.Spec.Tags.KeepLatest = ptr.To[int32](50)
		createMirror(m)
		expectReady(m)

		updateMirror(m, func(m *mirrorv1alpha1.ArtifactMirror) { m.Spec.Tags.Tags = []string{"1.0", v310} })
		expectRefused(m, ReasonLimitExceeded, "tags.tags has 2 entries, more than maxExplicitTags 1")
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

	It("lets the oldest mirrors of a namespace in and the rest wait", func() {
		t := limited("limits-count", mirrorv1alpha1.TargetLimits{MaxMirrorsPerNamespace: ptr.To[int32](2)})
		a, b, c := mirrorOf(t, teamA, "count-a"), mirrorOf(t, teamA, "count-b"), mirrorOf(t, teamA, "count-c")
		for _, m := range []*mirrorv1alpha1.ArtifactMirror{a, b, c} {
			// Separate paths, so only the namespace count links them.
			m.Spec.Target.Repository = "count/" + m.Name
			createMirror(m)
		}
		other := mirrorOf(t, teamB, "count-other")
		other.Spec.Target.Repository = "count/other"
		createMirror(other)

		expectReady(a)
		expectReady(b)
		expectRefused(c, ReasonLimitExceeded, "maxMirrorsPerNamespace 2 of ClusterMirrorTarget limits-count is used up by older ArtifactMirrors in namespace team-a")
		expectReady(other)

		deleteAndWait(a)
		expectReady(c)
		Expect(mirrorReady(b)()).To(HaveField("Status", metav1.ConditionTrue))

		// Moving to another target frees a place too.
		d := mirrorOf(t, teamA, "count-d")
		d.Spec.Target.Repository = "count/count-d"
		createMirror(d)
		expectRefused(d, ReasonLimitExceeded, "maxMirrorsPerNamespace")
		updateMirror(b, func(m *mirrorv1alpha1.ArtifactMirror) { m.Spec.TargetRef = mirrorTarget })
		expectReady(d)
	})

	It("does not let a mirror over the count limit claim a path", func() {
		t := limited("limits-claim", mirrorv1alpha1.TargetLimits{MaxMirrorsPerNamespace: ptr.To[int32](1)})
		first := mirrorOf(t, teamA, "claim-1")
		createMirror(first)
		expectReady(first)
		over := mirrorOf(t, teamA, "claim-2")
		over.Spec.Source.Registry = ghcrRegistry
		over.Spec.Target.Repository = "claimed/app"
		createMirror(over)
		expectRefused(over, ReasonLimitExceeded, "maxMirrorsPerNamespace 1 of")

		newer := mirrorOf(t, teamB, "claim-3")
		newer.Spec.Target.Repository = "claimed/app"
		createMirror(newer)
		expectReady(newer)
	})

	It("passes maxArtifactSize to the sync Job", func() {
		size := resource.MustParse("1Gi")
		t := limited("limits-size", mirrorv1alpha1.TargetLimits{MaxArtifactSize: &size})
		m := mirrorOf(t, teamA, "size")
		createMirror(m)
		expectReady(m)
		var cm corev1.ConfigMap
		Expect(k8sClient.Get(ctx, objectKey(m), &cm)).To(Succeed())
		spec, err := syncspec.Decode(bytes.NewReader([]byte(cm.Data[specKey])))
		Expect(err).NotTo(HaveOccurred())
		Expect(spec.MaxArtifactSize).To(BeEquivalentTo(1 << 30))
	})
})
