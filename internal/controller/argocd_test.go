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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const (
	trackingID  = "argocd.argoproj.io/tracking-id"
	instanceKey = "app.kubernetes.io/instance"
	ignoreExtra = "IgnoreExtraneous"
	noPrune     = "Prune=false,Delete=false"
	webApp      = "apps-web"
)

func TestArgoTracking(t *testing.T) {
	m := newMirror(teamA, "unit")
	own := "apps-web:mirror.tagwarden.dev/ArtifactMirror:team-a/unit"
	with := func(annotations, labels map[string]string) *mirrorv1alpha1.ArtifactMirror {
		c := m.DeepCopy()
		c.Annotations, c.Labels = annotations, labels
		return c
	}
	cjID := "apps-web:batch/CronJob:tagwarden-system/cj"
	for _, tc := range []struct {
		name     string
		mode     string
		mirror   *mirrorv1alpha1.ArtifactMirror
		wantID   string
		wantLbl  string
		mismatch string
	}{
		{name: "annotation", mode: ArgoCDTrackingInherit, mirror: with(map[string]string{trackingID: own}, nil), wantID: cjID},
		{name: "label", mode: ArgoCDTrackingInherit, mirror: with(nil, map[string]string{instanceKey: webApp}), wantLbl: webApp},
		{name: "annotation wins over label", mode: ArgoCDTrackingInherit,
			mirror: with(map[string]string{trackingID: own}, map[string]string{instanceKey: "stale-app"}), wantID: cjID},
		{name: "app with colon", mode: ArgoCDTrackingInherit,
			mirror: with(map[string]string{trackingID: "ns_app:mirror.tagwarden.dev/ArtifactMirror:team-a/unit"}, nil),
			wantID: "ns_app:batch/CronJob:tagwarden-system/cj"},
		{name: "other name", mode: ArgoCDTrackingInherit, mismatch: "apps-web:mirror.tagwarden.dev/ArtifactMirror:team-a/other",
			mirror: with(map[string]string{trackingID: "apps-web:mirror.tagwarden.dev/ArtifactMirror:team-a/other"}, map[string]string{instanceKey: "x"})},
		{name: "other namespace", mode: ArgoCDTrackingInherit, mismatch: "a:mirror.tagwarden.dev/ArtifactMirror:team-b/unit",
			mirror: with(map[string]string{trackingID: "a:mirror.tagwarden.dev/ArtifactMirror:team-b/unit"}, nil)},
		{name: "other kind", mode: ArgoCDTrackingInherit, mismatch: "a:apps/Deployment:team-a/unit",
			mirror: with(map[string]string{trackingID: "a:apps/Deployment:team-a/unit"}, nil)},
		{name: "other group", mode: ArgoCDTrackingInherit, mismatch: "a:example.com/ArtifactMirror:team-a/unit",
			mirror: with(map[string]string{trackingID: "a:example.com/ArtifactMirror:team-a/unit"}, nil)},
		{name: "garbage", mode: ArgoCDTrackingInherit, mismatch: "nonsense",
			mirror: with(map[string]string{trackingID: "nonsense"}, nil)},
		{name: "no tracking", mode: ArgoCDTrackingInherit, mirror: with(nil, nil)},
		{name: "flag off annotation", mode: "", mirror: with(map[string]string{trackingID: own}, nil)},
		{name: "flag off label", mode: "", mirror: with(nil, map[string]string{instanceKey: webApp})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			labels, annotations, mismatch := argoTracking(tc.mode, instanceKey, tc.mirror, "tagwarden-system", "cj")
			if mismatch != tc.mismatch {
				t.Errorf("mismatch = %q, want %q", mismatch, tc.mismatch)
			}
			if tc.wantID == "" && tc.wantLbl == "" {
				if len(labels) != 0 || len(annotations) != 0 {
					t.Errorf("got %v %v, want nothing", labels, annotations)
				}
				return
			}
			if annotations[trackingID] != tc.wantID || labels[instanceKey] != tc.wantLbl {
				t.Errorf("tracking id %q label %q, want %q %q", annotations[trackingID], labels[instanceKey], tc.wantID, tc.wantLbl)
			}
			if annotations["argocd.argoproj.io/compare-options"] != ignoreExtra ||
				annotations["argocd.argoproj.io/sync-options"] != noPrune {
				t.Errorf("options = %v", annotations)
			}
		})
	}
}

var _ = Describe("Argo CD tracking", func() {
	cjMeta := func(m *mirrorv1alpha1.ArtifactMirror) func() (*batchv1.CronJob, error) { return cronJob(m) }
	trackedMirror := func(name string, annotations, labels map[string]string) *mirrorv1alpha1.ArtifactMirror {
		m := newMirror(teamA, name)
		m.Annotations, m.Labels = annotations, labels
		return m
	}

	It("tracks the CronJob in the app of the mirror (annotation mode)", func() {
		m := trackedMirror("track-anno", map[string]string{trackingID: "apps-web:mirror.tagwarden.dev/ArtifactMirror:team-a/track-anno"}, nil)
		createMirror(m)
		Eventually(func(g Gomega) {
			cj, err := cjMeta(m)()
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cj.Annotations).To(HaveKeyWithValue(trackingID,
				"apps-web:batch/CronJob:"+operatorNamespace+"/"+objectName(m)))
			g.Expect(cj.Annotations).To(HaveKeyWithValue("argocd.argoproj.io/compare-options", ignoreExtra))
			g.Expect(cj.Annotations).To(HaveKeyWithValue("argocd.argoproj.io/sync-options", noPrune))
			g.Expect(cj.Spec.JobTemplate.Annotations).NotTo(HaveKey(trackingID))
			g.Expect(cj.Spec.JobTemplate.Spec.Template.Annotations).NotTo(HaveKey(trackingID))
		}).Should(Succeed())
	})

	It("copies the instance label (label mode)", func() {
		m := trackedMirror("track-label", nil, map[string]string{instanceKey: webApp})
		createMirror(m)
		Eventually(func(g Gomega) {
			cj, err := cjMeta(m)()
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cj.Labels).To(HaveKeyWithValue(instanceKey, webApp))
			g.Expect(cj.Annotations).NotTo(HaveKey(trackingID))
			g.Expect(cj.Annotations).To(HaveKeyWithValue("argocd.argoproj.io/compare-options", ignoreExtra))
			g.Expect(cj.Annotations).To(HaveKeyWithValue("argocd.argoproj.io/sync-options", noPrune))
		}).Should(Succeed())
	})

	It("sets nothing and warns once when the id names another object", func() {
		m := trackedMirror("track-other", map[string]string{trackingID: "apps-web:mirror.tagwarden.dev/ArtifactMirror:team-a/else"},
			map[string]string{instanceKey: webApp})
		createMirror(m)
		Eventually(mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
		Eventually(func() []string { return recorder.Events(teamA, m.Name) }).Should(ContainElement(
			ContainSubstring("Warning ArgoCDTrackingMismatch")))
		cj, err := cjMeta(m)()
		Expect(err).NotTo(HaveOccurred())
		Expect(cj.Annotations).NotTo(HaveKey(trackingID))
		Expect(cj.Annotations).NotTo(HaveKey("argocd.argoproj.io/sync-options"))
		Expect(cj.Labels).NotTo(HaveKey(instanceKey))

		// A reconcile without a state change adds no second Event.
		updateMirror(m, func(m *mirrorv1alpha1.ArtifactMirror) { m.Labels["example.com/touch"] = "1" })
		Consistently(func() int {
			n := 0
			for _, e := range recorder.Events(teamA, m.Name) {
				if containsReason(e, "ArgoCDTrackingMismatch") {
					n++
				}
			}
			return n
		}, "2s").Should(Equal(1))
	})

	It("removes the metadata when the mirror loses its tracking", func() {
		m := trackedMirror("track-lose", map[string]string{trackingID: "apps-web:mirror.tagwarden.dev/ArtifactMirror:team-a/track-lose"}, nil)
		createMirror(m)
		Eventually(func(g Gomega) {
			cj, err := cjMeta(m)()
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cj.Annotations).To(HaveKey(trackingID))
		}).Should(Succeed())
		updateMirror(m, func(m *mirrorv1alpha1.ArtifactMirror) { delete(m.Annotations, trackingID) })
		Eventually(func(g Gomega) {
			cj, err := cjMeta(m)()
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cj.Annotations).NotTo(HaveKey(trackingID))
			g.Expect(cj.Annotations).NotTo(HaveKey("argocd.argoproj.io/compare-options"))
			g.Expect(cj.Annotations).NotTo(HaveKey("argocd.argoproj.io/sync-options"))
		}).Should(Succeed())
	})

	It("restores a hand-edited tracking annotation", func() {
		m := trackedMirror("track-edit", map[string]string{trackingID: "apps-web:mirror.tagwarden.dev/ArtifactMirror:team-a/track-edit"}, nil)
		createMirror(m)
		want := "apps-web:batch/CronJob:" + operatorNamespace + "/" + objectName(m)
		Eventually(func() map[string]string { cj, _ := cjMeta(m)(); return cj.Annotations }).Should(HaveKeyWithValue(trackingID, want))
		cj, _ := cjMeta(m)()
		cj.Annotations[trackingID] = "evil:batch/CronJob:x/y"
		cj.Annotations["argocd.argoproj.io/sync-options"] = "Prune=true"
		Expect(k8sClient.Update(ctx, cj)).To(Succeed())
		Eventually(func(g Gomega) {
			got, _ := cjMeta(m)()
			g.Expect(got.Annotations).To(HaveKeyWithValue(trackingID, want))
			g.Expect(got.Annotations).To(HaveKeyWithValue("argocd.argoproj.io/sync-options", noPrune))
		}).Should(Succeed())
	})

	It("does not update a tracked CronJob that did not change", func() {
		m := trackedMirror("track-steady", nil, map[string]string{instanceKey: webApp})
		createMirror(m)
		Eventually(func() map[string]string { cj, _ := cjMeta(m)(); return cj.GetLabels() }).Should(HaveKey(instanceKey))
		cj, _ := cjMeta(m)()
		updates := writes.Load()
		updateMirror(m, func(m *mirrorv1alpha1.ArtifactMirror) { m.Labels["example.com/touch"] = "1" })
		Consistently(func() string { got, _ := cjMeta(m)(); return got.ResourceVersion }, "2s").Should(Equal(cj.ResourceVersion))
		Expect(writes.Load()).To(Equal(updates), "CronJob or ConfigMap update calls")
	})
})

func containsReason(event, reason string) bool { return strings.Contains(event, " "+reason+" ") }
