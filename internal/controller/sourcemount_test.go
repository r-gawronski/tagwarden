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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

var _ = Describe("source Secrets in a sync CronJob", func() {
	const name = "tgt-src-mount"
	var secretVolumes = func(m *mirrorv1alpha1.ArtifactMirror) map[string]string {
		Eventually(func() error { _, err := cronJob(m)(); return err }).Should(Succeed())
		got, _ := cronJob(m)()
		out := map[string]string{}
		pod := got.Spec.JobTemplate.Spec.Template.Spec
		for _, v := range pod.Volumes {
			if v.Secret != nil {
				out[v.Name] = v.Secret.SecretName
			}
		}
		for _, c := range pod.Containers {
			for _, vm := range c.VolumeMounts {
				if vm.Name == "source-auth" {
					Expect(vm.MountPath).To(Equal("/var/run/tagwarden/source"))
					Expect(vm.ReadOnly).To(BeTrue())
				}
				if vm.Name == "source-ca" {
					Expect(vm.MountPath).To(Equal("/var/run/tagwarden/source-ca"))
					Expect(vm.ReadOnly).To(BeTrue())
				}
			}
		}
		return out
	}
	mirrorOf := func(ns, mname, registry, repo string) *mirrorv1alpha1.ArtifactMirror {
		m := newMirror(ns, mname)
		m.Spec.TargetRef = name
		m.Spec.Source = mirrorv1alpha1.Source{Registry: mirrorv1alpha1.RegistryHost(registry), Repository: repo}
		m.Spec.Target.Repository = "src/" + mname
		return m
	}

	BeforeEach(func() { createSourceSecrets(name) })

	It("mounts only the Secrets of its own source", func() {
		t := createReadyTarget(name, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			withSourceSecrets(t)
			t.Spec.AllowedSources = []mirrorv1alpha1.RegistryHost{ghcrRegistry, k8sHost, dockerHubHost}
		})
		DeferCleanup(k8sClient.Delete, ctx, t)

		ghcr := mirrorOf(teamA, "src-ghcr", "GHCR.io", "org/app")
		hub := mirrorOf(teamA, "src-hub", "index.docker.io", "nginx")
		other := mirrorOf(teamA, "src-other", k8sHost, "pause")
		for _, m := range []*mirrorv1alpha1.ArtifactMirror{ghcr, hub, other} {
			createMirror(m)
			Eventually(mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
		}

		Expect(secretVolumes(ghcr)).To(HaveKeyWithValue("source-auth", name+"-src-auth"))
		Expect(secretVolumes(ghcr)).To(HaveKeyWithValue("source-ca", name+"-src-ca"))
		Expect(secretVolumes(hub)).To(HaveKeyWithValue("source-auth", name+"-src-hub"))
		Expect(secretVolumes(hub)).NotTo(HaveKey("source-ca"))
		Expect(secretVolumes(other)).NotTo(HaveKey("source-auth"))
		Expect(secretVolumes(other)).NotTo(HaveKey("source-ca"))

		cj, _ := cronJob(ghcr)()
		v := cj.Spec.JobTemplate.Spec.Template.Spec.Volumes
		for _, vol := range v {
			if vol.Name == "source-auth" {
				Expect(vol.Secret.Items).To(Equal([]corev1.KeyToPath{{Key: corev1.DockerConfigJsonKey, Path: dockerCfgFile}}))
				Expect(*vol.Secret.DefaultMode).To(BeEquivalentTo(0o440))
			}
			if vol.Name == "source-ca" {
				Expect(vol.Secret.Items).To(Equal([]corev1.KeyToPath{{Key: caKey, Path: "ca.crt"}}))
			}
		}

		// Neither the spec ConfigMap nor the pod env carries a value.
		var cm corev1.ConfigMap
		Expect(k8sClient.Get(ctx, objectKey(ghcr), &cm)).To(Succeed())
		expectNoSecrets(cm.Data["spec.json"])
		for _, e := range cj.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Env {
			Expect(e.Value).NotTo(ContainSubstring(sourcePass))
		}
	})
})
