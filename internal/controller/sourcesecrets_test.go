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
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const (
	dockerHubHost = "docker.io"
	k8sHost       = "registry.k8s.io"
	passwordKey   = "password"
	usernameKey   = "username"
	dockerCfgFile = ".dockerconfigjson"
)

// sourceSecrets returns a credentials Secret for ghcr.io, one for Docker
// Hub and a source CA Secret, named prefix-src-{auth,hub,ca}.
func sourceSecrets(prefix string) []*corev1.Secret {
	om := func(n string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: prefix + "-src-" + n, Namespace: operatorNamespace}
	}
	cfg := func(host string) map[string][]byte {
		b, _ := json.Marshal(map[string]any{"auths": map[string]any{
			"https://" + host + "/v1/": map[string]string{usernameKey: "puller", passwordKey: sourcePass},
		}})
		return map[string][]byte{corev1.DockerConfigJsonKey: b}
	}
	return []*corev1.Secret{
		{ObjectMeta: om("auth"), Type: corev1.SecretTypeDockerConfigJson, Data: cfg("ghcr.io")},
		{ObjectMeta: om("hub"), Type: corev1.SecretTypeDockerConfigJson, Data: cfg("index.docker.io")},
		{ObjectMeta: om("ca"), Data: map[string][]byte{caKey: testCAPEM()}},
	}
}

// withSourceSecrets points the target at the secrets of sourceSecrets(t.Name).
func withSourceSecrets(t *mirrorv1alpha1.ClusterMirrorTarget) {
	t.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
		{Registry: ghcrRegistry, SecretRef: &mirrorv1alpha1.SecretRef{Name: t.Name + "-src-auth"}},
		{Registry: "registry-1.docker.io", SecretRef: &mirrorv1alpha1.SecretRef{Name: t.Name + "-src-hub"}},
	}
	t.Spec.SourceCABundles = []mirrorv1alpha1.SourceCABundle{
		{Registry: ghcrRegistry, SecretRef: mirrorv1alpha1.SecretKeyRef{Name: t.Name + "-src-ca", Key: caKey}},
	}
}

func createSourceSecrets(prefix string) {
	for _, s := range sourceSecrets(prefix) {
		ExpectWithOffset(1, k8sClient.Create(ctx, s)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, s)
	}
}

var _ = Describe("source Secrets of a ClusterMirrorTarget", func() {
	It("is Ready with valid source Secrets, also when they appear later", func() {
		name := "tgt-src-ok"
		for _, s := range targetSecrets(name) {
			Expect(k8sClient.Create(ctx, s)).To(Succeed())
			DeferCleanup(k8sClient.Delete, ctx, s)
		}
		t := newTarget(name)
		withSourceSecrets(t)
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, t)
		Eventually(func() *metav1.Condition { return targetReady(name) }).Should(And(
			HaveField("Reason", ReasonSecretNotFound),
			HaveField("Message", ContainSubstring(name+"-src-auth")),
		))
		createSourceSecrets(name)
		Eventually(func() *metav1.Condition { return targetReady(name) }).Should(
			HaveField("Status", metav1.ConditionTrue))
	})

	DescribeTable("reports an invalid source Secret",
		func(name string, mutate func(map[string]*corev1.Secret), reason, message string) {
			for _, s := range targetSecrets(name) {
				Expect(k8sClient.Create(ctx, s)).To(Succeed())
				DeferCleanup(k8sClient.Delete, ctx, s)
			}
			secrets := map[string]*corev1.Secret{}
			for _, s := range sourceSecrets(name) {
				secrets[strings.TrimPrefix(s.Name, name+"-src-")] = s
			}
			mutate(secrets)
			for _, s := range secrets {
				Expect(k8sClient.Create(ctx, s)).To(Succeed())
				DeferCleanup(k8sClient.Delete, ctx, s)
			}
			t := newTarget(name)
			withSourceSecrets(t)
			Expect(k8sClient.Create(ctx, t)).To(Succeed())
			DeferCleanup(k8sClient.Delete, ctx, t)
			var cond *metav1.Condition
			Eventually(func() *metav1.Condition { cond = targetReady(name); return cond }).Should(And(
				HaveField("Status", metav1.ConditionFalse),
				HaveField("Reason", reason),
				HaveField("Message", ContainSubstring(message)),
			))
			expectNoSecrets(cond.Message)
			Eventually(func() []string { return recorder.Events("", name) }).Should(ContainElement(ContainSubstring("Warning " + reason)))
			for _, e := range recorder.Events("", name) {
				expectNoSecrets(e)
			}
		},
		Entry("credentials of the wrong type", "tgt-src-type", func(s map[string]*corev1.Secret) {
			s["auth"].Type = corev1.SecretTypeOpaque
		}, ReasonInvalidSecret, "tgt-src-type-src-auth is of type Opaque"),
		Entry("credentials without an entry for the registry", "tgt-src-host", func(s map[string]*corev1.Secret) {
			s["auth"].Data = s["hub"].Data
		}, ReasonInvalidSecret, "tgt-src-host-src-auth has no auths entry for ghcr.io"),
		Entry("Docker Hub credentials under index.docker.io", "tgt-src-hub", func(s map[string]*corev1.Secret) {
			s["hub"].Data = s["auth"].Data
		}, ReasonInvalidSecret, "tgt-src-hub-src-hub has no auths entry for registry-1.docker.io"),
		Entry("missing CA", "tgt-src-noca", func(s map[string]*corev1.Secret) {
			delete(s, "ca")
		}, ReasonSecretNotFound, "tgt-src-noca-src-ca not found"),
		Entry("CA without a certificate", "tgt-src-badca", func(s map[string]*corev1.Secret) {
			s["ca"].Data[caKey] = []byte(sourcePass)
		}, ReasonInvalidSecret, "tgt-src-badca-src-ca key ca.crt holds no PEM certificate"),
	)

	DescribeTable("rejects two entries for one registry",
		func(name string, mutate func(*mirrorv1alpha1.ClusterMirrorTarget), message string) {
			for _, s := range append(targetSecrets(name), sourceSecrets(name)...) {
				Expect(k8sClient.Create(ctx, s)).To(Succeed())
				DeferCleanup(k8sClient.Delete, ctx, s)
			}
			t := newTarget(name)
			withSourceSecrets(t)
			mutate(t)
			Expect(k8sClient.Create(ctx, t)).To(Succeed())
			DeferCleanup(k8sClient.Delete, ctx, t)
			Eventually(func() *metav1.Condition { return targetReady(name) }).Should(And(
				HaveField("Status", metav1.ConditionFalse),
				HaveField("Reason", ReasonInvalidSpec),
				HaveField("Message", ContainSubstring(message)),
			))
		},
		Entry("credentials by Docker Hub alias", "tgt-src-dup", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.SourceCredentials = append(t.Spec.SourceCredentials,
				mirrorv1alpha1.SourceCredential{Registry: dockerHubHost, SecretRef: &mirrorv1alpha1.SecretRef{Name: t.Name + "-src-hub"}})
		}, "sourceCredentials"),
		Entry("CA bundles by case", "tgt-src-dupca", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.SourceCABundles = append(t.Spec.SourceCABundles,
				mirrorv1alpha1.SourceCABundle{Registry: "GHCR.io", SecretRef: t.Spec.SourceCABundles[0].SecretRef})
		}, "sourceCABundles"),
	)
})
