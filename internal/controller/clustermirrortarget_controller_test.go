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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const caKey = "ca.crt"

// Secret values that must never show up outside the Secrets.
const (
	pushPassword  = "push-secret-value"
	proxyPassword = "proxy-secret-value"
	clientKey     = "client-key-value"
	sourcePass    = "source-secret-value"
)

func testCAPEM() []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// targetSecrets returns valid Secrets for validTarget, named with prefix.
func targetSecrets(prefix string) []*corev1.Secret {
	om := func(n string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: prefix + "-" + n, Namespace: operatorNamespace}
	}
	ca := testCAPEM()
	return []*corev1.Secret{
		{ObjectMeta: om("push"), Type: corev1.SecretTypeDockerConfigJson, Data: map[string][]byte{
			corev1.DockerConfigJsonKey: []byte(`{"auths":{"https://registry.example.internal:8443/v1/":{"username":"robot","password":"` + pushPassword + `"}}}`),
		}},
		{ObjectMeta: om("ca"), Data: map[string][]byte{caKey: ca}},
		{ObjectMeta: om("client-tls"), Type: corev1.SecretTypeTLS, Data: map[string][]byte{
			"tls.crt": ca, "tls.key": []byte(clientKey),
		}},
		{ObjectMeta: om("proxy-ca"), Data: map[string][]byte{caKey: ca}},
		{ObjectMeta: om("proxy-auth"), Type: corev1.SecretTypeBasicAuth, Data: map[string][]byte{
			usernameKey: []byte("proxy-user"), passwordKey: []byte(proxyPassword),
		}},
	}
}

// newTarget returns validTarget pointing at the Secrets of targetSecrets(name).
func newTarget(name string) *mirrorv1alpha1.ClusterMirrorTarget {
	t := validTarget(name)
	t.Spec.CredentialsSecretRef.Name = name + "-push"
	t.Spec.CABundleSecretRef.Name = name + "-ca"
	t.Spec.ClientCertSecretRef.Name = name + "-client-tls"
	t.Spec.Proxy.CABundleSecretRef.Name = name + "-proxy-ca"
	t.Spec.Proxy.CredentialsSecretRef.Name = name + "-proxy-auth"
	return t
}

// createReadyTarget creates a target with valid Secrets and waits for Ready.
func createReadyTarget(name string, mutate ...func(*mirrorv1alpha1.ClusterMirrorTarget)) *mirrorv1alpha1.ClusterMirrorTarget {
	for _, s := range targetSecrets(name) {
		Expect(k8sClient.Create(ctx, s)).To(Succeed())
	}
	t := newTarget(name)
	for _, f := range mutate {
		f(t)
	}
	Expect(k8sClient.Create(ctx, t)).To(Succeed())
	Eventually(func() *metav1.Condition { return targetReady(name) }).Should(
		HaveField("Status", metav1.ConditionTrue))
	return t
}

func targetReady(name string) *metav1.Condition {
	var t mirrorv1alpha1.ClusterMirrorTarget
	if k8sClient.Get(ctx, types.NamespacedName{Name: name}, &t) != nil {
		return nil
	}
	return meta.FindStatusCondition(t.Status.Conditions, ConditionReady)
}

func expectNoSecrets(texts ...string) {
	for _, s := range texts {
		for _, v := range []string{pushPassword, proxyPassword, clientKey, sourcePass, "robot"} {
			ExpectWithOffset(1, s).NotTo(ContainSubstring(v))
		}
	}
}

var _ = Describe("ClusterMirrorTarget Controller", func() {
	It("is Ready once every referenced Secret is valid", func() {
		t := newTarget("tgt-ready")
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, t)
		Eventually(func() *metav1.Condition { return targetReady(t.Name) }).Should(And(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", ReasonSecretNotFound),
			HaveField("Message", ContainSubstring("tgt-ready-push")),
		))

		for _, s := range targetSecrets(t.Name) {
			Expect(k8sClient.Create(ctx, s)).To(Succeed())
			DeferCleanup(k8sClient.Delete, ctx, s)
		}
		Eventually(func() *metav1.Condition { return targetReady(t.Name) }).Should(And(
			HaveField("Status", metav1.ConditionTrue),
			HaveField("Reason", ReasonReady),
			HaveField("ObservedGeneration", t.Generation),
		))
	})

	DescribeTable("reports an invalid Secret",
		func(name string, mutate func(map[string]*corev1.Secret), reason, message string) {
			secrets := map[string]*corev1.Secret{}
			for _, s := range targetSecrets(name) {
				secrets[strings.TrimPrefix(s.Name, name+"-")] = s
			}
			mutate(secrets)
			for _, s := range secrets {
				Expect(k8sClient.Create(ctx, s)).To(Succeed())
				DeferCleanup(k8sClient.Delete, ctx, s)
			}
			t := newTarget(name)
			Expect(k8sClient.Create(ctx, t)).To(Succeed())
			DeferCleanup(k8sClient.Delete, ctx, t)
			var cond *metav1.Condition
			Eventually(func() *metav1.Condition { cond = targetReady(name); return cond }).Should(And(
				HaveField("Status", metav1.ConditionFalse),
				HaveField("Reason", reason),
				HaveField("Message", ContainSubstring(message)),
			))
			expectNoSecrets(cond.Message)
		},
		Entry("push Secret of the wrong type", "tgt-push-type", func(s map[string]*corev1.Secret) {
			s["push"].Type = corev1.SecretTypeOpaque
		}, ReasonInvalidSecret, "want kubernetes.io/dockerconfigjson"),
		Entry("push Secret without an entry for the registry", "tgt-push-host", func(s map[string]*corev1.Secret) {
			s["push"].Data[corev1.DockerConfigJsonKey] = []byte(`{"auths":{"other.example.internal":{"password":"` + pushPassword + `"}}}`)
		}, ReasonInvalidSecret, "no auths entry for registry.example.internal:8443"),
		Entry("CA without a certificate", "tgt-ca", func(s map[string]*corev1.Secret) {
			s["ca"].Data[caKey] = []byte(pushPassword)
		}, ReasonInvalidSecret, "tgt-ca-ca key ca.crt holds no PEM certificate"),
		Entry("proxy CA under another key", "tgt-proxy-ca", func(s map[string]*corev1.Secret) {
			s["proxy-ca"].Data = map[string][]byte{"other": s["proxy-ca"].Data[caKey]}
		}, ReasonInvalidSecret, "tgt-proxy-ca-proxy-ca key ca.crt"),
		Entry("client certificate not of type TLS", "tgt-client", func(s map[string]*corev1.Secret) {
			s["client-tls"].Type = corev1.SecretTypeOpaque
		}, ReasonInvalidSecret, "want kubernetes.io/tls"),
		Entry("proxy credentials without a password", "tgt-proxy-auth", func(s map[string]*corev1.Secret) {
			s["proxy-auth"].Type = corev1.SecretTypeOpaque
			delete(s["proxy-auth"].Data, passwordKey)
		}, ReasonInvalidSecret, "no key password"),
		Entry("missing proxy credentials", "tgt-proxy-missing", func(s map[string]*corev1.Secret) {
			delete(s, "proxy-auth")
		}, ReasonSecretNotFound, "tgt-proxy-missing-proxy-auth not found"),
	)

	DescribeTable("refuses allowedSources that map to one target path segment",
		func(name string, sources []mirrorv1alpha1.RegistryHost, message string) {
			for _, s := range targetSecrets(name) {
				Expect(k8sClient.Create(ctx, s)).To(Succeed())
				DeferCleanup(k8sClient.Delete, ctx, s)
			}
			t := newTarget(name)
			t.Spec.AllowedSources = sources
			Expect(k8sClient.Create(ctx, t)).To(Succeed())
			DeferCleanup(k8sClient.Delete, ctx, t)
			Eventually(func() *metav1.Condition { return targetReady(name) }).Should(And(
				HaveField("Status", metav1.ConditionFalse),
				HaveField("Reason", ReasonAmbiguousAllowedSources),
				HaveField("Message", ContainSubstring(message)),
			))
			Expect(recorder.Events("", name)).To(ContainElement(ContainSubstring("Warning " + ReasonAmbiguousAllowedSources)))
		},
		Entry("port and dash", "tgt-ambiguous-port", []mirrorv1alpha1.RegistryHost{"reg.example.internal:5000", "reg.example.internal-5000"},
			"reg.example.internal-5000"),
		Entry("IPv6 forms", "tgt-ambiguous-ipv6", []mirrorv1alpha1.RegistryHost{"[2001:db8::1]:5000", "2001-db8--1-5000"},
			"2001-db8--1-5000"),
	)

	It("allows Docker Hub aliases, which are one registry", func() {
		createReadyTarget("tgt-docker-aliases", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.AllowedSources = []mirrorv1alpha1.RegistryHost{dockerHubHost, "index.docker.io", "Registry-1.Docker.IO"}
		})
	})

	It("turns not Ready when a Secret is deleted", func() {
		t := createReadyTarget("tgt-delete")
		DeferCleanup(k8sClient.Delete, ctx, t)
		Expect(k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: "tgt-delete-ca", Namespace: operatorNamespace,
		}})).To(Succeed())
		Eventually(func() *metav1.Condition { return targetReady(t.Name) }).Should(
			HaveField("Reason", ReasonSecretNotFound))
	})
})

var _ = Describe("hasAuth", func() {
	It("matches auths keys like the sync Job and rejects garbage", func() {
		Expect(hasAuth([]byte(`{"auths":{"Registry.Example.Internal":{}}}`), "registry.example.internal")).To(BeTrue())
		Expect(hasAuth([]byte(`{"auths":{"https://registry.example.internal/v2/":{}}}`), "registry.example.internal")).To(BeTrue())
		Expect(hasAuth([]byte(`{"auths":{"registry.example.internal:5000":{}}}`), "registry.example.internal")).To(BeFalse())
		Expect(hasAuth([]byte(`not json`), "registry.example.internal")).To(BeFalse())
	})
})
