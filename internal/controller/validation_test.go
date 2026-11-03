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
	"io/fs"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

func validTarget(name string) *mirrorv1alpha1.ClusterMirrorTarget {
	return &mirrorv1alpha1.ClusterMirrorTarget{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: mirrorv1alpha1.ClusterMirrorTargetSpec{
			Registry:             "registry.example.internal:8443",
			CredentialsSecretRef: mirrorv1alpha1.SecretRef{Name: "registry-push"},
			CABundleSecretRef:    &mirrorv1alpha1.SecretKeyRef{Name: "registry-ca", Key: "ca.crt"},
			ClientCertSecretRef:  &mirrorv1alpha1.SecretRef{Name: "registry-client-tls"},
			Proxy: &mirrorv1alpha1.ProxySpec{
				HTTPSProxy:           "http://proxy.example.internal:3128",
				NoProxy:              []string{".example.internal", "10.0.0.0/8"},
				CABundleSecretRef:    &mirrorv1alpha1.SecretKeyRef{Name: "proxy-ca", Key: "ca.crt"},
				CredentialsSecretRef: &mirrorv1alpha1.SecretRef{Name: "proxy-auth"},
			},
			AllowedSources: []mirrorv1alpha1.RegistryHost{"registry.k8s.io", "ghcr.io"},
			AllowedNamespaces: &metav1.LabelSelector{
				MatchLabels: map[string]string{"mirror.tagwarden.dev/allowed": "true"},
			},
			Policy: mirrorv1alpha1.TargetPolicy{OnTagMutation: mirrorv1alpha1.OnTagMutationFail},
		},
	}
}

func validMirror(name string) *mirrorv1alpha1.ArtifactMirror {
	return &mirrorv1alpha1.ArtifactMirror{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: mirrorv1alpha1.ArtifactMirrorSpec{
			TargetRef: "default",
			Schedule:  "0 3 * * *",
			Type:      mirrorv1alpha1.ArtifactTypeImage,
			Source: mirrorv1alpha1.Source{
				Registry:   "registry.k8s.io",
				Repository: "pause",
			},
			Target: mirrorv1alpha1.Target{Project: "mirror"},
			Tags: mirrorv1alpha1.TagSelector{
				Include:     []string{`^\d+\.\d+$`},
				Exclude:     []string{"-rc"},
				SemverRange: ">=3.9",
				KeepLatest:  ptr.To[int32](3),
				Tags:        []string{"3.10"},
			},
			Platforms: []string{"linux/amd64", "linux/arm64/v8"},
		},
	}
}

var _ = Describe("API validation", func() {
	It("accepts the samples", func() {
		samples := map[string]client.Object{
			"mirror_v1alpha1_clustermirrortarget.yaml": &mirrorv1alpha1.ClusterMirrorTarget{},
			"mirror_v1alpha1_artifactmirror.yaml":      &mirrorv1alpha1.ArtifactMirror{},
		}
		dir := os.DirFS("../../config/samples")
		for file, obj := range samples {
			data, err := fs.ReadFile(dir, file)
			Expect(err).NotTo(HaveOccurred())
			Expect(yaml.UnmarshalStrict(data, obj)).To(Succeed(), file)
			if _, namespaced := obj.(*mirrorv1alpha1.ArtifactMirror); namespaced {
				obj.SetNamespace("default")
			}
			Expect(k8sClient.Create(ctx, obj)).To(Succeed(), file)
			Expect(k8sClient.Delete(ctx, obj)).To(Succeed(), file)
		}
	})

	It("accepts a full ClusterMirrorTarget", func() {
		obj := validTarget("valid-target")
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
	})

	It("accepts an empty namespace selector that allows all namespaces", func() {
		obj := validTarget("all-namespaces-target")
		obj.Spec.AllowedNamespaces = &metav1.LabelSelector{}
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
	})

	It("defaults the CA bundle key and tag mutation policy", func() {
		obj := validTarget("defaults-target")
		obj.Spec.CABundleSecretRef.Key = ""
		obj.Spec.Policy = mirrorv1alpha1.TargetPolicy{}
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		Expect(obj.Spec.CABundleSecretRef.Key).To(Equal("ca.crt"))
		Expect(obj.Spec.Policy.OnTagMutation).To(Equal(mirrorv1alpha1.OnTagMutationFail))
		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
	})

	It("accepts a full ArtifactMirror", func() {
		obj := validMirror("valid-mirror")
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
	})

	It("accepts a schedule macro", func() {
		obj := validMirror("macro-mirror")
		obj.Spec.Schedule = "@daily"
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
	})

	DescribeTable("rejects an invalid ClusterMirrorTarget",
		func(mutate func(*mirrorv1alpha1.ClusterMirrorTarget)) {
			obj := validTarget("invalid-target")
			mutate(obj)
			err := k8sClient.Create(ctx, obj)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected Invalid, got %v", err)
		},
		Entry("registry with scheme", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Registry = "https://registry.example.internal"
		}),
		Entry("proxy URL with userinfo", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Proxy.HTTPSProxy = "http://user:pass@proxy.example.internal:3128"
		}),
		Entry("no allowed sources", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.AllowedSources = nil
		}),
		Entry("allowed source with scheme", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.AllowedSources = []mirrorv1alpha1.RegistryHost{"https://ghcr.io"}
		}),
		Entry("no allowed namespaces", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.AllowedNamespaces = nil
		}),
		Entry("unknown tag mutation policy", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Policy.OnTagMutation = "Replace"
		}),
	)

	DescribeTable("rejects an invalid ArtifactMirror",
		func(mutate func(*mirrorv1alpha1.ArtifactMirror)) {
			obj := validMirror("invalid-mirror")
			mutate(obj)
			err := k8sClient.Create(ctx, obj)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected Invalid, got %v", err)
		},
		Entry("keepLatest 0", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Tags.KeepLatest = ptr.To[int32](0)
		}),
		Entry("keepLatest 101", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Tags.KeepLatest = ptr.To[int32](101)
		}),
		Entry("invalid schedule", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Schedule = "every day"
		}),
		Entry("unknown type", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Type = "Foo"
		}),
		Entry("empty source repository", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Source.Repository = ""
		}),
		Entry("source registry with scheme", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Source.Registry = "https://x"
		}),
		Entry("no tag selector", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Tags = mirrorv1alpha1.TagSelector{}
		}),
		Entry("only an exclude filter", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Tags = mirrorv1alpha1.TagSelector{Exclude: []string{"-rc"}}
		}),
		Entry("too many include patterns", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Tags.Include = make([]string, 21)
			for i := range o.Spec.Tags.Include {
				o.Spec.Tags.Include[i] = string(rune('a' + i))
			}
		}),
		Entry("invalid platform", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Platforms = []string{"linux"}
		}),
	)
})
