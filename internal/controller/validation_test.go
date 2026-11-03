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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
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
			CredentialsSecretRef: &mirrorv1alpha1.SecretRef{Name: "registry-push"},
			CABundleSecretRef:    &mirrorv1alpha1.SecretKeyRef{Name: "registry-ca", Key: caKey},
			ClientCertSecretRef:  &mirrorv1alpha1.SecretRef{Name: "registry-client-tls"},
			Proxy: &mirrorv1alpha1.ProxySpec{
				HTTPSProxy:           "http://proxy.example.internal:3128",
				NoProxy:              []string{".example.internal", "10.0.0.0/8"},
				CABundleSecretRef:    &mirrorv1alpha1.SecretKeyRef{Name: "proxy-ca", Key: caKey},
				CredentialsSecretRef: &mirrorv1alpha1.SecretRef{Name: "proxy-auth"},
			},
			AllowedSources: []mirrorv1alpha1.RegistryHost{k8sHost, "ghcr.io"},
			Projects: []mirrorv1alpha1.TargetProject{
				// The controller tests set target.repository in this project.
				{Name: "mirror", NamespaceSelector: &metav1.LabelSelector{}, AllowRepositoryOverride: true},
				{Name: "team-a", NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"example.com/team": "a"},
				}},
			},
			Policy: mirrorv1alpha1.TargetPolicy{OnTagMutation: mirrorv1alpha1.OnTagMutationFail},
		},
	}
}

const zeroGUID = "00000000-0000-0000-0000-000000000000"

// useAzure switches the target push to Azure workload identity.
func useAzure(t *mirrorv1alpha1.ClusterMirrorTarget) {
	t.Spec.Registry = "myregistry.azurecr.io"
	t.Spec.CredentialsSecretRef = nil
	t.Spec.Auth = &mirrorv1alpha1.RegistryAuth{AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}}
	t.Spec.WorkloadIdentity = &mirrorv1alpha1.WorkloadIdentity{
		ServiceAccountName: "tagwarden-sync-azure",
		Azure:              &mirrorv1alpha1.AzureIdentity{ClientID: zeroGUID, TenantID: zeroGUID},
	}
}

const (
	exampleRoleARN = "arn:aws:iam::123456789012:role/tagwarden-sync"
	exampleRegion  = "eu-west-1"
	exampleECR     = "123456789012.dkr.ecr." + exampleRegion + ".amazonaws.com"
)

// useAWS switches the target push to AWS workload identity.
func useAWS(t *mirrorv1alpha1.ClusterMirrorTarget) {
	t.Spec.Registry = exampleECR
	t.Spec.CredentialsSecretRef = nil
	t.Spec.Auth = &mirrorv1alpha1.RegistryAuth{AWSWorkloadIdentity: &mirrorv1alpha1.AWSWorkloadIdentityAuth{}}
	t.Spec.WorkloadIdentity = &mirrorv1alpha1.WorkloadIdentity{
		ServiceAccountName: "tagwarden-sync-aws",
		AWS:                &mirrorv1alpha1.AWSIdentity{RoleARN: exampleRoleARN, Region: exampleRegion},
	}
}

const (
	exampleGCPAudience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/providers/cluster"
	exampleGAR         = "europe-west1-docker.pkg.dev"
)

// useGCP switches the target push to Google Cloud workload identity.
func useGCP(t *mirrorv1alpha1.ClusterMirrorTarget) {
	t.Spec.Registry = exampleGAR
	t.Spec.CredentialsSecretRef = nil
	t.Spec.Auth = &mirrorv1alpha1.RegistryAuth{GCPWorkloadIdentity: &mirrorv1alpha1.GCPWorkloadIdentityAuth{}}
	t.Spec.WorkloadIdentity = &mirrorv1alpha1.WorkloadIdentity{
		ServiceAccountName: "tagwarden-sync-gcp",
		GCP:                &mirrorv1alpha1.GCPIdentity{Audience: exampleGCPAudience},
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
				Registry:   k8sHost,
				Repository: "pause",
			},
			Target: mirrorv1alpha1.Target{Project: "mirror", Repository: "k8s/pause"},
			Tags: mirrorv1alpha1.TagSelector{
				Include:         []string{`^\d+\.\d+$`},
				Exclude:         []string{"-rc"},
				SemverRange:     ">=3.9",
				KeepLatest:      ptr.To[int32](3),
				AllowPrerelease: true,
				Tags:            []string{"3.10"},
			},
			RequiredPlatforms: []string{"linux/amd64", "linux/arm64/v8"},
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
			deleteAndWait(obj)
		}
	})

	DescribeTable("accepts a valid ClusterMirrorTarget",
		func(mutate func(*mirrorv1alpha1.ClusterMirrorTarget)) {
			obj := validTarget("valid-target")
			mutate(obj)
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
		},
		Entry("full example", func(*mirrorv1alpha1.ClusterMirrorTarget) {}),
		Entry("registry with port 443", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Registry = "registry-1.docker.io:443"
		}),
		Entry("localhost registry", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Registry = "localhost:5000"
		}),
		Entry("IPv6 registry", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Registry = "[::1]:5000"
		}),
		Entry("limits", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			size := resource.MustParse("10Gi")
			o.Spec.Limits = &mirrorv1alpha1.TargetLimits{
				MinSyncInterval:        &metav1.Duration{Duration: 5 * time.Minute},
				MaxMirrorsPerNamespace: ptr.To[int32](1),
				MaxKeepLatest:          ptr.To[int32](100),
				MaxExplicitTags:        ptr.To[int32](100),
				MaxArtifactSize:        &size,
			}
		}),
		Entry("empty limits", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Limits = &mirrorv1alpha1.TargetLimits{}
		}),
		Entry("Azure workload identity", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.WorkloadIdentity.Azure.AuthorityHost = "https://login.microsoftonline.us/"
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: "src.azurecr.io", AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}},
				{Registry: "Other-ab12cd.AzureCR.us:443", AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}},
				{Registry: ghcrRegistry, SecretRef: &mirrorv1alpha1.SecretRef{Name: "ghcr-pull"}},
			}
		}),
		Entry("AWS workload identity", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(o)
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: "210987654321.dkr.ecr.eu-west-1.amazonaws.com", AWSWorkloadIdentity: &mirrorv1alpha1.AWSWorkloadIdentityAuth{}},
				{Registry: "123456789012.DKR.ECR-FIPS.us-gov-west-1.amazonaws.com:443", AWSWorkloadIdentity: &mirrorv1alpha1.AWSWorkloadIdentityAuth{}},
				{Registry: "other.azurecr.io", AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}},
			}
			o.Spec.WorkloadIdentity.Azure = &mirrorv1alpha1.AzureIdentity{ClientID: zeroGUID, TenantID: zeroGUID}
		}),
		Entry("AWS role in China", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(o)
			o.Spec.Registry = "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn"
			o.Spec.WorkloadIdentity.AWS = &mirrorv1alpha1.AWSIdentity{
				RoleARN: "arn:aws-cn:iam::123456789012:role/path/tagwarden-sync", Region: "cn-north-1",
			}
		}),
		Entry("GCP workload identity", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.WorkloadIdentity.GCP.ServiceAccountEmail = "tagwarden-sync@example-project.iam.gserviceaccount.com"
			gcp := &mirrorv1alpha1.GCPWorkloadIdentityAuth{}
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: "US-docker.pkg.dev:443", GCPWorkloadIdentity: gcp},
				{Registry: "gcr.io", GCPWorkloadIdentity: gcp},
				{Registry: "eu.gcr.io", GCPWorkloadIdentity: gcp},
				{Registry: "asia.gcr.io", GCPWorkloadIdentity: gcp},
			}
		}),
		Entry("all three providers", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: exampleECR, AWSWorkloadIdentity: &mirrorv1alpha1.AWSWorkloadIdentityAuth{}},
				{Registry: "other.azurecr.io", AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}},
			}
			o.Spec.WorkloadIdentity.AWS = &mirrorv1alpha1.AWSIdentity{RoleARN: exampleRoleARN, Region: exampleRegion}
			o.Spec.WorkloadIdentity.Azure = &mirrorv1alpha1.AzureIdentity{ClientID: zeroGUID, TenantID: zeroGUID}
		}),
	)

	It("defaults the CA bundle key and tag mutation policy", func() {
		obj := validTarget("defaults-target")
		obj.Spec.CABundleSecretRef.Key = ""
		obj.Spec.Policy = mirrorv1alpha1.TargetPolicy{}
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		Expect(obj.Spec.CABundleSecretRef.Key).To(Equal("ca.crt"))
		Expect(obj.Spec.Policy.OnTagMutation).To(Equal(mirrorv1alpha1.OnTagMutationFail))
		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
	})

	DescribeTable("accepts a valid ArtifactMirror",
		func(mutate func(*mirrorv1alpha1.ArtifactMirror)) {
			obj := validMirror("valid-mirror")
			mutate(obj)
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			deleteAndWait(obj)
		},
		Entry("full example", func(*mirrorv1alpha1.ArtifactMirror) {}),
		Entry("@daily", func(o *mirrorv1alpha1.ArtifactMirror) { o.Spec.Schedule = "@daily" }),
		Entry("@midnight", func(o *mirrorv1alpha1.ArtifactMirror) { o.Spec.Schedule = "@midnight" }),
		Entry("@annually", func(o *mirrorv1alpha1.ArtifactMirror) { o.Spec.Schedule = "@annually" }),
		Entry("cron with steps and names", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Schedule = "*/15 1-5 ? * MON-FRI"
		}),
		Entry("explicit tags only", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Tags = mirrorv1alpha1.TagSelector{Tags: []string{"3.10"}}
		}),
		Entry("nested source repository", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Source.Repository = "library/nginx"
		}),
	)

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
		Entry("registry with userinfo", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Registry = "u:p@registry.example.internal"
		}),
		Entry("registry with a space", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Registry = "a b"
		}),
		Entry("registry with an empty port", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Registry = "host:"
		}),
		Entry("proxy URL with userinfo", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Proxy.HTTPSProxy = "http://user:pass@proxy.example.internal:3128"
		}),
		Entry("SOCKS proxy", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Proxy.HTTPSProxy = "socks5://x:1080"
		}),
		Entry("no allowed sources", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.AllowedSources = nil
		}),
		Entry("allowed source with scheme", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.AllowedSources = []mirrorv1alpha1.RegistryHost{"https://ghcr.io"}
		}),
		Entry("no projects", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Projects = nil
		}),
		Entry("project with an invalid name", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Projects[0].Name = "Upper"
		}),
		Entry("project with a path", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Projects[0].Name = "a/b"
		}),
		Entry("project without a namespace selector", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Projects[0].NamespaceSelector = nil
		}),
		Entry("duplicate project", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Projects[1].Name = o.Spec.Projects[0].Name
		}),
		Entry("unknown tag mutation policy", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Policy.OnTagMutation = "Replace"
		}),
		Entry("minSyncInterval below 5m", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Limits = &mirrorv1alpha1.TargetLimits{MinSyncInterval: &metav1.Duration{Duration: time.Minute}}
		}),
		Entry("maxMirrorsPerNamespace 0", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Limits = &mirrorv1alpha1.TargetLimits{MaxMirrorsPerNamespace: ptr.To[int32](0)}
		}),
		Entry("maxKeepLatest 101", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Limits = &mirrorv1alpha1.TargetLimits{MaxKeepLatest: ptr.To[int32](101)}
		}),
		Entry("maxExplicitTags 0", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.Limits = &mirrorv1alpha1.TargetLimits{MaxExplicitTags: ptr.To[int32](0)}
		}),
		Entry("maxArtifactSize 0", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			size := resource.MustParse("0")
			o.Spec.Limits = &mirrorv1alpha1.TargetLimits{MaxArtifactSize: &size}
		}),
		Entry("negative maxArtifactSize", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			size := resource.MustParse("-1Gi")
			o.Spec.Limits = &mirrorv1alpha1.TargetLimits{MaxArtifactSize: &size}
		}),
		Entry("no push credentials", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.CredentialsSecretRef = nil
		}),
		Entry("credentialsSecretRef and auth", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.CredentialsSecretRef = &mirrorv1alpha1.SecretRef{Name: "registry-push"}
		}),
		Entry("auth without a provider", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.Auth.AzureWorkloadIdentity = nil
		}),
		Entry("source credential without a provider", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{{Registry: ghcrRegistry}}
		}),
		Entry("source credential with two providers", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{{
				Registry: ghcrRegistry, SecretRef: &mirrorv1alpha1.SecretRef{Name: "ghcr-pull"},
				AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{},
			}}
		}),
		Entry("client ID not a GUID", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.WorkloadIdentity.Azure.ClientID = "my-app"
		}),
		Entry("tenant ID not a GUID", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.WorkloadIdentity.Azure.TenantID = "example.onmicrosoft.com"
		}),
		Entry("http authority host", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.WorkloadIdentity.Azure.AuthorityHost = "http://login.example.internal/"
		}),
		Entry("authority host with credentials", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.WorkloadIdentity.Azure.AuthorityHost = "https://u:p@login.example.internal/"
		}),
		Entry("unknown authority host", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.WorkloadIdentity.Azure.AuthorityHost = "https://login.example.internal/"
		}),
		Entry("authority host with a tenant path", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.WorkloadIdentity.Azure.AuthorityHost = "https://login.microsoftonline.com/" + zeroGUID
		}),
		Entry("Azure push to a non-ACR registry", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.Registry = "registry.example.internal"
		}),
		Entry("Azure push to an ACR host on another port", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.Registry = "myregistry.azurecr.io:5000"
		}),
		Entry("Azure pull from a non-ACR registry", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: ghcrRegistry, AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}},
			}
		}),
		Entry("Azure pull from a look-alike host", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: "src.azurecr.io.example.internal", AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}},
			}
		}),
		Entry("auth with two providers", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(o)
			o.Spec.Auth.AzureWorkloadIdentity = &mirrorv1alpha1.AzureWorkloadIdentityAuth{}
		}),
		Entry("source credential with secret and AWS", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{{
				Registry: exampleECR, SecretRef: &mirrorv1alpha1.SecretRef{Name: "ecr-pull"},
				AWSWorkloadIdentity: &mirrorv1alpha1.AWSWorkloadIdentityAuth{},
			}}
		}),
		Entry("AWS push to a non-ECR registry", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(o)
			o.Spec.Registry = "registry.example.internal"
		}),
		Entry("AWS push to an ACR registry", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(o)
			o.Spec.Registry = "myregistry.azurecr.io"
		}),
		Entry("Azure push to an ECR registry", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.Registry = exampleECR
		}),
		Entry("AWS push to an ECR host on another port", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(o)
			o.Spec.Registry = exampleECR + ":5000"
		}),
		Entry("AWS pull from public ECR", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: "public.ecr.aws", AWSWorkloadIdentity: &mirrorv1alpha1.AWSWorkloadIdentityAuth{}},
			}
		}),
		Entry("AWS pull from a look-alike host", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{{
				Registry:            exampleECR + ".example.internal",
				AWSWorkloadIdentity: &mirrorv1alpha1.AWSWorkloadIdentityAuth{},
			}}
		}),
		Entry("role ARN of a user", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(o)
			o.Spec.WorkloadIdentity.AWS.RoleARN = "arn:aws:iam::123456789012:user/sync"
		}),
		Entry("role ARN with a short account", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(o)
			o.Spec.WorkloadIdentity.AWS.RoleARN = "arn:aws:iam::12345:role/sync"
		}),
		Entry("unknown region", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(o)
			o.Spec.WorkloadIdentity.AWS.Region = "eu-west-1.example.internal"
		}),
		Entry("role and region in different partitions", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(o)
			o.Spec.WorkloadIdentity.AWS.Region = "cn-north-1"
		}),
		Entry("auth with GCP and AWS", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.Auth.AWSWorkloadIdentity = &mirrorv1alpha1.AWSWorkloadIdentityAuth{}
		}),
		Entry("source credential with secret and GCP", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{{
				Registry: exampleGAR, SecretRef: &mirrorv1alpha1.SecretRef{Name: "gar-pull"},
				GCPWorkloadIdentity: &mirrorv1alpha1.GCPWorkloadIdentityAuth{},
			}}
		}),
		Entry("GCP push to a non-GAR registry", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.Registry = "other.example.internal"
		}),
		Entry("GCP push to an ECR registry", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.Registry = exampleECR
		}),
		Entry("GCP push to a GAR host on another port", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.Registry = exampleGAR + ":5000"
		}),
		Entry("GCP pull from a look-alike host", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{{
				Registry: exampleGAR + ".example.internal", GCPWorkloadIdentity: &mirrorv1alpha1.GCPWorkloadIdentityAuth{},
			}}
		}),
		Entry("GCP pull from another gcr.io host", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{{
				Registry: "mirror.gcr.io", GCPWorkloadIdentity: &mirrorv1alpha1.GCPWorkloadIdentityAuth{},
			}}
		}),
		Entry("GCP pull from a non-ASCII look-alike", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			o.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{{
				Registry: "us-doc\u212Aer.pkg.dev", GCPWorkloadIdentity: &mirrorv1alpha1.GCPWorkloadIdentityAuth{},
			}}
		}),
		Entry("GCP audience with a URL scheme", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.WorkloadIdentity.GCP.Audience = "https:" + exampleGCPAudience
		}),
		Entry("GCP audience on another host", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.WorkloadIdentity.GCP.Audience = "//iam.example.internal/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/providers/cluster"
		}),
		Entry("GCP audience with a project ID", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.WorkloadIdentity.GCP.Audience = "//iam.googleapis.com/projects/example-project/locations/global/workloadIdentityPools/tagwarden/providers/cluster"
		}),
		Entry("GCP service account outside IAM", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.WorkloadIdentity.GCP.ServiceAccountEmail = "123456789012-compute@developer.gserviceaccount.com"
		}),
		Entry("GCP identity without audience", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(o)
			o.Spec.WorkloadIdentity.GCP.Audience = ""
		}),
		Entry("invalid ServiceAccount name", func(o *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(o)
			o.Spec.WorkloadIdentity.ServiceAccountName = "Sync_SA"
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
		Entry("invalid schedule", func(o *mirrorv1alpha1.ArtifactMirror) { o.Spec.Schedule = "every day" }),
		Entry("@every schedule", func(o *mirrorv1alpha1.ArtifactMirror) { o.Spec.Schedule = "@every 1h" }),
		Entry("schedule with a time zone", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Schedule = "CRON_TZ=UTC 0 3 * * *"
		}),
		Entry("schedule with a short time zone", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Schedule = "TZ=UTC 3 * * *"
		}),
		Entry("unknown type", func(o *mirrorv1alpha1.ArtifactMirror) { o.Spec.Type = "Foo" }),
		Entry("empty source repository", func(o *mirrorv1alpha1.ArtifactMirror) { o.Spec.Source.Repository = "" }),
		Entry("upper case source repository", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Source.Repository = "Upper"
		}),
		Entry("source repository with ..", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Source.Repository = "../x"
		}),
		Entry("source repository with //", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Source.Repository = "a//b"
		}),
		Entry("target repository with ..", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Target.Repository = "../x"
		}),
		Entry("source registry with scheme", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Source.Registry = "https://x"
		}),
		Entry("empty target project", func(o *mirrorv1alpha1.ArtifactMirror) { o.Spec.Target.Project = "" }),
		Entry("target project with a path", func(o *mirrorv1alpha1.ArtifactMirror) { o.Spec.Target.Project = "a/b" }),
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
		Entry("exclude pattern too long", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Tags.Exclude = []string{strings.Repeat("a", 257)}
		}),
		Entry("semverRange too long", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Tags.SemverRange = ">=" + strings.Repeat("1", 255)
		}),
		Entry("invalid explicit tag", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.Tags.Tags = []string{"-bad"}
		}),
		Entry("invalid platform", func(o *mirrorv1alpha1.ArtifactMirror) {
			o.Spec.RequiredPlatforms = []string{"linux"}
		}),
	)
})
