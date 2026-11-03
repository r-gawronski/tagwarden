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
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

var _ = Describe("Workload identity in a sync CronJob", func() {
	const (
		azureSource = "src.azurecr.io"
		tokenVolume = "azure-token"
		ecrSource   = "210987654321.dkr.ecr.eu-west-1.amazonaws.com"
		awsVolume   = "aws-token"
		garSource   = "us-docker.pkg.dev"
		gcpVolume   = "gcp-token"
		gcpAudience = "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/providers/cluster"
	)
	podOf := func(m *mirrorv1alpha1.ArtifactMirror) corev1.PodSpec {
		EventuallyWithOffset(1, mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
		cj, err := cronJob(m)()
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		return cj.Spec.JobTemplate.Spec.Template.Spec
	}
	specOf := func(m *mirrorv1alpha1.ArtifactMirror) syncspec.Spec {
		var cm corev1.ConfigMap
		ExpectWithOffset(1, k8sClient.Get(ctx, objectKey(m), &cm)).To(Succeed())
		s, err := syncspec.Decode(bytes.NewReader([]byte(cm.Data[specKey])))
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		return s
	}
	volume := func(p corev1.PodSpec, name string) *corev1.Volume {
		for i := range p.Volumes {
			if p.Volumes[i].Name == name {
				return &p.Volumes[i]
			}
		}
		return nil
	}
	expectProjected := func(p corev1.PodSpec, name, audience string) {
		v := volume(p, name)
		ExpectWithOffset(1, v).NotTo(BeNil())
		ExpectWithOffset(1, v.Projected.Sources).To(Equal([]corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
			Audience: audience, ExpirationSeconds: new(int64(3600)), Path: "token",
		}}}))
		ExpectWithOffset(1, p.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
			Name: name, MountPath: "/var/run/tagwarden/" + name, ReadOnly: true,
		}))
		ExpectWithOffset(1, *p.AutomountServiceAccountToken).To(BeFalse())
	}
	expectToken := func(p corev1.PodSpec) {
		expectProjected(p, tokenVolume, "api://AzureADTokenExchange")
		ExpectWithOffset(1, p.ServiceAccountName).To(Equal("tagwarden-sync-azure"))
	}
	expectAWSToken := func(p corev1.PodSpec) { expectProjected(p, awsVolume, "sts.amazonaws.com") }
	expectGCPToken := func(p corev1.PodSpec) { expectProjected(p, gcpVolume, gcpAudience) }
	mirrorOf := func(target, mname, registry string) *mirrorv1alpha1.ArtifactMirror {
		m := newMirror(teamA, mname)
		m.Spec.TargetRef = target
		m.Spec.Source = mirrorv1alpha1.Source{Registry: mirrorv1alpha1.RegistryHost(registry), Repository: "pause"}
		m.Spec.Target.Repository = "wi/" + mname
		createMirror(m)
		return m
	}

	It("mounts the projected token only in pods of Azure sources", func() {
		const name = "tgt-wi-source"
		t := createReadyTarget(name, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.AllowedSources = append(t.Spec.AllowedSources, azureSource)
			t.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: azureSource, AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}},
			}
			t.Spec.WorkloadIdentity = &mirrorv1alpha1.WorkloadIdentity{
				ServiceAccountName: "tagwarden-sync-azure",
				Azure:              &mirrorv1alpha1.AzureIdentity{ClientID: zeroGUID, TenantID: zeroGUID},
			}
		})
		DeferCleanup(k8sClient.Delete, ctx, t)
		azure := mirrorOf(name, "wi-azure", azureSource)
		plain := mirrorOf(name, "wi-plain", k8sHost)

		p := podOf(azure)
		expectToken(p)
		Expect(volume(p, "target-auth")).NotTo(BeNil())
		s := specOf(azure)
		Expect(s.SourceAuth).To(Equal(syncspec.AuthAzureWorkloadIdentity))
		Expect(s.TargetAuth).To(BeEmpty())
		Expect(*s.Azure).To(Equal(syncspec.Azure{
			ClientID: zeroGUID, TenantID: zeroGUID,
			AuthorityHost: syncspec.DefaultAzureAuthorityHost,
		}))

		p = podOf(plain)
		Expect(volume(p, tokenVolume)).To(BeNil())
		Expect(p.ServiceAccountName).To(Equal(SyncServiceAccount))
		s = specOf(plain)
		Expect(s.SourceAuth).To(BeEmpty())
		Expect(s.Azure).To(BeNil())
	})

	It("pushes with the identity and restores a removed token volume", func() {
		const name = "tgt-wi-push"
		t := createReadyTarget(name, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			useAzure(t)
			t.Spec.WorkloadIdentity.Azure.AuthorityHost = "https://login.microsoftonline.us/"
		})
		DeferCleanup(k8sClient.Delete, ctx, t)
		m := mirrorOf(name, "wi-push", k8sHost)

		p := podOf(m)
		expectToken(p)
		Expect(volume(p, "target-auth")).To(BeNil())
		s := specOf(m)
		Expect(s.TargetAuth).To(Equal(syncspec.AuthAzureWorkloadIdentity))
		Expect(s.Azure.AuthorityHost).To(Equal("https://login.microsoftonline.us/"))

		cj, _ := cronJob(m)()
		pod := &cj.Spec.JobTemplate.Spec.Template.Spec
		pod.ServiceAccountName = "other-sa"
		pod.Volumes = slices.DeleteFunc(pod.Volumes, func(v corev1.Volume) bool { return v.Name == tokenVolume })
		pod.Containers[0].VolumeMounts = slices.DeleteFunc(pod.Containers[0].VolumeMounts,
			func(v corev1.VolumeMount) bool { return v.Name == tokenVolume })
		Expect(k8sClient.Update(ctx, cj)).To(Succeed())
		Eventually(func(g Gomega) {
			got, err := cronJob(m)()
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(got.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName).To(Equal("tagwarden-sync-azure"))
			g.Expect(volume(got.Spec.JobTemplate.Spec.Template.Spec, tokenVolume)).NotTo(BeNil())
		}).Should(Succeed())
	})

	It("is not Ready when Azure auth has no Azure identity", func() {
		const name = "tgt-wi-missing"
		for _, s := range targetSecrets(name) {
			Expect(k8sClient.Create(ctx, s)).To(Succeed())
		}
		t := newTarget(name)
		t.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
			{Registry: azureSource, AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}},
		}
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, t)
		Eventually(func() *metav1.Condition { return targetReady(name) }).Should(And(
			HaveField("Status", metav1.ConditionFalse), HaveField("Reason", ReasonInvalidSpec),
			HaveField("Message", ContainSubstring("spec.workloadIdentity.azure"))))
	})

	It("mounts the projected token only in pods of ECR sources", func() {
		const name = "tgt-aws-source"
		t := createReadyTarget(name, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.AllowedSources = append(t.Spec.AllowedSources, ecrSource)
			t.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: ecrSource, AWSWorkloadIdentity: &mirrorv1alpha1.AWSWorkloadIdentityAuth{}},
			}
			t.Spec.WorkloadIdentity = &mirrorv1alpha1.WorkloadIdentity{
				AWS: &mirrorv1alpha1.AWSIdentity{RoleARN: exampleRoleARN, Region: exampleRegion},
			}
		})
		DeferCleanup(k8sClient.Delete, ctx, t)
		ecr := mirrorOf(name, "aws-ecr", ecrSource)
		plain := mirrorOf(name, "aws-plain", k8sHost)

		p := podOf(ecr)
		expectAWSToken(p)
		Expect(volume(p, tokenVolume)).To(BeNil())
		Expect(volume(p, "target-auth")).NotTo(BeNil())
		Expect(p.ServiceAccountName).To(Equal(SyncServiceAccount))
		s := specOf(ecr)
		Expect(s.SourceAuth).To(Equal(syncspec.AuthAWSWorkloadIdentity))
		Expect(s.TargetAuth).To(BeEmpty())
		Expect(*s.AWS).To(Equal(syncspec.AWS{RoleARN: exampleRoleARN, Region: exampleRegion}))
		Expect(s.Azure).To(BeNil())

		p = podOf(plain)
		Expect(volume(p, awsVolume)).To(BeNil())
		s = specOf(plain)
		Expect(s.SourceAuth).To(BeEmpty())
		Expect(s.AWS).To(BeNil())
	})

	It("mounts both tokens when the push uses AWS and the pull Azure", func() {
		const name = "tgt-aws-both"
		t := createReadyTarget(name, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			useAWS(t)
			t.Spec.AllowedSources = append(t.Spec.AllowedSources, azureSource)
			t.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: azureSource, AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}},
			}
			t.Spec.WorkloadIdentity.Azure = &mirrorv1alpha1.AzureIdentity{ClientID: zeroGUID, TenantID: zeroGUID}
		})
		DeferCleanup(k8sClient.Delete, ctx, t)
		both := mirrorOf(name, "aws-both", azureSource)
		push := mirrorOf(name, "aws-push", k8sHost)

		p := podOf(both)
		expectAWSToken(p)
		expectProjected(p, tokenVolume, "api://AzureADTokenExchange")
		Expect(volume(p, "target-auth")).To(BeNil())
		Expect(p.ServiceAccountName).To(Equal("tagwarden-sync-aws"))
		s := specOf(both)
		Expect(s.TargetAuth).To(Equal(syncspec.AuthAWSWorkloadIdentity))
		Expect(s.SourceAuth).To(Equal(syncspec.AuthAzureWorkloadIdentity))
		Expect(s.AWS).NotTo(BeNil())
		Expect(s.Azure).NotTo(BeNil())

		p = podOf(push)
		expectAWSToken(p)
		Expect(volume(p, tokenVolume)).To(BeNil())
		Expect(specOf(push).Azure).To(BeNil())
	})

	It("is not Ready when AWS auth has no AWS identity", func() {
		const name = "tgt-aws-missing"
		for _, s := range targetSecrets(name) {
			Expect(k8sClient.Create(ctx, s)).To(Succeed())
		}
		t := newTarget(name)
		t.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
			{Registry: ecrSource, AWSWorkloadIdentity: &mirrorv1alpha1.AWSWorkloadIdentityAuth{}},
		}
		t.Spec.WorkloadIdentity = &mirrorv1alpha1.WorkloadIdentity{
			Azure: &mirrorv1alpha1.AzureIdentity{ClientID: zeroGUID, TenantID: zeroGUID},
		}
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, t)
		Eventually(func() *metav1.Condition { return targetReady(name) }).Should(And(
			HaveField("Status", metav1.ConditionFalse), HaveField("Reason", ReasonInvalidSpec),
			HaveField("Message", ContainSubstring("spec.workloadIdentity.aws"))))
	})

	It("mounts the GCP token only in pods of Artifact Registry sources", func() {
		const name = "tgt-gcp-source"
		t := createReadyTarget(name, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.AllowedSources = append(t.Spec.AllowedSources, garSource)
			t.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: garSource, GCPWorkloadIdentity: &mirrorv1alpha1.GCPWorkloadIdentityAuth{}},
			}
			t.Spec.WorkloadIdentity = &mirrorv1alpha1.WorkloadIdentity{
				GCP: &mirrorv1alpha1.GCPIdentity{Audience: exampleGCPAudience},
			}
		})
		DeferCleanup(k8sClient.Delete, ctx, t)
		gar := mirrorOf(name, "gcp-gar", garSource)
		plain := mirrorOf(name, "gcp-plain", k8sHost)

		p := podOf(gar)
		expectGCPToken(p)
		Expect(volume(p, tokenVolume)).To(BeNil())
		Expect(volume(p, awsVolume)).To(BeNil())
		Expect(volume(p, "target-auth")).NotTo(BeNil())
		Expect(p.ServiceAccountName).To(Equal(SyncServiceAccount))
		s := specOf(gar)
		Expect(s.SourceAuth).To(Equal(syncspec.AuthGCPWorkloadIdentity))
		Expect(s.TargetAuth).To(BeEmpty())
		Expect(*s.GCP).To(Equal(syncspec.GCP{Audience: exampleGCPAudience}))

		p = podOf(plain)
		Expect(volume(p, gcpVolume)).To(BeNil())
		s = specOf(plain)
		Expect(s.SourceAuth).To(BeEmpty())
		Expect(s.GCP).To(BeNil())
	})

	It("mounts one token per provider when a target uses all three", func() {
		const name = "tgt-gcp-all"
		const email = "tagwarden-sync@example-project.iam.gserviceaccount.com"
		t := createReadyTarget(name, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			useGCP(t)
			t.Spec.WorkloadIdentity.GCP.ServiceAccountEmail = email
			t.Spec.AllowedSources = append(t.Spec.AllowedSources, azureSource, ecrSource)
			t.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
				{Registry: azureSource, AzureWorkloadIdentity: &mirrorv1alpha1.AzureWorkloadIdentityAuth{}},
				{Registry: ecrSource, AWSWorkloadIdentity: &mirrorv1alpha1.AWSWorkloadIdentityAuth{}},
			}
			t.Spec.WorkloadIdentity.Azure = &mirrorv1alpha1.AzureIdentity{ClientID: zeroGUID, TenantID: zeroGUID}
			t.Spec.WorkloadIdentity.AWS = &mirrorv1alpha1.AWSIdentity{RoleARN: exampleRoleARN, Region: exampleRegion}
		})
		DeferCleanup(k8sClient.Delete, ctx, t)
		fromAzure := mirrorOf(name, "all-azure", azureSource)
		fromECR := mirrorOf(name, "all-ecr", ecrSource)
		push := mirrorOf(name, "all-push", k8sHost)

		p := podOf(fromAzure)
		expectGCPToken(p)
		expectProjected(p, tokenVolume, "api://AzureADTokenExchange")
		Expect(volume(p, awsVolume)).To(BeNil())
		Expect(p.ServiceAccountName).To(Equal("tagwarden-sync-gcp"))
		s := specOf(fromAzure)
		Expect(s.TargetAuth).To(Equal(syncspec.AuthGCPWorkloadIdentity))
		Expect(s.SourceAuth).To(Equal(syncspec.AuthAzureWorkloadIdentity))
		Expect(*s.GCP).To(Equal(syncspec.GCP{Audience: exampleGCPAudience, ServiceAccountEmail: email}))
		Expect(s.Azure).NotTo(BeNil())
		Expect(s.AWS).To(BeNil())

		p = podOf(fromECR)
		expectGCPToken(p)
		expectAWSToken(p)
		Expect(volume(p, tokenVolume)).To(BeNil())
		Expect(specOf(fromECR).Azure).To(BeNil())

		p = podOf(push)
		expectGCPToken(p)
		Expect(volume(p, tokenVolume)).To(BeNil())
		Expect(volume(p, awsVolume)).To(BeNil())
		Expect(volume(p, "target-auth")).To(BeNil())
	})

	It("is not Ready when GCP auth has no GCP identity", func() {
		const name = "tgt-gcp-missing"
		for _, s := range targetSecrets(name) {
			Expect(k8sClient.Create(ctx, s)).To(Succeed())
		}
		t := newTarget(name)
		t.Spec.SourceCredentials = []mirrorv1alpha1.SourceCredential{
			{Registry: garSource, GCPWorkloadIdentity: &mirrorv1alpha1.GCPWorkloadIdentityAuth{}},
		}
		t.Spec.WorkloadIdentity = &mirrorv1alpha1.WorkloadIdentity{
			AWS: &mirrorv1alpha1.AWSIdentity{RoleARN: exampleRoleARN, Region: exampleRegion},
		}
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, t)
		Eventually(func() *metav1.Condition { return targetReady(name) }).Should(And(
			HaveField("Status", metav1.ConditionFalse), HaveField("Reason", ReasonInvalidSpec),
			HaveField("Message", ContainSubstring("spec.workloadIdentity.gcp"))))
	})
})
