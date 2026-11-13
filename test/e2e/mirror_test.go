//go:build e2e

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

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/test/utils"
)

// The mirror tests run a source registry, a target registry and a Squid
// proxy in e2e-infra. NetworkPolicies let the sync pods reach only DNS, the
// proxy and the target, and only the proxy reaches the source.
var _ = Describe("Mirroring", Ordered, Label("mirror"), func() {
	var (
		ca               *testCA
		srcRepo, dstRepo name.Repository
		srcOpts, dstOpts []remote.Option
		releases         = map[string]v1.Hash{}
	)

	SetDefaultEventuallyTimeout(3 * time.Minute)
	SetDefaultEventuallyPollingInterval(2 * time.Second)

	BeforeAll(func() {
		removeLeftovers()
		ca = newTestCA()

		var err error
		deployInfra(ca)

		By("seeding the source with three releases")
		srcRepo, err = name.NewRepository(portForward("source") + "/e2e/app")
		Expect(err).NotTo(HaveOccurred())
		dstRepo, err = name.NewRepository(portForward("target") + "/mirror/e2e/app")
		Expect(err).NotTo(HaveOccurred())
		srcOpts, dstOpts = ca.remoteOpts(false), ca.remoteOpts(true)
		for _, tag := range []string{"1.0.0", "1.1.0", "1.2.0"} {
			releases[tag] = pushRelease(srcRepo, tag, srcOpts)
		}

		By("adding the targets and mirrors with a second helm upgrade")
		_, err = utils.Run(exec.Command("helm", "upgrade", helmRelease, "dist/chart", "--namespace", namespace,
			"--reuse-values", "-f", "test/e2e/testdata/values-mirrors.yaml", "--wait=legacy", "--timeout", "3m"))
		Expect(err).NotTo(HaveOccurred())

		for _, m := range []string{"app", "app-direct"} {
			Eventually(func(g Gomega) {
				g.Expect(meta.IsStatusConditionTrue(getMirror(g, e2eTeam, m).Status.Conditions, "Ready")).To(BeTrue())
			}).Should(Succeed(), "mirror %s is not Ready", m)
		}
	})

	syncedTags := func(tags ...string) []mirrorv1alpha1.SyncedTag {
		out := make([]mirrorv1alpha1.SyncedTag, 0, len(tags))
		for _, t := range tags {
			out = append(out, mirrorv1alpha1.SyncedTag{Tag: t, Digest: releases[t].String()})
		}
		return out
	}

	// expectTargetHoldsTags checks that the target has exactly the tags, by
	// the source digests, each with its signature referrer.
	expectTargetHoldsTags := func(tags ...string) {
		listed, err := remote.List(dstRepo, dstOpts...)
		Expect(err).NotTo(HaveOccurred())
		Expect(listed).To(ConsistOf(tags))
		for _, tag := range tags {
			desc, err := remote.Head(dstRepo.Tag(tag), dstOpts...)
			Expect(err).NotTo(HaveOccurred())
			Expect(desc.Digest).To(Equal(releases[tag]), "digest of %s", tag)
			idx, err := remote.Referrers(dstRepo.Digest(desc.Digest.String()), dstOpts...)
			Expect(err).NotTo(HaveOccurred())
			im, err := idx.IndexManifest()
			Expect(err).NotTo(HaveOccurred())
			Expect(slices.ContainsFunc(im.Manifests, func(d v1.Descriptor) bool {
				return d.ArtifactType == sigArtifactType
			})).To(BeTrue(), "referrer of %s", tag)
		}
	}

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			dumpDiagnostics()
		}
	})

	expectSynced := func(mirror string, status metav1.ConditionStatus, reason string) *mirrorv1alpha1.ArtifactMirror {
		var m *mirrorv1alpha1.ArtifactMirror
		EventuallyWithOffset(1, func(g Gomega) {
			m = getMirror(g, e2eTeam, mirror)
			c := meta.FindStatusCondition(m.Status.Conditions, "Synced")
			g.Expect(c).NotTo(BeNil())
			g.Expect(c.Status).To(Equal(status))
			g.Expect(c.Reason).To(Equal(reason))
		}).Should(Succeed())
		return m
	}

	It("mirrors the latest releases with their referrers through the proxy", func() {
		runSync("app", "app-1", "Complete")
		m := expectSynced("app", metav1.ConditionTrue, "Synced")
		Expect(m.Status.Synced).To(Equal(syncedTags("1.2.0", "1.1.0")))
		expectTargetHoldsTags("1.1.0", "1.2.0")
	})

	It("lets sync pods reach the source only through the proxy", func() {
		By("probing from a pod that the sync NetworkPolicy selects")
		const probe = "egress-probe"
		// kindnet adds a new pod to its policy sets asynchronously, so the
		// first packets of a fresh pod can pass. Retry until a direct
		// connection times out (curl exit 28), for up to about 30s.
		script := fmt.Sprintf(`set -u
url=https://source.example.internal:5000/v2/
blocked=
for i in $(seq 1 6); do
  curl -sS --max-time 3 --cacert /ca/ca.crt --resolve source.example.internal:5000:%s "$url"
  if [ $? -eq 28 ]; then blocked=1; break; fi
  sleep 2
done
[ -n "$blocked" ] || { echo "direct connection to the source was never blocked"; exit 1; }
curl -sSf --max-time 20 --cacert /ca/ca.crt --proxy http://proxy.e2e-infra.svc.cluster.local:3128 \
  --proxy-user "$PROXY_USER:$PROXY_PASSWORD" "$url"`, sourceIP)
		pod := map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": probe, "namespace": namespace,
				"labels": map[string]string{"tagwarden.dev/mirror": "probe"}},
			"spec": map[string]any{
				"restartPolicy":                "Never",
				"automountServiceAccountToken": false,
				"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532,
					"seccompProfile": map[string]string{"type": "RuntimeDefault"}},
				"containers": []any{map[string]any{
					"name": "probe", "image": probeImage, "command": []string{"sh", "-c", script},
					"env": []any{
						secretEnv("PROXY_USER", corev1.BasicAuthUsernameKey),
						secretEnv("PROXY_PASSWORD", corev1.BasicAuthPasswordKey),
					},
					"securityContext": map[string]any{"allowPrivilegeEscalation": false,
						"readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}},
					"volumeMounts": []any{map[string]any{"name": "ca", "mountPath": "/ca", "readOnly": true}},
				}},
				"volumes": []any{map[string]any{"name": "ca", "secret": map[string]string{"secretName": "e2e-ca"}}},
			},
		}
		b, err := json.Marshal(pod)
		Expect(err).NotTo(HaveOccurred())
		kubectlApply(b)
		DeferCleanup(func() {
			_, _ = utils.Run(exec.Command("kubectl", "delete", "pod", probe, "-n", namespace, "--ignore-not-found"))
		})
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "pod", probe, "-n", namespace,
				"-o", "jsonpath={.status.phase}"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(BeElementOf("Succeeded", "Failed"))
		}).Should(Succeed())
		logs, _ := utils.Run(exec.Command("kubectl", "logs", probe, "-n", namespace))
		phase, err := utils.Run(exec.Command("kubectl", "get", "pod", probe, "-n", namespace,
			"-o", "jsonpath={.status.phase}"))
		Expect(err).NotTo(HaveOccurred())
		Expect(phase).To(Equal("Succeeded"), "probe output:\n%s", logs)
	})

	It("fails the same mirror without the proxy", func() {
		runSync("app-direct", "app-direct-1", "Failed")
		m := expectSynced("app-direct", metav1.ConditionFalse, "SyncFailed")
		Expect(m.Status.Synced).To(BeEmpty())
		// Cluster DNS cannot resolve the source; only the proxy can.
		Expect(meta.FindStatusCondition(m.Status.Conditions, "Synced").Message).To(
			ContainSubstring("resolve source.example.internal"))
		_, err := remote.List(dstRepo.Repo("mirror", "e2e", "app-direct"), dstOpts...)
		Expect(err).To(HaveOccurred(), "the target must not hold the direct mirror")
	})

	It("moves the keepLatest window when the source gets a newer release", func() {
		releases["1.3.0"] = pushRelease(srcRepo, "1.3.0", srcOpts)
		runSync("app", "app-2", "Complete")
		Eventually(func(g Gomega) {
			g.Expect(getMirror(g, e2eTeam, "app").Status.Synced).To(Equal(syncedTags("1.3.0", "1.2.0")))
		}).Should(Succeed())
		// Tags that leave the window stay on the target.
		expectTargetHoldsTags("1.1.0", "1.2.0", "1.3.0")
	})

	DescribeTable("refuses a mirror the target does not allow",
		func(mirror, mirrorNamespace, registry, reason string) {
			kubectlApply(fmt.Appendf(nil, `{"apiVersion":"mirror.tagwarden.dev/v1alpha1","kind":"ArtifactMirror",`+
				`"metadata":{"name":%q,"namespace":%q},"spec":{"targetRef":"e2e-proxy","schedule":"@daily",`+
				`"source":{"registry":%q,"repository":"e2e/app"},"target":{"project":"mirror","repository":%q},`+
				`"tags":{"keepLatest":1}}}`, mirror, mirrorNamespace, registry, mirror))
			Eventually(func(g Gomega) {
				c := meta.FindStatusCondition(getMirror(g, mirrorNamespace, mirror).Status.Conditions, "Ready")
				g.Expect(c).NotTo(BeNil())
				g.Expect(c.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(c.Reason).To(Equal(reason))
			}).Should(Succeed())
			_, err := utils.Run(exec.Command("kubectl", "get", "cronjob", cronJobName(mirrorNamespace, mirror),
				"-n", namespace))
			Expect(err).To(MatchError(ContainSubstring("NotFound")))
		},
		Entry("project not allowed for the namespace", "other-team", e2eOther,
			"source.example.internal:5000", "ProjectNotAllowed"),
		Entry("source not in allowedSources", "unlisted-source", e2eTeam, "registry.example.com", "SourceNotAllowed"),
	)

	It("mirrors from a real registry through the proxy", func() {
		if os.Getenv("E2E_INTERNET") != "1" {
			Skip("set E2E_INTERNET=1 to mirror registry.k8s.io/pause through the proxy")
		}
		kubectlApply([]byte(`{"apiVersion":"mirror.tagwarden.dev/v1alpha1","kind":"ArtifactMirror",` +
			`"metadata":{"name":"pause","namespace":"` + e2eTeam + `"},"spec":{"targetRef":"e2e-proxy",` +
			`"schedule":"0 0 1 1 *","source":{"registry":"registry.k8s.io","repository":"pause"},` +
			`"target":{"project":"mirror","repository":"e2e/pause"},"tags":{"tags":["3.10"]}}}`))
		Eventually(func(g Gomega) {
			g.Expect(meta.IsStatusConditionTrue(getMirror(g, e2eTeam, "pause").Status.Conditions, "Ready")).To(BeTrue())
		}).Should(Succeed())
		runSync("pause", "pause-1", "Complete")
		m := expectSynced("pause", metav1.ConditionTrue, "Synced")
		Expect(m.Status.Synced).To(HaveLen(1))
		desc, err := remote.Head(dstRepo.Repo("mirror", "e2e", "pause").Tag("3.10"), dstOpts...)
		Expect(err).NotTo(HaveOccurred())
		Expect(desc.Digest.String()).To(Equal(m.Status.Synced[0].Digest))
	})
})

func secretEnv(env, key string) map[string]any {
	return map[string]any{"name": env, "valueFrom": map[string]any{
		"secretKeyRef": map[string]string{"name": "proxy-auth", "key": key}}}
}
