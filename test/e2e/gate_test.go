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
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
	"github.com/r-gawronski/tagwarden/test/utils"
)

// Scenarios of step 8 of docs/design/vulnerability-gate.md. Run with
// make test-e2e-gate.
var _ = Describe("Vulnerability gate", Ordered, ContinueOnFailure, Label("gate"), func() {
	var (
		ca      *testCA
		dstHost string
		dstOpts []remote.Option
	)

	SetDefaultEventuallyTimeout(3 * time.Minute)
	SetDefaultEventuallyPollingInterval(2 * time.Second)

	BeforeAll(func() {
		start := time.Now()
		removeLeftovers()
		ca = newTestCA()
		deployInfra(ca)
		createDBPullSecret()
		netpol, err := os.ReadFile("test/e2e/testdata/gate-netpol.yaml")
		Expect(err).NotTo(HaveOccurred())
		kubectlApply(netpol)
		dstOpts = ca.remoteOpts(true)

		By("seeding the source of the user mirror")
		srcRepo, err := name.NewRepository(portForward("source") + "/e2e/app")
		Expect(err).NotTo(HaveOccurred())
		pushRelease(srcRepo, "1.0.0", ca.remoteOpts(false))

		By("pulling the pinned Trivy image on the kind nodes")
		pullOnNodes(trivyRepository + "@" + trivyDigest)

		By("installing the targets and mirrors, Trivy still off")
		gateHelm(false)
		syncFeeds()
		_, _ = fmt.Fprintf(GinkgoWriter, "gate setup: feeds synced after %s\n", time.Since(start))

		By("switching Trivy on; the server downloads the DB from the target registry")
		gateHelm(true)
		waitTrivyReady()
		_, _ = fmt.Fprintf(GinkgoWriter, "gate setup: Trivy ready after %s\n", time.Since(start))

		dstHost = portForward("target")
	})

	BeforeEach(func() {
		setGate(defaultGate())
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			dumpDiagnostics()
			for _, args := range [][]string{
				{"get", "statefulset,pods,pvc,networkpolicy", "-n", namespace, "-o", "wide"},
				{"logs", "-n", namespace, "pod/" + trivyServer + "-0", "--tail=100"},
				{"get", "vulnerabilityexceptions", "-o", "yaml"},
			} {
				out, err := utils.Run(exec.Command("kubectl", args...))
				_, _ = fmt.Fprintf(GinkgoWriter, "kubectl %s:\n%s\n%v\n", strings.Join(args, " "), out, err)
			}
		}
	})

	// run drives one pod through the gate and returns the settled mirror.
	// The target repository is emptied afterwards so the next spec sees the
	// tag as new.
	run := func(prefix string, img gateImage) (ns, pod string, m *mirrorv1alpha1.ArtifactMirror) {
		ns, pod = newTenant(prefix), "app"
		DeferCleanup(func() { purgeTarget(dstHost, img.targetPath(), dstOpts) })
		applyAnnotatedPod(ns, img)
		return ns, pod, awaitGatedRun(ns, img)
	}

	expectOnTarget := func(img gateImage, want bool) {
		GinkgoHelper()
		tags := targetTags(dstHost, img.targetPath(), dstOpts)
		if !want {
			Expect(tags).NotTo(ContainElement(img.tag))
			return
		}
		Expect(tags).To(ContainElement(img.tag))
		repo, err := name.NewRepository(dstHost + "/" + img.targetPath())
		Expect(err).NotTo(HaveOccurred())
		desc, err := remote.Head(repo.Tag(img.tag), dstOpts...)
		Expect(err).NotTo(HaveOccurred())
		Expect(desc.Digest.String()).To(Equal(img.digest), "digest on the target")
	}

	expectEvent := func(ns, pod, reason, typ, containing string) {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			evs := podEvents(ns, pod)[reason]
			g.Expect(evs).NotTo(BeEmpty(), "no %s Event", reason)
			g.Expect(evs[0].Type).To(Equal(typ))
			g.Expect(evs[0].Message).To(ContainSubstring(containing))
		}).Should(Succeed())
	}

	// ---- Independent of the rendering and status PRs ----

	It("serves the mirrored DB at the pinned version", func() {
		info := serverVersion()
		Expect(info.Version).To(Equal(trivyVersion))
		Expect(info.VulnerabilityDB.UpdatedAt).To(BeTemporally("~", time.Now(), 14*24*time.Hour))
		_, _ = fmt.Fprintf(GinkgoWriter, "DB UpdatedAt %s NextUpdate %s\n",
			info.VulnerabilityDB.UpdatedAt, info.VulnerabilityDB.NextUpdate)

		By("reporting the server on the target")
		Eventually(func(g Gomega) {
			t := getTarget(g)
			g.Expect(meta.IsStatusConditionTrue(t.Status.Conditions, "ScannerReady")).To(BeTrue())
			g.Expect(meta.IsStatusConditionTrue(t.Status.Conditions, "VulnerabilityDBReady")).To(BeTrue())
		}).Should(Succeed())
	})

	It("refuses a user mirror in the reserved project under Block", func() {
		setGate(map[string]any{"action": "Block"})
		kubectlApply([]byte(`{"apiVersion":"mirror.tagwarden.dev/v1alpha1","kind":"ArtifactMirror",` +
			`"metadata":{"name":"squatter","namespace":"` + e2eTeam + `"},"spec":{"targetRef":"` + gateTarget + `",` +
			`"schedule":"0 0 1 1 *","source":{"registry":"source.example.internal:5000","repository":"e2e/app"},` +
			`"target":{"project":"` + autoProject + `"},"tags":{"keepLatest":1}}}`))
		DeferCleanup(func() {
			_, _ = utils.Run(exec.Command("kubectl", "delete", "artifactmirror", "squatter", "-n", e2eTeam,
				"--ignore-not-found"))
		})
		Eventually(func(g Gomega) {
			c := condition(getMirror(g, e2eTeam, "squatter").Status.Conditions, "Ready")
			g.Expect(c).NotTo(BeNil())
			g.Expect(c.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(c.Reason).To(Equal("ProjectReservedForAutoMirror"))
		}).Should(Succeed())

		By("leaving the same mirror alone under Report")
		setGate(map[string]any{"action": "Report", "onScanError": "Report"})
		Eventually(func(g Gomega) {
			g.Expect(meta.IsStatusConditionTrue(getMirror(g, e2eTeam, "squatter").Status.Conditions, "Ready")).To(BeTrue())
		}).Should(Succeed())
	})

	// ---- Verdicts ----

	Describe("verdicts", func() {
		It("mirrors a vulnerable image under Report and tells the pod", func() {
			ns, pod, m := run("gate-report", vulnerableImage)
			Expect(meta.IsStatusConditionTrue(m.Status.Conditions, "Synced")).To(BeTrue())
			expectOnTarget(vulnerableImage, true)

			f := findingFor(m, vulnerableImage.tag)
			Expect(f).NotTo(BeNil(), "status.findings has no entry for %s", vulnerableImage.tag)
			Expect(f.Verdict).To(Equal(mirrorv1alpha1.VerdictFindings))
			Expect(f.Outcome).To(Equal(mirrorv1alpha1.OutcomeCopied))
			Expect(f.Severity).To(Equal(mirrorv1alpha1.SeverityCritical))
			Expect(f.TopIDs).To(ContainElement(vulnerableCVE))
			Expect(meta.IsStatusConditionTrue(m.Status.Conditions, "VulnerabilitiesFound")).To(BeTrue())
			Expect(condition(m.Status.Conditions, "VulnerabilityGate").Status).To(Equal(metav1.ConditionTrue))

			expectEvent(ns, pod, "VulnerabilitiesFound", corev1.EventTypeWarning, vulnerableCVE)
		})

		It("mirrors a clean image without findings or Events", func() {
			ns, pod, m := run("gate-clean", cleanImage)
			expectOnTarget(cleanImage, true)
			Expect(m.Status.Findings).To(BeEmpty())
			Expect(meta.IsStatusConditionTrue(m.Status.Conditions, "VulnerabilitiesFound")).To(BeFalse())
			Consistently(func() map[string][]corev1.Event { return podEvents(ns, pod) }, 15*time.Second).
				ShouldNot(Or(HaveKey("VulnerabilitiesFound"), HaveKey("MirrorRefused")))
		})

		It("refuses a vulnerable image under Block", func() {
			setGate(map[string]any{"action": "Block"})
			ns, pod, m := run("gate-block", vulnerableImage)
			expectOnTarget(vulnerableImage, false)

			f := findingFor(m, vulnerableImage.tag)
			Expect(f).NotTo(BeNil())
			Expect(f.Outcome).To(Equal(mirrorv1alpha1.OutcomeBlocked))
			Expect(f.TopIDs).To(ContainElement(vulnerableCVE))
			expectEvent(ns, pod, "MirrorRefused", corev1.EventTypeWarning, "VulnerabilityBlocked")
		})

		It("lets the image through with an exception for its namespace, and blocks again when it expires", func() {
			setGate(map[string]any{"action": "Block"})
			ns := newTenant("gate-exc")
			exName := "e2e-" + ns
			expires := time.Now().Add(3 * time.Minute).UTC().Format(time.RFC3339)
			ex, err := json.Marshal(map[string]any{
				"apiVersion": "mirror.tagwarden.dev/v1alpha1", "kind": "VulnerabilityException",
				"metadata": map[string]any{"name": exName},
				"spec": map[string]any{
					"targetRef": gateTarget, "namespaces": []string{ns},
					"repository": vulnerableImage.source(), "digests": []string{vulnerableImage.digest},
					"expires": expires, "approvedBy": "e2e-approver",
					"reason": "e2e: accept the busybox finding of the pinned test image",
				},
			})
			Expect(err).NotTo(HaveOccurred())
			kubectlApply(ex)
			DeferCleanup(func() {
				_, _ = utils.Run(exec.Command("kubectl", "delete", "vulnerabilityexception", exName, "--ignore-not-found"))
				purgeTarget(dstHost, vulnerableImage.targetPath(), dstOpts)
			})
			exceptionActive := func() metav1.ConditionStatus {
				out, err := utils.Run(exec.Command("kubectl", "get", "vulnerabilityexception", exName, "-o",
					`jsonpath={.status.conditions[?(@.type=="Active")].status}`))
				Expect(err).NotTo(HaveOccurred())
				return metav1.ConditionStatus(out)
			}
			Eventually(exceptionActive).Should(Equal(metav1.ConditionTrue))

			By("passing the gate while the exception is active")
			applyAnnotatedPod(ns, vulnerableImage)
			awaitGatedRun(ns, vulnerableImage)
			expectOnTarget(vulnerableImage, true)
			Expect(podEvents(ns, "app")).NotTo(HaveKey("MirrorRefused"))

			By("waiting for the exception to expire")
			Eventually(exceptionActive, 5*time.Minute).Should(Equal(metav1.ConditionFalse))

			By("blocking the same digest as a new tag on the target")
			purgeTarget(dstHost, vulnerableImage.targetPath(), dstOpts)
			runSyncIn(ns, vulnerableImage.generatedMirror(), "after-expiry", "Complete")
			Eventually(func(g Gomega) {
				f := findingFor(generated(g, ns, vulnerableImage), vulnerableImage.tag)
				g.Expect(f).NotTo(BeNil())
				g.Expect(f.Outcome).To(Equal(mirrorv1alpha1.OutcomeBlocked))
			}).Should(Succeed())
			expectOnTarget(vulnerableImage, false)
		})
	})

	// ---- Scanner outage, stale DB ----

	Describe("scanner failures", func() {
		It("reports a stopped server on the target while a user mirror keeps syncing", func() {
			_, err := utils.Run(exec.Command("kubectl", "scale", "statefulset", trivyServer, "-n", namespace, "--replicas=0"))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				_, _ = utils.Run(exec.Command("kubectl", "scale", "statefulset", trivyServer, "-n", namespace, "--replicas=1"))
				waitTrivyReady()
			})
			Eventually(func(g Gomega) {
				c := condition(getTarget(g).Status.Conditions, "ScannerReady")
				g.Expect(c).NotTo(BeNil())
				g.Expect(c.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(c.Reason).To(Equal("ScannerUnavailable"))
			}, 5*time.Minute).Should(Succeed())

			By("syncing the user mirror on the same target")
			runSyncIn(e2eTeam, "user-app", "user-app-outage", "Complete")
			Eventually(func(g Gomega) {
				c := condition(getMirror(g, e2eTeam, "user-app").Status.Conditions, "Synced")
				g.Expect(c).NotTo(BeNil())
				g.Expect(c.Status).To(Equal(metav1.ConditionTrue))
			}).Should(Succeed())
			Expect(targetTags(dstHost, "mirror/e2e/user-app", dstOpts)).To(ContainElement("1.0.0"))

			By("turning a generated mirror's scan into a scan error")
			setGate(map[string]any{"onScanError": "Block"})
			_, _, m := run("gate-outage", vulnerableImage)
			f := findingFor(m, vulnerableImage.tag)
			Expect(f).NotTo(BeNil())
			Expect(f.Verdict).To(Equal(mirrorv1alpha1.VerdictScanError))
			Expect(f.ScanError).To(Equal("ScannerUnavailable"))
			Expect(f.Outcome).To(Equal(mirrorv1alpha1.OutcomeBlocked))
		})

		It("treats a stale DB as a scan error under each onScanError", func() {
			By("pushing a copy of the DB that is 30 days old")
			pushStaleDB(dstHost, dstOpts)
			restartTrivyWithDB(staleDBTag)
			DeferCleanup(func() { restartTrivyWithDB("2") })
			Eventually(func(g Gomega) {
				c := condition(getTarget(g).Status.Conditions, "VulnerabilityDBReady")
				g.Expect(c).NotTo(BeNil())
				g.Expect(c.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(c.Reason).To(Equal("DBStale"))
			}, 5*time.Minute).Should(Succeed())

			By("copying the tag under onScanError Report")
			setGate(map[string]any{"onScanError": "Report"})
			_, _, m := run("gate-stale-report", cleanImage)
			f := findingFor(m, cleanImage.tag)
			Expect(f).NotTo(BeNil())
			Expect(f.Verdict).To(Equal(mirrorv1alpha1.VerdictScanError))
			Expect(f.ScanError).To(Equal("DBStale"))
			Expect(f.Outcome).To(Equal(mirrorv1alpha1.OutcomeCopied))
			expectOnTarget(cleanImage, true)
			purgeTarget(dstHost, cleanImage.targetPath(), dstOpts)

			By("not copying the tag under onScanError Block")
			setGate(map[string]any{"onScanError": "Block"})
			ns, pod, m := run("gate-stale-block", cleanImage)
			f = findingFor(m, cleanImage.tag)
			Expect(f).NotTo(BeNil())
			Expect(f.Outcome).To(Equal(mirrorv1alpha1.OutcomeBlocked))
			expectOnTarget(cleanImage, false)
			expectEvent(ns, pod, "MirrorRefused", corev1.EventTypeWarning, "DBStale")
		})

		It("is loud when no scanner is configured", func() {
			By("removing the chart's Trivy server and with it the manager's scanner flags")
			gateHelm(false)
			DeferCleanup(func() {
				gateHelm(true)
				waitTrivyReady()
			})
			Eventually(func(g Gomega) {
				c := condition(getTarget(g).Status.Conditions, "ScannerReady")
				g.Expect(c).NotTo(BeNil())
				g.Expect(c.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(c.Reason).To(Equal("NotConfigured"))
			}).Should(Succeed())

			By("flagging the generated mirror and warning, even under Report")
			ns, pod, m := run("gate-noscanner", vulnerableImage)
			gate := condition(m.Status.Conditions, "VulnerabilityGate")
			Expect(gate).NotTo(BeNil())
			Expect(gate.Status).To(Equal(metav1.ConditionFalse))
			Expect(gate.Reason).To(Equal("NotConfigured"))
			expectOnTarget(vulnerableImage, true) // copied unscanned, loudly
			Eventually(func(g Gomega) {
				out, err := utils.Run(exec.Command("kubectl", "get", "events", "-n", ns, "-o", "json",
					"--field-selector", "involvedObject.kind=ArtifactMirror,type=Warning"))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(ContainSubstring("NotConfigured"))
			}).Should(Succeed())
			Eventually(func(g Gomega) {
				g.Expect(podEvents(ns, pod)).To(HaveKey("VulnerabilityScanFailed"))
			}).Should(Succeed())

			By("refusing to render a CronJob under Block")
			setGate(map[string]any{"action": "Block", "onScanError": "Block"})
			ns2 := newTenant("gate-noscanner-block")
			applyAnnotatedPod(ns2, cleanImage)
			Eventually(func(g Gomega) {
				c := condition(generated(g, ns2, cleanImage).Status.Conditions, "Ready")
				g.Expect(c).NotTo(BeNil())
				g.Expect(c.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(c.Reason).To(Equal("ScannerUnavailable"))
			}).Should(Succeed())
			_, err := utils.Run(exec.Command("kubectl", "get", "cronjob",
				cronJobName(ns2, cleanImage.generatedMirror()), "-n", namespace))
			Expect(err).To(MatchError(ContainSubstring("NotFound")))
			// Not asserted: the gauge tagwarden_vulnerability_gate_unscanned{target}
			// is 1 here. Reading it needs the authenticated metrics endpoint (see
			// the Manager spec) and is left for a follow-up.
		})
	})

	// ---- Cases the step 6 and 7 author asked to verify ----

	Describe("sidecar", func() {
		// sidecarOf returns the scanner container of the CronJob of a
		// generated mirror: a native sidecar, an init container with
		// restartPolicy Always.
		sidecarOf := func(ns string, img gateImage) (corev1.Container, corev1.PodSpec) {
			GinkgoHelper()
			var cj batchv1.CronJob
			Eventually(func(g Gomega) {
				out, err := utils.Run(exec.Command("kubectl", "get", "cronjob",
					cronJobName(ns, img.generatedMirror()), "-n", namespace, "-o", "json"))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(json.Unmarshal([]byte(out), &cj)).To(Succeed())
			}).Should(Succeed())
			for _, c := range cj.Spec.JobTemplate.Spec.Template.Spec.InitContainers {
				if c.Name == "scanner" {
					return c, cj.Spec.JobTemplate.Spec.Template.Spec
				}
			}
			Fail("the CronJob has no scanner sidecar")
			return corev1.Container{}, corev1.PodSpec{}
		}

		It("starts as 65532 with a read-only root and takes the report template from the environment", func() {
			ns := newTenant("gate-sidecar")
			DeferCleanup(func() { purgeTarget(dstHost, cleanImage.targetPath(), dstOpts) })
			applyAnnotatedPod(ns, cleanImage)

			By("checking the rendered container")
			sc, podSpec := sidecarOf(ns, cleanImage)
			Expect(sc.Image).To(HaveSuffix("@" + trivyDigest))
			Expect(sc.SecurityContext).NotTo(BeNil())
			Expect(sc.SecurityContext.ReadOnlyRootFilesystem).To(HaveValue(BeTrue()))
			Expect(sc.SecurityContext.AllowPrivilegeEscalation).To(HaveValue(BeFalse()))
			Expect(sc.SecurityContext.Capabilities.Drop).To(ConsistOf(corev1.Capability("ALL")))
			// The Trivy image has no USER: the user comes from the pod.
			Expect(podSpec.SecurityContext.RunAsUser).To(HaveValue(BeEquivalentTo(65532)))
			Expect(podSpec.SecurityContext.RunAsNonRoot).To(HaveValue(BeTrue()))
			Expect(sc.Command).To(Equal([]string{"/bin/sh", "-c", syncspec.SidecarScript}))
			var tmpl string
			for _, e := range sc.Env {
				if e.Name == syncspec.ScannerTemplateEnv {
					tmpl = e.Value
				}
			}
			Expect(tmpl).NotTo(BeEmpty(), "%s is not set", syncspec.ScannerTemplateEnv)
			Expect(syncspec.SidecarScript).To(ContainSubstring(`--template "$TAGWARDEN_REPORT_TEMPLATE"`))
			Expect(syncspec.SidecarScript).NotTo(ContainSubstring("@"+syncspec.ScanDir),
				"the template must be inline, not read from a file")

			By("checking the running container while the Job is alive")
			// Best effort: the Job is short. Poll fast for a Running scanner.
			Eventually(func(g Gomega) {
				out, err := utils.Run(exec.Command("kubectl", "exec", "-n", namespace, "-c", "scanner",
					podOfMirror(ns, cleanImage), "--", "sh", "-c",
					`id -u; touch /probe 2>&1 | head -1; test -n "$TAGWARDEN_REPORT_TEMPLATE" && echo template-from-env`))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(ContainSubstring("65532"))
				g.Expect(out).To(ContainSubstring("Read-only file system"))
				g.Expect(out).To(ContainSubstring("template-from-env"))
			}, 3*time.Minute, 500*time.Millisecond).Should(Succeed())
			awaitGatedRun(ns, cleanImage)
		})

		It("deletes the Job and reports ScannerUnavailable when the sidecar image cannot be pulled", func() {
			// The e2e chart values set --scanner-start-timeout to 60s.
			missing := trivyRepository + "@sha256:" + strings.Repeat("0", 64)
			setGate(map[string]any{"scanner": map[string]any{"image": missing, "version": trivyVersion}})
			ns := newTenant("gate-nopull")
			DeferCleanup(func() { purgeTarget(dstHost, cleanImage.targetPath(), dstOpts) })
			applyAnnotatedPod(ns, cleanImage)
			Eventually(func(g Gomega) {
				waiting := []string{}
				for _, p := range syncPods(ns, cleanImage) {
					for _, cs := range p.Status.InitContainerStatuses {
						if cs.State.Waiting != nil {
							waiting = append(waiting, cs.State.Waiting.Reason)
						}
					}
				}
				g.Expect(waiting).To(ContainElement(BeElementOf("ErrImagePull", "ImagePullBackOff")))
			}, 2*time.Minute).Should(Succeed())
			By("reporting once the grace period has passed")
			mirror := cleanImage.generatedMirror()
			notStarted := `^scanner sidecar did not start \((ErrImagePull|ImagePullBackOff)\); sync Job deleted, nothing copied$`
			Eventually(func() *metav1.Condition {
				return meta.FindStatusCondition(getMirror(Default, ns, mirror).Status.Conditions, "VulnerabilityGate")
			}, 3*time.Minute).Should(And(HaveField("Status", metav1.ConditionFalse), HaveField("Reason", "ScannerUnavailable"),
				HaveField("Message", MatchRegexp(notStarted))))
			Eventually(func(g Gomega) {
				evs := objectEvents(ns, "ArtifactMirror", mirror)["ScannerUnavailable"]
				g.Expect(evs).NotTo(BeEmpty())
				g.Expect(evs[0].Message).To(ContainSubstring("scanner sidecar did not start"))
			}).Should(Succeed())
			Eventually(func(g Gomega) {
				// An earlier scanner probe may have left its own Event of this reason.
				msgs := []string{}
				for _, e := range podEvents(ns, "app")["VulnerabilityScanFailed"] {
					msgs = append(msgs, e.Message)
				}
				g.Expect(msgs).To(ContainElement(ContainSubstring("scanner sidecar did not start")))
			}).Should(Succeed())
			Expect(targetTags(dstHost, cleanImage.targetPath(), dstOpts)).To(BeEmpty())
		})

		DescribeTable("handles a missing token Secret as ScanFailed",
			func(onScanError string, wantCopied bool) {
				setGate(map[string]any{"onScanError": onScanError,
					"scanner": map[string]any{"tokenSecretRef": map[string]any{"name": "no-such-token"}}})
				ns, pod, m := run("gate-notoken", cleanImage)
				f := findingFor(m, cleanImage.tag)
				Expect(f).NotTo(BeNil())
				Expect(f.Verdict).To(Equal(mirrorv1alpha1.VerdictScanError))
				Expect(f.ScanError).To(Equal("ScanFailed"))
				expectOnTarget(cleanImage, wantCopied)
				if wantCopied {
					expectEvent(ns, "app", "VulnerabilityScanFailed", corev1.EventTypeWarning, "ScanFailed")
				} else {
					expectEvent(ns, pod, "MirrorRefused", corev1.EventTypeWarning, "ScanFailed")
				}
			},
			Entry("under Report the tag is copied", "Report", true),
			Entry("under Block the tag is not copied", "Block", false),
		)
	})
})

// syncPods returns the sync pods of the generated mirror of an image in a
// namespace, oldest first.
func syncPods(ns string, img gateImage) []corev1.Pod {
	out, err := utils.Run(exec.Command("kubectl", "get", "pods", "-n", namespace, "-o", "json",
		"--sort-by=.metadata.creationTimestamp"))
	if err != nil {
		return nil
	}
	var list corev1.PodList
	if json.Unmarshal([]byte(out), &list) != nil {
		return nil
	}
	var pods []corev1.Pod
	for _, p := range list.Items {
		if p.Annotations["tagwarden.dev/mirror-namespace"] == ns &&
			p.Annotations["tagwarden.dev/mirror-name"] == img.generatedMirror() {
			pods = append(pods, p)
		}
	}
	return pods
}

// podOfMirror returns the newest sync pod name, or "" before one exists. The
// caller polls, so an empty result is a failed attempt, not a failed spec.
func podOfMirror(ns string, img gateImage) string {
	pods := syncPods(ns, img)
	if len(pods) == 0 {
		return ""
	}
	return pods[len(pods)-1].Name
}
