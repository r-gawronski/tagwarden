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
	"crypto/rand"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r-gawronski/tagwarden/internal/sbom"
	"github.com/r-gawronski/tagwarden/test/utils"
)

// cycloneDX is the artifactType of a CycloneDX SBOM referrer.
const cycloneDX = "application/vnd.cyclonedx+json"

// Scenarios of step 6 of docs/design/sbom.md. The generator is the pinned
// Trivy image, pulled on the nodes like in the gate tests. It needs no
// network and no vulnerability DB, so these tests run with make test-e2e.
var _ = Describe("SBOM generation", Ordered, Label("sbom"), func() {
	var (
		ca               *testCA
		srcHost, dstHost string
		srcOpts, dstOpts []remote.Option
		app              v1.Hash
		appChildren      []v1.Hash
	)

	SetDefaultEventuallyTimeout(3 * time.Minute)
	SetDefaultEventuallyPollingInterval(2 * time.Second)

	BeforeAll(func() {
		removeLeftovers()
		ca = newTestCA()
		deployInfra(ca)
		srcHost, dstHost = portForward("source"), portForward("target")
		srcOpts, dstOpts = ca.remoteOpts(false), ca.remoteOpts(true)

		By("seeding a two-platform image and one whose arm64 layer is not a tar archive")
		app, appChildren = pushSBOMIndex(srcHost+"/e2e/sbom-app", srcOpts, false)
		pushSBOMIndex(srcHost+"/e2e/sbom-broken", srcOpts, true)

		By("pulling the pinned Trivy image on the kind nodes")
		pullOnNodes(trivyRepository + "@" + trivyDigest)

		By("adding the SBOM targets and mirrors, with the chart's Trivy image as generator")
		_, err := utils.Run(exec.Command("helm", "upgrade", helmRelease, "dist/chart", "--namespace", namespace,
			"--reuse-values", "-f", "test/e2e/testdata/values-sbom.yaml",
			"--set", "trivy.enabled=false",
			"--set", "trivy.image.repository="+trivyRepository,
			"--set", "trivy.image.tag="+trivyVersion,
			"--set", "trivy.image.digest="+trivyDigest,
			"--wait=legacy", "--timeout", "3m"))
		Expect(err).NotTo(HaveOccurred())
		for _, m := range []string{"sbom-app", "sbom-broken", "sbom-later"} {
			Eventually(func(g Gomega) {
				g.Expect(meta.IsStatusConditionTrue(getMirror(g, e2eTeam, m).Status.Conditions, "Ready")).To(BeTrue())
			}).Should(Succeed(), "mirror %s is not Ready", m)
		}
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			dumpDiagnostics()
		}
	})

	sbomCondition := func(mirror string) func(g Gomega) *metav1.Condition {
		return func(g Gomega) *metav1.Condition {
			return meta.FindStatusCondition(getMirror(g, e2eTeam, mirror).Status.Conditions, "SBOM")
		}
	}

	It("attaches a CycloneDX referrer to each platform and copies on the index", func() {
		out, err := utils.Run(exec.Command("kubectl", "get", "cronjob", cronJobName(e2eTeam, "sbom-app"), "-n", namespace,
			"-o", "jsonpath={.spec.jobTemplate.spec.template.spec.initContainers[0].name}"))
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(Equal("sbom"))

		runSync("sbom-app", "sbom-app-1", "Complete")
		repo := dstHost + "/sbom/e2e/sbom-app"
		Expect(headDigest(repo+":1.0.0", dstOpts)).To(Equal(app), "the index is mirrored digest-identical")
		for _, child := range appChildren {
			refs := sbomReferrers(repo, child, dstOpts)
			Expect(refs).To(HaveLen(1), "SBOMs of %s", child)
			Expect(refs[0].Annotations).To(And(
				HaveKeyWithValue(sbom.AnnotationGenerator, "trivy/"+trivyVersion),
				HaveKeyWithValue(sbom.AnnotationFormat, "CycloneDX"),
				Not(HaveKey(sbom.AnnotationPlatform))))
			doc := sbomDocument(repo, refs[0], dstOpts)
			Expect(doc).To(HaveKeyWithValue("bomFormat", "CycloneDX"))
		}
		copies := sbomReferrers(repo, app, dstOpts)
		Expect(copies).To(HaveLen(2), "one copy per platform on the index")
		platforms := make([]string, 0, len(copies))
		for _, c := range copies {
			platforms = append(platforms, c.Annotations[sbom.AnnotationPlatform])
		}
		Expect(platforms).To(ConsistOf("linux/amd64", "linux/arm64"))

		Eventually(sbomCondition("sbom-app")).Should(And(
			HaveField("Status", metav1.ConditionTrue), HaveField("Reason", "Attached")))
	})

	It("publishes nothing when the generator fails under required: true, and says why", func() {
		runSync("sbom-broken", "sbom-broken-1", "Failed")
		Expect(targetTags(dstHost, "sbom/e2e/sbom-broken", dstOpts)).NotTo(ContainElement("1.0.0"))
		Eventually(sbomCondition("sbom-broken")).Should(And(
			HaveField("Status", metav1.ConditionFalse), HaveField("Reason", "GenerationFailed"),
			HaveField("Message", HavePrefix("not published: 1.0.0@sha256:"))))
		Eventually(func(g Gomega) {
			c := meta.FindStatusCondition(getMirror(g, e2eTeam, "sbom-broken").Status.Conditions, "Synced")
			g.Expect(c).NotTo(BeNil())
			g.Expect(c.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(c.Message).To(ContainSubstring("SBOM failed for 1"))
		}).Should(Succeed())
		Eventually(func(g Gomega) {
			evs := objectEvents(e2eTeam, "ArtifactMirror", "sbom-broken")["SBOMFailed"]
			g.Expect(evs).To(HaveLen(1))
			g.Expect(evs[0].Message).To(ContainSubstring("SBOM GenerationFailed, not published"))
		}).Should(Succeed())
	})

	It("does not let an ArtifactMirror weaken the target policy", func() {
		mirror := []byte(`{"apiVersion":"mirror.tagwarden.dev/v1alpha1","kind":"ArtifactMirror",` +
			`"metadata":{"name":"sbom-off","namespace":"` + e2eTeam + `"},"spec":{"targetRef":"e2e-sbom",` +
			`"schedule":"0 0 1 1 *","source":{"registry":"source.example.internal:5000","repository":"e2e/sbom-app"},` +
			`"target":{"project":"sbom","repository":"e2e/sbom-off"},"tags":{"tags":["1.0.0"]},` +
			`"sbom":{"mode":"Disabled","required":false}}}`)
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(string(mirror))
		_, err := utils.Run(cmd)
		// utils.Run quotes the output, so match without the quotes.
		Expect(err).To(MatchError(And(ContainSubstring("strict decoding error: unknown field"), ContainSubstring("spec.sbom"))))

		By("checking that the spec the sync Job reads carries the target policy")
		out, err := utils.Run(exec.Command("kubectl", "get", "configmap", cronJobName(e2eTeam, "sbom-app"), "-n", namespace,
			"-o", "jsonpath={.data.spec\\.json}"))
		Expect(err).NotTo(HaveOccurred())
		var spec struct {
			SBOM struct {
				Mode     string `json:"mode"`
				Required bool   `json:"required"`
			} `json:"sbom"`
		}
		Expect(json.Unmarshal([]byte(out), &spec)).To(Succeed())
		Expect(spec.SBOM.Mode).To(Equal("Generate"))
		Expect(spec.SBOM.Required).To(BeTrue())
	})

	It("attaches SBOMs to a tag already on the target once the policy is turned on", func() {
		repo := dstHost + "/later/e2e/sbom-app"
		runSync("sbom-later", "sbom-later-1", "Complete")
		Expect(headDigest(repo+":1.0.0", dstOpts)).To(Equal(app))
		Expect(sbomReferrers(repo, appChildren[0], dstOpts)).To(BeEmpty())

		_, err := utils.Run(exec.Command("kubectl", "patch", "clustermirrortarget", "e2e-sbom-later", "--type=merge",
			"-p", `{"spec":{"sbom":{"mode":"Generate"}}}`))
		Expect(err).NotTo(HaveOccurred())
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "cronjob", cronJobName(e2eTeam, "sbom-later"), "-n", namespace,
				"-o", "jsonpath={.spec.jobTemplate.spec.template.metadata.labels.tagwarden\\.dev/sbom}"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("trivy"))
		}).Should(Succeed())

		runSync("sbom-later", "sbom-later-2", "Complete")
		Expect(headDigest(repo+":1.0.0", dstOpts)).To(Equal(app), "the tag did not move")
		for _, child := range appChildren {
			Expect(sbomReferrers(repo, child, dstOpts)).To(HaveLen(1), "SBOMs of %s", child)
		}
		Expect(sbomReferrers(repo, app, dstOpts)).To(HaveLen(2))
		Eventually(sbomCondition("sbom-later")).Should(HaveField("Reason", "Attached"))
	})
})

// pushSBOMIndex pushes a linux/amd64 and linux/arm64 index as ref:1.0.0
// and returns its digest and the child digests. The layers are real tar
// archives, so Trivy can list them; with broken the arm64 layer is random
// bytes, which Trivy refuses ("failed to extract the archive").
func pushSBOMIndex(repo string, opts []remote.Option, broken bool) (v1.Hash, []v1.Hash) {
	r, err := name.NewRepository(repo)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	children := make([]v1.Hash, 0, 2)
	for _, arch := range []string{"amd64", "arm64"} {
		layer, err := random.Layer(512, types.OCILayer)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		if broken && arch == "arm64" {
			b := make([]byte, 256)
			_, err = rand.Read(b)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			layer = static.NewLayer(b, types.OCILayer)
		}
		img := ociImage(types.OCIConfigJSON, layer)
		cf, err := img.ConfigFile()
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		cf.OS, cf.Architecture = "linux", arch
		img, err = mutate.ConfigFile(img, cf)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		d, err := img.Digest()
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		children = append(children, d)
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        img,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}},
		})
	}
	ExpectWithOffset(1, remote.WriteIndex(r.Tag("1.0.0"), idx, opts...)).To(Succeed())
	desc, err := partial.Descriptor(idx)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return desc.Digest, children
}

func headDigest(ref string, opts []remote.Option) v1.Hash {
	r, err := name.ParseReference(ref)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	desc, err := remote.Head(r, opts...)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return desc.Digest
}

// sbomReferrer is a CycloneDX referrer with the annotations of its
// manifest, read from the manifest rather than the referrers list.
type sbomReferrer struct {
	Digest      v1.Hash
	Annotations map[string]string
	Layer       v1.Hash
}

// sbomReferrers lists the CycloneDX referrers of a digest in repo.
func sbomReferrers(repo string, subject v1.Hash, opts []remote.Option) []sbomReferrer {
	r, err := name.NewRepository(repo)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	idx, err := remote.Referrers(r.Digest(subject.String()), opts...)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	im, err := idx.IndexManifest()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	var out []sbomReferrer
	for _, d := range im.Manifests {
		if d.ArtifactType != cycloneDX {
			continue
		}
		img, err := remote.Image(r.Digest(d.Digest.String()), opts...)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		m, err := img.Manifest()
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		ExpectWithOffset(1, m.Subject).NotTo(BeNil())
		ExpectWithOffset(1, m.Subject.Digest).To(Equal(subject))
		ExpectWithOffset(1, m.Layers).To(HaveLen(1))
		out = append(out, sbomReferrer{Digest: d.Digest, Annotations: m.Annotations, Layer: m.Layers[0].Digest})
	}
	return out
}

// sbomDocument reads the SBOM layer of a referrer as a JSON object.
func sbomDocument(repo string, ref sbomReferrer, opts []remote.Option) map[string]any {
	r, err := name.NewRepository(repo)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	l, err := remote.Layer(r.Digest(ref.Layer.String()), opts...)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	rc, err := l.Compressed()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	var doc map[string]any
	ExpectWithOffset(1, json.Unmarshal(b, &doc)).To(Succeed())
	return doc
}
