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
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/test/utils"
)

// The gate e2e tests need a large vulnerability DB and the internet (the
// proxy of e2e-infra reaches ghcr.io, docker.io and registry.k8s.io on 443),
// so they carry the Ginkgo label "gate" and run with make test-e2e-gate only.
//
// kind's default CNI (kindnet) enforces NetworkPolicy since kind 0.24, which
// the mirror tests already rely on (the sync-egress and proxy-egress
// policies of infra.yaml). The gate tests therefore turn networkPolicy.enabled
// on and keep the chart's Trivy policy under test.
const (
	// gateTarget is the gated ClusterMirrorTarget of testdata/gate-values.yaml.
	gateTarget = "e2e-gate"
	// autoProject is its autoMirror.project, platformProject holds the feeds.
	autoProject     = "auto"
	platformProject = "platform"
	// trivyServer is the StatefulSet (and Service) the chart renders for
	// the release name "tagwarden".
	trivyServer = "tagwarden-trivy"

	// Trivy 0.76.1, the index digest pinned in docs/design/spikes.md.
	trivyRepository = "ghcr.io/aquasecurity/trivy"
	trivyVersion    = "0.76.1"
	trivyDigest     = "sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
	// dbRepository is the DB as the Trivy server sees it after the feeds
	// mirror copied ghcr.io/aquasecurity/trivy-db:2.
	dbRepository = targetHost + "/" + platformProject + "/ghcr.io/aquasecurity/trivy-db:2"
	// staleDBTag holds a copy of the DB with an old UpdatedAt.
	staleDBTag = "2-stale"
)

// gateImage is an upstream image a pod asks to be mirrored.
type gateImage struct {
	// registry and repository are the canonical source (auto-mirror form).
	registry, repository, tag string
	// digest is the index digest of tag. Pinning it keeps the scan result
	// stable; the pod references tag@digest.
	digest string
}

func (i gateImage) source() string { return i.registry + "/" + i.repository }

// ref is the image reference of the pod: repository:tag@digest. Docker Hub
// official images are written the short way, as a user would.
func (i gateImage) ref() string {
	repo := i.source()
	if i.registry == "docker.io" {
		repo = strings.TrimPrefix(i.repository, "library/")
	}
	return fmt.Sprintf("%s:%s@%s", repo, i.tag, i.digest)
}

// targetPath is the repository of the mirrored image on the target.
func (i gateImage) targetPath() string { return autoProject + "/" + i.source() }

// generatedMirror is the name of the generated ArtifactMirror of a source:
// auto-<16 hex of sha256(registry/repository)>.
func (i gateImage) generatedMirror() string {
	sum := sha256.Sum256([]byte(i.source()))
	return "auto-" + hex.EncodeToString(sum[:])[:16]
}

var (
	// vulnerableImage has CRITICAL CVE-2022-48174 (busybox, ssl_client and
	// busybox-binsh, fixed in 1.36.1-r1) and HIGH CVE-2023-5363 on both
	// linux/amd64 and linux/arm64 (checked with the pinned Trivy 0.76.1 and
	// the DB of 2026-11-04). A Docker manifest list of 7 platforms, about
	// 3 MiB per platform, no attestation children.
	vulnerableImage = gateImage{"docker.io", "library/alpine", "3.18.0",
		"sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11"}
	vulnerableCVE = "CVE-2022-48174"

	// cleanImage has no finding of any severity on linux/amd64 and
	// linux/arm64 in the same DB (no OS packages, one static binary).
	// registry.k8s.io/pause does not do: its Windows children carry old Go
	// binaries with CRITICAL findings. gcr.io/distroless/static is clean but
	// has too many tags for the sync engine's tag listing limit.
	cleanImage = gateImage{"docker.io", "library/hello-world", "linux",
		"sha256:5e22040d441e5fb3aed38368acbe8486b575d7018df38dbdfbc7311fbb2ef3a9"}
)

// kindNodes returns the container names of the nodes of the kind cluster.
func kindNodes() []string {
	kind := "kind"
	if v, ok := os.LookupEnv("KIND"); ok {
		kind = v
	}
	cluster := "kind"
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	out, err := utils.Run(exec.Command(kind, "get", "nodes", "--name", cluster))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return utils.GetNonEmptyLines(out)
}

// pullOnNodes pulls an image by digest into the containerd of every kind
// node, so the Trivy server and the sidecar start without a registry that
// the nodes trust. The nodes reach the internet; a production cluster
// mirrors the image with Tagwarden (see "DB distribution"). crictl pulls by
// digest, which "kind load docker-image" does not do for an index.
func pullOnNodes(ref string) {
	for _, node := range kindNodes() {
		_, err := utils.Run(exec.Command("docker", "exec", node, "crictl", "pull", ref))
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "pulling %s on %s", ref, node)
	}
}

// gateHelm upgrades the release with the gate targets and, when trivyOn is
// set, the in-chart Trivy server that reads the DB from the target registry.
// extra holds more --set arguments.
func gateHelm(trivyOn bool, extra ...string) {
	egress, err := json.Marshal([]map[string]any{{"cidr": "10.244.0.0/16", "port": 5000}})
	Expect(err).NotTo(HaveOccurred())
	args := make([]string, 0, 32+len(extra))
	args = append(args, "upgrade", helmRelease, "dist/chart", "--namespace", namespace, "--reuse-values",
		"-f", "test/e2e/testdata/gate-values.yaml",
		"--set", fmt.Sprintf("trivy.enabled=%t", trivyOn),
		"--set", "trivy.image.repository="+trivyRepository,
		"--set", "trivy.image.tag="+trivyVersion,
		"--set", "trivy.image.digest="+trivyDigest,
		"--set", "trivy.db.repository="+dbRepository,
		"--set", "trivy.db.credentialsSecretRef.name=trivy-db-pull",
		"--set", "trivy.db.caBundleSecretRef.name=e2e-ca",
		"--set", "trivy.db.caBundleSecretRef.key=ca.crt",
		"--set-json", "trivy.networkPolicy.registryEgress="+string(egress),
		"--set", "trivy.persistence.size=5Gi",
		"--set", "trivy.scannerStartTimeout=60s",
		"--force-conflicts", "--wait", "--timeout", "10m")
	args = append(args, extra...)
	_, err = utils.Run(exec.Command("helm", args...))
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "helm upgrade for the gate failed")
}

// createDBPullSecret creates the dockerconfigjson Secret the Trivy server
// pulls the DB with. The e2e registry has one account, so this is not the
// pull-only account of a production setup.
func createDBPullSecret() {
	auth := base64.StdEncoding.EncodeToString([]byte(e2eUser + ":" + e2ePassword))
	cfg, err := json.Marshal(map[string]any{"auths": map[string]any{targetHost: map[string]string{"auth": auth}}})
	Expect(err).NotTo(HaveOccurred())
	applySecret(namespace, "trivy-db-pull", corev1.SecretTypeDockerConfigJson,
		map[string][]byte{corev1.DockerConfigJsonKey: cfg})
}

// syncFeeds copies the Trivy DB into the target registry the way the design
// describes it: a user-defined mirror on a platform target with
// onTagMutation Overwrite, through the proxy.
func syncFeeds() {
	By("mirroring ghcr.io/aquasecurity/trivy-db:2 with the scanner-feeds target")
	EventuallyWithOffset(1, func(g Gomega) {
		m := getMirror(g, namespace, "trivy-db")
		g.Expect(meta.IsStatusConditionTrue(m.Status.Conditions, "Ready")).To(BeTrue())
	}, 3*time.Minute, 2*time.Second).Should(Succeed())
	runSyncIn(namespace, "trivy-db", fmt.Sprintf("trivy-db-%d", time.Now().Unix()), "Complete")
}

// waitTrivyReady waits for the StatefulSet pod. The first start downloads
// the DB (the startup probe allows 15 minutes).
func waitTrivyReady() {
	EventuallyWithOffset(1, func(g Gomega) {
		out, err := utils.Run(exec.Command("kubectl", "get", "statefulset", trivyServer, "-n", namespace,
			"-o", "jsonpath={.status.readyReplicas}"))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(Equal("1"))
	}, 15*time.Minute, 5*time.Second).Should(Succeed())
}

// forwardPort forwards a free local port to a port of a pod or Service and
// returns localhost:port. It stops with the spec tree.
func forwardPort(ns, target string, port int) string {
	cmd := exec.Command("kubectl", "port-forward", "-n", ns, target, fmt.Sprintf(":%d", port))
	out, err := cmd.StdoutPipe()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, cmd.Start()).To(Succeed())
	DeferCleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	r := bufio.NewReader(out)
	line, err := r.ReadString('\n')
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "port-forward to %s did not start", target)
	go func() { _, _ = io.Copy(io.Discard, r) }()
	var local int
	_, err = fmt.Sscanf(line, "Forwarding from 127.0.0.1:%d", &local)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "unexpected port-forward output %q", line)
	return fmt.Sprintf("localhost:%d", local)
}

// trivyVersionInfo is what GET /version of the Trivy server returns.
type trivyVersionInfo struct {
	Version         string
	VulnerabilityDB struct {
		UpdatedAt, NextUpdate time.Time
	}
}

// serverVersion reads /version from the Trivy pod through a port-forward
// (the API server proxy would be refused by the Trivy NetworkPolicy).
func serverVersion() trivyVersionInfo {
	addr := forwardPort(namespace, "pod/"+trivyServer+"-0", 4954)
	var info trivyVersionInfo
	EventuallyWithOffset(1, func(g Gomega) {
		resp, err := http.Get("http://" + addr + "/version") //nolint:noctx // test helper
		g.Expect(err).NotTo(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		g.Expect(json.NewDecoder(resp.Body).Decode(&info)).To(Succeed())
	}, 30*time.Second, time.Second).Should(Succeed())
	return info
}

// setGate merge-patches autoMirror.vulnerabilityGate of the gated target.
// Pass nil for a field to reset it to the chart's value.
func setGate(fields map[string]any) {
	patch, err := json.Marshal(map[string]any{"spec": map[string]any{"autoMirror": map[string]any{
		"vulnerabilityGate": fields}}})
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	_, err = utils.Run(exec.Command("kubectl", "patch", "clustermirrortarget", gateTarget,
		"--type", "merge", "-p", string(patch)))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
}

// defaultGate is the permissive policy of gate-values.yaml. Resetting
// scanner to nil removes any override of image, token or URL.
func defaultGate() map[string]any {
	return map[string]any{"action": "Report", "onScanError": "Report", "severity": "Critical",
		"maxDBAge": nil, "scanner": nil}
}

func getTarget(g Gomega) *mirrorv1alpha1.ClusterMirrorTarget {
	out, err := utils.Run(exec.Command("kubectl", "get", "clustermirrortarget", gateTarget, "-o", "json"))
	g.Expect(err).NotTo(HaveOccurred())
	var t mirrorv1alpha1.ClusterMirrorTarget
	g.Expect(json.Unmarshal([]byte(out), &t)).To(Succeed())
	return &t
}

// newTenant creates a namespace allowed to use the auto and mirror projects
// and deletes it after the spec, with its generated mirrors.
func newTenant(prefix string) string {
	ns := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1_000_000)
	kubectlApply(fmt.Appendf(nil, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":%q,`+
		`"labels":{"e2e.tagwarden.dev/team":"true"}}}`, ns))
	DeferCleanup(func() {
		_, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", ns, "--ignore-not-found", "--wait=false"))
	})
	return ns
}

// applyAnnotatedPod creates a pod that asks for the image to be mirrored
// with the gated target. The pod pulls from the internet and sleeps; the
// tests look at the mirror and the Events, not at the pod phase.
// The pod is named "app".
func applyAnnotatedPod(ns string, img gateImage) {
	container := map[string]any{"name": "app", "image": img.ref()}
	if img.repository == "library/alpine" {
		container["command"] = []string{"sleep", "3600"}
	}
	b, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "app", "namespace": ns,
			"annotations": map[string]string{mirrorv1alpha1.AutoMirrorAnnotation: gateTarget}},
		"spec": map[string]any{"containers": []any{container}},
	})
	Expect(err).NotTo(HaveOccurred())
	kubectlApply(b)
}

// generated returns the generated mirror of an image in a namespace.
func generated(g Gomega, ns string, img gateImage) *mirrorv1alpha1.ArtifactMirror {
	return getMirror(g, ns, img.generatedMirror())
}

// awaitGatedRun waits until the generated mirror has finished a run: its
// Synced condition exists (a blocked tag leaves Synced True, see the design).
func awaitGatedRun(ns string, img gateImage) *mirrorv1alpha1.ArtifactMirror {
	var m *mirrorv1alpha1.ArtifactMirror
	EventuallyWithOffset(1, func(g Gomega) {
		m = generated(g, ns, img)
		g.Expect(meta.FindStatusCondition(m.Status.Conditions, "Synced")).NotTo(BeNil())
	}, 8*time.Minute, 3*time.Second).Should(Succeed())
	return m
}

// podEvents returns the Events recorded for a pod, by reason.
func podEvents(ns, pod string) map[string][]corev1.Event { return objectEvents(ns, "Pod", pod) }

// objectEvents returns the Events recorded for an object, by reason.
func objectEvents(ns, kind, object string) map[string][]corev1.Event {
	out, err := utils.Run(exec.Command("kubectl", "get", "events", "-n", ns, "-o", "json",
		"--field-selector", "involvedObject.kind="+kind+",involvedObject.name="+object))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	var list corev1.EventList
	ExpectWithOffset(1, json.Unmarshal([]byte(out), &list)).To(Succeed())
	byReason := map[string][]corev1.Event{}
	for _, e := range list.Items {
		byReason[e.Reason] = append(byReason[e.Reason], e)
	}
	return byReason
}

// findingFor returns the status.findings entry of a tag, or nil.
func findingFor(m *mirrorv1alpha1.ArtifactMirror, tag string) *mirrorv1alpha1.VulnerabilityFinding {
	for i := range m.Status.Findings {
		if m.Status.Findings[i].Tag == tag {
			return &m.Status.Findings[i]
		}
	}
	return nil
}

// targetTags lists the tags of a repository on the target registry through
// a port-forward; a missing repository has no tags.
func targetTags(host, path string, opts []remote.Option) []string {
	repo, err := name.NewRepository(host + "/" + path)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	tags, err := remote.List(repo, opts...)
	if err != nil {
		return nil
	}
	return tags
}

// purgeTarget deletes every manifest of a target repository so the next run
// sees the tag as new: an already mirrored tag is never scanned again.
func purgeTarget(host, path string, opts []remote.Option) {
	repo, err := name.NewRepository(host + "/" + path)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	tags, err := remote.List(repo, opts...)
	if err != nil {
		return
	}
	for _, tag := range tags {
		desc, err := remote.Head(repo.Tag(tag), opts...)
		if err != nil {
			continue
		}
		_ = remote.Delete(repo.Digest(desc.Digest.String()), opts...)
	}
}

// pushStaleDB copies the mirrored DB to staleDBTag with an UpdatedAt 30
// days in the past, by rewriting metadata.json in the DB layer. The Trivy
// server reads the age from that file, so it reports a DB older than any
// maxDBAge. Returns once the tag is on the target.
func pushStaleDB(host string, opts []remote.Option) {
	src, err := name.ParseReference(host + "/" + platformProject + "/ghcr.io/aquasecurity/trivy-db:2")
	Expect(err).NotTo(HaveOccurred())
	img, err := remote.Image(src, opts...)
	Expect(err).NotTo(HaveOccurred())
	manifest, err := img.Manifest()
	Expect(err).NotTo(HaveOccurred())
	Expect(manifest.Layers).To(HaveLen(1))
	desc := manifest.Layers[0]
	layers, err := img.Layers()
	Expect(err).NotTo(HaveOccurred())
	rc, err := layers[0].Compressed()
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = rc.Close() }()

	tmp, err := os.CreateTemp("", "trivy-db-stale-*.tar.gz")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { _ = os.Remove(tmp.Name()) })
	rewriteDBMetadata(rc, tmp, time.Now().Add(-30*24*time.Hour))
	Expect(tmp.Close()).To(Succeed())

	layer, err := tarball.LayerFromFile(tmp.Name(), tarball.WithMediaType(desc.MediaType),
		tarball.WithCompressedCaching)
	Expect(err).NotTo(HaveOccurred())
	cfgType := manifest.Config.MediaType
	stale := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), cfgType)
	stale, err = mutate.Append(stale, mutate.Addendum{Layer: layer, MediaType: desc.MediaType,
		Annotations: desc.Annotations})
	Expect(err).NotTo(HaveOccurred())
	dst, err := name.ParseReference(host + "/" + platformProject + "/ghcr.io/aquasecurity/trivy-db:" + staleDBTag)
	Expect(err).NotTo(HaveOccurred())
	Expect(remote.Write(dst, stale, opts...)).To(Succeed())
}

// rewriteDBMetadata copies a gzip tar to w, replacing UpdatedAt, NextUpdate
// and DownloadedAt in metadata.json (updated, next = updated + 24h).
func rewriteDBMetadata(in io.Reader, w io.Writer, updated time.Time) {
	zr, err := gzip.NewReader(in)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	zw := gzip.NewWriter(w)
	tw := tar.NewWriter(zw)
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		if h.Name != "metadata.json" {
			ExpectWithOffset(1, tw.WriteHeader(h)).To(Succeed())
			_, err = io.CopyN(tw, tr, h.Size)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		var md map[string]any
		ExpectWithOffset(1, json.Unmarshal(raw, &md)).To(Succeed())
		md["UpdatedAt"] = updated.UTC().Format(time.RFC3339)
		md["NextUpdate"] = updated.Add(24 * time.Hour).UTC().Format(time.RFC3339)
		md["DownloadedAt"] = updated.UTC().Format(time.RFC3339)
		raw, err = json.Marshal(md)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		h.Size = int64(len(raw))
		ExpectWithOffset(1, tw.WriteHeader(h)).To(Succeed())
		_, err = tw.Write(raw)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	}
	ExpectWithOffset(1, tw.Close()).To(Succeed())
	ExpectWithOffset(1, zw.Close()).To(Succeed())
}

// restartTrivyWithDB points the server at another DB tag and starts it with
// an empty cache, because a cache whose NextUpdate lies ahead is not
// refreshed at start.
func restartTrivyWithDB(tag string) {
	repo := targetHost + "/" + platformProject + "/ghcr.io/aquasecurity/trivy-db:" + tag
	for _, args := range [][]string{
		{"scale", "statefulset", trivyServer, "-n", namespace, "--replicas=0"},
		{"wait", "pod/" + trivyServer + "-0", "-n", namespace, "--for=delete", "--timeout=2m"},
		{"delete", "pvc", "cache-" + trivyServer + "-0", "-n", namespace, "--ignore-not-found"},
	} {
		_, err := utils.Run(exec.Command("kubectl", args...))
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	}
	gateHelm(true, "--set", "trivy.db.repository="+repo)
	// helm does not undo the manual scale: its manifests did not change.
	_, err := utils.Run(exec.Command("kubectl", "scale", "statefulset", trivyServer, "-n", namespace, "--replicas=1"))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	waitTrivyReady()
}

// condition returns a status condition or nil.
func condition(conds []metav1.Condition, typ string) *metav1.Condition {
	return meta.FindStatusCondition(conds, typ)
}
