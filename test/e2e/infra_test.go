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
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/test/utils"
)

const (
	infraNamespace = "e2e-infra"
	// Test-only credentials of the target registry and the proxy. The
	// bcrypt hash in testdata/infra.yaml matches them.
	e2eUser     = "e2e"
	e2ePassword = "e2e-password"
	// sigArtifactType marks the cosign-style signature referrers.
	sigArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"
	// e2eTeam may use the mirror project; e2eOther may not.
	e2eTeam  = "e2e-team"
	e2eOther = "e2e-other"
	// targetHost is the target registry as the sync Jobs see it.
	targetHost = "target.e2e-infra.svc.cluster.local:5000"
	// sourceIP is the fixed ClusterIP of the source Service.
	sourceIP = "10.96.100.100"
	// probeImage runs the NetworkPolicy probe.
	probeImage = "curlimages/curl:8.17.0@sha256:935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40"
)

// testCA signs the source and target registry certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA() *testCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tagwarden e2e CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return &testCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf returns a PEM server certificate and key for the DNS names, also
// valid for localhost so the test reaches it through a port-forward.
func (ca *testCA) leaf(dnsNames ...string) (certPEM, keyPEM []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     append(dnsNames, "localhost"),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalECPrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// remoteOpts trusts the test CA and, with auth, logs in as the test user.
func (ca *testCA) remoteOpts(auth bool) []remote.Option {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	opts := []remote.Option{remote.WithTransport(t)}
	if auth {
		opts = append(opts, remote.WithAuth(&authn.Basic{Username: e2eUser, Password: e2ePassword}))
	}
	return opts
}

// kubectlApply applies a manifest from stdin, so Secret data never shows
// up in the logged command line.
func kubectlApply(manifest []byte) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(manifest)
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
}

func applySecret(namespace, secretName string, typ corev1.SecretType, data map[string][]byte) {
	b, err := json.Marshal(&corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: secretName},
		Type:       typ,
		Data:       data,
	})
	Expect(err).NotTo(HaveOccurred())
	kubectlApply(b)
}

// portForward forwards a free local port to port 5000 of an e2e-infra
// Service and returns localhost:port. The forward stops with the spec tree.
func portForward(svc string) string {
	cmd := exec.Command("kubectl", "port-forward", "-n", infraNamespace, "svc/"+svc, ":5000")
	out, err := cmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	Expect(cmd.Start()).To(Succeed())
	DeferCleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	r := bufio.NewReader(out)
	line, err := r.ReadString('\n')
	Expect(err).NotTo(HaveOccurred(), "port-forward to %s did not start", svc)
	// Drain the rest so kubectl never blocks on a full pipe.
	go func() { _, _ = io.Copy(io.Discard, r) }()
	var port int
	_, err = fmt.Sscanf(line, "Forwarding from 127.0.0.1:%d", &port)
	Expect(err).NotTo(HaveOccurred(), "unexpected port-forward output %q", line)
	return fmt.Sprintf("localhost:%d", port)
}

// pushRelease pushes a two-platform index as repo:tag with a cosign-style
// signature referrer and returns the index digest.
func pushRelease(repo name.Repository, tag string, opts []remote.Option) v1.Hash {
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	for _, arch := range []string{"amd64", "arm64"} {
		img := ociImage(types.OCIConfigJSON, randomLayer())
		cf, err := img.ConfigFile()
		Expect(err).NotTo(HaveOccurred())
		cf.OS, cf.Architecture = "linux", arch
		img, err = mutate.ConfigFile(img, cf)
		Expect(err).NotTo(HaveOccurred())
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        img,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}},
		})
	}
	Expect(remote.WriteIndex(repo.Tag(tag), idx, opts...)).To(Succeed())
	desc, err := partial.Descriptor(idx)
	Expect(err).NotTo(HaveOccurred())

	payload := `{"critical":{"image":{"docker-manifest-digest":"` + desc.Digest.String() + `"}}}`
	sig, ok := mutate.Subject(ociImage(sigArtifactType,
		static.NewLayer([]byte(payload), "application/vnd.dev.cosign.simplesigning.v1+json")), *desc).(v1.Image)
	Expect(ok).To(BeTrue())
	sd, err := sig.Digest()
	Expect(err).NotTo(HaveOccurred())
	Expect(remote.Write(repo.Digest(sd.String()), sig, opts...)).To(Succeed())
	return desc.Digest
}

// ociImage is a one-layer OCI image with the given config media type.
func ociImage(configType types.MediaType, layer v1.Layer) v1.Image {
	img := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), configType)
	img, err := mutate.AppendLayers(img, layer)
	Expect(err).NotTo(HaveOccurred())
	return img
}

func randomLayer() v1.Layer {
	b := make([]byte, 256)
	_, err := rand.Read(b)
	Expect(err).NotTo(HaveOccurred())
	return static.NewLayer(b, types.OCILayer)
}

// cronJobName matches the controller for short names: namespace, mirror and
// the first 8 hex characters of sha256(namespace/name).
func cronJobName(namespace, mirror string) string {
	sum := sha256.Sum256([]byte(namespace + "/" + mirror))
	return namespace + "-" + mirror + "-" + hex.EncodeToString(sum[:])[:8]
}

func getMirror(g Gomega, namespace, mirror string) *mirrorv1alpha1.ArtifactMirror {
	out, err := utils.Run(exec.Command("kubectl", "get", "artifactmirror", mirror, "-n", namespace, "-o", "json"))
	g.Expect(err).NotTo(HaveOccurred())
	var m mirrorv1alpha1.ArtifactMirror
	g.Expect(json.Unmarshal([]byte(out), &m)).To(Succeed())
	return &m
}

// runSync starts a Job from the CronJob of a mirror, as the schedule would,
// and waits until it finishes with the wanted condition (Complete or Failed).
func runSync(mirror, job, want string) {
	_, err := utils.Run(exec.Command("kubectl", "create", "job", job, "-n", namespace,
		"--from=cronjob/"+cronJobName(e2eTeam, mirror)))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	EventuallyWithOffset(1, func(g Gomega) {
		out, err := utils.Run(exec.Command("kubectl", "get", "job", job, "-n", namespace,
			"-o", `jsonpath={.status.conditions[?(@.status=="True")].type}`))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.Fields(out)).To(ContainElement(want))
	}, 5*time.Minute, 2*time.Second).Should(Succeed())
}

// removeLeftovers deletes what an earlier run on the same cluster left
// behind: mirrors, targets, sync Jobs and the test namespaces, so stale
// registry data, CAs or Job names cannot break this run.
func removeLeftovers() {
	By("removing leftovers of an earlier run")
	for _, args := range [][]string{
		{"delete", "artifactmirrors", "--all", "-A", "--ignore-not-found", "--wait"},
		{"delete", "clustermirrortargets", "--all", "--ignore-not-found", "--wait"},
		{"delete", "jobs", "--all", "-n", namespace, "--ignore-not-found", "--wait"},
		{"delete", "namespace", infraNamespace, e2eTeam, e2eOther, "--ignore-not-found", "--wait"},
	} {
		_, err := utils.Run(exec.Command("kubectl", args...))
		Expect(err).NotTo(HaveOccurred())
	}
}

// dumpDiagnostics prints the state the mirror tests depend on.
func dumpDiagnostics() {
	for _, args := range [][]string{
		{"get", "clustermirrortargets,artifactmirrors", "-A", "-o", "yaml"},
		{"get", "cronjobs,jobs,pods", "-n", namespace, "-o", "wide"},
		{"logs", "-n", namespace, "-l", "tagwarden.dev/mirror", "--prefix", "--tail=100"},
		{"logs", "-n", namespace, "-l", "control-plane=controller-manager", "--tail=200"},
		{"get", "pods", "-n", infraNamespace, "-o", "wide"},
		{"logs", "-n", infraNamespace, "deploy/proxy", "--tail=100"},
		{"get", "events", "-A", "--sort-by=.lastTimestamp"},
	} {
		out, err := utils.Run(exec.Command("kubectl", args...))
		_, _ = fmt.Fprintf(GinkgoWriter, "kubectl %s:\n%s\n%v\n", strings.Join(args, " "), out, err)
	}
}
