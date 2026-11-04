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
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const (
	trivyImage2  = "registry.example.internal/other/trivy@sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	nextVersion  = "0.77.0"
	extHost      = "trivy.example.internal"
	extURL       = "https://" + extHost
	svcHost      = "trivy.tagwarden-system.svc"
	metadataIP   = "169.254.169.254"
	serviceIP    = "10.96.0.10"
	unknownField = "unknown field"
)

func TestEffectiveScanner(t *testing.T) {
	flags := ScannerConfig{URL: "http://trivy.tagwarden-system.svc:4954", Image: trivyImage, Version: trivyVersion}
	tests := []struct {
		name    string
		spec    *mirrorv1alpha1.ScannerSpec
		flags   ScannerConfig
		want    ScannerConfig
		problem string
	}{
		{name: "flags only", flags: flags, want: flags},
		{name: "empty spec keeps flags", spec: &mirrorv1alpha1.ScannerSpec{}, flags: flags, want: flags},
		{name: "url overrides the flag", flags: flags,
			spec: &mirrorv1alpha1.ScannerSpec{URL: extURL + ":4954"},
			want: ScannerConfig{URL: extURL + ":4954", Image: trivyImage, Version: trivyVersion}},
		{name: "image and version override the flags", flags: flags,
			spec: &mirrorv1alpha1.ScannerSpec{Image: trivyImage2, Version: nextVersion},
			want: ScannerConfig{URL: flags.URL, Image: trivyImage2, Version: nextVersion}},
		{name: "everything from the target without flags",
			spec: &mirrorv1alpha1.ScannerSpec{URL: extURL, Image: trivyImage2, Version: nextVersion},
			want: ScannerConfig{URL: extURL, Image: trivyImage2, Version: nextVersion}},
		{name: "neither", problem: "not configured: set scanner.url"},
		{name: "url without a client", spec: &mirrorv1alpha1.ScannerSpec{URL: extURL},
			want: ScannerConfig{URL: extURL}, problem: "not configured: set scanner.image and scanner.version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, problem := effectiveScanner(tt.spec, tt.flags)
			if tt.problem == "" && problem != "" || !strings.HasPrefix(problem, tt.problem) {
				t.Fatalf("problem = %q, want prefix %q", problem, tt.problem)
			}
			if tt.problem == "" && got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestVersionMismatch(t *testing.T) {
	tests := []struct{ want, got, msg string }{
		{trivyVersion, trivyVersion, ""},
		{trivyVersion, "0.76.0", ""},
		{trivyVersion, "0.76.9", ""},
		{trivyVersion, "v0.76.2", ""},
		{trivyVersion, "0.75.0", "version 0.75.0, want 0.76.x"},
		{trivyVersion, nextVersion, "version 0.77.0, want 0.76.x"},
		{trivyVersion, "1.76.1", "version 1.76.1, want 0.76.x"},
		{trivyVersion, "dev", "server reports an invalid version, want 0.76.x"},
		{trivyVersion, "", "server reports an invalid version, want 0.76.x"},
	}
	for _, tt := range tests {
		if got := versionMismatch(tt.want, tt.got); got != tt.msg {
			t.Errorf("versionMismatch(%q, %q) = %q, want %q", tt.want, tt.got, got, tt.msg)
		}
	}
}

func TestDecodeVersion(t *testing.T) {
	tests := []struct {
		name, body, err string
	}{
		{name: "spike shape", body: `{"Version":"0.76.1","VulnerabilityDB":{"Version":2,"NextUpdate":"2026-11-04T19:16:30Z","UpdatedAt":"2026-11-03T19:16:30Z","DownloadedAt":"2026-11-03T20:00:00Z"}}`},
		{name: "optional Java DB and check bundle", body: `{"Version":"0.76.1","VulnerabilityDB":{"Version":2},"JavaDB":{"Version":1},"CheckBundle":{"Digest":"sha256:00"}}`},
		{name: "garbage", body: `<html>`, err: "invalid /version response"},
		{name: unknownField, body: `{"Version":"0.76.1","Token":"x"}`, err: unknownField},
		{name: "unknown DB field", body: `{"Version":"0.76.1","VulnerabilityDB":{"Extra":1}}`, err: unknownField},
		{name: "wrong type", body: `{"Version":76}`, err: "invalid /version response"},
		{name: "trailing data", body: `{"Version":"0.76.1"} {}`, err: "data after the JSON object"},
		{name: "no version", body: `{}`, err: "no Version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeVersion([]byte(tt.body))
			if tt.err == "" && err != nil || tt.err != "" && (err == nil || !strings.Contains(err.Error(), tt.err)) {
				t.Fatalf("err = %v, want %q", err, tt.err)
			}
		})
	}
}

func TestScannerAddrCheck(t *testing.T) {
	denied := []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")}
	tests := []struct {
		host, addr string
		ok         bool
	}{
		{extHost, "192.0.2.10", true},
		{extHost, metadataIP, false},
		{extHost, "100.100.100.200", false},
		{extHost, "127.0.0.1", false},
		{extHost, serviceIP, false},
		{svcHost, serviceIP, true},
		{svcHost + ".cluster.local", serviceIP, true},
		{svcHost, metadataIP, false},
		{svcHost, "127.0.0.1", false},
		{"svc.example.internal", serviceIP, false},
	}
	for _, tt := range tests {
		err := scannerAddrCheck(tt.host, denied, false)(netip.MustParseAddr(tt.addr))
		if (err == nil) != tt.ok {
			t.Errorf("%s -> %s: err = %v, want ok %v", tt.host, tt.addr, err, tt.ok)
		}
	}
}

func TestScannerConditions(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	c := ScannerConfig{URL: extURL, Image: trivyImage, Version: trivyVersion}
	info := func(v string, age time.Duration) *versionInfo {
		return &versionInfo{Version: v, VulnerabilityDB: &dbMetadata{UpdatedAt: now.Add(-age)}}
	}
	tests := []struct {
		name                 string
		problem              string
		info                 *versionInfo
		err                  error
		scReason, dbReason   string
		scStatus, dbStatus   metav1.ConditionStatus
		scMessage, dbMessage string
	}{
		{name: "healthy", info: info(trivyVersion, time.Hour),
			scStatus: metav1.ConditionTrue, scReason: ReasonReady, scMessage: "Trivy 0.76.1 at https://trivy.example.internal",
			dbStatus: metav1.ConditionTrue, dbReason: ReasonReady, dbMessage: "vulnerability DB updated 2026-11-04T11:00:00Z"},
		{name: "not configured", problem: "not configured: x",
			scStatus: metav1.ConditionFalse, scReason: ReasonScannerUnavailable, scMessage: "not configured: x",
			dbStatus: metav1.ConditionUnknown, dbReason: ReasonScannerUnavailable},
		{name: "unreachable", err: fmt.Errorf("connection refused"),
			scStatus: metav1.ConditionFalse, scReason: ReasonScannerUnavailable, scMessage: "unreachable: connection refused",
			dbStatus: metav1.ConditionUnknown, dbReason: ReasonScannerUnavailable},
		{name: "version mismatch keeps the DB check", info: info("0.75.0", time.Hour),
			scStatus: metav1.ConditionFalse, scReason: ReasonVersionMismatch, scMessage: "version 0.75.0, want 0.76.x",
			dbStatus: metav1.ConditionTrue, dbReason: ReasonReady},
		{name: "stale DB", info: info(trivyVersion, 73*time.Hour),
			scStatus: metav1.ConditionTrue, scReason: ReasonReady,
			dbStatus: metav1.ConditionFalse, dbReason: ReasonDBStale, dbMessage: "older than maxDBAge 72h0m0s"},
		{name: "no DB", info: &versionInfo{Version: trivyVersion},
			scStatus: metav1.ConditionTrue, scReason: ReasonReady,
			dbStatus: metav1.ConditionFalse, dbReason: ReasonDBStale, dbMessage: "no vulnerability DB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, db := scannerConditions(c, tt.problem, tt.info, tt.err, 72*time.Hour, now)
			if sc.Status != tt.scStatus || sc.Reason != tt.scReason || !strings.Contains(sc.Message, tt.scMessage) {
				t.Errorf("ScannerReady = %s %s %q", sc.Status, sc.Reason, sc.Message)
			}
			if db.Status != tt.dbStatus || db.Reason != tt.dbReason || !strings.Contains(db.Message, tt.dbMessage) {
				t.Errorf("VulnerabilityDBReady = %s %s %q", db.Status, db.Reason, db.Message)
			}
		})
	}
}

// fakeTrivy is an https Trivy server whose /version answer tests change.
type fakeTrivy struct {
	*httptest.Server
	body     atomic.Value // string
	status   atomic.Int64
	requests atomic.Int64
	tokens   atomic.Int64
}

func newFakeTrivy() *fakeTrivy {
	f := &fakeTrivy{}
	f.setVersion(trivyVersion, time.Hour)
	f.status.Store(http.StatusOK)
	f.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Trivy-Token") != "" || r.Header.Get("Authorization") != "" {
			f.tokens.Add(1)
		}
		switch r.URL.Path {
		case "/version":
			f.requests.Add(1)
			if s := int(f.status.Load()); s != http.StatusOK {
				http.Redirect(w, r, "/elsewhere", s)
				return
			}
			_, _ = w.Write([]byte(f.body.Load().(string)))
		default:
			http.Error(w, "unexpected", http.StatusTeapot)
		}
	}))
	DeferCleanup(f.Close)
	return f
}

func (f *fakeTrivy) setVersion(v string, dbAge time.Duration) {
	f.body.Store(fmt.Sprintf(`{"Version":%q,"VulnerabilityDB":{"Version":2,"UpdatedAt":%q}}`,
		v, time.Now().Add(-dbAge).UTC().Format(time.RFC3339)))
}

func (f *fakeTrivy) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Certificate().Raw})
}

// createGatedTarget creates a Ready target with the gate on and the scanner
// at url, trusting ca when set.
func createGatedTarget(name, url string, ca []byte, mutate ...func(*mirrorv1alpha1.ClusterMirrorTarget)) *mirrorv1alpha1.ClusterMirrorTarget {
	scanner := &mirrorv1alpha1.ScannerSpec{URL: url, Image: trivyImage, Version: trivyVersion,
		TokenSecretRef: &mirrorv1alpha1.TokenSecretKeyRef{Name: name + "-token-never-read"}}
	if ca != nil {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-trivy-ca", Namespace: operatorNamespace},
			Data: map[string][]byte{caKey: ca}}
		Expect(k8sClient.Create(ctx, s)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, s)
		scanner.CABundleSecretRef = &mirrorv1alpha1.SecretKeyRef{Name: s.Name, Key: caKey}
	}
	t := createReadyTarget(name, append([]func(*mirrorv1alpha1.ClusterMirrorTarget){func(t *mirrorv1alpha1.ClusterMirrorTarget) {
		t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: teamA,
			VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{Enabled: true, Scanner: scanner}}
	}}, mutate...)...)
	DeferCleanup(k8sClient.Delete, ctx, t)
	return t
}

func targetCondition(name, typ string) func() *metav1.Condition {
	return func() *metav1.Condition {
		var t mirrorv1alpha1.ClusterMirrorTarget
		if k8sClient.Get(ctx, types.NamespacedName{Name: name}, &t) != nil {
			return nil
		}
		return meta.FindStatusCondition(t.Status.Conditions, typ)
	}
}

func cond(status metav1.ConditionStatus, reason, message string) OmegaMatcher {
	return And(HaveField("Status", status), HaveField("Reason", reason), HaveField("Message", ContainSubstring(message)))
}

var _ = Describe("Scanner readiness", func() {
	It("reports a healthy scanner and DB without touching Ready or sending a token", func() {
		f := newFakeTrivy()
		t := createGatedTarget("scan-healthy", f.URL, f.caPEM())
		Eventually(targetCondition(t.Name, ConditionScannerReady)).Should(cond(metav1.ConditionTrue, ReasonReady, "Trivy 0.76.1"))
		Eventually(targetCondition(t.Name, ConditionVulnerabilityDBReady)).Should(cond(metav1.ConditionTrue, ReasonReady, "vulnerability DB updated"))
		Expect(targetReady(t.Name)).To(HaveField("Status", metav1.ConditionTrue))
		Expect(f.tokens.Load()).To(BeZero())
		Expect(recorder.Events("", t.Name)).To(ContainElement(ContainSubstring("Normal " + ConditionScannerReady)))
	})

	It("probes at most once per interval", func() {
		f := newFakeTrivy()
		t := createGatedTarget("scan-rate", f.URL, f.caPEM())
		Eventually(targetCondition(t.Name, ConditionScannerReady)).Should(HaveField("Status", metav1.ConditionTrue))
		// Status updates and a spec change reconcile again within the interval.
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: t.Name}, t); err != nil {
				return err
			}
			t.Spec.AutoMirror.VulnerabilityGate.Severity = mirrorv1alpha1.SeverityThresholdHigh
			return k8sClient.Update(ctx, t)
		})).To(Succeed())
		Consistently(f.requests.Load, 2*time.Second).Should(BeNumerically("==", 1))
	})

	DescribeTable("reports a broken scanner",
		func(name string, setup func(*fakeTrivy) string, typ string, status metav1.ConditionStatus, reason, message string) {
			f := newFakeTrivy()
			url := setup(f)
			t := createGatedTarget(name, url, f.caPEM())
			var c *metav1.Condition
			Eventually(func() *metav1.Condition { c = targetCondition(t.Name, typ)(); return c }).Should(cond(status, reason, message))
			Expect(targetReady(t.Name)).To(HaveField("Status", metav1.ConditionTrue))
			Expect(recorder.Events("", t.Name)).To(ContainElement(ContainSubstring("Warning " + reason)))
			Expect(f.tokens.Load()).To(BeZero())
		},
		Entry("wrong version", "scan-version", func(f *fakeTrivy) string { f.setVersion("0.75.0", time.Hour); return f.URL },
			ConditionScannerReady, metav1.ConditionFalse, ReasonVersionMismatch, "version 0.75.0, want 0.76.x"),
		Entry("stale DB", "scan-stale", func(f *fakeTrivy) string { f.setVersion(trivyVersion, 100*time.Hour); return f.URL },
			ConditionVulnerabilityDBReady, metav1.ConditionFalse, ReasonDBStale, "older than maxDBAge 72h"),
		Entry("garbage JSON", "scan-garbage", func(f *fakeTrivy) string { f.body.Store("<html>"); return f.URL },
			ConditionScannerReady, metav1.ConditionFalse, ReasonScannerUnavailable, "invalid /version response"),
		Entry("oversized body", "scan-huge", func(f *fakeTrivy) string {
			f.body.Store(`{"Version":"0.76.1","CheckBundle":"` + strings.Repeat("a", maxVersionBody) + `"}`)
			return f.URL
		}, ConditionScannerReady, metav1.ConditionFalse, ReasonScannerUnavailable, "response larger than"),
		Entry("redirect", "scan-redirect", func(f *fakeTrivy) string { f.status.Store(http.StatusFound); return f.URL },
			ConditionScannerReady, metav1.ConditionFalse, ReasonScannerUnavailable, "status 302"),
		Entry("down", "scan-down", func(f *fakeTrivy) string { f.Close(); return f.URL },
			ConditionScannerReady, metav1.ConditionFalse, ReasonScannerUnavailable, "unreachable"),
		Entry("down keeps the DB unknown", "scan-down-db", func(f *fakeTrivy) string { f.Close(); return f.URL },
			ConditionVulnerabilityDBReady, metav1.ConditionUnknown, ReasonScannerUnavailable, "did not answer"),
		Entry("cloud metadata address", "scan-metadata", func(*fakeTrivy) string { return "https://" + metadataIP },
			ConditionScannerReady, metav1.ConditionFalse, ReasonScannerUnavailable, "internal address "+metadataIP),
	)

	It("does not follow redirects", func() {
		f := newFakeTrivy()
		f.status.Store(http.StatusMovedPermanently)
		t := createGatedTarget("scan-no-follow", f.URL, f.caPEM())
		Eventually(targetCondition(t.Name, ConditionScannerReady)).Should(cond(metav1.ConditionFalse, ReasonScannerUnavailable, "status 301"))
		Expect(f.requests.Load()).To(BeNumerically("==", 1))
	})

	It("needs the scanner CA for a private https server", func() {
		f := newFakeTrivy()
		t := createGatedTarget("scan-no-ca", f.URL, nil)
		Eventually(targetCondition(t.Name, ConditionScannerReady)).Should(cond(metav1.ConditionFalse, ReasonScannerUnavailable, "certificate"))
	})

	It("reports a missing CA Secret on ScannerReady only", func() {
		t := createGatedTarget("scan-ca-missing", extURL, nil, func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.AutoMirror.VulnerabilityGate.Scanner.CABundleSecretRef = &mirrorv1alpha1.SecretKeyRef{Name: "scan-ca-missing-none", Key: caKey}
		})
		Eventually(targetCondition(t.Name, ConditionScannerReady)).Should(cond(metav1.ConditionFalse, ReasonScannerUnavailable, "Secret scan-ca-missing-none not found"))
		Expect(targetReady(t.Name)).To(HaveField("Status", metav1.ConditionTrue))
	})

	It("reports a gate without a scanner as not configured", func() {
		t := createReadyTarget("scan-unset", func(t *mirrorv1alpha1.ClusterMirrorTarget) {
			t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: teamA,
				VulnerabilityGate: &mirrorv1alpha1.VulnerabilityGate{Enabled: true}}
		})
		DeferCleanup(k8sClient.Delete, ctx, t)
		Eventually(targetCondition(t.Name, ConditionScannerReady)).Should(cond(metav1.ConditionFalse, ReasonScannerUnavailable, "not configured"))
	})

	It("removes both conditions when the gate is turned off", func() {
		f := newFakeTrivy()
		t := createGatedTarget("scan-off", f.URL, f.caPEM())
		Eventually(targetCondition(t.Name, ConditionVulnerabilityDBReady)).ShouldNot(BeNil())
		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: t.Name}, t); err != nil {
				return err
			}
			t.Spec.AutoMirror.VulnerabilityGate.Enabled = false
			return k8sClient.Update(ctx, t)
		})).To(Succeed())
		Eventually(targetCondition(t.Name, ConditionScannerReady)).Should(BeNil())
		Eventually(targetCondition(t.Name, ConditionVulnerabilityDBReady)).Should(BeNil())
		Expect(targetReady(t.Name)).To(HaveField("Status", metav1.ConditionTrue))
	})

	It("adds no scanner conditions to a target without the gate", func() {
		t := createReadyTarget("scan-none")
		DeferCleanup(k8sClient.Delete, ctx, t)
		Consistently(targetCondition(t.Name, ConditionScannerReady), time.Second).Should(BeNil())
	})

	It("keeps user mirrors syncing while the scanner is down", func() {
		f := newFakeTrivy()
		f.Close()
		t := createGatedTarget("scan-user-mirror", f.URL, f.caPEM())
		Eventually(targetCondition(t.Name, ConditionScannerReady)).Should(HaveField("Status", metav1.ConditionFalse))
		m := newMirror(teamA, "scan-user-mirror")
		m.Spec.TargetRef = t.Name
		createMirror(m)
		Eventually(mirrorReady(m)).Should(HaveField("Status", metav1.ConditionTrue))
		Eventually(cronJob(m)).ShouldNot(BeNil())
	})
})
