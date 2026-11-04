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

package sync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	stdsync "sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
	"github.com/r-gawronski/tagwarden/internal/tags"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

const (
	fifo          = "fifo"
	jdb           = "trivy-java.db"
	meta          = "metadata.json"
	pinnedVersion = "0.76.1"
	critical      = `[{"id":"CVE-2026-0001","pkg":"openssl","ver":"3.0.0","fix":"3.0.1","sev":"CRITICAL","status":"fixed"}]`
	clean         = `[]`
	noAnswer      = "" // the fake sidecar takes the request and never answers
)

// fakeSidecar speaks the sidecar protocol on a scan dir. answer returns the
// report and exit code for a manifest hex; an empty exit never answers.
type fakeSidecar struct {
	dir, layout string
	answer      func(hex string) (report, exit string)
	mu          stdsync.Mutex
	scanned     []string
	// unlisted records requests for digests missing at the top level of
	// the layout's index.json, which the real client cannot scan.
	unlisted []string
}

func (f *fakeSidecar) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.scanned)
}

func (f *fakeSidecar) run(ctx context.Context) {
	for ctx.Err() == nil {
		rs, _ := filepath.Glob(filepath.Join(f.dir, syncspec.ScanReqDir, "*.ready"))
		for _, r := range rs {
			_ = os.Remove(r)
			h := strings.TrimSuffix(filepath.Base(r), ".ready")
			f.mu.Lock()
			f.scanned = append(f.scanned, h)
			if !topLevel(f.layout, h) {
				f.unlisted = append(f.unlisted, h)
			}
			f.mu.Unlock()
			report, exit := f.answer(h)
			if exit == noAnswer {
				continue
			}
			out := filepath.Join(f.dir, syncspec.ScanOutDir, h)
			switch {
			case strings.HasPrefix(report, "symlink:"):
				_ = os.Symlink(strings.TrimPrefix(report, "symlink:"), out+".json")
			case report == fifo:
				_ = syscall.Mkfifo(out+".json", 0o600)
			default:
				_ = os.WriteFile(out+".json", []byte(report), 0o600)
			}
			_ = os.WriteFile(out+".exit", []byte(exit+"\n"), 0o600)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func topLevel(dir, hex string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "index.json")) //nolint:gosec // test temp dir
	if err != nil {
		return false
	}
	im, err := v1.ParseIndexManifest(bytes.NewReader(b))
	if err != nil {
		return false
	}
	return slices.ContainsFunc(im.Manifests, func(d v1.Descriptor) bool { return d.Digest.Hex == hex })
}

type gateEnv struct {
	gate    *Gate
	sidecar *fakeSidecar
	// version and dbAge are what the fake server's /version returns.
	version string
	dbAge   time.Duration
}

// newGate starts a fake Trivy server and a fake sidecar that answers every
// scan with answer, and returns a gate with policy p.
func newGate(t *testing.T, p vuln.Policy, answer func(hex string) (string, string)) *gateEnv {
	t.Helper()
	dir := t.TempDir()
	scan, work := filepath.Join(dir, "scan"), filepath.Join(dir, "work", "layout")
	for _, d := range []string{syncspec.ScanReqDir, syncspec.ScanOutDir} {
		if err := os.MkdirAll(filepath.Join(scan, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	e := &gateEnv{version: pinnedVersion, dbAge: time.Hour}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprintf(w, `{"Version":%q,"VulnerabilityDB":{"Version":2,"UpdatedAt":%q}}`,
			e.version, time.Now().Add(-e.dbAge).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(srv.Close)
	if err := os.WriteFile(filepath.Join(scan, syncspec.ScanVersionFile), []byte(`{"Version":"0.76.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.sidecar = &fakeSidecar{dir: scan, layout: work, answer: answer}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.sidecar.run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	e.gate = &Gate{
		Policy: p, Namespace: "team-a", Repository: "example.com/team/app",
		LayoutDir: work, ScanDir: scan,
		ServerURL: srv.URL, Client: srv.Client(), Version: pinnedVersion,
		MaxDBAge: 72 * time.Hour, Timeout: 2 * time.Second, Poll: 5 * time.Millisecond,
	}
	return e
}

func always(report, exit string) func(string) (string, string) {
	return func(string) (string, string) { return report, exit }
}

func gatedRequest(src, dst *testRegistry, g *Gate) Request {
	return Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{Tags: []string{v100}}, Gate: g}
}

func TestGateReportCopiesScannedBytes(t *testing.T) {
	src, dst := newRegistry(t, regOpts{referrers: true}), newRegistry(t, regOpts{referrers: true})
	img := image(t)
	d := push(t, src.repo, v100, img)
	sig := signature(t, &v1.Descriptor{MediaType: types.DockerManifestSchema2, Digest: d, Size: must(img.Size())})
	ref := push(t, src.repo, "sig", sig)
	e := newGate(t, vuln.Policy{Action: vuln.Report}, always(critical, "0"))

	res, err := Run(context.Background(), gatedRequest(src, dst, e.gate))
	if err != nil {
		t.Fatal(err)
	}
	if tagsOf(res.Copied)[0] != v100 || len(res.Blocked) != 0 || res.Gate != syncspec.GateOK || res.JavaScanned {
		t.Fatalf("result %+v", res)
	}
	sc := res.Copied[0].Scan
	if sc == nil || sc.Verdict != vuln.FindingsFound || sc.Block || sc.PresentOnTarget || sc.DBUpdatedAt.IsZero() ||
		!slices.Equal(sc.TopIDs, []string{"CVE-2026-0001"}) {
		t.Fatalf("scan %+v", sc)
	}
	if got := e.sidecar.requests(); !slices.Equal(got, []string{d.Hex}) || len(e.sidecar.unlisted) != 0 {
		t.Fatalf("scanned %v, unlisted %v", got, e.sidecar.unlisted)
	}
	if got, ok := headDigest(t, dst.repo.Tag(v100)); !ok || got != d.String() {
		t.Fatalf("target tag %s", got)
	}
	if _, ok := headDigest(t, dst.repo.Digest(ref.String())); !ok {
		t.Fatal("referrer not copied")
	}
	if _, err := os.Stat(e.gate.LayoutDir); !os.IsNotExist(err) {
		t.Fatalf("layout left behind: %v", err)
	}
}

func TestGateBlock(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	d := push(t, src.repo, v100, image(t))
	e := newGate(t, vuln.Policy{Action: vuln.Block}, always(critical, "0"))

	res, err := Run(context.Background(), gatedRequest(src, dst, e.gate))
	if err != nil {
		t.Fatalf("blocking for findings is no error: %v", err)
	}
	if len(res.Copied) != 0 || tagsOf(res.Blocked)[0] != v100 || res.Blocked[0].Scan.Verdict != vuln.FindingsFound || len(res.Errors) != 0 {
		t.Fatalf("result %+v", res)
	}
	if _, ok := headDigest(t, dst.repo.Digest(d.String())); ok || dst.writes.Load() != 0 {
		t.Fatalf("blocked digest reached the target (%d writes)", dst.writes.Load())
	}
}

func TestGateException(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	d := push(t, src.repo, v100, image(t))
	e := newGate(t, vuln.Policy{Action: vuln.Block}, always(critical, "0"))
	exc := vuln.Exception{Name: "accept", Namespaces: []string{"team-a"}, Repository: "example.com/team/app",
		Digests: []string{d.String()}, Expires: time.Now().Add(time.Hour)}

	for _, tc := range []struct {
		name string
		exc  vuln.Exception
		want vuln.Verdict
	}{
		{"other namespace", func() vuln.Exception { x := exc; x.Namespaces = []string{"team-b"}; return x }(), vuln.FindingsFound},
		{"expired", func() vuln.Exception { x := exc; x.Expires = time.Now().Add(-time.Second); return x }(), vuln.FindingsFound},
		{"matching", exc, vuln.Accepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.gate.Exceptions = []vuln.Exception{tc.exc}
			res, err := Run(context.Background(), gatedRequest(src, dst, e.gate))
			if err != nil {
				t.Fatal(err)
			}
			var sc *Scan
			for _, as := range [][]Artifact{res.Copied, res.Blocked} {
				if len(as) == 1 {
					sc = as[0].Scan
				}
			}
			copied := len(res.Copied) == 1
			if sc == nil || sc.Verdict != tc.want || copied != (tc.want == vuln.Accepted) {
				t.Fatalf("result %+v", res)
			}
		})
	}
}

func TestGateMultiArch(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	attestation := map[string]string{"vnd.docker.reference.type": "attestation-manifest"}
	amd64, arm64, att := image(t), image(t), attestationImage(t)
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	idx = mutate.AppendManifests(idx,
		// A publisher-controlled annotation never skips a real platform.
		mutate.IndexAddendum{Add: amd64, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}, Annotations: attestation}},
		mutate.IndexAddendum{Add: arm64, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}}},
		mutate.IndexAddendum{Add: att, Descriptor: v1.Descriptor{Platform: unknownPlatform, Annotations: attestation}},
	)
	d := push(t, src.repo, v100, idx)
	armHex := digestOf(t, arm64).Hex
	// arm64 has a critical finding, amd64 is clean.
	e := newGate(t, vuln.Policy{Action: vuln.Report}, func(h string) (string, string) {
		if h == armHex {
			return critical, "0"
		}
		return clean, "0"
	})

	res, err := Run(context.Background(), gatedRequest(src, dst, e.gate))
	if err != nil {
		t.Fatal(err)
	}
	got := e.sidecar.requests()
	slices.Sort(got)
	want := []string{digestOf(t, amd64).Hex, armHex}
	slices.Sort(want)
	if !slices.Equal(got, want) || len(e.sidecar.unlisted) != 0 {
		t.Fatalf("scanned %v, want %v (unlisted %v)", got, want, e.sidecar.unlisted)
	}
	sc := res.Copied[0].Scan
	if sc.Verdict != vuln.FindingsFound || len(sc.Platforms) != 2 || sc.Platforms[1].Platform != "linux/arm64" ||
		sc.Platforms[1].Verdict != vuln.FindingsFound || sc.Platforms[0].Verdict != vuln.Passed {
		t.Fatalf("scan %+v", sc)
	}
	// The index digest round-trips and every child, the attestation too, is on the target.
	if got, ok := headDigest(t, dst.repo.Tag(v100)); !ok || got != d.String() {
		t.Fatalf("target index %s, want %s", got, d)
	}
	for _, c := range []v1.Image{amd64, arm64, att} {
		if _, ok := headDigest(t, dst.repo.Digest(digestOf(t, c).String())); !ok {
			t.Fatal("child missing on target")
		}
	}
}

var unknownPlatform = &v1.Platform{OS: "unknown", Architecture: "unknown"}

// attestationImage is a buildkit-style attestation manifest: in-toto layers only.
func attestationImage(t *testing.T) v1.Image {
	t.Helper()
	return must(mutate.AppendLayers(empty.Image, static.NewLayer([]byte(`{"_type":"https://in-toto.io/Statement/v1"}`), "application/vnd.in-toto+json")))
}

// The platform label is publisher-controlled: an image labelled
// unknown/unknown is scanned, a nested index labelled so cannot be judged,
// and an index of attestations only is never a pass.
func TestGateUnknownPlatformLabel(t *testing.T) {
	for _, tc := range []struct {
		name    string
		add     func(t *testing.T) mutate.Appendable
		scanned bool
		verdict vuln.Verdict
	}{
		{"real image", func(t *testing.T) mutate.Appendable { return image(t) }, true, vuln.FindingsFound},
		{"nested index", func(t *testing.T) mutate.Appendable { return index(t, "linux/amd64") }, false, vuln.ScanError},
		{"attestations only", func(t *testing.T) mutate.Appendable { return attestationImage(t) }, false, vuln.ScanError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
			child := tc.add(t)
			idx := mutate.AppendManifests(mutate.IndexMediaType(empty.Index, types.OCIImageIndex),
				mutate.IndexAddendum{Add: child, Descriptor: v1.Descriptor{Platform: unknownPlatform}})
			push(t, src.repo, v100, idx)
			e := newGate(t, vuln.Policy{Action: vuln.Block, OnScanError: vuln.Block}, always(critical, "0"))

			res, _ := Run(context.Background(), gatedRequest(src, dst, e.gate))
			got := e.sidecar.requests()
			if (len(got) == 1 && got[0] == digestOf(t, child).Hex) != tc.scanned || len(res.Blocked) != 1 {
				t.Fatalf("scanned %v, result %+v", got, res)
			}
			sc := res.Blocked[0].Scan
			if sc.Verdict != tc.verdict || (tc.verdict == vuln.ScanError && (sc.Reason != syncspec.GateScanFailed || sc.Detail == "")) {
				t.Fatalf("scan %+v", sc)
			}
		})
	}
}

func TestGateScanErrors(t *testing.T) {
	huge := "[" + strings.Repeat(" ", vuln.MaxReportBytes) + "]"
	// A report outside the scan volume, valid JSON: a symlink must not reach it.
	outside := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(outside, []byte(clean), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, report, exit, reason string
		noSidecar                  bool
	}{
		{"garbage", "not json", "0", syncspec.GateScanFailed, false},
		{"huge", huge, "0", syncspec.GateScanFailed, false},
		{"exit 1", critical, "1", syncspec.GateScanFailed, false},
		{"symlink out of the volume", "symlink:" + outside, "0", syncspec.GateScanFailed, false},
		{fifo, fifo, "0", syncspec.GateScanFailed, false},
		{"exit garbage", clean, "zero", syncspec.GateScanFailed, false},
		{"timeout or crash", clean, noAnswer, syncspec.GateScanFailed, false},
		{"sidecar not running", clean, "0", syncspec.GateScannerUnavailable, true},
	} {
		for _, onErr := range []vuln.Action{vuln.Report, vuln.Block} {
			t.Run(tc.name+"/"+string(onErr), func(t *testing.T) {
				src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
				push(t, src.repo, v100, image(t))
				e := newGate(t, vuln.Policy{Action: vuln.Block, OnScanError: onErr}, always(tc.report, tc.exit))
				e.gate.Timeout = 300 * time.Millisecond
				if tc.noSidecar {
					_ = os.Remove(filepath.Join(e.gate.ScanDir, syncspec.ScanVersionFile))
					e.sidecar.answer = always(clean, noAnswer)
				}
				res, err := Run(context.Background(), gatedRequest(src, dst, e.gate))
				var arts []Artifact
				if onErr == vuln.Block {
					var sb *ScanBlockedError
					if !errors.As(err, &sb) || !sb.Retryable() || len(res.Copied) != 0 || len(res.Errors) != 1 {
						t.Fatalf("err %v, result %+v", err, res)
					}
					arts = res.Blocked
				} else {
					if err != nil || len(res.Copied) != 1 {
						t.Fatalf("err %v, result %+v", err, res)
					}
					arts = res.Copied
				}
				sc := arts[0].Scan
				if sc.Verdict != vuln.ScanError || sc.Reason != tc.reason || sc.Detail == "" {
					t.Fatalf("scan %+v", sc)
				}
			})
		}
	}
}

func TestGateScannerChecks(t *testing.T) {
	for _, tc := range []struct {
		name      string
		setup     func(e *gateEnv)
		reason    string
		retryable bool
	}{
		{"server version", func(e *gateEnv) { e.version = "0.75.0" }, syncspec.GateVersionMismatch, false},
		{"client version", func(e *gateEnv) {
			_ = os.WriteFile(filepath.Join(e.gate.ScanDir, syncspec.ScanVersionFile), []byte(`{"Version":"0.60.0"}`), 0o600)
		}, syncspec.GateVersionMismatch, false},
		{"stale DB", func(e *gateEnv) { e.dbAge = 73 * time.Hour }, syncspec.GateDBStale, false},
		{"server down", func(e *gateEnv) { e.gate.ServerURL = "http://127.0.0.1:1" }, syncspec.GateScannerUnavailable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
			push(t, src.repo, v100, image(t))
			push(t, src.repo, "v1.1.0", image(t))
			e := newGate(t, vuln.Policy{OnScanError: vuln.Block}, always(clean, "0"))
			tc.setup(e)
			req := gatedRequest(src, dst, e.gate)
			req.Policy = tags.Policy{KeepLatest: 2}
			res, err := Run(context.Background(), req)
			var sb *ScanBlockedError
			if !errors.As(err, &sb) || sb.Retryable() != tc.retryable || res.Gate != tc.reason || len(res.Blocked) != 2 {
				t.Fatalf("err %v, result %+v", err, res)
			}
			if n := len(e.sidecar.requests()); n != 0 {
				t.Fatalf("%d scans despite a failed check", n)
			}
			if dst.writes.Load() != 0 {
				t.Fatal("blocked tags reached the target")
			}
		})
	}
}

func TestGatePresentOnTarget(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	img := image(t)
	d := push(t, src.repo, v100, img)
	push(t, dst.repo, v100, img)
	e := newGate(t, vuln.Policy{Action: vuln.Block}, always(critical, "0"))

	res, err := Run(context.Background(), gatedRequest(src, dst, e.gate))
	if err != nil {
		t.Fatal(err)
	}
	sc := res.Skipped[0].Scan
	if sc == nil || !sc.PresentOnTarget || !sc.Block || len(res.Blocked) != 0 {
		t.Fatalf("result %+v", res)
	}

	e.gate.Judged = map[string]string{v100: d.String()}
	before := len(e.sidecar.requests())
	res, err = Run(context.Background(), gatedRequest(src, dst, e.gate))
	if err != nil || res.Skipped[0].Scan != nil || len(e.sidecar.requests()) != before || res.Gate != "" {
		t.Fatalf("recorded tag scanned again: %v %+v", err, res)
	}
}

// tarball builds a tar stream from headers; regular files get size bytes.
func tarball(t *testing.T, hs ...*tar.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range hs {
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func reg(n string, size int64) *tar.Header {
	return &tar.Header{Name: n, Typeflag: tar.TypeReg, Size: size}
}

func TestExtractTar(t *testing.T) {
	allowed := javaDBFiles
	for _, tc := range []struct {
		name string
		hs   []*tar.Header
		ok   bool
	}{
		{"valid", []*tar.Header{{Name: "./", Typeflag: tar.TypeDir}, reg("./"+jdb, 10), reg(meta, 2)}, true},
		{"absolute", []*tar.Header{reg("/etc/trivy-java.db", 1)}, false},
		{"parent", []*tar.Header{reg("../trivy-java.db", 1)}, false},
		{"nested parent", []*tar.Header{reg("a/../../metadata.json", 1)}, false},
		{"unexpected name", []*tar.Header{reg("evil.sh", 1)}, false},
		{"directory", []*tar.Header{{Name: "java-db/", Typeflag: tar.TypeDir}}, false},
		{"symlink", []*tar.Header{{Name: jdb, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}, false},
		{"hardlink", []*tar.Header{reg(meta, 1), {Name: jdb, Typeflag: tar.TypeLink, Linkname: "../../x"}}, false},
		{"char device", []*tar.Header{{Name: jdb, Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3}}, false},
		{"fifo", []*tar.Header{{Name: jdb, Typeflag: tar.TypeFifo}}, false},
		{"duplicate", []*tar.Header{reg(meta, 1), reg(meta, 1)}, false},
		{"too large", []*tar.Header{reg(jdb, 60), reg(meta, 50)}, false},
		{"too many files", []*tar.Header{reg(jdb, 1), reg(meta, 1), reg("./"+meta, 1)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outer := t.TempDir()
			dir := filepath.Join(outer, "java-db")
			if err := os.Mkdir(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			err = extractTar(bytes.NewReader(tarball(t, tc.hs...)), root, allowed, 2, 100)
			if (err == nil) != tc.ok {
				t.Fatalf("err %v", err)
			}
			// Nothing ever lands outside the root.
			entries, _ := os.ReadDir(outer)
			if len(entries) != 1 {
				t.Fatalf("outside root: %v", entries)
			}
		})
	}
	t.Run("existing symlink is not followed", func(t *testing.T) {
		dir, outside := t.TempDir(), filepath.Join(t.TempDir(), "target")
		if err := os.Symlink(outside, filepath.Join(dir, meta)); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if err := extractTar(bytes.NewReader(tarball(t, reg(meta, 1))), root, allowed, 2, 100); err == nil {
			t.Fatal("wrote through a symlink")
		}
		if _, err := os.Stat(outside); !os.IsNotExist(err) {
			t.Fatal("file created outside the root")
		}
	})
}

func javaDBImage(t *testing.T, mt types.MediaType, files ...*tar.Header) v1.Image {
	t.Helper()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(tarball(t, files...))
	_ = zw.Close()
	return must(mutate.AppendLayers(empty.Image, static.NewLayer(gz.Bytes(), mt)))
}

func TestGateJavaDB(t *testing.T) {
	for _, tc := range []struct {
		name string
		img  func(t *testing.T) v1.Image
		ok   bool
	}{
		{"valid", func(t *testing.T) v1.Image {
			return javaDBImage(t, javaDBMediaType, reg(jdb, 10), reg(meta, 2))
		}, true},
		{"wrong media type", func(t *testing.T) v1.Image {
			return javaDBImage(t, types.OCILayer, reg(jdb, 10))
		}, false},
		{"symlink in tarball", func(t *testing.T) v1.Image {
			return javaDBImage(t, javaDBMediaType, &tar.Header{Name: jdb, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
			push(t, src.repo, v100, image(t))
			ref := must(name.NewTag(dst.repo.Registry.Name() + "/platform/trivy-java-db:1"))
			push(t, ref.Context(), "1", tc.img(t))
			e := newGate(t, vuln.Policy{OnScanError: vuln.Block}, always(clean, "0"))
			e.gate.JavaDB = &ref

			res, err := Run(context.Background(), gatedRequest(src, dst, e.gate))
			db := filepath.Join(e.gate.ScanDir, syncspec.JavaDBDir, jdb)
			_, serr := os.Stat(db)
			if tc.ok {
				if err != nil || !res.JavaScanned || res.Gate != syncspec.GateOK || !res.Copied[0].Scan.JavaScanned || serr != nil {
					t.Fatalf("err %v, stat %v, result %+v", err, serr, res)
				}
				return
			}
			if err == nil || res.JavaScanned || res.Gate != syncspec.GateScannerUnavailable || serr == nil {
				t.Fatalf("err %v, result %+v", err, res)
			}
		})
	}
}

func TestGateCredentialsNotInScanDir(t *testing.T) {
	src, dst := newRegistry(t, regOpts{auth: true}), newRegistry(t, regOpts{})
	auth := remote.WithAuth(&authn.Basic{Username: user, Password: password})
	push(t, src.repo, v100, image(t), auth)
	e := newGate(t, vuln.Policy{}, always(clean, "0"))
	req := gatedRequest(src, dst, e.gate)
	req.SourceOpts = []remote.Option{auth}
	if _, err := Run(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	_ = filepath.WalkDir(filepath.Dir(e.gate.ScanDir), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p) //nolint:gosec // test temp dir
			if bytes.Contains(b, []byte(password)) {
				t.Fatalf("credential in %s", p)
			}
		}
		return nil
	})
}

// signature is a cosign simple signing artifact for subject.
func signature(t *testing.T, subject *v1.Descriptor) v1.Image {
	t.Helper()
	img := must(mutate.AppendLayers(empty.Image, static.NewLayer([]byte(`{"critical":{}}`), "application/vnd.dev.cosign.simplesigning.v1+json")))
	if subject != nil {
		img = mutate.Subject(img, *subject).(v1.Image)
	}
	return img
}

func TestGateReferrers(t *testing.T) {
	src, dst := newRegistry(t, regOpts{referrers: true}), newRegistry(t, regOpts{referrers: true})
	img := image(t)
	d := push(t, src.repo, v100, img)
	subject := &v1.Descriptor{MediaType: types.DockerManifestSchema2, Digest: d, Size: must(img.Size())}
	// A runnable image as referrer and as cosign .sig tag would bypass the scan.
	runnable := pushReferrer(t, src.repo, *subject)
	sig := signature(t, subject)
	push(t, src.repo, "unused", sig)
	sigTag := push(t, src.repo, fallbackTag(d)+".sig", image(t))

	e := newGate(t, vuln.Policy{Action: vuln.Report}, always(clean, "0"))
	res, err := Run(context.Background(), gatedRequest(src, dst, e.gate))
	if err != nil {
		t.Fatal(err)
	}
	a := res.Copied[0]
	if _, ok := headDigest(t, dst.repo.Digest(digestOf(t, sig).String())); !ok {
		t.Fatal("signature referrer not copied")
	}
	for _, h := range []v1.Hash{runnable, sigTag} {
		if _, ok := headDigest(t, dst.repo.Digest(h.String())); ok || !slices.Contains(a.SkippedReferrers, h.String()) {
			t.Fatalf("%s copied or not reported: %v", h, a.SkippedReferrers)
		}
	}

	t.Run("blocked tag on the target gets no referrers", func(t *testing.T) {
		dst := newRegistry(t, regOpts{referrers: true})
		push(t, dst.repo, v100, img)
		e := newGate(t, vuln.Policy{Action: vuln.Block}, always(critical, "0"))
		res, err := Run(context.Background(), gatedRequest(src, dst, e.gate))
		if err != nil || !res.Skipped[0].Scan.Block {
			t.Fatalf("err %v, result %+v", err, res)
		}
		if _, ok := headDigest(t, dst.repo.Digest(digestOf(t, sig).String())); ok {
			t.Fatal("referrer of a blocked tag copied")
		}
	})
}

func TestGateIgnoredMutationScansTarget(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	push(t, src.repo, v100, image(t))
	kept := push(t, dst.repo, v100, image(t))
	e := newGate(t, vuln.Policy{Action: vuln.Block}, always(critical, "0"))
	req := gatedRequest(src, dst, e.gate)
	req.OnTagMutation = v1alpha1.OnTagMutationIgnore

	res, err := Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	a := res.Skipped[0]
	if a.Digest != kept.String() || a.Scan == nil || !a.Scan.PresentOnTarget || a.Scan.Verdict != vuln.FindingsFound ||
		!slices.Equal(e.sidecar.requests(), []string{kept.Hex}) {
		t.Fatalf("artifact %+v, scanned %v", a, e.sidecar.requests())
	}
	e.gate.Judged = map[string]string{v100: kept.String()}
	if res, err = Run(context.Background(), req); err != nil || res.Skipped[0].Scan != nil {
		t.Fatalf("judged digest scanned again: %v %+v", err, res)
	}
}

func TestGateJavaDBIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trailer int  // bytes after the tar end marker, inside the gzip stream
		corrupt bool // a gzip MTIME byte flipped when served: valid gzip, wrong digest
	}{
		{"trailing data", maxJavaDBTrailing + 1, false},
		{"corrupted blob", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
			push(t, src.repo, v100, image(t))
			raw := append(tarball(t, reg(jdb, 10), reg(meta, 2)), bytes.Repeat([]byte{0}, tc.trailer)...)
			var gz bytes.Buffer
			w := gzip.NewWriter(&gz)
			_, _ = w.Write(raw)
			_ = w.Close()
			layer := static.NewLayer(gz.Bytes(), javaDBMediaType)
			ref := must(name.NewTag(dst.repo.Registry.Name() + "/platform/trivy-java-db:1"))
			push(t, ref.Context(), "1", must(mutate.AppendLayers(empty.Image, layer)))
			if tc.corrupt {
				dst.mu.Lock()
				dst.flipBlob = map[string]int{must(layer.Digest()).String(): 4}
				dst.mu.Unlock()
			}
			e := newGate(t, vuln.Policy{OnScanError: vuln.Block}, always(clean, "0"))
			e.gate.JavaDB = &ref

			res, err := Run(context.Background(), gatedRequest(src, dst, e.gate))
			if err == nil || res.JavaScanned || res.Gate != syncspec.GateScannerUnavailable {
				t.Fatalf("err %v, result %+v", err, res)
			}
			if _, err := os.Stat(filepath.Join(e.gate.ScanDir, syncspec.JavaDBDir)); !os.IsNotExist(err) {
				t.Fatalf("java DB left behind: %v", err)
			}
		})
	}
}
