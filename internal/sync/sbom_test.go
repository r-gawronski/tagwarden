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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	stdsync "sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/sbom"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
	"github.com/r-gawronski/tagwarden/internal/tags"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

const (
	cdxDoc  = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	spdxDoc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[]}`
	// huge makes the fake generator write a document over sbom.MaxSize.
	huge = "huge"
	// late makes the fake generator answer after the timeout.
	late = "late"
	// garbage is not JSON.
	garbage       = "garbage"
	detailMissing = "SBOM missing"
	detailInvalid = "invalid SBOM"
	trivyGen      = "trivy/0.76.1"
	linuxAMD64    = "linux/amd64"
)

// bigDoc is a valid CycloneDX document of about 4 KiB.
var bigDoc = `{"bomFormat":"CycloneDX","specVersion":"1.6","pad":"` + strings.Repeat("x", 4096) + `"}`

// fakeGenerator speaks the SBOM request kind of the sidecar protocol.
// answer returns the document and exit code for a hex and format; an
// empty exit never answers.
type fakeGenerator struct {
	dir     string
	answer  func(hex, format string) (doc, exit string)
	stopped atomic.Bool
	mu      stdsync.Mutex
	handled []string
}

func (f *fakeGenerator) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.handled)
}

func (f *fakeGenerator) run(ctx context.Context) {
	for ctx.Err() == nil {
		for _, format := range []string{"cyclonedx", "spdx-json"} {
			if f.stopped.Load() {
				break
			}
			rs, _ := filepath.Glob(filepath.Join(f.dir, syncspec.ScanReqDir, "*."+format))
			for _, r := range rs {
				_ = os.Remove(r)
				h := strings.TrimSuffix(filepath.Base(r), "."+format)
				f.mu.Lock()
				f.handled = append(f.handled, h+"."+format)
				f.mu.Unlock()
				doc, exit := f.answer(h, format)
				if exit == noAnswer {
					continue
				}
				out := filepath.Join(f.dir, syncspec.ScanOutDir, h+"."+format)
				switch {
				case doc == huge:
					big := `{"bomFormat":"CycloneDX","specVersion":"1.6","pad":"` + strings.Repeat("x", int(sbom.MaxSize)) + `"}`
					_ = os.WriteFile(out+".json", []byte(big), 0o600)
				case doc == late:
					time.Sleep(time.Second)
					_ = os.WriteFile(out+".json", []byte(cdxDoc), 0o600)
				case strings.HasPrefix(doc, "symlink:"):
					_ = os.Symlink(strings.TrimPrefix(doc, "symlink:"), out+".json")
				case doc == fifo:
					_ = syscall.Mkfifo(out+".json", 0o600)
				default:
					_ = os.WriteFile(out+".json", []byte(doc), 0o600)
				}
				_ = os.WriteFile(out+".exit.tmp", []byte(exit+"\n"), 0o600)
				_ = os.Rename(out+".exit.tmp", out+".exit")
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// newSBOM starts a fake generator on fresh scan and layout dirs and returns
// a Generate CycloneDX policy that uses it.
func newSBOM(t *testing.T, answer func(hex, format string) (string, string)) (*SBOM, *fakeGenerator) {
	t.Helper()
	dir := t.TempDir()
	return newSBOMIn(t, filepath.Join(dir, "scan"), filepath.Join(dir, "work", "layout"), answer)
}

func newSBOMIn(t *testing.T, scan, layout string, answer func(hex, format string) (string, string)) (*SBOM, *fakeGenerator) {
	t.Helper()
	for _, d := range []string{syncspec.ScanReqDir, syncspec.ScanOutDir} {
		if err := os.MkdirAll(filepath.Join(scan, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(scan, syncspec.ScanVersionFile), []byte(`{"Version":"0.76.2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &fakeGenerator{dir: scan, answer: answer}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return &SBOM{
		Mode: v1alpha1.SBOMModeGenerate, Format: sbom.CycloneDX, Version: pinnedVersion,
		LayoutDir: layout, ScanDir: scan, Timeout: 500 * time.Millisecond, Poll: 5 * time.Millisecond,
	}, g
}

func must2[T, U any](a T, b U, err error) (T, U) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func canned(doc, exit string) func(string, string) (string, string) {
	return func(string, string) (string, string) { return doc, exit }
}

func sbomRequest(src, dst *testRegistry, b *SBOM) Request {
	return Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{Tags: []string{v100}}, SBOM: b}
}

// referrersOf lists the referrers of d in repo.
func referrersOf(t *testing.T, repo name.Repository, d v1.Hash) []v1.Descriptor {
	t.Helper()
	im := must(must(remote.Referrers(repo.Digest(d.String()))).IndexManifest())
	return im.Manifests
}

func generated(t *testing.T, repo name.Repository, d v1.Hash, platform string) []v1.Descriptor {
	t.Helper()
	return slices.DeleteFunc(referrersOf(t, repo, d), func(m v1.Descriptor) bool { return !sbom.Generated(m, sbom.CycloneDX, platform) })
}

// docOf reads the single layer of the referrer m in repo.
func docOf(t *testing.T, repo name.Repository, m v1.Descriptor) string {
	t.Helper()
	img := must(remote.Image(repo.Digest(m.Digest.String())))
	ls := must(img.Layers())
	if len(ls) != 1 {
		t.Fatalf("referrer %s has %d layers", m.Digest, len(ls))
	}
	return string(must(io.ReadAll(must(ls[0].Compressed()))))
}

// multiArch is an index of two platforms and an attestation manifest.
func multiArch(t *testing.T) (v1.ImageIndex, v1.Image, v1.Image) {
	t.Helper()
	amd64, arm64 := image(t), image(t)
	idx := mutate.AppendManifests(mutate.IndexMediaType(empty.Index, types.OCIImageIndex),
		mutate.IndexAddendum{Add: amd64, Descriptor: v1.Descriptor{Platform: must(v1.ParsePlatform(linuxAMD64))}},
		mutate.IndexAddendum{Add: arm64, Descriptor: v1.Descriptor{Platform: must(v1.ParsePlatform("linux/arm64"))}},
		mutate.IndexAddendum{Add: attestationImage(t), Descriptor: v1.Descriptor{Platform: unknownPlatform}},
	)
	return idx, amd64, arm64
}

// TestSBOMGenerateMultiArch attaches a generated SBOM to each platform
// child and a copy of each to the index, with and without the referrers
// API on the target.
func TestSBOMGenerateMultiArch(t *testing.T) {
	for _, referrers := range []bool{true, false} {
		t.Run(fmt.Sprintf("referrers API %v", referrers), func(t *testing.T) {
			src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{referrers: referrers})
			idx, amd64, arm64 := multiArch(t)
			d := push(t, src.repo, v100, idx)
			b, g := newSBOM(t, canned(cdxDoc, "0"))

			res, err := Run(context.Background(), sbomRequest(src, dst, b))
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := headDigest(t, dst.repo.Tag(v100)); !ok || got != d.String() {
				t.Fatalf("target tag %s, want %s", got, d)
			}
			want := []string{digestOf(t, amd64).Hex + ".cyclonedx", digestOf(t, arm64).Hex + ".cyclonedx"}
			got := g.requests()
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("requests %v, want %v (attestation skipped)", got, want)
			}
			a := res.Copied[0]
			if a.SBOM == nil || a.SBOM.Reason != "" || len(a.SBOM.Platforms) != 2 || res.JavaScanned {
				t.Fatalf("SBOM %+v", a.SBOM)
			}
			for i, c := range []v1.Image{amd64, arm64} {
				p := a.SBOM.Platforms[i]
				refs := generated(t, dst.repo, digestOf(t, c), "")
				if len(refs) != 1 || p.Source != SBOMSourceGenerated || p.Referrer != refs[0].Digest.String() ||
					p.Size != int64(len(cdxDoc)) || p.JavaScanned || refs[0].Annotations[sbom.AnnotationJavaScanned] != "false" ||
					refs[0].Annotations[sbom.AnnotationGenerator] != "trivy/"+pinnedVersion {
					t.Fatalf("child %d: platform %+v, referrers %+v", i, p, refs)
				}
				if doc := docOf(t, dst.repo, refs[0]); doc != cdxDoc {
					t.Fatalf("document %q", doc)
				}
				if copies := generated(t, dst.repo, d, p.Platform); len(copies) != 1 {
					t.Fatalf("index copies for %s: %+v", p.Platform, copies)
				}
			}
			if len(referrersOf(t, dst.repo, d)) != 2 {
				t.Fatalf("index referrers %+v", referrersOf(t, dst.repo, d))
			}
			// The layout is gone after the tag.
			if _, err := os.Stat(b.LayoutDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("layout left: %v", err)
			}

			// A second run finds everything and generates nothing.
			res, err = Run(context.Background(), sbomRequest(src, dst, b))
			if err != nil {
				t.Fatal(err)
			}
			if len(g.requests()) != 2 || len(res.Skipped) != 1 || res.Skipped[0].SBOM.Reason != "" ||
				len(res.Skipped[0].SBOM.Platforms) != 2 || res.Skipped[0].SBOM.Platforms[0].Source != SBOMSourcePresent {
				t.Fatalf("second run: requests %v, result %+v", g.requests(), res.Skipped)
			}
		})
	}
}

func TestSBOMSingleImageSPDX(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	img := image(t)
	d := push(t, src.repo, v100, img)
	b, g := newSBOM(t, func(_, format string) (string, string) {
		if format != "spdx-json" {
			return cdxDoc, "0"
		}
		return spdxDoc, "0"
	})
	b.Format = sbom.SPDX

	res, err := Run(context.Background(), sbomRequest(src, dst, b))
	if err != nil {
		t.Fatal(err)
	}
	if got := g.requests(); !slices.Equal(got, []string{d.Hex + ".spdx-json"}) {
		t.Fatalf("requests %v", got)
	}
	refs := slices.DeleteFunc(referrersOf(t, dst.repo, d), func(m v1.Descriptor) bool { return !sbom.Generated(m, sbom.SPDX, "") })
	if len(refs) != 1 || docOf(t, dst.repo, refs[0]) != spdxDoc || len(res.Copied[0].SBOM.Platforms) != 1 {
		t.Fatalf("referrers %+v, result %+v", referrersOf(t, dst.repo, d), res.Copied[0].SBOM)
	}
	if len(referrersOf(t, dst.repo, d)) != 1 {
		t.Fatal("a single image gets one referrer, no index copy")
	}
}

// TestSBOMFailures feeds the fake generator canned, late, garbage and huge
// output. Under required: true nothing is pushed and the tag fails; under
// required: false the tag is published and the failure reported.
func TestSBOMFailures(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(outside, []byte(cdxDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, doc, exit, reason, detail string
		maxSize                         int64
		unavailable                     bool
	}{
		{name: garbage, doc: "not json", exit: "0", reason: syncspec.SBOMGenerationFailed, detail: detailInvalid},
		{name: "other format", doc: spdxDoc, exit: "0", reason: syncspec.SBOMGenerationFailed, detail: detailInvalid},
		{name: "trailing data", doc: cdxDoc + cdxDoc, exit: "0", reason: syncspec.SBOMGenerationFailed, detail: detailInvalid},
		{name: "exit 1", doc: cdxDoc, exit: "1", reason: syncspec.SBOMGenerationFailed, detail: "generator exited with an error"},
		{name: "garbage exit", doc: cdxDoc, exit: strings.Repeat("0", 20), reason: syncspec.SBOMGenerationFailed, detail: "invalid generator exit file"},
		{name: "no document", doc: "symlink:" + filepath.Join(dir, "missing"), exit: "0", reason: syncspec.SBOMGenerationFailed, detail: detailMissing},
		{name: "symlink", doc: "symlink:" + outside, exit: "0", reason: syncspec.SBOMGenerationFailed, detail: detailMissing},
		{name: "fifo", doc: fifo, exit: "0", reason: syncspec.SBOMGenerationFailed, detail: detailMissing},
		{name: "huge", doc: huge, exit: "0", reason: syncspec.SBOMTooLarge},
		{name: "over budget", doc: bigDoc, exit: "0", reason: syncspec.SBOMTooLarge, maxSize: 1000},
		{name: "late", doc: late, exit: "0", reason: syncspec.SBOMGenerationFailed, detail: "generation timed out"},
		{name: "taken, no answer", doc: cdxDoc, exit: noAnswer, reason: syncspec.SBOMGenerationFailed, detail: "generation timed out"},
		{name: "sidecar gone", doc: cdxDoc, exit: "0", reason: syncspec.SBOMGenerationFailed, detail: "generator sidecar did not answer", unavailable: true},
	} {
		for _, required := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s required %v", tc.name, required), func(t *testing.T) {
				src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
				img := image(t)
				d := push(t, src.repo, v100, img)
				b, g := newSBOM(t, canned(tc.doc, tc.exit))
				b.Required = required
				// The sidecar passed its start check, then stopped: requests stay.
				g.stopped.Store(tc.name == "sidecar gone")
				req := sbomRequest(src, dst, b)
				if tc.maxSize > 0 {
					req.MaxArtifactSize = max(artifactSize(t, img), tc.maxSize)
				}
				res, err := Run(context.Background(), req)
				var a Artifact
				switch {
				case required:
					if err == nil || len(res.Failed) != 1 || len(res.Copied) != 0 || !strings.Contains(res.Errors[0], "tag not published") {
						t.Fatalf("err %v, result %+v", err, res)
					}
					a = res.Failed[0]
					if _, ok := headDigest(t, dst.repo.Digest(d.String())); ok {
						t.Fatal("digest pushed although its SBOM failed")
					}
				default:
					if len(res.Copied) != 1 || errors.Is(err, ErrSBOMGeneratorUnavailable) != tc.unavailable || (err != nil) != tc.unavailable {
						t.Fatalf("err %v, result %+v", err, res)
					}
					a = res.Copied[0]
					if got, ok := headDigest(t, dst.repo.Tag(v100)); !ok || got != d.String() {
						t.Fatal("tag not published under required: false")
					}
				}
				if a.SBOM == nil || a.SBOM.Reason != tc.reason || tc.detail != "" && a.SBOM.Detail != tc.detail || a.Digest != d.String() {
					t.Fatalf("SBOM %+v of %+v", a.SBOM, a)
				}
				if len(generated(t, dst.repo, d, "")) != 0 {
					t.Fatal("failed SBOM attached")
				}
				outs, _ := filepath.Glob(filepath.Join(b.ScanDir, syncspec.ScanOutDir, "*"))
				if tc.name != "late" && len(outs) != 0 {
					t.Fatalf("answers left in the scan volume: %v", outs)
				}
			})
		}
	}
}

// TestSBOMRequiredIndexAllOrNothing fails the whole index when one child
// has no SBOM.
func TestSBOMRequiredIndexAllOrNothing(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	idx, _, arm64 := multiArch(t)
	d := push(t, src.repo, v100, idx)
	armHex := digestOf(t, arm64).Hex
	b, _ := newSBOM(t, func(h, _ string) (string, string) {
		if h == armHex {
			return garbage, "0"
		}
		return cdxDoc, "0"
	})
	b.Required = true
	res, err := Run(context.Background(), sbomRequest(src, dst, b))
	if err == nil || len(res.Failed) != 1 || res.Failed[0].SBOM.Reason != syncspec.SBOMGenerationFailed {
		t.Fatalf("err %v, result %+v", err, res)
	}
	if _, ok := headDigest(t, dst.repo.Digest(d.String())); ok {
		t.Fatal("index pushed")
	}
}

// TestSBOMAttachFailedRequired keeps the tag from moving when a referrer
// push fails; the digest stays on the target untagged.
func TestSBOMAttachFailedRequired(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	d := push(t, src.repo, v100, image(t))
	b, _ := newSBOM(t, canned(cdxDoc, "0"))
	b.Required = true
	dst.refuseReferrers.Store(true)
	res, err := Run(context.Background(), sbomRequest(src, dst, b))
	if err == nil || len(res.Failed) != 1 || res.Failed[0].SBOM.Reason != syncspec.SBOMAttachFailed {
		t.Fatalf("err %v, result %+v", err, res)
	}
	if _, ok := headDigest(t, dst.repo.Digest(d.String())); !ok {
		t.Fatal("digest not on the target")
	}
	if _, ok := headDigest(t, dst.repo.Tag(v100)); ok {
		t.Fatal("tag moved although the SBOM was not attached")
	}
}

func TestSBOMSidecarChecks(t *testing.T) {
	for _, tc := range []struct {
		name, version, detail string
		unavailable           bool
	}{
		{"not running", "", "generator sidecar not running", true},
		{"version mismatch", `{"Version":"0.77.0"}`, "generator version mismatch, want 0.76.x", false},
		{"invalid version", garbage, "generator sidecar: invalid version", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
			push(t, src.repo, v100, image(t))
			push(t, src.repo, "v2", image(t))
			b, g := newSBOM(t, canned(cdxDoc, "0"))
			vf := filepath.Join(b.ScanDir, syncspec.ScanVersionFile)
			if err := os.Remove(vf); err != nil {
				t.Fatal(err)
			}
			if tc.version != "" {
				if err := os.WriteFile(vf, []byte(tc.version), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			req := sbomRequest(src, dst, b)
			req.Policy.Tags = []string{v100, "v2"}
			res, err := Run(context.Background(), req)
			if errors.Is(err, ErrSBOMGeneratorUnavailable) != tc.unavailable || len(g.requests()) != 0 || len(res.Copied) != 2 {
				t.Fatalf("err %v, requests %v, result %+v", err, g.requests(), res)
			}
			for _, a := range res.Copied {
				if a.SBOM.Reason != syncspec.SBOMGenerationFailed || a.SBOM.Detail != tc.detail {
					t.Fatalf("SBOM %+v", a.SBOM)
				}
			}
		})
	}
}

// rawImage is an OCI 1.1 artifact with the empty config and one layer.
type rawImage struct {
	raw   []byte
	layer v1.Layer
}

func (i *rawImage) RawConfigFile() ([]byte, error)      { return []byte("{}"), nil }
func (i *rawImage) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }
func (i *rawImage) RawManifest() ([]byte, error)        { return i.raw, nil }
func (i *rawImage) LayerByDigest(v1.Hash) (partial.CompressedLayer, error) {
	return i.layer, nil
}

// upstreamSBOM pushes to repo an upstream SBOM referrer of subject with
// artifactType CycloneDX, document doc and annotations ann.
func upstreamSBOM(t *testing.T, repo name.Repository, subject v1.Descriptor, doc string, ann map[string]string) v1.Hash {
	t.Helper()
	mt := sbom.CycloneDX.MediaType()
	layer := static.NewLayer([]byte(doc), mt)
	ld := must(partial.Descriptor(layer))
	cfg, _ := must2(v1.SHA256(strings.NewReader("{}")))
	subject.Platform = nil
	raw := must(json.Marshal(v1.Manifest{
		SchemaVersion: 2, MediaType: types.OCIManifestSchema1, ArtifactType: string(mt),
		Config:  v1.Descriptor{MediaType: sbom.EmptyConfigMediaType, Digest: cfg, Size: 2},
		Layers:  []v1.Descriptor{{MediaType: mt, Digest: ld.Digest, Size: ld.Size}},
		Subject: &subject, Annotations: ann,
	}))
	img := must(partial.CompressedToImage(&rawImage{raw: raw, layer: layer}))
	h := digestOf(t, img)
	if err := remote.Write(repo.Digest(h.String()), img); err != nil {
		t.Fatal(err)
	}
	return h
}

// TestSBOMPreferUpstream uses a valid upstream SBOM of a child instead of
// generating one, and generates for children without one.
func TestSBOMPreferUpstream(t *testing.T) {
	src, dst := newRegistry(t, regOpts{referrers: true}), newRegistry(t, regOpts{referrers: true})
	idx, amd64, arm64 := multiArch(t)
	d := push(t, src.repo, v100, idx)
	amdDesc := must(partial.Descriptor(amd64))
	armDesc := must(partial.Descriptor(arm64))
	up := upstreamSBOM(t, src.repo, *amdDesc, cdxDoc, nil)
	// arm64 has only a forged generated SBOM and an invalid one: neither counts.
	forged := upstreamSBOM(t, src.repo, *armDesc, cdxDoc, map[string]string{sbom.AnnotationGenerator: trivyGen, sbom.AnnotationFormat: "CycloneDX"})
	upstreamSBOM(t, src.repo, *armDesc, `{"bomFormat":"CycloneDX"}`, nil)
	b, g := newSBOM(t, canned(cdxDoc, "0"))
	b.Mode = v1alpha1.SBOMModePreferUpstream

	res, err := Run(context.Background(), sbomRequest(src, dst, b))
	if err != nil {
		t.Fatal(err)
	}
	if got := g.requests(); !slices.Equal(got, []string{armDesc.Digest.Hex + ".cyclonedx"}) {
		t.Fatalf("requests %v", got)
	}
	ps := res.Copied[0].SBOM.Platforms
	if len(ps) != 2 || ps[0].Source != SBOMSourceUpstream || ps[0].Referrer != up.String() || ps[1].Source != SBOMSourceGenerated {
		t.Fatalf("platforms %+v", ps)
	}
	if _, ok := headDigest(t, dst.repo.Digest(up.String())); !ok {
		t.Fatal("upstream SBOM not copied")
	}
	if _, ok := headDigest(t, dst.repo.Digest(forged.String())); ok {
		t.Fatal("forged SBOM copied")
	}
	// Only generated SBOMs get index copies.
	if len(generated(t, dst.repo, d, "linux/arm64")) != 1 || len(referrersOf(t, dst.repo, d)) != 1 {
		t.Fatalf("index referrers %+v", referrersOf(t, dst.repo, d))
	}

	// The next run finds both on the target and does nothing.
	res, err = Run(context.Background(), sbomRequest(src, dst, b))
	if err != nil || len(g.requests()) != 1 || res.Skipped[0].SBOM.Reason != "" || len(res.Skipped[0].SBOM.Platforms) != 2 {
		t.Fatalf("second run: err %v, requests %v, SBOM %+v", err, g.requests(), res.Skipped[0].SBOM)
	}
}

// TestReservedAnnotationsNeverCopied skips upstream referrers that claim
// to be Tagwarden's, with or without an SBOM policy.
func TestReservedAnnotationsNeverCopied(t *testing.T) {
	src, dst := newRegistry(t, regOpts{referrers: true}), newRegistry(t, regOpts{referrers: true})
	img := image(t)
	push(t, src.repo, v100, img)
	desc := must(partial.Descriptor(img))
	forged := upstreamSBOM(t, src.repo, *desc, cdxDoc, map[string]string{"Dev.Tagwarden.sbom.generator": trivyGen})
	plain := upstreamSBOM(t, src.repo, *desc, cdxDoc, nil)

	res, err := Run(context.Background(), Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{Tags: []string{v100}}})
	if err != nil {
		t.Fatal(err)
	}
	a := res.Copied[0]
	if a.Referrers != 1 || !slices.Equal(a.SkippedReferrers, []string{forged.String()}) || a.SBOM != nil {
		t.Fatalf("artifact %+v", a)
	}
	if _, ok := headDigest(t, dst.repo.Digest(plain.String())); !ok {
		t.Fatal("plain referrer not copied")
	}
	if _, ok := headDigest(t, dst.repo.Digest(forged.String())); ok {
		t.Fatal("forged referrer copied")
	}
}

// TestSBOMBackfill attaches SBOMs to a tag mirrored before the policy,
// never untags it and does not fail the run.
func TestSBOMBackfill(t *testing.T) {
	for _, referrers := range []bool{true, false} {
		t.Run(fmt.Sprintf("referrers API %v", referrers), func(t *testing.T) {
			src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{referrers: referrers})
			idx, amd64, _ := multiArch(t)
			d := push(t, src.repo, v100, idx)
			if _, err := Run(context.Background(), Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{Tags: []string{v100}}}); err != nil {
				t.Fatal(err)
			}

			// A failing generator under required: true reports, keeps the tag.
			var fixed atomic.Bool
			b, _ := newSBOM(t, func(string, string) (string, string) {
				if fixed.Load() {
					return cdxDoc, "0"
				}
				return garbage, "0"
			})
			b.Required = true
			res, err := Run(context.Background(), sbomRequest(src, dst, b))
			if err != nil || len(res.Skipped) != 1 || res.Skipped[0].SBOM.Reason != syncspec.SBOMGenerationFailed {
				t.Fatalf("err %v, result %+v", err, res)
			}
			if got, ok := headDigest(t, dst.repo.Tag(v100)); !ok || got != d.String() {
				t.Fatal("published tag moved or untagged")
			}

			fixed.Store(true)
			res, err = Run(context.Background(), sbomRequest(src, dst, b))
			if err != nil || res.Skipped[0].SBOM.Reason != "" || len(res.Skipped[0].SBOM.Platforms) != 2 ||
				res.Skipped[0].SBOM.Platforms[0].Source != SBOMSourceGenerated {
				t.Fatalf("err %v, SBOM %+v", err, res.Skipped[0].SBOM)
			}
			if len(generated(t, dst.repo, digestOf(t, amd64), "")) != 1 || len(generated(t, dst.repo, d, linuxAMD64)) != 1 {
				t.Fatal("backfill did not attach the SBOMs")
			}
		})
	}
}

// TestSBOMBackfillIndexCopy attaches a missing index-level copy from the
// child referrer on the target, without generating again.
func TestSBOMBackfillIndexCopy(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{referrers: true})
	img := image(t)
	idx := mutate.AppendManifests(mutate.IndexMediaType(empty.Index, types.OCIImageIndex),
		mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: must(v1.ParsePlatform(linuxAMD64))}})
	d := push(t, src.repo, v100, idx)
	push(t, dst.repo, v100, idx)
	child := must(partial.Descriptor(img))
	child.Platform = nil
	ref := must(sbom.Referrer{Format: sbom.CycloneDX, Document: []byte(cdxDoc), Subject: *child, Generator: trivyGen, Created: time.Unix(1, 0)}.Image())
	if err := remote.Write(dst.repo.Digest(digestOf(t, ref).String()), ref); err != nil {
		t.Fatal(err)
	}
	b, g := newSBOM(t, canned(cdxDoc, "0"))

	res, err := Run(context.Background(), sbomRequest(src, dst, b))
	if err != nil || len(g.requests()) != 0 || res.Skipped[0].SBOM.Reason != "" {
		t.Fatalf("err %v, requests %v, SBOM %+v", err, g.requests(), res.Skipped[0].SBOM)
	}
	copies := generated(t, dst.repo, d, linuxAMD64)
	if len(copies) != 1 || docOf(t, dst.repo, copies[0]) != cdxDoc || copies[0].Annotations[sbom.AnnotationJavaScanned] != "false" {
		t.Fatalf("index copies %+v", copies)
	}
}

// TestSBOMIgnoredMutationUsesTarget generates the SBOM of the digest the
// target keeps, read from the target.
func TestSBOMIgnoredMutationUsesTarget(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	old := image(t)
	kept := push(t, dst.repo, v100, old)
	push(t, src.repo, v100, image(t))
	b, g := newSBOM(t, canned(cdxDoc, "0"))
	req := sbomRequest(src, dst, b)
	req.OnTagMutation = v1alpha1.OnTagMutationIgnore

	res, err := Run(context.Background(), req)
	if err != nil || !slices.Equal(g.requests(), []string{kept.Hex + ".cyclonedx"}) || res.Skipped[0].SBOM.Reason != "" {
		t.Fatalf("err %v, requests %v, result %+v", err, g.requests(), res)
	}
	if len(generated(t, dst.repo, kept, "")) != 1 {
		t.Fatal("SBOM not attached to the kept digest")
	}
}

// TestSBOMWithGate shares one layout and sidecar dir with the gate: a
// blocked tag gets no SBOM, a passed one does.
func TestSBOMWithGate(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	bad, good := image(t), image(t)
	push(t, src.repo, v100, bad)
	push(t, src.repo, "v2", good)
	badHex := digestOf(t, bad).Hex
	e := newGate(t, vuln.Policy{Action: vuln.Block, Severity: vuln.Critical}, func(h string) (string, string) {
		if h == badHex {
			return critical, "0"
		}
		return clean, "0"
	})
	b, g := newSBOMIn(t, e.gate.ScanDir, e.gate.LayoutDir, canned(cdxDoc, "0"))
	req := gatedRequest(src, dst, e.gate)
	req.Policy.Tags = []string{v100, "v2"}
	req.SBOM = b

	res, err := Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(g.requests(), []string{digestOf(t, good).Hex + ".cyclonedx"}) || len(res.Blocked) != 1 || res.Blocked[0].SBOM != nil {
		t.Fatalf("requests %v, result %+v", g.requests(), res)
	}
	if len(generated(t, dst.repo, digestOf(t, good), "")) != 1 {
		t.Fatal("passed tag has no SBOM")
	}
}
