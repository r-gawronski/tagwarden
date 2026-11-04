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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/r-gawronski/tagwarden/internal/syncspec"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

// Gate turns on the vulnerability gate for a run: every tag that would be
// copied, and every tag on the target without a judged verdict, is
// written to an OCI layout, scanned by the sidecar and judged before
// anything is pushed.
type Gate struct {
	Policy     vuln.Policy
	Exceptions []vuln.Exception
	// Namespace and Repository identify the mirror for exceptions;
	// Repository is the canonical source repository.
	Namespace, Repository string
	// Judged maps tags to the digest this mirror has a final verdict for.
	Judged map[string]string
	// LayoutDir and ScanDir are syncspec.LayoutDir and syncspec.ScanDir.
	LayoutDir, ScanDir string
	// ServerURL is the Trivy server; Client reads its /version.
	ServerURL string
	Client    *http.Client
	// Version is the pinned client version. The server and the sidecar
	// must have the same major.minor.
	Version  string
	MaxDBAge time.Duration
	// Timeout is the scan timeout of one manifest.
	Timeout time.Duration
	// JavaDB is pulled from the target registry before the first scan.
	// Nil means JAR files are not scanned.
	JavaDB *name.Tag
	// Now and Poll are for tests: the clock and the sidecar poll interval.
	Now  func() time.Time
	Poll time.Duration
}

// Scan is the gate outcome of one tag.
type Scan struct {
	vuln.Result
	// PresentOnTarget means the digest was already on the target.
	PresentOnTarget bool
	ScannedAt       time.Time
	// DBUpdatedAt is the server DB time, zero when the server was not
	// reachable.
	DBUpdatedAt time.Time
	// Detail explains the first scan error in a few words.
	Detail string
}

// ScanBlockedError means tags were not copied because they could not be
// judged under onScanError Block.
type ScanBlockedError struct{ Reasons []string }

func (e *ScanBlockedError) Error() string {
	return "sync: tags blocked by scan errors: " + strings.Join(e.Reasons, ", ")
}

// Retryable reports whether a new Job may get a verdict: false when every
// reason is a stale DB or a version mismatch, which need the platform to act.
func (e *ScanBlockedError) Retryable() bool {
	return slices.ContainsFunc(e.Reasons, func(r string) bool {
		return r != syncspec.GateDBStale && r != syncspec.GateVersionMismatch
	})
}

const (
	maxVersionBytes = 64 << 10
	javaDBMediaType = "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"
	// Caps on the Java DB, about 1 GB compressed and 1.5 GB unpacked today.
	maxJavaDBCompressed = 2 << 30
	maxJavaDBBytes      = 3 << 30
	maxJavaDBFiles      = 8
)

// javaDBFiles are the only names accepted from the Java DB tarball.
var javaDBFiles = []string{"trivy-java.db", "metadata.json"}

// gateState is the gate of one run. The scanner is checked once, before the
// first scan.
type gateState struct {
	Gate
	root        *os.Root
	checked     bool
	reason      string // syncspec.GateOK or a scan error reason
	detail      string
	dbUpdatedAt time.Time
	javaScanned bool
}

func (g *gateState) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// ensure runs the scanner check once per run.
func (g *gateState) ensure(ctx context.Context, s *syncer) {
	if g.checked {
		return
	}
	g.checked = true
	g.reason, g.detail = g.check(ctx, s)
}

func (g *gateState) check(ctx context.Context, s *syncer) (string, string) {
	var err error
	if g.root, err = os.OpenRoot(g.ScanDir); err != nil {
		return syncspec.GateScannerUnavailable, "scan volume missing"
	}
	if reason, detail := g.checkServer(ctx); reason != syncspec.GateOK {
		return reason, detail
	}
	if reason, detail := g.checkSidecar(ctx); reason != syncspec.GateOK {
		return reason, detail
	}
	if g.JavaDB != nil {
		if err := g.fetchJavaDB(ctx, s); err != nil {
			return syncspec.GateScannerUnavailable, "java DB unavailable"
		}
		g.javaScanned = true
	}
	return syncspec.GateOK, ""
}

// trivyVersion is the part of `trivy version --format json` and of the
// server's /version that the gate reads.
type trivyVersion struct {
	Version         string
	VulnerabilityDB *struct{ UpdatedAt time.Time }
}

func (g *gateState) checkServer(ctx context.Context) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, g.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(g.ServerURL, "/")+"/version", nil)
	if err != nil {
		return syncspec.GateScannerUnavailable, "invalid server URL"
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return syncspec.GateScannerUnavailable, "server unreachable"
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return syncspec.GateScannerUnavailable, fmt.Sprintf("server /version: HTTP %d", resp.StatusCode)
	}
	var v trivyVersion
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxVersionBytes)).Decode(&v); err != nil {
		return syncspec.GateScannerUnavailable, "server /version: invalid response"
	}
	if !sameMinor(v.Version, g.Version) {
		return syncspec.GateVersionMismatch, fmt.Sprintf("server version mismatch, want %s.x", minor(g.Version))
	}
	if v.VulnerabilityDB == nil || v.VulnerabilityDB.UpdatedAt.IsZero() {
		return syncspec.GateDBStale, "server has no vulnerability DB"
	}
	g.dbUpdatedAt = v.VulnerabilityDB.UpdatedAt.UTC()
	if age := g.now().Sub(g.dbUpdatedAt); age > g.MaxDBAge {
		return syncspec.GateDBStale, fmt.Sprintf("vulnerability DB updated %s ago, max %s", age.Round(time.Minute), g.MaxDBAge)
	}
	return syncspec.GateOK, ""
}

// checkSidecar waits for the version the sidecar writes at start.
func (g *gateState) checkSidecar(ctx context.Context) (string, string) {
	var b []byte
	err := g.wait(ctx, g.Timeout, func() (bool, error) {
		var err error
		b, err = readSmall(g.root, syncspec.ScanVersionFile, maxVersionBytes)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return true, err
	})
	if err != nil {
		return syncspec.GateScannerUnavailable, "scanner sidecar not running"
	}
	var v trivyVersion
	if json.Unmarshal(b, &v) != nil {
		return syncspec.GateScannerUnavailable, "scanner sidecar: invalid version"
	}
	if !sameMinor(v.Version, g.Version) {
		return syncspec.GateVersionMismatch, fmt.Sprintf("client version mismatch, want %s.x", minor(g.Version))
	}
	return syncspec.GateOK, ""
}

func minor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func sameMinor(a, b string) bool { return minor(a) != "" && minor(a) == minor(b) }

// fetchJavaDB pulls the Java DB through the target transport and extracts
// it into ScanDir/cache/java-db.
func (g *gateState) fetchJavaDB(ctx context.Context, s *syncer) error {
	desc, err := s.dst.Get(ctx, *g.JavaDB)
	if err != nil {
		return err
	}
	img, err := desc.Image()
	if err != nil {
		return err
	}
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	if len(layers) != 1 {
		return fmt.Errorf("want one layer, got %d", len(layers))
	}
	l := layers[0]
	if mt, err := l.MediaType(); err != nil || mt != javaDBMediaType {
		return errors.New("unexpected layer media type")
	}
	if n, err := l.Size(); err != nil || n > maxJavaDBCompressed {
		return errors.New("layer too large")
	}
	if err := g.root.MkdirAll(syncspec.JavaDBDir, 0o755); err != nil {
		return err
	}
	if err := g.extractJavaDB(l); err != nil {
		_ = g.root.RemoveAll(syncspec.JavaDBDir)
		return err
	}
	return nil
}

func (g *gateState) extractJavaDB(l v1.Layer) error {
	dir, err := g.root.OpenRoot(syncspec.JavaDBDir)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	rc, err := l.Compressed()
	if err != nil {
		return err
	}
	err = extractJavaDB(rc, dir)
	if cerr := rc.Close(); err == nil {
		err = cerr
	}
	return err
}

// maxJavaDBTrailing caps what may follow the tar end marker, which is
// padding in a valid tarball.
const maxJavaDBTrailing = 1 << 20

// extractJavaDB gunzips and extracts the Java DB, then reads the stream to
// its end: the registry blob reader checks the layer size and digest only
// at the end of the compressed stream, and a multistream gzip reader
// reaches it. Data after the tar end marker beyond the padding cap fails.
func extractJavaDB(compressed io.Reader, dir *os.Root) error {
	zr, err := gzip.NewReader(compressed)
	if err != nil {
		return err
	}
	if err := extractTar(zr, dir, javaDBFiles, maxJavaDBFiles, maxJavaDBBytes); err != nil {
		return err
	}
	n, err := io.Copy(io.Discard, io.LimitReader(zr, maxJavaDBTrailing+1))
	if err != nil {
		return err
	}
	if n > maxJavaDBTrailing {
		return errors.New("data after the tar archive")
	}
	return zr.Close()
}

// child is one manifest of an artifact to scan.
type child struct {
	platform string
	digest   v1.Hash
	skip     bool   // an attestation manifest, never scanned
	unusable string // why it cannot be scanned
}

// scan judges desc. When the scanner check failed it judges without a
// layout, and the returned taggable is desc. Otherwise it writes desc to
// the layout, scans each image manifest and returns the layout artifact,
// so the bytes pushed are the bytes scanned.
func (s *syncer) scan(ctx context.Context, desc *remote.Descriptor, present bool) (*Scan, remote.Taggable, error) {
	g := s.gate
	g.ensure(ctx, s)
	sc := &Scan{PresentOnTarget: present, DBUpdatedAt: g.dbUpdatedAt}
	subject := vuln.Subject{Namespace: g.Namespace, Repository: g.Repository, Digest: desc.Digest.String()}
	judge := func(in []vuln.PlatformInput) {
		sc.ScannedAt = g.now()
		sc.Result = vuln.Evaluate(g.Policy, g.Exceptions, subject, in, g.javaScanned, sc.ScannedAt)
	}
	if g.reason != syncspec.GateOK {
		sc.Detail = g.detail
		judge([]vuln.PlatformInput{{Digest: desc.Digest.String(), ScanError: g.reason}})
		return sc, desc, nil
	}
	t, children, err := writeLayout(g.LayoutDir, desc)
	switch {
	case errors.Is(err, syscall.ENOSPC):
		sc.Detail = "scan volume full, raise scanner.storage"
		judge([]vuln.PlatformInput{{Digest: desc.Digest.String(), ScanError: syncspec.GateScanFailed}})
		return sc, desc, nil
	case err != nil:
		return nil, nil, fmt.Errorf("write layout: %w", err)
	}
	in := []vuln.PlatformInput{}
	for _, c := range children {
		if c.skip {
			continue
		}
		pi := vuln.PlatformInput{Platform: c.platform, Digest: c.digest.String()}
		var detail string
		if c.unusable != "" {
			pi.ScanError, detail = syncspec.GateScanFailed, c.unusable
		} else {
			pi.Findings, pi.ScanError, detail = g.scanManifest(ctx, c.digest)
		}
		if detail != "" && sc.Detail == "" {
			sc.Detail = detail
		}
		in = append(in, pi)
	}
	if len(in) == 0 {
		// Only attestations: nothing to judge is never a pass.
		sc.Detail = "no image manifests"
		in = append(in, vuln.PlatformInput{Digest: desc.Digest.String(), ScanError: syncspec.GateScanFailed})
	}
	judge(in)
	return sc, t, nil
}

// writeLayout replaces dir with an OCI layout of desc that lists every
// child of an index at the top level of index.json, because the Trivy
// client only selects top-level digests. The returned taggable keeps the
// original manifest bytes and reads every blob from the layout.
func writeLayout(dir string, desc *remote.Descriptor) (remote.Taggable, []child, error) {
	if err := os.RemoveAll(dir); err != nil {
		return nil, nil, err
	}
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		return nil, nil, err
	}
	if !desc.MediaType.IsIndex() {
		if !desc.MediaType.IsImage() {
			return nil, nil, fmt.Errorf("unsupported media type %s", desc.MediaType)
		}
		img, err := desc.Image()
		if err != nil {
			return nil, nil, err
		}
		if err := p.WriteImage(img); err != nil {
			return nil, nil, err
		}
		if err := p.AppendDescriptor(desc.Descriptor); err != nil {
			return nil, nil, err
		}
		c := child{digest: desc.Digest}
		if cf, err := img.ConfigFile(); err == nil && cf.Platform() != nil {
			c.platform = cf.Platform().String()
		}
		mf, err := img.Manifest()
		if err != nil {
			return nil, nil, err
		}
		c.skip = vuln.SkipManifest(layerTypes(mf))
		li, err := p.Image(desc.Digest)
		return li, []child{c}, err
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, nil, err
	}
	im, err := v1.ParseIndexManifest(bytes.NewReader(desc.Manifest))
	if err != nil {
		return nil, nil, err
	}
	var children []child
	for _, m := range im.Manifests {
		c := child{digest: m.Digest}
		if m.Platform != nil {
			c.platform = m.Platform.String()
		}
		switch {
		case m.MediaType.IsImage():
			img, err := idx.Image(m.Digest)
			if err != nil {
				return nil, nil, err
			}
			if err := p.WriteImage(img); err != nil {
				return nil, nil, err
			}
			// The verified manifest decides, not the publisher's platform label.
			mf, err := img.Manifest()
			if err != nil {
				return nil, nil, err
			}
			c.skip = vuln.SkipManifest(layerTypes(mf))
		case m.MediaType.IsIndex():
			ci, err := idx.ImageIndex(m.Digest)
			if err != nil {
				return nil, nil, err
			}
			if err := p.WriteIndex(ci); err != nil {
				return nil, nil, err
			}
			c.unusable = "nested index"
		default:
			return nil, nil, fmt.Errorf("unsupported child media type %s", m.MediaType)
		}
		if err := p.AppendDescriptor(m); err != nil {
			return nil, nil, err
		}
		children = append(children, c)
	}
	top, err := p.ImageIndex()
	if err != nil {
		return nil, nil, err
	}
	return &layoutIndex{top: top, raw: desc.Manifest, mt: desc.MediaType}, children, nil
}

// layoutIndex is an index with its original manifest bytes whose children
// come from the top level of a layout.
type layoutIndex struct {
	top v1.ImageIndex
	raw []byte
	mt  types.MediaType
}

func (l *layoutIndex) MediaType() (types.MediaType, error) { return l.mt, nil }
func (l *layoutIndex) RawManifest() ([]byte, error)        { return l.raw, nil }
func (l *layoutIndex) Size() (int64, error)                { return int64(len(l.raw)), nil }
func (l *layoutIndex) Digest() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.raw))
	return h, err
}
func (l *layoutIndex) IndexManifest() (*v1.IndexManifest, error) {
	return v1.ParseIndexManifest(bytes.NewReader(l.raw))
}
func (l *layoutIndex) Image(h v1.Hash) (v1.Image, error)           { return l.top.Image(h) }
func (l *layoutIndex) ImageIndex(h v1.Hash) (v1.ImageIndex, error) { return l.top.ImageIndex(h) }
