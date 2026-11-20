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

package synccmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/r-gawronski/tagwarden/internal/sync"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

const cdxDoc = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`

// withSBOM gives e an SBOM policy and a fake generator that answers every
// request with doc and exit.
func (e *env) withSBOM(t *testing.T, source string, required bool, doc, exit string) {
	t.Helper()
	e.opts.scanDir, e.opts.layoutDir = filepath.Join(e.dir, "scan"), filepath.Join(e.dir, "work", "layout")
	for _, d := range []string{syncspec.ScanReqDir, syncspec.ScanOutDir} {
		if err := os.MkdirAll(filepath.Join(e.opts.scanDir, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	e.write(t, filepath.Join(e.opts.scanDir, syncspec.ScanVersionFile), `{"Version":"0.76.2"}`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			rs, _ := filepath.Glob(filepath.Join(e.opts.scanDir, syncspec.ScanReqDir, "*.cyclonedx"))
			for _, r := range rs {
				_ = os.Remove(r)
				out := filepath.Join(e.opts.scanDir, syncspec.ScanOutDir, filepath.Base(r))
				_ = os.WriteFile(out+".json", []byte(doc), 0o600)
				_ = os.WriteFile(out+".exit", []byte(exit), 0o600)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	policy := fmt.Sprintf(`{"mode":"Generate","format":"CycloneDX","required":%v,
		"generator":{"version":"0.76.2","image":"trivy@sha256:%s","timeout":"1s","javaDB":"Disabled"}}`, required, strings.Repeat("a", 64))
	e.writeSpec(t, source, `"allowedSources":[`+strconv.Quote(strings.Split(source, "/")[0])+`],"sbom":`+policy)
}

func TestRunSBOM(t *testing.T) {
	for _, tc := range []struct {
		name      string
		required  bool
		doc, exit string
		code      int
		published bool
		failure   string
	}{
		{"generated", true, cdxDoc, "0", syncspec.ExitOK, true, ""},
		{"failed, required", true, "garbage", "0", syncspec.ExitSyncFailed, false, syncspec.SBOMGenerationFailed},
		{"failed, not required", false, "garbage", "0", syncspec.ExitOK, true, syncspec.SBOMGenerationFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := newRegistry(t, false), newRegistry(t, true)
			pushImages(t, src, v110)
			e := newEnv(t, src, dst, password)
			e.withSBOM(t, src.String(), tc.required, tc.doc, tc.exit)

			code, out, msg := e.run(t)
			if code != tc.code {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			r, err := syncspec.ParseReport(msg)
			if err != nil {
				t.Fatalf("%v: %s", err, msg)
			}
			if r.V != syncspec.ReportVersionGate || r.JavaScanned == nil || *r.JavaScanned || r.Gate != "" || len(r.TagFindings) != 0 {
				t.Fatalf("report %s", msg)
			}
			lines := auditLines(t, out)
			if len(lines) != 1 || lines[0].SBOM == nil || lines[0].SBOM.Mode != "Generate" || lines[0].SBOM.Failure != tc.failure ||
				lines[0].SBOM.Generator.Version != "0.76.2" || lines[0].Scan != nil {
				t.Fatalf("audit %s", out)
			}
			if tc.failure == "" {
				p := lines[0].SBOM.Platforms
				if r.SBOMGenerated != 1 || r.SBOMFailed != 0 || len(p) != 1 || p[0].Source != sync.SBOMSourceGenerated || p[0].Referrer == "" {
					t.Fatalf("report %s\naudit %s", msg, out)
				}
			} else if r.SBOMFailed != 1 || len(r.SBOMFailures) != 1 || r.SBOMFailures[0].Reason != tc.failure ||
				r.SBOMFailures[0].Published != tc.published || r.SBOMFailures[0].Tag != v110 {
				t.Fatalf("report %s", msg)
			}
			_, err = remote.Head(dst.Tag(v110), remote.WithAuth(&authn.Basic{Username: user, Password: password}))
			if (err == nil) != tc.published {
				t.Fatalf("target tag present %v, want %v", err == nil, tc.published)
			}
			assertNoSecrets(t, out, msg)
		})
	}
}

// A re-scan Job of a gated mirror with an SBOM policy generates nothing.
func TestRunRescanNoSBOM(t *testing.T) {
	src, dst := newRegistry(t, false), newRegistry(t, false)
	pushImages(t, dst, v110)
	e := newEnv(t, src, dst, password)
	e.gated(t, src.String(), nil, time.Hour, clean, "0", true)
	spec, err := os.ReadFile(e.spec)
	if err != nil {
		t.Fatal(err)
	}
	policy := `,"sbom":{"mode":"Generate","format":"CycloneDX","generator":{"version":"0.76.1","timeout":"1s","javaDB":"Disabled"}}}`
	s := strings.Replace(string(spec), `"tags":{"keepLatest":2}`, `"tags":{"tags":["`+v110+`"]}`, 1)
	e.write(t, e.spec, strings.TrimSuffix(strings.TrimSpace(s), "}")+policy)
	code, out, msg := e.run(t, "--rescan")
	r, err := syncspec.ParseReport(msg)
	if code != syncspec.ExitOK || err != nil || !r.Rescan || r.SBOMGenerated+r.SBOMFailed != 0 || strings.Contains(out, `"sbom"`) {
		t.Fatalf("exit %d, err %v: %s\n%s", code, err, msg, out)
	}
}

func TestEncodeReportCutsSBOMFailuresFirst(t *testing.T) {
	r := report{V: syncspec.ReportVersionGate, SBOMFailed: syncspec.MaxSBOMFailures}
	for i := range syncspec.MaxSBOMFailures {
		r.SBOMFailures = append(r.SBOMFailures, syncspec.SBOMFailure{
			Tag: fmt.Sprintf("v1.0.%d", i), Digest: "sha256:" + strings.Repeat("c", 64), Reason: syncspec.SBOMGenerationFailed,
		})
	}
	for i := range 33 {
		r.Synced = append(r.Synced, syncedTag{Tag: fmt.Sprintf("v1.0.%d", i), Digest: "sha256:" + strings.Repeat("c", 64)})
	}
	got, err := syncspec.ParseReport(string(encode(r)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Truncated || len(got.Synced) != 33 || len(got.SBOMFailures) == syncspec.MaxSBOMFailures || got.SBOMFailed != syncspec.MaxSBOMFailures {
		t.Fatalf("synced %d (truncated %v), failures %d, failed %d", len(got.Synced), got.Truncated, len(got.SBOMFailures), got.SBOMFailed)
	}
}

// Every SBOM outcome the sync engine can produce encodes to a report that
// ParseReport accepts, and failures beyond the cap are only counted.
func TestSBOMSummaryRoundTrip(t *testing.T) {
	digest := "sha256:" + strings.Repeat("d", 64)
	res := sync.Result{}
	for i, reason := range []string{"", syncspec.SBOMGenerationFailed, syncspec.SBOMTooLarge, syncspec.SBOMAttachFailed, syncspec.SBOMMissing} {
		for j := range 3 {
			tag := fmt.Sprintf("v%d.%d", i, j)
			res.Selected = append(res.Selected, tag)
			a := sync.Artifact{Tag: tag, Digest: digest, SBOM: &sync.SBOMResult{Reason: reason, Detail: "x",
				Platforms: []sync.SBOMPlatform{{Source: sync.SBOMSourceGenerated}, {Source: sync.SBOMSourceUpstream}, {Source: sync.SBOMSourcePresent}}}}
			if j == 2 {
				res.Failed = append(res.Failed, a)
			} else {
				res.Copied = append(res.Copied, a)
			}
		}
	}
	r := summarize(res)
	sbomSummary(&r, res)
	b, _ := json.Marshal(r)
	got, err := syncspec.ParseReport(string(encode(r)))
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if got.SBOMFailed != 12 || len(got.SBOMFailures) != syncspec.MaxSBOMFailures || got.SBOMGenerated != 15 || got.SBOMUpstream != 15 ||
		got.SBOMFailures[2].Published || !got.SBOMFailures[0].Published {
		t.Fatalf("report %s", b)
	}
}
