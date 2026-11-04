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
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

const (
	onScanError   = "onScanError"
	block         = "Block"
	actionCopied  = "copied"
	actionBlocked = "blocked"
)

const critical = `[{"id":"CVE-2026-0001","pkg":"openssl","ver":"3.0.0","fix":"3.0.1","sev":"CRITICAL","status":"fixed"},
{"id":"RHSA-2026:0002","pkg":"glibc","ver":"2.0","fix":"","sev":"HIGH","status":"affected"}]`

// gated turns e into a gated run against a fake Trivy server whose DB is
// dbAge old and a fake sidecar that answers every scan with report and exit.
func (e *env) gated(t *testing.T, source string, gate map[string]any, dbAge time.Duration, report, exit string, sidecar bool) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"Version":"0.76.1","VulnerabilityDB":{"UpdatedAt":%q}}`, time.Now().Add(-dbAge).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(srv.Close)
	e.opts.scanDir, e.opts.layoutDir = filepath.Join(e.dir, "scan"), filepath.Join(e.dir, "work", "layout")
	e.opts.scannerCA = filepath.Join(e.dir, "missing", "scanner-ca.crt")
	for _, d := range []string{syncspec.ScanReqDir, syncspec.ScanOutDir} {
		if err := os.MkdirAll(filepath.Join(e.opts.scanDir, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if sidecar {
		e.write(t, filepath.Join(e.opts.scanDir, syncspec.ScanVersionFile), `{"Version":"0.76.1"}`)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go func() {
			for ctx.Err() == nil {
				rs, _ := filepath.Glob(filepath.Join(e.opts.scanDir, syncspec.ScanReqDir, "*.ready"))
				for _, r := range rs {
					_ = os.Remove(r)
					out := filepath.Join(e.opts.scanDir, syncspec.ScanOutDir, strings.TrimSuffix(filepath.Base(r), ".ready"))
					_ = os.WriteFile(out+".json", []byte(report), 0o600)
					_ = os.WriteFile(out+".exit", []byte(exit), 0o600)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	g := map[string]any{
		"action": "Report", "severity": "High", onScanError: "Report", "maxDBAge": "72h",
		"scanner": map[string]any{"url": srv.URL, "version": "0.76.1", "image": "trivy@sha256:" + strings.Repeat("a", 64), "timeout": "1s", "javaDB": "Disabled"},
	}
	maps.Copy(g, gate)
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	e.writeSpec(t, source, `"allowedSources":[`+strconv.Quote(strings.Split(source, "/")[0])+`],"gate":`+string(b))
}

func TestRunGated(t *testing.T) {
	for _, tc := range []struct {
		name         string
		gate         map[string]any
		dbAge        time.Duration
		exit         string
		sidecar      bool
		code         int
		copied       bool
		gateState    string
		auditAction  string
		verdict      v1alpha1.FindingVerdict
		reportReason string
	}{
		{"findings reported", nil, time.Hour, "0", true, syncspec.ExitOK, true, syncspec.GateOK, actionCopied, v1alpha1.VerdictFindings, ""},
		{"findings blocked", map[string]any{"action": block}, time.Hour, "0", true, syncspec.ExitOK, false, syncspec.GateOK, actionBlocked, v1alpha1.VerdictFindings, ""},
		{"stale DB reported", nil, 100 * time.Hour, "0", true, syncspec.ExitOK, true, syncspec.GateDBStale, actionCopied, v1alpha1.VerdictScanError, syncspec.GateDBStale},
		{"stale DB blocked", map[string]any{onScanError: block}, 100 * time.Hour, "0", true, syncspec.ExitConfig, false, syncspec.GateDBStale, actionBlocked, v1alpha1.VerdictScanError, syncspec.GateDBStale},
		{"scanner down blocked", map[string]any{onScanError: block}, time.Hour, "0", false, syncspec.ExitSyncFailed, false, syncspec.GateScannerUnavailable, actionBlocked, v1alpha1.VerdictScanError, syncspec.GateScannerUnavailable},
		{"scan failed blocked", map[string]any{onScanError: block}, time.Hour, "1", true, syncspec.ExitSyncFailed, false, syncspec.GateOK, actionBlocked, v1alpha1.VerdictScanError, syncspec.GateScanFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := newRegistry(t, false), newRegistry(t, true)
			pushImages(t, src, v110)
			e := newEnv(t, src, dst, password)
			e.gated(t, src.String(), tc.gate, tc.dbAge, critical, tc.exit, tc.sidecar)

			code, out, msg := e.run(t)
			if code != tc.code {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			checkGated(t, msg, out, tc.copied, tc.gateState, tc.auditAction, tc.verdict, tc.reportReason)
			_, err := remote.Head(dst.Tag(v110), remote.WithAuth(&authn.Basic{Username: user, Password: password}))
			if (err == nil) != tc.copied {
				t.Fatalf("target tag present %v, want %v", err == nil, tc.copied)
			}
			assertNoSecrets(t, out, msg)
		})
	}
}

func checkGated(t *testing.T, msg, out string, copied bool, gateState, auditAction string, verdict v1alpha1.FindingVerdict, reason string) {
	t.Helper()
	r, err := syncspec.ParseReport(msg)
	if err != nil {
		t.Fatalf("%v: %s", err, msg)
	}
	if r.V != syncspec.ReportVersionGate || r.Gate != gateState || r.JavaScanned == nil || *r.JavaScanned ||
		len(r.TagFindings) != 1 || (r.Blocked == 1) == copied || (r.Copied == 1) != copied {
		t.Fatalf("report %s", msg)
	}
	f := r.TagFindings[0]
	wantOutcome := v1alpha1.OutcomeBlocked
	if copied {
		wantOutcome = v1alpha1.OutcomeCopied
	}
	if f.Tag != v110 || f.Verdict != verdict || f.Outcome != wantOutcome || f.ScanError != reason || f.ScannedAt.IsZero() {
		t.Fatalf("tag finding %+v", f)
	}
	if verdict == v1alpha1.VerdictFindings {
		// RHSA-2026:0002 does not fit the status ID pattern and only reaches the audit line.
		if f.Severity != v1alpha1.SeverityCritical || f.Counts.Critical != 1 || f.Counts.High != 1 ||
			len(f.TopIDs) != 1 || f.TopIDs[0] != "CVE-2026-0001" || f.DBUpdatedAt == "" {
			t.Fatalf("tag finding %+v", f)
		}
	}
	checkGatedAudit(t, out, auditAction, verdict, wantOutcome)
}

func checkGatedAudit(t *testing.T, out, auditAction string, verdict v1alpha1.FindingVerdict, wantOutcome v1alpha1.FindingOutcome) {
	t.Helper()
	lines := auditLines(t, out)
	if len(lines) != 1 || lines[0].Action != auditAction || lines[0].Scan == nil {
		t.Fatalf("audit %s", out)
	}
	s := lines[0].Scan
	if s.Scanner.Version != "0.76.1" || s.JavaScanned || s.Outcome != strings.ToLower(string(wantOutcome)) ||
		s.Policy.Severity != "High" || (verdict == v1alpha1.VerdictFindings && !strings.Contains(out, "RHSA-2026:0002")) {
		t.Fatalf("audit scan %+v", s)
	}
}

// An ungated spec runs exactly as before: report version 1 without gate
// fields, no scan fields in the audit, and the scan paths are never touched.
func TestRunUngatedUnchanged(t *testing.T) {
	src, dst := newRegistry(t, false), newRegistry(t, true)
	pushImages(t, src, v110)
	e := newEnv(t, src, dst, password)
	e.opts.scanDir, e.opts.layoutDir = filepath.Join(e.dir, "scan"), filepath.Join(e.dir, "work", "layout")

	code, out, msg := e.run(t)
	if code != syncspec.ExitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(msg), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"findings", "accepted", "scanErrors", "blocked", "gate", "javaScanned", "tagFindings"} {
		if _, ok := raw[k]; ok {
			t.Fatalf("ungated report has %s: %s", k, msg)
		}
	}
	if raw["v"] != float64(syncspec.ReportVersion) || strings.Contains(out, `"scan"`) {
		t.Fatalf("report %s\naudit %s", msg, out)
	}
	for _, d := range []string{e.opts.scanDir, filepath.Dir(e.opts.layoutDir)} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("%s touched: %v", d, err)
		}
	}
}

func TestEncodeReportKeepsFindings(t *testing.T) {
	r := report{V: syncspec.ReportVersionGate, Findings: 30}
	for i := range 200 {
		r.Synced = append(r.Synced, syncedTag{Tag: fmt.Sprintf("v1.0.%d", i), Digest: "sha256:" + strings.Repeat("c", 64)})
	}
	for i := range 30 {
		r.TagFindings = append(r.TagFindings, syncspec.TagFinding{
			Tag: fmt.Sprintf("v1.0.%d", i), Digest: "sha256:" + strings.Repeat("c", 64), Verdict: v1alpha1.VerdictFindings,
			Outcome: v1alpha1.OutcomeBlocked, TopIDs: []string{"CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00003"},
		})
	}
	b := encode(r)
	got, err := syncspec.ParseReport(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if !got.FindingsTruncated || !got.Truncated || len(got.TagFindings) == 0 || len(got.Synced) == 200 || got.V != syncspec.ReportVersionGate {
		t.Fatalf("%d bytes: findings %d, synced %d", len(b), len(got.TagFindings), len(got.Synced))
	}
}
