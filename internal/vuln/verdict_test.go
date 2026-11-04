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

package vuln

import (
	"reflect"
	"testing"
	"time"
)

const (
	cve1        = "CVE-1"
	digA        = "sha256:a"
	failed      = "ScanFailed"
	linux       = "linux"
	amd64       = "amd64"
	unk         = "unknown"
	statusFixed = "fixed"
	linuxAmd64  = linux + "/" + amd64
)

var now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func f(id string, sev Severity, fix string) Finding {
	return Finding{ID: id, Pkg: "p", Version: "1", Fix: fix, Severity: sev}
}

func pl(name, digest string, fs ...Finding) PlatformInput {
	return PlatformInput{Platform: name, Digest: digest, Findings: fs}
}

func exc(name string, mod func(*Exception)) Exception {
	e := Exception{
		Name: name, Namespaces: []string{"team-a"}, Repository: "docker.io/library/nginx",
		Digests: []string{"sha256:idx"}, Expires: now.Add(time.Hour),
	}
	if mod != nil {
		mod(&e)
	}
	return e
}

var subj = Subject{Namespace: "team-a", Repository: "docker.io/library/nginx", Digest: "sha256:idx"}

func TestEvaluateSingle(t *testing.T) {
	crit := f(cve1, Critical, "2")
	tests := []struct {
		name       string
		policy     Policy
		excs       []Exception
		in         []PlatformInput
		wantV      Verdict
		wantBlock  bool
		wantIDs    []string
		wantAccept int
	}{
		{"clean", Policy{Action: Block, Severity: Critical}, nil,
			[]PlatformInput{pl(linuxAmd64, digA, f("CVE-2", High, "x"))}, Passed, false, nil, 0},
		{"critical report", Policy{Action: Report, Severity: Critical}, nil,
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, FindingsFound, false, []string{cve1}, 0},
		{"critical block", Policy{Action: Block, Severity: Critical}, nil,
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, FindingsFound, true, []string{cve1}, 0},
		{"threshold high counts critical", Policy{Action: Block, Severity: High}, nil,
			[]PlatformInput{pl(linuxAmd64, digA, f("CVE-3", High, "1"), crit)}, FindingsFound, true, []string{cve1, "CVE-3"}, 0},
		{"threshold low counts all but unknown", Policy{Action: Block, Severity: Low}, nil,
			[]PlatformInput{pl(linuxAmd64, digA, f("CVE-4", Low, "1"), f("CVE-5", Unknown, "1"))}, FindingsFound, true, []string{"CVE-4"}, 0},
		{"unknown never blocks", Policy{Action: Block, Severity: Low}, nil,
			[]PlatformInput{pl(linuxAmd64, digA, f("CVE-5", Unknown, "1"))}, Passed, false, nil, 0},
		{"includeUnknown counts", Policy{Action: Block, Severity: Critical, IncludeUnknown: true}, nil,
			[]PlatformInput{pl(linuxAmd64, digA, f("CVE-5", Unknown, "1"))}, FindingsFound, true, []string{"CVE-5"}, 0},
		{"ignoreUnfixed drops unfixed", Policy{Action: Block, Severity: Critical, IgnoreUnfixed: true}, nil,
			[]PlatformInput{pl(linuxAmd64, digA, f("CVE-6", Critical, ""))}, Passed, false, nil, 0},
		{"ignoreUnfixed keeps status fixed with empty fix", Policy{Action: Block, Severity: Critical, IgnoreUnfixed: true}, nil,
			[]PlatformInput{pl(linuxAmd64, digA, Finding{ID: cve1, Severity: Critical, Status: statusFixed})}, FindingsFound, true, []string{cve1}, 0},
		{"ignoreUnfixed keeps fixed", Policy{Action: Block, Severity: Critical, IgnoreUnfixed: true}, nil,
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, FindingsFound, true, []string{cve1}, 0},
		{"exception by digest covers all", Policy{Action: Block, Severity: Critical}, []Exception{exc("e1", nil)},
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, Accepted, false, nil, 1},
		{"exception by child digest", Policy{Action: Block, Severity: Critical},
			[]Exception{exc("e1", func(e *Exception) { e.Digests = []string{digA} })},
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, Accepted, false, nil, 1},
		{"exception other digest", Policy{Action: Block, Severity: Critical},
			[]Exception{exc("e1", func(e *Exception) { e.Digests = []string{"sha256:zzz"} })},
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, FindingsFound, true, []string{cve1}, 0},
		{"exception by id only", Policy{Action: Block, Severity: Critical},
			[]Exception{exc("e1", func(e *Exception) { e.Digests = nil; e.Vulnerabilities = []string{cve1} })},
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, Accepted, false, nil, 1},
		{"exception id covers one of two", Policy{Action: Block, Severity: Critical},
			[]Exception{exc("e1", func(e *Exception) { e.Digests = nil; e.Vulnerabilities = []string{cve1} })},
			[]PlatformInput{pl(linuxAmd64, digA, crit, f("CVE-7", Critical, "1"))}, FindingsFound, true, []string{"CVE-7"}, 1},
		{"exception digest and id both required", Policy{Action: Block, Severity: Critical},
			[]Exception{exc("e1", func(e *Exception) { e.Vulnerabilities = []string{"CVE-9"} })},
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, FindingsFound, true, []string{cve1}, 0},
		{"exception wrong namespace", Policy{Action: Block, Severity: Critical},
			[]Exception{exc("e1", func(e *Exception) { e.Namespaces = []string{"team-b"} })},
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, FindingsFound, true, []string{cve1}, 0},
		{"exception wrong repository", Policy{Action: Block, Severity: Critical},
			[]Exception{exc("e1", func(e *Exception) { e.Repository = "docker.io/library/redis" })},
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, FindingsFound, true, []string{cve1}, 0},
		{"exception expired", Policy{Action: Block, Severity: Critical},
			[]Exception{exc("e1", func(e *Exception) { e.Expires = now })},
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, FindingsFound, true, []string{cve1}, 0},
		{"exception without digest or id matches nothing", Policy{Action: Block, Severity: Critical},
			[]Exception{exc("e1", func(e *Exception) { e.Digests = nil })},
			[]PlatformInput{pl(linuxAmd64, digA, crit)}, FindingsFound, true, []string{cve1}, 0},
		{"scan error report", Policy{Action: Block, Severity: Critical, OnScanError: Report},
			nil, []PlatformInput{{Platform: linuxAmd64, Digest: digA, ScanError: failed}}, ScanError, false, nil, 0},
		{"scan error block", Policy{Action: Report, Severity: Critical, OnScanError: Block},
			nil, []PlatformInput{{Platform: linuxAmd64, Digest: digA, ScanError: "DBStale"}}, ScanError, true, nil, 0},
		{"no platforms is a scan error", Policy{Action: Report, Severity: Critical, OnScanError: Block},
			nil, nil, ScanError, true, nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Evaluate(tc.policy, tc.excs, subj, tc.in, false, now)
			if r.Verdict != tc.wantV {
				t.Errorf("verdict = %s, want %s", r.Verdict, tc.wantV)
			}
			if r.Block != tc.wantBlock {
				t.Errorf("block = %v, want %v", r.Block, tc.wantBlock)
			}
			if len(tc.in) > 0 && !reflect.DeepEqual(r.Platforms[0].IDs, tc.wantIDs) {
				t.Errorf("ids = %v, want %v", r.Platforms[0].IDs, tc.wantIDs)
			}
			if len(tc.in) > 0 && len(r.Platforms[0].Accepted) != tc.wantAccept {
				t.Errorf("accepted = %v, want %d", r.Platforms[0].Accepted, tc.wantAccept)
			}
		})
	}
}

func TestAcceptedNamesException(t *testing.T) {
	e := exc("zeta", nil)
	e2 := exc("alpha", nil)
	r := Evaluate(Policy{Action: Block, Severity: Critical}, []Exception{e, e2}, subj,
		[]PlatformInput{pl(linuxAmd64, digA, f(cve1, Critical, "1"))}, false, now)
	got := r.Platforms[0].Accepted
	if len(got) != 1 || got[0] != (AcceptedFinding{ID: cve1, Exception: "alpha"}) {
		t.Fatalf("accepted = %+v", got)
	}
}

func TestEvaluateIndex(t *testing.T) {
	crit := f(cve1, Critical, "1")
	p := Policy{Action: Block, Severity: Critical, OnScanError: Report}
	t.Run("one bad platform blocks the index", func(t *testing.T) {
		r := Evaluate(p, nil, subj, []PlatformInput{
			pl(linuxAmd64, digA), pl("linux/arm64", "sha256:b", crit)}, false, now)
		if r.Verdict != FindingsFound || !r.Block {
			t.Fatalf("got %s block=%v", r.Verdict, r.Block)
		}
		if r.Platforms[0].Verdict != Passed || r.Platforms[1].Verdict != FindingsFound {
			t.Fatalf("platforms: %+v", r.Platforms)
		}
	})
	t.Run("accepted beats passed", func(t *testing.T) {
		r := Evaluate(p, []Exception{exc("e", func(e *Exception) { e.Digests = []string{"sha256:b"} })}, subj, []PlatformInput{
			pl(linuxAmd64, digA), pl("linux/arm64", "sha256:b", crit)}, false, now)
		if r.Verdict != Accepted || r.Block {
			t.Fatalf("got %s block=%v", r.Verdict, r.Block)
		}
	})
	t.Run("findings and scan error, each mapped by its own action", func(t *testing.T) {
		in := []PlatformInput{pl(linuxAmd64, digA, crit), {Platform: "linux/arm64", Digest: "sha256:b", ScanError: failed}}
		r := Evaluate(Policy{Action: Report, Severity: Critical, OnScanError: Block}, nil, subj, in, false, now)
		if !r.Block || r.Verdict != FindingsFound || r.Reason != failed {
			t.Fatalf("got %s block=%v reason=%q", r.Verdict, r.Block, r.Reason)
		}
		r = Evaluate(Policy{Action: Block, Severity: Critical, OnScanError: Report}, nil, subj, in, false, now)
		if !r.Block {
			t.Fatal("findings under Block must block")
		}
		r = Evaluate(Policy{Action: Report, Severity: Critical, OnScanError: Report}, nil, subj, in, false, now)
		if r.Block {
			t.Fatal("Report/Report must copy")
		}
	})
}

func TestSummary(t *testing.T) {
	fs := make([]Finding, 0, 12)
	for i := range 8 {
		fs = append(fs, f("CVE-"+string(rune('A'+i)), Critical, "1"))
	}
	fs = append(fs, f("CVE-A", Critical, "1"), f("CVE-X", High, "1"), f("CVE-L", Low, ""), f("CVE-U", Unknown, ""))
	r := Evaluate(Policy{Action: Report, Severity: High}, nil, subj,
		[]PlatformInput{pl(linuxAmd64, digA, fs...), pl("linux/arm64", "sha256:b", f("CVE-Z", Critical, "1"))}, true, now)
	if !r.JavaScanned || !r.Platforms[0].JavaScanned {
		t.Error("javaScanned not carried")
	}
	if r.Highest != Critical {
		t.Errorf("highest = %s", r.Highest)
	}
	// Counts cover every reported finding of the worst platform.
	wantCounts := map[Severity]int{Critical: 9, High: 1, Low: 1, Unknown: 1}
	if !reflect.DeepEqual(r.Counts, wantCounts) {
		t.Errorf("counts = %v, want %v", r.Counts, wantCounts)
	}
	wantTop := []string{"CVE-A", "CVE-B", "CVE-C", "CVE-D", "CVE-E"}
	if !reflect.DeepEqual(r.TopIDs, wantTop) {
		t.Errorf("top = %v, want %v", r.TopIDs, wantTop)
	}
	if got := r.Platforms[0].IDs; len(got) != 9 || got[8] != "CVE-X" {
		t.Errorf("ids = %v", got)
	}
}

func TestIDsCap(t *testing.T) {
	fs := make([]Finding, 0, MaxAuditIDs+50)
	for i := range MaxAuditIDs + 50 {
		fs = append(fs, f("CVE-"+itoa(i), Critical, "1"))
	}
	r := Evaluate(Policy{Severity: Critical}, nil, subj, []PlatformInput{pl(linuxAmd64, digA, fs...)}, false, now)
	p := r.Platforms[0]
	if len(p.IDs) != MaxAuditIDs || !p.IDsTruncated {
		t.Fatalf("len=%d truncated=%v", len(p.IDs), p.IDsTruncated)
	}
}

func itoa(i int) string {
	const d = "0123456789"
	s := ""
	for ; i > 0 || s == ""; i /= 10 {
		s = string(d[i%10]) + s
	}
	// Pad so lexical order matches numeric order.
	for len(s) < 6 {
		s = "0" + s
	}
	return s
}

func TestSkipManifest(t *testing.T) {
	const (
		intoto = "application/vnd.in-toto+json"
		dsse   = "application/vnd.dsse.envelope.v1+json"
		tarGz  = "application/vnd.oci.image.layer.v1.tar+gzip"
		sig    = "application/vnd.dev.cosign.simplesigning.v1+json"
		spdx   = "application/spdx+json"
	)
	tests := []struct {
		layers         []string
		skip, artifact bool
	}{
		{nil, false, false},
		{[]string{intoto}, true, true},
		{[]string{intoto, dsse}, true, true},
		{[]string{intoto, tarGz}, false, false},
		{[]string{tarGz}, false, false},
		{[]string{sig}, false, true},
		{[]string{spdx, sig}, false, true},
		{[]string{sig, "application/vnd.docker.image.rootfs.diff.tar.gzip"}, false, false},
		{[]string{"application/jose+json"}, false, true},
		{[]string{"application/cose"}, false, false},
		{[]string{"text/spdx"}, false, false},
		{[]string{"application/vnd.cyclonedx+xml"}, false, false},
	}
	for _, tc := range tests {
		if got := SkipManifest(tc.layers); got != tc.skip {
			t.Errorf("SkipManifest(%v) = %v", tc.layers, got)
		}
		if got := SupplyChainArtifact(tc.layers); got != tc.artifact {
			t.Errorf("SupplyChainArtifact(%v) = %v", tc.layers, got)
		}
	}
}

func TestAcceptedDedupeAndCap(t *testing.T) {
	pol := Policy{Action: Block, Severity: Critical}
	e := exc("e1", nil)
	t.Run("duplicates collapse", func(t *testing.T) {
		fs := make([]Finding, 0, 5000)
		for range 5000 {
			fs = append(fs, f(cve1, Critical, "1"))
		}
		r := Evaluate(pol, []Exception{e}, subj, []PlatformInput{pl(linuxAmd64, digA, fs...)}, false, now)
		if got := r.Platforms[0]; len(got.Accepted) != 1 || got.AcceptedTruncated || r.Verdict != Accepted {
			t.Fatalf("accepted=%d trunc=%v verdict=%s", len(got.Accepted), got.AcceptedTruncated, r.Verdict)
		}
	})
	t.Run("cap keeps the verdict", func(t *testing.T) {
		fs := make([]Finding, 0, 3*MaxAuditIDs)
		for i := range 3 * MaxAuditIDs {
			fs = append(fs, f("CVE-"+itoa(i), Critical, "1"), f("CVE-"+itoa(i), Critical, "1"))
		}
		r := Evaluate(pol, []Exception{e}, subj, []PlatformInput{pl(linuxAmd64, digA, fs...)}, false, now)
		if got := r.Platforms[0]; len(got.Accepted) != MaxAuditIDs || !got.AcceptedTruncated || r.Verdict != Accepted || r.Block {
			t.Fatalf("accepted=%d trunc=%v verdict=%s", len(got.Accepted), got.AcceptedTruncated, r.Verdict)
		}
	})
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"Critical": Critical, "high": High, "MEDIUM": Medium, "Low": Low} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("Unknown"); err == nil {
		t.Error("Unknown must not be a threshold")
	}
}
